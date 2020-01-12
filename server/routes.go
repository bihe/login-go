package server

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/bihe/commons-go/security"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

// routes performs setup of middlewares and API handlers
func (s *server) routes() {
	r := chi.NewRouter()

	// A good base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.DefaultCompress)
	//r.Use(middleware.RedirectSlashes)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// serving static content
	serveStaticFile(r, "/favicon.ico", filepath.Join(s.basePath, "./assets/favicon.ico"))
	serveStaticDir(r, "/assets", http.Dir(filepath.Join(s.basePath, "./assets")))

	r.Get("/error", s.api.Call(s.api.HandleError))
	r.Get("/start-oidc", s.api.Call(s.api.HandleOIDCRedirect))
	r.Get("/auth/flow", s.api.Call(s.api.HandleAuthFlow))
	r.Get(s.api.GetOIDCRedirectURL(), s.api.Call(s.api.HandleOIDCRedirectFinal))
	r.Get("/signin-oidc", s.api.Call(s.api.HandleOIDCLogin))

	// this group "indicates" that all routes within this group use the JWT authentication
	r.Group(func(r chi.Router) {
		// authenticate and authorize users via JWT
		r.Use(security.NewJwtMiddleware(s.jwtOpts, s.cookieSettings).JwtContext)

		r.Get("/logout", s.api.Secure(s.api.HandleLogout))

		// group API methods together
		r.Route("/api/v1", func(r chi.Router) {
			r.Get("/appinfo", s.api.Secure(s.api.HandleAppInfo))
			r.Get("/sites", s.api.Secure(s.api.HandleGetSites))
			r.Post("/sites", s.api.Secure(s.api.HandleSaveSites))
			r.Get("/sites/users/{siteName}", s.api.Secure((s.api.HandleGetUsersForSite)))
		})
		// the SPA
		serveStaticDir(r, "/ui", http.Dir(filepath.Join(s.basePath, "./assets/ui")))

		// swagger
		serveStaticDir(r, "/swagger", http.Dir(filepath.Join(s.basePath, "./assets/swagger")))
	})

	r.Get("/", http.RedirectHandler("/ui", http.StatusMovedPermanently).ServeHTTP)
	s.router = r
}

// --------------------------------------------------------------------------
// internal logic / helpers
// --------------------------------------------------------------------------

func serveStaticDir(r chi.Router, public string, static http.Dir) {
	if strings.ContainsAny(public, "{}*") {
		panic("FileServer does not permit URL parameters.")
	}

	root, _ := filepath.Abs(string(static))
	if _, err := os.Stat(root); os.IsNotExist(err) {
		panic("Static Documents Directory Not Found")
	}

	fs := http.StripPrefix(public, http.FileServer(http.Dir(root)))

	r.Get(public+"*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := strings.Replace(r.RequestURI, public, "", 1)
		// if the file contains URL params, remove everything after ?
		if strings.Contains(file, "?") {
			parts := strings.Split(file, "?")
			if len(parts) == 2 {
				file = parts[0] // use everything before the ?
			}
		}
		if _, err := os.Stat(root + file); os.IsNotExist(err) {
			http.ServeFile(w, r, path.Join(root, "index.html"))
			return
		}
		fs.ServeHTTP(w, r)
	}))
}

func serveStaticFile(r chi.Router, path, filepath string) {
	if path == "" {
		panic("no path for fileServer defined!")
	}
	if strings.ContainsAny(path, "{}*") {
		panic("fileServer does not permit URL parameters.")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath)
	})

	r.Get(path, handler)
	r.Options(path, handler)
}
