package server

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/bihe/login-go/internal/cookies"
	"github.com/bihe/login-go/internal/security"
	"github.com/bihe/login-go/server/api"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"

	_ "github.com/bihe/login-go/docs" // import the swagger documentation
	httpSwagger "github.com/swaggo/http-swagger"
)

// NewRouter instantiates a new router type
func NewRouter(basePath string, a api.API, cookieSettings cookies.Settings, jwtOpts security.JwtOptions) chi.Router {
	r := chi.NewRouter()

	// A good base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.DefaultCompress)
	r.Use(middleware.RedirectSlashes)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// serving static content
	serveStaticFile(r, "/favicon.ico", filepath.Join(basePath, "./assets/favicon.ico"))
	serveStaticDir(r, "/assets", http.Dir(filepath.Join(basePath, "./assets")))

	r.Get("/error", a.Call(a.HandleError))
	r.Get("/oidc", a.Call(a.HandleOIDCRedirect))
	r.Get("/signin-oidc", a.Call(a.HandleOIDCLogin))
	r.Get("/auth/flow", a.Call(a.HandleAuthFlow))

	// this group "indicates" that all routes within this group use the JWT authentication
	r.Group(func(r chi.Router) {
		// authenticate and authorize users via JWT
		r.Use(security.NewJwtMiddleware(jwtOpts, cookieSettings).JwtContext)

		r.Get("/logout", a.Secure(a.HandleLogout))

		// group API methods together
		r.Route("/api/v1", func(r chi.Router) {
			r.Get("/appinfo", a.Secure(a.HandleAppInfo))
			r.Get("/sites", a.Secure(a.HandleGetSites))
			r.Post("/sites", a.Secure(a.HandleSaveSites))
		})
		// the SPA
		serveStaticDir(r, "/ui", http.Dir(filepath.Join(basePath, "./assets/ui")))

		// swagger
		r.Get("/swagger/*", httpSwagger.Handler(
			httpSwagger.URL("/swagger/doc.json"), //The url pointing to API definition"
		))
	})

	r.Get("/", http.RedirectHandler("/ui", http.StatusMovedPermanently).ServeHTTP)

	return r
}

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
		if strings.Index(file, "?") > -1 {
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
