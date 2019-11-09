package server

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/bihe/login-go/internal"
	"github.com/bihe/login-go/internal/config"
	"github.com/bihe/login-go/internal/cookies"
	"github.com/bihe/login-go/internal/persistence"
	"github.com/bihe/login-go/internal/security"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"

	per "github.com/bihe/commons-go/persistence"
	sec "github.com/bihe/commons-go/security"
)

// NewRouter instantiates a new router type
func NewRouter(basePath string, config config.AppConfig, version internal.VersionInfo, con per.Connection) chi.Router {
	r := chi.NewRouter()

	base, err := filepath.Abs(basePath)
	if err != nil {
		panic(fmt.Sprintf("cannot resolve basepath '%s', %v", basePath, err))
	}

	// A good base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.DefaultCompress)
	r.Use(middleware.RedirectSlashes)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// serving static content
	serveStaticFile(r, "/favicon.ico", filepath.Join(base, "./assets/favicon.ico"))
	serveStaticDir(r, "/assets", http.Dir(filepath.Join(base, "./assets")))

	// configure JWT authentication and use JWT middleware
	jwtOpts := security.JwtOptions{
		JwtSecret:  config.Sec.JwtSecret,
		JwtIssuer:  config.Sec.JwtIssuer,
		CookieName: config.Sec.CookieName,
		RequiredClaim: sec.Claim{
			Name:  config.Sec.Claim.Name,
			URL:   config.Sec.Claim.URL,
			Roles: config.Sec.Claim.Roles,
		},
		RedirectURL:   config.Sec.LoginRedirect,
		CacheDuration: config.Sec.CacheDuration,
	}
	cookieSettings := cookies.Settings{
		Path:   config.AppCookies.Path,
		Domain: config.AppCookies.Domain,
		Secure: config.AppCookies.Secure,
		Prefix: config.AppCookies.Prefix,
	}

	repo, err := persistence.NewRepository(con)
	if err != nil {
		panic(fmt.Sprintf("could not create a repository: %v", err))
	}
	api := NewAPI(base, cookieSettings, version, config.OIDC, config.Sec, repo)

	r.Get("/error", api.call(api.handleError))
	r.Get("/oidc", api.call(api.handleOIDCRedirect))
	r.Get("/signin-oidc", api.call(api.handleOIDCLogin))
	r.Get("/auth/flow", api.call(api.handleAuthFlow))

	// this group "indicates" that all routes within this group use the JWT authentication
	r.Group(func(r chi.Router) {
		// authenticate and authorize users via JWT
		r.Use(security.NewJwtMiddleware(jwtOpts, cookieSettings).JwtContext)

		r.Get("/logout", api.secure(api.handleLogout))

		// group API methods together
		r.Route("/api/v1", func(r chi.Router) {
			r.Get("/appinfo", api.secure(api.handleAppInfoGet))
		})

		// the SPA
		serveStaticDir(r, "/ui", http.Dir(filepath.Join(basePath, "./assets/ui")))
	})

	return r
}

func serveStaticDir(r chi.Router, path string, root http.FileSystem) {
	if path == "" {
		panic("no path for fileServer defined!")
	}
	if strings.ContainsAny(path, "{}*") {
		panic("fileServer does not permit URL parameters.")
	}
	fs := http.StripPrefix(path, http.FileServer(root))
	// add a slash to the end of the path
	if path != "/" && path[len(path)-1] != '/' {
		path += "/"
	}
	path += "*"
	r.Get(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
