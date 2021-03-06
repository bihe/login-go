// Package server defines the HTTP server and performs the setup for the API
package server

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	_ "github.com/go-sql-driver/mysql" // import the mysql driver

	"github.com/bihe/commons-go/cookies"
	"github.com/bihe/commons-go/errors"
	"github.com/bihe/commons-go/handler"
	"github.com/bihe/commons-go/security"
	"github.com/bihe/login-go/internal"
	"github.com/bihe/login-go/internal/config"
	"github.com/bihe/login-go/internal/persistence"

	"github.com/bihe/login-go/internal/api"

	per "github.com/bihe/commons-go/persistence"
)

// --------------------------------------------------------------------------
// internal logic to setup the server
// --------------------------------------------------------------------------

// Server struct defines the basic layout of a HTTP API server
type Server struct {
	basePath       string
	cookieSettings cookies.Settings
	jwtOpts        security.JwtOptions
	router         chi.Router
	api            api.Login
	appInfoAPI     *handler.AppInfoHandler
	environment    string
	logConfig      config.LogConfig
	cors           config.CorsSettings
}

// Create instantiates a new Server instance
func Create(basePath string, config config.AppConfig, version internal.VersionInfo, environment string) *Server {
	base, err := filepath.Abs(basePath)
	if err != nil {
		panic(fmt.Sprintf("cannot resolve basepath '%s', %v", basePath, err))
	}
	con := per.NewConn(config.DB.ConnStr)
	repo, err := persistence.NewRepository(con)
	if err != nil {
		panic(fmt.Sprintf("could not create a repository: %v", err))
	}

	env := config.Environment
	if environment != "" {
		env = environment
	}

	jwtOpts := security.JwtOptions{
		JwtSecret:  config.Sec.JwtSecret,
		JwtIssuer:  config.Sec.JwtIssuer,
		CookieName: config.Sec.CookieName,
		RequiredClaim: security.Claim{
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
	errorReporter := &errors.ErrorReporter{
		CookieSettings: cookieSettings,
		ErrorPath:      "/error",
	}
	baseHandler := handler.Handler{
		ErrRep: errorReporter,
	}

	appInfo := &handler.AppInfoHandler{
		Handler: baseHandler,
		Version: version.Version,
		Build:   version.Build,
	}

	srv := Server{
		basePath:       base,
		cookieSettings: cookieSettings,
		jwtOpts:        jwtOpts,

		environment: env,
		logConfig:   config.Log,
		cors:        config.Cors,
		api:         api.New(base, baseHandler, cookieSettings, version, config.OIDC, config.Sec, repo),
		appInfoAPI:  appInfo,
	}
	srv.routes()
	return &srv
}

// ServeHTTP turns the server into a http.Handler
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// use the go-chi logger middleware and redirect request logging to a file
func (s *Server) setupRequestLogging() {

	if s.environment != "Development" {
		var file *os.File
		file, err := os.OpenFile(s.logConfig.RequestPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			panic(fmt.Sprintf("cannot use filepath '%s' as a logfile: %v", s.logConfig.RequestPath, err))
		}
		middleware.DefaultLogger = middleware.RequestLogger(&middleware.DefaultLogFormatter{
			Logger:  log.New(file, "", log.LstdFlags),
			NoColor: true,
		})
	}
}
