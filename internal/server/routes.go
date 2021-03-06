package server

import (
	"net/http"
	"path/filepath"
	"time"

	"github.com/bihe/commons-go/handler"
	"github.com/bihe/commons-go/security"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/rs/cors"
)

// routes performs setup of middlewares and API handlers
func (s *Server) routes() {
	r := chi.NewRouter()

	// A good base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.DefaultCompress)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	// setup cors for single frontend
	cors := cors.New(cors.Options{
		AllowedOrigins:   s.cors.AllowedOrigins,
		AllowedMethods:   s.cors.AllowedMethods,
		AllowedHeaders:   s.cors.AllowedHeaders,
		AllowCredentials: s.cors.AllowCredentials,
		MaxAge:           s.cors.MaxAge,
	})
	r.Use(cors.Handler)

	s.setupRequestLogging()

	// serving static content
	handler.ServeStaticFile(r, "/favicon.ico", filepath.Join(s.basePath, "./web/assets/favicon.ico"))
	handler.ServeStaticDir(r, "/assets", http.Dir(filepath.Join(s.basePath, "./web/assets")))

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
			r.Get("/appinfo", s.appInfoAPI.Secure(s.appInfoAPI.HandleAppInfo))
			r.Get("/sites", s.api.Secure(s.api.HandleGetSites))
			r.Post("/sites", s.api.Secure(s.api.HandleSaveSites))
			r.Get("/sites/users/{siteName}", s.api.Secure((s.api.HandleGetUsersForSite)))
		})

		// swagger
		handler.ServeStaticDir(r, "/swagger", http.Dir(filepath.Join(s.basePath, "./web/assets/swagger")))
	})

	r.Get("/", s.api.Call(s.api.HandleError))
	s.router = r
}
