package api

import (
	"fmt"

	"github.com/bihe/login-go/api/appinfo"
	"github.com/bihe/login-go/api/authoidc"
	"github.com/bihe/login-go/core"
	"github.com/bihe/login-go/persistence"
	"github.com/bihe/login-go/security"
	"github.com/gin-gonic/gin"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
)

// RegisterRoutes defines the routes of the available handlers
func RegisterRoutes(r *gin.Engine, config core.Configuration, version core.VersionInfo, con persistence.Connection) {
	store := cookie.NewStore([]byte(config.Session.Secret))
	r.Use(sessions.Sessions(config.Session.CookieName, store))

	// serving static content
	r.StaticFile("/favicon.ico", "./assets/favicon.ico")
	r.Static("/assets", "./assets")

	// templates
	r.LoadHTMLFiles("templates/error.tmpl")
	repo, err := persistence.NewRepository(con)
	if err != nil {
		panic(fmt.Sprintf("could not create a repository: %v", err))
	}

	// open-ID-connect
	oidcH := authoidc.NewHandler(version, config.OIDC, config.Sec, repo)
	r.GET("/oidc", oidcH.GetRedirect)
	r.GET("/signin-oidc", oidcH.Signin)
	r.GET("/error", oidcH.Error)

	r.Use(security.JWTMiddleware(security.JwtOptions{
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
	}))

	// the SPA ui
	r.Static("/ui", "./ui")

	// the API
	api := r.Group("/api/v1")

	aih := &appinfo.Handler{VersionInfo: version}
	api.GET("/appinfo", aih.GetAppInfo)
}
