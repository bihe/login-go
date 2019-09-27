package api

import (
	"github.com/bihe/login-go/api/appinfo"
	"github.com/bihe/login-go/api/authoidc"
	"github.com/bihe/login-go/core"
	"github.com/gin-gonic/gin"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
)

// RegisterRoutes defines the routes of the available handlers
func RegisterRoutes(r *gin.Engine, config core.Configuration, version core.VersionInfo) (err error) {
	store := cookie.NewStore([]byte(config.Session.Secret))
	r.Use(sessions.Sessions(config.Session.CookieName, store))

	// serving static content
	r.Static("/ui", "./ui")
	r.StaticFile("/favicon.ico", "./assets/favicon.ico")
	r.Static("/assets", "./assets")

	// oidc handling
	r.LoadHTMLFiles("templates/error.tmpl")
	oidcH := authoidc.NewHandler(version, config.OIDC)
	r.GET("/oidc", oidcH.GetRedirect)
	r.GET("/signin-oidc", oidcH.Signin)
	r.GET("/error", oidcH.Error)

	// the API
	api := r.Group("/api/v1")

	aih := &appinfo.Handler{VersionInfo: version}
	api.GET("/appinfo", aih.GetAppInfo)

	return nil
}
