package api

import (
	"fmt"

	"github.com/bihe/login-go/api/appinfo"
	"github.com/bihe/login-go/api/authoidc"
	"github.com/bihe/login-go/core"
	"github.com/bihe/login-go/persistence"
	"github.com/bihe/login-go/security"
	"github.com/gin-gonic/gin"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "github.com/bihe/login-go/docs" // make generated swagger doc available
)

// RegisterRoutes defines the routes of the available handlers
func RegisterRoutes(r *gin.Engine, config core.Configuration, version core.VersionInfo, con persistence.Connection) {
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
	oidcH := authoidc.NewHandler(version, config.OIDC, config.Sec, core.CookieSettings{
		Path:   config.AppCookies.Path,
		Domain: config.AppCookies.Domain,
		Secure: config.AppCookies.Secure,
		Prefix: config.AppCookies.Prefix,
	}, repo)
	r.GET("/oidc", oidcH.GetRedirect)
	r.GET("/signin-oidc", oidcH.Signin)
	r.GET("/error", oidcH.Error)
	r.GET("/auth/flow", oidcH.AuthFlow)

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

	// logout has to be "after" the JWT middleware
	r.GET("/logout", oidcH.Logout)

	// swagger doc
	url := ginSwagger.URL("/swagger/doc.json")
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, url))

	// the SPA ui
	r.Static("/ui", "./ui")

	// the API
	api := r.Group("/api/v1")
	aih := &appinfo.Handler{VersionInfo: version}
	api.GET("/appinfo", aih.GetAppInfo)
}
