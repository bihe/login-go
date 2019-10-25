package api

import (
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/bihe/login-go/api/appinfo"
	"github.com/bihe/login-go/api/authoidc"
	"github.com/bihe/login-go/api/sites"
	"github.com/bihe/login-go/core"
	"github.com/bihe/login-go/persistence"
	"github.com/bihe/login-go/security"
	"github.com/gin-gonic/gin"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "github.com/bihe/login-go/docs" // make generated swagger doc available

	per "github.com/bihe/commons-go/persistence"
	sec "github.com/bihe/commons-go/security"
)

// RegisterRoutes defines the routes of the available handlers
func RegisterRoutes(r *gin.Engine, config core.Configuration, version core.VersionInfo, con per.Connection) {
	// application cookie settings
	// used for client-sessions-like messages and interaction
	cookie := core.CookieSettings{
		Path:   config.AppCookies.Path,
		Domain: config.AppCookies.Domain,
		Secure: config.AppCookies.Secure,
		Prefix: config.AppCookies.Prefix,
	}

	// kind of central error handling (@see labstack echo!)
	r.Use(core.ApplicationErrorReporter(cookie))

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
	oidcH := authoidc.NewHandler(version, config.OIDC, config.Sec, cookie, repo)
	r.GET("/oidc", oidcH.GetRedirect)
	r.GET("/signin-oidc", oidcH.Signin)
	r.GET("/error", oidcH.Error)
	r.GET("/auth/flow", oidcH.AuthFlow)

	r.Use(security.JWTMiddleware(security.JwtOptions{
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
	}))

	// logout has to be "after" the JWT middleware
	r.GET("/logout", security.W(oidcH.Logout))

	// swagger doc
	url := ginSwagger.URL("/swagger/doc.json")
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, url))

	// the API
	api := r.Group("/api/v1")

	// appinfo
	aih := &appinfo.Handler{VersionInfo: version}
	api.GET("/appinfo", security.W(aih.GetAppInfo))

	// sites
	sh := sites.NewHandler(config.Sec.Claim.Roles[0], repo) // the first role of the claims is used as the "edit-role"!
	api.GET("/sites", security.W(sh.GetSites))
	api.POST("/sites", security.W(sh.SaveSites))

	// the SPA ui
	r.Static("/ui", "./ui")

	// fallback for unresolved SPA paths
	// copied from: https://github.com/go-ggz/ggz/blob/8e98db8d743a66bf2f3ea8dbb8c48686abc150a5/web/index.go
	r.NoRoute(func(c *gin.Context) {
		file, _ := ioutil.ReadFile("ui/index.html")
		etag := fmt.Sprintf("%x", md5.Sum(file))
		c.Header("ETag", etag)
		c.Header("Cache-Control", "no-cache")

		if match := c.GetHeader("If-None-Match"); match != "" {
			if strings.Contains(match, etag) {
				c.Status(http.StatusNotModified)
				return
			}
		}

		c.Data(http.StatusOK, "text/html; charset=utf-8", file)
	})

}
