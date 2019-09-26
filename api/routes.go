package api

import (
	"github.com/bihe/login-go/api/appinfo"
	"github.com/bihe/login-go/core"
	"github.com/gin-gonic/gin"
)

// RegisterRoutes defines the routes of the available handlers
func RegisterRoutes(r *gin.Engine, config core.Configuration, version core.VersionInfo) (err error) {
	api := r.Group("/api/v1")

	aih := &appinfo.Handler{VersionInfo: version}
	api.GET("/appinfo", aih.GetAppInfo)

	return nil
}
