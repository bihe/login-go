package appinfo

import (
	"fmt"
	"net/http"

	"github.com/bihe/login-go/core"
	"github.com/gin-gonic/gin"

	log "github.com/sirupsen/logrus"
)

// Meta specifies application metadata
type Meta struct {
	Runtime string `json:"runtime"`
	Version string `json:"version"`
}

// Handler provides methods for application metadata
type Handler struct {
	core.VersionInfo
}

// GetAppInfo returns application metadata in JSON format
func (h *Handler) GetAppInfo(c *gin.Context) {
	log.Debugf("return the application metadata info")

	info := Meta{
		Runtime: h.Runtime,
		Version: fmt.Sprintf("%s-%s", h.Version, h.Build),
	}
	c.JSON(http.StatusOK, info)
}
