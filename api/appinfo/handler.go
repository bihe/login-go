package appinfo

import (
	"fmt"
	"net/http"

	"github.com/bihe/login-go/core"
	"github.com/bihe/login-go/security"
	"github.com/gin-gonic/gin"

	log "github.com/sirupsen/logrus"
)

// Meta specifies application metadata
type Meta struct {
	Runtime string `json:"runtime"`
	Version string `json:"version"`
	UserInfo
}

// UserInfo provides information about the currently loged-in user
type UserInfo struct {
	Email       string   `json:"email"`
	DisplayName string   `json:"displayName"`
	Roles       []string `json:"roles"`
}

// Handler provides methods for application metadata
type Handler struct {
	core.VersionInfo
}

// GetAppInfo returns application metadata in JSON format
func (h *Handler) GetAppInfo(c *gin.Context) {
	log.Debugf("return the application metadata info")
	user := c.MustGet(core.User).(security.User)

	info := Meta{
		Runtime: h.Runtime,
		Version: fmt.Sprintf("%s-%s", h.Version, h.Build),
		UserInfo: UserInfo{
			Email:       user.Email,
			DisplayName: user.DisplayName,
			Roles:       user.Roles,
		},
	}
	c.JSON(http.StatusOK, info)
}
