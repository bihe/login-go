package appinfo

import (
	"fmt"
	"net/http"

	"github.com/bihe/login-go/core"
	"github.com/bihe/login-go/security"

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

// GetAppInfo godoc
// @Summary provides information about the application
// @Description meta-data of the application including authenticated user and version
// @Tags appinfo
// @Produce  json
// @Success 200 {object} appinfo.Meta
// @Failure 401 {object} core.ProblemDetail
// @Failure 403 {object} core.ProblemDetail
// @Router /api/v1/appinfo [get]
func (h *Handler) GetAppInfo(a *security.AppContext) {
	log.Debugf("return the application metadata info")
	user := a.User()
	info := Meta{
		Runtime: h.Runtime,
		Version: fmt.Sprintf("%s-%s", h.Version, h.Build),
		UserInfo: UserInfo{
			Email:       user.Email,
			DisplayName: user.DisplayName,
			Roles:       user.Roles,
		},
	}
	a.JSON(http.StatusOK, info)
}
