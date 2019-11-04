package server

import (
	"fmt"
	"net/http"

	sec "github.com/bihe/commons-go/security"
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

// handleAppInfoGet godoc
// @Summary provides information about the application
// @Description meta-data of the application including authenticated user and version
// @Tags appinfo
// @Produce  json
// @Success 200 {object} appinfo.Meta
// @Failure 401 {object} errors.ProblemDetail
// @Failure 403 {object} errors.ProblemDetail
// @Router /api/v1/appinfo [get]
func (a *API) handleAppInfoGet(user sec.User, w http.ResponseWriter, r *http.Request) error {
	log.WithField("func", "appinfo.Get").Debugf("return the application metadata info")
	info := Meta{
		Runtime: a.Runtime,
		Version: fmt.Sprintf("%s-%s", a.Version, a.Build),
		UserInfo: UserInfo{
			Email:       user.Email,
			DisplayName: user.DisplayName,
			Roles:       user.Roles,
		},
	}
	a.respond(w, r, http.StatusOK, info)
	return nil
}
