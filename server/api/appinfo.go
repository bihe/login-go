package api

import (
	"fmt"
	"net/http"

	sec "github.com/bihe/commons-go/security"
	log "github.com/sirupsen/logrus"
)

// HandleAppInfo godoc
// @Summary provides information about the application
// @Description meta-data of the application including authenticated user and version
// @Tags appinfo
// @Produce  json
// @Success 200 {object} api.Meta
// @Failure 401 {object} errors.ProblemDetail
// @Failure 403 {object} errors.ProblemDetail
// @Router /api/v1/appinfo [get]
func (a *handlers) HandleAppInfo(user sec.User, w http.ResponseWriter, r *http.Request) error {
	log.WithField("func", "server.HandleAppInfo").Debugf("return the application metadata info")
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
