package sites

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/bihe/login-go/core"
	"github.com/bihe/login-go/persistence"
	"github.com/bihe/login-go/security"
	"github.com/gin-gonic/gin"

	log "github.com/sirupsen/logrus"
)

// --------------------------------------------------------------------------
// models
// --------------------------------------------------------------------------

// UserInfo holds information about the current user and sites
type UserInfo struct {
	User     string     `json:"user"`
	Editable bool       `json:"editable"`
	Sites    []SiteInfo `json:"userSites"`
}

// SiteInfo holds data of a site
type SiteInfo struct {
	Name string   `json:"name"`
	URL  string   `json:"url"`
	Perm []string `json:"permissions"`
}

// --------------------------------------------------------------------------
// the Handler
// --------------------------------------------------------------------------

// Handler defines the methods for the sites api
type Handler struct {
	site     string
	editRole string
	repo     persistence.Repository
}

// NewHandler returns a pointer to a handler
func NewHandler(siteName, editRole string, repo persistence.Repository) *Handler {
	return &Handler{
		editRole: editRole,
		repo:     repo,
	}
}

// GetSites godoc
// @Summary sites of current user
// @Description returns all the sites of the current loged-in user
// @Tags sites
// @Produce  json
// @Success 200 {object} sites.UserInfo
// @Failure 401 {object} core.ProblemDetail
// @Failure 403 {object} core.ProblemDetail
// @Failure 404 {object} core.ProblemDetail
// @Router /api/v1/sites [get]
func (h *Handler) GetSites(c *gin.Context) {
	user := c.MustGet(core.User).(security.User)
	sites, err := h.repo.GetSitesByUser(user.Email)
	if err != nil {
		log.Warnf("cannot get sites of current user '%s', %v", user.Email, err)
		c.Error(core.NotFoundError{Err: fmt.Errorf("no sites for given user '%s'", user.Email), Request: c.Request})
		return
	}

	u := UserInfo{
		User: user.Email,
	}
	u.Editable = hasRole(h.editRole, user.Roles)
	for _, s := range sites {
		parts := strings.Split(s.PermList, ";")
		u.Sites = append(u.Sites, SiteInfo{
			Name: s.Name,
			URL:  s.URL,
			Perm: parts,
		})
	}

	c.JSON(http.StatusOK, u)
}

func hasRole(want string, has []string) bool {
	if has != nil {
		for _, p := range has {
			if p == want {
				return true
			}
		}
	}
	return false
}
