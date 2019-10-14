package sites

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bihe/login-go/core"
	"github.com/bihe/login-go/persistence"
	"github.com/bihe/login-go/security"

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
	editRole string
	repo     persistence.Repository
}

// NewHandler returns a pointer to a handler
func NewHandler(editRole string, repo persistence.Repository) *Handler {
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
func (h *Handler) GetSites(a *security.AppContext) {
	user := a.User()
	sites, err := h.repo.GetSitesByUser(user.Email)
	if err != nil {
		log.Warnf("cannot get sites of current user '%s', %v", user.Email, err)
		a.Error(core.NotFoundError{Err: fmt.Errorf("no sites for given user '%s'", user.Email), Request: a.Request})
		return
	}

	u := UserInfo{
		User: user.Username,
	}
	u.Editable = a.HasRole(h.editRole)
	for _, s := range sites {
		parts := strings.Split(s.PermList, ";")
		u.Sites = append(u.Sites, SiteInfo{
			Name: s.Name,
			URL:  s.URL,
			Perm: parts,
		})
	}

	a.JSON(http.StatusOK, u)
}

// SaveSites godoc
// @Summary stores the given sites
// @Description takes a list of sites and stores the supplied sites for the user
// @Tags sites
// @Produce  json
// @Success 201 {string} sites.UserInfo
// @Failure 400 {object} core.ProblemDetail
// @Failure 401 {object} core.ProblemDetail
// @Failure 403 {object} core.ProblemDetail
// @Failure 500 {object} core.ProblemDetail
// @Router /api/v1/sites [post]
func (h *Handler) SaveSites(a *security.AppContext) {
	user := a.User()
	if !a.HasRole(h.editRole) {
		log.Warnf("user '%s' tried to save but does not have required permissions", user.Email)
		a.Error(core.SecurityError{Err: fmt.Errorf("user '%s' is not allowed to perform this action", user.Email), Request: a.Request})
		return
	}

	// payload is an array of SiteInfo
	var (
		payload []SiteInfo
		err     error
	)
	if err = a.BindJSON(&payload); err != nil {
		a.Error(core.BadRequestError{Err: fmt.Errorf("could not use supplied payload: %v", err), Request: a.Request})
		a.Abort()
		return
	}

	var sites []persistence.UserSite
	for _, p := range payload {
		sites = append(sites, persistence.UserSite{
			Name:     p.Name,
			URL:      p.URL,
			PermList: strings.Join(p.Perm, ";"),
			User:     user.Email,
			Created:  time.Now().UTC(),
		})
	}
	err = h.repo.StoreSiteForUser(user.Email, sites, persistence.Atomic{})
	if err != nil {
		log.Errorf("could not save sites of user '%s': %v", user.Email, err)
		a.Error(core.ServerError{Err: fmt.Errorf("could not save payload: %v", err), Request: a.Request})
		a.Abort()
		return
	}

	a.Status(http.StatusCreated)
}
