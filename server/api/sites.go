package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bihe/commons-go/errors"
	"github.com/bihe/commons-go/security"
	"github.com/bihe/login-go/internal/persistence"

	per "github.com/bihe/commons-go/persistence"
	log "github.com/sirupsen/logrus"
)

// HandleGetSites godoc
// @Summary sites of current user
// @Description returns all the sites of the current loged-in user
// @Tags sites
// @Produce  json
// @Success 200 {object} api.UserSites
// @Failure 401 {object} errors.ProblemDetail
// @Failure 403 {object} errors.ProblemDetail
// @Failure 404 {object} errors.ProblemDetail
// @Router /api/v1/sites [get]
func (a *loginAPI) HandleGetSites(user security.User, w http.ResponseWriter, r *http.Request) error {
	sites, err := a.repo.GetSitesByUser(user.Email)
	if err != nil {
		log.Warnf("cannot get sites of current user '%s', %v", user.Email, err)
		return errors.NotFoundError{Err: fmt.Errorf("no sites for given user '%s'", user.Email), Request: r}
	}

	u := UserSites{
		User: user.Username,
	}
	u.Editable = a.hasRole(user, a.editRole)
	for _, s := range sites {
		parts := strings.Split(s.PermList, ";")
		u.Sites = append(u.Sites, SiteInfo{
			Name: s.Name,
			URL:  s.URL,
			Perm: parts,
		})
	}
	a.respond(w, r, http.StatusOK, u)
	return nil
}

// HandleSaveSites godoc
// @Summary stores the given sites
// @Description takes a list of sites and stores the supplied sites for the user
// @Tags sites
// @Produce  json
// @Success 201
// @Failure 400 {object} errors.ProblemDetail
// @Failure 401 {object} errors.ProblemDetail
// @Failure 403 {object} errors.ProblemDetail
// @Failure 500 {object} errors.ProblemDetail
// @Router /api/v1/sites [post]
func (a *loginAPI) HandleSaveSites(user security.User, w http.ResponseWriter, r *http.Request) error {
	if !a.hasRole(user, a.editRole) {
		log.Warnf("user '%s' tried to save but does not have required permissions", user.Email)
		return errors.SecurityError{Err: fmt.Errorf("user '%s' is not allowed to perform this action", user.Email), Request: r}
	}

	// payload is an array of SiteInfo
	var (
		payload []SiteInfo
		err     error
	)
	if err = a.decode(w, r, &payload); err != nil {
		return errors.BadRequestError{Err: fmt.Errorf("could not use supplied payload: %v", err), Request: r}
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
	err = a.repo.StoreSiteForUser(user.Email, sites, per.Atomic{})
	if err != nil {
		log.Errorf("could not save sites of user '%s': %v", user.Email, err)
		return errors.ServerError{Err: fmt.Errorf("could not save payload: %v", err), Request: r}
	}
	w.WriteHeader(http.StatusCreated)
	return nil
}
