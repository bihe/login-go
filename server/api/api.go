// Package api implements the HTTP API of the login-application
package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bihe/commons-go/cookies"
	"github.com/bihe/commons-go/errors"
	"github.com/bihe/commons-go/security"
	"github.com/bihe/login-go/internal"
	"github.com/bihe/login-go/internal/config"
	"github.com/bihe/login-go/internal/persistence"
	"golang.org/x/oauth2"

	c "github.com/bihe/commons-go/config"
	log "github.com/sirupsen/logrus"
)

// --------------------------------------------------------------------------
// models
// --------------------------------------------------------------------------

// UserSites holds information about the current user and sites
type UserSites struct {
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

// UserList holds the usernames for a given site
type UserList struct {
	Count int      `json:"count"`
	Users []string `json:"users"`
}

// --------------------------------------------------------------------------
// API Interface
// --------------------------------------------------------------------------

// Login defines the HTTP handlers responding to requests
type Login interface {
	// oidc
	HandleError(w http.ResponseWriter, r *http.Request) error
	HandleOIDCRedirect(w http.ResponseWriter, r *http.Request) error
	HandleAuthFlow(w http.ResponseWriter, r *http.Request) error
	HandleOIDCRedirectFinal(w http.ResponseWriter, r *http.Request) error
	HandleOIDCLogin(w http.ResponseWriter, r *http.Request) error
	HandleLogout(user security.User, w http.ResponseWriter, r *http.Request) error

	// appinfo
	HandleAppInfo(user security.User, w http.ResponseWriter, r *http.Request) error

	// sites
	HandleGetSites(user security.User, w http.ResponseWriter, r *http.Request) error
	HandleSaveSites(user security.User, w http.ResponseWriter, r *http.Request) error
	HandleGetUsersForSite(user security.User, w http.ResponseWriter, r *http.Request) error

	// wrapper methods
	Secure(f func(user security.User, w http.ResponseWriter, r *http.Request) error) http.HandlerFunc
	Call(f func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc

	// configuration
	GetOIDCRedirectURL() string
}

var _ Login = (*loginAPI)(nil)

// loginAPI implements the handlers of the API definition
type loginAPI struct {
	internal.VersionInfo
	errRep         *errors.ErrorReporter
	cookieSettings cookies.Settings
	appCookie      *cookies.AppCookie
	basePath       string

	// oidc objects
	oauthConfig   *oauth2.Config
	oauthVerifier OIDCVerifier

	// store
	repo persistence.Repository
	// jwt logic
	jwt config.Security
	// user having this role are allowed to edit
	editRole string
}

// New creates a new instance of the API type
func New(basePath string, cs cookies.Settings, version internal.VersionInfo, oauth config.OAuthConfig, jwt config.Security, repo persistence.Repository) Login {
	c, v := NewOIDC(oauth)
	api := loginAPI{
		VersionInfo:    version,
		cookieSettings: cs,
		errRep:         errors.NewReporter(cs),
		appCookie:      cookies.NewAppCookie(cs),
		basePath:       basePath,
		oauthConfig:    c,
		oauthVerifier:  v,
		repo:           repo,
		jwt:            jwt,
		editRole:       jwt.Claim.Roles[0], // use the first role of the defined claims as the edit role
	}

	return &api
}

// Secure wraps handlers to have a common signature
// a User is retrieved from the context and a possible error from the handler function is processed
func (a *loginAPI) Secure(f func(user security.User, w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.Context().Value(c.User)
		if u == nil {
			log.WithField("func", "server.secure").Errorf("user is not available in context!")
			a.errRep.Negotiate(w, r, fmt.Errorf("user is not available in context"))
			return
		}
		user := r.Context().Value(c.User).(*security.User)
		if err := f(*user, w, r); err != nil {
			log.WithField("func", "server.secure").Errorf("error during API call %v\n", err)
			a.errRep.Negotiate(w, r, err)
			return
		}
	})
}

// Call wraps handlers to have a common signature
func (a *loginAPI) Call(f func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			log.WithField("func", "server.call").Errorf("error during API call %v\n", err)
			a.errRep.Negotiate(w, r, err)
			return
		}
	})
}

// --------------------------------------------------------------------------
// internal API helpers
// --------------------------------------------------------------------------

// respond converts data into appropriate responses for the client
// this can be JSON, Plaintext, ...
func (a *loginAPI) respond(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(code)
	if data != nil {
		err := json.NewEncoder(w).Encode(data)
		if err != nil {
			log.WithField("func", "server.respond").Errorf("could not marshal json %v\n", err)
			a.errRep.Negotiate(w, r, errors.ServerError{
				Err:     fmt.Errorf("could not marshal json %v", err),
				Request: r,
			})
			return
		}
	}
}

// decode parses supplied JSON payload
func (a *loginAPI) decode(w http.ResponseWriter, r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("no body payload available")
	}
	return json.NewDecoder(r.Body).Decode(v)
}

// hasRole checks if the given user has the given role
func (a *loginAPI) hasRole(user security.User, role string) bool {
	for _, p := range user.Roles {
		if p == role {
			return true
		}
	}
	return false
}

func query(r *http.Request, name string) string {
	keys, ok := r.URL.Query()[name]

	if !ok || len(keys[0]) < 1 {
		log.WithField("func", "server.getQuery").Debugf("Url Param '%s' is missing", name)
		return ""
	}

	return keys[0]
}
