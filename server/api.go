package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	sec "github.com/bihe/commons-go/security"
	"github.com/bihe/login-go/internal"
	"github.com/bihe/login-go/internal/config"
	"github.com/bihe/login-go/internal/cookies"
	"github.com/bihe/login-go/internal/errors"
	log "github.com/sirupsen/logrus"
)

// API uses handlers to respond to HTTP requests
type API struct {
	internal.VersionInfo
	errRep         *errors.ErrorReporter
	cookieSettings cookies.Settings
	basePath       string
}

// NewAPI creates a new instance of the API type
func NewAPI(basePath string, cookies cookies.Settings, version internal.VersionInfo) *API {
	api := API{
		VersionInfo:    version,
		cookieSettings: cookies,
		errRep:         errors.NewReporter(cookies),
		basePath:       basePath,
	}
	return &api
}

// respond converts data into appropriate responses for the client
// this can be JSON, Plaintext, ...
func (a *API) respond(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
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

// secure wraps handlers to have a common signature
// a User is retrieved from the context and a possible error from the handler function is processed
func (a *API) secure(f func(user sec.User, w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.Context().Value(config.User)
		if u == nil {
			log.WithField("func", "server.secure").Errorf("user is not available in context!")
			a.errRep.Negotiate(w, r, fmt.Errorf("user is not available in context"))
			return
		}
		user := r.Context().Value(config.User).(*sec.User)
		if err := f(*user, w, r); err != nil {
			log.WithField("func", "server.secure").Errorf("error during API call %v\n", err)
			a.errRep.Negotiate(w, r, err)
			return
		}
	})
}

// call wraps handlers to have a common signature
func (a *API) call(f func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			log.WithField("func", "server.call").Errorf("error during API call %v\n", err)
			a.errRep.Negotiate(w, r, err)
			return
		}
	})
}
