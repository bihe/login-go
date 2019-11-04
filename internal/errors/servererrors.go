package errors

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bihe/login-go/internal/config"
	"github.com/bihe/login-go/internal/cookies"
	"github.com/markusthoemmes/goautoneg"

	log "github.com/sirupsen/logrus"
)

type content int

const (
	// TEXT content-type requested by client
	TEXT content = iota
	// JSON content-type requested by client
	JSON
	// HTML content-type requested by cleint
	HTML
)

// --------------------------------------------------------------------------
// Error responses adhering to https://tools.ietf.org/html/rfc7807
// --------------------------------------------------------------------------

// ProblemDetail combines the fields defined in RFC7807
//
// "Note that both "type" and "instance" accept relative URIs; this means
// that they must be resolved relative to the document's base URI"
type ProblemDetail struct {
	// Type is a URI reference [RFC3986] that identifies the
	// problem type.  This specification encourages that, when
	// dereferenced, it provide human-readable documentation for the problem
	Type string `json:"type"`
	// Title is a short, human-readable summary of the problem type
	Title string `json:"title"`
	// Status is the HTTP status code
	Status int `json:"status"`
	// Detail is a human-readable explanation specific to this occurrence of the problem
	Detail string `json:"detail,omitempty"`
	// Instance is a URI reference that identifies the specific occurrence of the problem
	Instance string `json:"instance,omitempty"`
}

// --------------------------------------------------------------------------
// Specific Errors
// --------------------------------------------------------------------------

// NotFoundError is used when a given object cannot be found
type NotFoundError struct {
	Err     error
	Request *http.Request
}

// Error implements the error interface
func (e NotFoundError) Error() string {
	return fmt.Sprintf("the object for request '%s' cannot be found: %v", e.Request.RequestURI, e.Err)
}

// BadRequestError indicates that the client request cannot be fulfilled
type BadRequestError struct {
	Err     error
	Request *http.Request
}

// Error implements the error interface
func (e BadRequestError) Error() string {
	return fmt.Sprintf("the request '%s' cannot be fulfilled because: %v", e.Request.RequestURI, e.Err)
}

// ServerError is used when an unexpected situation occurred
type ServerError struct {
	Err     error
	Request *http.Request
}

// Error implements the error interface
func (e ServerError) Error() string {
	return fmt.Sprintf("the request '%s' resulted in an unexpected error: %v", e.Request.RequestURI, e.Err)
}

// RedirectError is a specific error indicating a necessary redirect
type RedirectError struct {
	Err     error
	Request *http.Request
	Status  int
	URL     string
}

// Error implements the error interface
func (e RedirectError) Error() string {
	return fmt.Sprintf("the request '%s' resulted in a redirect to: '%s', error: %v", e.Request.RequestURI, e.URL, e.Err)
}

// SecurityError is used when something is not allowed
type SecurityError struct {
	Err     error
	Request *http.Request
}

// Error implements the error interface
func (e SecurityError) Error() string {
	return fmt.Sprintf("the request '%s' is not allowed: %v", e.Request.RequestURI, e.Err)
}

// --------------------------------------------------------------------------
// Shortcuts for commen error responses
// --------------------------------------------------------------------------

const t = "about:blank"

// ErrBadRequest returns a http.StatusBadRequest
func ErrBadRequest(err BadRequestError) *ProblemDetail {
	return &ProblemDetail{
		Type:   t,
		Title:  "the request cannot be fulfilled",
		Status: http.StatusBadRequest,
		Detail: err.Error(),
	}
}

// ErrNotFound returns a http.StatusNotFound
func ErrNotFound(err NotFoundError) *ProblemDetail {
	return &ProblemDetail{
		Type:   t,
		Title:  "object cannot be found",
		Status: http.StatusNotFound,
		Detail: err.Error(),
	}
}

// ErrServerError returns a http.StatusInternalServerError
func ErrServerError(err ServerError) *ProblemDetail {
	return &ProblemDetail{
		Type:   t,
		Title:  "cannot service the request",
		Status: http.StatusInternalServerError,
		Detail: err.Error(),
	}
}

// ErrSecurityError returns a http.StatusForbidden
func ErrSecurityError(err SecurityError) *ProblemDetail {
	return &ProblemDetail{
		Type:   t,
		Title:  "operation is not allowed",
		Status: http.StatusForbidden,
		Detail: err.Error(),
	}
}

// ErrRedirectError returns a http.StatusTemporaryRedirect
func ErrRedirectError(err RedirectError) *ProblemDetail {
	return &ProblemDetail{
		Type:     t,
		Title:    "a redirect is necessary",
		Status:   err.Status,
		Detail:   err.Error(),
		Instance: err.URL,
	}
}

// --------------------------------------------------------------------------
// Error handling
// --------------------------------------------------------------------------

// ErrorReporter handles sending of errors to clients respecting the context (Accept header)
type ErrorReporter struct {
	cookie *cookies.AppCookie
}

// NewReporter creates a new instance of the ErrorReporter type
func NewReporter(c cookies.Settings) *ErrorReporter {
	r := ErrorReporter{cookie: cookies.NewAppCookie(c)}
	return &r
}

// Negotiate respects content-types, sets the status code and returns error information
func (e *ErrorReporter) Negotiate(w http.ResponseWriter, r *http.Request, err error) {
	var pd *ProblemDetail
	content := negotiateContent(r)

	// default error is the server-error
	if svrErr, ok := err.(ServerError); ok {
		pd = ErrServerError(svrErr)
	} else {
		pd = ErrServerError(ServerError{Err: err, Request: r})
	}

	if redirect, ok := err.(RedirectError); ok {
		pd = ErrRedirectError(redirect)
		switch content {
		case HTML:
			e.cookie.Set(config.FlashKeyError, pd.Detail, config.CookieDefaultExp, w)
			http.Redirect(w, r, redirect.URL, http.StatusTemporaryRedirect)
			break
		default:
			status := http.StatusTemporaryRedirect
			if pd.Status > 0 {
				status = pd.Status
			}
			writeProblemJSON(w, status, pd)
			break
		}
		return
	}

	if notfound, ok := err.(NotFoundError); ok {
		pd = ErrNotFound(notfound)
	}

	if badrequest, ok := err.(BadRequestError); ok {
		pd = ErrBadRequest(badrequest)
	}

	if security, ok := err.(SecurityError); ok {
		pd = ErrSecurityError(security)
	}

	switch content {
	case HTML:
		e.cookie.Set(config.FlashKeyError, pd.Detail, config.CookieDefaultExp, w)
		http.Redirect(w, r, config.ErrorPath, http.StatusTemporaryRedirect)
		break
	default:
		status := http.StatusTemporaryRedirect
		if pd.Status > 0 {
			status = pd.Status
		}
		writeProblemJSON(w, status, pd)
		break
	}
}

func writeProblemJSON(w http.ResponseWriter, code int, pd *ProblemDetail) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(code)
	b, err := json.Marshal(pd)
	if err != nil {
		log.WithField("func", "writeProblemJSON").Errorf("could not marshal json %v\n", err)
	}
	_, err = w.Write(b)
	if err != nil {
		log.WithField("func", "writeProblemJSON").Errorf("could not write bytes using http.ResponseWriter: %v\n", err)
	}
}

func negotiateContent(r *http.Request) content {
	header := r.Header.Get("Accept")
	if header == "" {
		return JSON // default
	}

	accept := goautoneg.ParseAccept(header)
	if len(accept) == 0 {
		return JSON // default
	}

	// use the first element, because this has the highest priority
	switch accept[0].SubType {
	case "html":
		return HTML
	case "json":
		return JSON
	case "plain":
		return TEXT
	default:
		return JSON
	}
}
