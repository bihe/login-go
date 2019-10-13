package core

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
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
// Error handling middleware
// --------------------------------------------------------------------------

// ApplicationErrorReporter is a middleware to handle errors centrally
func ApplicationErrorReporter(cookie CookieSettings) gin.HandlerFunc {
	return errorReporter(cookie, gin.ErrorTypeAny)
}

func errorReporter(cookie CookieSettings, errType gin.ErrorType) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Skip if no errors
		if c.Errors.Last() == nil {
			return
		}

		detectedErrors := c.Errors.ByType(errType)
		log.Debugf("will handle application errors!")

		var e *ProblemDetail
		content := negotiateContent(c)

		if len(detectedErrors) > 0 {
			err := detectedErrors[0].Err

			// default error is the server-error
			if svrErr, ok := err.(ServerError); ok {
				e = ErrServerError(svrErr)
			} else {
				e = ErrServerError(ServerError{Err: err, Request: c.Request})
			}

			if redirect, ok := err.(RedirectError); ok {
				e = ErrRedirectError(redirect)
				switch content {
				case HTML:
					SetCookie(FlashKeyError, e.Detail, CookieDefaultExp, cookie, c)
					c.Redirect(http.StatusTemporaryRedirect, redirect.URL)
					break
				default:
					status := http.StatusTemporaryRedirect
					if e.Status > 0 {
						status = e.Status
					}
					c.JSON(status, e)
					break
				}
				return
			}

			if notfound, ok := err.(NotFoundError); ok {
				e = ErrNotFound(notfound)
			}

			if badrequest, ok := err.(BadRequestError); ok {
				e = ErrBadRequest(badrequest)
			}

			if security, ok := err.(SecurityError); ok {
				e = ErrSecurityError(security)
			}

			switch content {
			case HTML:
				SetCookie(FlashKeyError, e.Detail, CookieDefaultExp, cookie, c)
				c.Redirect(http.StatusTemporaryRedirect, ErrorPath)
				break
			default:
				status := http.StatusTemporaryRedirect
				if e.Status > 0 {
					status = e.Status
				}
				c.JSON(status, e)
				break
			}
			c.Abort()
		}
	}
}

func negotiateContent(c *gin.Context) content {
	header := c.Request.Header.Get("Accept")
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
