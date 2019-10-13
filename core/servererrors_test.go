package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const errText = "error occured"

func TestErrorHandler(t *testing.T) {
	// Setup
	var (
		pd  ProblemDetail
		s   string
		rec *httptest.ResponseRecorder
	)

	errReq := httptest.NewRequest(http.MethodGet, "/", nil)
	testcases := []struct {
		Name     string
		Status   int
		Error    error
		Accept   string
		Redirect string
	}{
		{
			Name:   "NotFoundError",
			Status: http.StatusNotFound,
			Error:  NotFoundError{Err: fmt.Errorf(errText), Request: errReq},
			Accept: "application/json",
		},
		{
			Name:   "BadRequestError",
			Status: http.StatusBadRequest,
			Error:  BadRequestError{Err: fmt.Errorf(errText), Request: errReq},
			Accept: "application/json",
		},
		{
			Name:     "RedirectErrorBrowser",
			Status:   http.StatusTemporaryRedirect,
			Error:    RedirectError{Err: fmt.Errorf(errText), Request: errReq, URL: "http://redirect", Status: http.StatusTemporaryRedirect},
			Accept:   "text/html",
			Redirect: "http://redirect",
		},
		{
			Name:   "RedirectErrorBrowserJSON",
			Status: http.StatusTemporaryRedirect,
			Error:  RedirectError{Err: fmt.Errorf(errText), Request: errReq, URL: "http://redirect", Status: http.StatusTemporaryRedirect},
			Accept: "application/json",
		},
		{
			Name:   "error",
			Status: http.StatusInternalServerError,
			Error:  fmt.Errorf(errText),
			Accept: "application/json",
		},
		{
			Name:     "error.HTML",
			Status:   http.StatusTemporaryRedirect,
			Error:    fmt.Errorf(errText),
			Accept:   "text/html",
			Redirect: "/error",
		},
		{
			Name:   "security",
			Status: http.StatusForbidden,
			Error:  SecurityError{Err: fmt.Errorf(errText), Request: errReq},
			Accept: "application/json",
		},
		{
			Name:   "no-error",
			Status: http.StatusOK,
			Error:  nil,
			Accept: "application/json",
		},
	}

	gin.SetMode(gin.TestMode)

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			rec = httptest.NewRecorder()

			c, r := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			c.Request.Header.Add("Accept", tc.Accept)

			r.Use(ApplicationErrorReporter(CookieSettings{
				Path:   "/",
				Domain: "localhost",
				Secure: false,
			}))
			r.GET("/", func(c *gin.Context) {
				if tc.Error != nil {
					c.Error(tc.Error)
					return
				}
				c.Status(http.StatusOK)
				return
			})
			r.ServeHTTP(rec, c.Request)

			assert.Equal(t, tc.Status, rec.Code)

			if tc.Redirect != "" {
				assert.Equal(t, tc.Redirect, rec.Header().Get("Location"))
				return
			}
			s = string(rec.Body.Bytes())
			if s != "" {
				assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &pd))
			}
		})
	}
}

func TestContentNegotiation(t *testing.T) {

	tests := []struct {
		name   string
		header string
		want   content
	}{{
		name:   "empty",
		header: "",
		want:   JSON,
	}, {
		name:   "html",
		header: "text/html",
		want:   HTML,
	}, {
		name:   "json",
		header: "application/json",
		want:   JSON,
	}, {
		name:   "text",
		header: "text/plain",
		want:   TEXT,
	}, {
		name:   "nosubtype",
		header: "text/",
		want:   JSON,
	}, {
		name:   "fancysubtype",
		header: "text/fancy",
		want:   JSON,
	}, {
		name:   "complext",
		header: "text/plain; q=0.5, application/json, text/x-dvi; q=0.8, text/x-c",
		want:   JSON,
	}}

	gin.SetMode(gin.TestMode)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			c.Request.Header.Set("Accept", test.header)

			content := negotiateContent(c)

			if content != test.want {
				t.Errorf("Unexpected value\ngot:  %+v\nwant: %+v", content, test.want)
			}
		})
	}
}
