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
	redirect := "http://redirect"
	testcases := []struct {
		Name   string
		Status int
		Error  error
	}{
		{
			Name:   "NotFoundError",
			Status: http.StatusNotFound,
			Error:  NotFoundError{Err: fmt.Errorf(errText), Request: errReq},
		},
		{
			Name:   "BadRequestError",
			Status: http.StatusBadRequest,
			Error:  BadRequestError{Err: fmt.Errorf(errText), Request: errReq},
		},
		{
			Name:   "error",
			Status: http.StatusInternalServerError,
			Error:  fmt.Errorf(errText),
		},
	}

	gin.SetMode(gin.TestMode)

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			rec = httptest.NewRecorder()

			c, r := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

			if tc.Name == "RedirectErrorBrowser" {
				c.Request.Header.Add("Accept", "text/html")
			}

			r.Use(ApplicationErrorReporter())
			r.GET("/", func(c *gin.Context) {
				c.Error(tc.Error)
				return
			})
			r.ServeHTTP(rec, c.Request)

			assert.Equal(t, tc.Status, rec.Code)

			if tc.Name == "RedirectErrorBrowser" {
				assert.Equal(t, redirect, rec.Header().Get("Location"))
				return
			}

			s = string(rec.Body.Bytes())
			assert.NotEqual(t, "", s)
			assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &pd))

			assert.Equal(t, tc.Status, pd.Status)

			if tc.Name == "RedirectError" {
				assert.Equal(t, redirect, pd.Instance)
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
