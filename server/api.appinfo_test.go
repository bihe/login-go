package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sec "github.com/bihe/commons-go/security"
	"github.com/bihe/login-go/internal/config"
	"github.com/bihe/login-go/internal/errors"
	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
)

func TestGetAppInfo(t *testing.T) {
	r := chi.NewRouter()
	api := NewAPI("templatepath", cookieSettings, version, oauthConfig, jwtConfig, &mockRepository{})

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), config.User, &sec.User{
				Username:    "username",
				Email:       "a.b@c.de",
				DisplayName: "displayname",
				Roles:       []string{"role"},
				UserID:      "12345",
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	r.Get("/appinfo", api.secure(api.handleAppInfoGet))

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/appinfo", nil)

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var m Meta
	err := json.Unmarshal(rec.Body.Bytes(), &m)
	if err != nil {
		t.Errorf("could not get valid json: %v", err)
	}

	assert.Equal(t, "r", m.Runtime)
	assert.Equal(t, "1-2", m.Version)
}

func TestGetAppInfoNilUser(t *testing.T) {
	r := chi.NewRouter()
	api := NewAPI("templatepath", cookieSettings, version, oauthConfig, jwtConfig, &mockRepository{})
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), config.User, nil)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	r.Get("/appinfo", api.secure(api.handleAppInfoGet))

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/appinfo", nil)

	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	var p errors.ProblemDetail
	err := json.Unmarshal(rec.Body.Bytes(), &p)
	if err != nil {
		t.Errorf("could not unmarshall: %v", err)
	}
	assert.Equal(t, http.StatusInternalServerError, p.Status)
}
