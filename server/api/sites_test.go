package api

import (
	"bytes"
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

func TestGetSites(t *testing.T) {
	r := chi.NewRouter()
	a := New("templatepath", cookieSettings, version, oauthConfig, jwtConfig, &mockRepository{})
	api := a.(*handlers)

	api.repo = &mockRepository{}
	api.editRole = "role"

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
	r.Get("/sites", api.Secure(api.HandleGetSites))

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/sites", nil)

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var u UserSites
	err := json.Unmarshal(rec.Body.Bytes(), &u)
	if err != nil {
		t.Errorf("could not get valid json: %v", err)
	}

	assert.Equal(t, "username", u.User)
	assert.Equal(t, true, u.Editable)
	assert.Equal(t, "site", u.Sites[0].Name)
}

func TestFailSites(t *testing.T) {
	r := chi.NewRouter()
	a := New("templatepath", cookieSettings, version, oauthConfig, jwtConfig, &mockRepository{})
	api := a.(*handlers)

	api.repo = &mockRepository{fail: true}
	api.editRole = "role"

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
	r.Get("/sites", api.Secure(api.HandleGetSites))

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/sites", nil)

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	var p errors.ProblemDetail
	err := json.Unmarshal(rec.Body.Bytes(), &p)
	if err != nil {
		t.Errorf("could not get valid json: %v", err)
	}
}

func TestSaveSites(t *testing.T) {
	r := chi.NewRouter()
	a := New("templatepath", cookieSettings, version, oauthConfig, jwtConfig, &mockRepository{})
	api := a.(*handlers)

	api.repo = &mockRepository{fail: false}
	api.editRole = "role"

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
	r.Post("/sites", api.Secure(api.HandleSaveSites))

	sites := []SiteInfo{SiteInfo{
		Name: "site",
		URL:  "http://example",
		Perm: []string{"role1", "role2"},
	}}
	payload, _ := json.Marshal(sites)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/sites", bytes.NewBuffer(payload))

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestSaveSitesFail(t *testing.T) {
	r := chi.NewRouter()
	a := New("templatepath", cookieSettings, version, oauthConfig, jwtConfig, &mockRepository{})
	api := a.(*handlers)

	api.repo = &mockRepository{fail: true}
	api.editRole = "role"

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
	r.Post("/sites", api.Secure(api.HandleSaveSites))

	sites := []SiteInfo{SiteInfo{
		Name: "site",
		URL:  "http://example",
		Perm: []string{"role1", "role2"},
	}}
	payload, _ := json.Marshal(sites)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/sites", bytes.NewBuffer(payload))

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var p errors.ProblemDetail
	err := json.Unmarshal(rec.Body.Bytes(), &p)
	if err != nil {
		t.Errorf("could not get valid json: %v", err)
	}
}

func TestSaveSitesNoPayload(t *testing.T) {
	r := chi.NewRouter()
	a := New("templatepath", cookieSettings, version, oauthConfig, jwtConfig, &mockRepository{})
	api := a.(*handlers)

	api.repo = &mockRepository{fail: true}
	api.editRole = "role"

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
	r.Post("/sites", api.Secure(api.HandleSaveSites))

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/sites", nil)

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var p errors.ProblemDetail
	err := json.Unmarshal(rec.Body.Bytes(), &p)
	if err != nil {
		t.Errorf("could not get valid json: %v", err)
	}
}

func TestSaveSitesNotAllowed(t *testing.T) {
	r := chi.NewRouter()
	a := New("templatepath", cookieSettings, version, oauthConfig, jwtConfig, &mockRepository{})
	api := a.(*handlers)

	api.repo = &mockRepository{fail: true}
	api.editRole = "missing-role"

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
	r.Post("/sites", api.Secure(api.HandleSaveSites))

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/sites", nil)

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	var p errors.ProblemDetail
	err := json.Unmarshal(rec.Body.Bytes(), &p)
	if err != nil {
		t.Errorf("could not get valid json: %v", err)
	}
}