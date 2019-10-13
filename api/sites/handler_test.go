package sites

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bihe/login-go/core"
	"github.com/bihe/login-go/persistence"
	"github.com/bihe/login-go/security"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

var Err = fmt.Errorf("error")

// --------------------------------------------------------------------------
// mock repository
// --------------------------------------------------------------------------

/*
	CreateAtomic() (Atomic, error)
	GetSitesByUser(user string) ([]UserSite, error)
	StoreSiteForUser(user string, sites []UserSite, a Atomic) (err error)
	StoreLogin(login Login, a Atomic) (err error)
*/

type mockRepository struct {
	fail bool
}

func (m mockRepository) CreateAtomic() (persistence.Atomic, error) {
	return persistence.Atomic{}, nil
}

func (m mockRepository) GetSitesByUser(user string) ([]persistence.UserSite, error) {
	if m.fail {
		return nil, Err
	}

	return []persistence.UserSite{
		persistence.UserSite{
			Name:     "site",
			User:     "username",
			URL:      "http://example.com",
			PermList: "role;role1",
		},
	}, nil
}

func (m mockRepository) StoreSiteForUser(user string, sites []persistence.UserSite, a persistence.Atomic) (err error) {
	if m.fail {
		return Err
	}
	return nil
}

func (m mockRepository) StoreLogin(login persistence.Login, a persistence.Atomic) (err error) {
	return nil
}

// --------------------------------------------------------------------------
// test methods
// --------------------------------------------------------------------------

func TestNewHandler(t *testing.T) {
	h := NewHandler("site", "role", mockRepository{})
	if h == nil {
		t.Errorf("could not get a handler")
	}
}

func TestGetSites(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()

	r.Use(func(c *gin.Context) {
		c.Set(core.User, security.User{
			Username:    "username",
			Email:       "a.b@c.de",
			DisplayName: "displayname",
			Roles:       []string{"role"},
			UserID:      "12345",
		})
	})

	h := &Handler{
		editRole: "role",
		repo:     mockRepository{},
	}
	r.GET("/sites", security.W(h.GetSites))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/sites", nil)

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var u UserInfo
	err := json.Unmarshal(w.Body.Bytes(), &u)
	if err != nil {
		t.Errorf("could not get valid json: %v", err)
	}

	assert.Equal(t, "username", u.User)
	assert.Equal(t, true, u.Editable)
	assert.Equal(t, "site", u.Sites[0].Name)
}

var cookieSettings = core.CookieSettings{
	Domain: "localhost",
	Path:   "/",
	Secure: false,
	Prefix: "test",
}

func TestFailSites(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()

	r.Use(core.ApplicationErrorReporter(cookieSettings))
	r.Use(func(c *gin.Context) {
		c.Set(core.User, security.User{
			Username:    "username",
			Email:       "a.b@c.de",
			DisplayName: "displayname",
			Roles:       []string{"role"},
			UserID:      "12345",
		})
	})

	h := &Handler{
		editRole: "role",
		repo:     mockRepository{fail: true},
	}
	r.GET("/sites", security.W(h.GetSites))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/sites", nil)

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var p core.ProblemDetail
	err := json.Unmarshal(w.Body.Bytes(), &p)
	if err != nil {
		t.Errorf("could not get valid json: %v", err)
	}
}

func TestSaveSites(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()

	r.Use(core.ApplicationErrorReporter(cookieSettings))
	r.Use(func(c *gin.Context) {
		c.Set(core.User, security.User{
			Username:    "username",
			Email:       "a.b@c.de",
			DisplayName: "displayname",
			Roles:       []string{"role"},
			UserID:      "12345",
		})
	})

	h := &Handler{
		editRole: "role",
		repo:     mockRepository{fail: false},
	}
	r.POST("/sites", security.W(h.SaveSites))

	sites := []SiteInfo{SiteInfo{
		Name: "site",
		URL:  "http://example",
		Perm: []string{"role1", "role2"},
	}}
	payload, _ := json.Marshal(sites)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/sites", bytes.NewBuffer(payload))

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestSaveSitesFail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()

	r.Use(core.ApplicationErrorReporter(cookieSettings))
	r.Use(func(c *gin.Context) {
		c.Set(core.User, security.User{
			Username:    "username",
			Email:       "a.b@c.de",
			DisplayName: "displayname",
			Roles:       []string{"role"},
			UserID:      "12345",
		})
	})

	h := &Handler{
		editRole: "role",
		repo:     mockRepository{fail: true},
	}
	r.POST("/sites", security.W(h.SaveSites))

	sites := []SiteInfo{SiteInfo{
		Name: "site",
		URL:  "http://example",
		Perm: []string{"role1", "role2"},
	}}
	payload, _ := json.Marshal(sites)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/sites", bytes.NewBuffer(payload))

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var p core.ProblemDetail
	err := json.Unmarshal(w.Body.Bytes(), &p)
	if err != nil {
		t.Errorf("could not get valid json: %v", err)
	}
}

func TestSaveSitesNoPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()

	r.Use(core.ApplicationErrorReporter(cookieSettings))
	r.Use(func(c *gin.Context) {
		c.Set(core.User, security.User{
			Username:    "username",
			Email:       "a.b@c.de",
			DisplayName: "displayname",
			Roles:       []string{"role"},
			UserID:      "12345",
		})
	})

	h := &Handler{
		editRole: "role",
		repo:     mockRepository{fail: true},
	}
	r.POST("/sites", security.W(h.SaveSites))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/sites", nil)

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var p core.ProblemDetail
	err := json.Unmarshal(w.Body.Bytes(), &p)
	if err != nil {
		t.Errorf("could not get valid json: %v", err)
	}
}

func TestSaveSitesNotAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()

	r.Use(core.ApplicationErrorReporter(cookieSettings))
	r.Use(func(c *gin.Context) {
		c.Set(core.User, security.User{
			Username:    "username",
			Email:       "a.b@c.de",
			DisplayName: "displayname",
			Roles:       []string{"role"},
			UserID:      "12345",
		})
	})

	h := &Handler{
		editRole: "missing-role",
		repo:     mockRepository{fail: true},
	}
	r.POST("/sites", security.W(h.SaveSites))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/sites", nil)

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	var p core.ProblemDetail
	err := json.Unmarshal(w.Body.Bytes(), &p)
	if err != nil {
		t.Errorf("could not get valid json: %v", err)
	}
}
