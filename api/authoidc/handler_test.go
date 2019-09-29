package authoidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bihe/login-go/core"
	"github.com/bihe/login-go/persistence"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

var Err = fmt.Errorf("error")

// --------------------------------------------------------------------------
// mocking of OAUTH logic
// --------------------------------------------------------------------------

func setupMockOAuthServer() (*httptest.Server, func()) {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		// Should return authorization code back to the user
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Should return acccess token back to the user
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=mocktoken&scope=user&token_type=bearer"))
	})

	server := httptest.NewServer(mux)

	return server, func() {
		server.Close()
	}
}

func newOAuthConf(url string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  "REDIRECT_URL",
		Scopes:       []string{"email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  url + "/auth",
			TokenURL: url + "/token",
		},
	}
}

type mockToken struct {
	fail bool
}

func (t *mockToken) GetClaims(v interface{}) error {
	if t.fail {
		return Err
	}

	claims := `{
  "email": "a.b@c.de",
  "email_verified": true,
  "name": "NAME",
  "picture": "PICTURE",
  "given_name": "GIVEN_NAME",
  "family_name": "FAMILY_NAME",
  "locale": "en",
  "sub": "1"
}`
	return json.Unmarshal([]byte(claims), v)
}

type mockVerifier struct {
	fail      bool
	failToken bool
}

func (v *mockVerifier) VerifyToken(ctx context.Context, rawToken string) (OIDCToken, error) {
	if v.fail {
		return nil, Err
	}
	return &mockToken{v.failToken}, nil
}

func GetHandler() *Handler {
	version := core.VersionInfo{
		Version: "1",
		Build:   "2",
		Runtime: "r",
	}
	oauth := core.OAuthConfig{
		ClientID:     "CLIENTID",
		ClientSecret: "SECRET",
		RedirectURL:  "http://localhost",
		Provider:     "https://accounts.google.com",
	}
	sec := core.Security{
		JwtIssuer:    "issuer",
		JwtSecret:    "secretsecretsecretsecret",
		Expiry:       1,
		CookieName:   "cookie_name",
		CookieDomain: "localhost",
		CookiePath:   "/",
		CookieSecure: false,
	}

	return NewHandler(version, oauth, sec, &mockRepository{})
}

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

func (m *mockRepository) CreateAtomic() (persistence.Atomic, error) {
	return persistence.Atomic{}, nil
}

func (m *mockRepository) GetSitesByUser(user string) ([]persistence.UserSite, error) {
	if m.fail {
		return nil, Err
	}

	return []persistence.UserSite{
		persistence.UserSite{
			Name:     "site",
			User:     "USER",
			URL:      "http://example.com",
			PermList: "Role1;Role2",
		},
	}, nil
}

func (m *mockRepository) StoreSiteForUser(user string, sites []persistence.UserSite, a persistence.Atomic) (err error) {
	return nil
}

func (m *mockRepository) StoreLogin(login persistence.Login, a persistence.Atomic) (err error) {
	return nil
}

// --------------------------------------------------------------------------
// test methods
// --------------------------------------------------------------------------

func TestNewHandler(t *testing.T) {
	h := GetHandler()
	if h == nil {
		t.Errorf("could not instantiate a new handler!")
	}
}

func TestOIDCRedirect(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("cookie", store))

	h := GetHandler()
	r.GET("/oidc", h.GetRedirect)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/oidc", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	l := w.Header().Get("Location")
	u, err := url.Parse(l)
	if err != nil {
		t.Errorf("could not parse url: %v", err)
	}

	assert.Equal(t, "accounts.google.com", u.Hostname())
	assert.Equal(t, "CLIENTID", u.Query().Get("client_id"))
	assert.Equal(t, "http://localhost", u.Query().Get("redirect_uri"))
	assert.Equal(t, "openid profile email", u.Query().Get("scope"))
}

func TestOIDCSignin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("cookie", store))
	r.Use(core.ApplicationErrorReporter())
	state := "S"

	testSrv, closeSrv := setupMockOAuthServer()
	defer func() {
		closeSrv()
	}()

	h := GetHandler()
	oauthConf := newOAuthConf(testSrv.URL)
	h.oauthConfig = *oauthConf
	h.oauthVerifier = &mockVerifier{}

	r.Use(func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set(stateParam, state)
		s.Save()
	})
	r.GET("/signin", h.Signin)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	url := fmt.Sprintf("/signin?%s=%s", stateParam, state)

	c.Request = httptest.NewRequest(http.MethodGet, url, nil)

	r.ServeHTTP(rec, c.Request)

	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code)
}

func TestOIDCSigninFailRepo(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("cookie", store))
	r.Use(core.ApplicationErrorReporter())
	state := "S"

	testSrv, closeSrv := setupMockOAuthServer()
	defer func() {
		closeSrv()
	}()

	h := GetHandler()
	oauthConf := newOAuthConf(testSrv.URL)
	h.oauthConfig = *oauthConf
	h.oauthVerifier = &mockVerifier{}
	h.repo = &mockRepository{true}

	r.Use(func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set(stateParam, state)
		s.Save()
	})
	r.GET("/signin", h.Signin)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	url := fmt.Sprintf("/signin?%s=%s", stateParam, state)

	c.Request = httptest.NewRequest(http.MethodGet, url, nil)

	r.ServeHTTP(rec, c.Request)

	assert.Equal(t, "/error", rec.Header().Get("Location"))
	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code)
}

func TestOIDCSigninFailState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("cookie", store))
	r.Use(core.ApplicationErrorReporter())
	state := "S"
	url := "/signin"

	testSrv, closeSrv := setupMockOAuthServer()
	defer func() {
		closeSrv()
	}()

	h := GetHandler()
	oauthConf := newOAuthConf(testSrv.URL)
	h.oauthConfig = *oauthConf
	h.oauthVerifier = &mockVerifier{}

	r.Use(func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set(stateParam, state)
		s.Save()
	})
	r.GET(url, h.Signin)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, url, nil)

	r.ServeHTTP(rec, c.Request)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOIDCSigninFailVerify(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("cookie", store))
	r.Use(core.ApplicationErrorReporter())
	state := "S"

	testSrv, closeSrv := setupMockOAuthServer()
	defer func() {
		closeSrv()
	}()

	h := GetHandler()
	oauthConf := newOAuthConf(testSrv.URL)
	h.oauthConfig = *oauthConf
	h.oauthVerifier = &mockVerifier{fail: true}

	r.Use(func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set(stateParam, state)
		s.Save()
	})
	r.GET("/signin", h.Signin)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	url := fmt.Sprintf("/signin?%s=%s", stateParam, state)

	c.Request = httptest.NewRequest(http.MethodGet, url, nil)

	r.ServeHTTP(rec, c.Request)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestOIDCSigninFailClaims(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("cookie", store))
	r.Use(core.ApplicationErrorReporter())
	state := "S"

	testSrv, closeSrv := setupMockOAuthServer()
	defer func() {
		closeSrv()
	}()

	h := GetHandler()
	oauthConf := newOAuthConf(testSrv.URL)
	h.oauthConfig = *oauthConf
	h.oauthVerifier = &mockVerifier{failToken: true}

	r.Use(func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set(stateParam, state)
		s.Save()
	})
	r.GET("/signin", h.Signin)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	url := fmt.Sprintf("/signin?%s=%s", stateParam, state)

	c.Request = httptest.NewRequest(http.MethodGet, url, nil)

	r.ServeHTTP(rec, c.Request)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("cookie", store))
	r.LoadHTMLFiles("../../templates/error.tmpl")

	h := GetHandler()
	r.GET("/error", h.Error)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/error", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := string(w.Body.Bytes())
	if strings.Index(body, "<title>login.binggl.net</title>") == -1 {
		t.Errorf("no html found!")
	}
}
