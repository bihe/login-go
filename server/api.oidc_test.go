package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/bihe/login-go/internal/persistence"
	"github.com/bihe/login-go/internal/security"
	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	per "github.com/bihe/commons-go/persistence"
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

// --------------------------------------------------------------------------
// mock repository
// --------------------------------------------------------------------------

/*
	CreateAtomic() (Atomic, error)
	GetSitesByUser(user string) ([]UserSite, error)
	StoreSiteForUser(user string, sites []UserSite, a Atomic) (err error)
	StoreLogin(login Login, a Atomic) (err error)
*/

var _ persistence.Repository = (*mockRepository)(nil)

type mockRepository struct {
	fail bool
}

func (m *mockRepository) CreateAtomic() (per.Atomic, error) {
	return per.Atomic{}, nil
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

func (m *mockRepository) StoreSiteForUser(user string, sites []persistence.UserSite, a per.Atomic) (err error) {
	return nil
}

func (m *mockRepository) StoreLogin(login persistence.Login, a per.Atomic) (err error) {
	return nil
}

// --------------------------------------------------------------------------
// test methods
// --------------------------------------------------------------------------

func TestNewOIDC(t *testing.T) {
	o, v := NewOIDC(oauthConfig)
	if o == nil || v == nil {
		t.Errorf("could not instantiate oidc!")
	}
}

func TestErrorPage(t *testing.T) {
	r, api := newAPIRouter()
	api.basePath = "../"
	r.Get("/error", api.call(api.handleError))

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/error", nil)

	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	body := string(rec.Body.Bytes())
	if body == "" {
		t.Errorf("could not get the template!")
	}
}

func TestOIDCRedirect(t *testing.T) {
	r, api := newAPIRouter()
	r.Get("/oidc", api.call(api.handleOIDCRedirect))

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/oidc", nil)

	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusFound, rec.Code)

	l := rec.Header().Get("Location")
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
	testSrv, closeSrv := setupMockOAuthServer()
	defer func() {
		closeSrv()
	}()

	r, api := newAPIRouter()
	r.Get(signIn, api.call(api.handleOIDCLogin))
	oauthConf := newOAuthConf(testSrv.URL)
	api.oauthConfig = oauthConf
	api.oauthVerifier = &mockVerifier{}

	url := fmt.Sprintf(signInURL, stateParam, state)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: state})

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code)
}

func TestOIDCSigninFailRepo(t *testing.T) {
	testSrv, closeSrv := setupMockOAuthServer()
	defer func() {
		closeSrv()
	}()

	r, api := newAPIRouter()
	r.Get(signIn, api.call(api.handleOIDCLogin))
	oauthConf := newOAuthConf(testSrv.URL)
	api.oauthConfig = oauthConf
	api.oauthVerifier = &mockVerifier{}
	// tell the repository to FAIL
	api.repo = &mockRepository{true}

	rec := httptest.NewRecorder()
	url := fmt.Sprintf(signInURL, stateParam, state)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: state})

	r.ServeHTTP(rec, req)

	assert.Equal(t, errorPath, rec.Header().Get("Location"))
	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code)
}

func TestOIDCSigninFailState(t *testing.T) {
	testSrv, closeSrv := setupMockOAuthServer()
	defer func() {
		closeSrv()
	}()

	r, api := newAPIRouter()
	r.Get(signIn, api.call(api.handleOIDCLogin))
	oauthConf := newOAuthConf(testSrv.URL)
	api.oauthConfig = oauthConf
	api.oauthVerifier = &mockVerifier{}
	// the url does not have a state param - FAIL
	url := signIn
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: state})

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOIDCSigninFailVerify(t *testing.T) {
	testSrv, closeSrv := setupMockOAuthServer()
	defer func() {
		closeSrv()
	}()

	r, api := newAPIRouter()
	r.Get(signIn, api.call(api.handleOIDCLogin))
	oauthConf := newOAuthConf(testSrv.URL)
	api.oauthConfig = oauthConf
	// instruct the verifier to FAIL
	api.oauthVerifier = &mockVerifier{fail: true}

	rec := httptest.NewRecorder()
	url := fmt.Sprintf(signInURL, stateParam, state)

	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: state})

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestOIDCSigninFailClaims(t *testing.T) {
	testSrv, closeSrv := setupMockOAuthServer()
	defer func() {
		closeSrv()
	}()

	r, api := newAPIRouter()
	r.Get(signIn, api.call(api.handleOIDCLogin))
	oauthConf := newOAuthConf(testSrv.URL)
	api.oauthConfig = oauthConf
	// instruct the verifier to FAIL on tokens
	api.oauthVerifier = &mockVerifier{failToken: true}

	rec := httptest.NewRecorder()
	url := fmt.Sprintf(signInURL, stateParam, state)

	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: state})

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestOIDCAuthFlow(t *testing.T) {
	r, api := newAPIRouter()
	authFlowURL := "/auth/flow"
	r.Get(authFlowURL, api.call(api.handleAuthFlow))

	redirectURL := "/customRedirect"
	authFlowURL += fmt.Sprintf("?%s=%s&%s=%s", siteParam, "site", redirectParam, redirectURL)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", authFlowURL, nil)

	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusFound, rec.Code)

	l := rec.Header().Get("Location")
	u, err := url.Parse(l)
	if err != nil {
		t.Errorf("could not parse url: %v", err)
	}

	assert.Equal(t, "accounts.google.com", u.Hostname())
	assert.Equal(t, "CLIENTID", u.Query().Get("client_id"))
	assert.Equal(t, "http://localhost", u.Query().Get("redirect_uri"))
	assert.Equal(t, "openid profile email", u.Query().Get("scope"))
}

func TestOIDCAuthFlowFail(t *testing.T) {
	r, api := newAPIRouter()
	authFlowURL := "/auth/flow"
	r.Get(authFlowURL, api.call(api.handleAuthFlow))
	// no query-parameters supplied
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", authFlowURL, nil)

	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOIDCSigninAuthFlow(t *testing.T) {
	testSrv, closeSrv := setupMockOAuthServer()
	defer func() {
		closeSrv()
	}()

	r, api := newAPIRouter()
	r.Get(signIn, api.call(api.handleOIDCLogin))
	oauthConf := newOAuthConf(testSrv.URL)
	api.oauthConfig = oauthConf
	api.oauthVerifier = &mockVerifier{}
	api.repo = &mockRepository{}

	redirectURL := "/customRedirect"

	rec := httptest.NewRecorder()
	url := fmt.Sprintf(signInURL, stateParam, state)

	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: state})
	req.AddCookie(&http.Cookie{Name: authFlowCookieName, Value: fmt.Sprintf("%s%s%s", "site", authFlowSep, redirectURL)})

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code)
	assert.Equal(t, redirectURL, rec.Header().Get("Location"))
}

func TestLogout(t *testing.T) {
	logout := "/logout"
	r, api := newAPIRouter()

	r.Use(security.NewJwtMiddleware(jwtOpts, cookieSettings).JwtContext)
	r.Get(logout, api.secure(api.handleLogout))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, logout, nil)
	req.AddCookie(&http.Cookie{Name: jwtConfig.CookieName, Value: token})

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code)
	l := rec.Header().Get("Location")
	if l != errorPath {
		t.Errorf("wrong redirect to error page")
	}

}

func newAPIRouter() (chi.Router, *API) {
	r := chi.NewRouter()
	api := NewAPI("templatepath", cookieSettings, version, oauthConfig, jwtConfig, &mockRepository{})
	return r, api

}
