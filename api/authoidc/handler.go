package authoidc

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/bihe/login-go/core"
	"github.com/bihe/login-go/persistence"
	"github.com/bihe/login-go/security"
	"github.com/gin-gonic/gin"

	log "github.com/sirupsen/logrus"
)

// --------------------------------------------------------------------------
// constants and defintions
// --------------------------------------------------------------------------

const stateParam = "state"
const codeParam = "code"
const idTokenParam = "id_token"

var openIDScope = []string{oidc.ScopeOpenID, "profile", "email"}

// --------------------------------------------------------------------------
// OIDC wrapping
// --------------------------------------------------------------------------

// OIDCToken wraps the underlying implementation of oidc-token
type OIDCToken interface {
	GetClaims(v interface{}) error
}

type oidcToken struct {
	*oidc.IDToken
}

// GetClaims returns the token claims
func (t *oidcToken) GetClaims(v interface{}) error {
	return t.Claims(v)
}

// OIDCVerifier wraps the underlying implementation of oidc-verify
type OIDCVerifier interface {
	VerifyToken(ctx context.Context, rawToken string) (OIDCToken, error)
}

type oidcVerifier struct {
	*oidc.IDTokenVerifier
}

func (v *oidcVerifier) VerifyToken(ctx context.Context, rawToken string) (OIDCToken, error) {
	t, err := v.Verify(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	return &oidcToken{t}, nil
}

// --------------------------------------------------------------------------
// the Handler
// --------------------------------------------------------------------------

// Handler defines the OIDC logic
type Handler struct {
	core.VersionInfo
	config core.OAuthConfig
	// oauth / oidc related
	oauthConfig   oauth2.Config
	oauthVerifier OIDCVerifier
	// store
	repo persistence.Repository
	// jwt logic
	jwt core.Security
	// application cookie settings
	cookie core.CookieSettings
}

// NewHandler creates a new instance of the OIDC handler
func NewHandler(v core.VersionInfo, c core.OAuthConfig, s core.Security, cookie core.CookieSettings, repo persistence.Repository) *Handler {
	h := Handler{config: c}
	h.VersionInfo = v
	h.repo = repo
	h.jwt = s
	h.cookie = cookie

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, c.Provider)
	if err != nil {
		log.Fatal(err)
	}
	oidcConfig := &oidc.Config{
		ClientID: c.ClientID,
	}
	ver := provider.Verifier(oidcConfig)
	h.oauthVerifier = &oidcVerifier{ver}
	h.oauthConfig = oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  c.RedirectURL,
		Scopes:       openIDScope,
	}
	return &h
}

// GetRedirect returns a HTTP redirect to the OIDC authentication party
func (h *Handler) GetRedirect(c *gin.Context) {
	state := randToken()
	h.setAppCookie(stateParam, state, c)
	c.Redirect(http.StatusFound, h.oauthConfig.AuthCodeURL(state))
}

const siteParam = "~site"
const redirectParam = "~url"
const authFlowCookie = "auth_flow"
const authFlowSep = "|"

// AuthFlow initiates the authentication and redirects to a specific URL
func (h *Handler) AuthFlow(c *gin.Context) {
	state := randToken()
	h.setAppCookie(stateParam, state, c)

	site, redirect := c.Query(siteParam), c.Query(redirectParam)
	if site == "" || redirect == "" {
		c.Error(core.BadRequestError{Err: fmt.Errorf("missing or invalid parameters supplied"), Request: c.Request})
		return
	}
	h.setAppCookie(authFlowCookie, fmt.Sprintf("%s%s%s", site, authFlowSep, redirect), c)
	c.Redirect(http.StatusFound, h.oauthConfig.AuthCodeURL(state))
}

// Signin performs the login/authentication of the OIDC context
// the user of the external authentication provider is checked against
// the database. If a match is found a token with the valid claims is created
// and a redirect is made to the defined URL
func (h *Handler) Signin(c *gin.Context) {
	ctx := context.Background()

	// read the stateParam again
	state := h.getAppCookie(stateParam, c)
	log.Debugf("got state param: %s", state)

	if c.Query(stateParam) != state {
		c.Error(core.BadRequestError{Err: fmt.Errorf("state did not match"), Request: c.Request})
		return
	}
	h.delAppCookie(stateParam, c)

	// is this an auth/flow request
	var (
		authFlow       bool
		site, redirect string
	)
	authFlowParams := h.getAppCookie(authFlowCookie, c)
	if authFlowParams != "" {
		log.Debugf("auth/flow login-mode")
		parts := strings.Split(authFlowParams, "|")
		site = parts[0]
		redirect = parts[1]
		authFlow = true
	}
	h.delAppCookie(authFlowCookie, c)

	oauth2Token, err := h.oauthConfig.Exchange(ctx, c.Query(codeParam))
	if err != nil {
		c.Error(core.ServerError{Err: fmt.Errorf("failed to exchange token: %v", err), Request: c.Request})
		return
	}
	rawIDToken, ok := oauth2Token.Extra(idTokenParam).(string)
	if !ok {
		c.Error(core.ServerError{Err: fmt.Errorf("no id_token field in oauth2 token"), Request: c.Request})
		return
	}
	idToken, err := h.oauthVerifier.VerifyToken(ctx, rawIDToken)
	if err != nil {
		c.Error(core.ServerError{Err: fmt.Errorf("failed to verify ID Token: %v", err), Request: c.Request})
		return
	}

	var oidcClaims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		DisplayName   string `json:"name"`
		PicURL        string `json:"picture"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Locale        string `json:"locale"`
		UserID        string `json:"sub"`
	}

	if err := idToken.GetClaims(&oidcClaims); err != nil {
		c.Error(core.ServerError{Err: fmt.Errorf("claims error: %v", err), Request: c.Request})
		return
	}

	// the user was authenticated successfully, check if sites are available for the given user!
	success := true
	sites, err := h.repo.GetSitesByUser(oidcClaims.Email)
	if err != nil {
		log.Warnf("successfull login by '%s' but error fetching sites! %v", oidcClaims.Email, err)
		success = false
	}

	if sites == nil || len(sites) == 0 {
		log.Warnf("successfull login by '%s' but no sites availabel!", oidcClaims.Email)
		success = false
	}

	if authFlow {
		log.Debugf("auth/flow - check for specific site '%s'", site)
		success = false
		// check specific site
		for _, e := range sites {
			if e.Name == site {
				success = true
				break
			}
		}
	}

	if !success {
		h.setAppCookie(core.FlashKeyError, fmt.Sprintf("User '%s' is not allowed to login!", oidcClaims.Email), c)

		c.Abort()
		c.Redirect(http.StatusTemporaryRedirect, "/error")
		return
	}

	// create the token using the claims of the database
	var siteClaims []string
	for _, s := range sites {
		siteClaims = append(siteClaims, fmt.Sprintf("%s|%s|%s", s.Name, s.URL, s.PermList))
	}
	claims := security.Claims{
		Type:        "login.User",
		DisplayName: oidcClaims.DisplayName,
		Email:       oidcClaims.Email,
		UserID:      oidcClaims.UserID,
		UserName:    oidcClaims.Email,
		GivenName:   oidcClaims.GivenName,
		Surname:     oidcClaims.FamilyName,
		Claims:      siteClaims,
	}
	token, err := security.CreateToken(h.jwt.JwtIssuer, []byte(h.jwt.JwtSecret), h.jwt.Expiry, claims)
	if err != nil {
		log.Errorf("could not create a JWT token: %v", err)
		c.Error(core.ServerError{Err: fmt.Errorf("error creating JWT: %v", err), Request: c.Request})
		return
	}

	login := persistence.Login{
		User:    oidcClaims.Email,
		Created: time.Now().UTC(),
		Type:    persistence.DIRECT,
	}

	if authFlow {
		login.Type = persistence.FLOW
	}

	err = h.repo.StoreLogin(login, persistence.Atomic{})
	if err != nil {
		log.Errorf("the login could not be saved: %v", err)
		c.Error(core.ServerError{Err: fmt.Errorf("error storing the login: %v", err), Request: c.Request})
		return
	}

	// set the cookie
	exp := h.jwt.Expiry * 24 * 3600
	h.setJWTCookie(h.jwt.CookieName, token, exp, c)

	redirectURL := h.jwt.LoginRedirect
	if authFlow {
		log.Debugf("auth/flow - redirect to specific URL: '%s'", redirect)
		redirectURL = fmt.Sprintf("%s", redirect)
	}

	// redirect to provided URL
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

// Logout invalidates the authenticated user
func (h *Handler) Logout(c *gin.Context) {
	user := c.MustGet(core.User).(security.User)

	// remove the cookie by expiring it
	h.setJWTCookie(h.jwt.CookieName, "", -1, c)
	h.setAppCookie(core.FlashKeyInfo, fmt.Sprintf("User '%s' was logged-off!", user.Email), c)

	c.Abort()
	c.Redirect(http.StatusTemporaryRedirect, h.jwt.LoginRedirect+core.ErrorPath)
}

// Error returns a HTML template showing errors
func (h *Handler) Error(c *gin.Context) {
	var (
		msg       string
		err       string
		isError   bool
		isMessage bool
	)

	// read (flash)
	err = h.getAppCookie(core.FlashKeyError, c)
	if err != "" {
		isError = true
	}
	msg = h.getAppCookie(core.FlashKeyInfo, c)
	if msg != "" {
		isMessage = true
	}

	// clear (flash)
	h.delAppCookie(core.FlashKeyError, c)
	h.delAppCookie(core.FlashKeyInfo, c)

	c.HTML(http.StatusOK, "error.tmpl", gin.H{
		"year":      time.Now().Year(),
		"appname":   "login.binggl.net",
		"version":   fmt.Sprintf("%s-%s", h.Version, h.Build),
		"isError":   isError,
		"error":     err,
		"isMessage": isMessage,
		"msg":       msg,
	})
}

func (h *Handler) setJWTCookie(name, value string, exp int, c *gin.Context) {
	c.SetCookie(name,
		value,
		exp, /* exp in seconds */
		h.jwt.CookiePath,
		h.jwt.CookieDomain,
		h.jwt.CookieSecure,
		true /* http-only */)
}

func (h *Handler) setAppCookie(name, value string, c *gin.Context) {
	core.SetCookie(name, value, core.CookieDefaultExp, h.cookie, c)
}

func (h *Handler) delAppCookie(name string, c *gin.Context) {
	core.SetCookie(name, "", -1, h.cookie, c)
}

func (h *Handler) getAppCookie(name string, c *gin.Context) string {
	return core.GetCookie(name, h.cookie, c)
}

func randToken() string {
	u := uuid.New()
	return u.String()
}
