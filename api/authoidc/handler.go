package authoidc

import (
	"context"
	"fmt"
	"net/http"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/gin-contrib/sessions"
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
}

// NewHandler creates a new instance of the OIDC handler
func NewHandler(v core.VersionInfo, c core.OAuthConfig, s core.Security, repo persistence.Repository) *Handler {
	h := Handler{config: c}
	h.VersionInfo = v
	h.repo = repo
	h.jwt = s

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
	s := sessions.Default(c)
	state := randToken()
	s.Set(stateParam, state)
	s.Save()
	c.Redirect(http.StatusFound, h.oauthConfig.AuthCodeURL(state))
}

// Signin performs the login/authentication of the OIDC context
// the user of the external authentication provider is checked against
// the database. If a match is found a token with the valid claims is created
// and a redirect is made to the defined URL
func (h *Handler) Signin(c *gin.Context) {
	s := sessions.Default(c)
	ctx := context.Background()

	// read the stateParam again
	state := s.Get(stateParam)
	log.Debugf("got state param: %s", state)

	if c.Query(stateParam) != state {
		c.Error(core.BadRequestError{Err: fmt.Errorf("state did not match"), Request: c.Request})
		return
	}

	s.Delete(stateParam)
	s.Save()

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

	if !success {
		// save a flash message in the session.store
		s.AddFlash(fmt.Sprintf("User '%s' is not allowed to login!", oidcClaims.Email), core.FlashKeyError)
		s.Save()

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

	// set the cookie
	exp := h.jwt.Expiry * 24 * 3600
	c.SetCookie(h.jwt.CookieName,
		token,
		exp, /* exp in seconds */
		h.jwt.CookiePath,
		h.jwt.CookieDomain,
		h.jwt.CookieSecure,
		true /* http-only */)

	// redirect to provided URL
	c.Redirect(http.StatusTemporaryRedirect, h.jwt.LoginRedirect)

}

// Error returns a HTML template showing errors
func (h *Handler) Error(c *gin.Context) {
	s := sessions.Default(c)
	var (
		msg       string
		err       string
		isError   bool
		isMessage bool
	)

	flashes := s.Flashes(core.FlashKeyError)
	if len(flashes) > 0 {
		err = fmt.Sprintf("%v", flashes[0])
		isError = true
	}

	flashes = s.Flashes(core.FlashKeyInfo)
	if len(flashes) > 0 {
		msg = fmt.Sprintf("%v", flashes[0])
		isMessage = true
	}

	s.Clear()
	s.Save()

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

func randToken() string {
	u := uuid.New()
	return u.String()
}
