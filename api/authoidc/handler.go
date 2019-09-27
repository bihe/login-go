package authoidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/gin-contrib/sessions"
	"golang.org/x/oauth2"

	"github.com/bihe/login-go/core"
	"github.com/gin-gonic/gin"
)

// --------------------------------------------------------------------------
// constants and defintions
// --------------------------------------------------------------------------

const stateParam = "state"
const codeParam = "code"
const idTokenParam = "id_token"

var openIDScope = []string{oidc.ScopeOpenID, "profile", "email"}

// --------------------------------------------------------------------------
// the Handler
// --------------------------------------------------------------------------

// Handler defines the OIDC logic
type Handler struct {
	core.VersionInfo
	config core.OAuthConfig
	// oauth / oidc related
	oauthConfig   oauth2.Config
	oauthVerifier *oidc.IDTokenVerifier
}

// NewHandler creates a new instance of the OIDC handler
func NewHandler(v core.VersionInfo, c core.OAuthConfig) *Handler {
	h := Handler{config: c}
	h.VersionInfo = v
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, c.Provider)
	if err != nil {
		log.Fatal(err)
	}
	oidcConfig := &oidc.Config{
		ClientID: c.ClientID,
	}
	h.oauthVerifier = provider.Verifier(oidcConfig)
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
func (h *Handler) Signin(c *gin.Context) {
	s := sessions.Default(c)
	ctx := context.Background()

	// read the stateParam again
	state := s.Get(stateParam)

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
	idToken, err := h.oauthVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		c.Error(core.ServerError{Err: fmt.Errorf("filed to verify ID Token: %v", err), Request: c.Request})
		return
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		DisplayName   string `json:"name"`
		PicURL        string `json:"picture"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Locale        string `json:"locale"`
		UserID        string `json:"sub"`
	}

	if err := idToken.Claims(&claims); err != nil {
		c.Error(core.ServerError{Err: fmt.Errorf("claims error: %v", err), Request: c.Request})
		return
	}

	// TODO: verify the claims
	// on success create token and forward to / or to provided redirect URL
	// on error redirect to /error

	s.AddFlash(claims.DisplayName, core.FlashKeyError)
	s.Save()
	c.Redirect(http.StatusTemporaryRedirect, "/error")

	//c.JSON(http.StatusOK, claims)
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

// https://skarlso.github.io/2016/06/12/google-signin-with-go/
func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
