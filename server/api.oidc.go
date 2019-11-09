package server

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/bihe/login-go/internal/config"
	"github.com/bihe/login-go/internal/cookies"
	"github.com/bihe/login-go/internal/errors"
	"github.com/bihe/login-go/internal/persistence"
	"github.com/google/uuid"

	"github.com/coreos/go-oidc"

	per "github.com/bihe/commons-go/persistence"
	sec "github.com/bihe/commons-go/security"
	log "github.com/sirupsen/logrus"
)

// --------------------------------------------------------------------------
// constants and defintions
// --------------------------------------------------------------------------

const stateParam = "state"
const codeParam = "code"
const idTokenParam = "id_token"
const siteParam = "~site"
const redirectParam = "~url"
const authFlowCookie = "auth_flow"
const authFlowSep = "|"

var openIDScope = []string{oidc.ScopeOpenID, "profile", "email"}

const templateDir = "templates"
const errorTemplate = "error.tmpl"

// Error returns a HTML template showing errors
func (a *API) handleError(w http.ResponseWriter, r *http.Request) error {
	cookie := cookies.NewAppCookie(a.cookieSettings)
	var (
		msg       string
		err       string
		isError   bool
		isMessage bool
	)

	// read (flash)
	err = cookie.Get(config.FlashKeyError, r)
	if err != "" {
		isError = true
	}
	msg = cookie.Get(config.FlashKeyInfo, r)
	if msg != "" {
		isMessage = true
	}

	// clear (flash)
	cookie.Del(config.FlashKeyError, w)
	cookie.Del(config.FlashKeyInfo, w)

	data := map[string]interface{}{
		"year":      time.Now().Year(),
		"appname":   "login.binggl.net",
		"version":   fmt.Sprintf("%s-%s", a.Version, a.Build),
		"isError":   isError,
		"error":     err,
		"isMessage": isMessage,
		"msg":       msg,
	}

	path := filepath.Join(a.basePath, templateDir, errorTemplate)
	tmpl, e := template.ParseFiles(path)
	if e != nil {
		return e
	}
	tmpl.Execute(w, data)
	return nil
}

const cookieExpiry = 60

// handleOIDCRedirect initiates the OAUTH flow by redirecting the authentication system
func (a *API) handleOIDCRedirect(w http.ResponseWriter, r *http.Request) error {
	state := randToken()
	a.appCookie.Set(stateParam, state, cookieExpiry, w)
	log.WithField("func", "server.handleOIDCRedirect").Debugf("GetRedirect: initiate using state '%s'", state)
	http.Redirect(w, r, a.oauthConfig.AuthCodeURL(state), http.StatusFound)
	return nil
}

// handleAuthFlow initiates the authentication and redirects to a specific URL
func (a *API) handleAuthFlow(w http.ResponseWriter, r *http.Request) error {
	state := randToken()
	a.appCookie.Set(stateParam, state, cookieExpiry, w)
	log.WithField("func", "server.handleAuthFlow").Debugf("initiate using state '%s'", state)

	site, redirect := query(r, siteParam), query(r, redirectParam)
	if site == "" || redirect == "" {
		return errors.BadRequestError{Err: fmt.Errorf("missing or invalid parameters supplied"), Request: r}
	}
	a.appCookie.Set(authFlowCookie, fmt.Sprintf("%s%s%s", site, authFlowSep, redirect), cookieExpiry, w)
	http.Redirect(w, r, a.oauthConfig.AuthCodeURL(state), http.StatusFound)
	return nil
}

// handleOIDCLogin performs the login/authentication of the OIDC context
// the user of the external authentication provider is checked against
// the database. If a match is found a token with the valid claims is created
// and a redirect is made to the defined URL
func (a *API) handleOIDCLogin(w http.ResponseWriter, r *http.Request) error {
	ctx := context.Background()

	// read the stateParam again
	state := a.appCookie.Get(stateParam, r)
	log.WithField("func", "server.handleOIDCLogin").Debugf("got state param: %s", state)

	if query(r, stateParam) != state {
		return errors.BadRequestError{Err: fmt.Errorf("state did not match"), Request: r}
	}
	a.appCookie.Del(stateParam, w)

	// is this an auth/flow request
	var (
		authFlow       bool
		site, redirect string
	)
	authFlowParams := a.appCookie.Get(authFlowCookie, r)
	if authFlowParams != "" {
		log.WithField("func", "server.handleOIDCLogin").Debugf("auth/flow login-mode")
		parts := strings.Split(authFlowParams, "|")
		site = parts[0]
		redirect = parts[1]
		authFlow = true
	}
	a.appCookie.Del(authFlowCookie, w)

	oauth2Token, err := a.oauthConfig.Exchange(ctx, query(r, codeParam))
	if err != nil {
		return errors.ServerError{Err: fmt.Errorf("failed to exchange token: %v", err), Request: r}
	}
	rawIDToken, ok := oauth2Token.Extra(idTokenParam).(string)
	if !ok {
		return errors.ServerError{Err: fmt.Errorf("no id_token field in oauth2 token"), Request: r}
	}
	idToken, err := a.oauthVerifier.VerifyToken(ctx, rawIDToken)
	if err != nil {
		return errors.ServerError{Err: fmt.Errorf("failed to verify ID Token: %v", err), Request: r}
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
		return errors.ServerError{Err: fmt.Errorf("claims error: %v", err), Request: r}
	}

	// the user was authenticated successfully, check if sites are available for the given user!
	success := true
	sites, err := a.repo.GetSitesByUser(oidcClaims.Email)
	if err != nil {
		log.WithField("func", "server.handleOIDCLogin").Warnf("successfull login by '%s' but error fetching sites! %v", oidcClaims.Email, err)
		success = false
	}

	if sites == nil || len(sites) == 0 {
		log.WithField("func", "server.handleOIDCLogin").Warnf("successfull login by '%s' but no sites availabel!", oidcClaims.Email)
		success = false
	}

	if authFlow {
		log.WithField("func", "server.handleOIDCLogin").Debugf("auth/flow - check for specific site '%s'", site)
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
		a.appCookie.Set(config.FlashKeyError, fmt.Sprintf("User '%s' is not allowed to login!", oidcClaims.Email), cookieExpiry, w)
		http.Redirect(w, r, "/error", http.StatusTemporaryRedirect)
		return nil
	}

	// create the token using the claims of the database
	var siteClaims []string
	for _, s := range sites {
		siteClaims = append(siteClaims, fmt.Sprintf("%s|%s|%s", s.Name, s.URL, s.PermList))
	}
	claims := sec.Claims{
		Type:        "login.User",
		DisplayName: oidcClaims.DisplayName,
		Email:       oidcClaims.Email,
		UserID:      oidcClaims.UserID,
		UserName:    oidcClaims.Email,
		GivenName:   oidcClaims.GivenName,
		Surname:     oidcClaims.FamilyName,
		Claims:      siteClaims,
	}
	token, err := sec.CreateToken(a.jwt.JwtIssuer, []byte(a.jwt.JwtSecret), a.jwt.Expiry, claims)
	if err != nil {
		log.WithField("func", "server.handleOIDCLogin").Errorf("could not create a JWT token: %v", err)
		return errors.ServerError{Err: fmt.Errorf("error creating JWT: %v", err), Request: r}
	}

	login := persistence.Login{
		User:    oidcClaims.Email,
		Created: time.Now().UTC(),
		Type:    persistence.DIRECT,
	}

	if authFlow {
		login.Type = persistence.FLOW
	}

	err = a.repo.StoreLogin(login, per.Atomic{})
	if err != nil {
		log.WithField("func", "server.handleOIDCLogin").Errorf("the login could not be saved: %v", err)
		return errors.ServerError{Err: fmt.Errorf("error storing the login: %v", err), Request: r}
	}

	// set the cookie
	exp := a.jwt.Expiry * 24 * 3600
	a.setJWTCookie(a.jwt.CookieName, token, exp, w)

	redirectURL := a.jwt.LoginRedirect
	if authFlow {
		log.WithField("func", "server.handleOIDCLogin").Debugf("auth/flow - redirect to specific URL: '%s'", redirect)
		redirectURL = redirect
	}

	// redirect to provided URL
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
	return nil
}

// handleLogout invalidates the authenticated user
func (a *API) handleLogout(user sec.User, w http.ResponseWriter, r *http.Request) error {
	log.WithField("func", "server.handleLogout").Debugf("for user '%s'", user.Username)
	// remove the cookie by expiring it
	a.setJWTCookie(a.jwt.CookieName, "", -1, w)
	a.appCookie.Set(config.FlashKeyInfo, fmt.Sprintf("User '%s' was logged-off!", user.Email), cookieExpiry, w)
	http.Redirect(w, r, a.jwt.LoginRedirect+config.ErrorPath, http.StatusTemporaryRedirect)
	return nil
}

func (a *API) setJWTCookie(name, value string, exp int, w http.ResponseWriter) {
	cookie := http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   a.jwt.CookieDomain,
		Path:     a.jwt.CookiePath,
		MaxAge:   exp, /* exp in seconds */
		Secure:   a.jwt.CookieSecure,
		HttpOnly: true, // only let the api access those cookies
	}
	http.SetCookie(w, &cookie)
}

func randToken() string {
	u := uuid.New()
	return u.String()
}

func query(r *http.Request, name string) string {
	keys, ok := r.URL.Query()[name]

	if !ok || len(keys[0]) < 1 {
		log.WithField("func", "server.getQuery").Debugf("Url Param '%s' is missing", name)
		return ""
	}

	return keys[0]
}
