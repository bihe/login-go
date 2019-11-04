package server

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"time"

	"github.com/bihe/login-go/internal/config"
	"github.com/bihe/login-go/internal/cookies"

	"github.com/coreos/go-oidc"
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
	msg = cookie.Get(config.FlashKeyError, r)
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
