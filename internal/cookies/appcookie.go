package cookies

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
)

// AppCookie is responsible for writing, reading cookies
type AppCookie struct {
	settings Settings
}

// NewAppCookie returns a new instance of type AppCookie
func NewAppCookie(c Settings) *AppCookie {
	return &AppCookie{settings: c}
}

// Set create a cookie with the given name and value and using the provided settings
func (a *AppCookie) Set(name, value string, expirySec int, w http.ResponseWriter) {
	cookieName := fmt.Sprintf("%s_%s", a.settings.Prefix, name)
	cookie := http.Cookie{
		Name:     cookieName,
		Value:    value,
		Domain:   a.settings.Domain,
		Path:     a.settings.Path,
		MaxAge:   expirySec,
		Secure:   a.settings.Secure,
		HttpOnly: true, // only let the api access those cookies
	}
	http.SetCookie(w, &cookie)
}

// Del removes the cookie by setting MaxAge to < 0
func (a *AppCookie) Del(name string, w http.ResponseWriter) {
	cookieName := fmt.Sprintf("%s_%s", a.settings.Prefix, name)
	cookie := http.Cookie{
		Name:     cookieName,
		Value:    "",
		Domain:   a.settings.Domain,
		Path:     a.settings.Path,
		MaxAge:   -1,
		Secure:   a.settings.Secure,
		HttpOnly: true, // only let the api access those cookies
	}
	http.SetCookie(w, &cookie)
}

// Get retrieves a cookie value
func (a *AppCookie) Get(name string, r *http.Request) string {
	var (
		cookie *http.Cookie
		err    error
	)
	cookieName := fmt.Sprintf("%s_%s", a.settings.Prefix, name)
	if cookie, err = r.Cookie(cookieName); err != nil {
		log.WithField("func", "cookies.Get").Debugf("could not read cookie '%s': %v\n", cookieName, err)
		return ""
	}
	return cookie.Value
}
