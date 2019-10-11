package core

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

// CookieSettings defines parameters for cookies used for HTML-based errors
type CookieSettings struct {
	Path   string
	Domain string
	Secure bool
	Prefix string
}

// SetCookie create a cookie with the given name and value and using the provided settings
func SetCookie(name, value string, expiry int, cookie CookieSettings, c *gin.Context) {
	cookieName := fmt.Sprintf("%s_%s", cookie.Prefix, name)
	c.SetCookie(cookieName,
		value,
		expiry,
		cookie.Path,
		cookie.Domain,
		cookie.Secure,
		true /* http-only */)
}

// GetCookie retrieves a cookie value
func GetCookie(name string, cookie CookieSettings, c *gin.Context) string {
	cookieName := fmt.Sprintf("%s_%s", cookie.Prefix, name)
	value, _ := c.Cookie(cookieName)
	return value
}
