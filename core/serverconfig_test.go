package core

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const configString = `{
	"security": {
		"jwtIssuer": "issuer",
		"jwtSecret": "secret",
		"expiry": 7,
		"cookieName": "cookie",
		"cookieDomain": "example.com",
		"cookiePath": "/",
		"cookieSecure": true
	},
	"database": {
		"connectionString": "./bookmarks.db"
    },
    "logging": {
		"filePath": "/temp/file",
		"requestPath": "/temp/request",
		"logLevel": "debug"
	},
	"oidc": {
		"clientID": "clientID",
		"clientSecret": "clientSecret",
		"redirectURL": "redirectURL"
	},
	"session": {
		"cookieName": "cookie",
		"secret": "secret",
		"provider": "provider"
	}
}`

// TestConfigReader reads config settings from json
func TestConfigReader(t *testing.T) {
	reader := strings.NewReader(configString)
	config, err := GetSettings(reader)
	if err != nil {
		t.Error("Could not read.", err)
	}

	assert.Equal(t, "issuer", config.Sec.JwtIssuer)
	assert.Equal(t, 7, config.Sec.Expiry)
	assert.Equal(t, "secret", config.Sec.JwtSecret)
	assert.Equal(t, "cookie", config.Sec.CookieName)
	assert.Equal(t, "example.com", config.Sec.CookieDomain)
	assert.Equal(t, "/", config.Sec.CookiePath)
	assert.Equal(t, true, config.Sec.CookieSecure)

	assert.Equal(t, "./bookmarks.db", config.DB.ConnStr)

	assert.Equal(t, "/temp/file", config.Log.FilePath)
	assert.Equal(t, "/temp/request", config.Log.RequestPath)
	assert.Equal(t, "debug", config.Log.LogLevel)

	assert.Equal(t, "clientID", config.OIDC.ClientID)
	assert.Equal(t, "clientSecret", config.OIDC.ClientSecret)
	assert.Equal(t, "redirectURL", config.OIDC.RedirectURL)

	assert.Equal(t, "cookie", config.Session.CookieName)
	assert.Equal(t, "secret", config.Session.Secret)
}
