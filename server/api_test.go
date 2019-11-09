package server

import (
	sec "github.com/bihe/commons-go/security"
	"github.com/bihe/login-go/internal"
	"github.com/bihe/login-go/internal/config"
	"github.com/bihe/login-go/internal/cookies"
	"github.com/bihe/login-go/internal/security"
)

// package wide test-data

const state = "S"
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5NzE0MDkyNzQsImp0aSI6IjUwN2MwZjRhLThmMGYtNDZlMC1kZGRkLTM3NDZmOTExMmQ1ZSIsImlhdCI6MTQ3MDgwNDQ3NCwiaXNzIjoiaXNzdWVyIiwic3ViIjoiYS5iQGMuZGUiLCJUeXBlIjoibG9naW4uVXNlciIsIkRpc3BsYXlOYW1lIjoiTmFtZSIsIkVtYWlsIjoiYS5iQGMuZGUiLCJVc2VySWQiOiIxMjM0IiwiVXNlck5hbWUiOiJhYmMiLCJHaXZlbk5hbWUiOiJhIiwiU3VybmFtZSI6ImIiLCJDbGFpbXMiOlsiY2xhaW18aHR0cDovL2xvY2FsaG9zdDozMDAwfHJvbGUiXX0.oRsKGYJhO2Fe972TgRn65AbMqCHAghxBA4qN5IQFYkw"
const signIn = "/signin"
const signInURL = "/signin?%s=%s"
const errorPath = "/error"

var stateCookieName = cookieSettings.Prefix + "_" + stateParam
var authFlowCookieName = cookieSettings.Prefix + "_" + authFlowCookie

var oauthConfig = config.OAuthConfig{
	ClientID:     "CLIENTID",
	ClientSecret: "SECRET",
	RedirectURL:  "http://localhost",
	Provider:     "https://accounts.google.com",
}

var jwtConfig = config.Security{
	JwtIssuer:    "issuer",
	JwtSecret:    "secret",
	Expiry:       1,
	CookieName:   "cookie",
	CookieDomain: "localhost",
	CookiePath:   "/",
	CookieSecure: false,
}

var version = internal.VersionInfo{
	Version: "1",
	Build:   "2",
	Runtime: "r",
}

var cookieSettings = cookies.Settings{
	Path:   "/",
	Domain: "localhost",
	Secure: false,
	Prefix: "test",
}

var jwtOpts = security.JwtOptions{
	JwtSecret:  jwtConfig.JwtSecret,
	JwtIssuer:  jwtConfig.JwtIssuer,
	CookieName: jwtConfig.CookieName,
	RequiredClaim: sec.Claim{
		Name:  "claim",
		URL:   "http://localhost:3000",
		Roles: []string{"role"},
	},
	RedirectURL:   "/redirect",
	CacheDuration: "10m",
}
