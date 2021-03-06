package api

import (
	"github.com/bihe/commons-go/cookies"
	"github.com/bihe/commons-go/errors"
	"github.com/bihe/commons-go/handler"
	"github.com/bihe/commons-go/security"
	"github.com/bihe/login-go/internal"
	"github.com/bihe/login-go/internal/config"
	"github.com/bihe/login-go/internal/persistence"

	per "github.com/bihe/commons-go/persistence"
)

// package wide test-data

const state = "S"
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5NzE0MDkyNzQsImp0aSI6IjUwN2MwZjRhLThmMGYtNDZlMC1kZGRkLTM3NDZmOTExMmQ1ZSIsImlhdCI6MTQ3MDgwNDQ3NCwiaXNzIjoiaXNzdWVyIiwic3ViIjoiYS5iQGMuZGUiLCJUeXBlIjoibG9naW4uVXNlciIsIkRpc3BsYXlOYW1lIjoiTmFtZSIsIkVtYWlsIjoiYS5iQGMuZGUiLCJVc2VySWQiOiIxMjM0IiwiVXNlck5hbWUiOiJhYmMiLCJHaXZlbk5hbWUiOiJhIiwiU3VybmFtZSI6ImIiLCJDbGFpbXMiOlsiY2xhaW18aHR0cDovL2xvY2FsaG9zdDozMDAwfHJvbGUiXX0.oRsKGYJhO2Fe972TgRn65AbMqCHAghxBA4qN5IQFYkw"
const signIn = "/signin"
const signInURL = "/signin?%s=%s"

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
	Claim: config.Claim{
		Name:  "claim",
		URL:   "http://localhost:3000",
		Roles: []string{"role"},
	},
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
	RequiredClaim: security.Claim{
		Name:  "claim",
		URL:   "http://localhost:3000",
		Roles: []string{"role"},
	},
	RedirectURL:   "/redirect",
	CacheDuration: "10m",
}

// common components necessary for handlers
var baseHandler = handler.Handler{
	ErrRep: &errors.ErrorReporter{
		CookieSettings: cookies.Settings{
			Path:   "/",
			Domain: "localhost",
		},
		ErrorPath: "error",
	},
}

// --------------------------------------------------------------------------
// mock repository
// --------------------------------------------------------------------------

/*
	CreateAtomic() (Atomic, error)
	GetSitesByUser(user string) ([]UserSite, error)
	StoreSiteForUser(user string, sites []UserSite, a Atomic) (err error)
	StoreLogin(login Login, a Atomic) (err error)
	GetUsersForSite(site string) ([]string, error)
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
	if m.fail {
		return Err
	}
	return nil
}

func (m *mockRepository) StoreLogin(login persistence.Login, a per.Atomic) (err error) {
	if m.fail {
		return Err
	}
	return nil
}

func (m *mockRepository) GetUsersForSite(site string) ([]string, error) {
	if m.fail {
		return nil, Err
	}

	return []string{
		"user1",
		"user2",
	}, nil
}
