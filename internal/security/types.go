package security

import sec "github.com/bihe/commons-go/security"

// JwtOptions defines presets for the Authentication handler
// by the default the JWT token is fetched from the Authentication header
// as a fallback it is possible to fetch the token from a specific cookie
type JwtOptions struct {
	// JwtSecret is the jwt signing key
	JwtSecret string
	// JwtIssuer specifies identifies the principal that issued the token
	JwtIssuer string
	// CookieName spedifies the HTTP cookie holding the token
	CookieName string
	// RequiredClaim to access the application
	RequiredClaim sec.Claim
	// RedirectURL forwards the request to an external authentication service
	RedirectURL string
	// CacheDuration defines the duration to cache the JWT token result
	CacheDuration string
}
