package core

import (
	"encoding/json"
	"io"
	"io/ioutil"
)

// Configuration holds the application configuration
type Configuration struct {
	Sec     Security      `json:"security"`
	DB      Database      `json:"database"`
	Log     LogConfig     `json:"logging"`
	OIDC    OAuthConfig   `json:"oidc"`
	Session SessionConfig `json:"session"`
}

// Security settings for the application
type Security struct {
	JwtIssuer     string `json:"jwtIssuer"`
	JwtSecret     string `json:"jwtSecret"`
	Expiry        int    `json:"expiry"`
	CookieName    string `json:"cookieName"`
	CookieDomain  string `json:"cookieDomain"`
	CookiePath    string `json:"cookiePath"`
	CookieSecure  bool   `json:"cookieSecure"`
	Claim         Claim  `json:"claim"`
	CacheDuration string `json:"cacheDuration"`
	LoginRedirect string `json:"loginRedirect"`
}

// Claim defines the required claims
type Claim struct {
	Name  string   `json:"name"`
	URL   string   `json:"url"`
	Roles []string `json:"roles"`
}

// Database defines the connection string
type Database struct {
	ConnStr string `json:"connectionString"`
}

// LogConfig is used to define settings for the logging process
type LogConfig struct {
	FilePath    string `json:"filePath"`
	RequestPath string `json:"requestPath"`
	LogLevel    string `json:"logLevel"`
}

// OAuthConfig is used to configure OAuth OpenID Connect
type OAuthConfig struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	RedirectURL  string `json:"redirectURL"`
	Provider     string `json:"provider"`
}

// SessionConfig configures cookie session storage
type SessionConfig struct {
	CookieName string `json:"cookieName"`
	Secret     string `json:"secret"`
}

// GetSettings returns application configuration values
func GetSettings(r io.Reader) (*Configuration, error) {
	var (
		c    Configuration
		cont []byte
		err  error
	)
	if cont, err = ioutil.ReadAll(r); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(cont, &c); err != nil {
		return nil, err
	}

	return &c, nil
}
