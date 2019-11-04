package security

import (
	"context"

	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bihe/login-go/internal/config"
	"github.com/bihe/login-go/internal/cookies"
	"github.com/bihe/login-go/internal/errors"

	sec "github.com/bihe/commons-go/security"
	log "github.com/sirupsen/logrus"
)

// JwtMiddleware is used to authenticate a user based on a token
// the token is either retrieved by the well known Authorization header
// or fetched from a cookie
type JwtMiddleware struct {
	jwt    JwtOptions
	errRep *errors.ErrorReporter
}

// NewJwtMiddleware creates a new instance using the provided options
func NewJwtMiddleware(options JwtOptions, settings cookies.Settings) *JwtMiddleware {
	m := JwtMiddleware{
		jwt:    options,
		errRep: errors.NewReporter(settings),
	}
	return &m
}

// JwtContext performs the middleware action
func (j *JwtMiddleware) JwtContext(next http.Handler) http.Handler {
	return handleJWT(next, j.jwt, j.errRep)
}

func handleJWT(next http.Handler, options JwtOptions, errRep *errors.ErrorReporter) http.Handler {
	cache := sec.NewMemCache(parseDuration(options.CacheDuration))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			err   error
			token string
		)

		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			token = strings.Replace(authHeader, "Bearer ", "", 1)
		}
		if token == "" {
			// fallback to get the token via the cookie
			var cookie *http.Cookie
			if cookie, err = r.Cookie(options.CookieName); err != nil {
				log.WithField("func", "security.handleJWT").Warnf("could not get token from header nor cookie: %v", err)
				// neither the header nor the cookie supplied a jwt token
				errRep.Negotiate(w, r, errors.RedirectError{
					Status:  http.StatusUnauthorized,
					Err:     fmt.Errorf("invalid authentication, no JWT token present"),
					Request: r,
					URL:     options.RedirectURL + config.ErrorPath,
				})
				return
			}

			token = cookie.Value
		}

		// to speed up processing use the cache for token lookups
		var user sec.User
		u := cache.Get(token)
		if u != nil {
			// cache hit, put the user in the context
			ctx := context.WithValue(r.Context(), config.User, u)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		var payload sec.JwtTokenPayload
		if payload, err = sec.ParseJwtToken(token, options.JwtSecret, options.JwtIssuer); err != nil {
			log.WithField("func", "security.handleJWT").Warnf("Could not decode the JWT token payload: %s", err)
			errRep.Negotiate(w, r, errors.RedirectError{
				Status:  http.StatusUnauthorized,
				Err:     fmt.Errorf("invalid authentication, could not parse the JWT token: %v", err),
				Request: r,
				URL:     options.RedirectURL + config.ErrorPath,
			})
			return
		}
		var roles []string
		claim := options.RequiredClaim
		if roles, err = sec.Authorize(sec.Claim{Name: claim.Name, URL: claim.URL, Roles: claim.Roles}, payload.Claims); err != nil {
			log.WithField("func", "security.handleJWT").Warnf("Insufficient permissions to access the resource: %s", err)
			errRep.Negotiate(w, r, errors.RedirectError{
				Status:  http.StatusForbidden,
				Err:     fmt.Errorf("Invalid authorization: %v", err),
				Request: r,
				URL:     options.RedirectURL + config.ErrorPath,
			})
			return
		}

		user = sec.User{
			DisplayName:   payload.DisplayName,
			Email:         payload.Email,
			Roles:         roles,
			UserID:        payload.UserID,
			Username:      payload.UserName,
			Authenticated: true,
		}
		cache.Set(token, &user)

		ctx := context.WithValue(r.Context(), config.User, &user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func parseDuration(duration string) time.Duration {
	d, err := time.ParseDuration(duration)
	if err != nil {
		panic(fmt.Sprintf("wrong value, cannot parse duration: %v", err))
	}
	return d
}
