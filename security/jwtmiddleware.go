package security

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/bihe/login-go/core"
	"github.com/gin-gonic/gin"
)

// JWTMiddleware is used to authenticate a user based on a token
// the token is either retrieved by the well known Authorization header
// or fetched from a cookie
func JWTMiddleware(options JwtOptions) gin.HandlerFunc {
	cache := newMemCache(parseDuration(options.CacheDuration))
	return handleJWT(options, cache)
}

func handleJWT(options JwtOptions, cache *memoryCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		var (
			err   error
			token string
		)

		authHeader := c.Request.Header.Get("Authorization")
		if authHeader != "" {
			token = strings.Replace(authHeader, "Bearer ", "", 1)
		}
		if token == "" {
			// fallback to get the token via the cookie
			if token, err = c.Cookie(options.CookieName); err != nil {
				// neither the header nor the cookie supplied a jwt token
				c.Error(core.RedirectError{
					Status:  http.StatusUnauthorized,
					Err:     fmt.Errorf("invalid authentication, no JWT token present"),
					Request: c.Request,
					URL:     options.RedirectURL + core.ErrorPath,
				})
				c.Abort()
				return
			}
		}

		// to speed up processing use the cache for token lookups
		var user User
		u := cache.get(token)
		if u != nil {
			// cache hit, put the user in the context
			log.Debug("Cache HIT!")
			c.Set(core.User, *u)
			c.Next()
			return
		}

		log.Debug("Cache MISS!")

		var payload JwtTokenPayload
		if payload, err = ParseJwtToken(token, options.JwtSecret, options.JwtIssuer); err != nil {
			log.Warnf("Could not decode the JWT token payload: %s", err)
			c.Error(core.RedirectError{
				Status:  http.StatusUnauthorized,
				Err:     fmt.Errorf("invalid authentication, could not parse the JWT token: %v", err),
				Request: c.Request,
				URL:     options.RedirectURL + core.ErrorPath,
			})
			c.Abort()
			return
		}
		var roles []string
		if roles, err = Authorize(options.RequiredClaim, payload.Claims); err != nil {
			log.Warnf("Insufficient permissions to access the resource: %s", err)
			c.Error(core.RedirectError{
				Status:  http.StatusForbidden,
				Err:     fmt.Errorf("Invalid authorization: %v", err),
				Request: c.Request,
				URL:     options.RedirectURL + core.ErrorPath,
			})
			c.Abort()
			return
		}

		user = User{
			DisplayName:   payload.DisplayName,
			Email:         payload.Email,
			Roles:         roles,
			UserID:        payload.UserID,
			Username:      payload.UserName,
			Authenticated: true,
		}
		cache.set(token, &user)
		c.Set(core.User, user)

		c.Next()
	}
}

func parseDuration(duration string) time.Duration {
	d, err := time.ParseDuration(duration)
	if err != nil {
		panic(fmt.Sprintf("wrong value, cannot parse duration: %v", err))
	}
	return d
}
