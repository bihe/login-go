package security

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bihe/login-go/core"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const cookie = "cookie"
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4NzAzOTI2NDcsImp0aSI6IjZmYWQ1YzAwLWZlZTItNDU5Yy1hYmFkLTIwNDU3Y2ZmM2Q4YSIsImlhdCI6MTU1OTc4Nzg0NywiaXNzIjoiaXNzdWVyIiwic3ViIjoidXNlciIsIlR5cGUiOiJsb2dpbi5Vc2VyIiwiRGlzcGxheU5hbWUiOiJEaXNwbGF5IE5hbWUiLCJFbWFpbCI6ImEuYkBjLmRlIiwiVXNlcklkIjoiMTIzNDUiLCJVc2VyTmFtZSI6ImEuYkBjLmRlIiwiR2l2ZW5OYW1lIjoiRGlzcGxheSIsIlN1cm5hbWUiOiJOYW1lIiwiQ2xhaW1zIjpbImNsYWltfGh0dHA6Ly9sb2NhbGhvc3Q6MzAwMHxyb2xlIl19.qUwvHXBmV_FuwLtykOnzu3AMbxSqrg82bQlAi3Nabyo"
const path = "/JWT"
const unmarshall = "could not unmarshall problemdetails: %v"

var jwtOpts = JwtOptions{
	JwtSecret:  "secret",
	JwtIssuer:  "issuer",
	CookieName: cookie,
	RequiredClaim: Claim{
		Name:  "claim",
		URL:   "http://localhost:3000",
		Roles: []string{"role"},
	},
	RedirectURL:   "/redirect",
	CacheDuration: "10m",
}

func TestJWTMiddlewareCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, r := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(&http.Cookie{Name: cookie, Value: token})
	c.Request = req

	r.Use(JWTMiddleware(jwtOpts))

	r.GET(path, func(c *gin.Context) {
		return
	})
	r.ServeHTTP(rec, c.Request)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestJWTMiddlewareCookieAndCache(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, r := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(&http.Cookie{Name: cookie, Value: token})
	c.Request = req

	r.Use(JWTMiddleware(jwtOpts))

	r.GET(path, func(c *gin.Context) {
		return
	})
	r.ServeHTTP(rec, c.Request)
	r.ServeHTTP(rec, c.Request)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestJWTMiddlewareBearer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, r := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Add("Authorization", "Bearer "+token)
	c.Request = req

	r.Use(JWTMiddleware(jwtOpts))

	r.GET(path, func(c *gin.Context) {
		return
	})
	r.ServeHTTP(rec, c.Request)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestJWTMiddlewareNoToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, r := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	c.Request = req

	r.Use(core.ApplicationErrorReporter())
	r.Use(JWTMiddleware(jwtOpts))

	r.GET(path, func(c *gin.Context) {
		return
	})
	r.ServeHTTP(rec, c.Request)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var p core.ProblemDetail
	err := json.Unmarshal(rec.Body.Bytes(), &p)
	if err != nil {
		t.Errorf(unmarshall, err)
	}
	assert.Equal(t, http.StatusUnauthorized, p.Status)
}

func TestJWTMiddlewareWrongToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, r := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Add("Authorization", "Bearer "+"token")
	c.Request = req

	r.Use(core.ApplicationErrorReporter())
	r.Use(JWTMiddleware(jwtOpts))

	r.GET(path, func(c *gin.Context) {
		return
	})
	r.ServeHTTP(rec, c.Request)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var p core.ProblemDetail
	err := json.Unmarshal(rec.Body.Bytes(), &p)
	if err != nil {
		t.Errorf(unmarshall, err)
	}
	assert.Equal(t, http.StatusUnauthorized, p.Status)
}
