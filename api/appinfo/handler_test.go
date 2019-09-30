package appinfo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bihe/login-go/core"
	"github.com/bihe/login-go/security"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestGetAppInfo(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()

	version := core.VersionInfo{
		Version: "1",
		Build:   "2",
		Runtime: "r",
	}

	r.Use(func(c *gin.Context) {
		c.Set(core.User, security.User{
			Username:    "username",
			Email:       "a.b@c.de",
			DisplayName: "displayname",
			Roles:       []string{"role"},
			UserID:      "12345",
		})
	})

	aih := &Handler{VersionInfo: version}
	r.GET("/appinfo", aih.GetAppInfo)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/appinfo", nil)

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var m Meta
	err := json.Unmarshal(w.Body.Bytes(), &m)
	if err != nil {
		t.Errorf("could not get valid json: %v", err)
	}

	assert.Equal(t, "r", m.Runtime)
	assert.Equal(t, "1-2", m.Version)
}
