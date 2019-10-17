package security

import (
	"net/http/httptest"
	"testing"

	"github.com/bihe/login-go/core"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	sec "github.com/bihe/commons-go/security"
)

func TestUserInContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Set(core.User, sec.User{
		Username:    "username",
		Email:       "a.b@c.de",
		DisplayName: "displayname",
		Roles:       []string{"role"},
		UserID:      "12345",
	})

	ctxt := &AppContext{c}
	u := ctxt.User()
	if u.Username != "username" {
		t.Errorf("could not get user from context")
	}
}

func TestUserFail(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)

	ctxt := &AppContext{c}
	assert.Panics(t, func() { ctxt.User() }, "no user in context - should panic")
}

func TestUserHasRole(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Set(core.User, sec.User{
		Username:    "username",
		Email:       "a.b@c.de",
		DisplayName: "displayname",
		Roles:       []string{"role1", "role2"},
		UserID:      "12345",
	})

	ctxt := &AppContext{c}
	if ctxt.HasRole("role1") == false {
		t.Errorf("User role is not found: role1")
	}
	if ctxt.HasRole("role2") == false {
		t.Errorf("User role is not found: role1")
	}
	if ctxt.HasRole("role") == true {
		t.Errorf("User does not have role: role")
	}
}
