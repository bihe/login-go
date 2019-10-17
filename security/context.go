package security

import (
	sec "github.com/bihe/commons-go/security"
	"github.com/bihe/login-go/core"
	"github.com/gin-gonic/gin"
)

// AppContext implements an application specific context
type AppContext struct {
	*gin.Context
}

// User returns the currently loged-in User
func (a *AppContext) User() sec.User {
	return a.MustGet(core.User).(sec.User)

}

// HasRole checks if the current user has the given role
func (a *AppContext) HasRole(role string) bool {
	user := a.MustGet(core.User).(sec.User)
	for _, p := range user.Roles {
		if p == role {
			return true
		}
	}
	return false
}
