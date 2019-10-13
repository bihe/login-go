package security

import "github.com/gin-gonic/gin"

// W wraps a function
func W(fn func(*AppContext)) gin.HandlerFunc {
	return func(c *gin.Context) {
		fn(&AppContext{c})
	}
}
