// +build !prod

package main

import (
	"os"

	"github.com/bihe/login-go/core"
	"github.com/gin-gonic/gin"

	log "github.com/sirupsen/logrus"
)

func setupLog(g *gin.Engine, config core.Configuration) {

	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
}
