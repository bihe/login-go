// +build prod

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/bihe/login-go/core"
	"github.com/gin-gonic/gin"

	log "github.com/sirupsen/logrus"
)

func setupLog(g *gin.Engine, config core.Configuration) {
	gin.DisableConsoleColor()
	f, _ := os.Create(config.Log.RequestPath)
	gin.DefaultWriter = io.MultiWriter(f)

	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
	var file *os.File
	file, err := os.OpenFile(config.Log.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(fmt.Sprintf("cannot use filepath '%s' as a logfile: %v", config.Log.FilePath, err))
	}
	log.SetOutput(file)
	level, err := log.ParseLevel(config.Log.LogLevel)
	if err != nil {
		panic(fmt.Sprintf("cannot use supplied level '%s' as a loglevel: %v", config.Log.LogLevel, err))
	}
	log.SetLevel(level)
}
