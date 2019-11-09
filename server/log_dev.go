// +build !prod

package server

import (
	"os"

	"github.com/bihe/login-go/internal/config"

	log "github.com/sirupsen/logrus"
)

func setupLog(config config.AppConfig) {

	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
}
