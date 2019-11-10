package main

import (
	"fmt"
	"os"

	"github.com/bihe/login-go/server"
)

var (
	// Version exports the application version
	Version = "2.0.0"
	// Build provides information about the application build
	Build = "20190926.211500"
	// Runtime specifies the golang version used
	Runtime = "golang"
)

// @title login application
// @version 2.0
// @description The central login for all my applications

// @license.name Apache 2.0
// @license.url https://github.com/bihe/login-go/blob/master/LICENSE

func main() {
	if err := server.Run(Version, Build, Runtime); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
