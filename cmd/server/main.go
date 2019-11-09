package main

import (
	"fmt"
	"os"

	"github.com/bihe/login-go/server"
)

// @title login application
// @version 2.0
// @description The central login for all my applications

// @license.name Apache 2.0
// @license.url https://github.com/bihe/login-go/blob/master/LICENSE

func main() {
	if err := server.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
