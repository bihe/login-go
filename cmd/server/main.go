package main

import (
	"fmt"
	"os"

	"github.com/bihe/login-go/server"
)

func main() {
	if err := server.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
