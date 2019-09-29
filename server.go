package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/bihe/login-go/api"
	"github.com/bihe/login-go/core"
	"github.com/bihe/login-go/persistence"
	"github.com/gin-gonic/gin"
)

var (
	// Version exports the application version
	Version = "2.0.0"
	// Build provides information about the application build
	Build = "20190926.211500"
	// Runtime specifies the golang version used
	Runtime = "golang"
)

// ServerArgs is uded to configure the API server
type ServerArgs struct {
	HostName   string
	Port       int
	ConfigFile string
}

func main() {
	api, addr := setupAPIServer()

	srv := &http.Server{
		Addr:    addr,
		Handler: api,
	}

	go func() {
		// service connections
		fmt.Printf("starting login.api (%s-%s)\n", Version, Build)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal)
	// kill (no param) default send syscall.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall.SIGKILL but can't be catch, so don't need add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}
	// catching ctx.Done(). timeout of 5 seconds.
	select {
	case <-ctx.Done():
		log.Println("timeout of 5 seconds.")
	}
	log.Println("Server exiting")

}

func parseFlags() *ServerArgs {
	c := new(ServerArgs)
	flag.StringVar(&c.HostName, "hostname", "localhost", "the server hostname")
	flag.IntVar(&c.Port, "port", 3000, "network port to listen")
	flag.StringVar(&c.ConfigFile, "c", "application.json", "path to the application c file")
	flag.Parse()
	return c
}

func configFromFile(configFileName string) core.Configuration {
	f, err := os.Open(configFileName)
	if err != nil {
		panic(fmt.Sprintf("Could not open specific config file '%s': %v", configFileName, err))
	}
	defer f.Close()

	c, err := core.GetSettings(f)
	if err != nil {
		panic(fmt.Sprintf("Could not get server config values from file '%s': %v", configFileName, err))
	}
	return *c
}

func setupAPIServer() (*gin.Engine, string) {
	args := parseFlags()
	c := configFromFile(args.ConfigFile)

	r := gin.New()
	setupLog(r, c)

	// Global middleware
	// Logger middleware will write the logs to gin.DefaultWriter even if you set with GIN_MODE=release.
	// By default gin.DefaultWriter = os.Stdout
	r.Use(gin.Logger())

	// Recovery middleware recovers from any panics and writes a 500 if there was one.
	r.Use(gin.Recovery())

	// kind of central error handling (@see labstack echo!)
	r.Use(core.ApplicationErrorReporter())

	// persistence store && application version
	version := core.VersionInfo{
		Version: Version,
		Build:   Build,
		Runtime: Runtime,
	}
	con := persistence.NewConn(c.DB.ConnStr)
	api.RegisterRoutes(r, c, version, con)

	return r, fmt.Sprintf("%s:%d", args.HostName, args.Port)
}
