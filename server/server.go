package server

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bihe/login-go/internal"
	"github.com/bihe/login-go/internal/config"
	"github.com/wangii/emoji"

	log "github.com/sirupsen/logrus"
)

var (
	// Version exports the application version
	Version = "2.0.0"
	// Build provides information about the application build
	Build = "20190926.211500"
	// Runtime specifies the golang version used
	Runtime = "golang"
)

// Args is uded to configure the API server
type Args struct {
	HostName   string
	Port       int
	ConfigFile string
	BasePath   string
}

// Run configures and starts the Server
func Run() (err error) {
	srv := setupServer()
	go func() {
		log.Printf("%s Starting server ...", emoji.EmojiTagToUnicode(`:rocket:`))
		log.Printf("%s Listening on '%s'", emoji.EmojiTagToUnicode(`:computer:`), srv.Addr)
		log.Printf("%s Version: '%s-%s'\n", emoji.EmojiTagToUnicode(`:bookmark:`), Version, Build)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			return
		}
	}()
	return graceful(srv, 5*time.Second)
}

// --------------------------------------------------------------------------
// internal logic / helpers
// --------------------------------------------------------------------------

func setupServer() *http.Server {
	args := parseFlags()
	config := configFromFile(args.ConfigFile)
	version := internal.VersionInfo{
		Version: Version,
		Build:   Build,
		Runtime: Runtime,
	}
	r := NewRouter(args.BasePath, config, version)
	//setupLog(r, c)
	addr := fmt.Sprintf("%s:%d", args.HostName, args.Port)
	srv := &http.Server{Addr: addr, Handler: r}
	return srv
}

func graceful(s *http.Server, timeout time.Duration) error {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	log.Infof("\nShutdown with timeout: %s\n", timeout)
	if err := s.Shutdown(ctx); err != nil {
		return err
	}

	log.Info("Server stopped")
	return nil
}

func parseFlags() *Args {
	c := new(Args)
	flag.StringVar(&c.HostName, "hostname", "localhost", "the server hostname")
	flag.IntVar(&c.Port, "port", 3000, "network port to listen")
	flag.StringVar(&c.BasePath, "b", "./", "the base path of the appliction")
	flag.StringVar(&c.ConfigFile, "c", "application.json", "path to the application c file")
	flag.Parse()
	return c
}

func configFromFile(configFileName string) config.AppConfig {
	f, err := os.Open(configFileName)
	if err != nil {
		panic(fmt.Sprintf("Could not open specific config file '%s': %v", configFileName, err))
	}
	defer f.Close()

	c, err := config.Read(f)
	if err != nil {
		panic(fmt.Sprintf("Could not get server config values from file '%s': %v", configFileName, err))
	}
	return *c
}
