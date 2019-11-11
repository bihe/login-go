package server

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-chi/chi"
	_ "github.com/go-sql-driver/mysql" // import the mysql driver

	"github.com/bihe/commons-go/cookies"
	"github.com/bihe/commons-go/security"
	"github.com/bihe/login-go/internal"
	"github.com/bihe/login-go/internal/config"
	"github.com/bihe/login-go/internal/persistence"

	"github.com/bihe/login-go/server/api"
	"github.com/wangii/emoji"

	per "github.com/bihe/commons-go/persistence"
	log "github.com/sirupsen/logrus"
)

// Args is uded to configure the API server
type Args struct {
	HostName   string
	Port       int
	ConfigFile string
	BasePath   string
}

// Run configures and starts the Server
func Run(version, build, runtime string) (err error) {
	srv := setupServer(version, build, runtime)
	go func() {
		fmt.Printf("%s Starting server ...\n", emoji.EmojiTagToUnicode(`:rocket:`))
		fmt.Printf("%s Listening on '%s'\n", emoji.EmojiTagToUnicode(`:computer:`), srv.Addr)
		fmt.Printf("%s Version: '%s-%s'\n", emoji.EmojiTagToUnicode(`:bookmark:`), version, build)
		fmt.Printf("%s Runtime: '%s'\n", emoji.EmojiTagToUnicode(`:hamster:`), runtime)
		fmt.Printf("%s Ready!\n", emoji.EmojiTagToUnicode(`:checkered_flag:`))
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			return
		}
	}()
	return graceful(srv, 5*time.Second)
}

// --------------------------------------------------------------------------
// internal logic / helpers
// --------------------------------------------------------------------------

type server struct {
	router chi.Router
}

func setupServer(version, build, runtime string) *http.Server {
	v := internal.VersionInfo{
		Version: version,
		Build:   build,
		Runtime: runtime,
	}

	args := parseFlags()
	config := configFromFile(args.ConfigFile)

	apiSrv := createServer(args.BasePath, config, v)
	setupLog(config)
	log.SetLevel(log.DebugLevel)
	addr := fmt.Sprintf("%s:%d", args.HostName, args.Port)
	srv := &http.Server{Addr: addr, Handler: apiSrv.router}
	return srv
}

func createServer(basePath string, config config.AppConfig, version internal.VersionInfo) *server {
	base, err := filepath.Abs(basePath)
	if err != nil {
		panic(fmt.Sprintf("cannot resolve basepath '%s', %v", basePath, err))
	}

	// configure JWT authentication and use JWT middleware
	jwtOpts := security.JwtOptions{
		JwtSecret:  config.Sec.JwtSecret,
		JwtIssuer:  config.Sec.JwtIssuer,
		CookieName: config.Sec.CookieName,
		RequiredClaim: security.Claim{
			Name:  config.Sec.Claim.Name,
			URL:   config.Sec.Claim.URL,
			Roles: config.Sec.Claim.Roles,
		},
		RedirectURL:   config.Sec.LoginRedirect,
		CacheDuration: config.Sec.CacheDuration,
	}
	cookieSettings := cookies.Settings{
		Path:   config.AppCookies.Path,
		Domain: config.AppCookies.Domain,
		Secure: config.AppCookies.Secure,
		Prefix: config.AppCookies.Prefix,
	}
	con := per.NewConn(config.DB.ConnStr)
	repo, err := persistence.NewRepository(con)
	if err != nil {
		panic(fmt.Sprintf("could not create a repository: %v", err))
	}

	apiSrv := api.New(base, cookieSettings, version, config.OIDC, config.Sec, repo)

	return &server{
		router: NewRouter(base, apiSrv, cookieSettings, jwtOpts),
	}
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
	if !fileExists(configFileName) {
		// if the given filename does not exists, use the filename from an environment variable
		// if that fails as well, the logic will panic below
		configFileName = os.Getenv("CONFIG_FILE_NAME")
	}
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

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return true
}
