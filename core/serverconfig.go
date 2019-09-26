package core

import (
	"encoding/json"
	"io"
	"io/ioutil"
)

// Configuration holds the application configuration
type Configuration struct {
	DB  Database  `json:"database"`
	Log LogConfig `json:"logging"`
}

// Database defines the connection string
type Database struct {
	ConnStr string `json:"connectionString"`
}

// LogConfig is used to define settings for the logging process
type LogConfig struct {
	FilePath    string `json:"filePath"`
	RequestPath string `json:"requestPath"`
	LogLevel    string `json:"logLevel"`
}

// GetSettings returns application configuration values
func GetSettings(r io.Reader) (*Configuration, error) {
	var (
		c    Configuration
		cont []byte
		err  error
	)
	if cont, err = ioutil.ReadAll(r); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(cont, &c); err != nil {
		return nil, err
	}

	return &c, nil
}
