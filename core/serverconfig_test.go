package core

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const configString = `{
    "database": {
		"connectionString": "./bookmarks.db"
    },
    "logging": {
		"filePath": "/temp/file",
		"requestPath": "/temp/request",
		"logLevel": "debug"
    }
}`

// TestConfigReader reads config settings from json
func TestConfigReader(t *testing.T) {
	reader := strings.NewReader(configString)
	config, err := GetSettings(reader)
	if err != nil {
		t.Error("Could not read.", err)
	}

	assert.Equal(t, "./bookmarks.db", config.DB.ConnStr)

	assert.Equal(t, "/temp/file", config.Log.FilePath)
	assert.Equal(t, "/temp/request", config.Log.RequestPath)
	assert.Equal(t, "debug", config.Log.LogLevel)
}
