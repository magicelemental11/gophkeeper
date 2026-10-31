// Package config resolves the client settings from flags and environment variables.
package config

import (
	"os"
	"path/filepath"
)

// DefaultServer is the server address used when none is given.
const DefaultServer = "localhost:3200"

// Environment variables overriding the flags.
const (
	EnvServer   = "GOPHKEEPER_SERVER"
	EnvCA       = "GOPHKEEPER_CA"
	EnvDataDir  = "GOPHKEEPER_DATA_DIR"
	EnvPassword = "GOPHKEEPER_PASSWORD"
)

// Config holds the client settings.
type Config struct {
	Server   string
	CA       string // CA certificate path, empty to use the system roots
	DataDir  string
	Insecure bool // connect without TLS, for local tests only
}

// DefaultDataDir returns the gophkeeper directory inside the user configuration directory.
func DefaultDataDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ".gophkeeper"
	}
	return filepath.Join(dir, "gophkeeper")
}

// Resolve applies the precedence environment variable, flag, default to the flag values.
func Resolve(flags Config) Config {
	c := flags
	c.Server = pick(EnvServer, flags.Server, DefaultServer)
	c.CA = pick(EnvCA, flags.CA, "")
	c.DataDir = pick(EnvDataDir, flags.DataDir, "")
	if c.DataDir == "" {
		c.DataDir = DefaultDataDir()
	}
	return c
}

func pick(env, flag, fallback string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	if flag != "" {
		return flag
	}
	return fallback
}
