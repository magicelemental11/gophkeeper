// Package config resolves the client settings from flags and environment variables.
package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// DefaultServer is the server address used when none is given.
const DefaultServer = "localhost:3200"

// Environment variables used when the matching flag is not given.
const (
	EnvServer   = "GOPHKEEPER_SERVER"
	EnvCA       = "GOPHKEEPER_CA"
	EnvDataDir  = "GOPHKEEPER_DATA_DIR"
	EnvPassword = "GOPHKEEPER_PASSWORD"
)

// Config holds the client settings. An empty field of the flag values passed to Resolve means the flag
// was not given.
type Config struct {
	Server  string
	CA      string // CA certificate path, empty to use the system roots
	DataDir string
}

// DefaultDataDir returns the gophkeeper directory inside the user configuration directory.
func DefaultDataDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ".gophkeeper"
	}
	return filepath.Join(dir, "gophkeeper")
}

// Resolve applies the precedence flag, environment variable, default to the flag values.
// An environment variable that is set but empty is an error.
func Resolve(flags Config) (Config, error) {
	var c Config
	var err error
	if c.Server, err = pick(flags.Server, EnvServer, DefaultServer); err != nil {
		return Config{}, err
	}
	if c.CA, err = pick(flags.CA, EnvCA, ""); err != nil {
		return Config{}, err
	}
	if c.DataDir, err = pick(flags.DataDir, EnvDataDir, ""); err != nil {
		return Config{}, err
	}
	if c.DataDir == "" {
		c.DataDir = DefaultDataDir()
	}
	return c, nil
}

// Password returns the master password from GOPHKEEPER_PASSWORD and whether the variable is set.
// A set but empty variable is an error.
func Password() (string, bool, error) {
	return lookupNonEmpty(EnvPassword)
}

func pick(flag, env, fallback string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	v, ok, err := lookupNonEmpty(env)
	if err != nil {
		return "", err
	}
	if ok {
		return v, nil
	}
	return fallback, nil
}

func lookupNonEmpty(env string) (string, bool, error) {
	v, ok := os.LookupEnv(env)
	if ok && v == "" {
		return "", false, fmt.Errorf("%s is set but empty", env)
	}
	return v, ok, nil
}
