// Package config loads the server settings from flags and environment variables.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

const defaultAddress = ":3200"

// Config holds the server settings.
type Config struct {
	Address     string
	DatabaseDSN string
	JWTSecret   string
	TLSCert     string
	TLSKey      string
}

var envNames = []struct{ flag, env string }{
	{"a", "ADDRESS"},
	{"d", "DATABASE_DSN"},
	{"j", "JWT_SECRET"},
	{"tls-cert", "TLS_CERT"},
	{"tls-key", "TLS_KEY"},
}

// Load parses args into a Config. Precedence: flag, environment variable, default.
// An environment variable that is set but empty is an error. The database DSN, JWT secret,
// TLS certificate and key are required.
func Load(args []string) (Config, error) {
	var cfg Config
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.StringVar(&cfg.Address, "a", defaultAddress, "listen address (env ADDRESS)")
	fs.StringVar(&cfg.DatabaseDSN, "d", "", "PostgreSQL DSN, required (env DATABASE_DSN)")
	fs.StringVar(&cfg.JWTSecret, "j", "", "JWT signing secret, required (env JWT_SECRET)")
	fs.StringVar(&cfg.TLSCert, "tls-cert", "", "TLS certificate path, required (env TLS_CERT)")
	fs.StringVar(&cfg.TLSKey, "tls-key", "", "TLS private key path, required (env TLS_KEY)")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for _, n := range envNames {
		if set[n.flag] {
			continue
		}
		v, ok := os.LookupEnv(n.env)
		if !ok {
			continue
		}
		if v == "" {
			return Config{}, fmt.Errorf("%s is set but empty", n.env)
		}
		if err := fs.Set(n.flag, v); err != nil {
			return Config{}, err
		}
	}

	switch {
	case cfg.DatabaseDSN == "":
		return Config{}, errors.New("database DSN is required (-d or DATABASE_DSN)")
	case cfg.JWTSecret == "":
		return Config{}, errors.New("JWT secret is required (-j or JWT_SECRET)")
	case cfg.TLSCert == "" || cfg.TLSKey == "":
		return Config{}, errors.New("TLS certificate and key are required (-tls-cert and -tls-key, or TLS_CERT and TLS_KEY)")
	}
	return cfg, nil
}
