// Package config loads the server settings from environment variables and flags.
package config

import (
	"errors"
	"flag"
	"os"
	"strconv"
)

const defaultAddress = ":3200"

// Config holds the server settings.
type Config struct {
	Address     string
	DatabaseDSN string
	JWTSecret   string
	TLSCert     string
	TLSKey      string
	Insecure    bool // serve without TLS, for local tests only
}

// Load parses args into a Config. Precedence: environment variable, flag, default.
// The database DSN and JWT secret are required, and so are the TLS certificate and key unless Insecure is set.
func Load(args []string) (Config, error) {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	address := fs.String("a", defaultAddress, "listen address")
	dsn := fs.String("d", "", "PostgreSQL DSN (required)")
	secret := fs.String("j", "", "JWT signing secret (required)")
	cert := fs.String("tls-cert", "", "TLS certificate path")
	key := fs.String("tls-key", "", "TLS private key path")
	insecure := fs.Bool("insecure", false, "serve without TLS (local tests only)")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg := Config{
		Address:     envString("ADDRESS", *address),
		DatabaseDSN: envString("DATABASE_DSN", *dsn),
		JWTSecret:   envString("JWT_SECRET", *secret),
		TLSCert:     envString("TLS_CERT", *cert),
		TLSKey:      envString("TLS_KEY", *key),
		Insecure:    *insecure,
	}
	if v := os.Getenv("INSECURE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, errors.New("INSECURE must be true or false")
		}
		cfg.Insecure = b
	}

	switch {
	case cfg.DatabaseDSN == "":
		return Config{}, errors.New("database DSN is required (-d or DATABASE_DSN)")
	case cfg.JWTSecret == "":
		return Config{}, errors.New("JWT secret is required (-j or JWT_SECRET)")
	case !cfg.Insecure && (cfg.TLSCert == "" || cfg.TLSKey == ""):
		return Config{}, errors.New("TLS certificate and key are required (-tls-cert, -tls-key) unless -insecure is set")
	}
	return cfg, nil
}

func envString(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
