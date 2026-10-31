package config

import (
	"os"
	"testing"
)

func clearEnv(t *testing.T) {
	for _, name := range []string{"ADDRESS", "DATABASE_DSN", "JWT_SECRET", "TLS_CERT", "TLS_KEY", "INSECURE"} {
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
}

var required = []string{"-d", "dsn", "-j", "secret", "-tls-cert", "c.crt", "-tls-key", "c.key"}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)
	cfg, err := Load(required)
	want := Config{Address: ":3200", DatabaseDSN: "dsn", JWTSecret: "secret", TLSCert: "c.crt", TLSKey: "c.key"}
	if err != nil || cfg != want {
		t.Fatalf("got %+v, %v", cfg, err)
	}
}

func TestLoadEnvOverFlags(t *testing.T) {
	clearEnv(t)
	t.Setenv("ADDRESS", ":1")
	t.Setenv("DATABASE_DSN", "env-dsn")
	t.Setenv("JWT_SECRET", "env-secret")
	t.Setenv("TLS_CERT", "env.crt")
	t.Setenv("TLS_KEY", "env.key")
	cfg, err := Load(append([]string{"-a", ":2"}, required...))
	want := Config{Address: ":1", DatabaseDSN: "env-dsn", JWTSecret: "env-secret", TLSCert: "env.crt", TLSKey: "env.key"}
	if err != nil || cfg != want {
		t.Fatalf("got %+v, %v", cfg, err)
	}
}

func TestLoadInsecure(t *testing.T) {
	clearEnv(t)
	cfg, err := Load([]string{"-d", "dsn", "-j", "s", "-insecure"})
	if err != nil || !cfg.Insecure {
		t.Fatalf("got %+v, %v", cfg, err)
	}
	t.Setenv("INSECURE", "true")
	if cfg, err = Load([]string{"-d", "dsn", "-j", "s"}); err != nil || !cfg.Insecure {
		t.Fatalf("got %+v, %v", cfg, err)
	}
	t.Setenv("INSECURE", "maybe")
	if _, err = Load([]string{"-d", "dsn", "-j", "s"}); err == nil {
		t.Fatal("expected error for invalid INSECURE")
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no dsn", []string{"-j", "s", "-insecure"}},
		{"no secret", []string{"-d", "dsn", "-insecure"}},
		{"no cert", []string{"-d", "dsn", "-j", "s", "-tls-key", "k"}},
		{"no key", []string{"-d", "dsn", "-j", "s", "-tls-cert", "c"}},
		{"unknown flag", []string{"-x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			if _, err := Load(tt.args); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
