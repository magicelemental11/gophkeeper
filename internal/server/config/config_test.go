package config

import (
	"os"
	"testing"
)

func clearEnv(t *testing.T) {
	for _, n := range envNames {
		t.Setenv(n.env, "")
		os.Unsetenv(n.env)
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

func TestLoadEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv("ADDRESS", ":1")
	t.Setenv("DATABASE_DSN", "env-dsn")
	t.Setenv("JWT_SECRET", "env-secret")
	t.Setenv("TLS_CERT", "env.crt")
	t.Setenv("TLS_KEY", "env.key")
	cfg, err := Load(nil)
	want := Config{Address: ":1", DatabaseDSN: "env-dsn", JWTSecret: "env-secret", TLSCert: "env.crt", TLSKey: "env.key"}
	if err != nil || cfg != want {
		t.Fatalf("got %+v, %v", cfg, err)
	}
}

func TestLoadFlagsOverEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv("ADDRESS", ":1")
	t.Setenv("DATABASE_DSN", "env-dsn")
	t.Setenv("JWT_SECRET", "env-secret")
	cfg, err := Load(append([]string{"-a", ":2"}, required...))
	want := Config{Address: ":2", DatabaseDSN: "dsn", JWTSecret: "secret", TLSCert: "c.crt", TLSKey: "c.key"}
	if err != nil || cfg != want {
		t.Fatalf("got %+v, %v", cfg, err)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{"no dsn", []string{"-j", "s", "-tls-cert", "c", "-tls-key", "k"}, nil},
		{"no secret", []string{"-d", "dsn", "-tls-cert", "c", "-tls-key", "k"}, nil},
		{"no cert", []string{"-d", "dsn", "-j", "s", "-tls-key", "k"}, nil},
		{"no key", []string{"-d", "dsn", "-j", "s", "-tls-cert", "c"}, nil},
		{"unknown flag", []string{"-x"}, nil},
		{"empty env", required, map[string]string{"ADDRESS": ""}},
		{"empty dsn env", []string{"-j", "s", "-tls-cert", "c", "-tls-key", "k"}, map[string]string{"DATABASE_DSN": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			if _, err := Load(tt.args); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
