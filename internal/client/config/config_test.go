package config

import (
	"os"
	"path/filepath"
	"testing"
)

func clearEnv(t *testing.T) {
	for _, name := range []string{EnvServer, EnvCA, EnvDataDir, EnvPassword} {
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
}

func TestResolve(t *testing.T) {
	clearEnv(t)
	got, err := Resolve(Config{})
	if err != nil || got.Server != DefaultServer || got.CA != "" || got.DataDir != DefaultDataDir() || filepath.Base(got.DataDir) != "gophkeeper" {
		t.Fatalf("defaults: %+v, %v", got, err)
	}

	t.Setenv(EnvServer, "env:1")
	t.Setenv(EnvCA, "env.crt")
	t.Setenv(EnvDataDir, "/env")
	want := Config{Server: "env:1", CA: "env.crt", DataDir: "/env"}
	if got, err := Resolve(Config{}); err != nil || got != want {
		t.Fatalf("env: %+v, %v", got, err)
	}

	flags := Config{Server: "flag:1", CA: "flag.crt", DataDir: "/flag"}
	if got, err := Resolve(flags); err != nil || got != flags {
		t.Fatalf("flags over env: %+v, %v", got, err)
	}
}

func TestResolveEmptyEnv(t *testing.T) {
	for _, name := range []string{EnvServer, EnvCA, EnvDataDir} {
		t.Run(name, func(t *testing.T) {
			clearEnv(t)
			t.Setenv(name, "")
			if _, err := Resolve(Config{}); err == nil {
				t.Fatal("empty variable accepted")
			}
			if _, err := Resolve(Config{Server: "s", CA: "c", DataDir: "d"}); err != nil {
				t.Fatalf("flags given: %v", err)
			}
		})
	}
}

func TestPassword(t *testing.T) {
	clearEnv(t)
	if _, ok, err := Password(); ok || err != nil {
		t.Fatalf("unset: %v, %v", ok, err)
	}
	t.Setenv(EnvPassword, "secret")
	if p, ok, err := Password(); p != "secret" || !ok || err != nil {
		t.Fatalf("set: %q, %v, %v", p, ok, err)
	}
	t.Setenv(EnvPassword, "")
	if _, _, err := Password(); err == nil {
		t.Fatal("empty password accepted")
	}
}

func TestDefaultDataDirFallback(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("AppData", "")
	if DefaultDataDir() == "" {
		t.Fatal("empty data dir")
	}
}
