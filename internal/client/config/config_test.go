package config

import (
	"path/filepath"
	"testing"
)

func TestResolve(t *testing.T) {
	for _, name := range []string{EnvServer, EnvCA, EnvDataDir} {
		t.Setenv(name, "")
	}
	got := Resolve(Config{})
	if got.Server != DefaultServer || got.CA != "" || got.DataDir != DefaultDataDir() || filepath.Base(got.DataDir) != "gophkeeper" {
		t.Fatalf("defaults: %+v", got)
	}

	flags := Config{Server: "flag:1", CA: "flag.crt", DataDir: "/flag", Insecure: true}
	if got := Resolve(flags); got != flags {
		t.Fatalf("flags: %+v", got)
	}

	t.Setenv(EnvServer, "env:1")
	t.Setenv(EnvCA, "env.crt")
	t.Setenv(EnvDataDir, "/env")
	want := Config{Server: "env:1", CA: "env.crt", DataDir: "/env", Insecure: true}
	if got := Resolve(flags); got != want {
		t.Fatalf("env: %+v", got)
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
