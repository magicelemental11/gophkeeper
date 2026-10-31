package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gophkeeper-bin")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "gophkeeper")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-ldflags", "-X github.com/magicelemental11/gophkeeper/internal/buildinfo.Version=v9.9.9", "-o", binary, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func TestBinaryVersion(t *testing.T) {
	out, err := exec.Command(binary, "version").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Build version: v9.9.9") {
		t.Fatalf("%s, %v", out, err)
	}
}

func TestBinaryExitCode(t *testing.T) {
	cmd := exec.Command(binary, "--data-dir", t.TempDir(), "list")
	cmd.Env = append(os.Environ(), "GOPHKEEPER_PASSWORD=whatever-pass")
	out, err := cmd.CombinedOutput()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 || !strings.Contains(string(out), "not logged in") {
		t.Fatalf("%s, %v", out, err)
	}
}
