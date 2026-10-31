package store

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/uuid"
)

func TestSession(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if _, err := LoadSession(dir); !errors.Is(err, ErrNoSession) {
		t.Fatalf("empty dir: %v", err)
	}
	want := Session{Server: "s:1", Login: "alice", Token: "t", Revision: 5, Check: []byte{1}}
	if err := SaveSession(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSession(dir)
	if err != nil || got.Server != want.Server || got.Login != want.Login || got.Token != want.Token || got.Revision != 5 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if err := ClearSession(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSession(dir); !errors.Is(err, ErrNoSession) {
		t.Fatalf("after clear: %v", err)
	}
	if err := ClearSession(dir); err != nil {
		t.Fatalf("second clear: %v", err)
	}
}

func TestCache(t *testing.T) {
	dir := t.TempDir()
	c, err := LoadCache(dir, "s:1", "alice")
	if err != nil || len(c.Entries) != 0 {
		t.Fatalf("empty: %+v, %v", c, err)
	}
	a, b := uuid.New(), uuid.New()
	c.Put(a, Entry{Version: 1, Payload: []byte("a")})
	c.Put(b, Entry{Dirty: true, Payload: []byte("b")})
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}

	c, err = LoadCache(dir, "s:1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := c.Get(a); !ok || e.Version != 1 || string(e.Payload) != "a" {
		t.Fatalf("a: %+v", e)
	}
	if d := c.Dirty(); len(d) != 1 || d[0] != b {
		t.Fatalf("dirty: %v", d)
	}
	c.Remove(a)
	if _, ok := c.Get(a); ok {
		t.Fatal("removed entry found")
	}

	for _, other := range [][2]string{{"s:2", "alice"}, {"s:1", "bob"}} {
		c, err := LoadCache(dir, other[0], other[1])
		if err != nil || len(c.Entries) != 0 {
			t.Fatalf("%v: %+v, %v", other, c.Entries, err)
		}
	}
}

func TestCorruptedFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{SessionFile, CacheFile} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{broken"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadSession(dir); err == nil {
		t.Error("broken session loaded")
	}
	if _, err := LoadCache(dir, "s", "l"); err == nil {
		t.Error("broken cache loaded")
	}
}

func TestPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not enforced on Windows")
	}
	dir := filepath.Join(t.TempDir(), "data")
	if err := SaveSession(dir, Session{Login: "a"}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v, %v", fi.Mode().Perm(), err)
	}
	if fi, err := os.Stat(filepath.Join(dir, SessionFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v, %v", fi.Mode().Perm(), err)
	}
}

func TestAtomicWriteKeepsOldFileOnError(t *testing.T) {
	dir := t.TempDir()
	if err := writeFileAtomic(dir, "f", []byte("old")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "sub")
	if err := os.MkdirAll(filepath.Join(target, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(dir, "sub", []byte("new")); err == nil {
		t.Fatal("rename over a directory succeeded")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("temp file left behind: %v", entries)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "f")); string(data) != "old" {
		t.Fatalf("old file changed: %q", data)
	}
	if err := writeFileAtomic(filepath.Join(dir, "f", "nested"), "x", nil); err == nil {
		t.Fatal("write under a file succeeded")
	}
}
