package api_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/magicelemental11/gophkeeper/internal/client/api"
	"github.com/magicelemental11/gophkeeper/internal/testserver"
)

var key = bytes.Repeat([]byte{1}, 32)

func TestClient(t *testing.T) {
	srv := testserver.Start(t)
	c := srv.Dial(t)
	ctx := context.Background()

	tok, err := c.Register(ctx, "alice", key)
	if err != nil || tok == "" {
		t.Fatalf("register: %v", err)
	}
	if _, err := c.Register(ctx, "alice", key); !errors.Is(err, api.ErrLoginTaken) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := c.Login(ctx, "alice", bytes.Repeat([]byte{2}, 32)); !errors.Is(err, api.ErrUnauthenticated) {
		t.Fatalf("bad login: %v", err)
	}
	if _, err := c.Login(ctx, "a", key); err == nil || errors.Is(err, api.ErrUnauthenticated) {
		t.Fatalf("invalid login: %v", err)
	}
	if _, _, _, err := c.Sync(ctx, 0); !errors.Is(err, api.ErrUnauthenticated) {
		t.Fatalf("sync without token: %v", err)
	}
	if tok, err = c.Login(ctx, "alice", key); err != nil {
		t.Fatal(err)
	}
	c.SetToken(tok)

	id := uuid.New()
	it, err := c.Upsert(ctx, id, 0, []byte("v1"))
	if err != nil || it.ID != id || it.Version != 1 || it.UpdatedAt.IsZero() {
		t.Fatalf("upsert: %+v, %v", it, err)
	}
	var conflict *api.ConflictError
	if _, err := c.Upsert(ctx, id, 0, []byte("v2")); !errors.As(err, &conflict) || string(conflict.Current.Payload) != "v1" {
		t.Fatalf("conflict: %v", err)
	}
	if conflict.Error() == "" {
		t.Fatal("empty conflict text")
	}
	if got, err := c.Get(ctx, id); err != nil || string(got.Payload) != "v1" {
		t.Fatalf("get: %+v, %v", got, err)
	}
	if _, err := c.Get(ctx, uuid.New()); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	if del, err := c.Delete(ctx, id, 1); err != nil || !del.Deleted {
		t.Fatalf("delete: %+v, %v", del, err)
	}
	items, rev, more, err := c.Sync(ctx, 0)
	if err != nil || more || rev != 2 || len(items) != 1 || !items[0].Deleted {
		t.Fatalf("sync: %+v, %d, %v", items, rev, err)
	}

	srv.Down()
	if _, _, _, err := c.Sync(ctx, 0); !errors.Is(err, api.ErrUnavailable) {
		t.Fatalf("down: %v", err)
	}
}

func TestDial(t *testing.T) {
	c, err := api.Dial("localhost:1", "", false)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := api.Dial("localhost:1", filepath.Join(t.TempDir(), "missing.crt"), false); err == nil {
		t.Fatal("missing CA accepted")
	}
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Dial("localhost:1", ca, false); err == nil {
		t.Fatal("bad CA accepted")
	}
	if _, err := api.Dial("bad\x00addr", "", true); err == nil {
		t.Fatal("bad address accepted")
	}
}
