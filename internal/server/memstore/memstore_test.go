package memstore

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/magicelemental11/gophkeeper/internal/server/storage"
)

func TestStore(t *testing.T) {
	ctx := context.Background()
	s := New()
	alice, err := s.CreateUser(ctx, "alice", "h")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "alice", "h"); !errors.Is(err, storage.ErrLoginTaken) {
		t.Fatalf("duplicate: %v", err)
	}
	if u, err := s.UserByLogin(ctx, "alice"); err != nil || u.ID != alice {
		t.Fatalf("by login: %+v, %v", u, err)
	}
	if _, err := s.UserByLogin(ctx, "bob"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}

	a, b := uuid.New(), uuid.New()
	if _, err := s.Upsert(ctx, alice, a, 1, []byte("x")); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	if it, err := s.Upsert(ctx, alice, a, 0, []byte("a1")); err != nil || it.Version != 1 || it.Revision != 1 {
		t.Fatalf("create: %+v, %v", it, err)
	}
	var conflict *storage.ConflictError
	if _, err := s.Upsert(ctx, alice, a, 0, []byte("a1")); !errors.As(err, &conflict) {
		t.Fatalf("conflict: %v", err)
	}
	if _, err := s.Upsert(ctx, alice, b, 0, []byte("b1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Delete(ctx, alice, a, 5); !errors.As(err, &conflict) {
		t.Fatalf("delete conflict: %v", err)
	}
	if it, err := s.Delete(ctx, alice, a, 1); err != nil || !it.Deleted || it.Revision != 3 {
		t.Fatalf("delete: %+v, %v", it, err)
	}
	if it, err := s.Delete(ctx, alice, a, 0); err != nil || it.Revision != 3 {
		t.Fatalf("repeat delete: %+v, %v", it, err)
	}
	if _, err := s.Delete(ctx, alice, uuid.New(), 0); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
	if it, err := s.Get(ctx, alice, a); err != nil || !it.Deleted {
		t.Fatalf("get: %+v, %v", it, err)
	}
	if _, err := s.Get(ctx, alice, uuid.New()); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	ch, err := s.ChangesSince(ctx, alice, 1, 1<<20)
	if err != nil || ch.Revision != 3 || ch.More || len(ch.Items) != 2 || ch.Items[0].ID != b || ch.Items[1].ID != a {
		t.Fatalf("changes: %+v, %v", ch, err)
	}
	ch, err = s.ChangesSince(ctx, alice, 0, 0)
	if err != nil || ch.Revision != ch.Items[0].Revision || !ch.More || len(ch.Items) != 1 {
		t.Fatalf("first page: %+v, %v", ch, err)
	}
	if _, err := s.ChangesSince(ctx, 99, 0, 0); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}

	s.Err = errors.New("boom")
	if _, err := s.CreateUser(ctx, "x", "h"); err != s.Err {
		t.Fatal(err)
	}
	if _, err := s.UserByLogin(ctx, "alice"); err != s.Err {
		t.Fatal(err)
	}
	if _, err := s.Upsert(ctx, alice, a, 0, nil); err != s.Err {
		t.Fatal(err)
	}
	if _, err := s.Delete(ctx, alice, a, 0); err != s.Err {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, alice, a); err != s.Err {
		t.Fatal(err)
	}
}
