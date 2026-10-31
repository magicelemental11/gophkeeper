package storage

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func newUser(t *testing.T, s *Storage, login string) int64 {
	t.Helper()
	id, err := s.CreateUser(context.Background(), login, "hash")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestItemLifecycle(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	user := newUser(t, s, "alice")
	id := uuid.New()

	if _, err := s.Upsert(ctx, user, id, 3, []byte("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update of missing item: %v", err)
	}
	created, err := s.Upsert(ctx, user, id, 0, []byte("v1"))
	if err != nil || created.Version != 1 || created.Revision != 1 || !bytes.Equal(created.Payload, []byte("v1")) {
		t.Fatalf("create: %+v, %v", created, err)
	}

	var conflict *ConflictError
	if _, err := s.Upsert(ctx, user, id, 0, []byte("dup")); !errors.As(err, &conflict) || conflict.Current.Version != 1 {
		t.Fatalf("stale upsert: %v", err)
	}
	if conflict.Error() == "" {
		t.Fatal("empty error text")
	}

	updated, err := s.Upsert(ctx, user, id, 1, []byte("v2"))
	if err != nil || updated.Version != 2 || updated.Revision != 2 {
		t.Fatalf("update: %+v, %v", updated, err)
	}

	if _, err := s.Delete(ctx, user, id, 1); !errors.As(err, &conflict) {
		t.Fatalf("stale delete: %v", err)
	}
	deleted, err := s.Delete(ctx, user, id, 2)
	if err != nil || !deleted.Deleted || deleted.Payload != nil || deleted.Version != 3 || deleted.Revision != 3 {
		t.Fatalf("delete: %+v, %v", deleted, err)
	}
	again, err := s.Delete(ctx, user, id, 0)
	if err != nil || again.Version != 3 || again.Revision != 3 {
		t.Fatalf("repeated delete: %+v, %v", again, err)
	}

	restored, err := s.Upsert(ctx, user, id, 3, []byte("v4"))
	if err != nil || restored.Deleted || restored.Version != 4 || restored.Revision != 4 {
		t.Fatalf("restore: %+v, %v", restored, err)
	}
	got, err := s.Get(ctx, user, id)
	if err != nil || got.Version != 4 || !bytes.Equal(got.Payload, []byte("v4")) {
		t.Fatalf("get: %+v, %v", got, err)
	}
	if _, err := s.Delete(ctx, user, uuid.New(), 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
	if _, err := s.Upsert(ctx, 999, uuid.New(), 0, []byte("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestChangesSince(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	user := newUser(t, s, "alice")
	a, b := uuid.New(), uuid.New()
	mustUpsert := func(id uuid.UUID, base int64) {
		t.Helper()
		if _, err := s.Upsert(ctx, user, id, base, []byte("p")); err != nil {
			t.Fatal(err)
		}
	}
	mustUpsert(a, 0)
	mustUpsert(b, 0)
	mustUpsert(a, 1)
	if _, err := s.Delete(ctx, user, b, 1); err != nil {
		t.Fatal(err)
	}

	ch, err := s.ChangesSince(ctx, user, 0, 1<<20)
	if err != nil || ch.Revision != 4 || ch.More || len(ch.Items) != 2 || ch.Items[0].ID != a || ch.Items[1].ID != b || !ch.Items[1].Deleted {
		t.Fatalf("all: %+v, %v", ch, err)
	}
	ch, err = s.ChangesSince(ctx, user, 0, 0)
	if err != nil || ch.Revision != 3 || !ch.More || len(ch.Items) != 1 || ch.Items[0].ID != a {
		t.Fatalf("first page: %+v, %v", ch, err)
	}
	ch, err = s.ChangesSince(ctx, user, 3, 0)
	if err != nil || ch.Revision != 4 || ch.More || len(ch.Items) != 1 || ch.Items[0].ID != b {
		t.Fatalf("since 3: %+v, %v", ch, err)
	}
	ch, err = s.ChangesSince(ctx, user, 4, 0)
	if err != nil || ch.Revision != 4 || ch.More || len(ch.Items) != 0 {
		t.Fatalf("since 4: %+v, %v", ch, err)
	}
	if _, err := s.ChangesSince(ctx, 999, 0, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestPageLen(t *testing.T) {
	tests := []struct {
		sizes []int
		max   int
		want  int
	}{
		{nil, 10, 0},
		{[]int{20}, 10, 1},
		{[]int{4, 6, 1}, 10, 2},
		{[]int{4, 0, 6}, 10, 3},
		{[]int{11, 1}, 10, 1},
	}
	for _, tt := range tests {
		if got := PageLen(tt.sizes, tt.max); got != tt.want {
			t.Errorf("PageLen(%v, %d) = %d, want %d", tt.sizes, tt.max, got, tt.want)
		}
	}
}

func TestItemsIsolatedByUser(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	alice, bob := newUser(t, s, "alice"), newUser(t, s, "bob")
	id := uuid.New()
	if _, err := s.Upsert(ctx, alice, id, 0, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, bob, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get: %v", err)
	}
	if _, err := s.Upsert(ctx, bob, id, 1, []byte("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := s.Delete(ctx, bob, id, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete: %v", err)
	}
	if ch, err := s.ChangesSince(ctx, bob, 0, 1<<20); err != nil || len(ch.Items) != 0 {
		t.Fatalf("sync: %+v, %v", ch, err)
	}
	if got, err := s.Get(ctx, alice, id); err != nil || string(got.Payload) != "secret" {
		t.Fatalf("alice item changed: %+v, %v", got, err)
	}
}

func TestConcurrentUpsert(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	user := newUser(t, s, "alice")
	id := uuid.New()
	if _, err := s.Upsert(ctx, user, id, 0, []byte("v1")); err != nil {
		t.Fatal(err)
	}

	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Go(func() {
			_, err := s.Upsert(ctx, user, id, 1, []byte("v2"))
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		var conflict *ConflictError
		switch {
		case err == nil:
			ok++
		case !errors.As(err, &conflict):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d upserts succeeded, want 1", ok)
	}
}
