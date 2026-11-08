package storage

import (
	"context"
	"errors"
	"testing"
)

func TestUsers(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.UserByLogin(ctx, "alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	id, err := s.CreateUser(ctx, "alice", "hash")
	if err != nil || id == 0 {
		t.Fatalf("create: %d, %v", id, err)
	}
	if _, err := s.CreateUser(ctx, "alice", "other"); !errors.Is(err, ErrLoginTaken) {
		t.Fatalf("want ErrLoginTaken, got %v", err)
	}
	u, err := s.UserByLogin(ctx, "alice")
	if err != nil || u != (User{ID: id, Login: "alice", AuthHash: "hash"}) {
		t.Fatalf("got %+v, %v", u, err)
	}
}
