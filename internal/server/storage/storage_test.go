package storage

import (
	"context"
	"os"
	"testing"
)

func newTestStorage(t *testing.T) *Storage {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN is not set")
	}
	s, err := New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if _, err := s.pool.Exec(context.Background(), `TRUNCATE users, items RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMigrationsIdempotent(t *testing.T) {
	s := newTestStorage(t)
	if err := migrateUp(s.pool); err != nil {
		t.Fatalf("second run: %v", err)
	}
	var n int
	err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM information_schema.tables WHERE table_name IN ('users', 'items')`).Scan(&n)
	if err != nil || n != 2 {
		t.Fatalf("tables: %d, %v", n, err)
	}
}

func TestNewBadDSN(t *testing.T) {
	if _, err := New(context.Background(), "postgres://nobody@127.0.0.1:1/none?connect_timeout=1"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := New(context.Background(), "::bad::"); err == nil {
		t.Fatal("expected error")
	}
}
