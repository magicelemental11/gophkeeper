package app_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/magicelemental11/gophkeeper/internal/client/api"
	"github.com/magicelemental11/gophkeeper/internal/client/app"
	"github.com/magicelemental11/gophkeeper/internal/client/store"
	"github.com/magicelemental11/gophkeeper/internal/crypto"
	"github.com/magicelemental11/gophkeeper/internal/testserver"
	"github.com/magicelemental11/gophkeeper/internal/vault"
)

const (
	server   = "test"
	password = "master-password"
)

var ctx = context.Background()

func fastDerive(login, password string) (crypto.Keys, error) {
	return crypto.DeriveWith(crypto.Params{Time: 1, Memory: 64, Threads: 1}, login, password)
}

func newApp(t *testing.T, srv *testserver.Server, dir string) *app.App {
	t.Helper()
	a, err := app.New(app.Config{
		DataDir: dir,
		Dial: func(string) (app.Remote, error) {
			return api.Dial(testserver.Address, "", true, srv.DialOption())
		},
		Derive: fastDerive,
		Now:    func() time.Time { return time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

func names(t *testing.T, a *app.App) []string {
	t.Helper()
	records, err := a.List("")
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(records))
	for i, r := range records {
		out[i] = r.Name
	}
	return out
}

func equal(a, b []string) bool { return strings.Join(a, "|") == strings.Join(b, "|") }

func TestNewAndExistingUser(t *testing.T) {
	srv := testserver.Start(t)
	laptop := newApp(t, srv, t.TempDir())
	if _, err := laptop.Register(ctx, server, "alice", password); err != nil {
		t.Fatal(err)
	}
	records := []vault.Record{
		vault.New("mail", "https://mail.example", vault.Credentials{Login: "alice", Password: "hunter2-secret"}),
		vault.New("note", "", vault.Text{Content: "plaintext-note-body"}),
		vault.New("photo", "", vault.Binary{FileName: "a.png", Content: []byte("binary-content-xyz")}),
		vault.New("visa", "bank", vault.Card{Number: "4111111111111111", Holder: "ALICE", Expiry: "12/30", CVV: "987"}),
	}
	for _, r := range records {
		rep, err := laptop.Add(ctx, r)
		if err != nil || rep.Pushed != 1 || rep.Offline {
			t.Fatalf("add %s: %+v, %v", r.Name, rep, err)
		}
	}

	phoneDir := t.TempDir()
	phone := newApp(t, srv, phoneDir)
	rep, err := phone.Login(ctx, server, "alice", password)
	if err != nil || rep.Pulled != 4 {
		t.Fatalf("login: %+v, %v", rep, err)
	}
	if got := names(t, phone); !equal(got, []string{"mail", "note", "photo", "visa"}) {
		t.Fatalf("phone sees %v", got)
	}
	card, err := phone.Find("visa")
	if err != nil || card.Data.(vault.Card).CVV != "987" || card.Meta != "bank" {
		t.Fatalf("card: %+v, %v", card, err)
	}

	reopened := newApp(t, srv, phoneDir)
	if s, ok := reopened.Session(); !ok || s.Login != "alice" {
		t.Fatalf("session: %+v", s)
	}
	if _, err := reopened.List(""); !errors.Is(err, app.ErrLocked) {
		t.Fatalf("locked: %v", err)
	}
	if err := reopened.Unlock("wrong-password"); !errors.Is(err, app.ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	if err := reopened.Unlock(password); err != nil {
		t.Fatal(err)
	}
	if got := names(t, reopened); len(got) != 4 {
		t.Fatalf("reopened sees %v", got)
	}
}

func TestNothingSecretOnDisk(t *testing.T) {
	srv := testserver.Start(t)
	dir := t.TempDir()
	a := newApp(t, srv, dir)
	if _, err := a.Register(ctx, server, "alice", password); err != nil {
		t.Fatal(err)
	}
	secrets := []string{"hunter2-secret", "plaintext-note-body", "4111111111111111", "my-record-name", "my-meta", password}
	if _, err := a.Add(ctx, vault.New("my-record-name", "my-meta", vault.Credentials{Login: "x", Password: "hunter2-secret"})); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add(ctx, vault.New("n", "", vault.Text{Content: "plaintext-note-body"})); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add(ctx, vault.New("c", "", vault.Card{Number: "4111111111111111", Expiry: "12/30", CVV: "123"})); err != nil {
		t.Fatal(err)
	}
	keys, _ := fastDerive("alice", password)
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range secrets {
			if bytes.Contains(data, []byte(s)) {
				t.Errorf("%s contains %q", f.Name(), s)
			}
		}
		if bytes.Contains(data, keys.Enc) {
			t.Errorf("%s contains the encryption key", f.Name())
		}
	}
}

func TestConflict(t *testing.T) {
	srv := testserver.Start(t)
	a := newApp(t, srv, t.TempDir())
	b := newApp(t, srv, t.TempDir())
	if _, err := a.Register(ctx, server, "alice", password); err != nil {
		t.Fatal(err)
	}
	r := vault.New("mail", "", vault.Credentials{Login: "alice", Password: "old"})
	if _, err := a.Add(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Login(ctx, server, "alice", password); err != nil {
		t.Fatal(err)
	}

	ra, _ := a.Get(r.ID)
	ra.SetData(vault.Credentials{Login: "alice", Password: "from-a"})
	if _, err := a.Update(ctx, ra); err != nil {
		t.Fatal(err)
	}
	rb, _ := b.Get(r.ID)
	rb.SetData(vault.Credentials{Login: "alice", Password: "from-b"})
	rep, err := b.Update(ctx, rb)
	if err != nil || rep.Conflicts != 1 {
		t.Fatalf("conflict: %+v, %v", rep, err)
	}
	want := []string{"mail", "mail (conflict 2026-10-31 12:00)"}
	if got := names(t, b); !equal(got, want) {
		t.Fatalf("b sees %v", got)
	}
	if got, _ := b.Get(r.ID); got.Data.(vault.Credentials).Password != "from-a" {
		t.Fatalf("server version lost: %+v", got)
	}
	if _, err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got := names(t, a); !equal(got, want) {
		t.Fatalf("a sees %v", got)
	}
	copyRec, _ := a.Find("mail (conflict 2026-10-31 12:00)")
	if copyRec.Data.(vault.Credentials).Password != "from-b" {
		t.Fatalf("local version lost: %+v", copyRec)
	}
}

func TestDeleteSyncsAndDeleteConflict(t *testing.T) {
	srv := testserver.Start(t)
	a := newApp(t, srv, t.TempDir())
	b := newApp(t, srv, t.TempDir())
	if _, err := a.Register(ctx, server, "alice", password); err != nil {
		t.Fatal(err)
	}
	keep := vault.New("keep", "", vault.Text{Content: "1"})
	gone := vault.New("gone", "", vault.Text{Content: "2"})
	for _, r := range []vault.Record{keep, gone} {
		if _, err := a.Add(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.Login(ctx, server, "alice", password); err != nil {
		t.Fatal(err)
	}

	if _, err := a.Delete(ctx, gone.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Delete(ctx, gone.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	updated, _ := a.Get(keep.ID)
	updated.SetData(vault.Text{Content: "edited"})
	if _, err := a.Update(ctx, updated); err != nil {
		t.Fatal(err)
	}

	rep, err := b.Delete(ctx, keep.ID)
	if err != nil || rep.Conflicts != 1 {
		t.Fatalf("stale delete: %+v, %v", rep, err)
	}
	if got := names(t, b); !equal(got, []string{"keep"}) {
		t.Fatalf("b sees %v", got)
	}
	if got, _ := b.Get(keep.ID); got.Data.(vault.Text).Content != "edited" {
		t.Fatalf("server version lost: %+v", got)
	}
}

func TestOfflineChanges(t *testing.T) {
	srv := testserver.Start(t)
	a := newApp(t, srv, t.TempDir())
	if _, err := a.Register(ctx, server, "alice", password); err != nil {
		t.Fatal(err)
	}
	synced := vault.New("synced", "", vault.Text{Content: "1"})
	if _, err := a.Add(ctx, synced); err != nil {
		t.Fatal(err)
	}

	srv.Down()
	local := vault.New("offline", "", vault.Text{Content: "x"})
	rep, err := a.Add(ctx, local)
	if err != nil || !rep.Offline {
		t.Fatalf("offline add: %+v, %v", rep, err)
	}
	temp := vault.New("temp", "", vault.Text{Content: "y"})
	if _, err := a.Add(ctx, temp); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Delete(ctx, temp.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Delete(ctx, synced.ID); err != nil {
		t.Fatal(err)
	}
	if a.Pending() != 2 {
		t.Fatalf("pending %d", a.Pending())
	}
	if _, err := a.Sync(ctx); !errors.Is(err, api.ErrUnavailable) {
		t.Fatalf("sync while down: %v", err)
	}

	srv.Up()
	rep, err = a.Sync(ctx)
	if err != nil || rep.Pushed != 2 || a.Pending() != 0 {
		t.Fatalf("sync after outage: %+v, %v, pending %d", rep, err, a.Pending())
	}
	b := newApp(t, srv, t.TempDir())
	if _, err := b.Login(ctx, server, "alice", password); err != nil {
		t.Fatal(err)
	}
	if got := names(t, b); !equal(got, []string{"offline"}) {
		t.Fatalf("b sees %v", got)
	}
}

func TestFind(t *testing.T) {
	srv := testserver.Start(t)
	a := newApp(t, srv, t.TempDir())
	if _, err := a.Register(ctx, server, "alice", password); err != nil {
		t.Fatal(err)
	}
	one := vault.New("one", "", vault.Text{})
	for _, r := range []vault.Record{one, vault.New("dup", "", vault.Text{}), vault.New("dup", "", vault.Text{})} {
		if _, err := a.Add(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if r, err := a.Find(one.ID.String()[:8]); err != nil || r.ID != one.ID {
		t.Fatalf("prefix: %v", err)
	}
	if r, err := a.Find(strings.ToUpper(one.ID.String())); err != nil || r.ID != one.ID {
		t.Fatalf("upper id: %v", err)
	}
	var amb *app.AmbiguousError
	if _, err := a.Find("dup"); !errors.As(err, &amb) || len(amb.Matches) != 2 || !strings.Contains(err.Error(), "dup") {
		t.Fatalf("ambiguous: %v", err)
	}
	if _, err := a.Find("missing"); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := a.Get(uuid.New()); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	texts, err := a.List(vault.KindText)
	if err != nil || len(texts) != 3 {
		t.Fatalf("list text: %v, %v", texts, err)
	}
	if cards, _ := a.List(vault.KindCard); len(cards) != 0 {
		t.Fatalf("list card: %v", cards)
	}
}

func TestErrors(t *testing.T) {
	srv := testserver.Start(t)
	dir := t.TempDir()
	a := newApp(t, srv, dir)
	r := vault.New("x", "", vault.Text{})

	if _, err := a.List(""); !errors.Is(err, app.ErrNotLoggedIn) {
		t.Fatalf("list: %v", err)
	}
	if _, err := a.Sync(ctx); !errors.Is(err, app.ErrNotLoggedIn) {
		t.Fatalf("sync: %v", err)
	}
	if _, err := a.Delete(ctx, r.ID); !errors.Is(err, app.ErrNotLoggedIn) {
		t.Fatalf("delete: %v", err)
	}
	if err := a.Unlock(password); !errors.Is(err, app.ErrNotLoggedIn) {
		t.Fatalf("unlock: %v", err)
	}
	if _, err := a.Register(ctx, server, "alice", "short"); err == nil {
		t.Fatal("short password accepted")
	}
	if _, err := a.Login(ctx, server, "alice", password); !errors.Is(err, api.ErrUnauthenticated) {
		t.Fatalf("login unknown: %v", err)
	}
	if _, err := a.Register(ctx, server, "alice", password); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Register(ctx, server, "alice", password); !errors.Is(err, api.ErrLoginTaken) {
		t.Fatalf("register twice: %v", err)
	}
	if _, err := a.Login(ctx, server, "alice", password); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add(ctx, vault.Record{ID: uuid.New(), Name: "no data"}); err == nil {
		t.Fatal("invalid record accepted")
	}
	if _, err := a.Add(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add(ctx, r); err == nil {
		t.Fatal("duplicate add accepted")
	}
	if _, err := a.Update(ctx, vault.New("y", "", vault.Text{})); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	bad := r
	bad.Name = ""
	if _, err := a.Update(ctx, bad); err == nil {
		t.Fatal("invalid update accepted")
	}

	s, _ := a.Session()
	s.Token = "expired"
	if err := store.SaveSession(dir, s); err != nil {
		t.Fatal(err)
	}
	expired := newApp(t, srv, dir)
	if _, err := expired.Sync(ctx); !errors.Is(err, app.ErrSessionExpired) {
		t.Fatalf("expired: %v", err)
	}

	if err := a.Logout(); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Session(); ok || a.Pending() != 0 {
		t.Fatal("still logged in")
	}
	if _, err := store.LoadSession(dir); !errors.Is(err, store.ErrNoSession) {
		t.Fatalf("session file: %v", err)
	}
}

func TestAccountSwitchDropsCache(t *testing.T) {
	srv := testserver.Start(t)
	dir := t.TempDir()
	a := newApp(t, srv, dir)
	if _, err := a.Register(ctx, server, "alice", password); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add(ctx, vault.New("alice-only", "", vault.Text{})); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Register(ctx, server, "bob", password); err != nil {
		t.Fatal(err)
	}
	if got := names(t, a); len(got) != 0 {
		t.Fatalf("bob sees %v", got)
	}
	if _, err := a.Login(ctx, server, "alice", password); err != nil {
		t.Fatal(err)
	}
	if got := names(t, a); !equal(got, []string{"alice-only"}) {
		t.Fatalf("alice sees %v", got)
	}
}

func TestUnsentChangesBlockAccountSwitch(t *testing.T) {
	srv := testserver.Start(t)
	a := newApp(t, srv, t.TempDir())
	if _, err := a.Register(ctx, server, "Alice", password); err != nil {
		t.Fatal(err)
	}
	if s, _ := a.Session(); s.Login != "alice" {
		t.Fatalf("login %q", s.Login)
	}
	srv.Down()
	if _, err := a.Add(ctx, vault.New("local", "", vault.Text{})); err != nil {
		t.Fatal(err)
	}
	srv.Up()
	if _, err := a.Login(ctx, server, "bob", password); !errors.Is(err, app.ErrUnsentChanges) {
		t.Fatalf("switch: %v", err)
	}
	if _, err := a.Login(ctx, server, "ALICE", password); err != nil || a.Pending() != 0 {
		t.Fatalf("same account: %v, pending %d", err, a.Pending())
	}
}

func TestBrokenDataDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, store.SessionFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.New(app.Config{DataDir: dir}); err == nil {
		t.Fatal("broken session accepted")
	}
	if err := store.SaveSession(dir, store.Session{Login: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, store.CacheFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.New(app.Config{DataDir: dir}); err == nil {
		t.Fatal("broken cache accepted")
	}
}

func TestDialError(t *testing.T) {
	a, err := app.New(app.Config{
		DataDir: t.TempDir(),
		Dial:    func(string) (app.Remote, error) { return nil, errors.New("dial failed") },
		Derive:  fastDerive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Login(ctx, server, "alice", password); err == nil || err.Error() != "dial failed" {
		t.Fatalf("got %v", err)
	}
}
