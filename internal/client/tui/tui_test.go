package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/magicelemental11/gophkeeper/internal/client/api"
	"github.com/magicelemental11/gophkeeper/internal/client/app"
	"github.com/magicelemental11/gophkeeper/internal/crypto"
	"github.com/magicelemental11/gophkeeper/internal/testserver"
)

const password = "master-password"

var now = time.Date(2026, 10, 31, 12, 0, 10, 0, time.UTC)

func newApp(t *testing.T, srv *testserver.Server, dir string) *app.App {
	t.Helper()
	a, err := app.New(app.Config{
		DataDir: dir,
		Dial: func(string) (app.Remote, error) {
			return api.Dial(testserver.Address, srv.CA, srv.DialOption())
		},
		Derive: func(login, password string) (crypto.Keys, error) {
			return crypto.DeriveWith(crypto.Params{Time: 1, Memory: 64, Threads: 1}, login, password)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

type driver struct {
	t *testing.T
	m tea.Model
}

func key(k string) tea.KeyMsg {
	types := map[string]tea.KeyType{
		"enter": tea.KeyEnter, "tab": tea.KeyTab, "shift+tab": tea.KeyShiftTab, "esc": tea.KeyEsc,
		"up": tea.KeyUp, "down": tea.KeyDown, "ctrl+c": tea.KeyCtrlC, "ctrl+r": tea.KeyCtrlR, "ctrl+s": tea.KeyCtrlS,
	}
	if typ, ok := types[k]; ok {
		return tea.KeyMsg{Type: typ}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
}

func (d *driver) press(keys ...string) {
	for _, k := range keys {
		d.m, _ = d.m.Update(key(k))
	}
}

func (d *driver) typ(text string) {
	for _, r := range text {
		d.m, _ = d.m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

func (d *driver) exec(k string) {
	d.t.Helper()
	var cmd tea.Cmd
	d.m, cmd = d.m.Update(key(k))
	if cmd == nil {
		d.t.Fatalf("%s started no operation; view:\n%s", k, d.view())
	}
	if !d.model().busy {
		d.t.Fatalf("%s did not mark the model busy", k)
	}
	d.m, _ = d.m.Update(cmd())
}

func (d *driver) model() Model { return d.m.(Model) }
func (d *driver) view() string { return d.m.View() }

func (d *driver) sees(parts ...string) {
	d.t.Helper()
	v := d.view()
	for _, p := range parts {
		if !strings.Contains(v, p) {
			d.t.Fatalf("view lacks %q:\n%s", p, v)
		}
	}
}

func (d *driver) lacks(parts ...string) {
	d.t.Helper()
	v := d.view()
	for _, p := range parts {
		if strings.Contains(v, p) {
			d.t.Fatalf("view contains %q:\n%s", p, v)
		}
	}
}

func newDriver(t *testing.T, a *app.App) *driver {
	m := New(context.Background(), a, "test", func() time.Time { return now })
	if m.Init() == nil {
		t.Fatal("no init command")
	}
	return &driver{t: t, m: m}
}

func (d *driver) addRecord(kind string, fields ...string) {
	d.t.Helper()
	d.press("a", kind)
	for i, f := range fields {
		if i > 0 {
			d.press("tab")
		}
		d.typ(f)
	}
	d.exec("ctrl+s")
}

func TestScenario(t *testing.T) {
	srv := testserver.Start(t)
	d := newDriver(t, newApp(t, srv, t.TempDir()))

	d.sees("Log in", "Server", "Login", "Master password")
	d.typ("alice")
	d.press("tab")
	d.typ(password)
	d.exec("ctrl+r")
	d.sees("Records (all)", "no records", "status: synced")

	d.addRecord("1", "mail", "https://mail.example", "alice", "site-password")
	d.addRecord("2", "note", "", "hello text")
	d.addRecord("4", "visa", "bank", "4111111111111111", "ALICE", "01/20", "123")
	d.addRecord("5", "github", "", "otpauth://totp/GitHub:alice?secret="+otpSecret)
	file := filepath.Join(t.TempDir(), "doc.pdf")
	os.WriteFile(file, []byte("pdf"), 0o600)
	d.addRecord("3", "doc", "", file)
	d.sees("doc", "github", "mail", "note", "visa", "https://mail.example")

	d.press("down", "down", "enter")
	d.sees("mail  (credentials)", "Password: ********")
	d.lacks("site-password")
	d.press("r")
	d.sees("site-password")
	d.press("esc", "up", "up", "enter")
	d.sees("doc.pdf", "3 bytes")
	d.press("esc", "down", "enter")
	d.sees("GitHub", "Code: ", "(20 s left)")
	d.lacks(otpSecret)
	d.press("esc", "down", "down", "down", "enter")
	d.sees("****1111", "01/20 (expired)", "CVV:    ********")

	d.press("e")
	d.sees("Edit visa")
	d.typ("-old")
	d.exec("ctrl+s")
	d.sees("visa-old  (card)")
	d.press("esc")

	d.press("/")
	d.typ("note")
	d.press("enter")
	d.sees("note")
	d.lacks("visa-old")
	d.press("/", "esc")
	d.sees("visa-old")

	d.press("f", "f")
	d.sees("Records (text)", "note")
	d.lacks("mail")
	d.press("f", "f", "f", "f")
	d.sees("Records (all)")

	d.press("down", "down", "down", "d")
	d.sees(`Delete text "note"? (y/n)`)
	d.press("n")
	d.sees("note")
	d.press("d")
	d.exec("y")
	d.lacks("note")

	d.press("up", "up", "up", "up", "e")
	d.press("tab", "tab")
	d.exec("enter")
	d.sees("doc  (binary)", "3 bytes")
	d.press("esc")

	srv.Down()
	d.addRecord("2", "offline note", "", "x")
	d.sees("offline, 1 changes not sent")
	d.exec("s")
	d.sees("offline, 1 changes not sent")
	srv.Up()
	d.exec("s")
	d.sees("status: synced")

	var cmd tea.Cmd
	_, cmd = d.m.Update(key("ctrl+c"))
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("ctrl+c does not quit")
	}
}

func TestUnlockAndErrors(t *testing.T) {
	srv := testserver.Start(t)
	dir := t.TempDir()
	a := newApp(t, srv, dir)
	if _, err := a.Register(context.Background(), "test", "bob", password); err != nil {
		t.Fatal(err)
	}

	d := newDriver(t, newApp(t, srv, dir))
	d.sees("Master password for bob")
	d.typ("wrong-password")
	d.exec("enter")
	d.sees("wrong master password", "Log in")
	d.typ(password)
	d.exec("enter")
	d.sees("Records (all)")

	d.press("a", "9")
	d.sees("New record kind")
	d.press("4")
	d.typ("bad card")
	d.press("tab", "tab")
	d.typ("1234")
	d.press("ctrl+s")
	d.sees("error: card number")
	d.press("esc", "a", "esc", "a", "3")
	d.typ("file")
	d.press("ctrl+s")
	d.sees("file path is required")
	d.press("down", "down")
	d.typ(filepath.Join(t.TempDir(), "missing"))
	d.press("ctrl+s")
	d.sees("no such file")
	d.press("esc", "a", "5")
	d.typ("otp")
	d.press("tab", "tab")
	d.typ("otpauth://hotp/x")
	d.press("ctrl+s")
	d.sees("otpauth://totp/")
	d.press("esc", "a", "5")
	d.typ("otp")
	d.press("tab", "tab")
	d.typ(otpSecret)
	d.press("tab")
	d.typ("Issuer")
	d.press("shift+tab", "up", "enter", "enter", "enter")
	d.exec("enter")
	d.sees("otp", "status: synced")

	d.press("enter", "d")
	d.exec("y")
	d.sees("no records")
	d.press("enter", "e", "d", "up", "k", "j")

	d.press("L")
	d.sees("Server", "Login")
	d.typ("nobody")
	d.press("tab")
	d.typ(password)
	d.exec("enter")
	d.sees("not authenticated")

	srv.Down()
	d.press("shift+tab")
	d.typ("x")
	d.exec("enter")
	d.sees("server is unavailable")
	d.lacks("Records")
	d.press("esc")
}

func TestBackgroundSync(t *testing.T) {
	srv := testserver.Start(t)
	d := newDriver(t, newApp(t, srv, t.TempDir()))
	d.typ("carol")
	d.press("tab")
	d.typ(password)
	d.exec("ctrl+r")

	for i := 1; i < int(SyncEvery/time.Second); i++ {
		d.m, _ = d.m.Update(tickMsg(now))
		if d.model().busy {
			t.Fatalf("synced early at tick %d", i)
		}
	}
	var cmd tea.Cmd
	d.m, cmd = d.m.Update(tickMsg(now))
	if !d.model().busy {
		t.Fatal("no sync after the interval")
	}
	d.sees("working...")
	batch, ok := cmd().(tea.BatchMsg)
	if !ok || len(batch) != 2 {
		t.Fatalf("got %T", cmd())
	}
	d.m, _ = d.m.Update(batch[1]())
	d.sees("status: synced")
	d.lacks("working...")

	d.m, _ = d.m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	d.press("ctrl+c")
	if d.model().busy {
		t.Fatal("still busy")
	}
}
