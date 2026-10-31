package cli_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/magicelemental11/gophkeeper/internal/client/api"
	"github.com/magicelemental11/gophkeeper/internal/client/app"
	"github.com/magicelemental11/gophkeeper/internal/client/cli"
	"github.com/magicelemental11/gophkeeper/internal/crypto"
	"github.com/magicelemental11/gophkeeper/internal/testserver"
)

const password = "master-password"

type prompter struct {
	answers []string
	asked   []string
}

func (p *prompter) next(prompt string) (string, error) {
	p.asked = append(p.asked, prompt)
	if len(p.answers) == 0 {
		return "", errors.New("unexpected prompt " + prompt)
	}
	a := p.answers[0]
	p.answers = p.answers[1:]
	return a, nil
}

func (p *prompter) Password(prompt string) (string, error) { return p.next(prompt) }
func (p *prompter) Line(prompt string) (string, error)     { return p.next(prompt) }

type device struct {
	t   *testing.T
	srv *testserver.Server
	dir string
	now time.Time
}

func newDevice(t *testing.T, srv *testserver.Server) *device {
	return &device{t: t, srv: srv, dir: t.TempDir(), now: time.Date(2026, 10, 31, 12, 0, 15, 0, time.UTC)}
}

type result struct {
	out, err string
	code     int
	prompts  []string
}

func (d *device) run(stdin string, answers []string, args ...string) result {
	d.t.Helper()
	p := &prompter{answers: answers}
	root := cli.NewRoot(cli.Deps{
		Dial: func(string, string, bool) (app.Remote, error) {
			return api.Dial(testserver.Address, "", true, d.srv.DialOption())
		},
		Derive: func(login, password string) (crypto.Keys, error) {
			return crypto.DeriveWith(crypto.Params{Time: 1, Memory: 64, Threads: 1}, login, password)
		},
		Prompter: p,
		Now:      func() time.Time { return d.now },
	})
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetIn(strings.NewReader(stdin))
	code := cli.Execute(context.Background(), root, append([]string{"--data-dir", d.dir}, args...))
	return result{out: out.String(), err: errOut.String(), code: code, prompts: p.asked}
}

func (d *device) ok(args ...string) string {
	d.t.Helper()
	res := d.run("", nil, args...)
	if res.code != 0 {
		d.t.Fatalf("%v: code %d, %s", args, res.code, res.err)
	}
	return res.out
}

func (d *device) fail(want string, args ...string) {
	d.t.Helper()
	res := d.run("", nil, args...)
	if res.code != 1 || !strings.Contains(res.err, want) {
		d.t.Fatalf("%v: code %d, stderr %q, want %q", args, res.code, res.err, want)
	}
}

func contains(t *testing.T, s string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(s, p) {
			t.Fatalf("output lacks %q:\n%s", p, s)
		}
	}
}

func lacks(t *testing.T, s string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if strings.Contains(s, p) {
			t.Fatalf("output contains %q:\n%s", p, s)
		}
	}
}

func TestVersion(t *testing.T) {
	d := newDevice(t, testserver.Start(t))
	contains(t, d.ok("version"), "Build version:", "Build date:", "Build commit:")
}

func TestScenario(t *testing.T) {
	srv := testserver.Start(t)
	laptop := newDevice(t, srv)

	res := laptop.run("", []string{"alice", password, password}, "register")
	if res.code != 0 {
		t.Fatalf("register: %s", res.err)
	}
	contains(t, res.out, "Registered and logged in as alice")

	t.Setenv("GOPHKEEPER_PASSWORD", password)
	res = laptop.run("site-password\n", nil, "add", "credentials", "--name", "mail", "--login", "alice@example.com",
		"--meta", "https://mail.example\nrecovery codes: 111 222", "--password-stdin")
	if res.code != 0 {
		t.Fatalf("add credentials: %s", res.err)
	}
	contains(t, res.out, "Added credentials \"mail\"", "Synced: sent 1")

	res = laptop.run("note from stdin", nil, "add", "text", "--name", "note")
	if res.code != 0 {
		t.Fatalf("add text: %s", res.err)
	}
	file := filepath.Join(t.TempDir(), "photo.png")
	if err := os.WriteFile(file, []byte{0, 1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	laptop.ok("add", "binary", "--name", "photo", "--file", file)
	res = laptop.run("", []string{"987"}, "add", "card", "--name", "visa", "--number", "4111 1111 1111 1111",
		"--holder", "ALICE", "--expiry", "12/30")
	if res.code != 0 || len(res.prompts) != 1 || res.prompts[0] != "CVV: " {
		t.Fatalf("add card: %+v", res)
	}
	laptop.ok("add", "otp", "--name", "github", "--uri", "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP")

	phone := newDevice(t, srv)
	contains(t, phone.ok("login", "--login", "alice"), "Logged in as alice", "received 5")
	list := phone.ok("list")
	contains(t, list, "ID", "KIND", "github", "mail", "note", "photo", "visa", "https://mail.example")
	lacks(t, list, "site-password", "recovery codes", "987", "4111")
	contains(t, phone.ok("list", "--kind", "card"), "visa")
	lacks(t, phone.ok("list", "--kind", "card"), "mail")

	shown := phone.ok("show", "mail")
	contains(t, shown, "alice@example.com", "********", "recovery codes: 111 222")
	lacks(t, shown, "site-password")
	contains(t, phone.ok("show", "mail", "--reveal"), "site-password")

	card := phone.ok("show", "visa")
	contains(t, card, "****1111", "ALICE", "12/30")
	lacks(t, card, "987", "4111111111111111", "expired")
	contains(t, phone.ok("show", "visa", "-r"), "4111111111111111", "987")

	contains(t, phone.ok("show", "note"), "note from stdin")
	contains(t, phone.ok("show", "photo"), "photo.png", "4 bytes")
	contains(t, phone.ok("show", "github"), "GitHub", "alice", "6 digits")
	lacks(t, phone.ok("show", "github"), "JBSWY3DPEHPK3PXP")
	contains(t, phone.ok("otp", "github"), "(valid for 15 s)")

	out := filepath.Join(t.TempDir(), "restored.png")
	contains(t, phone.ok("get-file", "photo", "-o", out), "Saved 4 bytes")
	if data, _ := os.ReadFile(out); !bytes.Equal(data, []byte{0, 1, 2, 3}) {
		t.Fatalf("restored %v", data)
	}
	phone.fail("exists, use --force", "get-file", "photo", "-o", out)
	phone.ok("get-file", "photo", "-o", out, "--force")
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", fi.Mode().Perm())
		}
	}

	phone.ok("edit", "mail", "--login", "new@example.com", "--name", "email")
	res = phone.run("", []string{"new-site-password"}, "edit", "email", "--password")
	if res.code != 0 {
		t.Fatalf("edit password: %s", res.err)
	}
	phone.ok("edit", "note", "--content", "edited")
	phone.ok("edit", "visa", "--expiry", "01/20")
	phone.ok("edit", "github", "--digits", "8")
	newFile := filepath.Join(t.TempDir(), "new.bin")
	os.WriteFile(newFile, []byte("abc"), 0o600)
	phone.ok("edit", "photo", "--file", newFile, "--meta", "replaced")
	phone.fail("not applicable to a text record", "edit", "note", "--number", "1")

	contains(t, laptop.ok("sync"), "received 5")
	contains(t, laptop.ok("show", "email", "--reveal"), "new@example.com", "new-site-password")
	contains(t, laptop.ok("show", "note"), "edited")
	contains(t, laptop.ok("show", "visa"), "01/20 (expired)")
	contains(t, laptop.ok("show", "photo"), "new.bin", "3 bytes", "replaced")
	if code := laptop.ok("otp", "github"); len(strings.Fields(code)[0]) != 8 {
		t.Fatalf("otp %q", code)
	}

	res = laptop.run("", []string{"n"}, "delete", "note")
	contains(t, res.out, "Cancelled")
	res = laptop.run("", []string{"y"}, "delete", "note")
	contains(t, res.out, "Deleted \"note\"")
	laptop.ok("delete", "visa", "--yes")
	phone.ok("sync")
	lacks(t, phone.ok("list"), "note", "visa")

	contains(t, phone.ok("logout"), "Logged out")
	phone.fail("not logged in", "list")
}

func TestErrors(t *testing.T) {
	srv := testserver.Start(t)
	d := newDevice(t, srv)
	t.Setenv("GOPHKEEPER_PASSWORD", password)

	d.fail("not logged in", "list")
	d.fail("not logged in", "sync")
	d.fail("unknown kind", "list", "--kind", "note")
	d.fail("not authenticated", "login", "--login", "alice")
	d.ok("register", "--login", "alice")
	d.fail("already taken", "register", "--login", "alice")

	t.Setenv("GOPHKEEPER_PASSWORD", "wrong-password")
	d.fail("wrong master password", "list")
	t.Setenv("GOPHKEEPER_PASSWORD", password)

	d.fail("record not found", "show", "missing")
	if res := d.run("123\n", nil, "add", "card", "--name", "c", "--number", "4111111111111112", "--expiry", "12/30", "--cvv-stdin"); !strings.Contains(res.err, "card number") {
		t.Fatalf("bad number: %+v", res)
	}
	d.fail("read stdin", "add", "card", "--name", "c", "--number", "4111111111111111", "--expiry", "12/30", "--cvv-stdin")
	if res := d.run("12\n", nil, "add", "card", "--name", "c", "--number", "4111111111111111", "--expiry", "12/30", "--cvv-stdin"); res.code != 1 {
		t.Fatal("short CVV accepted")
	}
	if res := d.run("123\n", nil, "add", "card", "--name", "c", "--number", "4111111111111111", "--expiry", "2030-12", "--cvv-stdin"); !strings.Contains(res.err, "expiry") {
		t.Fatalf("bad expiry: %+v", res)
	}
	d.fail("required flag", "add", "binary", "--name", "b")
	d.fail("no such file", "add", "binary", "--name", "b", "--file", filepath.Join(t.TempDir(), "missing"))
	d.fail("base32", "add", "otp", "--name", "o", "--secret", "!!!")
	if res := d.run("\n", nil, "add", "credentials", "--name", "c", "--password-stdin"); !strings.Contains(res.err, "must not both be empty") {
		t.Fatalf("empty credentials: %+v", res)
	}

	d.ok("add", "text", "--name", "dup", "--content", "1")
	d.ok("add", "text", "--name", "dup", "--content", "2")
	d.fail("matches several records", "show", "dup")
	d.fail("record not found", "get-file", "nothing", "-o", "x")
	d.ok("add", "text", "--name", "single", "--content", "1")
	d.fail("not binary", "get-file", "single", "-o", filepath.Join(t.TempDir(), "x"))
	d.fail("not otp", "otp", "single")

	srv.Down()
	contains(t, d.ok("add", "text", "--name", "offline", "--content", "x"), "Saved locally")
	contains(t, d.ok("list"), "offline", "1 local changes not sent yet")
	d.fail("server is unavailable", "sync")
	srv.Up()
	contains(t, d.ok("sync"), "sent 1")
}

func TestRegisterPrompts(t *testing.T) {
	d := newDevice(t, testserver.Start(t))
	t.Setenv("GOPHKEEPER_PASSWORD", "")
	if res := d.run("", []string{password, "different"}, "register", "-l", "alice"); !strings.Contains(res.err, "do not match") {
		t.Fatalf("mismatch: %+v", res)
	}
	if res := d.run("", []string{"short"}, "register", "-l", "alice"); !strings.Contains(res.err, "at least 8") {
		t.Fatalf("short: %+v", res)
	}
	if res := d.run("", nil, "register", "-l", "alice"); res.code != 1 {
		t.Fatalf("no input: %+v", res)
	}
	t.Setenv("GOPHKEEPER_PASSWORD", "short")
	d.fail("at least 8", "register", "-l", "alice")
}

func TestMetaFileAndTextFile(t *testing.T) {
	d := newDevice(t, testserver.Start(t))
	t.Setenv("GOPHKEEPER_PASSWORD", password)
	d.ok("register", "-l", "alice")
	dir := t.TempDir()
	meta := filepath.Join(dir, "meta.txt")
	text := filepath.Join(dir, "text.txt")
	os.WriteFile(meta, []byte("codes:\n123456"), 0o600)
	os.WriteFile(text, []byte("from file"), 0o600)
	d.ok("add", "text", "--name", "t", "--file", text, "--meta-file", meta)
	contains(t, d.ok("show", "t"), "from file", "codes:\n123456")
	d.fail("no such file", "add", "text", "--name", "x", "--file", filepath.Join(dir, "missing"))
	d.fail("no such file", "add", "text", "--name", "x", "--content", "a", "--meta-file", filepath.Join(dir, "missing"))
	d.ok("edit", "t", "--file", text, "--meta", "")
	lacks(t, d.ok("show", "t"), "Meta:")
	d.ok("add", "otp", "--name", "o", "--secret", "JBSWY3DPEHPK3PXP", "--issuer", "X", "--account", "a", "--period", "60", "--algorithm", "sha256")
	contains(t, d.ok("show", "o", "--reveal"), "JBSWY3DPEHPK3PXP", "60 s, SHA256")
	d.ok("edit", "o", "--uri", "otpauth://totp/Y:b?secret=JBSWY3DPEHPK3PXP", "--account", "c", "--secret", "JBSWY3DPEHPK3PXQ", "--issuer", "Z", "--period", "30", "--algorithm", "SHA1")
	contains(t, d.ok("show", "o", "-r"), "Z", "c", "JBSWY3DPEHPK3PXQ")
	d.fail("OTP URI", "edit", "o", "--uri", "https://x")
}
