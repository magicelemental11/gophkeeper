package integration

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/magicelemental11/gophkeeper/internal/client/api"
	"github.com/magicelemental11/gophkeeper/internal/client/app"
	"github.com/magicelemental11/gophkeeper/internal/crypto"
	"github.com/magicelemental11/gophkeeper/internal/server/auth"
	"github.com/magicelemental11/gophkeeper/internal/server/service"
	"github.com/magicelemental11/gophkeeper/internal/server/storage"
	"github.com/magicelemental11/gophkeeper/internal/testcert"
	"github.com/magicelemental11/gophkeeper/internal/vault"
)

func startServer(t *testing.T) (addr, caPath string) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN is not set")
	}
	store, err := storage.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)

	creds, caPath := testcert.Credentials(t)
	srv := service.NewServer(store, auth.NewIssuer("integration", time.Hour), zap.NewNop(), grpc.Creds(creds))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), caPath
}

func newClient(t *testing.T, caPath string) *app.App {
	t.Helper()
	a, err := app.New(app.Config{
		DataDir: t.TempDir(),
		Dial: func(server string) (app.Remote, error) {
			return api.Dial(server, caPath)
		},
		Derive: func(login, password string) (crypto.Keys, error) {
			return crypto.DeriveWith(crypto.Params{Time: 1, Memory: 1024, Threads: 1}, login, password)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

func TestFullScenario(t *testing.T) {
	addr, caPath := startServer(t)
	ctx := context.Background()
	login := "it-" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	const password = "integration-password"

	laptop := newClient(t, caPath)
	if _, err := laptop.Register(ctx, addr, login, password); err != nil {
		t.Fatal(err)
	}
	records := []vault.Record{
		vault.New("mail", "site", vault.Credentials{Login: "a", Password: "b"}),
		vault.New("note", "", vault.Text{Content: "text"}),
		vault.New("file", "", vault.Binary{FileName: "f.bin", Content: make([]byte, 1<<20)}),
		vault.New("card", "bank", vault.Card{Number: "4111111111111111", Expiry: "12/30", CVV: "123"}),
		vault.New("otp", "", vault.OTP{Secret: otpSecret}),
	}
	for _, r := range records {
		if _, err := laptop.Add(ctx, r); err != nil {
			t.Fatalf("add %s: %v", r.Name, err)
		}
	}

	phone := newClient(t, caPath)
	rep, err := phone.Login(ctx, addr, login, password)
	if err != nil || rep.Pulled != len(records) {
		t.Fatalf("login: %+v, %v", rep, err)
	}

	note, _ := phone.Find("note")
	note.SetData(vault.Text{Content: "from phone"})
	if _, err := phone.Update(ctx, note); err != nil {
		t.Fatal(err)
	}
	stale, _ := laptop.Find("note")
	stale.SetData(vault.Text{Content: "from laptop"})
	rep, err = laptop.Update(ctx, stale)
	if err != nil || rep.Conflicts != 1 {
		t.Fatalf("conflict: %+v, %v", rep, err)
	}

	card, _ := laptop.Find("card")
	if _, err := laptop.Delete(ctx, card.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := phone.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := phone.List("")
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(got))
	for i, r := range got {
		names[i] = r.Name
	}
	if len(names) != 5 || names[0] != "file" || !strings.HasPrefix(names[3], "note (conflict ") {
		t.Fatalf("phone sees %v", names)
	}
	if n, _ := phone.Find("note"); n.Data.(vault.Text).Content != "from phone" {
		t.Fatalf("note: %+v", n)
	}
}

func TestUntrustedCertificate(t *testing.T) {
	addr, _ := startServer(t)
	otherCA := testcert.Write(t, t.TempDir()).CA
	a := newClient(t, otherCA)
	if _, err := a.Register(context.Background(), addr, "it-untrusted", "integration-password"); err == nil {
		t.Fatal("connected with an untrusted certificate")
	}
}
