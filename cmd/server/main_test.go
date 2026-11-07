package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/magicelemental11/gophkeeper/internal/proto"
	"github.com/magicelemental11/gophkeeper/internal/server/config"
	"github.com/magicelemental11/gophkeeper/internal/testcert"
)

func listen(t *testing.T) net.Listener {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return lis
}

func TestRunErrors(t *testing.T) {
	ctx := context.Background()
	cfg := config.Config{DatabaseDSN: "::bad::", JWTSecret: "s", TLSCert: "missing.crt", TLSKey: "missing.key"}
	if err := run(ctx, cfg, listen(t), zap.NewNop()); err == nil {
		t.Fatal("expected TLS error")
	}
	certs := testcert.Write(t, t.TempDir())
	cfg.TLSCert, cfg.TLSKey = certs.Cert, certs.Key
	if err := run(ctx, cfg, listen(t), zap.NewNop()); err == nil {
		t.Fatal("expected database error")
	}
}

func TestRunServesAndStops(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN is not set")
	}
	lis := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	certs := testcert.Write(t, t.TempDir())
	go func() {
		done <- run(ctx, config.Config{DatabaseDSN: dsn, JWTSecret: "s", TLSCert: certs.Cert, TLSKey: certs.Key}, lis, zap.NewNop())
	}()

	creds, err := credentials.NewClientTLSFromFile(certs.CA, "")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	login := "smoke-" + time.Now().Format("150405.000000")
	_, err = pb.NewAuthServiceClient(conn).Register(ctx, pb.AuthRequest_builder{Login: login, AuthKey: bytes.Repeat([]byte{1}, 32)}.Build())
	if err != nil {
		t.Fatal(err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not stop")
	}
}
