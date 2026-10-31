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
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/magicelemental11/gophkeeper/internal/proto"
	"github.com/magicelemental11/gophkeeper/internal/server/config"
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
	cfg.Insecure = true
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
	go func() {
		done <- run(ctx, config.Config{DatabaseDSN: dsn, JWTSecret: "s", Insecure: true}, lis, zap.NewNop())
	}()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	login := "smoke-" + time.Now().Format("150405.000000")
	_, err = pb.NewAuthServiceClient(conn).Register(ctx, &pb.AuthRequest{Login: login, AuthKey: bytes.Repeat([]byte{1}, 32)})
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
