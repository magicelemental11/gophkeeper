// Command server runs the GophKeeper gRPC server.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/magicelemental11/gophkeeper/internal/buildinfo"
	"github.com/magicelemental11/gophkeeper/internal/server/auth"
	"github.com/magicelemental11/gophkeeper/internal/server/config"
	"github.com/magicelemental11/gophkeeper/internal/server/service"
	"github.com/magicelemental11/gophkeeper/internal/server/storage"
)

const shutdownTimeout = 10 * time.Second

func main() {
	buildinfo.Fprint(os.Stdout, "gophkeeper server")

	cfg, err := config.Load(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal(err)
	}
	defer logger.Sync()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	lis, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		logger.Fatal("listen", zap.Error(err))
	}
	if err := run(ctx, cfg, lis, logger); err != nil {
		logger.Fatal("server stopped", zap.Error(err))
	}
}

func run(ctx context.Context, cfg config.Config, lis net.Listener, logger *zap.Logger) error {
	var opts []grpc.ServerOption
	if !cfg.Insecure {
		creds, err := credentials.NewServerTLSFromFile(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			lis.Close()
			return fmt.Errorf("load TLS: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	store, err := storage.New(ctx, cfg.DatabaseDSN)
	if err != nil {
		lis.Close()
		return err
	}
	defer store.Close()

	srv := service.NewServer(store, auth.NewIssuer(cfg.JWTSecret, auth.TokenTTL), logger, opts...)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(lis) }()
	logger.Info("server started", zap.String("address", lis.Addr().String()), zap.Bool("tls", !cfg.Insecure))

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	stopped := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(shutdownTimeout):
		srv.Stop()
		<-stopped
	}
	return nil
}
