// Package service implements the AuthService and VaultService gRPC services.
package service

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	pb "github.com/magicelemental11/gophkeeper/internal/proto"
	"github.com/magicelemental11/gophkeeper/internal/server/auth"
)

// MaxMessageSize limits gRPC messages in both directions.
const MaxMessageSize = 16 << 20

// PublicMethods are the full method names callable without a token.
var PublicMethods = map[string]bool{
	pb.AuthService_Register_FullMethodName: true,
	pb.AuthService_Login_FullMethodName:    true,
}

// Store is the storage both services need; *storage.Storage implements it.
type Store interface {
	UserStore
	ItemStore
}

// NewServer returns a gRPC server with both services registered behind the logging and auth interceptors.
// Extra options, such as TLS credentials, are appended.
func NewServer(store Store, issuer *auth.Issuer, logger *zap.Logger, opts ...grpc.ServerOption) *grpc.Server {
	opts = append([]grpc.ServerOption{
		grpc.MaxRecvMsgSize(MaxMessageSize),
		grpc.MaxSendMsgSize(MaxMessageSize),
		grpc.ChainUnaryInterceptor(Logging(logger), auth.UnaryInterceptor(issuer, PublicMethods)),
	}, opts...)
	srv := grpc.NewServer(opts...)
	pb.RegisterAuthServiceServer(srv, NewAuthServer(store, issuer, logger))
	pb.RegisterVaultServiceServer(srv, NewVaultServer(store, logger))
	return srv
}

// Logging logs the method, status code and duration of every call.
func Logging(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := next(ctx, req)
		logger.Info("grpc request",
			zap.String("method", info.FullMethod),
			zap.String("code", status.Code(err).String()),
			zap.Duration("duration", time.Since(start)),
		)
		return resp, err
	}
}
