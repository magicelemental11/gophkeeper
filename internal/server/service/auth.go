package service

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/magicelemental11/gophkeeper/internal/proto"
	"github.com/magicelemental11/gophkeeper/internal/server/auth"
	"github.com/magicelemental11/gophkeeper/internal/server/storage"
)

// AuthKeySize is the length of the authentication key derived on the client.
const AuthKeySize = 32

// UserStore keeps user accounts; *storage.Storage implements it.
type UserStore interface {
	CreateUser(ctx context.Context, login, authHash string) (int64, error)
	UserByLogin(ctx context.Context, login string) (storage.User, error)
}

// AuthServer implements pb.AuthServiceServer.
type AuthServer struct {
	pb.UnimplementedAuthServiceServer
	users  UserStore
	issuer *auth.Issuer
	logger *zap.Logger
}

// NewAuthServer returns an AuthServer on top of the user store.
func NewAuthServer(users UserStore, issuer *auth.Issuer, logger *zap.Logger) *AuthServer {
	return &AuthServer{users: users, issuer: issuer, logger: logger}
}

// Register creates a user and returns a token, or codes.AlreadyExists if the login is taken.
// Logins are case-insensitive.
func (s *AuthServer) Register(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	login, err := validateAuth(req)
	if err != nil {
		return nil, err
	}
	hash, err := auth.HashKey(req.GetAuthKey())
	if err != nil {
		return nil, s.internal("hash key", err)
	}
	id, err := s.users.CreateUser(ctx, login, hash)
	if errors.Is(err, storage.ErrLoginTaken) {
		return nil, status.Error(codes.AlreadyExists, "login is already taken")
	}
	if err != nil {
		return nil, s.internal("create user", err)
	}
	s.logger.Info("user registered", zap.String("login", maskLogin(login)), zap.Int64("user_id", id))
	return s.token(id)
}

// Login checks the login and key and returns a token. Unknown login and wrong key give the same
// codes.Unauthenticated error.
func (s *AuthServer) Login(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	login, err := validateAuth(req)
	if err != nil {
		return nil, err
	}
	u, err := s.users.UserByLogin(ctx, login)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, s.internal("find user", err)
	}
	if err != nil || !auth.CheckKey(u.AuthHash, req.GetAuthKey()) {
		s.logger.Info("login failed", zap.String("login", maskLogin(login)))
		return nil, status.Error(codes.Unauthenticated, "invalid login or password")
	}
	return s.token(u.ID)
}

func (s *AuthServer) token(userID int64) (*pb.AuthResponse, error) {
	tok, err := s.issuer.Issue(userID)
	if err != nil {
		return nil, s.internal("issue token", err)
	}
	return pb.AuthResponse_builder{Token: tok}.Build(), nil
}

func (s *AuthServer) internal(op string, err error) error {
	s.logger.Error(op, zap.Error(err))
	return status.Error(codes.Internal, "internal error")
}

func validateAuth(req *pb.AuthRequest) (string, error) {
	login := strings.ToLower(strings.TrimSpace(req.GetLogin()))
	if n := utf8.RuneCountInString(login); n < 3 || n > 64 {
		return "", status.Error(codes.InvalidArgument, "login must be 3 to 64 characters")
	}
	if len(req.GetAuthKey()) != AuthKeySize {
		return "", status.Error(codes.InvalidArgument, "auth key must be 32 bytes")
	}
	return login, nil
}

func maskLogin(login string) string {
	r := []rune(login)
	if len(r) <= 2 {
		return "***"
	}
	return string(r[:2]) + "***"
}
