// Package auth hashes authentication keys, issues JWT access tokens and checks them in a gRPC interceptor.
package auth

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TokenTTL is how long an issued token stays valid.
const TokenTTL = 24 * time.Hour

// ErrInvalidToken is returned for a malformed, forged or expired token.
var ErrInvalidToken = errors.New("invalid token")

// HashKey returns the bcrypt hash of an authentication key.
func HashKey(key []byte) (string, error) {
	h, err := bcrypt.GenerateFromPassword(key, bcrypt.DefaultCost)
	return string(h), err
}

// CheckKey reports whether key matches a hash made by HashKey.
func CheckKey(hash string, key []byte) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), key) == nil
}

// Issuer signs and verifies HS256 tokens whose subject is the user ID.
type Issuer struct {
	secret []byte
	ttl    time.Duration
}

// NewIssuer returns an Issuer signing with secret; tokens expire after ttl.
func NewIssuer(secret string, ttl time.Duration) *Issuer {
	return &Issuer{secret: []byte(secret), ttl: ttl}
}

// Issue returns a signed token for the user.
func (i *Issuer) Issue(userID int64) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   strconv.FormatInt(userID, 10),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(i.ttl)),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(i.secret)
}

// Parse verifies the token and returns the user ID from it, or ErrInvalidToken.
func (i *Issuer) Parse(token string) (int64, error) {
	var claims jwt.RegisteredClaims
	_, err := jwt.ParseWithClaims(token, &claims, func(*jwt.Token) (any, error) { return i.secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired())
	if err != nil {
		return 0, ErrInvalidToken
	}
	id, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil || id <= 0 {
		return 0, ErrInvalidToken
	}
	return id, nil
}

type userIDKey struct{}

// WithUserID returns a context carrying the authenticated user ID.
func WithUserID(ctx context.Context, id int64) context.Context {
	return context.WithValue(ctx, userIDKey{}, id)
}

// UserID returns the user ID put into ctx by the interceptor.
func UserID(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(userIDKey{}).(int64)
	return id, ok
}

// UnaryInterceptor requires an "authorization: Bearer <token>" metadata entry on every method
// except the full method names in public, and puts the user ID from the token into the context.
// Calls without a valid token fail with codes.Unauthenticated.
func UnaryInterceptor(issuer *Issuer, public map[string]bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		if public[info.FullMethod] {
			return next(ctx, req)
		}
		md, _ := metadata.FromIncomingContext(ctx)
		values := md.Get("authorization")
		if len(values) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing token")
		}
		token, ok := strings.CutPrefix(values[0], "Bearer ")
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "invalid authorization format")
		}
		id, err := issuer.Parse(token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		return next(WithUserID(ctx, id), req)
	}
}
