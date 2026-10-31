package auth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestHashKey(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	h, err := HashKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if !CheckKey(h, key) {
		t.Error("right key rejected")
	}
	if CheckKey(h, []byte("0123456789abcdef0123456789abcdeX")) {
		t.Error("wrong key accepted")
	}
	if CheckKey("not a hash", key) {
		t.Error("broken hash accepted")
	}
}

func TestIssuer(t *testing.T) {
	i := NewIssuer("secret", time.Hour)
	tok, err := i.Issue(42)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := i.Parse(tok); err != nil || id != 42 {
		t.Fatalf("got %d, %v", id, err)
	}

	expired, _ := NewIssuer("secret", -time.Minute).Issue(42)
	forged, _ := NewIssuer("other", time.Hour).Issue(42)
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.RegisteredClaims{
		Subject: "42", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	noExp, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: "42"}).SignedString([]byte("secret"))
	badSub, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: "abc", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).SignedString([]byte("secret"))

	for name, tok := range map[string]string{
		"expired": expired, "forged": forged, "alg none": none, "no exp": noExp, "bad subject": badSub, "garbage": "x.y.z",
	} {
		if _, err := i.Parse(tok); err != ErrInvalidToken {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestUnaryInterceptor(t *testing.T) {
	i := NewIssuer("secret", time.Hour)
	tok, _ := i.Issue(7)
	intercept := UnaryInterceptor(i, map[string]bool{"/public": true})

	tests := []struct {
		name   string
		method string
		md     metadata.MD
		want   codes.Code
		userID int64
	}{
		{"public without token", "/public", nil, codes.OK, 0},
		{"no metadata", "/private", nil, codes.Unauthenticated, 0},
		{"no bearer", "/private", metadata.Pairs("authorization", tok), codes.Unauthenticated, 0},
		{"bad token", "/private", metadata.Pairs("authorization", "Bearer bad"), codes.Unauthenticated, 0},
		{"valid", "/private", metadata.Pairs("authorization", "Bearer "+tok), codes.OK, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.md != nil {
				ctx = metadata.NewIncomingContext(ctx, tt.md)
			}
			var got int64
			_, err := intercept(ctx, nil, &grpc.UnaryServerInfo{FullMethod: tt.method}, func(ctx context.Context, _ any) (any, error) {
				got, _ = UserID(ctx)
				return nil, nil
			})
			if status.Code(err) != tt.want || got != tt.userID {
				t.Fatalf("code %v, user %d", status.Code(err), got)
			}
		})
	}
}
