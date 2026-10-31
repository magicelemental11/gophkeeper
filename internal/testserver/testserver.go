// Package testserver runs the GophKeeper server with an in-memory store over an in-memory connection, for tests.
package testserver

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	"github.com/magicelemental11/gophkeeper/internal/client/api"
	"github.com/magicelemental11/gophkeeper/internal/server/auth"
	"github.com/magicelemental11/gophkeeper/internal/server/memstore"
	"github.com/magicelemental11/gophkeeper/internal/server/service"
)

// Address is the target to dial; any value works since connections go through the in-memory listener.
const Address = "passthrough:///bufnet"

// Server is a running test server that can be taken down and brought back with the same data.
type Server struct {
	Store  *memstore.Store
	Issuer *auth.Issuer

	mu  sync.Mutex
	lis *bufconn.Listener
	srv *grpc.Server
}

// Start runs a server and stops it when the test ends.
func Start(tb testing.TB) *Server {
	tb.Helper()
	s := &Server{Store: memstore.New(), Issuer: auth.NewIssuer("test-secret", time.Hour)}
	s.Up()
	tb.Cleanup(s.Down)
	return s
}

// Up starts serving if the server is down.
func (s *Server) Up() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		return
	}
	s.lis = bufconn.Listen(1 << 20)
	s.srv = service.NewServer(s.Store, s.Issuer, zap.NewNop())
	go s.srv.Serve(s.lis)
}

// Down stops the server; clients get api.ErrUnavailable until Up is called.
func (s *Server) Down() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv == nil {
		return
	}
	s.srv.Stop()
	s.srv, s.lis = nil, nil
}

// DialOption routes connections to the current listener.
func (s *Server) DialOption() grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		s.mu.Lock()
		lis := s.lis
		s.mu.Unlock()
		if lis == nil {
			return nil, errors.New("server is down")
		}
		return lis.DialContext(ctx)
	})
}

// Dial returns a client of the server, closed when the test ends.
func (s *Server) Dial(tb testing.TB) *api.Client {
	tb.Helper()
	c, err := api.Dial(Address, "", true, s.DialOption())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { c.Close() })
	return c
}
