// Package api is a thin client of the GophKeeper gRPC services that maps status codes to errors.
package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/magicelemental11/gophkeeper/internal/proto"
)

// MaxMessageSize limits gRPC messages in both directions, matching the server.
const MaxMessageSize = 16 << 20

// CallTimeout bounds every call.
const CallTimeout = 30 * time.Second

// Errors mapped from gRPC status codes.
var (
	ErrUnauthenticated = errors.New("not authenticated")
	ErrLoginTaken      = errors.New("login is already taken")
	ErrNotFound        = errors.New("not found")
	ErrUnavailable     = errors.New("server is unavailable")
)

// Item is an encrypted record as stored on the server.
type Item struct {
	ID        uuid.UUID
	Version   int64
	Revision  int64
	Deleted   bool
	Payload   []byte
	UpdatedAt time.Time
}

// ConflictError is returned when the base version is stale; Current is the item on the server.
type ConflictError struct {
	Current Item
}

// Error describes the conflicting item.
func (e *ConflictError) Error() string {
	return fmt.Sprintf("version conflict on item %s", e.Current.ID)
}

// Client calls the AuthService and VaultService. It is safe for concurrent use.
type Client struct {
	conn  *grpc.ClientConn
	auth  pb.AuthServiceClient
	vault pb.VaultServiceClient

	mu    sync.RWMutex
	token string
}

// Dial returns a client of the server at addr. TLS is verified against the CA certificate at caPath,
// or against the system roots when caPath is empty. insecure disables TLS and is meant for local tests.
func Dial(addr, caPath string, insecureConn bool, opts ...grpc.DialOption) (*Client, error) {
	creds := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	switch {
	case insecureConn:
		creds = insecure.NewCredentials()
	case caPath != "":
		var err error
		if creds, err = credentials.NewClientTLSFromFile(caPath, ""); err != nil {
			return nil, fmt.Errorf("load CA: %w", err)
		}
	}
	opts = append([]grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxMessageSize), grpc.MaxCallSendMsgSize(MaxMessageSize)),
	}, opts...)
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, auth: pb.NewAuthServiceClient(conn), vault: pb.NewVaultServiceClient(conn)}, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// SetToken sets the token sent with vault calls.
func (c *Client) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
}

// Register creates a user and returns its token.
func (c *Client) Register(ctx context.Context, login string, authKey []byte) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	resp, err := c.auth.Register(ctx, &pb.AuthRequest{Login: login, AuthKey: authKey})
	if err != nil {
		return "", mapError(err)
	}
	return resp.GetToken(), nil
}

// Login returns a token for an existing user.
func (c *Client) Login(ctx context.Context, login string, authKey []byte) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	resp, err := c.auth.Login(ctx, &pb.AuthRequest{Login: login, AuthKey: authKey})
	if err != nil {
		return "", mapError(err)
	}
	return resp.GetToken(), nil
}

// Upsert creates (baseVersion 0) or replaces an item.
func (c *Client) Upsert(ctx context.Context, id uuid.UUID, baseVersion int64, payload []byte) (Item, error) {
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	return item(c.vault.Upsert(ctx, &pb.UpsertRequest{Id: id.String(), BaseVersion: baseVersion, Payload: payload}))
}

// Delete turns an item into a tombstone.
func (c *Client) Delete(ctx context.Context, id uuid.UUID, baseVersion int64) (Item, error) {
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	return item(c.vault.Delete(ctx, &pb.DeleteRequest{Id: id.String(), BaseVersion: baseVersion}))
}

// Get returns a single item.
func (c *Client) Get(ctx context.Context, id uuid.UUID) (Item, error) {
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	return item(c.vault.Get(ctx, &pb.GetRequest{Id: id.String()}))
}

// Sync returns a page of items changed after since, the revision to continue from and whether
// more pages follow.
func (c *Client) Sync(ctx context.Context, since int64) ([]Item, int64, bool, error) {
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	resp, err := c.vault.Sync(ctx, &pb.SyncRequest{SinceRevision: since})
	if err != nil {
		return nil, 0, false, mapError(err)
	}
	items := make([]Item, 0, len(resp.GetItems()))
	for _, p := range resp.GetItems() {
		it, err := fromProto(p)
		if err != nil {
			return nil, 0, false, err
		}
		items = append(items, it)
	}
	return items, resp.GetRevision(), resp.GetHasMore(), nil
}

func (c *Client) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	return context.WithTimeout(ctx, CallTimeout)
}

func item(p *pb.Item, err error) (Item, error) {
	if err != nil {
		return Item{}, mapError(err)
	}
	return fromProto(p)
}

func fromProto(p *pb.Item) (Item, error) {
	id, err := uuid.Parse(p.GetId())
	if err != nil {
		return Item{}, fmt.Errorf("server returned a bad item id: %w", err)
	}
	return Item{
		ID:        id,
		Version:   p.GetVersion(),
		Revision:  p.GetRevision(),
		Deleted:   p.GetDeleted(),
		Payload:   p.GetPayload(),
		UpdatedAt: p.GetUpdatedAt().AsTime(),
	}, nil
}

func mapError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.Unauthenticated:
		return ErrUnauthenticated
	case codes.AlreadyExists:
		return ErrLoginTaken
	case codes.NotFound:
		return ErrNotFound
	case codes.Unavailable, codes.DeadlineExceeded:
		return fmt.Errorf("%w: %s", ErrUnavailable, st.Message())
	case codes.Aborted:
		for _, d := range st.Details() {
			if p, ok := d.(*pb.Item); ok {
				if cur, err := fromProto(p); err == nil {
					return &ConflictError{Current: cur}
				}
			}
		}
	}
	return fmt.Errorf("server: %s", st.Message())
}
