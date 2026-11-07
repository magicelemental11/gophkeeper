package service

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/magicelemental11/gophkeeper/internal/proto"
	"github.com/magicelemental11/gophkeeper/internal/server/auth"
	"github.com/magicelemental11/gophkeeper/internal/server/memstore"
	"github.com/magicelemental11/gophkeeper/internal/testcert"
)

type env struct {
	store *memstore.Store
	auth  pb.AuthServiceClient
	vault pb.VaultServiceClient
}

func newEnv(t *testing.T) *env {
	t.Helper()
	store := memstore.New()
	serverCreds, caPath := testcert.Credentials(t)
	srv := NewServer(store, auth.NewIssuer("secret", time.Hour), zap.NewNop(), grpc.Creds(serverCreds))
	lis := bufconn.Listen(1 << 20)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	clientCreds, err := credentials.NewClientTLSFromFile(caPath, "")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(clientCreds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxMessageSize), grpc.MaxCallSendMsgSize(MaxMessageSize)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &env{store: store, auth: pb.NewAuthServiceClient(conn), vault: pb.NewVaultServiceClient(conn)}
}

var key = bytes.Repeat([]byte{1}, AuthKeySize)

func (e *env) register(t *testing.T, login string) context.Context {
	t.Helper()
	resp, err := e.auth.Register(context.Background(), pb.AuthRequest_builder{Login: login, AuthKey: key}.Build())
	if err != nil {
		t.Fatal(err)
	}
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+resp.GetToken())
}

func code(err error) codes.Code { return status.Code(err) }

func TestAuth(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if _, err := e.auth.Register(ctx, pb.AuthRequest_builder{Login: "  alice  ", AuthKey: key}.Build()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.auth.Register(ctx, pb.AuthRequest_builder{Login: "alice", AuthKey: key}.Build()); code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate: %v", err)
	}
	resp, err := e.auth.Login(ctx, pb.AuthRequest_builder{Login: "alice", AuthKey: key}.Build())
	if err != nil || resp.GetToken() == "" {
		t.Fatalf("login: %v", err)
	}
	wrong := bytes.Repeat([]byte{2}, AuthKeySize)
	_, errWrong := e.auth.Login(ctx, pb.AuthRequest_builder{Login: "alice", AuthKey: wrong}.Build())
	_, errMissing := e.auth.Login(ctx, pb.AuthRequest_builder{Login: "nobody", AuthKey: key}.Build())
	if code(errWrong) != codes.Unauthenticated || errWrong.Error() != errMissing.Error() {
		t.Fatalf("wrong key %v, unknown login %v", errWrong, errMissing)
	}

	for name, b := range map[string]pb.AuthRequest_builder{
		"short login": {Login: "ab", AuthKey: key},
		"long login":  {Login: string(bytes.Repeat([]byte("a"), 65)), AuthKey: key},
		"short key":   {Login: "alice", AuthKey: key[:16]},
	} {
		req := b.Build()
		if _, err := e.auth.Register(ctx, req); code(err) != codes.InvalidArgument {
			t.Errorf("register %s: %v", name, err)
		}
		if _, err := e.auth.Login(ctx, req); code(err) != codes.InvalidArgument {
			t.Errorf("login %s: %v", name, err)
		}
	}

	e.store.Err = errors.New("db down")
	if _, err := e.auth.Register(ctx, pb.AuthRequest_builder{Login: "bob", AuthKey: key}.Build()); code(err) != codes.Internal {
		t.Fatalf("register storage error: %v", err)
	}
	if _, err := e.auth.Login(ctx, pb.AuthRequest_builder{Login: "bob", AuthKey: key}.Build()); code(err) != codes.Internal {
		t.Fatalf("login storage error: %v", err)
	}
}

func TestVaultRequiresToken(t *testing.T) {
	e := newEnv(t)
	if _, err := e.vault.Sync(context.Background(), pb.SyncRequest_builder{}.Build()); code(err) != codes.Unauthenticated {
		t.Fatalf("got %v", err)
	}
}

func TestVault(t *testing.T) {
	e := newEnv(t)
	alice := e.register(t, "alice")
	id := uuid.NewString()

	created, err := e.vault.Upsert(alice, pb.UpsertRequest_builder{Name: "n", Id: id, Payload: []byte("v1")}.Build())
	if err != nil || created.GetVersion() != 1 || created.GetUpdatedAt() == nil {
		t.Fatalf("create: %v, %v", created, err)
	}
	_, err = e.vault.Upsert(alice, pb.UpsertRequest_builder{Name: "n", Id: id, Payload: []byte("again")}.Build())
	if code(err) != codes.Aborted {
		t.Fatalf("conflict: %v", err)
	}
	details := status.Convert(err).Details()
	if len(details) != 1 {
		t.Fatalf("details: %v", details)
	}
	if cur, ok := details[0].(*pb.Item); !ok || cur.GetVersion() != 1 || string(cur.GetPayload()) != "v1" {
		t.Fatalf("detail: %v", details[0])
	}

	if got, err := e.vault.Get(alice, pb.GetRequest_builder{Id: id}.Build()); err != nil || string(got.GetPayload()) != "v1" {
		t.Fatalf("get: %v, %v", got, err)
	}
	if del, err := e.vault.Delete(alice, pb.DeleteRequest_builder{Id: id, BaseVersion: 1}.Build()); err != nil || !del.GetDeleted() {
		t.Fatalf("delete: %v, %v", del, err)
	}
	resp, err := e.vault.Sync(alice, pb.SyncRequest_builder{}.Build())
	if err != nil || resp.GetRevision() != 2 || len(resp.GetItems()) != 1 || !resp.GetItems()[0].GetDeleted() {
		t.Fatalf("sync: %v, %v", resp, err)
	}

	bob := e.register(t, "bob")
	if _, err := e.vault.Get(bob, pb.GetRequest_builder{Id: id}.Build()); code(err) != codes.NotFound {
		t.Fatalf("foreign get: %v", err)
	}
	if _, err := e.vault.Delete(bob, pb.DeleteRequest_builder{Id: id, BaseVersion: 2}.Build()); code(err) != codes.NotFound {
		t.Fatalf("foreign delete: %v", err)
	}
}

func TestSyncPages(t *testing.T) {
	e := newEnv(t)
	ctx := e.register(t, "alice")
	for range 5 {
		if _, err := e.vault.Upsert(ctx, pb.UpsertRequest_builder{Name: "n", Id: uuid.NewString(), Payload: make([]byte, 5<<20)}.Build()); err != nil {
			t.Fatal(err)
		}
	}
	var since int64
	var pages, items int
	for {
		resp, err := e.vault.Sync(ctx, pb.SyncRequest_builder{SinceRevision: since}.Build())
		if err != nil {
			t.Fatal(err)
		}
		pages++
		items += len(resp.GetItems())
		since = resp.GetRevision()
		if !resp.GetHasMore() {
			break
		}
		if last := resp.GetItems()[len(resp.GetItems())-1]; last.GetRevision() != since {
			t.Fatalf("revision %d, last item %d", since, last.GetRevision())
		}
	}
	if pages != 3 || items != 5 || since != 5 {
		t.Fatalf("pages %d, items %d, revision %d", pages, items, since)
	}
}

func TestSearch(t *testing.T) {
	e := newEnv(t)
	alice := e.register(t, "alice")
	for _, name := range []string{"Mail", "bank", "mailbox"} {
		req := pb.UpsertRequest_builder{Id: uuid.NewString(), Name: name, Meta: "meta " + name, Payload: []byte(name)}.Build()
		if _, err := e.vault.Upsert(alice, req); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := e.vault.Search(alice, pb.SearchRequest_builder{Query: "MAIL"}.Build())
	if err != nil || resp.GetHasMore() || len(resp.GetItems()) != 2 {
		t.Fatalf("search: %v, %v", resp, err)
	}
	if got := resp.GetItems()[0]; got.GetName() != "Mail" || got.GetMeta() != "meta Mail" || string(got.GetPayload()) != "Mail" {
		t.Fatalf("item: %v", got)
	}
	bob := e.register(t, "bob")
	if resp, err := e.vault.Search(bob, pb.SearchRequest_builder{}.Build()); err != nil || len(resp.GetItems()) != 0 {
		t.Fatalf("foreign search: %v, %v", resp, err)
	}
	if _, err := e.vault.Search(context.Background(), pb.SearchRequest_builder{}.Build()); code(err) != codes.Unauthenticated {
		t.Fatalf("no token: %v", err)
	}
	e.store.Err = errors.New("db down")
	if _, err := e.vault.Search(alice, pb.SearchRequest_builder{}.Build()); code(err) != codes.Internal {
		t.Fatalf("storage error: %v", err)
	}
}

func TestLoggingLevels(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	interceptor := Logging(zap.New(core))
	info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}
	for _, err := range []error{
		nil,
		status.Error(codes.NotFound, "x"),
		status.Error(codes.Internal, "x"),
		status.Error(codes.DataLoss, "x"),
		errors.New("plain error"),
	} {
		interceptor(context.Background(), nil, info, func(context.Context, any) (any, error) { return nil, err })
	}
	var levels []zapcore.Level
	for _, entry := range logs.All() {
		levels = append(levels, entry.Level)
	}
	want := []zapcore.Level{zap.DebugLevel, zap.DebugLevel, zap.ErrorLevel, zap.ErrorLevel, zap.ErrorLevel}
	if !slices.Equal(levels, want) {
		t.Fatalf("levels %v, want %v", levels, want)
	}
}

func TestLoginCaseInsensitive(t *testing.T) {
	e := newEnv(t)
	if _, err := e.auth.Register(context.Background(), pb.AuthRequest_builder{Login: "Alice", AuthKey: key}.Build()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.auth.Login(context.Background(), pb.AuthRequest_builder{Login: "aLiCe", AuthKey: key}.Build()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.auth.Register(context.Background(), pb.AuthRequest_builder{Login: "ALICE", AuthKey: key}.Build()); code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestVaultValidation(t *testing.T) {
	e := newEnv(t)
	ctx := e.register(t, "alice")
	id := uuid.NewString()
	tests := map[string]func() error{
		"bad id": func() error {
			_, err := e.vault.Upsert(ctx, pb.UpsertRequest_builder{Name: "n", Id: "nope", Payload: []byte("x")}.Build())
			return err
		},
		"empty payload": func() error {
			_, err := e.vault.Upsert(ctx, pb.UpsertRequest_builder{Name: "n", Id: id}.Build())
			return err
		},
		"payload too big": func() error {
			_, err := e.vault.Upsert(ctx, pb.UpsertRequest_builder{Name: "n", Id: id, Payload: make([]byte, MaxPayloadSize+1)}.Build())
			return err
		},
		"negative version": func() error {
			_, err := e.vault.Delete(ctx, pb.DeleteRequest_builder{Id: id, BaseVersion: -1}.Build())
			return err
		},
		"bad get id": func() error {
			_, err := e.vault.Get(ctx, pb.GetRequest_builder{Id: ""}.Build())
			return err
		},
		"empty name": func() error {
			_, err := e.vault.Upsert(ctx, pb.UpsertRequest_builder{Id: id, Payload: []byte("x")}.Build())
			return err
		},
		"long name": func() error {
			_, err := e.vault.Upsert(ctx, pb.UpsertRequest_builder{Name: strings.Repeat("я", MaxNameLength+1), Id: id, Payload: []byte("x")}.Build())
			return err
		},
		"long meta": func() error {
			_, err := e.vault.Upsert(ctx, pb.UpsertRequest_builder{Name: "n", Meta: strings.Repeat("m", MaxMetaSize+1), Id: id, Payload: []byte("x")}.Build())
			return err
		},
		"long query": func() error {
			_, err := e.vault.Search(ctx, pb.SearchRequest_builder{Query: strings.Repeat("q", MaxMetaSize+1)}.Build())
			return err
		},
		"negative revision": func() error {
			_, err := e.vault.Sync(ctx, pb.SyncRequest_builder{SinceRevision: -1}.Build())
			return err
		},
	}
	for name, call := range tests {
		if err := call(); code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.vault.Upsert(ctx, pb.UpsertRequest_builder{Name: "n", Id: id, Payload: make([]byte, MaxPayloadSize)}.Build()); err != nil {
		t.Fatalf("max payload: %v", err)
	}
}

func TestVaultStorageErrors(t *testing.T) {
	e := newEnv(t)
	ctx := e.register(t, "alice")
	e.store.Err = errors.New("db down")
	if _, err := e.vault.Sync(ctx, pb.SyncRequest_builder{}.Build()); code(err) != codes.Internal {
		t.Fatalf("sync: %v", err)
	}
	if _, err := e.vault.Get(ctx, pb.GetRequest_builder{Id: uuid.NewString()}.Build()); code(err) != codes.Internal {
		t.Fatalf("get: %v", err)
	}
	e.store.Err = context.Canceled
	if _, err := e.vault.Get(ctx, pb.GetRequest_builder{Id: uuid.NewString()}.Build()); code(err) != codes.Canceled {
		t.Fatalf("canceled: %v", err)
	}
}

func TestMissingUserInContext(t *testing.T) {
	s := NewVaultServer(memstore.New(), zap.NewNop())
	if _, err := s.Sync(context.Background(), pb.SyncRequest_builder{}.Build()); code(err) != codes.Unauthenticated {
		t.Fatalf("sync: %v", err)
	}
	if _, err := s.Get(context.Background(), pb.GetRequest_builder{Id: uuid.NewString()}.Build()); code(err) != codes.Unauthenticated {
		t.Fatalf("get: %v", err)
	}
}

func TestMaskLogin(t *testing.T) {
	for in, want := range map[string]string{"alice": "al***", "ab": "***", "жёлудь": "жё***"} {
		if got := maskLogin(in); got != want {
			t.Errorf("maskLogin(%q) = %q, want %q", in, got, want)
		}
	}
}
