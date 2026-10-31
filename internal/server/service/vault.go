package service

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/magicelemental11/gophkeeper/internal/proto"
	"github.com/magicelemental11/gophkeeper/internal/server/auth"
	"github.com/magicelemental11/gophkeeper/internal/server/storage"
)

// MaxPayloadSize limits an encrypted item: 10 MiB of data plus room for serialization and encryption.
const MaxPayloadSize = 11 << 20

// SyncPageSize is the payload budget of one Sync response, keeping it under MaxMessageSize.
// A response always holds at least one item.
const SyncPageSize = 12 << 20

// ItemStore keeps encrypted items; *storage.Storage implements it.
type ItemStore interface {
	Upsert(ctx context.Context, userID int64, id uuid.UUID, baseVersion int64, payload []byte) (storage.Item, error)
	Delete(ctx context.Context, userID int64, id uuid.UUID, baseVersion int64) (storage.Item, error)
	Get(ctx context.Context, userID int64, id uuid.UUID) (storage.Item, error)
	ChangesSince(ctx context.Context, userID int64, since int64, maxBytes int) (storage.Changes, error)
}

// VaultServer implements pb.VaultServiceServer. The user always comes from the token in the context.
type VaultServer struct {
	pb.UnimplementedVaultServiceServer
	items  ItemStore
	logger *zap.Logger
}

// NewVaultServer returns a VaultServer on top of the item store.
func NewVaultServer(items ItemStore, logger *zap.Logger) *VaultServer {
	return &VaultServer{items: items, logger: logger}
}

// Upsert creates or replaces an item. A version mismatch returns codes.Aborted with the current item
// in the status details.
func (s *VaultServer) Upsert(ctx context.Context, req *pb.UpsertRequest) (*pb.Item, error) {
	userID, id, err := s.target(ctx, req.GetId(), req.GetBaseVersion())
	if err != nil {
		return nil, err
	}
	if n := len(req.GetPayload()); n == 0 || n > MaxPayloadSize {
		return nil, status.Error(codes.InvalidArgument, "payload must be 1 byte to 11 MiB")
	}
	it, err := s.items.Upsert(ctx, userID, id, req.GetBaseVersion(), req.GetPayload())
	return s.result(it, err)
}

// Delete turns an item into a tombstone, with the same version check as Upsert.
func (s *VaultServer) Delete(ctx context.Context, req *pb.DeleteRequest) (*pb.Item, error) {
	userID, id, err := s.target(ctx, req.GetId(), req.GetBaseVersion())
	if err != nil {
		return nil, err
	}
	it, err := s.items.Delete(ctx, userID, id, req.GetBaseVersion())
	return s.result(it, err)
}

// Get returns an item of the user, or codes.NotFound.
func (s *VaultServer) Get(ctx context.Context, req *pb.GetRequest) (*pb.Item, error) {
	userID, id, err := s.target(ctx, req.GetId(), 0)
	if err != nil {
		return nil, err
	}
	it, err := s.items.Get(ctx, userID, id)
	return s.result(it, err)
}

// Sync returns the items changed after since_revision and the current revision.
func (s *VaultServer) Sync(ctx context.Context, req *pb.SyncRequest) (*pb.SyncResponse, error) {
	userID, err := currentUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetSinceRevision() < 0 {
		return nil, status.Error(codes.InvalidArgument, "since_revision must not be negative")
	}
	ch, err := s.items.ChangesSince(ctx, userID, req.GetSinceRevision(), SyncPageSize)
	if err != nil {
		return nil, s.mapError(err)
	}
	return &pb.SyncResponse{Items: toProtoList(ch.Items), Revision: ch.Revision, HasMore: ch.More}, nil
}

func (s *VaultServer) target(ctx context.Context, rawID string, baseVersion int64) (int64, uuid.UUID, error) {
	userID, err := currentUser(ctx)
	if err != nil {
		return 0, uuid.Nil, err
	}
	id, err := uuid.Parse(rawID)
	if err != nil {
		return 0, uuid.Nil, status.Error(codes.InvalidArgument, "id must be a UUID")
	}
	if baseVersion < 0 {
		return 0, uuid.Nil, status.Error(codes.InvalidArgument, "base_version must not be negative")
	}
	return userID, id, nil
}

func (s *VaultServer) result(it storage.Item, err error) (*pb.Item, error) {
	if err != nil {
		return nil, s.mapError(err)
	}
	return toProto(it), nil
}

func (s *VaultServer) mapError(err error) error {
	var conflict *storage.ConflictError
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return status.Error(codes.NotFound, "item not found")
	case errors.As(err, &conflict):
		st, detailErr := status.New(codes.Aborted, "version conflict").WithDetails(toProto(conflict.Current))
		if detailErr != nil {
			s.logger.Error("attach conflict details", zap.Error(detailErr))
			return status.Error(codes.Aborted, "version conflict")
		}
		return st.Err()
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "canceled")
	default:
		s.logger.Error("storage error", zap.Error(err))
		return status.Error(codes.Internal, "internal error")
	}
}

func currentUser(ctx context.Context) (int64, error) {
	id, ok := auth.UserID(ctx)
	if !ok {
		return 0, status.Error(codes.Unauthenticated, "missing user")
	}
	return id, nil
}
