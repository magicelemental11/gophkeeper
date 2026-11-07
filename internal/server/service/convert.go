package service

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/magicelemental11/gophkeeper/internal/proto"
	"github.com/magicelemental11/gophkeeper/internal/server/storage"
)

func toProto(it storage.Item) *pb.Item {
	return pb.Item_builder{
		Id:        it.ID.String(),
		Version:   it.Version,
		Revision:  it.Revision,
		Deleted:   it.Deleted,
		Name:      it.Name,
		Meta:      it.Meta,
		Payload:   it.Payload,
		UpdatedAt: timestamppb.New(it.UpdatedAt),
	}.Build()
}

func toProtoList(items []storage.Item) []*pb.Item {
	out := make([]*pb.Item, len(items))
	for i, it := range items {
		out[i] = toProto(it)
	}
	return out
}
