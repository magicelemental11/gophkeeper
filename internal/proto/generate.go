// Package proto holds the Go code generated from api/proto/gophkeeper.proto.
//
// Regenerating needs protoc and the plugins pinned below:
//
//	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
//	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
//	go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@v2.33.0
//	go generate ./internal/proto
package proto

//go:generate protoc --proto_path=../../api/proto --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative --openapiv2_out=../../api/openapi --openapiv2_opt=output_format=json gophkeeper.proto
