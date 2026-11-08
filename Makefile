MODULE  := github.com/magicelemental11/gophkeeper
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo N/A)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo N/A)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/buildinfo.Version=$(VERSION) \
	-X $(MODULE)/internal/buildinfo.Date=$(DATE) \
	-X $(MODULE)/internal/buildinfo.Commit=$(COMMIT)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: build release proto test cover certs clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-server ./cmd/server
	go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper ./cmd/client

release:
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; \
		[ $$os = windows ] && ext=.exe; \
		echo "dist/gophkeeper-$$os-$$arch$$ext"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" \
			-o dist/gophkeeper-$$os-$$arch$$ext ./cmd/client || exit 1; \
	done

proto:
	go generate ./internal/proto

test:
	go test -race -p 1 ./...

cover:
	go test -race -p 1 -coverprofile=cover.out ./...
	grep -v '\.pb\.go' cover.out > cover.filtered.out
	go tool cover -func=cover.filtered.out | tail -1

certs:
	./scripts/gencert.sh certs

clean:
	rm -rf bin dist cover.out cover.filtered.out
