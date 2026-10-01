VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/wsjrosiris/serverbrain/internal/agent.Version=$(VERSION)

.PHONY: all build test vet dist clean run

all: vet test build

build:
	go build -o bin/sb-server ./cmd/sb-server
	go build -ldflags "$(LDFLAGS)" -o bin/sb-agent ./cmd/sb-agent

test:
	go test -race ./...

vet:
	go vet ./...
	GOOS=windows go vet ./...

# Release binaries: control plane for Linux/Windows, agent for Windows (+Linux for dev).
dist:
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/sb-server-linux-amd64 ./cmd/sb-server
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/sb-server-windows-amd64.exe ./cmd/sb-server
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/sb-agent-windows-amd64.exe ./cmd/sb-agent
	GOOS=windows GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/sb-agent-windows-arm64.exe ./cmd/sb-agent
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/sb-agent-linux-amd64 ./cmd/sb-agent

run: build
	./bin/sb-server -addr 127.0.0.1:8080 -db serverbrain.db

clean:
	rm -rf bin dist
