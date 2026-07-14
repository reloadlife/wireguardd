MODULE  := github.com/reloadlife/wireguardd
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: all build test lint cover run-daemon run-ctl cross clean deps

all: build

deps:
	go mod tidy
	go mod download

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/wireguardd ./cmd/wireguardd
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/wireguardctl ./cmd/wireguardctl

test:
	go test -race -count=1 ./...

cover:
	go test -race -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -n 1

lint:
	golangci-lint run ./...

run-daemon: build
	./bin/wireguardd run --config configs/wireguardd.example.yaml

run-ctl: build
	./bin/wireguardctl

cross:
	mkdir -p bin
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/wireguardd-linux-amd64 ./cmd/wireguardd
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/wireguardctl-linux-amd64 ./cmd/wireguardctl
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/wireguardd-linux-arm64 ./cmd/wireguardd
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/wireguardctl-linux-arm64 ./cmd/wireguardctl

clean:
	rm -rf bin dist coverage.out coverage.html
