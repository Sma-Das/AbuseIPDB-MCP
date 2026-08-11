.PHONY: all build test test-race vet fmt check docker-build

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)

all: check build

build:
	mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/abuseipdb-mcp ./cmd/abuseipdb-mcp

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(rg --files -g '*.go')

check:
	test -z "$$(gofmt -l $$(rg --files -g '*.go'))"
	go vet ./...
	go test ./...

docker-build:
	docker build \
		--build-arg VERSION="$(VERSION)" \
		--build-arg COMMIT="$(COMMIT)" \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		-t abuseipdb-mcp:local .
