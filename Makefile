.PHONY: build build-daemon build-cli test race run fmt vet tidy docker install-cli clean

# Version stamps injected into the daemon so every log line carries the build
# identity (see cmd/cloakline/buildinfo.go). Overridable: `make build VERSION=v0.1.3`.
VERSION    ?= dev
COMMIT     ?= $(shell git rev-parse HEAD 2>/dev/null)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)

# Build both binaries.
build: build-daemon build-cli

build-daemon:
	go build -trimpath -ldflags "$(LDFLAGS)" -o ./bin/cloakline.exe ./cmd/cloakline

build-cli:
	go build -trimpath -o ./bin/cloak.exe ./cmd/cloak

test:
	go test ./...

race:
	go test -race ./...

run:
	go run ./cmd/cloakline --config ./configs

fmt:
	gofmt -w .

vet:
	go vet ./...

tidy:
	go mod tidy

docker:
	docker build -t cloakline:local .

install-cli: build-cli
	cp ./bin/cloak.exe $(GOPATH)/bin/cloak.exe 2>/dev/null || cp ./bin/cloak.exe /usr/local/bin/cloak

clean:
	rm -rf ./bin
