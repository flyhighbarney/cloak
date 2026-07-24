.PHONY: build build-daemon build-cli test race run fmt vet tidy docker install-cli clean

# Build both binaries.
build: build-daemon build-cli

build-daemon:
	go build -trimpath -o ./bin/cloakline.exe ./cmd/cloakline

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
