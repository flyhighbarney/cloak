.PHONY: build build-policyd build-policyctl test race run docker fmt vet tidy install-cli clean

# Build both binaries.
build: build-policyd build-policyctl

build-policyd:
	go build -trimpath -o ./bin/policyd ./cmd/policyd

build-policyctl:
	go build -trimpath -o ./bin/policyctl ./cmd/policyctl

test:
	go test ./...

race:
	go test -race ./...

run:
	go run ./cmd/policyd --config ./configs

fmt:
	gofmt -w .

vet:
	go vet ./...

tidy:
	go mod tidy

docker:
	docker build -t policyd:local .

install-cli: build-policyctl
	cp ./bin/policyctl $(GOPATH)/bin/policyctl 2>/dev/null || cp ./bin/policyctl /usr/local/bin/policyctl

clean:
	rm -rf ./bin
