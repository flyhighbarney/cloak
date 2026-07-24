.PHONY: build test race run docker fmt vet tidy

build:
	go build -trimpath -o ./bin/policyd ./cmd/policyd

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
