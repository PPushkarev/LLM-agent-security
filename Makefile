.PHONY: build build-linux mcp-example test check test-linux

build:
	go build -o guard ./cmd/guard

mcp-example:
	go build -o guard-mcp-example ./cmd/guard-mcp-example

test:
	go test -race ./...

check:
	go vet ./...
	go test -race ./...
	GOOS=linux go build ./...

# On macOS, executes Linux tests in a disposable Docker namespace test lab.
test-linux:
	./scripts/test-linux.sh

build-linux:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/guard-linux-amd64 ./cmd/guard
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o dist/guard-linux-arm64 ./cmd/guard
