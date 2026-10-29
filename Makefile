.PHONY: build mcp-example test check

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
