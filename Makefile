.PHONY: help build run-dpkid run-client test test-coverage lint fmt clean

BINARY_DIR=./bin
DPKID=$(BINARY_DIR)/dpkid
DPKI_CLI=$(BINARY_DIR)/dpki-cli

help:
	@echo "Available targets:"
	@echo "  build      - Build a binary"
	@echo "  run-dpkid  - Build and run a dpkid binary"
	@echo "  run-client - Build and run a client binary"
	@echo "  test       - Run tests"
	@echo "  test-cover - Run tests with coverage"
	@echo "  lint       - Lint code"
	@echo "  fmt        - Format code"
	@echo "  clean      - Delete built binaries"

build:
	@mkdir -p $(BINARY_DIR)
	go build -o $(DPKID) ./cmd/dpkid
	go build -o $(DPKI_CLI) ./cmd/dpki-cli

run-dpkid:
	@mkdir -p $(BINARY_DIR)
	go build -o $(DPKID) ./cmd/dpkid
	$(DPKID)

run-client:
	@mkdir -p $(BINARY_DIR)
	go build -o $(DPKI_CLI) ./cmd/dpki-cli
	$(DPKI_CLI)

test:
	go test -v -race ./...
	
test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

fmt:
	gofumpt -w .
	goimports -w .

clean:
	rm -rf $(BINARY_DIR) coverage.out coverage.html
