BINARY     := holmes
SERVER_BIN := holmes_server
INSTALL_DIR := /usr/local/bin

.PHONY: server install uninstall build test clean

## Start the server (builds first, then runs on :8080)
## Loads .env if present (for NVD_API_KEY etc.)
server:
	@echo "Building server..."
	@go build -o $(SERVER_BIN) ./cmd/server
	@echo "Starting holmes server on :8080  (Ctrl+C to stop)"
	@[ -f .env ] && export $$(grep -v '^#' .env | xargs) || true; ./$(SERVER_BIN)

## Build the CLI binary locally (output: ./holmes)
build:
	@go build -o $(BINARY) ./cmd/cli

## Install the CLI to $(INSTALL_DIR) so 'holmes' works from any terminal
install: build
	@echo "Installing $(BINARY) to $(INSTALL_DIR)/$(BINARY)"
	@sudo cp $(BINARY) $(INSTALL_DIR)/$(BINARY)
	@echo "Done. Run: holmes --help"

## Remove the installed CLI binary
uninstall:
	@echo "Removing $(INSTALL_DIR)/$(BINARY)"
	@sudo rm -f $(INSTALL_DIR)/$(BINARY)

## Run all tests
test:
	@go test ./...

## Remove built binaries
clean:
	@rm -f $(BINARY) $(SERVER_BIN)
