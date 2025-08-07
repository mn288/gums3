SHELL := /usr/bin/env bash

BIN_DIR := bin
DIST_DIR := dist

TARGETS := \
	linux   amd64 gums3-linux_amd64 \
	darwin  amd64 gums3-darwin_amd64 \
	darwin  arm64 gums3-darwin_arm64 \
	windows amd64 gums3-windows_amd64.exe

.PHONY: help build cross dist run-server run-cli checksum clean tidy fmt

help:
	@echo "Targets: build cross dist run-server run-cli checksum tidy fmt clean"

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(DIST_DIR):
	@mkdir -p $(DIST_DIR)

build: $(BIN_DIR)
	CGO_ENABLED=0 go build -o $(BIN_DIR)/gums3 .
	@echo "Built $(BIN_DIR)/gums3"

cross: $(BIN_DIR)
	@set -euo pipefail; \
	arr=($(TARGETS)); \
	for ((i=0; i<$$(( $${#arr[@]} / 3 )); i++)); do \
		GOOS=$${arr[$$((i*3))]}; GOARCH=$${arr[$$((i*3+1))]}; OUT=$${arr[$$((i*3+2))]}; \
		echo "Building $(BIN_DIR)/$$OUT"; \
		CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH go build -o $(BIN_DIR)/$$OUT .; \
	done; \
	ls -lah $(BIN_DIR)

dist: $(DIST_DIR)
	@set -euo pipefail; \
	arr=($(TARGETS)); \
	for ((i=0; i<$$(( $${#arr[@]} / 3 )); i++)); do \
		GOOS=$${arr[$$((i*3))]}; GOARCH=$${arr[$$((i*3+1))]}; OUT=$${arr[$$((i*3+2))]}; \
		echo "Building $(DIST_DIR)/$$OUT"; \
		CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH go build -o $(DIST_DIR)/$$OUT .; \
	done; \
	cd $(DIST_DIR) && sha256sum * > SHA256SUMS.txt && ls -lah

run-server:
	go run . server -p $${PORT:-8080} --insecure

run-cli:
	go run . cli $${ARGS:-}

checksum: $(DIST_DIR)
	@cd $(DIST_DIR) && sha256sum * > SHA256SUMS.txt && cat SHA256SUMS.txt

tidy:
	go mod tidy

fmt:
	go fmt ./...

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)
	@echo "Cleaned $(BIN_DIR) and $(DIST_DIR)"


