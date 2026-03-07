SHELL := /bin/bash

GO ?= go
APP_NAME ?= mamotama-center
BIN_DIR ?= bin
PKG ?= ./cmd/mamotama-center
CONFIG ?= ./center.config.json
VERSION ?= dev
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS ?= -X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT) -X main.buildDate=$(BUILD_DATE)

.PHONY: help fmt test test-race vet check build run config-check db-init db-check db-migrate device-revoke device-policy-download clean

help:
	@echo "Targets:"
	@echo "  make build         Build local binary"
	@echo "  make run           Run with CONFIG=./center.config.json"
	@echo "  make config-check  Validate center config and exit"
	@echo "  make db-init       Initialize SQLite schema and exit"
	@echo "  make db-check      Verify SQLite schema and exit"
	@echo "  make db-migrate    Apply SQLite migration(s) and exit"
	@echo "  make device-revoke Revoke active key for one device (CENTER_URL + DEVICE_ID required)"
	@echo "    - optional: REASON='compromised'"
	@echo "    - optional: CENTER_ADMIN_API_KEY_FILE=..."
	@echo "  make device-policy-download Download desired/current policy for one device"
	@echo "    - required: CENTER_URL, DEVICE_ID"
	@echo "    - optional: POLICY_STATE=desired|current (default desired)"
	@echo "    - optional: POLICY_FORMAT=raw|json (default raw)"
	@echo "    - optional: OUT=<output_file>"
	@echo "    - optional: CENTER_ADMIN_API_KEY_FILE=..."
	@echo "  make test          Run tests"
	@echo "  make test-race     Run tests with race detector"
	@echo "  make fmt           Format Go code"
	@echo "  make vet           Run go vet"
	@echo "  make check         Run fmt + vet + test"
	@echo "  make clean         Remove built binaries"

fmt:
	$(GO) fmt ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

check: fmt vet test

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME) $(PKG)

run:
	$(GO) run $(PKG) -config $(CONFIG)

config-check:
	$(GO) run $(PKG) -config $(CONFIG) -validate-config

db-init:
	$(GO) run $(PKG) -config $(CONFIG) -db-init

db-check:
	$(GO) run $(PKG) -config $(CONFIG) -db-check

db-migrate:
	$(GO) run $(PKG) -config $(CONFIG) -db-migrate

device-revoke:
	@if [ -z "$(CENTER_URL)" ]; then \
		echo "CENTER_URL is required"; \
		exit 1; \
	fi
	@if [ -z "$(DEVICE_ID)" ]; then \
		echo "DEVICE_ID is required"; \
		exit 1; \
	fi
	CENTER_ADMIN_API_KEY="$(CENTER_ADMIN_API_KEY)" CENTER_ADMIN_API_KEY_FILE="$(CENTER_ADMIN_API_KEY_FILE)" \
		bash ./scripts/center_revoke.sh "$(CENTER_URL)" "$(DEVICE_ID)" "$(REASON)"

device-policy-download:
	@if [ -z "$(CENTER_URL)" ]; then \
		echo "CENTER_URL is required"; \
		exit 1; \
	fi
	@if [ -z "$(DEVICE_ID)" ]; then \
		echo "DEVICE_ID is required"; \
		exit 1; \
	fi
	CENTER_ADMIN_API_KEY="$(CENTER_ADMIN_API_KEY)" CENTER_ADMIN_API_KEY_FILE="$(CENTER_ADMIN_API_KEY_FILE)" \
	POLICY_FORMAT="$(POLICY_FORMAT)" \
		bash ./scripts/center_policy_download.sh "$(CENTER_URL)" "$(DEVICE_ID)" "$(POLICY_STATE)" "$(OUT)"

clean:
	rm -rf $(BIN_DIR)
