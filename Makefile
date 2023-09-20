export SHELL := /bin/bash
export SHELLOPTS := errexit

GOPATH ?= $(shell go env GOPATH)
BIN_DIR := $(GOPATH)/bin
GOLANGCI_LINT := $(BIN_DIR)/golangci-lint

.PHONY: lint lintfix test build

$(GOLANGCI_LINT):
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(BIN_DIR) v1.54.2

lint: $(GOLANGCI_LINT)
	@$(GOLANGCI_LINT) run

lintfix: $(GOLANGCI_LINT)
	@$(GOLANGCI_LINT) run --fix

test:
	go test -race ./...

build:
	go build -o vuln-list-update .
