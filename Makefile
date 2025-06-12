# Go MCP Library Makefile
# ========================

# Project configuration
PROJECT_NAME = gomcp
MODULE_NAME = github.com/dhirajsb/gomcp
GO_VERSION = 1.21

# Build configuration
BUILD_DIR = build
BIN_DIR = bin
BINARY_NAME = $(PROJECT_NAME)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME = $(shell date -u '+%Y-%m-%d_%H:%M:%S')
COMMIT = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go build flags
LDFLAGS = -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.commit=$(COMMIT)"
BUILD_FLAGS = -v $(LDFLAGS)

# Tool paths
GOBIN = $(shell pwd)/$(BIN_DIR)
PATH := $(GOBIN):$(PATH)
export GOBIN
export PATH

# Coverage configuration
COVERAGE_DIR = coverage
COVERAGE_FILE = $(COVERAGE_DIR)/coverage.out
COVERAGE_HTML = $(COVERAGE_DIR)/coverage.html

# Linting and formatting
GOLANGCI_LINT_VERSION = v1.61.0

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[0;33m
BLUE = \033[0;34m
MAGENTA = \033[0;35m
CYAN = \033[0;36m
WHITE = \033[0;37m
RESET = \033[0m

.PHONY: help
help: ## Display this help message
	@echo "$(CYAN)Go MCP Library - Available Commands$(RESET)"
	@echo "====================================="
	@awk 'BEGIN {FS = ":.*##"; printf "\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(GREEN)%-15s$(RESET) %s\n", $$1, $$2 } /^##@/ { printf "\n$(YELLOW)%s$(RESET)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@echo ""

##@ Development

.PHONY: install
install: ## Install project dependencies
	@echo "$(BLUE)Installing dependencies...$(RESET)"
	go mod download
	go mod tidy

.PHONY: build
build: clean ## Build the library
	@echo "$(BLUE)Building library...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	go build $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./...

.PHONY: build-examples
build-examples: ## Build all example applications
	@echo "$(BLUE)Building examples...$(RESET)"
	@mkdir -p $(BUILD_DIR)/examples
	go build $(BUILD_FLAGS) -o $(BUILD_DIR)/examples/simple ./examples/simple
	go build $(BUILD_FLAGS) -o $(BUILD_DIR)/examples/typed ./examples/typed  
	go build $(BUILD_FLAGS) -o $(BUILD_DIR)/examples/http ./examples/http
	@echo "$(GREEN)Examples built successfully!$(RESET)"

.PHONY: run-simple
run-simple: ## Run the simple example
	@echo "$(BLUE)Running simple example...$(RESET)"
	go run ./examples/simple/main.go

.PHONY: run-typed
run-typed: ## Run the typed parameters example
	@echo "$(BLUE)Running typed example...$(RESET)"
	go run ./examples/typed/main.go

.PHONY: run-http
run-http: ## Run the HTTP server example
	@echo "$(BLUE)Running HTTP example on localhost:8080...$(RESET)"
	go run ./examples/http/main.go

##@ Testing

.PHONY: test
test: ## Run all tests
	@echo "$(BLUE)Running tests...$(RESET)"
	go test ./... -v

.PHONY: test-short
test-short: ## Run tests with short flag (skip long-running tests)
	@echo "$(BLUE)Running short tests...$(RESET)"
	go test ./... -v -short

.PHONY: test-race
test-race: ## Run tests with race detection
	@echo "$(BLUE)Running tests with race detection...$(RESET)"
	go test ./... -v -race

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	@echo "$(BLUE)Running tests with coverage...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	go test ./... -coverprofile=$(COVERAGE_FILE) -covermode=atomic
	go tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	go tool cover -func=$(COVERAGE_FILE)
	@echo "$(GREEN)Coverage report generated: $(COVERAGE_HTML)$(RESET)"

.PHONY: test-bench
test-bench: ## Run benchmark tests
	@echo "$(BLUE)Running benchmark tests...$(RESET)"
	go test ./... -bench=. -benchmem

.PHONY: test-integration
test-integration: ## Run integration tests (if any)
	@echo "$(BLUE)Running integration tests...$(RESET)"
	go test ./... -tags=integration -v

##@ Code Quality

.PHONY: fmt
fmt: ## Format Go code
	@echo "$(BLUE)Formatting code...$(RESET)"
	go fmt ./...
	@echo "$(GREEN)Code formatted successfully!$(RESET)"

.PHONY: vet
vet: ## Run go vet
	@echo "$(BLUE)Running go vet...$(RESET)"
	go vet ./...
	@echo "$(GREEN)Vet completed successfully!$(RESET)"

.PHONY: lint
lint: ## Run golangci-lint
	@echo "$(BLUE)Running golangci-lint...$(RESET)"
	@mkdir -p $(BIN_DIR)
	@if ! test -f $(BIN_DIR)/golangci-lint; then \
		echo "$(YELLOW)Installing golangci-lint...$(RESET)"; \
		GOBIN=$(GOBIN) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
	fi
	$(BIN_DIR)/golangci-lint run ./...
	@echo "$(GREEN)Linting completed successfully!$(RESET)"

.PHONY: lint-fix
lint-fix: ## Run golangci-lint with auto-fix
	@echo "$(BLUE)Running golangci-lint with auto-fix...$(RESET)"
	@mkdir -p $(BIN_DIR)
	@if ! test -f $(BIN_DIR)/golangci-lint; then \
		echo "$(YELLOW)Installing golangci-lint...$(RESET)"; \
		GOBIN=$(GOBIN) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
	fi
	$(BIN_DIR)/golangci-lint run --fix ./...

.PHONY: tidy
tidy: ## Tidy and verify go modules
	@echo "$(BLUE)Tidying modules...$(RESET)"
	go mod tidy
	go mod verify
	@echo "$(GREEN)Modules tidied successfully!$(RESET)"

.PHONY: check
check: fmt vet lint test ## Run all code quality checks
	@echo "$(GREEN)All checks passed!$(RESET)"

.PHONY: security-check
security-check: vuln ## Run security checks including vulnerability scanning
	@echo "$(GREEN)Security checks completed!$(RESET)"

##@ Documentation

.PHONY: docs
docs: ## Generate documentation
	@echo "$(BLUE)Generating documentation...$(RESET)"
	@mkdir -p docs/api
	go doc -all ./... > docs/api/package-docs.txt
	@echo "$(GREEN)Documentation generated in docs/api/$(RESET)"

.PHONY: godoc
godoc: ## Start local godoc server
	@echo "$(BLUE)Starting godoc server on http://localhost:6060$(RESET)"
	@mkdir -p $(BIN_DIR)
	@if ! test -f $(BIN_DIR)/godoc; then \
		echo "$(YELLOW)Installing godoc...$(RESET)"; \
		GOBIN=$(GOBIN) go install golang.org/x/tools/cmd/godoc@latest; \
	fi
	$(BIN_DIR)/godoc -http=:6060

##@ Maintenance

.PHONY: clean
clean: ## Clean build artifacts and cache
	@echo "$(BLUE)Cleaning build artifacts...$(RESET)"
	rm -rf $(BUILD_DIR)
	rm -rf $(COVERAGE_DIR)
	rm -rf $(BIN_DIR)
	go clean -cache -testcache -modcache
	@echo "$(GREEN)Clean completed!$(RESET)"

.PHONY: clean-deps
clean-deps: ## Clean and reinstall dependencies
	@echo "$(BLUE)Cleaning and reinstalling dependencies...$(RESET)"
	go clean -modcache
	rm -f go.sum
	go mod download
	go mod tidy

.PHONY: update-deps
update-deps: ## Update all dependencies
	@echo "$(BLUE)Updating dependencies...$(RESET)"
	go get -u ./...
	go mod tidy
	@echo "$(GREEN)Dependencies updated!$(RESET)"

.PHONY: vuln
vuln: ## Run Go vulnerability checker
	@echo "$(BLUE)Running govulncheck...$(RESET)"
	@mkdir -p $(BIN_DIR)
	@if ! test -f $(BIN_DIR)/govulncheck; then \
		echo "$(YELLOW)Installing govulncheck...$(RESET)"; \
		GOBIN=$(GOBIN) go install golang.org/x/vuln/cmd/govulncheck@latest; \
	fi
	$(BIN_DIR)/govulncheck ./...
	@echo "$(GREEN)Vulnerability check completed!$(RESET)"

.PHONY: security-scan
security-scan: vuln ## Run security vulnerability scan
	@echo "$(GREEN)Security scan completed!$(RESET)"

##@ Release

.PHONY: version
version: ## Display version information
	@echo "$(BLUE)Version Information:$(RESET)"
	@echo "  Project: $(PROJECT_NAME)"
	@echo "  Module:  $(MODULE_NAME)"
	@echo "  Version: $(VERSION)"
	@echo "  Commit:  $(COMMIT)"
	@echo "  Built:   $(BUILD_TIME)"
	@echo "  Go:      $(shell go version)"

.PHONY: tag
tag: ## Create a new git tag (use VERSION=x.x.x)
	@if [ -z "$(VERSION)" ] || [ "$(VERSION)" = "dev" ]; then \
		echo "$(RED)Please specify VERSION (e.g., make tag VERSION=1.0.0)$(RESET)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Creating tag $(VERSION)...$(RESET)"
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git push origin v$(VERSION)
	@echo "$(GREEN)Tag v$(VERSION) created and pushed!$(RESET)"

.PHONY: release-check
release-check: clean check test-coverage ## Run all checks before release
	@echo "$(GREEN)Release checks completed successfully!$(RESET)"

##@ Docker (Future)

.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(RESET)"
	@echo "$(YELLOW)Docker support not implemented yet$(RESET)"

.PHONY: docker-run
docker-run: ## Run Docker container
	@echo "$(BLUE)Running Docker container...$(RESET)"
	@echo "$(YELLOW)Docker support not implemented yet$(RESET)"

##@ CI/CD

.PHONY: ci
ci: install check test-coverage ## Run CI pipeline locally
	@echo "$(GREEN)CI pipeline completed successfully!$(RESET)"

.PHONY: pre-commit
pre-commit: fmt vet lint test-short ## Run pre-commit checks
	@echo "$(GREEN)Pre-commit checks passed!$(RESET)"

.PHONY: setup-hooks
setup-hooks: ## Setup git hooks
	@echo "$(BLUE)Setting up git hooks...$(RESET)"
	@mkdir -p .git/hooks
	@echo '#!/bin/bash\nmake pre-commit' > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "$(GREEN)Git hooks setup completed!$(RESET)"

##@ Information

.PHONY: status
status: ## Show project status
	@echo "$(CYAN)Project Status$(RESET)"
	@echo "=============="
	@echo "  Go version: $(shell go version)"
	@echo "  Module:     $(MODULE_NAME)"
	@echo "  Version:    $(VERSION)"
	@echo "  Build dir:  $(BUILD_DIR)"
	@echo ""
	@echo "$(CYAN)Dependencies:$(RESET)"
	@go list -m all | head -10
	@echo ""
	@echo "$(CYAN)Test Status:$(RESET)"
	@go test ./... -short | grep -E "(PASS|FAIL|ok)"

.PHONY: deps
deps: ## List project dependencies
	@echo "$(BLUE)Project Dependencies:$(RESET)"
	go list -m all

.PHONY: tools
tools: ## Install development tools
	@echo "$(BLUE)Installing development tools...$(RESET)"
	@mkdir -p $(BIN_DIR)
	GOBIN=$(GOBIN) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	GOBIN=$(GOBIN) go install golang.org/x/tools/cmd/godoc@latest
	GOBIN=$(GOBIN) go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "$(GREEN)Development tools installed in $(BIN_DIR)!$(RESET)"

# Default target
.DEFAULT_GOAL := help