# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

.DEFAULT_GOAL := help

.PHONY: help all build examples fmt fmt-check lint lint-ci vet vuln test test-multicast coverage coverage-check cover bench fuzz check clean coverpkg-check cross e2e interop interop-images

help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# The parent otfabric/go.work does not list this module.
export GOWORK := off

# Format with the gofmt of the Go version in go.mod, as CI does.
GO_MOD_VERSION := $(shell sed -nE 's/^go ([0-9]+\.[0-9]+).*/\1/p' go.mod | head -n1)
GOFMT_CI = $(shell GOTOOLCHAIN=go$(GO_MOD_VERSION).0 go env GOROOT)/bin/gofmt

BIN_DIR := bin
TEST_PKGS := $(shell go list ./... | grep -v '/examples' | grep -v '/interop')
# Packages whose coverage counts (TESTING.md): not the examples, the
# end-to-end and interop suites or the test helpers.
COVER_PKGS := $(shell go list ./... | grep -v '/examples' | grep -v '/e2e' | grep -v '/interop' | grep -v '/internal/fakeknx' | grep -v '/internal/leak' | paste -sd, -)
COVER_MIN := 85

all: build ## Build the examples

build: ## Build the examples into ./bin
	@mkdir -p $(BIN_DIR)
	@for dir in examples/*/; do \
		[ -d "$$dir" ] || continue; name="$$(basename "$$dir")"; \
		go build -o "$(BIN_DIR)/example-$$name" "./$$dir"; \
	done

RUN_EXAMPLES := virtual-server dpt
examples: ## Run the self-contained examples (loopback only; each must exit successfully)
	@for e in $(RUN_EXAMPLES); do \
		echo "Running example $$e"; \
		go run ./examples/$$e >/dev/null || { echo "example $$e failed"; exit 1; }; \
	done

fmt: ## Format with the gofmt of the go.mod Go version
	@$(GOFMT_CI) -w .

fmt-check: ## Fail if gofmt (go.mod version or local) would change a file
	@ci="$$($(GOFMT_CI) -l .)"; loc="$$(gofmt -l .)"; \
	if [ -n "$$ci$$loc" ]; then echo "Not formatted:"; echo "$$ci $$loc"; exit 1; fi

lint: ## Run staticcheck (every platform of the socket code)
	@staticcheck ./...
	@GOOS=linux staticcheck ./...
	@GOOS=windows staticcheck ./...

lint-ci: ## Run golangci-lint
	@golangci-lint run ./...

vet: ## Run go vet for this platform, Linux (amd64, arm) and Windows
	@go vet ./...
	@GOOS=linux go vet ./...
	@GOOS=linux GOARCH=arm go vet ./...
	@GOOS=windows go vet ./...

vuln: ## Run govulncheck
	@govulncheck ./...

test: ## Run the tests with the race detector (multicast tests skip where multicast does not work)
	@go test -count=1 -race $(TEST_PKGS)

test-multicast: ## Run the tests, failing instead of skipping when multicast does not work (Linux CI)
	@KNX_REQUIRE_MULTICAST=1 go test -count=1 -race $(TEST_PKGS)

e2e: ## Run the end-to-end suite over loopback sockets
	@go test -count=1 -race ./e2e

coverage: ## Run the tests with coverage across the library packages (writes coverage.out)
	@go test -count=1 -race -covermode=atomic -coverpkg=$(COVER_PKGS) -coverprofile=coverage.out $(TEST_PKGS)
	@go tool cover -func=coverage.out | tail -1

coverage-check: coverage ## Fail when total coverage is below COVER_MIN
	@total=$$(go tool cover -func=coverage.out | tail -1 | awk '{print $$3}' | tr -d %); \
	echo "total $$total% (minimum $(COVER_MIN)%)"; \
	awk -v t=$$total -v m=$(COVER_MIN) 'BEGIN { exit (t+0 < m+0) }'

cover: coverage ## Open the coverage report in a browser
	@go tool cover -html=coverage.out

bench: ## Run the benchmarks
	@go test -count=1 -run='^$$' -bench=. -benchmem $(TEST_PKGS)

FUZZTIME ?= 30s
fuzz: ## Run every fuzz target for FUZZTIME (default 30s)
	@for pkg in $(TEST_PKGS); do \
		for f in $$(go test -list '^Fuzz' $$pkg | grep '^Fuzz'); do \
			echo "fuzz $$pkg $$f"; \
			go test -run='^$$' -fuzz="^$$f$$" -fuzztime=$(FUZZTIME) $$pkg || exit 1; \
		done; \
	done

coverpkg-check: ## Fail when CI's coverpkg (.github/workflows/ci.yml) is not COVER_PKGS
	@grep -qF -- "$(COVER_PKGS)" .github/workflows/ci.yml || { echo "coverpkg in .github/workflows/ci.yml must be: $(COVER_PKGS)"; exit 1; }

cross: ## Build every package for the release platforms
	@for t in linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64; do \
		echo "build $$t"; GOOS=$${t%/*} GOARCH=$${t#*/} CGO_ENABLED=0 go build ./... || exit 1; done

# Independent implementations: otfabric/knx-interop v0.2.0. The published
# (MIT) images are pinned by digest in interop/harness_test.go; the images
# with GPL binaries are never published, so interop-images builds them from
# knx-interop's source at INTEROP_REF as :dev (KNX_INTEROP_IMAGE_<ADAPTER>
# overrides any image).
INTEROP_REF ?= v0.2.0
interop-images: ## Build the knx-interop images from source as :dev (needs Docker)
	@rm -rf $(BIN_DIR)/knx-interop && mkdir -p $(BIN_DIR)
	@git clone -q --depth 1 --branch $(INTEROP_REF) https://github.com/otfabric/knx-interop.git $(BIN_DIR)/knx-interop
	@$(MAKE) -C $(BIN_DIR)/knx-interop images VERSION=dev ADAPTERS="knxd calimero-server calimero-tools"

interop: ## Run the interop suite against the knx-interop images (Docker; writes bin/interop-report.json)
	@mkdir -p $(BIN_DIR)
	@KNX_REQUIRE_INTEROP=1 KNX_INTEROP_REPORT=$(CURDIR)/$(BIN_DIR)/interop-report.json \
		go test -tags=interop -count=1 -timeout=60m -v ./interop/...

check: fmt-check lint lint-ci vet vuln test coverage-check examples cross ## Everything CI checks except the interop job

clean: ## Remove binaries and coverage files
	@rm -rf $(BIN_DIR) coverage.out coverage.html
