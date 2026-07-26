# Run via mise so the pinned toolchain is on PATH, e.g. `mise exec -- make check`.
CARGO ?= cargo

.DEFAULT_GOAL := help

# ---- quality -------------------------------------------------------------

.PHONY: check
check: fmt-check lint test  ## Run all checks (fmt, clippy, tests)

.PHONY: fmt
fmt:  ## Format the code
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check:  ## Verify formatting
	$(CARGO) fmt --all -- --check

.PHONY: lint
lint:  ## Run clippy with warnings denied across the full feature matrix
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

.PHONY: test
test:  ## Run the test suite (default features)
	$(CARGO) test --workspace

.PHONY: test-all-features
test-all-features:  ## Run the test suite with every feature enabled
	$(CARGO) test --workspace --all-features

.PHONY: build-no-default-features
build-no-default-features:  ## Build with every crate's default features off (matches CI)
	$(CARGO) build --workspace --no-default-features

.PHONY: doc
doc:  ## Build docs with every feature enabled (matches CI)
	$(CARGO) doc --workspace --all-features --no-deps

# ---- infra / db ------------------------------------------------------------

.PHONY: up
up:  ## Start local Postgres (used by stridelabs-testing's fail-loud tests)
	docker compose up -d

.PHONY: down
down:  ## Stop local Postgres
	docker compose down

# ---- misc -------------------------------------------------------------

.PHONY: clean
clean:  ## Remove build artifacts
	$(CARGO) clean

.PHONY: help
help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
