.PHONY: verify

verify:
	@echo "Running Format Checks..."
	cargo fmt --all -- --check
	prettier --check .
	@echo "Running Static Analysis..."
	cargo clippy --all-targets --all-features -- -D warnings
	eslint . --ext .ts
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck **/*.sh; fi
	@if command -v hadolint >/dev/null 2>&1; then hadolint orchestrator/Dockerfile; hadolint indexer/Dockerfile; fi
	@echo "Running Security Audits..."
	cargo audit
	npm --prefix orchestrator audit
	npm --prefix indexer audit
	@echo "Running Tests..."
	cargo test --workspace --all-features
	npm run test:all

