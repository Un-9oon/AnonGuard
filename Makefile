.PHONY: verify

verify:
	@echo "Installing exact pinned toolchain..."
	rustup toolchain install $$(grep 'channel' rust-toolchain.toml | awk -F '"' '{print $$2}') || true
	@echo "Running fmt..."
	cargo fmt --check
	@echo "Running clippy..."
	cargo clippy --all-targets -- -D warnings
	@echo "Running tests..."
	cargo test --all
	@echo "Running audit..."
	cargo audit
	@echo "Running bench..."
	cargo bench --no-run
