.PHONY: verify

verify:
	rustup toolchain install $(shell grep 'channel' rust-toolchain.toml | awk -F '"' '{print $$2}') || true
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo test --all
	cargo audit
	cargo bench --no-run
