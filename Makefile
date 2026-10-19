# Local verification for gateway. `make verify` is the single entry point and
# mirrors what CI runs (see odd/tasks/ci-cd-deploy.md).
#
# Toolchain: Rust 1.98 (same as the `rust:1.98-bookworm` builder in the
# Dockerfile). rustup installs to ~/.cargo/bin, which non-interactive shells
# do not always have on PATH.
export PATH := $(HOME)/.cargo/bin:$(PATH)

.PHONY: verify check fmt lint test test-integration doc

# Full verification. Integration tests need Docker (testcontainers); if Docker
# is unavailable, use `make check` and report the blocker, never replace them
# with mocks (see docs/verification.md).
verify: fmt lint test test-integration doc

# Same as verify without the Docker-dependent integration tests.
check: fmt lint test doc

fmt:
	cargo fmt --check

lint:
	cargo clippy --all-targets -- -D warnings

# Unit tests; tests marked #[ignore = "requiere Docker"] are skipped.
test:
	cargo test

# Integration tests against a real LocalStack (SNS/SQS, localstack/localstack:4.4)
# via testcontainers (requires Docker); no AWS account or credentials needed.
test-integration:
	cargo test -- --ignored

# rustdoc of public items (the crate uses #![deny(missing_docs)]).
doc:
	cargo doc --no-deps
