# Install the hook binary to ~/.cargo/bin
install:
    cargo install --path crates/agent-jj

# Run all checks (format, lint, test)
check:
    cargo fmt --check
    cargo clippy --workspace -- -D warnings
    cargo nextest run --workspace --no-fail-fast

# Format all code
fmt:
    cargo fmt

# Run tests
test:
    cargo nextest run --workspace --no-fail-fast
