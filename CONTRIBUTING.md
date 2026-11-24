# Contributing

1. **Pure Rust Only**: Keep `#![forbid(unsafe_code)]` active in `src/lib.rs`, `src/main.rs`, and integration tests.
2. **Zero Panics in Production**: Avoid `.unwrap()` / `.expect()` outside test modules (`clippy::unwrap_used` is enabled).
3. **Terminal Safety**: Sanitize any external string displayed in the CLI or Ratatui TUI with `canonical::sanitize_terminal_text`.
4. **Verification Gate**: Run `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` before submitting pull requests.
