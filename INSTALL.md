# Installation

## Requirements

- Rust `1.99.1` or newer (2024 edition, pure Rust — no external C OpenSSL or Graphviz runtime required; SQLite is compiled cleanly via `rusqlite` bundled mode).

## Build from Source

```bash
git clone https://github.com/tsiscoe/Sextant.git
cd Sextant
cargo build --release
```

The binary is emitted at `target/release/sextant` (`target\release\sextant.exe` on Windows).

## Running Checks

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```
