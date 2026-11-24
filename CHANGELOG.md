# Changelog

## v0.1.2 (2026-11-20) — Residual Cryptographic & Systems Hardening (`RESIDUAL-01`..`RESIDUAL-07`)

- **`RESIDUAL-01` (`src/merkle.rs`, `src/crypto.rs`):** Bound `WitnessAnchor::FinalizedNode` to `policy_hash`, `initial_anchor`, and `header_signature` (rejecting `session_id` or policy relabeling in `verify_witness`), and enforced `target_sequence == leaf_index + 1` unconditionally even when `leaf_index == 0`.
- **`RESIDUAL-02` (`src/crypto.rs`, `src/cli.rs`):** Enforced session finalization irreversibility (`PostFinalizeAppend` after `SessionFinalize`) and flipped `verify-path` to require finalized ledgers by default (opt-in `--allow-in-progress`).
- **`RESIDUAL-03` (`src/index.rs`, `src/cli.rs`):** Stopped calling `enforce_owner_only_acl` on parent directories (preventing unexpected permission strip on shared folders), hardened SQLite with `PRAGMA trusted_schema = OFF` + `PRAGMA busy_timeout = 5000`, enforced full `verify_ledger` + sequence equivocation checks in `index_ledger` and `load_session`, and switched `--key-out` to `create_new(true)` + pre-write ACL lockdown.
- **`RESIDUAL-04` (`src/canonical.rs`, `src/cli.rs`):** Rejected non-minimal overlong LEB128 varint encodings in `decode_leb128_u64` and routed passive `wrap` stdout JSON-RPC observations through `parse_strict_json_value`.
- **`RESIDUAL-05` (`src/wire.rs`, `src/fleet.rs`):** Switched `read_bounded_vec` to incremental 64 KiB chunked pre-allocation (`reader.take(...).read_to_end(...)`) and unified payload hashing across `crypto`, `wire`, and `fleet` via `hash_payload_bytes` (with `0x01`/`0x00` strict JSON vs raw byte domain separation).
- **`RESIDUAL-06` (`src/canonical.rs`):** Extended `sanitize_terminal_text` to strip 7-bit `ESC P` (DCS), `ESC X` (SOS), `ESC ^` (PM), and `ESC _` (APC) control-string frames cleanly.
- **`RESIDUAL-07` & `NEW-01` (`src/cli.rs`, `src/merkle.rs`):** Added `--signing-key-file` + `SEXTANT_SIGNING_KEY` environment key loading and removed raw `--signing-key` CLI argv on `record`, added `--timeout-secs` subprocess termination (`SextantError::Timeout`) on `wrap`, and added pinned `ExternalNotary` witness anchoring (`verify-path --notary-verifying-key`).

## v0.1.1 (2026-11-20) — Adversarial Hardening (`SEC-01`..`SEC-08`)

- **`SEC-01` (`src/canonical.rs`):** Enforced strict duplicate JSON object-key rejection (`StrictValueSeed`) across all nesting depths.
- **`SEC-02` (`src/crypto.rs`):** Added `MAX_CALL_STACK_DEPTH` (`64`), monotonic `timestamp_ns` enforcement (`TimestampRegression`), and `verify_finalized_ledger` (`--require-finalized`).
- **`SEC-03` (`src/merkle.rs`):** Eliminated odd-tail leaf duplication via `0x02` promotion and `0x03 || leaf_count` root commitment with positional `leaf_index`/`total_leaves` checks in `verify_witness`.
- **`SEC-04` (`src/wire.rs`):** Enforced `256 MiB` aggregate stream decoding budget (`MAX_TOTAL_LEDGER_BYTES`) and strict rejection of trailing 1..3 partial magic bytes.
- **`SEC-05` (`src/index.rs`):** Locked `.db`/`.db-wal`/`.db-shm` via `enforce_owner_only_acl` (`icacls` / `chmod 0600`) and rejected conflicting `session_id` overwrites.
- **`SEC-06` (`src/cli.rs`):** Applied `enforce_owner_only_acl` to `--key-out`, bounded `wrap` child capture (`16 MiB`), and tagged passive stdout JSON-RPC lines as `observed:stdout:*`.
- **`SEC-07` (`src/fleet.rs`):** Separated raw payload bytes (`arg_payload_raw`/`ret_payload_raw`) from sanitized display previews (`arg_display_sanitized`/`ret_display_sanitized`) so ANSI payloads verify cleanly.
- **`SEC-08` (`src/tui/mod.rs`, `src/canonical.rs`):** Replaced quadratic TUI verification with `O(N)` `verify_entries_incremental`, added 8-bit C1 CSI (`0x9B`) stripping, and prevented `.witness.json` silent overwrites.

## v0.1.0 (2026-11-20)

- Initial release of `sextant` (`sextant_core` + `sextant` CLI/TUI) under Rust 2024 Edition and `#![forbid(unsafe_code)]`.
- Implemented dual-anchor `BLAKE3` hash-chain accumulator + balanced `SubAgentFork`/`SubAgentJoin` Merkle subtree binding (`INV-01`..`INV-05`).
- Added `O(log k)` live and offline `ProvenanceWitness` generation and verification.
- Added `"SEXT"` v1 binary wire reader/writer and bundled `rusqlite` WAL state index.
- Added `clap` v4 CLI (`init`, `wrap`, `record`, `verify-path`, `export-graph`, `tui`) and 3-pane `ratatui` v0.30 provenance inspector.
- Added 500-case `proptest` verification suite and `TestBackend` TUI coverage.
