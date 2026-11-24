# Sextant (`sextant` v0.1.2)

**Tamper-Proof Flight Recorder for Autonomous AI Agents**

Sextant is a pure-Rust 2024 (`#![forbid(unsafe_code)]`) flight recorder for AI agents: it cryptographically signs and links every tool call, sub-agent handoff, and return payload in real time so you can prove what an agent actually ran (`BLAKE3` hash chain + ephemeral `Ed25519` session keys).

## Security Invariants

| ID | Invariant | Cryptographic Enforcement |
| :--- | :--- | :--- |
| **INV-01** | Append-Only History Monotonicity | Linear accumulation `H_n = BLAKE3(H_{n-1} || NodeHash_n)` plus strictly monotonic `sequence` and `prev_accumulator` checks. |
| **INV-02** | Strict Parent-Child Binding | Balanced `SubAgentFork` / `SubAgentJoin` stack frames bind every nested child `NodeHash` to its fork parent; orphan splicing fails with `ParentMismatch`. |
| **INV-03** | Non-Repudiation of Emitted Steps | Detached `Ed25519` signature over `accumulated_hash` at every step using an ephemeral session key. |
| **INV-04** | Zero-Knowledge Subtree Verification | `O(log k)` binary Merkle `ProvenanceWitness` proofs verify node membership without disclosing sibling arguments or outputs. |
| **INV-05** | Ephemeral Memory Sanitization | `SessionSigner` implements `zeroize::ZeroizeOnDrop`, wiping signing seed entropy when dropped. |

## Quick Start

```bash
# Build release binary
cargo build --release

# Initialize a cryptographically bound session
sextant init \
  --session-id "agent-run-01" \
  --policy-file ./policy.json \
  --ledger-out ./trace.bin \
  --key-out ./session.key

# Wrap an autonomous command inside an ephemeral verified provenance envelope (INV-05)
sextant wrap \
  --session-id "agent-run-02" \
  --policy-file ./policy.json \
  --ledger-out ./wrapped.bin \
  --timeout-secs 120 \
  -- your-agent-command --flag

# Append to an existing session using a restricted seed file or SEXTANT_SIGNING_KEY
sextant record \
  --ledger ./trace.bin \
  --signing-key-file ./session.key \
  --tool-id "search" \
  --args '{"q":"rust"}'

# Verify finalized ledger integrity end-to-end (add --allow-in-progress for open sessions)
sextant verify-path --ledger ./wrapped.bin --verbose

# Export call-graph visualization (DOT, SVG, JSON) or extract an O(log k) witness
sextant export-graph --ledger ./wrapped.bin --format svg --out ./graph.svg
sextant export-graph --ledger ./wrapped.bin --witness-seq 3 --out ./seq3.witness.json
sextant verify-path --witness ./seq3.witness.json

# Launch 3-pane Ratatui v0.30 provenance inspector
sextant tui --ledger ./wrapped.bin
```

## Fleet Integration

- **SigNET**: Ingests `SigNET` Ed25519 capability receipts as `RecordType::PolicyAssertion` nodes (`fleet::ingest_signet_receipt`).
- **Faraday**: Digests sandboxed child-process `stdout`/`stderr` streams via BLAKE3 without storing raw secret values (`fleet::build_faraday_stream_payload`).
- **Selective Redaction**: Supports selective payload redaction (`fleet::export_redacted_bundle`) while preserving full `verify_redacted_bundle` cryptographic validation.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```
