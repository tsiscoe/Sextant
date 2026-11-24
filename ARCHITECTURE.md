# Architecture (`sextant` v0.1.2)

## Module Topology

| Module | Responsibility |
| :--- | :--- |
| `src/lib.rs` | Crate root enforcing `#![forbid(unsafe_code)]` and defining `SextantError` / `SextantResult`. |
| `src/canonical.rs` | `BTreeMap`-backed lexicographically sorted JSON canonicalization, unsigned LEB128 integer encoding/decoding, and CWE-150 ANSI/OSC/Bidi terminal text sanitization. |
| `src/merkle.rs` | Domain-separated (`0x00` leaf, `0x01` internal) binary Merkle roots, `O(log k)` audit paths, `ProvenanceWitness`, and offline/live `verify_witness`. |
| `src/crypto.rs` | `SessionSigner` (`ZeroizeOnDrop`), `RecordType`, `ExecutionNode`, `LedgerEntry`, `AccumulatorState`, and unified `ReplayTracker` verification across `INV-01`..`INV-05`. |
| `src/wire.rs` | Append-only `"SEXT"` v1 binary wire encoder/decoder with `64 MiB` bounded reads and `sync_all()` durability. |
| `src/index.rs` | Bundled `rusqlite` WAL-mode SQLite state index using `BEGIN IMMEDIATE` transactions for sequence, tool, and parent queries. |
| `src/fleet.rs` | Adapters for `SigNET` capability receipts, `Faraday` process stream digests, and salted-Merkle redacted exports. |
| `src/cli.rs` | `clap` v4 command router (`init`, `wrap`, `record`, `verify-path`, `export-graph`, `tui`). |
| `src/tui/` | 3-pane `ratatui` v0.30 TEA inspector (`Call Graph Tree`, `Node Payload Inspector`, `Cryptographic Witness`). |

## Dual-Anchor Node Schema

Every `ExecutionNode` preserves both call-tree lineage and linear accumulator progression:

1. **Session Root (`H_0`)**: `BLAKE3_DERIVE("SEXTANT_SESSION_V1", len(session_id) || session_id || verifying_key || policy_hash)`.
2. **Call-Tree Binding (`parent_hash`, `INV-02`)**: At root call depth, `parent_hash` links to the immediate root predecessor (starting at `H_0`). Inside a `SubAgentFork` frame (bounded to `MAX_CALL_STACK_DEPTH = 64`), every nested invocation binds `parent_hash` to `fork_node_hash`; closing via `SubAgentJoin` computes `subtree_merkle_root = compute_merkle_root(children)` (`0x00` leaf, `0x01` internal, `0x02` odd-tail promote, `0x03 || leaf_count` root commit) and pops the frame.
3. **Linear Accumulator (`prev_accumulator`, `INV-01`)**: Every step updates `H_n = BLAKE3(H_{n-1} || NodeHash_n)` and signs `H_n` with `Ed25519` (`INV-03`).
4. **Finalized Session Tree (`SessionFinalize`)**: Commits the global binary Merkle root over all preceding `NodeHash` leaves into `subtree_merkle_root`, enabling post-drop offline `O(log k)` `ProvenanceWitness` extraction without keeping the ephemeral signing key (`INV-04`, `INV-05`).
