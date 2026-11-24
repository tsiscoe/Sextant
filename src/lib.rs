#![forbid(unsafe_code)]
//! **Sextant** — Verifiable Route & Call-Graph Provenance Engine for Autonomous Agent Execution.
//!
//! Built on pure Rust 2024 (`#![forbid(unsafe_code)]`) with `zeroize::ZeroizeOnDrop` ephemeral
//! session signing keys, `BLAKE3` domain-separated hash chaining, `Ed25519` state transition
//! signatures, and `O(log k)` Merkle call-graph witnesses.

pub mod canonical;
pub mod cli;
pub mod crypto;
pub mod fleet;
pub mod index;
pub mod merkle;
pub mod tui;
pub mod wire;

use thiserror::Error;

/// Unified error taxonomy for Sextant provenance accumulation, verification, wire framing, and indexing.
#[derive(Debug, Error)]
pub enum SextantError {
    /// Sequence numbers must increase strictly monotonically (`expected == prev + 1`).
    #[error("invalid sequence transition: expected {expected}, got {actual}")]
    InvalidSequence { expected: u64, actual: u64 },

    /// Recorded `parent_hash` does not match the active call-frame parent or predecessor.
    #[error("parent hash mismatch at sequence {sequence}: orphan or spliced execution step")]
    ParentMismatch { sequence: u64 },

    /// Linear accumulator digest `H_n` did not match `BLAKE3(H_{n-1} || NodeHash_n)`.
    #[error("accumulator mismatch at sequence {sequence}: linear history altered")]
    AccumulatorMismatch { sequence: u64 },

    /// Recomputed canonical `NodeHash_n` did not match the stored digest.
    #[error("node hash mismatch at sequence {sequence}: payload or metadata tampered")]
    NodeHashMismatch { sequence: u64 },

    /// `SubAgentJoin` subtree Merkle root did not match the children executed in its frame.
    #[error("subtree Merkle root mismatch at sequence {sequence}")]
    SubtreeMerkleMismatch { sequence: u64 },

    /// Detached Ed25519 signature over `accumulated_hash` failed verification.
    #[error("cryptographic verification failure at sequence {sequence}")]
    SignatureVerificationFailed { sequence: u64 },

    /// Ledger file header signature or anchor did not verify against the session parameters.
    #[error("session header signature verification failed")]
    HeaderSignatureInvalid,

    /// Initial anchor `H_0` did not match `BLAKE3_DERIVE("SEXTANT_SESSION_V1", ...)`.
    #[error("session anchor H_0 mismatch against session ID, verifying key, and policy hash")]
    SessionAnchorMismatch,

    /// Binary wire header lacked the `"SEXT"` (`0x53455854`) magic prefix.
    #[error("invalid wire magic bytes (expected SEXT)")]
    InvalidWireMagic,

    /// Binary wire format version is unsupported by this reader.
    #[error("unsupported wire format version: {0}")]
    UnsupportedWireVersion(u16),

    /// Wire record type tag did not map to a known `RecordType`.
    #[error("invalid record type tag: 0x{0:04x}")]
    InvalidRecordType(u16),

    /// Call-graph fork/join nesting violated balanced stack semantics.
    #[error("unbalanced call-graph fork/join frame: {0}")]
    UnbalancedCallStack(String),

    /// Sub-agent fork nesting exceeded the safety depth bound.
    #[error("call-graph nesting depth exceeded maximum ({max})")]
    CallStackDepthExceeded { max: usize },

    /// Timestamp regressed relative to the previous sequential node.
    #[error("timestamp regression at sequence {sequence}: {actual_ns} ns < previous {prev_ns} ns")]
    TimestampRegression {
        sequence: u64,
        prev_ns: u64,
        actual_ns: u64,
    },

    /// Attempted to append a node after a terminal `SessionFinalize` record (`RESIDUAL-02`).
    #[error("cannot append execution node at sequence {sequence} after SessionFinalize")]
    PostFinalizeAppend { sequence: u64 },

    /// Verification required a finalized session ledger with zero unclosed forks.
    #[error("unfinalized ledger: {unclosed_forks} unclosed fork(s) or missing SessionFinalize")]
    UnfinalizedLedger { unclosed_forks: usize },

    /// Wrapped child command exceeded `--timeout-secs`.
    #[error("wrapped process timed out: {0}")]
    Timeout(String),

    /// Strict JSON canonicalization encountered invalid or duplicate-key JSON input.
    #[error("canonical JSON encoding error: {0}")]
    CanonicalJsonRequired(String),

    /// Owner-only filesystem ACL enforcement failed (`icacls` / `chmod 0600`).
    #[error("filesystem ACL enforcement failed: {0}")]
    AclError(String),

    /// Malformed or overflowing unsigned LEB128 integer encoding.
    #[error("malformed LEB128 integer encoding")]
    InvalidLeb128,

    /// Requested node sequence index does not exist in the ledger.
    #[error("execution node sequence {0} not found")]
    NodeNotFound(u64),

    /// Provenance witness failed Merkle inclusion or signature validation.
    #[error("provenance witness verification failed: {0}")]
    WitnessVerificationFailed(String),

    /// Hex/bytes parsing or signing key custody error.
    #[error("key error: {0}")]
    KeyError(String),

    /// Embedded SQLite WAL index failure.
    #[error("provenance index error: {0}")]
    IndexError(String),

    /// JSON serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Filesystem or stream I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Crate-wide result alias for Sextant operations.
pub type SextantResult<T> = Result<T, SextantError>;
