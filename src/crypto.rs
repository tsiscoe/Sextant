//! Cryptographic primitives, `ZeroizeOnDrop` ephemeral signer, and hash-chain accumulator (`INV-01`..`INV-05`).

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::canonical::{canonicalize_payload_bytes_checked, hash_payload_bytes};
use crate::merkle::{
    HashDigest, ProvenanceWitness, WitnessAnchor, ZERO_DIGEST, build_merkle_audit_path,
    compute_canonical_node_hash, compute_linear_accumulator, compute_merkle_root,
    compute_session_anchor_digest, compute_witness_checkpoint_digest,
};
use crate::{SextantError, SextantResult};

/// Maximum permitted `SubAgentFork` nesting depth (`SEC-02`).
pub const MAX_CALL_STACK_DEPTH: usize = 64;

/// Execution step classification recorded in the verifiable call graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum RecordType {
    SessionInit = 0x0001,
    ToolInvocation = 0x0002,
    ToolReturn = 0x0003,
    SubAgentFork = 0x0004,
    SubAgentJoin = 0x0005,
    PolicyAssertion = 0x0006,
    SessionFinalize = 0x0007,
}

impl RecordType {
    /// Numeric wire representation for canonical hashing and binary framing.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Parse a human-readable CLI record type string (case-insensitive).
    pub fn from_name(name: &str) -> SextantResult<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "init" | "session_init" | "sessioninit" => Ok(Self::SessionInit),
            "invoke" | "tool_invocation" | "toolinvocation" => Ok(Self::ToolInvocation),
            "return" | "tool_return" | "toolreturn" => Ok(Self::ToolReturn),
            "fork" | "subagent_fork" | "subagentfork" => Ok(Self::SubAgentFork),
            "join" | "subagent_join" | "subagentjoin" => Ok(Self::SubAgentJoin),
            "policy" | "policy_assertion" | "policyassertion" => Ok(Self::PolicyAssertion),
            "finalize" | "session_finalize" | "sessionfinalize" => Ok(Self::SessionFinalize),
            other => Err(SextantError::KeyError(format!(
                "unknown record type '{other}'"
            ))),
        }
    }
}

impl TryFrom<u16> for RecordType {
    type Error = SextantError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::SessionInit),
            0x0002 => Ok(Self::ToolInvocation),
            0x0003 => Ok(Self::ToolReturn),
            0x0004 => Ok(Self::SubAgentFork),
            0x0005 => Ok(Self::SubAgentJoin),
            0x0006 => Ok(Self::PolicyAssertion),
            0x0007 => Ok(Self::SessionFinalize),
            other => Err(SextantError::InvalidRecordType(other)),
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::SessionInit => "SessionInit",
            Self::ToolInvocation => "ToolInvocation",
            Self::ToolReturn => "ToolReturn",
            Self::SubAgentFork => "SubAgentFork",
            Self::SubAgentJoin => "SubAgentJoin",
            Self::PolicyAssertion => "PolicyAssertion",
            Self::SessionFinalize => "SessionFinalize",
        };
        f.write_str(label)
    }
}

/// Ephemeral session identity key held strictly in RAM and zeroized on drop (`INV-05`).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionSigner {
    pub signing_key_bytes: [u8; 32],
}

impl SessionSigner {
    /// Generate a fresh ephemeral Ed25519 session signing key from OS entropy.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self {
            signing_key_bytes: signing_key.to_bytes(),
        }
    }

    /// Construct a signer from raw 32-byte Ed25519 seed material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            signing_key_bytes: bytes,
        }
    }

    /// Parse a 64-character hex string into an ephemeral `SessionSigner`.
    pub fn from_hex(hex_seed: &str) -> SextantResult<Self> {
        let trimmed = Zeroizing::new(hex_seed.trim().to_string());
        let decoded =
            Zeroizing::new(hex::decode(trimmed.as_bytes()).map_err(|err| {
                SextantError::KeyError(format!("invalid hex signing key: {err}"))
            })?);
        if decoded.len() != 32 {
            return Err(SextantError::KeyError(format!(
                "expected 32-byte Ed25519 seed, got {} bytes",
                decoded.len()
            )));
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&decoded);
        Ok(Self::from_bytes(*seed))
    }

    /// Derive the public verifying key corresponding to this session signer.
    pub fn verifying_key(&self) -> VerifyingKey {
        let sk = SigningKey::from_bytes(&self.signing_key_bytes);
        sk.verifying_key()
    }

    /// Sign an arbitrary digest or state commitment under Ed25519 (`INV-03`).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let sk = SigningKey::from_bytes(&self.signing_key_bytes);
        sk.sign(message).to_bytes()
    }

    /// Export raw seed bytes inside a `Zeroizing` guard when explicit key handoff is requested.
    pub fn export_seed_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.signing_key_bytes))
    }
}

/// Immutable cryptographic node committed into the linear hash chain and call-graph Merkle tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionNode {
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub record_type: RecordType,
    pub parent_hash: HashDigest,
    pub prev_accumulator: HashDigest,
    pub subtree_merkle_root: HashDigest,
    pub tool_id: String,
    pub arguments_digest: HashDigest,
    pub return_digest: HashDigest,
    pub node_hash: HashDigest,
    pub accumulated_hash: HashDigest,
    #[serde(with = "crate::canonical::sig_serde")]
    pub signature: [u8; 64],
}

/// Full execution ledger entry pairing a cryptographic node with its canonicalized byte payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub node: ExecutionNode,
    pub arg_payload: Vec<u8>,
    pub ret_payload: Vec<u8>,
}

/// Domain-separated session root header anchored to `H_0`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub session_id: String,
    pub verifying_key: [u8; 32],
    pub policy_hash: HashDigest,
    pub initial_anchor: HashDigest,
    #[serde(with = "crate::canonical::sig_serde")]
    pub header_signature: [u8; 64],
}

impl SessionMetadata {
    /// Recompute `H_0` and verify the Ed25519 signature binding session metadata.
    pub fn verify(&self) -> SextantResult<VerifyingKey> {
        let expected_anchor =
            compute_session_anchor(&self.session_id, &self.verifying_key, &self.policy_hash);
        let anchor_ok: bool =
            subtle::ConstantTimeEq::ct_eq(&expected_anchor[..], &self.initial_anchor[..]).into();
        if !anchor_ok {
            return Err(SextantError::SessionAnchorMismatch);
        }

        let vk = VerifyingKey::from_bytes(&self.verifying_key)
            .map_err(|_| SextantError::HeaderSignatureInvalid)?;
        let sig = Signature::from_bytes(&self.header_signature);
        vk.verify_strict(&self.initial_anchor, &sig)
            .map_err(|_| SextantError::HeaderSignatureInvalid)?;
        Ok(vk)
    }
}

/// Compute `H_0 = BLAKE3_DERIVE("SEXTANT_SESSION_V1", len(session_id) || session_id || vk || policy_hash)`.
pub fn compute_session_anchor(
    session_id: &str,
    verifying_key: &[u8; 32],
    policy_hash: &HashDigest,
) -> HashDigest {
    compute_session_anchor_digest(session_id, verifying_key, policy_hash)
}

/// Active call-tree frame created on `SubAgentFork` and sealed on `SubAgentJoin`.
#[derive(Debug, Clone)]
struct CallFrame {
    fork_node_hash: HashDigest,
    child_hashes: Vec<HashDigest>,
}

/// Verification summary emitted after validating all five security invariants across a ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub session_id: String,
    pub total_nodes: usize,
    pub final_sequence: u64,
    pub initial_anchor: HashDigest,
    pub final_accumulator: HashDigest,
    pub unclosed_forks: usize,
    pub finalized: bool,
    pub payload_digests_verified: bool,
}

/// Per-node incremental verification output returned in `O(N)` time for TUI and diagnostics (`SEC-08`).
pub struct IncrementalVerification {
    pub overall: SextantResult<VerificationReport>,
    pub per_sequence: Vec<(u64, Result<RecordType, String>)>,
}

/// Stateful dual-anchor provenance accumulator (`INV-01` linear stream + `INV-02` call-graph stack).
pub struct AccumulatorState {
    pub metadata: SessionMetadata,
    pub sequence: u64,
    pub last_timestamp_ns: u64,
    pub current_accumulator: HashDigest,
    pub last_node_hash: HashDigest,
    pub verifying_key: VerifyingKey,
    pub finalized: bool,
    signer: SessionSigner,
    call_stack: Vec<CallFrame>,
    entries: Vec<LedgerEntry>,
}

impl AccumulatorState {
    /// Initialize a fresh cryptographically bound session with a newly generated ephemeral signer.
    pub fn new(session_id: String, policy_document: &[u8]) -> Self {
        let signer = SessionSigner::generate();
        Self::with_signer(session_id, policy_document, signer)
    }

    /// Initialize a session with an explicitly supplied `SessionSigner`.
    pub fn with_signer(session_id: String, policy_document: &[u8], signer: SessionSigner) -> Self {
        let verifying_key = signer.verifying_key();
        let vk_bytes = verifying_key.to_bytes();
        let policy_hash = *blake3::hash(policy_document).as_bytes();
        let initial_anchor = compute_session_anchor(&session_id, &vk_bytes, &policy_hash);
        let header_signature = signer.sign(&initial_anchor);

        let metadata = SessionMetadata {
            session_id,
            verifying_key: vk_bytes,
            policy_hash,
            initial_anchor,
            header_signature,
        };

        Self {
            metadata,
            sequence: 0,
            last_timestamp_ns: 0,
            current_accumulator: initial_anchor,
            last_node_hash: initial_anchor,
            verifying_key,
            finalized: false,
            signer,
            call_stack: Vec::new(),
            entries: Vec::new(),
        }
    }

    /// Resume appending to a verified ledger using the matching ephemeral `SessionSigner`.
    pub fn resume(
        metadata: SessionMetadata,
        entries: Vec<LedgerEntry>,
        signer: SessionSigner,
    ) -> SextantResult<Self> {
        let vk = metadata.verify()?;
        if signer.verifying_key().to_bytes() != metadata.verifying_key {
            return Err(SextantError::KeyError(
                "supplied signing key does not match ledger verifying key".to_string(),
            ));
        }

        let mut replayer = ReplayTracker::new(&metadata);
        for entry in &entries {
            replayer.step(entry, &vk, true)?;
        }

        Ok(Self {
            metadata,
            sequence: replayer.sequence,
            last_timestamp_ns: replayer.last_timestamp_ns,
            current_accumulator: replayer.current_accumulator,
            last_node_hash: replayer.last_node_hash,
            verifying_key: vk,
            finalized: replayer.finalized,
            signer,
            call_stack: replayer.call_stack,
            entries,
        })
    }

    /// Return the active `parent_hash` for the next recorded node (`INV-02`).
    pub fn active_parent_hash(&self) -> HashDigest {
        self.call_stack
            .last()
            .map_or(self.last_node_hash, |frame| frame.fork_node_hash)
    }

    /// All recorded entries in execution order.
    pub fn entries(&self) -> &[LedgerEntry] {
        &self.entries
    }

    /// Read-only access to the active signer when explicitly exporting ephemeral seed bytes.
    pub fn signer(&self) -> &SessionSigner {
        &self.signer
    }

    /// Record an execution step, updating both the linear accumulator and the call-graph frame stack.
    pub fn record_action(
        &mut self,
        tool_id: &str,
        arguments: &[u8],
        return_payload: &[u8],
        record_type: RecordType,
        timestamp_ns: u64,
    ) -> SextantResult<ExecutionNode> {
        let next_seq = self
            .sequence
            .checked_add(1)
            .ok_or(SextantError::InvalidSequence {
                expected: u64::MAX,
                actual: self.sequence,
            })?;

        if self.finalized {
            return Err(SextantError::PostFinalizeAppend { sequence: next_seq });
        }

        if timestamp_ns < self.last_timestamp_ns {
            return Err(SextantError::TimestampRegression {
                sequence: next_seq,
                prev_ns: self.last_timestamp_ns,
                actual_ns: timestamp_ns,
            });
        }

        if record_type == RecordType::SubAgentFork && self.call_stack.len() >= MAX_CALL_STACK_DEPTH
        {
            return Err(SextantError::CallStackDepthExceeded {
                max: MAX_CALL_STACK_DEPTH,
            });
        }

        let canonical_args = canonicalize_payload_bytes_checked(arguments)?;
        let canonical_ret = canonicalize_payload_bytes_checked(return_payload)?;

        let (parent_hash, subtree_merkle_root, popped_frame) = match record_type {
            RecordType::SubAgentJoin => {
                let frame = self.call_stack.pop().ok_or_else(|| {
                    SextantError::UnbalancedCallStack(
                        "SubAgentJoin recorded with no active SubAgentFork".to_string(),
                    )
                })?;
                let root = compute_merkle_root(&frame.child_hashes);
                (frame.fork_node_hash, root, Some(frame))
            }
            RecordType::SessionFinalize => {
                if !self.call_stack.is_empty() {
                    return Err(SextantError::UnbalancedCallStack(format!(
                        "SessionFinalize attempted with {} unclosed SubAgentFork frame(s)",
                        self.call_stack.len()
                    )));
                }
                let all_hashes: Vec<HashDigest> =
                    self.entries.iter().map(|e| e.node.node_hash).collect();
                (self.last_node_hash, compute_merkle_root(&all_hashes), None)
            }
            _ => (self.active_parent_hash(), ZERO_DIGEST, None),
        };

        let prev_accumulator = self.current_accumulator;
        let arg_hash = hash_payload_bytes(&canonical_args);
        let ret_hash = hash_payload_bytes(&canonical_ret);

        let node_hash = compute_canonical_node_hash(
            &parent_hash,
            next_seq,
            timestamp_ns,
            record_type.as_u16(),
            tool_id,
            &arg_hash,
            &ret_hash,
            &subtree_merkle_root,
        );

        let next_accumulator = compute_linear_accumulator(&prev_accumulator, &node_hash);
        let signature = self.signer.sign(&next_accumulator);

        let node = ExecutionNode {
            sequence: next_seq,
            timestamp_ns,
            record_type,
            parent_hash,
            prev_accumulator,
            subtree_merkle_root,
            tool_id: tool_id.to_string(),
            arguments_digest: arg_hash,
            return_digest: ret_hash,
            node_hash,
            accumulated_hash: next_accumulator,
            signature,
        };

        drop(popped_frame);
        match record_type {
            RecordType::SubAgentFork => {
                if let Some(outer) = self.call_stack.last_mut() {
                    outer.child_hashes.push(node_hash);
                }
                self.call_stack.push(CallFrame {
                    fork_node_hash: node_hash,
                    child_hashes: Vec::new(),
                });
            }
            RecordType::SubAgentJoin => {
                if let Some(outer) = self.call_stack.last_mut() {
                    outer.child_hashes.push(node_hash);
                }
            }
            _ => {
                if let Some(active) = self.call_stack.last_mut() {
                    active.child_hashes.push(node_hash);
                }
            }
        }

        if record_type == RecordType::SessionFinalize {
            self.finalized = true;
        }
        self.sequence = next_seq;
        self.last_timestamp_ns = timestamp_ns;
        self.last_node_hash = node_hash;
        self.current_accumulator = next_accumulator;
        self.entries.push(LedgerEntry {
            node: node.clone(),
            arg_payload: canonical_args,
            ret_payload: canonical_ret,
        });

        Ok(node)
    }

    /// Generate a zero-knowledge `O(log k)` inclusion witness using the live ephemeral signer.
    pub fn generate_witness(&self, target_sequence: u64) -> SextantResult<ProvenanceWitness> {
        let leaves: Vec<HashDigest> = self.entries.iter().map(|e| e.node.node_hash).collect();
        let target_idx = self
            .entries
            .iter()
            .position(|e| e.node.sequence == target_sequence)
            .ok_or(SextantError::NodeNotFound(target_sequence))?;

        let total_leaves = leaves.len();
        let (merkle_root, audit_path) = build_merkle_audit_path(&leaves, target_idx)?;
        let checkpoint_digest = compute_witness_checkpoint_digest(
            &self.metadata.session_id,
            &self.current_accumulator,
            &merkle_root,
            target_idx,
            total_leaves,
        );
        let root_signature = self.signer.sign(&checkpoint_digest);

        Ok(ProvenanceWitness {
            session_id: self.metadata.session_id.clone(),
            agent_verifying_key: self.metadata.verifying_key,
            target_sequence,
            leaf_index: target_idx,
            total_leaves,
            target_node_hash: leaves[target_idx],
            accumulator_root: self.current_accumulator,
            merkle_root,
            audit_path,
            anchor: WitnessAnchor::DirectCheckpoint,
            root_signature,
        })
    }
}

/// Generate a self-verifying offline `ProvenanceWitness` from a finalized ledger without needing the private key (`INV-05`).
pub fn generate_offline_witness(
    metadata: &SessionMetadata,
    entries: &[LedgerEntry],
    target_sequence: u64,
) -> SextantResult<ProvenanceWitness> {
    let finalize_pos = entries
        .iter()
        .rposition(|e| e.node.record_type == RecordType::SessionFinalize)
        .ok_or_else(|| {
            SextantError::WitnessVerificationFailed(
                "offline witness requires a SessionFinalize anchor node in the ledger".to_string(),
            )
        })?;

    let anchor_entry = &entries[finalize_pos];
    let preceding_leaves: Vec<HashDigest> = entries[..finalize_pos]
        .iter()
        .map(|e| e.node.node_hash)
        .collect();

    let target_idx = entries[..finalize_pos]
        .iter()
        .position(|e| e.node.sequence == target_sequence)
        .ok_or(SextantError::NodeNotFound(target_sequence))?;

    let total_leaves = preceding_leaves.len();
    let (merkle_root, audit_path) = build_merkle_audit_path(&preceding_leaves, target_idx)?;
    if merkle_root != anchor_entry.node.subtree_merkle_root {
        return Err(SextantError::SubtreeMerkleMismatch {
            sequence: anchor_entry.node.sequence,
        });
    }

    Ok(ProvenanceWitness {
        session_id: metadata.session_id.clone(),
        agent_verifying_key: metadata.verifying_key,
        target_sequence,
        leaf_index: target_idx,
        total_leaves,
        target_node_hash: preceding_leaves[target_idx],
        accumulator_root: anchor_entry.node.accumulated_hash,
        merkle_root,
        audit_path,
        anchor: WitnessAnchor::FinalizedNode {
            policy_hash: metadata.policy_hash,
            initial_anchor: metadata.initial_anchor,
            header_signature: metadata.header_signature,
            anchor_sequence: anchor_entry.node.sequence,
            anchor_parent_hash: anchor_entry.node.parent_hash,
            anchor_prev_accumulator: anchor_entry.node.prev_accumulator,
            anchor_timestamp_ns: anchor_entry.node.timestamp_ns,
            anchor_record_type: anchor_entry.node.record_type.as_u16(),
            anchor_tool_id: anchor_entry.node.tool_id.clone(),
            anchor_arg_hash: anchor_entry.node.arguments_digest,
            anchor_ret_hash: anchor_entry.node.return_digest,
        },
        root_signature: anchor_entry.node.signature,
    })
}

/// Shared cryptographic replay state machine verifying `INV-01`..`INV-04` across all entries.
struct ReplayTracker {
    sequence: u64,
    last_timestamp_ns: u64,
    current_accumulator: HashDigest,
    last_node_hash: HashDigest,
    call_stack: Vec<CallFrame>,
    all_node_hashes: Vec<HashDigest>,
    finalized: bool,
}

impl ReplayTracker {
    fn new(metadata: &SessionMetadata) -> Self {
        Self {
            sequence: 0,
            last_timestamp_ns: 0,
            current_accumulator: metadata.initial_anchor,
            last_node_hash: metadata.initial_anchor,
            call_stack: Vec::new(),
            all_node_hashes: Vec::new(),
            finalized: false,
        }
    }

    fn step(
        &mut self,
        entry: &LedgerEntry,
        verifying_key: &VerifyingKey,
        verify_payload_digests: bool,
    ) -> SextantResult<()> {
        let node = &entry.node;
        let expected_seq = self.sequence + 1;
        if node.sequence != expected_seq {
            return Err(SextantError::InvalidSequence {
                expected: expected_seq,
                actual: node.sequence,
            });
        }

        if self.finalized {
            return Err(SextantError::PostFinalizeAppend {
                sequence: node.sequence,
            });
        }

        if node.timestamp_ns < self.last_timestamp_ns {
            return Err(SextantError::TimestampRegression {
                sequence: node.sequence,
                prev_ns: self.last_timestamp_ns,
                actual_ns: node.timestamp_ns,
            });
        }

        if node.record_type == RecordType::SubAgentFork
            && self.call_stack.len() >= MAX_CALL_STACK_DEPTH
        {
            return Err(SextantError::CallStackDepthExceeded {
                max: MAX_CALL_STACK_DEPTH,
            });
        }

        if verify_payload_digests {
            let arg_hash = hash_payload_bytes(&entry.arg_payload);
            let ret_hash = hash_payload_bytes(&entry.ret_payload);
            if arg_hash != node.arguments_digest || ret_hash != node.return_digest {
                return Err(SextantError::NodeHashMismatch {
                    sequence: node.sequence,
                });
            }
        }

        let (expected_parent, expected_subtree_root) = match node.record_type {
            RecordType::SubAgentJoin => {
                let frame = self.call_stack.last().ok_or_else(|| {
                    SextantError::UnbalancedCallStack(format!(
                        "SubAgentJoin at sequence {} has no matching SubAgentFork",
                        node.sequence
                    ))
                })?;
                (
                    frame.fork_node_hash,
                    compute_merkle_root(&frame.child_hashes),
                )
            }
            RecordType::SessionFinalize => {
                if !self.call_stack.is_empty() {
                    return Err(SextantError::UnbalancedCallStack(format!(
                        "SessionFinalize at sequence {} leaves unclosed forks",
                        node.sequence
                    )));
                }
                (
                    self.last_node_hash,
                    compute_merkle_root(&self.all_node_hashes),
                )
            }
            _ => {
                let parent = self
                    .call_stack
                    .last()
                    .map_or(self.last_node_hash, |frame| frame.fork_node_hash);
                (parent, ZERO_DIGEST)
            }
        };

        if node.parent_hash != expected_parent {
            return Err(SextantError::ParentMismatch {
                sequence: node.sequence,
            });
        }

        if node.prev_accumulator != self.current_accumulator {
            return Err(SextantError::AccumulatorMismatch {
                sequence: node.sequence,
            });
        }

        if node.subtree_merkle_root != expected_subtree_root {
            return Err(SextantError::SubtreeMerkleMismatch {
                sequence: node.sequence,
            });
        }

        let recomputed_node_hash = compute_canonical_node_hash(
            &node.parent_hash,
            node.sequence,
            node.timestamp_ns,
            node.record_type.as_u16(),
            &node.tool_id,
            &node.arguments_digest,
            &node.return_digest,
            &node.subtree_merkle_root,
        );
        if recomputed_node_hash != node.node_hash {
            return Err(SextantError::NodeHashMismatch {
                sequence: node.sequence,
            });
        }

        let recomputed_acc = compute_linear_accumulator(&self.current_accumulator, &node.node_hash);
        if recomputed_acc != node.accumulated_hash {
            return Err(SextantError::AccumulatorMismatch {
                sequence: node.sequence,
            });
        }

        let sig = Signature::from_bytes(&node.signature);
        verifying_key
            .verify_strict(&node.accumulated_hash, &sig)
            .map_err(|_| SextantError::SignatureVerificationFailed {
                sequence: node.sequence,
            })?;

        match node.record_type {
            RecordType::SubAgentFork => {
                if let Some(outer) = self.call_stack.last_mut() {
                    outer.child_hashes.push(node.node_hash);
                }
                self.call_stack.push(CallFrame {
                    fork_node_hash: node.node_hash,
                    child_hashes: Vec::new(),
                });
            }
            RecordType::SubAgentJoin => {
                let _ = self.call_stack.pop();
                if let Some(outer) = self.call_stack.last_mut() {
                    outer.child_hashes.push(node.node_hash);
                }
            }
            RecordType::SessionFinalize => {
                self.finalized = true;
            }
            _ => {
                if let Some(active) = self.call_stack.last_mut() {
                    active.child_hashes.push(node.node_hash);
                }
            }
        }

        self.sequence = node.sequence;
        self.last_timestamp_ns = node.timestamp_ns;
        self.last_node_hash = node.node_hash;
        self.current_accumulator = node.accumulated_hash;
        self.all_node_hashes.push(node.node_hash);
        Ok(())
    }
}

/// Verify an entire ledger in `O(N)` time across all sequential nodes and invariants.
pub fn verify_ledger(
    metadata: &SessionMetadata,
    entries: &[LedgerEntry],
    verify_payload_digests: bool,
) -> SextantResult<VerificationReport> {
    let vk = metadata.verify()?;
    let mut tracker = ReplayTracker::new(metadata);

    for entry in entries {
        tracker.step(entry, &vk, verify_payload_digests)?;
    }

    Ok(VerificationReport {
        session_id: metadata.session_id.clone(),
        total_nodes: entries.len(),
        final_sequence: tracker.sequence,
        initial_anchor: metadata.initial_anchor,
        final_accumulator: tracker.current_accumulator,
        unclosed_forks: tracker.call_stack.len(),
        finalized: tracker.finalized,
        payload_digests_verified: verify_payload_digests,
    })
}

/// Strictly verify that a ledger is both cryptographically intact AND cleanly finalized (`SEC-02`).
pub fn verify_finalized_ledger(
    metadata: &SessionMetadata,
    entries: &[LedgerEntry],
    verify_payload_digests: bool,
) -> SextantResult<VerificationReport> {
    let report = verify_ledger(metadata, entries, verify_payload_digests)?;
    if report.unclosed_forks > 0 || !report.finalized {
        return Err(SextantError::UnfinalizedLedger {
            unclosed_forks: report.unclosed_forks,
        });
    }
    Ok(report)
}

/// Single-pass `O(N)` incremental verification returning per-node status without quadratic re-checks (`SEC-08`).
pub fn verify_entries_incremental(
    metadata: &SessionMetadata,
    entries: &[LedgerEntry],
    verify_payload_digests: bool,
) -> IncrementalVerification {
    let vk = match metadata.verify() {
        Ok(vk) => vk,
        Err(err) => {
            let reason = err.to_string();
            let per_sequence = entries
                .iter()
                .map(|e| (e.node.sequence, Err(reason.clone())))
                .collect();
            return IncrementalVerification {
                overall: Err(err),
                per_sequence,
            };
        }
    };

    let mut tracker = ReplayTracker::new(metadata);
    let mut per_sequence = Vec::with_capacity(entries.len());
    let mut first_failure: Option<(SextantError, String)> = None;

    for entry in entries {
        if let Some((_, ref reason)) = first_failure {
            per_sequence.push((entry.node.sequence, Err(reason.clone())));
            continue;
        }
        match tracker.step(entry, &vk, verify_payload_digests) {
            Ok(()) => per_sequence.push((entry.node.sequence, Ok(entry.node.record_type))),
            Err(err) => {
                let msg = err.to_string();
                per_sequence.push((entry.node.sequence, Err(msg.clone())));
                first_failure = Some((err, msg));
            }
        }
    }

    let overall = match first_failure {
        Some((err, _)) => Err(err),
        None => Ok(VerificationReport {
            session_id: metadata.session_id.clone(),
            total_nodes: entries.len(),
            final_sequence: tracker.sequence,
            initial_anchor: metadata.initial_anchor,
            final_accumulator: tracker.current_accumulator,
            unclosed_forks: tracker.call_stack.len(),
            finalized: tracker.finalized,
            payload_digests_verified: verify_payload_digests,
        }),
    };

    IncrementalVerification {
        overall,
        per_sequence,
    }
}

/// Verify only `ExecutionNode` commitments (e.g., after selective payload redaction).
pub fn verify_redacted_nodes(
    metadata: &SessionMetadata,
    nodes: &[ExecutionNode],
) -> SextantResult<VerificationReport> {
    let wrapped: Vec<LedgerEntry> = nodes
        .iter()
        .cloned()
        .map(|node| LedgerEntry {
            node,
            arg_payload: Vec::new(),
            ret_payload: Vec::new(),
        })
        .collect();
    verify_ledger(metadata, &wrapped, false)
}
