//! Call-graph Merkle DAG primitives and `O(log k)` selective-disclosure witnesses (`INV-04`, `RESIDUAL-01`).

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::canonical::encode_leb128_u64;
use crate::{SextantError, SextantResult};

/// Fixed 32-byte BLAKE3 cryptographic digest.
pub type HashDigest = [u8; 32];

/// Zeroed 32-byte digest used for leaf `subtree_merkle_root` and `Promote` sentinel steps.
pub const ZERO_DIGEST: HashDigest = [0u8; 32];

/// Direction of a sibling (or odd-tail promotion) step along a Merkle audit path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditDirection {
    Left,
    Right,
    /// Trailing unpaired node promoted via domain-separated `0x02 || only_child` (eliminates CVE-2012-2459).
    Promote,
}

/// Single step in an `O(log k)` Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSibling {
    pub direction: AuditDirection,
    pub digest: HashDigest,
}

/// Cryptographic anchor tying a `ProvenanceWitness` Merkle root to the session's Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum WitnessAnchor {
    /// Direct checkpoint signed in-RAM by the live ephemeral `SessionSigner`.
    DirectCheckpoint,
    /// Self-contained proof anchored to an immutable `SessionFinalize` node and signed `H_0` root (`RESIDUAL-01`).
    FinalizedNode {
        policy_hash: HashDigest,
        initial_anchor: HashDigest,
        #[serde(with = "crate::canonical::sig_serde")]
        header_signature: [u8; 64],
        anchor_sequence: u64,
        anchor_parent_hash: HashDigest,
        anchor_prev_accumulator: HashDigest,
        anchor_timestamp_ns: u64,
        anchor_record_type: u16,
        anchor_tool_id: String,
        anchor_arg_hash: HashDigest,
        anchor_ret_hash: HashDigest,
    },
    /// External detached notary witness anchor (Colmena countersignature model).
    ExternalNotary {
        notary_id: String,
        /// Ed25519 verifying key of the detached external notary (must not equal `agent_verifying_key`).
        notary_verifying_key: [u8; 32],
        external_chain_head: HashDigest,
        notary_sequence: u64,
        timestamp_utc: u64,
        #[serde(with = "crate::canonical::sig_serde")]
        notary_signature: [u8; 64],
    },
}

/// Selective-disclosure inclusion receipt proving a node occurred at an exact position in a signed session (`INV-04`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceWitness {
    pub session_id: String,
    pub agent_verifying_key: [u8; 32],
    pub target_sequence: u64,
    pub leaf_index: usize,
    pub total_leaves: usize,
    pub target_node_hash: HashDigest,
    pub accumulator_root: HashDigest,
    pub merkle_root: HashDigest,
    pub audit_path: Vec<AuditSibling>,
    pub anchor: WitnessAnchor,
    #[serde(with = "crate::canonical::sig_serde")]
    pub root_signature: [u8; 64],
}

/// Compute `H_0 = BLAKE3_DERIVE("SEXTANT_SESSION_V1", len(session_id) || session_id || vk || policy_hash)`.
pub fn compute_session_anchor_digest(
    session_id: &str,
    verifying_key: &[u8; 32],
    policy_hash: &HashDigest,
) -> HashDigest {
    let mut hasher = blake3::Hasher::new_derive_key("SEXTANT_SESSION_V1");
    let id_bytes = session_id.as_bytes();
    hasher.update(&(id_bytes.len() as u64).to_le_bytes());
    hasher.update(id_bytes);
    hasher.update(verifying_key);
    hasher.update(policy_hash);
    *hasher.finalize().as_bytes()
}

/// Domain-separated leaf hash (`0x00 || digest`) preventing second-preimage tree attacks.
pub fn hash_merkle_leaf(leaf: &HashDigest) -> HashDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x00]);
    hasher.update(leaf);
    *hasher.finalize().as_bytes()
}

/// Domain-separated internal Merkle node hash (`0x01 || left || right`).
pub fn hash_merkle_internal(left: &HashDigest, right: &HashDigest) -> HashDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x01]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Domain-separated odd-tail promotion hash (`0x02 || only_child`), defeating CVE-2012-2459 duplication.
pub fn hash_merkle_odd_promote(only_child: &HashDigest) -> HashDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x02]);
    hasher.update(only_child);
    *hasher.finalize().as_bytes()
}

/// Domain-separated cardinality root commitment (`0x03 || leaf_count_le64 || top_hash`).
pub fn hash_merkle_root_commit(top_hash: &HashDigest, leaf_count: usize) -> HashDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x03]);
    hasher.update(&(leaf_count as u64).to_le_bytes());
    hasher.update(top_hash);
    *hasher.finalize().as_bytes()
}

fn reduce_merkle_layer(level: &[HashDigest]) -> Vec<HashDigest> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    for pair in level.chunks(2) {
        if let Some(right) = pair.get(1) {
            next.push(hash_merkle_internal(&pair[0], right));
        } else {
            next.push(hash_merkle_odd_promote(&pair[0]));
        }
    }
    next
}

/// Compute the deterministic binary Merkle root over `leaves` with domain-separated odd-tail promotion.
pub fn compute_merkle_root(leaves: &[HashDigest]) -> HashDigest {
    if leaves.is_empty() {
        return ZERO_DIGEST;
    }

    let mut level: Vec<HashDigest> = leaves.iter().map(hash_merkle_leaf).collect();
    while level.len() > 1 {
        level = reduce_merkle_layer(&level);
    }

    hash_merkle_root_commit(&level[0], leaves.len())
}

/// Build `(merkle_root, audit_path)` for `leaves[target_index]` in `O(log k)` proof size.
pub fn build_merkle_audit_path(
    leaves: &[HashDigest],
    target_index: usize,
) -> SextantResult<(HashDigest, Vec<AuditSibling>)> {
    if leaves.is_empty() || target_index >= leaves.len() {
        return Err(SextantError::WitnessVerificationFailed(format!(
            "target leaf index {target_index} out of bounds for {} leaves",
            leaves.len()
        )));
    }

    let mut level: Vec<HashDigest> = leaves.iter().map(hash_merkle_leaf).collect();
    let total_leaves = leaves.len();
    let mut idx = target_index;
    let mut path = Vec::new();

    while level.len() > 1 {
        let step = if idx.is_multiple_of(2) {
            if let Some(&right) = level.get(idx + 1) {
                AuditSibling {
                    direction: AuditDirection::Right,
                    digest: right,
                }
            } else {
                AuditSibling {
                    direction: AuditDirection::Promote,
                    digest: ZERO_DIGEST,
                }
            }
        } else {
            AuditSibling {
                direction: AuditDirection::Left,
                digest: level[idx - 1],
            }
        };
        path.push(step);

        level = reduce_merkle_layer(&level);
        idx /= 2;
    }

    Ok((hash_merkle_root_commit(&level[0], total_leaves), path))
}

/// Recompute the Merkle root with strict positional index and tree-cardinality validation (`SEC-03`).
pub fn verify_merkle_audit_path(
    target_leaf: &HashDigest,
    leaf_index: usize,
    total_leaves: usize,
    expected_root: &HashDigest,
    audit_path: &[AuditSibling],
) -> bool {
    if total_leaves == 0 || leaf_index >= total_leaves {
        return false;
    }

    let mut current = hash_merkle_leaf(target_leaf);
    let mut idx = leaf_index;
    let mut level_len = total_leaves;

    for step in audit_path {
        if level_len <= 1 {
            return false;
        }
        current = if idx.is_multiple_of(2) {
            if idx + 1 < level_len {
                if step.direction != AuditDirection::Right {
                    return false;
                }
                hash_merkle_internal(&current, &step.digest)
            } else {
                if step.direction != AuditDirection::Promote || step.digest != ZERO_DIGEST {
                    return false;
                }
                hash_merkle_odd_promote(&current)
            }
        } else {
            if step.direction != AuditDirection::Left {
                return false;
            }
            hash_merkle_internal(&step.digest, &current)
        };
        idx /= 2;
        level_len = level_len.div_ceil(2);
    }

    if level_len != 1 {
        return false;
    }
    let committed = hash_merkle_root_commit(&current, total_leaves);
    subtle::ConstantTimeEq::ct_eq(&committed[..], &expected_root[..]).into()
}

/// Compute the canonical checkpoint message signed by `WitnessAnchor::DirectCheckpoint`.
pub fn compute_witness_checkpoint_digest(
    session_id: &str,
    accumulator_root: &HashDigest,
    merkle_root: &HashDigest,
    leaf_index: usize,
    total_leaves: usize,
) -> HashDigest {
    let mut hasher = blake3::Hasher::new_derive_key("SEXTANT_WITNESS_CHECKPOINT_V1");
    let id_bytes = session_id.as_bytes();
    hasher.update(&(id_bytes.len() as u64).to_le_bytes());
    hasher.update(id_bytes);
    hasher.update(accumulator_root);
    hasher.update(merkle_root);
    hasher.update(&(leaf_index as u64).to_le_bytes());
    hasher.update(&(total_leaves as u64).to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute the domain-separated external notary digest binding session, agent key, accumulator,
/// Merkle root, leaf count, notary identity, external chain head, sequence, and timestamp (`NEW-01`).
#[allow(clippy::too_many_arguments)]
pub fn compute_external_notary_digest(
    session_id: &str,
    agent_verifying_key: &[u8; 32],
    accumulator_root: &HashDigest,
    merkle_root: &HashDigest,
    total_leaves: usize,
    notary_id: &str,
    external_chain_head: &HashDigest,
    notary_sequence: u64,
    timestamp_utc: u64,
) -> HashDigest {
    let mut hasher = blake3::Hasher::new_derive_key("SEXTANT_EXTERNAL_NOTARY_V1");
    let sess_bytes = session_id.as_bytes();
    hasher.update(&(sess_bytes.len() as u64).to_le_bytes());
    hasher.update(sess_bytes);
    hasher.update(agent_verifying_key);
    hasher.update(accumulator_root);
    hasher.update(merkle_root);
    hasher.update(&(total_leaves as u64).to_le_bytes());
    let id_bytes = notary_id.as_bytes();
    hasher.update(&(id_bytes.len() as u64).to_le_bytes());
    hasher.update(id_bytes);
    hasher.update(external_chain_head);
    hasher.update(&notary_sequence.to_le_bytes());
    hasher.update(&timestamp_utc.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute the canonical node hash from all pre-image components.
#[allow(clippy::too_many_arguments)]
pub fn compute_canonical_node_hash(
    parent_hash: &HashDigest,
    sequence: u64,
    timestamp_ns: u64,
    record_type_code: u16,
    tool_id: &str,
    arguments_digest: &HashDigest,
    return_digest: &HashDigest,
    subtree_merkle_root: &HashDigest,
) -> HashDigest {
    let mut seq_leb = Vec::with_capacity(10);
    encode_leb128_u64(sequence, &mut seq_leb);

    let tool_bytes = tool_id.as_bytes();
    let tool_len = (tool_bytes.len() as u64).to_le_bytes();

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"SEXTANT_NODE_V1");
    hasher.update(parent_hash);
    hasher.update(&seq_leb);
    hasher.update(&timestamp_ns.to_le_bytes());
    hasher.update(&record_type_code.to_le_bytes());
    hasher.update(&tool_len);
    hasher.update(tool_bytes);
    hasher.update(arguments_digest);
    hasher.update(return_digest);
    hasher.update(subtree_merkle_root);
    *hasher.finalize().as_bytes()
}

/// Compute linear accumulator step `H_n = BLAKE3(H_{n-1} || NodeHash_n)`.
pub fn compute_linear_accumulator(
    prev_accumulator: &HashDigest,
    node_hash: &HashDigest,
) -> HashDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev_accumulator);
    hasher.update(node_hash);
    *hasher.finalize().as_bytes()
}

/// Verify a `ProvenanceWitness` across `DirectCheckpoint`, `FinalizedNode`, and pinned `ExternalNotary` modes (`INV-04`, `RESIDUAL-01`, `NEW-01`).
pub fn verify_witness(witness: &ProvenanceWitness) -> SextantResult<()> {
    verify_witness_with_notary(witness, None)
}

/// Verify a `ProvenanceWitness` with an optional pinned trusted external notary verifying key (`NEW-01`).
pub fn verify_witness_with_notary(
    witness: &ProvenanceWitness,
    expected_notary_vk: Option<&[u8; 32]>,
) -> SextantResult<()> {
    // Unconditionally bind target_sequence to leaf_index + 1 before evaluating either anchor mode.
    if witness.target_sequence == 0 || witness.target_sequence != (witness.leaf_index as u64) + 1 {
        return Err(SextantError::WitnessVerificationFailed(
            "witness target_sequence does not match leaf_index + 1".to_string(),
        ));
    }

    let verifying_key = VerifyingKey::from_bytes(&witness.agent_verifying_key)
        .map_err(|err| SextantError::WitnessVerificationFailed(err.to_string()))?;
    let sig = Signature::from_bytes(&witness.root_signature);

    match &witness.anchor {
        WitnessAnchor::DirectCheckpoint => {
            let digest = compute_witness_checkpoint_digest(
                &witness.session_id,
                &witness.accumulator_root,
                &witness.merkle_root,
                witness.leaf_index,
                witness.total_leaves,
            );
            verifying_key.verify_strict(&digest, &sig).map_err(|_| {
                SextantError::WitnessVerificationFailed(
                    "checkpoint Ed25519 signature invalid".to_string(),
                )
            })?;
        }
        WitnessAnchor::FinalizedNode {
            policy_hash,
            initial_anchor,
            header_signature,
            anchor_sequence,
            anchor_parent_hash,
            anchor_prev_accumulator,
            anchor_timestamp_ns,
            anchor_record_type,
            anchor_tool_id,
            anchor_arg_hash,
            anchor_ret_hash,
        } => {
            // Cryptographically bind witness.session_id to H_0 and the agent's Ed25519 header signature.
            let expected_h0 = compute_session_anchor_digest(
                &witness.session_id,
                &witness.agent_verifying_key,
                policy_hash,
            );
            let h0_ok: bool =
                subtle::ConstantTimeEq::ct_eq(&expected_h0[..], &initial_anchor[..]).into();
            if !h0_ok {
                return Err(SextantError::SessionAnchorMismatch);
            }
            let hdr_sig = Signature::from_bytes(header_signature);
            verifying_key
                .verify_strict(initial_anchor, &hdr_sig)
                .map_err(|_| SextantError::HeaderSignatureInvalid)?;

            if *anchor_record_type != 0x0007
                || *anchor_sequence == 0
                || witness.total_leaves as u64 != anchor_sequence - 1
            {
                return Err(SextantError::WitnessVerificationFailed(
                    "invalid finalized anchor cardinality or record type".to_string(),
                ));
            }
            let recomputed_anchor_node = compute_canonical_node_hash(
                anchor_parent_hash,
                *anchor_sequence,
                *anchor_timestamp_ns,
                *anchor_record_type,
                anchor_tool_id,
                anchor_arg_hash,
                anchor_ret_hash,
                &witness.merkle_root,
            );
            let recomputed_acc =
                compute_linear_accumulator(anchor_prev_accumulator, &recomputed_anchor_node);
            let acc_matches: bool =
                subtle::ConstantTimeEq::ct_eq(&recomputed_acc[..], &witness.accumulator_root[..])
                    .into();
            if !acc_matches {
                return Err(SextantError::WitnessVerificationFailed(
                    "anchor accumulator mismatch against merkle_root".to_string(),
                ));
            }
            verifying_key
                .verify_strict(&witness.accumulator_root, &sig)
                .map_err(|_| {
                    SextantError::WitnessVerificationFailed(
                        "anchor node Ed25519 signature invalid".to_string(),
                    )
                })?;
        }
        WitnessAnchor::ExternalNotary {
            notary_id,
            notary_verifying_key,
            external_chain_head,
            notary_sequence,
            timestamp_utc,
            notary_signature,
        } => {
            let Some(pinned_notary_vk) = expected_notary_vk else {
                return Err(SextantError::WitnessVerificationFailed(
                    "ExternalNotary witness requires an explicit trusted notary verifying key"
                        .to_string(),
                ));
            };
            if notary_id.trim().is_empty() {
                return Err(SextantError::WitnessVerificationFailed(
                    "external notary_id cannot be empty".to_string(),
                ));
            }
            let pinned_matches: bool =
                subtle::ConstantTimeEq::ct_eq(&notary_verifying_key[..], &pinned_notary_vk[..])
                    .into();
            if !pinned_matches {
                return Err(SextantError::WitnessVerificationFailed(
                    "external notary verifying key mismatch against trusted notary root"
                        .to_string(),
                ));
            }
            let self_notarized: bool = subtle::ConstantTimeEq::ct_eq(
                &notary_verifying_key[..],
                &witness.agent_verifying_key[..],
            )
            .into();
            if self_notarized {
                return Err(SextantError::WitnessVerificationFailed(
                    "self-notarization rejected: external notary key must differ from agent verifying key"
                        .to_string(),
                ));
            }

            // Require valid agent checkpoint root_signature before accepting detached notary countersignature.
            let checkpoint_digest = compute_witness_checkpoint_digest(
                &witness.session_id,
                &witness.accumulator_root,
                &witness.merkle_root,
                witness.leaf_index,
                witness.total_leaves,
            );
            verifying_key
                .verify_strict(&checkpoint_digest, &sig)
                .map_err(|_| {
                    SextantError::WitnessVerificationFailed(
                        "external notary checkpoint Ed25519 root_signature invalid".to_string(),
                    )
                })?;

            // Verify binding across full session provenance, detached notary key, and external chain head.
            let notary_digest = compute_external_notary_digest(
                &witness.session_id,
                &witness.agent_verifying_key,
                &witness.accumulator_root,
                &witness.merkle_root,
                witness.total_leaves,
                notary_id,
                external_chain_head,
                *notary_sequence,
                *timestamp_utc,
            );
            let notary_vk = VerifyingKey::from_bytes(notary_verifying_key)
                .map_err(|err| SextantError::WitnessVerificationFailed(err.to_string()))?;
            let notary_sig = Signature::from_bytes(notary_signature);
            notary_vk
                .verify_strict(&notary_digest, &notary_sig)
                .map_err(|_| {
                    SextantError::WitnessVerificationFailed(
                        "external notary Ed25519 countersignature invalid".to_string(),
                    )
                })?;
        }
    }

    if !verify_merkle_audit_path(
        &witness.target_node_hash,
        witness.leaf_index,
        witness.total_leaves,
        &witness.merkle_root,
        &witness.audit_path,
    ) {
        return Err(SextantError::WitnessVerificationFailed(
            "Merkle audit path failed positional root reconstruction".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_path_verifies_and_rejects_odd_tail_duplication() {
        for count in [1usize, 2, 3, 5, 8, 13] {
            let leaves: Vec<HashDigest> = (0..count)
                .map(|i| *blake3::hash(&i.to_le_bytes()).as_bytes())
                .collect();
            let root = compute_merkle_root(&leaves);

            // CVE-2012-2459 guard: duplicating the trailing leaf in an odd-sized list changes root!
            if count % 2 == 1 {
                let mut duplicated = leaves.clone();
                duplicated.push(leaves[count - 1]);
                assert_ne!(compute_merkle_root(&duplicated), root);
            }

            for (idx, leaf) in leaves.iter().enumerate() {
                let (path_root, path) =
                    build_merkle_audit_path(&leaves, idx).expect("audit path builds");
                assert_eq!(path_root, root);
                assert!(verify_merkle_audit_path(leaf, idx, count, &root, &path));

                assert!(!verify_merkle_audit_path(
                    leaf,
                    idx + 1,
                    count,
                    &root,
                    &path
                ));
                assert!(!verify_merkle_audit_path(
                    leaf,
                    idx,
                    count + 1,
                    &root,
                    &path
                ));

                let mut tampered = *leaf;
                tampered[0] ^= 0x01;
                assert!(!verify_merkle_audit_path(
                    &tampered, idx, count, &root, &path
                ));
            }
        }
    }
}
