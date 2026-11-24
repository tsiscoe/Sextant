//! Fleet integration adapters for `SigNET`, `Faraday`, and selective payload redaction (`SEC-07`).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::canonical::sanitize_terminal_text;
use crate::crypto::{
    AccumulatorState, ExecutionNode, LedgerEntry, RecordType, SessionMetadata, VerificationReport,
    verify_redacted_nodes,
};
use crate::merkle::HashDigest;
use crate::{SextantError, SextantResult};

/// Receipt payload bridging a `SigNET` Ed25519 capability grant into a Sextant `PolicyAssertion`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignetCapabilityReceipt {
    pub tool_id: String,
    pub capability_token_digest: String,
    pub attenuation_depth: u8,
    pub merkle_receipt_root: String,
    pub decision: String,
}

/// Sanitized stream digest bridging `Faraday` zero-disk process stdout/stderr into `ReturnPayload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaradayStreamDigest {
    pub exit_code: i32,
    pub stdout_blake3: String,
    pub stderr_blake3: String,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub preview: String,
}

/// Selectively redacted execution tree export compatible with salted-Merkle workflows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactedProvenanceBundle {
    pub metadata: SessionMetadata,
    pub entries: Vec<RedactedEntry>,
}

/// Individual entry in a redacted provenance bundle separating raw verifiable bytes from sanitized display text (`SEC-07`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactedEntry {
    pub node: ExecutionNode,
    pub redacted: bool,
    pub arg_payload_raw: Option<Vec<u8>>,
    pub ret_payload_raw: Option<Vec<u8>>,
    pub arg_display_sanitized: Option<String>,
    pub ret_display_sanitized: Option<String>,
}

/// Record a `SigNET` firewall clearance decision directly into the provenance accumulator.
pub fn ingest_signet_receipt(
    accumulator: &mut AccumulatorState,
    receipt: &SignetCapabilityReceipt,
    timestamp_ns: u64,
) -> SextantResult<ExecutionNode> {
    let args_json = serde_json::to_vec(&serde_json::json!({
        "firewall": "signet",
        "tool_id": receipt.tool_id,
        "token_digest": receipt.capability_token_digest,
        "attenuation_depth": receipt.attenuation_depth,
    }))?;
    let ret_json = serde_json::to_vec(&serde_json::json!({
        "decision": receipt.decision,
        "merkle_receipt_root": receipt.merkle_receipt_root,
    }))?;

    accumulator.record_action(
        &format!("signet:policy:{}", receipt.tool_id),
        &args_json,
        &ret_json,
        RecordType::PolicyAssertion,
        timestamp_ns,
    )
}

/// Hash sanitized `Faraday` child-process streams without persisting secret plaintext in return payloads.
pub fn build_faraday_stream_payload(
    exit_code: i32,
    stdout: &[u8],
    stderr: &[u8],
) -> SextantResult<Vec<u8>> {
    let stdout_hash = hex::encode(blake3::hash(stdout).as_bytes());
    let stderr_hash = hex::encode(blake3::hash(stderr).as_bytes());
    let preview_raw = String::from_utf8_lossy(&stdout[..stdout.len().min(160)]);
    let preview = sanitize_terminal_text(&preview_raw);

    let summary = FaradayStreamDigest {
        exit_code,
        stdout_blake3: stdout_hash,
        stderr_blake3: stderr_hash,
        stdout_bytes: stdout.len(),
        stderr_bytes: stderr.len(),
        preview,
    };

    Ok(serde_json::to_vec(&summary)?)
}

/// Export a selectively redacted execution tree (`INV-04`) keeping raw commitments and sanitized previews aligned (`SEC-07`).
pub fn export_redacted_bundle(
    metadata: &SessionMetadata,
    entries: &[LedgerEntry],
    redact_sequences: &BTreeSet<u64>,
) -> RedactedProvenanceBundle {
    let redacted_entries = entries
        .iter()
        .map(|entry| {
            let is_redacted = redact_sequences.contains(&entry.node.sequence);
            if is_redacted {
                RedactedEntry {
                    node: entry.node.clone(),
                    redacted: true,
                    arg_payload_raw: None,
                    ret_payload_raw: None,
                    arg_display_sanitized: None,
                    ret_display_sanitized: None,
                }
            } else {
                RedactedEntry {
                    node: entry.node.clone(),
                    redacted: false,
                    arg_payload_raw: Some(entry.arg_payload.clone()),
                    ret_payload_raw: Some(entry.ret_payload.clone()),
                    arg_display_sanitized: Some(sanitize_terminal_text(&String::from_utf8_lossy(
                        &entry.arg_payload,
                    ))),
                    ret_display_sanitized: Some(sanitize_terminal_text(&String::from_utf8_lossy(
                        &entry.ret_payload,
                    ))),
                }
            }
        })
        .collect();

    RedactedProvenanceBundle {
        metadata: metadata.clone(),
        entries: redacted_entries,
    }
}

/// Verify a redacted provenance bundle against exact pre-sanitization byte digests (`SEC-07`).
pub fn verify_redacted_bundle(
    bundle: &RedactedProvenanceBundle,
) -> SextantResult<VerificationReport> {
    let nodes: Vec<ExecutionNode> = bundle.entries.iter().map(|e| e.node.clone()).collect();
    let report = verify_redacted_nodes(&bundle.metadata, &nodes)?;

    for entry in &bundle.entries {
        if !entry.redacted {
            let (Some(arg), Some(ret)) = (&entry.arg_payload_raw, &entry.ret_payload_raw) else {
                return Err(SextantError::WitnessVerificationFailed(format!(
                    "unredacted bundle entry {} missing raw payload",
                    entry.node.sequence
                )));
            };
            let arg_digest: HashDigest = crate::canonical::hash_payload_bytes(arg);
            let ret_digest: HashDigest = crate::canonical::hash_payload_bytes(ret);
            if arg_digest != entry.node.arguments_digest || ret_digest != entry.node.return_digest {
                return Err(SextantError::NodeHashMismatch {
                    sequence: entry.node.sequence,
                });
            }
        }
    }

    Ok(report)
}
