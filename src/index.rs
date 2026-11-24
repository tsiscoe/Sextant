//! Embedded SQLite WAL provenance state index (`rusqlite` + `BEGIN IMMEDIATE` + ACL lockdown, `SEC-05`).

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::canonical::enforce_owner_only_acl;
use crate::crypto::{ExecutionNode, LedgerEntry, RecordType, SessionMetadata};
use crate::merkle::HashDigest;
use crate::{SextantError, SextantResult};

/// Embedded SQLite WAL index providing sub-millisecond call-graph and sequence queries.
pub struct SqliteProvenanceIndex {
    conn: Connection,
    db_path: Option<PathBuf>,
}

impl SqliteProvenanceIndex {
    /// Open or initialize a WAL-mode provenance index database at `path` with owner-only ACLs (`SEC-05`, `RESIDUAL-03`).
    pub fn open(path: &Path) -> SextantResult<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path).map_err(|e| SextantError::IndexError(e.to_string()))?;
        let index = Self::configure_and_migrate(conn, Some(path.to_path_buf()))?;
        index.enforce_db_and_sidecar_acls()?;
        Ok(index)
    }

    /// Open an isolated in-memory SQLite provenance index for tests and transient queries.
    pub fn open_in_memory() -> SextantResult<Self> {
        let conn =
            Connection::open_in_memory().map_err(|e| SextantError::IndexError(e.to_string()))?;
        Self::configure_and_migrate(conn, None)
    }

    fn configure_and_migrate(conn: Connection, db_path: Option<PathBuf>) -> SextantResult<Self> {
        conn.execute_batch(
            "PRAGMA trusted_schema = OFF;
             PRAGMA busy_timeout = 5000;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS sessions (
                 session_id TEXT PRIMARY KEY,
                 verifying_key BLOB NOT NULL,
                 policy_hash BLOB NOT NULL,
                 initial_anchor BLOB NOT NULL,
                 header_signature BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS execution_nodes (
                 session_id TEXT NOT NULL,
                 sequence INTEGER NOT NULL,
                 timestamp_ns TEXT NOT NULL,
                 record_type INTEGER NOT NULL,
                 parent_hash BLOB NOT NULL,
                 prev_accumulator BLOB NOT NULL,
                 subtree_merkle_root BLOB NOT NULL,
                 tool_id TEXT NOT NULL,
                 arguments_digest BLOB NOT NULL,
                 return_digest BLOB NOT NULL,
                 node_hash BLOB NOT NULL,
                 accumulated_hash BLOB NOT NULL,
                 signature BLOB NOT NULL,
                 arg_payload BLOB NOT NULL,
                 ret_payload BLOB NOT NULL,
                 PRIMARY KEY (session_id, sequence),
                 FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
             );
             CREATE INDEX IF NOT EXISTS idx_nodes_tool ON execution_nodes(session_id, tool_id);
             CREATE INDEX IF NOT EXISTS idx_nodes_parent ON execution_nodes(session_id, parent_hash);",
        )
        .map_err(|e| SextantError::IndexError(e.to_string()))?;

        Ok(Self { conn, db_path })
    }

    fn enforce_db_and_sidecar_acls(&self) -> SextantResult<()> {
        let Some(ref path) = self.db_path else {
            return Ok(());
        };
        if path.exists() {
            enforce_owner_only_acl(path, false)?;
        }
        let path_str = path.to_string_lossy();
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{path_str}{suffix}"));
            if sidecar.exists() {
                enforce_owner_only_acl(&sidecar, false)?;
            }
        }
        Ok(())
    }

    /// Atomically index a verified session inside a `BEGIN IMMEDIATE` transaction (`SEC-05`, `RESIDUAL-03`).
    ///
    /// Fully verifies the cryptographic ledger before indexing and refuses overwriting existing
    /// session headers or sequence numbers with conflicting hashes (equivocation defense).
    pub fn index_ledger(
        &mut self,
        metadata: &SessionMetadata,
        entries: &[LedgerEntry],
    ) -> SextantResult<()> {
        crate::crypto::verify_ledger(metadata, entries, true)?;

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| SextantError::IndexError(e.to_string()))?;

        let existing: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT verifying_key, initial_anchor FROM sessions WHERE session_id = ?1",
                params![metadata.session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| SextantError::IndexError(e.to_string()))?;

        if let Some((existing_vk, existing_anchor)) = existing {
            if existing_vk.as_slice() != metadata.verifying_key
                || existing_anchor.as_slice() != metadata.initial_anchor
            {
                return Err(SextantError::IndexError(format!(
                    "session '{}' already indexed with conflicting cryptographic anchor",
                    metadata.session_id
                )));
            }
        } else {
            tx.execute(
                "INSERT INTO sessions (
                    session_id, verifying_key, policy_hash, initial_anchor, header_signature
                ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    metadata.session_id,
                    &metadata.verifying_key[..],
                    &metadata.policy_hash[..],
                    &metadata.initial_anchor[..],
                    &metadata.header_signature[..],
                ],
            )
            .map_err(|e| SextantError::IndexError(e.to_string()))?;
        }

        {
            let mut check_stmt = tx
                .prepare(
                    "SELECT node_hash, accumulated_hash
                     FROM execution_nodes
                     WHERE session_id = ?1 AND sequence = ?2",
                )
                .map_err(|e| SextantError::IndexError(e.to_string()))?;
            let mut stmt = tx
                .prepare(
                    "INSERT INTO execution_nodes (
                        session_id, sequence, timestamp_ns, record_type, parent_hash,
                        prev_accumulator, subtree_merkle_root, tool_id, arguments_digest,
                        return_digest, node_hash, accumulated_hash, signature,
                        arg_payload, ret_payload
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
                    ON CONFLICT(session_id, sequence) DO NOTHING",
                )
                .map_err(|e| SextantError::IndexError(e.to_string()))?;

            for entry in entries {
                let n = &entry.node;
                let seq_i64 = i64::try_from(n.sequence)
                    .map_err(|_| SextantError::IndexError("sequence overflows i64".into()))?;
                let existing_node: Option<(Vec<u8>, Vec<u8>)> = check_stmt
                    .query_row(params![metadata.session_id, seq_i64], |row| {
                        Ok((row.get(0)?, row.get(1)?))
                    })
                    .optional()
                    .map_err(|e| SextantError::IndexError(e.to_string()))?;
                if let Some((existing_node_hash, existing_acc_hash)) = existing_node {
                    if existing_node_hash.as_slice() != n.node_hash
                        || existing_acc_hash.as_slice() != n.accumulated_hash
                    {
                        return Err(SextantError::IndexError(format!(
                            "equivocation detected at session '{}' sequence {}",
                            metadata.session_id, n.sequence
                        )));
                    }
                    continue;
                }
                stmt.execute(params![
                    metadata.session_id,
                    seq_i64,
                    n.timestamp_ns.to_string(),
                    i64::from(n.record_type.as_u16()),
                    &n.parent_hash[..],
                    &n.prev_accumulator[..],
                    &n.subtree_merkle_root[..],
                    n.tool_id,
                    &n.arguments_digest[..],
                    &n.return_digest[..],
                    &n.node_hash[..],
                    &n.accumulated_hash[..],
                    &n.signature[..],
                    &entry.arg_payload[..],
                    &entry.ret_payload[..],
                ])
                .map_err(|e| SextantError::IndexError(e.to_string()))?;
            }
        }

        tx.commit()
            .map_err(|e| SextantError::IndexError(e.to_string()))?;
        self.enforce_db_and_sidecar_acls()?;
        Ok(())
    }

    /// Load and cryptographically verify a session header and all ordered `LedgerEntry` rows.
    pub fn load_session(
        &self,
        session_id: &str,
    ) -> SextantResult<(SessionMetadata, Vec<LedgerEntry>)> {
        let metadata = self
            .conn
            .query_row(
                "SELECT session_id, verifying_key, policy_hash, initial_anchor, header_signature
                 FROM sessions WHERE session_id = ?1",
                params![session_id],
                |row| {
                    let id: String = row.get(0)?;
                    let vk: Vec<u8> = row.get(1)?;
                    let ph: Vec<u8> = row.get(2)?;
                    let anc: Vec<u8> = row.get(3)?;
                    let sig: Vec<u8> = row.get(4)?;
                    Ok((id, vk, ph, anc, sig))
                },
            )
            .map_err(|e| SextantError::IndexError(e.to_string()))?;

        let meta = SessionMetadata {
            session_id: metadata.0,
            verifying_key: vec_to_fixed::<32>(&metadata.1)?,
            policy_hash: vec_to_fixed::<32>(&metadata.2)?,
            initial_anchor: vec_to_fixed::<32>(&metadata.3)?,
            header_signature: vec_to_fixed::<64>(&metadata.4)?,
        };

        let entries = self.query_entries_where(
            "SELECT sequence, timestamp_ns, record_type, parent_hash, prev_accumulator,
                    subtree_merkle_root, tool_id, arguments_digest, return_digest,
                    node_hash, accumulated_hash, signature, arg_payload, ret_payload
             FROM execution_nodes WHERE session_id = ?1 ORDER BY sequence ASC",
            params![session_id],
        )?;

        crate::crypto::verify_ledger(&meta, &entries, true)?;

        Ok((meta, entries))
    }

    /// Query indexed nodes matching a given `tool_id`.
    pub fn query_by_tool(
        &self,
        session_id: &str,
        tool_id: &str,
    ) -> SextantResult<Vec<LedgerEntry>> {
        self.query_entries_where(
            "SELECT sequence, timestamp_ns, record_type, parent_hash, prev_accumulator,
                    subtree_merkle_root, tool_id, arguments_digest, return_digest,
                    node_hash, accumulated_hash, signature, arg_payload, ret_payload
             FROM execution_nodes WHERE session_id = ?1 AND tool_id = ?2 ORDER BY sequence ASC",
            params![session_id, tool_id],
        )
    }

    /// Query all child nodes referencing `parent_hash`.
    pub fn query_children(
        &self,
        session_id: &str,
        parent_hash: &HashDigest,
    ) -> SextantResult<Vec<LedgerEntry>> {
        self.query_entries_where(
            "SELECT sequence, timestamp_ns, record_type, parent_hash, prev_accumulator,
                    subtree_merkle_root, tool_id, arguments_digest, return_digest,
                    node_hash, accumulated_hash, signature, arg_payload, ret_payload
             FROM execution_nodes WHERE session_id = ?1 AND parent_hash = ?2 ORDER BY sequence ASC",
            params![session_id, &parent_hash[..]],
        )
    }

    fn query_entries_where<P: rusqlite::Params>(
        &self,
        sql: &str,
        params: P,
    ) -> SextantResult<Vec<LedgerEntry>> {
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| SextantError::IndexError(e.to_string()))?;

        let rows = stmt
            .query_map(params, |row| {
                let seq_i64: i64 = row.get(0)?;
                let ts_str: String = row.get(1)?;
                let rtype_i64: i64 = row.get(2)?;
                let parent: Vec<u8> = row.get(3)?;
                let prev_acc: Vec<u8> = row.get(4)?;
                let subtree: Vec<u8> = row.get(5)?;
                let tool_id: String = row.get(6)?;
                let arg_dig: Vec<u8> = row.get(7)?;
                let ret_dig: Vec<u8> = row.get(8)?;
                let node_hash: Vec<u8> = row.get(9)?;
                let acc_hash: Vec<u8> = row.get(10)?;
                let sig: Vec<u8> = row.get(11)?;
                let arg_payload: Vec<u8> = row.get(12)?;
                let ret_payload: Vec<u8> = row.get(13)?;
                Ok((
                    seq_i64,
                    ts_str,
                    rtype_i64,
                    parent,
                    prev_acc,
                    subtree,
                    tool_id,
                    arg_dig,
                    ret_dig,
                    node_hash,
                    acc_hash,
                    sig,
                    arg_payload,
                    ret_payload,
                ))
            })
            .map_err(|e| SextantError::IndexError(e.to_string()))?;

        let mut out = Vec::new();
        for row_res in rows {
            let r = row_res.map_err(|e| SextantError::IndexError(e.to_string()))?;
            let sequence = u64::try_from(r.0)
                .map_err(|_| SextantError::IndexError("negative sequence in index".into()))?;
            let timestamp_ns =
                r.1.parse::<u64>()
                    .map_err(|_| SextantError::IndexError("invalid timestamp in index".into()))?;
            let rtype_u16 = u16::try_from(r.2)
                .map_err(|_| SextantError::IndexError("invalid record_type in index".into()))?;
            let record_type = RecordType::try_from(rtype_u16)?;

            out.push(LedgerEntry {
                node: ExecutionNode {
                    sequence,
                    timestamp_ns,
                    record_type,
                    parent_hash: vec_to_fixed::<32>(&r.3)?,
                    prev_accumulator: vec_to_fixed::<32>(&r.4)?,
                    subtree_merkle_root: vec_to_fixed::<32>(&r.5)?,
                    tool_id: r.6,
                    arguments_digest: vec_to_fixed::<32>(&r.7)?,
                    return_digest: vec_to_fixed::<32>(&r.8)?,
                    node_hash: vec_to_fixed::<32>(&r.9)?,
                    accumulated_hash: vec_to_fixed::<32>(&r.10)?,
                    signature: vec_to_fixed::<64>(&r.11)?,
                },
                arg_payload: r.12,
                ret_payload: r.13,
            });
        }
        Ok(out)
    }
}

fn vec_to_fixed<const N: usize>(bytes: &[u8]) -> SextantResult<[u8; N]> {
    bytes.try_into().map_err(|_| {
        SextantError::IndexError(format!("expected {N} byte blob, got {}", bytes.len()))
    })
}
