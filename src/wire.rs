//! Append-only `"SEXT"` v1 binary wire format reader, writer, and bounded stream verifier (`SEC-04`).

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use crate::crypto::{
    ExecutionNode, LedgerEntry, RecordType, SessionMetadata, VerificationReport, verify_ledger,
};
use crate::merkle::HashDigest;
use crate::{SextantError, SextantResult};

/// Fixed 4-byte wire magic prefix (`"SEXT"`).
pub const WIRE_MAGIC: [u8; 4] = [0x53, 0x45, 0x58, 0x54];

/// Current binary wire specification version.
pub const WIRE_VERSION: u16 = 0x0001;

/// Preamble marker tag distinguishing a file session header from execution node records.
const HEADER_RECORD_MARKER: u16 = 0x0000;

/// Defensive maximum per-field allocation bound (64 MiB) when decoding untrusted wire streams.
const MAX_WIRE_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

/// Aggregate stream payload memory ceiling across an entire decoded ledger (256 MiB, `SEC-04`).
const MAX_TOTAL_LEDGER_BYTES: usize = 256 * 1024 * 1024;

/// Encode a `SessionMetadata` preamble header to any `Write` sink.
pub fn write_header<W: Write>(writer: &mut W, metadata: &SessionMetadata) -> SextantResult<()> {
    let id_bytes = metadata.session_id.as_bytes();
    let id_len = u16::try_from(id_bytes.len()).map_err(|_| {
        SextantError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "session_id exceeds u16 wire bound",
        ))
    })?;

    writer.write_all(&WIRE_MAGIC)?;
    writer.write_all(&WIRE_VERSION.to_le_bytes())?;
    writer.write_all(&HEADER_RECORD_MARKER.to_le_bytes())?;
    writer.write_all(&id_len.to_le_bytes())?;
    writer.write_all(id_bytes)?;
    writer.write_all(&metadata.verifying_key)?;
    writer.write_all(&metadata.policy_hash)?;
    writer.write_all(&metadata.initial_anchor)?;
    writer.write_all(&metadata.header_signature)?;
    Ok(())
}

/// Encode a single `LedgerEntry` record to any `Write` sink.
pub fn write_entry<W: Write>(writer: &mut W, entry: &LedgerEntry) -> SextantResult<()> {
    let node = &entry.node;
    let tool_bytes = node.tool_id.as_bytes();
    let tool_len = u16::try_from(tool_bytes.len()).map_err(|_| {
        SextantError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tool_id exceeds u16 wire bound",
        ))
    })?;
    let arg_len = u32::try_from(entry.arg_payload.len()).map_err(|_| {
        SextantError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "arg_payload exceeds u32 wire bound",
        ))
    })?;
    let ret_len = u32::try_from(entry.ret_payload.len()).map_err(|_| {
        SextantError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ret_payload exceeds u32 wire bound",
        ))
    })?;

    writer.write_all(&WIRE_MAGIC)?;
    writer.write_all(&WIRE_VERSION.to_le_bytes())?;
    writer.write_all(&node.record_type.as_u16().to_le_bytes())?;
    writer.write_all(&node.sequence.to_le_bytes())?;
    writer.write_all(&node.timestamp_ns.to_le_bytes())?;
    writer.write_all(&node.parent_hash)?;
    writer.write_all(&node.prev_accumulator)?;
    writer.write_all(&node.subtree_merkle_root)?;
    writer.write_all(&node.node_hash)?;
    writer.write_all(&node.accumulated_hash)?;
    writer.write_all(&tool_len.to_le_bytes())?;
    writer.write_all(tool_bytes)?;
    writer.write_all(&arg_len.to_le_bytes())?;
    writer.write_all(&entry.arg_payload)?;
    writer.write_all(&ret_len.to_le_bytes())?;
    writer.write_all(&entry.ret_payload)?;
    writer.write_all(&node.signature)?;
    Ok(())
}

/// Write a complete ledger (`SessionMetadata` + all `LedgerEntry` records) atomically via buffered I/O.
pub fn write_ledger_to_writer<W: Write>(
    writer: &mut W,
    metadata: &SessionMetadata,
    entries: &[LedgerEntry],
) -> SextantResult<()> {
    write_header(writer, metadata)?;
    for entry in entries {
        write_entry(writer, entry)?;
    }
    writer.flush()?;
    Ok(())
}

/// Persist an entire ledger to `path` and flush to OS storage.
pub fn write_ledger_to_path(
    path: &Path,
    metadata: &SessionMetadata,
    entries: &[LedgerEntry],
) -> SextantResult<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    write_ledger_to_writer(&mut writer, metadata, entries)?;
    writer
        .into_inner()
        .map_err(|e| e.into_error())?
        .sync_all()?;
    Ok(())
}

/// Append a single `LedgerEntry` to an existing ledger file on disk.
pub fn append_entry_to_path(path: &Path, entry: &LedgerEntry) -> SextantResult<()> {
    let file = OpenOptions::new().append(true).open(path)?;
    let mut writer = BufWriter::new(file);
    write_entry(&mut writer, entry)?;
    writer.flush()?;
    writer
        .into_inner()
        .map_err(|e| e.into_error())?
        .sync_all()?;
    Ok(())
}

/// Read an entire binary ledger from any `Read` stream, enforcing aggregate memory bounds (`SEC-04`).
pub fn read_ledger_from_reader<R: Read>(
    reader: &mut R,
) -> SextantResult<(SessionMetadata, Vec<LedgerEntry>)> {
    let mut remaining_budget = MAX_TOTAL_LEDGER_BYTES;
    let metadata = read_header(reader, &mut remaining_budget)?;
    let mut entries = Vec::new();
    while let Some(entry) = read_next_entry(reader, &mut remaining_budget)? {
        entries.push(entry);
    }
    Ok((metadata, entries))
}

/// Read a binary ledger file from `path`.
pub fn read_ledger_from_path(path: &Path) -> SextantResult<(SessionMetadata, Vec<LedgerEntry>)> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    read_ledger_from_reader(&mut reader)
}

/// Read and cryptographically verify a ledger stream across all 5 security invariants.
pub fn verify_ledger_stream<R: Read>(reader: &mut R) -> SextantResult<VerificationReport> {
    let (metadata, entries) = read_ledger_from_reader(reader)?;
    verify_ledger(&metadata, &entries, true)
}

fn read_header<R: Read>(reader: &mut R, budget: &mut usize) -> SextantResult<SessionMetadata> {
    let magic = read_exact_array::<4, _>(reader)?;
    if magic != WIRE_MAGIC {
        return Err(SextantError::InvalidWireMagic);
    }
    let version = read_u16_le(reader)?;
    if version != WIRE_VERSION {
        return Err(SextantError::UnsupportedWireVersion(version));
    }
    let marker = read_u16_le(reader)?;
    if marker != HEADER_RECORD_MARKER {
        return Err(SextantError::InvalidRecordType(marker));
    }

    let id_len = usize::from(read_u16_le(reader)?);
    let id_bytes = read_bounded_vec(reader, id_len, budget)?;
    let session_id = String::from_utf8(id_bytes).map_err(|err| {
        SextantError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    })?;

    let verifying_key = read_exact_array::<32, _>(reader)?;
    let policy_hash = read_exact_array::<32, _>(reader)?;
    let initial_anchor = read_exact_array::<32, _>(reader)?;
    let header_signature = read_exact_array::<64, _>(reader)?;

    Ok(SessionMetadata {
        session_id,
        verifying_key,
        policy_hash,
        initial_anchor,
        header_signature,
    })
}

fn read_next_entry<R: Read>(
    reader: &mut R,
    budget: &mut usize,
) -> SextantResult<Option<LedgerEntry>> {
    // Read first byte separately so 1..3 trailing partial magic bytes fail cleanly instead of returning EOF.
    let mut first_byte = [0u8; 1];
    loop {
        match reader.read(&mut first_byte) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(SextantError::Io(err)),
        }
    }

    let rest = read_exact_array::<3, _>(reader)?;
    let magic = [first_byte[0], rest[0], rest[1], rest[2]];
    if magic != WIRE_MAGIC {
        return Err(SextantError::InvalidWireMagic);
    }

    let version = read_u16_le(reader)?;
    if version != WIRE_VERSION {
        return Err(SextantError::UnsupportedWireVersion(version));
    }
    let type_tag = read_u16_le(reader)?;
    let record_type = RecordType::try_from(type_tag)?;

    let sequence = read_u64_le(reader)?;
    let timestamp_ns = read_u64_le(reader)?;
    let parent_hash: HashDigest = read_exact_array::<32, _>(reader)?;
    let prev_accumulator: HashDigest = read_exact_array::<32, _>(reader)?;
    let subtree_merkle_root: HashDigest = read_exact_array::<32, _>(reader)?;
    let node_hash: HashDigest = read_exact_array::<32, _>(reader)?;
    let accumulated_hash: HashDigest = read_exact_array::<32, _>(reader)?;

    let tool_len = usize::from(read_u16_le(reader)?);
    let tool_bytes = read_bounded_vec(reader, tool_len, budget)?;
    let tool_id = String::from_utf8(tool_bytes).map_err(|err| {
        SextantError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    })?;

    let arg_len = read_u32_le(reader)? as usize;
    let arg_payload = read_bounded_vec(reader, arg_len, budget)?;
    let ret_len = read_u32_le(reader)? as usize;
    let ret_payload = read_bounded_vec(reader, ret_len, budget)?;
    let signature = read_exact_array::<64, _>(reader)?;

    Ok(Some(LedgerEntry {
        node: ExecutionNode {
            sequence,
            timestamp_ns,
            record_type,
            parent_hash,
            prev_accumulator,
            subtree_merkle_root,
            tool_id,
            arguments_digest: crate::canonical::hash_payload_bytes(&arg_payload),
            return_digest: crate::canonical::hash_payload_bytes(&ret_payload),
            node_hash,
            accumulated_hash,
            signature,
        },
        arg_payload,
        ret_payload,
    }))
}

fn read_exact_array<const N: usize, R: Read>(reader: &mut R) -> SextantResult<[u8; N]> {
    let mut buf = [0u8; N];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_u16_le<R: Read>(reader: &mut R) -> SextantResult<u16> {
    Ok(u16::from_le_bytes(read_exact_array::<2, _>(reader)?))
}

fn read_u32_le<R: Read>(reader: &mut R) -> SextantResult<u32> {
    Ok(u32::from_le_bytes(read_exact_array::<4, _>(reader)?))
}

fn read_u64_le<R: Read>(reader: &mut R) -> SextantResult<u64> {
    Ok(u64::from_le_bytes(read_exact_array::<8, _>(reader)?))
}

fn read_bounded_vec<R: Read>(
    reader: &mut R,
    len: usize,
    budget: &mut usize,
) -> SextantResult<Vec<u8>> {
    if len > MAX_WIRE_PAYLOAD_BYTES || len > *budget {
        return Err(SextantError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("wire field length {len} exceeds maximum memory budget"),
        )));
    }
    *budget -= len;
    // Cap initial reservation to 64 KiB so a truncated frame declaring up to MAX_WIRE_PAYLOAD_BYTES
    // cannot force an immediate multi-megabyte allocation before EOF is encountered.
    let mut buf = Vec::with_capacity(len.min(64 * 1024));
    reader.take(len as u64).read_to_end(&mut buf)?;
    if buf.len() != len {
        return Err(SextantError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!(
                "truncated wire field: expected {len} bytes, got {}",
                buf.len()
            ),
        )));
    }
    Ok(buf)
}
