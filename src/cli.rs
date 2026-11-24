//! Clap v4 CLI surface for `sextant` (`init`, `wrap`, `record`, `verify-path`, `export-graph`, `tui`).

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;

use crate::canonical::{enforce_owner_only_acl, sanitize_terminal_text};
use crate::crypto::{
    AccumulatorState, ExecutionNode, LedgerEntry, RecordType, SessionMetadata, SessionSigner,
    generate_offline_witness, verify_finalized_ledger, verify_ledger,
};
use crate::fleet::build_faraday_stream_payload;
use crate::index::SqliteProvenanceIndex;
use crate::merkle::{HashDigest, ProvenanceWitness, verify_witness_with_notary};
use crate::tui::run_tui;
use crate::wire::{append_entry_to_path, read_ledger_from_path, write_ledger_to_path};
use crate::{SextantError, SextantResult};

/// Maximum buffered stdout/stderr retained per wrapped child process (`SEC-06`).
const MAX_WRAP_CAPTURE_BYTES: usize = 16 * 1024 * 1024;

/// Maximum newline-delimited JSON-RPC lines sampled from untrusted child stdout (`SEC-06`).
const MAX_MCP_OBSERVED_LINES: usize = 4096;

/// Verifiable route and call-graph provenance engine for autonomous agent execution.
#[derive(Debug, Parser)]
#[command(
    name = "sextant",
    version,
    about = "SEXTANT — Navigational Bearings for Agent Execution Trees"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize a new cryptographically bound provenance session ledger.
    Init {
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        policy_file: PathBuf,
        #[arg(long)]
        ledger_out: PathBuf,
        /// Optional path to write ephemeral hex signing seed for subsequent `record` appends.
        #[arg(long)]
        key_out: Option<PathBuf>,
        /// Optional SQLite WAL index path.
        #[arg(long)]
        db_out: Option<PathBuf>,
    },
    /// Execute a command inside an ephemeral verified provenance envelope (INV-05).
    Wrap {
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        policy_file: PathBuf,
        #[arg(long)]
        ledger_out: PathBuf,
        #[arg(long)]
        db_out: Option<PathBuf>,
        /// Maximum wall-clock seconds before terminating the wrapped child process (`RESIDUAL-07`).
        #[arg(long)]
        timeout_secs: Option<u64>,
        /// Command and arguments to execute under provenance tracking.
        #[arg(required = true, last = true)]
        command: Vec<String>,
    },
    /// Append an explicit tool invocation or call-graph node using an active session key.
    Record {
        #[arg(long)]
        ledger: PathBuf,
        /// Path to file containing 64-char Ed25519 seed hex (or set SEXTANT_SIGNING_KEY env var).
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
        #[arg(long)]
        tool_id: String,
        #[arg(long, default_value = "{}")]
        args: String,
        #[arg(long, default_value = "{}")]
        ret: String,
        #[arg(long, default_value = "invoke")]
        record_type: String,
        #[arg(long)]
        db_out: Option<PathBuf>,
    },
    /// Verify a complete binary ledger or standalone O(log k) provenance witness.
    VerifyPath {
        #[arg(long)]
        ledger: Option<PathBuf>,
        #[arg(long)]
        verifying_key: Option<String>,
        /// Trusted 64-char hex Ed25519 verifying key required when verifying an ExternalNotary witness (`NEW-01`).
        #[arg(long)]
        notary_verifying_key: Option<String>,
        #[arg(long)]
        policy_file: Option<PathBuf>,
        #[arg(long)]
        witness: Option<PathBuf>,
        /// Permit unfinalized / in-progress ledgers instead of requiring SessionFinalize and zero unclosed forks (`RESIDUAL-02`).
        #[arg(long)]
        allow_in_progress: bool,
        #[arg(long)]
        verbose: bool,
    },
    /// Render the call graph as DOT, SVG, or JSON, or extract an O(log k) witness proof.
    ExportGraph {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Extract a standalone ProvenanceWitness JSON for a specific sequence index.
        #[arg(long)]
        witness_seq: Option<u64>,
    },
    /// Launch the 3-pane interactive terminal provenance inspector.
    Tui {
        #[arg(long)]
        ledger: PathBuf,
    },
}

/// Supported call-graph export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    Dot,
    Svg,
    Json,
}

/// Execute parsed CLI arguments and return an explicit process exit code.
pub fn execute_cli(cli: Cli) -> SextantResult<ExitCode> {
    match cli.command {
        Commands::Init {
            session_id,
            policy_file,
            ledger_out,
            key_out,
            db_out,
        } => {
            let policy_bytes = fs::read(&policy_file)?;
            let mut acc = AccumulatorState::new(session_id, &policy_bytes);
            let ts = now_nanos();
            let init_args = serde_json::to_vec(&serde_json::json!({
                "policy_file": policy_file.display().to_string(),
                "policy_blake3": hex::encode(acc.metadata.policy_hash),
            }))?;
            acc.record_action(
                "sextant:init",
                &init_args,
                b"{\"status\":\"initialized\"}",
                RecordType::SessionInit,
                ts,
            )?;

            write_ledger_to_path(&ledger_out, &acc.metadata, acc.entries())?;
            if let Some(db_path) = db_out {
                let mut idx = SqliteProvenanceIndex::open(&db_path)?;
                idx.index_ledger(&acc.metadata, acc.entries())?;
            }

            if let Some(ref key_path) = key_out {
                let seed_hex = acc.signer().export_seed_hex();
                write_restricted_secret(key_path, seed_hex.as_bytes())?;
            }

            println!("Session initialized: {}", acc.metadata.session_id);
            println!("Ledger written: {}", ledger_out.display());
            println!("Verifying Key: {}", hex::encode(acc.metadata.verifying_key));
            println!(
                "Initial Anchor H0: {}",
                hex::encode(acc.metadata.initial_anchor)
            );
            Ok(ExitCode::SUCCESS)
        }
        Commands::Wrap {
            session_id,
            policy_file,
            ledger_out,
            db_out,
            timeout_secs,
            command,
        } => {
            let policy_bytes = fs::read(&policy_file)?;
            let mut acc = AccumulatorState::new(session_id, &policy_bytes);
            acc.record_action(
                "sextant:init",
                b"{}",
                b"{\"status\":\"armed\"}",
                RecordType::SessionInit,
                now_nanos(),
            )?;
            acc.record_action(
                "sextant:policy_root",
                &serde_json::to_vec(&serde_json::json!({
                    "policy_hash": hex::encode(acc.metadata.policy_hash)
                }))?,
                b"{\"decision\":\"allow\"}",
                RecordType::PolicyAssertion,
                now_nanos(),
            )?;

            let program = command.first().ok_or_else(|| {
                SextantError::KeyError("wrap requires a target executable command".to_string())
            })?;
            let args = &command[1..];

            let captured = run_bounded_command(program, args, timeout_secs)?;

            let invoke_args = serde_json::to_vec(&serde_json::json!({
                "program": program,
                "args": args,
            }))?;
            acc.record_action(
                program,
                &invoke_args,
                b"{\"status\":\"dispatched\"}",
                RecordType::ToolInvocation,
                now_nanos(),
            )?;

            // Parse bounded untrusted stdout JSON-RPC observations cleanly tagged as untrusted stdout.
            record_mcp_observations(&mut acc, &captured.stdout)?;

            let stream_payload = build_faraday_stream_payload(
                captured.exit_code,
                &captured.stdout,
                &captured.stderr,
            )?;
            acc.record_action(
                program,
                &invoke_args,
                &stream_payload,
                RecordType::ToolReturn,
                now_nanos(),
            )?;

            let final_node = acc.record_action(
                "sextant:finalize",
                b"{}",
                &serde_json::to_vec(&serde_json::json!({
                    "exit_code": captured.exit_code,
                    "stdout_truncated": captured.stdout_truncated,
                    "stderr_truncated": captured.stderr_truncated,
                }))?,
                RecordType::SessionFinalize,
                now_nanos(),
            )?;

            write_ledger_to_path(&ledger_out, &acc.metadata, acc.entries())?;
            if let Some(db_path) = db_out {
                let mut idx = SqliteProvenanceIndex::open(&db_path)?;
                idx.index_ledger(&acc.metadata, acc.entries())?;
            }

            println!(
                "Wrapped '{}' (exit={}) -> {} nodes",
                program,
                captured.exit_code,
                acc.entries().len()
            );
            println!("Verifying Key: {}", hex::encode(acc.metadata.verifying_key));
            println!(
                "Final Accumulator Hn: {}",
                hex::encode(final_node.accumulated_hash)
            );

            Ok(if captured.exit_code == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(u8::try_from(captured.exit_code.clamp(1, 255)).unwrap_or(1))
            })
        }
        Commands::Record {
            ledger,
            signing_key_file,
            tool_id,
            args,
            ret,
            record_type,
            db_out,
        } => {
            let (metadata, entries) = read_ledger_from_path(&ledger)?;
            let seed_hex = resolve_seed_hex(signing_key_file.as_deref())?;
            let signer = SessionSigner::from_hex(&seed_hex)?;
            let mut acc = AccumulatorState::resume(metadata, entries, signer)?;

            let rtype = RecordType::from_name(&record_type)?;
            let node = acc.record_action(
                &tool_id,
                args.as_bytes(),
                ret.as_bytes(),
                rtype,
                now_nanos(),
            )?;

            let entry = acc
                .entries()
                .last()
                .ok_or(SextantError::NodeNotFound(node.sequence))?;
            append_entry_to_path(&ledger, entry)?;

            if let Some(db_path) = db_out {
                let mut idx = SqliteProvenanceIndex::open(&db_path)?;
                idx.index_ledger(&acc.metadata, acc.entries())?;
            }

            println!("Recorded node #{} ({}): {}", node.sequence, rtype, tool_id);
            println!("NodeHash: {}", hex::encode(node.node_hash));
            println!("AccumulatedHash: {}", hex::encode(node.accumulated_hash));
            Ok(ExitCode::SUCCESS)
        }
        Commands::VerifyPath {
            ledger,
            verifying_key,
            notary_verifying_key,
            policy_file,
            witness,
            allow_in_progress,
            verbose,
        } => {
            if let Some(witness_path) = witness {
                let raw = fs::read_to_string(&witness_path)?;
                let parsed: ProvenanceWitness = serde_json::from_str(&raw)?;
                if let Some(ref expected_vk_hex) = verifying_key {
                    let expected_vk = parse_hex_32(expected_vk_hex)?;
                    if parsed.agent_verifying_key != expected_vk {
                        return Err(SextantError::WitnessVerificationFailed(
                            "verifying key mismatch against --verifying-key".to_string(),
                        ));
                    }
                }
                let expected_notary_vk = notary_verifying_key
                    .as_deref()
                    .map(parse_hex_32)
                    .transpose()?;
                verify_witness_with_notary(&parsed, expected_notary_vk.as_ref())?;
                println!(
                    "Witness VALID: session={} seq={} merkle_root={}",
                    parsed.session_id,
                    parsed.target_sequence,
                    hex::encode(parsed.merkle_root)
                );
                return Ok(ExitCode::SUCCESS);
            }

            let ledger_path = ledger.ok_or_else(|| {
                SextantError::KeyError("verify-path requires --ledger or --witness".to_string())
            })?;
            let (metadata, entries) = read_ledger_from_path(&ledger_path)?;

            if let Some(ref vk_hex) = verifying_key {
                let expected_vk = parse_hex_32(vk_hex)?;
                if metadata.verifying_key != expected_vk {
                    return Err(SextantError::HeaderSignatureInvalid);
                }
            }

            if let Some(ref p_path) = policy_file {
                let p_bytes = fs::read(p_path)?;
                let p_hash = *blake3::hash(&p_bytes).as_bytes();
                if metadata.policy_hash != p_hash {
                    return Err(SextantError::SessionAnchorMismatch);
                }
            }

            let report = if allow_in_progress {
                verify_ledger(&metadata, &entries, true)?
            } else {
                verify_finalized_ledger(&metadata, &entries, true)?
            };
            println!(
                "Anchor Validated: H0={}",
                hex::encode(report.initial_anchor)
            );
            println!(
                "Monotonic Progression: {} node(s), seq 1..={}",
                report.total_nodes, report.final_sequence
            );
            println!(
                "Signature Consistency: VERIFIED ({})",
                hex::encode(metadata.verifying_key)
            );
            println!(
                "Merkle DAG Integrity: {} unclosed fork(s), finalized={}, Hn={}",
                report.unclosed_forks,
                report.finalized,
                hex::encode(report.final_accumulator)
            );

            if verbose {
                for entry in &entries {
                    println!(
                        "  #{:03} [{}] {} -> node={} acc={}",
                        entry.node.sequence,
                        entry.node.record_type,
                        entry.node.tool_id,
                        &hex::encode(entry.node.node_hash)[..16],
                        &hex::encode(entry.node.accumulated_hash)[..16],
                    );
                }
            }

            Ok(ExitCode::SUCCESS)
        }
        Commands::ExportGraph {
            ledger,
            format,
            out,
            witness_seq,
        } => {
            let (metadata, entries) = read_ledger_from_path(&ledger)?;
            verify_ledger(&metadata, &entries, true)?;

            let content = if let Some(seq) = witness_seq {
                let witness = generate_offline_witness(&metadata, &entries, seq)?;
                serde_json::to_string_pretty(&witness)?
            } else {
                match format {
                    ExportFormat::Dot => render_dot(&metadata, &entries),
                    ExportFormat::Svg => render_svg(&metadata, &entries),
                    ExportFormat::Json => serde_json::to_string_pretty(&serde_json::json!({
                        "metadata": metadata,
                        "nodes": entries.iter().map(|e| &e.node).collect::<Vec<&ExecutionNode>>(),
                    }))?,
                }
            };

            if let Some(out_path) = out {
                if let Some(parent) = out_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&out_path, content)?;
                println!("Exported provenance artifact -> {}", out_path.display());
            } else {
                println!("{content}");
            }

            Ok(ExitCode::SUCCESS)
        }
        Commands::Tui { ledger } => {
            run_tui(&ledger)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

struct BoundedCommandOutput {
    exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

fn run_bounded_command(
    program: &str,
    args: &[String],
    timeout_secs: Option<u64>,
) -> SextantResult<BoundedCommandOutput> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let (status, stdout, stdout_truncated, stderr, stderr_truncated) =
        std::thread::scope(|scope| -> SextantResult<_> {
            let out_handle = scope.spawn(move || read_capped_stream(stdout_pipe));
            let err_handle = scope.spawn(move || read_capped_stream(stderr_pipe));

            let status = if let Some(secs) = timeout_secs {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
                loop {
                    if let Some(st) = child.try_wait()? {
                        break st;
                    }
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(SextantError::Timeout(format!(
                            "wrapped command '{program}' exceeded timeout of {secs}s"
                        )));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            } else {
                child.wait()?
            };

            let (out, out_t) = out_handle.join().unwrap_or((Vec::new(), true));
            let (err, err_t) = err_handle.join().unwrap_or((Vec::new(), true));
            Ok((status, out, out_t, err, err_t))
        })?;

    let exit_code = status.code().unwrap_or(1);
    Ok(BoundedCommandOutput {
        exit_code,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

fn read_capped_stream<R: Read>(pipe: Option<R>) -> (Vec<u8>, bool) {
    let Some(mut reader) = pipe else {
        return (Vec::new(), false);
    };
    let mut buf = Vec::new();
    let mut truncated = false;
    let mut chunk = [0u8; 8192];

    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let remaining = MAX_WRAP_CAPTURE_BYTES.saturating_sub(buf.len());
                if remaining > 0 {
                    let take = n.min(remaining);
                    buf.extend_from_slice(&chunk[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }

    (buf, truncated)
}

fn record_mcp_observations(acc: &mut AccumulatorState, stdout: &[u8]) -> SextantResult<()> {
    let text = String::from_utf8_lossy(stdout);
    for line in text.lines().take(MAX_MCP_OBSERVED_LINES) {
        let trimmed = line.trim();
        if !trimmed.starts_with('{') {
            continue;
        }
        if let Ok(val) = crate::canonical::parse_strict_json_value(trimmed.as_bytes())
            && let Some(method) = val.get("method").and_then(|m| m.as_str())
        {
            let raw_name = val
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or(method);
            let safe_name = sanitize_terminal_text(raw_name);
            let params_bytes = serde_json::to_vec(val.get("params").unwrap_or(&val))?;
            acc.record_action(
                &format!("observed:stdout:{safe_name}"),
                &params_bytes,
                b"{\"observed\":\"untrusted_child_stdout\",\"trust\":\"unverified\"}",
                RecordType::ToolInvocation,
                now_nanos(),
            )?;
        }
    }
    Ok(())
}

fn render_dot(metadata: &SessionMetadata, entries: &[LedgerEntry]) -> String {
    let mut out = String::from("digraph sextant_provenance {\n  rankdir=TB;\n");
    let mut hash_to_seq: HashMap<HashDigest, u64> = HashMap::with_capacity(entries.len());
    for entry in entries {
        hash_to_seq.insert(entry.node.node_hash, entry.node.sequence);
    }

    out.push_str(&format!(
        "  n0 [label=\"H0 Anchor\\n{}\", shape=box];\n",
        escape_dot(&metadata.session_id)
    ));
    for entry in entries {
        let n = &entry.node;
        out.push_str(&format!(
            "  n{} [label=\"#{} {}\\n{}\"];\n",
            n.sequence,
            n.sequence,
            escape_dot(&n.tool_id),
            n.record_type
        ));
        let parent_seq = hash_to_seq.get(&n.parent_hash).copied().unwrap_or(0);
        out.push_str(&format!("  n{parent_seq} -> n{};\n", n.sequence));
    }
    out.push_str("}\n");
    out
}

fn render_svg(metadata: &SessionMetadata, entries: &[LedgerEntry]) -> String {
    let height = 90 + (entries.len().max(1) * 76);
    let mut out = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"760\" height=\"{height}\" viewBox=\"0 0 760 {height}\" style=\"background:#080809;font-family:monospace\">\n"
    );
    out.push_str(&format!(
        "  <text x=\"24\" y=\"34\" fill=\"#f3f2f2\" font-size=\"15\" font-weight=\"bold\">SEXTANT CALL GRAPH // {}</text>\n",
        escape_xml(&metadata.session_id)
    ));
    out.push_str(&format!(
        "  <text x=\"24\" y=\"54\" fill=\"#ec3013\" font-size=\"11\">H0: {}</text>\n",
        hex::encode(metadata.initial_anchor)
    ));

    let mut depth_map: HashMap<HashDigest, usize> = HashMap::new();
    for (idx, entry) in entries.iter().enumerate() {
        let n = &entry.node;
        let depth = depth_map.get(&n.parent_hash).copied().unwrap_or(0);
        if n.record_type == RecordType::SubAgentFork {
            depth_map.insert(n.node_hash, depth + 1);
        }
        let x = 24 + (depth * 28);
        let y = 74 + (idx * 72);
        let w = 710usize.saturating_sub(depth * 28);
        let stroke = match n.record_type {
            RecordType::PolicyAssertion => "#38bdf8",
            RecordType::SubAgentFork | RecordType::SubAgentJoin => "#f59e0b",
            RecordType::SessionFinalize => "#22c55e",
            _ => "#ec3013",
        };
        out.push_str(&format!(
            "  <rect x=\"{x}\" y=\"{y}\" width=\"{w}\" height=\"56\" rx=\"8\" fill=\"#121316\" stroke=\"{stroke}\" stroke-width=\"1.5\"/>\n"
        ));
        out.push_str(&format!(
            "  <text x=\"{}\" y=\"{}\" fill=\"#f3f2f2\" font-size=\"12\" font-weight=\"bold\">#{:03} {} [{}]</text>\n",
            x + 14,
            y + 22,
            n.sequence,
            escape_xml(&n.tool_id),
            n.record_type
        ));
        out.push_str(&format!(
            "  <text x=\"{}\" y=\"{}\" fill=\"#9e9a98\" font-size=\"10\">node={} | acc={}</text>\n",
            x + 14,
            y + 42,
            &hex::encode(n.node_hash)[..24],
            &hex::encode(n.accumulated_hash)[..24],
        ));
    }

    out.push_str("</svg>\n");
    out
}

fn escape_dot(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn resolve_seed_hex(key_file: Option<&Path>) -> SextantResult<Zeroizing<String>> {
    if let Some(path) = key_file {
        let raw = Zeroizing::new(fs::read_to_string(path)?);
        return Ok(Zeroizing::new(raw.trim().to_string()));
    }
    if let Ok(env_val) = std::env::var("SEXTANT_SIGNING_KEY")
        && !env_val.trim().is_empty()
    {
        return load_seed_hex(&env_val);
    }
    Err(SextantError::KeyError(
        "record requires --signing-key-file or SEXTANT_SIGNING_KEY environment variable"
            .to_string(),
    ))
}

fn load_seed_hex(arg: &str) -> SextantResult<Zeroizing<String>> {
    let path = Path::new(arg);
    if path.exists() && path.is_file() {
        let raw = Zeroizing::new(fs::read_to_string(path)?);
        return Ok(Zeroizing::new(raw.trim().to_string()));
    }
    Ok(Zeroizing::new(arg.trim().to_string()))
}

fn parse_hex_32(hex_str: &str) -> SextantResult<HashDigest> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|err| SextantError::KeyError(format!("invalid 32-byte hex digest: {err}")))?;
    bytes
        .try_into()
        .map_err(|_| SextantError::KeyError("expected exactly 32 bytes (64 hex chars)".into()))
}

fn write_restricted_secret(path: &Path, data: &[u8]) -> SextantResult<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut f = opts.open(path)?;
    if let Err(err) = enforce_owner_only_acl(path, false) {
        drop(f);
        let _ = fs::remove_file(path);
        return Err(err);
    }
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}
