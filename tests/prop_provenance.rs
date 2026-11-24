#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use proptest::prelude::*;
use ratatui::{Terminal, backend::TestBackend};
use sextant_core::canonical::canonicalize_payload_bytes;
use sextant_core::cli::{Cli, ExportFormat, execute_cli};
use sextant_core::crypto::{
    AccumulatorState, RecordType, SessionSigner, generate_offline_witness, verify_ledger,
};
use sextant_core::fleet::{
    SignetCapabilityReceipt, build_faraday_stream_payload, export_redacted_bundle,
    ingest_signet_receipt, verify_redacted_bundle,
};
use sextant_core::index::SqliteProvenanceIndex;
use sextant_core::merkle::verify_witness;
use sextant_core::tui::{SextantTuiApp, panes};
use sextant_core::wire::{
    append_entry_to_path, read_ledger_from_path, verify_ledger_stream, write_ledger_to_path,
};
use sextant_core::{SextantError, cli};
use tempfile::tempdir;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn prop_tamper_evident_accumulator(
        tool_names in prop::collection::vec("[a-z_]{3,12}", 1..20),
        tamper_index in any::<usize>(),
        tamper_byte in 1u8..=u8::MAX,
    ) {
        let policy = b"POLICY_ROOT_V1";
        let mut acc = AccumulatorState::new("prop-session".to_string(), policy);

        for (i, name) in tool_names.iter().enumerate() {
            acc.record_action(
                name,
                b"{\"arg\":\"test\"}",
                b"{\"ret\":\"ok\"}",
                RecordType::ToolInvocation,
                1000 + i as u64,
            ).expect("action recording must succeed");
        }
        acc.record_action(
            "sextant:finalize",
            b"{}",
            b"{\"done\":true}",
            RecordType::SessionFinalize,
            9999,
        ).expect("finalize must succeed");

        prop_assert!(verify_ledger(&acc.metadata, acc.entries(), true).is_ok());

        let mut tampered_entries = acc.entries().to_vec();
        let target_idx = tamper_index % tampered_entries.len();
        tampered_entries[target_idx].node.node_hash[0] ^= tamper_byte;

        let err = verify_ledger(&acc.metadata, &tampered_entries, true)
            .expect_err("mutated node_hash must fail ledger verification");
        let is_node_mismatch = matches!(err, SextantError::NodeHashMismatch { .. });
        prop_assert!(is_node_mismatch, "expected NodeHashMismatch, got {err:?}");

        // Also mutate raw payload bytes without touching digests to verify payload binding.
        let mut payload_tampered = acc.entries().to_vec();
        payload_tampered[target_idx].arg_payload.push(b' ');
        prop_assert!(verify_ledger(&acc.metadata, &payload_tampered, true).is_err());

        // Also mutate Ed25519 signature bytes to verify INV-03 non-repudiation.
        let mut sig_tampered = acc.entries().to_vec();
        sig_tampered[target_idx].node.signature[0] ^= tamper_byte;
        prop_assert!(verify_ledger(&acc.metadata, &sig_tampered, true).is_err());
    }

    #[test]
    fn prop_canonical_json_key_order_invariance(
        a in -10_000i64..10_000,
        b in "[a-zA-Z0-9_]{1,16}",
        c in any::<bool>(),
    ) {
        let doc1 = format!(r#"{{ "z": {a}, "m": "{b}", "a": {{ "flag": {c}, "x": 1 }} }}"#);
        let doc2 = format!(r#"{{"a":{{"x":1,"flag":{c}}},"m":"{b}","z":{a}}}"#);
        prop_assert_eq!(
            canonicalize_payload_bytes(doc1.as_bytes()),
            canonicalize_payload_bytes(doc2.as_bytes())
        );

        let seed = [0x42u8; 32];
        let mut acc1 = AccumulatorState::with_signer(
            "canon".to_string(),
            b"pol",
            SessionSigner::from_bytes(seed),
        );
        let mut acc2 = AccumulatorState::with_signer(
            "canon".to_string(),
            b"pol",
            SessionSigner::from_bytes(seed),
        );

        let n1 = acc1.record_action("tool", doc1.as_bytes(), b"{}", RecordType::ToolInvocation, 42)
            .expect("record 1");
        let n2 = acc2.record_action("tool", doc2.as_bytes(), b"{}", RecordType::ToolInvocation, 42)
            .expect("record 2");

        prop_assert_eq!(n1.arguments_digest, n2.arguments_digest);
        prop_assert_eq!(n1.node_hash, n2.node_hash);
        prop_assert_eq!(n1.accumulated_hash, n2.accumulated_hash);
    }
}

#[test]
fn nested_fork_join_parent_binding_and_orphan_rejection() {
    let mut acc = AccumulatorState::new("nested-tree".to_string(), b"strict-policy");
    let root_step = acc
        .record_action(
            "planner",
            b"{\"plan\":1}",
            b"{\"ok\":true}",
            RecordType::ToolInvocation,
            10,
        )
        .expect("root step");
    assert_eq!(root_step.parent_hash, acc.metadata.initial_anchor);

    let fork_outer = acc
        .record_action(
            "subagent:researcher",
            b"{\"scope\":\"deps\"}",
            b"{\"forked\":true}",
            RecordType::SubAgentFork,
            20,
        )
        .expect("outer fork");
    assert_eq!(fork_outer.parent_hash, root_step.node_hash);

    let child_a = acc
        .record_action(
            "mcp_grep",
            b"{\"q\":\"blake3\"}",
            b"{\"hits\":4}",
            RecordType::ToolInvocation,
            30,
        )
        .expect("child a");
    let child_b = acc
        .record_action(
            "mcp_read",
            b"{\"file\":\"lib.rs\"}",
            b"{\"lines\":80}",
            RecordType::ToolInvocation,
            40,
        )
        .expect("child b");
    // INV-02: Both siblings under the fork must point to fork_outer.node_hash!
    assert_eq!(child_a.parent_hash, fork_outer.node_hash);
    assert_eq!(child_b.parent_hash, fork_outer.node_hash);

    let join_outer = acc
        .record_action(
            "subagent:researcher",
            b"{}",
            b"{\"merged\":true}",
            RecordType::SubAgentJoin,
            50,
        )
        .expect("outer join");
    assert_eq!(join_outer.parent_hash, fork_outer.node_hash);
    assert_ne!(join_outer.subtree_merkle_root, [0u8; 32]);

    // Unbalanced join must fail.
    let unbalanced = acc.record_action("bad", b"{}", b"{}", RecordType::SubAgentJoin, 55);
    assert!(matches!(
        unbalanced,
        Err(SextantError::UnbalancedCallStack(_))
    ));

    acc.record_action(
        "sextant:finalize",
        b"{}",
        b"{}",
        RecordType::SessionFinalize,
        60,
    )
    .expect("finalize");

    assert!(verify_ledger(&acc.metadata, acc.entries(), true).is_ok());

    // Orphan splicing check: replace child_b.parent_hash with root_step.node_hash -> ParentMismatch!
    let mut spliced = acc.entries().to_vec();
    spliced[3].node.parent_hash = root_step.node_hash;
    let err = verify_ledger(&acc.metadata, &spliced, true).expect_err("orphan splice must fail");
    assert!(matches!(err, SextantError::ParentMismatch { sequence: 4 }));
}

#[test]
fn live_and_offline_zero_knowledge_witness_verification() {
    let mut acc = AccumulatorState::new("witness-session".to_string(), b"pol-v1");
    for seq in 1..=8u64 {
        acc.record_action(
            &format!("tool_{seq}"),
            format!(r#"{{"secret":"s{seq}"}}"#).as_bytes(),
            format!(r#"{{"out":"r{seq}"}}"#).as_bytes(),
            RecordType::ToolInvocation,
            seq * 100,
        )
        .expect("record step");
    }

    // Live direct checkpoint witness before finalize.
    let live_witness = acc.generate_witness(5).expect("live witness");
    assert!(live_witness.audit_path.len() <= 3);
    assert!(verify_witness(&live_witness).is_ok());

    // Finalize session, clone metadata/entries, and drop ephemeral signer (INV-05).
    acc.record_action(
        "sextant:finalize",
        b"{}",
        b"{}",
        RecordType::SessionFinalize,
        900,
    )
    .expect("finalize");
    let metadata = acc.metadata.clone();
    let entries = acc.entries().to_vec();
    drop(acc);

    // Offline witness extraction without holding private key.
    let offline_witness =
        generate_offline_witness(&metadata, &entries, 3).expect("offline witness");
    assert!(verify_witness(&offline_witness).is_ok());

    let mut bad_witness = offline_witness.clone();
    bad_witness.target_node_hash[0] ^= 0xff;
    assert!(verify_witness(&bad_witness).is_err());
}

#[test]
fn binary_wire_append_sqlite_index_and_fleet_adapters() {
    let dir = tempdir().expect("tempdir");
    let ledger_path = dir.path().join("trace.bin");
    let db_path = dir.path().join("index.db");

    let signer = SessionSigner::from_bytes([0x19u8; 32]);
    let seed_hex = signer.export_seed_hex();

    let mut acc = AccumulatorState::with_signer("fleet-session".to_string(), b"policy-doc", signer);
    ingest_signet_receipt(
        &mut acc,
        &SignetCapabilityReceipt {
            tool_id: "mcp_sqlite_query".to_string(),
            capability_token_digest: "aa11bb22".to_string(),
            attenuation_depth: 2,
            merkle_receipt_root: "cc33dd44".to_string(),
            decision: "ALLOW".to_string(),
        },
        100,
    )
    .expect("signet receipt");

    let faraday_ret = build_faraday_stream_payload(0, b"ok \x1b[31mred\x1b[0m", b"").expect("ret");
    acc.record_action(
        "faraday:cage",
        b"{\"cmd\":\"ls\"}",
        &faraday_ret,
        RecordType::ToolReturn,
        200,
    )
    .expect("faraday step");

    write_ledger_to_path(&ledger_path, &acc.metadata, acc.entries()).expect("write ledger");

    // Resume via CLI `record` + append to disk + finalize.
    let resumed_signer = SessionSigner::from_hex(&seed_hex).expect("hex signer");
    let (loaded_meta, loaded_entries) = read_ledger_from_path(&ledger_path).expect("read ledger");
    let mut resumed =
        AccumulatorState::resume(loaded_meta, loaded_entries, resumed_signer).expect("resume");
    resumed
        .record_action(
            "sextant:finalize",
            b"{}",
            b"{}",
            RecordType::SessionFinalize,
            300,
        )
        .expect("finalize");
    let final_entry = resumed.entries().last().expect("final entry");
    append_entry_to_path(&ledger_path, final_entry).expect("append entry");

    let file = std::fs::File::open(&ledger_path).expect("open ledger");
    let mut buf = std::io::BufReader::new(file);
    let report = verify_ledger_stream(&mut buf).expect("stream verify");
    assert_eq!(report.total_nodes, 3);

    // Index in SQLite WAL and verify queries.
    let (meta, entries) = read_ledger_from_path(&ledger_path).expect("reload");
    let mut idx = SqliteProvenanceIndex::open(&db_path).expect("open db");
    idx.index_ledger(&meta, &entries).expect("index ledger");
    let (db_meta, db_entries) = idx.load_session("fleet-session").expect("load session");
    assert!(verify_ledger(&db_meta, &db_entries, true).is_ok());
    assert_eq!(
        idx.query_by_tool("fleet-session", "faraday:cage")
            .expect("query tool")
            .len(),
        1
    );

    // Selective redaction verification.
    let mut redact = BTreeSet::new();
    redact.insert(2);
    let bundle = export_redacted_bundle(&meta, &entries, &redact);
    assert!(bundle.entries[1].redacted);
    assert!(bundle.entries[1].arg_payload_raw.is_none());
    assert!(verify_redacted_bundle(&bundle).is_ok());

    // CLI export-graph SVG test.
    let svg_path = dir.path().join("graph.svg");
    let exit = execute_cli(Cli {
        command: cli::Commands::ExportGraph {
            ledger: ledger_path,
            format: ExportFormat::Svg,
            out: Some(svg_path.clone()),
            witness_seq: None,
        },
    })
    .expect("export svg");
    assert_eq!(exit, std::process::ExitCode::SUCCESS);
    let svg = std::fs::read_to_string(svg_path).expect("read svg");
    assert!(svg.contains("<svg"));
    assert!(svg.contains("faraday:cage"));
}

#[test]
fn tui_test_backend_navigation_fold_witness_and_cwe150() {
    let dir = tempdir().expect("tempdir");
    let ledger_path = dir.path().join("tui_trace.bin");

    let mut acc = AccumulatorState::new("tui\x1b[31m_sess\x1b[0m".to_string(), b"policy");
    acc.record_action(
        "fork\u{202E}_agent",
        b"{\"x\":1}",
        b"{}",
        RecordType::SubAgentFork,
        10,
    )
    .expect("fork");
    acc.record_action(
        "nested_tool\x1b]0;pwn\x07",
        b"{\"secret\":\"\x1b[32mhi\x1b[0m\"}",
        b"{\"ok\":true}",
        RecordType::ToolInvocation,
        20,
    )
    .expect("child");
    acc.record_action("fork_agent", b"{}", b"{}", RecordType::SubAgentJoin, 30)
        .expect("join");
    acc.record_action(
        "sextant:finalize",
        b"{}",
        b"{}",
        RecordType::SessionFinalize,
        40,
    )
    .expect("finalize");

    write_ledger_to_path(&ledger_path, &acc.metadata, acc.entries()).expect("write tui ledger");

    let mut app = SextantTuiApp::from_path(&ledger_path).expect("load tui app");
    assert!(app.ledger_verified);
    assert_eq!(app.visible_rows.len(), 4);

    // Fold the SubAgentFork at row 0 -> hides child + join (visible rows drop from 4 to 2).
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.visible_rows.len(), 2);

    // Unfold again -> restores 4 rows.
    app.handle_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert_eq!(app.visible_rows.len(), 4);

    // Navigate down to nested child and export witness via 'v'.
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
    assert_eq!(app.selected_entry().expect("selected").node.sequence, 2);
    app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
    let expected_witness = ledger_path.with_extension("seq2.witness.json");
    assert!(expected_witness.exists());

    // Render onto headless TestBackend and verify CWE-150 sanitization stripped ESC and bidi chars.
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|frame| panes::render(frame, &app))
        .expect("draw frame");

    let mut rendered = String::new();
    let buf = terminal.backend().buffer();
    for cell in buf.content() {
        rendered.push_str(cell.symbol());
    }
    assert!(!rendered.contains('\u{001b}'));
    assert!(!rendered.contains('\u{202E}'));
    assert!(rendered.contains("CALL GRAPH TREE"));
    assert!(rendered.contains("NODE PAYLOAD INSPECTOR"));
    assert!(rendered.contains("CRYPTOGRAPHIC WITNESS"));

    // Pressing 'v' again must not silently overwrite the first witness file (SEC-08).
    app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
    assert!(ledger_path.with_extension("seq2.1.witness.json").exists());
}

#[test]
fn sec01_to_sec08_adversarial_hardening_gates() {
    use sextant_core::canonical::{canonicalize_strict_json, sanitize_terminal_text};
    use sextant_core::crypto::{MAX_CALL_STACK_DEPTH, verify_finalized_ledger};
    use sextant_core::wire::read_ledger_from_reader;

    // SEC-01: Duplicate JSON object keys rejected across all nesting levels.
    assert!(matches!(
        canonicalize_strict_json(br#"{"a":1,"b":{"k":1,"k":2}}"#),
        Err(SextantError::CanonicalJsonRequired(_))
    ));
    let mut acc = AccumulatorState::new("sec-suite".to_string(), b"policy");
    assert!(matches!(
        acc.record_action(
            "t",
            br#"{"x":1,"x":2}"#,
            b"{}",
            RecordType::ToolInvocation,
            100,
        ),
        Err(SextantError::CanonicalJsonRequired(_))
    ));

    // SEC-02: Timestamp regression, max stack depth, and unfinalized ledger rejection.
    acc.record_action("step1", b"{}", b"{}", RecordType::ToolInvocation, 200)
        .expect("step1");
    assert!(matches!(
        acc.record_action("step2", b"{}", b"{}", RecordType::ToolInvocation, 199),
        Err(SextantError::TimestampRegression { .. })
    ));
    assert!(matches!(
        verify_finalized_ledger(&acc.metadata, acc.entries(), true),
        Err(SextantError::UnfinalizedLedger { .. })
    ));

    let mut deep_acc = AccumulatorState::new("deep".to_string(), b"p");
    for d in 0..MAX_CALL_STACK_DEPTH {
        deep_acc
            .record_action(
                &format!("fork_{d}"),
                b"{}",
                b"{}",
                RecordType::SubAgentFork,
                (d + 1) as u64,
            )
            .expect("within depth limit");
    }
    assert!(matches!(
        deep_acc.record_action("overflow", b"{}", b"{}", RecordType::SubAgentFork, 999),
        Err(SextantError::CallStackDepthExceeded { .. })
    ));

    // SEC-03: Witness positional leaf_index & total_leaves forgery rejected.
    let mut w_acc = AccumulatorState::new("sec03".to_string(), b"p");
    for i in 1..=3u64 {
        w_acc
            .record_action(
                &format!("n{i}"),
                b"{}",
                b"{}",
                RecordType::ToolInvocation,
                i,
            )
            .expect("node");
    }
    let mut witness = w_acc.generate_witness(2).expect("witness");
    witness.leaf_index = 0;
    assert!(verify_witness(&witness).is_err());

    // SEC-04: Trailing partial wire bytes rejected on stream decode.
    let mut wire_buf = Vec::new();
    sextant_core::wire::write_ledger_to_writer(&mut wire_buf, &w_acc.metadata, w_acc.entries())
        .expect("write wire");
    wire_buf.extend_from_slice(&[0x53, 0x45]); // partial magic tail
    let mut cursor = std::io::Cursor::new(wire_buf);
    assert!(read_ledger_from_reader(&mut cursor).is_err());

    // SEC-05: SQLite index rejects forged/conflicting session_id overwrite.
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("sec05.db");
    let mut idx = SqliteProvenanceIndex::open(&db_path).expect("open db");
    idx.index_ledger(&w_acc.metadata, w_acc.entries())
        .expect("initial index");
    let conflict_acc = AccumulatorState::new("sec03".to_string(), b"other-policy");
    assert!(matches!(
        idx.index_ledger(&conflict_acc.metadata, conflict_acc.entries()),
        Err(SextantError::IndexError(_))
    ));

    // SEC-06: CLI init --key-out enforces owner-only ACL cleanly without panic.
    let policy_path = dir.path().join("policy.json");
    let cli_ledger = dir.path().join("cli.bin");
    let cli_key = dir.path().join("session.key");
    std::fs::write(&policy_path, b"{\"strict\":true}").expect("policy write");
    let exit = execute_cli(Cli {
        command: cli::Commands::Init {
            session_id: "sec06-cli".to_string(),
            policy_file: policy_path,
            ledger_out: cli_ledger,
            key_out: Some(cli_key.clone()),
            db_out: None,
        },
    })
    .expect("cli init");
    assert_eq!(exit, std::process::ExitCode::SUCCESS);
    assert!(cli_key.exists());

    // SEC-07: Unredacted ANSI payloads verify cleanly against raw arguments_digest.
    let mut ansi_acc = AccumulatorState::new("sec07".to_string(), b"p");
    ansi_acc
        .record_action(
            "ansi_tool",
            b"raw \x1b[31mred\x1b[0m payload",
            b"{\"ok\":true}",
            RecordType::ToolInvocation,
            10,
        )
        .expect("record ansi");
    ansi_acc
        .record_action("keep", b"{}", b"{}", RecordType::ToolInvocation, 20)
        .expect("keep");
    let mut redact = BTreeSet::new();
    redact.insert(2);
    let ansi_bundle = export_redacted_bundle(&ansi_acc.metadata, ansi_acc.entries(), &redact);
    assert!(verify_redacted_bundle(&ansi_bundle).is_ok());

    // SEC-08: 8-bit C1 CSI sequence stripped completely.
    assert_eq!(sanitize_terminal_text("ok\u{009b}31mbad"), "okbad");
}

#[test]
fn residual01_to_residual07_hardening_gates() {
    use sextant_core::canonical::{
        decode_leb128_u64, hash_payload_bytes, parse_strict_json_value, sanitize_terminal_text,
    };
    use sextant_core::crypto::verify_finalized_ledger;
    use sextant_core::merkle::WitnessAnchor;
    use sextant_core::wire::read_ledger_from_reader;

    // RESIDUAL-01: FinalizedNode binds session_id & policy_hash, and target_sequence == leaf_index + 1 even at leaf 0.
    let mut acc = AccumulatorState::new("res01-session".to_string(), b"policy-res01");
    acc.record_action("step1", b"{}", b"{}", RecordType::ToolInvocation, 10)
        .expect("step1");
    acc.record_action("step2", b"{}", b"{}", RecordType::ToolInvocation, 20)
        .expect("step2");
    acc.record_action(
        "sextant:finalize",
        b"{}",
        b"{}",
        RecordType::SessionFinalize,
        30,
    )
    .expect("finalize");

    let mut w_seq1 = generate_offline_witness(&acc.metadata, acc.entries(), 1).expect("witness 1");
    assert_eq!(w_seq1.leaf_index, 0);
    assert!(verify_witness(&w_seq1).is_ok());
    w_seq1.target_sequence = 2; // Forged sequence against leaf_index 0
    assert!(matches!(
        verify_witness(&w_seq1),
        Err(SextantError::WitnessVerificationFailed(_))
    ));

    let mut w_seq2 = generate_offline_witness(&acc.metadata, acc.entries(), 2).expect("witness 2");
    assert!(verify_witness(&w_seq2).is_ok());
    let mut relabeled = w_seq2.clone();
    relabeled.session_id = "stolen-session".to_string();
    assert!(verify_witness(&relabeled).is_err());

    if let WitnessAnchor::FinalizedNode { policy_hash, .. } = &mut w_seq2.anchor {
        policy_hash[0] ^= 0xff;
    }
    assert!(verify_witness(&w_seq2).is_err());

    // RESIDUAL-02: SessionFinalize seals the accumulator permanently (direct and via resume).
    assert!(matches!(
        acc.record_action("post", b"{}", b"{}", RecordType::ToolInvocation, 40),
        Err(SextantError::PostFinalizeAppend { sequence: 4 })
    ));
    let seed_hex = acc.signer().export_seed_hex();
    let mut resumed_final = AccumulatorState::resume(
        acc.metadata.clone(),
        acc.entries().to_vec(),
        SessionSigner::from_hex(&seed_hex).expect("signer"),
    )
    .expect("resume finalized");
    assert!(matches!(
        resumed_final.record_action("post2", b"{}", b"{}", RecordType::ToolInvocation, 50),
        Err(SextantError::PostFinalizeAppend { sequence: 4 })
    ));

    // RESIDUAL-03 & RESIDUAL-07: --key-out create_new, --signing-key-file, default finalized VerifyPath, and SQLite equivocation.
    let dir = tempdir().expect("tempdir");
    let policy_path = dir.path().join("policy.json");
    let ledger_path = dir.path().join("res.bin");
    let key_path = dir.path().join("res.key");
    let db_path = dir.path().join("res.db");
    std::fs::write(&policy_path, b"{\"strict\":true}").expect("policy write");

    execute_cli(Cli {
        command: cli::Commands::Init {
            session_id: "res03-cli".to_string(),
            policy_file: policy_path.clone(),
            ledger_out: ledger_path.clone(),
            key_out: Some(key_path.clone()),
            db_out: Some(db_path.clone()),
        },
    })
    .expect("init");

    // Re-running init on an existing --key-out refuses overwrite (create_new).
    assert!(
        execute_cli(Cli {
            command: cli::Commands::Init {
                session_id: "res03-cli-2".to_string(),
                policy_file: policy_path.clone(),
                ledger_out: dir.path().join("other.bin"),
                key_out: Some(key_path.clone()),
                db_out: None,
            },
        })
        .is_err()
    );

    // Append using --signing-key-file.
    execute_cli(Cli {
        command: cli::Commands::Record {
            ledger: ledger_path.clone(),
            signing_key_file: Some(key_path.clone()),
            tool_id: "read_file".to_string(),
            args: "{\"path\":\"a.txt\"}".to_string(),
            ret: "{\"ok\":true}".to_string(),
            record_type: "invoke".to_string(),
            db_out: Some(db_path.clone()),
        },
    })
    .expect("record via --signing-key-file");

    // VerifyPath rejects unfinalized ledger by default, permits with --allow-in-progress.
    assert!(matches!(
        execute_cli(Cli {
            command: cli::Commands::VerifyPath {
                ledger: Some(ledger_path.clone()),
                verifying_key: None,
                notary_verifying_key: None,
                policy_file: Some(policy_path.clone()),
                witness: None,
                allow_in_progress: false,
                verbose: false,
            },
        }),
        Err(SextantError::UnfinalizedLedger { .. })
    ));
    execute_cli(Cli {
        command: cli::Commands::VerifyPath {
            ledger: Some(ledger_path.clone()),
            verifying_key: None,
            notary_verifying_key: None,
            policy_file: Some(policy_path.clone()),
            witness: None,
            allow_in_progress: true,
            verbose: false,
        },
    })
    .expect("verify-path --allow-in-progress");

    // SQLite equivocation rejection: fork two histories at sequence=2 under the same session/key.
    let eq_dir = tempdir().expect("eq dir");
    let mut eq_a = AccumulatorState::new("equiv-sess".to_string(), b"eq-policy");
    eq_a.record_action("init", b"{}", b"{}", RecordType::SessionInit, 1)
        .expect("init");
    let eq_seed = eq_a.signer().export_seed_hex();
    let eq_prefix_meta = eq_a.metadata.clone();
    let eq_prefix_entries = eq_a.entries().to_vec();
    eq_a.record_action("branch_legit", b"{}", b"{}", RecordType::ToolInvocation, 2)
        .expect("branch a");

    let mut eq_b = AccumulatorState::resume(
        eq_prefix_meta,
        eq_prefix_entries,
        SessionSigner::from_hex(&eq_seed).expect("eq signer"),
    )
    .expect("resume eq");
    eq_b.record_action("branch_evil", b"{}", b"{}", RecordType::ToolInvocation, 2)
        .expect("branch b");

    let mut eq_idx = SqliteProvenanceIndex::open(&eq_dir.path().join("eq.db")).expect("open eq");
    eq_idx
        .index_ledger(&eq_a.metadata, eq_a.entries())
        .expect("index branch A");
    assert!(matches!(
        eq_idx.index_ledger(&eq_b.metadata, eq_b.entries()),
        Err(SextantError::IndexError(_))
    ));
    assert!(eq_idx.load_session("equiv-sess").is_ok());

    // RESIDUAL-04: Overlong LEB128 [0x80, 0x00] rejected; duplicate JSON keys rejected.
    assert!(matches!(
        decode_leb128_u64(&[0x80, 0x00]),
        Err(SextantError::InvalidLeb128)
    ));
    assert!(matches!(
        parse_strict_json_value(br#"{"method":"tools/call","method":"spoof"}"#),
        Err(SextantError::CanonicalJsonRequired(_))
    ));

    // RESIDUAL-05: Chunked wire decode rejects truncated declared 2 MiB frame without OOM prealloc + hash_payload_bytes domain separation.
    let canon_json =
        sextant_core::canonical::canonicalize_payload_bytes_checked(br#"{"b":2,"a":1}"#)
            .expect("canonical json");
    assert_eq!(canon_json, br#"{"a":1,"b":2}"#);
    assert_eq!(
        hash_payload_bytes(&canon_json),
        *blake3::hash(b"\x01{\"a\":1,\"b\":2}").as_bytes()
    );
    assert_eq!(
        hash_payload_bytes(b"raw-non-json"),
        *blake3::hash(b"\x00raw-non-json").as_bytes()
    );
    let mut trunc_wire = Vec::new();
    sextant_core::wire::write_ledger_to_writer(&mut trunc_wire, &eq_a.metadata, eq_a.entries())
        .expect("write eq wire");
    // Craft a synthetic truncated entry header declaring a 2 MiB arg payload followed by only 8 bytes.
    trunc_wire.extend_from_slice(b"SEXT");
    trunc_wire.extend_from_slice(&1u16.to_le_bytes()); // version
    trunc_wire.extend_from_slice(&2u16.to_le_bytes()); // ToolInvocation
    trunc_wire.extend_from_slice(&99u64.to_le_bytes()); // seq
    trunc_wire.extend_from_slice(&99u64.to_le_bytes()); // ts
    trunc_wire.extend_from_slice(&[0u8; 32 * 5]); // parent..acc hashes
    trunc_wire.extend_from_slice(&1u16.to_le_bytes()); // tool_len = 1
    trunc_wire.push(b'x');
    trunc_wire.extend_from_slice(&(2u32 * 1024 * 1024).to_le_bytes()); // arg_len = 2 MiB
    trunc_wire.extend_from_slice(b"12345678"); // truncated payload!
    let mut trunc_cursor = std::io::Cursor::new(trunc_wire);
    assert!(read_ledger_from_reader(&mut trunc_cursor).is_err());

    // RESIDUAL-06: 7-bit DCS / SOS / PM / APC sequences stripped cleanly.
    assert_eq!(
        sanitize_terminal_text(
            "ok\u{001b}P1;2|bad\u{001b}\\-\u{001b}_apc\u{001b}\\-\u{001b}^pm\u{0007}-\u{001b}Xsos\u{001b}\\end"
        ),
        "ok---end"
    );

    // RESIDUAL-07: Wrap --timeout-secs terminates long-running child promptly.
    let timeout_ledger = dir.path().join("timeout.bin");
    #[cfg(windows)]
    let timeout_cmd = vec![
        "powershell".to_string(),
        "-NoProfile".to_string(),
        "-Command".to_string(),
        "Start-Sleep -Seconds 10".to_string(),
    ];
    #[cfg(not(windows))]
    let timeout_cmd = vec![
        "sh".to_string(),
        "-c".to_string(),
        "exec sleep 10".to_string(),
    ];

    let started = std::time::Instant::now();
    let timeout_res = execute_cli(Cli {
        command: cli::Commands::Wrap {
            session_id: "res07-timeout".to_string(),
            policy_file: policy_path,
            ledger_out: timeout_ledger,
            db_out: None,
            timeout_secs: Some(1),
            command: timeout_cmd,
        },
    });
    assert!(matches!(timeout_res, Err(SextantError::Timeout(_))));
    assert!(started.elapsed() < std::time::Duration::from_secs(6));
    assert!(verify_finalized_ledger(&eq_a.metadata, eq_a.entries(), true).is_err());
}

#[test]
fn new01_external_notary_and_residual07_cli_argv_gates() {
    use clap::Parser;
    use sextant_core::merkle::{
        WitnessAnchor, compute_external_notary_digest, verify_witness_with_notary,
    };

    let mut acc = AccumulatorState::new("new01-session".to_string(), b"policy-new01");
    acc.record_action("step1", b"{}", b"{}", RecordType::ToolInvocation, 10)
        .expect("step1");
    acc.record_action("step2", b"{}", b"{}", RecordType::ToolInvocation, 20)
        .expect("step2");

    let base_witness = acc.generate_witness(1).expect("live witness");
    let notary_signer = SessionSigner::generate();
    let notary_vk = notary_signer.verifying_key().to_bytes();
    let chain_head = *blake3::hash(b"external-notary-chain-head-v1").as_bytes();
    let notary_seq = 42u64;
    let notary_ts = 1_795_382_400u64;

    let make_notary_witness = |notary_id: &str, signer: &SessionSigner, head: [u8; 32]| {
        let mut w = base_witness.clone();
        let signer_vk = signer.verifying_key().to_bytes();
        let digest = compute_external_notary_digest(
            &w.session_id,
            &w.agent_verifying_key,
            &w.accumulator_root,
            &w.merkle_root,
            w.total_leaves,
            notary_id,
            &head,
            notary_seq,
            notary_ts,
        );
        w.anchor = WitnessAnchor::ExternalNotary {
            notary_id: notary_id.to_string(),
            notary_verifying_key: signer_vk,
            external_chain_head: head,
            notary_sequence: notary_seq,
            timestamp_utc: notary_ts,
            notary_signature: signer.sign(&digest),
        };
        w
    };

    // 1. Valid pinned ExternalNotary witness succeeds.
    let valid_w = make_notary_witness("colmena-notary-01", &notary_signer, chain_head);
    assert!(verify_witness_with_notary(&valid_w, Some(&notary_vk)).is_ok());

    // 2. Calling verify_witness() without a pinned notary trust root fails closed.
    assert!(matches!(
        verify_witness(&valid_w),
        Err(SextantError::WitnessVerificationFailed(_))
    ));

    // 3. Wrong pinned notary verifying key fails closed.
    let other_notary_vk = SessionSigner::generate().verifying_key().to_bytes();
    assert!(matches!(
        verify_witness_with_notary(&valid_w, Some(&other_notary_vk)),
        Err(SextantError::WitnessVerificationFailed(_))
    ));

    // 4. Self-notarization (notary_verifying_key == agent_verifying_key, even if pinned) fails closed.
    let agent_signer = SessionSigner::from_bytes(acc.signer().signing_key_bytes);
    let self_notary_w = make_notary_witness("self-notary", &agent_signer, chain_head);
    assert!(matches!(
        verify_witness_with_notary(&self_notary_w, Some(&valid_w.agent_verifying_key)),
        Err(SextantError::WitnessVerificationFailed(_))
    ));

    // 5. Corrupting agent checkpoint root_signature fails closed.
    let mut bad_root_sig = valid_w.clone();
    bad_root_sig.root_signature[0] ^= 0x01;
    assert!(matches!(
        verify_witness_with_notary(&bad_root_sig, Some(&notary_vk)),
        Err(SextantError::WitnessVerificationFailed(_))
    ));

    // 6. Corrupting session_id, accumulator_root, or total_leaves fails closed.
    let mut bad_session = valid_w.clone();
    bad_session.session_id = "forged-session".to_string();
    assert!(matches!(
        verify_witness_with_notary(&bad_session, Some(&notary_vk)),
        Err(SextantError::WitnessVerificationFailed(_))
    ));
    let mut bad_acc = valid_w.clone();
    bad_acc.accumulator_root[0] ^= 0xff;
    assert!(matches!(
        verify_witness_with_notary(&bad_acc, Some(&notary_vk)),
        Err(SextantError::WitnessVerificationFailed(_))
    ));
    let mut bad_leaves = valid_w.clone();
    bad_leaves.total_leaves += 1;
    assert!(matches!(
        verify_witness_with_notary(&bad_leaves, Some(&notary_vk)),
        Err(SextantError::WitnessVerificationFailed(_))
    ));

    // 7. Corrupting notary_signature or external_chain_head fails closed.
    let mut bad_notary_sig = valid_w.clone();
    if let WitnessAnchor::ExternalNotary {
        notary_signature, ..
    } = &mut bad_notary_sig.anchor
    {
        notary_signature[0] ^= 0x55;
    }
    assert!(matches!(
        verify_witness_with_notary(&bad_notary_sig, Some(&notary_vk)),
        Err(SextantError::WitnessVerificationFailed(_))
    ));
    let mut bad_head = valid_w.clone();
    if let WitnessAnchor::ExternalNotary {
        external_chain_head,
        ..
    } = &mut bad_head.anchor
    {
        external_chain_head[0] ^= 0xAA;
    }
    assert!(matches!(
        verify_witness_with_notary(&bad_head, Some(&notary_vk)),
        Err(SextantError::WitnessVerificationFailed(_))
    ));

    // 8. CLI VerifyPath rejects ExternalNotary without --notary-verifying-key and accepts with it.
    let dir = tempdir().expect("tempdir");
    let witness_path = dir.path().join("external_notary.witness.json");
    std::fs::write(
        &witness_path,
        serde_json::to_string_pretty(&valid_w).expect("serialize witness"),
    )
    .expect("write witness json");
    assert!(matches!(
        execute_cli(Cli {
            command: cli::Commands::VerifyPath {
                ledger: None,
                verifying_key: None,
                notary_verifying_key: None,
                policy_file: None,
                witness: Some(witness_path.clone()),
                allow_in_progress: false,
                verbose: false,
            },
        }),
        Err(SextantError::WitnessVerificationFailed(_))
    ));
    execute_cli(Cli {
        command: cli::Commands::VerifyPath {
            ledger: None,
            verifying_key: Some(hex::encode(valid_w.agent_verifying_key)),
            notary_verifying_key: Some(hex::encode(notary_vk)),
            policy_file: None,
            witness: Some(witness_path),
            allow_in_progress: false,
            verbose: false,
        },
    })
    .expect("cli verify-path with pinned --notary-verifying-key");

    // 9. RESIDUAL-07: Deprecated raw --signing-key CLI flag is rejected at argv parse time.
    assert!(
        Cli::try_parse_from([
            "sextant",
            "record",
            "--ledger",
            "a.bin",
            "--signing-key",
            "deadbeef",
            "--tool-id",
            "t",
        ])
        .is_err()
    );
}
