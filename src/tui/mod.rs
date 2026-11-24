//! Ratatui v0.30+ 3-pane interactive call-graph provenance inspector (`sextant tui`).

pub mod panes;

use std::collections::{BTreeSet, HashMap};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};

use crate::SextantResult;
use crate::canonical::sanitize_terminal_text;
use crate::crypto::{
    LedgerEntry, RecordType, SessionMetadata, generate_offline_witness, verify_entries_incremental,
};
use crate::merkle::{HashDigest, ZERO_DIGEST};
use crate::wire::read_ledger_from_path;

/// Active pane focus inside the 3-pane Sextant TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePane {
    CallGraphTree,
    PayloadInspector,
    CryptographicWitness,
}

/// Visual verification state computed per execution node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeIntegrity {
    Verified,
    ActiveFork,
    PolicyGate,
    Tampered(String),
}

/// Flattened display row derived from the hierarchical call-graph tree.
#[derive(Debug, Clone)]
pub struct TreeRow {
    pub entry_index: usize,
    pub sequence: u64,
    pub depth: usize,
    pub is_fork: bool,
    pub is_collapsed: bool,
    pub integrity: NodeIntegrity,
}

/// Interactive TEA model driving the 3-pane provenance inspector.
pub struct SextantTuiApp {
    pub ledger_label: String,
    pub ledger_path: Option<PathBuf>,
    pub metadata: SessionMetadata,
    pub entries: Vec<LedgerEntry>,
    pub integrity_by_seq: HashMap<u64, NodeIntegrity>,
    pub ledger_verified: bool,
    pub verification_summary: String,
    pub collapsed_forks: BTreeSet<u64>,
    pub visible_rows: Vec<TreeRow>,
    pub selected_row: usize,
    pub payload_scroll: u16,
    pub active_pane: ActivePane,
    pub status_message: String,
    pub running: bool,
}

impl SextantTuiApp {
    /// Load and inspect a binary ledger file from disk.
    pub fn from_path(path: &Path) -> SextantResult<Self> {
        let (metadata, entries) = read_ledger_from_path(path)?;
        Ok(Self::from_ledger(
            path.display().to_string(),
            Some(path.to_path_buf()),
            metadata,
            entries,
        ))
    }

    /// Construct a TUI state snapshot directly from in-memory session metadata and entries.
    pub fn from_ledger(
        ledger_label: impl Into<String>,
        ledger_path: Option<PathBuf>,
        metadata: SessionMetadata,
        entries: Vec<LedgerEntry>,
    ) -> Self {
        let (ledger_verified, verification_summary, integrity_by_seq) =
            evaluate_node_integrity(&metadata, &entries);

        let mut app = Self {
            ledger_label: sanitize_terminal_text(&ledger_label.into()),
            ledger_path,
            metadata,
            entries,
            integrity_by_seq,
            ledger_verified,
            verification_summary,
            collapsed_forks: BTreeSet::new(),
            visible_rows: Vec::new(),
            selected_row: 0,
            payload_scroll: 0,
            active_pane: ActivePane::CallGraphTree,
            status_message:
                "Tab: pane | j/k: navigate | Enter/Space: fold | v: export witness | q: quit"
                    .to_string(),
            running: true,
        };
        app.rebuild_visible_rows();
        app
    }

    /// Recompute visible call-graph tree rows respecting collapsed `SubAgentFork` frames.
    pub fn rebuild_visible_rows(&mut self) {
        let mut rows = Vec::new();
        let mut fork_stack: Vec<u64> = Vec::new();
        let mut hidden_until_fork_seq: Option<u64> = None;

        for (idx, entry) in self.entries.iter().enumerate() {
            let seq = entry.node.sequence;
            let rtype = entry.node.record_type;

            if rtype == RecordType::SubAgentJoin {
                let closed_fork = fork_stack.pop();
                if hidden_until_fork_seq.is_some() && closed_fork == hidden_until_fork_seq {
                    hidden_until_fork_seq = None;
                    continue;
                }
            }

            if hidden_until_fork_seq.is_some() {
                if rtype == RecordType::SubAgentFork {
                    fork_stack.push(seq);
                }
                continue;
            }

            let depth = fork_stack.len();
            let is_fork = rtype == RecordType::SubAgentFork;
            let is_collapsed = is_fork && self.collapsed_forks.contains(&seq);
            let integrity = self
                .integrity_by_seq
                .get(&seq)
                .cloned()
                .unwrap_or(NodeIntegrity::Verified);

            rows.push(TreeRow {
                entry_index: idx,
                sequence: seq,
                depth,
                is_fork,
                is_collapsed,
                integrity,
            });

            if is_fork {
                fork_stack.push(seq);
                if is_collapsed {
                    hidden_until_fork_seq = Some(seq);
                }
            }
        }

        self.visible_rows = rows;
        if self.visible_rows.is_empty() {
            self.selected_row = 0;
        } else if self.selected_row >= self.visible_rows.len() {
            self.selected_row = self.visible_rows.len() - 1;
        }
    }

    /// Return the currently selected `LedgerEntry`, if any.
    pub fn selected_entry(&self) -> Option<&LedgerEntry> {
        let row = self.visible_rows.get(self.selected_row)?;
        self.entries.get(row.entry_index)
    }

    /// Return the `NodeIntegrity` status for the currently selected node.
    pub fn selected_integrity(&self) -> NodeIntegrity {
        self.visible_rows
            .get(self.selected_row)
            .map_or(NodeIntegrity::Verified, |r| r.integrity.clone())
    }

    /// Compute tree depth of the selected row for witness context display.
    pub fn selected_merkle_depth(&self) -> usize {
        let count = self.entries.len();
        if count <= 1 {
            0
        } else {
            (count.next_power_of_two()).trailing_zeros() as usize
        }
    }

    /// Handle a single `KeyEvent` (callers must filter `KeyEventKind::Press`).
    pub fn handle_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.running = false;
            }
            KeyCode::Tab => {
                self.active_pane = match self.active_pane {
                    ActivePane::CallGraphTree => ActivePane::PayloadInspector,
                    ActivePane::PayloadInspector => ActivePane::CryptographicWitness,
                    ActivePane::CryptographicWitness => ActivePane::CallGraphTree,
                };
            }
            KeyCode::BackTab => {
                self.active_pane = match self.active_pane {
                    ActivePane::CallGraphTree => ActivePane::CryptographicWitness,
                    ActivePane::PayloadInspector => ActivePane::CallGraphTree,
                    ActivePane::CryptographicWitness => ActivePane::PayloadInspector,
                };
            }
            KeyCode::Up | KeyCode::Char('k') => match self.active_pane {
                ActivePane::PayloadInspector => {
                    self.payload_scroll = self.payload_scroll.saturating_sub(1);
                }
                _ => {
                    self.selected_row = self.selected_row.saturating_sub(1);
                    self.payload_scroll = 0;
                }
            },
            KeyCode::Down | KeyCode::Char('j') => match self.active_pane {
                ActivePane::PayloadInspector => {
                    self.payload_scroll = self.payload_scroll.saturating_add(1);
                }
                _ => {
                    if !self.visible_rows.is_empty() {
                        self.selected_row =
                            (self.selected_row + 1).min(self.visible_rows.len() - 1);
                        self.payload_scroll = 0;
                    }
                }
            },
            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(row) = self.visible_rows.get(self.selected_row)
                    && row.is_fork
                {
                    let seq = row.sequence;
                    if !self.collapsed_forks.remove(&seq) {
                        self.collapsed_forks.insert(seq);
                    }
                    self.rebuild_visible_rows();
                }
            }
            KeyCode::Char('v') => {
                self.export_selected_witness();
            }
            _ => {}
        }
    }

    fn export_selected_witness(&mut self) {
        let Some(entry) = self.selected_entry() else {
            self.status_message = "No node selected for witness export.".to_string();
            return;
        };
        let target_seq = entry.node.sequence;
        let witness = match generate_offline_witness(&self.metadata, &self.entries, target_seq) {
            Ok(w) => w,
            Err(err) => {
                self.status_message =
                    sanitize_terminal_text(&format!("Witness unavailable: {err}"));
                return;
            }
        };

        let out_path = self.unique_witness_output_path(target_seq);
        match serde_json::to_string_pretty(&witness) {
            Ok(json) => {
                let write_res = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&out_path)
                    .and_then(|mut f| {
                        f.write_all(json.as_bytes())?;
                        f.sync_all()
                    });
                match write_res {
                    Ok(()) => {
                        self.status_message = sanitize_terminal_text(&format!(
                            "Exported witness for seq #{target_seq} -> {}",
                            out_path.display()
                        ));
                    }
                    Err(err) => {
                        self.status_message =
                            sanitize_terminal_text(&format!("Failed writing witness: {err}"));
                    }
                }
            }
            Err(err) => {
                self.status_message =
                    sanitize_terminal_text(&format!("Witness JSON encode error: {err}"));
            }
        }
    }

    fn unique_witness_output_path(&self, seq: u64) -> PathBuf {
        let base = match &self.ledger_path {
            Some(path) => path.with_extension(format!("seq{seq}.witness.json")),
            None => PathBuf::from(format!("sextant-seq{seq}.witness.json")),
        };
        if !base.exists() {
            return base;
        }
        for attempt in 1..=99u32 {
            let candidate = match &self.ledger_path {
                Some(path) => path.with_extension(format!("seq{seq}.{attempt}.witness.json")),
                None => PathBuf::from(format!("sextant-seq{seq}.{attempt}.witness.json")),
            };
            if !candidate.exists() {
                return candidate;
            }
        }
        base
    }
}

/// Evaluate per-node cryptographic integrity in a single `O(N)` pass (`SEC-08`).
fn evaluate_node_integrity(
    metadata: &SessionMetadata,
    entries: &[LedgerEntry],
) -> (bool, String, HashMap<u64, NodeIntegrity>) {
    let mut map = HashMap::with_capacity(entries.len());
    let incremental = verify_entries_incremental(metadata, entries, true);

    match incremental.overall {
        Ok(report) => {
            for entry in entries {
                let n = &entry.node;
                match n.record_type {
                    RecordType::SubAgentFork => {
                        map.insert(n.sequence, NodeIntegrity::ActiveFork);
                    }
                    RecordType::SubAgentJoin => {
                        map.insert(n.sequence, NodeIntegrity::Verified);
                        if let Some(fork_entry) =
                            entries.iter().find(|e| e.node.node_hash == n.parent_hash)
                        {
                            map.insert(fork_entry.node.sequence, NodeIntegrity::Verified);
                        }
                    }
                    RecordType::PolicyAssertion => {
                        map.insert(n.sequence, NodeIntegrity::PolicyGate);
                    }
                    _ => {
                        map.insert(n.sequence, NodeIntegrity::Verified);
                    }
                }
            }
            let summary = format!(
                "VERIFIED ({} nodes, root={})",
                report.total_nodes,
                short_hex(&report.final_accumulator)
            );
            (true, summary, map)
        }
        Err(err) => {
            let overall_reason = sanitize_terminal_text(&err.to_string());
            for (seq, outcome) in incremental.per_sequence {
                match outcome {
                    Ok(RecordType::PolicyAssertion) => {
                        map.insert(seq, NodeIntegrity::PolicyGate);
                    }
                    Ok(RecordType::SubAgentFork) => {
                        map.insert(seq, NodeIntegrity::ActiveFork);
                    }
                    Ok(_) => {
                        map.insert(seq, NodeIntegrity::Verified);
                    }
                    Err(msg) => {
                        map.insert(seq, NodeIntegrity::Tampered(sanitize_terminal_text(&msg)));
                    }
                }
            }
            (false, format!("FAILED: {overall_reason}"), map)
        }
    }
}

fn short_hex(digest: &HashDigest) -> String {
    if *digest == ZERO_DIGEST {
        return "0000..0000".to_string();
    }
    let full = hex::encode(digest);
    format!("{}..{}", &full[..8], &full[full.len() - 8..])
}

/// Launch the interactive 3-pane Ratatui v0.30 terminal UI for a binary ledger file.
pub fn run_tui(ledger_path: &Path) -> SextantResult<()> {
    let mut app = SextantTuiApp::from_path(ledger_path)?;
    let mut terminal = ratatui::init();

    let loop_result = (|| -> SextantResult<()> {
        while app.running {
            terminal.draw(|frame| panes::render(frame, &app))?;
            if event::poll(Duration::from_millis(120))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                app.handle_key(key);
            }
        }
        Ok(())
    })();

    ratatui::restore();
    loop_result
}
