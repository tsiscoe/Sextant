//! 3-pane `ratatui` v0.30 renderer for Sextant (`Call Graph Tree`, `Node Payload Inspector`, `Cryptographic Witness`).

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};

use crate::canonical::sanitize_terminal_text;
use crate::crypto::{ExecutionNode, LedgerEntry};
use crate::merkle::{HashDigest, ZERO_DIGEST};

use super::{ActivePane, NodeIntegrity, SextantTuiApp};

/// Render the synchronized 3-pane Sextant provenance console.
pub fn render(frame: &mut Frame, app: &SextantTuiApp) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let status_chip_style = if app.ledger_verified {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::White)
            .bg(Color::Red)
            .add_modifier(Modifier::BOLD)
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " SEXTANT v0.1.0 ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" // "),
        Span::styled(
            sanitize_terminal_text(&app.metadata.session_id),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!(" {} ", sanitize_terminal_text(&app.verification_summary)),
            status_chip_style,
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, vertical[0]);

    // Section 7.1: Left 35% Width = Call Graph Tree; Right 65% Width = Payload (60% H) + Witness (40% H).
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(vertical[1]);

    let right_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(columns[1]);

    render_tree_pane(frame, app, columns[0]);
    render_payload_pane(frame, app, right_rows[0]);
    render_witness_pane(frame, app, right_rows[1]);

    let footer = Paragraph::new(sanitize_terminal_text(&app.status_message))
        .style(Style::default().fg(Color::Gray));
    frame.render_widget(footer, vertical[2]);
}

fn render_tree_pane(frame: &mut Frame, app: &SextantTuiApp, area: ratatui::layout::Rect) {
    let border_style = pane_border_style(app.active_pane == ActivePane::CallGraphTree);

    let items: Vec<ListItem> = if app.visible_rows.is_empty() {
        vec![ListItem::new("No execution nodes recorded.")]
    } else {
        app.visible_rows
            .iter()
            .filter_map(|row| {
                let entry = app.entries.get(row.entry_index)?;
                let indent = "  ".repeat(row.depth);
                let marker = if row.is_fork {
                    if row.is_collapsed { "[+] " } else { "[-] " }
                } else {
                    "  "
                };

                let (badge, color) = match &row.integrity {
                    NodeIntegrity::Verified => ("[OK]", Color::Green),
                    NodeIntegrity::PolicyGate => ("[POL]", Color::Cyan),
                    NodeIntegrity::ActiveFork => ("[RUN]", Color::Yellow),
                    NodeIntegrity::Tampered(_) => ("[ERR]", Color::Red),
                };

                let line = Line::from(vec![
                    Span::styled(
                        format!("{badge} "),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!(
                        "{indent}{marker}#{:03} {} ({})",
                        entry.node.sequence,
                        sanitize_terminal_text(&entry.node.tool_id),
                        entry.node.record_type
                    )),
                ]);
                Some(ListItem::new(line))
            })
            .collect()
    };

    let mut list_state = ListState::default();
    if !app.visible_rows.is_empty() {
        list_state.select(Some(app.selected_row));
    }

    let tree_list = List::new(items)
        .block(
            Block::default()
                .title(" [01] CALL GRAPH TREE ")
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    frame.render_stateful_widget(tree_list, area, &mut list_state);
}

fn render_payload_pane(frame: &mut Frame, app: &SextantTuiApp, area: ratatui::layout::Rect) {
    let border_style = pane_border_style(app.active_pane == ActivePane::PayloadInspector);
    let body = if let Some(entry) = app.selected_entry() {
        format_payload_detail(entry, &app.ledger_label)
    } else {
        "Select a node in Pane 1 to inspect canonical payloads.".to_string()
    };

    let inspector = Paragraph::new(body)
        .scroll((app.payload_scroll, 0))
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(" [02] NODE PAYLOAD INSPECTOR ")
                .borders(Borders::ALL)
                .border_style(border_style),
        );
    frame.render_widget(inspector, area);
}

fn render_witness_pane(frame: &mut Frame, app: &SextantTuiApp, area: ratatui::layout::Rect) {
    let border_style = pane_border_style(app.active_pane == ActivePane::CryptographicWitness);
    let body = if let Some(entry) = app.selected_entry() {
        format_witness_detail(
            &entry.node,
            &app.selected_integrity(),
            app.selected_merkle_depth(),
            &app.metadata.verifying_key,
        )
    } else {
        "Select a node in Pane 1 to inspect cryptographic witness state.".to_string()
    };

    let witness = Paragraph::new(body).wrap(Wrap { trim: false }).block(
        Block::default()
            .title(" [03] CRYPTOGRAPHIC WITNESS ")
            .borders(Borders::ALL)
            .border_style(border_style),
    );
    frame.render_widget(witness, area);
}

fn format_payload_detail(entry: &LedgerEntry, ledger_label: &str) -> String {
    let arg_text = pretty_payload(&entry.arg_payload);
    let ret_text = pretty_payload(&entry.ret_payload);
    format!(
        "Ledger: {}\nSequence: #{} | Type: {} | Timestamp (ns): {}\nTool ID: {}\n\nArguments (Canonical):\n{}\n\nReturn Payload (Canonical):\n{}",
        sanitize_terminal_text(ledger_label),
        entry.node.sequence,
        entry.node.record_type,
        entry.node.timestamp_ns,
        sanitize_terminal_text(&entry.node.tool_id),
        arg_text,
        ret_text,
    )
}

fn format_witness_detail(
    node: &ExecutionNode,
    integrity: &NodeIntegrity,
    merkle_depth: usize,
    verifying_key: &[u8; 32],
) -> String {
    let status_line = match integrity {
        NodeIntegrity::Verified => "Ed25519 + BLAKE3 Chain: VALID".to_string(),
        NodeIntegrity::ActiveFork => "Ed25519 + BLAKE3 Chain: VALID (Active Fork)".to_string(),
        NodeIntegrity::PolicyGate => "Ed25519 + BLAKE3 Chain: VALID (Policy Gate)".to_string(),
        NodeIntegrity::Tampered(reason) => format!("VERIFICATION FAILED: {reason}"),
    };

    let subtree = if node.subtree_merkle_root == ZERO_DIGEST {
        "<leaf / none>".to_string()
    } else {
        hex_digest(&node.subtree_merkle_root)
    };

    format!(
        "Status: {}\nVerifying Key: {}\nNodeHash_n: {}\nAccumulated H_n: {}\nParentHash: {}\nPrevAccumulator: {}\nSubtree Merkle Root: {}\nMerkle Audit Path Depth: O(log N) = {} step(s)\nSignature (Ed25519): {}...",
        sanitize_terminal_text(&status_line),
        hex::encode(verifying_key),
        hex_digest(&node.node_hash),
        hex_digest(&node.accumulated_hash),
        hex_digest(&node.parent_hash),
        hex_digest(&node.prev_accumulator),
        subtree,
        merkle_depth,
        hex::encode(&node.signature[..16]),
    )
}

fn pretty_payload(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "<empty>".to_string();
    }
    let rendered = match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(val) => serde_json::to_string_pretty(&val)
            .unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned()),
        Err(_) => String::from_utf8_lossy(bytes).into_owned(),
    };
    sanitize_terminal_text(&rendered)
}

fn hex_digest(digest: &HashDigest) -> String {
    hex::encode(digest)
}

fn pane_border_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}
