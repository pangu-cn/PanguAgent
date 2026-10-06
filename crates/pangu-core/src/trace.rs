//! Item 7: a visual trace — a timeline view over the Journal.
//!
//! # A projection, not a second source of truth
//!
//! The Journal is the audit authority: append-only, hash-chained, with stable
//! `event_id` receipts. A trace is **derived** from it and is marked as such
//! (`derived: true`, `authoritative: false`), exactly like `pangu-stream/1`.
//! Deleting a trace loses nothing; it can always be rebuilt from the Journal.
//!
//! That distinction matters because a timeline is the artifact a human reads
//! when deciding whether a run behaved. If a trace could be edited into
//! disagreeing with the Journal, it would be a way to *look* correct without
//! being correct. So this module only reads: it never writes to the Journal,
//! and it never presents a value it did not read from a record.
//!
//! # What a trace shows
//!
//! One row per event, in `seq` order (which is the order they were sealed, not
//! the order they claim). Each row carries:
//!
//! - position and time, so a stall is visible as a gap
//! - kind, turn, and the action fields the event actually has
//! - a **severity** derived from the event kind, so the reader's eye goes to
//!   blockages, breaches and rollbacks before routine turns
//! - the receipt, when the record has one
//!
//! # Spans
//!
//! Events come in pairs (`ToolRequested`/`ToolFinished`, `TurnStarted`/
//! `RunFinished`) but the Journal records points. A trace pairs them into spans
//! so durations are visible, matching on `call_id` where the event carries one
//! and on turn otherwise. An unmatched start or end is reported as an **open**
//! span rather than a guessed duration: a run killed mid-tool must not look like
//! a fast tool.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::events::{Event, EventKind};

/// How prominently a trace row should be shown.
///
/// Derived from the event kind, never from the message text: a model can write
/// the message, so letting text drive presentation would let a run style its own
/// audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Routine progress.
    Normal,
    /// Worth noticing but the boundary held.
    Notice,
    /// The boundary refused or blocked something.
    Blocked,
    /// A limit was hit, or something failed irrecoverably.
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Normal => "normal",
            Severity::Notice => "notice",
            Severity::Blocked => "blocked",
            Severity::Critical => "critical",
        }
    }

    /// Classify an event kind.
    pub fn of(kind: EventKind) -> Self {
        match kind {
            // A refusal is the boundary working, and it is what a reader is
            // usually looking for.
            EventKind::ToolBlocked => Severity::Blocked,
            // Budget exhaustion stops the run; rollback and checkpoint failures
            // mean state may not be what the run believes.
            EventKind::BudgetExhausted
            | EventKind::CheckpointFailed
            | EventKind::RollbackFailed => Severity::Critical,
            // Transitions worth a second look, but the run continued correctly.
            EventKind::ApprovalRequested
            | EventKind::ApprovalResolved
            | EventKind::PolicyDecision
            | EventKind::PhaseChanged
            | EventKind::ProviderSwitched
            | EventKind::RollbackRequested
            | EventKind::RollbackStarted
            | EventKind::RollbackApplied
            | EventKind::RollbackSkippedAlreadyApplied
            | EventKind::FailedPathRecorded
            | EventKind::MemoryProposed
            | EventKind::TaskDelegated => Severity::Notice,
            _ => Severity::Normal,
        }
    }
}

/// One row of the timeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceRow {
    /// Position in the sealed stream.
    pub seq: u64,
    pub at: String,
    pub kind: String,
    pub severity: Severity,
    pub turn: u32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invariant: Option<String>,
    /// The Journal receipt, when the record carries one. Its absence is shown as
    /// absence rather than filled in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
}

impl TraceRow {
    fn from_event(event: &Event) -> Self {
        Self {
            seq: event.seq,
            at: event.at.clone(),
            kind: event.kind.as_str().to_string(),
            severity: Severity::of(event.kind),
            turn: event.turn,
            message: event.message.clone(),
            tool: event.tool.clone(),
            call_id: event.call_id.clone(),
            verdict: event.verdict.clone(),
            risk: event.risk.clone(),
            rule_id: event.rule_id.clone(),
            invariant: event.invariant.clone(),
            event_id: event.event_id.clone(),
        }
    }

    /// A one-line rendering for a terminal.
    pub fn line(&self) -> String {
        let mut text = format!(
            "{:>6}  {:>6}ms  {:<10} t{:<3} {}",
            self.seq,
            self.at.rsplit('.').next().unwrap_or(""),
            self.severity.as_str(),
            self.turn,
            self.kind
        );
        if let Some(tool) = &self.tool {
            text.push_str(&format!(" {tool}"));
        }
        if let Some(verdict) = &self.verdict {
            text.push_str(&format!(" [{verdict}]"));
        }
        if !self.message.is_empty() {
            text.push_str(&format!(" — {}", self.message));
        }
        text
    }
}

/// A paired span between two events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Span {
    pub label: String,
    pub start_seq: u64,
    pub start_at: String,
    pub turn: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Absent when the matching end event was never recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_at: Option<String>,
    /// Recorded duration when the end event carries one.
    ///
    /// Preferred over subtracting timestamps: the event's own measurement is
    /// what the run believed, and recomputing it would silently disagree with
    /// the audit trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// True when the span never closed. A run killed mid-tool shows as open
    /// rather than as an instant.
    pub open: bool,
}

/// The full timeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trace {
    /// Always true: a trace is computed from the Journal.
    pub derived: bool,
    /// Always false: the Journal is the authority, never this.
    pub authoritative: bool,
    pub rows: Vec<TraceRow>,
    pub spans: Vec<Span>,
    /// Counts by severity, for an at-a-glance summary.
    pub by_severity: BTreeMap<String, usize>,
    /// Counts by event kind.
    pub by_kind: BTreeMap<String, usize>,
}

/// Build a trace from sealed events.
///
/// Events are ordered by `seq` rather than by their `at` timestamp: a clock can
/// move or be wrong, and the seal order is what the Journal guarantees. Rows are
/// emitted in the order they were justified, which is what a reader needs.
pub fn trace_of(events: &[Event]) -> Result<Trace> {
    let mut ordered: Vec<&Event> = events.iter().collect();
    ordered.sort_by_key(|event| event.seq);

    let rows: Vec<TraceRow> = ordered
        .iter()
        .map(|event| TraceRow::from_event(event))
        .collect();

    let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for row in &rows {
        *by_severity
            .entry(row.severity.as_str().to_string())
            .or_insert(0) += 1;
        *by_kind.entry(row.kind.clone()).or_insert(0) += 1;
    }

    let spans = pair_spans(&ordered);

    Ok(Trace {
        derived: true,
        authoritative: false,
        rows,
        spans,
        by_severity,
        by_kind,
    })
}

/// Pair start/end events into spans.
///
/// The key is `call_id` when both sides carry one, otherwise the turn number
/// plus the tool name. Using the call id where available is what keeps two
/// concurrent calls in one turn from being merged into a single span.
fn pair_spans(ordered: &[&Event]) -> Vec<Span> {
    let mut spans: Vec<Span> = Vec::new();
    // label -> open span index, keyed so a second start without an end does not
    // overwrite the first (that would hide a lost end event).
    let mut open: BTreeMap<String, Vec<usize>> = BTreeMap::new();

    for event in ordered {
        let (label, is_start) = match event.kind {
            EventKind::ToolRequested => ("tool", true),
            EventKind::ToolStarted => ("tool", true),
            EventKind::ToolFinished => ("tool", false),
            EventKind::TurnStarted => ("turn", true),
            EventKind::RunFinished => ("turn", false),
            _ => continue,
        };
        let key = span_key(event, label);

        if is_start {
            let index = spans.len();
            spans.push(Span {
                label: label.to_string(),
                start_seq: event.seq,
                start_at: event.at.clone(),
                turn: event.turn,
                tool: event.tool.clone(),
                end_seq: None,
                end_at: None,
                duration_ms: None,
                open: true,
            });
            open.entry(key).or_default().push(index);
        } else if let Some(indices) = open.get_mut(&key) {
            // Close the most recent matching start.
            if let Some(index) = indices.pop() {
                let span = &mut spans[index];
                span.end_seq = Some(event.seq);
                span.end_at = Some(event.at.clone());
                span.duration_ms = event.duration_ms;
                span.open = false;
            }
        }
        // An end with no start is not invented into a span: a truncated Journal
        // should show as an unmatched end, not as a zero-length span.
    }

    spans
}

fn span_key(event: &Event, label: &str) -> String {
    match &event.call_id {
        // The call id is unique per call, so it is the right key when present.
        Some(id) => format!("{label}:{id}"),
        None => format!(
            "{label}:t{}:{}",
            event.turn,
            event.tool.as_deref().unwrap_or("")
        ),
    }
}

/// Render a trace as text, for a terminal.
pub fn render_text(trace: &Trace) -> String {
    let mut out = String::new();
    out.push_str("TRACE (derived from the Journal; the Journal is the authority)\n");
    let summary: Vec<String> = trace
        .by_severity
        .iter()
        .map(|(severity, count)| format!("{severity}={count}"))
        .collect();
    out.push_str(&format!(
        "{} event(s): {}\n\n",
        trace.rows.len(),
        summary.join(" ")
    ));

    for row in &trace.rows {
        out.push_str(&row.line());
        out.push('\n');
    }

    if !trace.spans.is_empty() {
        out.push_str("\nSPANS\n");
        for span in &trace.spans {
            let duration = match (span.duration_ms, span.open) {
                (Some(ms), _) => format!("{ms}ms"),
                (None, true) => "OPEN (no end event recorded)".to_string(),
                (None, false) => "no recorded duration".to_string(),
            };
            out.push_str(&format!(
                "  {:<6} seq {:<6} turn {:<3} {:<24} {}\n",
                span.label,
                span.start_seq,
                span.turn,
                span.tool.as_deref().unwrap_or(""),
                duration
            ));
        }
    }
    out
}

/// Render a trace as an SVG timeline.
///
/// Self-contained: no script, no external font, no network. A trace may be
/// shared as evidence, and an artifact that needs a browser extension or a CDN
/// to render is not evidence anyone can check later.
pub fn render_svg(trace: &Trace) -> String {
    const ROW_HEIGHT: usize = 18;
    const LEFT: usize = 90;
    const WIDTH: usize = 1000;
    let height = 40 + trace.rows.len() * ROW_HEIGHT;

    let mut out = String::new();
    out.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{WIDTH}\" height=\"{height}\" \
         viewBox=\"0 0 {WIDTH} {height}\" font-family=\"monospace\" font-size=\"11\">\n"
    ));
    out.push_str("<rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\n");
    out.push_str(&format!(
        "<text x=\"6\" y=\"16\" font-size=\"13\">Pangu trace — {}</text>\n",
        escape(&format!(
            "{} events (derived; not authoritative)",
            trace.rows.len()
        ))
    ));

    for (index, row) in trace.rows.iter().enumerate() {
        let y = 30 + index * ROW_HEIGHT;
        let colour = match row.severity {
            Severity::Normal => "#444444",
            Severity::Notice => "#0b6ea8",
            Severity::Blocked => "#b06a00",
            Severity::Critical => "#b00020",
        };
        let weight = match row.severity {
            Severity::Normal => "normal",
            Severity::Notice => "normal",
            Severity::Blocked => "bold",
            Severity::Critical => "bold",
        };
        // A left stripe makes severity scannable without reading the text.
        out.push_str(&format!(
            "<rect x=\"0\" y=\"{y}\" width=\"4\" height=\"{}\" fill=\"{colour}\"/>\n",
            ROW_HEIGHT - 2
        ));
        out.push_str(&format!(
            "<text x=\"10\" y=\"{}\" fill=\"#888888\">seq {}</text>\n",
            y + 12,
            row.seq
        ));
        out.push_str(&format!(
            "<text x=\"{LEFT}\" y=\"{}\" fill=\"{colour}\" font-weight=\"{weight}\">t{} {}</text>\n",
            y + 12,
            row.turn,
            escape(&format!(
                "{}{}",
                row.kind,
                row.tool
                    .as_ref()
                    .map(|tool| format!(" {tool}"))
                    .unwrap_or_default()
            ))
        ));
        let detail = if row.message.is_empty() {
            row.verdict.clone().unwrap_or_default()
        } else {
            row.message.clone()
        };
        if !detail.is_empty() {
            out.push_str(&format!(
                "<text x=\"420\" y=\"{}\" fill=\"#666666\">{}</text>\n",
                y + 12,
                escape(&truncate(&detail, 70))
            ));
        }
    }

    out.push_str("</svg>\n");
    out
}

/// Markdown, for pasting a trace into a report or an issue.
pub fn render_markdown(trace: &Trace) -> String {
    let mut out = String::new();
    out.push_str("# Pangu trace\n\n");
    out.push_str("Derived from the Journal; the Journal is the authority, not this view.\n\n");
    let summary: Vec<String> = trace
        .by_severity
        .iter()
        .map(|(severity, count)| format!("`{severity}` {count}"))
        .collect();
    out.push_str(&format!(
        "{} events — {}\n\n",
        trace.rows.len(),
        summary.join(" · ")
    ));

    out.push_str("| seq | turn | severity | kind | tool | detail |\n");
    out.push_str("|---|---|---|---|---|---|\n");
    for row in &trace.rows {
        out.push_str(&format!(
            "| {} | {} | {} | `{}` | {} | {} |\n",
            row.seq,
            row.turn,
            row.severity.as_str(),
            row.kind,
            row.tool.as_deref().unwrap_or(""),
            escape_markdown(&truncate(&row.message, 80))
        ));
    }
    out
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn escape_markdown(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let cut: String = text.chars().take(limit).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(seq: u64, turn: u32, kind: EventKind, message: &str) -> Event {
        let mut event = Event::new(kind, turn, message);
        event.seq = seq;
        event
    }

    #[test]
    fn rows_follow_seal_order_not_timestamp_order() {
        // Two events whose timestamps disagree with their seal order. The seal
        // order is what the Journal guarantees.
        let mut first = event(1, 1, EventKind::RunStarted, "started");
        first.at = "2026-01-01T00:00:05Z".into();
        let mut second = event(2, 1, EventKind::ToolRequested, "requested");
        second.at = "2026-01-01T00:00:01Z".into();
        let trace = trace_of(&[second, first]).unwrap();
        assert_eq!(trace.rows[0].seq, 1);
        assert_eq!(trace.rows[1].seq, 2);
    }

    #[test]
    fn a_trace_is_marked_derived_and_not_authoritative() {
        let trace = trace_of(&[event(1, 1, EventKind::RunStarted, "x")]).unwrap();
        assert!(trace.derived);
        assert!(!trace.authoritative);
    }

    #[test]
    fn severity_comes_from_the_kind_not_the_message() {
        // A message that reads like a catastrophe, on a routine event, must not
        // be styled as one: a model can write the message.
        let loud = event(1, 1, EventKind::ModelResponse, "CATASTROPHIC FAILURE!!!");
        let quiet = event(2, 1, EventKind::ToolBlocked, "no");
        let trace = trace_of(&[loud, quiet]).unwrap();
        assert_eq!(trace.rows[0].severity, Severity::Normal);
        assert_eq!(trace.rows[1].severity, Severity::Blocked);
    }

    #[test]
    fn a_blocked_tool_is_blocked_severity() {
        assert_eq!(Severity::of(EventKind::ToolBlocked), Severity::Blocked);
    }

    #[test]
    fn budget_exhaustion_is_critical() {
        assert_eq!(Severity::of(EventKind::BudgetExhausted), Severity::Critical);
    }

    #[test]
    fn a_rollback_failure_is_critical() {
        assert_eq!(Severity::of(EventKind::RollbackFailed), Severity::Critical);
    }

    #[test]
    fn approval_events_are_notice() {
        assert_eq!(Severity::of(EventKind::ApprovalRequested), Severity::Notice);
    }

    #[test]
    fn counts_are_reported_by_severity_and_kind() {
        let trace = trace_of(&[
            event(1, 1, EventKind::ToolBlocked, "a"),
            event(2, 1, EventKind::ToolBlocked, "b"),
            event(3, 1, EventKind::RunFinished, "c"),
        ])
        .unwrap();
        assert_eq!(trace.by_severity.get("blocked"), Some(&2));
        assert_eq!(trace.by_severity.get("normal"), Some(&1));
        assert_eq!(trace.by_kind.get("tool_blocked"), Some(&2));
    }

    #[test]
    fn a_matched_tool_call_becomes_a_closed_span() {
        let mut start = event(1, 1, EventKind::ToolStarted, "started");
        start.tool = Some("read_file".into());
        start.call_id = Some("call_1".into());
        let mut end = event(2, 1, EventKind::ToolFinished, "finished");
        end.tool = Some("read_file".into());
        end.call_id = Some("call_1".into());
        end.duration_ms = Some(42);

        let trace = trace_of(&[start, end]).unwrap();
        assert_eq!(trace.spans.len(), 1);
        let span = &trace.spans[0];
        assert!(!span.open);
        assert_eq!(span.end_seq, Some(2));
        // The event's own measurement is used, not a subtraction.
        assert_eq!(span.duration_ms, Some(42));
    }

    #[test]
    fn an_unmatched_start_is_reported_open_not_as_an_instant() {
        // A run killed mid-tool must not look like a fast tool.
        let mut start = event(1, 1, EventKind::ToolStarted, "started");
        start.tool = Some("slow_tool".into());
        start.call_id = Some("call_1".into());
        let trace = trace_of(&[start]).unwrap();
        assert_eq!(trace.spans.len(), 1);
        assert!(trace.spans[0].open);
        assert_eq!(trace.spans[0].duration_ms, None);
        let rendered = render_text(&trace);
        assert!(rendered.contains("OPEN"), "{rendered}");
    }

    #[test]
    fn an_unmatched_end_does_not_invent_a_span() {
        let mut end = event(1, 1, EventKind::ToolFinished, "finished");
        end.call_id = Some("call_1".into());
        let trace = trace_of(&[end]).unwrap();
        assert!(
            trace.spans.is_empty(),
            "a truncated journal must not fabricate"
        );
    }

    #[test]
    fn two_calls_in_one_turn_are_not_merged() {
        // Without the call id as the key these would pair into one span.
        let mut a_start = event(1, 1, EventKind::ToolStarted, "a");
        a_start.call_id = Some("call_a".into());
        a_start.tool = Some("read_file".into());
        let mut b_start = event(2, 1, EventKind::ToolStarted, "b");
        b_start.call_id = Some("call_b".into());
        b_start.tool = Some("read_file".into());
        let mut a_end = event(3, 1, EventKind::ToolFinished, "a done");
        a_end.call_id = Some("call_a".into());
        let mut b_end = event(4, 1, EventKind::ToolFinished, "b done");
        b_end.call_id = Some("call_b".into());

        let trace = trace_of(&[a_start, b_start, a_end, b_end]).unwrap();
        assert_eq!(trace.spans.len(), 2);
        assert!(trace.spans.iter().all(|span| !span.open));
        // Each closed its own start.
        let a = trace.spans.iter().find(|s| s.start_seq == 1).unwrap();
        assert_eq!(a.end_seq, Some(3));
        let b = trace.spans.iter().find(|s| s.start_seq == 2).unwrap();
        assert_eq!(b.end_seq, Some(4));
    }

    #[test]
    fn a_span_without_recorded_duration_says_so() {
        let mut start = event(1, 1, EventKind::ToolStarted, "s");
        start.call_id = Some("c".into());
        let mut end = event(2, 1, EventKind::ToolFinished, "e");
        end.call_id = Some("c".into());
        // No duration_ms recorded.
        let trace = trace_of(&[start, end]).unwrap();
        assert_eq!(trace.spans[0].duration_ms, None);
        let rendered = render_text(&trace);
        assert!(rendered.contains("no recorded duration"), "{rendered}");
    }

    #[test]
    fn a_receipt_is_carried_through_when_present() {
        let mut with_receipt = event(1, 1, EventKind::RunStarted, "x");
        with_receipt.event_id = Some("evt_abc".into());
        let trace = trace_of(&[with_receipt]).unwrap();
        assert_eq!(trace.rows[0].event_id.as_deref(), Some("evt_abc"));
    }

    #[test]
    fn a_missing_receipt_is_shown_as_absent_not_filled_in() {
        let trace = trace_of(&[event(1, 1, EventKind::RunStarted, "x")]).unwrap();
        assert!(trace.rows[0].event_id.is_none());
    }

    #[test]
    fn an_empty_journal_yields_an_empty_trace() {
        let trace = trace_of(&[]).unwrap();
        assert!(trace.rows.is_empty());
        assert!(trace.spans.is_empty());
    }

    #[test]
    fn svg_output_escapes_markup() {
        let nasty = event(1, 1, EventKind::Note, "<script>alert(1)</script>");
        let trace = trace_of(&[nasty]).unwrap();
        let svg = render_svg(&trace);
        assert!(
            !svg.contains("<script>"),
            "a message must not become markup in a shareable artifact"
        );
        assert!(svg.contains("&lt;script&gt;"), "{svg}");
    }

    #[test]
    fn svg_is_self_contained() {
        let trace = trace_of(&[event(1, 1, EventKind::RunStarted, "x")]).unwrap();
        let svg = render_svg(&trace);
        assert!(svg.starts_with("<svg"), "{svg}");
        // No script and no fetched resource: evidence must render offline. The
        // `xmlns` namespace URI is exempt because it is an identifier, not a
        // retrieval — every SVG carries it and nothing is fetched for it.
        assert!(!svg.contains("<script"), "{svg}");
        assert!(!svg.contains("<image"), "{svg}");
        let without_namespace = svg.replace("http://www.w3.org/2000/svg", "");
        assert!(
            !without_namespace.contains("http://") && !without_namespace.contains("https://"),
            "no external resource may be referenced: {svg}"
        );
        assert!(!svg.contains("@import"), "{svg}");
    }

    /// The trace names events exactly as the Journal does, so a derived view can
    /// always be cross-checked against the record it summarises.
    #[test]
    fn event_kind_names_match_the_wire_format() {
        for kind in [
            EventKind::RunStarted,
            EventKind::ToolBlocked,
            EventKind::MemoryProposed,
            EventKind::TaskDelegated,
            EventKind::RollbackSkippedAlreadyApplied,
            EventKind::ContextAssembled,
        ] {
            let wire = serde_json::to_value(kind).unwrap();
            let wire = wire.as_str().expect("kinds serialise as strings");
            assert_eq!(
                kind.as_str(),
                wire,
                "the derived name must match the wire name for {kind:?}"
            );
        }
    }

    #[test]
    fn markdown_escapes_pipes_in_messages() {
        let nasty = event(1, 1, EventKind::Note, "a | b | c");
        let trace = trace_of(&[nasty]).unwrap();
        let md = render_markdown(&trace);
        // An unescaped pipe would break the table into extra columns.
        assert!(md.contains("a \\| b"), "{md}");
    }

    #[test]
    fn markdown_states_the_authority() {
        let trace = trace_of(&[event(1, 1, EventKind::RunStarted, "x")]).unwrap();
        let md = render_markdown(&trace);
        assert!(md.contains("Journal is the authority"), "{md}");
    }

    #[test]
    fn long_messages_are_truncated_visibly() {
        let long = event(1, 1, EventKind::Note, &"x".repeat(500));
        let trace = trace_of(&[long]).unwrap();
        let svg = render_svg(&trace);
        assert!(svg.contains('…'), "truncation must be visible");
    }
}
