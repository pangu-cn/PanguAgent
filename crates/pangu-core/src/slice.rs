//! Slice map over the full conversation (ADR-0005 §3.5/§3.8).
//!
//! The slice file is a **mapping table**: it projects the full context (which
//! always stays on disk) into spans an assembler can pick without loading
//! everything. A slice is a *span* of one or more messages — one turn, one
//! tool burst, one refused path — and `derived_from` lists the message
//! indices it aggregates.
//!
//! Binding is identical to the summary file (§3.5, 2026-10-03 confirmed):
//! `prefix_digest` + `message_count` over the conversation prefix. Appending
//! a message never invalidates an existing closed slice.
//!
//! Pairing (§3.8) is enforced by construction and verified: every
//! `tool_calls[i]` and its `Tool{call_id}` results must live in the *same*
//! span, otherwise an assembler would produce a wire-illegal history or an
//! orphaned result.

use serde::{Deserialize, Serialize};

use crate::{Error, Message, Result};

pub const SLICE_SCHEMA_VERSION: u32 = 1;

/// What a span *is*, from the conversation's point of view. Coarse filtering
/// (§3.6) keys on this; it is derived, never stored separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SliceKind {
    /// A complete user/assistant/tool exchange.
    Turn,
    /// A tool result came back as an error — a refused or failed path.
    Refusal,
    /// Two or more tool results in one span — a tool-call burst.
    ToolBurst,
    /// Everything that is not a turn body: the system prompt today.
    Phase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SliceEntry {
    /// Deterministic: `<kind>-<start_message>-<end_message>`.
    pub slice_id: String,
    /// First and last message covered (inclusive).
    pub start_message: usize,
    pub end_message: usize,
    /// Line range inside the first/last message's content (0-based).
    pub start_line: usize,
    pub end_line: usize,
    /// hex_sha256 of the covered bytes (see `span_bytes`).
    pub range_digest: String,
    pub kind: SliceKind,
    /// Deterministic summary of the span, from the per-message extraction.
    pub summary: String,
    /// The `message_index` values this span aggregates.
    pub derived_from: Vec<usize>,
    /// Whether the span's bytes are used verbatim. Always `true` today; the
    /// summary-only mode (A6-3) flips it, it is not a model decision.
    pub verbatim: bool,
    /// Reserved for model-written slices (§3.3 reading (b), deferred to B3).
    /// Invariant today: always `false`.
    #[serde(default)]
    pub unverified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationSlices {
    pub schema_version: u32,
    pub prefix_digest: String,
    pub message_count: usize,
    pub entries: Vec<SliceEntry>,
}

/// The bytes a span covers: for each message in the span, its content lines
/// (`start_line..` on the first message, `..=end_line` on the last), joined
/// with `\n`. Deterministic, so it can be re-derived for verification.
fn span_bytes(messages: &[Message], entry: &SliceEntry) -> Result<Vec<u8>> {
    if entry.start_message > entry.end_message || entry.end_message >= messages.len() {
        return Err(Error::Config(format!(
            "slice {} covers messages {}..={} but {} exist",
            entry.slice_id,
            entry.start_message,
            entry.end_message,
            messages.len()
        )));
    }
    let mut lines = Vec::new();
    for (index, message) in messages[entry.start_message..=entry.end_message]
        .iter()
        .enumerate()
    {
        let content_lines: Vec<&str> = crate::conversation::message_content(message)
            .split('\n')
            .collect();
        let start = if index == 0 { entry.start_line } else { 0 };
        let end = if index == entry.end_message - entry.start_message {
            entry.end_line
        } else {
            content_lines.len().saturating_sub(1)
        };
        if start > end || end >= content_lines.len() {
            return Err(Error::Config(format!(
                "slice {} claims lines {start}..={end} of a {}-line message",
                entry.slice_id,
                content_lines.len()
            )));
        }
        lines.extend_from_slice(&content_lines[start..=end]);
    }
    Ok(lines.join("\n").into_bytes())
}

fn span_range_digest(messages: &[Message], entry: &SliceEntry) -> Result<String> {
    Ok(crate::hex_sha256(&String::from_utf8_lossy(&span_bytes(
        messages, entry,
    )?)))
}

fn slice_kind(messages: &[Message], start: usize, end: usize) -> SliceKind {
    let span = &messages[start..=end];
    if span
        .iter()
        .all(|message| matches!(message, Message::System { .. }))
    {
        return SliceKind::Phase;
    }
    if span
        .iter()
        .any(|message| matches!(message, Message::Tool { is_error: true, .. }))
    {
        return SliceKind::Refusal;
    }
    let tool_count = span
        .iter()
        .filter(|message| matches!(message, Message::Tool { .. }))
        .count();
    if tool_count >= 2 {
        return SliceKind::ToolBurst;
    }
    SliceKind::Turn
}

fn slice_summary(messages: &[Message], start: usize, end: usize) -> Result<String> {
    let mut parts = Vec::new();
    for (index, message) in messages[start..=end].iter().enumerate() {
        parts.push(crate::summarize_message(message, start + index)?.summary);
    }
    Ok(crate::one_line(&parts.join(" | "), 400))
}

fn kind_name(kind: SliceKind) -> &'static str {
    match kind {
        SliceKind::Turn => "turn",
        SliceKind::Refusal => "refusal",
        SliceKind::ToolBurst => "tool_burst",
        SliceKind::Phase => "phase",
    }
}

fn build_entry(messages: &[Message], start: usize, end: usize) -> Result<SliceEntry> {
    let kind = slice_kind(messages, start, end);
    let last_lines = crate::conversation::message_content(&messages[end])
        .split('\n')
        .count();
    let mut entry = SliceEntry {
        slice_id: format!("{}-{}-{}", kind_name(kind), start, end),
        start_message: start,
        end_message: end,
        start_line: 0,
        end_line: last_lines.saturating_sub(1),
        range_digest: String::new(),
        kind,
        summary: slice_summary(messages, start, end)?,
        derived_from: (start..=end).collect(),
        verbatim: true,
        unverified: false,
    };
    entry.range_digest = span_range_digest(messages, &entry)?;
    Ok(entry)
}

/// Deterministic slicing: system prompt, then one span per turn (a user
/// message up to the next user/system message), with a leading span for any
/// non-turn prefix. No model involvement — laya never enters this chain.
pub fn slice(messages: &[Message]) -> Result<ConversationSlices> {
    let mut entries = Vec::new();
    let mut index = 0;
    while index < messages.len() {
        let start = index;
        match &messages[index] {
            Message::System { .. } => {
                index += 1;
            }
            Message::User { .. } | Message::Assistant { .. } | Message::Tool { .. } => {
                index += 1;
                while index < messages.len()
                    && !matches!(
                        messages[index],
                        Message::User { .. } | Message::System { .. }
                    )
                {
                    index += 1;
                }
            }
        }
        entries.push(build_entry(messages, start, index - 1)?);
    }
    Ok(ConversationSlices {
        schema_version: SLICE_SCHEMA_VERSION,
        prefix_digest: crate::ConversationSnapshot::digest_of(messages)?,
        message_count: messages.len(),
        entries,
    })
}

/// A span is *closed* when nothing in it can still grow: every tool call
/// inside has its results inside, and it does not end on a user message that
/// could start a longer turn. Open spans are the only ones `extend` will
/// re-cut.
fn span_is_closed(messages: &[Message], entry: &SliceEntry) -> bool {
    if matches!(messages[entry.end_message], Message::User { .. }) {
        return false;
    }
    for message in &messages[entry.start_message..=entry.end_message] {
        if let Message::Assistant { tool_calls, .. } = message {
            for call in tool_calls {
                let has_result = messages[entry.start_message..=entry.end_message]
                    .iter()
                    .any(|candidate| {
                        matches!(candidate, Message::Tool { call_id, .. } if call_id == &call.id)
                    });
                if !has_result {
                    return false;
                }
            }
        }
    }
    true
}

/// Grow a slice file over a longer history, §3.5 incremental semantics.
///
/// Closed entries are kept verbatim; only an open trailing span (a turn that
/// was interrupted mid-flight, or one user message awaiting its assistant) is
/// re-cut over the newly visible history. Old entries are re-verified against
/// the old prefix first — a hand-edited index is refused, not extended.
pub fn extend(old: &ConversationSlices, messages: &[Message]) -> Result<ConversationSlices> {
    if old.message_count > messages.len() {
        return Err(Error::Config(format!(
            "slices cover {} messages but the history has only {}",
            old.message_count,
            messages.len()
        )));
    }
    let old_prefix_digest = crate::ConversationSnapshot::digest_of(&messages[..old.message_count])?;
    if old_prefix_digest != old.prefix_digest {
        return Err(Error::Config(
            "the history beneath the existing slices changed; existing slices no longer bind to \
             this conversation and must not be extended"
                .into(),
        ));
    }
    // Tamper check before trusting old entries into the new file.
    verify(old, &messages[..old.message_count])?;

    let mut closed = old.entries.clone();
    let recut_from = match closed.last() {
        Some(last) if !span_is_closed(&messages[..old.message_count], last) => {
            let recut_from = last.start_message;
            closed.pop();
            recut_from
        }
        _ => old.message_count,
    };
    let mut entries = closed;
    let mut index = recut_from;
    while index < messages.len() {
        let start = index;
        match &messages[index] {
            Message::System { .. } => {
                index += 1;
            }
            Message::User { .. } | Message::Assistant { .. } | Message::Tool { .. } => {
                index += 1;
                while index < messages.len()
                    && !matches!(
                        messages[index],
                        Message::User { .. } | Message::System { .. }
                    )
                {
                    index += 1;
                }
            }
        }
        entries.push(build_entry(messages, start, index - 1)?);
    }
    Ok(ConversationSlices {
        schema_version: old.schema_version,
        prefix_digest: crate::ConversationSnapshot::digest_of(messages)?,
        message_count: messages.len(),
        entries,
    })
}

/// All checks, mirroring the summary verifier: prefix binding, per-entry
/// range re-derivation, and §3.8 pairing integrity across the whole covered
/// prefix.
pub fn verify(slices: &ConversationSlices, messages: &[Message]) -> Result<()> {
    if slices.schema_version != SLICE_SCHEMA_VERSION {
        return Err(Error::Config(format!(
            "unsupported slice schema version {}",
            slices.schema_version
        )));
    }
    if slices.message_count > messages.len() {
        return Err(Error::Config(format!(
            "slices cover {} messages but the history has only {}",
            slices.message_count,
            messages.len()
        )));
    }
    let actual_prefix = crate::ConversationSnapshot::digest_of(&messages[..slices.message_count])?;
    if actual_prefix != slices.prefix_digest {
        return Err(Error::Config(
            "slice prefix_digest mismatch: the history beneath the slices changed".into(),
        ));
    }
    // The entries must tile [0, message_count) with no overlap or gap.
    let mut cursor = 0;
    for entry in &slices.entries {
        if entry.start_message != cursor {
            return Err(Error::Config(format!(
                "slice {} starts at {} but the previous slice ended at {}",
                entry.slice_id,
                entry.start_message,
                cursor.saturating_sub(1)
            )));
        }
        if entry.end_message < entry.start_message || entry.end_message >= slices.message_count {
            return Err(Error::Config(format!(
                "slice {} has an incoherent span {}..={}",
                entry.slice_id, entry.start_message, entry.end_message
            )));
        }
        let expected_derived: Vec<usize> = (entry.start_message..=entry.end_message).collect();
        if entry.derived_from != expected_derived {
            return Err(Error::Config(format!(
                "slice {} derived_from does not match its declared span",
                entry.slice_id
            )));
        }
        let kind = slice_kind(
            &messages[..slices.message_count],
            entry.start_message,
            entry.end_message,
        );
        if entry.kind != kind {
            return Err(Error::Config(format!(
                "slice {} kind mismatch: derived {kind:?}, recorded {:?}",
                entry.slice_id, entry.kind
            )));
        }
        let expected_summary = slice_summary(
            &messages[..slices.message_count],
            entry.start_message,
            entry.end_message,
        )?;
        if entry.summary != expected_summary {
            return Err(Error::Config(format!(
                "slice {} summary does not re-derive from its span",
                entry.slice_id
            )));
        }
        let expected_digest = span_range_digest(&messages[..slices.message_count], entry)?;
        if entry.range_digest != expected_digest {
            return Err(Error::Config(format!(
                "slice {} range_digest mismatch: the bytes it describes changed",
                entry.slice_id
            )));
        }
        if !entry.verbatim || entry.unverified {
            return Err(Error::Config(format!(
                "slice {} carries a write-back-style verbatim/unverified flag A6-1b does not \
                 produce",
                entry.slice_id
            )));
        }
        // §3.8 pairing, in both directions, within the covered prefix.
        for (i, message) in messages[entry.start_message..=entry.end_message]
            .iter()
            .enumerate()
        {
            let absolute = entry.start_message + i;
            match message {
                Message::Assistant { tool_calls, .. } => {
                    for call in tool_calls {
                        let result_exists = messages[..slices.message_count].iter().any(
                            |candidate| {
                                matches!(candidate, Message::Tool { call_id, .. } if call_id == &call.id)
                            },
                        );
                        let result_in_span = messages[entry.start_message..=entry.end_message]
                            .iter()
                            .any(|candidate| {
                                matches!(candidate, Message::Tool { call_id, .. } if call_id == &call.id)
                            });
                        if result_exists && !result_in_span {
                            return Err(Error::Config(format!(
                                "slice {} holds a call whose result lives outside the span; \
                                 that assembled history would be wire-illegal",
                                entry.slice_id
                            )));
                        }
                        let _ = absolute;
                    }
                }
                Message::Tool { call_id, .. } => {
                    let call_in_span = messages[entry.start_message..=entry.end_message]
                        .iter()
                        .any(|candidate| match candidate {
                            Message::Assistant { tool_calls, .. } => {
                                tool_calls.iter().any(|call| &call.id == call_id)
                            }
                            _ => false,
                        });
                    if !call_in_span {
                        return Err(Error::Config(format!(
                            "slice {} holds an orphaned tool result {call_id} whose call is \
                             outside the span",
                            entry.slice_id
                        )));
                    }
                }
                _ => {}
            }
        }
        cursor = entry.end_message + 1;
    }
    if cursor != slices.message_count {
        return Err(Error::Config(format!(
            "slices cover messages 0..{} but stop at {}",
            slices.message_count, cursor
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn turn() -> Vec<Message> {
        vec![
            Message::user("read notes.md"),
            Message::assistant_calls(
                "reading",
                vec![crate::ToolCall {
                    id: "c1".into(),
                    name: "read_file".into(),
                    args: serde_json::json!({"path": "notes.md"}),
                }],
            ),
            Message::tool_result("c1", "read_file", "hello"),
            Message::assistant("done"),
        ]
    }

    fn history() -> Vec<Message> {
        let mut messages = vec![Message::system("you are pangu")];
        messages.extend(turn());
        messages.push(Message::user("now write x.md"));
        messages.push(Message::assistant("ok"));
        messages
    }

    #[test]
    fn slicing_is_deterministic_and_tiles_the_history() {
        let messages = history();
        let first = slice(&messages).expect("slice");
        let second = slice(&messages).expect("slice");
        assert_eq!(first, second);
        assert_eq!(first.message_count, messages.len());
        assert_eq!(first.entries[0].kind, SliceKind::Phase);
        assert_eq!(first.entries[1].kind, SliceKind::Turn);
        assert_eq!(first.entries[1].derived_from, vec![1, 2, 3, 4]);
        assert_eq!(first.entries[2].kind, SliceKind::Turn);
        verify(&first, &messages).expect("fresh slices verify");
    }

    #[test]
    fn a_refused_path_gets_its_own_kind() {
        let mut messages = history();
        messages.push(Message::user("do it"));
        messages.push(Message::assistant_calls(
            "trying",
            vec![crate::ToolCall {
                id: "c9".into(),
                name: "write_file".into(),
                args: serde_json::json!({}),
            }],
        ));
        messages.push(Message::Tool {
            call_id: "c9".into(),
            name: "write_file".into(),
            content: "denied: forbidden path".into(),
            is_error: true,
        });
        let slices = slice(&messages).expect("slice");
        let last = slices.entries.last().expect("an entry");
        assert_eq!(last.kind, SliceKind::Refusal);
        verify(&slices, &messages).expect("verify");
    }

    #[test]
    fn a_tool_burst_is_its_own_kind() {
        let mut messages = vec![Message::system("s"), Message::user("go")];
        messages.push(Message::assistant_calls(
            "burst",
            vec![
                crate::ToolCall {
                    id: "a".into(),
                    name: "t1".into(),
                    args: serde_json::json!({}),
                },
                crate::ToolCall {
                    id: "b".into(),
                    name: "t2".into(),
                    args: serde_json::json!({}),
                },
            ],
        ));
        messages.push(Message::tool_result("a", "t1", "1"));
        messages.push(Message::tool_result("b", "t2", "2"));
        let slices = slice(&messages).expect("slice");
        assert_eq!(slices.entries[1].kind, SliceKind::ToolBurst);
        verify(&slices, &messages).expect("verify");
    }

    #[test]
    fn pairing_violations_are_refused() {
        let messages = history();
        let slices = slice(&messages).expect("slice");
        // Forge a broken index directly: split the turn span so the assistant
        // call and its result land in different entries, as if two spans were
        // concatenated illegally.
        let mut broken = slices;
        broken.entries[1].end_message = 2;
        broken.entries[1].derived_from = vec![1, 2];
        broken.entries[1].range_digest =
            span_range_digest(&messages[..broken.message_count], &broken.entries[1]).unwrap();
        broken.entries[1].summary = slice_summary(&messages[..broken.message_count], 1, 2).unwrap();
        broken
            .entries
            .insert(2, build_entry(&messages, 3, 4).expect("build"));
        let error = verify(&broken, &messages).expect_err("must refuse");
        assert!(
            error.to_string().contains("wire-illegal") || error.to_string().contains("orphaned"),
            "got: {error}"
        );
    }

    #[test]
    fn extending_closes_an_open_span() {
        // Interrupted run: assistant called a tool, result never arrived.
        let messages = vec![
            Message::system("s"),
            Message::user("read notes.md"),
            Message::assistant_calls(
                "reading",
                vec![crate::ToolCall {
                    id: "c1".into(),
                    name: "read_file".into(),
                    args: serde_json::json!({}),
                }],
            ),
        ];
        let old = slice(&messages).expect("slice");
        verify(&old, &messages).expect("open span verifies: its result is not in the prefix");
        let mut continued = messages.clone();
        continued.push(Message::tool_result("c1", "read_file", "hello"));
        continued.push(Message::assistant("done"));
        let extended = extend(&old, &continued).expect("extend");
        verify(&extended, &continued).expect("extended verifies");
        // The interrupted span must have been re-cut to include the result.
        assert_eq!(extended.entries.last().unwrap().end_message, 4);
    }

    #[test]
    fn extending_keeps_closed_spans_and_appends() {
        let messages = history();
        let old = slice(&messages).expect("slice");
        let mut longer = messages.clone();
        longer.extend(turn());
        let extended = extend(&old, &longer).expect("extend");
        assert_eq!(&extended.entries[..old.entries.len()], &old.entries[..]);
        verify(&extended, &longer).expect("extended verifies");
    }

    #[test]
    fn extending_over_a_changed_history_refuses() {
        let mut messages = history();
        let old = slice(&messages).expect("slice");
        messages[0] = Message::system("different");
        let error = extend(&old, &messages).expect_err("must refuse");
        assert!(error.to_string().contains("beneath"), "got: {error}");
    }

    #[test]
    fn extending_over_a_hand_edited_index_refuses() {
        let messages = history();
        let mut old = slice(&messages).expect("slice");
        old.entries[1].summary = "forged".into();
        let mut longer = messages.clone();
        longer.push(Message::user("again"));
        let error = extend(&old, &longer).expect_err("must refuse");
        assert!(error.to_string().contains("re-derive"), "got: {error}");
    }
}
