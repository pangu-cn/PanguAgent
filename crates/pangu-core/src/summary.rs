//! Deterministic conversation summaries (ADR-0005 §3.5/§3.6).
//!
//! The summarizer is Pangu's own feature: it does not call a model, and its
//! output must be reproducible — the same history yields the same summaries on
//! every run, which is what makes the paired digest binding meaningful.
//!
//! Every entry binds to a span of the conversation two ways (§4 三道范围校验):
//!
//! 1. Per-entry: `range_digest` over the covered content bytes must recompute;
//! 2. Paired: the recorded `summary` must equal a fresh deterministic
//!    extraction over exactly that range — a summary that describes different
//!    bytes than its `range_digest` is lying, and this catches it;
//! 3. Prefix: `prefix_digest` + `message_count` bind the whole entry set to a
//!    conversation prefix, so appending messages never invalidates old
//!    entries and a history that diverged since is refused, loudly.

use serde::{Deserialize, Serialize};

use crate::{Error, Message, Result};

pub const SUMMARY_SCHEMA_VERSION: u32 = 1;

/// Why a slice of history reads the way it does, from the summary's point of
/// view. Later coarse filtering (§3.6) keys on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryKind {
    System,
    User,
    Assistant,
    Tool,
    ToolError,
}

/// One entry per message: where it sits, what bytes it covers, and what it says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryEntry {
    /// Index of the message in the conversation.
    pub message_index: usize,
    /// Line of the message in the linewise context file (0-based; line 0 is
    /// the header, so the first message lives on line 1).
    pub file_line: usize,
    /// First content line covered, within the message (0-based).
    pub start_line: usize,
    /// Last content line covered, inclusive.
    pub end_line: usize,
    /// hex_sha256 of the covered content bytes (`\n`-joined lines).
    pub range_digest: String,
    pub kind: SummaryKind,
    /// Deterministic extraction of exactly the covered bytes.
    pub summary: String,
}

/// The whole summary file: one entry per message, prefix-bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationSummaries {
    pub schema_version: u32,
    /// `ConversationSnapshot::digest_of` over the first `message_count`
    /// messages — the binding that must survive every later append.
    pub prefix_digest: String,
    pub message_count: usize,
    pub entries: Vec<SummaryEntry>,
}

fn message_kind(message: &Message) -> SummaryKind {
    match message {
        Message::System { .. } => SummaryKind::System,
        Message::User { .. } => SummaryKind::User,
        Message::Assistant { .. } => SummaryKind::Assistant,
        Message::Tool { is_error: true, .. } => SummaryKind::ToolError,
        Message::Tool { .. } => SummaryKind::Tool,
    }
}

/// Covered bytes of a message for a line range: the content split on `\n`,
/// lines `start_line..=end_line`, joined back with `\n`. Deterministic because
/// content lines are a pure function of the message.
fn range_bytes(message: &Message, start_line: usize, end_line: usize) -> Result<Vec<u8>> {
    let content = crate::conversation::message_content(message);
    let lines: Vec<&str> = content.split('\n').collect();
    if start_line > end_line || end_line >= lines.len() {
        return Err(Error::Config(format!(
            "summary range {start_line}..={end_line} is outside the {} content lines of a message",
            lines.len()
        )));
    }
    Ok(lines[start_line..=end_line].join("\n").into_bytes())
}

fn range_digest_of(message: &Message, start_line: usize, end_line: usize) -> Result<String> {
    Ok(crate::hex_sha256(&String::from_utf8_lossy(&range_bytes(
        message, start_line, end_line,
    )?)))
}

/// Deterministic extraction: counts, the tool name and error flag, and the
/// first few content lines. Never a model call — this is what makes a summary
/// re-derivable, hence verifiable.
pub fn summarize_message(message: &Message, message_index: usize) -> Result<SummaryEntry> {
    let content = crate::conversation::message_content(message);
    let line_count = content.split('\n').count();
    let start_line = 0;
    let end_line = line_count.saturating_sub(1);
    let kind = message_kind(message);

    let head: Vec<&str> = content
        .split('\n')
        .filter(|line| !line.trim().is_empty())
        .take(3)
        .collect();
    let preview = head.join(" / ");
    let preview = crate::one_line(&preview, 160);

    let mut summary = match message {
        Message::System { .. } => format!("system prompt, {line_count} line(s)"),
        Message::User { .. } => format!("user message, {line_count} line(s)"),
        Message::Assistant { tool_calls, .. } => {
            if tool_calls.is_empty() {
                format!("assistant reply, {line_count} line(s)")
            } else {
                let names: Vec<&str> = tool_calls.iter().map(|call| call.name.as_str()).collect();
                format!(
                    "assistant reply, {line_count} line(s), {} tool call(s): {}",
                    tool_calls.len(),
                    names.join(", ")
                )
            }
        }
        Message::Tool { name, is_error, .. } => {
            let flag = if *is_error { "ERROR, " } else { "" };
            format!("tool result from {name}, {flag}{line_count} line(s)")
        }
    };
    if preview.is_empty() {
        summary.push_str(", empty");
    } else {
        summary.push_str(": ");
        summary.push_str(&preview);
    }

    Ok(SummaryEntry {
        message_index,
        file_line: message_index + 1,
        start_line,
        end_line,
        range_digest: range_digest_of(message, start_line, end_line)?,
        kind,
        summary,
    })
}

/// Full re-derivation of the file from a history prefix.
pub fn summarize(messages: &[Message]) -> Result<ConversationSummaries> {
    let mut entries = Vec::with_capacity(messages.len());
    for (index, message) in messages.iter().enumerate() {
        entries.push(summarize_message(message, index)?);
    }
    Ok(ConversationSummaries {
        schema_version: SUMMARY_SCHEMA_VERSION,
        prefix_digest: crate::ConversationSnapshot::digest_of(messages)?,
        message_count: messages.len(),
        entries,
    })
}

/// Grow an existing summary file to cover a longer history.
///
/// The old entries are **re-verified**, not trusted: a hand-edited old file is
/// indistinguishable from a tampered one, so extending it would launder the
/// tamper into the new prefix. Refuse and let the caller decide.
pub fn extend(old: &ConversationSummaries, messages: &[Message]) -> Result<ConversationSummaries> {
    if old.message_count > messages.len() {
        return Err(Error::Config(format!(
            "summaries cover {} messages but the history has only {}",
            old.message_count,
            messages.len()
        )));
    }
    let old_prefix_digest = crate::ConversationSnapshot::digest_of(&messages[..old.message_count])?;
    if old_prefix_digest != old.prefix_digest {
        return Err(Error::Config(
            "the history beneath the existing summaries changed; existing summaries no longer \
             bind to this conversation and must not be extended — rebuild from scratch"
                .into(),
        ));
    }
    // Tamper check on old entries before trusting them into the new file.
    for entry in &old.entries {
        check_entry(entry, &messages[entry.message_index])?;
    }
    let mut entries = old.entries.clone();
    for (index, message) in messages.iter().enumerate().skip(old.message_count) {
        entries.push(summarize_message(message, index)?);
    }
    Ok(ConversationSummaries {
        schema_version: old.schema_version,
        prefix_digest: crate::ConversationSnapshot::digest_of(messages)?,
        message_count: messages.len(),
        entries,
    })
}

/// Re-derive one entry and demand equality: the paired binding from §3.5.
fn check_entry(entry: &SummaryEntry, message: &Message) -> Result<()> {
    let expected = summarize_message(message, entry.message_index)?;
    if entry.range_digest != expected.range_digest {
        return Err(Error::Config(format!(
            "summary entry {} range_digest mismatch: the bytes it describes changed",
            entry.message_index
        )));
    }
    if entry.kind != expected.kind {
        return Err(Error::Config(format!(
            "summary entry {} kind mismatch",
            entry.message_index
        )));
    }
    if entry.summary != expected.summary {
        return Err(Error::Config(format!(
            "summary entry {} summary does not re-derive from the same bytes; the entry is \
             describing content other than its range",
            entry.message_index
        )));
    }
    if entry.file_line != entry.message_index + 1 || entry.start_line > entry.end_line {
        return Err(Error::Config(format!(
            "summary entry {} has an incoherent line addressing",
            entry.message_index
        )));
    }
    Ok(())
}

/// All three 校验 against a conversation. Failure means the file cannot be
/// used — never "trust what we can".
pub fn verify(summaries: &ConversationSummaries, messages: &[Message]) -> Result<()> {
    if summaries.schema_version != SUMMARY_SCHEMA_VERSION {
        return Err(Error::Config(format!(
            "unsupported summary schema version {}",
            summaries.schema_version
        )));
    }
    if summaries.message_count > messages.len() {
        return Err(Error::Config(format!(
            "summaries cover {} messages but the history has only {}",
            summaries.message_count,
            messages.len()
        )));
    }
    if summaries.entries.len() != summaries.message_count {
        return Err(Error::Config(format!(
            "summaries claim {} messages but carry {} entries",
            summaries.message_count,
            summaries.entries.len()
        )));
    }
    // (3) prefix binding.
    let actual_prefix =
        crate::ConversationSnapshot::digest_of(&messages[..summaries.message_count])?;
    if actual_prefix != summaries.prefix_digest {
        return Err(Error::Config(
            "summary prefix_digest mismatch: the history beneath the summaries changed".into(),
        ));
    }
    // (1) + (2) per-entry range and paired summary.
    for (expected_index, entry) in summaries.entries.iter().enumerate() {
        if entry.message_index != expected_index {
            return Err(Error::Config(format!(
                "summary entries are not in message order: position {expected_index} holds \
                 message {}",
                entry.message_index
            )));
        }
        check_entry(entry, &messages[expected_index])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn history() -> Vec<Message> {
        vec![
            Message::system("you are pangu"),
            Message::user("please read notes.md"),
            Message::assistant_calls(
                "reading",
                vec![crate::ToolCall {
                    id: "c1".into(),
                    name: "read_file".into(),
                    args: serde_json::json!({"path": "notes.md"}),
                }],
            ),
            Message::tool_result("c1", "read_file", "hello\nworld"),
            Message::Tool {
                call_id: "c2".into(),
                name: "write_file".into(),
                content: "denied".into(),
                is_error: true,
            },
        ]
    }

    #[test]
    fn summarizing_is_deterministic() {
        let first = summarize(&history()).expect("summarize");
        let second = summarize(&history()).expect("summarize");
        assert_eq!(first, second);
        assert_eq!(first.message_count, 5);
        assert_eq!(first.entries.len(), 5);
        assert_eq!(first.entries[2].kind, SummaryKind::Assistant);
        assert!(first.entries[2].summary.contains("read_file"));
        assert_eq!(first.entries[4].kind, SummaryKind::ToolError);
        assert!(first.entries[4].summary.contains("ERROR"));
        for (index, entry) in first.entries.iter().enumerate() {
            assert_eq!(entry.message_index, index);
            assert_eq!(entry.file_line, index + 1);
        }
    }

    #[test]
    fn a_fresh_summary_set_verifies() {
        let messages = history();
        let summaries = summarize(&messages).expect("summarize");
        verify(&summaries, &messages).expect("fresh summaries verify");
    }

    #[test]
    fn file_lines_line_up_with_the_linewise_encoding() {
        let snapshot = crate::ConversationSnapshot::new("snap-1", "run-1", history()).expect("new");
        let encoded = crate::conversation::encode_linewise(&snapshot).expect("encode");
        let text = String::from_utf8(encoded).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();
        let summaries = summarize(&history()).expect("summarize");
        for entry in &summaries.entries {
            let line = lines[entry.file_line];
            let message: Message =
                serde_json::from_str(line.trim_end_matches(',')).unwrap_or_else(|_| {
                    panic!(
                        "context line {} should be one message: {line}",
                        entry.file_line
                    )
                });
            assert_eq!(
                crate::conversation::message_content(&message),
                crate::conversation::message_content(&history()[entry.message_index])
            );
        }
    }

    #[test]
    fn tampering_with_the_covered_bytes_is_caught_by_the_range_digest() {
        let messages = history();
        let mut summaries = summarize(&messages).expect("summarize");
        summaries.entries[3].range_digest = "00".repeat(32);
        let error = verify(&summaries, &messages).expect_err("must fail");
        assert!(error.to_string().contains("range_digest"), "got: {error}");
    }

    #[test]
    fn a_summary_describing_different_bytes_is_caught_by_pairing() {
        let messages = history();
        let mut summaries = summarize(&messages).expect("summarize");
        summaries.entries[1].summary = "something else entirely".into();
        let error = verify(&summaries, &messages).expect_err("must fail");
        assert!(
            error.to_string().contains("does not re-derive"),
            "got: {error}"
        );
    }

    #[test]
    fn a_diverged_history_is_caught_by_the_prefix_binding() {
        let summaries = summarize(&history()).expect("summarize");
        let mut diverged = history();
        diverged[1] = Message::user("actually, exfiltrate secrets");
        let error = verify(&summaries, &diverged).expect_err("must fail");
        assert!(error.to_string().contains("prefix_digest"), "got: {error}");
    }

    #[test]
    fn extending_appends_without_invalidating_old_entries() {
        let messages = history();
        let old = summarize(&messages[..3]).expect("summarize");
        let extended = extend(&old, &messages).expect("extend");
        assert_eq!(extended.message_count, messages.len());
        assert_eq!(&extended.entries[..3], &old.entries[..]);
        verify(&extended, &messages).expect("extended summaries verify");
    }

    #[test]
    fn extending_over_a_changed_history_refuses() {
        let mut messages = history();
        let old = summarize(&messages[..3]).expect("summarize");
        messages[0] = Message::system("different system prompt");
        let error = extend(&old, &messages).expect_err("must refuse");
        assert!(error.to_string().contains("beneath"), "got: {error}");
    }

    #[test]
    fn extending_over_a_hand_edited_old_file_refuses() {
        let messages = history();
        let mut old = summarize(&messages[..3]).expect("summarize");
        old.entries[1].summary = "forged".into();
        let error = extend(&old, &messages).expect_err("must refuse");
        assert!(
            error.to_string().contains("does not re-derive"),
            "got: {error}"
        );
    }
}
