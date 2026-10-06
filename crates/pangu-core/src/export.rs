//! A5: session export with a privacy pre-scan.
//!
//! The conversation snapshot is already redacted at rest; the export pass
//! exists because "already redacted" is a claim, not a proof. Before
//! anything leaves the store we scan every text field again for secret
//! markers, absolute paths carrying user names, and oversized blobs
//! (typical tool output). Two policies:
//!
//! - [`ExportPolicy::Sanitize`] (default): still export, but every hit is
//!   neutralized in the output and reported.
//! - [`ExportPolicy::Strict`]: refuse the export when any secret-shaped
//!   marker is present. Nothing is written.
//!
//! The exported transcript is `derived: true` / `authoritative: false`: it
//! is a projection of the snapshot, never a recovery source.

use serde::{Deserialize, Serialize};

use crate::conversation::ConversationSnapshot;
use crate::events::redact_text;
use crate::messages::Message;
use crate::{Error, Result};

/// 64 KiB: bigger than any honest tool output we want inline in a
/// transcript; larger blobs get a content hash and a truncation marker.
pub const LARGE_OBJECT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    SecretLike,
    AbsolutePath,
    LargeObject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    /// Where in the snapshot: `message[i]` or `message[i].tool_calls[j]`.
    pub location: String,
    /// Short, already-redacted, human-readable note.
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyReport {
    pub findings: Vec<Finding>,
    pub secrets: usize,
    pub absolute_paths: usize,
    pub large_objects: usize,
}

impl PrivacyReport {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportPolicy {
    Sanitize,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exported {
    /// One JSON object per line: a header record plus one record per
    /// message. Derived projection, not authoritative.
    pub transcript: String,
    pub report: PrivacyReport,
}

fn absolute_path_hit(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "c:\\users\\",
        "c:/users/",
        "/users/",
        "/home/",
        "/root/",
        "/var/root/",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn mask_absolute_paths(text: &str) -> String {
    let mut out = text.to_string();
    for marker in [
        "C:\\Users\\",
        "c:\\users\\",
        "C:/Users/",
        "c:/users/",
        "/Users/",
        "/users/",
        "/Home/",
        "/home/",
        "/Root/",
        "/root/",
        "/var/root/",
    ] {
        out = out.replace(marker, "[ABS_PATH]/");
    }
    out
}

fn scan_field(
    location: &str,
    text: &str,
    findings: &mut Vec<Finding>,
    secrets: &mut usize,
    absolute_paths: &mut usize,
    large_objects: &mut usize,
) {
    if redact_text(text) != text {
        *secrets += 1;
        findings.push(Finding {
            kind: FindingKind::SecretLike,
            location: location.into(),
            detail: "secret-shaped marker present; field redacted".into(),
        });
    }
    if absolute_path_hit(text) {
        *absolute_paths += 1;
        findings.push(Finding {
            kind: FindingKind::AbsolutePath,
            location: location.into(),
            detail: "absolute path with user directory present; masked".into(),
        });
    }
    if text.len() > LARGE_OBJECT_BYTES {
        *large_objects += 1;
        findings.push(Finding {
            kind: FindingKind::LargeObject,
            location: location.into(),
            detail: format!("{} bytes; truncated", text.len()),
        });
    }
}

fn sanitize_text(text: &str) -> String {
    let redacted = redact_text(text);
    let masked = mask_absolute_paths(&redacted);
    if masked.len() > LARGE_OBJECT_BYTES {
        format!(
            "{}…[truncated, {} bytes, sha256={}]",
            crate::util::floor_char_boundary(&masked, LARGE_OBJECT_BYTES),
            masked.len(),
            crate::hex_sha256(&masked)
        )
    } else {
        masked
    }
}

fn sanitize_message(message: &Message) -> Message {
    match message {
        Message::System { content } => Message::System {
            content: sanitize_text(content),
        },
        Message::User { content } => Message::User {
            content: sanitize_text(content),
        },
        Message::Assistant {
            content,
            tool_calls,
        } => Message::Assistant {
            content: sanitize_text(content),
            tool_calls: tool_calls
                .iter()
                .map(|call| crate::ToolCall {
                    id: call.id.clone(),
                    name: call.name.clone(),
                    args: match serde_json::from_str(&sanitize_text(
                        &serde_json::to_string(&call.args).unwrap_or_default(),
                    )) {
                        Ok(args) => args,
                        Err(_) => serde_json::json!({}),
                    },
                })
                .collect(),
        },
        Message::Tool {
            call_id,
            name,
            content,
            is_error,
        } => Message::Tool {
            call_id: call_id.clone(),
            name: name.clone(),
            content: sanitize_text(content),
            is_error: *is_error,
        },
    }
}

/// Scan `snapshot` and return a sanitized JSONL transcript plus the
/// findings that justified each sanitization step.
pub fn export_snapshot(snapshot: &ConversationSnapshot, policy: ExportPolicy) -> Result<Exported> {
    let mut report = PrivacyReport::default();
    for (index, message) in snapshot.messages.iter().enumerate() {
        let location = format!("message[{index}]");
        let (content, tool_outputs): (&str, Vec<String>) = match message {
            Message::System { content }
            | Message::User { content }
            | Message::Assistant { content, .. }
            | Message::Tool { content, .. } => (content, Vec::new()),
        };
        scan_field(
            &location,
            content,
            &mut report.findings,
            &mut report.secrets,
            &mut report.absolute_paths,
            &mut report.large_objects,
        );
        for extra in tool_outputs {
            scan_field(
                &location,
                &extra,
                &mut report.findings,
                &mut report.secrets,
                &mut report.absolute_paths,
                &mut report.large_objects,
            );
        }
        if let Message::Assistant { tool_calls, .. } = message {
            for (j, call) in tool_calls.iter().enumerate() {
                let args = serde_json::to_string(&call.args).unwrap_or_default();
                scan_field(
                    &format!("message[{index}].tool_calls[{j}]"),
                    &args,
                    &mut report.findings,
                    &mut report.secrets,
                    &mut report.absolute_paths,
                    &mut report.large_objects,
                );
            }
        }
    }

    if policy == ExportPolicy::Strict && report.secrets > 0 {
        return Err(Error::Other(format!(
            "strict export refused: {} secret-shaped field(s) found in conversation {}",
            report.secrets, snapshot.snapshot_id
        )));
    }

    let mut transcript = String::new();
    transcript.push_str(
        &serde_json::json!({
            "record": "header",
            "schema": "pangu-export/1",
            "snapshot_id": snapshot.snapshot_id,
            "run_id": snapshot.run_id,
            "created_at": snapshot.created_at,
            "message_count": snapshot.messages.len(),
            "history_digest": snapshot.history_digest,
            "derived": true,
            "authoritative": false,
            "privacy": {
                "secrets": report.secrets,
                "absolute_paths": report.absolute_paths,
                "large_objects": report.large_objects,
            }
        })
        .to_string(),
    );
    transcript.push('\n');
    for message in &snapshot.messages {
        let sanitized = sanitize_message(message);
        transcript.push_str(
            &serde_json::json!({
                "record": "message",
                "message": sanitized,
            })
            .to_string(),
        );
        transcript.push('\n');
    }

    Ok(Exported { transcript, report })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_with(messages: Vec<Message>) -> ConversationSnapshot {
        ConversationSnapshot::new("snap-export", "run/export", messages).expect("snapshot")
    }

    #[test]
    fn clean_conversation_exports_without_findings() {
        let snapshot = snapshot_with(vec![
            Message::system("you are helpful"),
            Message::user("hello"),
            Message::assistant("hi there"),
        ]);
        let exported = export_snapshot(&snapshot, ExportPolicy::Sanitize).expect("export");
        assert!(exported.report.is_clean());
        assert!(exported.transcript.contains("pangu-export/1"));
        assert!(exported.transcript.contains("hello"));
    }

    #[test]
    fn secrets_are_reported_and_masked_in_sanitize_mode() {
        let snapshot = snapshot_with(vec![Message::user("my key is sk-1234567890abcdef")]);
        // The store itself redacts at write time; simulate a hand-edited
        // store leaking one by constructing a message directly.
        let mut snapshot = snapshot;
        snapshot.messages = vec![Message::user("my key is sk-1234567890abcdef")];
        let exported = export_snapshot(&snapshot, ExportPolicy::Sanitize).expect("export");
        assert_eq!(exported.report.secrets, 1);
        assert!(!exported.transcript.contains("sk-1234567890abcdef"));
    }

    #[test]
    fn strict_mode_refuses_secret_shaped_text() {
        let snapshot = snapshot_with(vec![Message::user("token=abc123")]);
        let mut snapshot = snapshot;
        snapshot.messages = vec![Message::user("token=abc123")];
        let err = export_snapshot(&snapshot, ExportPolicy::Strict).unwrap_err();
        assert!(err.to_string().contains("strict export refused"));
    }

    #[test]
    fn absolute_paths_are_masked() {
        let snapshot = snapshot_with(vec![Message::user(
            "open C:\\Users\\alice\\secret.txt please",
        )]);
        let mut snapshot = snapshot;
        snapshot.messages = vec![Message::user("open C:\\Users\\alice\\secret.txt please")];
        let exported = export_snapshot(&snapshot, ExportPolicy::Sanitize).expect("export");
        assert_eq!(exported.report.absolute_paths, 1);
        assert!(exported.transcript.contains("[ABS_PATH]"));
        assert!(!exported.transcript.contains("C:\\\\Users"));
    }

    #[test]
    fn large_tool_output_is_truncated_with_hash() {
        let big = "x".repeat(LARGE_OBJECT_BYTES + 10);
        let snapshot = snapshot_with(vec![Message::user("hi")]);
        let mut snapshot = snapshot;
        snapshot.messages = vec![Message::Tool {
            call_id: "c1".into(),
            name: "run_shell".into(),
            content: big,
            is_error: false,
        }];
        let exported = export_snapshot(&snapshot, ExportPolicy::Sanitize).expect("export");
        assert_eq!(exported.report.large_objects, 1);
        assert!(exported.transcript.contains("truncated"));
        assert!(exported.transcript.contains("sha256="));
    }
}
