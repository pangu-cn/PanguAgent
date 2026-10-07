//! Persisted conversation history, so an interrupted run can resume.
//!
//! This exists because `SessionNode` records the *workspace*, not the
//! conversation. Without it, "resume" would only mean "restore the files",
//! which is what rollback already does.
//!
//! The rule that matters most here is ADR-0004 §4.3: a restored history is
//! **model input and nothing else**. It carries no decision, no effect, and no
//! memory of an approval. A resumed run still passes every action through
//! `Policy -> Sandbox -> Approval`. History is what the model reads, so history
//! is never authorization.

use serde::{Deserialize, Serialize};

use crate::{Error, Message, Result};

pub const CONVERSATION_SCHEMA_VERSION: u32 = 1;

/// Bound on a single stored conversation.
pub const MAX_CONVERSATION_BYTES: usize = 8 * 1024 * 1024;

/// Bound on the message count of a single stored conversation.
pub const MAX_CONVERSATION_MESSAGES: usize = 10_000;

/// Bound on one message's text after redaction.
pub const MAX_MESSAGE_CONTENT_BYTES: usize = 256 * 1024;

/// Why a conversation was compacted, and from what.
///
/// Present on every snapshot that compaction produced. A conversation with no
/// compaction record is verbatim, which is the default and the only automatic
/// behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionRecord {
    /// Content digest of the conversation this one replaced.
    pub compacted_from_digest: String,
    /// How many messages were dropped.
    pub dropped_messages: usize,
    /// How many trailing messages were kept verbatim.
    pub kept_messages: usize,
    /// What the dropped span was replaced with.
    pub summary: String,
}

/// A restorable conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationSnapshot {
    pub schema_version: u32,
    pub snapshot_id: String,
    /// The session node this conversation was captured at, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_node_id: Option<String>,
    pub run_id: String,
    /// Already redacted. Never stored raw.
    pub messages: Vec<Message>,
    /// Content digest of `messages`.
    pub history_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compaction: Option<CompactionRecord>,
    pub created_at: String,
}

impl ConversationSnapshot {
    pub fn new(
        snapshot_id: impl Into<String>,
        run_id: impl Into<String>,
        messages: Vec<Message>,
    ) -> Result<Self> {
        let messages = redact_messages(messages);
        let history_digest = Self::digest_of(&messages)?;
        Ok(Self {
            schema_version: CONVERSATION_SCHEMA_VERSION,
            snapshot_id: snapshot_id.into(),
            session_node_id: None,
            run_id: run_id.into(),
            messages,
            history_digest,
            compaction: None,
            created_at: crate::now_rfc3339(),
        })
    }

    /// Content digest over the redacted messages.
    ///
    /// Computed over the message list only, so it stays stable across
    /// metadata changes and can be referenced by a later compaction.
    pub fn digest_of(messages: &[Message]) -> Result<String> {
        let encoded = serde_json::to_vec(messages)?;
        Ok(crate::hex_sha256(&String::from_utf8_lossy(&encoded)))
    }

    pub fn with_session_node(mut self, session_node_id: impl Into<String>) -> Self {
        self.session_node_id = Some(session_node_id.into());
        self
    }

    /// Replace the history with a compacted form, recording where it came from.
    ///
    /// The caller supplies the summary; this function does not invent one. An
    /// empty summary is refused, because a compaction that drops context
    /// without saying what replaced it is indistinguishable from data loss.
    pub fn compacted(
        mut self,
        new_snapshot_id: impl Into<String>,
        summary: impl Into<String>,
        kept_messages: Vec<Message>,
    ) -> Result<Self> {
        // A compaction is a *new* record. Reusing the id would collide with the
        // store's immutability rule, and overwriting would destroy the very
        // history the new record says it came from.
        let new_snapshot_id = new_snapshot_id.into();
        if new_snapshot_id == self.snapshot_id {
            return Err(Error::Config(
                "a compaction must use a new snapshot_id; the original stays readable".into(),
            ));
        }
        self.snapshot_id = new_snapshot_id;
        let summary = summary.into();
        if summary.trim().is_empty() {
            return Err(Error::Config(
                "compaction requires a non-empty summary; dropping history without saying what \
                 replaced it is indistinguishable from data loss"
                    .into(),
            ));
        }
        let previous_digest = self.history_digest.clone();
        let dropped = self.messages.len().saturating_sub(kept_messages.len());
        let kept = kept_messages.len();
        // A compaction that keeps everything is not a compaction. Refusing it
        // keeps the record honest about what happened.
        if dropped == 0 {
            return Err(Error::Config(format!(
                "compaction kept all {kept} message(s); refusing to record a compaction that \
                 discarded nothing"
            )));
        }
        let messages = redact_messages(kept_messages);
        self.messages = messages;
        self.history_digest = Self::digest_of(&self.messages)?;
        self.compaction = Some(CompactionRecord {
            compacted_from_digest: previous_digest,
            dropped_messages: dropped,
            kept_messages: kept,
            summary,
        });
        self.created_at = crate::now_rfc3339();
        Ok(self)
    }

    /// Restore the messages to seed a run's context.
    ///
    /// This is the only path from stored history back into a live run, and it
    /// returns plain `Message` values. There is deliberately no method on this
    /// type that yields a `Decision`, an `Effect`, or an approval.
    pub fn restore(&self) -> Result<Vec<Message>> {
        self.validate()?;
        Ok(self.messages.clone())
    }

    /// Reject anything that is not a well-formed, untampered snapshot.
    ///
    /// A digest mismatch is an error, never a "restore what we can". Restoring
    /// a partially-tampered history would mean acting on a conversation the
    /// operator never had.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONVERSATION_SCHEMA_VERSION {
            return Err(Error::Config(format!(
                "unsupported conversation schema version {}",
                self.schema_version
            )));
        }
        if self.snapshot_id.trim().is_empty() {
            return Err(Error::Config("conversation snapshot_id is empty".into()));
        }
        if self.run_id.trim().is_empty() {
            return Err(Error::Config("conversation run_id is empty".into()));
        }
        if self.messages.is_empty() {
            return Err(Error::Config(
                "conversation has no messages; a damaged history must not be restored as an \
                 empty one, because that silently restarts the session"
                    .into(),
            ));
        }
        if self.messages.len() > MAX_CONVERSATION_MESSAGES {
            return Err(Error::Config(format!(
                "conversation has {} messages, over the {} limit",
                self.messages.len(),
                MAX_CONVERSATION_MESSAGES
            )));
        }
        for message in &self.messages {
            let content = message_content(message);
            if content.len() > MAX_MESSAGE_CONTENT_BYTES {
                return Err(Error::Config(format!(
                    "a message exceeds {MAX_MESSAGE_CONTENT_BYTES} bytes after redaction"
                )));
            }
        }
        let actual = Self::digest_of(&self.messages)?;
        if actual != self.history_digest {
            return Err(Error::Config(format!(
                "conversation history digest mismatch: expected {}, computed {actual}. The stored \
                 history was modified after it was written.",
                self.history_digest
            )));
        }
        if let Some(compaction) = &self.compaction {
            if compaction.summary.trim().is_empty() {
                return Err(Error::Config(
                    "compaction record has an empty summary".into(),
                ));
            }
            if compaction.dropped_messages == 0 {
                return Err(Error::Config(
                    "compaction record claims to have dropped nothing".into(),
                ));
            }
        }
        Ok(())
    }

    /// Whether this conversation is verbatim, or the product of a compaction.
    pub fn is_compacted(&self) -> bool {
        self.compaction.is_some()
    }
}

/// The user-visible text of a message, whichever variant it is.
pub fn message_content(message: &Message) -> &str {
    match message {
        Message::System { content }
        | Message::User { content }
        | Message::Assistant { content, .. }
        | Message::Tool { content, .. } => content,
    }
}

/// Redact every message in a history.
///
/// Applied on the way in and never on the way out, so a stored conversation
/// cannot be the place a secret survives that the live run would have caught.
pub fn redact_messages(messages: Vec<Message>) -> Vec<Message> {
    messages
        .into_iter()
        .map(|message| match message {
            Message::System { content } => Message::System {
                content: crate::redact_text(&content),
            },
            Message::User { content } => Message::User {
                content: crate::redact_text(&content),
            },
            Message::Assistant {
                content,
                tool_calls,
            } => Message::Assistant {
                content: crate::redact_text(&content),
                tool_calls: tool_calls
                    .into_iter()
                    .map(|call| crate::ToolCall {
                        id: call.id,
                        name: call.name,
                        args: crate::redact_value(&call.args),
                    })
                    .collect(),
            },
            Message::Tool {
                call_id,
                name,
                content,
                is_error,
            } => Message::Tool {
                call_id,
                name,
                content: crate::redact_text(&content),
                is_error,
            },
        })
        .collect()
}

/// Check that a serialized conversation stays within the storage bound.
pub fn validate_encoded_size(encoded: &[u8]) -> Result<()> {
    if encoded.len() > MAX_CONVERSATION_BYTES {
        return Err(Error::Other(format!(
            "conversation exceeds {MAX_CONVERSATION_BYTES} bytes when encoded"
        )));
    }
    Ok(())
}

/// Mirror of every [`ConversationSnapshot`] field except `messages`.
///
/// It exists so [`encode_linewise`] does not have to hand-write each field. It
/// is a **maintenance hazard by construction**: a field added to the snapshot
/// and not added here would silently vanish from disk. `header_ref_covers_every_
/// field` is the guard that turns that into a test failure.
#[derive(Serialize)]
struct HeaderRef<'a> {
    schema_version: u32,
    snapshot_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_node_id: Option<&'a str>,
    run_id: &'a str,
    history_digest: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    compaction: Option<&'a CompactionRecord>,
    created_at: &'a str,
}

impl<'a> HeaderRef<'a> {
    fn of(snapshot: &'a ConversationSnapshot) -> Self {
        Self {
            schema_version: snapshot.schema_version,
            snapshot_id: &snapshot.snapshot_id,
            session_node_id: snapshot.session_node_id.as_deref(),
            run_id: &snapshot.run_id,
            history_digest: &snapshot.history_digest,
            compaction: snapshot.compaction.as_ref(),
            created_at: &snapshot.created_at,
        }
    }
}

/// Encode a snapshot with **one message per line**.
///
/// The previous form was `serde_json::to_vec`, which writes the whole snapshot
/// on a single line, so "which lines does this slice cover" had no answer. This
/// layout is what ADR-0005 §3.5's `start_line` / `end_line` address.
///
/// Wire-compatible, not byte-compatible: JSON is whitespace-insensitive, so
/// `from_slice` reads the old single-line files and the new ones alike. No
/// migration is needed and both layouts can sit in one store.
///
/// No existing digest is invalidated: [`ConversationSnapshot::digest_of`]
/// hashes `serde_json::to_vec(messages)` — the *logical* messages — not the
/// file bytes, so it is unaffected by how the file is laid out.
///
/// A message can never span two lines: `serde_json` escapes newlines inside
/// strings, so content with embedded line breaks stays on one line. The
/// `encoding_puts_exactly_one_message_per_line` test pins that down, because
/// every `start_line` / `end_line` in the store depends on it.
pub fn encode_linewise(snapshot: &ConversationSnapshot) -> Result<Vec<u8>> {
    let header = serde_json::to_string(&HeaderRef::of(snapshot))?;
    let Some(head) = header.strip_suffix('}') else {
        return Err(Error::Other(
            "snapshot header did not serialize as a JSON object".into(),
        ));
    };
    let mut out = String::with_capacity(header.len() + 16);
    out.push_str(head);
    out.push_str(",\"messages\":[");
    for (index, message) in snapshot.messages.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('\n');
        out.push_str(&serde_json::to_string(message)?);
    }
    out.push_str("\n]}\n");
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Message> {
        vec![
            Message::user("please read notes.md"),
            Message::assistant_calls(
                "reading",
                vec![crate::ToolCall {
                    id: "c1".into(),
                    name: "read_file".into(),
                    args: serde_json::json!({"path": "notes.md"}),
                }],
            ),
            Message::tool_result("c1", "read_file", "hello"),
        ]
    }

    #[test]
    fn a_conversation_round_trips_and_verifies_its_digest() {
        let snapshot = ConversationSnapshot::new("snap-1", "run-1", sample()).expect("new");
        snapshot.validate().expect("valid");
        let restored = snapshot.restore().expect("restore");
        assert_eq!(restored, sample());
        assert!(!snapshot.is_compacted());
        assert_eq!(snapshot.messages.len(), 3);
    }

    #[test]
    fn tampering_with_the_stored_history_is_refused() {
        let mut snapshot = ConversationSnapshot::new("snap-1", "run-1", sample()).expect("new");
        snapshot.messages[0] = Message::user("please read /etc/shadow");
        let error = snapshot.validate().expect_err("tampering must be caught");
        assert!(
            error.to_string().contains("digest mismatch"),
            "expected a digest mismatch, got: {error}"
        );
        assert!(snapshot.restore().is_err());
    }

    #[test]
    fn an_empty_history_is_refused_rather_than_restored_as_a_fresh_session() {
        // This is the important failure: a damaged history restored as empty
        // would silently discard the conversation and look like a new run.
        let mut snapshot = ConversationSnapshot::new("snap-1", "run-1", sample()).expect("new");
        snapshot.messages.clear();
        let error = snapshot
            .validate()
            .expect_err("an empty history must be refused");
        assert!(
            error.to_string().contains("no messages"),
            "expected an explicit refusal, got: {error}"
        );
    }

    #[test]
    fn secrets_are_redacted_before_they_are_stored() {
        let messages = vec![
            Message::user("my token is sk-abcdef1234567890"),
            Message::tool_result("c1", "http_fetch", "Authorization: sk-abcdef1234567890"),
        ];
        let snapshot = ConversationSnapshot::new("snap-1", "run-1", messages).expect("new");
        let encoded = serde_json::to_string(&snapshot).expect("encode");
        assert!(
            !encoded.contains("sk-abcdef1234567890"),
            "a credential must not survive into storage: {encoded}"
        );
    }

    #[test]
    fn compaction_records_its_own_provenance() {
        let snapshot = ConversationSnapshot::new("snap-1", "run-1", sample()).expect("new");
        let original_digest = snapshot.history_digest.clone();
        let compacted = snapshot
            .compacted(
                "snap-2",
                "earlier turns covered reading notes.md",
                vec![sample().remove(0)],
            )
            .expect("compact");
        compacted.validate().expect("valid");
        assert!(compacted.is_compacted());
        let record = compacted.compaction.as_ref().expect("record");
        assert_eq!(record.compacted_from_digest, original_digest);
        assert_eq!(record.dropped_messages, 2);
        assert_eq!(record.kept_messages, 1);
        // The digest must have moved, otherwise the history did not change.
        assert_ne!(compacted.history_digest, original_digest);
    }

    #[test]
    fn a_compaction_without_a_summary_or_without_dropping_anything_is_refused() {
        let snapshot = ConversationSnapshot::new("snap-1", "run-1", sample()).expect("new");
        assert!(snapshot
            .clone()
            .compacted("snap-2", "   ", sample())
            .is_err());
        // Keeping everything is not a compaction; recording one would make the
        // record lie about what happened.
        assert!(snapshot.compacted("snap-2", "summary", sample()).is_err());
    }

    #[test]
    fn a_forged_compaction_record_is_refused() {
        let mut snapshot = ConversationSnapshot::new("snap-1", "run-1", sample()).expect("new");
        snapshot.compaction = Some(CompactionRecord {
            compacted_from_digest: "a".repeat(64),
            dropped_messages: 0,
            kept_messages: 3,
            summary: "looks fine".into(),
        });
        assert!(
            snapshot.validate().is_err(),
            "a record claiming to have dropped nothing must be refused"
        );
    }

    #[test]
    fn an_oversized_conversation_is_refused() {
        let big = "x".repeat(MAX_MESSAGE_CONTENT_BYTES + 1);
        let mut snapshot =
            ConversationSnapshot::new("snap-1", "run-1", vec![Message::user("ok")]).expect("new");
        snapshot.messages[0] = Message::user(big);
        snapshot.history_digest = ConversationSnapshot::digest_of(&snapshot.messages).unwrap();
        assert!(snapshot.validate().is_err());
        assert!(validate_encoded_size(&vec![0u8; MAX_CONVERSATION_BYTES + 1]).is_err());
    }

    #[test]
    fn an_unsupported_schema_version_is_refused() {
        let mut snapshot = ConversationSnapshot::new("snap-1", "run-1", sample()).expect("new");
        snapshot.schema_version = 99;
        assert!(snapshot.validate().is_err());
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;
    use crate::ArtifactStore;

    /// The OS temp directory with symlinked ancestors resolved.
    ///
    /// The journal and artifact layers reject any path containing a symlink
    /// component, and the sandbox canonicalizes its workspace before comparing
    /// prefixes. On Linux container images `/tmp` is often a symlink, so a raw
    /// `temp_dir()` path is refused there while working on a machine whose temp
    /// directory is a real directory — the test passes locally and fails in CI for a
    /// reason unrelated to the code under test. Resolving the base once removes the
    /// whole class of mistake.
    fn temp_base() -> std::path::PathBuf {
        let base = std::env::temp_dir();
        std::fs::canonicalize(&base).unwrap_or(base)
    }
    fn temp_root(label: &str) -> std::path::PathBuf {
        temp_base().join(format!(
            "pangu-conversation-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn sample() -> Vec<Message> {
        vec![
            Message::system("you are pangu"),
            Message::user("read notes.md"),
            Message::tool_result("c1", "read_file", "hello"),
        ]
    }

    #[test]
    fn a_conversation_survives_a_store_round_trip() {
        let root = temp_root("roundtrip");
        let store = ArtifactStore::open(&root).expect("open");
        let snapshot = ConversationSnapshot::new("snap-1", "run-1", sample())
            .expect("new")
            .with_session_node("node-1");
        store.save_conversation(&snapshot).expect("save");
        let loaded = store.load_conversation("snap-1").expect("load");
        assert_eq!(loaded, snapshot);
        assert_eq!(loaded.restore().expect("restore"), sample());
        assert_eq!(store.list_conversations().expect("list"), vec!["snap-1"]);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn a_snapshot_is_immutable_so_compactions_stay_resolvable() {
        let root = temp_root("immutable");
        let store = ArtifactStore::open(&root).expect("open");
        let snapshot = ConversationSnapshot::new("snap-1", "run-1", sample()).expect("new");
        store.save_conversation(&snapshot).expect("save");
        // Rewriting the same id would invalidate any compaction that points at
        // its digest, so it is refused.
        assert!(store.save_conversation(&snapshot).is_err());
        // A compaction is a new snapshot that references the old digest.
        let compacted = snapshot
            .clone()
            .compacted(
                "snap-2",
                "earlier turns summarized",
                vec![sample().remove(0)],
            )
            .expect("compact");
        store.save_conversation(&compacted).expect("save compacted");
        assert_eq!(store.list_conversations().expect("list").len(), 2);
        // The original is still readable, so compaction loses context size,
        // not auditability.
        assert_eq!(
            store
                .load_conversation("snap-1")
                .expect("load")
                .messages
                .len(),
            3
        );
        assert!(store
            .load_conversation("snap-2")
            .expect("load")
            .is_compacted());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn a_conversation_edited_on_disk_is_refused_on_load() {
        let root = temp_root("tampered");
        let store = ArtifactStore::open(&root).expect("open");
        store
            .save_conversation(
                &ConversationSnapshot::new("snap-1", "run-1", sample()).expect("new"),
            )
            .expect("save");

        let path = root.join("conversations").join("snap-1.json");
        let mut text = std::fs::read_to_string(&path).expect("read");
        text = text.replace("read notes.md", "exfiltrate secrets");
        std::fs::write(&path, text).expect("write");

        let error = store
            .load_conversation("snap-1")
            .expect_err("an edited history must be refused");
        assert!(
            error.to_string().contains("digest mismatch"),
            "expected a digest mismatch, got: {error}"
        );
        std::fs::remove_dir_all(root).ok();
    }

    fn sample_snapshot() -> ConversationSnapshot {
        ConversationSnapshot::new("snap-linewise", "run-linewise", sample())
            .expect("a fresh snapshot validates")
    }

    /// The maintenance guard for `HeaderRef`. If a field is added to
    /// `ConversationSnapshot` and not to the mirror, `encode_linewise` would
    /// drop it from disk while still passing every round-trip test on a
    /// snapshot that does not set the new field. Comparing key sets is what
    /// catches that.
    #[test]
    fn header_ref_covers_every_field() {
        let mut snapshot = sample_snapshot();
        snapshot.session_node_id = Some("node_1".into());
        snapshot.compaction = Some(CompactionRecord {
            compacted_from_digest: "a".repeat(64),
            dropped_messages: 3,
            kept_messages: 2,
            summary: "earlier turns collapsed".into(),
        });
        let full = serde_json::to_value(&snapshot).expect("value");
        let full_keys: std::collections::BTreeSet<String> = full
            .as_object()
            .expect("object")
            .keys()
            .filter(|key| key.as_str() != "messages")
            .cloned()
            .collect();
        let header = serde_json::to_value(HeaderRef::of(&snapshot)).expect("value");
        let header_keys: std::collections::BTreeSet<String> = header
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            header_keys, full_keys,
            "`HeaderRef` and `ConversationSnapshot` have drifted; a field is not              being written to disk. Set every field to Some/Some first — the              comparison above runs with both set, so `skip_serializing_if`              cannot hide a missing key."
        );
    }

    /// The property ADR-0005 §3.5 depends on: a message occupies exactly one
    /// line, so a stored `start_line` / `end_line` still names the same bytes
    /// after any future edit to the encoder.
    #[test]
    fn encoding_puts_exactly_one_message_per_line() {
        let mut snapshot = sample_snapshot();
        // Content with embedded newlines is the case that could break the
        // invariant: `serde_json` must escape them rather than emit them raw.
        snapshot.messages.push(Message::Tool {
            call_id: "call_1".into(),
            name: "read_file".into(),
            content: "line one
line two
line three"
                .into(),
            is_error: false,
        });
        let encoded = encode_linewise(&snapshot).expect("encode");
        let text = String::from_utf8(encoded).expect("utf8");
        assert!(
            !text.contains("line one
line two"),
            "a raw newline leaked out of a message body, so messages no longer              occupy one line each: {text}"
        );
        // header line, one line per message, closing line
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.len(),
            snapshot.messages.len() + 2,
            "expected a header line, one line per message, and a closing line;              got {} lines for {} messages: {text}",
            lines.len(),
            snapshot.messages.len()
        );
        for line in &lines {
            assert!(!line.trim().is_empty(), "blank line in {text}");
        }
    }

    #[test]
    fn linewise_encoding_round_trips() {
        let mut snapshot = sample_snapshot();
        snapshot.session_node_id = Some("node_1".into());
        let encoded = encode_linewise(&snapshot).expect("encode");
        let decoded: ConversationSnapshot =
            serde_json::from_slice(&encoded).expect("decode must accept the new layout");
        assert_eq!(decoded, snapshot);
    }

    /// Backward compatibility is the whole reason this change is safe to ship
    /// without a migration: a file written by the old single-line encoder must
    /// still load, with an intact digest.
    #[test]
    fn a_single_line_snapshot_written_by_the_old_encoder_still_loads() {
        let snapshot = sample_snapshot();
        let legacy = serde_json::to_vec(&snapshot).expect("legacy encode");
        assert_eq!(
            legacy.iter().filter(|byte| **byte == b'\n').count(),
            0,
            "the test premise is that the old encoder produced no newlines"
        );
        let decoded: ConversationSnapshot = serde_json::from_slice(&legacy).expect("legacy decode");
        assert_eq!(decoded, snapshot);
        assert_eq!(decoded.history_digest, snapshot.history_digest);
    }
}
