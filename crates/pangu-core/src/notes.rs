//! Model-authored context notes (ADR-0014, amending ADR-0005 §3.5/§3.6).
//!
//! A note is the model's own summary of a span of its conversation, emitted
//! through the agent-owned `note_context` control call in a fixed schema. It
//! is **untrusted data**: the span it claims to cover is verified against the
//! live history (it must exist, and the covered prefix digest must recompute),
//! but the summary text can never be re-extracted and therefore can never be
//! verified — it is accepted as data and injected with a fixed annotation.
//! That asymmetry is the whole price of this feature (ADR-0014 §7).
//!
//! Notes are append-only and derived: they never edit `contexts/`,
//! `summaries/` or `slices/`, and the deterministic summarizer remains the
//! floor — with notes absent, invalid or disabled, everything behaves exactly
//! as it does without them (ADR-0014 D5).

use serde::{Deserialize, Serialize};

use crate::{Error, Message, Result};

pub const NOTE_SCHEMA_VERSION: u32 = 1;

/// Bounds. Every operator- or model-supplied list is bounded
/// (I-Effect-Bounded); a keyring-sized cap on summaries keeps a runaway loop
/// from writing an unbounded note file.
pub const MAX_MODEL_NOTES: usize = 64;
/// Upper bound on one note's summary text.
pub const MAX_NOTE_SUMMARY_BYTES: usize = 2 * 1024;
/// One control call may declare at most this many spans.
pub const MAX_NOTE_SPANS: usize = 4;
/// Upper bounds on the open-item list.
pub const MAX_NOTE_OPEN_ITEMS: usize = 8;
pub const MAX_NOTE_OPEN_ITEM_BYTES: usize = 256;

/// What the `note_context` control call must look like. This is the
/// "standardized output format" the model writes into: unknown fields are
/// rejected rather than ignored, so a schema drift fails the call loudly
/// instead of silently degrading the note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteArgs {
    /// Message spans this note covers. Optional because the model sees an
    /// assembled *projection* of the history and cannot reliably address
    /// absolute message indices; omitted means the system binds the note to
    /// the whole history as it stands, which keeps the span binding intact
    /// without asking the model to guess indices. When declared, each span
    /// must exist in the history.
    #[serde(default)]
    pub spans: Vec<NoteSpan>,
    /// The model-authored summary of the covered spans.
    pub summary: String,
    /// Open items the model wants its future self to keep in view.
    #[serde(default)]
    pub open_items: Vec<String>,
}

/// An inclusive message span `start_message..=end_message`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteSpan {
    pub start_message: usize,
    pub end_message: usize,
}

/// One stored note: the model's claim about a span, bound to the conversation
/// prefix it was written against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelNote {
    /// Turn of the run that emitted the note (provenance only).
    pub turn: usize,
    /// Inclusive covered span.
    pub start_message: usize,
    pub end_message: usize,
    /// `ConversationSnapshot::digest_of` over the first `message_count`
    /// messages of the history — the binding that must survive every later
    /// append, same rule as summaries/slices (ADR-0005 §3.5).
    pub message_count: usize,
    pub prefix_digest: String,
    /// The note text: bounded, no control characters, **never re-verified**.
    pub summary: String,
    #[serde(default)]
    pub open_items: Vec<String>,
    /// Always `true`: a model-authored note is unverified by construction.
    /// Fielded so consumers pattern-match instead of trusting the source.
    pub unverified: bool,
}

/// The stored note set for one run: append-only, loaded as a whole (small and
/// bounded by construction).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationNotes {
    pub schema_version: u32,
    pub notes: Vec<ModelNote>,
}

impl ConversationNotes {
    pub fn new() -> Self {
        Self {
            schema_version: NOTE_SCHEMA_VERSION,
            notes: Vec::new(),
        }
    }

    /// Append notes, keeping the file bounded. Older notes are preserved;
    /// refusing to grow is the loud alternative to silent truncation.
    pub fn append(&mut self, mut notes: Vec<ModelNote>) -> Result<()> {
        if self.notes.len().saturating_add(notes.len()) > MAX_MODEL_NOTES {
            return Err(Error::Config(format!(
                "at most {MAX_MODEL_NOTES} model notes per conversation"
            )));
        }
        self.notes.append(&mut notes);
        Ok(())
    }
}

impl Default for ConversationNotes {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate one `note_context` call against the live history and build the
/// note to store. `message_count` is the history length at call time: a span
/// beyond the history is refused rather than clamped.
pub fn note_from_args(
    turn: usize,
    args: &serde_json::Value,
    messages: &[Message],
) -> Result<ModelNote> {
    let parsed: NoteArgs = serde_json::from_value(args.clone())
        .map_err(|error| Error::Config(format!("invalid note_context arguments: {error}")))?;
    if messages.is_empty() {
        return Err(Error::Config(
            "an empty history has nothing to note".into(),
        ));
    }
    if parsed.spans.len() > MAX_NOTE_SPANS {
        return Err(Error::Config(format!(
            "note_context supports at most {MAX_NOTE_SPANS} spans per call"
        )));
    }
    let mut start_message = usize::MAX;
    let mut end_message = 0usize;
    if parsed.spans.is_empty() {
        // Omitted spans: the note covers the whole history as it stands. The
        // model cannot address a projected window by absolute index, so the
        // system performs the binding — the digests are no less real for it.
        start_message = 0;
        end_message = messages.len() - 1;
    }
    for span in &parsed.spans {
        if span.start_message > span.end_message {
            return Err(Error::Config(format!(
                "note span {}..={} is inverted",
                span.start_message, span.end_message
            )));
        }
        if span.end_message >= messages.len() {
            return Err(Error::Config(format!(
                "note span {}..={} exceeds the {} stored messages",
                span.start_message,
                span.end_message,
                messages.len()
            )));
        }
        start_message = start_message.min(span.start_message);
        end_message = end_message.max(span.end_message);
    }
    let summary = validate_bounded_text(&parsed.summary, MAX_NOTE_SUMMARY_BYTES, "summary")?;
    if parsed.open_items.len() > MAX_NOTE_OPEN_ITEMS {
        return Err(Error::Config(format!(
            "note_context supports at most {MAX_NOTE_OPEN_ITEMS} open items"
        )));
    }
    let mut open_items = Vec::new();
    for item in &parsed.open_items {
        open_items.push(validate_bounded_text(
            item,
            MAX_NOTE_OPEN_ITEM_BYTES,
            "open item",
        )?);
    }
    // Bind the covered prefix: the digest of the first `end_message + 1`
    // messages is what a later load recomputes.
    let message_count = end_message + 1;
    let prefix_digest = crate::ConversationSnapshot::digest_of(&messages[..message_count])?;
    Ok(ModelNote {
        turn,
        start_message,
        end_message,
        message_count,
        prefix_digest,
        summary,
        open_items,
        unverified: true,
    })
}

/// Shared text rule for note fields: non-empty, bounded, no control
/// characters. Applied to the model's own output, so a rejected field is
/// fed back as an invalid tool call — never silently truncated.
fn validate_bounded_text(value: &str, max_bytes: usize, field: &str) -> Result<String> {
    if value.trim().is_empty() {
        return Err(Error::Config(format!("note {field} must not be empty")));
    }
    if value.len() > max_bytes {
        return Err(Error::Config(format!(
            "note {field} exceeds {max_bytes} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(Error::Config(format!(
            "note {field} must not contain control characters"
        )));
    }
    Ok(value.to_string())
}

/// Verify stored notes against a live history.
///
/// Each note's claimed prefix must recompute and its span must still be in
/// range — a note that describes different bytes than it binds to is lying,
/// and this refuses it loudly. The *text* is not re-checked: there is
/// nothing to re-extract it from (ADR-0014 D3).
pub fn verify(notes: &ConversationNotes, messages: &[Message]) -> Result<()> {
    if notes.schema_version != NOTE_SCHEMA_VERSION {
        return Err(Error::Config(format!(
            "unsupported note schema version {}",
            notes.schema_version
        )));
    }
    if notes.notes.len() > MAX_MODEL_NOTES {
        return Err(Error::Config(format!(
            "note file carries {} notes; at most {MAX_MODEL_NOTES} are supported",
            notes.notes.len()
        )));
    }
    for note in &notes.notes {
        if !note.unverified {
            return Err(Error::Config(
                "a stored note must be marked unverified; an unmarked note is not \
                 model-authored data"
                    .into(),
            ));
        }
        if note.message_count == 0 || note.message_count > messages.len() {
            return Err(Error::Config(format!(
                "note covers {} messages but the history has {}",
                note.message_count,
                messages.len()
            )));
        }
        if note.start_message > note.end_message || note.end_message >= note.message_count {
            return Err(Error::Config(format!(
                "note span {}..={} is outside its covered {} messages",
                note.start_message, note.end_message, note.message_count
            )));
        }
        let actual_prefix = crate::ConversationSnapshot::digest_of(
            &messages[..note.message_count],
        )?;
        if actual_prefix != note.prefix_digest {
            return Err(Error::Config(
                "note prefix_digest mismatch: the history beneath the note changed".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Message;

    fn history() -> Vec<Message> {
        vec![
            Message::system("boundary prompt"),
            Message::user("goal"),
            Message::assistant("working"),
            Message::tool_result("call-1", "read_file", "file contents"),
            Message::assistant("done"),
        ]
    }

    fn args(summary: &str) -> serde_json::Value {
        serde_json::json!({
            "spans": [{"start_message": 1, "end_message": 3}],
            "summary": summary,
        })
    }

    #[test]
    fn a_valid_note_binds_its_covered_prefix() {
        let messages = history();
        let note = note_from_args(3, &args("read the goal and one file"), &messages)
            .expect("valid note");
        assert_eq!(note.turn, 3);
        assert_eq!((note.start_message, note.end_message), (1, 3));
        assert_eq!(note.message_count, 4);
        assert!(note.unverified, "model notes are unverified by construction");
        assert!(note.open_items.is_empty());
        let stored = ConversationNotes {
            schema_version: NOTE_SCHEMA_VERSION,
            notes: vec![note],
        };
        verify(&stored, &messages).expect("fresh note verifies");
    }

    #[test]
    fn spans_beyond_the_history_are_refused_not_clamped() {
        let messages = history();
        let beyond = serde_json::json!({
            "spans": [{"start_message": 1, "end_message": 99}],
            "summary": "claims messages that do not exist",
        });
        let error = note_from_args(1, &beyond, &messages).expect_err("span beyond history");
        assert!(error.to_string().contains("exceeds"));
        let inverted = serde_json::json!({
            "spans": [{"start_message": 3, "end_message": 1}],
            "summary": "inverted",
        });
        assert!(note_from_args(1, &inverted, &messages).is_err());
    }

    #[test]
    fn omitted_spans_bind_the_whole_history() {
        // The model sees an assembled projection and cannot address absolute
        // indices; omitting spans lets the system perform the binding.
        let messages = history();
        let note = note_from_args(2, &serde_json::json!({"summary": "everything so far"}), &messages)
            .expect("note without spans");
        assert_eq!(
            (note.start_message, note.end_message),
            (0, messages.len() - 1)
        );
        assert_eq!(note.message_count, messages.len());
    }

    #[test]
    fn schema_drift_and_oversized_fields_fail_the_call() {
        let messages = history();
        // Unknown field: the standardized format is enforced, not best-effort.
        let drifted = serde_json::json!({
            "spans": [{"start_message": 0, "end_message": 1}],
            "summary": "fine",
            "extra": "ignored?",
        });
        assert!(note_from_args(1, &drifted, &messages).is_err());
        // Missing required field.
        let missing = serde_json::json!({"spans": [{"start_message": 0, "end_message": 1}]});
        assert!(note_from_args(1, &missing, &messages).is_err());
        // Oversized summary.
        let huge = "x".repeat(MAX_NOTE_SUMMARY_BYTES + 1);
        assert!(note_from_args(1, &args(&huge), &messages).is_err());
        // Control characters.
        let control = serde_json::json!({
            "spans": [{"start_message": 0, "end_message": 1}],
            "summary": "line\nbreak",
        });
        assert!(note_from_args(1, &control, &messages).is_err());
        // Too many spans.
        let many = serde_json::json!({
            "spans": (0..=MAX_NOTE_SPANS)
                .map(|index| serde_json::json!({"start_message": index, "end_message": index}))
                .collect::<Vec<_>>(),
            "summary": "too many spans",
        });
        assert!(note_from_args(1, &many, &messages).is_err());
    }

    #[test]
    fn a_note_whose_history_changed_beneath_it_is_refused() {
        let messages = history();
        let note = note_from_args(2, &args("summary"), &messages).expect("note");
        let mut stored = ConversationNotes::new();
        stored.append(vec![note]).expect("append");
        // Appending messages never invalidates an existing note.
        let mut grown = messages.clone();
        grown.push(Message::assistant("later work"));
        verify(&stored, &grown).expect("appends keep old notes valid");
        // Editing the covered prefix does.
        let mut edited = messages.clone();
        edited[2] = Message::assistant("different work");
        let error = verify(&stored, &edited).expect_err("edited prefix must fail");
        assert!(error.to_string().contains("prefix_digest"), "got: {error}");
    }

    #[test]
    fn the_note_file_is_bounded_and_older_notes_survive_appends() {
        let messages = history();
        let mut stored = ConversationNotes::new();
        stored
            .append(vec![note_from_args(1, &args("first"), &messages).expect("first")])
            .expect("first append");
        stored
            .append(vec![note_from_args(2, &args("second"), &messages).expect("second")])
            .expect("second append");
        assert_eq!(stored.notes.len(), 2);
        verify(&stored, &messages).expect("both verify");
        let filler: Vec<ModelNote> = (0..MAX_MODEL_NOTES)
            .map(|turn| note_from_args(turn, &args("filler"), &messages).expect("filler"))
            .collect();
        let error = stored.append(filler).expect_err("bound must hold");
        assert!(error.to_string().contains("at most"));
    }
}
