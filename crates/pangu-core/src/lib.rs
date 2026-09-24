//! Shared vocabulary for Pangu Agent.
//!
//! This crate contains data types and infrastructure shared by the boundary,
//! runtime, provider, and toolkit layers. Policy decisions belong in
//! `pangu-boundary`; this crate does not decide whether an action is allowed.

pub mod error;
pub mod events;
pub mod glob;
pub mod journal;
pub mod json;
pub mod messages;
pub mod replay;
pub mod util;

pub use error::{Error, Result};
pub use events::{
    redact_event, redact_text, redact_value, Event, EventKind, EventSink, JournalMeta, MemSink,
    NullSink, Price, TeeSink, Usage,
};
pub use glob::Glob;
pub use journal::{ConsoleSink, Journal};
pub use messages::{ChatResponse, ContentPart, Message, MessageRole};
pub use util::{approx_tokens_of_chars, hex_sha256, now_rfc3339, short_hash, truncate_middle};

/// JSON values used at the provider and policy boundaries.
pub type Value = serde_json::Value;

/// A model request for one tool invocation. It is untrusted until an
/// executor has assessed it and the agent has obtained a verdict.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub args: Value,
}

impl ToolCall {
    pub fn new(name: &str, args: Value) -> Self {
        let id = format!("call_{}", util::short_hash(&format!("{name}{args}")));
        Self {
            id,
            name: name.to_string(),
            args,
        }
    }

    /// Validate the untrusted wire shape before it reaches an adapter or
    /// enters the event/history stream.
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() || self.id.len() > 256 || self.id.chars().any(char::is_control)
        {
            return Err(Error::InvalidArgs {
                tool: safe_tool_label(&self.name),
                detail: "tool call id is empty, too long, or contains control characters".into(),
            });
        }
        if self.name.trim().is_empty()
            || self.name.len() > 128
            || self.name.chars().any(char::is_control)
        {
            return Err(Error::InvalidArgs {
                tool: safe_tool_label(&self.name),
                detail: "tool call name is empty, too long, or contains control characters".into(),
            });
        }
        if !self.args.is_object() {
            return Err(Error::InvalidArgs {
                tool: safe_tool_label(&self.name),
                detail: "tool call arguments must be a JSON object".into(),
            });
        }
        let size = serde_json::to_string(&self.args)?.len();
        if size > 128 * 1024 {
            return Err(Error::InvalidArgs {
                tool: safe_tool_label(&self.name),
                detail: "tool call arguments exceed 128 KiB".into(),
            });
        }
        Ok(())
    }
}

/// Function-calling schema supplied to a provider.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// JSON Schema (a deliberately small draft-07-compatible subset).
    pub parameters: Value,
}

impl ToolSpec {
    pub fn new(name: &str, description: &str, parameters: Value) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            parameters,
        }
    }
}

fn safe_tool_label(name: &str) -> String {
    let redacted = redact_text(name);
    let sanitized = redacted
        .chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect::<String>();
    let bounded = truncate_middle(&sanitized, 128);
    if bounded.trim().is_empty() {
        "invalid_tool".into()
    } else {
        bounded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_call_validation_rejects_untrusted_shapes() {
        let valid = ToolCall::new("read_file", serde_json::json!({"path": "Cargo.toml"}));
        assert!(valid.validate().is_ok());
        assert!(ToolCall {
            id: "c1".into(),
            name: "read_file".into(),
            args: serde_json::json!([]),
        }
        .validate()
        .is_err());
        assert!(ToolCall {
            id: "c1".into(),
            name: "read_file".into(),
            args: serde_json::json!({"path": "x"}),
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn event_redaction_sanitizes_fields_and_keeps_hash_consistent() {
        let event = Event::new(EventKind::Note, 0, "line one\nline two")
            .tool("read_file\n\u{1b}[31m")
            .payload(serde_json::json!({"token": "secret", "ok": true}));
        let event = redact_event(event);
        assert!(!event.message.contains('\n'));
        assert!(!event.tool.as_deref().unwrap_or_default().contains('\u{1b}'));
        assert_eq!(event.payload.as_ref().unwrap()["token"], "[REDACTED]");
        assert_eq!(
            event.sha,
            Event::compute_sha(&event.prev_sha, &event.canonical())
        );
    }
}
