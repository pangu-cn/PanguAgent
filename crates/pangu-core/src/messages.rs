use serde::{Deserialize, Serialize};

use crate::{ToolCall, Usage};

/// Messages exchanged with a provider. Tool results are represented as
/// `Tool` messages rather than being folded into assistant text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "lowercase")]
pub enum Message {
    System {
        content: String,
    },
    User {
        content: String,
    },
    Assistant {
        content: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tool_calls: Vec<ToolCall>,
    },
    Tool {
        call_id: String,
        name: String,
        content: String,
        #[serde(default)]
        is_error: bool,
    },
}

impl Message {
    pub fn system(content: impl Into<String>) -> Self {
        Self::System {
            content: content.into(),
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self::User {
            content: content.into(),
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self::Assistant {
            content: content.into(),
            tool_calls: Vec::new(),
        }
    }

    pub fn assistant_calls(content: impl Into<String>, tool_calls: Vec<ToolCall>) -> Self {
        Self::Assistant {
            content: content.into(),
            tool_calls,
        }
    }

    pub fn tool_result(
        call_id: impl Into<String>,
        name: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        Self::Tool {
            call_id: call_id.into(),
            name: name.into(),
            content: content.into(),
            is_error: false,
        }
    }

    pub fn tool_error(
        call_id: impl Into<String>,
        name: impl Into<String>,
        err: &crate::Error,
    ) -> Self {
        let message = crate::redact_text(&err.to_string());
        let message = crate::truncate_middle(&message, 16 * 1024);
        Self::Tool {
            call_id: call_id.into(),
            name: name.into(),
            content: serde_json::json!({"error": message, "code": err.code()}).to_string(),
            is_error: true,
        }
    }

    pub fn role(&self) -> MessageRole {
        match self {
            Self::System { .. } => MessageRole::System,
            Self::User { .. } => MessageRole::User,
            Self::Assistant { .. } => MessageRole::Assistant,
            Self::Tool { .. } => MessageRole::Tool,
        }
    }

    pub fn char_len(&self) -> usize {
        match self {
            Self::System { content } | Self::User { content } => content.len(),
            Self::Assistant {
                content,
                tool_calls,
            } => {
                content.len()
                    + tool_calls
                        .iter()
                        .map(|call| {
                            call.name.len()
                                + serde_json::to_string(&call.args)
                                    .map(|s| s.len())
                                    .unwrap_or(0)
                        })
                        .sum::<usize>()
            }
            Self::Tool { content, .. } => content.len(),
        }
    }

    pub fn approx_tokens(&self) -> u64 {
        crate::util::approx_tokens_of_chars(self.char_len() as u64)
    }
}

/// A typed response from a provider adapter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatResponse {
    pub messages: Vec<Message>,
    pub usage: Usage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    Text { text: String },
}

impl ContentPart {
    pub fn text(&self) -> &str {
        match self {
            Self::Text { text } => text,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_messages_round_trip() {
        let message = Message::tool_result("c1", "read_file", "hello");
        let encoded = serde_json::to_string(&message).unwrap();
        let decoded: Message = serde_json::from_str(&encoded).unwrap();
        assert_eq!(message, decoded);
    }
}
