//! MCP (Model Context Protocol) client-side support.
//!
//! # What MCP is here, and what it is not
//!
//! MCP is a **transport and discovery** protocol: a server advertises tools,
//! resources and prompts over JSON-RPC 2.0, and a client calls them. It is not
//! a permission system, and the specification deliberately says nothing about
//! whether a given call should be allowed.
//!
//! Pangu therefore treats an MCP server as one more *tool source*, never as an
//! authority:
//!
//! - Discovered tools appear in the model's tool list **only after** they are
//!   declared in configuration and mapped to a capability. A server cannot add
//!   capability by advertising more tools.
//! - Every invocation travels the ordinary chain: Policy → Sandbox → Approval
//!   → `VerifiedAction` → executor. The MCP client is an executor, not a
//!   shortcut around the boundary.
//! - A server's tool description is **untrusted text**. It is shown to the
//!   model (that is its purpose) but never parsed as policy, never granted
//!   privileges, and never used to build a `VerifiedAction` on its own.
//!
//! # Why the client is written from scratch
//!
//! The reference SDKs bundle server lifecycle, OAuth flows, sampling and
//! notification handling — a large surface whose defaults are "connect to
//! whatever the config names and forward whatever it says". That is the
//! opposite of what a boundary-first agent needs. This implementation is the
//! protocol subset needed to call tools safely, with the boundary decisions
//! kept in Pangu where they can be audited.
//!
//! Deliberately **not** implemented: server-initiated sampling (a server asking
//! the model to generate), server-initiated filesystem or network access,
//! long-lived subscriptions, and automatic reconnection. Each of those grants a
//! remote process a path into the run; none is needed to call a tool.
//!
//! # Protocol versions
//!
//! Requests carry an explicit `protocolVersion`. A server answering with a
//! different version is recorded, not silently accepted: a mismatch can change
//! message shapes, and pretending otherwise would corrupt the audit trail.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{Error, Result};

/// The MCP revision this client speaks.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Identifier for a JSON-RPC message.
///
/// Requests need an id to correlate responses. Ids are per-connection and
/// monotonic, which makes them useful in an audit trail: a gap means a response
/// was lost, and a duplicate means the peer is confused.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    Number(u64),
    Text(String),
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestId::Number(value) => write!(formatter, "{value}"),
            RequestId::Text(value) => write!(formatter, "{value}"),
        }
    }
}

/// Allocates request ids for one connection.
#[derive(Debug)]
pub struct IdAllocator {
    next: AtomicU64,
}

impl IdAllocator {
    pub fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
        }
    }

    pub fn next(&self) -> RequestId {
        RequestId::Number(self.next.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for IdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize)]
pub struct Request {
    pub jsonrpc: &'static str,
    pub id: RequestId,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl Request {
    pub fn new(id: RequestId, method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            method: method.into(),
            params,
        }
    }

    pub fn to_line(&self) -> Result<String> {
        let text = serde_json::to_string(self)?;
        // A newline inside the payload would desynchronise a line-delimited
        // transport, turning one request into two malformed ones. `to_string`
        // escapes real newlines; this guards against a literal control character
        // sneaking through a hand-built `Value`.
        if text.contains('\n') || text.contains('\r') {
            return Err(Error::Config("JSON-RPC frame must be a single line".into()));
        }
        Ok(text)
    }
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "JSON-RPC error {}: {}", self.code, self.message)
    }
}

/// A JSON-RPC 2.0 response, or an inbound notification.
///
/// Notifications carry no id and expect no reply. Server notifications are
/// **accepted and ignored**: acting on them would let a remote process steer
/// the run outside the boundary. They are parsed so that a well-behaved server
/// sending `notifications/message` does not desynchronise the stream.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Incoming {
    Response {
        #[allow(dead_code)]
        jsonrpc: Option<String>,
        id: RequestId,
        #[serde(default)]
        result: Option<Value>,
        #[serde(default)]
        error: Option<RpcError>,
    },
    Notification {
        method: String,
        #[serde(default)]
        params: Option<Value>,
    },
}

impl Incoming {
    /// Parse one frame, rejecting anything that is not valid JSON-RPC 2.0.
    pub fn parse(line: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(line)
            .map_err(|error| Error::Config(format!("MCP frame is not valid JSON: {error}")))?;
        // An object either has an `id` (a response) or a `method` (a
        // notification). Guessing at anything else would misroute a reply.
        let has_id = value.get("id").is_some();
        let has_method = value.get("method").is_some();
        match (has_id, has_method) {
            (true, false) => Ok(Incoming::Response {
                jsonrpc: None,
                id: serde_json::from_value(value["id"].clone()).map_err(|error| {
                    Error::Config(format!("MCP response id is not a string or number: {error}"))
                })?,
                result: value.get("result").cloned(),
                error: value
                    .get("error")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|error| {
                        Error::Config(format!("MCP error object is malformed: {error}"))
                    })?,
            }),
            (false, true) => Ok(Incoming::Notification {
                method: value
                    .get("method")
                    .and_then(|method| method.as_str())
                    .ok_or_else(|| Error::Config("MCP notification has no method name".into()))?
                    .to_string(),
                params: value.get("params").cloned(),
            }),
            (true, true) => Err(Error::Config(
                "MCP frame has both an id and a method, which is neither a response nor a notification"
                    .into(),
            )),
            (false, false) => Err(Error::Config(
                "MCP frame has neither an id nor a method".into(),
            )),
        }
    }

    /// The result value, turning a JSON-RPC error into a Rust error.
    pub fn into_result(self) -> Result<Value> {
        match self {
            Incoming::Response {
                result: Some(result),
                error: None,
                ..
            } => Ok(result),
            Incoming::Response {
                error: Some(error), ..
            } => Err(Error::Config(error.to_string())),
            Incoming::Response { id, .. } => Err(Error::Config(format!(
                "MCP response {id} carried neither a result nor an error"
            ))),
            Incoming::Notification { method, .. } => Err(Error::Config(format!(
                "MCP method `{method}` answered with a notification instead of a result"
            ))),
        }
    }
}

/// A tool advertised by an MCP server.
///
/// `description` is untrusted text destined for the model. It is kept verbatim
/// (truncated at a fixed bound) so the audit trail shows exactly what the model
/// saw, and it is never interpreted by Pangu.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// JSON Schema for the tool's arguments, as the server supplied it.
    #[serde(rename = "inputSchema", default)]
    pub input_schema: Option<Value>,
    /// Behavioural hints. These are **claims by the server**, not guarantees.
    ///
    /// A server can mark a destructive tool `readOnlyHint: true`. Pangu records
    /// the hints for display and never lets them relax Policy: the capability a
    /// tool is mapped to in configuration is what governs, precisely because
    /// this field is server-controlled.
    #[serde(rename = "annotations", default)]
    pub annotations: Option<Value>,
}

/// The `initialize` result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub protocol_version: String,
    pub name: Option<String>,
    pub version: Option<String>,
    /// True when the server answered with a revision this client does not
    /// speak. Callers must surface this rather than proceed silently.
    pub version_mismatch: bool,
}

/// A call result.
#[derive(Debug, Clone, PartialEq)]
pub struct CallOutcome {
    /// Text collected from `content` entries, in order.
    pub text: String,
    /// True when the tool itself reported a failure (`isError`).
    ///
    /// This is a *tool* failure, distinct from a protocol error: the call
    /// succeeded and the tool said no. Conflating them would turn a tool's
    /// honest "I could not do that" into a transport fault.
    pub is_error: bool,
    /// Content entries that were not text, recorded by type so their existence
    /// is visible without embedding them.
    pub non_text: Vec<String>,
}

/// Extract the text of a `tools/call` result.
///
/// Content blocks other than text are recorded by type. Rendering an image or
/// resource block into a tool result would put unbounded server-controlled data
/// where the model reads it, so they are named and dropped.
pub fn read_call_outcome(value: &Value) -> Result<CallOutcome> {
    let is_error = value
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let entries = value
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Config("MCP tools/call result has no content array".into()))?;

    let mut parts: Vec<String> = Vec::new();
    let mut non_text: Vec<String> = Vec::new();
    for entry in entries {
        let kind = entry
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if kind == "text" {
            if let Some(text) = entry.get("text").and_then(Value::as_str) {
                parts.push(text.to_string());
            }
        } else {
            // Deduplicate so a result with 500 images names one type once.
            if !non_text.iter().any(|item| item == kind) {
                non_text.push(kind.to_string());
            }
        }
    }
    Ok(CallOutcome {
        text: parts.join("\n"),
        is_error,
        non_text,
    })
}

/// Read the `initialize` result, flagging a version mismatch.
pub fn read_server_info(value: &Value) -> Result<ServerInfo> {
    let protocol_version = value
        .get("protocolVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Config("MCP initialize result has no protocolVersion".into()))?
        .to_string();
    let info = value.get("serverInfo");
    Ok(ServerInfo {
        version_mismatch: protocol_version != PROTOCOL_VERSION,
        protocol_version,
        name: info
            .and_then(|info| info.get("name"))
            .and_then(Value::as_str)
            .map(str::to_string),
        version: info
            .and_then(|info| info.get("version"))
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

/// Read a `tools/list` result.
pub fn read_tools(value: &Value) -> Result<Vec<McpTool>> {
    let tools = value
        .get("tools")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Config("MCP tools/list result has no tools array".into()))?;
    let mut parsed = Vec::new();
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Config("MCP tool entry has no name".into()))?;
        parsed.push(McpTool {
            name: name.to_string(),
            description: tool
                .get("description")
                .and_then(Value::as_str)
                .map(|text| truncate(text, MAX_DESCRIPTION_BYTES)),
            input_schema: tool.get("inputSchema").cloned(),
            annotations: tool.get("annotations").cloned(),
        });
    }
    Ok(parsed)
}

/// Bound on a server-supplied description kept for display.
///
/// A server controls this string; without a bound it could fill the context
/// window by itself.
pub const MAX_DESCRIPTION_BYTES: usize = 1024;

fn truncate(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    // Truncate on a character boundary, and say so: silently showing half a
    // description would make the audit trail lie about what the model saw.
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… [truncated at {limit} bytes]", &text[..end])
}

/// Build the `initialize` params this client sends.
pub fn initialise_params() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            // No `sampling`, no `roots`: this client neither generates on a
            // server's behalf nor exposes filesystem roots to it. Declaring a
            // capability invites the server to use it.
            "tools": {}
        },
        "clientInfo": {
            "name": "pangu",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

/// Timeout for a single protocol call.
#[derive(Debug, Clone, Copy)]
pub struct McpTimeouts {
    /// How long the server gets to answer `initialize`.
    pub handshake: Duration,
    /// How long a `tools/list` or `tools/call` may take.
    pub call: Duration,
}

impl Default for McpTimeouts {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(20),
            call: Duration::from_secs(120),
        }
    }
}

/// Names of the tools a mapping may reference, keyed by server-local name.
pub type ToolMap = BTreeMap<String, String>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_serialises_to_one_line() {
        let request = Request::new(RequestId::Number(7), "tools/list", None);
        let line = request.to_line().unwrap();
        assert!(!line.contains('\n'), "{line}");
        assert!(line.contains("\"jsonrpc\":\"2.0\""), "{line}");
        assert!(line.contains("\"id\":7"), "{line}");
    }

    #[test]
    fn ids_are_monotonic() {
        let allocator = IdAllocator::new();
        assert_eq!(allocator.next(), RequestId::Number(1));
        assert_eq!(allocator.next(), RequestId::Number(2));
    }

    #[test]
    fn a_response_parses() {
        let parsed = Incoming::parse(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#).unwrap();
        let result = parsed.into_result().unwrap();
        assert_eq!(result["ok"], json!(true));
    }

    #[test]
    fn a_text_id_parses() {
        let parsed = Incoming::parse(r#"{"jsonrpc":"2.0","id":"abc","result":{}}"#).unwrap();
        assert!(parsed.into_result().is_ok());
    }

    #[test]
    fn an_error_response_becomes_an_error() {
        let parsed = Incoming::parse(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method"}}"#,
        )
        .unwrap();
        let error = parsed.into_result().unwrap_err().to_string();
        assert!(error.contains("no such method"), "{error}");
    }

    #[test]
    fn a_notification_parses_and_is_not_a_result() {
        let parsed = Incoming::parse(
            r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}"#,
        )
        .unwrap();
        assert!(matches!(parsed, Incoming::Notification { .. }));
    }

    #[test]
    fn a_frame_that_is_neither_is_refused() {
        // No id and no method: routing it either way would be a guess.
        assert!(Incoming::parse(r#"{"jsonrpc":"2.0"}"#).is_err());
        // Both: ambiguous by construction.
        assert!(Incoming::parse(r#"{"jsonrpc":"2.0","id":1,"method":"x"}"#).is_err());
        // Not JSON at all.
        assert!(Incoming::parse("not json").is_err());
    }

    #[test]
    fn text_content_is_collected_in_order() {
        let value = json!({
            "content": [
                {"type": "text", "text": "first"},
                {"type": "text", "text": "second"}
            ]
        });
        let outcome = read_call_outcome(&value).unwrap();
        assert_eq!(outcome.text, "first\nsecond");
        assert!(!outcome.is_error);
        assert!(outcome.non_text.is_empty());
    }

    #[test]
    fn non_text_content_is_named_but_not_inlined() {
        let value = json!({
            "content": [
                {"type": "image", "data": "AAAA", "mimeType": "image/png"},
                {"type": "image", "data": "BBBB", "mimeType": "image/png"},
                {"type": "resource", "resource": {"uri": "file:///etc/passwd"}}
            ]
        });
        let outcome = read_call_outcome(&value).unwrap();
        assert_eq!(outcome.text, "");
        // Deduplicated, and the payload is absent: an image or resource block
        // must not become tool output the model reads.
        assert_eq!(outcome.non_text, vec!["image", "resource"]);
    }

    #[test]
    fn a_tool_reported_failure_is_not_a_protocol_error() {
        let value = json!({
            "content": [{"type": "text", "text": "could not connect"}],
            "isError": true
        });
        let outcome = read_call_outcome(&value).unwrap();
        assert!(
            outcome.is_error,
            "a tool saying no is a result, not a fault"
        );
        assert_eq!(outcome.text, "could not connect");
    }

    #[test]
    fn a_call_result_without_content_is_refused() {
        assert!(read_call_outcome(&json!({"isError": false})).is_err());
    }

    #[test]
    fn a_version_mismatch_is_flagged_not_hidden() {
        let info = read_server_info(&json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "old-server", "version": "1.0"}
        }))
        .unwrap();
        assert!(info.version_mismatch);
        assert_eq!(info.name.as_deref(), Some("old-server"));
    }

    #[test]
    fn a_matching_version_is_not_flagged() {
        let info = read_server_info(&json!({
            "protocolVersion": PROTOCOL_VERSION,
            "serverInfo": {"name": "server"}
        }))
        .unwrap();
        assert!(!info.version_mismatch);
    }

    #[test]
    fn tools_parse_with_annotations_kept_as_claims() {
        let tools = read_tools(&json!({
            "tools": [{
                "name": "read_file",
                "description": "Read a file",
                "inputSchema": {"type": "object"},
                "annotations": {"readOnlyHint": true}
            }]
        }))
        .unwrap();
        assert_eq!(tools[0].name, "read_file");
        // The hint is preserved verbatim for display, and is not authority.
        assert_eq!(
            tools[0].annotations.as_ref().unwrap()["readOnlyHint"],
            json!(true)
        );
    }

    #[test]
    fn an_overlong_description_is_truncated_visibly() {
        let long = "x".repeat(MAX_DESCRIPTION_BYTES * 2);
        let tools = read_tools(&json!({
            "tools": [{"name": "t", "description": long}]
        }))
        .unwrap();
        let description = tools[0].description.as_ref().unwrap();
        assert!(description.contains("truncated"), "{description}");
        assert!(
            description.len() < long.len(),
            "the bound must actually bound"
        );
    }

    #[test]
    fn truncation_respects_character_boundaries() {
        // Multi-byte characters must not be split into invalid UTF-8.
        let text = "é".repeat(MAX_DESCRIPTION_BYTES);
        let tools = read_tools(&json!({
            "tools": [{"name": "t", "description": text}]
        }))
        .unwrap();
        assert!(tools[0].description.is_some());
    }

    #[test]
    fn initialise_never_declares_sampling_or_roots() {
        let params = initialise_params();
        let capabilities = &params["capabilities"];
        assert!(capabilities.get("sampling").is_none());
        assert!(capabilities.get("roots").is_none());
        assert_eq!(params["protocolVersion"], json!(PROTOCOL_VERSION));
    }
}
