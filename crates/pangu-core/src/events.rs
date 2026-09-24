use serde::{Deserialize, Serialize};

use crate::{Error, Result, Value};

const MAX_EVENT_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_EVENT_FIELD_BYTES: usize = 4 * 1024;
const MAX_EVENT_PAYLOAD_BYTES: usize = 256 * 1024;
const MAX_REDACT_INPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    RunStarted,
    TurnStarted,
    ModelRequest,
    ModelResponse,
    ToolRequested,
    PolicyDecision,
    ApprovalRequested,
    ApprovalResolved,
    ToolStarted,
    ToolBlocked,
    ToolFinished,
    BudgetExhausted,
    FinishRequested,
    RunFinished,
    Note,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub seq: u64,
    pub at: String,
    pub kind: EventKind,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(default)]
    pub prev_sha: String,
    #[serde(default)]
    pub sha: String,
}

impl Event {
    pub fn new(kind: EventKind, turn: u32, message: impl Into<String>) -> Self {
        let message = redact_text(&message.into());
        let message = crate::truncate_middle(&message, MAX_EVENT_MESSAGE_BYTES);
        Self {
            seq: 0,
            at: crate::now_rfc3339(),
            kind,
            turn,
            message,
            tool: None,
            call_id: None,
            verdict: None,
            risk: None,
            rule_id: None,
            invariant: None,
            duration_ms: None,
            usage: None,
            payload: None,
            prev_sha: String::new(),
            sha: String::new(),
        }
    }

    pub fn tool(mut self, tool: &str) -> Self {
        self.tool = Some(crate::truncate_middle(tool, MAX_EVENT_FIELD_BYTES));
        self
    }

    pub fn call_id(mut self, id: &str) -> Self {
        self.call_id = Some(crate::truncate_middle(id, MAX_EVENT_FIELD_BYTES));
        self
    }

    pub fn verdict(mut self, verdict: impl Into<String>) -> Self {
        self.verdict = Some(crate::truncate_middle(
            &verdict.into(),
            MAX_EVENT_FIELD_BYTES,
        ));
        self
    }

    pub fn risk(mut self, risk: impl Into<String>) -> Self {
        self.risk = Some(crate::truncate_middle(&risk.into(), MAX_EVENT_FIELD_BYTES));
        self
    }

    pub fn rule(mut self, id: &str) -> Self {
        self.rule_id = Some(crate::truncate_middle(id, MAX_EVENT_FIELD_BYTES));
        self
    }

    pub fn invariant(mut self, id: &str) -> Self {
        self.invariant = Some(crate::truncate_middle(id, MAX_EVENT_FIELD_BYTES));
        self
    }

    pub fn duration(mut self, ms: u64) -> Self {
        self.duration_ms = Some(ms);
        self
    }

    pub fn usage(mut self, usage: Usage) -> Self {
        self.usage = Some(usage);
        self
    }

    pub fn payload(mut self, value: Value) -> Self {
        let value = redact_value(&value);
        let size = serde_json::to_string(&value)
            .map(|text| text.len())
            .unwrap_or(MAX_EVENT_PAYLOAD_BYTES);
        self.payload = Some(if size > MAX_EVENT_PAYLOAD_BYTES {
            serde_json::json!({"truncated": true})
        } else {
            value
        });
        self
    }

    /// Canonical JSON used by the journal hash chain. Object keys are sorted
    /// recursively so a downstream `serde_json/preserve_order` feature cannot
    /// change the hash representation.
    pub fn canonical(&self) -> String {
        let mut value = serde_json::to_value(self).unwrap_or(Value::Null);
        if let Value::Object(map) = &mut value {
            map.remove("sha");
        }
        serde_json::to_string(&sort_json(value)).unwrap_or_else(|_| "null".to_string())
    }

    pub fn refresh_sha(&mut self) {
        self.sha = Self::compute_sha(&self.prev_sha, &self.canonical());
    }

    pub fn compute_sha(previous: &str, canonical: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(previous.as_bytes());
        hasher.update([0u8]);
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }
}

fn clean_event_field(input: &str, max_bytes: usize) -> String {
    let redacted = redact_text(input);
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
    crate::truncate_middle(&sanitized, max_bytes)
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Object(mut map) => {
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            let mut sorted = serde_json::Map::new();
            for key in keys {
                if let Some(value) = map.remove(&key) {
                    sorted.insert(key, sort_json(value));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        other => other,
    }
}

fn sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "key",
        "token",
        "secret",
        "password",
        "passwd",
        "authorization",
        "credential",
        "cookie",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

pub fn redact_text(input: &str) -> String {
    let input = if input.len() > MAX_REDACT_INPUT_BYTES {
        crate::util::floor_char_boundary(input, MAX_REDACT_INPUT_BYTES)
    } else {
        input.to_string()
    };
    let lower = input.to_ascii_lowercase();
    let markers = [
        "authorization:",
        "bearer ",
        "api_key=",
        "api_key:",
        "api_key ",
        "api-key=",
        "api-key:",
        "api-key ",
        "apikey=",
        "apikey:",
        "apikey ",
        "x-api-key=",
        "x-api-key:",
        "password=",
        "password:",
        "password ",
        "passwd=",
        "passwd:",
        "token=",
        "token:",
        "token ",
        "secret=",
        "secret:",
        "secret ",
        "secret_",
        "access_key=",
        "access_key:",
        "client_secret=",
        "client_secret:",
        "private_key=",
        "private_key:",
        "sk-",
        "ghp_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "aiza-",
    ];
    if markers.iter().any(|marker| lower.contains(marker)) {
        "[REDACTED]".to_string()
    } else {
        input.to_string()
    }
}

pub fn redact_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, value) in map {
                if sensitive_key(key) {
                    out.insert(key.clone(), Value::String("[REDACTED]".into()));
                } else {
                    out.insert(key.clone(), redact_value(value));
                }
            }
            Value::Object(out)
        }
        Value::Array(values) => Value::Array(values.iter().map(redact_value).collect()),
        Value::String(value) => Value::String(crate::truncate_middle(
            &redact_text(value),
            MAX_EVENT_PAYLOAD_BYTES,
        )),
        other => other.clone(),
    }
}

pub fn redact_event(mut event: Event) -> Event {
    event.at = clean_event_field(&event.at, MAX_EVENT_FIELD_BYTES);
    event.message = clean_event_field(&event.message, MAX_EVENT_MESSAGE_BYTES);
    event.prev_sha = crate::truncate_middle(&event.prev_sha, 128);
    event.sha = crate::truncate_middle(&event.sha, 128);
    if let Some(tool) = event.tool.as_mut() {
        *tool = clean_event_field(tool, MAX_EVENT_FIELD_BYTES);
    }
    if let Some(call_id) = event.call_id.as_mut() {
        *call_id = clean_event_field(call_id, MAX_EVENT_FIELD_BYTES);
    }
    if let Some(verdict) = event.verdict.as_mut() {
        *verdict = clean_event_field(verdict, MAX_EVENT_FIELD_BYTES);
    }
    if let Some(risk) = event.risk.as_mut() {
        *risk = clean_event_field(risk, MAX_EVENT_FIELD_BYTES);
    }
    if let Some(rule_id) = event.rule_id.as_mut() {
        *rule_id = clean_event_field(rule_id, MAX_EVENT_FIELD_BYTES);
    }
    if let Some(invariant) = event.invariant.as_mut() {
        *invariant = clean_event_field(invariant, MAX_EVENT_FIELD_BYTES);
    }
    event.payload = event.payload.as_ref().map(|value| {
        let value = redact_value(value);
        let size = serde_json::to_string(&value)
            .map(|text| text.len())
            .unwrap_or(MAX_EVENT_PAYLOAD_BYTES);
        if size > MAX_EVENT_PAYLOAD_BYTES {
            serde_json::json!({"truncated": true})
        } else {
            value
        }
    });
    event.refresh_sha();
    event
}

#[async_trait::async_trait]
pub trait EventSink: Send + Sync {
    /// Persist one event. Implementations must return an error to the caller;
    /// an audit failure may not be silently converted into a successful run.
    async fn emit(&self, event: Event) -> Result<()>;
}

pub struct NullSink;

#[async_trait::async_trait]
impl EventSink for NullSink {
    async fn emit(&self, _event: Event) -> Result<()> {
        Ok(())
    }
}

#[derive(Default)]
pub struct MemSink {
    events: std::sync::Mutex<Vec<Event>>,
}

impl MemSink {
    pub fn snapshot(&self) -> Vec<Event> {
        self.events.lock().expect("mem sink lock").clone()
    }

    pub fn kinds(&self) -> Vec<EventKind> {
        self.snapshot()
            .into_iter()
            .map(|event| event.kind)
            .collect()
    }
}

#[async_trait::async_trait]
impl EventSink for MemSink {
    async fn emit(&self, event: Event) -> Result<()> {
        self.events
            .lock()
            .expect("mem sink lock")
            .push(redact_event(event));
        Ok(())
    }
}

pub struct TeeSink {
    sinks: Vec<std::sync::Arc<dyn EventSink>>,
}

impl TeeSink {
    pub fn new(sinks: Vec<std::sync::Arc<dyn EventSink>>) -> Self {
        Self { sinks }
    }
}

#[async_trait::async_trait]
impl EventSink for TeeSink {
    async fn emit(&self, event: Event) -> Result<()> {
        for sink in &self.sinks {
            sink.emit(redact_event(event.clone())).await?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub input_tokens: u64,
    #[serde(default)]
    pub output_tokens: u64,
    #[serde(default)]
    pub cache_read_tokens: u64,
}

impl Usage {
    pub fn total(&self) -> u64 {
        self.input_tokens
            .saturating_add(self.output_tokens)
            .saturating_add(self.cache_read_tokens)
    }

    pub fn merge(&mut self, other: &Usage) {
        self.input_tokens = self.input_tokens.saturating_add(other.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(other.output_tokens);
        self.cache_read_tokens = self
            .cache_read_tokens
            .saturating_add(other.cache_read_tokens);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Price {
    pub input_usd_per_mtok: f64,
    pub output_usd_per_mtok: f64,
}

impl Price {
    pub fn zero() -> Self {
        Self {
            input_usd_per_mtok: 0.0,
            output_usd_per_mtok: 0.0,
        }
    }

    pub fn cost_usd(&self, usage: &Usage) -> f64 {
        (usage.input_tokens as f64 / 1_000_000.0) * self.input_usd_per_mtok
            + (usage.output_tokens as f64 / 1_000_000.0) * self.output_usd_per_mtok
            + (usage.cache_read_tokens as f64 / 1_000_000.0) * self.input_usd_per_mtok
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalMeta {
    pub format: String,
    pub agent_version: String,
    pub model: String,
    pub workspace: String,
    pub goal: String,
    pub boundary_digest: String,
    pub unattended: bool,
    #[serde(default)]
    pub config_files: Vec<String>,
}

impl JournalMeta {
    pub const FORMAT: &'static str = "pangu-journal/v1";

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// Convert an I/O failure into a core error without losing its source.
pub fn io_error(error: std::io::Error) -> Error {
    Error::Io(error)
}
