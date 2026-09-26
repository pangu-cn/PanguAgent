use serde::{Deserialize, Serialize};

use crate::{Error, Result, Value};

pub const JOURNAL_FORMAT_V1: &str = "pangu-journal/v1";
pub const JOURNAL_FORMAT_V2: &str = "pangu-journal/v2";

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
    CheckpointCreated,
    CheckpointFailed,
    RollbackRequested,
    RollbackStarted,
    RollbackApplied,
    RollbackSkippedAlreadyApplied,
    RollbackFailed,
    FailedPathRecorded,
}

impl EventKind {
    pub fn is_v2_only(self) -> bool {
        matches!(
            self,
            Self::CheckpointCreated
                | Self::CheckpointFailed
                | Self::RollbackRequested
                | Self::RollbackStarted
                | Self::RollbackApplied
                | Self::RollbackSkippedAlreadyApplied
                | Self::RollbackFailed
                | Self::FailedPathRecorded
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub seq: u64,
    pub at: String,
    pub kind: EventKind,
    /// Stable identifier assigned when a v2 event is sealed by Journal.
    /// Legacy v1 records omit this field and retain their original hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// Absent means the legacy `pangu-journal/v1` format. v2 records carry
    /// an explicit format marker so unknown schemas fail closed on replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reversibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_mutation: Option<bool>,
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
            event_id: None,
            schema: None,
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
            effect_scope: None,
            reversibility: None,
            action_digest: None,
            external_mutation: None,
            prev_sha: String::new(),
            sha: String::new(),
        }
    }

    pub fn new_v2(kind: EventKind, turn: u32, message: impl Into<String>) -> Self {
        let mut event = Self::new(kind, turn, message);
        event.schema = Some(JOURNAL_FORMAT_V2.to_string());
        event
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

    pub fn effect_scope(mut self, scope: impl Into<String>) -> Self {
        self.effect_scope = Some(crate::truncate_middle(
            &redact_text(&scope.into()),
            MAX_EVENT_FIELD_BYTES,
        ));
        self
    }

    pub fn reversibility(mut self, reversibility: impl Into<String>) -> Self {
        self.reversibility = Some(crate::truncate_middle(
            &redact_text(&reversibility.into()),
            MAX_EVENT_FIELD_BYTES,
        ));
        self
    }

    pub fn action_digest(mut self, digest: impl Into<String>) -> Self {
        self.action_digest = Some(crate::truncate_middle(
            &redact_text(&digest.into()),
            MAX_EVENT_FIELD_BYTES,
        ));
        self
    }

    pub fn external_mutation(mut self, value: bool) -> Self {
        self.external_mutation = Some(value);
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

    /// Validate a stable v2 event receipt independently of a particular
    /// journal implementation. This is used by checkpoint code before it
    /// trusts a sink-provided event as the source of an artifact.
    pub fn validate_v2_receipt(&self) -> Result<()> {
        self.validate_shape()?;
        if self.schema.as_deref() != Some(JOURNAL_FORMAT_V2)
            || self.prev_sha.is_empty()
            || self.sha.is_empty()
        {
            return Err(Error::Config(
                "event is not a complete pangu-journal/v2 receipt".into(),
            ));
        }
        crate::replay::validate_v2_metadata(self)?;
        let event_id = self
            .event_id
            .as_deref()
            .ok_or_else(|| Error::Config("v2 event is missing event_id".into()))?;
        let mut identity_event = self.clone();
        identity_event.event_id = None;
        let identity = format!("event-id:{}:{}", self.seq, identity_event.canonical());
        let expected_event_id = format!("evt_{}", Self::compute_sha(&self.prev_sha, &identity));
        if event_id != expected_event_id {
            return Err(Error::Config("v2 event_id receipt is invalid".into()));
        }
        if self.sha != Self::compute_sha(&self.prev_sha, &self.canonical()) {
            return Err(Error::Config("v2 event content receipt is invalid".into()));
        }
        Ok(())
    }

    /// Validate the bounded wire shape of an event before it is persisted or
    /// replayed. Content redaction is deliberately separate: callers may
    /// construct a large/sensitive event, but sinks must sanitize it first
    /// and replay must reject any record that bypassed that boundary.
    pub(crate) fn validate_shape(&self) -> Result<()> {
        validate_event_text("at", &self.at, MAX_EVENT_FIELD_BYTES)?;
        validate_event_text("message", &self.message, MAX_EVENT_MESSAGE_BYTES)?;
        for (field, value) in [
            ("tool", self.tool.as_deref()),
            ("call_id", self.call_id.as_deref()),
            ("verdict", self.verdict.as_deref()),
            ("risk", self.risk.as_deref()),
            ("rule_id", self.rule_id.as_deref()),
            ("invariant", self.invariant.as_deref()),
            ("effect_scope", self.effect_scope.as_deref()),
            ("reversibility", self.reversibility.as_deref()),
            ("action_digest", self.action_digest.as_deref()),
        ] {
            if let Some(value) = value {
                validate_event_text(field, value, MAX_EVENT_FIELD_BYTES)?;
            }
        }
        if self.event_id.as_deref().is_some_and(|id| {
            !id.strip_prefix("evt_").is_some_and(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        }) {
            return Err(Error::Config(
                "event_id is not a stable v2 identifier".into(),
            ));
        }
        if self.prev_sha.len() > 128 || self.sha.len() > 128 {
            return Err(Error::Config(
                "event hash fields exceed the supported bound".into(),
            ));
        }
        if !self.prev_sha.is_empty()
            && self.prev_sha != crate::journal::GENESIS
            && (self.prev_sha.len() != 64
                || !self.prev_sha.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(Error::Config(
                "event prev_sha is not a SHA-256 digest".into(),
            ));
        }
        if !self.sha.is_empty()
            && (self.sha.len() != 64 || !self.sha.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(Error::Config("event sha is not a SHA-256 digest".into()));
        }
        if let Some(payload) = &self.payload {
            let size = serde_json::to_string(payload)?.len();
            if size > MAX_EVENT_PAYLOAD_BYTES {
                return Err(Error::Config(
                    "event payload exceeds the supported bound".into(),
                ));
            }
        }
        match self.schema.as_deref() {
            None | Some(JOURNAL_FORMAT_V1) | Some(JOURNAL_FORMAT_V2) => {}
            Some(other) => {
                return Err(Error::Config(format!(
                    "unsupported journal event schema `{other}`"
                )))
            }
        }
        Ok(())
    }
}

fn validate_event_text(field: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.chars().any(|character| character.is_control())
    {
        return Err(Error::Config(format!(
            "event {field} is empty, unbounded, or contains control characters"
        )));
    }
    Ok(())
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
    let preserve_v2_receipt = event.schema.as_deref() == Some(JOURNAL_FORMAT_V2)
        && event.event_id.is_some()
        && event.validate_v2_receipt().is_ok();
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
    if let Some(event_id) = event.event_id.as_mut() {
        *event_id = clean_event_field(event_id, MAX_EVENT_FIELD_BYTES);
    }
    if let Some(schema) = event.schema.as_mut() {
        *schema = clean_event_field(schema, MAX_EVENT_FIELD_BYTES);
    }
    if let Some(scope) = event.effect_scope.as_mut() {
        *scope = clean_event_field(scope, MAX_EVENT_FIELD_BYTES);
    }
    if let Some(reversibility) = event.reversibility.as_mut() {
        *reversibility = clean_event_field(reversibility, MAX_EVENT_FIELD_BYTES);
    }
    if let Some(digest) = event.action_digest.as_mut() {
        *digest = clean_event_field(digest, MAX_EVENT_FIELD_BYTES);
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
    if preserve_v2_receipt {
        let mut identity_event = event.clone();
        identity_event.event_id = None;
        let identity = format!("event-id:{}:{}", event.seq, identity_event.canonical());
        event.event_id = Some(format!(
            "evt_{}",
            Event::compute_sha(&event.prev_sha, &identity)
        ));
    }
    event.refresh_sha();
    event
}

#[async_trait::async_trait]
pub trait EventSink: Send + Sync {
    /// Persist one event. Implementations must return an error to the caller;
    /// an audit failure may not be silently converted into a successful run.
    async fn emit(&self, event: Event) -> Result<()>;

    /// Persist an event and return the sealed receipt when the sink has one.
    /// Older sinks keep working through the default implementation; a
    /// journal-backed sink overrides it with the stable v2 event ID/sequence.
    async fn emit_with_receipt(&self, event: Event) -> Result<Event> {
        self.emit(event.clone()).await?;
        Ok(redact_event(event))
    }
}

pub struct NullSink;

#[async_trait::async_trait]
impl EventSink for NullSink {
    async fn emit(&self, _event: Event) -> Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct MemState {
    events: Vec<Event>,
    seq: u64,
    prev_sha: String,
    format: Option<String>,
}

pub struct MemSink {
    state: std::sync::Mutex<MemState>,
}

impl Default for MemSink {
    fn default() -> Self {
        Self {
            state: std::sync::Mutex::new(MemState {
                events: Vec::new(),
                seq: 0,
                prev_sha: crate::journal::GENESIS.to_string(),
                format: None,
            }),
        }
    }
}

impl MemSink {
    pub fn snapshot(&self) -> Vec<Event> {
        self.state.lock().expect("mem sink lock").events.clone()
    }

    pub fn kinds(&self) -> Vec<EventKind> {
        self.snapshot()
            .into_iter()
            .map(|event| event.kind)
            .collect()
    }

    fn seal_and_push(&self, event: Event) -> Result<Event> {
        let mut state = self.state.lock().expect("mem sink lock");
        if state.seq == u64::MAX {
            return Err(Error::Other("memory event sequence is exhausted".into()));
        }
        let format = match event.schema.as_deref() {
            None | Some(JOURNAL_FORMAT_V1) => JOURNAL_FORMAT_V1,
            Some(JOURNAL_FORMAT_V2) => JOURNAL_FORMAT_V2,
            Some(other) => {
                return Err(Error::Config(format!(
                    "unsupported journal event schema `{other}`"
                )))
            }
        };
        if let Some(existing) = &state.format {
            if existing != format {
                return Err(Error::Config(
                    "memory sink cannot mix v1 and v2 event schemas".into(),
                ));
            }
        }
        if format == JOURNAL_FORMAT_V1 && event.kind.is_v2_only() {
            return Err(Error::Config(
                "v2-only event cannot be written to a v1 memory sink".into(),
            ));
        }
        let mut sealed = redact_event(event);
        sealed.event_id = None;
        if format == JOURNAL_FORMAT_V1 {
            // Keep the richer in-memory shape for legacy embedders. The
            // on-disk Journal strips these fields before writing v1; MemSink
            // is not a serialized journal and existing callers rely on the
            // richer receipt.
            sealed.schema = None;
        } else {
            sealed.schema = Some(JOURNAL_FORMAT_V2.to_string());
            crate::replay::validate_v2_metadata(&sealed)?;
        }
        sealed.seq = state.seq;
        sealed.prev_sha = state.prev_sha.clone();
        sealed.validate_shape()?;
        if format == JOURNAL_FORMAT_V2 {
            let identity = format!("event-id:{}:{}", state.seq, sealed.canonical());
            sealed.event_id = Some(format!(
                "evt_{}",
                Event::compute_sha(&state.prev_sha, &identity)
            ));
        }
        sealed.sha = Event::compute_sha(&sealed.prev_sha, &sealed.canonical());
        state.events.push(sealed.clone());
        state.seq = state.seq.saturating_add(1);
        state.prev_sha = sealed.sha.clone();
        state.format = Some(format.to_string());
        Ok(sealed)
    }
}

#[async_trait::async_trait]
impl EventSink for MemSink {
    async fn emit(&self, event: Event) -> Result<()> {
        self.seal_and_push(event).map(|_| ())
    }

    async fn emit_with_receipt(&self, event: Event) -> Result<Event> {
        self.seal_and_push(event)
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
        // Use the receipt path even for callers that do not need the returned
        // event. Otherwise two durable sinks could silently diverge merely by
        // going through the legacy `emit` method.
        self.emit_with_receipt(event).await.map(|_| ())
    }

    async fn emit_with_receipt(&self, event: Event) -> Result<Event> {
        let mut receipt: Option<Event> = None;
        for sink in &self.sinks {
            let candidate = sink.emit_with_receipt(redact_event(event.clone())).await?;
            candidate.validate_shape()?;
            if candidate.schema.as_deref() == Some(JOURNAL_FORMAT_V2)
                && candidate.event_id.is_some()
            {
                candidate.validate_v2_receipt()?;
            }
            if let Some(previous) = &receipt {
                if let (Some(previous_id), Some(candidate_id)) =
                    (previous.event_id.as_deref(), candidate.event_id.as_deref())
                {
                    if previous.schema != candidate.schema
                        || previous.seq != candidate.seq
                        || previous.prev_sha != candidate.prev_sha
                        || previous.sha != candidate.sha
                        || previous_id != candidate_id
                    {
                        return Err(Error::Other(
                            "event tee durable receipts are inconsistent".into(),
                        ));
                    }
                }
            }
            if receipt.is_none() || candidate.event_id.is_some() {
                receipt = Some(candidate);
            }
        }
        receipt.ok_or_else(|| Error::Other("event tee has no sinks".into()))
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
    pub const FORMAT: &'static str = JOURNAL_FORMAT_V1;
    pub const FORMAT_V2: &'static str = JOURNAL_FORMAT_V2;

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }

    pub fn to_value_for_format(&self, format: &str) -> Value {
        let mut value = self.to_value();
        if let Value::Object(object) = &mut value {
            object.insert("format".into(), Value::String(format.to_string()));
        }
        value
    }
}

/// Convert an I/O failure into a core error without losing its source.
pub fn io_error(error: std::io::Error) -> Error {
    Error::Io(error)
}
