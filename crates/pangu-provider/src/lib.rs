//! Provider adapters. This crate translates typed messages to an explicit
//! OpenAI-compatible API and translates the response back to core messages.
//!
//! Multiple API keys may rotate across requests: every operator-supplied list
//! (environment variable names in config, resolved keys in memory) is bounded
//! and validated, and each `chat` call takes the next key in order. The keys
//! themselves never leave this crate's request headers.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::{json, Value};
use url::Url;

use pangu_agent::Provider;
use pangu_core::{ChatResponse, Message, ToolCall, ToolSpec, Usage};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Upper bound on how many API keys one provider may rotate across. Rotation
/// exists to spread quota across a few keys, not to hold an unbounded keyring;
/// every operator-supplied list is bounded (I-Effect-Bounded).
pub const MAX_API_KEYS: usize = 16;

pub struct OpenAiCompatibleProvider {
    model: String,
    base_url: String,
    /// Zero or more bearer keys, rotated one per request. An empty list means
    /// the endpoint needs no authentication (e.g. local ollama).
    api_keys: Vec<String>,
    /// Round-robin cursor; the Nth request uses key `N mod api_keys.len()`.
    cursor: AtomicUsize,
    temperature: Option<f32>,
    max_output_tokens: Option<u32>,
    client: reqwest::Client,
}

/// Clone is manual because the rotation cursor is an atomic: a clone starts
/// its own rotation from the first key instead of sharing the cursor.
impl Clone for OpenAiCompatibleProvider {
    fn clone(&self) -> Self {
        Self {
            model: self.model.clone(),
            base_url: self.base_url.clone(),
            api_keys: self.api_keys.clone(),
            cursor: AtomicUsize::new(0),
            temperature: self.temperature,
            max_output_tokens: self.max_output_tokens,
            client: self.client.clone(),
        }
    }
}

impl OpenAiCompatibleProvider {
    pub fn new(
        model: impl Into<String>,
        base_url: impl Into<String>,
        api_key: Option<String>,
        temperature: Option<f32>,
        max_output_tokens: Option<u32>,
        timeout_secs: u64,
    ) -> Result<Self> {
        Self::with_keys(
            model,
            base_url,
            api_key.into_iter().collect(),
            temperature,
            max_output_tokens,
            timeout_secs,
        )
    }

    /// Multi-key constructor: successive `chat` calls rotate across `api_keys`
    /// in declaration order. Everything else matches [`Self::new`].
    pub fn with_keys(
        model: impl Into<String>,
        base_url: impl Into<String>,
        api_keys: Vec<String>,
        temperature: Option<f32>,
        max_output_tokens: Option<u32>,
        timeout_secs: u64,
    ) -> Result<Self> {
        let model = model.into();
        if model.trim().is_empty() || model.len() > 256 || model.chars().any(char::is_control) {
            bail!("model must be non-empty, bounded, and contain no control characters");
        }
        if api_keys.len() > MAX_API_KEYS {
            bail!("at most {MAX_API_KEYS} API keys are supported per provider");
        }
        for key in &api_keys {
            validate_api_key(key)?;
        }
        let base_url = normalize_base_url(base_url.into())?;
        if let Some(value) = temperature {
            if !value.is_finite() || !(0.0..=2.0).contains(&value) {
                bail!("temperature must be finite and between 0 and 2");
            }
        }
        if max_output_tokens == Some(0) {
            bail!("max_output_tokens must be > 0");
        }
        if timeout_secs == 0 {
            bail!("timeout_secs must be > 0");
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(timeout_secs))
            .build()?;
        Ok(Self {
            model,
            base_url,
            api_keys,
            cursor: AtomicUsize::new(0),
            temperature,
            max_output_tokens,
            client,
        })
    }

    pub fn from_env(
        model: impl Into<String>,
        base_url: impl Into<String>,
        api_key_env: Option<&str>,
        temperature: Option<f32>,
        max_output_tokens: Option<u32>,
        timeout_secs: u64,
    ) -> Result<Self> {
        let api_keys = match api_key_env {
            Some(name) => resolve_api_keys(&[name])?,
            None => Vec::new(),
        };
        Self::with_keys(
            model,
            base_url,
            api_keys,
            temperature,
            max_output_tokens,
            timeout_secs,
        )
    }

    /// Multi-name variant of [`Self::from_env`]: every name is resolved from
    /// the process environment (unset or invalid fails the whole set — a
    /// half-resolved keyring would fail mid-run) and requests then rotate
    /// across the resolved keys in declaration order.
    pub fn from_envs(
        model: impl Into<String>,
        base_url: impl Into<String>,
        api_key_envs: &[String],
        temperature: Option<f32>,
        max_output_tokens: Option<u32>,
        timeout_secs: u64,
    ) -> Result<Self> {
        Self::with_keys(
            model,
            base_url,
            resolve_api_keys(api_key_envs)?,
            temperature,
            max_output_tokens,
            timeout_secs,
        )
    }

    /// Round-robin across the configured keys. A single-key provider (the CLI
    /// path) always uses that key; an empty list sends no Authorization header.
    fn next_api_key(&self) -> Option<&str> {
        let count = self.api_keys.len();
        if count == 0 {
            return None;
        }
        let index = self.cursor.fetch_add(1, Ordering::Relaxed) % count;
        self.api_keys.get(index).map(String::as_str)
    }
}

#[async_trait]
impl Provider for OpenAiCompatibleProvider {
    fn name(&self) -> &str {
        "openai-compatible"
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn describe(&self) -> String {
        format!(
            "{name} model={model} endpoint={base_url}",
            name = self.name(),
            model = self.model,
            base_url = self.base_url
        )
    }

    async fn chat(&self, messages: Vec<Message>, tools: Vec<ToolSpec>) -> Result<ChatResponse> {
        let wire_messages = messages.iter().map(message_to_wire).collect::<Vec<_>>();
        let wire_tools = tools
            .iter()
            .map(|tool| {
                json!({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.parameters,
                    }
                })
            })
            .collect::<Vec<_>>();
        let mut body = json!({
            "model": self.model,
            "messages": wire_messages,
            "tools": wire_tools,
            "tool_choice": "auto",
        });
        if let Some(temperature) = self.temperature {
            body["temperature"] = json!(temperature);
        }
        if let Some(max_tokens) = self.max_output_tokens {
            body["max_tokens"] = json!(max_tokens);
        }

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(key) = self.next_api_key() {
            let mut value = HeaderValue::from_str(&format!("Bearer {key}"))
                .map_err(|_| anyhow!("invalid API key value"))?;
            value.set_sensitive(true);
            headers.insert(AUTHORIZATION, value);
        }
        let mut response = self
            .client
            .post(format!("{}/chat/completions", self.base_url))
            .headers(headers)
            .json(&body)
            .send()
            .await
            .context("provider request failed")?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("provider response stream failed")?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                bail!("provider response exceeds {MAX_RESPONSE_BYTES} bytes");
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            bail!("provider returned HTTP {status}");
        }
        let value: Value =
            serde_json::from_slice(&bytes).context("provider returned invalid JSON")?;
        parse_response(&value)
    }
}

fn validate_api_key(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 4_096 || value.chars().any(char::is_control) {
        bail!("invalid API key value");
    }
    Ok(())
}

/// Validate one environment variable *name* before it is looked up: bounded,
/// no control characters, no `=` (which would make it two variables).
fn validate_env_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 256 || name.chars().any(|c| c.is_control() || c == '=') {
        bail!("invalid API key environment variable name");
    }
    Ok(())
}

/// Normalize declared environment variable names: validate each, reject more
/// than [`MAX_API_KEYS`] names, and collapse duplicates (first occurrence
/// wins) so rotation stays meaningful instead of repeating one key.
fn unique_env_names<S: AsRef<str>>(env_names: &[S]) -> Result<Vec<String>> {
    let mut unique: Vec<String> = Vec::new();
    for name in env_names {
        let name = name.as_ref();
        validate_env_name(name)?;
        if !unique.iter().any(|seen| seen == name) {
            unique.push(name.to_string());
        }
    }
    if unique.len() > MAX_API_KEYS {
        bail!("at most {MAX_API_KEYS} API key environment variables are supported");
    }
    Ok(unique)
}

/// Resolve environment variable *names* into API key values.
///
/// The declared list is only names — the values stay in the process
/// environment (ADR-0013 §4: configuration records where a key lives, never
/// the key). Resolution is all-or-nothing: one unset name or one invalid
/// value fails the whole set, because a half-resolved keyring would fail on a
/// later request mid-run. Identical resolved values are collapsed.
pub fn resolve_api_keys<S: AsRef<str>>(env_names: &[S]) -> Result<Vec<String>> {
    let mut keys: Vec<String> = Vec::new();
    for name in unique_env_names(env_names)? {
        let value = std::env::var(&name)
            .map_err(|_| anyhow!("required API key environment variable `{name}` is not set"))?;
        validate_api_key(&value).map_err(|_| anyhow!("invalid API key value"))?;
        if !keys.contains(&value) {
            keys.push(value);
        }
    }
    Ok(keys)
}

fn normalize_base_url(raw: String) -> Result<String> {
    if raw.len() > 2_048 {
        bail!("provider base URL is too long");
    }
    let parsed = Url::parse(&raw).map_err(|error| anyhow!("invalid provider base URL: {error}"))?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        bail!("provider base URL must use http or https");
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!("provider base URL must not contain credentials, query, or fragment");
    }
    if parsed.port() == Some(0) {
        bail!("provider base URL must use a non-zero port when a port is specified");
    }
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    if host.is_empty() {
        bail!("provider base URL must contain a host");
    }
    let loopback = host == "localhost"
        || host == "::1"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if parsed.scheme() == "http" && !loopback {
        bail!("remote provider base URL must use HTTPS");
    }
    let mut normalized = parsed.to_string();
    while normalized.ends_with('/') {
        normalized.pop();
    }
    Ok(normalized)
}

fn message_to_wire(message: &Message) -> Value {
    match message {
        Message::System { content } | Message::User { content } => {
            json!({"role": message.role().as_wire(), "content": content})
        }
        Message::Assistant {
            content,
            tool_calls,
        } => {
            let calls = tool_calls
                .iter()
                .map(|call| {
                    json!({
                        "id": call.id,
                        "type": "function",
                        "function": {"name": call.name, "arguments": call.args.to_string()}
                    })
                })
                .collect::<Vec<_>>();
            json!({"role": "assistant", "content": content, "tool_calls": calls})
        }
        Message::Tool {
            call_id,
            name,
            content,
            ..
        } => json!({"role": "tool", "tool_call_id": call_id, "name": name, "content": content}),
    }
}

fn parse_response(value: &Value) -> Result<ChatResponse> {
    let choice = value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .ok_or_else(|| anyhow!("provider response has no choices"))?;
    let message = choice
        .get("message")
        .ok_or_else(|| anyhow!("provider response has no message"))?;
    let content = message
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut tool_calls = Vec::new();
    if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
        for call in calls {
            let id = call
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let function = call
                .get("function")
                .ok_or_else(|| anyhow!("provider tool call has no function"))?;
            let name = function
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| {
                    !name.trim().is_empty()
                        && name.len() <= 128
                        && !name.chars().any(char::is_control)
                })
                .ok_or_else(|| anyhow!("provider tool call has an invalid name"))?;
            let arguments = function
                .get("arguments")
                .and_then(Value::as_str)
                .unwrap_or("{}");
            let args = serde_json::from_str::<Value>(arguments)
                .context("provider tool arguments are not JSON")?;
            if !args.is_object() {
                bail!("provider tool arguments must be a JSON object");
            }
            if id.trim().is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
                bail!("provider tool call has an invalid id");
            }
            if serde_json::to_string(&args)?.len() > 128 * 1024 {
                bail!("provider tool arguments exceed 128 KiB");
            }
            let call = ToolCall {
                id,
                name: name.to_string(),
                args,
            };
            call.validate()
                .map_err(|error| anyhow!(error.to_string()))?;
            tool_calls.push(call);
        }
    }
    let usage = value
        .get("usage")
        .ok_or_else(|| anyhow!("provider response has no usage"))?;
    let required_token_count = |key: &str| {
        usage
            .get(key)
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("provider response usage is missing `{key}`"))
    };
    let input_tokens = required_token_count("prompt_tokens")?;
    let output_tokens = required_token_count("completion_tokens")?;
    let cache_read_tokens = match usage.get("cache_read_tokens") {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| anyhow!("provider response usage has invalid `cache_read_tokens`"))?,
        None => 0,
    };
    let usage = Usage {
        input_tokens,
        output_tokens,
        cache_read_tokens,
    };
    let assistant = if tool_calls.is_empty() {
        Message::assistant(content)
    } else {
        Message::assistant_calls(content, tool_calls)
    };
    Ok(ChatResponse {
        messages: vec![assistant],
        usage,
    })
}

trait WireRole {
    fn as_wire(&self) -> &'static str;
}

impl WireRole for pangu_core::MessageRole {
    fn as_wire(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
        }
    }
}

/// B4 capability probe: one bounded GET `<base_url>/models` against the
/// configured provider endpoint. Operator-initiated diagnostics only — never
/// model-driven, never part of a run. Same client discipline as `chat` (no
/// proxy, no redirect, bounded response); non-2xx reports the status only and
/// never echoes the body or the key.
pub async fn probe_models(
    base_url: &str,
    api_key: Option<&str>,
    timeout_secs: u64,
) -> Result<Vec<String>> {
    if timeout_secs == 0 {
        bail!("timeout_secs must be > 0");
    }
    let url = format!("{}/models", normalize_base_url(base_url.to_string())?);
    if let Some(key) = api_key {
        validate_api_key(key)?;
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(timeout_secs))
        .build()?;
    let mut request = client.get(&url);
    if let Some(key) = api_key {
        request = request.bearer_auth(key);
    }
    let response = request.send().await?;
    let status = response.status();
    if !status.is_success() {
        bail!("models probe failed: HTTP {status}");
    }
    if let Some(length) = response.content_length() {
        if length as usize > MAX_RESPONSE_BYTES {
            bail!("models probe response exceeds {MAX_RESPONSE_BYTES} bytes");
        }
    }
    let body = response.bytes().await?;
    if body.len() > MAX_RESPONSE_BYTES {
        bail!("models probe response exceeds {MAX_RESPONSE_BYTES} bytes");
    }
    let value: Value = serde_json::from_slice(&body)
        .map_err(|_| anyhow!("models probe returned a non-JSON body"))?;
    let data = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("models probe response is missing `data`"))?;
    if data.len() > 1_000 {
        bail!("models probe returned too many entries");
    }
    let mut ids = Vec::new();
    for entry in data {
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("models probe entry is missing `id`"))?;
        if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
            bail!("models probe returned an invalid model id");
        }
        ids.push(id.to_string());
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_rejects_credentials_and_remote_http() {
        assert!(normalize_base_url("https://user:pass@example.com/v1".into()).is_err());
        assert!(normalize_base_url("http://example.com/v1".into()).is_err());
        assert!(normalize_base_url("http://localhost:11434/v1".into()).is_ok());
    }

    #[test]
    fn key_environment_names_are_bounded_deduped_and_validated() {
        // Duplicates collapse (first occurrence wins), keeping rotation meaningful.
        assert_eq!(
            unique_env_names(&["A_KEY".to_string(), "A_KEY".to_string(), "B_KEY".to_string()])
                .expect("names"),
            vec!["A_KEY".to_string(), "B_KEY".to_string()]
        );
        // Empty, oversized, control characters and `=` are not variable names.
        assert!(unique_env_names(&[String::new()]).is_err());
        assert!(unique_env_names(&["BAD=NAME".to_string()]).is_err());
        assert!(unique_env_names(&["bad\nname".to_string()]).is_err());
        assert!(unique_env_names(&[("x".repeat(257)).to_string()]).is_err());
        // The declared list is bounded.
        let too_many: Vec<String> =
            (0..=MAX_API_KEYS).map(|index| format!("KEY_{index}")).collect();
        let error = unique_env_names(&too_many).expect_err("too many names");
        assert!(error.to_string().contains("at most"));
    }

    #[test]
    fn with_keys_rejects_an_unbounded_keyring() {
        let too_many: Vec<String> =
            (0..=MAX_API_KEYS).map(|index| format!("key-{index}")).collect();
        // The provider deliberately has no Debug (it carries keys), so assert
        // through `err()` instead of `expect_err`.
        let error = OpenAiCompatibleProvider::with_keys(
            "test-model",
            "https://example.invalid/v1",
            too_many,
            None,
            Some(64),
            5,
        )
        .err()
        .expect("too many keys");
        assert!(error.to_string().contains("at most"));
    }

    #[test]
    fn unresolved_key_names_fail_the_whole_resolution() {
        // Never assert a positive lookup here: `std::env::set_var` is
        // process-global and racy across the test binary. Unset names must
        // fail the whole set rather than resolve half a keyring.
        let error = resolve_api_keys(&["PANGU_TEST_ABSENT_KEY".to_string()])
            .expect_err("unset variable must fail");
        assert!(error.to_string().contains("PANGU_TEST_ABSENT_KEY"));
    }

    #[test]
    fn parses_tool_call_and_requires_usage() {
        let value = json!({
            "choices": [{"message": {"content": "", "tool_calls": [{
                "id": "c1",
                "function": {"name": "read_file", "arguments": "{\"path\":\"Cargo.toml\"}"}
            }]}}],
            "usage": {"prompt_tokens": 4, "completion_tokens": 2}
        });
        let response = parse_response(&value).unwrap();
        assert_eq!(response.usage.input_tokens, 4);
        assert!(matches!(response.messages[0], Message::Assistant { .. }));
        let missing_usage = json!({"choices": [{"message": {"content": "ok"}}]});
        assert!(parse_response(&missing_usage).is_err());
        let missing_token_count = json!({
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 4}
        });
        assert!(parse_response(&missing_token_count).is_err());
    }
}
