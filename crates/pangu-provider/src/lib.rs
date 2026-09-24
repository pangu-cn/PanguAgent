//! Provider adapters. This crate translates typed messages to an explicit
//! OpenAI-compatible API and translates the response back to core messages.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::{json, Value};
use url::Url;

use pangu_agent::Provider;
use pangu_core::{ChatResponse, Message, ToolCall, ToolSpec, Usage};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct OpenAiCompatibleProvider {
    model: String,
    base_url: String,
    api_key: Option<String>,
    temperature: Option<f32>,
    max_output_tokens: Option<u32>,
    client: reqwest::Client,
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
        let model = model.into();
        if model.trim().is_empty() || model.len() > 256 || model.chars().any(char::is_control) {
            bail!("model must be non-empty, bounded, and contain no control characters");
        }
        if let Some(key) = api_key.as_deref() {
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
            api_key,
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
        let api_key = match api_key_env {
            Some(name) => {
                let value = std::env::var(name).map_err(|_| {
                    anyhow!("required API key environment variable `{name}` is not set")
                })?;
                validate_api_key(&value).map_err(|_| anyhow!("invalid API key value"))?;
                Some(value)
            }
            None => None,
        };
        Self::new(
            model,
            base_url,
            api_key,
            temperature,
            max_output_tokens,
            timeout_secs,
        )
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
        if let Some(key) = &self.api_key {
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
