use std::time::Duration;

use pangu_agent::Provider;
use pangu_core::{ChatResponse, Message};
use pangu_provider::{OpenAiCompatibleProvider, MAX_API_KEYS};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::oneshot;

struct MockServer {
    base_url: String,
    request: oneshot::Receiver<String>,
}

async fn spawn_server(
    status: &'static str,
    body: String,
    headers: Vec<(&'static str, String)>,
) -> MockServer {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind mock provider server");
    let address = listener.local_addr().expect("mock provider address");
    let (request_tx, request_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept provider request");
        let request = read_request(&mut socket).await;
        let _ = request_tx.send(request);

        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (name, value) in headers {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(&value);
            response.push_str("\r\n");
        }
        response.push_str("\r\n");
        response.push_str(&body);
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.shutdown().await;
    });

    MockServer {
        base_url: format!("http://{address}/v1"),
        request: request_rx,
    }
}

async fn read_request(socket: &mut TcpStream) -> String {
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let count = socket
            .read(&mut buffer)
            .await
            .expect("read provider request");
        if count == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..count]);

        let Some(header_end) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&data[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        if data.len() >= header_end + 4 + content_length {
            break;
        }
    }
    String::from_utf8_lossy(&data).into_owned()
}

fn provider(base_url: String) -> OpenAiCompatibleProvider {
    OpenAiCompatibleProvider::new(
        "test-model",
        base_url,
        Some("test-key".into()),
        None,
        Some(64),
        5,
    )
    .expect("provider")
}

/// Serve `times` sequential requests, reporting each request's Authorization
/// header over the returned channel. The single-shot mock above cannot prove
/// rotation, which is a property *across* requests.
async fn spawn_rotating_server(times: usize, body: String) -> (String, mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind mock provider server");
    let address = listener.local_addr().expect("mock provider address");
    let (authorizations_tx, authorizations_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        for _ in 0..times {
            let (mut socket, _) = listener.accept().await.expect("accept provider request");
            let request = read_request(&mut socket).await;
            let _ = authorizations_tx.send(authorization_of(&request));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });
    (format!("http://{address}/v1"), authorizations_rx)
}

fn authorization_of(request: &str) -> String {
    request
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("authorization")
                .then(|| value.trim().to_string())
        })
        .unwrap_or_default()
}

fn success_body() -> String {
    serde_json::json!({
        "choices": [{"message": {"content": "ok"}}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 1}
    })
    .to_string()
}

async fn chat(provider: &OpenAiCompatibleProvider) -> anyhow::Result<ChatResponse> {
    tokio::time::timeout(
        Duration::from_secs(5),
        provider.chat(Vec::new(), Vec::new()),
    )
    .await
    .expect("provider request timeout")
}

#[tokio::test]
async fn sends_authorization_and_parses_tool_call_and_cache_usage() {
    let body = serde_json::json!({
        "choices": [{"message": {"content": "", "tool_calls": [{
            "id": "call-1",
            "type": "function",
            "function": {
                "name": "read_file",
                "arguments": "{\"path\":\"Cargo.toml\"}"
            }
        }]}}],
        "usage": {
            "prompt_tokens": 11,
            "completion_tokens": 3,
            "cache_read_tokens": 5
        }
    })
    .to_string();
    let server = spawn_server("200 OK", body, Vec::new()).await;
    let provider = provider(server.base_url.clone());

    let response = chat(&provider).await.expect("provider response");
    assert_eq!(response.usage.input_tokens, 11);
    assert_eq!(response.usage.output_tokens, 3);
    assert_eq!(response.usage.cache_read_tokens, 5);
    let Message::Assistant { tool_calls, .. } = &response.messages[0] else {
        panic!("expected assistant response");
    };
    assert_eq!(tool_calls[0].id, "call-1");
    assert_eq!(tool_calls[0].name, "read_file");

    let request = server.request.await.expect("captured request");
    let lower = request.to_ascii_lowercase();
    assert!(lower.starts_with("post /v1/chat/completions "));
    assert!(lower.contains("authorization: bearer test-key"));
    let body = request.split_once("\r\n\r\n").expect("request body").1;
    let body: Value = serde_json::from_str(body).expect("request JSON");
    assert_eq!(body["model"], "test-model");
    assert_eq!(body["tool_choice"], "auto");
}

#[tokio::test]
async fn non_success_response_does_not_expose_remote_body() {
    let secret = "remote-secret-that-must-not-escape";
    let body = serde_json::json!({"error": secret}).to_string();
    let server = spawn_server("500 Internal Server Error", body, Vec::new()).await;
    let provider = provider(server.base_url.clone());

    let error = chat(&provider).await.expect_err("provider must reject 500");
    let message = error.to_string();
    assert!(message.contains("500"));
    assert!(!message.contains(secret));
    let _ = server.request.await;
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let secret = "redirect-body-secret";
    let server = spawn_server(
        "302 Found",
        secret.to_string(),
        vec![(
            "Location",
            "http://127.0.0.1:1/should-not-be-requested".into(),
        )],
    )
    .await;
    let provider = provider(server.base_url.clone());

    let error = chat(&provider)
        .await
        .expect_err("redirect must be rejected");
    let message = error.to_string();
    assert!(message.contains("302"));
    assert!(!message.contains(secret));
    let _ = server.request.await;
}

#[tokio::test]
async fn oversized_response_is_rejected_before_json_parsing() {
    let body = "x".repeat(2 * 1024 * 1024 + 1);
    let server = spawn_server("200 OK", body, Vec::new()).await;
    let provider = provider(server.base_url.clone());

    let error = chat(&provider)
        .await
        .expect_err("oversized response must fail");
    let message = error.to_string();
    assert!(message.contains("provider response exceeds 2097152 bytes"));
    let _ = server.request.await;
}

// ---- API key rotation ------------------------------------------------------

#[tokio::test]
async fn multiple_keys_rotate_across_requests_in_order() {
    let (base_url, mut authorizations) = spawn_rotating_server(3, success_body()).await;
    let provider = OpenAiCompatibleProvider::with_keys(
        "test-model",
        base_url,
        vec!["key-one".into(), "key-two".into()],
        None,
        Some(64),
        5,
    )
    .expect("provider");

    chat(&provider).await.expect("first response");
    chat(&provider).await.expect("second response");
    chat(&provider).await.expect("third response");

    let mut seen = Vec::new();
    for _ in 0..3 {
        seen.push(
            tokio::time::timeout(Duration::from_secs(5), authorizations.recv())
                .await
                .expect("authorization report")
                .expect("channel open"),
        );
    }
    assert_eq!(
        seen,
        vec![
            "Bearer key-one".to_string(),
            "Bearer key-two".to_string(),
            "Bearer key-one".to_string(),
        ],
        "the Nth request must use key N mod key_count"
    );
}

#[tokio::test]
async fn keyless_provider_sends_no_authorization_header() {
    let (base_url, mut authorizations) = spawn_rotating_server(1, success_body()).await;
    // Local endpoints (e.g. ollama) need no key: an empty key list is the
    // unauthenticated case, not an error.
    let provider = OpenAiCompatibleProvider::with_keys(
        "test-model",
        base_url,
        Vec::new(),
        None,
        Some(64),
        5,
    )
    .expect("provider");

    chat(&provider).await.expect("response without a key");

    let seen = tokio::time::timeout(Duration::from_secs(5), authorizations.recv())
        .await
        .expect("authorization report")
        .expect("channel open");
    assert!(seen.is_empty(), "no key means no header: {seen:?}");
}

#[tokio::test]
async fn keyring_bounds_are_enforced_at_construction() {
    // MAX_API_KEYS is the documented ceiling; one more must fail closed rather
    // than silently truncate the operator's declaration.
    let too_many: Vec<String> = (0..=MAX_API_KEYS).map(|index| format!("key-{index}")).collect();
    assert!(OpenAiCompatibleProvider::with_keys(
        "test-model",
        "https://example.invalid/v1",
        too_many,
        None,
        Some(64),
        5,
    )
    .is_err());
}

// ---- B4: capability probe ------------------------------------------------

#[tokio::test]
async fn probe_lists_models_from_the_endpoint() {
    let body = serde_json::json!({"data": [{"id": "gpt-4o"}, {"id": "local-model"}]}).to_string();
    let server = spawn_server("200 OK", body, Vec::new()).await;
    let ids = pangu_provider::probe_models(&server.base_url, Some("sk-probe-key"), 5)
        .await
        .expect("probe");
    assert_eq!(ids, vec!["gpt-4o".to_string(), "local-model".to_string()]);
    let request = server.request.await.expect("request captured");
    assert!(request.starts_with("GET"), "probe must use GET: {request}");
    assert!(request.contains("/models"), "probe path: {request}");
    let request = request.to_ascii_lowercase();
    assert!(
        request.contains("authorization: bearer sk-probe-key"),
        "probe must send the key as a bearer token: {request}"
    );
}

#[tokio::test]
async fn probe_failure_reports_status_only_and_never_the_body() {
    let server = spawn_server(
        "401 Unauthorized",
        "SECRET-PROVIDER-BODY".into(),
        Vec::new(),
    )
    .await;
    let error = pangu_provider::probe_models(&server.base_url, None, 5)
        .await
        .expect_err("401 must fail");
    let text = error.to_string();
    assert!(text.contains("401"), "status required: {text}");
    assert!(
        !text.contains("SECRET-PROVIDER-BODY"),
        "error body must not be echoed: {text}"
    );
}

#[tokio::test]
async fn probe_rejects_oversized_and_malformed_bodies() {
    // MAX_RESPONSE_BYTES in the provider is 2 MiB; 3 MiB must be refused.
    let oversized = "x".repeat(3 * 1024 * 1024);
    let server = spawn_server("200 OK", oversized, Vec::new()).await;
    assert!(
        pangu_provider::probe_models(&server.base_url, None, 5)
            .await
            .is_err(),
        "oversized body must be refused"
    );

    let server = spawn_server("200 OK", "not-json".into(), Vec::new()).await;
    assert!(
        pangu_provider::probe_models(&server.base_url, None, 5)
            .await
            .is_err(),
        "malformed body must be refused"
    );

    let server = spawn_server("200 OK", "{\"nope\": 1}".into(), Vec::new()).await;
    assert!(
        pangu_provider::probe_models(&server.base_url, None, 5)
            .await
            .is_err(),
        "missing `data` must be refused"
    );
}
