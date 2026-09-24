use std::time::Duration;

use pangu_agent::Provider;
use pangu_core::{ChatResponse, Message};
use pangu_provider::OpenAiCompatibleProvider;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
