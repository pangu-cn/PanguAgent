use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use pangu_core::redact_text;

use crate::risk::Risk;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// Actions requiring a human are rejected, not implicitly allowed.
    Never,
    #[default]
    #[serde(alias = "destructive", alias = "DestructiveAndAbove")]
    DestructiveAndAbove,
    Always,
}

impl ApprovalMode {
    pub fn needs_approval(self, risk: Risk) -> bool {
        match self {
            // `Never` disables the human mechanism, so actions that would
            // otherwise require a human are rejected by the runtime rather
            // than silently treated as approved.
            Self::Never => risk.at_least(Risk::Destructive),
            Self::DestructiveAndAbove => risk.at_least(Risk::Destructive),
            Self::Always => true,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::DestructiveAndAbove => "destructive_and_above",
            Self::Always => "always",
        }
    }
}

impl std::fmt::Display for ApprovalMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for ApprovalMode {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "never" | "off" | "none" => Ok(Self::Never),
            "destructiveandabove" | "destructive_and_above" | "destructive" => {
                Ok(Self::DestructiveAndAbove)
            }
            "always" | "on" | "every" => Ok(Self::Always),
            other => Err(format!("unknown approval mode `{other}`")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub tool: String,
    pub call_id: String,
    pub risk: Risk,
    pub rule_id: Option<String>,
    pub reason: String,
    pub target: Option<String>,
    pub invariant: Option<String>,
    pub preview: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalResponse {
    AllowOnce,
    /// Historical name retained for API compatibility. The label is audited,
    /// but approval is never persisted across calls in this version.
    AllowRule(String),
    Deny,
    Abort(String),
    NoAnswer,
}

impl ApprovalResponse {
    pub fn allowed(&self) -> bool {
        matches!(self, Self::AllowOnce | Self::AllowRule(_))
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AllowOnce => "allow_once",
            Self::AllowRule(_) => "allow_rule",
            Self::Deny => "deny",
            Self::Abort(_) => "abort",
            Self::NoAnswer => "no_answer",
        }
    }
}

#[async_trait]
pub trait ApprovalHandler: Send + Sync {
    fn mode(&self) -> ApprovalMode;

    /// A handler must return an explicit response. Timeout and missing input
    /// are represented by `NoAnswer`, which is never treated as consent.
    async fn decide(&self, request: &ApprovalRequest) -> ApprovalResponse;
}

pub struct Unattended(pub ApprovalMode);

#[async_trait]
impl ApprovalHandler for Unattended {
    fn mode(&self) -> ApprovalMode {
        self.0
    }

    async fn decide(&self, _request: &ApprovalRequest) -> ApprovalResponse {
        ApprovalResponse::NoAnswer
    }
}

pub struct ScriptedApproval {
    mode: ApprovalMode,
    answers: Arc<Mutex<Vec<ApprovalResponse>>>,
    allow_when_empty: bool,
    pub seen: Arc<Mutex<Vec<String>>>,
}

impl ScriptedApproval {
    /// A normal scripted handler is fail-closed when its script is exhausted.
    pub fn new(mode: ApprovalMode, answers: Vec<ApprovalResponse>) -> Self {
        Self {
            mode,
            answers: Arc::new(Mutex::new(answers)),
            allow_when_empty: false,
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Explicitly opt into an allow-once fallback for demos/tests.
    pub fn allow_all(mode: ApprovalMode) -> Self {
        Self {
            mode,
            answers: Arc::new(Mutex::new(Vec::new())),
            allow_when_empty: true,
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn seen_ids(&self) -> Vec<String> {
        self.seen.lock().expect("approval seen lock").clone()
    }
}

#[async_trait]
impl ApprovalHandler for ScriptedApproval {
    fn mode(&self) -> ApprovalMode {
        self.mode
    }

    async fn decide(&self, request: &ApprovalRequest) -> ApprovalResponse {
        self.seen
            .lock()
            .expect("approval seen lock")
            .push(request.id.clone());
        let mut answers = self.answers.lock().expect("approval answers lock");
        if let Some(answer) = answers.first().cloned() {
            answers.remove(0);
            answer
        } else if self.allow_when_empty {
            ApprovalResponse::AllowOnce
        } else {
            ApprovalResponse::NoAnswer
        }
    }
}

pub struct StdinApproval {
    mode: ApprovalMode,
    timeout: Duration,
    cancelled: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
}

impl StdinApproval {
    pub fn new(mode: ApprovalMode, timeout: Duration) -> Self {
        Self {
            mode,
            timeout,
            cancelled: Arc::new(AtomicBool::new(false)),
            counter: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn cancellation_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    pub fn render(&self, request: &ApprovalRequest) -> String {
        let mut output = format!(
            "\n\x1b[33m需要确认\x1b[0m {}  [risk={}]  预算第 {} 次\n",
            safe_display(&request.tool, 128),
            request.risk,
            self.counter.fetch_add(1, Ordering::Relaxed) + 1
        );
        output.push_str(&format!(
            "  原因 : {}\n",
            safe_display(&request.reason, 4_096)
        ));
        if let Some(target) = &request.target {
            output.push_str(&format!("  目标 : {}\n", safe_display(target, 4_096)));
        }
        for (key, value) in &request.args {
            output.push_str(&format!(
                "  {} = {}\n",
                safe_display(key, 128),
                safe_display(value, 4_096)
            ));
        }
        output.push_str(&format!(
            "  预览 :\n{}\n",
            indent(&safe_display(&request.preview, 16_384))
        ));
        output.push_str("  [y] 仅这一次  [n] 拒绝  [q] 中止回合 > ");
        output
    }
}

fn safe_display(input: &str, max_bytes: usize) -> String {
    let redacted = redact_text(input);
    let sanitized = redacted
        .chars()
        .map(|character| {
            if character.is_control() && character != '\n' && character != '\t' {
                '�'
            } else {
                character
            }
        })
        .collect::<String>();
    pangu_core::truncate_middle(&sanitized, max_bytes)
}

fn indent(text: &str) -> String {
    text.lines()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[async_trait]
impl ApprovalHandler for StdinApproval {
    fn mode(&self) -> ApprovalMode {
        self.mode
    }

    async fn decide(&self, request: &ApprovalRequest) -> ApprovalResponse {
        if self.cancelled.load(Ordering::Relaxed) {
            return ApprovalResponse::Abort("回合已被取消".into());
        }
        eprint!("{}", self.render(request));
        let read = tokio::task::spawn_blocking(|| {
            let mut input = Vec::new();
            let result = std::io::stdin().lock().take(4_097).read_to_end(&mut input);
            (result, input)
        });
        let result = tokio::time::timeout(self.timeout, read).await;
        let text = match result {
            Ok(Ok((Ok(read), bytes))) if read <= 4_096 => {
                String::from_utf8(bytes).unwrap_or_default()
            }
            _ => return ApprovalResponse::NoAnswer,
        };
        match text.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => ApprovalResponse::AllowOnce,
            "q" | "abort" | "quit" => ApprovalResponse::Abort("人选择中止回合".into()),
            _ => ApprovalResponse::Deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            id: "a1".into(),
            tool: "write_file".into(),
            call_id: "c1".into(),
            risk: Risk::Destructive,
            rule_id: Some("write".into()),
            reason: "需要确认".into(),
            target: None,
            invariant: None,
            preview: "path=README.md".into(),
            args: Vec::new(),
        }
    }

    #[test]
    fn always_mode_requires_approval_for_read_only_actions() {
        assert!(ApprovalMode::Always.needs_approval(Risk::ReadOnly));
        assert!(!ApprovalMode::DestructiveAndAbove.needs_approval(Risk::Reversible));
        assert!(ApprovalMode::DestructiveAndAbove.needs_approval(Risk::Destructive));
    }

    #[test]
    fn never_mode_rejects_human_gated_risks() {
        assert!(ApprovalMode::Never.needs_approval(Risk::Destructive));
        assert!(ApprovalMode::Never.needs_approval(Risk::NeedsHuman));
        assert!(!ApprovalMode::Never.needs_approval(Risk::Reversible));
    }

    #[tokio::test]
    async fn exhausted_script_is_denied_by_default() {
        let handler =
            ScriptedApproval::new(ApprovalMode::Always, vec![ApprovalResponse::AllowOnce]);
        assert_eq!(
            handler.decide(&request()).await,
            ApprovalResponse::AllowOnce
        );
        assert_eq!(handler.decide(&request()).await, ApprovalResponse::NoAnswer);
    }
}
