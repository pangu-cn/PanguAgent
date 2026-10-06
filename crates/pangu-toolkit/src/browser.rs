//! Browser tools: the CDP session exposed through the L1–L4 chain.
//!
//! # How a browser action maps onto this project's model
//!
//! Nothing here bypasses the gate chain. Each tool declares what it does in
//! `Toolkit::assess`, and only then can it execute:
//!
//! | Tool | Risk | Effect | Why |
//! |------|------|--------|-----|
//! | `browser_open` | `NeedsHuman` | `ExternalRead` | It reaches a **host**, exactly like `http_fetch`. The host must be declared so the network boundary sees it. |
//! | `browser_read` | `ReadOnly` | `NoEffect` | Reading the current page changes nothing. |
//! | `browser_screenshot` | `ReadOnly` | `NoEffect` | Same: an observation, not a change. |
//! | `browser_click` | `Reversible` | `ExternalMutation` | A click can submit a form or buy something. The page decides what it does, so this is **not** read-only even though the input is one coordinate pair. |
//! | `browser_type` | `Reversible` | `ExternalMutation` | Typing into a field can trigger a handler that acts. |
//!
//! The choice that matters most: **a click is not read-only.** Treating it as
//! such would be the same class of mistake as trusting a server's
//! `readOnlyHint` — it would let a self-described harmless action skip the human
//! gate while its actual effect is decided elsewhere.
//!
//! # Session lifetime
//!
//! One browser session per run, created on first use and kept on the `Toolkit`.
//! A session per tool call would lose the page between a click and the read that
//! follows it, which is exactly the sequence computer use consists of.

use std::sync::Mutex;

use anyhow::{anyhow, bail, Result};
use pangu_boundary::browser::{BrowserConfig, BrowserSession, BrowserUnavailable};
use pangu_boundary::runtime::Runtime;
use serde_json::{json, Value};

use crate::ToolOutput;

/// The tools this module implements.
pub const BROWSER_TOOLS: &[&str] = &[
    "browser_open",
    "browser_read",
    "browser_screenshot",
    "browser_click",
    "browser_type",
];

/// Whether `name` is a browser tool.
pub fn is_browser_tool(name: &str) -> bool {
    BROWSER_TOOLS.contains(&name)
}

/// One live session, plus the state needed to report what was enforced.
pub struct BrowserHandle {
    session: BrowserSession,
    /// Where screenshots are written, inside the writable boundary.
    artifact_dir: std::path::PathBuf,
    counter: u64,
}

impl BrowserHandle {
    /// Launch a session, honouring a declared sandbox runtime when present.
    ///
    /// When `runtime` is `Some` and unusable, this refuses: launching the
    /// browser on the host after the operator asked for isolation would make the
    /// audit record false, which is the same rule the command executor follows.
    pub fn launch(
        config: &BrowserConfig,
        runtime: Option<&Runtime>,
        artifact_dir: std::path::PathBuf,
    ) -> Result<Self> {
        if let Some(runtime) = runtime {
            if !runtime.allows_execution() {
                return Err(anyhow!("{}", runtime.refusal()));
            }
        }
        let launcher = runtime.and_then(|runtime| {
            runtime
                .launcher()
                .map(|(program, leading)| (program.to_string(), leading.to_vec()))
        });
        let launcher_ref = launcher
            .as_ref()
            .map(|(program, leading)| (program.as_str(), leading.as_slice()));
        let session = BrowserSession::launch(config, launcher_ref)?;
        Ok(Self {
            session,
            artifact_dir,
            counter: 0,
        })
    }

    /// The session handle.
    ///
    /// Public so the toolkit's browser handlers can drive it; the session is
    /// only ever reached through `BrowserSlot::with`, which owns the lock.
    pub fn session(&mut self) -> Result<&mut BrowserSession> {
        Ok(&mut self.session)
    }

    /// Save a screenshot into the run's own storage and return its relative path.
    ///
    /// Written inside the writable boundary rather than to a temp directory so
    /// the artifact is covered by the same rules as every other run artifact,
    /// and so its existence is recorded rather than assumed.
    pub fn save_screenshot(&mut self, data: &[u8]) -> Result<String> {
        std::fs::create_dir_all(&self.artifact_dir).map_err(|error| {
            anyhow!(
                "cannot create the screenshot directory {}: {error}",
                self.artifact_dir.display()
            )
        })?;
        self.counter += 1;
        let name = format!("screenshot-{:03}.png", self.counter);
        let path = self.artifact_dir.join(&name);
        std::fs::write(&path, data)
            .map_err(|error| anyhow!("cannot write the screenshot {}: {error}", path.display()))?;
        Ok(name)
    }
}

/// Shared, lazily-created browser session.
///
/// A `Mutex` rather than an async lock because the CDP client is synchronous:
/// the toolkit executes tools on a blocking path, and introducing an async lock
/// here would only add a way to deadlock.
#[derive(Default)]
pub struct BrowserSlot {
    handle: Mutex<Option<BrowserHandle>>,
}

impl BrowserSlot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a session is already open.
    pub fn is_open(&self) -> bool {
        self.handle
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    /// Run `body` with the open session, launching one first if needed.
    pub fn with<T>(
        &self,
        config: &BrowserConfig,
        runtime: Option<&Runtime>,
        artifact_dir: std::path::PathBuf,
        body: impl FnOnce(&mut BrowserHandle) -> Result<T>,
    ) -> Result<T> {
        let mut guard = self
            .handle
            .lock()
            .map_err(|_| anyhow!("the browser session lock was poisoned by an earlier panic"))?;
        if guard.is_none() {
            *guard = Some(BrowserHandle::launch(config, runtime, artifact_dir)?);
        }
        let handle = guard.as_mut().expect("just ensured to be Some");
        body(handle)
    }

    /// Close the session, releasing the browser process and its profile.
    pub fn close(&self) {
        if let Ok(mut guard) = self.handle.lock() {
            // Dropping the handle kills the child process. This is the only
            // place a session ends deliberately; a leaked headless browser would
            // hold its profile directory into the next run.
            *guard = None;
        }
    }
}

/// Resolve the browser configuration, or refuse with an actionable message.
///
/// The executable must be an absolute path that exists; a name on `PATH` is not
/// accepted because the sandbox resolves programs itself and a bare name would
/// mean "whatever the loader finds", which is not a decision this module should
/// delegate.
pub fn resolve_config(
    executable: Option<&str>,
    profile_dir: std::path::PathBuf,
    network: bool,
    extra_args: Vec<String>,
) -> Result<BrowserConfig> {
    let resolved = match executable {
        Some(path) => {
            let path = std::path::PathBuf::from(path);
            if !path.is_file() {
                return Err(BrowserUnavailable::NotInstalled {
                    looked_for: vec![path.display().to_string()],
                }
                .refusal()
                .into());
            }
            if !path.is_absolute() {
                bail!(
                    "[browser] executable must be an absolute path; got {}",
                    path.display()
                );
            }
            path
        }
        None => BrowserConfig::find_executable().ok_or_else(|| {
            BrowserUnavailable::NotInstalled {
                looked_for: vec![
                    "%PROGRAMFILES%/Google/Chrome/Application/chrome.exe".into(),
                    "%PROGRAMFILES%/Microsoft/Edge/Application/msedge.exe".into(),
                    "/usr/bin/google-chrome".into(),
                    "/usr/bin/chromium".into(),
                ],
            }
            .refusal()
        })?,
    };
    Ok(BrowserConfig {
        executable: resolved,
        profile_dir,
        network,
        extra_args,
    })
}

/// Parse the `selector` argument shared by the interaction tools.
pub fn required_selector(args: &Value) -> Result<String> {
    let selector = args
        .get("selector")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("`selector` is required and must be a string"))?
        .trim()
        .to_string();
    if selector.is_empty() {
        bail!("`selector` must not be empty");
    }
    if selector.len() > 1024 {
        bail!("`selector` is longer than 1024 bytes");
    }
    Ok(selector)
}

/// Render a snapshot as the tool's result text.
///
/// The truncation flag is stated in the output rather than kept internal: a
/// caller that does not know the text was clipped would treat a partial page as
/// the whole page.
pub fn render_snapshot(url: &str, title: &str, text: &str, truncated: bool) -> String {
    let mut rendered = format!("url: {url}\ntitle: {title}\n");
    if truncated {
        rendered.push_str("text (truncated):\n");
    } else {
        rendered.push_str("text:\n");
    }
    rendered.push_str(text);
    rendered
}

/// The tool output for a browser action.
///
/// The human-readable summary is the content; a machine-checkable fact goes in
/// `evidence` so a `verify` step can assert on the action having happened
/// without parsing prose.
pub fn output(summary: String, evidence: Option<String>) -> ToolOutput {
    match evidence {
        Some(evidence) => ToolOutput::evidenced(summary, evidence),
        None => ToolOutput::text(summary),
    }
}

/// Describe a browser tool's risk and effect, for `assess`.
pub fn describe(name: &str) -> Option<(&'static str, bool)> {
    // Returns (effect kind, requires a host). `effect kind` is one of
    // "external_read", "read", "external_mutation".
    match name {
        "browser_open" => Some(("external_read", true)),
        "browser_read" | "browser_screenshot" => Some(("read", false)),
        "browser_click" | "browser_type" => Some(("external_mutation", false)),
        _ => None,
    }
}

/// The JSON schema for one browser tool, for the model-facing tool list.
pub fn schema(name: &str) -> Option<Value> {
    Some(match name {
        "browser_open" => json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["url"],
            "properties": {"url": {"type": "string", "format": "uri"}}
        }),
        "browser_read" => json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }),
        "browser_screenshot" => json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }),
        "browser_click" => json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["selector"],
            "properties": {"selector": {"type": "string", "minLength": 1}}
        }),
        "browser_type" => json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["text"],
            "properties": {"text": {"type": "string"}}
        }),
        _ => return None,
    })
}

/// One-line description of a browser tool, for the model-facing tool list.
pub fn description(name: &str) -> Option<&'static str> {
    Some(match name {
        "browser_open" => {
            "Navigate the sandboxed headless browser to an allow-listed URL and return the page text."
        }
        "browser_read" => "Read the current browser page: URL, title and visible text.",
        "browser_screenshot" => {
            "Capture a PNG screenshot of the current page into the run's artifacts."
        }
        "browser_click" => {
            "Click the element matching a CSS selector, dispatching a real mouse event at its centre."
        }
        "browser_type" => "Type text into the focused element, one key event per character.",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_advertised_tool_has_a_schema_and_a_description() {
        // A tool advertised without a schema would fail on its first call; one
        // without a description would be uncallable by a model that reads the
        // list. Both are caught here rather than in production.
        for name in BROWSER_TOOLS {
            assert!(schema(name).is_some(), "{name} has no schema");
            assert!(description(name).is_some(), "{name} has no description");
            assert!(describe(name).is_some(), "{name} has no risk mapping");
        }
    }

    #[test]
    fn a_click_is_not_classified_as_read_only() {
        // The page decides what a click does. Treating it as read-only would let
        // a state-changing action skip the human gate, which is the same mistake
        // as trusting a server's readOnlyHint.
        let (effect, needs_host) = describe("browser_click").expect("click is known");
        assert_eq!(effect, "external_mutation");
        assert!(!needs_host);
    }

    #[test]
    fn typing_is_not_classified_as_read_only() {
        let (effect, _) = describe("browser_type").expect("type is known");
        assert_eq!(effect, "external_mutation");
    }

    #[test]
    fn opening_a_page_reaches_a_host_and_says_so() {
        // Navigation is an outbound network action; if it did not declare its
        // host, the network boundary would never see where the browser went.
        let (effect, needs_host) = describe("browser_open").expect("open is known");
        assert_eq!(effect, "external_read");
        assert!(needs_host, "navigation must declare its host");
    }

    #[test]
    fn reading_the_current_page_is_read_only() {
        for name in ["browser_read", "browser_screenshot"] {
            let (effect, needs_host) = describe(name).expect("known");
            assert_eq!(effect, "read", "{name}");
            assert!(!needs_host, "{name} does not select a new host");
        }
    }

    #[test]
    fn an_unknown_name_is_not_claimed_as_a_browser_tool() {
        assert!(!is_browser_tool("run_command"));
        assert!(schema("not_a_tool").is_none());
        assert!(description("not_a_tool").is_none());
        assert!(describe("not_a_tool").is_none());
    }

    #[test]
    fn a_selector_is_required_and_bounded() {
        assert!(required_selector(&json!({})).is_err());
        assert!(required_selector(&json!({"selector": "   "})).is_err());
        assert!(required_selector(&json!({"selector": 42})).is_err());
        assert!(required_selector(&json!({"selector": "x".repeat(1025)})).is_err());
        assert_eq!(
            required_selector(&json!({"selector": " #go "})).expect("valid"),
            "#go"
        );
    }

    #[test]
    fn a_relative_executable_is_refused() {
        // The sandbox resolves programs itself; a relative path would mean
        // "whatever the loader finds", which is not this module's decision.
        let error = resolve_config(
            Some("chrome"),
            std::path::PathBuf::from("/tmp/p"),
            false,
            Vec::new(),
        )
        .expect_err("must refuse");
        let text = error.to_string();
        assert!(
            text.contains("no Chromium-based browser was found"),
            "{text}"
        );
    }

    #[test]
    fn an_absolute_but_missing_executable_is_refused_with_its_path() {
        let missing = if cfg!(windows) {
            "C:\\definitely\\not\\here\\chrome.exe"
        } else {
            "/definitely/not/here/chrome"
        };
        let error = resolve_config(
            Some(missing),
            std::path::PathBuf::from("/tmp/p"),
            false,
            Vec::new(),
        )
        .expect_err("must refuse");
        let text = error.to_string();
        assert!(
            text.contains("no Chromium-based browser was found"),
            "{text}"
        );
    }

    #[test]
    fn a_truncated_snapshot_says_so() {
        // A caller that cannot see the text was clipped would treat a partial
        // page as the whole page.
        let rendered = render_snapshot("https://x", "T", "body", true);
        assert!(rendered.contains("text (truncated):"), "{rendered}");
        let whole = render_snapshot("https://x", "T", "body", false);
        assert!(!whole.contains("truncated"), "{whole}");
    }

    #[test]
    fn a_closed_slot_reports_no_open_session() {
        let slot = BrowserSlot::new();
        assert!(!slot.is_open());
        slot.close();
        assert!(!slot.is_open());
    }
}
