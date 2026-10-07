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
//! | `browser_screenshot` | `Reversible` | `Workspace` / `Reversible` | The observation itself changes nothing, but saving the PNG writes a run artifact. The assessment names that artifact directory so the writable-root check sees the actual write. |
//! | `browser_click` | `NeedsHuman` | `ExternalMutation` / `Irreversible` | A click can submit a form or buy something. The page decides what it does, so this is **not** read-only even though the input is one coordinate pair, and it is not reversible either: this program cannot undo a state change that lives on a server it does not control. The assessment names the already-open browser session as its resource. |
//! | `browser_type` | `NeedsHuman` | `ExternalMutation` / `Irreversible` | Typing into a field can trigger a handler that acts. Same reasoning as `browser_click`. |
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
}

impl BrowserHandle {
    /// Launch a session, honouring a declared sandbox runtime when present.
    ///
    /// When `runtime` is `Some` and unusable, this refuses: launching the
    /// browser on the host after the operator asked for isolation would make the
    /// audit record false, which is the same rule the command executor follows.
    pub fn launch(config: &BrowserConfig, runtime: Option<&Runtime>) -> Result<Self> {
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
        Ok(Self { session })
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
    pub fn save_screenshot_at(&mut self, path: &std::path::Path, data: &[u8]) -> Result<String> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("screenshot path has no parent"))?;
        std::fs::create_dir_all(parent).map_err(|error| {
            anyhow!(
                "cannot create the screenshot directory {}: {error}",
                parent.display()
            )
        })?;
        std::fs::write(path, data)
            .map_err(|error| anyhow!("cannot write the screenshot {}: {error}", path.display()))?;
        Ok("screenshot.png".to_string())
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
        body: impl FnOnce(&mut BrowserHandle) -> Result<T>,
    ) -> Result<T> {
        let mut guard = self
            .handle
            .lock()
            .map_err(|_| anyhow!("the browser session lock was poisoned by an earlier panic"))?;
        if guard.is_none() {
            *guard = Some(BrowserHandle::launch(config, runtime)?);
        }
        let handle = guard.as_mut().expect("just ensured to be Some");
        body(handle)
    }

    /// Run `body` only when a session is already open.
    ///
    /// Unlike [`Self::with`], this never launches a browser. A post-action check
    /// must observe the page that the action changed, not open a new blank one.
    pub fn with_open<T>(&self, body: impl FnOnce(&mut BrowserHandle) -> Result<T>) -> Result<T> {
        let mut guard = self
            .handle
            .lock()
            .map_err(|_| anyhow!("the browser session lock was poisoned by an earlier panic"))?;
        let handle = guard
            .as_mut()
            .ok_or_else(|| anyhow!("the browser session is not open"))?;
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
                    // Displayable: the operator uses this to go find the browser,
                    // so it has to be a path they can act on.
                    looked_for: vec![pangu_core::util::displayable_path(&path)],
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
    for argument in &extra_args {
        let forbidden = [
            "--remote-debugging-address",
            "--remote-debugging-port",
            "--remote-debugging-socket",
        ];
        if forbidden
            .iter()
            .any(|prefix| argument == prefix || argument.starts_with(&format!("{prefix}=")))
        {
            bail!("[browser] args must not override the loopback debugger endpoint: {argument}");
        }
    }
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
pub fn navigation_host(url: &str) -> Result<String> {
    let parsed =
        url::Url::parse(url).map_err(|error| anyhow!("`url` is not a valid URL: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        bail!(
            "browser navigation only supports http and https; got `{}`",
            parsed.scheme()
        );
    }
    let host_name = parsed
        .host_str()
        .ok_or_else(|| anyhow!("the URL has no host"))?
        .to_ascii_lowercase();
    let port = parsed.port_or_known_default().unwrap_or(443);
    Ok(if host_name.contains(':') {
        format!("[{host_name}]:{port}")
    } else {
        format!("{host_name}:{port}")
    })
}

pub fn require_navigation_url(
    url: &str,
    mut check_url: impl FnMut(&str) -> Result<()>,
    validated_hosts: &[String],
) -> Result<()> {
    check_url(url)?;
    require_validated_navigation_host(url, validated_hosts)
}

pub fn require_validated_navigation_host(url: &str, validated_hosts: &[String]) -> Result<()> {
    let host = navigation_host(url)?;
    if !validated_hosts.iter().any(|validated| validated == &host) {
        bail!("navigation host `{host}` was not validated by L3");
    }
    Ok(())
}

pub fn validated_screenshot_path(
    configured_dir: &std::path::Path,
    validated_paths: &[std::path::PathBuf],
) -> Result<std::path::PathBuf> {
    let requested = configured_dir.join("screenshot.png");
    require_validated_screenshot_path(&requested, validated_paths)?;
    validated_paths
        .iter()
        .find(|validated| same_path(validated, &requested))
        .cloned()
        .ok_or_else(|| anyhow!("screenshot path was not validated by L3"))
}

pub fn require_validated_screenshot_path(
    path: &std::path::Path,
    validated_paths: &[std::path::PathBuf],
) -> Result<()> {
    if !validated_paths
        .iter()
        .any(|validated| same_path(validated, path))
    {
        bail!(
            "screenshot path `{}` was not validated by L3",
            path.display()
        );
    }
    Ok(())
}

fn same_path(left: &std::path::Path, right: &std::path::Path) -> bool {
    let left = lexical_components(left);
    let right = lexical_components(right);
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            // Windows paths are case-insensitive. Linux paths are not, so a
            // case-only difference must remain a different file there.
            if cfg!(windows) {
                left.eq_ignore_ascii_case(&right)
            } else {
                *left == right
            }
        })
}

fn strip_verbatim_prefix(component: &str) -> String {
    if let Some(rest) = component.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    component
        .strip_prefix(r"\\?\")
        .unwrap_or(component)
        .to_string()
}

fn lexical_components(path: &std::path::Path) -> Vec<String> {
    let mut components = Vec::new();
    let mut prefix_len = 0usize;
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                // Never pop a root or drive prefix. Doing so could make an
                // absolute path compare equal to a different relative path.
                if components.len() > prefix_len {
                    components.pop();
                } else {
                    components.push("..".to_string());
                }
            }
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                components.push(strip_verbatim_prefix(
                    &component.as_os_str().to_string_lossy(),
                ));
                prefix_len = components.len();
            }
            std::path::Component::Normal(name) => {
                components.push(name.to_string_lossy().into_owned());
            }
        }
    }
    components
}

pub fn require_validated_browser_action(name: &str, browser_session: bool) -> Result<()> {
    // Open is authorized by its checked host, and screenshot by its writable
    // artifact path. Read, click, and type use the browser session itself.
    if matches!(name, "browser_read" | "browser_click" | "browser_type") && !browser_session {
        bail!("`{name}` was not authorized as a browser session; L3 did not validate it");
    }
    Ok(())
}

pub fn page_must_not_remain_open(error: &anyhow::Error) -> bool {
    let text = error.to_string();
    text.contains("landed outside the boundary") || text.contains("not an allowed http(s) page")
}

pub fn require_allowed_page_url(
    url: &str,
    mut check_host: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let parsed = url::Url::parse(url).map_err(|error| anyhow!("landed URL is invalid: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        bail!(
            "navigation landed on `{}`, which is not an allowed http(s) page",
            parsed.scheme()
        );
    }
    let host_name = parsed
        .host_str()
        .ok_or_else(|| anyhow!("navigation landed on a URL with no host"))?
        .to_ascii_lowercase();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let host = if host_name.contains(':') {
        format!("[{host_name}]:{port}")
    } else {
        format!("{host_name}:{port}")
    };
    check_host(&host)
        .map_err(|error| anyhow!("navigation landed outside the boundary on {host}: {error}"))
}

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
    fn a_redirected_page_is_checked_again() {
        let error =
            require_allowed_page_url("https://outside.example/", |_| Err(anyhow!("host denied")))
                .expect_err("the landed host must be checked");
        assert!(error.to_string().contains("outside"), "{error}");

        let error = require_allowed_page_url("file:///etc/passwd", |_| Ok(()))
            .expect_err("a redirect to file: must be refused");
        assert!(error.to_string().contains("file"), "{error}");
        assert!(page_must_not_remain_open(&error));
    }

    #[test]
    fn execution_refuses_a_browser_action_l3_did_not_authorize() {
        let error = require_validated_browser_action("browser_click", false)
            .expect_err("click needs the validated session");
        assert!(error.to_string().contains("L3"), "{error}");
        require_validated_browser_action("browser_click", true).expect("validated click");
        require_validated_browser_action("browser_screenshot", false)
            .expect("screenshot is authorized by its write path");
        require_validated_browser_action("browser_open", false)
            .expect("open is authorized by its checked host");
        require_validated_navigation_host(
            "https://allowed.example/path",
            &["allowed.example:443".into()],
        )
        .expect("the validated host may be opened");
        let error = require_validated_navigation_host(
            "https://other.example/",
            &["allowed.example:443".into()],
        )
        .expect_err("a different host must not reuse the approval");
        assert!(error.to_string().contains("other.example"), "{error}");
        let error = require_navigation_url(
            "https://user:secret@allowed.example/",
            |_| Err(anyhow!("credentials are forbidden")),
            &["allowed.example:443".into()],
        )
        .expect_err("credentials must be rejected before navigation");
        assert!(error.to_string().contains("credential"), "{error}");
        let approved = std::path::PathBuf::from("artifacts/screenshot.png");
        require_validated_screenshot_path(&approved, std::slice::from_ref(&approved))
            .expect("the validated screenshot path may be written");
        let error = require_validated_screenshot_path(
            std::path::Path::new("artifacts/screenshot-002.png"),
            &[std::path::PathBuf::from("artifacts/screenshot.png")],
        )
        .expect_err("a different filename must not reuse the approval");
        assert!(error.to_string().contains("screenshot-002"), "{error}");
        let case_difference = require_validated_screenshot_path(
            std::path::Path::new("Artifacts/Screenshot.PNG"),
            &[approved],
        );
        if cfg!(windows) {
            case_difference.expect("Windows path comparison ignores ASCII case");
        } else {
            case_difference.expect_err("Linux path comparison remains case-sensitive");
        }
        require_validated_screenshot_path(
            std::path::Path::new("artifacts/./screenshot.png"),
            &[std::path::PathBuf::from("artifacts/screenshot.png")],
        )
        .expect("a current-directory component does not change the file");
        let selected = validated_screenshot_path(
            std::path::Path::new("artifacts"),
            &[std::path::PathBuf::from("artifacts/./screenshot.png")],
        )
        .expect("the canonical validated path is the one written");
        assert_eq!(
            selected,
            std::path::PathBuf::from("artifacts/./screenshot.png")
        );
        if cfg!(windows) {
            require_validated_screenshot_path(
                std::path::Path::new(r"\\?\C:\work\artifacts\screenshot.png"),
                &[std::path::PathBuf::from(
                    r"C:\work\artifacts\screenshot.png",
                )],
            )
            .expect("a Windows verbatim prefix does not change the file");
        }
    }

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
    fn debugger_endpoint_overrides_are_refused() {
        let error = resolve_config(
            None,
            std::path::PathBuf::from("/tmp/p"),
            false,
            vec!["--remote-debugging-address=0.0.0.0".into()],
        )
        .expect_err("must refuse");
        assert!(
            error.to_string().contains("must not override the loopback"),
            "{error}"
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
