//! A CDP session: launch a headless browser and drive it.
//!
//! # The protocol in one paragraph
//!
//! Chromium exposes an HTTP endpoint when started with `--remote-debugging-port`.
//! `GET /json/version` reports the browser-level WebSocket URL, and
//! `GET /json/new?<url>` opens a tab and returns its own WebSocket URL. Each
//! tab's socket accepts JSON commands of the form
//! `{"id": N, "method": "...", "params": {...}}` and replies with either
//! `{"id": N, "result": {...}}` or `{"id": N, "error": {...}}`, interleaved with
//! `{"method": "..."}` events that carry no id.
//!
//! # What this module is careful about
//!
//! - **A reply is matched to its request by id**, and replies for other ids are
//!   set aside rather than mistaken for the current one. CDP answers commands in
//!   order in practice, but relying on that would break the moment an event
//!   arrives mid-flight — which happens on every navigation.
//! - **An error reply is an error**, never a silent empty result. A navigation
//!   to a blocked host that returned "success" with no data is exactly the kind
//!   of false evidence this project exists to prevent.
//! - **Timeouts name the command that did not answer.** "Timed out" alone is not
//!   actionable.
//! - **The browser process is killed on drop.** A leaked headless browser holds
//!   the profile directory and a port, so the next run would fail for a reason
//!   that has nothing to do with it.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pangu_core::{Error, Result};
use serde_json::{json, Value};

use super::websocket::{Opcode, WebSocket};
use super::{BrowserConfig, BrowserUnavailable, COMMAND_TIMEOUT, LAUNCH_TIMEOUT};

/// One page as observed, with the facts a caller needs to act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageSnapshot {
    /// The page's current URL, as reported by the browser (after redirects).
    pub url: String,
    pub title: String,
    /// Visible text, already bounded and truncated by [`MAX_TEXT_BYTES`].
    pub text: String,
    /// Whether `text` was truncated, so a caller cannot mistake a clipped page
    /// for a complete one.
    pub truncated: bool,
}

/// Bound on the text a snapshot returns.
///
/// Bounded because a page's text is attacker-controlled input that flows into
/// the model's context; an unbounded read would let a page decide how much of
/// the budget it consumes.
pub const MAX_TEXT_BYTES: usize = 64 * 1024;

/// A live browser session.
pub struct BrowserSession {
    child: Child,
    profile_dir: std::path::PathBuf,
    socket: WebSocket,
    next_id: u64,
    /// Replies that arrived while waiting for a different command.
    pending: HashMap<u64, Value>,
    /// Whether this session's execution is isolated, recorded so the reported
    /// scope matches reality.
    isolates: bool,
    /// Whether page navigation may leave `data:` and `about:` URLs.
    network: bool,
}

impl BrowserSession {
    /// Launch a browser and attach to a fresh page.
    ///
    /// `runtime_launcher` is the program and leading arguments of a declared
    /// sandbox runtime (see [`crate::runtime::Runtime::launcher`]). When present,
    /// the browser is started *through* it so the browser process lives inside
    /// the sandbox rather than beside it. `None` means there is no declared
    /// sandbox, and the session records that fact.
    pub fn launch(
        config: &BrowserConfig,
        runtime_launcher: Option<(&str, &[String])>,
    ) -> Result<Self> {
        if !config.executable.is_file() {
            return Err(BrowserUnavailable::NotInstalled {
                // Displayable: this list is what the operator uses to go find the
                // browser, so it must be a path they can paste into a shell.
                looked_for: vec![pangu_core::util::displayable_path(&config.executable)],
            }
            .refusal());
        }
        create_private_profile_dir(&config.profile_dir)?;

        let args = config.args();
        let mut command = match runtime_launcher {
            Some((program, leading)) => {
                let mut command = Command::new(program);
                command.args(leading);
                command.arg(&config.executable);
                command
            }
            None => Command::new(&config.executable),
        };
        command
            .args(&args)
            // stderr is captured rather than inherited: Chromium writes a great
            // deal of noise, and on failure the last lines are the useful part.
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = command.spawn().map_err(|error| {
            BrowserUnavailable::LaunchFailed {
                reason: format!("{}: {error}", config.executable.display()),
            }
            .refusal()
        })?;

        let endpoint = wait_for_endpoint(&config.profile_dir)?;
        let tab = open_tab(&endpoint)?;
        let socket = connect_websocket(&tab)?;

        let session = Self {
            child,
            profile_dir: config.profile_dir.clone(),
            socket,
            next_id: 1,
            pending: HashMap::new(),
            isolates: runtime_launcher.is_some(),
            network: config.network,
        };
        Ok(session)
    }

    /// Whether the browser runs inside a declared sandbox runtime.
    ///
    /// Reported so a caller can say what was actually enforced instead of
    /// implying isolation whenever a browser is used.
    pub fn isolates(&self) -> bool {
        self.isolates
    }

    /// The operating system process id of the browser, for an audit record.
    pub fn process_id(&self) -> Option<u32> {
        Some(self.child.id())
    }

    /// Send a CDP command and return its result.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let request = json!({"id": id, "method": method, "params": params});
        self.socket.send_text(&request.to_string())?;

        let deadline = Instant::now() + COMMAND_TIMEOUT;
        loop {
            if let Some(reply) = self.pending.remove(&id) {
                return unwrap_reply(method, reply);
            }
            match self.read_message(deadline)? {
                Some(reply) => {
                    if reply.get("id").and_then(Value::as_u64) == Some(id) {
                        return unwrap_reply(method, reply);
                    }
                    self.retain_if_requested(reply);
                }
                None => {
                    return Err(Error::Other(format!(
                        "CDP command `{method}` did not answer within {}s",
                        COMMAND_TIMEOUT.as_secs()
                    )))
                }
            }
        }
    }

    /// Read one message, or `None` if the deadline passed.
    ///
    /// Returns `None` rather than an error so the caller can distinguish "no
    /// message yet" from "the connection is broken"; a broken connection is
    /// still an error, raised here.
    fn read_message(&mut self, deadline: Instant) -> Result<Option<Value>> {
        if Instant::now() >= deadline {
            return Ok(None);
        }
        let frame = self.socket.read_frame(deadline)?;
        match frame.opcode {
            Opcode::Close => Err(Error::Other(
                "the browser closed the CDP connection; the session ended".into(),
            )),
            Opcode::Text => {
                let text = String::from_utf8_lossy(&frame.payload);
                let value: Value = serde_json::from_str(&text).map_err(|error| {
                    Error::Other(format!("CDP sent a message that is not JSON: {error}"))
                })?;
                Ok(Some(value))
            }
            // CDP is a text protocol; a binary message means something else is
            // on this socket, which must not be parsed as CDP.
            Opcode::Binary => Err(Error::Other(
                "CDP sent a binary frame, but the protocol is text-only".into(),
            )),
            Opcode::Ping | Opcode::Pong => Ok(None),
        }
    }

    /// Navigate the page, waiting for the load event.
    pub fn navigate(&mut self, url: &str) -> Result<()> {
        if !self.network && !local_page_url(url) {
            return Err(Error::Other(format!(
                "navigation refused while network is disabled: {url}"
            )));
        }
        self.call("Page.enable", json!({}))?;
        let result = self.call("Page.navigate", json!({"url": url}))?;
        // Chromium reports a failed navigation inside a successful CDP result,
        // as `errorText`, rather than as a protocol error. Waiting for the load
        // event after that reports "the page did not finish loading" and throws
        // away the real reason.
        if let Some(error) = navigation_error_text(&result) {
            return Err(Error::Other(format!("navigation failed: {error}")));
        }
        self.wait_for_load()?;
        Ok(())
    }

    /// Wait for `Page.loadEventFired`, bounded.
    ///
    /// Bounded because a page can load forever; the caller gets a timeout naming
    /// the page rather than a run that never proceeds.
    fn wait_for_load(&mut self) -> Result<()> {
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        loop {
            match self.read_message(deadline)? {
                Some(message) => {
                    if message.get("method").and_then(Value::as_str) == Some("Page.loadEventFired")
                    {
                        return Ok(());
                    }
                    // A command can fail after its first result was accepted.
                    // Keeping only the reply and waiting for the load event would
                    // turn that failure into a generic load timeout.
                    if message.get("error").is_some() {
                        return unwrap_reply("Page.navigate", message).map(|_| ());
                    }
                    self.retain_if_requested(message);
                }
                None => {
                    return Err(Error::Other(format!(
                        "the page did not finish loading within {}s",
                        COMMAND_TIMEOUT.as_secs()
                    )))
                }
            }
        }
    }

    /// Observe the current page: URL, title and visible text.
    ///
    /// The text comes from `document.body.innerText`, which is what a reader
    /// sees — not the HTML source, which would include scripts and styles the
    /// user never sees and would let a page hide text from a human while
    /// showing it to the model.
    pub fn snapshot(&mut self) -> Result<PageSnapshot> {
        let url = self.evaluate("document.location.href")?;
        let title = self.evaluate("document.title")?;
        let text = self.evaluate("document.body ? document.body.innerText : ''")?;

        let truncated = text.len() > MAX_TEXT_BYTES;
        let text = if truncated {
            // Truncate on a character boundary: slicing mid-codepoint would
            // produce invalid UTF-8 and panic.
            let mut end = MAX_TEXT_BYTES;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            text[..end].to_string()
        } else {
            text
        };

        Ok(PageSnapshot {
            url,
            title,
            text,
            truncated,
        })
    }

    /// Evaluate a JavaScript expression and return its string value.
    ///
    /// Non-string results are rendered as their JSON form rather than dropped:
    /// a `null` page must be distinguishable from a missing value.
    pub fn evaluate(&mut self, expression: &str) -> Result<String> {
        let reply = self.call(
            "Runtime.evaluate",
            json!({
                "expression": expression,
                // `returnByValue` so the result arrives as data rather than as a
                // remote object handle the caller would have to fetch.
                "returnByValue": true,
                "awaitPromise": true,
            }),
        )?;
        if let Some(exception) = reply
            .get("exceptionDetails")
            .and_then(|details| details.get("text"))
            .and_then(Value::as_str)
        {
            return Err(Error::Other(format!(
                "the page raised an error while evaluating: {exception}"
            )));
        }
        let value = reply
            .get("result")
            .and_then(|result| result.get("value"))
            .cloned()
            .unwrap_or(Value::Null);
        Ok(match value {
            Value::String(text) => text,
            Value::Null => String::new(),
            other => other.to_string(),
        })
    }

    /// Take a PNG screenshot of the visible viewport.
    pub fn screenshot(&mut self) -> Result<Vec<u8>> {
        let reply = self.call(
            "Page.captureScreenshot",
            json!({"format": "png", "captureBeyondViewport": false}),
        )?;
        let encoded = reply
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Other("the screenshot reply carried no image data".into()))?;
        decode_base64(encoded)
    }

    /// Click the element matching a CSS selector.
    ///
    /// The click is dispatched through `Input.dispatchMouseEvent` at the
    /// element's centre rather than via `element.click()`, because a synthetic
    /// DOM click does not go through hit-testing: it would fire on an element
    /// that is covered by an overlay or scrolled out of view, and the caller
    /// would believe a real user action happened.
    pub fn click(&mut self, selector: &str) -> Result<()> {
        let box_reply = self.call(
            "Runtime.evaluate",
            json!({
                "expression": format!(
                    "(() => {{ const el = document.querySelector({}); \
                     if (!el) return null; \
                     el.scrollIntoView({{block: 'center'}}); \
                     const r = el.getBoundingClientRect(); \
                     return JSON.stringify({{x: r.left + r.width / 2, y: r.top + r.height / 2}}); }})()",
                    serde_json::to_string(selector).expect("selector is a string")
                ),
                "returnByValue": true,
            }),
        )?;
        let raw = box_reply
            .get("result")
            .and_then(|result| result.get("value"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Error::Other(format!(
                    "no element matched the selector {selector:?}; nothing was clicked"
                ))
            })?;
        let point: Value = serde_json::from_str(raw)
            .map_err(|error| Error::Other(format!("could not read the element's box: {error}")))?;
        let x = point.get("x").and_then(Value::as_f64).unwrap_or(0.0);
        let y = point.get("y").and_then(Value::as_f64).unwrap_or(0.0);

        for kind in ["mousePressed", "mouseReleased"] {
            self.call(
                "Input.dispatchMouseEvent",
                json!({
                    "type": kind,
                    "x": x,
                    "y": y,
                    "button": "left",
                    "clickCount": 1,
                }),
            )?;
        }
        Ok(())
    }

    /// Type text into the focused element, character by character.
    ///
    /// Per-character because a single `Input.insertText` does not fire the key
    /// events that most frameworks listen to, so a form would appear filled
    /// while its handlers never ran.
    pub fn type_text(&mut self, text: &str) -> Result<()> {
        for character in text.chars() {
            self.call(
                "Input.dispatchKeyEvent",
                json!({"type": "keyDown", "text": character.to_string()}),
            )?;
            self.call(
                "Input.dispatchKeyEvent",
                json!({"type": "keyUp", "text": character.to_string()}),
            )?;
        }
        Ok(())
    }
}

impl Drop for BrowserSession {
    fn drop(&mut self) {
        // Ask the browser to exit cleanly, then make sure of it. A leaked
        // headless browser holds the profile directory and the port, so the next
        // run would fail for reasons unrelated to itself.
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The profile holds cookies and cache outside the workspace. Leaving it
        // in the system temporary directory would preserve that state after the
        // session ends.
        if let Err(error) = remove_profile_dir(&self.profile_dir) {
            eprintln!("pangu: {error}");
        }
    }
}

impl BrowserSession {
    /// Keep a reply only when it answers a command this session actually sent.
    fn retain_if_requested(&mut self, message: Value) {
        if retainable_reply_id(message.get("id").and_then(Value::as_u64), self.next_id).is_some() {
            if let Some(id) = message.get("id").and_then(Value::as_u64) {
                self.pending.insert(id, message);
            }
        }
    }
}

/// Whether a reply id may be stored while waiting for something else.
///
/// Both `call` and `wait_for_load` read the socket, so both must apply this
/// rule. A peer chooses the ids it sends. Retaining every one would let a
/// hostile or merely broken page grow `pending` without limit — each reply up
/// to `MAX_FRAME_BYTES` (32 MiB) — until the process runs out of memory.
/// `next_id` counts upward from the start of the session, so an id at or above
/// it was never requested and can never be awaited. An ordinary `browser_open`
/// reaches this path; compromising the socket first is not required.
pub(crate) fn remove_profile_dir(path: &std::path::Path) -> Result<()> {
    let root = std::env::temp_dir().join("pangu-browser");
    std::fs::create_dir_all(&root).map_err(|error| {
        Error::Other(format!(
            "cannot prepare the browser profile root {}: {error}",
            root.display()
        ))
    })?;
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        Error::Other(format!(
            "cannot resolve browser profile {}: {error}",
            path.display()
        ))
    })?;
    let canonical_root = std::fs::canonicalize(&root).map_err(|error| {
        Error::Other(format!(
            "cannot resolve the browser profile root {}: {error}",
            root.display()
        ))
    })?;
    if !profile_is_child_of(&canonical, &canonical_root) {
        return Err(Error::Other(format!(
            "refusing to delete browser profile outside pangu-browser: {}",
            canonical.display()
        )));
    }
    std::fs::remove_dir_all(path).map_err(|error| {
        Error::Other(format!(
            "cannot delete browser profile {}: {error}",
            path.display()
        ))
    })
}

pub(crate) fn create_private_profile_dir(path: &std::path::Path) -> Result<()> {
    let temp = std::env::temp_dir();
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component);
        if current.starts_with(&temp) && current != temp {
            if let Ok(metadata) = std::fs::symlink_metadata(&current) {
                if metadata.file_type().is_symlink() {
                    return Err(Error::Other(format!(
                        "refusing to use a symlinked browser profile: {}",
                        current.display()
                    )));
                }
            }
        }
    }
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(Error::Other(format!(
                "refusing to use a symlinked browser profile: {}",
                path.display()
            )));
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            Error::Other(format!(
                "cannot create the browser profile root {}: {error}",
                parent.display()
            ))
        })?;
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(Error::Other(format!(
                "cannot create the browser profile directory {}: {error}",
                path.display()
            )));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                Error::Other(format!(
                    "cannot restrict the browser profile directory {}: {error}",
                    path.display()
                ))
            },
        )?;
    }
    Ok(())
}

fn profile_is_child_of(path: &std::path::Path, root: &std::path::Path) -> bool {
    let mut path = path.components();
    for component in root.components() {
        if path.next() != Some(component) {
            return false;
        }
    }
    path.next().is_some()
}

fn retainable_reply_id(id: Option<u64>, next_id: u64) -> Option<u64> {
    id.filter(|id| *id < next_id)
}

/// The navigation failure carried inside an otherwise successful CDP result.
///
fn local_page_url(url: &str) -> bool {
    let scheme = url.split_once(':').map(|(scheme, _)| scheme);
    matches!(scheme, Some("data" | "about"))
}

/// `Page.navigate` returns `{"result":{"frameId":"...","errorText":"net::ERR_..."}}`
/// when the URL cannot be loaded. An empty or whitespace-only value is not a
/// failure: a successful result has no `errorText`.
fn navigation_error_text(result: &Value) -> Option<&str> {
    result
        .get("errorText")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

/// Turn a CDP reply into a result or an error.
///
/// An `error` member is a failure, never an empty success.
fn unwrap_reply(method: &str, reply: Value) -> Result<Value> {
    if let Some(error) = reply.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("no message");
        let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
        return Err(Error::Other(format!(
            "CDP command `{method}` failed (code {code}): {message}"
        )));
    }
    Ok(reply.get("result").cloned().unwrap_or(Value::Null))
}

/// Wait for the browser to write its endpoint into the profile directory.
///
/// Chromium writes `DevToolsActivePort` with the port on the first line and the
/// browser path on the second. Polling is used because the file appears only
/// after the browser has bound its socket; a fixed sleep would be either too
/// short (flaky) or too long (slow).
fn wait_for_endpoint(profile_dir: &std::path::Path) -> Result<String> {
    let marker = profile_dir.join("DevToolsActivePort");
    let deadline = Instant::now() + LAUNCH_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(contents) = std::fs::read_to_string(&marker) {
            let mut lines = contents.lines();
            if let Some(port) = lines.next().map(str::trim) {
                if port.chars().all(|character| character.is_ascii_digit())
                    && port.parse::<u16>().ok().filter(|port| *port > 0).is_some()
                {
                    let path = lines.next().unwrap_or("/devtools/browser").trim();
                    if !path.starts_with("/devtools/")
                        || path.contains("..")
                        || path.chars().any(|character| {
                            character.is_control() || matches!(character, '?' | '#' | '\\' | ' ')
                        })
                    {
                        return Err(Error::Other(format!(
                            "the browser published an unexpected debugger path: {path}"
                        )));
                    }
                    return Ok(format!("ws://127.0.0.1:{port}{path}"));
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(BrowserUnavailable::DidNotPublishEndpoint {
        waited_secs: LAUNCH_TIMEOUT.as_secs(),
    }
    .refusal())
}

/// Open a tab and return its WebSocket URL.
fn open_tab(endpoint: &str) -> Result<String> {
    // The browser-level socket can create targets directly, which avoids
    // depending on the HTTP `/json/new` endpoint that some builds restrict to
    // same-origin requests.
    if let Some(host) = endpoint.strip_prefix("ws://") {
        let (authority, _) = host.split_once('/').unwrap_or((host, ""));
        let (address, port) = authority
            .split_once(':')
            .ok_or_else(|| Error::Other(format!("unexpected endpoint form: {endpoint}")))?;
        let target = request_over_http(address, port, "PUT", "/json/new?about:blank")
            .or_else(|_| request_over_http(address, port, "GET", "/json/new?about:blank"))?;
        let parsed: Value = serde_json::from_str(&target)
            .map_err(|error| Error::Other(format!("could not read the new tab reply: {error}")))?;
        let url = parsed
            .get("webSocketDebuggerUrl")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                Error::Other("the browser opened a tab but returned no debugger URL".into())
            })?;
        require_loopback_websocket(&url)?;
        return Ok(url);
    }
    Err(Error::Other(format!(
        "the browser endpoint {endpoint} is not a WebSocket URL"
    )))
}

/// A bounded single-request HTTP call, used only for `/json/new`.
fn require_loopback_websocket(url: &str) -> Result<()> {
    let rest = url
        .strip_prefix("ws://")
        .ok_or_else(|| Error::Other(format!("unsupported CDP endpoint: {url}")))?;
    let authority = rest
        .split_once('/')
        .map(|(authority, _)| authority)
        .unwrap_or(rest);
    let host = authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(authority);
    if host != "127.0.0.1" && host != "localhost" && host != "[::1]" {
        return Err(Error::Other(format!(
            "refusing a CDP endpoint that is not loopback: {url}"
        )));
    }
    Ok(())
}

fn request_over_http(address: &str, port: &str, method: &str, path: &str) -> Result<String> {
    let mut stream = TcpStream::connect(format!("{address}:{port}")).map_err(|error| {
        Error::Other(format!("cannot reach the browser's HTTP endpoint: {error}"))
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| Error::Other(format!("cannot set a read timeout: {error}")))?;
    let request =
        format!("{method} {path} HTTP/1.1\r\nHost: {address}:{port}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| Error::Other(format!("cannot send the tab request: {error}")))?;

    // Read the head, then exactly `Content-Length` bytes of body.
    //
    // Reading to EOF instead would hang: Chromium answers this endpoint over a
    // kept-alive connection and never closes it, so a "read until closed" would
    // wait for the read timeout on every successful call — which is what an
    // earlier version of this function did, and it made every browser test fail
    // with a connection timeout while the browser was working perfectly.
    let mut collected = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(10);
    let head_end = loop {
        if let Some(position) = collected.windows(4).position(|w| w == b"\r\n\r\n") {
            break position + 4;
        }
        if Instant::now() >= deadline {
            return Err(Error::Other(
                "the browser did not answer the tab request in time".into(),
            ));
        }
        if collected.len() > 64 * 1024 {
            return Err(Error::Other(
                "the browser's tab response header was unreasonably large".into(),
            ));
        }
        let read = stream
            .read(&mut chunk)
            .map_err(|error| Error::Other(format!("cannot read the tab response: {error}")))?;
        if read == 0 {
            return Err(Error::Other(
                "the browser closed the connection during the tab request".into(),
            ));
        }
        collected.extend_from_slice(&chunk[..read]);
    };

    let head = String::from_utf8_lossy(&collected[..head_end]).into_owned();
    let status_ok = head
        .lines()
        .next()
        .map(|line| line.contains("200"))
        .unwrap_or(false);
    if !status_ok {
        return Err(Error::Other(format!(
            "the browser refused to open a tab: {}",
            head.lines().next().unwrap_or("<empty>")
        )));
    }
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .ok_or_else(|| {
            Error::Other("the tab response had no Content-Length; refusing to guess its end".into())
        })?;
    if length > 1024 * 1024 {
        return Err(Error::Other(format!(
            "the tab response declared {length} bytes, which is larger than a tab descriptor"
        )));
    }

    let mut body = collected[head_end..].to_vec();
    while body.len() < length {
        if Instant::now() >= deadline {
            return Err(Error::Other(format!(
                "the tab response stopped after {} of {length} bytes",
                body.len()
            )));
        }
        let read = stream
            .read(&mut chunk)
            .map_err(|error| Error::Other(format!("cannot read the tab body: {error}")))?;
        if read == 0 {
            return Err(Error::Other(format!(
                "the browser closed the connection after {} of {length} bytes",
                body.len()
            )));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    String::from_utf8(body)
        .map_err(|error| Error::Other(format!("the tab response was not UTF-8: {error}")))
}

/// Connect a WebSocket to a CDP endpoint URL.
fn connect_websocket(url: &str) -> Result<WebSocket> {
    require_loopback_websocket(url)?;
    let rest = url
        .strip_prefix("ws://")
        .ok_or_else(|| Error::Other(format!("unsupported CDP endpoint: {url}")))?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host_header = authority.to_string();
    let stream = TcpStream::connect(authority)
        .map_err(|error| Error::Other(format!("cannot connect to the CDP endpoint: {error}")))?;
    stream
        .set_read_timeout(Some(COMMAND_TIMEOUT))
        .map_err(|error| Error::Other(format!("cannot set a read timeout: {error}")))?;
    let key = generate_handshake_key();
    WebSocket::handshake(stream, &host_header, &format!("/{path}"), &key)
}

/// A random-looking `Sec-WebSocket-Key`, base64 of 16 bytes.
///
/// Not a secret: the RFC uses it to prove the server read the request, not to
/// authenticate either end.
fn generate_handshake_key() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    hasher.write_u64(std::process::id() as u64);
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&hasher.finish().to_be_bytes());
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(hasher.finish());
    bytes[8..].copy_from_slice(&hasher.finish().to_be_bytes());
    super::websocket::encode_base64(&bytes)
}

/// Decode standard base64, rejecting malformed input.
fn decode_base64(input: &str) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            // Whitespace is tolerated; anything else is a real error.
            b'\r' | b'\n' | b' ' | b'\t' => continue,
            other => {
                return Err(Error::Other(format!(
                    "the screenshot data contained an invalid base64 character: {other:#X}"
                )))
            }
        };
        accumulator = (accumulator << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
    }
    Ok(output)
}

/// Where the browser writes its endpoint, for diagnostics.
pub fn endpoint_marker(profile_dir: &std::path::Path) -> PathBuf {
    profile_dir.join("DevToolsActivePort")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unsolicited_reply_id_is_not_retained() {
        // The session has issued ids 1 and 2, so the next id is 3. A peer that
        // invents ids must not be able to make the client store them.
        assert_eq!(retainable_reply_id(Some(1), 3), Some(1));
        assert_eq!(retainable_reply_id(Some(2), 3), Some(2));
        assert_eq!(retainable_reply_id(Some(3), 3), None);
        assert_eq!(retainable_reply_id(Some(u64::MAX), 3), None);
        assert_eq!(retainable_reply_id(None, 3), None);
    }

    #[test]
    fn a_navigation_result_keeps_its_error_text() {
        let failed = json!({"frameId": "abc", "errorText": "net::ERR_NAME_NOT_RESOLVED"});
        assert_eq!(
            navigation_error_text(&failed),
            Some("net::ERR_NAME_NOT_RESOLVED")
        );
        assert_eq!(
            navigation_error_text(&json!({"frameId": "abc"})),
            None,
            "a result without errorText loaded successfully"
        );
        assert_eq!(
            navigation_error_text(&json!({"errorText": "   "})),
            None,
            "whitespace is not a navigation failure"
        );
    }

    #[test]
    fn an_error_reply_becomes_an_error_not_an_empty_result() {
        // A navigation that "succeeded" with no data would be false evidence.
        let reply = json!({"id": 1, "error": {"code": -32000, "message": "net::ERR_FAILED"}});
        let error = unwrap_reply("Page.navigate", reply).expect_err("must fail");
        let text = error.to_string();
        assert!(text.contains("Page.navigate"), "{text}");
        assert!(text.contains("ERR_FAILED"), "{text}");
        assert!(text.contains("-32000"), "the code must be kept: {text}");
    }

    #[test]
    fn a_result_reply_is_unwrapped() {
        let reply = json!({"id": 1, "result": {"frameId": "abc"}});
        let result = unwrap_reply("Page.navigate", reply).expect("must succeed");
        assert_eq!(result.get("frameId").and_then(Value::as_str), Some("abc"));
    }

    #[test]
    fn a_result_with_no_body_is_null_not_an_error() {
        // Some commands legitimately return nothing; that is not a failure.
        let reply = json!({"id": 1, "result": {}});
        assert!(unwrap_reply("Runtime.enable", reply).is_ok());
    }

    #[test]
    fn base64_round_trips_a_png_header() {
        // The PNG magic bytes, which is what a screenshot must start with.
        let png: Vec<u8> = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let encoded = crate::browser::websocket::encode_base64(&png);
        assert_eq!(decode_base64(&encoded).expect("decode"), png);
    }

    #[test]
    fn base64_rejects_an_invalid_character() {
        let error = decode_base64("AAA$").expect_err("must reject");
        assert!(error.to_string().contains("invalid base64"), "{error}");
    }

    #[test]
    fn base64_tolerates_line_wrapping() {
        // Some CDP builds wrap the payload; treating that as corruption would
        // fail on a valid screenshot.
        let decoded = decode_base64("aGVs\r\nbG8=").expect("decode");
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn ending_a_session_removes_its_temporary_profile() {
        let shared_root = std::env::temp_dir().join("pangu-browser");
        let _ = std::fs::remove_dir_all(&shared_root);
        let unrelated =
            std::env::temp_dir().join(format!("pangu-unrelated-{}", std::process::id()));
        std::fs::create_dir_all(&unrelated).expect("unrelated");
        let missing_root = remove_profile_dir(&unrelated);
        assert!(
            missing_root.is_err(),
            "a missing profile root must not make cleanup unrestricted"
        );
        assert!(unrelated.exists());
        let _ = std::fs::remove_dir_all(unrelated);
        let root = std::env::temp_dir()
            .join("pangu-browser")
            .join(format!("profile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("profile");
        std::fs::write(root.join("Cookies"), b"secret").expect("cookie");
        remove_profile_dir(&root).expect("the temporary profile must be removable");
        let escaped = std::env::temp_dir().join("pangu-browser-outside");
        let escaped_via_parent = root.join("..").join("..").join("pangu-browser-outside");
        std::fs::create_dir_all(&escaped).expect("outside");
        let refused = remove_profile_dir(&escaped_via_parent);
        assert!(
            refused.is_err(),
            "cleanup must not delete an unrelated directory"
        );
        assert!(
            !root.exists(),
            "the temporary profile must not survive the session"
        );
        assert!(escaped.exists(), "a parent escape must not be deleted");
        let shared_root = std::env::temp_dir().join("pangu-browser");
        std::fs::create_dir_all(shared_root.join("other-session")).expect("other session");
        let refused_root = remove_profile_dir(&shared_root);
        assert!(
            refused_root.is_err(),
            "cleanup must not delete the shared profile root"
        );
        assert!(shared_root.join("other-session").exists());
        let sibling = std::env::temp_dir().join("pangu-browser-evil");
        std::fs::create_dir_all(&sibling).expect("sibling");
        let refused_sibling = remove_profile_dir(&sibling);
        assert!(
            refused_sibling.is_err(),
            "a similarly named sibling must not match the profile root"
        );
        assert!(sibling.exists());
        let _ = std::fs::remove_dir_all(sibling);
        let _ = std::fs::remove_dir_all(escaped);
    }

    #[test]
    fn a_browser_profile_is_private_to_its_owner() {
        let root = std::env::temp_dir().join(format!(
            "pangu-browser-private-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        create_private_profile_dir(&root).expect("private profile");
        assert!(root.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&root)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "other users must not read browser cookies");
        }
        let _ = std::fs::remove_dir_all(root);
        #[cfg(unix)]
        {
            let link_root = std::env::temp_dir().join("pangu-browser");
            std::fs::create_dir_all(&link_root).expect("link root");
            let linked = link_root.join(format!("link-{}", std::process::id()));
            let target =
                std::env::temp_dir().join(format!("pangu-link-target-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&target);
            std::fs::create_dir_all(&target).expect("link target");
            let _ = std::fs::remove_file(&linked);
            std::os::unix::fs::symlink(&target, &linked).expect("symlink");
            let refused = create_private_profile_dir(&linked);
            assert!(refused.is_err(), "a profile symlink must not be followed");
            let _ = std::fs::remove_file(linked);
            let _ = std::fs::remove_dir_all(target);
            let parent_link = link_root.join(format!("parent-link-{}", std::process::id()));
            let parent_target =
                std::env::temp_dir().join(format!("pangu-parent-target-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&parent_target);
            std::fs::create_dir_all(&parent_target).expect("parent target");
            let _ = std::fs::remove_file(&parent_link);
            std::os::unix::fs::symlink(&parent_target, &parent_link).expect("parent symlink");
            let child = parent_link.join("session");
            let refused_parent = create_private_profile_dir(&child);
            assert!(
                refused_parent.is_err(),
                "a symlinked parent must not receive the profile"
            );
            assert!(!parent_target.join("session").exists());
            let _ = std::fs::remove_file(parent_link);
            let _ = std::fs::remove_dir_all(parent_target);
        }
    }

    #[test]
    fn a_non_loopback_debugger_url_is_refused() {
        let error = require_loopback_websocket("ws://10.0.0.8:9222/devtools/page/1")
            .expect_err("remote debugger");
        assert!(error.to_string().contains("not loopback"), "{error}");
        require_loopback_websocket("ws://127.0.0.1:9222/devtools/page/1").expect("loopback");
    }

    #[test]
    fn the_endpoint_marker_lives_in_the_profile_directory() {
        let dir = PathBuf::from("/run/browser/s1");
        assert_eq!(
            endpoint_marker(&dir),
            PathBuf::from("/run/browser/s1/DevToolsActivePort")
        );
    }

    #[test]
    fn handshake_keys_differ_between_calls() {
        // A constant key would still interoperate, which is precisely why a
        // regression here would go unnoticed.
        let keys = (0..8).map(|_| generate_handshake_key()).collect::<Vec<_>>();
        let unique = keys.iter().collect::<std::collections::HashSet<_>>();
        assert!(unique.len() > 1, "handshake keys repeated: {keys:?}");
    }
}
