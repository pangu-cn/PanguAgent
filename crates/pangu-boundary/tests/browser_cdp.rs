//! The CDP client driven against a real browser.
//!
//! # Why this suite exists
//!
//! The unit tests in `browser::*` prove the frame codec, the handshake token and
//! the reply handling in isolation. They cannot prove the client interoperates
//! with Chromium: a codec can be self-consistent and still speak the wrong
//! dialect. These tests start a real headless browser and assert on what it
//! actually returns.
//!
//! # Test isolation
//!
//! These tests launch a browser, so they are `#[ignore]`d by default and must be
//! run explicitly:
//!
//! ```text
//! cargo test -p pangu-boundary --test browser_cdp -- --ignored --test-threads=1
//! ```
//!
//! They are ignored rather than skipped silently for the same reason as the
//! container tests: a test that quietly does nothing reports success it did not
//! earn. When no browser is installed the tests fail with a message saying so,
//! rather than passing.
//!
//! # `--test-threads=1` is required, not a preference
//!
//! Each test launches its own Chromium, and `cargo test` runs tests in parallel
//! by default. Nine simultaneous browser launches is more than the teardown keeps
//! up with: a leaked profile directory was reproduced under concurrency and does
//! **not** occur serially, on the same machine.
//!
//! The failure mode is quiet, which is why it is written down. The tests still
//! *pass* while a browser and its profile survive; the damage appears later as an
//! unrelated flake, because a stale profile holds a lock and the next run then
//! fails for a reason that has nothing to do with the code under test. That is
//! the same class of misleading signal the rest of this suite exists to avoid.
//! CI passes `--test-threads=1` for this reason.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use pangu_boundary::browser::{BrowserConfig, BrowserSession};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A per-test root under the OS temp directory, removed when the test ends.
///
/// Cleanup is not cosmetic. A Chromium profile directory holds a lock, and a
/// leaked one leaves a browser holding it; 36 such directories accumulated while
/// this suite was being written, and one run failed for that reason rather than
/// for anything in the code. Reusing a fixed path would be worse still, since
/// concurrent runs would then collide by construction.
///
/// Removal is best-effort: on Windows a just-killed process can still hold its
/// files for a moment, and failing a passing test over leftover temp files would
/// be the wrong trade. The `Drop` runs whether the test passed or panicked, so a
/// failing assertion does not also leak.
struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "pangu-cdp-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("create root");
        Self(root)
    }
}
impl std::ops::Deref for TempRoot {
    type Target = std::path::Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<std::path::Path> for TempRoot {
    fn as_ref(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        // A few retries: Chromium's teardown is asynchronous, so the first
        // attempt can lose a race with the process it just exited.
        for _ in 0..5 {
            if std::fs::remove_dir_all(&self.0).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

fn temp_root(label: &str) -> TempRoot {
    TempRoot::new(label)
}

fn config(root: &std::path::Path) -> BrowserConfig {
    BrowserConfig {
        executable: BrowserConfig::find_executable().unwrap_or_else(|| {
            // Loud on purpose. These tests are `#[ignore]`d precisely so that
            // "no browser here" is never silently reported as success; a skip
            // would read as coverage. On CI the browser is installed by the
            // workflow's setup step, so reaching this on CI means that step
            // failed.
            panic!(
                "no Chromium-based browser found; these tests require a real one. \
                 Install Chrome/Chromium (CI installs it in the workflow's setup step) \
                 and re-run: cargo test -p pangu-boundary --test browser_cdp -- --ignored"
            )
        }),
        profile_dir: root.join("profile"),
        network: true,
        // `--no-sandbox` and `--disable-dev-shm-usage` are needed on containerised
        // CI runners: the first because the sandbox needs capabilities a
        // container does not grant, the second because `/dev/shm` is often only
        // 64 MB there and Chromium crashes when it fills up.
        extra_args: vec!["--no-sandbox".into(), "--disable-dev-shm-usage".into()],
    }
}

/// The handshake really completes and the socket really carries CDP.
///
/// This is the test that proves interoperability: `Browser.getVersion` is
/// answered by the browser itself, not by anything in this crate.
#[test]
#[ignore = "launches a real browser; run with --ignored"]
fn a_real_browser_answers_a_cdp_command() {
    let root = temp_root("version");
    let mut session = BrowserSession::launch(&config(&root), None).expect("launch");

    let version = session
        .call("Browser.getVersion", serde_json::json!({}))
        .expect("Browser.getVersion must be answered");

    let product = version
        .get("product")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    println!("connected browser: {product}");
    assert!(
        !product.is_empty(),
        "the browser must report a product string, got: {version}"
    );
    // Whichever browser answered, it must be a Chromium by this point: the
    // handshake token and the protocol reply both had to be correct.
    println!("session isolates = {}", session.isolates());

    drop(session);
}

/// Navigation works, and the snapshot reflects the loaded page.
#[test]
#[ignore = "launches a real browser; run with --ignored"]
fn navigation_and_snapshot_reflect_a_data_url() {
    let root = temp_root("navigate");
    let mut session = BrowserSession::launch(&config(&root), None).expect("launch");

    // A data URL avoids depending on the network, so a failure here is a CDP
    // failure rather than a connectivity one.
    let page = "data:text/html,<html><head><title>pangu probe</title></head>\
                <body><p>hello from the probe page</p></body></html>";
    session.navigate(page).expect("navigate");
    let snapshot = session.snapshot().expect("snapshot");

    println!("title = {:?}", snapshot.title);
    println!("text = {:?}", snapshot.text);
    assert_eq!(snapshot.title, "pangu probe");
    assert!(
        snapshot.text.contains("hello from the probe page"),
        "the visible text must be returned; got {:?}",
        snapshot.text
    );
    assert!(!snapshot.truncated);

    drop(session);
}

/// A screenshot returns real PNG bytes.
#[test]
#[ignore = "launches a real browser; run with --ignored"]
fn a_screenshot_is_a_png() {
    let root = temp_root("screenshot");
    let mut session = BrowserSession::launch(&config(&root), None).expect("launch");
    session
        .navigate("data:text/html,<body style='background:%23ff0000'></body>")
        .expect("navigate");

    let png = session.screenshot().expect("screenshot");
    println!("screenshot bytes = {}", png.len());

    // The PNG signature, which is what makes the bytes a PNG rather than an
    // arbitrary blob that merely decoded from base64.
    assert!(
        png.len() > 8 && png[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
        "the screenshot must be a PNG; first bytes: {:?}",
        &png[..png.len().min(8)]
    );
    // A 1280x800 viewport cannot compress to a handful of bytes.
    assert!(png.len() > 1000, "suspiciously small: {} bytes", png.len());

    drop(session);
}

/// A click through `Input.dispatchMouseEvent` actually reaches the page.
///
/// This is the assertion that matters for computer use: the click must produce
/// the page's own effect, not merely return without error.
#[test]
#[ignore = "launches a real browser; run with --ignored"]
fn a_click_reaches_the_page_and_changes_it() {
    let root = temp_root("click");
    let mut session = BrowserSession::launch(&config(&root), None).expect("launch");

    let page = "data:text/html,<body>\
                <button id='go' onclick=\"document.title='clicked'\">go</button>\
                </body>";
    session.navigate(page).expect("navigate");
    assert_eq!(session.snapshot().expect("before").title, "");

    session.click("#go").expect("click");
    // The title is set by the page's own handler, so it proves the click was
    // delivered to the element rather than only dispatched at a coordinate.
    let after = session.snapshot().expect("after");
    println!("title after click = {:?}", after.title);
    assert_eq!(after.title, "clicked", "the page's onclick must have run");

    drop(session);
}

/// Typing reaches the page's own value, not just an internal buffer.
#[test]
#[ignore = "launches a real browser; run with --ignored"]
fn typing_enters_text_into_a_field() {
    let root = temp_root("type");
    let mut session = BrowserSession::launch(&config(&root), None).expect("launch");
    session
        .navigate("data:text/html,<body><input id='f'></body>")
        .expect("navigate");

    session.click("#f").expect("focus the field");
    session.type_text("hi").expect("type");
    let value = session
        .evaluate("document.getElementById('f').value")
        .expect("read");
    println!("field value = {value:?}");
    assert_eq!(value, "hi");

    drop(session);
}

/// Clicking a selector that matches nothing is an error, not a silent no-op.
#[test]
#[ignore = "launches a real browser; run with --ignored"]
fn clicking_a_missing_element_is_refused() {
    let root = temp_root("missing");
    let mut session = BrowserSession::launch(&config(&root), None).expect("launch");
    session
        .navigate("data:text/html,<body></body>")
        .expect("navigate");

    let error = session
        .click("#does-not-exist")
        .expect_err("a missing element must be an error");
    let text = error.to_string();
    println!("refusal: {text}");
    assert!(text.contains("#does-not-exist"), "{text}");
    assert!(text.contains("nothing was clicked"), "{text}");

    drop(session);
}

/// A browser error surfaces as an error rather than an empty success.
#[test]
#[ignore = "launches a real browser; run with --ignored"]
fn an_impossible_command_is_reported_as_a_failure() {
    let root = temp_root("bad-command");
    let mut session = BrowserSession::launch(&config(&root), None).expect("launch");

    let error = session
        .call("No.SuchDomain.noSuchMethod", serde_json::json!({}))
        .expect_err("an unknown CDP method must fail");
    let text = error.to_string();
    println!("refusal: {text}");
    // The method name must appear, so the operator knows which call failed.
    assert!(text.contains("No.SuchDomain.noSuchMethod"), "{text}");

    // `TempRoot`'s `Drop` removes the directory, but `session` still holds the
    // browser open at that point — and on Windows an open profile cannot be
    // deleted, so cleanup would silently lose the race. Dropping the session
    // first means the directory is already unreferenced when `root` goes out of
    // scope.
    drop(session);
}

/// The browser process is gone once the session is dropped.
#[test]
#[ignore = "launches a real browser; run with --ignored"]
fn dropping_the_session_leaves_no_browser_behind() {
    let root = temp_root("cleanup");
    let process_id = {
        let session = BrowserSession::launch(&config(&root), None).expect("launch");
        session.process_id().expect("a process id")
    };

    // Give the kill a moment to be reaped.
    std::thread::sleep(std::time::Duration::from_millis(500));
    // `tasklist`/`ps` availability differs; the portable check is that the
    // profile directory is no longer locked, which a live browser would hold.
    let removed = std::fs::remove_dir_all(&root);
    println!("profile dir removed after drop: {removed:?} (pid was {process_id})");
    assert!(
        removed.is_ok(),
        "the profile directory must be released after the session is dropped: {removed:?}"
    );
}

/// Two sessions get independent browsers and independent state.
#[test]
#[ignore = "launches a real browser; run with --ignored"]
fn sessions_do_not_share_state() {
    let root = temp_root("isolation");
    let mut first = BrowserSession::launch(&config(&root), None).expect("first");
    let mut second = BrowserSession::launch(&config(&root), None).expect("second");

    first
        .navigate("data:text/html,<title>one</title>")
        .expect("nav1");
    second
        .navigate("data:text/html,<title>two</title>")
        .expect("nav2");

    assert_eq!(first.snapshot().expect("s1").title, "one");
    assert_eq!(second.snapshot().expect("s2").title, "two");

    // Both sessions are dropped before `root` goes out of scope, so the two
    // profile directories are unreferenced when `TempRoot::drop` removes them.
    drop(first);
    drop(second);
}
