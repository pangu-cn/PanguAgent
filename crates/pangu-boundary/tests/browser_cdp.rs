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
//! cargo test -p pangu-boundary --test browser_cdp -- --ignored --nocapture
//! ```
//!
//! They are ignored rather than skipped silently for the same reason as the
//! container tests: a test that quietly does nothing reports success it did not
//! earn. When no browser is installed the tests fail with a message saying so,
//! rather than passing.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use pangu_boundary::browser::{BrowserConfig, BrowserSession};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn temp_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "pangu-cdp-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("create root");
    root
}

fn config(root: &std::path::Path) -> BrowserConfig {
    BrowserConfig {
        executable: BrowserConfig::find_executable().unwrap_or_else(|| {
            panic!(
                "no Chromium-based browser found on this machine; these tests require one. \
                 Install Chrome or Edge and re-run, or leave them ignored"
            )
        }),
        profile_dir: root.join("profile"),
        network: true,
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
    let _ = std::fs::remove_dir_all(&root);
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
    let _ = std::fs::remove_dir_all(&root);
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
    let _ = std::fs::remove_dir_all(&root);
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
    let _ = std::fs::remove_dir_all(&root);
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
    let _ = std::fs::remove_dir_all(&root);
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
    let _ = std::fs::remove_dir_all(&root);
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

    drop(session);
    let _ = std::fs::remove_dir_all(&root);
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

    drop(first);
    drop(second);
    let _ = std::fs::remove_dir_all(&root);
}
