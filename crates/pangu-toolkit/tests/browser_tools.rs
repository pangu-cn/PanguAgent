//! F9: the browser tools are opt-in, and the gate applies to them.
//!
//! # What this suite proves that the unit tests cannot
//!
//! `pangu-toolkit::browser`'s own tests check the risk *mapping*. They cannot
//! show that the mapping reaches the tool list, or that an unconfigured toolkit
//! refuses a browser call. Both matter:
//!
//! - If the tools were advertised while disabled, a model would call a
//!   capability the operator never enabled and would get an error at call time
//!   instead of not seeing it at all.
//! - If `assess` accepted a browser call on a toolkit with no browser, the
//!   enforcement would live in the executor only, and a mis-wired executor would
//!   run it ungated.

use std::path::PathBuf;

use pangu_agent::ToolExecutor;
use pangu_boundary::{Config, Sandbox};
use pangu_toolkit::Toolkit;

/// A browser config that points at a path, without requiring a browser to exist.
///
/// These tests exercise `assess`, which validates the URL and the arguments and
/// refuses **before** anything is launched. Gating them on
/// `find_executable().is_some()` made them silently pass on any machine without a
/// browser — reporting "ok" while testing nothing, which is the failure mode this
/// whole file exists to avoid.
///
/// The path does not have to be a real browser for a rejection to be testable:
/// `assess` never runs it. Tests that actually launch a browser live in
/// `pangu-boundary/tests/browser_cdp.rs`, where a missing browser is a loud
/// failure rather than a skip.
fn config_at(root: &std::path::Path) -> pangu_boundary::browser::BrowserConfig {
    pangu_boundary::browser::BrowserConfig {
        executable: std::path::PathBuf::from(if cfg!(windows) {
            r"C:\nonexistent\chrome.exe"
        } else {
            "/nonexistent/chrome"
        }),
        profile_dir: root.join("profile"),
        network: false,
        extra_args: Vec::new(),
    }
}

fn sandbox_for(root: &std::path::Path) -> Sandbox {
    let mut config = Config::embedded().expect("embedded");
    config.boundary.workspace = root.to_path_buf();
    config.boundary.readable_roots = vec![root.to_path_buf()];
    config.boundary.writable_roots = vec![root.to_path_buf()];
    Sandbox::from_config(&config.boundary).expect("sandbox")
}

fn temp_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "pangu-f9-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&root).expect("create root");
    root
}

/// With no browser configured, the browser tools must not appear at all.
///
/// This is the load-bearing half of "opt-in": advertising a tool the operator
/// did not enable would let a model attempt a capability that was never granted.
#[test]
fn browser_tools_are_absent_when_no_browser_is_configured() {
    let toolkit = Toolkit::new();
    let names: Vec<String> = toolkit.specs().into_iter().map(|spec| spec.name).collect();

    for browser_tool in pangu_toolkit::browser::BROWSER_TOOLS {
        assert!(
            !names.contains(&browser_tool.to_string()),
            "`{browser_tool}` must not be advertised without a browser; got {names:?}"
        );
    }
    assert!(!toolkit.has_browser());
}

/// With a browser configured, every browser tool appears exactly once.
#[test]
fn browser_tools_are_advertised_once_when_configured() {
    let root = temp_root("advertised");
    // A real executable is needed: `resolve_config` refuses a path that is not
    // a file, which is the point of resolving at all.
    let executable = pangu_boundary::browser::BrowserConfig::find_executable()
        .expect("this test requires a Chromium-based browser to be installed");
    let config = pangu_boundary::browser::BrowserConfig {
        executable,
        profile_dir: root.join("profile"),
        network: false,
        extra_args: Vec::new(),
    };
    let toolkit = Toolkit::new().with_browser(config, root.join("artifacts"));
    let names: Vec<String> = toolkit.specs().into_iter().map(|spec| spec.name).collect();

    for browser_tool in pangu_toolkit::browser::BROWSER_TOOLS {
        let count = names.iter().filter(|name| *name == browser_tool).count();
        assert_eq!(
            count, 1,
            "`{browser_tool}` appeared {count} times: {names:?}"
        );
    }
    assert!(toolkit.has_browser());
    assert!(
        !toolkit.browser_is_open(),
        "advertising the tools must not launch a browser"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// A browser call on a toolkit with no browser is refused at `assess`.
///
/// Gating at `assess` rather than only in the executor is what makes the
/// refusal structural: a mis-wired executor cannot run what `assess` never
/// approved.
#[tokio::test]
async fn a_browser_call_without_a_browser_is_refused_before_execution() {
    let root = temp_root("refused");
    let sandbox = sandbox_for(&root);
    let toolkit = Toolkit::new();

    let call = pangu_core::ToolCall::new(
        "browser_open",
        serde_json::json!({"url": "https://example.com"}),
    );
    let error = toolkit
        .assess(&call, &sandbox)
        .await
        .expect_err("a browser call with no browser must be refused");
    let text = error.to_string();
    assert!(text.contains("no browser is configured"), "{text}");

    let _ = std::fs::remove_dir_all(&root);
}

/// Navigation is an outbound request, so an unlisted host is refused.
///
/// Without this, the network boundary would never see where the browser went and
/// a page could load from a host the operator never allowed.
#[tokio::test]
async fn navigation_to_a_host_outside_the_boundary_is_refused() {
    let root = temp_root("host");
    let sandbox = sandbox_for(&root);
    let config = config_at(&root);

    let toolkit = Toolkit::new().with_browser(config, root.join("artifacts"));

    // The embedded config allows no hosts, so any navigation must be refused by
    // the network boundary.
    let call = pangu_core::ToolCall::new(
        "browser_open",
        serde_json::json!({"url": "https://not-allowed.example/"}),
    );
    match toolkit.assess(&call, &sandbox).await {
        Ok(_) => panic!("navigation to an unlisted host must not be assessed as allowed"),
        Err(error) => {
            let text = error.to_string();
            println!("refused as expected: {text}");
            assert!(
                !text.is_empty(),
                "a refusal must carry a reason, not be empty"
            );
        }
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// A non-http scheme is refused: `file:` would read the host filesystem.
#[tokio::test]
async fn a_file_url_is_refused() {
    let root = temp_root("scheme");
    let sandbox = sandbox_for(&root);
    let config = config_at(&root);

    let toolkit = Toolkit::new().with_browser(config, root.join("artifacts"));

    let call = pangu_core::ToolCall::new(
        "browser_open",
        serde_json::json!({"url": "file:///etc/passwd"}),
    );
    let error = toolkit
        .assess(&call, &sandbox)
        .await
        .expect_err("a file: URL must be refused");
    let text = error.to_string();
    println!("refused as expected: {text}");
    assert!(text.contains("http"), "{text}");

    let _ = std::fs::remove_dir_all(&root);
}

/// An unexpected argument is refused rather than ignored.
#[tokio::test]
async fn unknown_arguments_are_refused() {
    let root = temp_root("args");
    let sandbox = sandbox_for(&root);
    let config = config_at(&root);

    let toolkit = Toolkit::new().with_browser(config, root.join("artifacts"));

    // Silently ignoring an unexpected argument would mean the model's stated
    // intent and the executed action could differ.
    let call =
        pangu_core::ToolCall::new("browser_read", serde_json::json!({"inject": "something"}));
    let error = toolkit
        .assess(&call, &sandbox)
        .await
        .expect_err("an unknown argument must be refused");
    assert!(error.to_string().contains("inject"), "{error}");

    let _ = std::fs::remove_dir_all(&root);
}
