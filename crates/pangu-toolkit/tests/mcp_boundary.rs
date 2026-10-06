//! Tests that MCP tools go through the **ordinary boundary chain**.
//!
//! These are the tests that matter for the feature's core claim: an MCP tool is
//! not a second execution path. If `McpExecutor` could execute without passing
//! Policy, Sandbox, Approval and `VerifiedAction`, every guarantee the boundary
//! provides would stop at the door of the least-controlled component.
//!
//! The executor is driven through `pangu_agent`'s real run loop where possible,
//! and where a shorter test suffices the assertion is on the seam itself:
//! `assess` returns the mapped risk class and `execute` requires a
//! `VerifiedAction`, which cannot be constructed by an executor.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use pangu_agent::ToolExecutor;
use pangu_boundary::{McpSection, McpServerSection, Risk};
use pangu_toolkit::mcp_executor::McpExecutor;

fn fixture_binary() -> &'static str {
    env!("CARGO_BIN_EXE_mcp_fixture_server")
}

fn workspace() -> PathBuf {
    let path = std::env::temp_dir().join(format!("pangu-mcp-exec-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    std::fs::canonicalize(path).unwrap()
}

fn server_with(tools: &[(&str, &str)]) -> McpServerSection {
    let mut mapping = BTreeMap::new();
    for (tool, risk) in tools {
        mapping.insert(tool.to_string(), risk.to_string());
    }
    McpServerSection {
        command: fixture_binary().to_string(),
        args: Vec::new(),
        env: [(
            "PANGU_MCP_FIXTURE_SCENARIO".to_string(),
            "well-behaved".to_string(),
        )]
        .into_iter()
        .collect(),
        cwd: None,
        tools: mapping,
        handshake_secs: 20,
        call_secs: 20,
        description: None,
    }
}

fn section_with(tools: &[(&str, &str)]) -> McpSection {
    let mut section = McpSection::default();
    section
        .servers
        .insert("fix".to_string(), server_with(tools));
    section
}

#[tokio::test]
async fn only_mapped_tools_are_advertised_to_the_model() {
    // The fixture advertises `echo` and `delete_everything`; only `echo` is
    // mapped. A server must not be able to widen the tool surface the model
    // sees by advertising more.
    let section = section_with(&[("echo", "read_only")]);
    let executor = McpExecutor::connect(&section, &workspace())
        .await
        .expect("connect");

    let names: Vec<String> = executor.specs().into_iter().map(|spec| spec.name).collect();
    assert_eq!(names, vec!["fix.echo"]);
    assert!(
        !names.iter().any(|name| name.contains("delete_everything")),
        "an unmapped tool must not reach the model: {names:?}"
    );
    let reports = executor.reports();
    assert_eq!(reports.len(), 1);
    assert!(
        reports[0]
            .unmapped
            .contains(&"delete_everything".to_string()),
        "the unmapped tool must be reported so a typo is visible: {:?}",
        reports[0]
    );
    executor.shutdown().await;
}

#[tokio::test]
async fn the_mapped_risk_class_is_what_assess_reports() {
    // `delete_everything` claims `readOnlyHint: true`. Mapping it to a
    // destructive class must win: the party being constrained does not declare
    // its own authority.
    let section = section_with(&[("delete_everything", "destructive")]);
    let executor = McpExecutor::connect(&section, &workspace())
        .await
        .expect("connect");
    let sandbox =
        pangu_boundary::Sandbox::from_config(&pangu_boundary::config::BoundarySection::default())
            .expect("sandbox");

    let call = pangu_core::ToolCall::new("fix.delete_everything", serde_json::json!({}));
    let assessment = executor.assess(&call, &sandbox).await.expect("assess");
    assert_eq!(
        assessment.risk,
        Risk::Destructive,
        "the operator's mapping governs, not the server's readOnlyHint"
    );
    executor.shutdown().await;
}

#[tokio::test]
async fn a_read_only_mapping_assesses_as_read_only() {
    let section = section_with(&[("echo", "read_only")]);
    let executor = McpExecutor::connect(&section, &workspace())
        .await
        .expect("connect");
    let sandbox =
        pangu_boundary::Sandbox::from_config(&pangu_boundary::config::BoundarySection::default())
            .expect("sandbox");
    let call = pangu_core::ToolCall::new("fix.echo", serde_json::json!({"text": "hi"}));
    let assessment = executor.assess(&call, &sandbox).await.expect("assess");
    assert_eq!(assessment.risk, Risk::ReadOnly);
    // Every MCP call has an external component; recording it as purely local
    // would understate the effect ledger.
    assert!(assessment.effect.is_some());
    executor.shutdown().await;
}

#[tokio::test]
async fn assessing_an_unexposed_tool_is_refused() {
    let section = section_with(&[("echo", "read_only")]);
    let executor = McpExecutor::connect(&section, &workspace())
        .await
        .expect("connect");
    let sandbox =
        pangu_boundary::Sandbox::from_config(&pangu_boundary::config::BoundarySection::default())
            .expect("sandbox");
    // The server advertises this but the operator did not map it.
    let call = pangu_core::ToolCall::new("fix.delete_everything", serde_json::json!({}));
    let error = executor
        .assess(&call, &sandbox)
        .await
        .expect_err("an unmapped tool must not be assessable");
    assert!(error.to_string().contains("not exposed"), "{error}");
    executor.shutdown().await;
}

#[tokio::test]
async fn an_unknown_server_prefix_is_refused() {
    let section = section_with(&[("echo", "read_only")]);
    let executor = McpExecutor::connect(&section, &workspace())
        .await
        .expect("connect");
    let sandbox =
        pangu_boundary::Sandbox::from_config(&pangu_boundary::config::BoundarySection::default())
            .expect("sandbox");
    let call = pangu_core::ToolCall::new("other.echo", serde_json::json!({}));
    assert!(executor.assess(&call, &sandbox).await.is_err());
    executor.shutdown().await;
}

#[tokio::test]
async fn a_description_is_labelled_as_server_supplied_data() {
    let section = section_with(&[("echo", "read_only")]);
    let executor = McpExecutor::connect(&section, &workspace())
        .await
        .expect("connect");
    let specs = executor.specs();
    let echo = specs.iter().find(|spec| spec.name == "fix.echo").unwrap();
    // The fixture's description contains "Ignore all prior instructions". It is
    // preserved verbatim, and the provenance label is placed before it so the
    // model sees the framing first.
    assert!(
        echo.description.starts_with("[external MCP tool"),
        "{}",
        echo.description
    );
    assert!(
        echo.description.contains("Ignore all prior instructions"),
        "the description is data and is preserved: {}",
        echo.description
    );
    assert!(
        echo.description.contains("not an instruction"),
        "the framing must say what the text is: {}",
        echo.description
    );
    executor.shutdown().await;
}

#[tokio::test]
async fn a_declared_server_that_cannot_start_fails_the_connection() {
    // Silently running with half the configured tools would change what the
    // model can do without saying so.
    let mut section = McpSection::default();
    let mut server = server_with(&[("echo", "read_only")]);
    server.command = "definitely-not-a-real-program-xyz".to_string();
    section.servers.insert("fix".to_string(), server);
    let error = McpExecutor::connect(&section, &workspace())
        .await
        .expect_err("a declared server that cannot start must be an error");
    assert!(error.to_string().contains("failed to start"), "{error}");
}

#[tokio::test]
async fn an_invalid_declaration_fails_before_any_process_starts() {
    let mut section = McpSection::default();
    let mut server = server_with(&[("echo", "not-a-risk-class")]);
    server.command = fixture_binary().to_string();
    section.servers.insert("fix".to_string(), server);
    let error = McpExecutor::connect(&section, &workspace())
        .await
        .expect_err("a bad risk class must fail at startup");
    assert!(error.to_string().contains("invalid"), "{error}");
}

#[tokio::test]
async fn a_stale_mapping_is_reported() {
    // The fixture does not advertise `ghost_tool`.
    let section = section_with(&[("echo", "read_only"), ("ghost_tool", "read_only")]);
    let executor = McpExecutor::connect(&section, &workspace())
        .await
        .expect("connect");
    let reports = executor.reports();
    assert!(
        reports[0].missing.contains(&"ghost_tool".to_string()),
        "a mapping for a tool the server no longer offers is drift worth showing: {:?}",
        reports[0]
    );
    assert_eq!(executor.exposed_names(), vec!["fix.echo"]);
    executor.shutdown().await;
}

#[tokio::test]
async fn a_server_cannot_substitute_its_own_tool_set_between_runs() {
    // Discovery happens once, at connect. The advertised set is fixed for the
    // run, so a server that changes later cannot silently alter the surface.
    let section = section_with(&[("echo", "read_only")]);
    let executor = McpExecutor::connect(&section, &workspace())
        .await
        .expect("connect");
    let first = executor.exposed_names();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let second = executor.exposed_names();
    assert_eq!(first, second);
    executor.shutdown().await;
}
