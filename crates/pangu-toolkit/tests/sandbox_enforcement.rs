//! F8 end to end: a declared sandbox that does not work refuses commands.
//!
//! # What this proves that unit tests cannot
//!
//! The unit tests check that `allows_execution()` follows the probe. This test
//! checks the thing that actually matters to an operator: a real `Toolkit`,
//! given a real config declaring a real-but-broken runtime, **fails the command
//! with an explanation** instead of running it on the host.
//!
//! It deliberately does not need a working container runtime. The most important
//! case is the broken one — that is the case where the old behaviour silently
//! ran on the host while the audit trail said `container`.

use std::path::PathBuf;
use std::sync::Arc;

use pangu_boundary::runtime::{RuntimeConfig, SandboxRuntime};

/// A workspace under the OS temp dir.
fn workspace(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("pangu-f8-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&path).expect("create workspace");
    path
}

/// Build a runtime that is requested but cannot possibly work, so the refusal
/// path is exercised on any machine.
fn broken_runtime(workspace: PathBuf) -> pangu_boundary::runtime::Runtime {
    let config = RuntimeConfig {
        // Firecracker is unavailable on this platform by construction, which
        // makes it a reliable stand-in for "the operator asked for a sandbox
        // that is not there".
        runtime: SandboxRuntime::Firecracker,
        image: "some-rootfs.img".into(),
        workspace,
        network: false,
        memory_mib: 256,
        cpus: 1,
        probe_command: vec!["echo".into(), "pangu-probe-ok".into()],
        probe_expect: "pangu-probe-ok".into(),
    };
    config.resolve()
}

/// The operator-visible contract: a broken declared sandbox means commands fail,
/// and the failure says why.
///
/// This drives `sandbox_admits`, which is the exact function the executor calls
/// before spawning. Testing the refusal message alone would not do: that would
/// still pass if the executor stopped consulting the runtime at all.
#[test]
fn a_broken_declared_sandbox_is_refused_at_the_execution_gate() {
    let root = workspace("refuses");
    let runtime = broken_runtime(root.clone());
    assert!(
        !runtime.allows_execution(),
        "the test needs an unusable runtime to exercise the refusal; got: {}",
        runtime.probe().summary()
    );

    // The gate itself must refuse.
    let decision = pangu_toolkit::sandbox_admits(Some(&runtime));
    let error = decision.expect_err("an unusable declared sandbox must refuse the command");
    let message = error.to_string();
    assert!(message.contains("refusing to execute"), "{message}");
    assert!(
        message.contains("audit trail"),
        "the refusal must explain why there is no host fallback: {message}"
    );

    // The toolkit must still expose the runtime it was given, so the refusal is
    // traceable to a concrete configuration rather than being anonymous.
    let toolkit = pangu_toolkit::Toolkit::new().with_runtime(Arc::new(runtime));
    assert!(toolkit.runtime().is_some());

    let _ = std::fs::remove_dir_all(&root);
}

/// The other half of the gate: a usable runtime must be admitted.
///
/// Without this, a gate that refused *everything* would pass the test above.
#[test]
fn a_usable_runtime_is_admitted() {
    let root = workspace("admits");
    let runtime = RuntimeConfig {
        runtime: SandboxRuntime::Local,
        image: String::new(),
        workspace: root.clone(),
        network: false,
        memory_mib: 0,
        cpus: 0,
        probe_command: vec!["echo".into(), "pangu-probe-ok".into()],
        probe_expect: "pangu-probe-ok".into(),
    }
    .resolve();
    assert!(runtime.allows_execution());
    assert!(
        pangu_toolkit::sandbox_admits(Some(&runtime)).is_ok(),
        "a usable runtime must be admitted"
    );

    // And no runtime at all (the unchanged local profile) is admitted too.
    assert!(
        pangu_toolkit::sandbox_admits(None).is_ok(),
        "no declared runtime must keep the previous behaviour"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `local` must keep working: the refusal is specific to a *declared* sandbox,
/// not a blanket block on command execution.
#[test]
fn the_local_profile_still_allows_commands() {
    let root = workspace("local");
    let runtime = RuntimeConfig {
        runtime: SandboxRuntime::Local,
        image: String::new(),
        workspace: root.clone(),
        network: false,
        memory_mib: 0,
        cpus: 0,
        probe_command: vec!["echo".into(), "pangu-probe-ok".into()],
        probe_expect: "pangu-probe-ok".into(),
    }
    .resolve();

    assert!(
        runtime.allows_execution(),
        "local is the escape hatch and must keep working"
    );
    let toolkit = pangu_toolkit::Toolkit::new().with_runtime(Arc::new(runtime));
    assert!(toolkit.runtime().is_some());

    let _ = std::fs::remove_dir_all(&root);
}

/// With no runtime attached, the toolkit behaves exactly as before.
///
/// This is the compatibility property: existing deployments that never declare
/// `[execution] runtime` must be unaffected.
#[test]
fn no_declared_runtime_means_no_enforcement_and_no_change() {
    let toolkit = pangu_toolkit::Toolkit::new();
    assert!(
        toolkit.runtime().is_none(),
        "a toolkit built without a runtime must not acquire one"
    );
    // Its manifest must be unchanged by the F8 work: the sandbox is not a tool.
    let names: Vec<String> = toolkit
        .manifest()
        .capabilities
        .iter()
        .map(|c| c.name.clone())
        .collect();
    assert!(
        !names.iter().any(|name| name.contains("sandbox")),
        "F8 must not add a tool the model could call: {names:?}"
    );
}
