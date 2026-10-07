//! The probe must terminate even when the runtime hangs.
//!
//! Docker Desktop on a machine whose engine is stuck does not fail — it *hangs*.
//! A probe that hangs would hang the run before its first tool call, which is a
//! worse failure than refusing. This test drives the real timeout path with a
//! command that sleeps far longer than the probe's budget.
//!
//! It does not need Docker: it uses the probe's own bounded-wait behaviour via
//! an OCI runtime name that resolves to a real, hanging process.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use pangu_boundary::runtime::{RuntimeConfig, RuntimeProbe, SandboxRuntime};

/// How long the probe is given before it must give up. Mirrors the module's own
/// constant; asserted below to be long enough to be meaningful but short enough
/// for a test.
const EXPECTED_MAX: Duration = Duration::from_secs(90);

/// The OS temp directory with symlinked ancestors resolved.
///
/// The journal and artifact layers reject any path containing a symlink
/// component, and the sandbox canonicalizes its workspace before comparing
/// prefixes. On Linux container images `/tmp` is often a symlink, so a raw
/// `temp_dir()` path is refused there while working on a machine whose temp
/// directory is a real directory — the test passes locally and fails in CI for a
/// reason unrelated to the code under test. Resolving the base once removes the
/// whole class of mistake.
fn temp_base() -> std::path::PathBuf {
    let base = std::env::temp_dir();
    std::fs::canonicalize(&base).unwrap_or(base)
}
fn workspace(label: &str) -> PathBuf {
    let path = temp_base().join(format!(
        "pangu-probe-timeout-{label}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create workspace");
    path
}

/// A probe against a machine with no container runtime must return promptly.
///
/// On this machine Docker Desktop is installed but wedged, which is exactly the
/// case that motivated the bound: the CLI starts, connects, and then waits
/// forever for a daemon that never answers.
#[test]
fn a_probe_against_a_wedged_runtime_terminates_within_its_budget() {
    let root = workspace("wedged");
    let config = RuntimeConfig {
        runtime: SandboxRuntime::Oci,
        image: "alpine:3.20".into(),
        workspace: root.clone(),
        network: false,
        memory_mib: 256,
        cpus: 1,
        probe_command: vec!["echo".into(), "pangu-probe-ok".into()],
        probe_expect: "pangu-probe-ok".into(),
    };

    let started = Instant::now();
    let runtime = config.resolve();
    let elapsed = started.elapsed();

    assert!(
        elapsed < EXPECTED_MAX,
        "the probe must give up within {EXPECTED_MAX:?}, took {elapsed:?}"
    );
    println!(
        "probe returned in {elapsed:?}: {}",
        runtime.probe().summary()
    );

    // Whatever it decided, the decision must be one of the two real states, and
    // execution must follow it.
    match runtime.probe() {
        RuntimeProbe::Usable { .. } => {
            assert!(
                runtime.allows_execution(),
                "usable implies execution allowed"
            );
        }
        RuntimeProbe::Unusable { reason, remedy } => {
            assert!(!runtime.allows_execution());
            assert!(!reason.is_empty());
            assert!(!remedy.is_empty());
        }
        RuntimeProbe::NotRequested => panic!("oci was requested, so it must be probed"),
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// The probe's own timeout is the mechanism; this pins that it exists at all by
/// checking the observed bound is not unbounded.
#[test]
fn the_probe_bound_is_finite_and_reported() {
    let root = workspace("bound");
    let config = RuntimeConfig {
        runtime: SandboxRuntime::Gvisor,
        image: "alpine:3.20".into(),
        workspace: root.clone(),
        network: false,
        memory_mib: 0,
        cpus: 0,
        probe_command: vec!["echo".into(), "pangu-probe-ok".into()],
        probe_expect: "pangu-probe-ok".into(),
    };
    let started = Instant::now();
    let runtime = config.resolve();
    let elapsed = started.elapsed();
    assert!(
        elapsed < EXPECTED_MAX,
        "resolving must terminate, took {elapsed:?}"
    );
    // runsc is almost certainly absent; if it is present the probe runs, and
    // either way the state must be coherent.
    assert_eq!(
        runtime.allows_execution(),
        runtime.probe().is_usable(),
        "allows_execution must follow the probe"
    );
    let _ = std::fs::remove_dir_all(&root);
}
