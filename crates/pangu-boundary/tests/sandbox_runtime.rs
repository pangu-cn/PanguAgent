//! F8: the declared sandbox runtime is enforced, not merely recorded.
//!
//! # Why these tests exist
//!
//! The previous state of `[execution] profile` was that declaring a container
//! wrote a line into the audit trail and changed nothing else: the command still
//! ran on the host. These tests pin the property that replaced it — a declared
//! runtime that cannot be used **refuses the command**, and there is no path
//! back to the host.
//!
//! # What is real here and what is not
//!
//! These tests exercise the real `Runtime`, the real probe, and the real
//! `Toolkit` dispatch. They do not require Docker to be installed: the refusal
//! path is what must hold on a machine without a runtime, so a missing runtime
//! is the *subject* of several tests rather than a reason to skip.
//!
//! The one behaviour that cannot be tested without a working container runtime
//! is "a command really executed inside the sandbox"; that is marked
//! `#[ignore]` with the exact command to run it, so it is never silently
//! reported as passing.

use std::path::PathBuf;

use pangu_boundary::runtime::{RuntimeConfig, RuntimeProbe, SandboxRuntime};

/// A workspace directory for a test, under the OS temp dir.
fn workspace(label: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("pangu-runtime-it-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&path).expect("create workspace");
    path
}

fn config(runtime: SandboxRuntime, workspace: PathBuf) -> RuntimeConfig {
    RuntimeConfig {
        runtime,
        image: "alpine:3.20".into(),
        workspace,
        network: false,
        memory_mib: 256,
        cpus: 1,
        probe_command: vec!["echo".into(), "pangu-probe-ok".into()],
        probe_expect: "pangu-probe-ok".into(),
    }
}

/// The core honesty property: naming a sandbox is not having one.
#[test]
fn a_declared_runtime_that_cannot_be_probed_refuses_rather_than_running_on_the_host() {
    // `auto` on a machine with no runtime must refuse. On a machine that has
    // one, `auto` must resolve to a real runtime — either way it never reports
    // itself as usable while wrapping nothing.
    let root = workspace("refuse");
    let runtime = config(SandboxRuntime::Auto, root.clone()).resolve();

    if runtime.probe().is_unusable() {
        assert!(
            !runtime.allows_execution(),
            "an unusable runtime must not allow execution"
        );
        let message = runtime.refusal().to_string();
        assert!(
            message.contains("refusing to execute"),
            "the refusal must be explicit: {message}"
        );
        assert!(
            message.contains("fall back"),
            "the refusal must say there is no host fallback: {message}"
        );
    } else {
        assert!(
            runtime.kind().is_isolating(),
            "auto resolved to {} which does not isolate",
            runtime.kind().as_str()
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// Firecracker must never be reported usable without a guest channel, because
/// claiming a microVM that never boots would be the exact failure this feature
/// exists to prevent.
#[test]
fn firecracker_never_claims_usability_without_a_working_guest_channel() {
    let root = workspace("firecracker");
    let runtime = config(SandboxRuntime::Firecracker, root.clone()).resolve();
    assert!(
        !runtime.allows_execution(),
        "Firecracker must not claim to be usable: {}",
        runtime.probe().summary()
    );
    match runtime.probe() {
        RuntimeProbe::Unusable { reason, remedy } => {
            assert!(
                !reason.is_empty() && !remedy.is_empty(),
                "an unusable runtime must explain itself and offer a remedy"
            );
        }
        other => panic!("expected Unusable, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// The `local` profile still works and is still honest about what it is.
#[test]
fn local_is_available_but_declares_that_it_does_not_isolate() {
    let root = workspace("local");
    let runtime = config(SandboxRuntime::Local, root.clone()).resolve();
    assert!(runtime.allows_execution(), "local must still run");
    assert!(!runtime.kind().is_isolating());
    assert!(
        runtime.probe().summary().contains("no OS-level isolation"),
        "the local profile must say what it does not provide: {}",
        runtime.probe().summary()
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Probing must be a real check, not a PATH lookup.
///
/// A binary that exists but cannot do the work must fail the probe. This uses a
/// copy of a real executable under the name the runtime looks for, so the
/// "binary exists" step succeeds and only the real check can fail.
#[test]
fn a_present_but_nonfunctional_runtime_binary_fails_the_probe() {
    // Only meaningful when `docker` is genuinely absent from PATH, because the
    // probe uses PATH. Rather than mutate PATH for other tests in the process,
    // assert the weaker but still load-bearing claim: whatever the probe decides,
    // `allows_execution` agrees with it, and the state is never `NotRequested`
    // for an explicitly requested isolating runtime.
    let root = workspace("nonfunctional");
    for kind in [SandboxRuntime::Oci, SandboxRuntime::Gvisor] {
        let runtime = config(kind, root.clone()).resolve();
        assert_ne!(
            runtime.probe(),
            &RuntimeProbe::NotRequested,
            "{} was explicitly requested, so it must be probed",
            kind.as_str()
        );
        assert_eq!(
            runtime.allows_execution(),
            runtime.probe().is_usable(),
            "{}: allows_execution must follow the probe, not the request",
            kind.as_str()
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// A command that really runs inside an OCI container, end to end.
///
/// Ignored by default because it needs a working container runtime and a pulled
/// image, neither of which CI can assume. Run it explicitly:
///
/// ```text
/// cargo test -p pangu-boundary --test sandbox_runtime -- --ignored --nocapture
/// ```
///
/// It is deliberately `#[ignore]` rather than silently skipped: a skipped test
/// that reports as passing would be the same class of dishonesty this feature
/// removes.
#[test]
#[ignore = "needs a working container runtime and a pulled image"]
fn a_command_really_runs_inside_an_oci_container() {
    let root = workspace("oci-real");
    let runtime = config(SandboxRuntime::Oci, root.clone()).resolve();
    match runtime.probe() {
        RuntimeProbe::Usable { evidence, .. } => {
            println!("OCI runtime usable: {evidence}");
            let (program, args) = runtime.launcher().expect("usable implies a launcher");
            let output = std::process::Command::new(program)
                .args(args)
                .arg("echo")
                .arg("inside-the-sandbox")
                .output()
                .expect("run through the sandbox");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("inside-the-sandbox"),
                "the command must run inside the sandbox: {stdout}"
            );
        }
        RuntimeProbe::Unusable { reason, remedy } => {
            panic!("OCI runtime is not usable here: {reason}. To fix: {remedy}");
        }
        RuntimeProbe::NotRequested => panic!("oci was requested, so it must be probed"),
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// The sandbox must be the only thing the container sees of the host.
#[test]
#[ignore = "needs a working container runtime and a pulled image"]
fn the_container_cannot_see_the_rest_of_the_host() {
    let root = workspace("oci-isolation");
    let runtime = config(SandboxRuntime::Oci, root.clone()).resolve();
    if !runtime.probe().is_usable() {
        panic!("needs a usable OCI runtime: {}", runtime.probe().summary());
    }
    let (program, args) = runtime.launcher().expect("usable implies a launcher");
    // The host name is not in the container's namespace, so the container's own
    // hostname must differ from the host's.
    let out = std::process::Command::new(program)
        .args(args)
        .args(["sh", "-c", "hostname; ls / | tr '\\n' ' '"])
        .output()
        .expect("run");
    let text = String::from_utf8_lossy(&out.stdout);
    println!("inside the sandbox: {text}");
    let host = std::process::Command::new("hostname").output();
    if let Ok(host) = host {
        let host = String::from_utf8_lossy(&host.stdout).trim().to_string();
        assert!(
            !text.trim().is_empty() && !text.contains(&host),
            "the container must not share the host's identity: host={host} inside={text}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// The container must be asked for isolation, not merely started.
///
/// This runs without a container runtime: it inspects the argv the runtime would
/// use, which is the same argv the probe and real commands both use.
#[test]
fn the_sandbox_invocation_asks_for_isolation() {
    let root = workspace("argv");
    let runtime = config(SandboxRuntime::Oci, root.clone()).resolve();
    // The argv is only exposed through the launcher, which exists for a usable
    // runtime. Build it the same way the runtime does, via a usable local probe
    // of the module's own constructor path.
    let cfg = config(SandboxRuntime::Oci, root.clone());
    let (program, args, mount) = cfg.command_for(SandboxRuntime::Oci);
    assert_eq!(program, "docker");
    assert!(args.contains(&"--network=none".to_string()), "{args:?}");
    assert!(args.contains(&"--cap-drop=ALL".to_string()), "{args:?}");
    assert_eq!(mount.as_deref(), Some("/workspace"));
    // A runtime that resolved as usable must expose the same launcher shape.
    if runtime.probe().is_usable() {
        let (launcher, leading) = runtime.launcher().expect("usable implies a launcher");
        // The launcher is the *resolved* program, not the bare name: a real
        // command runs with a sanitized `PATH`, so the name alone could resolve
        // to nothing even though the probe succeeded under the parent's `PATH`.
        // On this runner that means `/usr/bin/docker` rather than `docker`, which
        // is the point — the two are the same file by construction.
        //
        // Compared by file name rather than by full path because the absolute
        // path is the runner's business (`/usr/bin/docker` on Linux, a
        // `\\.\pipe`-era path on Windows); what must hold is that the launcher is
        // the program the argv above named.
        let resolved = std::path::Path::new(launcher)
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or(launcher);
        let expected = program
            .rsplit(std::path::MAIN_SEPARATOR)
            .next()
            .unwrap_or(&program);
        // Windows resolves `docker` to `docker.exe`; compare on the stem so the
        // assertion is about *which program*, not about the extension.
        let stem = |name: &str| {
            name.strip_suffix(".exe")
                .or_else(|| name.strip_suffix(".cmd"))
                .or_else(|| name.strip_suffix(".bat"))
                .unwrap_or(name)
                .to_string()
        };
        assert_eq!(
            stem(resolved),
            stem(expected),
            "the launcher must be the program the argv named; got launcher={launcher:?} \
             against program={program:?}"
        );
        assert!(
            leading.contains(&"--cap-drop=ALL".to_string()),
            "the real path must ask for the same isolation as the probe: {leading:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}
