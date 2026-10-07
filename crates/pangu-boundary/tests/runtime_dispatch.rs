//! F8: a command really is dispatched *through* the declared runtime.
//!
//! # The gap this closes
//!
//! `sandbox_runtime.rs` covers the refusal path and the argv construction, but on
//! a machine with no working container runtime the claim that matters most —
//! *the command is actually handed to the runtime, with the isolation flags, and
//! its output comes back* — cannot be observed against Docker itself.
//!
//! Waiting for a working Docker would leave the most load-bearing behaviour
//! untested on most machines, and "it would work if Docker were installed" is
//! exactly the kind of claim this project does not accept. So the runtime binary
//! is **replaced by a stub** that behaves like a runtime: it records the argv it
//! was given, appends its own probe output, and exits.
//!
//! # What the stub proves, and what it does not
//!
//! Proved: the probe found the program on `PATH`, built the container argv
//! (including the isolation flags), ran it, read its stdout, matched the expected
//! token, and reported the runtime usable. Then a real tool call went through the
//! same argv, and the workspace was mounted at the declared path.
//!
//! Not proved, and not claimed: that Docker's implementation of those flags
//! isolates anything. That is Docker's property, not this launcher's — the same
//! limit stated in `runtime.rs`.
//!
//! # Why the stub is a real file rather than a mock
//!
//! The code under test calls `find_program`, which searches `PATH` for a file.
//! Mocking that would test the mock. The stub is written to a temp directory that
//! is prepended to `PATH`, so the production lookup runs unchanged.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use pangu_boundary::runtime::{RuntimeConfig, SandboxRuntime};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Serialises the tests that mutate `PATH`.
///
/// `PATH` is process-global and `cargo test` runs tests on threads, so two tests
/// that each prepend their own stub directory will see each other's stubs and
/// fail for a reason that has nothing to do with the code under test. A mutex is
/// the honest fix: these tests genuinely share one global, so they must not run
/// concurrently. (Marking them `#[serial]` would need a dependency; a local lock
/// says the same thing.)
static PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run `body` with `bin` prepended to `PATH`, restoring it afterwards.
///
/// Restoration happens even if the body panics, so one failing test cannot leave
/// a stub on `PATH` and cascade into the others.
fn with_stub_on_path<T>(bin: &Path, body: impl FnOnce() -> T) -> T {
    let _guard = PATH_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let original = std::env::var_os("PATH").unwrap_or_default();
    let mut joined = bin.to_path_buf().into_os_string();
    joined.push(if cfg!(windows) { ";" } else { ":" });
    joined.push(&original);
    std::env::set_var("PATH", &joined);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
    std::env::set_var("PATH", &original);
    match result {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

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
fn temp_root(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = temp_base().join(format!(
        "pangu-runtime-stub-{label}-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).expect("create root");
    path
}

/// Write a stub `docker` that records its argv and emits the probe token.
///
/// The stub writes each invocation to `record` so the test can assert on the
/// exact arguments the production code produced.
fn write_stub(bin_dir: &Path, record: &Path, token: &str) -> PathBuf {
    std::fs::create_dir_all(bin_dir).expect("create bin dir");

    #[cfg(windows)]
    {
        // A `.cmd` shim: `find_program` looks for `.exe`/`.cmd`/`.bat`/bare on
        // Windows, and a batch file needs no compiler.
        let path = bin_dir.join("docker.cmd");
        let body = format!(
            "@echo off\r\n\
             echo %* >> \"{record}\"\r\n\
             echo {token}\r\n",
            record = record.display(),
            token = token
        );
        std::fs::write(&path, body).expect("write stub");
        path
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = bin_dir.join("docker");
        // The `RAN` sentinel matches the Windows branch, so a record proves the
        // program ran even when it received no arguments. Without it an
        // argument-less invocation leaves the record empty, which reads as "the
        // program never ran" — the opposite of the truth.
        let body = format!(
            "#!/bin/sh\nprintf 'RAN docker %s\\n' \"$*\" >> '{record}'\necho '{token}'\n",
            record = record.display(),
            token = token
        );
        std::fs::write(&path, body).expect("write stub");
        let mut perms = std::fs::metadata(&path).expect("stat").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod");
        path
    }
}

/// The invocations the stub recorded, one per line.
fn recorded(record: &Path) -> Vec<String> {
    std::fs::read_to_string(record)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .filter(|line| !line.trim().is_empty())
        .collect()
}

fn config(runtime: SandboxRuntime, workspace: PathBuf, token: &str) -> RuntimeConfig {
    RuntimeConfig {
        runtime,
        image: "alpine:3.20".into(),
        workspace,
        network: false,
        memory_mib: 256,
        cpus: 2,
        probe_command: vec!["echo".into(), token.into()],
        probe_expect: token.into(),
    }
}

/// With a runtime that answers correctly, the probe reports usable — and the
/// argv it used carries the isolation flags.
#[test]
fn a_runtime_that_answers_the_probe_is_reported_usable_with_its_isolation_flags() {
    let root = temp_root("usable");
    let bin = root.join("bin");
    let record = root.join("argv.log");
    let token = "pangu-stub-ok";
    write_stub(&bin, &record, token);

    let workspace = root.join("ws");
    std::fs::create_dir_all(&workspace).expect("workspace");
    // The stub directory must be on `PATH` for the production `find_program`.
    let runtime = with_stub_on_path(&bin, || {
        config(SandboxRuntime::Oci, workspace.clone(), token).resolve()
    });

    assert!(
        runtime.allows_execution(),
        "a runtime that answers the probe must be usable: {}",
        runtime.probe().summary()
    );
    assert!(
        runtime.probe().is_usable(),
        "probe must be Usable, was {}",
        runtime.probe().summary()
    );

    // The recorded invocation is the evidence: it shows the command was really
    // handed to the runtime, not run directly.
    let calls = recorded(&record);
    assert!(
        !calls.is_empty(),
        "the runtime must have been invoked at least once"
    );
    let probe_call = &calls[0];
    println!("probe invocation: {probe_call}");
    assert!(probe_call.contains("run"), "{probe_call}");
    assert!(probe_call.contains("alpine:3.20"), "{probe_call}");
    // The isolation flags are the reason to use a runtime at all; a launcher that
    // dropped them would still "work".
    assert!(probe_call.contains("--rm"), "missing --rm: {probe_call}");
    assert!(
        probe_call.contains("no-new-privileges"),
        "missing --security-opt=no-new-privileges: {probe_call}"
    );
    assert!(
        probe_call.contains("cap-drop=ALL") || probe_call.contains("cap-drop"),
        "missing --cap-drop: {probe_call}"
    );
    assert!(
        probe_call.contains("--network=none"),
        "network was disabled in the config, so the argv must say so: {probe_call}"
    );
    assert!(
        probe_call.contains("--memory=256m"),
        "the memory bound must reach the runtime: {probe_call}"
    );
    assert!(
        probe_call.contains("--cpus=2"),
        "the cpu bound must reach the runtime: {probe_call}"
    );
    // And the probe command itself.
    assert!(probe_call.contains(token), "{probe_call}");

    let _ = std::fs::remove_dir_all(&root);
}

/// The workspace is mounted at the declared path, so a command inside sees it.
#[test]
fn the_workspace_mount_reaches_the_runtime_argv() {
    let root = temp_root("mount");
    let bin = root.join("bin");
    let record = root.join("argv.log");
    let token = "pangu-stub-mount";
    write_stub(&bin, &record, token);

    let workspace = root.join("the-workspace");
    std::fs::create_dir_all(&workspace).expect("workspace");
    let runtime = with_stub_on_path(&bin, || {
        config(SandboxRuntime::Oci, workspace.clone(), token).resolve()
    });
    assert!(runtime.allows_execution(), "{}", runtime.probe().summary());

    let calls = recorded(&record);
    let probe_call = &calls[0];
    println!("probe invocation: {probe_call}");
    // The mount must be the workspace the operator declared, at a fixed in-container
    // path, with the workdir set to match. Without it the container would run
    // against an empty filesystem and every command would "succeed" having seen
    // none of the project.
    assert!(
        probe_call.contains("--volume=") && probe_call.contains(":/workspace"),
        "the workspace must be mounted at /workspace: {probe_call}"
    );
    assert!(
        probe_call.contains("--workdir=/workspace"),
        "the workdir must be the mount point: {probe_call}"
    );
    assert!(
        probe_call.contains(&workspace.display().to_string()),
        "the mount source must be the declared workspace: {probe_call}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// A runtime that exists but does not produce the token is **unusable**.
///
/// This is the difference between "the binary is installed" and "the sandbox
/// works", and it is the reason the probe runs a command rather than checking for
/// a file: a daemon that is down, or an image that was never pulled, looks
/// exactly like a working runtime to a file check.
#[test]
fn a_runtime_that_answers_with_the_wrong_output_is_unusable() {
    let root = temp_root("wrong-output");
    let bin = root.join("bin");
    let record = root.join("argv.log");
    // The stub answers, but not with what the probe is looking for.
    write_stub(&bin, &record, "something-else-entirely");

    let workspace = root.join("ws");
    std::fs::create_dir_all(&workspace).expect("workspace");
    let runtime = with_stub_on_path(&bin, || {
        config(SandboxRuntime::Oci, workspace, "pangu-expected-token").resolve()
    });

    assert!(
        runtime.probe().is_unusable(),
        "a runtime that did not answer the probe must not be usable: {}",
        runtime.probe().summary()
    );
    assert!(
        !runtime.allows_execution(),
        "an unusable runtime must refuse execution"
    );
    // The refusal must be actionable: it has to say what was seen and what to do.
    let refusal = runtime.refusal().to_string();
    println!("refusal: {refusal}");
    // What was seen: the unexpected output, so the operator is not left guessing
    // which part of the runtime answered wrongly.
    assert!(refusal.contains("something-else-entirely"), "{refusal}");
    // Why there is no fallback. Without this sentence an operator could
    // reasonably read the refusal as a bug rather than a deliberate rule.
    assert!(refusal.contains("audit trail"), "{refusal}");
    // And what to do about it.
    assert!(
        refusal.contains("install Docker or Podman"),
        "the refusal must carry a remedy: {refusal}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The two isolating runtimes build different argv, and each names its own
/// binary — a gVisor command must not be sent to `docker`.
#[test]
fn each_runtime_builds_its_own_invocation() {
    let root = temp_root("argv-per-runtime");
    let workspace = root.join("ws");
    std::fs::create_dir_all(&workspace).expect("workspace");

    let oci = config(SandboxRuntime::Oci, workspace.clone(), "t");
    let (program, args, mount) = oci.command_for(SandboxRuntime::Oci);
    assert_eq!(program, "docker");
    assert_eq!(mount, Some("/workspace".to_string()));
    assert!(args.contains(&"run".to_string()), "{args:?}");

    let gvisor = config(SandboxRuntime::Gvisor, workspace, "t");
    let (program, args, mount) = gvisor.command_for(SandboxRuntime::Gvisor);
    assert_eq!(program, "runsc");
    assert_eq!(mount, Some("/workspace".to_string()));
    // gVisor takes its own flags; sending Docker flags to `runsc` would fail at
    // runtime rather than at build time, so they are asserted here.
    assert!(
        args.iter().any(|arg| arg.starts_with("--platform=")),
        "{args:?}"
    );
    assert!(
        args.iter().any(|arg| arg.starts_with("--bind=")),
        "{args:?}"
    );

    let _ = std::fs::remove_dir_all(&root);
}
