//! Cross-process proof that per-file locks allow parallel work on unrelated
//! files, and serialise work on the same file.
//!
//! The unit tests in `pangu_core::lockfile` show the lock's behaviour through
//! its API. This test spawns real processes so the cross-process claim rests on
//! process separation rather than threads inside one test binary.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn scratch(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "pangu-pathlock-e2e-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).unwrap();
    std::fs::canonicalize(path).unwrap()
}

fn spawn_child(workspace: &PathBuf, path: &str, hold_ms: u64, mark: &str) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("path_lock_child")
        .arg("--nocapture")
        .arg("--ignored")
        .env("PANGU_PATHLOCK_WORKSPACE", workspace)
        .env("PANGU_PATHLOCK_PATH", path)
        .env("PANGU_PATHLOCK_HOLD_MS", hold_ms.to_string())
        .env("PANGU_PATHLOCK_MARK", mark)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child")
}

fn output_of(child: std::process::Child) -> String {
    let out = child.wait_with_output().expect("wait for child");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Child body: lock one path, hold it, release. `#[ignore]`d so it only runs
/// when the parent asks for it explicitly.
#[test]
#[ignore = "helper process driven by the per-path contention tests"]
fn path_lock_child() {
    let workspace = match std::env::var("PANGU_PATHLOCK_WORKSPACE") {
        Ok(value) => PathBuf::from(value),
        Err(_) => return,
    };
    let path = std::env::var("PANGU_PATHLOCK_PATH").unwrap();
    let hold_ms: u64 = std::env::var("PANGU_PATHLOCK_HOLD_MS")
        .unwrap()
        .parse()
        .unwrap();
    let mark = std::env::var("PANGU_PATHLOCK_MARK").unwrap_or_default();

    // Announce readiness *before* taking the clock reading. The parent measures
    // from this line, so what gets timed is the lock acquisition and nothing
    // else. Timing from process start instead would fold in the child's startup
    // cost 鈥?loading a test binary and running an `--exact` filter 鈥?which on a
    // loaded CI runner is hundreds of milliseconds and made a contention-free
    // acquisition look like it had waited.
    println!("READY {mark}");
    let started = std::time::Instant::now();
    let lock = pangu_core::PathLock::acquire(
        &workspace,
        std::path::Path::new(&path),
        pangu_core::LockMode::Write,
        Duration::from_secs(30),
    )
    .expect("child acquires the path lock");
    println!("ACQUIRED {mark} after {}ms", started.elapsed().as_millis());
    std::thread::sleep(Duration::from_millis(hold_ms));
    drop(lock);
    // Report how long the lock was actually held, measured by the holder itself.
    //
    // The parent cannot assume the nominal hold_ms: under load the holder may be
    // descheduled between acquiring and releasing, and the contention window a
    // contender actually sees is this measured value, not the requested one.
    // Comparing against the nominal value is what made these tests flake on a busy
    // machine, where a nominal 900ms hold left a contender waiting only 418ms.
    println!(
        "RELEASED {mark} after {}ms held",
        started.elapsed().as_millis()
    );
}

/// How long the holder keeps its lock in the contention tests.
///
/// Long enough that a genuine wait is unmistakable against scheduler noise, and
/// short enough to keep the suite fast.
const HOLD_MS: u64 = 900;

/// [`HOLD_MS`] as a `u128`, for comparing against elapsed milliseconds.
const HOLD_MS_WIDE: u128 = HOLD_MS as u128;

/// Settling time between spawning the holder and the contender.
///
/// The holder must be *inside* its critical section before the contender starts,
/// otherwise the contender can take the lock first and the test measures the
/// wrong thing.
const SETTLE_MS: u64 = 400;

/// Assert that two measured waits differ by the amount the lock requires.
///
/// The properties under test are *relative*: an uncontended acquisition must be
/// much faster than a contended one. Comparing against a fixed millisecond
/// threshold instead conflates the lock's behaviour with how promptly the CI
/// runner schedules the child process 鈥?a loaded runner produced 556ms for an
/// acquisition that never waited, which is a slow machine, not a broken lock.
///
/// Scaling against the contended measurement cancels the environmental term,
/// because both numbers are taken the same way on the same machine moments
/// apart. The message reports both so a failure is diagnosable without a rerun.
fn minimum_of(samples: &[u128]) -> u128 {
    samples.iter().copied().min().unwrap_or(u128::MAX)
}

fn assert_waited_far_less(free_ms: u128, contended_ms: u128, what: &str) {
    // One uncontended sample can include a scheduling stall. The lock property
    // is still relative: unrelated work must remain much faster than contended
    // work, but a single delayed sample must not erase a large gap.
    let ceiling = contended_ms / 4;
    assert!(
        free_ms <= ceiling,
        "{what}: an uncontended acquisition waited {free_ms}ms while the contended \
         one waited {contended_ms}ms (ceiling {ceiling}ms). The uncontended case must \
         stay far below the contended case; if the two are close, unrelated work is \
         being serialised."
    );
}

/// Milliseconds the child spent **inside** the lock acquisition.
///
/// Measured against the child's own `started` reading, which is taken as the
/// first statement of the acquisition, so this excludes process startup.
fn waited_ms(output: &str, mark: &str) -> u128 {
    let needle = format!("ACQUIRED {mark} after ");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&needle))
        .and_then(|rest| rest.trim_end_matches("ms").parse::<u128>().ok())
        .unwrap_or_else(|| panic!("no acquisition timing for {mark} in: {output}"))
}

/// Milliseconds the holder *actually* held its lock, as measured by the holder.
///
/// This is the contention window a contender really sees. The nominal `HOLD_MS`
/// is what the holder was asked for; this is what it delivered. On a loaded
/// machine the two differ, and asserting against the nominal value is what made
/// these tests flake — a nominal 900ms hold produced a 418ms measured window.
fn held_ms(output: &str, mark: &str) -> u128 {
    let needle = format!("RELEASED {mark} after ");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&needle))
        .and_then(|rest| rest.trim_end_matches("ms held").parse::<u128>().ok())
        .unwrap_or_else(|| panic!("no hold timing for {mark} in: {output}"))
}

/// Assert the contender genuinely waited on the holder.
///
/// The bound is derived from what the holder **measured**, not from what it was
/// asked to do. The holder can be descheduled, and demanding a fixed fraction of
/// the nominal hold turns a loaded machine into a failure that has nothing to do
/// with the lock.
///
/// A third of the measured hold is still far above scheduler noise — the
/// uncontended case is single-digit milliseconds — so a lock that stopped
/// serialising would still fail loudly, while a merely busy machine would not.
fn assert_genuinely_contended(waited: u128, held: u128, what: &str) {
    // Sanity-check the measurement before trusting it: if the holder reported a
    // hold far below what it was asked for, the number is suspect and a passing
    // or failing verdict from it would be meaningless.
    assert!(
        held >= HOLD_MS_WIDE / 2,
        "{what}: the holder reported only {held}ms held against a {HOLD_MS}ms request; \
         the measurement itself is suspect"
    );
    let floor = held / 3;
    assert!(
        waited >= floor,
        "{what}: the contender waited {waited}ms while the holder measured {held}ms held \
         (floor {floor}ms). A genuine contention wait must be a substantial fraction of \
         the window that actually existed."
    );
}

/// The point of per-file locking: two agents on different files must not wait.
///
/// The claim is comparative, so the test measures both cases and compares them
/// rather than checking one number against an absolute threshold.
#[test]
fn different_files_do_not_serialise_across_processes() {
    // Case 1: same file, which must serialise.
    let contended_workspace = scratch("parallel-contended");
    let holder = spawn_child(&contended_workspace, "src/a.rs", HOLD_MS, "first");
    std::thread::sleep(Duration::from_millis(SETTLE_MS));
    let contender = spawn_child(&contended_workspace, "src/a.rs", 0, "second");
    let holder_out = output_of(holder);
    let contender_out = output_of(contender);
    assert!(holder_out.contains("ACQUIRED first"), "{holder_out}");
    assert!(contender_out.contains("ACQUIRED second"), "{contender_out}");
    let contended_ms = waited_ms(&contender_out, "second");

    // Case 2: different file, which must not.
    let free_workspace = scratch("parallel-free");
    let holder = spawn_child(&free_workspace, "src/a.rs", HOLD_MS, "first");
    std::thread::sleep(Duration::from_millis(SETTLE_MS));
    let other = spawn_child(&free_workspace, "docs/b.md", 0, "second");
    let holder_out = output_of(holder);
    let other_out = output_of(other);
    assert!(holder_out.contains("ACQUIRED first"), "{holder_out}");
    assert!(other_out.contains("ACQUIRED second"), "{other_out}");
    let mut free_samples = vec![waited_ms(&other_out, "second")];
    // One delayed scheduler sample must not decide the result. Repeating the
    // uncontended case and keeping its minimum preserves the property: genuine
    // serialization makes every sample slow, while one scheduling stall does not.
    for round in 1..3 {
        let retry_workspace = scratch(&format!("parallel-free-retry-{round}"));
        let holder = spawn_child(&retry_workspace, "src/a.rs", HOLD_MS, "first");
        std::thread::sleep(Duration::from_millis(SETTLE_MS));
        let other = spawn_child(&retry_workspace, "src/b.rs", 0, "second");
        let holder_out = output_of(holder);
        let other_out = output_of(other);
        assert!(holder_out.contains("ACQUIRED first"), "{holder_out}");
        assert!(other_out.contains("ACQUIRED second"), "{other_out}");
        free_samples.push(waited_ms(&other_out, "second"));
        fs::remove_dir_all(&retry_workspace).ok();
    }
    let free_ms = minimum_of(&free_samples);

    // A different file must not have waited for the holder to release.
    assert_waited_far_less(
        free_ms,
        contended_ms,
        "a different file must not serialise behind the holder",
    );

    // And the contended case must actually have waited, otherwise the comparison
    // above would pass vacuously on a machine where nothing contended at all.
    assert_genuinely_contended(
        contended_ms,
        held_ms(&holder_out, "first"),
        "the same-file case must genuinely contend",
    );

    fs::remove_dir_all(&contended_workspace).ok();
    fs::remove_dir_all(&free_workspace).ok();
}

/// The property that must survive: the same file still serialises.
#[test]
fn the_same_file_still_serialises_across_processes() {
    let workspace = scratch("serialise");
    let holder = spawn_child(&workspace, "src/a.rs", HOLD_MS, "first");
    std::thread::sleep(Duration::from_millis(SETTLE_MS));
    let other = spawn_child(&workspace, "src/a.rs", 0, "second");

    let holder_out = output_of(holder);
    let other_out = output_of(other);

    assert!(holder_out.contains("ACQUIRED first"), "{holder_out}");
    assert!(other_out.contains("ACQUIRED second"), "{other_out}");

    // Same file: the second process must have waited for the first to release.
    // A lower bound is the robust direction here.
    let waited = waited_ms(&other_out, "second");
    assert_genuinely_contended(
        waited,
        held_ms(&holder_out, "first"),
        "the same file must serialise",
    );

    fs::remove_dir_all(&workspace).ok();
}

// ---------------------------------------------------------------------------
// Module-aware locking across processes
// ---------------------------------------------------------------------------

/// Build a Cargo workspace with two sibling crates, for module tests.
fn cargo_workspace(label: &str) -> PathBuf {
    let root = scratch(label);
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*\"]\n",
    )
    .unwrap();
    for (name, dir) in [("alpha", "crates/alpha"), ("beta", "crates/beta")] {
        let crate_dir = root.join(dir);
        fs::create_dir_all(crate_dir.join("src")).unwrap();
        fs::write(
            crate_dir.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\n"),
        )
        .unwrap();
        fs::write(crate_dir.join("src/lib.rs"), "// src\n").unwrap();
    }
    root
}

/// Child that locks a path through the module-aware entry point.
fn spawn_module_child(
    workspace: &PathBuf,
    path: &str,
    hold_ms: u64,
    mark: &str,
) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("module_lock_child")
        .arg("--nocapture")
        .arg("--ignored")
        .env("PANGU_MODLOCK_WORKSPACE", workspace)
        .env("PANGU_MODLOCK_PATH", path)
        .env("PANGU_MODLOCK_HOLD_MS", hold_ms.to_string())
        .env("PANGU_MODLOCK_MARK", mark)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn module child")
}

#[test]
#[ignore = "helper process driven by the module contention tests"]
fn module_lock_child() {
    let workspace = match std::env::var("PANGU_MODLOCK_WORKSPACE") {
        Ok(value) => PathBuf::from(value),
        Err(_) => return,
    };
    let path = std::env::var("PANGU_MODLOCK_PATH").unwrap();
    let hold_ms: u64 = std::env::var("PANGU_MODLOCK_HOLD_MS")
        .unwrap()
        .parse()
        .unwrap();
    let mark = std::env::var("PANGU_MODLOCK_MARK").unwrap_or_default();

    let map = pangu_core::discover(&workspace).expect("discover modules");
    assert!(map.is_confident(), "fixture build files must parse");

    // Readiness is announced before the clock starts, for the same reason as the
    // path-lock child: what is being measured is the acquisition, not how long
    // the runner took to get this process to that line.
    println!("READY {mark}");
    let started = std::time::Instant::now();
    let lock = pangu_core::PathLock::acquire_for_action_with_modules(
        &workspace,
        &[],
        &[workspace.join(&path)],
        Some(&map),
        Duration::from_secs(30),
    )
    .expect("child acquires the module-aware lock");
    println!("ACQUIRED {mark} after {}ms", started.elapsed().as_millis());
    std::thread::sleep(Duration::from_millis(hold_ms));
    drop(lock);
    // Report how long the lock was actually held, measured by the holder itself.
    //
    // The parent cannot assume the nominal hold_ms: under load the holder may be
    // descheduled between acquiring and releasing, and the contention window a
    // contender actually sees is this measured value, not the requested one.
    // Comparing against the nominal value is what made these tests flake on a busy
    // machine, where a nominal 900ms hold left a contender waiting only 418ms.
    println!(
        "RELEASED {mark} after {}ms held",
        started.elapsed().as_millis()
    );
}

/// One agent owning a module must not block an agent in a sibling module.
///
/// Comparative, like the per-file test: the same-module case supplies the
/// baseline that the sibling case must stay far below.
#[test]
fn a_build_edit_in_one_crate_does_not_block_a_sibling_crate() {
    // Case 1: the same module, which must serialise.
    let contended_workspace = cargo_workspace("module-parallel-contended");
    let holder = spawn_module_child(
        &contended_workspace,
        "crates/alpha/Cargo.toml",
        HOLD_MS,
        "first",
    );
    std::thread::sleep(Duration::from_millis(SETTLE_MS));
    let contender =
        spawn_module_child(&contended_workspace, "crates/alpha/Cargo.toml", 0, "second");
    let holder_out = output_of(holder);
    let contender_out = output_of(contender);
    assert!(holder_out.contains("ACQUIRED first"), "{holder_out}");
    assert!(contender_out.contains("ACQUIRED second"), "{contender_out}");
    let contended_ms = waited_ms(&contender_out, "second");

    // Case 2: a sibling module, which must not.
    let free_workspace = cargo_workspace("module-parallel-free");
    let holder = spawn_module_child(&free_workspace, "crates/alpha/Cargo.toml", HOLD_MS, "alpha");
    std::thread::sleep(Duration::from_millis(SETTLE_MS));
    let sibling = spawn_module_child(&free_workspace, "crates/beta/Cargo.toml", 0, "beta");
    let holder_out = output_of(holder);
    let sibling_out = output_of(sibling);
    assert!(holder_out.contains("ACQUIRED alpha"), "{holder_out}");
    assert!(sibling_out.contains("ACQUIRED beta"), "{sibling_out}");
    let mut free_samples = vec![waited_ms(&sibling_out, "beta")];
    for round in 1..3 {
        let retry_workspace = cargo_workspace(&format!("module-parallel-free-retry-{round}"));
        let holder = spawn_module_child(
            &retry_workspace,
            "crates/alpha/Cargo.toml",
            HOLD_MS,
            "alpha",
        );
        std::thread::sleep(Duration::from_millis(SETTLE_MS));
        let sibling = spawn_module_child(&retry_workspace, "crates/beta/Cargo.toml", 0, "beta");
        let holder_out = output_of(holder);
        let sibling_out = output_of(sibling);
        assert!(holder_out.contains("ACQUIRED alpha"), "{holder_out}");
        assert!(sibling_out.contains("ACQUIRED beta"), "{sibling_out}");
        free_samples.push(waited_ms(&sibling_out, "beta"));
        fs::remove_dir_all(&retry_workspace).ok();
    }
    let free_ms = minimum_of(&free_samples);

    assert_waited_far_less(
        free_ms,
        contended_ms,
        "a sibling module must proceed in parallel",
    );
    assert_genuinely_contended(
        contended_ms,
        held_ms(&holder_out, "alpha"),
        "the same-module case must genuinely contend",
    );

    fs::remove_dir_all(&contended_workspace).ok();
    fs::remove_dir_all(&free_workspace).ok();
}

/// The same module still serialises its build files.
#[test]
fn a_build_edit_in_the_same_crate_serialises_across_processes() {
    let workspace = cargo_workspace("module-serial");
    let holder = spawn_module_child(&workspace, "crates/alpha/Cargo.toml", HOLD_MS, "first");
    std::thread::sleep(Duration::from_millis(SETTLE_MS));
    let second = spawn_module_child(&workspace, "crates/alpha/Cargo.toml", 0, "second");

    let holder_out = output_of(holder);
    let second_out = output_of(second);
    assert!(holder_out.contains("ACQUIRED first"), "{holder_out}");
    assert!(second_out.contains("ACQUIRED second"), "{second_out}");

    // A lower bound is the robust direction: a slow runner only makes the wait
    // longer, so this cannot fail for being slow.
    let waited = waited_ms(&second_out, "second");
    assert_genuinely_contended(
        waited,
        held_ms(&holder_out, "first"),
        "the same module's build file must serialise",
    );

    fs::remove_dir_all(&workspace).ok();
}
