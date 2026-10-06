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
    println!("RELEASED {mark}");
}

fn waited_ms(output: &str, mark: &str) -> u128 {
    let needle = format!("ACQUIRED {mark} after ");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&needle))
        .and_then(|rest| rest.trim_end_matches("ms").parse::<u128>().ok())
        .unwrap_or_else(|| panic!("no acquisition timing for {mark} in: {output}"))
}

/// The point of per-file locking: two agents on different files must not wait.
#[test]
fn different_files_do_not_serialise_across_processes() {
    let workspace = scratch("parallel");
    let holder = spawn_child(&workspace, "src/a.rs", 900, "first");
    std::thread::sleep(Duration::from_millis(250));
    let other = spawn_child(&workspace, "docs/b.md", 0, "second");

    let holder_out = output_of(holder);
    let other_out = output_of(other);

    assert!(holder_out.contains("ACQUIRED first"), "{holder_out}");
    assert!(other_out.contains("ACQUIRED second"), "{other_out}");

    // The second process touches a different file, so it must not have waited
    // for the first one's 900ms hold.
    let waited = waited_ms(&other_out, "second");
    assert!(
        waited < 400,
        "a different file must not wait for the first holder; waited {waited}ms"
    );

    fs::remove_dir_all(&workspace).ok();
}

/// The property that must survive: the same file still serialises.
#[test]
fn the_same_file_still_serialises_across_processes() {
    let workspace = scratch("serialise");
    let holder = spawn_child(&workspace, "src/a.rs", 900, "first");
    std::thread::sleep(Duration::from_millis(250));
    let other = spawn_child(&workspace, "src/a.rs", 0, "second");

    let holder_out = output_of(holder);
    let other_out = output_of(other);

    assert!(holder_out.contains("ACQUIRED first"), "{holder_out}");
    assert!(other_out.contains("ACQUIRED second"), "{other_out}");

    // Same file: the second process must have waited for the first to release.
    let waited = waited_ms(&other_out, "second");
    assert!(
        waited >= 300,
        "the same file must serialise; second waited only {waited}ms"
    );

    fs::remove_dir_all(&workspace).ok();
}
