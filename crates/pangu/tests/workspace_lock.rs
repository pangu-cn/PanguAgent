//! End-to-end contention: two real OS processes share one workspace.
//!
//! The unit tests in `pangu_core::lockfile` exercise the lock through its API.
//! This test instead spawns separate processes against a shared directory, so
//! the cross-process claim rests on real process separation rather than threads
//! inside one test binary (where an accidental in-process mutex could produce
//! the same observable behaviour).
//!
//! The parent never writes the lock file itself: it asserts only on what the
//! children report, so a bug in the parent's own locking cannot mask a bug in
//! the lock's.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn scratch(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "pangu-lock-e2e-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).unwrap();
    std::fs::canonicalize(path).unwrap()
}

/// Re-runs this test binary with an environment variable set, so a child
/// process performs the locking work. `cargo test` passes the test name; we
/// pick a dedicated helper by name.
fn spawn_holder(workspace: &Path, hold_ms: u64, mark: &str) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("lock_contention_holder_child")
        .arg("--nocapture")
        .arg("--ignored")
        .env("PANGU_LOCK_E2E_ROLE", "holder")
        .env("PANGU_LOCK_E2E_WORKSPACE", workspace)
        .env("PANGU_LOCK_E2E_HOLD_MS", hold_ms.to_string())
        .env("PANGU_LOCK_E2E_MARK", mark)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn holder")
}

fn spawn_waiter(workspace: &Path, timeout_ms: u64, mark: &str) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("lock_contention_holder_child")
        .arg("--nocapture")
        .arg("--ignored")
        .env("PANGU_LOCK_E2E_ROLE", "waiter")
        .env("PANGU_LOCK_E2E_WORKSPACE", workspace)
        .env("PANGU_LOCK_E2E_TIMEOUT_MS", timeout_ms.to_string())
        .env("PANGU_LOCK_E2E_MARK", mark)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn waiter")
}

fn output_of(child: std::process::Child) -> String {
    let out = child.wait_with_output().expect("wait for child");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The child body. Kept `#[ignore]`d so it never runs as a normal test; the
/// parent invokes it explicitly with `--ignored`.
#[test]
#[ignore = "helper process driven by the contention tests"]
fn lock_contention_holder_child() {
    let role = match std::env::var("PANGU_LOCK_E2E_ROLE") {
        Ok(value) => value,
        Err(_) => return,
    };
    let workspace = PathBuf::from(std::env::var("PANGU_LOCK_E2E_WORKSPACE").unwrap());
    let mark = std::env::var("PANGU_LOCK_E2E_MARK").unwrap_or_default();

    match role.as_str() {
        "holder" => {
            let hold_ms: u64 = std::env::var("PANGU_LOCK_E2E_HOLD_MS")
                .unwrap()
                .parse()
                .unwrap();
            let lock = pangu_core::WorkspaceLock::acquire(
                &workspace,
                pangu_core::LockMode::Write,
                Duration::from_secs(30),
            )
            .expect("holder acquires");
            println!("ACQUIRED {mark}");
            // Write inside the critical section and leave it behind, so the
            // parent can prove the write happened while the lock was held.
            fs::write(workspace.join("order.log"), format!("{mark}:in\n")).unwrap();
            std::thread::sleep(Duration::from_millis(hold_ms));
            drop(lock);
            println!("RELEASED {mark}");
        }
        "waiter" => {
            let timeout_ms: u64 = std::env::var("PANGU_LOCK_E2E_TIMEOUT_MS")
                .unwrap()
                .parse()
                .unwrap();
            let started = Instant::now();
            match pangu_core::WorkspaceLock::acquire(
                &workspace,
                pangu_core::LockMode::Write,
                Duration::from_millis(timeout_ms),
            ) {
                Ok(lock) => {
                    println!("ACQUIRED {mark} after {}ms", started.elapsed().as_millis());
                    drop(lock);
                    println!("RELEASED {mark}");
                }
                Err(error) => {
                    println!("REFUSED {mark} after {}ms", started.elapsed().as_millis());
                    println!("REASON {error}");
                }
            }
        }
        other => panic!("unknown role {other}"),
    }
}

#[test]
fn a_second_process_waits_for_the_first_and_then_proceeds() {
    let workspace = scratch("serialise");
    let holder = spawn_holder(&workspace, 700, "first");
    // Give the holder time to actually take the lock before the waiter starts,
    // so the waiter cannot win the race and make the test vacuous.
    std::thread::sleep(Duration::from_millis(300));
    let waiter = spawn_waiter(&workspace, 10_000, "second");

    let holder_out = output_of(holder);
    let waiter_out = output_of(waiter);

    assert!(
        holder_out.contains("ACQUIRED first"),
        "the holder must acquire: {holder_out}"
    );
    assert!(
        waiter_out.contains("ACQUIRED second"),
        "the waiter must eventually acquire rather than fail: {waiter_out}"
    );
    // The waiter must have had to wait — if it acquired instantly, the lock was
    // not actually held by the other process.
    let waited = waiter_out
        .lines()
        .find_map(|line| line.strip_prefix("ACQUIRED second after "))
        .and_then(|rest| rest.trim_end_matches("ms").parse::<u128>().ok())
        .expect("the waiter reports how long it waited");
    assert!(
        waited >= 200,
        "the waiter should have blocked while the holder ran, waited only {waited}ms"
    );

    fs::remove_dir_all(&workspace).ok();
}

#[test]
fn a_second_process_is_refused_when_the_holder_never_releases() {
    let workspace = scratch("timeout");
    // A holder that outlives the waiter's deadline: the waiter must give up and
    // say why, instead of blocking. This is the crashed-holder shape.
    let holder = spawn_holder(&workspace, 2_500, "stubborn");
    std::thread::sleep(Duration::from_millis(300));
    let waiter = spawn_waiter(&workspace, 400, "impatient");

    let holder_out = output_of(holder);
    let waiter_out = output_of(waiter);

    assert!(
        holder_out.contains("ACQUIRED stubborn"),
        "the holder must acquire: {holder_out}"
    );
    assert!(
        waiter_out.contains("REFUSED impatient"),
        "the waiter must be refused, not hang or succeed: {waiter_out}"
    );
    assert!(
        waiter_out.contains("not acquired within"),
        "the refusal must name the timeout: {waiter_out}"
    );
    assert!(
        waiter_out.contains("pid"),
        "the refusal must name the holder for the operator: {waiter_out}"
    );

    fs::remove_dir_all(&workspace).ok();
}

#[test]
fn a_reader_does_not_block_another_reader() {
    let workspace = scratch("shared-read");
    let _reader = pangu_core::WorkspaceLock::acquire(
        &workspace,
        pangu_core::LockMode::Read,
        Duration::from_secs(1),
    )
    .unwrap();
    let child = {
        let workspace = workspace.clone();
        std::thread::spawn(move || {
            pangu_core::WorkspaceLock::acquire(
                &workspace,
                pangu_core::LockMode::Read,
                Duration::from_millis(500),
            )
            .is_ok()
        })
    };
    assert!(
        child.join().unwrap(),
        "a second reader must not be blocked by the first"
    );
    fs::remove_dir_all(&workspace).ok();
}

#[test]
fn the_lock_file_is_gone_once_every_holder_released() {
    let workspace = scratch("cleanup");
    {
        let _lock = pangu_core::WorkspaceLock::acquire(
            &workspace,
            pangu_core::LockMode::Write,
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(workspace.join(pangu_core::WORKSPACE_LOCK_FILE).exists());
    }
    assert!(
        !workspace.join(pangu_core::WORKSPACE_LOCK_FILE).exists(),
        "a normal release must leave no lock file behind"
    );
    fs::remove_dir_all(&workspace).ok();
}
