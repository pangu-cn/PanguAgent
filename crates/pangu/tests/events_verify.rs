//! `pangu events read --verify` must recompute the journal hash chain.
//!
//! The event stream is a *derived projection*: it carries no hash chain of its
//! own, so a reader that merely echoes the `sha` field it parsed back is not
//! reporting verification. Those two statements render identically
//!
//! ```text
//!   hash chain verified: 15 event(s), head sha 70940634a7ca1df1 ...
//!   origin.journal_sha:  c5487e2894098098a26969be0ba76922...
//! ```
//!
//! and mean very different things, which is exactly how a CI auditor would be
//! misled by a tampered file. `--verify` closes that gap by routing through
//! `replay::read`, which recomputes every digest and refuses on mismatch.
//!
//! These tests run the real binary: the guarantee is about the process an
//! operator or a CI job actually invokes, not about a library call.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use pangu_core::events::{Event, EventKind};
use pangu_core::journal::Journal;
use pangu_core::stream::{StreamEvent, StreamWriter};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A directory under the platform temp dir, canonicalized once so fixtures
/// satisfy the artifact/journal symlink policy on CI runners.
fn fixture_root(label: &str) -> PathBuf {
    let base = std::env::temp_dir();
    let base = fs::canonicalize(&base).unwrap_or(base);
    let root = base.join(format!(
        "pangu-events-verify-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).expect("fixture root");
    fs::canonicalize(&root).expect("canonical fixture root")
}

struct Fixture {
    root: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Fixture {
    fn new(label: &str) -> Self {
        Self {
            root: fixture_root(label),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// A journal with `count` chained events, written through the real writer.
    fn journal(&self, name: &str, count: usize) -> PathBuf {
        let path = self.path(name);
        let journal = Journal::create_v2(&path).expect("create journal");
        for index in 0..count {
            journal
                .record(&Event::new(
                    EventKind::TurnStarted,
                    index as u32 + 1,
                    format!("turn {}", index + 1),
                ))
                .expect("record event");
        }
        drop(journal);
        path
    }

    /// Run the real binary and return (success, stdout, stderr).
    fn run(&self, args: &[&str]) -> (bool, String, String) {
        let exe = env!("CARGO_BIN_EXE_pangu");
        let output = Command::new(exe)
            .args(args)
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .output()
            .expect("invoke pangu");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }
}

#[test]
fn verify_accepts_an_intact_journal_and_reports_the_recomputed_head() {
    let fixture = Fixture::new("clean");
    let journal = fixture.journal("journal.jsonl", 4);

    let (ok, stdout, stderr) =
        fixture.run(&["events", "read", journal.to_str().unwrap(), "--verify"]);

    assert!(
        ok,
        "--verify must accept an intact journal; stderr: {stderr}"
    );
    assert!(
        stdout.contains("hash chain verified"),
        "a verified read must say so explicitly: {stdout}"
    );
    assert!(
        stdout.contains("4 event(s)"),
        "the count of verified events must be reported: {stdout}"
    );
}

/// The defect this flag exists for: without it, a rewritten `sha` is echoed
/// back as though it were the chain's own answer.
#[test]
fn verify_refuses_a_rewritten_sha_that_a_plain_read_echoes_back() {
    let fixture = Fixture::new("tamper-sha");
    let journal = fixture.journal("journal.jsonl", 4);
    let tampered = fixture.path("tampered.jsonl");

    let raw = fs::read_to_string(&journal).expect("read journal");
    let zeros = "0".repeat(64);
    let rewritten = raw
        .lines()
        .enumerate()
        .map(|(index, line)| {
            if index == 2 {
                // Replace the digest of record 2 with a well-formed-but-wrong
                // one: still 64 hex chars, so only recomputation catches it.
                let start = line.rfind("\"sha\":\"").expect("sha field");
                let mut line = line.to_string();
                line.replace_range(start + 7..start + 71, &zeros);
                line
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&tampered, format!("{rewritten}\n")).expect("write tampered journal");

    // The plain read cannot tell, and must not claim that it can.
    let (plain_ok, plain_out, plain_err) =
        fixture.run(&["events", "read", tampered.to_str().unwrap()]);
    assert!(
        plain_ok,
        "the projection is documented to read the file as written; stderr: {plain_err}"
    );
    assert!(
        !plain_out.contains("hash chain verified"),
        "a plain read must never imply the chain was checked: {plain_out}"
    );

    // With --verify the same file is refused, and nothing is printed first.
    let (verify_ok, verify_out, verify_err) =
        fixture.run(&["events", "read", tampered.to_str().unwrap(), "--verify"]);
    assert!(!verify_ok, "--verify must fail on a rewritten sha");
    assert!(
        verify_err.contains("tamper detected") || verify_err.contains("did not verify"),
        "the failure must name tampering, not be a generic error: {verify_err}"
    );
    assert!(
        !verify_out.contains("tool_finished") && !verify_out.contains("turn 3"),
        "no record may be printed from a file that failed verification: {verify_out}"
    );
}

/// A truncated tail is the one corruption a hash chain cannot distinguish from
/// a short journal, so it must not silently verify as if complete.
#[test]
fn verify_refuses_a_journal_with_damaged_lines() {
    let fixture = Fixture::new("damaged");
    let journal = fixture.journal("journal.jsonl", 3);
    let damaged = fixture.path("damaged.jsonl");

    let raw = fs::read_to_string(&journal).expect("read journal");
    let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
    lines[1] = "{ this is not json".to_string();
    fs::write(&damaged, format!("{}\n", lines.join("\n"))).expect("write damaged journal");

    let (ok, _stdout, stderr) =
        fixture.run(&["events", "read", damaged.to_str().unwrap(), "--verify"]);
    assert!(!ok, "--verify must refuse a journal with unparseable lines");
    // The damage is caught while parsing the file, before the chain is reached;
    // what matters is that the read fails and names the offending line rather
    // than returning a prefix that looks complete.
    assert!(
        stderr.contains("damaged")
            || stderr.contains("did not verify")
            || stderr.contains("failed to migrate"),
        "the failure must point at the corrupt line: {stderr}"
    );
    assert!(
        stderr.contains("line 2"),
        "the failure must name which line is corrupt: {stderr}"
    );
}

/// `--verify` on something that has no chain to verify is a claim about a check
/// that never happened, so it fails closed instead of reporting a vacuous
/// success.
#[test]
fn verify_refuses_a_projection_that_carries_no_hash_chain() {
    let fixture = Fixture::new("projection");
    let stream = fixture.path("stream.jsonl");

    let writer = StreamWriter::create(&stream).expect("create stream");
    let source = Event::new(EventKind::RunStarted, 0, "run started");
    writer
        .append(&StreamEvent::from_event(&source).expect("project event"))
        .expect("append record");
    drop(writer);

    let (ok, _stdout, stderr) =
        fixture.run(&["events", "read", stream.to_str().unwrap(), "--verify"]);
    assert!(
        !ok,
        "--verify on a chainless projection must fail closed, not report success"
    );
    assert!(
        stderr.contains("no hash chain") || stderr.contains("projection"),
        "the failure must explain that a projection has no chain: {stderr}"
    );

    // The same file still reads fine without --verify: the projection is
    // legitimate, it simply is not evidence of integrity.
    let (plain_ok, _out, plain_err) = fixture.run(&["events", "read", stream.to_str().unwrap()]);
    assert!(
        plain_ok,
        "reading a projection without --verify must keep working: {plain_err}"
    );
}

/// The JSON envelope must carry the verification result as data, so a CI job
/// can branch on it without scraping prose.
#[test]
fn verify_reports_structured_integrity_in_json() {
    let fixture = Fixture::new("json");
    let journal = fixture.journal("journal.jsonl", 3);

    let (ok, stdout, stderr) = fixture.run(&[
        "events",
        "read",
        journal.to_str().unwrap(),
        "--verify",
        "--json",
    ]);
    assert!(ok, "json verify must succeed; stderr: {stderr}");

    let value: serde_json::Value = serde_json::from_str(&stdout).expect("parse json");
    let integrity = value.get("integrity").expect("integrity field");
    assert_eq!(integrity["verified"], serde_json::json!(true));
    assert_eq!(integrity["events_verified"], serde_json::json!(3));
    assert!(
        integrity["head_sha"]
            .as_str()
            .is_some_and(|sha| sha.len() == 64),
        "head_sha must be the recomputed digest: {integrity}"
    );

    // Without --verify the field is present and explicitly null: a consumer
    // must be able to tell "not checked" from "checked and intact".
    let (ok, stdout, _err) = fixture.run(&["events", "read", journal.to_str().unwrap(), "--json"]);
    assert!(ok, "plain json read must succeed");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("parse json");
    assert_eq!(
        value.get("integrity"),
        Some(&serde_json::Value::Null),
        "an unchecked read must report integrity as null, never as verified"
    );
}
