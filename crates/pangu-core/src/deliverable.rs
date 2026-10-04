//! D3/D4: the deliverable registry — declared artifacts, run-time evidence,
//! and operator acceptance.
//!
//! A **deliverable** is an artifact the goal declares up front (`[[goal.deliverable]]`):
//! a path, a kind, and an acceptor. The model produces the file through the
//! normal tool surface (L1–L4 apply as always); a `complete` finish is only
//! accepted when every declared deliverable passes its run-time checks
//! (existence, size, and the declared acceptor). The run then records a
//! signed-off snapshot — path, SHA-256, byte count, run id — into the
//! registry under `<workspace>/.pangu/deliverables.json`, and the operator
//! accepts or rejects each record through the CLI.
//!
//! Threat model (W-18): a generated report or table is not a fact. The
//! registry keeps the data version (digest + time + run), the check results
//! are audited, and human acceptance is a separate, explicit act outside any
//! run — the model cannot accept its own work.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::util::{hex_sha256, hex_sha256_bytes, now_rfc3339};

/// Schema tag of the on-disk deliverable registry.
pub const DELIVERABLES_SCHEMA: &str = "pangu-deliverables/1";

/// The declared acceptor for a deliverable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Acceptor {
    /// Human acceptance via the CLI, after the run. The run only records.
    Manual,
    /// At least one successful `verify:` evidence item in this run (the F3
    /// verification loop ran and passed).
    Verify,
    /// The artifact must parse as a single JSON value.
    Json,
    /// The artifact must parse as JSON Lines (every line a JSON value).
    Jsonl,
}

impl Acceptor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Verify => "verify",
            Self::Json => "json",
            Self::Jsonl => "jsonl",
        }
    }

    pub fn parse(input: &str) -> Option<Self> {
        match input {
            "manual" => Some(Self::Manual),
            "verify" => Some(Self::Verify),
            "json" => Some(Self::Json),
            "jsonl" => Some(Self::Jsonl),
            _ => None,
        }
    }
}

/// One declared deliverable (frozen into the contract).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliverableSpec {
    pub name: String,
    /// Workspace-relative path (`/`-separated). Never under `.pangu`.
    pub path: String,
    /// Free-form slug up to 32 bytes (report/patch/table/data/...).
    pub kind: String,
    pub acceptor: Acceptor,
    /// Minimum artifact size in bytes (default 1: must be non-empty).
    #[serde(default = "min_bytes_default")]
    pub min_bytes: u64,
}

fn min_bytes_default() -> u64 {
    1
}

/// One audit entry in a record's acceptance history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeliverableTransition {
    pub at: String,
    pub action: String,
    pub by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The acceptance status of one recorded deliverable. Transitions are
/// one-way and audited: pending → accepted | rejected. A new run recording
/// the same name appends a fresh record; history is never rewritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Acceptance {
    Pending,
    Accepted,
    Rejected,
}

impl Acceptance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

/// One recorded deliverable snapshot from a finished run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeliverableRecord {
    pub id: String,
    pub name: String,
    pub path: String,
    pub kind: String,
    pub acceptor: Acceptor,
    /// SHA-256 of the artifact bytes at recording time — the data version.
    pub sha256: String,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    pub recorded_at: String,
    pub acceptance: Acceptance,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transitions: Vec<DeliverableTransition>,
}

/// The deliverable registry: `<dir>/deliverables.json`.
///
/// Same disciplines as the memory store: load failures are hard errors,
/// writes are atomic (temp + rename), transitions are one-way and audited,
/// and there is no cross-process lock (last-writer-wins, documented; run-side
/// recordings are also in the Journal as `DeliverableRecorded` events, so a
/// lost concurrent write is recoverable from the audit trail).
#[derive(Debug)]
pub struct DeliverableStore {
    dir: PathBuf,
    records: std::sync::Mutex<Vec<DeliverableRecord>>,
}

/// The result of a run-time acceptance check for one deliverable.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckOutcome {
    pub name: String,
    pub passed: bool,
    pub detail: String,
    /// Artifact data version when the check passed.
    pub sha256: Option<String>,
    pub bytes: Option<u64>,
}

impl DeliverableStore {
    /// Open (creating the directory if needed) and load the registry.
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|error| {
            Error::Config(format!(
                "cannot create deliverables directory {}: {error}",
                dir.display()
            ))
        })?;
        let path = dir.join("deliverables.json");
        let records = if path.exists() {
            let raw = std::fs::read_to_string(&path).map_err(|error| {
                Error::Config(format!("cannot read {}: {error}", path.display()))
            })?;
            let parsed: DeliverablesFile = serde_json::from_str(&raw).map_err(|error| {
                Error::Config(format!(
                    "deliverables registry {} is corrupted (schema {DELIVERABLES_SCHEMA}): {error}",
                    path.display()
                ))
            })?;
            if parsed.schema != DELIVERABLES_SCHEMA {
                return Err(Error::Config(format!(
                    "deliverables registry {} has unknown schema {} (expected {DELIVERABLES_SCHEMA})",
                    path.display(),
                    parsed.schema
                )));
            }
            validate_records(&parsed.records, &path)?;
            parsed.records
        } else {
            Vec::new()
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            records: std::sync::Mutex::new(records),
        })
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join("deliverables.json")
    }

    pub fn records(&self) -> Vec<DeliverableRecord> {
        lock(&self.records).clone()
    }

    /// The latest record for one deliverable name.
    pub fn latest(&self, name: &str) -> Option<DeliverableRecord> {
        lock(&self.records)
            .iter()
            .rev()
            .find(|record| record.name == name)
            .cloned()
    }

    /// Record the run's delivery snapshot for one declared deliverable.
    /// Called only after the run's acceptance checks passed.
    pub fn record(
        &self,
        spec: &DeliverableSpec,
        sha256: &str,
        bytes: u64,
        run: Option<&str>,
    ) -> Result<DeliverableRecord> {
        let mut guard = lock(&self.records);
        let id = format!(
            "del-{}",
            &hex_sha256(&format!(
                "{}|{}|{sha256}|{}",
                now_rfc3339(),
                spec.name,
                run.unwrap_or("")
            ))[..12]
        );
        let record = DeliverableRecord {
            id,
            name: spec.name.clone(),
            path: spec.path.clone(),
            kind: spec.kind.clone(),
            acceptor: spec.acceptor,
            sha256: sha256.to_string(),
            bytes,
            run: run.map(str::to_string),
            recorded_at: now_rfc3339(),
            acceptance: Acceptance::Pending,
            transitions: Vec::new(),
        };
        guard.push(record.clone());
        self.save_locked(&guard)
            .map_err(|error| Error::Other(format!("recording {}: {error}", record.name)))?;
        Ok(record)
    }

    /// Operator accepts the latest pending record of one deliverable.
    pub fn accept(&self, name: &str, by: &str, note: Option<String>) -> Result<()> {
        self.transition(name, Acceptance::Accepted, by, note)
    }

    /// Operator rejects the latest pending record of one deliverable.
    pub fn reject(&self, name: &str, by: &str, note: Option<String>) -> Result<()> {
        self.transition(name, Acceptance::Rejected, by, note)
    }

    fn transition(&self, name: &str, to: Acceptance, by: &str, note: Option<String>) -> Result<()> {
        if by.trim().is_empty() {
            return Err(Error::InvalidArgs {
                tool: "deliverable".into(),
                detail: "transition actor (by) must not be empty".into(),
            });
        }
        let mut guard = lock(&self.records);
        let record = guard
            .iter_mut()
            .filter(|record| record.name == name && record.acceptance == Acceptance::Pending)
            .last()
            .ok_or_else(|| {
                Error::Other(format!(
                    "no pending deliverable record for `{name}` (it may already be decided)"
                ))
            })?;
        record.acceptance = to;
        record.transitions.push(DeliverableTransition {
            at: now_rfc3339(),
            action: match to {
                Acceptance::Accepted => "accepted",
                Acceptance::Rejected => "rejected",
                Acceptance::Pending => "pending",
            }
            .to_string(),
            by: by.to_string(),
            note,
        });
        self.save_locked(&guard)
            .map_err(|error| Error::Other(format!("transitioning {name}: {error}")))
    }

    fn save_locked(&self, records: &[DeliverableRecord]) -> Result<()> {
        let path = self.path();
        let temp = self
            .dir
            .join(format!("deliverables.json.tmp-{}", std::process::id()));
        let file = DeliverablesFile {
            schema: DELIVERABLES_SCHEMA.to_string(),
            records: records.to_vec(),
        };
        let raw = serde_json::to_string_pretty(&file)?;
        if temp.exists() {
            std::fs::remove_file(&temp).map_err(Error::Io)?;
        }
        std::fs::write(&temp, raw).map_err(Error::Io)?;
        std::fs::rename(&temp, path).map_err(Error::Io)?;
        Ok(())
    }
}

fn lock<'a>(
    mutex: &'a std::sync::Mutex<Vec<DeliverableRecord>>,
) -> std::sync::MutexGuard<'a, Vec<DeliverableRecord>> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug, Serialize, Deserialize)]
struct DeliverablesFile {
    schema: String,
    records: Vec<DeliverableRecord>,
}

fn validate_records(records: &[DeliverableRecord], path: &Path) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for record in records {
        if !seen.insert(record.id.as_str()) {
            return Err(Error::Config(format!(
                "duplicate deliverable record id {} in {}",
                record.id,
                path.display()
            )));
        }
        if record.sha256.len() != 64 || !record.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Config(format!(
                "deliverable record {} in {} has a malformed digest",
                record.id,
                path.display()
            )));
        }
        let legal = match record.acceptance {
            Acceptance::Pending => record.transitions.is_empty(),
            Acceptance::Accepted | Acceptance::Rejected => record.transitions.len() == 1,
        };
        if !legal {
            return Err(Error::Config(format!(
                "deliverable record {} in {} has {} transitions for status {:?}",
                record.id,
                path.display(),
                record.transitions.len(),
                record.acceptance
            )));
        }
    }
    Ok(())
}

/// Run-time acceptance check for one declared deliverable against the
/// workspace. This is the gate `complete` must pass; failures carry a
/// model-readable detail so the run can repair and retry.
pub fn check_spec(
    spec: &DeliverableSpec,
    workspace: &Path,
    has_verify_evidence: bool,
) -> CheckOutcome {
    let fail = |detail: String| CheckOutcome {
        name: spec.name.clone(),
        passed: false,
        detail,
        sha256: None,
        bytes: None,
    };
    if validate_relative_path(&spec.path).is_err() {
        return CheckOutcome {
            name: spec.name.clone(),
            passed: false,
            detail: "deliverable path is not a safe workspace-relative path".into(),
            sha256: None,
            bytes: None,
        };
    }
    let path = workspace.join(spec.path.replace('/', std::path::MAIN_SEPARATOR_STR));
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return fail(format!(
                "deliverable `{}` is missing at `{}` ({error}); write it with write_file first",
                spec.name, spec.path
            ))
        }
    };
    if (bytes.len() as u64) < spec.min_bytes {
        return fail(format!(
            "deliverable `{}` is {} bytes, below the declared minimum of {}",
            spec.name,
            bytes.len(),
            spec.min_bytes
        ));
    }
    match spec.acceptor {
        Acceptor::Manual => {}
        Acceptor::Verify => {
            if !has_verify_evidence {
                return fail(format!(
                    "deliverable `{}` requires a successful verify run (F3) in this run; \
                     run the verify tool first",
                    spec.name
                ));
            }
        }
        Acceptor::Json => {
            if serde_json::from_slice::<serde_json::Value>(&bytes).is_err() {
                return fail(format!(
                    "deliverable `{}` must be a single valid JSON document",
                    spec.name
                ));
            }
        }
        Acceptor::Jsonl => {
            let text = match std::str::from_utf8(&bytes) {
                Ok(text) => text,
                Err(_) => {
                    return fail(format!(
                        "deliverable `{}` must be UTF-8 JSON Lines",
                        spec.name
                    ))
                }
            };
            for (index, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                if serde_json::from_str::<serde_json::Value>(line).is_err() {
                    return fail(format!(
                        "deliverable `{}` line {} is not valid JSON (JSON Lines format)",
                        spec.name,
                        index + 1
                    ));
                }
            }
        }
    }
    CheckOutcome {
        name: spec.name.clone(),
        passed: true,
        detail: format!("ok ({})", spec.acceptor.as_str()),
        sha256: Some(hex_sha256_bytes(&bytes)),
        bytes: Some(bytes.len() as u64),
    }
}

/// Shared path-safety rule for declared deliverable paths.
pub fn validate_relative_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(Error::Config(format!(
            "deliverable path `{path}` is not a safe workspace-relative path"
        )));
    }
    if path.split('/').next() == Some(".pangu") {
        return Err(Error::Config(
            "deliverable paths must not live inside the `.pangu` tree".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("pangu-deliverable-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn spec(name: &str, path: &str, acceptor: Acceptor) -> DeliverableSpec {
        DeliverableSpec {
            name: name.into(),
            path: path.into(),
            kind: "report".into(),
            acceptor,
            min_bytes: 1,
        }
    }

    #[test]
    fn check_requires_existence_size_and_format() {
        let root = temp_root("check");
        // Missing file.
        let outcome = check_spec(&spec("r", "out/report.md", Acceptor::Manual), &root, false);
        assert!(!outcome.passed);
        assert!(outcome.detail.contains("missing"), "{}", outcome.detail);

        // Empty file below min_bytes.
        std::fs::create_dir_all(root.join("out")).expect("dir");
        std::fs::write(root.join("out/report.md"), "").expect("empty");
        let outcome = check_spec(&spec("r", "out/report.md", Acceptor::Manual), &root, false);
        assert!(!outcome.passed);
        assert!(outcome.detail.contains("below the declared minimum"));

        // Non-JSON content against the json acceptor.
        std::fs::write(root.join("out/report.md"), "not json").expect("content");
        let outcome = check_spec(&spec("r", "out/report.md", Acceptor::Json), &root, false);
        assert!(!outcome.passed);
        assert!(outcome.detail.contains("valid JSON"));

        // Valid JSON passes.
        std::fs::write(root.join("out/report.md"), "{\"ok\": true}").expect("content");
        let outcome = check_spec(&spec("r", "out/report.md", Acceptor::Json), &root, false);
        assert!(outcome.passed);
        assert_eq!(outcome.sha256.as_deref().map(str::len), Some(64));

        // JSONL: one bad line fails the whole artifact.
        std::fs::write(root.join("out/report.md"), "{\"a\":1}\nnot json\n").expect("content");
        let outcome = check_spec(&spec("r", "out/report.md", Acceptor::Jsonl), &root, false);
        assert!(!outcome.passed);
        assert!(outcome.detail.contains("line 2"));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn verify_acceptor_demands_verify_evidence() {
        let root = temp_root("verify");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(root.join("r.md"), "content").expect("content");
        let without = check_spec(&spec("r", "r.md", Acceptor::Verify), &root, false);
        assert!(!without.passed);
        assert!(without.detail.contains("verify"));
        let with = check_spec(&spec("r", "r.md", Acceptor::Verify), &root, true);
        assert!(with.passed);
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn record_then_accept_then_reject_is_audited_and_one_way() {
        let root = temp_root("lifecycle");
        let store = DeliverableStore::open(&root.join("deliverables")).expect("store");
        let spec = spec("report", "out/report.md", Acceptor::Manual);
        let record = store
            .record(&spec, &"a".repeat(64), 42, Some("run-1"))
            .expect("record");
        assert_eq!(record.acceptance, Acceptance::Pending);
        assert_eq!(store.records().len(), 1);

        store
            .accept("report", "operator:alice", Some("looks right".into()))
            .expect("accept");
        // Accepted -> rejected is illegal.
        assert!(store.reject("report", "cli", None).is_err());
        // A new run records a fresh pending entry.
        store
            .record(&spec, &"b".repeat(64), 50, Some("run-2"))
            .expect("record");
        store
            .reject("report", "operator:alice", None)
            .expect("reject");
        let records = store.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].acceptance, Acceptance::Accepted);
        assert_eq!(
            records[0].transitions[0].note.as_deref(),
            Some("looks right")
        );
        assert_eq!(records[1].acceptance, Acceptance::Rejected);
        // Latest points at the new record.
        assert_eq!(
            store.latest("report").expect("latest").sha256,
            "b".repeat(64)
        );
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn store_round_trips_and_rejects_corruption() {
        let root = temp_root("roundtrip");
        let store = DeliverableStore::open(&root.join("deliverables")).expect("store");
        let spec = spec("report", "out/report.md", Acceptor::Manual);
        store
            .record(&spec, &"c".repeat(64), 7, None)
            .expect("record");
        drop(store);
        let reloaded = DeliverableStore::open(&root.join("deliverables")).expect("reload");
        assert_eq!(reloaded.records().len(), 1);
        let path = root.join("deliverables").join("deliverables.json");
        let raw = std::fs::read_to_string(&path).expect("read");
        std::fs::write(&path, raw.replace("\"pending\"", "\"bogus\"")).expect("write");
        assert!(DeliverableStore::open(&root.join("deliverables")).is_err());
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn paths_must_be_safe_and_outside_pangu() {
        assert!(validate_relative_path("../escape.md").is_err());
        assert!(validate_relative_path("/abs.md").is_err());
        assert!(validate_relative_path("a//b.md").is_err());
        assert!(validate_relative_path(".pangu/journal.jsonl").is_err());
        assert!(validate_relative_path("out/report.md").is_ok());
    }
}
