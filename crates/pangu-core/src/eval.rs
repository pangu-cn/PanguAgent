//! F5: the issue-to-patch evaluation record — a machine-fact dossier that
//! makes one run reproducible and auditable.
//!
//! Borrowed from SWE-agent's experiment discipline: an evaluation fixes the
//! issue, the repository version, the frozen contract, the produced patch
//! (as registered deliverables), the trajectory pointer, and the cost. It
//! deliberately has **no score field**: benchmark numbers, model self-reports
//! and prose summaries do not replace acceptance evidence (W-31). What
//! "fixed the issue" means is decided outside the run — by `verify:`
//! evidence (F3) captured in the record, and by human acceptance of the
//! registered deliverables (D4).
//!
//! Storage mirrors the deliverables registry: `<workspace>/.pangu/eval/`
//! (a tool-forbidden root), atomic writes, corruption is a hard error, and
//! records are append-only — history is never rewritten.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::events::Usage;
use crate::util::{hex_sha256, now_rfc3339};

/// Schema tag of the on-disk evaluation registry.
pub const EVAL_SCHEMA: &str = "pangu-eval/1";

/// Fixed disclaimer recorded with every evaluation: the run status is a
/// machine fact about the session, not a claim that the issue is fixed.
pub const EVAL_NOT_ACCEPTANCE: &str = "status/evidence are machine facts; they do not assert the issue is fixed. Acceptance = verify evidence + human deliverable sign-off (benchmark scores do not replace acceptance).";

/// The issue input of an evaluation, pinned by content digest. The digest is
/// taken when the run starts; the goal text embedded in the contract is the
/// issue content at that moment (edits during the run do not affect it, and
/// the digest says exactly which version was used).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalIssue {
    /// Workspace-relative path of the issue document.
    pub path: String,
    /// SHA-256 of the issue content at run start.
    pub sha256: String,
}

/// One registered deliverable as it stood when the run finished.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalDeliverable {
    pub name: String,
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    /// Acceptance state at evaluation time (`pending`/`accepted`/`rejected`).
    pub acceptance: String,
}

/// One evaluation: the frozen inputs, the run's machine-fact outcome, and
/// pointers into the audit trail. Append-only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvalRecord {
    pub schema: String,
    pub id: String,
    pub profile: String,
    pub started_at: String,
    pub finished_at: String,
    pub issue: EvalIssue,
    /// Git `HEAD` of the workspace at run start, or `"unknown"` when the
    /// workspace is not a git repository. This is an operator-environment
    /// observation, not a verified fact.
    pub workspace_version: String,
    /// Digest of the GoalContract that froze every rule of the run.
    pub contract_digest: String,
    /// Terminal status of the run (complete/failed/needs_input/aborted/
    /// budget_exhausted).
    pub status: String,
    pub turns: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Total priced cost of the run; `None` when the primary model has no
    /// declared price (cost is then unknowable, never zero).
    pub cost_usd: Option<f64>,
    /// Count of `verify:` evidence items (F3 verification loop successes).
    pub verify_evidence: usize,
    pub evidence_total: usize,
    pub deliverables: Vec<EvalDeliverable>,
    /// Journal file name holding the full trajectory (redacted events).
    pub journal: String,
    pub notes: Vec<String>,
}

/// On-disk envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvalFile {
    schema: String,
    records: Vec<EvalRecord>,
}

/// Append-only evaluation registry under `<workspace>/.pangu/eval/`.
#[derive(Debug)]
pub struct EvalStore {
    dir: PathBuf,
    records: Mutex<Vec<EvalRecord>>,
}

fn lock<'a>(mutex: &'a Mutex<Vec<EvalRecord>>) -> std::sync::MutexGuard<'a, Vec<EvalRecord>> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl EvalStore {
    /// Open (or create) the registry directory. A corrupted file is a hard
    /// error — silently resetting an audit trail is exactly the failure this
    /// store exists to prevent.
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|error| {
            Error::Config(format!("creating eval registry {}: {error}", dir.display()))
        })?;
        let path = dir.join("records.json");
        let records = if path.exists() {
            let raw = std::fs::read_to_string(&path).map_err(|error| {
                Error::Config(format!("reading eval registry {}: {error}", path.display()))
            })?;
            let parsed: EvalFile = serde_json::from_str(&raw).map_err(|error| {
                Error::Config(format!(
                    "eval registry {} is corrupted (schema {EVAL_SCHEMA}): {error}",
                    path.display()
                ))
            })?;
            if parsed.schema != EVAL_SCHEMA {
                return Err(Error::Config(format!(
                    "eval registry {} has unknown schema {} (expected {EVAL_SCHEMA})",
                    path.display(),
                    parsed.schema
                )));
            }
            // Structural validation: unique ids, digest-shaped fields.
            let mut seen = std::collections::HashSet::new();
            for record in &parsed.records {
                if !seen.insert(record.id.clone()) {
                    return Err(Error::Config(format!(
                        "eval registry {} has duplicate record id {}",
                        path.display(),
                        record.id
                    )));
                }
                if record.issue.sha256.len() != 64
                    || !record.issue.sha256.chars().all(|c| c.is_ascii_hexdigit())
                {
                    return Err(Error::Config(format!(
                        "eval record {} has a malformed issue digest",
                        record.id
                    )));
                }
            }
            parsed.records
        } else {
            Vec::new()
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            records: Mutex::new(records),
        })
    }

    fn path(&self) -> PathBuf {
        self.dir.join("records.json")
    }

    /// Snapshot of all records, oldest first.
    pub fn records(&self) -> Vec<EvalRecord> {
        lock(&self.records).clone()
    }

    /// Append one record. Duplicate ids are rejected — a collision would
    /// mean two runs claim the same audit identity.
    pub fn append(&self, record: EvalRecord) -> Result<EvalRecord> {
        let mut guard = lock(&self.records);
        if guard.iter().any(|existing| existing.id == record.id) {
            return Err(Error::Other(format!(
                "duplicate evaluation id {} (refusing to overwrite history)",
                record.id
            )));
        }
        guard.push(record.clone());
        self.save_locked(&guard)
            .map_err(|error| Error::Other(format!("appending eval {}: {error}", record.id)))?;
        Ok(record)
    }

    fn save_locked(&self, records: &[EvalRecord]) -> Result<()> {
        let path = self.path();
        let temp = self
            .dir
            .join(format!("records.json.tmp-{}", std::process::id()));
        let file = EvalFile {
            schema: EVAL_SCHEMA.to_string(),
            records: records.to_vec(),
        };
        let body = serde_json::to_string_pretty(&file)
            .map_err(|error| Error::Other(format!("serializing eval registry: {error}")))?;
        std::fs::write(&temp, body)
            .map_err(|error| Error::Other(format!("writing {}: {error}", temp.display())))?;
        std::fs::rename(&temp, &path)
            .map_err(|error| Error::Other(format!("finalizing {}: {error}", path.display())))?;
        Ok(())
    }
}

/// The run-side facts of one finished evaluation run: terminal status,
/// trajectory summary, cost, and the evidence list.
#[derive(Debug, Clone)]
pub struct EvalRunFacts {
    /// Terminal status of the run (complete/failed/needs_input/aborted/
    /// budget_exhausted).
    pub status: String,
    pub turns: u32,
    pub usage: Usage,
    /// Total priced cost; `None` when the primary model has no declared
    /// price (cost is then unknowable, never zero).
    pub cost_usd: Option<f64>,
    /// The run's evidence list (verify:/read:/... prefixes).
    pub evidence: Vec<String>,
}

/// Everything the CLI collects about one evaluation run, handed to the
/// agent-run wrapper and finalized after the run ends.
pub struct EvalContext {
    pub profile: String,
    pub issue: EvalIssue,
    pub workspace_version: String,
    pub contract_digest: String,
    pub started_at: String,
    pub store: EvalStore,
}

impl EvalContext {
    /// Assemble the record from the run's outcome. `deliverables` are the
    /// ones registered by this run (empty when the goal declared none) and
    /// `journal` names the trajectory file.
    pub fn finish(
        self,
        facts: &EvalRunFacts,
        deliverables: Vec<EvalDeliverable>,
        journal: &str,
    ) -> Result<EvalRecord> {
        let verify_evidence = facts
            .evidence
            .iter()
            .filter(|item| item.starts_with("verify:"))
            .count();
        let record = EvalRecord {
            schema: EVAL_SCHEMA.to_string(),
            id: format!(
                "eval-{}",
                &hex_sha256(&format!(
                    "{}|{}|{}",
                    self.started_at, self.contract_digest, self.issue.sha256
                ))[..12]
            ),
            profile: self.profile,
            started_at: self.started_at,
            finished_at: now_rfc3339(),
            issue: self.issue,
            workspace_version: self.workspace_version,
            contract_digest: self.contract_digest,
            status: facts.status.clone(),
            turns: facts.turns,
            input_tokens: facts.usage.input_tokens,
            output_tokens: facts.usage.output_tokens,
            cost_usd: facts.cost_usd,
            verify_evidence,
            evidence_total: facts.evidence.len(),
            deliverables,
            journal: journal.to_string(),
            notes: vec![EVAL_NOT_ACCEPTANCE.to_string()],
        };
        self.store.append(record.clone())?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pangu-eval-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn sample_record(id: &str) -> EvalRecord {
        EvalRecord {
            schema: EVAL_SCHEMA.to_string(),
            id: id.to_string(),
            profile: "issue-fix".into(),
            started_at: "2026-01-01T00:00:00+00:00".into(),
            finished_at: "2026-01-01T00:01:00+00:00".into(),
            issue: EvalIssue {
                path: "issues/001.md".into(),
                sha256: "a".repeat(64),
            },
            workspace_version: "unknown".into(),
            contract_digest: "d".repeat(64),
            status: "complete".into(),
            turns: 3,
            input_tokens: 100,
            output_tokens: 50,
            cost_usd: Some(0.25),
            verify_evidence: 1,
            evidence_total: 2,
            deliverables: vec![EvalDeliverable {
                name: "patch".into(),
                path: "out/patch.diff".into(),
                sha256: "b".repeat(64),
                bytes: 42,
                acceptance: "pending".into(),
            }],
            journal: "journal-run-x.jsonl".into(),
            notes: vec![EVAL_NOT_ACCEPTANCE.into()],
        }
    }

    #[test]
    fn append_and_reload_roundtrip() {
        let dir = temp_dir("roundtrip");
        let store = EvalStore::open(&dir.join("eval")).expect("open");
        assert!(store.records().is_empty());
        store.append(sample_record("eval-1")).expect("append");
        assert_eq!(store.records().len(), 1);

        let reopened = EvalStore::open(&dir.join("eval")).expect("reopen");
        assert_eq!(reopened.records(), store.records());
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn duplicate_id_is_rejected() {
        let dir = temp_dir("dup");
        let store = EvalStore::open(&dir.join("eval")).expect("open");
        store.append(sample_record("eval-1")).expect("first");
        let error = store
            .append(sample_record("eval-1"))
            .expect_err("duplicate id");
        assert!(error.to_string().contains("duplicate evaluation id"));
        assert_eq!(store.records().len(), 1);
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn corrupted_registry_is_a_hard_error() {
        let dir = temp_dir("corrupt");
        let eval_dir = dir.join("eval");
        std::fs::create_dir_all(&eval_dir).expect("dir");
        std::fs::write(eval_dir.join("records.json"), "{ not json").expect("corrupt");
        let error = EvalStore::open(&eval_dir).expect_err("corrupt");
        assert!(error.to_string().contains("corrupted"), "{error}");

        // Wrong schema tag also fails loudly.
        std::fs::write(
            eval_dir.join("records.json"),
            r#"{"schema":"pangu-eval/9","records":[]}"#,
        )
        .expect("schema");
        let error = EvalStore::open(&eval_dir).expect_err("schema");
        assert!(error.to_string().contains("unknown schema"), "{error}");
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn malformed_issue_digest_fails_load() {
        let dir = temp_dir("digest");
        let eval_dir = dir.join("eval");
        std::fs::create_dir_all(&eval_dir).expect("dir");
        let mut record = sample_record("eval-bad");
        record.issue.sha256 = "zz".into();
        std::fs::write(
            eval_dir.join("records.json"),
            serde_json::to_string(&EvalFile {
                schema: EVAL_SCHEMA.into(),
                records: vec![record],
            })
            .expect("json"),
        )
        .expect("write");
        let error = EvalStore::open(&eval_dir).expect_err("bad digest");
        assert!(
            error.to_string().contains("malformed issue digest"),
            "{error}"
        );
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn finish_assembles_the_record_and_counts_verify_evidence() {
        let dir = temp_dir("finish");
        let usage = Usage {
            input_tokens: 11,
            output_tokens: 7,
            cache_read_tokens: 0,
        };
        let context = EvalContext {
            profile: "issue-fix".into(),
            issue: EvalIssue {
                path: "issues/001.md".into(),
                sha256: "a".repeat(64),
            },
            workspace_version: "abc123".into(),
            contract_digest: "d".repeat(64),
            started_at: "2026-01-01T00:00:00+00:00".into(),
            store: EvalStore::open(&dir.join("eval")).expect("store"),
        };
        let facts = EvalRunFacts {
            status: "complete".into(),
            turns: 4,
            usage,
            cost_usd: None,
            evidence: vec!["verify: cargo test ok".into(), "read: notes".into()],
        };
        let record = context
            .finish(
                &facts,
                vec![EvalDeliverable {
                    name: "patch".into(),
                    path: "out/patch.diff".into(),
                    sha256: "b".repeat(64),
                    bytes: 9,
                    acceptance: "pending".into(),
                }],
                "journal-run-1.jsonl",
            )
            .expect("finish");
        assert_eq!(record.verify_evidence, 1);
        assert_eq!(record.evidence_total, 2);
        assert_eq!(record.cost_usd, None, "unpriced stays None, never 0");
        assert!(record.id.starts_with("eval-"));
        assert!(record
            .notes
            .iter()
            .any(|note| note.contains("do not assert the issue is fixed")));
        // The record is persisted.
        assert_eq!(
            EvalStore::open(&dir.join("eval"))
                .expect("reopen")
                .records()
                .len(),
            1
        );
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}
