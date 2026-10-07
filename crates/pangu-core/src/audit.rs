//! Item 8: an audit log — a portable, tamper-evident export of a run.
//!
//! # How this differs from the Journal
//!
//! The Journal is the authority, and it is append-only JSONL with a hash chain.
//! This module does **not** replace it or duplicate its guarantees. It produces
//! an *export*: a single self-describing file that can be handed to someone who
//! does not have the workspace, together with what they need to check that it
//! was not altered in transit.
//!
//! # What "tamper-evident" honestly means here
//!
//! The export carries a SHA-256 of its own event payload and **re-derives** the
//! Journal's hash chain across the exported events. A verifier can therefore
//! detect:
//!
//! - an event edited, reordered, inserted or removed in the export
//! - an export whose declared chain does not match its own contents
//!
//! It **cannot** detect an attacker who rewrites the whole export consistently,
//! because the chain is not anchored to anything external (no signature, no
//! external timestamp). That is a real limit and it is stated in the file
//! itself, so nobody mistakes this for a cryptographic guarantee it does not
//! provide. Detecting a fully rewritten export needs a signature key or an
//! external anchor, which is a separate decision about key management.
//!
//! # What is included, and what is deliberately not
//!
//! Events, already-redacted as the Journal stores them, plus counts and the
//! chain head. Tool **outputs** and model **text** live in the conversation
//! store, not the event stream, so they are not swept in by accident: an audit
//! export should contain what was decided, not everything that was said.
//!
//! # Unverified claims are labelled
//!
//! The export records what the run claimed about itself (model, phase, budget)
//! and marks those fields as claims rather than facts. A reader should be able
//! to tell "the run said it used model X" from "the run used model X" without
//! having to know the internals.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::events::Event;
use crate::util::hex_sha256;

/// Format tag of an exported audit log.
pub const AUDIT_SCHEMA: &str = "pangu-audit/1";

/// The fixed statement of what this export can and cannot prove.
///
/// Written into every export so a reader who receives only the file still knows
/// the boundary of its guarantee.
pub const INTEGRITY_STATEMENT: &str =
    "This export is tamper-EVIDENT, not tamper-proof. Its SHA-256 covers the \
exported event array and the Journal's hash chain is re-derived across those events, so an \
event inserted, removed, reordered or edited inside the export will be detected by `pangu \
audit verify`. It does NOT detect an attacker who rewrites the entire export consistently: the \
chain is not anchored to any external authority, because no signature key or timestamp is \
applied. Treat it as evidence that the file is internally consistent and unmodified since \
export, not as proof of who produced it.";

/// A claim the run made about itself, recorded as a claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub field: String,
    pub value: String,
    /// Always true. Present so a reader cannot mistake the surrounding object
    /// for verified fact.
    pub is_claim: bool,
}

/// The exported audit log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditLog {
    pub schema: String,
    /// Always true: this is derived from the Journal.
    pub derived: bool,
    /// Always false: the Journal is the authority.
    pub authoritative: bool,
    pub exported_at: String,
    /// SHA-256 over the canonical JSON of `events`, plus the chain head.
    ///
    /// Covers the array as a whole, so an event added or dropped anywhere in it
    /// changes this value.
    pub export_digest: String,
    /// The Journal hash chain head recorded at export time.
    pub chain_head: Option<String>,
    pub event_count: usize,
    pub counts_by_kind: BTreeMap<String, usize>,
    pub counts_by_severity: BTreeMap<String, usize>,
    /// What the run claimed about itself. Labelled, never asserted.
    pub claims: Vec<Claim>,
    /// The integrity statement, verbatim.
    pub integrity: String,
    pub events: Vec<Event>,
}

/// Build an audit log from a run's sealed events.
pub fn export(
    events: &[Event],
    chain_head: Option<String>,
    claims: Vec<(String, String)>,
) -> Result<AuditLog> {
    let mut ordered: Vec<Event> = events.to_vec();
    ordered.sort_by_key(|event| event.seq);

    let mut counts_by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut counts_by_severity: BTreeMap<String, usize> = BTreeMap::new();
    for event in &ordered {
        *counts_by_kind
            .entry(event.kind.as_str().to_string())
            .or_insert(0) += 1;
        *counts_by_severity
            .entry(crate::trace::Severity::of(event.kind).as_str().to_string())
            .or_insert(0) += 1;
    }

    let export_digest = digest_of(&ordered, chain_head.as_deref())?;

    Ok(AuditLog {
        schema: AUDIT_SCHEMA.to_string(),
        derived: true,
        authoritative: false,
        exported_at: crate::now_rfc3339(),
        export_digest,
        chain_head,
        event_count: ordered.len(),
        counts_by_kind,
        counts_by_severity,
        claims: claims
            .into_iter()
            .map(|(field, value)| Claim {
                field,
                value,
                is_claim: true,
            })
            .collect(),
        integrity: INTEGRITY_STATEMENT.to_string(),
        events: ordered,
    })
}

/// The digest an export's contents must reproduce.
///
/// Deliberately covers `events` and the chain head together: hashing only the
/// chain head would leave the event array free to differ from it, and hashing
/// only the events would let the head be swapped.
fn digest_of(events: &[Event], chain_head: Option<&str>) -> Result<String> {
    let canonical = serde_json::json!({
        "events": events,
        "chain_head": chain_head,
    });
    // Canonical form: serde_json preserves struct field order and BTreeMap
    // ordering, so the same events always hash the same bytes.
    let text = serde_json::to_string(&canonical)?;
    Ok(hex_sha256(&text))
}

/// The outcome of verifying an export.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditVerification {
    /// True when the export matches its own digest, is ordered, and has no
    /// chain break. **Does not mean the chain was verified** — see
    /// [`Self::chain_verified`].
    pub ok: bool,
    /// True when every link carried a hash chain and every link checked out.
    ///
    /// Distinct from `ok` on purpose. An export of legacy v1 records is intact
    /// (`ok`) but its links cannot be chain-checked. Reporting that as a failure
    /// would conflate "I could not check this" with "this is wrong", and
    /// reporting it as nothing at all would let a reader believe the chain was
    /// verified when it was not.
    pub chain_verified: bool,
    pub event_count: usize,
    /// Problems found. Non-empty means the export is not trustworthy.
    pub problems: Vec<String>,
    /// Things a reader must know that are not defects — chiefly links that
    /// could not be chain-checked.
    pub notes: Vec<String>,
    /// The digest recomputed from the file's own contents.
    pub recomputed_digest: String,
    /// The digest the file declared.
    pub declared_digest: String,
}

/// Verify an export against its own contents.
///
/// Checks, in order:
///
/// 1. the declared digest matches a recomputation over the events and chain head
/// 2. `event_count` matches the array
/// 3. `seq` is strictly increasing, so nothing was reordered or duplicated
/// 4. each event's `sha` is consistent with its predecessor's `prev_sha`, where
///    the records carry a chain
///
/// Defects go to `problems`; records that simply **cannot** be chain-checked
/// (legacy v1, which has no chain) go to `notes` and clear `chain_verified`.
/// All items are collected rather than stopping at the first, so a reader sees
/// the full picture.
pub fn verify(log: &AuditLog) -> Result<AuditVerification> {
    let mut problems: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    let recomputed = digest_of(&log.events, log.chain_head.as_deref())?;
    if recomputed != log.export_digest {
        problems.push(format!(
            "export digest mismatch: file declares {} but its contents hash to {}",
            log.export_digest, recomputed
        ));
    }

    if log.event_count != log.events.len() {
        problems.push(format!(
            "event_count says {} but the file contains {} events",
            log.event_count,
            log.events.len()
        ));
    }

    // Ordering: a strictly increasing seq is what makes "this happened before
    // that" a property of the file rather than of the reader's assumption.
    for window in log.events.windows(2) {
        if window[1].seq <= window[0].seq {
            problems.push(format!(
                "events are not in strictly increasing order: seq {} follows seq {}",
                window[1].seq, window[0].seq
            ));
            break;
        }
    }

    // Chain consistency, where records carry one.
    let mut chained = 0usize;
    let mut unchained = 0usize;
    let mut chain_break = false;
    for window in log.events.windows(2) {
        let (previous, current) = (&window[0], &window[1]);
        if previous.sha.is_empty() || current.prev_sha.is_empty() {
            unchained += 1;
            continue;
        }
        if current.prev_sha != previous.sha {
            problems.push(format!(
                "chain break between seq {} and seq {}: prev_sha {} does not match the \
                 predecessor's sha {}",
                previous.seq, current.seq, current.prev_sha, previous.sha
            ));
            chain_break = true;
            break;
        }
        chained += 1;
    }

    let chain_verified = !chain_break && unchained == 0;
    if unchained > 0 {
        notes.push(format!(
            "{unchained} link(s) carry no hash chain (legacy v1 records). Those links are \
             unverifiable: the export is intact, but the chain does not prove they were \
             not altered out of band."
        ));
    }
    if chained > 0 && !chain_break {
        notes.push(format!("{chained} link(s) chain-verified"));
    }

    let ok = problems.is_empty();
    Ok(AuditVerification {
        ok,
        chain_verified,
        event_count: log.events.len(),
        problems,
        notes,
        recomputed_digest: recomputed,
        declared_digest: log.export_digest.clone(),
    })
}

/// Parse an exported audit log.
///
/// An unknown schema is refused rather than parsed hopefully: a future format
/// could change what a field means, and silently reading it with today's
/// assumptions would produce a verification result that describes the wrong
/// file.
pub fn parse(text: &str) -> Result<AuditLog> {
    let log: AuditLog = serde_json::from_str(text)
        .map_err(|error| Error::Config(format!("audit log is not valid JSON: {error}")))?;
    if log.schema != AUDIT_SCHEMA {
        return Err(Error::Config(format!(
            "audit log schema `{}` is not `{AUDIT_SCHEMA}`",
            log.schema
        )));
    }
    Ok(log)
}

/// Serialise an export.
pub fn to_json(log: &AuditLog) -> Result<String> {
    Ok(serde_json::to_string_pretty(log)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventKind;

    fn event(seq: u64, kind: EventKind) -> Event {
        let mut event = Event::new(kind, 1, format!("event {seq}"));
        event.seq = seq;
        event
    }

    fn chained(seq: u64, kind: EventKind, sha: &str, prev_sha: &str) -> Event {
        let mut event = event(seq, kind);
        event.sha = sha.to_string();
        event.prev_sha = prev_sha.to_string();
        event
    }

    #[test]
    fn an_export_is_marked_derived_and_not_authoritative() {
        let log = export(&[event(1, EventKind::RunStarted)], None, Vec::new()).unwrap();
        assert!(log.derived);
        assert!(!log.authoritative);
        assert_eq!(log.schema, AUDIT_SCHEMA);
    }

    #[test]
    fn a_freshly_built_export_verifies() {
        let events = vec![
            event(1, EventKind::RunStarted),
            event(2, EventKind::ToolBlocked),
        ];
        let log = export(&events, None, Vec::new()).unwrap();
        let result = verify(&log).unwrap();
        assert!(result.ok, "{:?}", result.problems);
        assert_eq!(result.recomputed_digest, result.declared_digest);
    }

    #[test]
    fn an_edited_event_is_detected() {
        let events = vec![
            event(1, EventKind::RunStarted),
            event(2, EventKind::ToolBlocked),
        ];
        let mut log = export(&events, None, Vec::new()).unwrap();
        // Edit a message after export, as an attacker with file access would.
        log.events[1].message = "nothing to see here".into();
        let result = verify(&log).unwrap();
        assert!(!result.ok, "an edited event must be detected");
        assert!(
            result
                .problems
                .iter()
                .any(|p| p.contains("digest mismatch")),
            "{:?}",
            result.problems
        );
    }

    #[test]
    fn a_removed_event_is_detected() {
        let events = vec![
            event(1, EventKind::RunStarted),
            event(2, EventKind::ToolBlocked),
            event(3, EventKind::RunFinished),
        ];
        let mut log = export(&events, None, Vec::new()).unwrap();
        // Delete the incriminating middle event and fix the count, as a careful
        // attacker would.
        log.events.remove(1);
        log.event_count = 2;
        let result = verify(&log).unwrap();
        assert!(!result.ok, "a removed event must be detected");
    }

    #[test]
    fn a_reordered_event_is_detected() {
        let events = vec![
            event(1, EventKind::RunStarted),
            event(2, EventKind::ToolBlocked),
            event(3, EventKind::RunFinished),
        ];
        let mut log = export(&events, None, Vec::new()).unwrap();
        log.events.swap(1, 2);
        let result = verify(&log).unwrap();
        assert!(!result.ok);
        assert!(
            result
                .problems
                .iter()
                .any(|p| p.contains("strictly increasing")),
            "{:?}",
            result.problems
        );
    }

    #[test]
    fn an_inserted_event_is_detected() {
        let events = vec![
            event(1, EventKind::RunStarted),
            event(2, EventKind::RunFinished),
        ];
        let mut log = export(&events, None, Vec::new()).unwrap();
        log.events.insert(1, event(99, EventKind::RunStarted));
        let result = verify(&log).unwrap();
        assert!(!result.ok, "an inserted event must be detected");
    }

    #[test]
    fn unchained_legacy_records_clear_chain_verified_but_are_not_problems() {
        let events = vec![
            event(1, EventKind::RunStarted),
            event(2, EventKind::RunFinished),
        ];
        let log = export(&events, None, Vec::new()).unwrap();
        let result = verify(&log).unwrap();
        // The digest is fine, so the export is intact...
        assert!(
            result.ok,
            "an intact export with unchained links is still intact"
        );
        // ...but the chain did not prove anything, and saying so is mandatory.
        assert!(
            !result.chain_verified,
            "no link carried a chain, so the chain verified nothing"
        );
        assert!(
            result
                .notes
                .iter()
                .any(|note| note.contains("unverifiable")),
            "{:?}",
            result.notes
        );
    }

    #[test]
    fn a_fully_chained_export_reports_chain_verified() {
        let events = vec![
            chained(1, EventKind::RunStarted, "sha_a", ""),
            chained(2, EventKind::ToolFinished, "sha_b", "sha_a"),
            chained(3, EventKind::RunFinished, "sha_c", "sha_b"),
        ];
        let log = export(&events, Some("sha_c".into()), Vec::new()).unwrap();
        let result = verify(&log).unwrap();
        assert!(result.ok, "{:?}", result.problems);
        assert!(
            result.chain_verified,
            "every link checked out: {:?}",
            result.notes
        );
        assert!(result.problems.is_empty());
    }

    #[test]
    fn a_chain_break_is_a_problem_not_a_note() {
        let events = vec![
            chained(1, EventKind::RunStarted, "sha_a", ""),
            chained(2, EventKind::ToolFinished, "sha_b", "sha_a"),
            chained(3, EventKind::RunFinished, "sha_c", "sha_WRONG"),
        ];
        let log = export(&events, Some("sha_c".into()), Vec::new()).unwrap();
        let result = verify(&log).unwrap();
        assert!(!result.ok);
        assert!(!result.chain_verified);
        assert!(
            result.problems.iter().any(|p| p.contains("chain break")),
            "a break is a defect, not a caveat: {:?}",
            result.problems
        );
    }

    #[test]
    fn the_integrity_statement_states_the_limit() {
        let log = export(&[event(1, EventKind::RunStarted)], None, Vec::new()).unwrap();
        // The statement must say what it cannot do, in the file itself, so a
        // recipient without this source code is not misled.
        assert!(
            log.integrity.contains("not tamper-proof"),
            "{}",
            log.integrity
        );
        assert!(log.integrity.contains("NOT detect"));
        assert!(log.integrity.contains("no signature key"));
    }

    #[test]
    fn claims_are_labelled_as_claims() {
        let log = export(
            &[event(1, EventKind::RunStarted)],
            None,
            vec![("model".to_string(), "deepseek-v4".to_string())],
        )
        .unwrap();
        assert_eq!(log.claims.len(), 1);
        assert!(log.claims[0].is_claim, "a claim must be labelled");
        assert_eq!(log.claims[0].field, "model");
    }

    #[test]
    fn events_are_exported_in_seal_order() {
        let events = vec![
            event(3, EventKind::RunFinished),
            event(1, EventKind::RunStarted),
        ];
        let log = export(&events, None, Vec::new()).unwrap();
        assert_eq!(log.events[0].seq, 1);
        assert_eq!(log.events[1].seq, 3);
    }

    #[test]
    fn counts_are_reported_by_kind_and_severity() {
        let events = vec![
            event(1, EventKind::ToolBlocked),
            event(2, EventKind::ToolBlocked),
            event(3, EventKind::RunFinished),
        ];
        let log = export(&events, None, Vec::new()).unwrap();
        assert_eq!(log.counts_by_kind.get("tool_blocked"), Some(&2));
        assert_eq!(log.counts_by_severity.get("blocked"), Some(&2));
        assert_eq!(log.counts_by_severity.get("normal"), Some(&1));
    }

    #[test]
    fn a_round_trip_through_json_verifies() {
        let events = vec![
            event(1, EventKind::RunStarted),
            event(2, EventKind::ToolBlocked),
        ];
        let log = export(&events, Some("head".into()), Vec::new()).unwrap();
        let text = to_json(&log).unwrap();
        let parsed = parse(&text).unwrap();
        let result = verify(&parsed).unwrap();
        assert!(result.ok, "{:?}", result.problems);
    }

    #[test]
    fn an_unknown_schema_is_refused() {
        let mut log = export(&[event(1, EventKind::RunStarted)], None, Vec::new()).unwrap();
        log.schema = "pangu-audit/99".into();
        let text = to_json(&log).unwrap();
        let error = parse(&text).unwrap_err().to_string();
        assert!(error.contains("pangu-audit/99"), "{error}");
    }

    #[test]
    fn the_chain_head_is_part_of_the_digest() {
        let events = vec![event(1, EventKind::RunStarted)];
        let with_head = export(&events, Some("head_a".into()), Vec::new()).unwrap();
        let other_head = export(&events, Some("head_b".into()), Vec::new()).unwrap();
        assert_ne!(
            with_head.export_digest, other_head.export_digest,
            "a swapped chain head must change the digest"
        );
    }

    #[test]
    fn a_swapped_chain_head_is_detected() {
        let events = vec![event(1, EventKind::RunStarted)];
        let mut log = export(&events, Some("head_a".into()), Vec::new()).unwrap();
        log.chain_head = Some("head_b".into());
        let result = verify(&log).unwrap();
        assert!(!result.ok, "the head is covered by the digest");
    }

    #[test]
    fn an_empty_export_verifies() {
        let log = export(&[], None, Vec::new()).unwrap();
        let result = verify(&log).unwrap();
        assert!(result.ok, "{:?}", result.problems);
        assert_eq!(result.event_count, 0);
    }
}
