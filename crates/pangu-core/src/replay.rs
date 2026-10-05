use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::events::{Event, EventKind, JOURNAL_FORMAT_V1, JOURNAL_FORMAT_V2};
use crate::journal::{reject_symlink_components, GENESIS, MAX_JOURNAL_EVENT_LINE_BYTES};
use crate::{Error, Result};

pub const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_JOURNAL_EVENTS: usize = 1_000_000;

/// Read a journal without validating it. Malformed records are returned as a
/// damage report; callers that require integrity use `read`.
pub fn read_raw(path: &Path) -> Result<(Vec<Event>, Option<String>)> {
    reject_symlink_components(path)?;
    let link_metadata = std::fs::symlink_metadata(path)?;
    if link_metadata.file_type().is_symlink() {
        return Err(Error::Config(format!(
            "journal path must not be a symlink: {}",
            path.display()
        )));
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(Error::Config(format!(
                "journal path must not be a symlink: {}",
                path.display()
            )))
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(Error::Config("journal path must be a regular file".into()))
        }
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(Error::Io(error)),
        Err(error) => return Err(Error::Io(error)),
    };
    if metadata.len() > MAX_JOURNAL_BYTES {
        return Err(Error::Other(format!(
            "journal {} exceeds {} bytes",
            path.display(),
            MAX_JOURNAL_BYTES
        )));
    }
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_JOURNAL_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(Error::Other(format!(
            "journal {} exceeds {} bytes",
            path.display(),
            MAX_JOURNAL_BYTES
        )));
    }
    reject_symlink_components(path)?;
    let metadata_after_read = std::fs::symlink_metadata(path)?;
    if metadata_after_read.file_type().is_symlink() || !metadata_after_read.is_file() {
        return Err(Error::Config(
            "journal path changed while being read".into(),
        ));
    }
    let data = String::from_utf8(bytes).map_err(|error| {
        Error::Other(format!("journal {} is not UTF-8: {error}", path.display()))
    })?;
    let mut events = Vec::new();
    let mut tail_problem = None;
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_JOURNAL_EVENT_LINE_BYTES {
            return Err(Error::Other(format!(
                "journal event line exceeds {} bytes",
                MAX_JOURNAL_EVENT_LINE_BYTES
            )));
        }
        match serde_json::from_str::<Event>(line) {
            Ok(event) => {
                event.validate_shape()?;
                validate_event_schema(&event)?;
                if events.len() >= MAX_JOURNAL_EVENTS {
                    return Err(Error::Other(format!(
                        "journal {} exceeds {} events",
                        path.display(),
                        MAX_JOURNAL_EVENTS
                    )));
                }
                events.push(event)
            }
            Err(error) => tail_problem = Some(format!("unparseable line: {error}")),
        }
    }
    Ok((events, tail_problem))
}

pub fn read(path: &Path) -> Result<Vec<Event>> {
    let (events, problem) = read_raw(path)?;
    if let Some(problem) = problem {
        return Err(Error::Other(format!(
            "journal {} is damaged: {problem}",
            path.display()
        )));
    }
    verify(&events).map_err(|reason| {
        Error::Other(format!(
            "journal {} failed verification: {reason}",
            path.display()
        ))
    })?;
    Ok(events)
}

/// The verified facts about a journal's hash chain.
///
/// This is deliberately a *result of a check*, not a claim. It exists so a
/// caller can print "the chain that was recomputed here is intact" instead of
/// echoing a `sha` field it merely read back — those two statements look
/// identical in output and mean different things.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalIntegrity {
    /// Always true: this value only exists after `verify` recomputed the chain.
    pub verified: bool,
    /// The chain is only as long as the events that were checked.
    pub events_verified: usize,
    /// The `sha` of the last verified event; empty for an empty journal.
    pub head_sha: String,
    /// The journal format marker observed on the records (`pangu-journal/v1`
    /// or `/v2`), or `None` when there were no events to judge.
    pub journal_format: Option<String>,
}

/// Read a journal and report what verification actually established.
///
/// Use this when the caller must be able to say the chain was recomputed. It
/// is stricter than [`read_raw`] (which tolerates a corrupt tail and returns a
/// damage report) and reports the recomputed state that [`read`] discards.
pub fn verify_journal(path: &Path) -> Result<(Vec<Event>, JournalIntegrity)> {
    let events = read(path)?;
    let integrity = JournalIntegrity {
        verified: true,
        events_verified: events.len(),
        head_sha: events
            .last()
            .map(|event| event.sha.clone())
            .unwrap_or_default(),
        journal_format: journal_format(&events)?.map(str::to_string),
    };
    Ok((events, integrity))
}

/// The journal format marker shared by every event, or `None` when empty.
///
/// Mixed formats are impossible here: [`verify`] already refuses them, so this
/// only has to report what verification established.
pub fn journal_format(events: &[Event]) -> Result<Option<&str>> {
    let mut format = None;
    for event in events {
        let event_format = validate_event_schema(event)?;
        match format {
            None => format = Some(event_format),
            Some(seen) if seen == event_format => {}
            Some(_) => {
                return Err(Error::Other(
                    "journal contains mixed v1/v2 event schemas".into(),
                ))
            }
        }
    }
    Ok(format)
}

pub fn verify(events: &[Event]) -> Result<()> {
    let mut previous = GENESIS.to_string();
    let mut expected_seq = 0u64;
    let mut journal_format: Option<&str> = None;
    for event in events {
        event.validate_shape()?;
        let event_format = validate_event_schema(event)?;
        if journal_format.is_none() {
            journal_format = Some(event_format);
        } else if journal_format != Some(event_format) {
            return Err(Error::Other(
                "journal contains mixed v1/v2 event schemas".into(),
            ));
        }
        if event.kind.is_v2_only() && event_format != JOURNAL_FORMAT_V2 {
            return Err(Error::Other(
                "v2-only event found in a pangu-journal/v1 stream".into(),
            ));
        }
        if event_format == JOURNAL_FORMAT_V1
            && (event.event_id.is_some()
                || event.effect_scope.is_some()
                || event.reversibility.is_some()
                || event.action_digest.is_some()
                || event.external_mutation.is_some())
        {
            return Err(Error::Other(
                "v2 event fields found in a pangu-journal/v1 stream".into(),
            ));
        }
        if event_format == JOURNAL_FORMAT_V2 {
            validate_v2_metadata(event)?;
            if !event.event_id.as_deref().is_some_and(|id| {
                id.strip_prefix("evt_").is_some_and(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            }) {
                return Err(Error::Other(
                    "v2 event is missing a valid stable event_id".into(),
                ));
            }
            let mut identity_event = event.clone();
            identity_event.event_id = None;
            let identity = format!("event-id:{}:{}", event.seq, identity_event.canonical());
            let expected_event_id =
                format!("evt_{}", Event::compute_sha(&event.prev_sha, &identity));
            if event.event_id.as_deref() != Some(expected_event_id.as_str()) {
                return Err(Error::Other(format!(
                    "v2 event_id mismatch at seq {}",
                    event.seq
                )));
            }
        }
        if event.seq != expected_seq {
            return Err(Error::Other(format!(
                "seq gap at {}: expected {expected_seq}, got {}",
                event.at, event.seq
            )));
        }
        if event.prev_sha != previous {
            return Err(Error::Other(format!(
                "chain broken at seq {}: prev_sha mismatch",
                event.seq
            )));
        }
        let recomputed = Event::compute_sha(&event.prev_sha, &event.canonical());
        if recomputed != event.sha {
            return Err(Error::Other(format!(
                "tamper detected at seq {} (sha mismatch)",
                event.seq
            )));
        }
        previous = event.sha.clone();
        expected_seq = expected_seq
            .checked_add(1)
            .ok_or_else(|| Error::Other("journal sequence counter overflowed".into()))?;
    }
    Ok(())
}

fn validate_event_schema(event: &Event) -> Result<&str> {
    match event.schema.as_deref() {
        None => Ok(JOURNAL_FORMAT_V1),
        Some(JOURNAL_FORMAT_V1) | Some(JOURNAL_FORMAT_V2) => Ok(event.schema.as_deref().unwrap()),
        Some(other) => Err(Error::Other(format!(
            "unsupported journal event schema `{other}`"
        ))),
    }
}

pub(crate) fn validate_v2_metadata(event: &Event) -> Result<()> {
    let has_effect_metadata = event.effect_scope.is_some()
        || event.reversibility.is_some()
        || event.action_digest.is_some()
        || event.external_mutation.is_some();
    if !has_effect_metadata {
        return Ok(());
    }
    if event.effect_scope.is_none()
        || event.reversibility.is_none()
        || event.action_digest.is_none()
        || event.external_mutation.is_none()
    {
        return Err(Error::Other(
            "v2 effect metadata must be emitted as a complete set".into(),
        ));
    }
    let scope = event.effect_scope.as_deref().unwrap_or_default();
    let reversibility = event.reversibility.as_deref().unwrap_or_default();
    if !matches!(
        scope,
        "workspace" | "session" | "process_read" | "external_read" | "external_mutation"
    ) || !matches!(reversibility, "no_effect" | "reversible" | "irreversible")
    {
        return Err(Error::Other(
            "v2 event contains an unknown effect scope or reversibility".into(),
        ));
    }
    let digest = event.action_digest.as_deref().unwrap_or_default();
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Other(
            "v2 event contains an invalid action digest".into(),
        ));
    }
    let external_mutation = event.external_mutation.unwrap_or(false);
    if external_mutation && (scope != "external_mutation" || reversibility != "irreversible") {
        return Err(Error::Other(
            "v2 external mutation metadata is inconsistent".into(),
        ));
    }
    if scope == "external_mutation" && !external_mutation {
        return Err(Error::Other(
            "v2 external mutation scope must set external_mutation=true".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub turns: u32,
    pub model_calls: u32,
    pub tool_calls: u32,
    pub tools_ok: u32,
    pub tools_failed: u32,
    pub tools_blocked: u32,
    pub denials: u32,
    pub approvals_asked: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub wall_ms: u64,
    pub outcome: Option<String>,
    pub evidence: Vec<String>,
    pub goal: Option<String>,
    pub model: Option<String>,
    pub unattended: bool,
}

impl Summary {
    pub fn from_events(events: &[Event]) -> Self {
        let mut summary = Self::default();
        for event in events {
            summary.turns = summary.turns.max(event.turn);
            match event.kind {
                EventKind::RunStarted => {
                    if let Some(payload) = &event.payload {
                        summary.goal = payload
                            .get("goal")
                            .and_then(Value::as_str)
                            .map(str::to_string);
                        summary.model = payload
                            .get("model")
                            .and_then(Value::as_str)
                            .map(str::to_string);
                        summary.unattended = payload
                            .get("unattended")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                    }
                }
                EventKind::ModelRequest => {
                    summary.model_calls = summary.model_calls.saturating_add(1)
                }
                EventKind::ToolRequested => {
                    summary.tool_calls = summary.tool_calls.saturating_add(1)
                }
                EventKind::ToolBlocked => {
                    summary.tools_blocked = summary.tools_blocked.saturating_add(1);
                }
                EventKind::ToolFinished => {
                    let ok = event
                        .payload
                        .as_ref()
                        .and_then(|p| p.get("ok"))
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if ok {
                        summary.tools_ok = summary.tools_ok.saturating_add(1);
                        if let Some(evidence) = event
                            .payload
                            .as_ref()
                            .and_then(|p| p.get("evidence"))
                            .and_then(Value::as_str)
                        {
                            summary.evidence.push(evidence.to_string());
                        }
                    } else {
                        summary.tools_failed = summary.tools_failed.saturating_add(1);
                    }
                    if let Some(duration) = event.duration_ms {
                        summary.wall_ms = summary.wall_ms.saturating_add(duration);
                    }
                }
                EventKind::PolicyDecision => {
                    if event.verdict.as_deref() == Some("deny") {
                        summary.denials = summary.denials.saturating_add(1);
                    }
                }
                EventKind::ApprovalRequested => {
                    summary.approvals_asked = summary.approvals_asked.saturating_add(1)
                }
                EventKind::ModelResponse => {
                    if let Some(usage) = event.usage {
                        summary.input_tokens =
                            summary.input_tokens.saturating_add(usage.input_tokens);
                        summary.output_tokens =
                            summary.output_tokens.saturating_add(usage.output_tokens);
                    }
                }
                EventKind::RunFinished => {
                    summary.outcome = event
                        .payload
                        .as_ref()
                        .and_then(|p| p.get("status"))
                        .and_then(Value::as_str)
                        .map(str::to_string);
                }
                _ => {}
            }
        }
        summary
    }

    pub fn evidence_actions(&self) -> usize {
        self.evidence.len()
    }
}

use crate::Value;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventKind as EK;
    use crate::journal::GENESIS;
    use crate::Usage;

    fn chain() -> Vec<Event> {
        let mut previous = GENESIS.to_string();
        let mut events = Vec::new();
        for (index, kind) in [EK::RunStarted, EK::ToolRequested, EK::RunFinished]
            .iter()
            .enumerate()
        {
            let mut event = Event::new(*kind, index as u32, format!("e{index}"));
            event.seq = index as u64;
            event.prev_sha = previous.clone();
            event.sha = Event::compute_sha(&previous, &event.canonical());
            previous = event.sha.clone();
            events.push(event);
        }
        events
    }

    #[test]
    fn good_chain_verifies() {
        assert!(verify(&chain()).is_ok());
    }

    #[test]
    fn editing_and_dropping_are_detected() {
        let mut edited = chain();
        edited[1].message = "rewritten".into();
        assert!(verify(&edited).is_err());
        let mut dropped = chain();
        dropped.remove(1);
        assert!(verify(&dropped).is_err());
    }

    #[test]
    fn summary_requires_explicit_success_payload() {
        let mut events = chain();
        let mut finished =
            Event::new(EK::ToolFinished, 1, "done").payload(serde_json::json!({"ok": true}));
        finished.usage = Some(Usage {
            input_tokens: 3,
            ..Default::default()
        });
        finished.seq = events.len() as u64;
        finished.prev_sha = events.last().unwrap().sha.clone();
        finished.sha = Event::compute_sha(&finished.prev_sha, &finished.canonical());
        events.push(finished);
        assert_eq!(Summary::from_events(&events).tools_ok, 1);
    }

    fn temp_journal(name: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir();
        let base = std::fs::canonicalize(&base).unwrap_or(base);
        base.join(format!(
            "pangu-replay-{name}-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    /// `verify_journal` must report the state it recomputed, not the state the
    /// file claimed. The head digest is the one fact a caller cannot get from
    /// a plain read, because a plain read only echoes what was stored.
    #[test]
    fn verify_journal_reports_the_recomputed_head_and_format() {
        let path = temp_journal("head");
        let journal = crate::Journal::create_v2(&path).expect("create");
        let mut last = String::new();
        for index in 0..3 {
            last = journal
                .record(&Event::new(EK::TurnStarted, index, format!("t{index}")))
                .expect("record")
                .sha;
        }
        drop(journal);

        let (events, integrity) = verify_journal(&path).expect("verify");
        assert_eq!(events.len(), 3);
        assert!(integrity.verified);
        assert_eq!(integrity.events_verified, 3);
        assert_eq!(integrity.head_sha, last);
        assert_eq!(integrity.journal_format.as_deref(), Some(JOURNAL_FORMAT_V2));
        std::fs::remove_file(path).ok();
    }

    /// A rewritten digest is well-formed — same length, still hex — so echoing
    /// it back cannot distinguish it from a real one. Only recomputation can.
    #[test]
    fn verify_journal_refuses_a_well_formed_but_wrong_digest() {
        let path = temp_journal("wrong-digest");
        let journal = crate::Journal::create_v2(&path).expect("create");
        for index in 0..3 {
            journal
                .record(&Event::new(EK::TurnStarted, index, format!("t{index}")))
                .expect("record");
        }
        drop(journal);

        let raw = std::fs::read_to_string(&path).expect("read");
        let zeros = "0".repeat(64);
        let rewritten: Vec<String> = raw
            .lines()
            .enumerate()
            .map(|(index, line)| {
                if index == 1 {
                    let start = line.rfind("\"sha\":\"").expect("sha field");
                    let mut line = line.to_string();
                    line.replace_range(start + 7..start + 71, &zeros);
                    line
                } else {
                    line.to_string()
                }
            })
            .collect();
        std::fs::write(&path, format!("{}\n", rewritten.join("\n"))).expect("write");

        let error = verify_journal(&path).expect_err("a rewritten digest must be caught");
        assert!(
            error.to_string().contains("tamper detected"),
            "expected a tamper report, got: {error}"
        );
        std::fs::remove_file(path).ok();
    }

    /// An empty journal has nothing to contradict, so it verifies — but it must
    /// not report a head digest it never computed.
    #[test]
    fn verify_journal_of_an_empty_file_reports_no_head() {
        let path = temp_journal("empty");
        std::fs::write(&path, "").expect("write empty");

        let (events, integrity) = verify_journal(&path).expect("verify empty");
        assert!(events.is_empty());
        assert!(integrity.verified);
        assert_eq!(integrity.events_verified, 0);
        assert!(integrity.head_sha.is_empty());
        assert!(integrity.journal_format.is_none());
        std::fs::remove_file(path).ok();
    }
}
