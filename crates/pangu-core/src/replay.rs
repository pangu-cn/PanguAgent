use std::io::Read;
use std::path::Path;

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
}
