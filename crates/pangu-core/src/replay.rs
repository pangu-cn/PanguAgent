use std::path::Path;

use crate::events::{Event, EventKind};
use crate::journal::{reject_symlink_components, GENESIS, MAX_JOURNAL_EVENT_LINE_BYTES};
use crate::{Error, Result};

const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
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
    let metadata = match std::fs::metadata(path) {
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
    let data = match std::fs::read_to_string(path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(Error::Io(error)),
        Err(error) => return Err(Error::Io(error)),
    };
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
    for event in events {
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
