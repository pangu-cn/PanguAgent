use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::events::{
    redact_event, Event, EventKind, EventSink, JOURNAL_FORMAT_V1, JOURNAL_FORMAT_V2,
};
use crate::{Error, Result};

pub const GENESIS: &str = "GENESIS";
pub const MAX_JOURNAL_EVENT_LINE_BYTES: usize = 1024 * 1024;

pub struct Journal {
    path: PathBuf,
    state: Mutex<State>,
}

struct State {
    seq: u64,
    prev_sha: String,
    format: String,
    file: BufWriter<std::fs::File>,
    bytes: u64,
}

impl Journal {
    /// Create a new journal. Existing paths are rejected; use
    /// [`Journal::append_to`] when continuing an existing chain.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        Self::open(path.as_ref(), true, JOURNAL_FORMAT_V1)
    }

    /// Create a new v2 journal. v1 remains the default for existing callers.
    pub fn create_v2(path: impl AsRef<Path>) -> Result<Self> {
        Self::open(path.as_ref(), true, JOURNAL_FORMAT_V2)
    }

    /// Append to a valid existing journal. A damaged journal is an error; it
    /// must never be silently restarted with a new chain.
    pub fn append_to(path: impl AsRef<Path>) -> Result<Self> {
        Self::open(path.as_ref(), false, JOURNAL_FORMAT_V1)
    }

    /// Append to an existing v2 journal without changing its schema.
    pub fn append_to_v2(path: impl AsRef<Path>) -> Result<Self> {
        Self::open(path.as_ref(), false, JOURNAL_FORMAT_V2)
    }

    fn open(path: &Path, truncate: bool, format: &str) -> Result<Self> {
        reject_symlink_components(path)?;
        if truncate && path.exists() {
            return Err(Error::Config(format!(
                "journal already exists; use append_to: {}",
                path.display()
            )));
        }
        if !truncate && !path.exists() {
            return Err(Error::Config(format!(
                "journal does not exist; use create: {}",
                path.display()
            )));
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
                reject_symlink_components(parent)?;
            }
        }
        reject_symlink_components(path)?;

        let (seq, prev_sha) = if truncate {
            (0, GENESIS.to_string())
        } else if path.exists() {
            let events = crate::replay::read(path)?;
            let existing_format = events
                .first()
                .and_then(|event| event.schema.as_deref())
                .unwrap_or(JOURNAL_FORMAT_V1);
            if existing_format != format {
                return Err(Error::Config(format!(
                    "journal format mismatch: expected {format}, found {existing_format}"
                )));
            }
            let Some(last) = events.last() else {
                return Err(Error::Config(format!(
                    "journal exists but has no events; use create: {}",
                    path.display()
                )));
            };
            (
                last.seq
                    .checked_add(1)
                    .ok_or_else(|| Error::Other("journal sequence counter overflowed".into()))?,
                last.sha.clone(),
            )
        } else {
            (0, GENESIS.to_string())
        };

        let mut options = std::fs::OpenOptions::new();
        options
            .create(true)
            .truncate(truncate)
            .append(!truncate)
            .write(truncate);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        let bytes = if truncate {
            0
        } else {
            std::fs::metadata(path)?.len()
        };
        Ok(Self {
            path: path.to_path_buf(),
            state: Mutex::new(State {
                seq,
                prev_sha,
                format: format.to_string(),
                file: BufWriter::new(file),
                bytes,
            }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Seal and write one event while holding the journal lock for the entire
    /// operation. State advances only after the complete line is flushed.
    pub fn record(&self, event: &Event) -> Result<Event> {
        let mut state = self.state.lock().expect("journal lock");
        if state.seq == u64::MAX {
            return Err(Error::Other("journal sequence counter is exhausted".into()));
        }
        if state.format == JOURNAL_FORMAT_V1 && event.kind.is_v2_only() {
            return Err(Error::Config(
                "v2-only event cannot be written to a pangu-journal/v1 file".into(),
            ));
        }
        if let Some(schema) = event.schema.as_deref() {
            if schema != state.format {
                return Err(Error::Config(format!(
                    "event schema {schema} does not match journal format {}",
                    state.format
                )));
            }
        }
        let mut sealed = redact_event(event.clone());
        // v1 must remain byte-for-byte compatible with the original event
        // shape. v2 receives both an explicit schema marker and a stable ID;
        // the ID is derived from the sealed position and event content before
        // the final content hash is computed.
        sealed.event_id = None;
        if state.format == JOURNAL_FORMAT_V1 {
            // Do not silently extend the legacy on-disk shape. In-memory
            // sinks may still expose the richer event, but a v1 Journal keeps
            // the original fields and hash representation.
            sealed.effect_scope = None;
            sealed.reversibility = None;
            sealed.action_digest = None;
            sealed.external_mutation = None;
        }
        sealed.schema = (state.format == JOURNAL_FORMAT_V2).then(|| JOURNAL_FORMAT_V2.to_string());
        sealed.validate_shape()?;
        if state.format == JOURNAL_FORMAT_V2 {
            crate::replay::validate_v2_metadata(&sealed)?;
        }
        sealed.seq = state.seq;
        sealed.prev_sha = state.prev_sha.clone();
        if state.format == JOURNAL_FORMAT_V2 {
            let identity = format!("event-id:{}:{}", state.seq, sealed.canonical());
            sealed.event_id = Some(format!(
                "evt_{}",
                Event::compute_sha(&state.prev_sha, &identity)
            ));
        }
        sealed.sha = Event::compute_sha(&sealed.prev_sha, &sealed.canonical());
        if state.format == JOURNAL_FORMAT_V2 {
            sealed.validate_v2_receipt()?;
        }
        let line = serde_json::to_string(&sealed)?;
        if line.len() > MAX_JOURNAL_EVENT_LINE_BYTES {
            return Err(Error::Other(format!(
                "journal event exceeds {} bytes",
                MAX_JOURNAL_EVENT_LINE_BYTES
            )));
        }
        let line_bytes = (line.len() as u64)
            .checked_add(1)
            .ok_or_else(|| Error::Other("journal event size overflowed".into()))?;
        let next_bytes = state
            .bytes
            .checked_add(line_bytes)
            .ok_or_else(|| Error::Other("journal size overflowed".into()))?;
        if next_bytes > crate::replay::MAX_JOURNAL_BYTES {
            return Err(Error::Other("journal exceeds the size limit".into()));
        }
        write_line(&mut state.file, &line)?;
        state.bytes = next_bytes;
        state.seq = state.seq.saturating_add(1);
        state.prev_sha = sealed.sha.clone();
        Ok(sealed)
    }

    pub fn verify(&self) -> Result<Vec<Event>> {
        crate::replay::read(&self.path)
    }
}

pub(crate) fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut current = path.to_path_buf();
    loop {
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::Config(format!(
                    "journal path must not contain symlink components: {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Io(error)),
        }
        if !current.pop() {
            break;
        }
    }
    Ok(())
}

fn write_line(writer: &mut BufWriter<std::fs::File>, line: &str) -> Result<()> {
    let mut bytes = Vec::with_capacity(line.len() + 1);
    bytes.extend_from_slice(line.as_bytes());
    bytes.push(b'\n');
    writer.write_all(&bytes)?;
    writer.flush()?;
    writer.get_ref().sync_data()?;
    Ok(())
}

#[async_trait::async_trait]
impl EventSink for Journal {
    async fn emit(&self, event: Event) -> Result<()> {
        self.record(&event).map(|_| ())
    }

    async fn emit_with_receipt(&self, event: Event) -> Result<Event> {
        self.record(&event)
    }
}

pub struct ConsoleSink {
    enabled: bool,
    verbose: bool,
}

impl ConsoleSink {
    pub fn new(enabled: bool, verbose: bool) -> Self {
        Self { enabled, verbose }
    }

    pub fn render(&self, event: &Event) -> String {
        let event = redact_event(event.clone());
        let tag = match event.kind {
            EventKind::RunStarted => "◆ run",
            EventKind::TurnStarted => "· turn",
            EventKind::ModelRequest => "→ llm ",
            EventKind::ModelResponse => "← llm ",
            EventKind::ToolRequested => "◇ ask ",
            EventKind::PolicyDecision => "§ gate",
            EventKind::ApprovalRequested | EventKind::ApprovalResolved => "⚑ human",
            EventKind::ToolStarted => "  … ",
            EventKind::ToolBlocked => "  × ",
            EventKind::ToolFinished => "  ✓ ",
            EventKind::BudgetExhausted => "⛔ budget",
            EventKind::FinishRequested => "✳ finish",
            EventKind::RunFinished => "◆ done",
            EventKind::Note => "# ",
            EventKind::CheckpointCreated => "◈ checkpoint",
            EventKind::CheckpointFailed => "× checkpoint",
            EventKind::RollbackRequested => "↶ rollback",
            EventKind::RollbackStarted => "  … ",
            EventKind::RollbackApplied => "  ✓ ",
            EventKind::RollbackSkippedAlreadyApplied => "  ↷ ",
            EventKind::RollbackFailed => "  × ",
            EventKind::FailedPathRecorded => "  ! ",
        };
        let mut output = format!("{tag} ");
        if let Some(tool) = &event.tool {
            output.push_str(tool);
            if let Some(verdict) = &event.verdict {
                output.push_str(&format!(" [{verdict}]"));
            }
            output.push_str(": ");
        } else {
            output.push_str("· ");
        }
        let body = if self.verbose {
            event.message
        } else {
            crate::util::one_line(&event.message, 160)
        };
        output.push_str(&body);
        if let Some(duration) = event.duration_ms {
            output.push_str(&format!(" ({duration}ms)"));
        }
        output
    }
}

#[async_trait::async_trait]
impl EventSink for ConsoleSink {
    async fn emit(&self, event: Event) -> Result<()> {
        if self.enabled {
            let mut stderr = std::io::stderr().lock();
            writeln!(stderr, "{}", self.render(&event))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_round_trip_and_tamper_detection() {
        let path = std::env::temp_dir().join(format!(
            "pangu-journal-test-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let journal = Journal::create(&path).unwrap();
        journal
            .record(&Event::new(EventKind::RunStarted, 0, "start"))
            .unwrap();
        journal
            .record(&Event::new(EventKind::RunFinished, 1, "done"))
            .unwrap();
        let events = journal.verify().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].prev_sha, events[0].sha);

        let mut source = std::fs::read_to_string(&path).unwrap();
        source = source.replacen("start", "tampered", 1);
        std::fs::write(&path, source).unwrap();
        assert!(crate::replay::read(&path).is_err());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn journal_v2_records_schema_and_stable_event_ids() {
        let path = std::env::temp_dir().join(format!(
            "pangu-journal-v2-test-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let journal = Journal::create_v2(&path).unwrap();
        let sealed = journal
            .record(&Event::new_v2(
                EventKind::CheckpointCreated,
                0,
                "checkpoint",
            ))
            .unwrap();
        assert_eq!(sealed.schema.as_deref(), Some(JOURNAL_FORMAT_V2));
        assert!(sealed
            .event_id
            .as_deref()
            .is_some_and(|id| id.starts_with("evt_")));
        let mut malformed = Event::new_v2(EventKind::ToolFinished, 1, "bad metadata");
        malformed.effect_scope = Some("workspace".into());
        assert!(journal.record(&malformed).is_err());

        let events = journal.verify().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, sealed.event_id);
        let mut tampered_id = events[0].clone();
        tampered_id.event_id = Some(format!("evt_{}", "0".repeat(64)));
        tampered_id.sha = Event::compute_sha(&tampered_id.prev_sha, &tampered_id.canonical());
        assert!(crate::replay::verify(&[tampered_id]).is_err());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn journal_v1_rejects_v2_only_events_and_format_mismatch() {
        let path = std::env::temp_dir().join(format!(
            "pangu-journal-v1-schema-test-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let journal = Journal::create(&path).unwrap();
        journal
            .record(&Event::new(EventKind::RunStarted, 0, "start"))
            .unwrap();
        assert!(journal
            .record(&Event::new_v2(EventKind::RollbackRequested, 0, "rollback"))
            .is_err());
        drop(journal);
        assert!(Journal::append_to_v2(&path).is_err());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn journal_append_requires_an_existing_chain() {
        let path = std::env::temp_dir().join(format!(
            "pangu-journal-missing-test-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(Journal::append_to(&path).is_err());
        std::fs::remove_file(path).ok();

        let empty_path = std::env::temp_dir().join(format!(
            "pangu-journal-empty-test-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&empty_path, "").unwrap();
        assert!(Journal::append_to(&empty_path).is_err());
        std::fs::remove_file(empty_path).ok();
    }

    #[test]
    fn journal_create_reports_unwritable_destination() {
        let directory = std::env::temp_dir().join(format!(
            "pangu-journal-directory-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        assert!(Journal::create(&directory).is_err());
        std::fs::remove_dir_all(directory).ok();
    }
}
