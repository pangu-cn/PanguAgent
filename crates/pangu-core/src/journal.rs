use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::events::{redact_event, Event, EventKind, EventSink};
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
    file: BufWriter<std::fs::File>,
}

impl Journal {
    /// Create a new journal. Existing paths are rejected; use
    /// [`Journal::append_to`] when continuing an existing chain.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        Self::open(path.as_ref(), true)
    }

    /// Append to a valid existing journal. A damaged journal is an error; it
    /// must never be silently restarted with a new chain.
    pub fn append_to(path: impl AsRef<Path>) -> Result<Self> {
        Self::open(path.as_ref(), false)
    }

    fn open(path: &Path, truncate: bool) -> Result<Self> {
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
            }
        }

        let (seq, prev_sha) = if truncate {
            (0, GENESIS.to_string())
        } else if path.exists() {
            let events = crate::replay::read(path)?;
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
        Ok(Self {
            path: path.to_path_buf(),
            state: Mutex::new(State {
                seq,
                prev_sha,
                file: BufWriter::new(file),
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
        let mut sealed = redact_event(event.clone());
        sealed.seq = state.seq;
        sealed.prev_sha = state.prev_sha.clone();
        sealed.sha = Event::compute_sha(&sealed.prev_sha, &sealed.canonical());
        let line = serde_json::to_string(&sealed)?;
        if line.len() > MAX_JOURNAL_EVENT_LINE_BYTES {
            return Err(Error::Other(format!(
                "journal event exceeds {} bytes",
                MAX_JOURNAL_EVENT_LINE_BYTES
            )));
        }
        write_line(&mut state.file, &line)?;
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
