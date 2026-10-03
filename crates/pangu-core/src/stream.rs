//! A stable, versioned NDJSON event stream for external consumers.
//!
//! This is deliberately **not** the Journal. The Journal is an internal,
//! hash-chained audit record whose shape changes as the implementation does.
//! This stream is a derived, versioned projection with a closed field set, so
//! an outside tool can consume it without binding itself to our internals.
//!
//! Three rules govern everything here:
//!
//! 1. **Derived, not authoritative.** The stream carries no hash chain of its
//!    own, so it cannot prove anything. It points back at the journal event it
//!    came from via [`StreamEvent::origin`].
//! 2. **One way.** Events flow from the journal outward. Nothing reads a stream
//!    to make a decision, so a stream can never authorize an action.
//! 3. **Fail closed.** An unknown schema, a future schema, or a corrupt line
//!    is an error. The stream is never truncated quietly.

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::events::{
    redact_event, Event, EventKind, EventSink, JOURNAL_FORMAT_V1, JOURNAL_FORMAT_V2,
};
use crate::{Error, Result};

/// The current event-stream contract version.
pub const STREAM_SCHEMA_V1: &str = "pangu-stream/1";

/// Every contract version this build can read, oldest first.
///
/// A version absent from this list is refused rather than guessed at, which is
/// what makes forward compatibility safe: a stream written by a newer Pangu is
/// rejected outright instead of being partially understood.
pub const SUPPORTED_STREAM_SCHEMAS: &[&str] = &[STREAM_SCHEMA_V1];

/// The journal formats the migrator accepts as legacy input.
const MIGRATABLE_JOURNAL_SCHEMAS: &[&str] = &[JOURNAL_FORMAT_V1, JOURNAL_FORMAT_V2];

/// Bound on one serialized stream record.
///
/// Smaller than the journal's limit on purpose: a stream record is meant to be
/// read by something that is not us.
pub const MAX_STREAM_LINE_BYTES: usize = 64 * 1024;

/// Bound on a whole stream file, matching the journal ceiling.
pub const MAX_STREAM_BYTES: u64 = 64 * 1024 * 1024;

/// Bound on how many records a single read will return.
pub const MAX_STREAM_RECORDS: usize = 1_000_000;

/// Whether a kind is part of the compatibility promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stability {
    /// Frozen. Present in every `pangu-stream/1`, and will keep its meaning.
    Stable,
    /// Present, but the shape or the set may still change. F7's
    /// checkpoint/rollback events sit here while that feature is still behind
    /// an experimental opt-in; promising compatibility now would be promising
    /// something about behavior that has not settled.
    Provisional,
}

impl Stability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Provisional => "provisional",
        }
    }
}

/// The kinds that appear in the public contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    RunStarted,
    TurnStarted,
    ModelRequest,
    ModelResponse,
    ToolRequested,
    PolicyDecision,
    ApprovalRequested,
    ApprovalResolved,
    ToolStarted,
    ToolBlocked,
    ToolFinished,
    BudgetExhausted,
    FinishRequested,
    RunFinished,
    Note,
    CheckpointCreated,
    CheckpointFailed,
    RollbackRequested,
    RollbackStarted,
    RollbackApplied,
    RollbackSkippedAlreadyApplied,
    RollbackFailed,
    FailedPathRecorded,
    ContextAssembled,
    /// F4: plan -> act phase transition (the `begin_act` control call).
    PhaseChanged,
    /// B5: switch to a declared fallback provider after a failure.
    ProviderSwitched,
    /// B3: a memory candidate was proposed (digest only, never content).
    MemoryProposed,
}

impl StreamKind {
    /// How much of a promise this kind carries.
    pub fn stability(self) -> Stability {
        match self {
            // The run lifecycle is the part an outside tool builds a UI on.
            Self::RunStarted
            | Self::TurnStarted
            | Self::ModelRequest
            | Self::ModelResponse
            | Self::ToolRequested
            | Self::PolicyDecision
            | Self::ApprovalRequested
            | Self::ApprovalResolved
            | Self::ToolStarted
            | Self::ToolBlocked
            | Self::ToolFinished
            | Self::BudgetExhausted
            | Self::FinishRequested
            | Self::RunFinished
            | Self::Note => Stability::Stable,
            // F7 is still experimental and default-off.
            _ => Stability::Provisional,
        }
    }

    /// Every kind in the contract, in emission order.
    pub fn all() -> &'static [Self] {
        &[
            Self::RunStarted,
            Self::TurnStarted,
            Self::ModelRequest,
            Self::ModelResponse,
            Self::ToolRequested,
            Self::PolicyDecision,
            Self::ApprovalRequested,
            Self::ApprovalResolved,
            Self::ToolStarted,
            Self::ToolBlocked,
            Self::ToolFinished,
            Self::BudgetExhausted,
            Self::FinishRequested,
            Self::RunFinished,
            Self::Note,
            Self::CheckpointCreated,
            Self::CheckpointFailed,
            Self::RollbackRequested,
            Self::RollbackStarted,
            Self::RollbackApplied,
            Self::RollbackSkippedAlreadyApplied,
            Self::RollbackFailed,
            Self::FailedPathRecorded,
            Self::ContextAssembled,
            Self::PhaseChanged,
            Self::ProviderSwitched,
            Self::MemoryProposed,
        ]
    }

    /// Project an internal event kind, or refuse it.
    ///
    /// Refusing is deliberate. A kind that never had a mapping is an
    /// implementation detail leaking into the contract, and passing it through
    /// under a guessed name would make the consumer's view quietly wrong.
    pub fn from_event(kind: EventKind) -> Result<Self> {
        Ok(match kind {
            EventKind::RunStarted => Self::RunStarted,
            EventKind::TurnStarted => Self::TurnStarted,
            EventKind::ModelRequest => Self::ModelRequest,
            EventKind::ModelResponse => Self::ModelResponse,
            EventKind::ToolRequested => Self::ToolRequested,
            EventKind::PolicyDecision => Self::PolicyDecision,
            EventKind::ApprovalRequested => Self::ApprovalRequested,
            EventKind::ApprovalResolved => Self::ApprovalResolved,
            EventKind::ToolStarted => Self::ToolStarted,
            EventKind::ToolBlocked => Self::ToolBlocked,
            EventKind::ToolFinished => Self::ToolFinished,
            EventKind::BudgetExhausted => Self::BudgetExhausted,
            EventKind::FinishRequested => Self::FinishRequested,
            EventKind::RunFinished => Self::RunFinished,
            EventKind::Note => Self::Note,
            EventKind::CheckpointCreated => Self::CheckpointCreated,
            EventKind::CheckpointFailed => Self::CheckpointFailed,
            EventKind::RollbackRequested => Self::RollbackRequested,
            EventKind::RollbackStarted => Self::RollbackStarted,
            EventKind::RollbackApplied => Self::RollbackApplied,
            EventKind::RollbackSkippedAlreadyApplied => Self::RollbackSkippedAlreadyApplied,
            EventKind::RollbackFailed => Self::RollbackFailed,
            EventKind::FailedPathRecorded => Self::FailedPathRecorded,
            EventKind::ContextAssembled => Self::ContextAssembled,
            EventKind::PhaseChanged => Self::PhaseChanged,
            EventKind::ProviderSwitched => Self::ProviderSwitched,
            EventKind::MemoryProposed => Self::MemoryProposed,
        })
    }
}

/// The effect metadata attached to an action event.
///
/// Closed set, for the same reason [`StreamEvent`] is: a consumer can match
/// exhaustively, and a field can never disappear without a version bump.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamEffect {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reversibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_mutation: Option<bool>,
}

/// The stable payload of a stream record.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamData {
    /// Already redacted and length-bounded by the same code the journal uses.
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invariant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<crate::Usage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<StreamEffect>,
}

/// Where this record came from, so anyone who needs proof can go get it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamOrigin {
    /// The journal sequence number this record was projected from.
    pub journal_seq: u64,
    /// The journal's content hash, which is what actually carries the audit
    /// weight. The stream's own presence proves nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_sha: Option<String>,
    /// The stable journal event ID, present only for v2 journals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
}

/// One record in the public stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamEvent {
    /// Always [`STREAM_SCHEMA_V1`] for this contract.
    pub schema: String,
    /// Position within this stream, starting at 0.
    pub seq: u64,
    pub at: String,
    pub kind: StreamKind,
    pub turn: u32,
    pub data: StreamData,
    pub origin: StreamOrigin,
    /// This record is a projection, not a record of what happened.
    ///
    /// Fixed to `true` on construction. It is a field rather than a convention
    /// so that a consumer reading the file cannot have to take our word for it.
    pub derived: bool,
    /// Always `false`. The audit authority is the journal, not this file.
    pub authoritative: bool,
}

impl StreamEvent {
    /// Project an internal event into the public contract.
    ///
    /// The event is redacted with the runtime's own redaction, so the stream
    /// cannot become the place a secret leaks that the journal would not let
    /// through.
    pub fn from_event(event: &Event) -> Result<Self> {
        let sealed = redact_event(event.clone());
        Ok(Self {
            schema: STREAM_SCHEMA_V1.to_string(),
            seq: sealed.seq,
            at: sealed.at.clone(),
            kind: StreamKind::from_event(sealed.kind)?,
            turn: sealed.turn,
            data: StreamData {
                message: sealed.message.clone(),
                tool: sealed.tool.clone(),
                call_id: sealed.call_id.clone(),
                verdict: sealed.verdict.clone(),
                risk: sealed.risk.clone(),
                rule_id: sealed.rule_id.clone(),
                invariant: sealed.invariant.clone(),
                duration_ms: sealed.duration_ms,
                usage: sealed.usage,
                effect: sealed.effect_scope.clone().map(|scope| StreamEffect {
                    scope: Some(scope),
                    reversibility: sealed.reversibility.clone(),
                    action_digest: sealed.action_digest.clone(),
                    external_mutation: sealed.external_mutation,
                }),
            },
            origin: StreamOrigin {
                journal_seq: sealed.seq,
                journal_sha: Some(sealed.sha.clone()),
                event_id: sealed.event_id.clone(),
            },
            derived: true,
            authoritative: false,
        })
    }

    pub fn stability(&self) -> Stability {
        self.kind.stability()
    }

    /// Reject anything that is not a well-formed v1 record.
    ///
    /// The two constants are checked rather than assumed: a hand-edited or
    /// maliciously crafted record that claimed `authoritative: true` must not
    /// be readable as if we had written it.
    pub fn validate(&self) -> Result<()> {
        if self.schema != STREAM_SCHEMA_V1 {
            return Err(Error::Config(format!(
                "unsupported stream schema `{}`; this build reads {STREAM_SCHEMA_V1}",
                crate::util::one_line(&self.schema, 64)
            )));
        }
        if !self.derived {
            return Err(Error::Config(
                "stream record is not marked derived; refusing to trust it".into(),
            ));
        }
        if self.authoritative {
            return Err(Error::Config(
                "stream record claims to be authoritative; the journal is, not the stream".into(),
            ));
        }
        if self.data.message.len() > crate::events::MAX_EVENT_MESSAGE_BYTES {
            return Err(Error::Config("stream message exceeds its bound".into()));
        }
        Ok(())
    }
}

/// A migrated record together with where it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct Migrated {
    pub event: StreamEvent,
    /// True when the input line was journal-format and had to be projected
    /// forward, rather than already being a stream record.
    pub from_journal: bool,
}

/// Reads older and newer records forward into the current contract.
///
/// The point of a migrator is that a consumer written against v1 keeps
/// working. It is also the point where forward-compat safety is decided: an
/// unrecognized version is refused, not partially parsed.
#[derive(Debug, Clone, Copy, Default)]
pub struct EventMigrator;

impl EventMigrator {
    pub fn new() -> Self {
        Self
    }

    /// Migrate one NDJSON line into the current contract.
    ///
    /// The result carries its own provenance. That is not bookkeeping: a
    /// migrated record reports the *current* schema, so the only way a reader
    /// can honestly say "this file was journal format" is if the migrator says
    /// so explicitly. Inferring it from the record would be always-false.
    pub fn migrate_line(&self, line: &str) -> Result<Migrated> {
        if line.len() > MAX_STREAM_LINE_BYTES {
            return Err(Error::Config(format!(
                "stream line exceeds {MAX_STREAM_LINE_BYTES} bytes"
            )));
        }
        // Probe the schema before decoding into any concrete type, so a
        // future record is refused for the right reason instead of failing as
        // a confusing deserialization error.
        let probe: crate::Value = serde_json::from_str(line)
            .map_err(|error| Error::Config(format!("stream line is not valid JSON: {error}")))?;
        // A missing `schema` is not an unknown schema. The internal Event type
        // documents an absent marker as the legacy `pangu-journal/v1` shape,
        // and v1 journals are written that way on purpose to stay
        // byte-compatible. Refusing them would make the migrator unable to read
        // the very format it was built to absorb. An *unrecognized* schema is
        // still refused below.
        let schema = probe
            .get("schema")
            .and_then(crate::Value::as_str)
            .unwrap_or(JOURNAL_FORMAT_V1)
            .to_string();

        if schema == STREAM_SCHEMA_V1 {
            let event: StreamEvent = serde_json::from_value(probe)?;
            event.validate()?;
            return Ok(Migrated {
                event,
                from_journal: false,
            });
        }
        if MIGRATABLE_JOURNAL_SCHEMAS.contains(&schema.as_str()) {
            // A journal line, not a stream line. Decoding it into the internal
            // shape and re-projecting keeps one code path for the mapping,
            // instead of a second, drift-prone copy.
            let internal: Event = serde_json::from_value(probe)?;
            return Ok(Migrated {
                event: StreamEvent::from_event(&internal)?,
                from_journal: true,
            });
        }
        if SUPPORTED_STREAM_SCHEMAS.contains(&schema.as_str()) {
            return Err(Error::Config(format!(
                "stream schema `{schema}` is listed as supported but not implemented; refusing to \
                 continue rather than emit a partial record"
            )));
        }
        Err(Error::Config(format!(
            "unknown stream schema `{schema}`; this build reads {STREAM_SCHEMA_V1}. Refusing \
             to guess: a newer writer's record is not this build's to interpret.",
            schema = crate::util::one_line(&schema, 64)
        )))
    }

    /// Which schemas this migrator will accept, for `pangu events --help` and
    /// for the summary a reader prints.
    pub fn supported_schemas() -> Vec<&'static str> {
        let mut schemas = SUPPORTED_STREAM_SCHEMAS.to_vec();
        schemas.extend_from_slice(MIGRATABLE_JOURNAL_SCHEMAS);
        schemas
    }
}

/// What a read produced, including anything the caller must be told about.
///
/// A truncated or partially-understood stream is reported, never presented as
/// complete. Silently returning the first N records would let a consumer
/// conclude "nothing happened after this point" when the truth is "we stopped
/// looking".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamSummary {
    pub schema: String,
    pub events: Vec<StreamEvent>,
    pub total_bytes: u64,
    pub records_read: usize,
    /// Set when reading stopped early because of a bound. The prefix is real;
    /// what follows it was never examined.
    pub truncated: bool,
    /// Set when input lines were journal-format and were migrated forward.
    pub migrated_from_journal: bool,
    /// How many records carry provisional kinds, which a consumer building a
    /// long-lived integration should know about.
    pub provisional_records: usize,
    /// A read always declares where the real audit authority is.
    pub authoritative: bool,
    pub note: String,
}

impl StreamSummary {
    fn new() -> Self {
        Self {
            schema: STREAM_SCHEMA_V1.to_string(),
            authoritative: false,
            truncated: false,
            migrated_from_journal: false,
            ..Self::default()
        }
    }

    pub fn render(&self) -> String {
        let mut out = format!(
            "stream {}: {} record(s), {total} byte(s)\n",
            self.schema,
            self.events.len(),
            total = self.total_bytes
        );
        if self.migrated_from_journal {
            out.push_str("  migrated from journal format on read\n");
        }
        if self.provisional_records > 0 {
            out.push_str(&format!(
                "  {count} record(s) carry provisional kinds whose shape may change\n",
                count = self.provisional_records
            ));
        }
        if self.truncated {
            out.push_str("  TRUNCATED: reading stopped at the size limit; records after this point were never examined\n");
        }
        out.push_str(&format!("  {}\n", self.note));
        out
    }
}

/// Read a stream file, migrating and validating every line.
pub fn read_stream(path: impl AsRef<Path>) -> Result<StreamSummary> {
    let path = path.as_ref();
    crate::journal::reject_symlink_components(path)?;
    let bytes = read_bounded(path)?;
    let text = String::from_utf8(bytes).map_err(|_| {
        Error::Config("stream file is not valid UTF-8; refusing to guess an encoding".into())
    })?;

    let migrator = EventMigrator::new();
    let mut summary = StreamSummary::new();
    summary.total_bytes = text.len() as u64;

    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if summary.events.len() >= MAX_STREAM_RECORDS {
            summary.truncated = true;
            break;
        }
        // A corrupt line fails the whole read. Returning the prefix would let
        // a caller act on a stream whose middle is missing.
        let migrated = migrator.migrate_line(line).map_err(|error| {
            Error::Config(format!(
                "stream line {} failed to migrate: {error}",
                index + 1
            ))
        })?;
        if migrated.from_journal {
            summary.migrated_from_journal = true;
        }
        let event = migrated.event;
        if event.stability() == Stability::Provisional {
            summary.provisional_records += 1;
        }
        summary.events.push(event);
    }
    summary.records_read = summary.events.len();
    summary.note =
        "derived projection; the hash-chained journal remains the audit authority".to_string();
    Ok(summary)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MAX_STREAM_BYTES {
        return Err(Error::Config(format!(
            "stream file exceeds {MAX_STREAM_BYTES} bytes"
        )));
    }
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_STREAM_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STREAM_BYTES {
        return Err(Error::Config(format!(
            "stream file exceeds {MAX_STREAM_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

/// Append-only NDJSON writer, usable as an [`EventSink`].
///
/// A write failure is returned to the caller rather than swallowed. The
/// `EventSink` contract already requires that an audit failure not become a
/// successful run, and a truncated stream that looks fine is worse than a
/// visible error.
pub struct StreamWriter {
    path: PathBuf,
    seq: Mutex<u64>,
    file: Mutex<BufWriter<std::fs::File>>,
    bytes: Mutex<u64>,
}

impl StreamWriter {
    /// Create a new stream file. An existing path is refused, so a stream is
    /// never silently overwritten and two runs never interleave into one file.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        crate::journal::reject_symlink_components(&path)?;
        if path.exists() {
            return Err(Error::Config(format!(
                "stream already exists; refusing to overwrite: {}",
                path.display()
            )));
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
                crate::journal::reject_symlink_components(parent)?;
            }
        }
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        Ok(Self {
            path,
            seq: Mutex::new(0),
            file: Mutex::new(BufWriter::new(file)),
            bytes: Mutex::new(0),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write one already-projected record.
    pub fn append(&self, event: &StreamEvent) -> Result<()> {
        event.validate()?;
        let mut file = self.file.lock().expect("stream file lock");
        let mut bytes = self.bytes.lock().expect("stream byte lock");
        let line = serde_json::to_string(event)?;
        if line.len() > MAX_STREAM_LINE_BYTES {
            return Err(Error::Other(format!(
                "stream record exceeds {MAX_STREAM_LINE_BYTES} bytes"
            )));
        }
        let next = bytes
            .checked_add(line.len() as u64 + 1)
            .ok_or_else(|| Error::Other("stream size overflowed".into()))?;
        if next > MAX_STREAM_BYTES {
            return Err(Error::Other("stream exceeds the size limit".into()));
        }
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.get_ref().sync_data()?;
        *bytes = next;
        Ok(())
    }

    /// Project and append one internal event, assigning the next sequence
    /// number.
    ///
    /// This is the whole body of the sink; the async `emit` only wraps it. A
    /// write is a plain file operation, so exposing it synchronously keeps the
    /// tests free of a runtime dependency just to count records.
    pub fn record_event(&self, event: &Event) -> Result<StreamEvent> {
        let mut record = StreamEvent::from_event(event)?;
        let mut seq = self.seq.lock().expect("stream seq lock");
        record.seq = *seq;
        self.append(&record)?;
        *seq = seq.saturating_add(1);
        Ok(record)
    }
}

#[async_trait::async_trait]
impl EventSink for StreamWriter {
    async fn emit(&self, event: Event) -> Result<()> {
        self.record_event(&event).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "pangu-stream-{label}-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn sample_event() -> Event {
        let mut event = Event::new_v2(EventKind::PolicyDecision, 1, "denied");
        event.tool = Some("write_file".into());
        event.call_id = Some("call-1".into());
        event.verdict = Some("deny".into());
        event.risk = Some("destructive".into());
        event.rule_id = Some("ask-write-file".into());
        event.invariant = Some("I-No-Silent-Bypass".into());
        event.seq = 7;
        event.sha = "a".repeat(64);
        event.event_id = Some("evt_abc".into());
        event
    }

    #[test]
    fn a_stream_record_declares_itself_derived_and_cannot_claim_authority() {
        let record = StreamEvent::from_event(&sample_event()).expect("project");
        assert!(record.derived);
        assert!(!record.authoritative);
        assert_eq!(record.schema, STREAM_SCHEMA_V1);
        record.validate().expect("valid");

        // A record that claims authority is refused, not believed.
        let mut forged = record.clone();
        forged.authoritative = true;
        assert!(forged.validate().is_err());

        let mut underived = record.clone();
        underived.derived = false;
        assert!(underived.validate().is_err());
    }

    #[test]
    fn the_record_points_back_at_the_journal_event() {
        let event = sample_event();
        let record = StreamEvent::from_event(&event).expect("project");
        assert_eq!(record.origin.journal_seq, 7);
        assert_eq!(record.origin.event_id.as_deref(), Some("evt_abc"));
        // Redaction rewrites the content, so the recorded hash must be the one
        // the sealed event actually has. A stream that pointed at a stale hash
        // would send a verifier to the wrong record.
        let sealed = redact_event(event);
        assert_eq!(
            record.origin.journal_sha.as_deref(),
            Some(sealed.sha.as_str())
        );
    }

    #[test]
    fn every_kind_maps_and_declares_its_stability() {
        for kind in StreamKind::all() {
            let internal = match kind {
                StreamKind::RunStarted => EventKind::RunStarted,
                StreamKind::TurnStarted => EventKind::TurnStarted,
                StreamKind::ModelRequest => EventKind::ModelRequest,
                StreamKind::ModelResponse => EventKind::ModelResponse,
                StreamKind::ToolRequested => EventKind::ToolRequested,
                StreamKind::PolicyDecision => EventKind::PolicyDecision,
                StreamKind::ApprovalRequested => EventKind::ApprovalRequested,
                StreamKind::ApprovalResolved => EventKind::ApprovalResolved,
                StreamKind::ToolStarted => EventKind::ToolStarted,
                StreamKind::ToolBlocked => EventKind::ToolBlocked,
                StreamKind::ToolFinished => EventKind::ToolFinished,
                StreamKind::BudgetExhausted => EventKind::BudgetExhausted,
                StreamKind::FinishRequested => EventKind::FinishRequested,
                StreamKind::RunFinished => EventKind::RunFinished,
                StreamKind::Note => EventKind::Note,
                StreamKind::CheckpointCreated => EventKind::CheckpointCreated,
                StreamKind::CheckpointFailed => EventKind::CheckpointFailed,
                StreamKind::RollbackRequested => EventKind::RollbackRequested,
                StreamKind::RollbackStarted => EventKind::RollbackStarted,
                StreamKind::RollbackApplied => EventKind::RollbackApplied,
                StreamKind::RollbackSkippedAlreadyApplied => {
                    EventKind::RollbackSkippedAlreadyApplied
                }
                StreamKind::RollbackFailed => EventKind::RollbackFailed,
                StreamKind::FailedPathRecorded => EventKind::FailedPathRecorded,
                StreamKind::ContextAssembled => EventKind::ContextAssembled,
                StreamKind::PhaseChanged => EventKind::PhaseChanged,
                StreamKind::ProviderSwitched => EventKind::ProviderSwitched,
                StreamKind::MemoryProposed => EventKind::MemoryProposed,
            };
            assert_eq!(StreamKind::from_event(internal).unwrap(), *kind);
        }
        assert_eq!(EventKind::Note, EventKind::Note);
        // F7's events are provisional, not frozen.
        assert_eq!(
            StreamKind::RollbackApplied.stability(),
            Stability::Provisional
        );
        assert_eq!(StreamKind::RunStarted.stability(), Stability::Stable);
    }

    #[test]
    fn round_trips_through_the_writer_and_reader() {
        let path = temp_path("roundtrip");
        let writer = StreamWriter::create(&path).expect("create");
        for kind in StreamKind::all() {
            let internal = Event::new_v2(
                match kind {
                    StreamKind::RunStarted => EventKind::RunStarted,
                    StreamKind::TurnStarted => EventKind::TurnStarted,
                    StreamKind::ModelRequest => EventKind::ModelRequest,
                    StreamKind::ModelResponse => EventKind::ModelResponse,
                    StreamKind::ToolRequested => EventKind::ToolRequested,
                    StreamKind::PolicyDecision => EventKind::PolicyDecision,
                    StreamKind::ApprovalRequested => EventKind::ApprovalRequested,
                    StreamKind::ApprovalResolved => EventKind::ApprovalResolved,
                    StreamKind::ToolStarted => EventKind::ToolStarted,
                    StreamKind::ToolBlocked => EventKind::ToolBlocked,
                    StreamKind::ToolFinished => EventKind::ToolFinished,
                    StreamKind::BudgetExhausted => EventKind::BudgetExhausted,
                    StreamKind::FinishRequested => EventKind::FinishRequested,
                    StreamKind::RunFinished => EventKind::RunFinished,
                    StreamKind::Note => EventKind::Note,
                    StreamKind::CheckpointCreated => EventKind::CheckpointCreated,
                    StreamKind::CheckpointFailed => EventKind::CheckpointFailed,
                    StreamKind::RollbackRequested => EventKind::RollbackRequested,
                    StreamKind::RollbackStarted => EventKind::RollbackStarted,
                    StreamKind::RollbackApplied => EventKind::RollbackApplied,
                    StreamKind::RollbackSkippedAlreadyApplied => {
                        EventKind::RollbackSkippedAlreadyApplied
                    }
                    StreamKind::RollbackFailed => EventKind::RollbackFailed,
                    StreamKind::FailedPathRecorded => EventKind::FailedPathRecorded,
                    StreamKind::ContextAssembled => EventKind::ContextAssembled,
                    StreamKind::PhaseChanged => EventKind::PhaseChanged,
                    StreamKind::ProviderSwitched => EventKind::ProviderSwitched,
                    StreamKind::MemoryProposed => EventKind::MemoryProposed,
                },
                0,
                "hello",
            );
            writer.record_event(&internal).expect("record");
        }
        let summary = read_stream(&path).expect("read");
        assert_eq!(summary.events.len(), StreamKind::all().len());
        assert!(!summary.truncated);
        assert!(!summary.migrated_from_journal);
        assert!(!summary.authoritative);
        assert!(
            summary.provisional_records > 0,
            "F7 kinds must be counted as provisional"
        );
        assert!(summary
            .render()
            .contains("journal remains the audit authority"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn a_journal_line_migrates_forward_and_says_so() {
        let journal_path = temp_path("migrate-from");
        let journal = crate::Journal::create_v2(&journal_path).expect("create journal");
        let sealed = journal.record(&sample_event()).expect("record");
        drop(journal);

        // Feed the raw journal file to the stream reader, which is the actual
        // "read an old journal as a stream" use case.
        let summary = read_stream(&journal_path).expect("migrate");
        assert!(summary.migrated_from_journal);
        assert_eq!(summary.events.len(), 1);
        assert_eq!(summary.events[0].kind, StreamKind::PolicyDecision);
        assert_eq!(
            summary.events[0].origin.journal_sha.as_deref(),
            Some(sealed.sha.as_str())
        );
        assert_eq!(summary.events[0].origin.event_id, sealed.event_id);
        std::fs::remove_file(journal_path).ok();
    }

    #[test]
    fn a_v1_journal_migrates_forward_even_though_it_carries_no_schema_field() {
        // v1 records deliberately omit the `schema` marker to stay
        // byte-compatible with the original format, so "no schema" has always
        // meant "v1 journal" internally. The migrator has to honor that, or it
        // cannot read the oldest format it exists to absorb.
        let path = temp_path("migrate-v1");
        let journal = crate::Journal::create(&path).expect("create v1 journal");
        journal
            .record(&Event::new(EventKind::ToolBlocked, 0, "blocked"))
            .expect("record");
        drop(journal);

        let raw = std::fs::read_to_string(&path).expect("read raw");
        assert!(
            !raw.contains("\"schema\""),
            "a v1 journal must not carry a schema marker: {raw}"
        );

        let summary = read_stream(&path).expect("migrate v1");
        assert!(summary.migrated_from_journal);
        assert_eq!(summary.events.len(), 1);
        assert_eq!(summary.events[0].kind, StreamKind::ToolBlocked);
        assert_eq!(summary.events[0].schema, STREAM_SCHEMA_V1);
        // v1 has no stable event id, so the origin must not invent one.
        assert_eq!(summary.events[0].origin.event_id, None);
        assert!(summary.events[0].origin.journal_sha.is_some());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn an_unknown_or_future_schema_is_refused_rather_than_guessed() {
        let migrator = EventMigrator::new();
        for schema in [
            "pangu-stream/2",
            "pangu-stream/99",
            "someone-elses-format/1",
            "",
        ] {
            if schema.is_empty() {
                continue;
            }
            let line = format!("{{\"schema\":\"{schema}\",\"seq\":0}}");
            let error = migrator
                .migrate_line(&line)
                .expect_err("an unknown schema must be refused");
            assert!(
                error.to_string().contains("unknown stream schema"),
                "expected a refusal naming the schema, got: {error}"
            );
        }
        // A record with no schema at all is also refused.
        assert!(migrator.migrate_line("{\"seq\":0}").is_err());
        assert!(migrator.migrate_line("not json").is_err());
    }

    #[test]
    fn a_corrupt_line_fails_the_whole_read() {
        let path = temp_path("corrupt");
        let writer = StreamWriter::create(&path).expect("create");
        writer
            .record_event(&Event::new_v2(EventKind::RunStarted, 0, "ok"))
            .expect("record");
        drop(writer);

        // Append a record that is valid JSON but not a valid stream record.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"schema\":\"pangu-stream/1\"}\n")
            .unwrap();

        let error = read_stream(&path).expect_err("a corrupt line must fail the read");
        assert!(
            error.to_string().contains("line 2"),
            "the error must name the offending line, got: {error}"
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn secrets_are_redacted_in_the_stream_exactly_as_in_the_journal() {
        let mut event = Event::new_v2(EventKind::ToolFinished, 0, "token sk-abcdef1234567890");
        event.tool = Some("read_file".into());
        let record = StreamEvent::from_event(&event).expect("project");
        assert!(
            !record.data.message.contains("sk-abcdef1234567890"),
            "the stream must not carry a credential: {}",
            record.data.message
        );
    }

    #[test]
    fn the_writer_refuses_to_overwrite_an_existing_stream() {
        let path = temp_path("no-overwrite");
        drop(StreamWriter::create(&path).expect("create"));
        assert!(StreamWriter::create(&path).is_err());
        std::fs::remove_file(path).ok();
    }
}
