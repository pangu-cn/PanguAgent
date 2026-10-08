use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{Error, Result};

pub const COMPAT_SCHEMA: &str = "pangu-compat/1";
pub const MIN_EVENT_STREAM: &str = "pangu-stream/1";
pub const MIN_ARTIFACT_SCHEMA: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlIntent {
    pub idempotency_key: String,
    pub workspace_digest: String,
    pub expires_at_unix: u64,
}

impl ControlIntent {
    pub fn new(task: &str, window: &str, workspace_digest: &str, ttl: Duration) -> Result<Self> {
        if task.trim().is_empty() || window.trim().is_empty() {
            return Err(Error::Config(
                "automation intent requires task and window".into(),
            ));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(Self {
            idempotency_key: crate::hex_sha256(&format!("{task}\n{window}")),
            workspace_digest: workspace_digest.to_string(),
            expires_at_unix: now.saturating_add(ttl.as_secs()),
        })
    }
}

#[derive(Debug, Default)]
pub struct ControlPlane {
    seen: std::sync::Mutex<BTreeSet<String>>,
}

impl ControlPlane {
    pub fn accept(&self, intent: &ControlIntent) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if intent.expires_at_unix <= now {
            return Err(Error::Config("automation intent expired".into()));
        }
        let mut seen = self.seen.lock().expect("control plane lock");
        if !seen.insert(intent.idempotency_key.clone()) {
            return Err(Error::Config("duplicate automation idempotency key".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToken {
    scope: String,
    expires_at_unix: u64,
}

impl SessionToken {
    pub fn issue(scope: &str, ttl: Duration) -> Result<Self> {
        if scope.trim().is_empty() || ttl.as_secs() == 0 || ttl.as_secs() > 900 {
            return Err(Error::Config(
                "session token ttl must be 1..=900 seconds".into(),
            ));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(Self {
            scope: scope.to_string(),
            expires_at_unix: now.saturating_add(ttl.as_secs()),
        })
    }

    pub fn allows(&self, scope: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.scope == scope && self.expires_at_unix > now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_intent_fails_closed() {
        let plane = ControlPlane::default();
        let intent =
            ControlIntent::new("task", "window", "workspace", Duration::from_secs(60)).unwrap();
        plane.accept(&intent).unwrap();
        assert!(plane.accept(&intent).is_err());
    }

    #[test]
    fn session_token_is_short_and_scoped() {
        assert!(SessionToken::issue("read", Duration::from_secs(901)).is_err());
        let token = SessionToken::issue("read", Duration::from_secs(60)).unwrap();
        assert!(token.allows("read"));
        assert!(!token.allows("write"));
    }
}
