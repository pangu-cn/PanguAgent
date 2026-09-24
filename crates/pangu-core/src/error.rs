use thiserror::Error;

/// Errors crossing the library boundary.
#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("action denied by policy: {reason}")]
    Denied { reason: String },

    #[error("path escapes the declared boundary: {path} ({reason})")]
    PathOutsideBoundary { path: String, reason: String },

    #[error("host not in egress allow-list: {host}")]
    EgressDenied { host: String },

    #[error("budget exhausted: {0}")]
    Budget(String),

    #[error("tool `{tool}` failed: {message}")]
    Tool { tool: String, message: String },

    #[error("provider error: {0}")]
    Provider(String),

    #[error("invalid tool arguments for `{tool}`: {detail}")]
    InvalidArgs { tool: String, detail: String },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("timeout after {secs}s")]
    Timeout { secs: u64 },

    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Whether the error can safely be returned to the model as a tool error
    /// while the current run continues.
    pub fn is_recoverable_for_model(&self) -> bool {
        !matches!(self, Error::Budget(_) | Error::Config(_))
    }

    pub fn code(&self) -> &'static str {
        match self {
            Error::Denied { .. } => "policy_denied",
            Error::PathOutsideBoundary { .. } => "path_outside_boundary",
            Error::EgressDenied { .. } => "egress_denied",
            Error::Budget(_) => "budget_exhausted",
            Error::Tool { .. } => "tool_error",
            Error::Provider(_) => "provider_error",
            Error::InvalidArgs { .. } => "invalid_args",
            Error::Timeout { .. } => "timeout",
            Error::Io(_) => "io_error",
            Error::Serde(_) => "serde_error",
            Error::Config(_) => "config_error",
            Error::Other(_) => "error",
        }
    }
}

pub type Result<T = ()> = std::result::Result<T, Error>;
