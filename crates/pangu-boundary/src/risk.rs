use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The only input to the human gate. A tool must derive this from its
/// arguments; model-supplied text never changes the risk class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    ReadOnly,
    Reversible,
    Destructive,
    NeedsHuman,
}

impl Risk {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Reversible => "reversible",
            Self::Destructive => "destructive",
            Self::NeedsHuman => "needs_human",
        }
    }

    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "read_only" | "readonly" | "ro" => Ok(Self::ReadOnly),
            "reversible" | "rw" => Ok(Self::Reversible),
            "destructive" => Ok(Self::Destructive),
            "needs_human" | "human" => Ok(Self::NeedsHuman),
            other => Err(format!("unknown risk class `{other}`")),
        }
    }

    pub fn at_least(self, other: Self) -> bool {
        self >= other
    }

    pub fn explain(self) -> &'static str {
        match self {
            Self::ReadOnly => "不改变外部世界",
            Self::Reversible => "改动可回滚",
            Self::Destructive => "不可逆或影响工作区之外",
            Self::NeedsHuman => "花钱、触及凭据或无法撤销",
        }
    }
}

impl fmt::Display for Risk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Risk {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_fail_closed() {
        assert!(Risk::NeedsHuman.at_least(Risk::Destructive));
        assert!(Risk::Destructive.at_least(Risk::Reversible));
        assert!(!Risk::ReadOnly.at_least(Risk::Reversible));
        assert!(Risk::parse("unknown").is_err());
    }
}
