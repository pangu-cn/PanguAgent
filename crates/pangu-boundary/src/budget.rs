use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use pangu_core::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct Budget {
    #[serde(default = "default_turns")]
    pub max_turns: u32,
    #[serde(default = "max_input_tokens")]
    pub max_input_tokens: u64,
    #[serde(default = "max_output_tokens")]
    pub max_output_tokens: u64,
    #[serde(default = "max_cost_usd_default")]
    pub max_cost_usd: f64,
    #[serde(
        default = "default_wall_clock_secs",
        deserialize_with = "deserialize_duration_secs",
        serialize_with = "serialize_duration_secs"
    )]
    pub max_wall_clock_secs: Duration,
}

fn default_turns() -> u32 {
    12
}
fn max_input_tokens() -> u64 {
    200_000
}
fn max_output_tokens() -> u64 {
    16_000
}
fn max_cost_usd_default() -> f64 {
    1.0
}
fn default_wall_clock_secs() -> Duration {
    Duration::from_secs(600)
}

fn deserialize_duration_secs<'de, D>(deserializer: D) -> std::result::Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let seconds = u64::deserialize(deserializer)?;
    Ok(Duration::from_secs(seconds))
}

fn serialize_duration_secs<S>(
    duration: &Duration,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u64(duration.as_secs())
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_turns: default_turns(),
            max_input_tokens: max_input_tokens(),
            max_output_tokens: max_output_tokens(),
            max_cost_usd: max_cost_usd_default(),
            max_wall_clock_secs: default_wall_clock_secs(),
        }
    }
}

impl Budget {
    pub fn validate(&self) -> Result<()> {
        if self.max_turns == 0 {
            return Err(Error::Config("budget.max_turns must be > 0".into()));
        }
        if self.max_input_tokens == 0 || self.max_output_tokens == 0 {
            return Err(Error::Config("budget token limits must be > 0".into()));
        }
        if !self.max_cost_usd.is_finite() || self.max_cost_usd < 0.0 {
            return Err(Error::Config(
                "budget.max_cost_usd must be finite and >= 0".into(),
            ));
        }
        if self.max_wall_clock_secs.is_zero() {
            return Err(Error::Config(
                "budget.max_wall_clock_secs must be > 0".into(),
            ));
        }
        Ok(())
    }

    /// All limits are inclusive: reaching a limit stops the next action.
    pub fn check(
        &self,
        turn: u32,
        input: u64,
        output: u64,
        cost: f64,
        elapsed: Duration,
    ) -> Vec<Breach> {
        let mut breaches = Vec::new();
        if turn >= self.max_turns {
            breaches.push(Breach::Turns);
        }
        if input >= self.max_input_tokens {
            breaches.push(Breach::InputTokens);
        }
        if output >= self.max_output_tokens {
            breaches.push(Breach::OutputTokens);
        }
        if !cost.is_finite() || cost < 0.0 || cost >= self.max_cost_usd {
            breaches.push(Breach::Cost);
        }
        if elapsed >= self.max_wall_clock_secs {
            breaches.push(Breach::WallClock);
        }
        breaches
    }

    pub fn safe_budget(&self) -> (u32, u64, u64, f64, Duration) {
        (
            self.max_turns.saturating_sub(1),
            self.max_input_tokens.saturating_sub(5_000),
            self.max_output_tokens.saturating_sub(2_000),
            (self.max_cost_usd * 0.95).max(0.0),
            self.max_wall_clock_secs
                .saturating_sub(Duration::from_secs(10)),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Breach {
    Turns,
    InputTokens,
    OutputTokens,
    Cost,
    WallClock,
}

impl std::fmt::Display for Breach {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Turns => "turn limit reached",
            Self::InputTokens => "input token limit reached",
            Self::OutputTokens => "output token limit reached",
            Self::Cost => "cost limit reached or unavailable",
            Self::WallClock => "wall-clock limit reached",
        })
    }
}

impl std::error::Error for Breach {}

impl std::str::FromStr for Breach {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "turns" | "steps" | "step_limit" => Ok(Self::Turns),
            "input_tokens" | "tokens_in" => Ok(Self::InputTokens),
            "output_tokens" | "tokens_out" => Ok(Self::OutputTokens),
            "cost" | "cost_usd" => Ok(Self::Cost),
            "wallclock" | "timeout" | "wall_clock" => Ok(Self::WallClock),
            other => Err(format!("unknown budget breach type `{other}`")),
        }
    }
}
