use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use pangu_core::{glob, Error, Result, Value};

use crate::risk::Risk;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Ask,
    Deny,
}

impl Effect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }
}

impl FromStr for Effect {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "allow" | "permit" => Ok(Self::Allow),
            "ask" | "confirm" => Ok(Self::Ask),
            "deny" | "block" | "forbid" => Ok(Self::Deny),
            other => Err(format!("unknown effect `{other}`")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActionRequest<'a> {
    pub tool: &'a str,
    pub call_id: &'a str,
    pub args: &'a Value,
    pub risk: Risk,
    pub paths: Vec<PathBuf>,
    pub hosts: Vec<String>,
    pub argv: Vec<String>,
    pub escapes_workspace: bool,
}

impl<'a> ActionRequest<'a> {
    /// Unknown/unclassified actions start at the human-risk end of the enum.
    pub fn new(tool: &'a str, call_id: &'a str, args: &'a Value) -> Self {
        Self {
            tool,
            call_id,
            args,
            risk: Risk::NeedsHuman,
            paths: Vec::new(),
            hosts: Vec::new(),
            argv: Vec::new(),
            escapes_workspace: false,
        }
    }

    pub fn with(mut self, risk: Risk) -> Self {
        self.risk = risk;
        self
    }

    pub fn command_text(&self) -> String {
        if !self.argv.is_empty() {
            return self.argv.join(" ");
        }
        match self.args.get("command") {
            Some(Value::String(command)) => command.clone(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| item.as_str().unwrap_or_default().to_string())
                .collect::<Vec<_>>()
                .join(" "),
            Some(value) => value.to_string(),
            None => String::new(),
        }
    }

    pub fn rel_paths(&self, workspace: &Path) -> Vec<String> {
        self.paths
            .iter()
            .map(|path| {
                path.strip_prefix(workspace)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub effect: Effect,
    #[serde(default = "any_tool")]
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg: Option<ArgMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_glob: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_glob: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_risk: Option<Risk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_risk: Option<Risk>,
    #[serde(default)]
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invariant: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgMatch {
    pub key: String,
    pub glob: String,
}

fn any_tool() -> String {
    "*".to_string()
}

impl Rule {
    pub fn deny(id: &str, tool: &str, reason: &str) -> Self {
        Self::new(id, Effect::Deny, tool, reason)
    }

    pub fn allow(id: &str, tool: &str, reason: &str) -> Self {
        Self::new(id, Effect::Allow, tool, reason)
    }

    pub fn ask(id: &str, tool: &str, reason: &str) -> Self {
        Self::new(id, Effect::Ask, tool, reason)
    }

    fn new(id: &str, effect: Effect, tool: &str, reason: &str) -> Self {
        Self {
            id: id.to_string(),
            effect,
            tool: tool.to_string(),
            arg: None,
            path_glob: None,
            host_glob: None,
            max_risk: None,
            min_risk: None,
            reason: reason.to_string(),
            invariant: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() || self.id.len() > 256 || self.id.chars().any(char::is_control)
        {
            return Err(Error::Config(
                "rule id must be non-empty, at most 256 bytes, and contain no control characters"
                    .into(),
            ));
        }
        if self.reason.len() > 4_096 || self.reason.chars().any(char::is_control) {
            return Err(Error::Config(
                "rule reason must be at most 4096 bytes and contain no control characters".into(),
            ));
        }
        if self
            .invariant
            .as_deref()
            .is_some_and(|value| value.len() > 256 || value.chars().any(char::is_control))
        {
            return Err(Error::Config(
                "rule invariant must be at most 256 bytes and contain no control characters".into(),
            ));
        }
        if self.tool.trim().is_empty()
            || self.tool.len() > 128
            || self.tool.chars().any(char::is_control)
        {
            return Err(Error::Config(format!(
                "rule `{}` has an invalid tool",
                self.id
            )));
        }
        if let Some(arg) = &self.arg {
            if arg.key.trim().is_empty()
                || arg.key.len() > 256
                || arg.key.chars().any(char::is_control)
            {
                return Err(Error::Config(format!(
                    "rule `{}` has an invalid arg key",
                    self.id
                )));
            }
            if arg.glob.chars().any(char::is_control) {
                return Err(Error::Config(format!(
                    "rule `{}` has a control character in its arg glob",
                    self.id
                )));
            }
            glob::Glob::new(&arg.glob)?;
        }
        if let Some(path) = &self.path_glob {
            if path.chars().any(char::is_control) {
                return Err(Error::Config(format!(
                    "rule `{}` has a control character in its path glob",
                    self.id
                )));
            }
            glob::Glob::new(path)?;
        }
        if let Some(host) = &self.host_glob {
            if host.chars().any(char::is_control) {
                return Err(Error::Config(format!(
                    "rule `{}` has a control character in its host glob",
                    self.id
                )));
            }
            glob::Glob::new(host)?;
        }
        if matches!((self.min_risk, self.max_risk), (Some(min), Some(max)) if min > max) {
            return Err(Error::Config(format!(
                "rule `{}` has min_risk > max_risk",
                self.id
            )));
        }
        Ok(())
    }

    pub fn matches(&self, request: &ActionRequest<'_>, workspace: &Path) -> bool {
        if self.tool != "*" && self.tool != request.tool {
            return false;
        }
        if self.max_risk.is_some_and(|max| request.risk > max)
            || self.min_risk.is_some_and(|min| request.risk < min)
        {
            return false;
        }
        if let Some(argument) = &self.arg {
            let value = if argument.key == "command" {
                Some(request.command_text())
            } else {
                pangu_core::json::path_text(request.args, &argument.key)
            };
            let Some(value) = value else { return false };
            let Ok(pattern) = glob::Glob::new(&argument.glob) else {
                return false;
            };
            if !pattern.is_match(&value) {
                return false;
            }
        }
        if let Some(pattern) = &self.path_glob {
            let relative = request.rel_paths(workspace);
            if relative.is_empty() {
                return false;
            }
            let Ok(pattern) = glob::Glob::new(pattern) else {
                return false;
            };
            let matches = |path: &str| pattern.is_match(path);
            if self.effect == Effect::Allow {
                if !relative.iter().all(|path| matches(path)) {
                    return false;
                }
            } else if !relative.iter().any(|path| matches(path)) {
                return false;
            }
        }
        if let Some(pattern) = &self.host_glob {
            if request.hosts.is_empty() {
                return false;
            }
            let Ok(pattern) = glob::Glob::new(pattern) else {
                return false;
            };
            let matches = |host: &str| {
                pattern.is_match(host)
                    || host_without_port(host).is_some_and(|bare| pattern.is_match(bare))
            };
            if self.effect == Effect::Allow {
                if !request.hosts.iter().all(|host| matches(host)) {
                    return false;
                }
            } else if !request.hosts.iter().any(|host| matches(host)) {
                return false;
            }
        }
        true
    }
}

fn host_without_port(host: &str) -> Option<&str> {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().filter(|bare| !bare.is_empty());
    }
    host.rsplit_once(':')
        .and_then(|(name, port)| port.parse::<u16>().ok().and(Some(name)))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub effect: Effect,
    pub risk: Risk,
    pub rule_id: Option<String>,
    pub reason: String,
    pub invariant: Option<String>,
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        self.effect == Effect::Allow
    }

    pub fn is_deny(&self) -> bool {
        self.effect == Effect::Deny
    }

    pub fn denial_message(&self) -> String {
        format!(
            "denied by policy (rule={}, risk={}): {}{}",
            self.rule_id.as_deref().unwrap_or("default-deny"),
            self.risk,
            self.reason,
            self.invariant
                .as_ref()
                .map(|id| format!(" [invariant {id}]"))
                .unwrap_or_default()
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct Policy {
    rules: Vec<Rule>,
}

impl Policy {
    pub fn new(rules: Vec<Rule>) -> Result<Self> {
        let mut ids = HashSet::new();
        for rule in &rules {
            rule.validate()?;
            if !ids.insert(rule.id.as_str()) {
                return Err(Error::Config(format!("duplicate rule id `{}`", rule.id)));
            }
        }
        Ok(Self { rules })
    }

    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn digest(&self) -> String {
        pangu_core::hex_sha256(&serde_json::to_string(&self.rules).unwrap_or_default())
    }

    /// Deny rules always take precedence. Among non-deny rules, the first
    /// match wins, preserving predictable ask/allow ordering.
    pub fn evaluate(&self, request: &ActionRequest<'_>, workspace: &Path) -> Decision {
        let has_parent_traversal = request.paths.iter().any(|path| {
            path.components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        });
        if request.escapes_workspace || has_parent_traversal {
            return Decision {
                effect: Effect::Deny,
                risk: request.risk,
                rule_id: None,
                reason: "path traversal is not allowed".into(),
                invariant: Some("I-Path-Safety".into()),
            };
        }
        if let Some(rule) = self
            .rules
            .iter()
            .find(|rule| rule.effect == Effect::Deny && rule.matches(request, workspace))
        {
            return Decision {
                effect: Effect::Deny,
                risk: request.risk,
                rule_id: Some(rule.id.clone()),
                reason: rule.reason.clone(),
                invariant: rule
                    .invariant
                    .clone()
                    .or_else(|| Some("I-No-Silent-Bypass".into())),
            };
        }
        if let Some(rule) = self
            .rules
            .iter()
            .find(|rule| rule.effect != Effect::Deny && rule.matches(request, workspace))
        {
            let escalated =
                rule.effect == Effect::Allow && request.risk.at_least(Risk::Destructive);
            let (effect, reason) = if escalated {
                (
                    Effect::Ask,
                    format!(
                        "rule `{}` was escalated to the human gate ({})",
                        rule.id, request.risk
                    ),
                )
            } else {
                (rule.effect, rule.reason.clone())
            };
            let invariant = if escalated {
                Some("I-Model-Cannot-Self-Approve".to_string())
            } else {
                rule.invariant.clone()
            };
            return Decision {
                effect,
                risk: request.risk,
                rule_id: Some(rule.id.clone()),
                reason,
                invariant,
            };
        }
        Decision {
            effect: Effect::Deny,
            risk: request.risk,
            rule_id: None,
            reason: format!("no rule matched tool `{}`; default deny", request.tool),
            invariant: Some("I-Default-Deny".into()),
        }
    }

    pub fn render(&self) -> String {
        self.rules
            .iter()
            .map(|rule| {
                format!(
                    "{:<6} {:<24} tool={}  — {}",
                    rule.effect.as_str(),
                    rule.id,
                    rule.tool,
                    pangu_core::truncate_middle(&pangu_core::redact_text(&rule.reason), 4_096)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deny_precedes_an_earlier_broad_allow() {
        let policy = Policy::new(vec![
            Rule::allow("all", "*", "broad"),
            Rule::deny("block", "write_file", "blocked"),
        ])
        .unwrap();
        let args = json!({"path": "README.md"});
        let request = ActionRequest::new("write_file", "c1", &args).with(Risk::Reversible);
        let decision = policy.evaluate(&request, Path::new("/workspace"));
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.rule_id.as_deref(), Some("block"));
    }

    #[test]
    fn allow_rule_requires_every_target_to_match() {
        let policy = Policy::new(vec![Rule {
            id: "only-src".into(),
            effect: Effect::Allow,
            tool: "read_file".into(),
            arg: None,
            path_glob: Some("src/**".into()),
            host_glob: None,
            max_risk: Some(Risk::ReadOnly),
            min_risk: None,
            reason: "src only".into(),
            invariant: None,
        }])
        .unwrap();
        let args = json!({});
        let mut request = ActionRequest::new("read_file", "c1", &args).with(Risk::ReadOnly);
        request.paths = vec![
            PathBuf::from("/workspace/src/a.rs"),
            PathBuf::from("/workspace/docs/a.md"),
        ];
        assert_eq!(
            policy.evaluate(&request, Path::new("/workspace")).effect,
            Effect::Deny
        );
        request.paths = vec![PathBuf::from("/workspace/src/a.rs")];
        assert_eq!(
            policy.evaluate(&request, Path::new("/workspace")).effect,
            Effect::Allow
        );
    }

    #[test]
    fn allow_host_rule_requires_every_host() {
        let policy = Policy::new(vec![Rule {
            id: "allowed-hosts".into(),
            effect: Effect::Allow,
            tool: "http_fetch".into(),
            arg: None,
            path_glob: None,
            host_glob: Some("api.example.com".into()),
            max_risk: Some(Risk::Reversible),
            min_risk: None,
            reason: "approved API only".into(),
            invariant: None,
        }])
        .unwrap();
        let args = json!({});
        let mut request = ActionRequest::new("http_fetch", "c1", &args).with(Risk::Reversible);
        request.hosts = vec!["api.example.com:443".into(), "evil.example:443".into()];
        assert_eq!(
            policy.evaluate(&request, Path::new("/workspace")).effect,
            Effect::Deny
        );
        request.hosts = vec!["api.example.com:443".into()];
        assert_eq!(
            policy.evaluate(&request, Path::new("/workspace")).effect,
            Effect::Allow
        );
    }

    #[test]
    fn parent_traversal_is_denied_before_rule_matching() {
        let policy = Policy::new(vec![Rule::allow("all", "*", "broad")]).unwrap();
        let args = json!({});
        let mut request = ActionRequest::new("read_file", "c1", &args).with(Risk::ReadOnly);
        request.paths = vec![PathBuf::from("../outside")];
        let decision = policy.evaluate(&request, Path::new("/workspace"));
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.invariant.as_deref(), Some("I-Path-Safety"));
    }

    #[test]
    fn no_rule_is_default_deny() {
        let args = json!({});
        let decision =
            Policy::empty().evaluate(&ActionRequest::new("read_file", "c", &args), Path::new("/"));
        assert_eq!(decision.effect, Effect::Deny);
    }
}
