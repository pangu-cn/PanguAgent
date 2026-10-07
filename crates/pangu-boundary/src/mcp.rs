//! MCP server declarations and the operator-facing contract for them.
//!
//! # The declaration is the authorization
//!
//! An MCP server is an arbitrary program. Everything a server can do to this run
//! is decided **here**, by the operator, in configuration — never by the server
//! and never by the model:
//!
//! - The command and its arguments come only from configuration.
//! - Each server-local tool name is mapped to exactly one Pangu capability
//!   (risk class and effect). A tool with no mapping is **not advertised to the
//!   model at all**, so "the server added a tool" cannot widen anything.
//! - Unmapped tools are reported, not silently dropped: an operator who mistyped
//!   a name should see that their mapping did nothing.
//!
//! # Why the mapping cannot be inferred
//!
//! A server's `readOnlyHint` annotation is a claim by the party being
//! constrained. Deriving the risk class from it would let a server declare its
//! own authority — the single thing the boundary exists to prevent. The mapping
//! is therefore explicit, and a server whose tools are all unmapped contributes
//! nothing.
//!
//! # What an MCP server is not protected from
//!
//! Pangu cannot confine a child process from inside itself. A configured server
//! runs with the privileges Pangu has, and may read or write anything the
//! operating system allows it, regardless of what its tools are mapped to. The
//! mapping constrains what the **model** can invoke; it does not sandbox the
//! server. The honest statement is that installing an MCP server is a
//! trust decision about a program, and the declaration is where the operator
//! makes it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use pangu_core::{Error, Result};

/// One declared MCP server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServerSection {
    /// The command to run. Never taken from the model.
    pub command: String,
    /// Arguments passed to the command, verbatim.
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables to pass. **Nothing else is inherited**, so a server
    /// cannot read provider keys or tokens that were not meant for it.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Working directory, relative to the workspace. Defaults to the workspace
    /// root. Absolute paths are refused: a server should not start somewhere
    /// outside the project it serves.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Tool mappings: server-local tool name -> Pangu risk class.
    ///
    /// Only listed tools are exposed. The value is `read_only`, `reversible`,
    /// `destructive` or `needs_human`, matching the ordinary risk classes.
    #[serde(default)]
    pub tools: BTreeMap<String, String>,
    /// How long the handshake may take.
    #[serde(default = "default_handshake_secs")]
    pub handshake_secs: u64,
    /// How long one tool call may take.
    #[serde(default = "default_call_secs")]
    pub call_secs: u64,
    /// Optional human note recorded in the run's audit trail. Redacted and
    /// bounded like other operator-supplied text.
    #[serde(default)]
    pub description: Option<String>,
}

fn default_handshake_secs() -> u64 {
    20
}

fn default_call_secs() -> u64 {
    120
}

impl McpServerSection {
    pub fn timeouts(&self) -> Duration {
        Duration::from_secs(self.call_secs)
    }

    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.handshake_secs)
    }

    /// The `cwd` resolved against the workspace, refusing anything outside it.
    pub fn resolve_cwd(&self, workspace: &std::path::Path) -> Result<Option<PathBuf>> {
        let Some(raw) = self.cwd.as_deref() else {
            return Ok(None);
        };
        if raw.trim().is_empty() {
            return Ok(None);
        }
        let candidate = std::path::Path::new(raw);
        if candidate.is_absolute() {
            // A server started outside the project would serve files the rest
            // of the boundary has no way to reason about.
            return Err(Error::Config(format!(
                "MCP server `{raw}` cwd must be relative to the workspace, not absolute"
            )));
        }
        if candidate
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(Error::Config(format!(
                "MCP server cwd `{raw}` must not escape the workspace"
            )));
        }
        let resolved = workspace.join(candidate);
        // The directory must exist, or the child fails at spawn with a message
        // that does not say which server it came from.
        if !resolved.is_dir() {
            return Err(Error::Config(format!(
                "MCP server cwd `{raw}` is not a directory under the workspace"
            )));
        }
        Ok(Some(resolved))
    }

    /// Validate the declaration without starting anything.
    pub fn validate(&self, name: &str) -> Result<()> {
        if self.command.trim().is_empty() {
            return Err(Error::Config(format!(
                "MCP server `{name}` has an empty command"
            )));
        }
        if self.command.contains('\0') {
            return Err(Error::Config(format!(
                "MCP server `{name}` command contains a NUL byte"
            )));
        }
        for (key, value) in &self.env {
            if key.is_empty() || key.contains('=') || key.contains('\0') {
                return Err(Error::Config(format!(
                    "MCP server `{name}` has an invalid environment variable name `{key}`"
                )));
            }
            if value.contains('\0') {
                return Err(Error::Config(format!(
                    "MCP server `{name}` environment variable `{key}` contains a NUL byte"
                )));
            }
        }
        if self.handshake_secs == 0 || self.call_secs == 0 {
            return Err(Error::Config(format!(
                "MCP server `{name}` timeouts must be greater than zero"
            )));
        }
        for (tool, risk) in &self.tools {
            if tool.trim().is_empty() {
                return Err(Error::Config(format!(
                    "MCP server `{name}` has an empty tool name in its mapping"
                )));
            }
            // Parse now so a typo fails at startup rather than the first time
            // the model happens to call that tool.
            crate::Risk::parse(risk).map_err(|error| {
                Error::Config(format!(
                    "MCP server `{name}` maps tool `{tool}` to an invalid risk class: {error}"
                ))
            })?;
        }
        if let Some(description) = &self.description {
            if description.len() > 512 {
                return Err(Error::Config(format!(
                    "MCP server `{name}` description exceeds 512 bytes"
                )));
            }
            if description
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
            {
                return Err(Error::Config(format!(
                    "MCP server `{name}` description contains control characters"
                )));
            }
        }
        Ok(())
    }

    /// Resolve one tool's mapped risk class.
    pub fn risk_of(&self, tool: &str) -> Result<crate::Risk> {
        let raw = self.tools.get(tool).ok_or_else(|| {
            Error::Config(format!("MCP tool `{tool}` has no declared risk class"))
        })?;
        crate::Risk::parse(raw).map_err(|error| {
            Error::Config(format!(
                "MCP tool `{tool}` has an invalid risk class: {error}"
            ))
        })
    }
}

/// All declared MCP servers.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct McpSection {
    /// Server name -> declaration. The name is the prefix used in tool names
    /// the model sees, so it must be a safe identifier.
    #[serde(default)]
    pub servers: BTreeMap<String, McpServerSection>,
}

impl McpSection {
    /// Validate every server. Called at startup so a bad declaration fails
    /// before a run begins, rather than mid-turn.
    pub fn validate(&self) -> Result<()> {
        for (name, server) in &self.servers {
            validate_server_name(name)?;
            server.validate(name)?;
        }
        Ok(())
    }

    /// True when no server is declared, in which case nothing about the run
    /// changes.
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }
}

/// Server names become part of tool names, so they must be conservative.
///
/// A name with a separator or a space would produce an ambiguous tool name and
/// make the mapping between the model-visible name and the server-local name
/// lossy.
pub fn validate_server_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Config("MCP server name must not be empty".into()));
    }
    if name.len() > 64 {
        return Err(Error::Config(format!(
            "MCP server name `{name}` exceeds 64 bytes"
        )));
    }
    let valid = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !valid {
        return Err(Error::Config(format!(
            "MCP server name `{name}` may only contain ASCII letters, digits, `-` and `_`"
        )));
    }
    Ok(())
}

/// The separator between a server name and a tool name in model-visible names.
///
/// [`validate_server_name`] rejects this character inside a server name, and the
/// tool name is taken verbatim from the server, so the split is unambiguous.
pub const TOOL_NAMESPACE: char = '.';

/// Build the model-visible name for a server's tool.
pub fn namespaced_tool_name(server: &str, tool: &str) -> String {
    format!("{server}{TOOL_NAMESPACE}{tool}")
}

/// Split a model-visible name back into (server, tool).
///
/// Splits on the **first** separator, so a server-local tool name containing one
/// still round-trips exactly.
pub fn split_tool_name(name: &str) -> Option<(&str, &str)> {
    let (server, tool) = name.split_once(TOOL_NAMESPACE)?;
    if server.is_empty() || tool.is_empty() {
        return None;
    }
    Some((server, tool))
}

/// What a server contributed after discovery, for reporting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerReport {
    pub server: String,
    pub protocol_version: String,
    /// True when the server answered on a revision this client does not speak.
    pub version_mismatch: bool,
    /// Tools that were mapped and are therefore exposed to the model.
    pub exposed: Vec<String>,
    /// Tools the server advertised that the operator did not map. Reported so a
    /// mistyped mapping is visible rather than silent.
    pub unmapped: Vec<String>,
    /// Mapped names the server did not advertise, which is usually a stale
    /// mapping after a server upgrade.
    pub missing: Vec<String>,
}

impl ServerReport {
    /// Whether the mapping and the server agree exactly.
    pub fn is_exact(&self) -> bool {
        self.unmapped.is_empty() && self.missing.is_empty()
    }

    /// A one-line summary for the operator.
    pub fn summary(&self) -> String {
        let mut text = format!(
            "{} ({}): {} exposed",
            self.server,
            self.protocol_version,
            self.exposed.len()
        );
        if self.version_mismatch {
            text.push_str("; protocol version differs from this client");
        }
        if !self.unmapped.is_empty() {
            text.push_str(&format!(
                "; {} advertised but unmapped, not exposed ({})",
                self.unmapped.len(),
                self.unmapped.join(", ")
            ));
        }
        if !self.missing.is_empty() {
            text.push_str(&format!(
                "; {} mapped but not advertised ({})",
                self.missing.len(),
                self.missing.join(", ")
            ));
        }
        text
    }
}

/// Compare what a server advertised against what the operator mapped.
pub fn report_for(
    server: &str,
    protocol_version: &str,
    version_mismatch: bool,
    advertised: &[String],
    mapped: &BTreeMap<String, String>,
) -> ServerReport {
    let mut exposed: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for tool in mapped.keys() {
        if advertised.iter().any(|item| item == tool) {
            exposed.push(tool.clone());
        } else {
            missing.push(tool.clone());
        }
    }
    let unmapped: Vec<String> = advertised
        .iter()
        .filter(|tool| !mapped.contains_key(tool.as_str()))
        .cloned()
        .collect();
    exposed.sort();
    missing.sort();
    let mut unmapped = unmapped;
    unmapped.sort();
    ServerReport {
        server: server.to_string(),
        protocol_version: protocol_version.to_string(),
        version_mismatch,
        exposed,
        unmapped,
        missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn section(command: &str) -> McpServerSection {
        McpServerSection {
            command: command.to_string(),
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            tools: BTreeMap::new(),
            handshake_secs: 20,
            call_secs: 120,
            description: None,
        }
    }

    #[test]
    fn an_empty_command_is_refused() {
        assert!(section("  ").validate("s").is_err());
    }

    #[test]
    fn zero_timeouts_are_refused() {
        let mut server = section("node");
        server.call_secs = 0;
        assert!(server.validate("s").is_err());
    }

    #[test]
    fn an_invalid_risk_class_fails_at_startup_not_at_first_use() {
        let mut server = section("node");
        server.tools.insert("read".into(), "harmless".into());
        let error = server.validate("s").unwrap_err().to_string();
        assert!(error.contains("invalid risk class"), "{error}");
    }

    #[test]
    fn an_invalid_env_name_is_refused() {
        let mut server = section("node");
        server.env.insert("BAD=NAME".into(), "x".into());
        assert!(server.validate("s").is_err());
    }

    #[test]
    fn an_overlong_description_is_refused() {
        let mut server = section("node");
        server.description = Some("x".repeat(600));
        assert!(server.validate("s").is_err());
    }

    #[test]
    fn a_control_character_in_a_description_is_refused() {
        let mut server = section("node");
        server.description = Some("bad\u{7}text".into());
        assert!(server.validate("s").is_err());
    }

    #[test]
    fn risk_of_returns_the_mapped_class() {
        let mut server = section("node");
        server.tools.insert("read".into(), "read_only".into());
        assert_eq!(server.risk_of("read").unwrap(), crate::Risk::ReadOnly);
        assert!(server.risk_of("unmapped").is_err());
    }

    #[test]
    fn server_names_are_conservative() {
        assert!(validate_server_name("files").is_ok());
        assert!(validate_server_name("my-server_2").is_ok());
        // A separator inside the name would make tool names ambiguous.
        assert!(validate_server_name("my.server").is_err());
        assert!(validate_server_name("my server").is_err());
        assert!(validate_server_name("").is_err());
        assert!(validate_server_name(&"x".repeat(65)).is_err());
    }

    #[test]
    fn tool_names_round_trip_through_the_namespace() {
        let name = namespaced_tool_name("files", "read_file");
        assert_eq!(name, "files.read_file");
        assert_eq!(split_tool_name(&name), Some(("files", "read_file")));
    }

    #[test]
    fn a_tool_name_containing_separators_still_round_trips() {
        // The server-local name may itself contain dots; splitting on the first
        // separator keeps the mapping exact.
        let name = namespaced_tool_name("files", "read.file.v2");
        assert_eq!(split_tool_name(&name), Some(("files", "read.file.v2")));
    }

    #[test]
    fn a_name_without_a_separator_does_not_split() {
        assert!(split_tool_name("plain").is_none());
        assert!(split_tool_name(".leading").is_none());
        assert!(split_tool_name("trailing.").is_none());
    }

    #[test]
    fn unmapped_advertised_tools_are_reported_not_exposed() {
        let mut mapped = BTreeMap::new();
        mapped.insert("read_file".to_string(), "read_only".to_string());
        let advertised = vec!["read_file".to_string(), "delete_all".to_string()];
        let report = report_for("files", "2025-06-18", false, &advertised, &mapped);
        assert_eq!(report.exposed, vec!["read_file"]);
        // The server's extra tool is visible to the operator but not to the
        // model: a server cannot widen its own authority by advertising.
        assert_eq!(report.unmapped, vec!["delete_all"]);
        assert!(!report.is_exact());
        assert!(
            report.summary().contains("unmapped"),
            "{}",
            report.summary()
        );
    }

    #[test]
    fn a_stale_mapping_is_reported() {
        let mut mapped = BTreeMap::new();
        mapped.insert("old_tool".to_string(), "read_only".to_string());
        let advertised = vec!["new_tool".to_string()];
        let report = report_for("files", "2025-06-18", false, &advertised, &mapped);
        assert!(report.exposed.is_empty());
        assert_eq!(report.missing, vec!["old_tool"]);
        assert!(
            report.summary().contains("not advertised"),
            "{}",
            report.summary()
        );
    }

    #[test]
    fn an_exact_mapping_reports_no_drift() {
        let mut mapped = BTreeMap::new();
        mapped.insert("read_file".to_string(), "read_only".to_string());
        let advertised = vec!["read_file".to_string()];
        let report = report_for("files", "2025-06-18", false, &advertised, &mapped);
        assert!(report.is_exact());
        assert!(!report.summary().contains("unmapped"));
    }

    #[test]
    fn a_version_mismatch_appears_in_the_summary() {
        let report = report_for("files", "2024-11-05", true, &[], &BTreeMap::new());
        assert!(report.summary().contains("differs"), "{}", report.summary());
    }

    #[test]
    fn an_absolute_cwd_is_refused() {
        let mut server = section("node");
        server.cwd = Some("C:\\elsewhere".into());
        let root = std::env::temp_dir();
        assert!(server.resolve_cwd(&root).is_err());
    }

    #[test]
    fn a_cwd_that_escapes_the_workspace_is_refused() {
        let mut server = section("node");
        server.cwd = Some("../outside".into());
        let root = std::env::temp_dir();
        assert!(server.resolve_cwd(&root).is_err());
    }

    #[test]
    fn an_mcp_section_with_no_servers_changes_nothing() {
        let section = McpSection::default();
        assert!(section.is_empty());
        assert!(section.validate().is_ok());
    }

    #[test]
    fn a_bad_server_name_fails_the_whole_section() {
        let mut section = McpSection::default();
        section
            .servers
            .insert("bad name".into(), section_of("node"));
        assert!(section.validate().is_err());
    }

    fn section_of(command: &str) -> McpServerSection {
        section(command)
    }
}
