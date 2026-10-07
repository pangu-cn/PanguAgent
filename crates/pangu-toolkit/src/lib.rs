//! Built-in tools. Every executor is an adapter around the Agent capability
//! protocol; no public method accepts an unverified model call for execution.

pub mod browser;
pub mod mcp_executor;
pub mod mcp_stdio;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt};

use pangu_agent::{
    Capability, CapabilityManifest, EffectDescriptor, EffectScope, Reversibility, ToolAssessment,
    ToolExecutor, ToolOutput, VerifiedAction,
};
use pangu_boundary::{Risk, Sandbox};
use pangu_core::{short_hash, MemoryStore, SkillRegistry, ToolCall, ToolSpec};

const MAX_SEARCH_RESULTS: usize = 200;
const MAX_SEARCH_ENTRIES: usize = 10_000;
const MAX_LIST_ENTRIES: usize = 10_000;

#[derive(Clone, Default)]
pub struct Toolkit {
    /// F3: the operator-configured verification command. Empty = the verify
    /// tool is not advertised and every call to it is rejected, exactly as if
    /// F3 were not compiled in.
    verify_command: Vec<String>,
    /// B3: the controlled memory candidate queue. `None` = the
    /// `propose_memory` tool does not exist, exactly as if B3 were not
    /// compiled in.
    memory: Option<std::sync::Arc<MemoryStore>>,
    /// B2: the skill registry. `None` = the `read_skill` tool does not
    /// exist, exactly as if B2 were not compiled in.
    skills: Option<std::sync::Arc<SkillRegistry>>,
    /// F8: the resolved OS-level sandbox runtime. `None` means no runtime was
    /// declared, which is the `local` profile: commands run on the host exactly
    /// as before.
    ///
    /// When present this is **enforced**: an unusable runtime refuses the
    /// command instead of falling back to the host. Preventing that fallback is
    /// the reason this field exists.
    runtime: Option<std::sync::Arc<pangu_boundary::runtime::Runtime>>,
    /// F9: the browser session, when a browser is configured.
    ///
    /// `None` means the browser tools do not exist, exactly as if F9 were not
    /// compiled in — the same discipline as `memory` and `skills`. A tool that
    /// is advertised but cannot run is worse than an absent one.
    browser: Option<std::sync::Arc<browser::BrowserSlot>>,
    /// F9: the resolved browser configuration.
    browser_config: Option<std::sync::Arc<pangu_boundary::browser::BrowserConfig>>,
    /// F9: where screenshots are written, inside the writable boundary.
    browser_artifact_dir: Option<std::sync::Arc<PathBuf>>,
}

impl Toolkit {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a toolkit whose `verify` tool runs exactly this argv. The command
    /// comes from `[verify] command` in the config, never from model output;
    /// the model can only trigger it as a whole.
    pub fn with_verify_command(command: Vec<String>) -> Self {
        Self {
            verify_command: command,
            memory: None,
            skills: None,
            runtime: None,
            browser: None,
            browser_config: None,
            browser_artifact_dir: None,
        }
    }

    /// B3: attach the memory candidate queue. The model can only *propose*
    /// through it; acceptance, rejection, and revocation are operator-only
    /// CLI actions outside any run.
    pub fn with_memory(mut self, store: std::sync::Arc<MemoryStore>) -> Self {
        self.memory = Some(store);
        self
    }

    /// B2: attach the skill registry. The model can only read a skill's
    /// instruction document; scripts are registered but never executed.
    pub fn with_skills(mut self, registry: std::sync::Arc<SkillRegistry>) -> Self {
        self.skills = Some(registry);
        self
    }

    /// F8: attach a resolved sandbox runtime.
    ///
    /// Callers pass the result of `RuntimeConfig::resolve`, which has already
    /// probed. An attached runtime that turns out to be unusable makes every
    /// command **fail** rather than run on the host.
    pub fn with_runtime(
        mut self,
        runtime: std::sync::Arc<pangu_boundary::runtime::Runtime>,
    ) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// F8: the attached runtime, if any.
    pub fn runtime(&self) -> Option<&std::sync::Arc<pangu_boundary::runtime::Runtime>> {
        self.runtime.as_ref()
    }

    /// F9: attach a browser.
    ///
    /// Until this is called the browser tools are **not advertised at all**:
    /// a model cannot call a capability the operator did not enable, and an
    /// operator who did not configure a browser should not see browser tools in
    /// the list.
    ///
    /// `artifact_dir` receives screenshots. It must be inside a writable root,
    /// so screenshots are covered by the same rules as every other run artifact.
    pub fn with_browser(
        mut self,
        config: pangu_boundary::browser::BrowserConfig,
        artifact_dir: PathBuf,
    ) -> Self {
        self.browser = Some(std::sync::Arc::new(browser::BrowserSlot::new()));
        self.browser_config = Some(std::sync::Arc::new(config));
        self.browser_artifact_dir = Some(std::sync::Arc::new(artifact_dir));
        self
    }

    /// F9: whether a browser is configured.
    pub fn has_browser(&self) -> bool {
        self.browser.is_some()
    }

    /// F9: whether a browser session is currently open.
    pub fn browser_is_open(&self) -> bool {
        self.browser
            .as_ref()
            .map(|slot| slot.is_open())
            .unwrap_or(false)
    }

    /// F9: close the browser session, releasing the process and its profile.
    ///
    /// Called at the end of a run so a headless browser is not left holding a
    /// profile directory and a port into the next run.
    pub fn close_browser(&self) {
        if let Some(slot) = &self.browser {
            slot.close();
        }
    }

    /// B3: the memory store handle, if attached.
    pub fn memory_store(&self) -> Option<&std::sync::Arc<MemoryStore>> {
        self.memory.as_ref()
    }

    /// B1: the static declaration of every capability this toolkit can
    /// dispatch. `specs()` and `manifest()` must stay in lockstep — a test
    /// asserts that the names match 1:1.
    pub fn manifest(&self) -> CapabilityManifest {
        let empty = || Vec::new();
        let mut capabilities = vec![
            Capability {
                name: "read_file".into(),
                version: "1".into(),
                risk: Risk::ReadOnly,
                effect: EffectDescriptor::new(EffectScope::Workspace, Reversibility::NoEffect),
                reads: vec!["workspace".into()],
                writes: empty(),
                hosts: empty(),
                processes: empty(),
                timeout_ms: None,
            },
            Capability {
                name: "list_dir".into(),
                version: "1".into(),
                risk: Risk::ReadOnly,
                effect: EffectDescriptor::new(EffectScope::Workspace, Reversibility::NoEffect),
                reads: vec!["workspace".into()],
                writes: empty(),
                hosts: empty(),
                processes: empty(),
                timeout_ms: None,
            },
            Capability {
                name: "search".into(),
                version: "1".into(),
                risk: Risk::ReadOnly,
                effect: EffectDescriptor::new(EffectScope::Workspace, Reversibility::NoEffect),
                reads: vec!["workspace".into()],
                writes: empty(),
                hosts: empty(),
                processes: empty(),
                timeout_ms: None,
            },
            Capability {
                name: "write_file".into(),
                version: "1".into(),
                risk: Risk::Reversible,
                effect: EffectDescriptor::new(EffectScope::Workspace, Reversibility::Reversible),
                reads: vec!["workspace".into()],
                writes: vec!["workspace".into()],
                hosts: empty(),
                processes: empty(),
                timeout_ms: None,
            },
            Capability {
                name: "http_fetch".into(),
                version: "1".into(),
                risk: Risk::NeedsHuman,
                effect: EffectDescriptor::new(EffectScope::ExternalRead, Reversibility::NoEffect),
                reads: empty(),
                writes: empty(),
                hosts: vec!["allowlisted".into()],
                processes: empty(),
                timeout_ms: None,
            },
            Capability {
                name: "finish".into(),
                version: "1".into(),
                risk: Risk::ReadOnly,
                effect: EffectDescriptor::new(EffectScope::Session, Reversibility::NoEffect),
                reads: empty(),
                writes: empty(),
                hosts: empty(),
                processes: empty(),
                timeout_ms: None,
            },
            Capability {
                name: "git_diff".into(),
                version: "1".into(),
                risk: Risk::ReadOnly,
                effect: EffectDescriptor::new(EffectScope::ProcessRead, Reversibility::NoEffect),
                reads: vec!["workspace".into()],
                writes: Vec::new(),
                hosts: Vec::new(),
                processes: vec!["git".into()],
                timeout_ms: None,
            },
            Capability {
                name: "run_command".into(),
                version: "1".into(),
                risk: Risk::NeedsHuman,
                effect: EffectDescriptor::new(EffectScope::ProcessRead, Reversibility::NoEffect),
                reads: empty(),
                writes: empty(),
                hosts: empty(),
                processes: vec!["allowlisted".into()],
                timeout_ms: None,
            },
        ];
        // F3: the verify capability mirrors the configured command. It exists
        // in the manifest only when the operator configured one, keeping the
        // manifest in lockstep with `specs()`.
        if !self.verify_command.is_empty() {
            capabilities.push(Capability {
                name: "verify".into(),
                version: "1".into(),
                risk: Risk::NeedsHuman,
                effect: EffectDescriptor::new(EffectScope::ProcessRead, Reversibility::NoEffect),
                reads: empty(),
                writes: empty(),
                hosts: empty(),
                processes: vec![self.verify_command[0].clone()],
                timeout_ms: None,
            });
        }
        // B3: proposing a memory only appends an inert pending candidate —
        // nothing reads it into a prompt until an operator accepts it, and it
        // can be rejected. The write target is Pangu-owned storage that is
        // excluded from every generic tool I/O path.
        if self.memory.is_some() {
            capabilities.push(Capability {
                name: "propose_memory".into(),
                version: "1".into(),
                risk: Risk::Reversible,
                effect: EffectDescriptor::new(EffectScope::Workspace, Reversibility::Reversible),
                reads: empty(),
                writes: vec![".pangu/memory/candidates.json".into()],
                hosts: empty(),
                processes: empty(),
                timeout_ms: None,
            });
        }
        // B2: read_skill reads one installed skill's instruction document.
        // The registry lives under the `.pangu` forbidden glob; the tool's
        // read target comes from operator-installed state, never from model
        // output.
        if self.skills.is_some() {
            capabilities.push(Capability {
                name: "read_skill".into(),
                version: "1".into(),
                risk: Risk::ReadOnly,
                effect: EffectDescriptor::new(EffectScope::Workspace, Reversibility::NoEffect),
                reads: vec![".pangu/skills".into()],
                writes: empty(),
                hosts: empty(),
                processes: empty(),
                timeout_ms: None,
            });
        }
        // F9: the browser tools exist only when a browser is configured, and
        // the manifest is the declared capability surface. Omitting them here
        // while `specs()` advertises them makes the declaration deny five
        // tools the model can actually call.
        if self.browser.is_some() {
            capabilities.extend([
                Capability {
                    name: "browser_open".into(),
                    version: "1".into(),
                    risk: Risk::NeedsHuman,
                    effect: EffectDescriptor::new(
                        EffectScope::ExternalRead,
                        Reversibility::NoEffect,
                    ),
                    reads: empty(),
                    writes: empty(),
                    hosts: vec!["allowlisted".into()],
                    processes: vec!["browser".into()],
                    timeout_ms: None,
                },
                Capability {
                    name: "browser_read".into(),
                    version: "1".into(),
                    risk: Risk::ReadOnly,
                    effect: EffectDescriptor::new(
                        EffectScope::ProcessRead,
                        Reversibility::NoEffect,
                    ),
                    reads: empty(),
                    writes: empty(),
                    hosts: empty(),
                    processes: vec!["browser".into()],
                    timeout_ms: None,
                },
                Capability {
                    name: "browser_screenshot".into(),
                    version: "1".into(),
                    risk: Risk::Reversible,
                    effect: EffectDescriptor::new(
                        EffectScope::Workspace,
                        Reversibility::Reversible,
                    ),
                    reads: empty(),
                    writes: vec!["artifact".into()],
                    hosts: empty(),
                    processes: empty(),
                    timeout_ms: None,
                },
                Capability {
                    name: "browser_click".into(),
                    version: "1".into(),
                    risk: Risk::NeedsHuman,
                    effect: EffectDescriptor::new(
                        EffectScope::ExternalMutation,
                        Reversibility::Irreversible,
                    ),
                    reads: empty(),
                    writes: empty(),
                    hosts: empty(),
                    processes: vec!["browser".into()],
                    timeout_ms: None,
                },
                Capability {
                    name: "browser_type".into(),
                    version: "1".into(),
                    risk: Risk::NeedsHuman,
                    effect: EffectDescriptor::new(
                        EffectScope::ExternalMutation,
                        Reversibility::Irreversible,
                    ),
                    reads: empty(),
                    writes: empty(),
                    hosts: empty(),
                    processes: vec!["browser".into()],
                    timeout_ms: None,
                },
            ]);
        }
        CapabilityManifest::new(capabilities)
    }

    /// F9: the risk and effect of a browser action.
    ///
    /// `browser_open` is the interesting case: it is an **outbound network
    /// action**, so it declares its host exactly as `http_fetch` does. Without
    /// that, the network boundary would never see where the browser went, and a
    /// page could be loaded from a host the operator never allowed.
    ///
    /// `browser_click` and `browser_type` are **not** read-only: the page
    /// decides what a click does, so classifying them as observations would let
    /// a state-changing action skip the human gate.
    ///
    /// # Why these are `NeedsHuman` + `Irreversible`
    ///
    /// This pairing is load-bearing, and getting it wrong made both tools
    /// unrunnable. `pangu-agent` validates every assessment through
    /// `EffectDescriptor::validate_for_risk` before Policy or Approval see it,
    /// and that rule is: an `ExternalMutation` must be `Irreversible` and must
    /// carry at least `Destructive` risk.
    ///
    /// These tools were originally declared `Reversible` on both axes. Both
    /// halves of that were rejected, so `browser_click` and `browser_type`
    /// failed on **every** call with `external_mutation must be paired with
    /// irreversible`. The tools were still advertised to the model, so it looked
    /// like a tool that errors rather than a capability that cannot run.
    ///
    /// The classification is also the honest one. A click is not reversible by
    /// this program: it cannot undo a submitted form, a placed order, or a
    /// deleted record, because the resulting state lives on a server the
    /// boundary does not control and may never observe. "Reversible" would claim
    /// an ability to restore that no code here has, and would additionally
    /// suggest the action needs less scrutiny than `browser_open`, which only
    /// fetches. `NeedsHuman` is what makes the human gate unconditional, exactly
    /// as it is for `run_command`.
    fn assess_browser(&self, call: &ToolCall, sandbox: &Sandbox) -> Result<ToolAssessment> {
        // The effect kind decides the branch; whether a host is declared is
        // expressed by declaring one below, not by a flag checked separately.
        let (kind, _) = browser::describe(&call.name)
            .ok_or_else(|| anyhow!("`{}` is not a browser tool", call.name))?;
        if self.browser.is_none() {
            // The spec is not advertised in this case, so reaching here means a
            // caller invented the tool name.
            bail!(
                "`{}` is not available: no browser is configured ([browser] enabled)",
                call.name
            );
        }

        match kind {
            "read" => {
                ensure_allowed_keys(&call.args, &[])?;
                // A screenshot is not an observation in the effect ledger: it
                // writes a PNG into the run's artifact directory. Calling that
                // `NoEffect` would let a write skip the reversible-write gate
                // while the manifest, which records the write, says otherwise.
                if call.name == "browser_screenshot" {
                    let artifact_dir = self
                        .browser_artifact_dir
                        .as_ref()
                        .ok_or_else(|| anyhow!("browser_screenshot has no artifact directory"))?;
                    // The PNG name is chosen at execution time. Declaring the
                    // directory makes the write checker look for its parent,
                    // which does not exist on the first screenshot. A placeholder
                    // file inside the configured directory checks that directory
                    // against the writable roots instead.
                    Ok(ToolAssessment::new(Risk::Reversible)
                        .with_effect(EffectDescriptor::new(
                            EffectScope::Workspace,
                            Reversibility::Reversible,
                        ))
                        .write(artifact_dir.as_ref().join("screenshot.png")))
                } else {
                    let mut assessment = ToolAssessment::new(Risk::ReadOnly).with_effect(
                        EffectDescriptor::new(EffectScope::ProcessRead, Reversibility::NoEffect),
                    );
                    // Reading the page uses the browser session the operator
                    // enabled. ProcessRead requires a named resource; without
                    // one, validate_effect rejects every browser_read.
                    assessment.browser_session = true;
                    Ok(assessment)
                }
            }
            "external_mutation" => {
                let mut assessment =
                    ToolAssessment::new(Risk::NeedsHuman).with_effect(EffectDescriptor::new(
                        EffectScope::ExternalMutation,
                        Reversibility::Irreversible,
                    ));
                assessment.browser_session = true;
                match call.name.as_str() {
                    "browser_click" => {
                        ensure_allowed_keys(&call.args, &["selector"])?;
                        let selector = browser::required_selector(&call.args)?;
                        assessment.preview = format!("click {selector}");
                    }
                    _ => {
                        ensure_allowed_keys(&call.args, &["text"])?;
                        let text = required_string(&call.args, "text")?;
                        // The text is previewed in a bounded, redacted form: it
                        // can contain anything, including a secret the operator
                        // would not expect to see echoed into a journal.
                        assessment.preview = format!("type {:?}", truncate_preview(&text, 200));
                    }
                }
                Ok(assessment)
            }
            "external_read" => {
                ensure_allowed_keys(&call.args, &["url"])?;
                let url = required_string(&call.args, "url")?;
                sandbox
                    .check_url(&url)
                    .map_err(|error| anyhow!("browser URL rejected: {error}"))?;
                let host = browser::navigation_host(&url)?;
                // Validate the host through the same boundary `http_fetch`
                // uses: navigation is an outbound request.
                sandbox.check_host(&host)?;
                let mut assessment = ToolAssessment::new(Risk::NeedsHuman)
                    .with_effect(EffectDescriptor::new(
                        EffectScope::ExternalRead,
                        Reversibility::NoEffect,
                    ))
                    .host(host);
                assessment.preview = format!("GET {} (browser)", url_preview(&url));
                Ok(assessment)
            }
            other => bail!("unhandled browser effect kind `{other}`"),
        }
    }

    /// F9: run a browser action against the session.
    ///
    /// The session is opened lazily on first use and kept for the rest of the
    /// run: a session per call would lose the page between a click and the read
    /// that follows it, and that sequence is what computer use consists of.
    fn execute_browser(&self, action: &VerifiedAction) -> Result<ToolOutput> {
        let slot = self
            .browser
            .as_ref()
            .ok_or_else(|| anyhow!("no browser is configured"))?;
        let config = self
            .browser_config
            .as_ref()
            .ok_or_else(|| anyhow!("no browser is configured"))?;
        let artifact_dir = self
            .browser_artifact_dir
            .as_ref()
            .ok_or_else(|| anyhow!("no browser artifact directory is configured"))?;

        let name = action.call().name.as_str();
        let args = action.call().args.clone();

        let outcome = slot.with(
            config,
            self.runtime.as_deref(),
            artifact_dir.as_ref().clone(),
            |handle| match name {
                "browser_open" => {
                    let url = required_string(&args, "url")?;
                    browser::require_navigation_url(
                        &url,
                        |url| {
                            action
                                .sandbox()
                                .check_url(url)
                                .map(|_| ())
                                .map_err(|error| anyhow!(error))
                        },
                        &action.resources().hosts,
                    )?;
                    let session = handle.session()?;
                    session.navigate(&url)?;
                    // Returning the page immediately saves a round trip: an
                    // `open` that yielded only "ok" would oblige the model to
                    // read next, doubling the calls for the common case.
                    let snapshot = session.snapshot()?;
                    // The requested host was checked before navigation. A redirect
                    // can land somewhere else, so the page actually reached must
                    // pass the same egress check before its content is returned.
                    require_current_page(action, &snapshot.url)?;
                    Ok(browser::output(
                        browser::render_snapshot(
                            &snapshot.url,
                            &snapshot.title,
                            &snapshot.text,
                            snapshot.truncated,
                        ),
                        Some(format!("navigated to {}", snapshot.url)),
                    ))
                }
                "browser_read" => {
                    let session = handle.session()?;
                    let snapshot = session.snapshot()?;
                    require_current_page(action, &snapshot.url)?;
                    Ok(browser::output(
                        browser::render_snapshot(
                            &snapshot.url,
                            &snapshot.title,
                            &snapshot.text,
                            snapshot.truncated,
                        ),
                        None,
                    ))
                }
                "browser_screenshot" => {
                    let session = handle.session()?;
                    require_current_page(action, &session.snapshot()?.url)?;
                    let path = artifact_dir.as_ref().join("screenshot.png");
                    browser::require_validated_screenshot_path(
                        &path,
                        &action.resources().write_paths,
                    )?;
                    let png = session.screenshot()?;
                    let bytes = png.len();
                    let name = handle.save_screenshot(&png)?;
                    Ok(browser::output(
                        format!("screenshot saved as {name} ({bytes} bytes, PNG)"),
                        // The evidence is the file that now exists, not a claim
                        // that a capture happened.
                        Some(format!("screenshot:{name}:{bytes}")),
                    ))
                }
                "browser_click" => {
                    let selector = browser::required_selector(&args)?;
                    let session = handle.session()?;
                    session.click(&selector)?;
                    Ok(browser::output(
                        format!("clicked {selector}"),
                        Some(format!("clicked:{selector}")),
                    ))
                }
                "browser_type" => {
                    let text = required_string(&args, "text")?;
                    let session = handle.session()?;
                    session.type_text(&text)?;
                    Ok(browser::output(
                        format!("typed {} characters", text.chars().count()),
                        Some(format!("typed:{}", text.chars().count())),
                    ))
                }
                other => bail!("`{other}` has no browser handler"),
            },
        );
        if let Err(error) = &outcome {
            if browser::page_must_not_remain_open(error) {
                // A refused page must not stay available to the next browser
                // action. This covers redirects from open/read/screenshot as
                // well as navigation caused by click or typing.
                slot.close();
            }
        } else if matches!(name, "browser_click" | "browser_type") {
            match slot.with_open(|handle| {
                let url = handle.session()?.snapshot()?.url;
                require_current_page(action, &url)
            }) {
                Ok(()) => {}
                Err(error) if browser::page_must_not_remain_open(&error) => {
                    slot.close();
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }
        outcome
    }
}

#[async_trait]
impl ToolExecutor for Toolkit {
    fn specs(&self) -> Vec<ToolSpec> {
        let mut specs = vec![
            ToolSpec::new(
                "read_file",
                "Read a UTF-8 file inside the readable boundary.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["path"],
                    "properties": {"path": {"type": "string"}}
                }),
            ),
            ToolSpec::new(
                "list_dir",
                "List one directory inside the readable boundary.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["path"],
                    "properties": {"path": {"type": "string"}}
                }),
            ),
            ToolSpec::new(
                "search",
                "Search UTF-8 files under a directory for a literal string.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["path", "query"],
                    "properties": {"path": {"type": "string"}, "query": {"type": "string", "minLength": 1}}
                }),
            ),
            ToolSpec::new(
                "write_file",
                "Create or replace a UTF-8 file inside a writable root.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["path", "content"],
                    "properties": {"path": {"type": "string"}, "content": {"type": "string"}}
                }),
            ),
            ToolSpec::new(
                "http_fetch",
                "Perform a bounded HTTP GET to an allow-listed host.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["url"],
                    "properties": {"url": {"type": "string", "format": "uri"}}
                }),
            ),
            ToolSpec::new(
                "finish",
                "Finish the run with complete, failed, needs_input, or aborted status.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["status"],
                    "properties": {"status": {"type": "string", "enum": ["complete", "failed", "needs_input", "aborted"]}}
                }),
            ),
            ToolSpec::new(
                "git_diff",
                "Show the working-tree or staged diff of the workspace (read-only git).",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "staged": {"type": "boolean"},
                        "path": {"type": "string"}
                    }
                }),
            ),
            ToolSpec::new(
                "run_command",
                "Run one allow-listed read-only command without a shell.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["command"],
                    "properties": {
                        "command": {"type": "string"},
                        "args": {"type": "array", "items": {"type": "string"}}
                    }
                }),
            ),
        ];
        // F3: advertise the verify tool only when the operator configured a
        // command. The model gets no arguments to control: it can trigger the
        // configured command as a whole, never change it.
        if !self.verify_command.is_empty() {
            specs.push(ToolSpec::new(
                "verify",
                "Run the operator-configured verification command (e.g. lint/test/compile) and return its output and exit status.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": [],
                    "properties": {}
                }),
            ));
        }
        // B2: advertise read_skill only when the registry is attached.
        if self.skills.is_some() {
            specs.push(ToolSpec::new(
                "read_skill",
                "Read the instruction document (SKILL.md) of one installed skill by name.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["name"],
                    "properties": {"name": {"type": "string", "minLength": 1}}
                }),
            ));
        }
        // B3: advertise the memory proposal tool only when the operator
        // enabled the queue. Proposals are inert until an operator accepts
        // them through the CLI.
        if self.memory.is_some() {
            specs.push(ToolSpec::new(
                "propose_memory",
                "Propose a memory candidate for the operator to review. It is NOT written into any prompt until the operator accepts it, and it never changes permissions or boundaries.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["content"],
                    "properties": {
                        "content": {"type": "string", "minLength": 1},
                        "kind": {"type": "string", "description": "short slug like note/preference/lesson"}
                    }
                }),
            ));
        }
        // F9: advertise the browser tools only when the operator configured a
        // browser. Until then they do not exist, so the model cannot call a
        // capability that was never enabled.
        if self.browser.is_some() {
            for name in browser::BROWSER_TOOLS {
                let (description, schema) = browser::description(name)
                    .zip(browser::schema(name))
                    .unwrap_or_else(|| {
                        unreachable!("every browser tool has a description and a schema")
                    });
                specs.push(ToolSpec::new(name, description, schema));
            }
        }
        specs
    }

    fn verify_command(&self) -> Vec<String> {
        self.verify_command.clone()
    }

    async fn assess(&self, call: &ToolCall, sandbox: &Sandbox) -> Result<ToolAssessment> {
        match call.name.as_str() {
            "read_file" => {
                ensure_allowed_keys(&call.args, &["path"])?;
                let path = required_path(&call.args, "path")?;
                let mut assessment = ToolAssessment::new(Risk::ReadOnly)
                    .with_effect(EffectDescriptor::new(
                        EffectScope::Workspace,
                        Reversibility::NoEffect,
                    ))
                    .read(path.clone());
                assessment.preview = format!("read {}", path.display());
                let _ = sandbox;
                Ok(assessment)
            }
            "list_dir" => {
                ensure_allowed_keys(&call.args, &["path"])?;
                let path = required_path(&call.args, "path")?;
                let mut assessment = ToolAssessment::new(Risk::ReadOnly)
                    .with_effect(EffectDescriptor::new(
                        EffectScope::Workspace,
                        Reversibility::NoEffect,
                    ))
                    .read(path.clone());
                assessment.preview = format!("list {}", path.display());
                Ok(assessment)
            }
            "search" => {
                ensure_allowed_keys(&call.args, &["path", "query"])?;
                let path = required_path(&call.args, "path")?;
                let query = required_string(&call.args, "query")?;
                if query.len() > 512 {
                    bail!("search query is too long");
                }
                let mut assessment = ToolAssessment::new(Risk::ReadOnly)
                    .with_effect(EffectDescriptor::new(
                        EffectScope::Workspace,
                        Reversibility::NoEffect,
                    ))
                    .read(path.clone());
                assessment.preview = format!(
                    "search {} query_sha256={}",
                    path.display(),
                    short_hash(&query)
                );
                Ok(assessment)
            }
            "write_file" => {
                ensure_allowed_keys(&call.args, &["path", "content"])?;
                let path = required_path(&call.args, "path")?;
                let content = required_string(&call.args, "content")?;
                if content.len() > sandbox.max_write_bytes {
                    bail!("write content exceeds configured limit");
                }
                let mut assessment = ToolAssessment::new(Risk::Reversible)
                    .with_effect(EffectDescriptor::new(
                        EffectScope::Workspace,
                        Reversibility::Reversible,
                    ))
                    .write(path.clone());
                assessment.preview = format!(
                    "write {} bytes={} sha256={}",
                    path.display(),
                    content.len(),
                    short_hash(&content)
                );
                Ok(assessment)
            }
            "http_fetch" => {
                ensure_allowed_keys(&call.args, &["url"])?;
                let url = required_string(&call.args, "url")?;
                if url.len() > 2_048 {
                    bail!("URL is too long");
                }
                // Assessment is side-effect free: parse the authority here,
                // but defer DNS/egress resolution to L3 after policy.
                let parsed = url::Url::parse(&url).map_err(|_| anyhow!("invalid URL"))?;
                if parsed.scheme() != "http" && parsed.scheme() != "https" {
                    bail!("URL must use http or https");
                }
                if !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || parsed.fragment().is_some()
                {
                    bail!("URL must not contain credentials or a fragment");
                }
                if parsed.port() == Some(0) {
                    bail!("URL must not use port zero");
                }
                let host_name = parsed
                    .host_str()
                    .ok_or_else(|| anyhow!("URL has no host"))?
                    .to_ascii_lowercase();
                let port = parsed.port_or_known_default().unwrap_or(443);
                let host = if host_name.contains(':') {
                    format!("[{host_name}]:{port}")
                } else {
                    format!("{host_name}:{port}")
                };
                let mut assessment = ToolAssessment::new(Risk::NeedsHuman)
                    .with_effect(EffectDescriptor::new(
                        EffectScope::ExternalRead,
                        Reversibility::NoEffect,
                    ))
                    .host(host);
                assessment.preview = format!("GET {}", url_preview(&url));
                Ok(assessment)
            }
            "run_command" => {
                ensure_allowed_keys(&call.args, &["command", "args"])?;
                let command = required_string(&call.args, "command")?;
                let args = optional_string_array(&call.args, "args")?;
                let mut argv = vec![command.clone()];
                argv.extend(args.iter().cloned());
                sandbox.validate_argv(&argv)?;
                let mut assessment = ToolAssessment::new(Risk::NeedsHuman).with_effect(
                    EffectDescriptor::new(EffectScope::ProcessRead, Reversibility::NoEffect),
                );
                for path in command_read_paths(&command, &args)? {
                    assessment = assessment.read(path);
                }
                assessment.argv = argv.clone();
                assessment.preview = format!(
                    "run {} args_sha256={}",
                    argv.first().map(String::as_str).unwrap_or_default(),
                    short_hash(&argv.iter().skip(1).cloned().collect::<Vec<_>>().join(" "))
                );
                Ok(assessment)
            }
            "verify" => {
                // The model gets no arguments to control: any key is a
                // rejection. The argv is the contract-frozen configured one.
                ensure_allowed_keys(&call.args, &[])?;
                if self.verify_command.is_empty() {
                    bail!("verify tool is not configured");
                }
                sandbox.validate_argv(&self.verify_command)?;
                let mut assessment = ToolAssessment::new(Risk::NeedsHuman).with_effect(
                    EffectDescriptor::new(EffectScope::ProcessRead, Reversibility::NoEffect),
                );
                assessment.argv = self.verify_command.clone();
                assessment.preview = format!(
                    "verify {} args_sha256={}",
                    self.verify_command[0],
                    short_hash(&self.verify_command[1..].join(" "))
                );
                Ok(assessment)
            }
            "read_skill" => {
                ensure_allowed_keys(&call.args, &["name"])?;
                let registry = self
                    .skills
                    .as_ref()
                    .ok_or_else(|| anyhow!("read_skill tool is not configured"))?;
                let name = required_string(&call.args, "name")?;
                if name.len() > 64 {
                    bail!("skill name is too long");
                }
                let mut assessment = ToolAssessment::new(Risk::ReadOnly).with_effect(
                    EffectDescriptor::new(EffectScope::Workspace, Reversibility::NoEffect),
                );
                assessment = assessment.read(registry.dir().to_path_buf());
                assessment.preview = format!("read_skill name={}", name);
                Ok(assessment)
            }
            "propose_memory" => {
                ensure_allowed_keys(&call.args, &["content", "kind"])?;
                let store = self
                    .memory
                    .as_ref()
                    .ok_or_else(|| anyhow!("propose_memory tool is not configured"))?;
                let content = required_string(&call.args, "content")?;
                let kind = call
                    .args
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("note");
                let mut assessment = ToolAssessment::new(Risk::Reversible).with_effect(
                    EffectDescriptor::new(EffectScope::Workspace, Reversibility::Reversible),
                );
                // The write target is the store's own file — the same file
                // every generic tool I/O path is forbidden to touch.
                assessment = assessment.write(store.path().to_path_buf());
                // Preview carries the digest, never the raw content: the
                // content is model text and may contain secrets.
                assessment.preview = format!(
                    "propose_memory kind={} bytes={} sha256={}",
                    kind,
                    content.len(),
                    short_hash(&content)
                );
                Ok(assessment)
            }
            "git_diff" => {
                ensure_allowed_keys(&call.args, &["staged", "path"])?;
                let staged = call
                    .args
                    .get("staged")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let mut argv = vec!["git".to_string(), "diff".to_string()];
                if staged {
                    argv.push("--cached".to_string());
                }
                let mut assessment = ToolAssessment::new(Risk::ReadOnly).with_effect(
                    EffectDescriptor::new(EffectScope::ProcessRead, Reversibility::NoEffect),
                );
                if let Some(path) = call.args.get("path").and_then(Value::as_str) {
                    if path.is_empty() || path.contains("..") || path.starts_with('/') {
                        bail!("path must be a relative in-workspace path");
                    }
                    argv.push("--".to_string());
                    argv.push(path.to_string());
                    assessment = assessment.read(PathBuf::from(path));
                }
                sandbox.validate_argv(&argv)?;
                assessment.argv = argv.clone();
                assessment.preview = format!(
                    "git diff{}{}",
                    if staged { " --cached" } else { "" },
                    call.args
                        .get("path")
                        .and_then(Value::as_str)
                        .map(|p| format!(" -- {p}"))
                        .unwrap_or_default()
                );
                Ok(assessment)
            }
            name if browser::is_browser_tool(name) => self.assess_browser(call, sandbox),
            other => bail!("unknown tool `{other}`"),
        }
    }

    async fn execute(&self, action: &VerifiedAction) -> Result<ToolOutput> {
        match action.call().name.as_str() {
            "read_file" => execute_read(action).await,
            "list_dir" => execute_list(action).await,
            "search" => execute_search(action).await,
            "write_file" => execute_write(action).await,
            "http_fetch" => execute_http(action).await,
            "git_diff" => execute_command(action, self.runtime.as_deref()).await,
            "run_command" => execute_command(action, self.runtime.as_deref()).await,
            "verify" => execute_verify(action, self.runtime.as_deref()).await,
            name if browser::is_browser_tool(name) => {
                browser::require_validated_browser_action(
                    name,
                    action.resources().browser_session,
                )?;
                self.execute_browser(action)
            }
            "propose_memory" => {
                let store = self
                    .memory
                    .clone()
                    .ok_or_else(|| anyhow!("propose_memory tool is not configured"))?;
                execute_propose_memory(action, &store)
            }
            "read_skill" => {
                let registry = self
                    .skills
                    .clone()
                    .ok_or_else(|| anyhow!("read_skill tool is not configured"))?;
                execute_read_skill(action, &registry)
            }
            other => bail!("tool `{other}` has no executor"),
        }
    }
}

fn url_preview(raw: &str) -> String {
    let Ok(mut url) = raw.parse::<url::Url>() else {
        return "[invalid URL]".into();
    };
    let path = url.path().to_string();
    url.set_query(None);
    url.set_fragment(None);
    if path != "/" && !path.is_empty() {
        url.set_path(&format!("/[path_sha256={}]", short_hash(&path)));
    }
    url.to_string()
}

/// Bound a string for display, marking clearly when it was cut.
///
/// A preview is a claim about what an action will do, so a silently shortened
/// one would misrepresent the action. The marker makes the omission visible.
///
/// Slicing respects character boundaries: cutting mid-codepoint would panic on
/// the next `chars()` call, and the input here is model- and page-controlled.
fn truncate_preview(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let kept: String = value.chars().take(max_chars).collect();
    format!(
        "{kept}…({} more characters)",
        value.chars().count() - max_chars
    )
}

fn ensure_allowed_keys(args: &Value, allowed: &[&str]) -> Result<()> {
    let object = args
        .as_object()
        .ok_or_else(|| anyhow!("tool arguments must be a JSON object"))?;
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        bail!("unknown tool argument `{key}`");
    }
    Ok(())
}

fn required_string(args: &Value, key: &str) -> Result<String> {
    args.as_object()
        .and_then(|object| object.get(key))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("missing or invalid `{key}`"))
}

fn required_path(args: &Value, key: &str) -> Result<PathBuf> {
    let value = required_string(args, key)?;
    if value.len() > 4_096 || value.chars().any(char::is_control) {
        bail!("`{key}` is too long or contains control characters");
    }
    Ok(PathBuf::from(value))
}

/// Paths a read-only command is expected to read.
///
/// # Why `git` needs its own rule
///
/// For most commands the first non-flag argument is a path (`cat notes.txt`).
/// For `git` it is a **subcommand**: in `git diff`, `diff` is not a file, and
/// treating it as one made the sandbox try to resolve
/// `<workspace>/diff`, fail with `os error 2` (the path does not exist), and
/// deny the action. No `git` command could run through `run_command`.
///
/// Paths after a subcommand are still collected (`git diff -- src/main.rs`), and
/// a bare `git diff` reads no named path — it reads the repository, which the
/// sandbox cannot enumerate, so the read set is empty and correct: the action is
/// still gated by `validate_argv`, which limits `git` to its read-only
/// subcommands.
fn command_read_paths(command: &str, args: &[String]) -> Result<Vec<PathBuf>> {
    let command = command.to_ascii_lowercase();
    if matches!(command.as_str(), "pwd" | "") {
        return Ok(Vec::new());
    }
    // For `git`, skip the subcommand before collecting paths. Every other
    // command's first bare argument is a path.
    let subcommand_seen = command != "git";
    let mut paths = Vec::new();
    let mut pattern_seen = command != "grep";
    let mut skip_next = false;
    let mut after_separator = false;
    let mut skipped_subcommand = subcommand_seen;
    for argument in args {
        if after_separator {
            paths.push(PathBuf::from(argument));
            continue;
        }
        if argument == "--" {
            after_separator = true;
            continue;
        }
        if argument.starts_with('-') {
            if matches!(
                argument.as_str(),
                "-o" | "--output"
                    | "--output-file"
                    | "-C"
                    | "--git-dir"
                    | "--work-tree"
                    | "--exec-path"
                    | "-c"
            ) {
                bail!("command option is not allowed: {argument}");
            }
            if matches!(argument.as_str(), "-e" | "--regexp") {
                skip_next = true;
            }
            continue;
        }
        if !skipped_subcommand {
            skipped_subcommand = true;
            continue;
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        if !pattern_seen {
            pattern_seen = true;
            continue;
        }
        paths.push(PathBuf::from(argument));
    }
    Ok(paths)
}

fn optional_string_array(args: &Value, key: &str) -> Result<Vec<String>> {
    let Some(object) = args.as_object() else {
        return Ok(Vec::new());
    };
    let Some(value) = object.get(key) else {
        return Ok(Vec::new());
    };
    let array = value
        .as_array()
        .ok_or_else(|| anyhow!("`{key}` must be an array"))?;
    array
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow!("`{key}` must contain strings"))
        })
        .collect()
}

async fn execute_read(action: &VerifiedAction) -> Result<ToolOutput> {
    let path = action
        .resources()
        .read_paths
        .first()
        .ok_or_else(|| anyhow!("verified read path missing"))?;
    let content = read_bounded(path, action.sandbox().max_tool_output_bytes)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    Ok(ToolOutput::evidenced(
        content,
        format!("read:{}", path.display()),
    ))
}

async fn execute_list(action: &VerifiedAction) -> Result<ToolOutput> {
    let path = action
        .resources()
        .read_paths
        .first()
        .ok_or_else(|| anyhow!("verified directory missing"))?;
    let mut entries = tokio::fs::read_dir(path)
        .await
        .with_context(|| format!("list {}", path.display()))?;
    let mut names = Vec::new();
    let mut output_bytes = 0usize;
    let mut visited = 0usize;
    while let Some(entry) = entries.next_entry().await? {
        visited = visited.saturating_add(1);
        if visited > MAX_LIST_ENTRIES {
            bail!("directory traversal exceeds configured entry limit");
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let child = entry.path();
        if action.sandbox().resolve_read(&child).is_allowed() {
            output_bytes = output_bytes.saturating_add(name.len() + 1);
            if output_bytes > action.sandbox().max_tool_output_bytes {
                bail!("directory listing exceeds configured output limit");
            }
            names.push(name);
        }
    }
    names.sort();
    Ok(ToolOutput::evidenced(
        names.join("\n"),
        format!("list:{}", path.display()),
    ))
}

async fn execute_search(action: &VerifiedAction) -> Result<ToolOutput> {
    let root = action
        .resources()
        .read_paths
        .first()
        .ok_or_else(|| anyhow!("verified search root missing"))?;
    let query = required_string(&action.call().args, "query")?;
    let mut matches = Vec::new();
    let mut visited = 0usize;
    search_tree(
        action.sandbox(),
        root,
        &query,
        &mut matches,
        &mut visited,
        0,
    )
    .await?;
    if matches.iter().map(String::len).sum::<usize>() > action.sandbox().max_tool_output_bytes {
        bail!("search results exceed configured output limit");
    }
    Ok(ToolOutput::evidenced(
        matches.join("\n"),
        format!("search:{}", root.display()),
    ))
}

fn search_tree<'a>(
    sandbox: &'a Sandbox,
    root: &'a Path,
    query: &'a str,
    matches: &'a mut Vec<String>,
    visited: &'a mut usize,
    depth: usize,
) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        if depth > 32 || matches.len() >= MAX_SEARCH_RESULTS {
            return Ok(());
        }
        let mut entries = tokio::fs::read_dir(root)
            .await
            .with_context(|| format!("search {}", root.display()))?;
        while let Some(entry) = entries.next_entry().await? {
            if matches.len() >= MAX_SEARCH_RESULTS {
                break;
            }
            *visited = (*visited).saturating_add(1);
            if *visited > MAX_SEARCH_ENTRIES {
                bail!("search traversal exceeds configured entry limit");
            }
            let path = entry.path();
            if !sandbox.resolve_read(&path).is_allowed() {
                continue;
            }
            let metadata = tokio::fs::symlink_metadata(&path).await?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                search_tree(sandbox, &path, query, matches, visited, depth + 1).await?;
            } else if metadata.is_file() {
                let Ok(content) = read_bounded(&path, sandbox.max_tool_output_bytes).await else {
                    continue;
                };
                for (line_number, line) in content.lines().enumerate() {
                    if line.contains(query) {
                        matches.push(format!(
                            "{}:{}:{}",
                            path.display(),
                            line_number + 1,
                            line.trim()
                        ));
                        if matches.len() >= MAX_SEARCH_RESULTS {
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    })
}

async fn execute_write(action: &VerifiedAction) -> Result<ToolOutput> {
    let path = action
        .resources()
        .write_paths
        .first()
        .ok_or_else(|| anyhow!("verified write path missing"))?;
    let content = required_string(&action.call().args, "content")?;
    if content.len() > action.sandbox().max_write_bytes {
        bail!("write content exceeds configured limit");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("write path has no parent"))?;
    if !parent.is_dir() {
        bail!("write parent directory does not exist");
    }
    if tokio::fs::symlink_metadata(path)
        .await
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        bail!("write target became a symlink");
    }
    tokio::fs::write(path, content.as_bytes())
        .await
        .with_context(|| format!("write {}", path.display()))?;
    Ok(ToolOutput::evidenced(
        format!("wrote {} bytes", content.len()),
        format!("write:{}", path.display()),
    ))
}

async fn read_bounded(path: &Path, limit: usize) -> Result<String> {
    let metadata = tokio::fs::symlink_metadata(path).await?;
    if metadata.len() > limit as u64 {
        bail!("file exceeds configured output limit");
    }
    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::with_capacity(metadata.len().min(limit as u64) as usize);
    let mut limited = file.take(limit as u64 + 1);
    limited.read_to_end(&mut bytes).await?;
    if bytes.len() > limit {
        bail!("file exceeds configured output limit");
    }
    String::from_utf8(bytes).context("file is not UTF-8")
}

async fn collect_reader(
    mut task: tokio::task::JoinHandle<Result<Vec<u8>>>,
    timeout: Duration,
) -> Result<Vec<u8>> {
    match tokio::time::timeout(timeout, &mut task).await {
        Ok(result) => result.context("command output reader failed")?,
        Err(_) => {
            task.abort();
            bail!("command output reader timed out");
        }
    }
}

async fn read_stream_limited<R>(mut reader: R, limit: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::with_capacity(limit.min(8 * 1024));
    let mut buffer = [0u8; 8 * 1024];
    let mut exceeded = false;
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        if !exceeded && output.len().saturating_add(count) <= limit {
            output.extend_from_slice(&buffer[..count]);
        } else {
            exceeded = true;
        }
    }
    if exceeded {
        bail!("command output exceeds configured limit");
    }
    Ok(output)
}

async fn execute_http(action: &VerifiedAction) -> Result<ToolOutput> {
    let raw_url = required_string(&action.call().args, "url")?;
    let url = action.sandbox().check_url(&raw_url)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(
            action.sandbox().subprocess_timeout_secs.max(1),
        ))
        .build()?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| anyhow!("HTTP request failed"))?
        .error_for_status()
        .map_err(|error| {
            let status = error.status().map(|status| status.as_u16()).unwrap_or(0);
            anyhow!("HTTP request returned status {status}")
        })?;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow!("HTTP response stream failed"))?
    {
        if body.len().saturating_add(chunk.len()) > action.sandbox().max_tool_output_bytes {
            bail!("HTTP response exceeds configured output limit");
        }
        body.extend_from_slice(&chunk);
    }
    let text = String::from_utf8(body).context("HTTP response is not UTF-8")?;
    Ok(ToolOutput::evidenced(
        text,
        format!(
            "http:{}",
            action
                .resources()
                .hosts
                .first()
                .cloned()
                .unwrap_or_default()
        ),
    ))
}

fn resolve_executable(program: &str, sandbox: &Sandbox) -> Result<PathBuf> {
    if program.contains('/') || program.contains('\\') {
        bail!("executable must be a bare allow-listed name");
    }
    if !sandbox
        .env_allow
        .iter()
        .any(|key| key.eq_ignore_ascii_case("PATH"))
    {
        bail!("PATH is not allowed for command resolution");
    }
    let path = std::env::var_os("PATH")
        .ok_or_else(|| anyhow!("PATH is not available for command resolution"))?;
    let extensions = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".into())
            .split(';')
            .map(str::to_owned)
            .collect::<Vec<_>>()
    } else {
        vec![String::new()]
    };
    for directory in std::env::split_paths(&path) {
        for extension in &extensions {
            let candidate = directory.join(format!("{program}{extension}"));
            let Ok(metadata) = std::fs::symlink_metadata(&candidate) else {
                continue;
            };
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                continue;
            }
            let canonical = std::fs::canonicalize(&candidate)?;
            if canonical.starts_with(&sandbox.workspace) {
                continue;
            }
            return Ok(canonical);
        }
    }
    bail!("executable `{program}` was not found outside the workspace")
}

fn require_current_page(action: &VerifiedAction, url: &str) -> Result<()> {
    browser::require_allowed_page_url(url, |host| {
        action
            .sandbox()
            .check_host(host)
            .map(|_| ())
            .map_err(|error| anyhow!(error))
    })
}

async fn execute_command(
    action: &VerifiedAction,
    runtime: Option<&pangu_boundary::runtime::Runtime>,
) -> Result<ToolOutput> {
    execute_command_tagged(action, "command", runtime).await
}

/// F3: verify shares the run_command subprocess discipline (no shell, cleaned
/// env, closed stdin, timeout, bounded output); only the evidence tag differs.
async fn execute_verify(
    action: &VerifiedAction,
    runtime: Option<&pangu_boundary::runtime::Runtime>,
) -> Result<ToolOutput> {
    execute_command_tagged(action, "verify", runtime).await
}

/// B3: append a pending memory candidate. The output carries the id and the
/// content digest only — the agent audits the proposal into the journal
/// without the raw content.
/// B2: return one skill's instruction document. The model supplies only the
/// name; the path comes from the operator-installed registry.
fn execute_read_skill(action: &VerifiedAction, registry: &SkillRegistry) -> Result<ToolOutput> {
    let call = action.call();
    let name = call
        .args
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("read_skill name is missing"))?;
    let doc = registry.read_doc(name)?;
    Ok(ToolOutput {
        content: doc,
        evidence: Some(format!("skill:{}", name)),
    })
}

fn execute_propose_memory(action: &VerifiedAction, store: &MemoryStore) -> Result<ToolOutput> {
    let call = action.call();
    let content = call
        .args
        .get("content")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("propose_memory content is missing"))?
        .to_string();
    let kind = call
        .args
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("note");
    let candidate = store.propose(&content, kind)?;
    Ok(ToolOutput {
        content: serde_json::to_string(&serde_json::json!({
            "id": candidate.id,
            "status": candidate.status.as_str(),
            "content_sha256": candidate.content_digest,
            "review": "queued for operator review; it is not active and carries no effect until accepted",
        }))?,
        evidence: Some(format!("memory:{}", candidate.id)),
    })
}

/// F8: the enforcement decision, as a pure function.
///
/// Split out of the executor so it can be tested directly. The property that
/// matters — *a declared sandbox that does not work refuses the command* — is
/// the one this feature exists for, and a test that only read
/// `Runtime::refusal()` would still pass if the executor stopped calling it.
///
/// `Ok(())` means "proceed". There is deliberately no branch returning `Ok` for
/// an unusable runtime, so no edit here can reintroduce a silent host fallback
/// without breaking a test.
pub fn sandbox_admits(runtime: Option<&pangu_boundary::runtime::Runtime>) -> Result<()> {
    match runtime {
        // No runtime declared: the `local` profile, unchanged behaviour.
        None => Ok(()),
        Some(runtime) => {
            if runtime.allows_execution() {
                Ok(())
            } else {
                // Its own message, so operator and audit trail can tell "the
                // sandbox refused" from "the command failed".
                Err(anyhow!("{}", runtime.refusal()))
            }
        }
    }
}

/// Describe what a spawn was about to run, for the failure message.
fn launcher_program_for_error(launcher: Option<(&str, &[String])>, argv0: &str) -> String {
    match launcher {
        Some((program, args)) => format!("{program} {args:?}"),
        None => format!("resolved `<{argv0}>` on PATH"),
    }
}

async fn execute_command_tagged(
    action: &VerifiedAction,
    tag: &str,
    runtime: Option<&pangu_boundary::runtime::Runtime>,
) -> Result<ToolOutput> {
    let argv = &action.resources().argv;
    if argv.is_empty() {
        bail!("empty command");
    }
    // F8: enforce the declared sandbox before anything is spawned.
    //
    // This is where "declared" becomes "enforced". An unusable runtime refuses
    // here; it does not fall through to the host, because the run's audit trail
    // records the declaration and executing outside it would make that record
    // false — the operator would believe they had isolation they did not have.
    sandbox_admits(runtime)?;
    // Inside a usable runtime the command is launched **through** the sandbox,
    // not on the host. The argv comes from the same `RuntimeConfig::command_for`
    // the probe used, so a runtime that passed the probe is invoked identically
    // here.
    let launcher = runtime.and_then(|runtime| runtime.launcher());
    let mount = runtime.and_then(|runtime| runtime.workspace_mount());
    // The workspace as the *host* sees it. Needed because the launcher process —
    // `docker`, `runsc` — is itself spawned on the host, so `current_dir` must be
    // a path that exists here. The in-container path (`/workspace`) is not one:
    // passing it made every sandboxed command fail with an invalid-directory
    // error before the runtime ever ran.
    let host_workspace = runtime.map(|runtime| runtime.workspace());
    let mut command = match launcher {
        Some((program, leading)) => {
            let mut command = tokio::process::Command::new(program);
            // `leading` carries the bind mount, so the workspace the command sees
            // is the one the operator declared, mounted at the in-container path.
            command.args(leading);
            // The command runs inside the sandbox, where `cwd` must be the in-container
            // mount point rather than the host path.
            command.args(argv).current_dir(mount.unwrap_or("."));
            command
        }
        None => {
            let executable = resolve_executable(&argv[0], action.sandbox())?;
            let mut command = tokio::process::Command::new(executable);
            command
                .args(&argv[1..])
                .current_dir(&action.resources().cwd);
            command
        }
    };
    // The launcher process runs on the host, so its own cwd must be a host path;
    // the in-container path above is what the *command* is told to use. Without
    // this the spawn fails with an invalid-directory error on a host where
    // `/workspace` does not exist, and the sandbox never starts.
    if let Some(host) = host_workspace {
        if host.is_dir() {
            command.current_dir(host);
        }
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command.env_clear();
    for (key, value) in action.sandbox().sanitize_env(&std::env::vars().collect()) {
        command.env(key, value);
    }
    let timeout = Duration::from_secs(action.sandbox().subprocess_timeout_secs);
    let deadline = tokio::time::Instant::now() + timeout;
    let remaining = || deadline.saturating_duration_since(tokio::time::Instant::now());
    let mut child = command.spawn().map_err(|error| {
        // Report the whole decision, not just the failing call: which program,
        // from where, in which directory, and with which environment. `anyhow`
        // context would be dropped by `Display` at the event boundary, so the
        // facts go into the message itself.
        anyhow!(
            "spawn failed: {error} | launching: {} | host cwd={} (exists={})",
            launcher_program_for_error(launcher, &argv[0]),
            host_workspace
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| action.resources().cwd.display().to_string()),
            host_workspace
                .map(Path::is_dir)
                .unwrap_or_else(|| action.resources().cwd.is_dir()),
        )
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("stdout pipe unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("stderr pipe unavailable"))?;
    let output_limit = action.sandbox().subprocess_output_limit;
    let stdout_task = tokio::spawn(read_stream_limited(stdout, output_limit));
    let stderr_task = tokio::spawn(read_stream_limited(stderr, output_limit));
    let status = match tokio::time::timeout(remaining(), child.wait()).await {
        Ok(result) => result?,
        Err(_) => {
            stdout_task.abort();
            stderr_task.abort();
            return Err(anyhow!("command timed out"));
        }
    };
    let stdout = collect_reader(stdout_task, remaining()).await?;
    let stderr = collect_reader(stderr_task, remaining()).await?;
    if stdout.len().saturating_add(stderr.len()) > output_limit {
        bail!("command output exceeds configured limit");
    }
    let mut text = String::from_utf8_lossy(&stdout).to_string();
    if !stderr.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str("stderr: ");
        text.push_str(&String::from_utf8_lossy(&stderr));
    }
    if !status.success() {
        bail!("command exited with {status}: {text}");
    }
    Ok(ToolOutput::evidenced(
        text,
        format!("{tag}:{}", short_hash(&argv.join(" "))),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_paths_skip_flags_and_grep_patterns() {
        let paths = command_read_paths(
            "grep",
            &[
                "-n".into(),
                "needle".into(),
                "src".into(),
                "--".into(),
                "README.md".into(),
            ],
        )
        .unwrap();
        assert_eq!(
            paths,
            vec![PathBuf::from("src"), PathBuf::from("README.md")]
        );
        assert!(command_read_paths("grep", &["-o".into(), "needle".into(), "x".into()]).is_err());
    }

    #[test]
    fn toolkit_exposes_only_the_finish_control_tool() {
        let specs = Toolkit::new().specs();
        assert!(specs.iter().any(|spec| spec.name == "finish"));
        assert!(!specs.iter().any(|spec| spec.name == "verify_claims"));
    }

    #[test]
    fn manifest_matches_specs_one_to_one() {
        let specs = Toolkit::new().specs();
        let manifest = Toolkit::new().manifest();
        manifest.validate().expect("manifest validates");
        let mut spec_names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        let mut manifest_names: Vec<&str> = manifest.names();
        spec_names.sort();
        manifest_names.sort();
        assert_eq!(spec_names, manifest_names);
    }

    #[test]
    fn verify_tool_is_advertised_only_when_configured() {
        let default = Toolkit::new();
        assert!(!default.specs().iter().any(|spec| spec.name == "verify"));
        assert!(!default.manifest().names().contains(&"verify"));
        assert!(default.verify_command().is_empty());

        let configured = Toolkit::with_verify_command(vec!["cargo".into(), "test".into()]);
        assert!(configured.specs().iter().any(|spec| spec.name == "verify"));
        assert!(configured.manifest().names().contains(&"verify"));
        assert_eq!(
            configured.verify_command(),
            vec!["cargo".to_string(), "test".to_string()]
        );
    }

    #[test]
    fn manifest_matches_specs_one_to_one_with_a_browser() {
        let toolkit = Toolkit::new().with_browser(
            pangu_boundary::browser::BrowserConfig {
                executable: PathBuf::from("browser"),
                profile_dir: PathBuf::from("profile"),
                network: false,
                extra_args: Vec::new(),
            },
            PathBuf::from("artifacts"),
        );
        let specs = toolkit.specs();
        let manifest = toolkit.manifest();
        manifest
            .validate()
            .expect("a browser-enabled manifest validates");
        let mut spec_names: Vec<&str> = specs.iter().map(|spec| spec.name.as_str()).collect();
        let mut manifest_names: Vec<&str> = manifest.names();
        spec_names.sort();
        manifest_names.sort();
        assert_eq!(
            spec_names, manifest_names,
            "enabling a browser must not make specs() and manifest() diverge"
        );
        for name in ["browser_click", "browser_type"] {
            let capability = manifest
                .get(name)
                .unwrap_or_else(|| panic!("{name} must be declared"));
            assert_eq!(capability.risk, Risk::NeedsHuman);
            capability
                .effect
                .validate_for_risk(capability.risk)
                .unwrap_or_else(|error| panic!("{name} has an effect L1 rejects: {error}"));
        }
    }

    #[test]
    fn manifest_matches_specs_one_to_one_with_verify() {
        let toolkit = Toolkit::with_verify_command(vec!["cargo".into(), "test".into()]);
        let specs = toolkit.specs();
        let manifest = toolkit.manifest();
        manifest.validate().expect("manifest validates");
        let mut spec_names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        let mut manifest_names: Vec<&str> = manifest.names();
        spec_names.sort();
        manifest_names.sort();
        assert_eq!(spec_names, manifest_names);
    }
}
