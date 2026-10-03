//! Read-only explanation of what the boundary would do with a hypothetical
//! action.
//!
//! This answers "why was this refused" before anything runs. It projects the
//! L1 contract, the L2 policy trace, the L3 sandbox projection and the L4
//! approval projection, and reports which rules matched, which were shadowed
//! and which were never reached.
//!
//! The central design constraint is that an explanation is **not an
//! authorization** (ADR-0002 §4.3):
//!
//! * verdicts are named `WouldDeny` / `WouldAsk` / `WouldAllow`, never `Deny`
//!   or `Allow`, so a reader cannot mistake one for a `Decision`;
//! * the serialized report always carries `advisory: true` and
//!   `authoritative: false`;
//! * there is deliberately no conversion into [`Decision`] or [`Effect`] —
//!   a caller cannot lift an explanation into the evaluation path;
//! * nothing here executes, writes, or emits an event.
//!
//! If a projection disagrees with a real run, the real run is authoritative
//! and the disagreement is a bug to report.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use pangu_core::{one_line, redact_text, truncate_middle};

use crate::approval::ApprovalMode;
use crate::policy::{ActionRequest, Effect, Policy, Rule};
use crate::risk::Risk;
use crate::sandbox::{ResolveOutcome, Sandbox};

/// Report schema. Bump when the shape changes incompatibly.
pub const EXPLAIN_SCHEMA: &str = "pangu-explain/1";

/// Bounds on what may be echoed back, so `explain` cannot become a way to
/// spray large objects or long secrets into a terminal or a CI log.
const MAX_ECHO_BYTES: usize = 4_096;

/// A hypothetical action. Nothing in here is executed.
#[derive(Debug, Clone)]
pub struct ExplainRequest {
    pub tool: String,
    pub args: Value,
    pub paths: Vec<PathBuf>,
    pub hosts: Vec<String>,
    pub argv: Vec<String>,
    /// Unknown/unclassified starts at the human-risk end, matching
    /// [`ActionRequest::new`].
    pub risk: Risk,
}

impl ExplainRequest {
    pub fn new(tool: impl Into<String>, args: Value) -> Self {
        Self {
            tool: tool.into(),
            args,
            paths: Vec::new(),
            hosts: Vec::new(),
            argv: Vec::new(),
            risk: Risk::NeedsHuman,
        }
    }

    pub fn with_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.paths = paths;
        self
    }

    pub fn with_hosts(mut self, hosts: Vec<String>) -> Self {
        self.hosts = hosts;
        self
    }

    pub fn with_argv(mut self, argv: Vec<String>) -> Self {
        self.argv = argv;
        self
    }

    pub fn with_risk(mut self, risk: Risk) -> Self {
        self.risk = risk;
        self
    }
}

/// The projected outcome. Deliberately not [`Effect`]: an explanation cannot
/// be promoted to a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Projection {
    /// The boundary would refuse the action.
    WouldDeny,
    /// The action would reach the human gate.
    WouldAsk,
    /// Every configured layer would let it through without asking.
    WouldAllow,
}

impl Projection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WouldDeny => "would_deny",
            Self::WouldAsk => "would_ask",
            Self::WouldAllow => "would_allow",
        }
    }

    /// A predicate, so a summary reads as prose instead of doubling the verb.
    pub fn phrase(self) -> &'static str {
        match self {
            Self::WouldDeny => "refused",
            Self::WouldAsk => "routed to the human gate",
            Self::WouldAllow => "allowed without asking",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    Contract,
    Policy,
    Sandbox,
    Approval,
}

impl Layer {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contract => "L1_contract",
            Self::Policy => "L2_policy",
            Self::Sandbox => "L3_sandbox",
            Self::Approval => "L4_approval",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerOutcome {
    /// This layer is satisfied and passes control onwards.
    Pass,
    /// This layer refuses; later layers were not consulted.
    Deny,
    /// This layer requires a human decision.
    NeedsHuman,
    /// This layer has nothing to check for this kind of action.
    NotApplicable,
}

impl LayerOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Deny => "deny",
            Self::NeedsHuman => "needs_human",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// What happened to one rule while the trace was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleStatus {
    /// Matched, and produced the reported decision.
    Decided,
    /// Matched, but a stronger check refused first.
    MatchedButRefused,
    /// Matched, but an earlier match already decided the same way, so this
    /// rule's id and reason are never the ones reported.
    Shadowed,
    /// Did not match this action.
    NoMatch,
    /// Matched, but the algorithm never reaches it.
    NotReached,
}

impl RuleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Decided => "decided",
            Self::MatchedButRefused => "matched_but_refused",
            Self::Shadowed => "shadowed",
            Self::NoMatch => "no_match",
            Self::NotReached => "not_reached",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTrace {
    pub rule_id: String,
    pub effect: Effect,
    pub status: RuleStatus,
    /// Redacted, bounded explanation of why the rule did or did not match.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerReport {
    pub layer: Layer,
    pub outcome: LayerOutcome,
    /// The rule that decided this layer, when a rule did.
    pub rule_id: Option<String>,
    /// Redacted, bounded reason.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainReport {
    pub schema: String,
    /// Always true. Present so a consumer cannot mistake this for a verdict
    /// produced by the evaluation path.
    pub advisory: bool,
    /// Always false, for the same reason.
    pub authoritative: bool,
    pub tool: String,
    pub risk: Risk,
    /// Only the workspace-relative form is kept; absolute paths are not echoed.
    pub workspace: String,
    pub boundary_digest: String,
    pub projection: Projection,
    pub layers: Vec<LayerReport>,
    pub rules: Vec<RuleTrace>,
    /// Rules that can never be the reported cause, with the reason why.
    pub dead_rules: Vec<DeadRule>,
    pub args_echo: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadRule {
    pub rule_id: String,
    pub reason: String,
}

impl ExplainReport {
    /// One-line summary for humans and for CI greps.
    pub fn summary(&self) -> String {
        let digest = &self.boundary_digest[..self.boundary_digest.len().min(16)];
        let mut out = format!(
            "projection: `{}` would be {} (risk {}, boundary {})\n",
            self.tool,
            self.projection.phrase(),
            self.risk.as_str(),
            digest
        );
        for layer in &self.layers {
            out.push_str(&format!(
                "  {:<14} {:<15} {}\n",
                layer.layer.as_str(),
                layer.outcome.as_str(),
                layer.detail
            ));
        }
        for dead in &self.dead_rules {
            out.push_str(&format!(
                "  dead rule      {}: {}\n",
                dead.rule_id, dead.reason
            ));
        }
        out.push_str(
            "  advisory only: a real run re-evaluates everything and wins if they disagree\n",
        );
        out
    }
}

/// Everything the projection needs. Borrowing the caller's own policy and
/// sandbox keeps `explain` free of hidden configuration: the report describes
/// the same objects a real run would use.
pub struct ExplainContext<'a> {
    pub policy: &'a Policy,
    pub sandbox: &'a Sandbox,
    pub workspace: &'a Path,
    pub approval_mode: ApprovalMode,
    pub boundary_digest: &'a str,
}

/// Build the explanation.
///
/// Fails rather than returning a partial report: a half-explained action is
/// more dangerous than an error, because the reader cannot tell what was
/// skipped.
pub fn explain_action(
    context: &ExplainContext<'_>,
    request: &ExplainRequest,
) -> pangu_core::Result<ExplainReport> {
    let policy = context.policy;
    let sandbox = context.sandbox;
    let workspace = context.workspace;
    let approval_mode = context.approval_mode;

    if request.tool.trim().is_empty() {
        return Err(pangu_core::Error::Config(
            "explain requires a tool name".into(),
        ));
    }
    if request.args.to_string().len() > MAX_ECHO_BYTES * 8 {
        return Err(pangu_core::Error::Config(format!(
            "explain args exceed {} bytes; refusing to echo an oversized payload",
            MAX_ECHO_BYTES * 8
        )));
    }

    let action = ActionRequest {
        tool: &request.tool,
        call_id: "explain-probe",
        args: &request.args,
        risk: request.risk,
        paths: request.paths.clone(),
        hosts: request.hosts.clone(),
        argv: request.argv.clone(),
        escapes_workspace: false,
    };

    let mut layers = Vec::new();
    let mut notes = Vec::new();

    // L2 policy, plus the rule trace and the shadow analysis that comes with
    // it. The decision is computed by the real evaluator, never re-derived
    // here: an explanation that disagreed with the evaluator would be worse
    // than no explanation.
    let decision = policy.evaluate(&action, workspace);
    let (traces, dead) = trace_rules(policy.explainable_rules(), &action, workspace, &decision);
    let policy_layer = match decision.effect {
        Effect::Deny => LayerReport {
            layer: Layer::Policy,
            outcome: LayerOutcome::Deny,
            rule_id: decision.rule_id.clone(),
            detail: bounded(&decision.denial_message()),
        },
        Effect::Ask => LayerReport {
            layer: Layer::Policy,
            outcome: LayerOutcome::NeedsHuman,
            rule_id: decision.rule_id.clone(),
            detail: bounded(&format!(
                "policy routes this action to the human gate: {}",
                decision.reason
            )),
        },
        Effect::Allow => LayerReport {
            layer: Layer::Policy,
            outcome: LayerOutcome::Pass,
            rule_id: decision.rule_id.clone(),
            detail: bounded(&format!("policy allows: {}", decision.reason)),
        },
    };

    // A hard path refusal short-circuits before any rule, so say so rather
    // than implying a rule was involved.
    if decision.rule_id.is_none() && decision.effect == Effect::Deny {
        notes.push(
            "this refusal came from the path-safety check, not from a rule; no rule is credited"
                .into(),
        );
    }

    // L3 sandbox, projected read-only. Only consulted when policy passed,
    // because that is the order the real chain uses.
    let sandbox_layer = if decision.effect == Effect::Deny {
        LayerReport {
            layer: Layer::Sandbox,
            outcome: LayerOutcome::NotApplicable,
            rule_id: None,
            detail: "not reached: policy already refused".into(),
        }
    } else {
        project_sandbox(sandbox, request)
    };

    // L4 approval, projected from the configured mode. `Never` refuses at the
    // gate rather than auto-approving, which is the fail-closed behaviour.
    let approval_layer = if decision.effect == Effect::Deny {
        LayerReport {
            layer: Layer::Approval,
            outcome: LayerOutcome::NotApplicable,
            rule_id: None,
            detail: "not reached: policy already refused".into(),
        }
    } else if sandbox_layer.outcome == LayerOutcome::Deny {
        LayerReport {
            layer: Layer::Approval,
            outcome: LayerOutcome::NotApplicable,
            rule_id: None,
            detail: "not reached: sandbox already refused".into(),
        }
    } else {
        project_approval(approval_mode, request.risk)
    };

    let projection =
        if decision.effect == Effect::Deny || sandbox_layer.outcome == LayerOutcome::Deny {
            Projection::WouldDeny
        } else if approval_layer.outcome == LayerOutcome::NeedsHuman
            || approval_layer.outcome == LayerOutcome::Deny
        {
            if approval_mode == ApprovalMode::Never {
                Projection::WouldDeny
            } else {
                Projection::WouldAsk
            }
        } else {
            Projection::WouldAllow
        };

    if approval_mode == ApprovalMode::Never
        && approval_layer.outcome == LayerOutcome::NeedsHuman
        && projection == Projection::WouldDeny
    {
        notes.push(
            "approval mode is `never`: anything that would have asked is refused instead of \
             silently allowed"
                .into(),
        );
    }

    layers.push(LayerReport {
        layer: Layer::Contract,
        outcome: LayerOutcome::NotApplicable,
        rule_id: None,
        detail: "the goal contract gates capabilities and budgets, not individual tools; \
                 run `pangu doctor` to see it"
            .into(),
    });
    layers.push(policy_layer);
    layers.push(sandbox_layer);
    layers.push(approval_layer);

    Ok(ExplainReport {
        schema: EXPLAIN_SCHEMA.to_string(),
        advisory: true,
        authoritative: false,
        tool: request.tool.clone(),
        risk: request.risk,
        workspace: workspace.display().to_string(),
        boundary_digest: context.boundary_digest.to_string(),
        projection,
        layers,
        rules: traces,
        dead_rules: dead,
        args_echo: bounded(&serde_json::to_string(&pangu_core::redact_value(
            &request.args,
        ))?),
        notes,
    })
}

fn project_sandbox(sandbox: &Sandbox, request: &ExplainRequest) -> LayerReport {
    let mut refusals = Vec::new();
    for path in &request.paths {
        let outcome = sandbox.resolve_write(path);
        if let ResolveOutcome::Allowed(_) = outcome {
            continue;
        }
        let reason = match outcome {
            ResolveOutcome::ForbiddenGlob(glob) => format!("matches forbidden glob {glob}"),
            ResolveOutcome::OutsideRoot(root) => format!("outside every writable root ({root})"),
            ResolveOutcome::Error(error) => error.to_string(),
            ResolveOutcome::Allowed(_) => unreachable!("handled above"),
        };
        refusals.push(format!("path {}: {}", display_path(path), reason));
    }
    for host in &request.hosts {
        if let Err(error) = sandbox.check_host(host) {
            refusals.push(format!("host {}: {}", host, bounded(&error.to_string())));
        }
    }
    for arg in &request.argv {
        if let Err(error) = sandbox.validate_argv(std::slice::from_ref(arg)) {
            refusals.push(format!("argv: {}", bounded(&error.to_string())));
        }
    }
    if !request.argv.is_empty() {
        let command = request.argv.first().cloned().unwrap_or_default();
        if !sandbox.can_exec(&command) {
            refusals.push(format!(
                "command `{command}` is not on the execution allow-list"
            ));
        }
    }

    if refusals.is_empty() {
        let checked = request.paths.len() + request.hosts.len() + request.argv.len();
        LayerReport {
            layer: Layer::Sandbox,
            outcome: if checked == 0 {
                LayerOutcome::NotApplicable
            } else {
                LayerOutcome::Pass
            },
            rule_id: None,
            detail: if checked == 0 {
                "no path, host or command was supplied, so there was nothing to check".into()
            } else {
                format!("{checked} resource(s) resolve inside the configured roots")
            },
        }
    } else {
        LayerReport {
            layer: Layer::Sandbox,
            outcome: LayerOutcome::Deny,
            rule_id: None,
            detail: bounded(&refusals.join("; ")),
        }
    }
}

fn project_approval(mode: ApprovalMode, risk: Risk) -> LayerReport {
    let needs = mode.needs_approval(risk);
    let outcome = match (mode, needs) {
        (ApprovalMode::Never, _) => LayerOutcome::Deny,
        (_, true) => LayerOutcome::NeedsHuman,
        (_, false) => LayerOutcome::Pass,
    };
    let detail = match mode {
        ApprovalMode::Never => format!(
            "approval mode is `never`; this action would be refused at the gate rather than \
             auto-approved (risk {})",
            risk.as_str()
        ),
        _ if needs => format!(
            "risk {} requires a human decision under approval mode `{}`",
            risk.as_str(),
            mode.as_str()
        ),
        _ => format!(
            "approval mode `{}` does not gate risk {}",
            mode.as_str(),
            risk.as_str()
        ),
    };
    LayerReport {
        layer: Layer::Approval,
        outcome,
        rule_id: None,
        detail: bounded(&detail),
    }
}

/// Walk the rules in evaluation order and report what happened to each.
fn trace_rules(
    rules: &[Rule],
    request: &ActionRequest<'_>,
    workspace: &Path,
    decision: &crate::policy::Decision,
) -> (Vec<RuleTrace>, Vec<DeadRule>) {
    // `Policy::evaluate` consults denies first, then non-denies, each in
    // declaration order. Shadowing is computed against that real order rather
    // than against a guess, otherwise the report would describe a different
    // algorithm than the one that runs.
    let mut traces = Vec::new();
    let mut dead = Vec::new();
    let mut first_matching_deny: Option<&str> = None;
    let mut first_matching_other: Option<&str> = None;

    for (index, rule) in rules.iter().enumerate() {
        if !rule.matches(request, workspace) {
            traces.push(RuleTrace {
                rule_id: rule.id.clone(),
                effect: rule.effect,
                status: RuleStatus::NoMatch,
                detail: "does not match this action".into(),
            });
            continue;
        }
        let status = match rule.effect {
            Effect::Deny => match first_matching_deny {
                None => {
                    first_matching_deny = Some(&rule.id);
                    if decision.effect == Effect::Deny
                        && decision.rule_id.as_deref() == Some(&rule.id)
                    {
                        RuleStatus::Decided
                    } else {
                        RuleStatus::MatchedButRefused
                    }
                }
                Some(_) => RuleStatus::Shadowed,
            },
            _ => match first_matching_other {
                None => {
                    first_matching_other = Some(&rule.id);
                    if decision.effect != Effect::Deny {
                        RuleStatus::Decided
                    } else {
                        RuleStatus::MatchedButRefused
                    }
                }
                Some(_) => RuleStatus::Shadowed,
            },
        };
        if status == RuleStatus::Shadowed {
            dead.push(DeadRule {
                rule_id: rule.id.clone(),
                reason: format!(
                    "an earlier {} rule already matches this action, so this one is never \
                     reported (declared at position {index})",
                    if rule.effect == Effect::Deny {
                        "deny"
                    } else {
                        "allow/ask"
                    }
                ),
            });
        }
        traces.push(RuleTrace {
            rule_id: rule.id.clone(),
            effect: rule.effect,
            status,
            detail: match status {
                RuleStatus::Decided => "matched and produced the reported decision".into(),
                RuleStatus::MatchedButRefused => {
                    "matched, but a stronger check refused first".into()
                }
                RuleStatus::Shadowed => "matched, but an earlier match is reported instead".into(),
                RuleStatus::NoMatch => "does not match this action".into(),
                RuleStatus::NotReached => "the algorithm stops before this rule".into(),
            },
        });
    }

    // Rules after the deciding one cannot change the outcome for this action.
    let decided_at = traces
        .iter()
        .position(|trace| trace.status == RuleStatus::Decided);
    if let Some(decided_at) = decided_at {
        for trace in traces.iter_mut().skip(decided_at + 1) {
            if trace.status == RuleStatus::NoMatch {
                trace.status = RuleStatus::NotReached;
                trace.detail = "the algorithm stops before this rule".into();
            }
        }
    }

    (traces, dead)
}

fn display_path(path: &Path) -> String {
    truncate_middle(&path.display().to_string(), 256)
}

/// Redact then bound, so an explanation can never be the place a secret or an
/// oversized payload leaks.
fn bounded(input: &str) -> String {
    truncate_middle(
        &one_line(&redact_text(input), MAX_ECHO_BYTES),
        MAX_ECHO_BYTES,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use serde_json::json;

    fn fixture() -> (Policy, Sandbox, std::path::PathBuf, String) {
        let config = Config::embedded().expect("embedded config");
        let policy = Policy::new(config.rules.clone()).expect("policy");
        let sandbox = Sandbox::from_config(&config.boundary).expect("sandbox");
        let workspace = config.workspace_abs();
        let digest = config.boundary_digest();
        (policy, sandbox, workspace, digest)
    }

    fn context<'a>(
        policy: &'a Policy,
        sandbox: &'a Sandbox,
        workspace: &'a Path,
        digest: &'a str,
    ) -> ExplainContext<'a> {
        gated(
            policy,
            sandbox,
            workspace,
            digest,
            ApprovalMode::DestructiveAndAbove,
        )
    }

    fn gated<'a>(
        policy: &'a Policy,
        sandbox: &'a Sandbox,
        workspace: &'a Path,
        digest: &'a str,
        approval_mode: ApprovalMode,
    ) -> ExplainContext<'a> {
        ExplainContext {
            policy,
            sandbox,
            workspace,
            approval_mode,
            boundary_digest: digest,
        }
    }

    #[test]
    fn a_report_is_advisory_and_cannot_masquerade_as_a_decision() {
        let (policy, sandbox, workspace, digest) = fixture();
        let report = explain_action(
            &context(&policy, &sandbox, &workspace, &digest),
            &ExplainRequest::new("read_file", json!({"path": "notes.txt"})),
        )
        .expect("explain");
        assert!(report.advisory);
        assert!(!report.authoritative);
        assert_eq!(report.schema, EXPLAIN_SCHEMA);
        // The projection vocabulary is deliberately not the decision
        // vocabulary, and there is no conversion from one to the other.
        assert!(matches!(
            report.projection,
            Projection::WouldDeny | Projection::WouldAsk | Projection::WouldAllow
        ));
        assert!(report.summary().contains("advisory only"));
    }

    #[test]
    fn an_empty_tool_is_refused_rather_than_explained() {
        let (policy, sandbox, workspace, digest) = fixture();
        let error = explain_action(
            &context(&policy, &sandbox, &workspace, &digest),
            &ExplainRequest::new("  ", json!({})),
        )
        .expect_err("an empty tool must not produce a report");
        assert!(error.to_string().contains("tool name"));
    }

    #[test]
    fn path_traversal_is_attributed_to_safety_not_to_a_rule() {
        let (policy, sandbox, workspace, digest) = fixture();
        let request = ExplainRequest::new("write_file", json!({"path": "../outside.txt"}))
            .with_paths(vec![PathBuf::from("../outside.txt")]);
        let report = explain_action(&context(&policy, &sandbox, &workspace, &digest), &request)
            .expect("explain");
        let policy_layer = report
            .layers
            .iter()
            .find(|layer| layer.layer == Layer::Policy)
            .expect("policy layer");
        assert_eq!(policy_layer.outcome, LayerOutcome::Deny);
        assert_eq!(policy_layer.rule_id, None);
        assert!(
            report.notes.iter().any(|note| note.contains("path-safety")),
            "the report must not credit a rule for a safety refusal: {:?}",
            report.notes
        );
    }

    #[test]
    fn a_shadowed_rule_is_reported_as_dead() {
        let (policy, sandbox, workspace, digest) = fixture();
        // A broad allow declared before the narrower rule it hides.
        let mut rules = policy.explainable_rules().to_vec();
        rules.insert(0, Rule::allow("broad-allow", "write_file", "broad allow"));
        let policy = Policy::new(rules).expect("policy");
        let report = explain_action(
            &context(&policy, &sandbox, &workspace, &digest),
            &ExplainRequest::new("write_file", json!({"path": "a.txt"}))
                .with_risk(Risk::Reversible),
        )
        .expect("explain");
        let decided: Vec<&str> = report
            .rules
            .iter()
            .filter(|trace| trace.status == RuleStatus::Decided)
            .map(|trace| trace.rule_id.as_str())
            .collect();
        assert_eq!(
            decided,
            vec!["broad-allow"],
            "the first matching allow must decide: {decided:?}"
        );
        assert!(
            report.rules.iter().any(|trace| {
                trace.rule_id != "broad-allow" && trace.status == RuleStatus::NotReached
            }),
            "later rules must be reported as unreachable rather than silently dropped: {:?}",
            report.rules
        );
    }

    #[test]
    fn approval_never_refuses_instead_of_auto_approving() {
        let (policy, sandbox, workspace, digest) = fixture();
        let report = explain_action(
            &gated(&policy, &sandbox, &workspace, &digest, ApprovalMode::Never),
            &ExplainRequest::new("write_file", json!({"path": "a.txt"}))
                .with_risk(Risk::Destructive)
                .with_paths(vec![PathBuf::from("a.txt")]),
        )
        .expect("explain");
        assert_eq!(report.projection, Projection::WouldDeny);
        let approval = report
            .layers
            .iter()
            .find(|layer| layer.layer == Layer::Approval)
            .expect("approval layer");
        assert_eq!(approval.outcome, LayerOutcome::Deny);
        assert!(approval.detail.contains("never"));
    }

    #[test]
    fn secrets_in_arguments_are_redacted_in_the_echo() {
        let (policy, sandbox, workspace, digest) = fixture();
        let report = explain_action(
            &context(&policy, &sandbox, &workspace, &digest),
            &ExplainRequest::new(
                "read_file",
                json!({"path": "x", "token": "sk-abcdef1234567890"}),
            ),
        )
        .expect("explain");
        assert!(
            !report.args_echo.contains("sk-abcdef1234567890"),
            "the echo must not carry a credential: {}",
            report.args_echo
        );
    }
}
