//! Pangu Agent command line interface.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod canvas_server;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use clap::{Parser, Subcommand};
use pangu_agent::{Agent, Provider};
use pangu_boundary::{
    explain_action, CliOverrides, Config, ExplainContext, ExplainRequest, GoalContract, Policy,
    Risk, Sandbox, StdinApproval, Unattended,
};
use pangu_core::{
    ChatResponse, DeliverableStore, EvalContext, EvalDeliverable, EvalIssue, EvalStore, Journal,
    MemoryLimits, MemoryStore, Message, RollbackRequest, SkillRegistry, TeeSink, ToolCall, Usage,
};
use pangu_provider::OpenAiCompatibleProvider;
use pangu_toolkit::Toolkit;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "pangu", about = "在显式边界内自主使用工具的 AI agent")]
struct Cli {
    #[arg(long = "goal", global = true)]
    goal: Option<String>,
    #[arg(short = 'c', long = "config", global = true)]
    config: Option<PathBuf>,
    #[arg(long = "dry-run", global = true)]
    dry_run: bool,
    #[arg(long = "dangerously-unattended", global = true)]
    unattended: bool,
    #[arg(long = "demo", global = true)]
    demo: bool,
    #[arg(long = "workspace", global = true)]
    workspace: Option<PathBuf>,
    #[arg(long = "max-turns", global = true)]
    max_turns: Option<u32>,
    #[arg(long = "max-cost-usd", global = true)]
    max_cost_usd: Option<f64>,
    #[arg(
        long = "checkpoint",
        visible_alias = "enable-checkpoint",
        global = true,
        conflicts_with = "no_checkpoint"
    )]
    checkpoint: bool,
    #[arg(long = "no-checkpoint", global = true)]
    no_checkpoint: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Clone, Debug, Subcommand)]
enum Commands {
    Doctor {
        #[arg(long = "journal")]
        journal: Option<PathBuf>,
    },
    Config {
        #[arg(long = "file")]
        file: Option<PathBuf>,
    },
    Run {
        goal: String,
        #[arg(long = "dry-run")]
        dry_run: bool,
    },
    Rollback {
        #[arg(long = "checkpoint-id", visible_alias = "target-checkpoint")]
        checkpoint_id: String,
        #[arg(long)]
        source_node: String,
        #[arg(long)]
        rollback_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long, default_value = "cli")]
        requested_by: String,
    },
    /// Explain what the boundary would do with a hypothetical action.
    ///
    /// Advisory only: it executes nothing, writes nothing, and is never an
    /// authorization. A real run re-evaluates everything.
    Explain {
        /// Tool name as the model would request it.
        #[arg(long)]
        tool: String,
        /// Arguments as `key=value` pairs, or a single JSON object.
        #[arg(long = "arg")]
        args: Vec<String>,
        /// Resource paths the action would touch.
        #[arg(long = "path")]
        paths: Vec<PathBuf>,
        /// Network hosts the action would reach.
        #[arg(long = "host")]
        hosts: Vec<String>,
        /// Full argv for a command action.
        #[arg(long = "arg0")]
        argv: Vec<String>,
        /// Risk class. Defaults to the human-risk end, matching an
        /// unclassified tool call.
        #[arg(long, value_enum)]
        risk: Option<RiskArg>,
        #[arg(long)]
        json: bool,
    },
    /// Persisted conversation history. Resume continues a conversation; it
    /// never restores the workspace, which is `pangu rollback`'s job.
    Conversation {
        #[command(subcommand)]
        action: ConversationCommands,
    },
    /// Navigate the session tree and replay recorded conversations. Read-only.
    Session {
        #[command(subcommand)]
        action: SessionCommands,
    },
    /// Inspect a stable event stream. Read-only, and never an authorization.
    Events {
        #[command(subcommand)]
        action: EventsCommands,
    },
    /// The local read-only canvas: serve a run's trace and audit export over
    /// loopback. It has no route that runs, approves or writes anything, so a
    /// page rendered from model output can never sit next to a control that
    /// authorizes it.
    Canvas {
        /// Journal to view. Defaults to the workspace journal.
        #[arg(long)]
        journal: Option<PathBuf>,
        /// Port to bind on 127.0.0.1. 0 asks the OS to choose a free one.
        #[arg(long, default_value_t = 8787)]
        port: u16,
        /// Print the URL and the token, then exit without serving. Useful for
        /// checking what would be opened.
        #[arg(long)]
        print_url: bool,
        /// Serve without a token. Only meaningful on a machine where every
        /// process is equally trusted; the audit view can contain private
        /// paths and messages.
        #[arg(long)]
        no_token: bool,
    },
    /// Read-only operator tooling. Nothing here repairs or cleans evidence.
    Artifact {
        #[command(subcommand)]
        action: ArtifactCommands,
    },
    /// B4 provider registry and endpoint diagnostics. `list` is offline;
    /// `probe` makes one bounded GET to the configured provider endpoint.
    Models {
        #[command(subcommand)]
        action: ModelsCommands,
    },
    /// Read-only repository map (F1). Nothing here reads file contents
    /// beyond the declared surface or writes anything.
    Repo {
        #[command(subcommand)]
        action: RepoCommands,
    },
    /// B3: operator lifecycle for the memory candidate queue. The model can
    /// only propose; accepting, rejecting, and revoking happen here, outside
    /// any run.
    Memory {
        #[command(subcommand)]
        action: MemoryCommands,
    },
    /// B2: operator lifecycle for the skill registry. The model can only
    /// read a skill's instruction document; install/verify/remove happen
    /// here, outside any run.
    Skills {
        #[command(subcommand)]
        action: SkillsCommands,
    },
    /// D3/D4: operator acceptance for declared deliverables. The run can
    /// only record a delivery snapshot; accepting or rejecting it is a
    /// human decision made here.
    Deliverable {
        #[command(subcommand)]
        action: DeliverableCommands,
    },
    /// F5: issue-to-patch evaluation profile. One run becomes a reproducible
    /// experiment: issue digest, workspace version, frozen contract, patch
    /// deliverables, trajectory pointer and cost. Scores never replace
    /// acceptance.
    Eval {
        #[command(subcommand)]
        action: EvalCommands,
    },
}

/// F5: evaluation lifecycle.
#[derive(Clone, Debug, Subcommand)]
enum EvalCommands {
    /// Run one evaluation: pin the issue, execute the goal, record the facts.
    Run,
    /// List recorded evaluations (machine facts, not acceptance verdicts).
    List {
        #[arg(long)]
        json: bool,
    },
}

/// D3/D4: deliverable acceptance lifecycle (operator-only).
#[derive(Clone, Debug, Subcommand)]
enum DeliverableCommands {
    /// List recorded delivery snapshots and their acceptance status.
    List {
        #[arg(long)]
        json: bool,
        /// Only show records still awaiting acceptance.
        #[arg(long)]
        pending: bool,
    },
    /// Accept the latest pending record of one deliverable.
    Accept {
        name: String,
        #[arg(long, default_value = "cli")]
        by: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Reject the latest pending record of one deliverable.
    Reject {
        name: String,
        #[arg(long, default_value = "cli")]
        by: String,
        #[arg(long)]
        note: Option<String>,
    },
}

/// B2: skill registry lifecycle (operator-only).
#[derive(Clone, Debug, Subcommand)]
enum SkillsCommands {
    /// Generate an ed25519 signing keypair; the private key is written to
    /// --out, the public key goes to stdout (pin it in [skills] verify_key).
    Keygen {
        /// File to write the private key (64 hex chars) into.
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Validate a skill package and install it into the registry.
    Install {
        /// Path to the package directory (must contain SKILL.toml).
        path: std::path::PathBuf,
        /// File holding the private key (64 hex chars) to sign the lock.
        #[arg(long)]
        sign_key: Option<std::path::PathBuf>,
    },
    /// List installed skills with their signing status.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Recompute hashes and verify signatures for one or all skills.
    Verify {
        /// Skill name; omit to verify everything.
        name: Option<String>,
    },
    /// Remove an installed skill (uninstall is reversible by reinstalling).
    Remove { name: String },
}

/// B3: memory candidate queue lifecycle (operator-only).
#[derive(Clone, Debug, Subcommand)]
enum MemoryCommands {
    /// List candidates (pending by default, all with --all).
    List {
        #[arg(long)]
        json: bool,
        /// Show rejected/revoked candidates too.
        #[arg(long)]
        all: bool,
    },
    /// Accept a pending candidate; it will be injected (labeled untrusted)
    /// into future runs.
    Accept {
        id: String,
        #[arg(long, default_value = "cli")]
        by: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Reject a pending candidate.
    Reject {
        id: String,
        #[arg(long, default_value = "cli")]
        by: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Revoke an accepted candidate; the record and its history remain in
    /// the store.
    Revoke {
        id: String,
        #[arg(long, default_value = "cli")]
        by: String,
        #[arg(long)]
        note: Option<String>,
    },
}

#[derive(Clone, Debug, Subcommand)]
enum RepoCommands {
    /// Build the repo map and print a token-budgeted view.
    Map {
        /// Root to scan. Defaults to the current directory.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Token budget for the printed view (approximate).
        #[arg(long, default_value = "2000")]
        budget: u64,
        #[arg(long)]
        json: bool,
    },
}

/// Risk classes accepted on the command line. Kept separate from the boundary
/// enum so the CLI surface cannot grow without a deliberate change.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum RiskArg {
    ReadOnly,
    Reversible,
    Destructive,
    NeedsHuman,
}

impl From<RiskArg> for Risk {
    fn from(value: RiskArg) -> Self {
        match value {
            RiskArg::ReadOnly => Self::ReadOnly,
            RiskArg::Reversible => Self::Reversible,
            RiskArg::Destructive => Self::Destructive,
            RiskArg::NeedsHuman => Self::NeedsHuman,
        }
    }
}

/// B4: provider registry and endpoint diagnostics.
#[derive(Clone, Debug, Subcommand)]
enum ModelsCommands {
    /// List built-in provider presets, models, and price tables (offline).
    List {
        #[arg(long)]
        json: bool,
    },
    /// Make one bounded GET `<base_url>/models` to the configured provider
    /// endpoint. Operator-initiated diagnostics; never model-driven.
    Probe {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Debug, Subcommand)]
enum ArtifactCommands {
    /// Report the verifiable state of an Artifact store without changing it.
    Inspect {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

/// Conversation history commands. `list` and `show` are read-only; a resume
/// still goes through every gate.
#[derive(Clone, Debug, Subcommand)]
enum ConversationCommands {
    /// List stored conversations, oldest first.
    List,
    /// Copy one stored conversation into a new snapshot. This copies dialogue only,
    /// never the workspace, approvals, or checkpoint state.
    Clone {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "cloned-conversation")]
        run_id: String,
    },
    /// Show one conversation's metadata without its full text.
    Show {
        /// Snapshot id. Defaults to the most recent.
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Export a conversation transcript after a privacy pre-scan. The
    /// output is a derived, never-authoritative projection.
    Export {
        /// Snapshot id. Defaults to the most recent.
        #[arg(long)]
        id: Option<String>,
        /// Destination file for the JSONL transcript. Required.
        #[arg(long)]
        out: PathBuf,
        /// Refuse the export outright when a secret-shaped field is found,
        /// instead of masking it.
        #[arg(long)]
        strict: bool,
        /// Print the privacy report as JSON instead of the transcript path.
        #[arg(long)]
        json: bool,
    },
}

/// Read-only navigation over the session node ledger (A1-3). Nothing here
/// creates, moves, or deletes a node, and replaying a node is not a rollback.
#[derive(Clone, Debug, Subcommand)]
enum SessionCommands {
    /// Show the session tree: roots, children, and each node's checkpoint.
    Tree {
        #[arg(long)]
        json: bool,
    },
    /// Copy the recorded dialogue into a new snapshot. This command does not
    /// copy the workspace, approvals, or checkpoint state.
    Fork {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "forked-conversation")]
        run_id: String,
    },
    /// Reconstruct the conversation recorded at one node, without restoring the
    /// workspace. For that, use `pangu rollback`.
    Replay {
        /// Session node id.
        node: String,
        /// Print the full message list rather than a summary.
        #[arg(long)]
        full: bool,
        #[arg(long)]
        json: bool,
    },
}

/// Read-only commands over the stable event stream. Nothing here writes,
/// repairs, or re-derives a stream.
#[derive(Clone, Debug, Subcommand)]
enum EventsCommands {
    /// Read a `pangu-stream/*` file (or a journal, migrated forward).
    Read {
        /// Path to the NDJSON stream, or to a journal file.
        path: PathBuf,
        #[arg(long)]
        json: bool,
        /// Print only records of this kind.
        #[arg(long = "kind")]
        kind: Option<String>,
        /// Recompute the journal hash chain and refuse a damaged or tampered
        /// file. Without this the projection reports the `sha` it read back,
        /// which is not the same claim as "the chain checks out".
        #[arg(long)]
        verify: bool,
    },
    /// List the contract: supported versions, kinds, and their stability.
    Contract {
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Cli::parse();
    match args.command.clone() {
        Some(Commands::Doctor { journal }) => doctor(&args, journal.as_deref()),
        Some(Commands::Config { file }) => config_command(file),
        Some(Commands::Explain {
            tool,
            args: arg_pairs,
            paths,
            hosts,
            argv,
            risk,
            json,
        }) => explain_command(
            &args,
            ExplainInvocation {
                tool,
                raw_args: arg_pairs,
                paths,
                hosts,
                argv,
                risk,
                json,
            },
        ),
        Some(Commands::Run { goal, dry_run }) => {
            run_command(&args, goal, dry_run || args.dry_run).await
        }
        Some(Commands::Rollback {
            checkpoint_id,
            source_node,
            rollback_id,
            reason,
            requested_by,
        }) => {
            rollback_command(
                &args,
                checkpoint_id,
                source_node,
                rollback_id,
                reason,
                requested_by,
            )
            .await
        }
        Some(Commands::Conversation { action }) => match action {
            ConversationCommands::List => conversation_list(&args),
            ConversationCommands::Clone { id, run_id } => conversation_clone(&args, &id, &run_id),
            ConversationCommands::Show { id, json } => conversation_show(&args, id, json),
            ConversationCommands::Export {
                id,
                out,
                strict,
                json,
            } => conversation_export(&args, id, out, strict, json),
        },
        Some(Commands::Session { action }) => match action {
            SessionCommands::Fork { id, run_id } => {
                println!("session fork copies dialogue only; it does not copy the workspace");
                conversation_clone(&args, &id, &run_id)
            }
            SessionCommands::Tree { json } => session_tree(&args, json),
            SessionCommands::Replay { node, full, json } => {
                session_replay(&args, &node, full, json)
            }
        },
        Some(Commands::Canvas {
            journal,
            port,
            print_url,
            no_token,
        }) => canvas_serve(&args, journal, port, print_url, no_token).await,
        Some(Commands::Events { action }) => match action {
            EventsCommands::Read {
                path,
                json,
                kind,
                verify,
            } => events_read(&path, kind, json, verify),
            EventsCommands::Contract { json } => events_contract(json),
        },
        Some(Commands::Skills { action }) => match action {
            SkillsCommands::Keygen { out } => skills_keygen(&out),
            SkillsCommands::Install { path, sign_key } => {
                skills_install(&args, &path, sign_key.as_deref())
            }
            SkillsCommands::List { json } => skills_list(&args, json),
            SkillsCommands::Verify { name } => skills_verify(&args, name.as_deref()),
            SkillsCommands::Remove { name } => skills_remove(&args, &name),
        },
        Some(Commands::Eval { action }) => match action {
            EvalCommands::Run => eval_run(&args).await,
            EvalCommands::List { json } => eval_list(&args, json),
        },
        Some(Commands::Deliverable { action }) => match action {
            DeliverableCommands::List { json, pending } => deliverable_list(&args, json, pending),
            DeliverableCommands::Accept { name, by, note } => {
                deliverable_decide(&args, "accept", &name, &by, note)
            }
            DeliverableCommands::Reject { name, by, note } => {
                deliverable_decide(&args, "reject", &name, &by, note)
            }
        },
        Some(Commands::Repo { action }) => match action {
            RepoCommands::Map { root, budget, json } => repo_map(root, budget, json),
        },
        Some(Commands::Artifact { action }) => match action {
            ArtifactCommands::Inspect { root, json } => artifact_inspect(&root, json),
        },
        Some(Commands::Models { action }) => match action {
            ModelsCommands::List { json } => models_list(json),
            ModelsCommands::Probe { json } => models_probe(&args, json).await,
        },
        Some(Commands::Memory { action }) => match action {
            MemoryCommands::List { json, all } => memory_list(&args, json, all),
            MemoryCommands::Accept { id, by, note } => {
                memory_decide(&args, "accept", &id, &by, note)
            }
            MemoryCommands::Reject { id, by, note } => {
                memory_decide(&args, "reject", &id, &by, note)
            }
            MemoryCommands::Revoke { id, by, note } => {
                memory_decide(&args, "revoke", &id, &by, note)
            }
        },
        None if args.demo => demo(&args).await,
        None => {
            let goal = match args.goal.clone() {
                Some(goal) => goal,
                None => {
                    print!("Enter your goal: ");
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };
            run_command(&args, goal, args.dry_run).await
        }
    }
}

/// The hypothetical action, collected from the command line.
struct ExplainInvocation {
    tool: String,
    raw_args: Vec<String>,
    paths: Vec<PathBuf>,
    hosts: Vec<String>,
    argv: Vec<String>,
    risk: Option<RiskArg>,
    json: bool,
}

/// Explain what the boundary would do with a hypothetical action.
///
/// This is a projection, not a decision. It executes nothing, writes nothing,
/// emits no event, and is never consulted by the evaluation path. A real run
/// re-evaluates everything, and the real result wins if the two disagree.
fn explain_command(args: &Cli, invocation: ExplainInvocation) -> Result<()> {
    let ExplainInvocation {
        tool,
        raw_args,
        paths,
        hosts,
        argv,
        risk,
        json,
    } = invocation;

    let (config, files) = Config::load(args.config.as_deref())?;
    let policy = Policy::new(config.rules.clone())?;
    let sandbox = Sandbox::from_config(&config.boundary)?;
    let workspace = config.workspace_abs();

    let request = ExplainRequest::new(tool, parse_explain_args(&raw_args)?)
        .with_paths(paths)
        .with_hosts(hosts)
        .with_argv(argv)
        .with_risk(risk.map_or(Risk::NeedsHuman, Risk::from));
    // A path that reaches outside the configured workspace is exactly the case
    // an operator most needs explained, so say so rather than letting an
    // absolute path silently look in-bounds.
    if request.paths.iter().any(|path| path.is_absolute()) {
        eprintln!(
            "note: absolute paths are resolved as given; the projection reports whether they \
             fall inside the configured roots"
        );
    }

    let context = ExplainContext {
        policy: &policy,
        sandbox: &sandbox,
        workspace: &workspace,
        approval_mode: config.boundary.approval.mode,
        boundary_digest: &config.boundary_digest(),
    };
    let report = explain_action(&context, &request)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        eprintln!("loaded config from {files:?}");
        print!("{}", report.summary());
        for trace in &report.rules {
            println!(
                "  rule {:<24} {:<6} {:<18} {}",
                trace.rule_id,
                trace.effect.as_str(),
                trace.status.as_str(),
                trace.detail
            );
        }
        for note in &report.notes {
            println!("  note: {note}");
        }
    }
    Ok(())
}

/// Accept either a single JSON object or repeated `key=value` pairs. Anything
/// that is neither is an error rather than a silently coerced string, because
/// a mistyped argument would otherwise produce a confident wrong explanation.
fn parse_explain_args(raw: &[String]) -> Result<serde_json::Value> {
    if raw.len() == 1 && raw[0].trim_start().starts_with('{') {
        return Ok(serde_json::from_str(&raw[0])?);
    }
    let mut object = serde_json::Map::new();
    for pair in raw {
        let (key, value) = pair.split_once('=').ok_or_else(|| {
            pangu_core::Error::Config(format!(
                "explain --arg expects `key=value` or one JSON object, got `{pair}`"
            ))
        })?;
        let value = value.trim();
        let parsed = match value {
            "true" => serde_json::Value::Bool(true),
            "false" => serde_json::Value::Bool(false),
            "null" => serde_json::Value::Null,
            _ if value.parse::<i64>().is_ok() => serde_json::from_str(value)?,
            _ => serde_json::Value::String(value.to_string()),
        };
        object.insert(key.to_string(), parsed);
    }
    Ok(serde_json::Value::Object(object))
}

fn doctor(args: &Cli, journal: Option<&std::path::Path>) -> Result<()> {
    let (config, files) = Config::load(args.config.as_deref())?;
    eprintln!("loaded config from {files:?}");
    println!("{}", config.explain());
    if let Some(path) = journal {
        let events = pangu_core::replay::read(path)?;
        let summary = pangu_core::replay::Summary::from_events(&events);
        println!(
            "journal: {}\nevents: {}\nturns: {}\nmodel_calls: {}\ntools: {} ok / {} failed / {} blocked\ndenials: {}\napprovals: {}\nusage: {} input + {} output tokens\noutcome: {}",
            path.display(),
            events.len(),
            summary.turns,
            summary.model_calls,
            summary.tools_ok,
            summary.tools_failed,
            summary.tools_blocked,
            summary.denials,
            summary.approvals_asked,
            summary.input_tokens,
            summary.output_tokens,
            summary.outcome.as_deref().unwrap_or("<incomplete>"),
        );
    }
    Ok(())
}

/// Read-only Artifact inspection.
///
/// This deliberately has no repair, cleanup, delete or retry path: the
/// recovery runbook requires an operator to preserve evidence and escalate
/// instead of letting the tool guess. A non-`verified` verdict exits non-zero
/// so CI and deployment scripts cannot mistake it for a healthy store.
/// Read a stable event stream, migrating an older journal forward if needed.
///
/// Read-only and advisory. This reports what a derived projection says; it
/// cannot verify a run, and the journal remains the audit authority.
///
/// With `verify` the journal hash chain is recomputed and a damaged or
/// tampered file is refused. That distinction matters because the projection
/// otherwise echoes the `sha` it read back — "this sha was in the file" and
/// "this sha was recomputed and the chain is intact" render identically and
/// mean very different things to a CI auditor.
/// Serve the local read-only canvas.
///
/// Nothing here executes, approves or writes anything in the workspace: the
/// canvas has no route that can. It binds loopback only and mints a token by
/// default, because a trace can contain private paths and messages.
async fn canvas_serve(
    args: &Cli,
    journal: Option<PathBuf>,
    port: u16,
    print_url: bool,
    no_token: bool,
) -> Result<()> {
    let (config, _files) = Config::load(args.config.as_deref())?;
    let workspace = config.boundary.workspace.clone();

    let journal_path = match journal {
        Some(path) => path,
        None => latest_journal(&workspace)?,
    };

    // Read and verify through the same path `pangu events read --verify` uses,
    // so the canvas cannot show a different picture from the CLI.
    let events = pangu_core::replay::read(&journal_path)?;
    if events.is_empty() {
        bail!(
            "journal {} has no events; nothing to display",
            journal_path.display()
        );
    }
    let integrity = pangu_core::replay::verify_journal(&journal_path)?;

    let token = if no_token {
        None
    } else {
        Some(pangu_core::canvas::Canvas::mint_token()?)
    };

    let mut canvas = pangu_core::canvas::Canvas::new(
        journal_path
            .file_stem()
            .map(|stem| stem.to_string_lossy().to_string())
            .unwrap_or_else(|| "journal".to_string()),
        &events,
        token.clone(),
    )?;

    // Attach an audit export so the page can show the integrity statement and
    // the run's own claims alongside the timeline. The chain head recorded here
    // is the verified one, not whatever a record claimed about itself.
    //
    // The claim is displayable rather than canonical: an audit export is read
    // away from the machine that produced it (§9.3 stores it off-box), and
    // Windows canonicalization prefixes `\\?\`, which resolves nowhere else.
    let claims = vec![(
        "workspace".to_string(),
        pangu_core::util::displayable_path(&workspace),
    )];
    let head = non_empty(integrity.1.head_sha.clone());
    let log = pangu_core::audit::export(&events, head, claims)?;
    canvas = canvas.with_audit(log);

    if print_url {
        println!("{}", canvas_url(port, token.as_deref()));
        return Ok(());
    }

    let bound = canvas_server::serve(canvas, port).await?;
    println!(
        "canvas (read-only): {}",
        canvas_url(bound.port(), token.as_deref())
    );
    if token.is_some() {
        println!("the token is required on every route; the canvas is bound to 127.0.0.1 only");
    } else {
        println!("WARNING: serving without a token (--no-token)");
    }
    println!("press Ctrl-C to stop");

    // Park forever: the server only returns on a fatal bind error.
    std::future::pending::<()>().await;
    Ok(())
}

/// The URL to open, with the token when there is one.
fn canvas_url(port: u16, token: Option<&str>) -> String {
    match token {
        Some(token) => format!("http://127.0.0.1:{port}/?token={token}"),
        None => format!("http://127.0.0.1:{port}/"),
    }
}

/// Treat an empty digest as absent.
///
/// An empty journal has no chain head, and recording `""` would look like a head
/// that was checked and found to be the empty string.
fn non_empty(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// The most recently written journal in the workspace.
///
/// Chosen by modification time rather than by name: the name carries a run
/// label whose ordering is not guaranteed. An absent journal is an error rather
/// than an empty canvas, so a typo in the workspace path does not look like a
/// run that recorded nothing.
fn latest_journal(workspace: &std::path::Path) -> Result<PathBuf> {
    let dir = workspace.join(".pangu");
    let mut candidates: Vec<(SystemTime, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .with_context(|| format!("cannot read {}", dir.display()))?
        .flatten()
    {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !name.starts_with("journal") || !name.ends_with(".jsonl") {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                candidates.push((modified, path));
            }
        }
    }
    candidates
        .into_iter()
        .max_by_key(|(modified, _)| *modified)
        .map(|(_, path)| path)
        .ok_or_else(|| {
            anyhow!(
                "no journal found in {}; pass --journal <path>",
                dir.display()
            )
        })
}

fn events_read(
    path: &std::path::Path,
    kind: Option<String>,
    json: bool,
    verify: bool,
) -> Result<()> {
    let summary = pangu_core::read_stream(path)?;

    // An unrecognized filter is an error, not an empty result. A typo in
    // `--kind` that silently printed nothing reads exactly like a run that
    // never emitted that event.
    let filter = match kind.as_deref() {
        None => None,
        Some(name) => Some(
            pangu_core::StreamKind::all()
                .iter()
                .find(|kind| {
                    serde_json::to_value(kind).ok().as_ref()
                        == Some(&serde_json::Value::String(name.to_string()))
                })
                .copied()
                .ok_or_else(|| {
                    pangu_core::Error::Config(format!(
                        "unknown stream kind `{name}`; run `pangu events contract` for the list"
                    ))
                })?,
        ),
    };

    // Recompute the hash chain before printing anything, so a caller piping
    // this into a report cannot get partial output from a tampered file.
    let integrity = if verify {
        Some(verify_chain(path, &summary)?)
    } else {
        None
    };
    let events: Vec<&pangu_core::StreamEvent> = summary
        .events
        .iter()
        .filter(|event| filter.is_none_or(|wanted| event.kind == wanted))
        .collect();

    if json {
        let payload = serde_json::json!({
            "summary": summary,
            "integrity": integrity.as_ref().map(|report| &report.integrity),
            "matched": events,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        print!("{}", summary.render());
        if let Some(integrity) = &integrity {
            println!("  {}", integrity.render());
        }
        for event in &events {
            println!(
                "  [{:>3}] {:<32} {} {}",
                event.seq,
                serde_json::to_value(event.kind)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default(),
                event.data.verdict.clone().unwrap_or_else(|| "-".into()),
                event.data.message
            );
        }
    }

    // A truncated read is a failure of the read, not a partial success.
    if summary.truncated {
        return Err(anyhow::anyhow!(
            "stream read was truncated at {} record(s); the output above is a prefix, not the whole \
             stream",
            summary.events.len()
        ));
    }
    Ok(())
}

/// Render the outcome of a real hash-chain verification, as opposed to a raw
/// read-back. `JournalIntegrity` already serializes itself for `--json`.
struct ChainReport {
    integrity: pangu_core::replay::JournalIntegrity,
}

impl ChainReport {
    fn render(&self) -> String {
        let format = self.integrity.journal_format.as_deref().unwrap_or("-");
        if self.integrity.events_verified == 0 {
            return format!(
                "hash chain verified: 0 event(s) ({format}); nothing to check, so this is not \
                 evidence that the file was ever written"
            );
        }
        format!(
            "hash chain verified: {} event(s) ({format}), head sha {} matches the recomputed chain",
            self.integrity.events_verified,
            pangu_core::short_hash(&self.integrity.head_sha)
        )
    }
}

/// Recompute the journal hash chain, refusing anything that does not check out.
///
/// Fails closed on a non-journal input instead of reporting a vacuous success:
/// a `pangu-stream/*` projection carries no hash chain, so "verified" would be
/// a claim about a check that never happened.
fn verify_chain(
    path: &std::path::Path,
    summary: &pangu_core::StreamSummary,
) -> Result<ChainReport> {
    if !summary.migrated_from_journal {
        return Err(anyhow::anyhow!(
            "{} is a pangu-stream projection, which carries no hash chain to verify; point \
             --verify at the journal file itself (the audit authority)",
            path.display()
        ));
    }
    let (_events, integrity) = pangu_core::replay::verify_journal(path)
        .map_err(|error| anyhow::anyhow!("journal {} did not verify: {error}", path.display()))?;
    Ok(ChainReport { integrity })
}

/// Print the contract: which versions this build reads, and which kinds are
/// frozen. A consumer building a long-lived integration needs this before it
/// can decide what to depend on.
fn events_contract(json: bool) -> Result<()> {
    let kinds: Vec<serde_json::Value> = pangu_core::StreamKind::all()
        .iter()
        .map(|kind| {
            serde_json::json!({
                "kind": kind,
                "stability": kind.stability(),
            })
        })
        .collect();
    let contract = serde_json::json!({
        "current_schema": pangu_core::STREAM_SCHEMA_V1,
        "readable_schemas": pangu_core::EventMigrator::supported_schemas(),
        "unknown_schema_policy": "refuse; never guess a newer writer's record",
        "kinds": kinds,
        "derived": true,
        "authoritative": false,
        "note": "derived projection; the hash-chained journal remains the audit authority",
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&contract)?);
    } else {
        println!(
            "event stream contract {}\n  readable schemas: {}\n  unknown schema: refuse, never guess\n  derived projection; the journal remains the audit authority\n  kinds:",
            pangu_core::STREAM_SCHEMA_V1,
            pangu_core::EventMigrator::supported_schemas().join(", ")
        );
        for kind in pangu_core::StreamKind::all() {
            println!(
                "    {:<32} {}",
                serde_json::to_value(kind)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default(),
                kind.stability().as_str()
            );
        }
    }
    Ok(())
}

/// Build the conversation store the agent would use, without running anything.
///
/// Reuses the agent's own runtime so the CLI and a real run agree on where
/// conversations live and which of them are readable.
fn conversation_store(
    args: &Cli,
) -> Result<Option<pangu_agent::conversation::ConversationRuntime>> {
    let (mut config, _) = Config::load(args.config.as_deref())?;
    if let Some(workspace) = &args.workspace {
        config.boundary.workspace = workspace.clone();
    }
    let contract = GoalContract::from_config("conversation maintenance", &config)?;
    Ok(pangu_agent::conversation::ConversationRuntime::from_contract(&contract)?)
}

fn conversation_list(args: &Cli) -> Result<()> {
    let Some(store) = conversation_store(args)? else {
        println!("conversation persistence is disabled; enable `conversation.enabled`");
        return Ok(());
    };
    let ids = store.list().map_err(|e| anyhow::anyhow!(e))?;
    if ids.is_empty() {
        println!("no stored conversations");
        return Ok(());
    }
    for id in ids {
        let snapshot = store.load(&id).map_err(|e| anyhow::anyhow!(e))?;
        println!(
            "{}  turn-less  messages={}  digest={}  {}{}",
            id,
            snapshot.messages.len(),
            &snapshot.history_digest[..16],
            snapshot.created_at,
            match &snapshot.compaction {
                Some(record) => format!("  [compacted: -{} message(s)]", record.dropped_messages),
                None => String::new(),
            }
        );
    }
    Ok(())
}

fn conversation_clone(args: &Cli, id: &str, run_id: &str) -> Result<()> {
    let Some(runtime) = conversation_store(args)? else {
        bail!("conversation persistence is disabled");
    };
    let cloned = runtime.clone_snapshot(id, run_id)?;
    println!("{}", cloned.snapshot_id);
    Ok(())
}

fn conversation_show(args: &Cli, id: Option<String>, json: bool) -> Result<()> {
    let Some(store) = conversation_store(args)? else {
        return Err(anyhow::anyhow!(
            "conversation persistence is disabled; enable `conversation.enabled`"
        ));
    };
    let snapshot = match id {
        Some(id) => store.load(&id).map_err(|e| anyhow::anyhow!(e))?,
        None => store
            .latest()
            .map_err(|e| anyhow::anyhow!(e))?
            .ok_or_else(|| anyhow::anyhow!("no stored conversation to show"))?,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
    } else {
        println!(
            "id: {}
run: {}
created: {}
messages: {}
digest: {}
derived: true
authoritative: false",
            snapshot.snapshot_id,
            snapshot.run_id,
            snapshot.created_at,
            snapshot.messages.len(),
            snapshot.history_digest,
        );
        if let Some(record) = &snapshot.compaction {
            println!(
                "compacted from {} (dropped {}, kept {})",
                record.compacted_from_digest, record.dropped_messages, record.kept_messages
            );
        }
    }
    Ok(())
}

fn conversation_export(
    args: &Cli,
    id: Option<String>,
    out: PathBuf,
    strict: bool,
    json: bool,
) -> Result<()> {
    let Some(store) = conversation_store(args)? else {
        return Err(anyhow::anyhow!(
            "conversation persistence is disabled; enable `conversation.enabled`"
        ));
    };
    let snapshot = match id {
        Some(id) => store.load(&id).map_err(|e| anyhow::anyhow!(e))?,
        None => store
            .latest()
            .map_err(|e| anyhow::anyhow!(e))?
            .ok_or_else(|| anyhow::anyhow!("no stored conversation to export"))?,
    };
    let policy = if strict {
        pangu_core::ExportPolicy::Strict
    } else {
        pangu_core::ExportPolicy::Sanitize
    };
    let exported =
        pangu_core::export_snapshot(&snapshot, policy).map_err(|e| anyhow::anyhow!(e))?;
    std::fs::write(&out, &exported.transcript)
        .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", out.display()))?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "out": out,
                "bytes": exported.transcript.len(),
                "report": exported.report,
            }))?
        );
    } else {
        let report = &exported.report;
        println!(
            "exported {} message(s) to {} ({} bytes)",
            snapshot.messages.len(),
            out.display(),
            exported.transcript.len()
        );
        println!(
            "privacy: {} secret(s), {} absolute path(s), {} large object(s) masked/truncated{}",
            report.secrets,
            report.absolute_paths,
            report.large_objects,
            if strict { ", strict mode" } else { "" }
        );
    }
    Ok(())
}

/// B4: offline listing of the built-in provider registry. Read-only; makes no
/// network request and prints each price table's as-of date.
fn models_list(json: bool) -> Result<()> {
    use pangu_boundary::{presets, REGISTRY_VERSION};
    if json {
        let value = serde_json::json!({
            "schema": REGISTRY_VERSION,
            "providers": presets(),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    println!("provider registry {}:", REGISTRY_VERSION);
    for preset in presets() {
        println!(
            "\n{}  {}  key_env={}  prices as of {}",
            preset.name,
            preset.base_url,
            preset.api_key_env.unwrap_or("(none)"),
            preset.prices_as_of,
        );
        if preset.models.is_empty() {
            println!("  (no built-in models; declare prices explicitly in config)");
            continue;
        }
        for model in preset.models {
            println!(
                "  {:<22} context {:>9}  max out {:>7}  tools {:>3}  ${:.2} in / ${:.2} out per MTok",
                model.name,
                model.context_window_tokens,
                model.max_output_tokens,
                if model.supports_tools { "yes" } else { "no" },
                model.input_usd_per_mtok,
                model.output_usd_per_mtok,
            );
        }
    }
    println!(
        "\nprice tables go stale; verify against the provider before relying, \
         and override model.input_usd_per_mtok / model.output_usd_per_mtok when they differ"
    );
    Ok(())
}

/// B3: open the operator-side memory store handle (no run label: the CLI
/// never proposes, it only reviews and transitions).
fn memory_store_cli(config: &Config) -> Result<MemoryStore> {
    let workspace = config.workspace_abs();
    let limits = MemoryLimits {
        max_pending: config.memory.max_pending,
        max_content_bytes: config.memory.max_content_bytes,
        max_kind_bytes: config.memory.max_kind_bytes,
        max_injected: config.memory.max_injected,
        max_injected_bytes: config.memory.max_injected_bytes,
    };
    Ok(MemoryStore::open(
        &workspace.join(".pangu").join("memory"),
        limits,
    )?)
}

/// B3: show the candidate queue for operator review. The full content is
/// shown on purpose: the operator is the reviewer and must see exactly what
/// would be injected.
fn memory_list(args: &Cli, json: bool, all: bool) -> Result<()> {
    let (config, _files) = Config::load(args.config.as_deref())?;
    let store = memory_store_cli(&config)?;
    let candidates = store.candidates();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": pangu_core::MEMORY_SCHEMA,
                "candidates": candidates,
                "derived": true,
                "authoritative": false,
            }))?
        );
        return Ok(());
    }
    let shown: Vec<_> = candidates
        .iter()
        .filter(|candidate| all || candidate.status == pangu_core::MemoryStatus::Pending)
        .collect();
    if shown.is_empty() {
        println!("no {} candidates", if all { "" } else { "pending" });
        return Ok(());
    }
    for candidate in shown {
        println!(
            "{} [{}] {} proposed={} digest={}",
            candidate.id,
            candidate.kind,
            candidate.status.as_str(),
            candidate.proposed_at,
            &candidate.content_digest[..12],
        );
        if let Some(run) = &candidate.proposed_in_run {
            println!("  run: {run}");
        }
        println!("  content: {}", candidate.content);
        for transition in &candidate.transitions {
            println!(
                "  transition: {} at {} by {}{}",
                transition.action,
                transition.at,
                transition.by,
                transition
                    .note
                    .as_deref()
                    .map(|note| format!(" ({note})"))
                    .unwrap_or_default(),
            );
        }
    }
    Ok(())
}

/// B3: one operator lifecycle transition (accept/reject/revoke). The store
/// enforces the legal-transition rules; the CLI only routes the decision.
fn memory_decide(args: &Cli, action: &str, id: &str, by: &str, note: Option<String>) -> Result<()> {
    let (config, _files) = Config::load(args.config.as_deref())?;
    let store = memory_store_cli(&config)?;
    match action {
        "accept" => store.accept(id, by, note)?,
        "reject" => store.reject(id, by, note)?,
        "revoke" => store.revoke(id, by, note)?,
        other => bail!("unknown memory action {other}"),
    }
    let past = match action {
        "accept" => "accepted",
        "reject" => "rejected",
        "revoke" => "revoked",
        other => other,
    };
    println!("{past} {id}");
    Ok(())
}

/// B2: generate an ed25519 signing keypair. The private key lands in the
/// requested file; only the public key is printed.
fn skills_keygen(out: &std::path::Path) -> Result<()> {
    let (seed_hex, public_hex) = pangu_core::skills::keygen()?;
    std::fs::write(
        out,
        format!(
            "{seed_hex}
"
        ),
    )
    .with_context(|| format!("writing {}", out.display()))?;
    println!("private key: {} (keep it secret)", out.display());
    println!("public key (pin in [skills] verify_key): {public_hex}");
    Ok(())
}

/// B2: validate a package and install it into the registry. Installation is
/// an operator action; the model has no path to it.
fn skills_install(
    args: &Cli,
    source: &std::path::Path,
    sign_key: Option<&std::path::Path>,
) -> Result<()> {
    let (config, _files) = Config::load(args.config.as_deref())?;
    let workspace = config.workspace_abs();
    let limits = config.skills.limits();
    let lock = pangu_core::skills::compute_lock(source, &limits)?;
    let lock = match sign_key {
        Some(key_path) => {
            let seed = std::fs::read_to_string(key_path)
                .with_context(|| format!("reading {}", key_path.display()))?;
            pangu_core::skills::sign_lock(&lock, seed.trim())?
        }
        None => lock,
    };
    let target = workspace.join(".pangu").join("skills").join(&lock.name);
    if target.exists() {
        bail!(
            "skill `{}` is already installed; remove it first (pangu skills remove {})",
            lock.name,
            lock.name
        );
    }
    std::fs::create_dir_all(&target)?;
    // Copy every locked file; the lock itself is written last so a crash
    // mid-copy leaves an unloadable (rejected) directory, never a verified
    // one with missing files.
    for file in &lock.files {
        let from = source.join(file.path.replace('/', std::path::MAIN_SEPARATOR_STR));
        let to = target.join(file.path.replace('/', std::path::MAIN_SEPARATOR_STR));
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&from, &to).with_context(|| format!("copying {}", file.path))?;
    }
    std::fs::write(
        target.join(pangu_core::skills::SKILL_LOCK_FILE),
        serde_json::to_string_pretty(&lock)?,
    )?;
    let signed = if lock.signature.is_some() {
        "signed"
    } else {
        "unsigned (no signing key provided)"
    };
    println!(
        "installed `{}` v{} [{}] files={} digest={}",
        lock.name,
        lock.version,
        signed,
        lock.files.len(),
        &lock.package_digest[..12],
    );
    Ok(())
}

/// B2: list installed skills.
fn skills_list(args: &Cli, json: bool) -> Result<()> {
    let (config, _files) = Config::load(args.config.as_deref())?;
    let registry = skills_registry(&config)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "skills": registry.skills().iter().map(|skill| serde_json::json!({
                    "name": skill.name,
                    "version": skill.version,
                    "description": skill.description,
                    "signed": skill.signature_verified(),
                    "signature_state": skill.signature_state.as_str(),
                    "package_digest": skill.lock.package_digest,
                    "files": skill.lock.files.len(),
                    "scripts": skill.lock.scripts,
                })).collect::<Vec<_>>(),
                "rejected": registry.rejected().iter().map(|rejected| serde_json::json!({
                    "dir_name": rejected.dir_name,
                    "reason": rejected.reason,
                })).collect::<Vec<_>>(),
                "derived": true,
                "authoritative": false,
            }))?
        );
        return Ok(());
    }
    for skill in registry.skills() {
        let trust = skill.signature_state.as_str();
        println!(
            "{} v{} [{}] files={} scripts={}",
            skill.name,
            skill.version,
            trust,
            skill.lock.files.len(),
            skill.lock.scripts.len(),
        );
        println!("  {}", skill.description);
    }
    for rejected in registry.rejected() {
        println!("REJECTED {}: {}", rejected.dir_name, rejected.reason);
    }
    if registry.skills().is_empty() && registry.rejected().is_empty() {
        println!("no skills installed");
    }
    Ok(())
}

/// B2: re-verify integrity (and signatures where present) of one or all
/// skills by reloading the registry — load verification IS the check.
fn skills_verify(args: &Cli, name: Option<&str>) -> Result<()> {
    let (config, _files) = Config::load(args.config.as_deref())?;
    let registry = skills_registry(&config)?;
    let mut failures = 0usize;
    for skill in registry.skills() {
        if let Some(wanted) = name {
            if skill.name != wanted {
                continue;
            }
        }
        let status = match skill.signature_state {
            pangu_core::SkillSignatureState::Verified => "verified (hashes + signature)",
            pangu_core::SkillSignatureState::Invalid => {
                failures += 1;
                "FAILED (signature does not verify)"
            }
            pangu_core::SkillSignatureState::Unverified => {
                "hashes ok; signature present but no verify_key pinned"
            }
            pangu_core::SkillSignatureState::Unsigned => "hashes ok, unsigned",
        };
        println!("{} v{}: {}", skill.name, skill.version, status);
    }
    for rejected in registry.rejected() {
        if name
            .map(|wanted| rejected.dir_name != wanted)
            .unwrap_or(false)
        {
            continue;
        }
        failures += 1;
        println!("{}: FAILED ({})", rejected.dir_name, rejected.reason);
    }
    if failures > 0 {
        bail!("{failures} skill(s) failed verification");
    }
    Ok(())
}

/// B2: remove an installed skill. Uninstall is reversible by reinstalling;
/// the registry directory is the only state involved.
fn skills_remove(args: &Cli, name: &str) -> Result<()> {
    let (config, _files) = Config::load(args.config.as_deref())?;
    let workspace = config.workspace_abs();
    let target = workspace.join(".pangu").join("skills").join(name);
    if !target.is_dir() {
        bail!("skill `{name}` is not installed");
    }
    std::fs::remove_dir_all(&target).with_context(|| format!("removing {}", target.display()))?;
    println!("removed {name}");
    Ok(())
}

/// F5: probe the workspace's git version. An observation of the operator
/// environment, recorded so an evaluation can be reproduced against the same
/// checkout; failures degrade honestly to `unknown`.
fn probe_workspace_version(workspace: &std::path::Path) -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(workspace)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// F5: run one issue-to-patch evaluation. The issue document is pinned by
/// content digest at run start and becomes the goal text (with its source
/// labeled); the run proceeds through the exact same boundary chain as
/// `pangu run`, and its machine-fact outcome is appended to
/// `<workspace>/.pangu/eval/records.json`. A run that errors before a
/// terminal state is audited in the journal only.
async fn eval_run(args: &Cli) -> Result<()> {
    let (mut config, files) = Config::load(args.config.as_deref())?;
    if !config.eval.is_declared() {
        bail!(
            "no evaluation profile declared; set [eval] profile and issue_path in the config \
             (see `pangu config`)"
        );
    }
    let overrides = CliOverrides {
        workspace: args.workspace.clone(),
        max_turns: args.max_turns,
        max_cost_usd: args.max_cost_usd,
        unattended: args.unattended,
        checkpoint_enabled: if args.checkpoint {
            Some(true)
        } else if args.no_checkpoint {
            Some(false)
        } else {
            None
        },
        ..Default::default()
    };
    config = config.apply(&overrides)?;
    if args.unattended {
        eprintln!("WARNING: unattended mode disables human approval; this is not a safety mode");
    }
    let workspace = config.workspace_abs();
    let issue_path = workspace.join(
        config
            .eval
            .issue_path
            .replace('/', std::path::MAIN_SEPARATOR_STR),
    );
    let issue_meta = std::fs::metadata(&issue_path)
        .map_err(|error| anyhow!("issue document {}: {error}", issue_path.display()))?;
    if !issue_meta.is_file() {
        bail!(
            "issue document {} is not a regular file",
            issue_path.display()
        );
    }
    if issue_meta.len() > 262_144 {
        bail!(
            "issue document {} is {} bytes; the evaluation input limit is 262144 bytes",
            issue_path.display(),
            issue_meta.len()
        );
    }
    let issue_content = std::fs::read_to_string(&issue_path)
        .map_err(|error| anyhow!("reading issue document {}: {error}", issue_path.display()))?;
    let issue = EvalIssue {
        path: config.eval.issue_path.clone(),
        sha256: pangu_core::hex_sha256(&issue_content),
    };
    let workspace_version = probe_workspace_version(&workspace);
    let store = EvalStore::open(&workspace.join(".pangu").join("eval"))?;
    let context = EvalContext {
        profile: config.eval.profile.clone(),
        issue: issue.clone(),
        workspace_version: workspace_version.clone(),
        contract_digest: String::new(),
        started_at: pangu_core::now_rfc3339(),
        store,
    };
    // The goal text embeds the issue with its source labeled: the model sees
    // where the task came from, and the digest pins exactly which version.
    let goal = format!(
        "Fix the issue below.\n\nIssue source: {} (sha256:{})\nWorkspace version: {}\n\n---\n{}",
        issue.path, issue.sha256, workspace_version, issue_content
    );
    let (primary, fallbacks) = build_provider_chain(&config)?;
    let status = execute_goal(
        config,
        files,
        goal,
        primary,
        fallbacks,
        false,
        Some(context),
    )
    .await?;
    if !status.is_success() {
        bail!("evaluation run ended with status {status}");
    }
    Ok(())
}

/// F5: list recorded evaluations. Every record carries the fixed disclaimer:
/// these are machine facts about runs, not acceptance verdicts.
fn eval_list(args: &Cli, json: bool) -> Result<()> {
    let (config, _) = Config::load(args.config.as_deref())?;
    let workspace = config.workspace_abs();
    let store = EvalStore::open(&workspace.join(".pangu").join("eval"))?;
    let records = store.records();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": pangu_core::EVAL_SCHEMA,
                "records": records,
                "derived": true,
                "authoritative": false,
            }))?
        );
        return Ok(());
    }
    if records.is_empty() {
        println!("no evaluation records");
        return Ok(());
    }
    for record in records {
        let cost = record
            .cost_usd
            .map(|cost| format!("${cost:.4}"))
            .unwrap_or_else(|| "unpriced".to_string());
        println!(
            "{} [{}] profile={} status={} turns={} verify_evidence={} cost={}",
            record.id,
            record.finished_at,
            record.profile,
            record.status,
            record.turns,
            record.verify_evidence,
            cost
        );
        println!(
            "  issue: {} (sha256:{})",
            record.issue.path,
            &record.issue.sha256[..12]
        );
        println!("  workspace_version: {}", record.workspace_version);
        println!("  contract: {}", &record.contract_digest[..12]);
        println!(
            "  usage: {} in / {} out tokens",
            record.input_tokens, record.output_tokens
        );
        println!("  journal: {}", record.journal);
        for deliverable in &record.deliverables {
            println!(
                "  deliverable {} [{}] bytes={} sha256={} acceptance={}",
                deliverable.name,
                deliverable.path,
                deliverable.bytes,
                &deliverable.sha256[..12],
                deliverable.acceptance
            );
        }
    }
    Ok(())
}

/// D3/D4: open the operator-side deliverable registry.
fn deliverables_cli(config: &Config) -> Result<DeliverableStore> {
    let workspace = config.workspace_abs();
    Ok(DeliverableStore::open(
        &workspace.join(".pangu").join("deliverables"),
    )?)
}

/// D3/D4: list recorded delivery snapshots.
fn deliverable_list(args: &Cli, json: bool, pending_only: bool) -> Result<()> {
    let (config, _files) = Config::load(args.config.as_deref())?;
    let store = deliverables_cli(&config)?;
    let records = store.records();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": pangu_core::DELIVERABLES_SCHEMA,
                "records": records,
                "derived": true,
                "authoritative": false,
            }))?
        );
        return Ok(());
    }
    let shown: Vec<_> = records
        .iter()
        .filter(|record| !pending_only || record.acceptance == pangu_core::Acceptance::Pending)
        .collect();
    if shown.is_empty() {
        println!("no deliverable records");
        return Ok(());
    }
    for record in shown {
        println!(
            "{} [{}] {} {} sha256={} bytes={}",
            record.name,
            record.kind,
            record.acceptance.as_str(),
            record.path,
            &record.sha256[..12],
            record.bytes,
        );
        if let Some(run) = &record.run {
            println!("  run: {run}");
        }
        println!("  recorded: {}", record.recorded_at);
        for transition in &record.transitions {
            println!(
                "  {}: at {} by {}{}",
                transition.action,
                transition.at,
                transition.by,
                transition
                    .note
                    .as_deref()
                    .map(|note| format!(" ({note})"))
                    .unwrap_or_default(),
            );
        }
    }
    Ok(())
}

/// D3/D4: one operator acceptance transition.
fn deliverable_decide(
    args: &Cli,
    action: &str,
    name: &str,
    by: &str,
    note: Option<String>,
) -> Result<()> {
    let (config, _files) = Config::load(args.config.as_deref())?;
    let store = deliverables_cli(&config)?;
    match action {
        "accept" => store.accept(name, by, note)?,
        "reject" => store.reject(name, by, note)?,
        other => bail!("unknown deliverable action {other}"),
    }
    println!("{action}ed deliverable `{name}`");
    Ok(())
}

/// B2: load the operator-side registry handle.
fn skills_registry(config: &Config) -> Result<SkillRegistry> {
    let workspace = config.workspace_abs();
    let limits = config.skills.limits();
    let verify_key = config.skills.verify_key.trim();
    Ok(SkillRegistry::load(
        &workspace.join(".pangu").join("skills"),
        &limits,
        if verify_key.is_empty() {
            None
        } else {
            Some(verify_key)
        },
    )?)
}

/// B4: one bounded capability probe against the effective provider endpoint.
async fn models_probe(args: &Cli, json: bool) -> Result<()> {
    let (config, _files) = Config::load(args.config.as_deref())?;
    let resolved = config.resolve_provider()?;
    let api_key = match &resolved.api_key_env {
        Some(name) => Some(
            std::env::var(name)
                .map_err(|_| anyhow::anyhow!("API key environment variable `{name}` is not set"))?,
        ),
        None => None,
    };
    let timeout = config.model.request_timeout_secs.unwrap_or(60);
    let models =
        pangu_provider::probe_models(&resolved.base_url, api_key.as_deref(), timeout).await?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "endpoint": resolved.base_url,
                "count": models.len(),
                "models": models,
            }))?
        );
        return Ok(());
    }
    println!(
        "endpoint {} offers {} model(s):",
        resolved.base_url,
        models.len()
    );
    for model in &models {
        println!("  {model}");
    }
    Ok(())
}

fn repo_map(root: Option<PathBuf>, budget: u64, json: bool) -> Result<()> {
    let root = root.unwrap_or_else(|| PathBuf::from("."));
    let map = pangu_core::build_repomap(&root, pangu_core::RepoMapOptions::default())
        .map_err(|e| anyhow::anyhow!(e))?;
    let view = pangu_core::repomap_view(&map, budget);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "fingerprint": pangu_core::repomap_fingerprint(&map),
                "files": map.files.len(),
                "edges": map.edges.len(),
                "skipped": map.skipped,
                "view": view,
            }))?
        );
    } else {
        println!(
            "# repo map  root={}  files={}  edges={}  fingerprint={}",
            map.root,
            map.files.len(),
            map.edges.len(),
            &pangu_core::repomap_fingerprint(&map)[..16]
        );
        if !map.skipped.is_empty() {
            println!("# skipped: {} entries", map.skipped.len());
        }
        print!("{}", view.text);
        if view.truncated {
            println!(
                "# … {} file(s) omitted by the {}-token budget",
                view.omitted_files.len(),
                budget
            );
        }
    }
    Ok(())
}

fn artifact_inspect(root: &std::path::Path, json: bool) -> Result<()> {
    let report = pangu_core::inspect_artifact_root(root)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "artifact root: {}\ninspected at: {}\nread-only: {}\n{}",
            report.root,
            report.generated_at,
            report.read_only,
            report.summary()
        );
        for checkpoint in &report.checkpoints {
            println!(
                "  checkpoint {} state={} verified={} marker={} files={} bytes={} node={} external_effect_after={}",
                checkpoint.checkpoint_id,
                serde_json::to_string(&checkpoint.state)?.trim_matches('"'),
                checkpoint.verified,
                checkpoint.committed_marker,
                checkpoint.file_entries,
                checkpoint.total_bytes,
                checkpoint
                    .session_node
                    .as_ref()
                    .map(|node| format!("{} consistent={}", node.session_node_id, node.consistent))
                    .unwrap_or_else(|| "<none>".into()),
                checkpoint.external_effect_after
            );
        }
        for operation in &report.operations {
            println!(
                "  operation {} checkpoint={} status={} transition_node={} error={}",
                operation.rollback_id,
                operation.checkpoint_id,
                serde_json::to_string(&operation.status)?.trim_matches('"'),
                operation
                    .transition_session_node_id
                    .as_deref()
                    .unwrap_or("<none>"),
                operation.error.as_deref().unwrap_or("<none>")
            );
        }
        for backup in &report.replace_backups {
            println!(
                "  replace-backup evidence: {}/{}",
                backup.scope, backup.path
            );
        }
        for problem in &report.problems {
            println!(
                "  [{}] {}: {}",
                problem.code, problem.subject, problem.detail
            );
        }
    }
    if report.verdict != pangu_core::InspectionVerdict::Verified {
        bail!(
            "artifact store is not fully verified; operator action is required: {}",
            report.summary()
        );
    }
    Ok(())
}

fn config_command(file: Option<PathBuf>) -> Result<()> {
    let source = Config::sample();
    match file {
        Some(path) => {
            std::fs::write(&path, source).with_context(|| format!("write {}", path.display()))?;
            eprintln!("wrote {}", path.display());
        }
        None => print!("{source}"),
    }
    Ok(())
}

async fn run_command(args: &Cli, goal: String, dry_run: bool) -> Result<()> {
    if goal.trim().is_empty() {
        bail!("goal must not be empty");
    }
    if args.unattended {
        eprintln!("WARNING: unattended mode disables human approval; this is not a safety mode");
    }
    let (mut config, files) = Config::load(args.config.as_deref())?;
    let overrides = CliOverrides {
        workspace: args.workspace.clone(),
        max_turns: args.max_turns,
        max_cost_usd: args.max_cost_usd,
        unattended: args.unattended,
        checkpoint_enabled: if args.checkpoint {
            Some(true)
        } else if args.no_checkpoint {
            Some(false)
        } else {
            None
        },
        ..Default::default()
    };
    config = config.apply(&overrides)?;
    if dry_run {
        println!(
            "dry run: no provider request or tool execution\n\n{}",
            config.explain()
        );
        return Ok(());
    }
    let (primary, fallbacks) = build_provider_chain(&config)?;
    let status = execute_goal(config, files, goal, primary, fallbacks, false, None).await?;
    if !status.is_success() {
        bail!("agent ended with status {status}");
    }
    Ok(())
}

async fn rollback_command(
    args: &Cli,
    checkpoint_id: String,
    source_session_node_id: String,
    rollback_id: String,
    reason: String,
    requested_by: String,
) -> Result<()> {
    if args.unattended {
        bail!("rollback requires an explicit human approval and cannot run unattended");
    }
    let (mut config, files) = Config::load(args.config.as_deref())?;
    config = config.apply(&CliOverrides {
        workspace: args.workspace.clone(),
        max_turns: args.max_turns,
        max_cost_usd: args.max_cost_usd,
        unattended: false,
        checkpoint_enabled: if args.checkpoint {
            Some(true)
        } else if args.no_checkpoint {
            Some(false)
        } else {
            None
        },
        ..Default::default()
    })?;
    if !config.checkpoint.enabled {
        bail!("checkpoint/rollback is disabled; enable it in config or pass --checkpoint");
    }
    let request = RollbackRequest {
        rollback_id,
        checkpoint_id,
        source_session_node_id,
        reason,
        failed_path_ref: None,
        requested_by,
    };
    request.validate()?;
    let mut contract = GoalContract::from_config("rollback maintenance", &config)?;
    contract.config_files = files
        .iter()
        .map(|path| pangu_core::util::displayable_path(path))
        .collect();
    if contract.is_unattended() {
        bail!("rollback cannot run with an unattended approval mode");
    }
    if args.dry_run {
        println!(
            "rollback dry run: checkpoint={} source_node={} rollback_id={}",
            request.checkpoint_id, request.source_session_node_id, request.rollback_id
        );
        return Ok(());
    }
    let policy = Arc::new(Policy::new(config.rules.clone())?);
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary)?);
    let journal_path = contract
        .workspace()
        .join(".pangu")
        .join(format!("journal-rollback-{}.jsonl", unix_nanos()));
    let journal = Arc::new(Journal::create_v2(&journal_path)?);
    let console = Arc::new(pangu_core::ConsoleSink::new(true, false));
    let sink = Arc::new(TeeSink::new(vec![journal, console]));
    let approval: Arc<dyn pangu_boundary::ApprovalHandler> = Arc::new(StdinApproval::new(
        contract.approval_mode,
        Duration::from_secs(config.boundary.approval.ask_timeout_secs),
    ));
    let memory = build_memory_store(
        &config,
        contract.workspace(),
        &format!("run-{}", unix_nanos()),
    )?;
    let skills = build_skills_registry(&config, contract.workspace())?;
    let deliverables = build_deliverables_registry(&config, contract.workspace())?;
    let toolkit = {
        let base = Toolkit::with_verify_command(config.verify.command.clone());
        let base = match &memory {
            Some(store) => base.with_memory(store.clone()),
            None => base,
        };
        let base = match &skills {
            Some(registry) => base.with_skills(registry.clone()),
            None => base,
        };
        let base = attach_runtime(base, &config, contract.workspace());
        let base = attach_browser(base, &config, contract.workspace())?;
        Arc::new(base)
    };
    let mut agent = Agent::new(
        contract,
        policy,
        sandbox,
        Arc::new(DemoProvider {
            calls: AtomicUsize::new(0),
        }),
        toolkit,
        approval,
        sink,
    )?;
    if let Some(store) = memory {
        agent = agent.with_memory(store);
    }
    if let Some(registry) = skills {
        agent = agent.with_skills(registry);
    }
    if let Some(store) = deliverables {
        agent = agent.with_deliverables(store);
    }
    let result = agent.rollback(request).await?;
    println!(
        "rollback: {:?}\ncheckpoint: {}\nsession_node: {}\njournal: {}",
        result.disposition,
        result.artifact.checkpoint_id,
        result.session_node_id.as_deref().unwrap_or("<unchanged>"),
        journal_path.display()
    );
    Ok(())
}

async fn demo(args: &Cli) -> Result<()> {
    eprintln!("WARNING: unattended demo mode; no human approval will be requested");
    let (config, files) = Config::load(args.config.as_deref())?;
    // `--checkpoint` / `--no-checkpoint` are runtime overrides, so they have
    // to be applied here too. Without this, `pangu --checkpoint --demo` and
    // `pangu --config cfg-with-checkpoint-off --demo` would quietly disagree
    // with what the operator asked for, in opposite directions, and neither
    // would say so.
    let mut config = config.apply(&CliOverrides {
        unattended: true,
        checkpoint_enabled: if args.checkpoint {
            Some(true)
        } else if args.no_checkpoint {
            Some(false)
        } else {
            None
        },
        ..Default::default()
    })?;
    // The scripted demo has no external billing. Declare its zero price
    // explicitly so the normal fail-closed cost gate remains meaningful.
    config.model.input_usd_per_mtok = Some(0.0);
    config.model.output_usd_per_mtok = Some(0.0);
    config.validate()?;
    if args.dry_run {
        println!("demo dry run\n\n{}", config.explain());
        return Ok(());
    }
    let provider = Arc::new(DemoProvider {
        calls: AtomicUsize::new(0),
    });
    let status = execute_goal(
        config,
        files,
        "读取 Cargo.toml 并报告包名".into(),
        provider,
        Vec::new(),
        true,
        None,
    )
    .await?;
    if !status.is_success() {
        bail!("demo ended with status {status}");
    }
    Ok(())
}

/// B5: build the declared provider chain (primary + fallbacks). Every member
/// is resolved and validated at config time; keys are read from the
/// environment here, so a missing fallback key fails the run loudly instead
/// of silently dropping the candidate.
type ProviderChain = (Arc<dyn Provider>, Vec<Arc<dyn Provider>>);

/// B3: build the run-side memory store when the contract enables the queue.
/// The store lives under `<workspace>/.pangu/memory/`, which the default
/// forbidden globs exclude from every tool I/O path — the only writers are
/// this store's own propose/transition methods.
fn build_memory_store(
    config: &Config,
    workspace: &std::path::Path,
    run_label: &str,
) -> Result<Option<Arc<MemoryStore>>> {
    if !config.memory.enabled {
        return Ok(None);
    }
    let limits = MemoryLimits {
        max_pending: config.memory.max_pending,
        max_content_bytes: config.memory.max_content_bytes,
        max_kind_bytes: config.memory.max_kind_bytes,
        max_injected: config.memory.max_injected,
        max_injected_bytes: config.memory.max_injected_bytes,
    };
    Ok(Some(Arc::new(MemoryStore::open_with_label(
        &workspace.join(".pangu").join("memory"),
        limits,
        Some(run_label.to_string()),
    )?)))
}

/// B2: build the run-side skill registry when the contract enables it. The
/// F8: resolve and attach the declared OS-level sandbox.
///
/// Resolution **probes** the runtime, so an operator learns at startup whether
/// the sandbox they asked for actually works — rather than from every command
/// being refused mid-run, or worse, from believing they had isolation they did
/// not have.
///
/// An unresolvable runtime is attached anyway rather than silently dropped: the
/// toolkit then refuses commands, which is the intended fail-closed behaviour.
/// Dropping it here would quietly restore host execution, which is exactly the
/// failure this feature removes.
fn attach_runtime(toolkit: Toolkit, config: &Config, workspace: &std::path::Path) -> Toolkit {
    if !config.execution.isolates() {
        return toolkit;
    }
    let runtime = config
        .execution
        .runtime_config(workspace.to_path_buf())
        .resolve();
    toolkit.with_runtime(Arc::new(runtime))
}

/// F9: attach the browser when the operator enabled it.
///
/// Returns the toolkit unchanged when `[browser] enabled = false` (the default),
/// in which case the browser tools are **not advertised at all** — the model
/// cannot call a capability the operator did not turn on.
///
/// A configuration error is reported rather than degraded: an operator who
/// enabled the browser and pointed it at a missing executable should hear about
/// it at startup, not discover it when a model first clicks.
fn attach_browser(
    toolkit: Toolkit,
    config: &Config,
    workspace: &std::path::Path,
) -> Result<Toolkit> {
    if !config.browser.enabled {
        return Ok(toolkit);
    }
    // Cookies and cache must not enter the workspace snapshot. `.pangu` is
    // excluded from checkpoints, so a profile there would disappear on rollback.
    let profile_root = std::env::temp_dir().join("pangu-browser");
    let profile = pangu_boundary::browser::profile_dir_under(
        &profile_root,
        &format!("browser-{}", unix_nanos()),
    );
    let mut profile_parts = profile.components();
    let profile_is_child = profile_root
        .components()
        .all(|component| profile_parts.next() == Some(component))
        && profile_parts.next().is_some();
    if !profile_is_child {
        anyhow::bail!(
            "browser profile {} is not inside {}",
            profile.display(),
            profile_root.display()
        );
    }
    let browser_config = pangu_toolkit::browser::resolve_config(
        config.browser.executable.as_deref(),
        profile,
        config.browser.network,
        config.browser.args.clone(),
    )?;
    // Screenshots go inside the run's own storage so they are covered by the
    // same rules as every other artifact, and are cleaned up with the run.
    let artifacts = workspace.join("artifacts").join("browser");
    if artifacts
        .components()
        .any(|component| component.as_os_str() == ".pangu")
    {
        anyhow::bail!(
            "browser screenshots must not be stored under .pangu; checkpoints exclude that tree"
        );
    }
    std::fs::create_dir_all(&artifacts).map_err(|error| {
        anyhow::anyhow!(
            "cannot create the browser artifact directory {}: {error}",
            artifacts.display()
        )
    })?;
    Ok(toolkit.with_browser(browser_config, artifacts))
}

/// registry lives under `<workspace>/.pangu/skills/` (tool-forbidden); the
/// contract already froze the loaded skill set, and the run compares against
/// it at startup.
fn build_skills_registry(
    config: &Config,
    workspace: &std::path::Path,
) -> Result<Option<Arc<SkillRegistry>>> {
    if !config.skills.enabled {
        return Ok(None);
    }
    let limits = config.skills.limits();
    let verify_key = config.skills.verify_key.trim();
    Ok(Some(Arc::new(SkillRegistry::load(
        &workspace.join(".pangu").join("skills"),
        &limits,
        if verify_key.is_empty() {
            None
        } else {
            Some(verify_key)
        },
    )?)))
}

/// D1: builds the restricted executor each sub-agent runs with: a fresh
/// toolkit with the contract-frozen verify command and nothing else — no
/// memory queue, no skills, no delegation. The child contract is checked
/// against whatever this returns, so a wider factory is refused, not
/// silently honored.
struct FreshToolkitFactory;

impl pangu_agent::SubtoolFactory for FreshToolkitFactory {
    fn build(&self, verify_command: Vec<String>) -> Result<Arc<dyn pangu_agent::ToolExecutor>> {
        Ok(Arc::new(Toolkit::with_verify_command(verify_command)))
    }
}

/// D3/D4: build the deliverable registry when the contract declares
/// deliverables. The registry lives under `<workspace>/.pangu/deliverables/`
/// (tool-forbidden); the run's finish gate records into it, and the
/// operator's accept/reject decisions live there.
fn build_deliverables_registry(
    config: &Config,
    workspace: &std::path::Path,
) -> Result<Option<Arc<DeliverableStore>>> {
    if config.goal.deliverable.is_empty() {
        return Ok(None);
    }
    Ok(Some(Arc::new(DeliverableStore::open(
        &workspace.join(".pangu").join("deliverables"),
    )?)))
}

fn build_provider_chain(config: &Config) -> Result<ProviderChain> {
    let resolved = config.resolve_provider()?;
    let model = resolved
        .model
        .clone()
        .ok_or_else(|| anyhow::anyhow!("model.model is required for a live run"))?;
    if resolved.input_usd_per_mtok.is_none() || resolved.output_usd_per_mtok.is_none() {
        bail!(
            "model input/output prices are required for a live run; set model.input_usd_per_mtok \
             and model.output_usd_per_mtok, or use model.provider with a known model (see `pangu models list`)"
        );
    }
    let primary = Arc::new(OpenAiCompatibleProvider::from_env(
        model,
        resolved.base_url,
        resolved.api_key_env.as_deref(),
        config.model.temperature,
        config.model.max_output_tokens,
        config.model.request_timeout_secs.unwrap_or(60),
    )?);
    let mut fallbacks = Vec::new();
    for candidate in config.resolve_fallbacks()? {
        let provider = Arc::new(OpenAiCompatibleProvider::from_env(
            candidate.model.clone(),
            candidate.base_url,
            candidate.api_key_env.as_deref(),
            config.model.temperature,
            config.model.max_output_tokens,
            config.model.request_timeout_secs.unwrap_or(60),
        )?);
        fallbacks.push(provider as Arc<dyn Provider>);
    }
    Ok((primary as Arc<dyn Provider>, fallbacks))
}

async fn execute_goal(
    config: Config,
    files: Vec<PathBuf>,
    goal: String,
    primary: Arc<dyn Provider>,
    fallbacks: Vec<Arc<dyn Provider>>,
    use_unattended: bool,
    eval: Option<EvalContext>,
) -> Result<pangu_boundary::GoalStatus> {
    let mut contract = GoalContract::from_config(goal, &config)?;
    contract.config_files = files
        .iter()
        .map(|path| pangu_core::util::displayable_path(path))
        .collect();
    // F5: pin the frozen contract into the evaluation context before the
    // agent is built (the contract is moved into it). The digest does not
    // include the goal text; the issue content is pinned separately by its
    // own digest in the evaluation record.
    let eval = eval.map(|mut context| {
        context.contract_digest = contract.digest().to_string();
        context
    });
    let policy = Arc::new(Policy::new(config.rules.clone())?);
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary)?);
    let run_label = format!("run-{}", unix_nanos());
    let journal_path = contract
        .workspace()
        .join(".pangu")
        .join(format!("journal-{run_label}.jsonl"));
    let journal = Arc::new(if contract.checkpoint.enabled {
        Journal::create_v2(&journal_path)?
    } else {
        Journal::create(&journal_path)?
    });
    let console = Arc::new(pangu_core::ConsoleSink::new(true, false));
    let sink = Arc::new(TeeSink::new(vec![journal, console]));
    let approval: Arc<dyn pangu_boundary::ApprovalHandler> =
        if use_unattended || contract.is_unattended() {
            Arc::new(Unattended(contract.approval_mode()))
        } else {
            Arc::new(StdinApproval::new(
                contract.approval_mode(),
                Duration::from_secs(config.boundary.approval.ask_timeout_secs),
            ))
        };
    let mut providers: Vec<Arc<dyn Provider>> = vec![primary];
    providers.extend(fallbacks);
    // B3: attach the memory queue when the contract enables it. The same
    // store backs the toolkit's `propose_memory` tool and the agent's
    // accepted-memory injection; the run refuses a half-attached queue.
    let memory = build_memory_store(&config, contract.workspace(), &run_label)?;
    // B2: attach the skill registry when the contract enables it. The same
    // registry backs the toolkit's `read_skill` tool and the agent's
    // contract-frozen skill-set comparison.
    let skills = build_skills_registry(&config, contract.workspace())?;
    // D3/D4: attach the deliverable registry when the contract declares
    // deliverables; the finish gate and the recording step share it.
    let deliverables = build_deliverables_registry(&config, contract.workspace())?;
    let deliverables_before = deliverables
        .as_ref()
        .map(|store| store.records().len())
        .unwrap_or(0);
    let toolkit = {
        let base = Toolkit::with_verify_command(config.verify.command.clone());
        let base = match &memory {
            Some(store) => base.with_memory(store.clone()),
            None => base,
        };
        let base = match &skills {
            Some(registry) => base.with_skills(registry.clone()),
            None => base,
        };
        let base = attach_runtime(base, &config, contract.workspace());
        let base = attach_browser(base, &config, contract.workspace())?;
        Arc::new(base)
    };
    let mut agent = Agent::with_chain(
        contract, policy, sandbox, providers, toolkit, approval, sink,
    )?;
    if let Some(store) = memory {
        agent = agent.with_memory(store);
    }
    if let Some(registry) = skills {
        agent = agent.with_skills(registry);
    }
    if let Some(store) = &deliverables {
        agent = agent.with_deliverables(store.clone());
    }
    // Concurrency: every tool call takes a per-path lock, so agents touching
    // the same file serialise while agents touching different files proceed in
    // parallel. The wait is bounded so a lock left by a killed process is
    // reported instead of hanging the run.
    agent = agent.with_path_locks(
        config.boundary.workspace_path_locks,
        std::time::Duration::from_secs(config.boundary.workspace_lock_wait_secs),
    );
    // Module-aware locking: when the workspace is organised into build modules
    // (Cargo crates, Gradle subprojects, Maven modules, npm workspaces), a build
    // file edit locks its module, so one agent can own a module without
    // blocking agents in sibling modules.
    if config.boundary.workspace_module_locks {
        match pangu_core::discover(std::path::Path::new(".")) {
            Ok(map) => {
                // Report only what was established: an unconfident map is not
                // used for locking, so saying "modules: ..." would overstate it.
                if map.is_confident() && !map.single_unit {
                    eprintln!("modules: {}", pangu_core::module_summary(&map));
                } else if !map.is_confident() {
                    eprintln!("modules: {}", pangu_core::module_summary(&map));
                    eprintln!(
                        "modules: falling back to per-file locks; a module map that \
                         could not be established is never used to scope locks"
                    );
                }
                agent = agent.with_module_map(Some(Arc::new(map)));
            }
            Err(error) => {
                // Discovery touches only the workspace, but a failure here must
                // not stop the run: per-file locking still holds.
                eprintln!("modules: discovery failed ({error}); using per-file locks");
            }
        }
    }
    // D1: attach the sub-agent factory when the contract enables
    // delegation; the child tool surface is a fresh toolkit (verify only).
    if config.boundary.allow_delegation {
        agent = agent.with_delegation(Arc::new(FreshToolkitFactory));
        // The coarse whole-workspace lock is opt-in: the child's own tool calls
        // already take per-path locks, and excluding the entire workspace would
        // block unrelated work.
        agent = agent.with_delegation_workspace_lock(
            config.boundary.delegation_workspace_lock,
            std::time::Duration::from_secs(config.boundary.workspace_lock_wait_secs),
        );
    }
    let outcome = agent.run().await?;
    eprintln!("journal: {}", journal_path.display());
    println!(
        "status: {}\nusage: {}\nevidence: {}",
        outcome.status,
        outcome.usage.total(),
        outcome.evidence.len()
    );
    // F5: append the evaluation record when a profile is active. Only runs
    // that reach a terminal state are recorded here; a run that errors
    // earlier is audited in the journal alone. The deliverables captured are
    // exactly the ones this run registered (records appended after the
    // pre-run snapshot).
    if let Some(context) = eval {
        let deliverables = deliverables
            .as_ref()
            .map(|store| {
                store
                    .records()
                    .into_iter()
                    .skip(deliverables_before)
                    .map(|record| EvalDeliverable {
                        name: record.name,
                        path: record.path,
                        sha256: record.sha256,
                        bytes: record.bytes,
                        acceptance: record.acceptance.as_str().to_string(),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let journal_file = journal_path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        let facts = pangu_core::EvalRunFacts {
            status: outcome.status.as_str().to_string(),
            turns: outcome.turns,
            usage: outcome.usage,
            cost_usd: outcome.cost_usd,
            evidence: outcome.evidence.clone(),
        };
        let record = context.finish(&facts, deliverables, &journal_file)?;
        eprintln!(
            "eval record: {} (profile `{}`, {} deliverable(s))",
            record.id,
            record.profile,
            record.deliverables.len()
        );
    }
    Ok(outcome.status)
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

struct DemoProvider {
    calls: AtomicUsize,
}

#[async_trait]
impl Provider for DemoProvider {
    fn name(&self) -> &str {
        "demo"
    }

    fn model(&self) -> &str {
        "scripted"
    }

    fn describe(&self) -> String {
        "scripted demo provider".into()
    }

    async fn chat(
        &self,
        _messages: Vec<Message>,
        _tools: Vec<pangu_core::ToolSpec>,
    ) -> Result<ChatResponse> {
        let call = if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
            ToolCall::new("read_file", serde_json::json!({"path": "Cargo.toml"}))
        } else {
            ToolCall::new("finish", serde_json::json!({"status": "complete"}))
        };
        Ok(ChatResponse {
            messages: vec![Message::assistant_calls("", vec![call])],
            usage: Usage::default(),
        })
    }
}

/// Open the checkpoint artifact store that holds the session node ledger.
///
/// The ledger is written by the checkpoint subsystem, so when checkpointing is
/// off there is no tree to show. That is reported rather than papered over with
/// an empty listing: "no nodes" and "the feature that records nodes is off"
/// are different facts, and an operator reading a report needs to tell them
/// apart.
fn session_contract(args: &Cli) -> Result<GoalContract> {
    let (mut config, _) = Config::load(args.config.as_deref())?;
    // The `--checkpoint` / `--no-checkpoint` flags are runtime overrides, not
    // config-file edits. Without applying them here, `pangu --checkpoint
    // session tree` would read the file and conclude checkpointing is off —
    // while the run that produced the tree was started with it on.
    config = config.apply(&CliOverrides {
        workspace: args.workspace.clone(),
        checkpoint_enabled: if args.checkpoint {
            Some(true)
        } else if args.no_checkpoint {
            Some(false)
        } else {
            None
        },
        ..Default::default()
    })?;
    if !config.checkpoint.enabled {
        bail!(
            "the session tree is written by the checkpoint subsystem; \
             enable `checkpoint.enabled` or pass --checkpoint"
        );
    }
    Ok(GoalContract::from_config("session maintenance", &config)?)
}

fn session_tree(args: &Cli, json: bool) -> Result<()> {
    let contract = session_contract(args)?;
    let store = pangu_core::ArtifactStore::open(&contract.checkpoint.artifact_root)?;
    let tree = pangu_core::session::SessionTree::load(&store)?;
    // An incomplete tree still renders — the gaps are labelled — but it is not
    // presented as a whole history, because a walk that stops at a missing
    // parent looks exactly like one that reached the beginning. The expected
    // run-root gap is reported separately from unexplained holes: warning about
    // the shape every run produces would train an operator to ignore the one
    // warning that matters.
    let complete = tree.ensure_complete().is_ok();
    let run_root_gaps = tree.run_root_gaps();
    let unexplained = tree.unexplained_orphans();
    if json {
        let roots: Vec<_> = tree
            .roots()
            .iter()
            .map(|node| {
                serde_json::json!({
                    "session_node_id": node.session_node_id,
                    "parent_session_node_id": node.parent_session_node_id,
                    "checkpoint_id": node.checkpoint_id,
                    "history_digest": node.history_digest,
                })
            })
            .collect();
        let payload = serde_json::json!({
            "schema": "pangu-session-tree/1",
            "nodes": tree.len(),
            "complete": complete,
            "orphans": tree.orphans(),
            "unexplained_orphans": unexplained,
            "run_root_gaps": run_root_gaps,
            "roots": roots,
            "advisory": true,
            "authoritative": false,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        print!("{}", tree.render());
        println!("nodes: {}", tree.len());
        if !unexplained.is_empty() {
            eprintln!(
                "WARNING: {} node(s) name a parent that is not in the ledger and is not a \
                 run root; this tree is incomplete",
                unexplained.len()
            );
        }
        if !run_root_gaps.is_empty() {
            println!(
                "note: {} node(s) start a run whose root is not recorded; that is how this \
                 version works (the start of a run is not written to the ledger), not damage",
                run_root_gaps.len()
            );
        }
    }
    Ok(())
}

fn session_replay(args: &Cli, node: &str, full: bool, json: bool) -> Result<()> {
    let contract = session_contract(args)?;
    let store = pangu_core::ArtifactStore::open(&contract.checkpoint.artifact_root)?;
    let tree = pangu_core::session::SessionTree::load(&store)?;
    // Navigation is checked before the conversation is read, so a cycle is
    // reported as a broken tree rather than as a missing conversation. Only
    // unexplained gaps refuse: a run-root gap is expected and says nothing
    // about whether this specific node's history is walkable.
    if let Err(error) = tree.ensure_complete() {
        let unexplained = tree.unexplained_orphans();
        if !unexplained.is_empty() {
            return Err(error.into());
        }
    }
    tree.node(node)?;

    let runtime = pangu_agent::conversation::ConversationRuntime::from_contract(&contract)?
        .ok_or_else(|| {
            anyhow!(
                "no conversation is recorded for this workspace;                  enable `conversation.enabled` to store them"
            )
        })?;
    let snapshots = runtime.at_node(node)?;
    let Some(snapshot) = snapshots.last() else {
        bail!(
            "session node `{node}` has no recorded conversation;              it may predate conversation persistence, or persistence was off              for the run that created it"
        );
    };
    let messages = snapshot.restore()?;

    if json {
        let payload = serde_json::json!({
            "schema": "pangu-session-replay/1",
            "session_node_id": node,
            "snapshot_id": snapshot.snapshot_id,
            "history_digest": snapshot.history_digest,
            "message_count": messages.len(),
            "snapshots_at_node": snapshots.len(),
            "messages": if full { serde_json::to_value(&messages)? } else { serde_json::Value::Null },
            "note": "a replayed conversation is model input only; it restores no                      workspace and grants no approval. Use `pangu rollback` for the                      workspace.",
            "advisory": true,
            "authoritative": false,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("node:     {node}");
        println!(
            "snapshot: {} ({} snapshot(s) at this node)",
            snapshot.snapshot_id,
            snapshots.len()
        );
        println!("digest:   {}", snapshot.history_digest);
        println!("messages: {}", messages.len());
        for message in &messages {
            let preview: String = pangu_core::conversation::message_content(message)
                .chars()
                .take(72)
                .collect();
            println!(
                "  {:9} {}",
                message.role().as_str(),
                preview.replace('\n', " ")
            );
        }
        if !full {
            println!("(use --full for the complete message list, or --json)");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// The platform temporary directory can sit behind a symlink or junction on
    /// CI runners, and the runtime refuses such paths for artifact roots and
    /// journals. Resolve it once so fixtures satisfy that policy.
    fn test_temp_root() -> std::path::PathBuf {
        let base = std::env::temp_dir();
        std::fs::canonicalize(&base).unwrap_or(base)
    }

    use super::*;

    #[test]
    fn rollback_uses_checkpoint_id_without_shadowing_global_enable_flag() {
        let cli = Cli::try_parse_from([
            "pangu",
            "--checkpoint",
            "rollback",
            "--checkpoint-id",
            "checkpoint-1",
            "--source-node",
            "node-1",
            "--rollback-id",
            "rollback-1",
            "--reason",
            "operator recovery",
        ])
        .expect("rollback arguments should parse");
        assert!(cli.checkpoint);
        match cli.command {
            Some(Commands::Rollback { checkpoint_id, .. }) => {
                assert_eq!(checkpoint_id, "checkpoint-1")
            }
            other => panic!("expected rollback command, got {other:?}"),
        }
    }

    #[test]
    fn global_checkpoint_flag_still_works_for_run() {
        let cli = Cli::try_parse_from(["pangu", "--checkpoint", "run", "goal"])
            .expect("run arguments should parse");
        assert!(cli.checkpoint);
        assert!(matches!(cli.command, Some(Commands::Run { .. })));
        let alias = Cli::try_parse_from(["pangu", "--enable-checkpoint", "run", "goal"])
            .expect("checkpoint alias should parse");
        assert!(alias.checkpoint);
    }

    #[tokio::test]
    async fn rollback_dry_run_validates_the_opt_in_config_before_reporting_success() {
        let root = test_temp_root().join(format!(
            "pangu-cli-rollback-dry-run-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut config = Config::embedded().unwrap();
        config.boundary.workspace = root.clone();
        config.boundary.readable_roots = vec![root.clone()];
        config.boundary.writable_roots = vec![root.clone()];
        config.checkpoint.enabled = true;
        config.checkpoint.artifact_root = root.join(".pangu/checkpoints");
        config.unattended = false;
        let config_path = root.join("boundary.toml");
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let cli = Cli::try_parse_from([
            "pangu",
            "--config",
            config_path.to_str().unwrap(),
            "rollback",
            "--checkpoint-id",
            "checkpoint-1",
            "--source-node",
            "node-1",
            "--rollback-id",
            "rollback-1",
            "--reason",
            "dry run",
            "--dry-run",
        ])
        .unwrap();
        rollback_command(
            &cli,
            "checkpoint-1".into(),
            "node-1".into(),
            "rollback-1".into(),
            "dry run".into(),
            "cli-test".into(),
        )
        .await
        .unwrap();
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn old_ambiguous_rollback_flag_is_rejected_instead_of_panicking() {
        let result = Cli::try_parse_from([
            "pangu",
            "rollback",
            "--checkpoint",
            "checkpoint-1",
            "--source-node",
            "node-1",
            "--rollback-id",
            "rollback-1",
            "--reason",
            "operator recovery",
        ]);
        assert!(result.is_err());
    }
}
