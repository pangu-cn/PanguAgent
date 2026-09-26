//! Pangu Agent command line interface.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use clap::{Parser, Subcommand};
use pangu_agent::{Agent, Provider};
use pangu_boundary::{
    CliOverrides, Config, GoalContract, Policy, Sandbox, StdinApproval, Unattended,
};
use pangu_core::{ChatResponse, Journal, Message, RollbackRequest, TeeSink, ToolCall, Usage};
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
    let provider = build_provider(&config)?;
    let status = execute_goal(config, files, goal, provider, false).await?;
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
        .map(|path| path.display().to_string())
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
    let agent = Agent::new(
        contract,
        policy,
        sandbox,
        Arc::new(DemoProvider {
            calls: AtomicUsize::new(0),
        }),
        Arc::new(Toolkit::new()),
        approval,
        sink,
    )?;
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
    let mut config = config.apply(&CliOverrides {
        unattended: true,
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
        true,
    )
    .await?;
    if !status.is_success() {
        bail!("demo ended with status {status}");
    }
    Ok(())
}

fn build_provider(config: &Config) -> Result<Arc<dyn Provider>> {
    let model = config
        .model
        .model
        .clone()
        .ok_or_else(|| anyhow::anyhow!("model.model is required for a live run"))?;
    if config.model.input_usd_per_mtok.is_none() || config.model.output_usd_per_mtok.is_none() {
        bail!("model.input_usd_per_mtok and model.output_usd_per_mtok are required for a live run");
    }
    let default_url = if config.model.protocol.as_deref() == Some("ollama") {
        "http://localhost:11434/v1"
    } else {
        "https://api.openai.com/v1"
    };
    let base_url = config
        .model
        .base_url
        .clone()
        .unwrap_or_else(|| default_url.to_string());
    let api_key_env = if config.model.protocol.as_deref() == Some("ollama") {
        None
    } else {
        config.model.api_key_env.as_deref()
    };
    let provider = OpenAiCompatibleProvider::from_env(
        model,
        base_url,
        api_key_env,
        config.model.temperature,
        config.model.max_output_tokens,
        config.model.request_timeout_secs.unwrap_or(60),
    )?;
    Ok(Arc::new(provider))
}

async fn execute_goal(
    config: Config,
    files: Vec<PathBuf>,
    goal: String,
    provider: Arc<dyn Provider>,
    use_unattended: bool,
) -> Result<pangu_boundary::GoalStatus> {
    let mut contract = GoalContract::from_config(goal, &config)?;
    contract.config_files = files
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    let policy = Arc::new(Policy::new(config.rules.clone())?);
    let sandbox = Arc::new(Sandbox::from_config(&config.boundary)?);
    let journal_path = contract
        .workspace()
        .join(".pangu")
        .join(format!("journal-{}.jsonl", unix_nanos()));
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
    let agent = Agent::new(
        contract,
        policy,
        sandbox,
        provider,
        Arc::new(Toolkit::new()),
        approval,
        sink,
    )?;
    let outcome = agent.run().await?;
    eprintln!("journal: {}", journal_path.display());
    println!(
        "status: {}\nusage: {}\nevidence: {}",
        outcome.status,
        outcome.usage.total(),
        outcome.evidence.len()
    );
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

#[cfg(test)]
mod tests {
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
        let root = std::env::temp_dir().join(format!(
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
