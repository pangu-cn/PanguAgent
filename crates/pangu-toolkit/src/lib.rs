//! Built-in tools. Every executor is an adapter around the Agent capability
//! protocol; no public method accepts an unverified model call for execution.

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
    EffectDescriptor, EffectScope, Reversibility, ToolAssessment, ToolExecutor, ToolOutput,
    VerifiedAction,
};
use pangu_boundary::{Risk, Sandbox};
use pangu_core::{short_hash, ToolCall, ToolSpec};

const MAX_SEARCH_RESULTS: usize = 200;
const MAX_SEARCH_ENTRIES: usize = 10_000;
const MAX_LIST_ENTRIES: usize = 10_000;

#[derive(Clone, Default)]
pub struct Toolkit;

impl Toolkit {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ToolExecutor for Toolkit {
    fn specs(&self) -> Vec<ToolSpec> {
        vec![
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
        ]
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
            "run_command" => execute_command(action).await,
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

fn command_read_paths(command: &str, args: &[String]) -> Result<Vec<PathBuf>> {
    let command = command.to_ascii_lowercase();
    if matches!(command.as_str(), "pwd" | "") {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    let mut pattern_seen = command != "grep";
    let mut skip_next = false;
    let mut after_separator = false;
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

async fn execute_command(action: &VerifiedAction) -> Result<ToolOutput> {
    let argv = &action.resources().argv;
    if argv.is_empty() {
        bail!("empty command");
    }
    let executable = resolve_executable(&argv[0], action.sandbox())?;
    let mut command = tokio::process::Command::new(executable);
    command
        .args(&argv[1..])
        .current_dir(&action.resources().cwd)
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
    let mut child = command
        .spawn()
        .with_context(|| format!("spawn {}", argv[0]))?;
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
        format!("command:{}", short_hash(&argv.join(" "))),
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
}
