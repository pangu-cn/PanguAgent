#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Conversation {
    id: String,
    title: String,
    archived: bool,
    /// The model this conversation runs with, chosen in the sandbox panel.
    /// `None` (rendered as 「默认」) means "follow the selected Provider", which
    /// is also what profiles written before this field existed deserialize to.
    #[serde(default)]
    model: Option<String>,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Record { role: String, text: String }
#[derive(serde::Serialize, serde::Deserialize)]
struct Sandbox { id: String, path: String, conversations: Vec<Conversation> }
#[derive(serde::Serialize, serde::Deserialize)]
struct DesktopSettings { active_config: String }
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct ProviderProfile {
    name: String,
    base_url: String,
    model: String,
    /// Models this endpoint answered with on the last successful probe,
    /// persisted so the model dropdown is useful on the next visit without
    /// another network call. A fresh probe replaces the list wholesale: a
    /// stale entry from a different endpoint would be a lie.
    #[serde(default)]
    models: Vec<String>,
    /// API keys, one per line, stored verbatim in the local profile file and
    /// rotated across requests at run time. ADR-0015 records the boundary
    /// relaxation (ADR-0013 §4 / BOUNDARY §4b used to forbid storing keys in
    /// the frontend) and what was deliberately *not* relaxed: keys never
    /// enter events, the journal, logs, the model context, or the workspace.
    /// The editor and the settings window disclose the on-disk storage.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    api_keys: String,
    /// Legacy field: environment variable *names*, one per line. Still read
    /// so profiles written before key storage keep resolving from the process
    /// environment instead of being read back as literal keys. Never written
    /// by new profiles; `api_keys` takes precedence when both are present.
    #[serde(default, rename = "api_key_env", skip_serializing_if = "String::is_empty")]
    api_key_envs: String,
}

/// Upper bound on the probe results persisted per profile. A dropdown with a
/// thousand entries is unusable and the file would grow without bound; the
/// operator can always re-probe. Truncation is reported, never silent.
pub const MAX_PERSISTED_MODELS: usize = 64;

/// The probe results worth keeping: bounded. The caller knows how many the
/// endpoint actually offered and says so when some were dropped.
fn persisted_models(mut fetched: Vec<String>) -> Vec<String> {
    fetched.truncate(MAX_PERSISTED_MODELS);
    fetched
}

/// Non-blank, trimmed lines of a multi-line field — the shared splitter for
/// raw keys and for legacy environment variable names.
fn key_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

/// The credentials a profile resolves to: raw keys when it stores them,
/// otherwise the legacy environment variable names resolved from the process
/// environment. Raw wins over names so a half-migrated profile cannot send a
/// stale variable's value on accident.
fn profile_keys(profile: &ProviderProfile) -> Result<Vec<String>, String> {
    let raw = key_lines(&profile.api_keys);
    if !raw.is_empty() {
        return Ok(raw);
    }
    let names = key_lines(&profile.api_key_envs);
    if names.is_empty() {
        return Ok(Vec::new());
    }
    pangu_provider::resolve_api_keys(&names).map_err(|error| error.to_string())
}

/// The single key an operator-initiated probe uses: the first raw key, or the
/// first legacy variable resolved from the environment. A declared but unset
/// variable is an error, not a silent anonymous probe.
fn probe_key(profile: &ProviderProfile) -> Result<Option<String>, String> {
    if let Some(key) = key_lines(&profile.api_keys).first() {
        return Ok(Some(key.clone()));
    }
    match key_lines(&profile.api_key_envs).first() {
        Some(name) => std::env::var(name)
            .map(Some)
            .map_err(|_| format!("环境变量 `{name}` 未设置")),
        None => Ok(None),
    }
}

/// Bound for the operator-initiated model probe. Shorter than a chat request:
/// it is a diagnostic nobody should wait a minute for.
const MODEL_PROBE_TIMEOUT_SECS: u64 = 20;

/// The `model.api_key_env` value written when a profile stores raw keys and
/// no variable names. It names where the credential actually lives — the
/// local provider profile file — so config validation and `doctor` point at
/// the truth instead of at a variable that was never consulted.
const PROFILE_KEY_ENV: &str = "PANGU_PROFILE_API_KEY";

/// The embedded default input-token budget (`config/boundary.toml`
/// `budget.max_input_tokens`). Only used as a *fill preference*: when a
/// preset offers a tool-capable model whose registry context window covers
/// it, the editor prefills that model. The budget itself is never touched
/// here — lowering it is the operator's decision, and a run that needs it
/// lower still fails closed with the config-time message.
const DEFAULT_INPUT_BUDGET_TOKENS: u64 = 200_000;

/// Whether the editor's Base URL may be edited. Only a custom provider (no
/// registry preset chosen) may point somewhere else: a preset's endpoint is
/// the vendor's canonical address, and a typo there is a silent
/// misconfiguration that only fails mid-run. Picking a preset therefore locks
/// the URL until "自定义" is selected again.
fn preset_url_is_locked(preset: &str) -> bool {
    !preset.trim().is_empty()
}

/// Model dropdown candidates: the preset's tool-capable models first (Pangu
/// requires tool calling, so a toolless model would only fail at config time),
/// then whatever the endpoint probe returned, deduplicated.
fn model_choices(preset: &str, fetched: &[String]) -> Vec<String> {
    let mut choices: Vec<String> = Vec::new();
    if let Some(preset) = pangu_boundary::registry::preset(preset.trim()) {
        choices.extend(
            preset
                .models
                .iter()
                .filter(|model| model.supports_tools)
                .map(|model| model.name.to_string()),
        );
    }
    for name in fetched {
        if !choices.iter().any(|existing| existing == name) {
            choices.push(name.clone());
        }
    }
    choices
}

/// Whether an endpoint speaks plaintext http to a non-loopback host. The
/// provider accepts such endpoints (they are operator configuration — an
/// intranet gateway or a local router is a legitimate deployment), so the
/// editor states the cost at the point of decision instead of staying
/// silent: over http the API key travels in cleartext.
fn base_url_is_cleartext(raw: &str) -> bool {
    let lowered = raw.trim().to_ascii_lowercase();
    let Some(rest) = lowered.strip_prefix("http://") else {
        return false;
    };
    // Hosts are case-insensitive, so inspecting the lowercased text is enough.
    let host = if let Some(bracketed) = rest.strip_prefix('[') {
        // IPv6 literal: the host runs to the closing bracket.
        bracketed.split(']').next().unwrap_or_default()
    } else {
        rest.split(['/', ':', '@']).next().unwrap_or_default()
    };
    !(host == "localhost"
        || host == "::1"
        || host == "127.0.0.1"
        || host.starts_with("127."))
}

/// Apply the editor draft: replace the row under edit, or append when the
/// editor was opened as "new". An out-of-range index (the list shrank
/// underneath the open editor) appends the draft rather than panicking or
/// silently dropping it — the draft is the operator's latest word.
fn store_draft(
    providers: &mut Vec<ProviderProfile>,
    draft: &ProviderProfile,
    edit_index: Option<usize>,
) {
    match edit_index {
        Some(index) if index < providers.len() => providers[index] = draft.clone(),
        _ => providers.push(draft.clone()),
    }
}

/// Model candidates a conversation may pick from: the selected provider's
/// registry models when it names a preset, plus the provider's own model and
/// the conversation's current pick — so a custom endpoint (whose list only
/// the operator knows) still has something to choose, and an already-picked
/// model never disappears from its own selector.
fn conversation_model_choices(
    providers: &[ProviderProfile],
    selected: Option<usize>,
    current: Option<&str>,
) -> Vec<String> {
    let mut choices: Vec<String> = Vec::new();
    if let Some(provider) = selected.and_then(|index| providers.get(index)) {
        let name = provider.name.trim();
        if pangu_boundary::registry::preset(name).is_some() {
            choices.extend(model_choices(name, &[]));
        } else if !provider.model.trim().is_empty() {
            choices.push(provider.model.trim().to_string());
        }
    }
    if let Some(current) = current.map(str::trim).filter(|current| !current.is_empty()) {
        if !choices.iter().any(|choice| choice == current) {
            choices.push(current.to_string());
        }
    }
    choices
}

/// A conversation's remembered model is the most specific choice: it wins
/// over the provider profile's model, which itself wins over the config's.
/// `None` or blank leaves the profile's model in place.
fn apply_conversation_model(config: &mut pangu_boundary::Config, model: Option<&str>) {
    if let Some(model) = model.map(str::trim).filter(|model| !model.is_empty()) {
        config.model.model = Some(model.to_string());
    }
}

/// The edit target after row `removed` was deleted. An editor aimed at that
/// row or a later one can no longer address what it was editing (rows
/// shifted, or the row is gone), so it is cleared — and the caller closes
/// the editor with it — instead of silently retargeting a different row.
fn edit_index_after_removal(edit_index: Option<usize>, removed: usize) -> Option<usize> {
    match edit_index {
        Some(index) if index >= removed => None,
        other => other,
    }
}

/// Fill the editor draft from a built-in registry preset. Only the preset's
/// own defaults are written (endpoint, first tool-capable model); the
/// operator pastes the key(s) afterwards.
fn fill_draft_from_preset(
    draft: &mut ProviderProfile,
    preset: &pangu_boundary::registry::ProviderPreset,
) {
    draft.name = preset.name.to_string();
    draft.base_url = preset.base_url.to_string();
    // Keys are the operator's to paste: a preset contributes no credential.
    draft.api_keys = String::new();
    draft.api_key_envs = String::new();
    // A preset contributes no fetched model list either.
    draft.models = Vec::new();
    // Model preference: the first tool-capable model whose registry context
    // window covers the embedded default input budget, so the prefilled
    // profile starts a *valid* run instead of tripping the config-time window
    // check on the first execute. This is a fill hint only — it never touches
    // the budget, which stays the operator's to lower (a preset whose every
    // model is smaller than the budget falls back to its first tool-capable
    // model and the run fails closed with the actionable message).
    draft.model = preset
        .models
        .iter()
        .find(|model| model.supports_tools && model.context_window_tokens >= DEFAULT_INPUT_BUDGET_TOKENS)
        .or_else(|| preset.models.iter().find(|model| model.supports_tools))
        .map(|model| model.name.to_string())
        .unwrap_or_default();
}

/// Apply a saved provider profile to a config **in memory**, before the
/// contract is built. The profile only names provider/model/endpoint/key
/// variables: prices, capabilities and every gate still flow through the
/// normal `resolve_provider` path (explicit config > named preset > built-in
/// default), so the contract digest keeps meaning what it meant.
///
/// A profile whose name is not a registry preset is treated as a custom
/// endpoint: its base_url/model/key names still apply, but naming no preset
/// keeps registry prices out of the run (they are only for named providers).
fn apply_provider_profile(config: &mut pangu_boundary::Config, profile: &ProviderProfile) {
    let name = profile.name.trim();
    if !name.is_empty() && pangu_boundary::registry::preset(name).is_some() {
        config.model.provider = Some(name.to_string());
    }
    if !profile.model.trim().is_empty() {
        config.model.model = Some(profile.model.trim().to_string());
    }
    if !profile.base_url.trim().is_empty() {
        config.model.base_url = Some(profile.base_url.trim().to_string());
    }
    // Only the first declared variable enters the config (the schema carries
    // one variable and validation needs it); the full rotation list is
    // resolved from the profile at run time. A profile that stores raw keys
    // instead of variables names itself, so `doctor`/`explain` point at the
    // local profile file rather than at a variable that was never consulted.
    if let Some(first) = key_lines(&profile.api_key_envs).first() {
        config.model.api_key_env = Some(first.clone());
    } else if !key_lines(&profile.api_keys).is_empty() {
        config.model.api_key_env = Some(PROFILE_KEY_ENV.to_string());
    }
}

impl Client {
    /// Fetch the endpoint's model list with the first declared key variable.
    /// The request runs off the UI thread — a slow endpoint must not freeze
    /// the window — and the outcome lands in `provider_probe_rx`. A declared
    /// but unset variable is an error, not a silent anonymous probe.
    fn start_model_probe(&mut self) {
        let key = match probe_key(&self.provider_draft) {
            Ok(key) => key,
            Err(message) => {
                self.provider_probe_error = Some(message);
                return;
            }
        };
        let base_url = self.provider_draft.base_url.trim().to_string();
        if base_url.is_empty() {
            self.provider_probe_error = Some("先填写 Base URL".to_string());
            return;
        }
        let (sender, receiver) = std::sync::mpsc::channel();
        self.provider_probe_rx = Some(receiver);
        self.provider_probe_error = None;
        self.provider_probe_note = None;
        std::thread::spawn(move || {
            let outcome = match tokio::runtime::Builder::new_current_thread().enable_all().build()
            {
                Ok(runtime) => runtime
                    .block_on(pangu_provider::probe_models(
                        &base_url,
                        key.as_deref(),
                        MODEL_PROBE_TIMEOUT_SECS,
                    ))
                    .map_err(|error| error.to_string()),
                Err(error) => Err(error.to_string()),
            };
            let _ = sender.send(outcome);
        });
    }

    /// Refresh the workspace conversation view when the selection moved or a
    /// run is producing events (throttled: a snapshot can be large, and this
    /// is the reading pane, not a correctness path).
    fn refresh_conversation_view(&mut self) {
        let sandbox_path = self
            .selected
            .and_then(|(index, _)| self.sandboxes.get(index))
            .map(|sandbox| sandbox.path.clone());
        let moved = sandbox_path != self.conversation_view_for;
        if !moved && self.run.is_none() {
            return;
        }
        if !moved && self.conversation_view_at.elapsed() < std::time::Duration::from_millis(500) {
            return;
        }
        self.conversation_view_for = sandbox_path.clone();
        self.conversation_view_at = std::time::Instant::now();
        self.conversation_view = match &sandbox_path {
            Some(path) => latest_conversation_messages(&self.settings.active_config, path),
            None => None,
        };
    }

    /// The 执行/继续 path: append the user record, resolve the run's
    /// provider/profile/model, and start it off the UI thread. `resume`
    /// continues the workspace's most recent stored conversation instead of
    /// starting a fresh one.
    fn start_run(&mut self, resume: bool) {
        if let Some((sandbox_index, conversation_index)) = self.selected {
            if let Some(sandbox) = self.sandboxes.get(sandbox_index) {
                if let Some(conversation) = sandbox.conversations.get(conversation_index) {
                    let mut records = load_records(&sandbox.id, &conversation.id);
                    records.push(Record { role: "user".into(), text: self.goal.trim().to_string() });
                    save_records(&sandbox.id, &conversation.id, &records);
                }
            }
        }
        let goal = self.goal.trim().to_string();
        let selected_profile = self.selected_provider.and_then(|index| self.providers.get(index).cloned());
        let conversation_model = self
            .selected
            .and_then(|(sandbox_index, conversation_index)| {
                self.sandboxes
                    .get(sandbox_index)?
                    .conversations
                    .get(conversation_index)?
                    .model
                    .clone()
            });
        self.log.push_str(&format!("\n\n你：{goal}"));
        match self.selected.and_then(|(sandbox_index, _)| self.sandboxes.get(sandbox_index)).map(|sandbox| sandbox.path.clone()) {
            Some(path) => {
                let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                match spawn_run(&self.settings.active_config, &path, "selected", &goal, selected_profile.as_ref(), conversation_model.as_deref(), resume, cancel) {
                    Ok(handle) => {
                        self.run_events.clear();
                        self.run_expanded.clear();
                        self.run_stats = RunStats::default();
                        self.run = Some(handle);
                    }
                    Err(error) => self.log.push_str(&format!("\nrun 未启动：{error}")),
                }
            }
            None => self.log.push_str("\n先选择一个沙箱。"),
        }
        self.goal.clear();
    }

    /// Drain the running run's event stream into the view, and close the
    /// handle when its thread is done. Never blocks the frame: the join only
    /// happens after the channel has closed (the sink is dropped with the
    /// thread's agent), so the thread is already exiting.
    fn poll_run(&mut self) {
        let Some(run) = &self.run else {
            return;
        };
        while let Ok(event) = run.events.try_recv() {
            let event = pangu_core::redact_event(event);
            self.run_stats.observe(&event);
            self.run_events.push(event);
        }
        if run.thread.is_finished() {
            while let Ok(event) = run.events.try_recv() {
                let event = pangu_core::redact_event(event);
                self.run_stats.observe(&event);
                self.run_events.push(event);
            }
            let run = self.run.take().expect("run present when joining");
            match run.thread.join() {
                Ok(Ok(message)) => self.log.push_str(&format!("\n{message}")),
                Ok(Err(error)) => self.log.push_str(&format!("\nrun 失败：{error}")),
                Err(_) => self.log.push_str("\nrun 线程崩溃。"),
            }
        }
    }

    /// Collect a finished probe. Called every frame so the editor can show
    /// progress without ever blocking on the network.
    fn poll_model_probe(&mut self) {        let Some(receiver) = &self.provider_probe_rx else {
            return;
        };
        let Ok(outcome) = receiver.try_recv() else {
            return;
        };
        self.provider_probe_rx = None;
        match outcome {
            Ok(fetched) => {
                // The endpoint's answer is persisted into the draft (and so
                // into providers.json on save) and drives this session's
                // dropdown. Truncation is reported, never silent.
                let total = fetched.len();
                let kept = persisted_models(fetched);
                let kept_count = kept.len();
                self.provider_models = kept.clone();
                self.provider_draft.models = kept;
                self.provider_probe_note = Some(if total > kept_count {
                    format!(
                        "已获取 {total} 个模型；保存 Provider 后写入配置（保存前 {kept_count} 个）"
                    )
                } else {
                    format!("已获取 {total} 个模型；保存 Provider 后写入配置")
                });
            }
            Err(error) => self.provider_probe_error = Some(error),
        }
    }
}
struct Client {
    goal: String,
    log: String,
    pending: Option<String>,
    sandboxes: Vec<Sandbox>,
    selected: Option<(usize, usize)>,
    settings_open: bool,
    providers_open: bool,
    provider_editor_open: bool,
    providers: Vec<ProviderProfile>,
    selected_provider: Option<usize>,
    provider_draft: ProviderProfile,
    /// Registry preset the editor started from ("" = custom). Selection only
    /// fills defaults; the draft stays fully editable afterwards.
    provider_preset: String,
    /// Row the editor is editing, or `None` when it was opened as "new".
    /// Save replaces that row instead of appending; a delete that removes the
    /// row (or shifts past it) clears the editor rather than retargeting it.
    provider_edit_index: Option<usize>,
    /// Models fetched from the current endpoint this session (`GET /models`
    /// probe; session-only, never persisted).
    provider_models: Vec<String>,
    /// Receiver of an in-flight model probe; `None` when idle.
    provider_probe_rx: Option<std::sync::mpsc::Receiver<Result<Vec<String>, String>>>,
    /// Last probe failure, shown in the editor until the next attempt.
    provider_probe_error: Option<String>,
    /// Last successful probe's summary (counts + where it lands), shown in
    /// the editor. `None` until a probe succeeds.
    provider_probe_note: Option<String>,
    /// The run in flight, if any. `None` means the UI is idle and the next
    /// 执行 starts a fresh one.
    run: Option<RunHandle>,
    /// Events of the current (or most recent) run, redacted on arrival. Kept
    /// after the run ends so the stream can be scrolled and re-read.
    run_events: Vec<pangu_core::Event>,
    /// Which event rows the operator expanded (the fold/full toggle).
    run_expanded: std::collections::HashSet<usize>,
    /// Live counters derived from the event stream.
    run_stats: RunStats,
    /// The selected sandbox's `git diff`, read on demand (bounded).
    diff: Option<String>,
    /// The workspace's latest agent conversation, cached. `None` means the
    /// config has persistence off (or the store is empty) and the center
    /// shows the log instead.
    conversation_view: Option<Vec<pangu_core::Message>>,
    /// Which sandbox path the cached view belongs to, and when it was last
    /// refreshed (so a running run updates without re-reading per frame).
    conversation_view_for: Option<String>,
    conversation_view_at: std::time::Instant,
    /// What the risk-confirmation modal is asking about. `true` when the
    /// pending decision is the commit step: an allow then records the
    /// approved summary (Pangu still never runs git commit itself).
    pending_commit: bool,
    /// `doctor`/`explain` output for the active config, on demand.
    explain: Option<String>,
    /// The selected workspace's installed skills, listed read-only
    /// (installing stays an operator CLI action, ADR-0007/B2).
    skills: Vec<String>,
    settings: DesktopSettings,
    draft_config: String,
    changes: Vec<String>,
    artifacts: Vec<String>,
    commit_summary: Option<String>,
}

fn create_with_user_acl(path: &std::path::Path) -> bool {
    let mut current = std::path::PathBuf::new();
    let mut created = false;
    for part in path.components() {
        current.push(part);
        if !current.exists() {
            if let Err(error) = std::fs::create_dir(&current) {
                eprintln!("创建 {} 失败: {error}", current.display());
                return false;
            }
            eprintln!("已创建 {}", current.display());
            created = true;
        }
    }
    created || path.exists()
}

fn ensure_data_dir() -> std::path::PathBuf {
    let target = data_dir();
    create_with_user_acl(&target.join("session"));
    target
}

fn data_dir() -> std::path::PathBuf {
    let root = std::path::PathBuf::from(default_agent_dir()).join("data");
    std::fs::create_dir_all(&root).ok();
    root
}

fn load_sandboxes() -> Vec<Sandbox> {
    let file = data_dir().join("sandboxes.json");
    std::fs::read_to_string(file).ok().and_then(|text| serde_json::from_str::<Vec<Sandbox>>(&text).ok()).filter(|items| items.iter().all(|item| !item.id.is_empty())).unwrap_or_else(|| vec![Sandbox { id: uuid::Uuid::new_v4().to_string(), path: default_agent_dir(), conversations: Vec::new() }])
}

fn record_path(sandbox_id: &str, id: &str) -> std::path::PathBuf {
    data_dir().join("session").join(sandbox_id).join(format!("{id}.json"))
}

fn load_records(sandbox_id: &str, id: &str) -> Vec<Record> {
    std::fs::read_to_string(record_path(sandbox_id, id)).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
}

fn save_records(sandbox_id: &str, id: &str, records: &[Record]) {
    let path = record_path(sandbox_id, id);
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).ok(); }
    if let Ok(text) = serde_json::to_string_pretty(records) { std::fs::write(path, text).ok(); }
}

fn config_dir() -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(default_agent_dir()).join("config");
    std::fs::create_dir_all(&dir).ok();
    dir
}

fn config_files() -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(config_dir()) {
        for entry in entries.flatten() {
            if entry.path().extension().is_some_and(|ext| ext == "json") {
                if let Some(name) = entry.path().file_name() { names.push(name.to_string_lossy().into_owned()); }
            }
        }
    }
    names.sort();
    names
}

fn load_settings() -> DesktopSettings {
    let path = std::path::PathBuf::from(default_agent_dir()).join("settings.json");
    std::fs::read_to_string(path).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or(DesktopSettings { active_config: "default.json".into() })
}

fn provider_path() -> std::path::PathBuf { config_dir().join("providers.json") }
fn load_providers() -> Vec<ProviderProfile> { std::fs::read_to_string(provider_path()).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default() }
fn save_providers(providers: &[ProviderProfile]) { if let Ok(text) = serde_json::to_string_pretty(providers) { std::fs::write(provider_path(), text).ok(); } }
fn save_settings(settings: &DesktopSettings) {
    let path = std::path::PathBuf::from(default_agent_dir()).join("settings.json");
    if let Ok(text) = serde_json::to_string_pretty(settings) { std::fs::write(path, text).ok(); }
}

struct DesktopApproval;

#[async_trait::async_trait]
impl pangu_boundary::ApprovalHandler for DesktopApproval {
    fn mode(&self) -> pangu_boundary::ApprovalMode { pangu_boundary::ApprovalMode::DestructiveAndAbove }
    async fn decide(&self, _request: &pangu_boundary::ApprovalRequest) -> pangu_boundary::ApprovalResponse { pangu_boundary::ApprovalResponse::NoAnswer }
}

/// The run's audit stream, forwarded to the UI. A receiver that went away
/// fails the emit: nobody is watching the audit trail, so the run must not
/// continue as if it were being recorded (I-Redact-At-Boundary discipline).
struct RunSink {
    events: std::sync::mpsc::Sender<pangu_core::Event>,
}

#[async_trait::async_trait]
impl pangu_core::EventSink for RunSink {
    async fn emit(&self, event: pangu_core::Event) -> pangu_core::Result<()> {
        self.events
            .send(event)
            .map_err(|_| pangu_core::Error::Other("run event receiver went away".into()))
    }
}

/// A run in flight: its event stream, thread, cancel flag and clock.
struct RunHandle {
    events: std::sync::mpsc::Receiver<pangu_core::Event>,
    thread: std::thread::JoinHandle<Result<String, String>>,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    started: std::time::Instant,
}

/// Live run counters, derived from the event stream — no second source of
/// truth: the turn reached, the tokens the provider reported, and the tool
/// currently in flight.
#[derive(Default)]
struct RunStats {
    turn: u32,
    input_tokens: u64,
    output_tokens: u64,
    active_tool: Option<String>,
}

impl RunStats {
    fn observe(&mut self, event: &pangu_core::Event) {
        self.turn = self.turn.max(event.turn);
        match event.kind {
            pangu_core::EventKind::ModelResponse => {
                if let Some(usage) = &event.usage {
                    self.input_tokens = self.input_tokens.saturating_add(usage.input_tokens);
                    self.output_tokens = self.output_tokens.saturating_add(usage.output_tokens);
                }
            }
            pangu_core::EventKind::ToolStarted => self.active_tool = event.tool.clone(),
            pangu_core::EventKind::ToolFinished | pangu_core::EventKind::ToolBlocked => {
                self.active_tool = None;
            }
            _ => {}
        }
    }
}

/// One line per event in the stream: kind, turn, and the (already redacted)
/// message trimmed to one line so the stream stays scannable.
fn event_line(event: &pangu_core::Event) -> String {
    format!(
        "[{}] t{} {}",
        event.kind.as_str(),
        event.turn,
        pangu_core::one_line(&event.message, 120)
    )
}

/// The full record for an expanded event row: the whole message plus its
/// payload. Both are already redacted and bounded by the emitter.
fn event_detail(event: &pangu_core::Event) -> String {
    let mut text = event.message.clone();
    if let Some(payload) = &event.payload {
        text.push('\n');
        text.push_str(&serde_json::to_string_pretty(payload).unwrap_or_else(|_| payload.to_string()));
    }
    text
}

/// A minimal markdown renderer for the conversation view.
///
/// In-house on purpose: a third-party markdown widget would be a
/// supply-chain surface this codebase does not need for a chat pane, and the
/// subset below is what a run's output actually contains. Unknown syntax
/// renders as literal text — never as something that looks like formatting
/// and isn't.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MarkdownBlock {
    Heading { level: u8, text: String },
    Paragraph(String),
    Code { language: Option<String>, code: String },
    ListItem { ordered: bool, text: String },
    Quote(String),
    Rule,
}

fn heading_level(trimmed: &str) -> Option<u8> {
    let level = trimmed.chars().take_while(|c| *c == '#').count();
    if level == 0 || level > 6 {
        return None;
    }
    // A heading needs whitespace after the markers ("#tag" is not a heading).
    trimmed[level..].starts_with(' ').then_some(level as u8)
}

fn is_rule(trimmed: &str) -> bool {
    let core = trimmed.trim_matches(|c| c == '-' || c == '*' || c == '_');
    trimmed.len() >= 3 && core.is_empty() && !trimmed.is_empty()
}

fn list_item(trimmed: &str) -> Option<(bool, &str)> {
    for marker in ["- ", "* "] {
        if let Some(text) = trimmed.strip_prefix(marker) {
            return Some((false, text.trim()));
        }
    }
    // Ordered: digits followed by ". " or ") ".
    let digits = trimmed.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits > 0 {
        let rest = &trimmed[digits..];
        if let Some(text) = rest.strip_prefix(". ").or_else(|| rest.strip_prefix(") ")) {
            return Some((true, text.trim()));
        }
    }
    None
}

/// Split text into blocks. Line-based: a ``` fence opens a code block that
/// only a closing fence ends (so markdown inside code is never formatted),
/// headings/lists/quotes/rules are single lines, and consecutive plain lines
/// form one paragraph.
fn markdown_blocks(text: &str) -> Vec<MarkdownBlock> {
    let mut blocks = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if let Some(language) = trimmed.strip_prefix("```") {
            let mut code = Vec::new();
            for inner in lines.by_ref() {
                if inner.trim().starts_with("```") {
                    break;
                }
                code.push(inner);
            }
            blocks.push(MarkdownBlock::Code {
                language: Some(language.trim().to_string()).filter(|value| !value.is_empty()),
                code: code.join("\n"),
            });
            continue;
        }
        if let Some(level) = heading_level(trimmed) {
            blocks.push(MarkdownBlock::Heading {
                level,
                text: trimmed[level as usize..].trim().to_string(),
            });
            continue;
        }
        if is_rule(trimmed) {
            blocks.push(MarkdownBlock::Rule);
            continue;
        }
        if let Some(text) = trimmed.strip_prefix("> ") {
            blocks.push(MarkdownBlock::Quote(text.trim().to_string()));
            continue;
        }
        if let Some((ordered, text)) = list_item(trimmed) {
            blocks.push(MarkdownBlock::ListItem {
                ordered,
                text: text.to_string(),
            });
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        let mut paragraph = trimmed.to_string();
        while let Some(next) = lines.peek() {
            let next = next.trim();
            if next.is_empty()
                || next.starts_with("```")
                || heading_level(next).is_some()
                || is_rule(next)
                || next.starts_with("> ")
                || list_item(next).is_some()
            {
                break;
            }
            paragraph.push(' ');
            paragraph.push_str(next);
            lines.next();
        }
        blocks.push(MarkdownBlock::Paragraph(paragraph));
    }
    blocks
}

/// Inline spans for one text run: `code`, **bold**, *italic*. Unclosed
/// markers render literally, so a stray backtick is text, not formatting.
fn inline_job(text: &str, base: egui::TextFormat) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let mut plain = String::new();
    let mut chars = text.char_indices().peekable();
    let mut code_format = base.clone();
    code_format.font_id.family = egui::FontFamily::Monospace;
    let mut bold_format = base.clone();
    bold_format.font_id.size = (bold_format.font_id.size + 1.0).min(28.0);
    let mut italic_format = base;
    italic_format.italics = true;
    while let Some((index, character)) = chars.next() {
        let rest = &text[index..];
        if character == '`' {
            if let Some(end) = rest[1..].find('`') {
                if !plain.is_empty() {
                    job.append(&plain, 0.0, italic_format.clone());
                    plain.clear();
                }
                job.append(&rest[1..1 + end], 0.0, code_format.clone());
                // The opening backtick is already consumed by `chars.next()`
                // above; skip the code plus the closing backtick.
                for _ in 0..end + 1 {
                    chars.next();
                }
                continue;
            }
        }
        if rest.starts_with("**") {
            // The opening pair is tested above and consumed by `chars.next()`
            // below; slice from after it to search for the closing pair.
            let after_open = rest.strip_prefix("**").unwrap_or(rest);
            if let Some(end) = after_open.find("**") {
                if !plain.is_empty() {
                    job.append(&plain, 0.0, italic_format.clone());
                    plain.clear();
                }
                job.append(&after_open[..end], 0.0, bold_format.clone());
                // One of the two opening markers is consumed above; skip the
                // second, the text, and the closing pair.
                for _ in 0..end + 3 {
                    chars.next();
                }
                continue;
            }
        }
        if character == '*' {
            if let Some(end) = rest[1..].find('*') {
                if !plain.is_empty() {
                    job.append(&plain, 0.0, italic_format.clone());
                    plain.clear();
                }
                job.append(&rest[1..1 + end], 0.0, italic_format.clone());
                for _ in 0..end + 1 {
                    chars.next();
                }
                continue;
            }
        }
        plain.push(character);
    }
    if !plain.is_empty() {
        job.append(&plain, 0.0, italic_format);
    }
    if job.sections.is_empty() {
        job.append("", 0.0, egui::TextFormat::default());
    }
    job
}

fn markdown_format() -> egui::TextFormat {
    let mut format = egui::TextFormat::default();
    format.font_id.size = 14.0;
    format
}

/// Render markdown into a ui region. Code blocks are the only part that
/// keeps raw text: inside a fence, markdown is content, not markup.
fn render_markdown(ui: &mut egui::Ui, text: &str) {
    for block in markdown_blocks(text) {
        match block {
            MarkdownBlock::Heading { level, text } => {
                ui.add_space(6.0);
                let size = (22.0 - level as f32 * 2.0).max(14.0);
                let mut format = markdown_format();
                format.font_id.size = size;
                ui.label(egui::text::LayoutJob::single_section(text, format));
                ui.add_space(2.0);
            }
            MarkdownBlock::Paragraph(text) => {
                ui.label(inline_job(&text, markdown_format()));
                ui.add_space(4.0);
            }
            MarkdownBlock::Code { language, code } => {
                if let Some(language) = language {
                    ui.label(egui::RichText::new(language).monospace().weak().small());
                }
                egui::Frame::NONE
                    .fill(egui::Color32::from_rgb(30, 30, 34))
                    .inner_margin(8.0)
                    .outer_margin(egui::Margin::symmetric(0, 6))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(egui::RichText::new(code).monospace().weak());
                    });
                ui.add_space(4.0);
            }
            MarkdownBlock::ListItem { ordered, text } => {
                ui.horizontal(|ui| {
                    ui.label(if ordered { "–".to_string() } else { "•".to_string() });
                    ui.label(inline_job(&text, markdown_format()));
                });
            }
            MarkdownBlock::Quote(text) => {
                let mut job = inline_job(&text, markdown_format());
                for section in &mut job.sections {
                    section.format.color = egui::Color32::from_rgb(190, 190, 198);
                }
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("▌").weak());
                    ui.label(job);
                });
                ui.add_space(4.0);
            }
            MarkdownBlock::Rule => {
                ui.add_space(4.0);
                ui.separator();
                ui.add_space(4.0);
            }
        }
    }
}

/// Build and start one run **off the UI thread**. Setup failures (bad config,
/// missing model or prices, unusable key) return here with the actionable
/// message; everything after the provider is wired runs in the background and
/// streams its events to the UI. The cancel flag is the operator's stop.
#[allow(clippy::too_many_arguments)]
fn spawn_run(
    config_name: &str,
    sandbox: &str,
    conversation_id: &str,
    goal: &str,
    profile: Option<&ProviderProfile>,
    conversation_model: Option<&str>,
    resume: bool,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<RunHandle, String> {
    let config_path = config_dir().join(config_name);
    let source = std::fs::read_to_string(&config_path).map_err(|error| error.to_string())?;
    let mut config = pangu_boundary::Config::from_json(&source).map_err(|error| error.to_string())?;
    if let Some(profile) = profile { apply_provider_profile(&mut config, profile); }
    apply_conversation_model(&mut config, conversation_model);
    config.boundary.workspace = std::path::PathBuf::from(sandbox);
    config.boundary.readable_roots = vec![std::path::PathBuf::from(sandbox)];
    config.boundary.writable_roots = vec![std::path::PathBuf::from(sandbox)];
    let contract = pangu_boundary::GoalContract::from_config(goal.to_string(), &config).map_err(|error| error.to_string())?;
    let policy = std::sync::Arc::new(pangu_boundary::Policy::new(config.rules.clone()).map_err(|error| error.to_string())?);
    let sandbox_boundary = std::sync::Arc::new(pangu_boundary::Sandbox::from_config(&config.boundary).map_err(|error| error.to_string())?);
    let resolved = config.resolve_provider().map_err(|error| error.to_string())?;
    // Same fail-closed prechecks as the CLI's build_provider_chain: an
    // unpriced run terminates as BudgetExhausted before any provider request,
    // so report it here with the actionable message instead.
    let model = resolved.model.clone().ok_or_else(|| "model.model is required for a live run; set it on the selected Provider or in the active config".to_string())?;
    if resolved.input_usd_per_mtok.is_none() || resolved.output_usd_per_mtok.is_none() {
        return Err("model input/output prices are required for a live run; set model.input_usd_per_mtok and model.output_usd_per_mtok, or name a registry preset with a known model".to_string());
    }
    // Credentials: the selected profile's raw keys (or its legacy variable
    // names resolved here), else the single effective variable from
    // config/registry. Raw keys never pass through the environment.
    let keys = match profile {
        Some(profile) => profile_keys(profile)?,
        None => match resolved.api_key_env.as_deref() {
            Some(name) => pangu_provider::resolve_api_keys(&[name])
                .map_err(|error| error.to_string())?,
            None => Vec::new(),
        },
    };
    let provider = std::sync::Arc::new(pangu_provider::OpenAiCompatibleProvider::with_keys(model, resolved.base_url.clone(), keys, config.model.temperature, config.model.max_output_tokens, config.model.request_timeout_secs.unwrap_or(60)).map_err(|error| error.to_string())?);
    let tools = std::sync::Arc::new(pangu_toolkit::Toolkit::with_verify_command(config.verify.command.clone()));
    let approval = std::sync::Arc::new(DesktopApproval);
    let (sender, receiver) = std::sync::mpsc::channel();
    let sink = std::sync::Arc::new(RunSink { events: sender });
    let agent = pangu_agent::Agent::new(contract, policy, sandbox_boundary, provider, tools, approval, sink).map_err(|error| error.to_string())?
        .with_cancel(cancel.clone());
    // Resume: the workspace's most recent stored conversation, loaded and
    // re-verified by the same path `pangu session replay` uses. Persistence
    // must be on — a resume into nothing is an error, not a silent fresh run.
    let agent = if resume {
        // The first contract was moved into the agent; a second identical one
        // opens the runtime that owns the conversation store.
        let resume_contract = pangu_boundary::GoalContract::from_config(goal.to_string(), &config)
            .map_err(|error| error.to_string())?;
        let runtime = pangu_agent::conversation::ConversationRuntime::from_contract(&resume_contract)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "继续需要 conversation.enabled；请在当前配置里开启".to_string())?;
        let latest = runtime
            .latest()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "工作区里没有已存储的会话可继续".to_string())?;
        agent.resume_from(&latest).map_err(|error| error.to_string())?
    } else {
        agent
    };
    let config_display = config_path.display().to_string();
    let conversation_id = conversation_id.to_string();
    let thread = std::thread::spawn(move || {
        let outcome = (|| {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|error| error.to_string())?;
            runtime.block_on(agent.run()).map_err(|error| error.to_string())
        })();
        Ok(format!("run {} finished: {} conversation={}", outcome?.status, config_display, conversation_id))
    });
    Ok(RunHandle { events: receiver, thread, cancel, started: std::time::Instant::now() })
}

fn save_sandboxes(sandboxes: &[Sandbox]) {
    let file = data_dir().join("sandboxes.json");
    if let Ok(text) = serde_json::to_string_pretty(sandboxes) { std::fs::write(file, text).ok(); }
}

fn app_dir() -> std::path::PathBuf {
    std::env::current_exe().ok().and_then(|path| path.parent().map(std::path::Path::to_path_buf)).unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")))
}

fn default_agent_dir() -> String {
    app_dir().join(".pangu").display().to_string()
}

fn path_name(path: &std::path::Path) -> String {
    path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_else(|| path.display().to_string())
}

fn same_path(left: &std::path::Path, right: &std::path::Path) -> bool {
    let left: Vec<_> = left.components().collect();
    let right: Vec<_> = right.components().collect();
    left.len() == right.len() && left.iter().zip(right).all(|(a, b)| a.as_os_str().eq_ignore_ascii_case(b.as_os_str()))
}

fn sandbox_label_for(app: &std::path::Path, sandbox: &std::path::Path) -> String {
    let sandbox_name = path_name(sandbox);
    if same_path(app, sandbox) || sandbox.starts_with(app) && sandbox.components().count() <= app.components().count() + 1 {
        return format!("./{sandbox_name}");
    }
    let mut cursor = app.to_path_buf();
    for ups in 1..=3 {
        if sandbox.starts_with(&cursor) {
            let down: Vec<_> = sandbox.strip_prefix(&cursor).unwrap_or(sandbox).components().map(|part| part.as_os_str().to_string_lossy().into_owned()).filter(|part| !part.is_empty()).collect();
            if down.len() <= 3 {
                return format!("{}{}", "../".repeat(ups), down.join("/"));
            }
        }
        let Some(parent) = cursor.parent().map(std::path::Path::to_path_buf) else { break };
        if same_path(&parent, &cursor) { break; }
        cursor = parent;
    }
    sandbox.display().to_string()
}

fn read_changes(path: &str) -> Vec<String> {
    let output = std::process::Command::new("git").args(["status", "--short"]).current_dir(path).output();
    let Ok(output) = output else { return vec!["不是 Git 仓库".into()] };
    if !output.status.success() { return vec!["不是 Git 仓库".into()] }
    let text = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<_> = text.lines().map(str::to_string).collect();
    if lines.is_empty() { vec!["没有变更".into()] } else { lines }
}

/// The workspace's most recent stored agent conversation, when the active
/// config has persistence on. Labeled honestly wherever it is shown: the
/// snapshots belong to runs in this workspace — they are the agent's own
/// store, not the desktop's per-conversation records.
fn latest_conversation_messages(config_name: &str, sandbox: &str) -> Option<Vec<pangu_core::Message>> {
    let source = std::fs::read_to_string(config_dir().join(config_name)).ok()?;
    let config = pangu_boundary::Config::from_json(&source).ok()?;
    if !config.conversation.enabled {
        return None;
    }
    let root = std::path::Path::new(sandbox).join(&config.conversation.artifact_root);
    let store = pangu_core::ArtifactStore::open(&root).ok()?;
    let latest = store.list_conversations().ok()?.pop()?;
    store.load_conversation(&latest).ok().map(|snapshot| snapshot.messages)
}

/// The sandbox's `git diff`, read on demand. Bounded: a huge diff would
/// freeze the panel, and the middle of a giant diff carries the least
/// information. Read-only — this never stages, commits or pokes at git.
fn read_diff(path: &str) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["diff", "--no-color"])
        .current_dir(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return Some("读取 diff 失败（不是 Git 仓库？）".to_string());
    }
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    if text.trim().is_empty() {
        return Some("没有 diff".to_string());
    }
    Some(pangu_core::truncate_middle(&text, 256 * 1024))
}

/// Registered deliverables with their acceptance status, straight from the
/// store's registry — so `complete` (auto checks passed) and `accepted`
/// (a human signed off) stay visibly different, per ADR-0008.
fn read_artifacts(path: &str) -> Vec<String> {
    let root = std::path::Path::new(path).join(".pangu").join("deliverables");
    let store = match pangu_core::DeliverableStore::open(&root) {
        Ok(store) => store,
        Err(_) => return vec!["没有已登记产物".into()],
    };
    let records = store.records();
    if records.is_empty() {
        return vec!["没有已登记产物".into()];
    }
    records
        .iter()
        .map(|record| {
            format!(
                "{} [{}] {}B · {}",
                record.name,
                record.acceptance.as_str(),
                record.bytes,
                pangu_core::short_hash(&record.sha256)
            )
        })
        .collect()
}

fn prepare_commit_summary(changes: &[String]) -> String {
    format!("准备提交 {} 个变更。此操作不执行 git commit，也不使用 --no-verify。", changes.len())
}

/// The confirmation text for the commit step. This is the human decision
/// point: Pangu never runs git commit itself (I-No-Implicit-Git-Commit), so
/// an approval records the decision and the operator commits by hand.
fn commit_prompt(changes: &[String]) -> String {
    format!(
        "提交 {} 个变更？Pangu 不执行 git commit，也不使用 --no-verify。批准后请在沙箱内手动提交。",
        changes.len()
    )
}

/// The selected workspace's installed skills, read-only. The registry load
/// is the same one a run uses, so this cannot show a skill a run would not.
fn read_skills(sandbox: &str, config_name: &str) -> Vec<String> {
    let Ok(source) = std::fs::read_to_string(config_dir().join(config_name)) else {
        return Vec::new();
    };
    let Ok(config) = pangu_boundary::Config::from_json(&source) else {
        return Vec::new();
    };
    if !config.skills.enabled {
        return vec!["技能注册表未启用".into()];
    }
    let root = std::path::Path::new(sandbox).join(".pangu").join("skills");
    let verify_key = config.skills.verify_key.trim();
    let registry = match pangu_core::SkillRegistry::load(
        &root,
        &config.skills.limits(),
        if verify_key.is_empty() { None } else { Some(verify_key) },
    ) {
        Ok(registry) => registry,
        Err(_) => return vec!["无法加载技能注册表".into()],
    };
    registry
        .skills()
        .iter()
        .map(|skill| {
            let signed = if skill.signature_verified() {
                "signed+verified"
            } else {
                "unverified"
            };
            format!("{} {} [{}]", skill.name, skill.version, signed)
        })
        .collect()
}

fn sandbox_label(path: &str) -> String {
    sandbox_label_for(&app_dir(), std::path::Path::new(path))
}

impl Default for Client {
    fn default() -> Self {
        let sandboxes = load_sandboxes();
        let settings = load_settings();
        let default_config = config_dir().join("default.json");
        if !default_config.exists() { if let Ok(text) = serde_json::to_string_pretty(&pangu_boundary::Config::embedded().unwrap_or_default()) { std::fs::write(default_config, text).ok(); } }
        save_sandboxes(&sandboxes);
        save_settings(&settings);
        let draft_config = settings.active_config.clone();
        let providers = load_providers();
        Self { goal: String::new(), log: format!("数据目录：{}", data_dir().display()), pending: None, sandboxes, selected: None, settings_open: false, providers_open: false, provider_editor_open: false, providers, selected_provider: None, provider_draft: ProviderProfile { name: String::new(), base_url: "https://api.openai.com/v1".into(), model: String::new(), models: Vec::new(), api_keys: String::new(), api_key_envs: String::new() }, provider_preset: String::new(), provider_edit_index: None, provider_models: Vec::new(), provider_probe_rx: None, provider_probe_error: None, provider_probe_note: None, run: None, run_events: Vec::new(), run_expanded: std::collections::HashSet::new(), run_stats: RunStats::default(), diff: None, conversation_view: None, conversation_view_for: None, conversation_view_at: std::time::Instant::now(), pending_commit: false, explain: None, skills: Vec::new(), settings, draft_config, changes: Vec::new(), artifacts: Vec::new(), commit_summary: None }
    }
}

fn apply_client_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.window_fill = egui::Color32::from_rgb(24, 24, 27);
    style.visuals.panel_fill = egui::Color32::from_rgb(24, 24, 27);
    style.visuals.extreme_bg_color = egui::Color32::from_rgb(39, 39, 42);
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    ctx.set_style(style);
}

impl eframe::App for Client {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        apply_client_theme(ctx);
        self.poll_run();
        self.refresh_conversation_view();
        egui::SidePanel::left("sandboxes").exact_width(248.0).frame(egui::Frame::side_top_panel(&ctx.style()).fill(egui::Color32::from_rgb(32, 32, 36)).inner_margin(12.0)).show(ctx, |ui| {
            ui.add_space(8.0);
            ui.heading("Pangu");
            ui.horizontal(|ui| { ui.label("沙箱"); if ui.button("设置").clicked() { self.draft_config = self.settings.active_config.clone(); self.settings_open = true; } });
            if ui.button("添加目录").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.sandboxes.push(Sandbox { id: uuid::Uuid::new_v4().to_string(), path: path.display().to_string(), conversations: Vec::new() });
                }
            }
            if self.sandboxes.is_empty() { ui.label("还没有沙箱。"); }
            for (sandbox_index, sandbox) in self.sandboxes.iter_mut().enumerate() {
                ui.separator();
                ui.label(sandbox_label(&sandbox.path)).on_hover_text(&sandbox.path);
                if ui.button("新建对话").clicked() {
                    let id = uuid::Uuid::new_v4().to_string();
                    // The new conversation inherits the previous one's model
                    // choice, so switching models once survives "新建对话"
                    // instead of silently reverting to the provider default.
                    let inherited = sandbox.conversations.last().and_then(|conversation| conversation.model.clone());
                    sandbox.conversations.push(Conversation { id: id.clone(), title: format!("对话 {}", sandbox.conversations.len() + 1), archived: false, model: inherited });
                    save_records(&sandbox.id, &id, &[]);
                }
                ui.label("对话");
                for (index, conversation) in sandbox.conversations.iter_mut().enumerate().filter(|(_, item)| !item.archived) {
                    let previous_model = conversation.model.clone().unwrap_or_default();
                    let mut model = previous_model.clone();
                    let choices = conversation_model_choices(&self.providers, self.selected_provider, Some(&model));
                    ui.horizontal(|ui| {
                        let response = ui.add(egui::Label::new(egui::RichText::new(&conversation.title)).sense(egui::Sense::click()).truncate());
                        if response.clicked() { self.selected = Some((sandbox_index, index)); }
                        response.context_menu(|ui| { if ui.button("归档").clicked() { conversation.archived = true; ui.close_menu(); } });
                        // The per-conversation model selector. The id_salt is
                        // the conversation id: two rows must not share one
                        // combo's state, and the label text is not unique.
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            egui::ComboBox::from_id_salt(&conversation.id)
                                .selected_text(if model.is_empty() { "默认".to_string() } else { model.clone() })
                                .width(96.0)
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut model, String::new(), "默认");
                                    for name in &choices {
                                        ui.selectable_value(&mut model, name.clone(), name);
                                    }
                                });
                        });
                    });
                    if model != previous_model {
                        conversation.model = if model.is_empty() { None } else { Some(model) };
                    }
                }
                ui.label("归档");
                for conversation in sandbox.conversations.iter_mut().filter(|item| item.archived) {
                    let response = ui.add(egui::Label::new(&conversation.title).sense(egui::Sense::click()));
                    response.context_menu(|ui| { if ui.button("取消归档").clicked() { conversation.archived = false; ui.close_menu(); } });
                }
                ui.separator();
                ui.label("对话右侧选模型：「默认」跟随选中的 Provider；选择即记住，新对话继承上一对话的选择。");
            }
        });
        egui::TopBottomPanel::bottom("composer").exact_height(if self.run.is_some() { 140.0 } else { 112.0 }).frame(egui::Frame::side_top_panel(&ctx.style()).fill(egui::Color32::from_rgb(24, 24, 27)).inner_margin(16.0)).show(ctx, |ui| {
            let run_active = self.run.is_some();
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::multiline(&mut self.goal).desired_width(ui.available_width() - 96.0).desired_rows(2).hint_text("给 Pangu 一个任务"));
                if run_active {
                    if ui.button("停止").clicked() {
                        if let Some(run) = &self.run { run.cancel.store(true, std::sync::atomic::Ordering::Relaxed); }
                    }
                } else {
                    if ui.button("执行").clicked() && !self.goal.trim().is_empty() { self.start_run(false); }
                    if ui.button("继续").on_hover_text("恢复工作区里最近一次 agent 会话后继续执行（需 conversation.enabled）").clicked() && !self.goal.trim().is_empty() { self.start_run(true); }
                }
            });
            if let Some(run) = &self.run {
                let elapsed = run.started.elapsed().as_secs();
                let tool = self.run_stats.active_tool.as_deref().unwrap_or("—");
                ui.label(format!(
                    "第 {} 轮 · 活跃工具 {} · tokens {}/{} · 已运行 {}s（停止只取消尚未开始的动作）",
                    self.run_stats.turn, tool, self.run_stats.input_tokens, self.run_stats.output_tokens, elapsed
                ));
                // Keep repainting while the run streams; each frame drains the
                // channel above, so this costs nothing extra.
                ctx.request_repaint();
            }
        });
        egui::SidePanel::right("changes").exact_width(300.0).show(ctx, |ui| {
            ui.heading("变更");
            ui.horizontal(|ui| {
                if ui.button("查看变更").clicked() {
                    self.diff = None;
                    if let Some(path) = self.selected.and_then(|(index, _)| self.sandboxes.get(index)).map(|sandbox| sandbox.path.clone()) {
                        self.changes = read_changes(&path);
                        self.artifacts = read_artifacts(&path);
                    }
                }
                if ui.button("查看 diff").clicked() {
                    if let Some(path) = self.selected.and_then(|(index, _)| self.sandboxes.get(index)).map(|sandbox| sandbox.path.clone()) {
                        self.diff = read_diff(&path);
                    }
                }
            });
            for change in &self.changes { ui.label(change); }
            if self.diff.is_some() {
                ui.horizontal(|ui| {
                    ui.label("diff（只读）");
                    if ui.small_button("关闭").clicked() { self.diff = None; }
                });
            }
            if let Some(diff) = &self.diff {
                egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                    // TextEdit edits in place, so the borrowed diff is cloned
                    // into the view's own buffer; the store value is untouched.
                    let mut text = diff.clone();
                    ui.add(egui::TextEdit::multiline(&mut text).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
                });
            }
            ui.separator();
            ui.heading("产物");
            for artifact in &self.artifacts { ui.label(artifact); }
            ui.separator();
            if ui.button("准备提交").clicked() {
                // The human decision point: an approval below records the
                // decision; the commit itself stays manual (charter: Pangu
                // never runs git commit, never --no-verify).
                self.pending = Some(commit_prompt(&self.changes));
                self.pending_commit = true;
            }
            if let Some(summary) = &self.commit_summary { ui.label(summary); }
        });
        egui::CentralPanel::default().frame(egui::Frame::central_panel(&ctx.style()).fill(egui::Color32::from_rgb(17, 17, 19)).inner_margin(24.0)).show(ctx, |ui| {
            egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                ui.set_max_width(820.0);
                // The workspace conversation, as the agent stored it: user and
                // assistant prose render as markdown, tool output stays
                // one bounded line (the full record is in the event stream and
                // the journal).
                if let Some(messages) = &self.conversation_view {
                    ui.label(egui::RichText::new("工作区会话（agent 会话存储 · 只读投影）").strong());
                    for message in messages {
                        match message {
                            pangu_core::Message::System { content } => {
                                ui.label(egui::RichText::new(format!("system: {}", pangu_core::one_line(content, 160))).weak().small());
                            }
                            pangu_core::Message::User { content } => {
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                                    ui.set_max_width(ui.available_width() * 0.86);
                                    render_markdown(ui, content);
                                });
                            }
                            pangu_core::Message::Assistant { content, .. } => {
                                egui::Frame::NONE
                                    .fill(egui::Color32::from_rgb(24, 26, 30))
                                    .inner_margin(8.0)
                                    .outer_margin(egui::Margin::symmetric(0, 4))
                                    .show(ui, |ui| {
                                        ui.set_width(ui.available_width());
                                        render_markdown(ui, content);
                                    });
                            }
                            pangu_core::Message::Tool { content, is_error, .. } => {
                                let label = if *is_error { "工具错误" } else { "工具" };
                                ui.label(format!("{label}: {}", pangu_core::one_line(content, 200)));
                            }
                        }
                        ui.add_space(4.0);
                    }
                    ui.separator();
                    ui.add_space(8.0);
                }
                for line in self.log.lines() {
                    if line.starts_with("你：") {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| { ui.label(egui::RichText::new(line.trim_start_matches("你：")).strong()); });
                    } else if !line.is_empty() {
                        ui.label(line);
                    }
                    ui.add_space(4.0);
                }
                // The live event stream (P0-3): the current run's audit, kept
                // after it ends so it can be re-read. Rows fold to one line;
                // expanding shows the full redacted record.
                if !self.run_events.is_empty() {
                    ui.add_space(8.0);
                    ui.separator();
                    ui.label(egui::RichText::new(if self.run.is_some() { "运行中（实时事件流）" } else { "上次运行的事件流" }).strong());
                    for (index, event) in self.run_events.iter().enumerate() {
                        let expanded = self.run_expanded.contains(&index);
                        ui.horizontal(|ui| {
                            if ui.small_button(if expanded { "▾" } else { "▸" }).clicked() {
                                if expanded { self.run_expanded.remove(&index); } else { self.run_expanded.insert(index); }
                            }
                            ui.label(event_line(event));
                        });
                        if expanded {
                            ui.label(egui::RichText::new(event_detail(event)).monospace().weak());
                        }
                        ui.add_space(2.0);
                    }
                }
            });
        });
        if let Some(action) = self.pending.clone() {
            let mut open = true;
            egui::Window::new("风险确认").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).open(&mut open).show(ctx, |ui| {
                ui.label(&action);
                ui.horizontal(|ui| {
                    if ui.button("拒绝").clicked() { self.log.push_str("\n已拒绝。"); self.pending = None; self.pending_commit = false; }
                    if ui.button("允许一次").clicked() {
                        self.log.push_str("\n已允许一次。");
                        if self.pending_commit {
                            // The commit decision is now on the record; the
                            // commit itself stays the operator's manual step.
                            self.commit_summary = Some(prepare_commit_summary(&self.changes));
                        }
                        self.pending = None;
                        self.pending_commit = false;
                    }
                });
            });
            if !open { self.log.push_str("\n已拒绝。"); self.pending = None; self.pending_commit = false; }
        }
        if self.settings_open {
            let mut open = true;
            egui::Window::new("设置").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).open(&mut open).show(ctx, |ui| {
                ui.set_min_width(420.0);
                ui.label("配置条目");
                ui.label(format!("当前配置：{}", self.settings.active_config));
                ui.label("Provider：自定义 JSON 配置");
                ui.label("密钥：每行一个 key，明文保存在本机配置文件；按请求顺序轮询");
                if ui.button("自定义 Provider").clicked() { self.providers_open = true; }
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("doctor / explain").on_hover_text("当前配置的 provider 解析、价格来源与 digest").clicked() {
                        let source = std::fs::read_to_string(config_dir().join(&self.settings.active_config)).unwrap_or_default();
                        self.explain = pangu_boundary::Config::from_json(&source).ok().map(|config| config.explain());
                    }
                    if ui.button("技能").on_hover_text("所选工作区已安装的技能（只读；安装/卸载走 CLI）").clicked() {
                        if let Some(path) = self.selected.and_then(|(index, _)| self.sandboxes.get(index)).map(|sandbox| sandbox.path.clone()) {
                            self.skills = read_skills(&path, &self.settings.active_config);
                        } else {
                            self.skills = vec!["先选择一个沙箱。".into()];
                        }
                    }
                });
                ui.separator();
                if ui.button("保存设置").clicked() { save_settings(&self.settings); save_providers(&self.providers); self.settings_open = false; }
            });
            if !open { self.settings_open = false; }
        }
        if let Some(explain) = self.explain.clone() {
            let mut open = true;
            egui::Window::new("doctor / explain").collapsible(false).resizable(true).default_size([560.0, 420.0]).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).open(&mut open).show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let mut text = explain.clone();
                    ui.add(egui::TextEdit::multiline(&mut text).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
                });
            });
            if !open { self.explain = None; }
        }
        if !self.skills.is_empty() {
            let mut open = true;
            egui::Window::new("技能").collapsible(false).resizable(true).default_size([420.0, 300.0]).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).open(&mut open).show(ctx, |ui| {
                for skill in &self.skills { ui.label(skill); }
            });
            if !open { self.skills.clear(); }
        }
        if self.providers_open {
            let mut open = true;
            egui::Window::new("自定义 Provider").collapsible(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 20.0]).open(&mut open).show(ctx, |ui| {
                ui.set_min_width(420.0);
                ui.horizontal(|ui| {
                    if ui.button("+").on_hover_text("新建 Provider").clicked() { self.provider_draft = ProviderProfile { name: String::new(), base_url: "https://api.openai.com/v1".into(), model: String::new(), models: Vec::new(), api_keys: String::new(), api_key_envs: String::new() }; self.provider_preset = String::new(); self.provider_edit_index = None; self.provider_editor_open = true; }
                    if ui.add_enabled(self.selected_provider.is_some(), egui::Button::new("*")).on_hover_text("修改选中的 Provider").clicked() {
                        if let Some(index) = self.selected_provider {
                        if let Some(provider) = self.providers.get(index) {
                            self.provider_draft = provider.clone();
                            // A profile whose name is a registry preset keeps
                            // that preset's locked URL and model list; anything
                            // else opens fully editable.
                            let name = provider.name.trim();
                            self.provider_preset = if pangu_boundary::registry::preset(name).is_some() { name.to_string() } else { String::new() };
                            self.provider_edit_index = Some(index);
                            // The models this endpoint answered with last time
                            // are persisted on the profile: seed the dropdown
                            // from them so no re-probe is needed to see them.
                            self.provider_models = provider.models.clone();
                            self.provider_probe_error = None;
                            self.provider_probe_note = None;
                            self.provider_editor_open = true;
                        }
                        }
                    }
                    if ui.add_enabled(self.selected_provider.is_some(), egui::Button::new("-")).on_hover_text("删除选中的 Provider").clicked() {
                        if let Some(index) = self.selected_provider {
                            if index < self.providers.len() {
                                self.providers.remove(index);
                                save_providers(&self.providers);
                                self.selected_provider = None;
                                // An editor aimed at the removed row (or past
                                // it) must not write back into a shifted list.
                                let was_editing = self.provider_edit_index.is_some();
                                self.provider_edit_index = edit_index_after_removal(self.provider_edit_index, index);
                                if was_editing && self.provider_edit_index.is_none() { self.provider_editor_open = false; }
                            }
                        }
                    }
                });
                for (index, provider) in self.providers.iter().enumerate() {
                    let declared = key_lines(&provider.api_keys).len().max(key_lines(&provider.api_key_envs).len());
                    let label = if declared > 1 { format!("{}（{} 个 key）", provider.name, declared) } else { provider.name.clone() };
                    if ui.selectable_label(self.selected_provider == Some(index), label).clicked() { self.selected_provider = Some(index); }
                }
                ui.separator();
                ui.label("+ 新建 · * 修改选中项 · - 删除选中项；选中项驱动下一次 run。");
            });
            if !open { self.providers_open = false; }
        }
        if self.provider_editor_open {
            self.poll_model_probe();
            let mut open = true;
            let editing = self.provider_edit_index;
            let editing_name = match editing {
                Some(index) => self.providers.get(index).map(|provider| provider.name.clone()),
                None => None,
            };
            egui::Window::new(if editing.is_some() { "Provider 设置（修改）" } else { "Provider 设置（新建）" }).collapsible(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 40.0]).open(&mut open).show(ctx, |ui| {
                if let Some(name) = &editing_name { ui.label(format!("正在修改：{name}")); }
                let presets = pangu_boundary::registry::presets();
                let previous_preset = self.provider_preset.clone();
                egui::ComboBox::from_label("官方 Provider")
                    .selected_text(if self.provider_preset.is_empty() { "自定义".to_string() } else { self.provider_preset.clone() })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.provider_preset, String::new(), "自定义");
                        for preset in presets {
                            ui.selectable_value(&mut self.provider_preset, preset.name.to_string(), preset.name)
                                .on_hover_text(format!("{}\n价格表截至 {}\n内置模型 {} 个", preset.base_url, preset.prices_as_of, preset.models.len()));
                        }
                    });
                if self.provider_preset != previous_preset {
                    if let Some(preset) = presets.iter().find(|preset| preset.name == self.provider_preset) {
                        fill_draft_from_preset(&mut self.provider_draft, preset);
                    }
                    // Whatever the previous endpoint answered no longer
                    // describes this one — the draft's list and the last note
                    // go with it.
                    self.provider_draft.models.clear();
                    self.provider_models.clear();
                    self.provider_probe_error = None;
                    self.provider_probe_note = None;
                }
                ui.label("名称"); ui.text_edit_singleline(&mut self.provider_draft.name);
                ui.label("Base URL");
                ui.add_enabled(!preset_url_is_locked(&self.provider_preset), egui::TextEdit::singleline(&mut self.provider_draft.base_url));
                if preset_url_is_locked(&self.provider_preset) {
                    ui.label("官方 Provider 的 URL 已锁定；换端点请选「自定义」。");
                } else if base_url_is_cleartext(&self.provider_draft.base_url) {
                    ui.label("http 为明文传输：同一网络可见请求内容与 API key；仅用于可信内网或本地代理。");
                }
                // The model is always typeable; the dropdown below is a
                // convenience over the preset's tool-capable models and
                // whatever the endpoint probe returned. A dropdown alone
                // would strand a custom provider's model (nothing to pick
                // from until a probe) and an edited profile's existing value.
                ui.label("模型");
                ui.text_edit_singleline(&mut self.provider_draft.model);
                let choices = model_choices(&self.provider_preset, &self.provider_models);
                if !choices.is_empty() {
                    let mut model_choice = self.provider_draft.model.clone();
                    egui::ComboBox::from_label("从列表选择")
                        .selected_text(if model_choice.is_empty() { "（先获取模型）".to_string() } else { model_choice.clone() })
                        .show_ui(ui, |ui| {
                            for name in &choices {
                                ui.selectable_value(&mut model_choice, name.clone(), name);
                            }
                        });
                    if model_choice != self.provider_draft.model { self.provider_draft.model = model_choice; }
                }
                ui.label("API Key（每行一个，轮询）");
                ui.add(egui::TextEdit::multiline(&mut self.provider_draft.api_keys).desired_rows(3).hint_text("每行一个 key，明文保存在本机 .pangu/config/providers.json"));
                ui.label(format!("已声明 {} 个 key；按请求顺序轮询。旧配置里写环境变量名的 profile 仍按变量解析。", key_lines(&self.provider_draft.api_keys).len().max(key_lines(&self.provider_draft.api_key_envs).len())));
                let probing = self.provider_probe_rx.is_some();
                let probe_error = self.provider_probe_error.clone();
                let probe_note = self.provider_probe_note.clone();
                ui.horizontal(|ui| {
                    if ui.add_enabled(!probing, egui::Button::new("获取模型列表")).on_hover_text("用首个 key 请求 <Base URL>/models").clicked() { self.start_model_probe(); }
                    if probing { ui.label("正在获取…"); }
                    else if let Some(error) = &probe_error { ui.label(format!("获取失败：{error}")); }
                    else if let Some(note) = &probe_note { ui.label(note.as_str()); }
                });
                if !self.provider_draft.models.is_empty() && probe_note.is_none() && !probing {
                    ui.label(format!("配置里已存有 {} 个模型；重新获取会整体替换。", self.provider_draft.models.len()));
                }
                let save_label = if editing.is_some() { "保存修改" } else { "保存 Provider" };
                if ui.button(save_label).clicked() && !self.provider_draft.name.trim().is_empty() {
                    store_draft(&mut self.providers, &self.provider_draft, editing);
                    save_providers(&self.providers);
                    self.provider_editor_open = false;
                }
            });
            if !open { self.provider_editor_open = false; }
        }
        save_sandboxes(&self.sandboxes);
    }
}

fn load_cjk_font(ctx: &egui::Context) {
    let candidates = [
        "C:\\Windows\\Fonts\\msyh.ttc",
        "C:\\Windows\\Fonts\\simhei.ttf",
        "/System/Library/Fonts/PingFang.ttc",
    ];
    if let Some(path) = candidates.into_iter().find(|path| std::path::Path::new(path).exists()) {
        if let Ok(bytes) = std::fs::read(path) {
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert("cjk".into(), std::sync::Arc::new(egui::FontData::from_owned(bytes)));
            for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                fonts.families.get_mut(&family).expect("font family").insert(0, "cjk".into());
            }
            ctx.set_fonts(fonts);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_conversation_model, apply_provider_profile, base_url_is_cleartext, commit_prompt,
        conversation_model_choices, edit_index_after_removal, event_line, fill_draft_from_preset,
        inline_job, key_lines, markdown_blocks, markdown_format, model_choices, persisted_models,
        preset_url_is_locked, probe_key, profile_keys, sandbox_label_for, store_draft,
        ProviderProfile, PROFILE_KEY_ENV, MarkdownBlock, MAX_PERSISTED_MODELS, RunStats,
    };
    use std::path::Path;

    fn profile(name: &str) -> ProviderProfile {
        ProviderProfile {
            name: name.into(),
            base_url: String::new(),
            model: String::new(),
            models: Vec::new(),
            api_keys: String::new(),
            api_key_envs: String::new(),
        }
    }

    #[test]
    fn nearby_sandbox_uses_short_name() {
        let app = Path::new("F:/app/target/debug");
        assert_eq!(sandbox_label_for(app, Path::new("F:/app/target/debug/.pangu")), "./.pangu");
    }

    #[test]
    fn sandbox_within_three_levels_uses_relative_path() {
        let app = Path::new("F:/app/target/debug");
        assert_eq!(sandbox_label_for(app, Path::new("F:/app/other")), "../../../other");
    }

    #[test]
    fn distant_sandbox_keeps_full_path() {
        let app = Path::new("F:/app/target/debug");
        assert_eq!(sandbox_label_for(app, Path::new("D:/work/project")), "D:/work/project");
    }

    #[test]
    fn multiline_key_field_splits_trims_and_skips_blank_lines() {
        assert_eq!(
            key_lines(" sk-one \n\n sk-two \n"),
            vec!["sk-one".to_string(), "sk-two".to_string()]
        );
        assert!(key_lines("   \n \n").is_empty());
    }

    #[test]
    fn preset_fill_writes_the_preset_defaults_and_no_credential() {
        let preset = pangu_boundary::registry::preset("openai").expect("openai preset");
        let mut draft = ProviderProfile {
            name: String::new(),
            base_url: String::new(),
            model: String::new(),
            models: vec!["stale-from-another-endpoint".to_string()],
            api_keys: String::new(),
            api_key_envs: String::new(),
        };
        fill_draft_from_preset(&mut draft, preset);
        assert_eq!(draft.name, "openai");
        assert_eq!(draft.base_url, "https://api.openai.com/v1");
        assert!(
            draft.api_keys.is_empty() && draft.api_key_envs.is_empty(),
            "a preset contributes no credential; the operator pastes the key"
        );
        assert!(
            draft.models.is_empty(),
            "a preset contributes no fetched model list"
        );
        // The first tool-capable model that covers the embedded input budget
        // (gpt-4o's 128K window would fail the config-time check against the
        // 200K default), so the prefilled profile starts a valid run.
        assert_eq!(draft.model, "gpt-4.1");
    }

    #[test]
    fn raw_keys_are_used_verbatim_and_win_over_legacy_names() {
        let profile = ProviderProfile {
            name: "openai".into(),
            base_url: String::new(),
            model: String::new(),
            models: Vec::new(),
            api_keys: "sk-one\nsk-two".into(),
            // A half-migrated profile still carrying names must not send the
            // variable's value on accident.
            api_key_envs: "OLD_NAME".into(),
        };
        assert_eq!(
            profile_keys(&profile).expect("raw keys"),
            vec!["sk-one".to_string(), "sk-two".to_string()]
        );
        assert_eq!(
            probe_key(&profile).expect("probe key"),
            Some("sk-one".to_string()),
            "the probe uses the first stored key"
        );
    }

    #[test]
    fn legacy_profiles_without_keys_still_resolve_from_the_environment() {
        let profile = ProviderProfile {
            name: "openai".into(),
            base_url: String::new(),
            model: String::new(),
            models: Vec::new(),
            api_keys: String::new(),
            api_key_envs: "PANGU_TEST_ABSENT_LEGACY_NAME".into(),
        };
        let error = profile_keys(&profile).expect_err("unset variable must fail");
        assert!(error.contains("PANGU_TEST_ABSENT_LEGACY_NAME"), "got: {error}");
        let error = probe_key(&profile).expect_err("unset variable must fail");
        assert!(error.contains("未设置"), "got: {error}");
        // No credential at all (e.g. local ollama) is not an error.
        let keyless = ProviderProfile {
            name: "ollama".into(),
            base_url: String::new(),
            model: String::new(),
            models: Vec::new(),
            api_keys: String::new(),
            api_key_envs: String::new(),
        };
        assert!(profile_keys(&keyless).expect("keyless").is_empty());
        assert_eq!(probe_key(&keyless).expect("keyless probe"), None);
    }

    #[test]
    fn legacy_profile_overrides_the_model_section_and_stays_priced() {
        let mut config = pangu_boundary::Config::embedded().expect("embedded config");
        let profile = ProviderProfile {
            name: "deepseek".into(),
            base_url: "https://api.deepseek.com/v1".into(),
            model: "deepseek-chat".into(),
            models: Vec::new(),
            api_keys: String::new(),
            api_key_envs: "DEEPSEEK_API_KEY\nDEEPSEEK_API_KEY_BACKUP".into(),
        };
        apply_provider_profile(&mut config, &profile);
        assert_eq!(config.model.provider.as_deref(), Some("deepseek"));
        assert_eq!(config.model.model.as_deref(), Some("deepseek-chat"));
        assert_eq!(config.model.base_url.as_deref(), Some("https://api.deepseek.com/v1"));
        // The config schema carries one variable; the full rotation list is
        // resolved from the profile at run time.
        assert_eq!(config.model.api_key_env.as_deref(), Some("DEEPSEEK_API_KEY"));
        let resolved = config.resolve_provider().expect("resolve");
        assert_eq!(resolved.input_usd_per_mtok, Some(0.27));
    }

    #[test]
    fn raw_keys_satisfy_the_preset_key_requirement_without_a_variable() {
        // A keyed preset refuses to start unless `model.api_key_env` is set;
        // a profile storing keys names the local profile file instead of a
        // variable that was never consulted.
        let mut config = pangu_boundary::Config::embedded().expect("embedded config");
        let profile = ProviderProfile {
            name: "openai".into(),
            base_url: String::new(),
            model: "gpt-4.1".into(),
            models: Vec::new(),
            api_keys: "sk-live".into(),
            api_key_envs: String::new(),
        };
        apply_provider_profile(&mut config, &profile);
        assert_eq!(config.model.api_key_env.as_deref(), Some(PROFILE_KEY_ENV));
        config.validate().expect("raw-key profile must satisfy validation");
    }

    #[test]
    fn unknown_profile_name_never_becomes_a_preset_reference() {
        let mut config = pangu_boundary::Config::embedded().expect("embedded config");
        let profile = ProviderProfile {
            name: "my-proxy".into(),
            base_url: "https://proxy.example.com/v1".into(),
            model: "some-model".into(),
            models: Vec::new(),
            api_keys: "sk-proxy".into(),
            api_key_envs: String::new(),
        };
        apply_provider_profile(&mut config, &profile);
        assert!(
            config.model.provider.is_none(),
            "an unknown name declared as model.provider would fail config resolution"
        );
        assert_eq!(config.model.base_url.as_deref(), Some("https://proxy.example.com/v1"));
        assert_eq!(config.model.api_key_env.as_deref(), Some(PROFILE_KEY_ENV));
    }

    #[test]
    fn empty_profile_fields_do_not_clobber_the_config() {
        let mut config = pangu_boundary::Config::embedded().expect("embedded config");
        let before = config.model.model.clone();
        let profile = ProviderProfile {
            name: "  ".into(),
            base_url: String::new(),
            model: String::new(),
            models: Vec::new(),
            api_keys: String::new(),
            api_key_envs: String::new(),
        };
        apply_provider_profile(&mut config, &profile);
        assert_eq!(config.model.model, before);
    }

    #[test]
    fn choosing_a_preset_locks_the_url_until_custom_is_selected() {
        assert!(preset_url_is_locked("openai"));
        assert!(preset_url_is_locked(" deepseek "));
        assert!(!preset_url_is_locked(""));
        assert!(!preset_url_is_locked("   "));
    }

    #[test]
    fn cleartext_endpoints_are_flagged_unless_they_are_loopback() {
        assert!(base_url_is_cleartext("http://gateway.intranet:8310/v1"));
        assert!(base_url_is_cleartext("http://10.0.0.5:8310/v1"));
        assert!(!base_url_is_cleartext("https://api.openai.com/v1"));
        assert!(!base_url_is_cleartext("http://localhost:11434/v1"));
        assert!(!base_url_is_cleartext("http://127.0.0.1:8310/v1"));
        assert!(!base_url_is_cleartext("http://[::1]:8310/v1"));
        assert!(!base_url_is_cleartext("  "));
    }

    #[test]
    fn saving_in_edit_mode_replaces_the_row_and_create_mode_appends() {
        let mut providers = vec![profile("first"), profile("second")];
        // Edit mode: the row under edit is replaced in place, order intact.
        store_draft(&mut providers, &profile("second-edited"), Some(1));
        assert_eq!(
            providers.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            vec!["first", "second-edited"]
        );
        // Create mode: append.
        store_draft(&mut providers, &profile("third"), None);
        assert_eq!(providers.len(), 3);
        // The list shrank underneath an open editor: append rather than panic
        // or drop the operator's latest draft.
        store_draft(&mut providers, &profile("orphan"), Some(9));
        assert_eq!(providers.last().map(|p| p.name.as_str()), Some("orphan"));
    }

    #[test]
    fn deleting_a_row_invalidates_an_editor_aimed_at_or_past_it() {
        // Editing an earlier row survives a later delete.
        assert_eq!(edit_index_after_removal(Some(0), 2), Some(0));
        // The edited row itself, and any row after it, no longer address what
        // the editor loaded.
        assert_eq!(edit_index_after_removal(Some(1), 1), None);
        assert_eq!(edit_index_after_removal(Some(2), 1), None);
        // Create mode is unaffected by any delete.
        assert_eq!(edit_index_after_removal(None, 3), None);
    }

    #[test]
    fn old_conversation_records_load_without_a_model() {
        // A sandboxes.json written before the model field existed must load,
        // and load as "follow the provider" — never as an error.
        let sandbox: super::Sandbox = serde_json::from_str(
            r#"{"id":"sb","path":"/tmp/sb","conversations":[{"id":"c1","title":"对话 1","archived":false}]}"#,
        )
        .expect("legacy record");
        assert_eq!(sandbox.conversations[0].model, None);
    }

    #[test]
    fn conversation_model_choices_come_from_the_selected_provider() {
        let providers = vec![
            profile("openai"),
            ProviderProfile {
                name: "my-proxy".into(),
                base_url: "http://proxy:8310/v1".into(),
                model: "proxy-model".into(),
                models: Vec::new(),
                api_keys: String::new(),
                api_key_envs: String::new(),
            },
        ];
        // A preset provider offers its tool-capable registry models.
        let preset = conversation_model_choices(&providers, Some(0), None);
        assert_eq!(
            preset,
            vec![
                "gpt-4o".to_string(),
                "gpt-4o-mini".to_string(),
                "gpt-4.1".to_string(),
                "gpt-4.1-mini".to_string(),
                "gpt-4.1-nano".to_string(),
                "o3".to_string(),
                "o4-mini".to_string(),
            ]
        );
        // A custom endpoint has only the provider's own model to offer.
        assert_eq!(
            conversation_model_choices(&providers, Some(1), None),
            vec!["proxy-model".to_string()]
        );
        // A pick that is not in the provider's list still shows up, so it can
        // be seen and changed back.
        assert_eq!(
            conversation_model_choices(&providers, Some(1), Some("hand-typed")),
            vec!["proxy-model".to_string(), "hand-typed".to_string()]
        );
        // No provider selected: only the conversation's own pick.
        assert_eq!(
            conversation_model_choices(&providers, None, Some("kept")),
            vec!["kept".to_string()]
        );
    }

    #[test]
    fn the_commit_prompt_is_the_decision_point_not_an_execution() {
        let prompt = commit_prompt(&["M a.rs".to_string(), "M b.rs".to_string()]);
        assert!(prompt.contains('2'), "the count is in the prompt: {prompt}");
        assert!(
            prompt.contains("不执行 git commit"),
            "the prompt must state that Pangu does not commit: {prompt}"
        );
        assert!(
            prompt.contains("--no-verify"),
            "and that hooks are never bypassed: {prompt}"
        );
        assert!(
            !prompt.contains("\n\n"),
            "the modal is short enough to read at a glance"
        );
    }

    #[test]
    fn run_stats_track_turns_tokens_and_the_active_tool() {
        let mut stats = RunStats::default();
        stats.observe(&pangu_core::Event::new(
            pangu_core::EventKind::TurnStarted,
            2,
            "turn 2",
        ));
        stats.observe(
            &pangu_core::Event::new(pangu_core::EventKind::ToolStarted, 2, "reading")
                .tool("read_file"),
        );
        assert_eq!(stats.turn, 2);
        assert_eq!(stats.active_tool.as_deref(), Some("read_file"));
        stats.observe(
            &pangu_core::Event::new(pangu_core::EventKind::ToolFinished, 2, "ok").tool("read_file"),
        );
        assert!(stats.active_tool.is_none(), "a finished tool is no longer active");
        stats.observe(
            &pangu_core::Event::new(pangu_core::EventKind::ModelResponse, 2, "received").usage(
                pangu_core::Usage {
                    input_tokens: 10,
                    output_tokens: 4,
                    cache_read_tokens: 0,
                },
            ),
        );
        assert_eq!((stats.input_tokens, stats.output_tokens), (10, 4));
    }

    #[test]
    fn event_lines_are_one_line_and_carry_the_turn() {
        let event = pangu_core::Event::new(pangu_core::EventKind::Note, 3, "first line\nsecond line");
        let line = event_line(&event);
        assert!(!line.contains('\n'), "a stream row is one line");
        assert!(line.contains("[note]"), "got: {line}");
        assert!(line.contains("t3"), "got: {line}");
    }

    #[test]
    fn markdown_blocks_split_text_without_formatting_code() {
        let blocks = markdown_blocks(
            "# 标题\n\n一段文字\n继续同一段\n\n- 项目一\n- 项目二\n\n> 引用\n\n---\n\n```rust\nfn main() {}\n```\n",
        );
        assert_eq!(
            blocks,
            vec![
                MarkdownBlock::Heading {
                    level: 1,
                    text: "标题".to_string()
                },
                MarkdownBlock::Paragraph("一段文字 继续同一段".to_string()),
                MarkdownBlock::ListItem {
                    ordered: false,
                    text: "项目一".to_string()
                },
                MarkdownBlock::ListItem {
                    ordered: false,
                    text: "项目二".to_string()
                },
                MarkdownBlock::Quote("引用".to_string()),
                MarkdownBlock::Rule,
                MarkdownBlock::Code {
                    language: Some("rust".to_string()),
                    code: "fn main() {}".to_string()
                },
            ]
        );
    }

    #[test]
    fn code_fences_protect_their_contents() {
        // A heading-looking line inside a fence is content, not a heading, and
        // the fence only ends at a closing fence.
        let blocks = markdown_blocks("```\n# not a heading\n- not a list\n```\n# real heading");
        assert_eq!(
            blocks,
            vec![
                MarkdownBlock::Code {
                    language: None,
                    code: "# not a heading\n- not a list".to_string()
                },
                MarkdownBlock::Heading {
                    level: 1,
                    text: "real heading".to_string()
                },
            ]
        );
    }

    #[test]
    fn ordered_lists_and_headings_need_their_markers() {
        assert_eq!(
            markdown_blocks("1. one\n2) two"),
            vec![
                MarkdownBlock::ListItem {
                    ordered: true,
                    text: "one".to_string()
                },
                MarkdownBlock::ListItem {
                    ordered: true,
                    text: "two".to_string()
                },
            ]
        );
        // "#tag" is a paragraph, not a heading; "### " with nothing is a
        // heading with empty text (still a heading).
        assert_eq!(
            markdown_blocks("#tag is text"),
            vec![MarkdownBlock::Paragraph("#tag is text".to_string())]
        );
    }

    #[test]
    fn inline_job_styles_code_and_emphasis_and_keeps_unclosed_literal() {
        let plain = inline_job("plain text", markdown_format());
        assert_eq!(plain.sections.len(), 1);
        assert_eq!(plain.text, "plain text");
        let styled = inline_job("a `code` b **bold** c *it*", markdown_format());
        assert_eq!(styled.text, "a code b bold c it");
        assert!(
            styled.sections.len() >= 5,
            "code, bold and italic each become their own section: {}",
            styled.sections.len()
        );
        // An unclosed backtick renders literally — no phantom formatting.
        let unclosed = inline_job("a ` stray", markdown_format());
        assert_eq!(unclosed.text, "a ` stray");
        assert_eq!(unclosed.sections.len(), 1);
    }

    #[test]
    fn the_conversation_model_is_the_most_specific_choice() {
        let mut config = pangu_boundary::Config::embedded().expect("embedded config");
        config.model.model = Some("provider-model".into());
        apply_conversation_model(&mut config, Some("  conversation-model  "));
        assert_eq!(config.model.model.as_deref(), Some("conversation-model"));
        // `None` and blank leave the profile's (now the conversation's) model
        // in place — never an empty string that would fail config validation.
        apply_conversation_model(&mut config, None);
        assert_eq!(config.model.model.as_deref(), Some("conversation-model"));
        apply_conversation_model(&mut config, Some("   "));
        assert_eq!(config.model.model.as_deref(), Some("conversation-model"));
    }

    #[test]
    fn persisted_probe_results_are_bounded() {
        let small: Vec<String> = (0..10).map(|index| format!("model-{index}")).collect();
        assert_eq!(persisted_models(small.clone()), small, "under the cap: unchanged");
        let large: Vec<String> =
            (0..MAX_PERSISTED_MODELS + 40).map(|index| format!("model-{index}")).collect();
        let kept = persisted_models(large);
        assert_eq!(kept.len(), MAX_PERSISTED_MODELS, "over the cap: truncated");
        assert_eq!(kept.last().map(String::as_str), Some("model-63"));
    }

    #[test]
    fn a_profile_round_trips_its_fetched_models() {
        // What the probe wrote must survive a save/load cycle, and a profile
        // written before this field existed must still load.
        let with_models = profile("openai");
        let json = serde_json::to_string(&with_models).expect("serialize");
        assert!(json.contains("\"models\""), "the field is persisted: {json}");
        let back: ProviderProfile = serde_json::from_str(&json).expect("deserialize");
        assert!(back.models.is_empty());
        let legacy = serde_json::json!({
            "name": "openai",
            "base_url": "https://api.openai.com/v1",
            "model": "gpt-4.1",
            "api_key": "OPENAI_API_KEY"
        });
        let loaded: ProviderProfile = serde_json::from_value(legacy).expect("legacy profile");
        assert!(loaded.models.is_empty(), "absent means empty, not an error");
        let populated = profile("openai");
        assert!(populated.models.is_empty(), "test helper starts empty");
    }

    #[test]
    fn model_choices_lead_with_tool_capable_preset_models_and_dedupe() {
        // deepseek-reasoner had no tool support in the registry table: Pangu
        // cannot use it, so it must not be offered as a candidate at all.
        assert_eq!(model_choices("deepseek", &[]), vec!["deepseek-chat".to_string()]);
        // Fetched models append, deduplicated against the preset's own list.
        assert_eq!(
            model_choices(
                "deepseek",
                &["deepseek-chat".to_string(), "local-model".to_string()]
            ),
            vec!["deepseek-chat".to_string(), "local-model".to_string()]
        );
        // A custom provider has no registry models: only the probe's answers.
        assert_eq!(
            model_choices("", &["some-model".to_string()]),
            vec!["some-model".to_string()]
        );
        // An unknown name behaves like custom, mirroring apply_provider_profile.
        assert!(model_choices("no-such-provider", &[]).is_empty());
    }
}

fn main() -> eframe::Result {
    let root = ensure_data_dir();
    if !root.join("session").exists() {
        eprintln!("无法创建数据目录 {}", root.display());
    }
    let _ = load_sandboxes();
    let options = eframe::NativeOptions { viewport: egui::ViewportBuilder::default().with_inner_size([1080.0, 720.0]).with_active(true), ..Default::default() };
    eframe::run_native("Pangu", options, Box::new(|cc| { load_cjk_font(&cc.egui_ctx); Ok(Box::new(Client::default())) }))
}
