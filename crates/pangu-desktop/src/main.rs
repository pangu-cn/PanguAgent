#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Conversation { id: String, title: String, archived: bool }
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
    /// One API key **environment variable name** per line. The file keeps the
    /// historical `api_key_env` key, so single-line profiles written by older
    /// builds load unchanged; multiple lines mean the runtime resolves every
    /// name from the process environment and rotates across the keys (the keys
    /// themselves are never stored — ADR-0013 §4).
    #[serde(rename = "api_key_env")]
    api_key_envs: String,
}

/// Split the multi-line environment variable field into declared names.
/// Blank lines are ignored; validation happens where the names are resolved.
fn api_key_env_names(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

/// Fill the editor draft from a built-in registry preset. Only the preset's
/// own defaults are written (endpoint, key variable, first tool-capable
/// model); the operator can still edit every field afterwards.
fn fill_draft_from_preset(
    draft: &mut ProviderProfile,
    preset: &pangu_boundary::registry::ProviderPreset,
) {
    draft.name = preset.name.to_string();
    draft.base_url = preset.base_url.to_string();
    draft.api_key_envs = preset.api_key_env.unwrap_or_default().to_string();
    draft.model = preset
        .models
        .iter()
        .find(|model| model.supports_tools)
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
    // Only the first name enters the config (the schema carries one variable
    // and validation needs it); the full rotation list is resolved directly
    // from the profile at run time.
    if let Some(first) = api_key_env_names(&profile.api_key_envs).first() {
        config.model.api_key_env = Some(first.clone());
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

/// Start one run. `profile` is the provider profile selected in the custom
/// provider window; when present it overrides the active config's `[model]`
/// section in memory (provider/model/endpoint/key variables) and its key
/// variables drive per-request rotation. Prices, capabilities and every gate
/// still come from the config + registry path.
fn run_selected(config_name: &str, sandbox: &str, conversation_id: &str, goal: &str, profile: Option<&ProviderProfile>) -> Result<String, String> {
    let config_path = config_dir().join(config_name);
    let source = std::fs::read_to_string(&config_path).map_err(|error| error.to_string())?;
    let mut config = pangu_boundary::Config::from_json(&source).map_err(|error| error.to_string())?;
    if let Some(profile) = profile { apply_provider_profile(&mut config, profile); }
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
    // Rotation list: the profile's declared names, else the single effective
    // variable from config/registry. Names are resolved (not stored) here.
    let key_envs = match profile {
        Some(profile) => {
            let names = api_key_env_names(&profile.api_key_envs);
            if names.is_empty() { resolved.api_key_env.clone().into_iter().collect::<Vec<_>>() } else { names }
        }
        None => resolved.api_key_env.clone().into_iter().collect::<Vec<_>>(),
    };
    let provider = std::sync::Arc::new(pangu_provider::OpenAiCompatibleProvider::from_envs(model, resolved.base_url.clone(), &key_envs, config.model.temperature, config.model.max_output_tokens, config.model.request_timeout_secs.unwrap_or(60)).map_err(|error| error.to_string())?);
    let tools = std::sync::Arc::new(pangu_toolkit::Toolkit::with_verify_command(config.verify.command.clone()));
    let approval = std::sync::Arc::new(DesktopApproval);
    let sink = std::sync::Arc::new(pangu_core::NullSink);
    let agent = pangu_agent::Agent::new(contract, policy, sandbox_boundary, provider, tools, approval, sink).map_err(|error| error.to_string())?;
    let outcome = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|error| error.to_string())?.block_on(agent.run()).map_err(|error| error.to_string())?;
    Ok(format!("run {} finished: {} conversation={conversation_id}", outcome.status, config_path.display()))
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

fn read_artifacts(path: &str) -> Vec<String> {
    let root = std::path::Path::new(path).join(".pangu").join("deliverables");
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            if let Some(name) = entry.path().file_name() { names.push(name.to_string_lossy().into_owned()); }
        }
    }
    if names.is_empty() { vec!["没有已登记产物".into()] } else { names }
}

fn prepare_commit_summary(changes: &[String]) -> String {
    format!("准备提交 {} 个变更。此操作不执行 git commit，也不使用 --no-verify。", changes.len())
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
        Self { goal: String::new(), log: format!("数据目录：{}", data_dir().display()), pending: None, sandboxes, selected: None, settings_open: false, providers_open: false, provider_editor_open: false, providers, selected_provider: None, provider_draft: ProviderProfile { name: String::new(), base_url: "https://api.openai.com/v1".into(), model: String::new(), api_key_envs: "OPENAI_API_KEY".into() }, provider_preset: String::new(), settings, draft_config, changes: Vec::new(), artifacts: Vec::new(), commit_summary: None }
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
                    sandbox.conversations.push(Conversation { id: id.clone(), title: format!("对话 {}", sandbox.conversations.len() + 1), archived: false });
                    save_records(&sandbox.id, &id, &[]);
                }
                ui.label("对话");
                for (index, conversation) in sandbox.conversations.iter_mut().enumerate().filter(|(_, item)| !item.archived) {
                    let response = ui.add(egui::Label::new(&conversation.title).sense(egui::Sense::click()));
                    if response.clicked() { self.selected = Some((sandbox_index, index)); }
                    response.context_menu(|ui| { if ui.button("归档").clicked() { conversation.archived = true; ui.close_menu(); } });
                }
                ui.label("归档");
                for conversation in sandbox.conversations.iter_mut().filter(|item| item.archived) {
                    let response = ui.add(egui::Label::new(&conversation.title).sense(egui::Sense::click()));
                    response.context_menu(|ui| { if ui.button("取消归档").clicked() { conversation.archived = false; ui.close_menu(); } });
                }
            }
        });
        egui::TopBottomPanel::bottom("composer").exact_height(112.0).frame(egui::Frame::side_top_panel(&ctx.style()).fill(egui::Color32::from_rgb(24, 24, 27)).inner_margin(16.0)).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::multiline(&mut self.goal).desired_width(ui.available_width() - 96.0).desired_rows(2).hint_text("给 Pangu 一个任务"));
                if ui.button("执行").clicked() && !self.goal.trim().is_empty() {
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
                    self.log.push_str(&format!("\n\n你：{goal}"));
                    match self.selected.and_then(|(sandbox_index, _)| self.sandboxes.get(sandbox_index)).map(|sandbox| sandbox.path.clone()) {
                        Some(path) => match run_selected(&self.settings.active_config, &path, "selected", &goal, selected_profile.as_ref()) {
                            Ok(message) => self.log.push_str(&format!("\n{message}")),
                            Err(error) => self.log.push_str(&format!("\nrun 未启动：{error}")),
                        },
                        None => self.log.push_str("\n先选择一个沙箱。"),
                    }
                    self.goal.clear();
                }
            });
        });
        egui::SidePanel::right("changes").exact_width(300.0).show(ctx, |ui| {
            ui.heading("变更");
            if ui.button("查看变更").clicked() {
                if let Some(path) = self.selected.and_then(|(index, _)| self.sandboxes.get(index)).map(|sandbox| sandbox.path.clone()) {
                    self.changes = read_changes(&path);
                    self.artifacts = read_artifacts(&path);
                }
            }
            for change in &self.changes { ui.label(change); }
            ui.separator();
            ui.heading("产物");
            for artifact in &self.artifacts { ui.label(artifact); }
            ui.separator();
            if ui.button("准备提交").clicked() { self.commit_summary = Some(prepare_commit_summary(&self.changes)); }
            if let Some(summary) = &self.commit_summary { ui.label(summary); }
        });
        egui::CentralPanel::default().frame(egui::Frame::central_panel(&ctx.style()).fill(egui::Color32::from_rgb(17, 17, 19)).inner_margin(24.0)).show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.set_max_width(820.0);
                for line in self.log.lines() {
                    if line.starts_with("你：") {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| { ui.label(egui::RichText::new(line.trim_start_matches("你：")).strong()); });
                    } else if !line.is_empty() {
                        ui.label(line);
                    }
                    ui.add_space(4.0);
                }
            });
        });
        if let Some(action) = self.pending.clone() {
            let mut open = true;
            egui::Window::new("风险确认").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).open(&mut open).show(ctx, |ui| {
                ui.label(&action);
                ui.horizontal(|ui| {
                    if ui.button("拒绝").clicked() { self.log.push_str("\n已拒绝。"); self.pending = None; }
                    if ui.button("允许一次").clicked() { self.log.push_str("\n已允许一次。"); self.pending = None; }
                });
            });
            if !open { self.log.push_str("\n已拒绝。"); self.pending = None; }
        }
        if self.settings_open {
            let mut open = true;
            egui::Window::new("设置").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).open(&mut open).show(ctx, |ui| {
                ui.set_min_width(420.0);
                ui.label("配置条目");
                ui.label(format!("当前配置：{}", self.settings.active_config));
                ui.label("Provider：自定义 JSON 配置");
                ui.label("密钥：只记录环境变量名；每行一个，运行时解析并轮询");
                if ui.button("自定义 Provider").clicked() { self.providers_open = true; }
                ui.separator();
                if ui.button("保存设置").clicked() { save_settings(&self.settings); save_providers(&self.providers); self.settings_open = false; }
            });
            if !open { self.settings_open = false; }
        }
        if self.providers_open {
            let mut open = true;
            egui::Window::new("自定义 Provider").collapsible(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 20.0]).open(&mut open).show(ctx, |ui| {
                ui.set_min_width(420.0);
                ui.horizontal(|ui| {
                    if ui.button("+").clicked() { self.provider_draft = ProviderProfile { name: String::new(), base_url: "https://api.openai.com/v1".into(), model: String::new(), api_key_envs: "OPENAI_API_KEY".into() }; self.provider_preset = String::new(); self.provider_editor_open = true; }
                    if ui.button("-").clicked() { if let Some(index) = self.selected_provider { if index < self.providers.len() { self.providers.remove(index); save_providers(&self.providers); self.selected_provider = None; } } }
                });
                for (index, provider) in self.providers.iter().enumerate() {
                    let declared = api_key_env_names(&provider.api_key_envs).len();
                    let label = if declared > 1 { format!("{}（{} 个 key 环境变量）", provider.name, declared) } else { provider.name.clone() };
                    if ui.selectable_label(self.selected_provider == Some(index), label).clicked() { self.selected_provider = Some(index); }
                }
                ui.separator();
                ui.label("选中项驱动下一次 run；Key 只写环境变量名。");
            });
            if !open { self.providers_open = false; }
        }
        if self.provider_editor_open {
            let mut open = true;
            egui::Window::new("Provider 设置").collapsible(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 40.0]).open(&mut open).show(ctx, |ui| {
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
                }
                ui.label("名称"); ui.text_edit_singleline(&mut self.provider_draft.name);
                ui.label("Base URL"); ui.text_edit_singleline(&mut self.provider_draft.base_url);
                ui.label("模型"); ui.text_edit_singleline(&mut self.provider_draft.model);
                ui.label("API Key 环境变量（每行一个，轮询）");
                ui.add(egui::TextEdit::multiline(&mut self.provider_draft.api_key_envs).desired_rows(3).hint_text("每行一个环境变量名，例如 OPENAI_API_KEY"));
                ui.label(format!("已声明 {} 个环境变量；按请求顺序轮询，未设置的变量会在 run 开始时报错。", api_key_env_names(&self.provider_draft.api_key_envs).len()));
                if ui.button("保存 Provider").clicked() && !self.provider_draft.name.trim().is_empty() {
                    self.providers.push(self.provider_draft.clone());
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
        api_key_env_names, apply_provider_profile, fill_draft_from_preset, sandbox_label_for,
        ProviderProfile,
    };
    use std::path::Path;

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
    fn multiline_env_names_split_trim_and_skip_blank_lines() {
        assert_eq!(
            api_key_env_names(" OPENAI_API_KEY \n\n OPENAI_API_KEY_2 \n"),
            vec!["OPENAI_API_KEY".to_string(), "OPENAI_API_KEY_2".to_string()]
        );
        assert!(api_key_env_names("   \n \n").is_empty());
    }

    #[test]
    fn preset_fill_writes_the_preset_defaults() {
        let preset = pangu_boundary::registry::preset("openai").expect("openai preset");
        let mut draft = ProviderProfile {
            name: String::new(),
            base_url: String::new(),
            model: String::new(),
            api_key_envs: String::new(),
        };
        fill_draft_from_preset(&mut draft, preset);
        assert_eq!(draft.name, "openai");
        assert_eq!(draft.base_url, "https://api.openai.com/v1");
        assert_eq!(draft.api_key_envs, "OPENAI_API_KEY");
        // The first tool-capable model of the preset, so the run starts priced.
        assert_eq!(draft.model, "gpt-4o");
    }

    #[test]
    fn preset_profile_overrides_the_model_section_and_stays_priced() {
        let mut config = pangu_boundary::Config::embedded().expect("embedded config");
        let profile = ProviderProfile {
            name: "deepseek".into(),
            base_url: "https://api.deepseek.com/v1".into(),
            model: "deepseek-chat".into(),
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
    fn unknown_profile_name_never_becomes_a_preset_reference() {
        let mut config = pangu_boundary::Config::embedded().expect("embedded config");
        let profile = ProviderProfile {
            name: "my-proxy".into(),
            base_url: "https://proxy.example.com/v1".into(),
            model: "some-model".into(),
            api_key_envs: "MY_PROXY_KEY".into(),
        };
        apply_provider_profile(&mut config, &profile);
        assert!(
            config.model.provider.is_none(),
            "an unknown name declared as model.provider would fail config resolution"
        );
        assert_eq!(config.model.base_url.as_deref(), Some("https://proxy.example.com/v1"));
        assert_eq!(config.model.api_key_env.as_deref(), Some("MY_PROXY_KEY"));
    }

    #[test]
    fn empty_profile_fields_do_not_clobber_the_config() {
        let mut config = pangu_boundary::Config::embedded().expect("embedded config");
        let before = config.model.model.clone();
        let profile = ProviderProfile {
            name: "  ".into(),
            base_url: String::new(),
            model: String::new(),
            api_key_envs: String::new(),
        };
        apply_provider_profile(&mut config, &profile);
        assert_eq!(config.model.model, before);
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
