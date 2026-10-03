# Pangu Agent 盘古智能体

> 一个在显式边界内自主使用工具的 AI agent。目标 G1-G5：诚实、可审计、不越界、成本有界、可嵌入。

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/pangu-cn/PanguAgent/actions/workflows/ci.yml/badge.svg)](https://github.com/pangu-cn/PanguAgent/actions/workflows/ci.yml)

## 快速开始

需要 Rust ≥ 1.82（`Cargo.toml` 的 `rust-version`）。仓库可以直接运行：

```bash
# 查看编译进程序的默认边界、预算和规则
cargo run -q -p pangu -- doctor

# 导出一份可编辑的默认配置
cargo run -q -p pangu -- config --file boundary.toml

# 使用 OPENAI_API_KEY 发起一次真实运行（配置中需填写 model 与输入/输出价格）
OPENAI_API_KEY=... cargo run -q -p pangu -- --config boundary.toml run "列出项目根目录下的 Rust 文件"

# 不需要 API key 的 scripted demo（会读取 Cargo.toml 并完成）
cargo run -q -p pangu -- --demo
```

默认运行会在工作区的 `.pangu/journal-<timestamp>.jsonl` 写入经过脱敏的哈希链事件。`doctor` 不会发模型请求或执行工具；`--dry-run` 只打印有效配置。

## 实验性 Checkpoint / Rollback

阶段二实现已经存在，但 checkpoint/rollback **默认关闭，仍是实验性 opt-in，不是 v0.1 的默认支持承诺**。启用后，成功 `VerifiedAction` 的 `ToolFinished` 才会产生 Pangu Artifact checkpoint；rollback 只能由 typed operator/library API 或 CLI 触发，不能由模型用自然语言或裸路径触发。

在配置中显式设置：

```toml
[checkpoint]
enabled = true
backend = "artifact"
artifact_root = ".pangu/checkpoints"
# 可选：声明可排除的构建产物/缓存目录（默认空，详见 docs/adr/0001）
exclude_roots = ["target"]
```

> 快照遍历整个工作区，且默认**不排除构建产物**。仓库里若有巨大的 `target/`，checkpoint 会撞上 `max_snapshot_bytes` 而失败——错误信息会指出具体是哪个文件越界。排除是有代价的：被排除的目录不会被回退，只能排除真正可重建的内容。

并为 `rollback` 提供显式 Policy 规则（例如 `effect = "ask"`）。运行开关是全局 `--checkpoint`（别名 `--enable-checkpoint`）；rollback 目标使用 `--checkpoint-id`（别名 `--target-checkpoint`），避免参数冲突：

```bash
# 生成/运行带 checkpoint 的 run；从 CheckpointCreated 事件取得 checkpoint_id 和 session_node_id
cargo run -q -p pangu -- --config boundary.toml --checkpoint run "列出项目文件"

# rollback 会重新校验 contract、source node、CAS 和外部副作用，并通过 stdin 请求一次人工确认
cargo run -q -p pangu -- --config boundary.toml rollback \
  --checkpoint-id CHECKPOINT_ID \
  --source-node SESSION_NODE_ID \
  --rollback-id ROLLBACK_ID \
  --reason "operator requested recovery"
```

`--dangerously-unattended` 与 rollback 不兼容；`Never`、无输入、超时、外部 mutation、workspace 漂移、损坏 Artifact 或 stale transaction lock 都会 fail closed。Git backend 当前未实现，也不会隐式创建 commit/branch/tag/stash 或修改 index。阶段二限制和 operator recovery 细节见 [`docs/CHECKPOINT_RECOVERY.md`](docs/CHECKPOINT_RECOVERY.md)、[`docs/adr/0001-checkpoint-rollback.md`](docs/adr/0001-checkpoint-rollback.md) 与 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 设计目标 (G1-G5)

| ID | 目标 | 验收标准 |
|----|------|----------|
| **G1** | **诚实** | 每个运行以显式 `GoalStatus` 结束；没有成功工具证据时不能 `complete` |
| **G2** | **可审计** | 事件写入 append-only JSONL，带序号、前向哈希和篡改检测 |
| **G3** | **自主但不越界** | 工具必须经过 policy、sandbox、approval，拒绝结果回灌模型 |
| **G4** | **成本有界** | turns/input/output/cost/wall-clock 五个预算闸门任一触顶即停 |
| **G5** | **可嵌入** | `pangu-agent` 暴露库 API，运行状态不放在全局变量中 |

## 有效边界

```text
GoalContract (L1)
      │
      ▼
Policy (L2) ──deny──▶ ToolBlocked + tool_result(is_error)
      │ allow/ask
      ▼
Sandbox (L3) ──拒绝──▶ ToolBlocked + tool_result(is_error)
      │ 通过
      ▼
Approval (L4) ──拒绝/超时──▶ ToolBlocked + tool_result(is_error)
      │ 明确允许
      ▼
ToolExecutor::execute(&VerifiedAction)
      │
      ▼
证据回灌模型 → 下一次回合
```

- **L1**：`GoalContract` 在一次 run 开始时冻结工作区、roots、预算、审批模式和环境/网络限制；模型不能修改它。
- **L2**：deny 规则优先；非 deny 规则按配置顺序匹配；没有匹配规则就是 deny。allow 规则的多 path/host 目标必须全部匹配。
- **L3**：相对路径以 workspace 为基准；检查 canonical path、symlink、forbidden glob、roots、argv、环境和出站 host。
- **L4**：`Never`、`DestructiveAndAbove`、`Always`；无人值守的 `NoAnswer` 永不等于同意。
- **执行**：模型只能产生 `ToolCall`；副作用适配器只能接收 Agent 在所有闸门之后创建的 `VerifiedAction`。

## 内置工具

| 工具 | 作用 | 声明风险 | 备注 |
|------|------|----------|------|
| `read_file` | 读取有界 UTF-8 文件 | `read_only` | 读取前经过 L3 |
| `list_dir` | 列出目录 | `read_only` | 跳过越界/禁止项 |
| `search` | 搜索目录中的 UTF-8 文本 | `read_only` | 有深度、结果数和输出上限 |
| `write_file` | 创建或替换工作区内文件 | `reversible` | 写入大小有上限；不是自动备份工具 |
| `http_fetch` | 有界 HTTP `GET` | `needs_human` | 仅 allow-list host；禁止重定向和私网/metadata |
| `run_command` | 运行无 shell 的只读命令 allow-list | `needs_human` | 不提供通用 shell；仍需审批 |
| `git_diff` | 只读查看 `git diff/status/log/show` | `read_only` | 仅白名单子命令与 flag + 相对路径；输出超限即失败；不提交、不修改 index |
| `verify` | 运行配置中预声明的验证命令（lint/test 等） | `needs_human` | 命令来自 `[verify] command`，模型只能整体触发；未配置时该工具不存在 |
| `begin_act` | 控制调用：结束只读 plan 阶段（仅 `goal.plan_first = true` 时存在） | 控制工具 | 不执行任何动作、不过任何闸门；act 阶段的每个变更动作仍逐项审批 |
| `finish` | 提交运行状态 | 控制工具 | `complete` 需要成功证据；不是外部副作用 |

`run_command` 当前只允许 `pwd`, `cat`, `ls`, `head`, `tail`, `grep`, `wc`, `sort`, `uniq`, `diff`, `md5sum`, `sha256sum` 及受限参数。`git_diff` 当前只允许 `git diff|status|log|show` 与白名单 flag（"undo" 归 `pangu rollback`，见 ROADMAP F2）。`http_fetch` 当前只实现 GET。

`verify` 只运行 `[verify] command` 预声明的**整条命令**：程序名必须在只读 argv 白名单（内置命令或 `boundary.extra_readonly_commands`）上，flag 受与 `run_command` 相同的 SAFE 列表限制，配置在启动时冻结进 `GoalContract`，每次调用都需人工批准。`extra_readonly_commands` 是操作者对被声明程序副作用的**断言**——Pangu 不验证其真实副作用，验证命令的外部效果（如依赖下载）不进 effect ledger、不被 rollback 处理。退出码与输出回灌模型；失败不产生 evidence，`finish(complete)` 因此被拒（I-Honest-Terminal）。

## Provider

当前实现的是 `OpenAiCompatibleProvider`：

- 请求 `POST {base_url}/chat/completions`，使用 OpenAI function-calling wire format。
- 远程端点默认要求 HTTPS；`http://localhost` 可用于本地兼容服务（例如 Ollama 的 OpenAI-compatible endpoint）。
- API key 只从 `model.api_key_env` 指定的环境变量读取，不从 TOML 参数直接读取。
- 响应体、工具参数和工具输出都有上限；provider 错误在边界处脱敏。
- 成本闸门要求价格可知：显式配置，或由内置注册表（见下）提供；缺失价格不会被当作免费运行，而会在下一次 provider 请求前以 `budget_exhausted` 失败。provider 报告的 `cache_read_tokens` 计入输入 token 预算并按输入价计费。`--demo` 明确使用零价格脚本 provider。
- 没有实现 Anthropic 专用协议；可使用提供 OpenAI-compatible API 的适配端点。

内置 provider 注册表（B4）为常见 OpenAI-compatible 服务提供 endpoint/key 默认值、每模型能力声明（context window、输出上限、是否支持工具调用）与带 as-of 日期的价格表：

```toml
[model]
provider = "deepseek"       # 使用注册表预设（`pangu models list` 查看全部）
model = "deepseek-chat"     # 已知模型自动获得价格与能力；未知模型须显式声明价格
# base_url / api_key_env / 价格显式设置时覆盖预设
```

规则与诚实边界：

- **价格表只在 `model.provider` 显式命名时生效**——命名 provider 即操作者决定采用其数据；显式配置永远覆盖预设。
- 价格表会过期：`pangu models list` 显示每个预设的 as-of 日期，依赖前请核对；本地 provider（如 ollama）无内置价格，必须显式声明。
- fail-closed 前移到配置期：未知 provider、keyed provider 缺 key 变量、不支持工具调用的模型、`budget.max_input_tokens` 超出模型 context window、请求输出上限超过模型能力，均在启动时拒绝。
- `pangu models list [--json]` 离线列出注册表；`pangu models probe [--json]` 对生效 endpoint 发一次有界 `GET /models`（操作者显式发起，非 2xx 只报状态码，不回显 body/key）。

Provider fallback（B5）默认关闭，声明后生效：

```toml
[[model.fallback]]
provider = "openai"          # 候选必须在注册表中（能力可验证）
model = "gpt-4.1-mini"
input_usd_per_mtok = 2.0     # 候选必须有可解析价格（显式或注册表）
output_usd_per_mtok = 0.0
```

- 主 provider `chat` 失败时按声明顺序尝试下一个候选；每次失败尝试与成功切换都有事件（`Note` / `ProviderSwitched`），切换后的请求记录实际服务的 provider/model——**永不静默**。
- 链冻结进 contract，注入链与 contract 不一致时 Agent 拒绝启动；成本按段累计（每段用该段价格），切换不能低估成本；链耗尽时运行失败，不回跳主 provider。
- 候选在配置期全部校验：必须在注册表、支持工具、context window 覆盖输入预算、价格可解析、不与主模型或先前候选重复。

## 配置与 CLI

默认配置编译在 `config/boundary.toml`。`pangu` 还会按以下顺序加载一个用户配置：`--config`、`PANGU_CONFIG`、当前目录 `pangu.toml`、用户目录的 `~/.config/pangu/boundary.toml`；未找到时使用 embedded 配置。相对 roots 会按有效 workspace 解析。

常用参数：

```text
pangu doctor
pangu config [--file PATH]
pangu run [--dry-run] "GOAL"
pangu --demo [--dry-run]
pangu explain --tool NAME [--arg K=V ...] [--arg0 PROGRAM ...] [--path P ...] [--host H ...] [--risk CLASS] [--json]
pangu events read PATH [--kind KIND] [--json]      # PATH 也可以是 Journal 文件（自动迁移 forward）
pangu events contract [--json]
pangu conversation list
pangu conversation show [--json]
pangu conversation export [--id ID] --out PATH [--strict] [--json]
pangu models list [--json]
pangu models probe [--json]
pangu session tree [--json]
pangu session replay NODE [--full] [--json]
pangu repo map [--root PATH] [--budget N] [--json]
pangu run --workspace PATH --max-turns N --max-cost-usd X "GOAL"
pangu --checkpoint run "GOAL"
pangu rollback --checkpoint-id ID --source-node NODE --rollback-id OP --reason "..."
pangu artifact inspect --root PATH [--json]
pangu run --dangerously-unattended "GOAL"
```

`pangu artifact inspect` 是只读检查器：它不创建、不修复、不删除、不重试任何东西，只把 Artifact store 的可验证状态和事故证据（stale transaction lock、replacement backup、operation 状态、effect/failed-path 账本、commit marker 与 blob hash 一致性）报成带 `unverifiable.*` / `operator.*` 代码的报告，并在报告为 `verified` 以外时返回非零退出码。完整语义见 [`docs/CHECKPOINT_RECOVERY.md`](docs/CHECKPOINT_RECOVERY.md)。

`pangu events` 是稳定 NDJSON 事件流的只读入口（`pangu-stream/1`），供 UI、Agent Server、CI 审计器等外部工具消费，而不必绑死内部结构。它是**派生投影**，不是权威记录：每条记录固定带 `derived: true` / `authoritative: false`，自身不带哈希链（因此无法自证），只通过 `origin` 回指 Journal 的 `seq`/`sha`/`event_id`。审计权威始终是带哈希链的 Journal。契约只增不改；要改必须发 `pangu-stream/2` 并提供迁移器。未知或未来 schema 一律拒绝而不猜测，损坏行导致整读失败而非返回前缀。`pangu events contract` 列出本版本可读的 schema 与每个 kind 的冻结状态（F7 的 checkpoint/rollback 目前是 `provisional`）。设计与非目标见 [`docs/adr/0003-event-stream-contract.md`](docs/adr/0003-event-stream-contract.md)。

`pangu explain` 在不执行任何副作用的前提下回答“**如果发起这个动作，边界会怎么判**”。它把 `Policy → Sandbox → Approval` 三层逐步投影，逐条规则报出 `decided` / `matched_but_refused` / `shadowed` / `no_match` / `not_reached`，并显式区分“规则拒绝”与“路径安全检查拒绝”（含被早先规则遮蔽的死规则分析）。它不执行、不写盘、不发事件、不是授权：`ExplainReport` 永远带 `advisory: true` / `authoritative: false`，且不提供到 `Effect` 的任何转换；真实运行会重新求值一切，两者不一致时以真实运行为准。设计与非目标见 [`docs/adr/0002-explain-policy-simulation.md`](docs/adr/0002-explain-policy-simulation.md)。

对话持久化默认**关闭**，需显式开启：

```toml
[conversation]
enabled = true
artifact_root = ".pangu/conversations"
save_every_turn = true
```

开启后，agent 在每轮 turn 结束与终局（无论成败）各存一份对话快照到 `Artifact store`，`pangu conversation list|show` 可只读查看。恢复一份快照只是把历史当**模型输入**重新喂回去：快照不携带任何 `Decision` / `Effect` / 已批准记忆，恢复后第一次发起工具调用仍走完整 `Policy → Sandbox → Approval`——第一轮拿到过的审批不会带进第二轮。存储前脱敏、内容 digest 读时校验（磁盘篡改即拒）、空历史与缺 system 轮的快照一律拒绝恢复。设计与非目标见 [`docs/adr/0004-conversation-persistence.md`](docs/adr/0004-conversation-persistence.md)。

`pangu session tree` / `pangu session replay` 是**只读**导航：列出会话节点（roots、children、各节点的 checkpoint），或把某个节点上记录的对话重建出来。两者都不写、不删、不移动节点，`replay` **也不恢复工作区**——那是 `pangu rollback` 的职责，两者不能互相替代。账本是一份可被手工编辑的 JSON 目录，所以遍历对环和缺失 parent 都按**损坏账本**处理：报错或标注，而不是给出一个看起来完整其实残缺的答案。当前已知每次普通运行的树**恰好有一个孤儿**（运行根节点从不落盘），`session tree` 会打 `WARNING`，`session replay` 拒绝执行——详见 [`docs/adr/0004-conversation-persistence.md`](docs/adr/0004-conversation-persistence.md) §7.3。

上下文组装（A6）已接入默认运行路径：每轮发给模型的不是全量 history，而是按预算组装的窗口——**不可协商的强制集**（system 轮、goal、被拒路径、未完成工具调用的配对闭包、最近 8 轮）∪ **请求集**（模型只能请求、不能排除；当前默认运行请求集为空，第二阶段选择器接缝留给 B6）。摘要是确定性抽取而非模型生成；切片绑定会话消息前缀 digest 与逐范围 digest，对不上即报错，绝不静默重生成；切片拼接处显式插入 seam 标记，每次组装发 `ContextAssembled` 事件并带降级统计（full / summary / omitted / seam 数）。降级链 `full → summary → omit-with-reason` 走完仍放不下强制集时按 `BudgetExhausted` 硬终止——不存在“永不终止的运行”。本地留存硬上界（8 MiB / 10,000 条 / 单条 256 KiB）暂未放宽。设计与非目标见 [`docs/adr/0005-context-assembly.md`](docs/adr/0005-context-assembly.md)。

验证命令（F3）默认关闭，需显式配置：

```toml
[boundary]
extra_readonly_commands = ["cargo"]   # 只接受裸程序名；不放宽路径/host 检查

[verify]
command = ["cargo", "test", "-q"]     # 留空 = 不向模型广告 verify 工具
```

配置后，模型可以调用 `verify` 运行这条命令（每次需人工批准），但不能增改任何参数；命令在启动时冻结进 contract，toolkit 广告与 contract 不一致时 Agent 拒绝启动。

Plan/Act 逐步审批（F4）默认关闭，需显式配置 `goal.plan_first = true`：

- 运行从**只读 plan 阶段**开始：风险高于 `read_only` 的动作（写入、命令、网络）在进任何闸门前被拒绝，回灌信息指向 `begin_act`；`read_file`/`search`/`git_diff` 等只读探索不受影响。
- 模型通过 `begin_act` 控制调用进入 act 阶段（发 `PhaseChanged` 事件）；它不执行任何动作，也不是授权——act 阶段的每个变更动作仍逐项走 L1-L4，人工批准一次一个。
- `write_file` 的审批请求带**有界、脱敏的 unified diff**（保留/删除/新增行）；无法内联 diff 时（非 UTF-8、过大、不可读）明确说明原因。Phase 规则冻结进 contract，模型不能更改。

执行后端声明（C5）默认关闭：

```toml
[execution]
profile = "container"                              # local（默认）| container | remote
description = "docker:ubuntu-24.04 sha256:..."     # 可选，审计用，脱敏限长
```

这是**操作者声明，不是 Pangu 验证过的事实**：Pangu 不启动、不管理、不验证容器或远程后端——从进程内部看它们与 local 无法区分。声明冻结进 contract 并记入 `RunStarted`（审计用）；任何 profile 下 L1-L4 链完全相同，`doctor`/`--dry-run` 会打印各 profile 的真实保护范围（例如：local = 仅应用层闸门、无 OS 隔离；container = 容器边界由部署者的容器运行时负责）。声明只改变"审计记录里写什么"，不改变任何闸门行为。

`--dangerously-unattended` 会把 approval mode 设为 `never`、使用 fail-closed 的 `Unattended` handler，并在 `RunStarted` 元数据中记录 `unattended=true`；需要人工或破坏性风险的动作会被拒绝，读-only 动作仍须通过其它闸门。它不是安全模式，只是明确放弃人工确认。

## 目录与依赖方向

```text
第 0 层  pangu-core        消息、事件、错误、JSON/glob、Journal/replay、Artifact、组装器
第 1 层  pangu-boundary    L1 contract、L2 policy、L3 sandbox、L4 approval、预算（依赖 core）
第 2 层  pangu-agent       Provider/ToolExecutor 协议、VerifiedAction、运行循环（依赖 core、boundary）
第 3 层  pangu-provider    OpenAI-compatible 适配（依赖 agent、core）
         pangu-toolkit     内置工具（依赖 agent、boundary、core）
第 4 层  pangu (CLI)       配置加载、Journal、demo、子命令（依赖以上全部）
```

- `pangu-core`：消息、事件、错误、JSON/glob、Journal/replay；不决定策略。
- `pangu-boundary`：L1 contract、L2 policy、L3 sandbox、L4 approval、预算。
- `pangu-agent`：唯一的模型回合编排和 `VerifiedAction` 创建入口。
- `pangu-toolkit`：实现 Agent 的 `ToolExecutor` 协议的内置工具。
- `pangu-provider`：实现 Agent 的 `Provider` 协议。
- `pangu`：配置加载、Journal、demo 和 CLI。

规范细节见 [`docs/BOUNDARY.md`](docs/BOUNDARY.md)，实现说明见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)，未来方向与特性选择见 [`docs/ROADMAP.md`](docs/ROADMAP.md)；全部文档的索引与阅读顺序见 [`docs/README.md`](docs/README.md)。Checkpoint/rollback 的已批准设计见 [`docs/adr/0001-checkpoint-rollback.md`](docs/adr/0001-checkpoint-rollback.md)；阶段二实现、测试矩阵和条件性不变量见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) 与 [`docs/BOUNDARY.md`](docs/BOUNDARY.md)，operator 处理步骤见 [`docs/CHECKPOINT_RECOVERY.md`](docs/CHECKPOINT_RECOVERY.md)。由于默认关闭、operator recovery 限制和正式激活门仍存在，本文不把它描述为默认支持能力。

## 开发与验证

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo run -q -p pangu -- --demo
```

Provider 集成测试使用本地 TCP mock server，不依赖外部网络或 API key；CI 在 Linux 和 Windows 上执行同一组验证命令。

添加工具时实现 `ToolExecutor::specs/assess/execute`：`assess` 只能解析和声明资源，`execute` 必须使用传入的 `VerifiedAction`，并为成功结果提供有界 evidence。不要让 provider 或外部调用者直接执行未验证的模型调用。

ADR-0001 阶段二的验证已随实现落地（checkpoint/rollback 仍为实验性 opt-in）：

- 成功 checkpoint、typed rollback、CAS/幂等、外部 effect、failed-path、stale lock、wall-clock budget 和真实 CLI 子进程均有测试覆盖；
- Journal v1/v2、稳定 receipt、TeeSink receipt 一致性及损坏/超限输入的 fail-closed 行为已验证；
- snapshot/manifest/blob/node/marker、symlink、特殊文件、权限和跨进程锁有独立测试；
- 每个条件性不变量都有独立测试（见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) 不变量测试矩阵），跨平台 replace hand-off 和 operator-only recovery 未被隐藏为自动保证；
- operator 演练与跨平台验收记录见 [`docs/CHECKPOINT_RECOVERY.md`](docs/CHECKPOINT_RECOVERY.md) 第 6、8 节及 [`docs/evidence/`](docs/evidence/)；正式激活前，文档持续区分“阶段二实现已存在”和“默认支持”。

## License

MIT License - see [LICENSE](LICENSE)

**维护者**：pangu-cn

**版本**：v0.1.0
