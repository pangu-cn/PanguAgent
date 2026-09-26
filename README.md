# Pangu Agent 盘古智能体

> 一个在显式边界内自主使用工具的 AI agent。目标 G1-G5：诚实、可审计、不越界、成本有界、可嵌入。

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## 快速开始

仓库可以直接运行：

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
```

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
| `finish` | 提交运行状态 | 控制工具 | `complete` 需要成功证据；不是外部副作用 |

`run_command` 当前只允许 `pwd`, `cat`, `ls`, `head`, `tail`, `grep`, `wc`, `sort`, `uniq`, `diff`, `md5sum`, `sha256sum` 及受限参数。`http_fetch` 当前只实现 GET。

## Provider

当前实现的是 `OpenAiCompatibleProvider`：

- 请求 `POST {base_url}/chat/completions`，使用 OpenAI function-calling wire format。
- 远程端点默认要求 HTTPS；`http://localhost` 可用于本地兼容服务（例如 Ollama 的 OpenAI-compatible endpoint）。
- API key 只从 `model.api_key_env` 指定的环境变量读取，不从 TOML 参数直接读取。
- 响应体、工具参数和工具输出都有上限；provider 错误在边界处脱敏。
- 成本闸门要求同时配置 `model.input_usd_per_mtok` 和 `model.output_usd_per_mtok`；provider 报告的 `cache_read_tokens` 计入输入 token 预算并按输入价计费。缺少价格不会被当作免费运行，而会在下一次 provider 请求前以 `budget_exhausted` 失败。`--demo` 明确使用零价格脚本 provider。
- 没有实现 Anthropic 专用协议；可使用提供 OpenAI-compatible API 的适配端点。

## 配置与 CLI

默认配置编译在 `config/boundary.toml`。`pangu` 还会按以下顺序加载一个用户配置：`--config`、`PANGU_CONFIG`、当前目录 `pangu.toml`、用户目录的 `~/.config/pangu/boundary.toml`；未找到时使用 embedded 配置。相对 roots 会按有效 workspace 解析。

常用参数：

```text
pangu doctor
pangu config [--file PATH]
pangu run [--dry-run] "GOAL"
pangu --demo [--dry-run]
pangu run --workspace PATH --max-turns N --max-cost-usd X "GOAL"
pangu --checkpoint run "GOAL"
pangu rollback --checkpoint-id ID --source-node NODE --rollback-id OP --reason "..."
pangu artifact inspect --root PATH [--json]
pangu run --dangerously-unattended "GOAL"
```

`pangu artifact inspect` 是只读检查器：它不创建、不修复、不删除、不重试任何东西，只把 Artifact store 的可验证状态和事故证据（stale transaction lock、replacement backup、operation 状态、effect/failed-path 账本、commit marker 与 blob hash 一致性）报成带 `unverifiable.*` / `operator.*` 代码的报告，并在报告为 `verified` 以外时返回非零退出码。完整语义见 [`docs/CHECKPOINT_RECOVERY.md`](docs/CHECKPOINT_RECOVERY.md)。

`--dangerously-unattended` 会把 approval mode 设为 `never`、使用 fail-closed 的 `Unattended` handler，并在 `RunStarted` 元数据中记录 `unattended=true`；需要人工或破坏性风险的动作会被拒绝，读-only 动作仍须通过其它闸门。它不是安全模式，只是明确放弃人工确认。

## 目录与依赖方向

```text
pangu-core ← pangu-boundary ← pangu-provider
       ↑              ↑       ↘
       └── pangu-agent ← pangu-toolkit
                    ↓
                  pangu (CLI)
```

- `pangu-core`：消息、事件、错误、JSON/glob、Journal/replay；不决定策略。
- `pangu-boundary`：L1 contract、L2 policy、L3 sandbox、L4 approval、预算。
- `pangu-agent`：唯一的模型回合编排和 `VerifiedAction` 创建入口。
- `pangu-toolkit`：实现 Agent 的 `ToolExecutor` 协议的内置工具。
- `pangu-provider`：实现 Agent 的 `Provider` 协议。
- `pangu`：配置加载、Journal、demo 和 CLI。

规范细节见 [`docs/BOUNDARY.md`](docs/BOUNDARY.md)，实现说明见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)，未来方向与特性选择见 [`docs/ROADMAP.md`](docs/ROADMAP.md)。Checkpoint/rollback 的已批准设计见 [`docs/adr/0001-checkpoint-rollback.md`](docs/adr/0001-checkpoint-rollback.md)；阶段二实现、测试矩阵和条件性不变量见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) 与 [`docs/BOUNDARY.md`](docs/BOUNDARY.md)，operator 处理步骤见 [`docs/CHECKPOINT_RECOVERY.md`](docs/CHECKPOINT_RECOVERY.md)。由于默认关闭、operator recovery 限制和正式激活门仍存在，本文不把它描述为默认支持能力。

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

ADR-0001 阶段二验证要求如下（checkpoint/rollback 仍为实验性 opt-in）：

- 覆盖成功 checkpoint、typed rollback、CAS/幂等、外部 effect、failed-path、stale lock、wall-clock budget 和真实 CLI 子进程；
- 验证 Journal v1/v2、稳定 receipt、TeeSink receipt 一致性及损坏/超限输入的 fail-closed 行为；
- 验证 snapshot/manifest/blob/node/marker、symlink、特殊文件、权限和跨进程锁；
- 每个条件性不变量都要有独立测试，跨平台 replace hand-off 和 operator-only recovery 不能被隐藏为自动保证；
- 在正式激活前，文档必须区分“阶段二实现已存在”和“默认支持”。

## License

MIT License - see [LICENSE](LICENSE)

**维护者**：pangu-cn

**版本**：v0.1.0
