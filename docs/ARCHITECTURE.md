# Pangu Agent 架构文档

本文描述当前 v0.1 实现；规范性不变量以 [`BOUNDARY.md`](BOUNDARY.md) 为准。若文档与代码冲突，应先修正文档或实现，不能默默改变边界。

## 核心目标

> checkpoint/rollback 的阶段二代码目前是**默认关闭的实验性 opt-in**。本节描述其实现结构；在正式激活前，不把它当作 v0.1 的默认产品承诺。

- **G1（诚实）**：没有成功工具证据，模型不能把运行标为 `complete`。
- **G2（可审计）**：每个运行通过 `EventSink` 发出事件；CLI 使用带 SHA-256 链的 JSONL Journal。
- **G3（自主但不越界）**：模型可以连续规划，但副作用只能走中心 capability 入口。
- **G4（成本有界）**：turn、输入 token、输出 token、费用和墙钟五个预算闸门；价格缺失按未知费用处理，而不是按零费用放行。
- **G5（可嵌入）**：核心库通过 trait 注入 provider、tool executor、approval handler 和 event sink，不依赖 CLI 全局状态。

## Workspace 与依赖

```text
pangu-core
    ▲
    │
pangu-boundary
    ▲                         ┌──────────────┐
    └──────────────┬──────────┤ pangu-agent  │──────► pangu-provider
                   │          └──────┬───────┘       pangu-toolkit
                   │                 │
             Goal/Policy/Sandbox  VerifiedAction
```

更精确地说：

- `pangu-core` 只依赖标准库、`serde`/`serde_json` 等基础库，定义消息、事件、错误、glob、Journal 和 replay。
- `pangu-boundary` 依赖 `pangu-core`，实现 L1 `GoalContract`、L2 `Policy`、L3 `Sandbox`、L4 `ApprovalHandler` 与 `Budget`。
- `pangu-agent` 依赖 `pangu-core` 和 `pangu-boundary`，定义 `Provider`、`ToolExecutor`、`VerifiedAction` 和状态机。
- `pangu-provider` 与 `pangu-toolkit` 依赖 agent 的协议类型；具体适配器不反向成为核心库的依赖。
- CLI `pangu` 负责配置、依赖注入、Journal 和 demo。

## 一次工具调用的状态机

```text
provider response
        │
        ▼
ToolCall（不可信 JSON）
        │
        ├─ finish：只接受有限 status，并检查成功证据
        │
        ▼
ToolExecutor::assess（只解析/分类，不执行）
        │  ToolAssessment: risk + paths + hosts + argv
        ▼
Policy::evaluate
        │  deny 优先；allow 多目标必须全匹配；无规则 default deny
        ├─ deny ───────────────► ToolBlocked + error tool_result
        ▼ allow/ask
Sandbox::validate_resources
        │  roots、canonical path、symlink、glob、argv、host、DNS
        ├─ error ──────────────► ToolBlocked + error tool_result
        ▼
ApprovalHandler（L4）
        │  仅明确 AllowOnce/AllowRule 才继续
        ├─ deny/no-answer─────► ToolBlocked + error tool_result
        ▼
构造 VerifiedAction（字段私有，构造函数不对外开放）
        │
        ▼
ToolStarted(v2 receipt) → [external mutation ledger] → ToolExecutor::execute(&VerifiedAction)
        │
        ├─ error ──────────────► ToolFinished(ok=false) + error tool_result
        ▼
ToolFinished(ok=true, sealed v2 receipt) → checkpoint（仅成功动作）
        │
        ├─ checkpoint 失败 ────► CheckpointFailed + fail_run/needs_input
        ▼
CheckpointCreated + session node + COMMITTED marker
```

checkpoint 的内部链是 `Policy::evaluate_internal → SnapshotRequest/Sandbox →（仅 ask 时）Approval → ArtifactStore`；它不递归创建 checkpoint。rollback 不通过模型工具触发，而是由 `Agent::rollback(&RollbackRequest)` 或 operator CLI 调用，并经过 rollback Policy、Sandbox 和 L4。

`ToolExecutor` 是受信适配器边界：Agent 不把模型文本直接转换成 shell 命令，也不给模型一个可以绕过 `assess` 的执行方法。`assess` 收到的 `&Sandbox` 只能用于解析和验证；真正执行必须使用 `VerifiedAction` 中已经解析的资源和 `cwd`。

成功 `ToolFinished` 后的阶段二 checkpoint 链如下：

```text
ToolExecutor::execute(&VerifiedAction)
  → ToolStarted (v2 receipt)
  → external mutation ledger (执行前)
  → ToolFinished(ok=true, sealed receipt)
  → Policy::evaluate_internal
  → SnapshotRequest / Sandbox
  → Approval（仅匹配 ask 时）
  → content-addressed snapshot + session node + COMMITTED
  → CheckpointCreated
```

checkpoint 只接受成功 `VerifiedAction` 对应的 `ToolFinished`；失败、被拒绝、超预算、`finish` 控制调用和非 v2/伪造 receipt 都不能产生 checkpoint。外部 mutation 在 adapter 执行前记账，所以工具错误或进程崩溃不会让 ledger 假定外部动作没有发生。

rollback 的结构化流程是：

```text
RollbackRequested
  → load target/source artifact and bind session/contract/policy
  → validate failed-path reference
  → reject external effect after target
  → Policy → Sandbox → Approval
  → RollbackStarted + durable operation transition binding
  → staged exact restore + CAS + final digest
  → transition session node
  → RollbackApplied / RollbackSkippedAlreadyApplied
```

`ArtifactStore` 在进程内 mutex 和跨进程 `.rollback-operation.lock` 下执行 ledger、快照、恢复和 node 写入。带 session node 的 checkpoint 必须有 `COMMITTED` marker；`load_checkpoint`、manifest、blob、路径、大小和 hash 校验失败均 fail closed。重复 `(checkpoint_id, rollback_id)` 在 Policy/Approval/外部 effect 检查前短路；如果 transition node 丢失，重复请求只按 immutable operation binding 修复 node，不再次写 workspace。

## 回合与终态

`Agent::run`（`run_stream` 是同一入口的便利别名）大致执行：

1. 发出 `RunStarted`，记录模型、workspace、配置来源、boundary digest 和 unattended 标记。
2. 在每次 provider 请求前以及每个 tool call 执行前检查 turn、历史估算 token、费用和墙钟预算；provider 报告的 `cache_read_tokens` 计入输入 token 预算，`price` 缺失会以 cost breach 停止。
3. provider 返回后合并真实 `Usage`，再次检查预算；超限直接发 `BudgetExhausted`。
4. 对每个模型工具调用执行上面的 L2-L4 链。拒绝和工具错误都作为 `Message::Tool { is_error: true }` 回灌模型。
5. `finish(status="complete")` 只有在 `min_successful_tool_calls` 个成功 evidence 后才保持 `Complete`；否则降级为 `Failed`。
6. 发出 `RunFinished` 并返回 `Outcome`。provider 或事件 sink 异常也尝试发终态事件，原始错误仍向上返回。

一个响应中的多个调用按顺序处理；第一个终态调用会终止当前响应剩余调用。未知工具、无法解析的参数和无法分类的适配器动作都走错误回灌，而不是直接执行。

## 事件与 Journal

事件类型包括：

```text
RunStarted, TurnStarted, ModelRequest, ModelResponse,
ToolRequested, PolicyDecision, ApprovalRequested, ApprovalResolved,
ToolStarted, ToolBlocked, ToolFinished, BudgetExhausted,
FinishRequested, RunFinished, Note,
CheckpointCreated, CheckpointFailed,
RollbackRequested, RollbackStarted, RollbackApplied,
RollbackSkippedAlreadyApplied, RollbackFailed, FailedPathRecorded
```

启用 checkpoint 的运行使用 `pangu-journal/v2`；禁用时保留 v1。v2 写入时封存 `schema`、连续 `seq`、`prev_sha`、内容 `sha` 和 `evt_<sha256>` 稳定 ID。`EventSink::emit` 保持兼容，内部 receipt 路径使用 `emit_with_receipt`；TeeSink 比较多个 durable sink 的 receipt，不一致则失败。Journal replay 只校验和索引，不恢复文件、不重放副作用。

每条事件包含 `seq`、`at`、`turn`、可选 tool/call/verdict/risk/rule/invariant/usage/payload。事件字段、payload 和 Journal 写入前会脱敏；消息、字段、payload 和单行 Journal 都有大小上限。

CLI 的 Journal 位于有效 workspace 的 `.pangu/journal-*.jsonl`。记录时：

```text
sha = SHA256(prev_sha || NUL || canonical_json)
```

`canonical_json` 排除事件自身的 `sha` 字段，并递归排序 JSON object key。`pangu_core::replay::read` 会检查序号连续性、前向哈希和内容哈希；损坏、篡改、插入或非末尾删除的 Journal 返回错误，不会静默重置。没有外部封存锚点时，单纯截断最后一个或多个事件无法仅靠链哈希证明。读取 Journal 不会重放工具副作用。

`Journal::create` 只创建不存在的文件；已有文件应使用 `Journal::append_to`，避免误覆盖审计记录。事件 sink 错误不会被转换成成功；写入失败会使运行失败。

## 各层实现

### L1 — `pangu-boundary::GoalContract`

Contract 保存一次 run 的目标文本、canonical workspace/roots、forbidden globs、预算、审批模式、网络 host、环境 allow-list、工具/进程限制、evidence 要求和 Policy digest。`Config::validate` 在构造时检查路径、symlink、glob、TOML、环境键、provider URL 和规则；`GoalContract::validate_against` 再检查 contract 与 Sandbox 的有效字段和 roots 有效顺序完全一致，`Agent::new` 检查实际 Policy digest 与 contract 一致，并拒绝 approval handler mode 不匹配的注入。

### L2 — `pangu-boundary::Policy`

规则是声明式的 `Rule { id, effect, tool, arg, path_glob, host_glob, min_risk, max_risk, reason, invariant }`。

- 所有 deny 规则先于 allow/ask 规则。
- 同一优先级按配置顺序匹配。
- allow 规则含 path/host 条件时，所有目标都必须匹配；ask/deny 条件可命中任一目标，但 deny 仍优先。
- 没有规则匹配返回 `I-Default-Deny`。
- `ReadOnly`/`Reversible` 的 allow 不会被升级为人工批准；destructive 及以上即使被 allow 也会升级为 ask。

### L3 — `pangu-boundary::Sandbox`

Sandbox 将相对路径解析到 workspace，而不是依赖进程当前目录。读路径必须已存在并落在 readable roots；写路径允许新文件，但 parent 必须存在且目标落在 writable roots。路径组件中的 symlink、`..`、NUL、UNC 和越界 canonical path 都拒绝。

- `forbidden_globs` 对绝对和 workspace-relative 路径都检查。
- 网络仅允许 HTTP/HTTPS、显式 host glob、非私网/非 metadata 地址；关闭 HTTP redirect，URL 不允许 credentials、fragment、零端口或敏感 query 参数。审批 preview 会移除 query/fragment，并以 path 的 SHA-256 摘要代替直接展示路径。
- argv 不经 shell，只能使用只读 allow-list；总长度、flag 和路径参数受限。
- 子进程 `stdin` 关闭、环境按 allow-list 清洗、超时 kill、stdout/stderr 有界读取。
- 文件、目录、搜索、HTTP 和命令输出均有大小/结果上限。

这些是应用层资源边界，不是 OS 沙箱、容器或虚拟机；规范明确不承诺抵御蓄意恶意代码。

### L4 — `ApprovalHandler`

`Never`、`DestructiveAndAbove` 和 `Always` 只决定何时请求人工确认，永远不把请求交给模型；`Never` 会拒绝需要人工/破坏性确认的动作，而不是自动放行。`NoAnswer`、超时和无人值守 handler 都 fail closed。`ApprovalRequest` 的参数和 preview 在展示/事件边界处脱敏。

rollback 始终把动作作为 destructive capability 送入 L2/L3/L4；CLI 使用 stdin approval。内部 checkpoint 是例外：L1 显式开关授权固定的非模型 capability，L2 仍执行 deny/匹配 ask/allow，L3 仍校验 SnapshotRequest/Sandbox，只有匹配 `ask` 才请求 L4。外部 mutation 不论 Policy 如何都必须先取得 L4。

### Provider 与工具适配器

当前只有 `OpenAiCompatibleProvider`。它将统一的 `Message`/`ToolSpec` 转为 OpenAI `/chat/completions` 请求，限制响应体，并要求每个响应提供有效的 `prompt_tokens` 和 `completion_tokens`；可选的 `cache_read_tokens` 也必须有效并计入输入预算。`Toolkit` 实现 `ToolExecutor`，所有工具在 `assess` 阶段声明资源和风险，在 `execute` 阶段只消费 `VerifiedAction`。Provider 集成测试使用本地 TCP mock server 覆盖成功响应、usage/cache token、非 2xx 脱敏、redirect 禁止和响应体上限，不依赖外部网络或 API key。

## Checkpoint/rollback 实现细节

### Artifact store

`pangu-core::ArtifactStore` 是 Pangu 自己的内容寻址存储：

- `SnapshotRequest` 只接受现有 canonical roots，拒绝越界、symlink、特殊文件和 excluded/forbidden 路径；默认排除 workspace 内 `.pangu` 和 Artifact root；
- 文件先读入有界内存，manifest/blob 写入临时目录，完成后以 rename 发布；带 session node 的目录只有在 `manifest.json`、embedded node、standalone session node 和 `COMMITTED` marker 全部持久化后才可加载；
- restore 验证目标完整状态，备份额外目录、应用目录权限、删除目标外路径，并在失败时尝试撤销；最终 workspace digest 必须与 artifact snapshot digest 相等；
- `RollbackOperation` 记录 source digest、状态、错误、完成时间和 transition node/event binding；`Failed` 不自动重试，`Applied` 重复请求只返回 `AlreadyApplied`；
- `effects.jsonl`、`failed-paths.jsonl`、session node 和 operation 文件均有大小、schema、路径和引用校验；外部 effect 必须在同一 run 且 checkpoint 之后才阻止 rollback；
- 进程内锁、跨进程 `create_new` transaction marker、symlink 检查和临时路径清理均 fail closed。发现 stale `.rollback-operation.lock` 时 runtime 不猜测恢复，operator 必须人工检查。

### Effect 与工具声明

`EffectDescriptor` 与 `Risk` 独立：workspace mutation 必须有 write path，process-read 必须有 argv，external-read 必须有 host，external-mutation 至少声明 host/argv/write path 且必须 `irreversible`/destructive；session effect 不能伪装成 filesystem/external effect。声明不一致在 Policy 前失败。

### 已知恢复限制

- Windows 覆盖写入需要 destination backup + rename hand-off；中断时 `.replace-backup-*` 是 operator 证据，不能自动当作普通垃圾清理；
- crash 可能在 workspace 已变更、operation/node 尚未完成之间留下 stale lock；不提供自动猜测或自动补偿；
- 不持有 Artifact lock 的外部 workspace writer 可能改变文件，最终 digest/CAS 会拒绝不确定结果，但应用层锁不是 OS/VM 隔离；
- replay 永不自动执行 restore，Git backend 当前明确未实现。

## 不变量测试矩阵

| ID | 测试/代码位置 | 断言 |
|----|---------------|------|
| I-Default-Deny | `pangu-boundary/src/policy.rs`, `tests/invariants.rs` | 无规则或 traversal 直接 deny |
| I-No-Silent-Bypass | `Policy::evaluate` | deny 优先，审批不能改写 deny |
| I-Model-Cannot-Self-Approve | `Policy::evaluate`, `ApprovalMode` | destructive 及以上必须进入 ask/拒绝 |
| I-Budget-Terminates | `Budget::check`, agent tests | 预算超限不执行工具 |
| I-No-Effect-Before-Verdict | agent state-machine tests, Toolkit integration tests | deny/approval/sandbox 错误时 executor 计数为零 |
| I-Boundary-Binding | `Agent::new`, contract tests | Sandbox/Policy 与 GoalContract digest 不一致时拒绝启动 |
| I-Append-Only-Journal | `pangu-core/src/journal.rs`, replay tests, `tests/invariants.rs` | 链完整，篡改、插入和非末尾删除被发现；末尾截断需外部锚点 |
| I-Redact-At-Boundary | event tests, root invariant test | secret 不进入事件字段或 payload |
| I-Honest-Terminal | agent tests, `tests/invariants.rs` | 无成功 evidence 的 complete 变为 failed |
| I-Real-Toolkit-Execution | `crates/pangu-toolkit/tests/toolkit_integration.rs` | read/list/search/write 经过真实 Agent capability 链；越界、forbidden glob、symlink 和输出超限无副作用 |
| I-Provider-Fail-Closed | `crates/pangu-provider/tests/openai_compatible.rs` | usage、非 2xx 脱敏、redirect 和响应体上限均 fail closed |
| I-Child-Env-Cleaned | sandbox implementation | child env 是 allow-list 子集 |
| I-Checkpoint-After-Verified-Action | `crates/pangu-agent/src/test_support.rs` | 只有成功 v2 `ToolFinished` 创建 checkpoint |
| I-Checkpoint-Atomic | `crates/pangu-core/src/artifact.rs` | manifest/blob/node/marker 缺失或损坏时拒绝加载 |
| I-Rollback-Trigger | `crates/pangu-agent/src/test_support.rs` | typed request、source/target/session/digest 绑定 |
| I-Irreversible-Requires-Human | agent/core tests | effect ledger 先于执行，未批准/外部 mutation 后拒绝 |
| I-Rollback-Scope | artifact/agent tests | rollback 不执行外部资源，只改 workspace/session |
| I-Rollback-Idempotent | artifact/agent/invariant tests | operation CAS、重复请求、transition node 修复和 Failed operation 不自动重试 |
| I-Failed-Path-Not-Repeated | agent/core tests | 同 run 等价失败执行前阻断，跨 run/错误 digest 拒绝 |
| I-No-Implicit-Git-Commit | `tests/invariants.rs`, config tests | Git backend 显式失败，默认不触发 Git |

## 已知边界

- 没有 Anthropic 专用 provider；没有删除、支付、发邮件、任意 shell 或多 agent 编排工具。
- DNS 解析和 provider endpoint 仍依赖用户配置；当前网络闸门会 check/recheck DNS，但没有把已验证的解析结果固定到连接所使用的 IP，因此仍存在 DNS rebinding / TOCTOU 限制。这不是抵抗恶意网络对手的隔离方案。
- 墙钟预算在 Agent 的 provider/tool phase 边界检查，内置适配器有各自超时；任意外部 trusted adapter 或同步 OS DNS 解析不会被通用 Agent future 强制抢占，宿主需要提供有界适配器。
- Journal replay 当前提供完整性校验和摘要，不重新执行工具。
- checkpoint/rollback 阶段二实现默认关闭、仅实验性 opt-in；Windows replace hand-off、stale lock 和无锁并发 writer 的限制见“已知恢复限制”，不构成 OS 级隔离或正式支持声明。operator 处理步骤和证据清单见 [`CHECKPOINT_RECOVERY.md`](CHECKPOINT_RECOVERY.md)。
- 默认 `pangu run` 需要用户提供 API key 和模型输入/输出价格；`pangu --demo` 使用本地 scripted provider 并显式声明零价格来验证状态机。
