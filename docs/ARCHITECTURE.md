# Pangu Agent 架构文档

本文描述当前 v0.1 实现；规范性不变量以 [`BOUNDARY.md`](BOUNDARY.md) 为准。若文档与代码冲突，应先修正文档或实现，不能默默改变边界。

## 核心目标

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
ToolStarted → ToolExecutor::execute(&VerifiedAction)
        │
        ├─ error ──────────────► ToolFinished(ok=false) + error tool_result
        ▼
ToolFinished(ok=true, evidence) → tool_result → 下一回合
```

`ToolExecutor` 是受信适配器边界：Agent 不把模型文本直接转换成 shell 命令，也不给模型一个可以绕过 `assess` 的执行方法。`assess` 收到的 `&Sandbox` 只能用于解析和验证；真正执行必须使用 `VerifiedAction` 中已经解析的资源和 `cwd`。

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
FinishRequested, RunFinished, Note
```

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

### Provider 与工具适配器

当前只有 `OpenAiCompatibleProvider`。它将统一的 `Message`/`ToolSpec` 转为 OpenAI `/chat/completions` 请求，限制响应体，并要求每个响应提供有效的 `prompt_tokens` 和 `completion_tokens`；可选的 `cache_read_tokens` 也必须有效并计入输入预算。`Toolkit` 实现 `ToolExecutor`，所有工具在 `assess` 阶段声明资源和风险，在 `execute` 阶段只消费 `VerifiedAction`。Provider 集成测试使用本地 TCP mock server 覆盖成功响应、usage/cache token、非 2xx 脱敏、redirect 禁止和响应体上限，不依赖外部网络或 API key。

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

## 已知边界

- 没有 Anthropic 专用 provider；没有删除、支付、发邮件、任意 shell 或多 agent 编排工具。
- DNS 解析和 provider endpoint 仍依赖用户配置；当前网络闸门会 check/recheck DNS，但没有把已验证的解析结果固定到连接所使用的 IP，因此仍存在 DNS rebinding / TOCTOU 限制。这不是抵抗恶意网络对手的隔离方案。
- 墙钟预算在 Agent 的 provider/tool phase 边界检查，内置适配器有各自超时；任意外部 trusted adapter 或同步 OS DNS 解析不会被通用 Agent future 强制抢占，宿主需要提供有界适配器。
- Journal replay 当前提供完整性校验和摘要，不重新执行工具。
- 默认 `pangu run` 需要用户提供 API key 和模型输入/输出价格；`pangu --demo` 使用本地 scripted provider 并显式声明零价格来验证状态机。
