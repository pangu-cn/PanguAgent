# Pangu Agent — 边界与目标宪章 (Boundary & Mission Charter)

> 版本 v1 · 状态：生效中 · 适用对象：`pangu` CLI、`pangu-agent` 库以及调用本仓库代码的运行实例。
>
> 本文件是规范文本。代码、测试和本文档必须一起修改；实现与本文档冲突时，不能把未声明的行为当作能力。

## 1. 它是什么

Pangu Agent 是一个在用户机器上、在显式声明的有效边界内自主使用工具的 AI agent。模型可以选择下一步，但模型输出不是授权，也不能直接调用外部副作用。

一次运行的有效链路固定为：

```text
GoalContract (L1)
      → Policy (L2)
      → Sandbox (L3)
      → Approval (L4)
      → VerifiedAction
      → ToolExecutor
```

任一层拒绝都必须产生可审计的 `ToolBlocked`（执行器已开始后失败则产生 `ToolFinished(ok=false)`），并把错误作为 `tool` 消息回灌模型；不得静默重试或绕过。

## 2. 目标（Goals）

| # | 目标 | 可验收要求 |
|---|------|-----------|
| G1 | **诚实** | 运行以显式 `GoalStatus` 结束；`Complete` 必须有至少 `min_successful_tool_calls` 个成功工具 evidence；`Failed`/`BudgetExhausted` 不得被改写成完成 |
| G2 | **可审计** | 每个运行发出结构化事件；CLI Journal 只追加、限制大小并可校验序号/哈希；重放不产生副作用 |
| G3 | **自主但不越界** | 在规则和资源边界内可连续行动；越界被确定性拒绝并回灌 |
| G4 | **成本有界** | `max_turns`、`max_input_tokens`、`max_output_tokens`、`max_cost_usd`、`max_wall_clock_secs` 五个闸门任一达到上限即停止后续动作；cache-read token 计入输入预算，价格缺失按未知费用 fail closed |
| G5 | **可嵌入** | Agent 通过 trait 注入 provider、tool executor、approval handler 和 event sink；不依赖 CLI 或隐藏的全局运行状态 |

非目标见第 5 节。

## 3. 边界（Boundaries）

### L1 — GoalContract（一次 run 的不可变意图）

Agent 启动时从已校验的 `Config` 构造并冻结 `GoalContract`：目标文本、canonical workspace、readable/writable roots、forbidden globs、预算、审批模式、网络/环境 allow-list、工具和子进程限制、evidence 要求，以及与 Policy 规则集绑定的 digest。模型不能修改这些字段；本版本没有 `update_plan` 或动态放宽边界的工具。

Contract 与 Sandbox 的有效字段及 readable/writable roots 的有效顺序必须在构造时一致。配置中的相对 roots 以有效 workspace 为基准；路径、symlink、glob、网络、argv 和环境配置在构造时验证。`Config::boundary_digest()` 描述有效配置边界；`GoalContract::digest()` 描述一次运行的 contract，并额外绑定 policy digest 与价格。Agent 启动时用后者校验传入的 Policy/Sandbox，并拒绝 approval handler mode 不匹配的注入。

### L2 — Policy（声明式规则）

规则是 `Rule { id, effect, tool, arg, path_glob, host_glob, min_risk, max_risk, reason, invariant }`。匹配规则如下：

1. 所有 `deny` 规则先于 `allow`/`ask` 规则；deny 不可被覆盖。
2. 非 deny 规则按配置顺序 first-match。
3. 没有匹配规则就是 `deny`（`I-Default-Deny`）。
4. 带 path/host 条件的 allow 规则必须让该动作的**每一个**目标都匹配；ask/deny 条件命中任一目标即可，但 deny 仍优先。
5. 工具风险由工具实现声明，模型不能通过参数降低风险。未知工具或无法分类的动作不能直接执行。
6. destructive 及以上动作即使用 allow 规则也升级为人工 ask（`I-Model-Cannot-Self-Approve`）。

### L3 — Sandbox（资源硬限制）

- **路径**：相对路径以 workspace 为基准；读路径必须存在并落在 `readable_roots`（workspace 必须包含在其中），写路径必须落在 workspace 内的 `writable_roots`。canonical path、symlink component、`..`、NUL、UNC 和越界路径均拒绝。禁止 glob 对绝对和 relative 路径都生效。
- **进程**：不经过 shell；argv 总长度、可执行程序、flag 和路径参数受限；child stdin 关闭、环境按 allow-list 清洗、超时 kill、stdout/stderr 有界读取。当前工具只提供只读命令 allow-list。
- **网络**：仅 HTTP/HTTPS；主机必须在显式 allow-list；默认拒绝 localhost、私网、链路本地、组播和 `169.254.169.254` metadata；禁止 URL credentials、fragment、零端口、敏感 query 参数和重定向。审批 preview 移除 query/fragment，并以 path 的 SHA-256 摘要代替直接展示路径。
- **凭据**：含 `KEY`、`TOKEN`、`SECRET`、`PASSWORD`、`PASSWD`、`AUTH` 或 `CREDENTIAL` 的环境键不能进入 child env；事件字段、payload、错误和 provider 错误在边界处脱敏。
- **资源**：每 action 的 path 数、写入字节、工具输出、搜索结果、argv、子进程输出和墙钟都有上限；provider 的 cache-read token 计入输入预算，cache-read 费用按输入价计算。Agent 在 provider/tool phase 边界以及每个 tool call 前检查预算和墙钟；内置 provider、approval handler 和 toolkit 适配器各自实施超时。任意外部注入的 trusted adapter 以及同步 OS DNS 解析不会被 Agent 强制抢占，宿主必须为它们提供可中断的超时适配器。

这些是应用层限制，不是 OS 强隔离；规范不承诺抵御蓄意恶意代码或具有内核权限的对手。网络检查会重新解析 DNS，但尚未把解析结果固定到实际连接 IP，不能声称消除了 DNS rebinding / TOCTOU 风险。

### L4 — Approval（人工闸门）

支持 `Never`、`DestructiveAndAbove`（默认）和 `Always`。`Never` 不等于自动批准：需要人工或破坏性风险的动作会被拒绝；只有 L4 handler 返回明确的允许才可继续。超时、`NoAnswer`、无输入和无人值守 handler 都是拒绝。模型永远不是批准来源。

当前实现不把一次批准永久写入全局状态；`AllowOnce` 只允许当前调用，`AllowRule` 也只对当前已验证调用生效（rule id 仍会进入审计事件）。审批 target、reason、preview 和参数键值在展示前脱敏、限长并清理控制字符。这比永久记忆更保守；未来若增加记忆，必须绑定完整动作指纹并保留 deny 优先。

### 边界之外

Pangu 防的是模型幻觉、注入诱导和粗心，不是完整的恶意代码隔离。不提供通用 shell、任意删除、支付、发邮件、凭据读取或默认放行便利模式。唯一明确的人工降级开关是 CLI 的 `--dangerously-unattended`：它要求 approval mode 为 `Never`，使用 fail-closed handler，并在 `RunStarted` 写入 `unattended=true`。

## 4. 不变量（Invariants）

1. **I-Default-Deny**：未显式允许且通过资源验证的动作不允许。
2. **I-No-Silent-Bypass**：deny 规则不能被 allow、人工批准或模型参数覆盖。
3. **I-Model-Cannot-Self-Approve**：批准只能来自 L4 外部 handler 或运行前已验证的策略；模型输出永远不是批准。
4. **I-Budget-Terminates**：预算达到任一上限后，不再发 provider 请求或执行工具，并产生终态事件。
5. **I-No-Effect-Before-Verdict**：在 policy、sandbox、approval 全部通过前，executor 不得收到 `VerifiedAction`；拒绝事件不能伪装成执行完成。
6. **I-Append-Only-Journal**：Journal 不覆盖已有文件；事件序号和前向哈希可检测修改、插入和非末尾删除。没有外部封存锚点时，单纯截断末尾事件不能仅靠哈希链证明。
7. **I-Boundary-Binding**：Agent 启动时拒绝与 GoalContract/Sandbox/Policy digest 不一致的配置对象。
8. **I-Redact-At-Boundary**：secret 在进入事件、错误展示和 provider 日志前被替换或限长。
9. **I-Honest-Terminal**：没有成功工具 evidence 的 `complete` 自动降级为 `failed`。
10. **I-Child-Env-Cleaned**：传给子进程的环境变量集合必须是有效 `env_allow` 的子集，且敏感键不能出现。
11. **I-Effect-Bounded**：所有 provider 响应、工具输出、错误、事件 payload 和 Journal 单行都有大小上限。

## 5. 非目标

- 不做通用聊天、角色扮演或“什么都问一句”的助手壳。
- 不做多 agent DAG、工作流 SaaS 或模型训练/微调平台。
- 不做 OS 级 seccomp、Landlock、容器或 VM 隔离。
- 不承诺“永远不被绕过”，也不把 Pangu 当作运行不受信任代码的完整安全边界。
- 不做遥测；除用户配置的 provider endpoint 和显式允许的 HTTP 工具外，不主动出站。
- 不实现 Anthropic 专用 provider；需要其他模型时使用 OpenAI-compatible endpoint。

## 6. 决策权归属

| 决策 | 归属 |
|------|------|
| 边界放宽/收紧 | 人，通过 `boundary.toml`/配置文件和版本控制 |
| 目标与下一步规划 | 模型，在有效边界内 |
| 某个动作能否通过 L2 | Policy，确定性裁决 |
| 路径、host、argv、环境是否有效 | Sandbox，确定性验证 |
| 是否获得一次性人工同意 | L4 外部 handler |
| 运行是否完成 | 模型提名，evidence 规则最终裁定 |

## 7. 演进规则

改动本宪章必须同时提交：

1. 对应的强制代码；
2. 能证明不变量的测试；
3. 事件/配置格式的兼容性说明；
4. 对历史动作可能被放宽的明确风险评估。

只改文档而不改代码，或只改代码而不更新本文件，都视为边界漂移。

当前 `ADR-0001` 仍待批准；第 4 节继续保持现有 11 条不变量不变。实现不得引用或依赖 ADR-0001 中尚未激活的拟新增不变量。
