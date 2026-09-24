# ADR-0001：Pangu Artifact 检查点与受限回退（提案）

> **状态：提案 / 待批准 / 待实现**
> **日期：2026-03-31**
> **范围：** `pangu-core`、`pangu-boundary`、`pangu-agent`、Artifact/session store、Journal、配置和文档
> **规范优先级：** 本文是设计提案，不是当前行为承诺。`docs/BOUNDARY.md` 仍是唯一生效的边界规范；在代码、不变量测试和兼容性说明完成前，本文中的新规则不能被实现为默认行为。

## 1. 背景

当前 Pangu 的副作用链固定为：

```text
assess → Policy (L2) → Sandbox (L3) → Approval (L4)
       → VerifiedAction → ToolExecutor
```

当前实现已经具备：

- `GoalContract`、`Policy`、`Sandbox`、`ApprovalHandler` 和预算边界；
- 私有构造的 `VerifiedAction`；
- append-only JSONL Journal 和结构化事件；
- 工具成功 evidence、失败回灌和终态诚实性；
- 工作区内可逆写入与有界只读工具。

但当前还没有：

- 持久化的会话树或会话节点；
- 工作区快照 Artifact；
- checkpoint 与事件的稳定引用；
- 受限的文件系统/会话回退；
- failed-path ledger；
- 外部副作用的独立 effect/reversibility 声明。

本 ADR 规定这些能力的**提案边界**，不把 Git commit 当作 checkpoint 的必要条件，也不把应用层文件恢复描述为 OS 级隔离。

## 2. 决策摘要

1. checkpoint 是 Pangu 自己的、版本化、不可变的 Artifact，不是 Git commit。
2. checkpoint 只在一次成功的 `VerifiedAction` 和对应的成功 `ToolFinished` 事件之后创建。
3. checkpoint 至少绑定：工作区快照、事件指针、会话节点 ID、父 checkpoint 和有效边界 digest。
4. rollback 只恢复工作区文件和会话状态，不执行外部补偿、不发送网络请求、不运行子进程、不调用连接器。
5. 外部 mutation 必须在执行前由工具实现声明为 `irreversible`，并取得 L4 明确人工允许。
6. rollback 由 typed `RollbackRequested` 触发，不能由模型的裸路径或自然语言直接执行。
7. rollback 采用稳定的 operation ID；重复请求必须幂等，不得再次产生状态变更。
8. 失败动作形成脱敏 failed-path 指纹；回退后的重新规划不得重复等价失败动作。
9. 默认 backend 是 Pangu Artifact store；Git 仅是显式可选 backend，默认不得创建 commit、branch、tag 或修改 index。
10. 在本 ADR 获得显式批准、且对应代码与测试合入前，本提案不修改当前生效的 `BOUNDARY.md` 不变量，也不改变任何运行时行为。

### 2.1 批准前硬门槛

在本 ADR 被**显式批准**，且对应代码与测试合入之前，实现者不得：

- 修改 `docs/BOUNDARY.md` 第 4 节的不变量编号或语义；
- 在 `pangu-agent` 中新增 checkpoint/rollback 状态机分支；
- 扩展 `ToolAssessment` 的公开字段以承载 `EffectDescriptor`；
- 在 Journal 中写入 v2 事件；
- 修改 `[checkpoint]` 配置的默认值或让 CLI 暴露相关开关；
- 在 README 或 ROADMAP 中把 F7 描述为“已支持”。

违反以上任一条，视为边界漂移，应先回退相关改动，再重新进行 ADR 评审。显式批准必须留下可审计的批准记录（日期、批准者/评审记录和所批准版本）；仅有讨论、路线图勾选或代码草稿不构成批准。

### 2.2 生效前禁止事项

在 ADR-0001 获得显式批准前，实现者不得：

- 修改 `docs/BOUNDARY.md` 第 4 节；
- 新增 checkpoint/rollback 状态机；
- 扩展 `ToolAssessment` 的公开字段；
- 写入 Journal v2 事件；
- 暴露 CLI 开关；
- 在 `README.md` 或 `docs/ROADMAP.md` 中声称 checkpoint/rollback 已支持。

这些禁止事项与 2.1 的批准前硬门槛同样适用；路线图勾选、讨论或代码草稿不构成批准。

## 3. 目标与非目标

### 3.1 目标

- 让长任务可以在不重复已提交外部副作用的前提下恢复本地工作状态；
- 让模型和用户可以定位“哪个事件、哪个会话节点、哪个文件快照”形成了当前状态；
- 让恢复操作具备确定的触发条件、原子性、幂等性和审计记录；
- 让失败路径成为可执行约束，而不只是给模型看的自然语言建议；
- 保持所有新增状态操作仍经过 L1–L4 和私有 `VerifiedAction` 构造入口。

### 3.2 非目标

- 不回滚已经发生的外部副作用；
- 不通过 Git reset、revert、force checkout 或远程 Git 操作实现回退；
- 不提供通用系统备份、卷快照、数据库时间点恢复或 OS 级隔离；
- 不允许模型自行扩大 roots、网络、凭据、预算或审批权限；
- 不把 checkpoint 失败伪装成动作失败前的安全回滚；
- 不让 Journal replay 自动执行文件恢复或其它副作用；
- 不在本提案中承诺多 Agent DAG、远程 Runner 或办公连接器实现。

## 4. 术语和数据模型

### 4.1 EffectDescriptor

现有 `Risk` 继续表示 Policy 和审批使用的风险等级；新增由工具实现控制的 effect 描述：

```text
EffectScope:
  workspace
  session
  process_read
  external_read
  external_mutation

Reversibility:
  no_effect
  reversible
  irreversible
```

约束：

- `external_mutation` 在 v1 中只能与 `irreversible` 配对，必须在执行前标记；
- 未知或缺失的 effect 描述对外部 mutation fail closed；
- 模型不能通过参数降低 `EffectScope` 或 `Reversibility`；
- 当前内置工具的声明必须与实际行为一致。

当前内置工具的初始声明建议：

| 工具 | EffectScope | Reversibility | 说明 |
|---|---|---|---|
| `read_file` / `list_dir` / `search` | workspace | no_effect | 读取行为 |
| `write_file` | workspace | reversible | 仅限已验证 writable root |
| `http_fetch` | external_read | no_effect | 仍受 host、网络和审批限制 |
| `run_command` | process_read | no_effect | 继续只允许现有 argv allow-list |

未来任何会产生外部 mutation 的工具都必须单独声明 effect，不能借用 `Risk::Reversible` 规避人工确认。

Risk 与 EffectDescriptor 必须一致：`external_mutation` 必须配 `irreversible`，且 `Risk` 不得低于 `destructive`；任一不一致均 fail closed，不进入 Policy。若 `Reversibility=irreversible`，Risk 也不得低于 `destructive`。

### 4.2 CheckpointArtifact

建议的逻辑字段：

```text
schema_version
checkpoint_id
parent_checkpoint_id
run_id
session_id
session_node_id
event_ref
workspace
contract_digest
policy_digest
snapshot_digest
file_entries[]
failed_path_ledger_ref
external_effect_summary[]
created_at
```

`file_entries` 至少记录：规范化路径、文件类型、大小、必要的权限位、内容 hash 和 Artifact blob 引用。物理实现可按内容 hash 去重，但恢复时必须能重建完整逻辑工作区状态。

快照必须：

- 只覆盖 L3 允许的 workspace roots；
- 排除 checkpoint Artifact 自身、临时目录、禁止 glob 和外部路径；
- 不跟随 symlink，不跨越 canonical roots；
- 受文件数、总字节数、单文件大小、路径数和恢复时间限制；
- 使用临时目录、manifest 校验和原子 rename；
- 对缺失、损坏或版本不支持的 Artifact fail closed。

### 4.3 SessionNode

会话节点是会话状态的不可变版本：

```text
session_node_id
parent_session_node_id
event_ref
checkpoint_id
history_digest / bounded_state_ref
failed_path_ledger_ref
applied_rollback_ids[]
```

模型可见历史和工具输出必须先脱敏、限长。原始上下文若需要保存，必须与普通 Journal 分离，并受访问控制和保留期限约束。

### 4.4 FailedPathRecord

失败路径不保存原始秘密或完整命令。建议字段：

```text
failure_id
failure_class
tool
canonical_args_digest
resource_digest
contract_digest
policy_digest
attempt_count
first_seen_event_ref
last_seen_event_ref
```

失败类别至少区分：

- `invalid_tool_call`；
- `policy_denied`；
- `sandbox_denied`；
- `approval_denied`；
- `tool_failed`；
- `irreversible_external_blocked`。

第一版的等价判断采用规范化工具、资源和失败类别；不把自然语言计划当成可靠的路径身份。若未来需要计划分支去重，必须额外定义稳定的 `PlanNodeId`。

FailedPathRecord 的清除规则如下：

- 新 run 不继承前一 run 的 failed-path 记录；
- 同一 run 内，只有新的 `GoalContract` 或明确的 L4 clear 才能清除；
- clear 本身是内部 maintenance `VerifiedAction`，必须经过既有 L1–L4 链；
- 被清除记录标记为 `superseded`，不得删除或改写原始失败证据。

## 5. 提议的新增不变量（尚未激活）

本节的 8 条拟新增不变量在 ADR 激活后，必须作为 `BOUNDARY.md` 第 4 节第 12–19 条插入；现有第 1–11 条的编号和语义保持不变。在激活前，不得将这些拟新增不变量写入 `BOUNDARY.md` 正文。

以下规则将在代码和测试完成后进入 `BOUNDARY.md`。在本次文档提案中，它们不是当前已实现保证。

### `I-Checkpoint-After-Verified-Action`

只有成功完成的 `VerifiedAction` 才能产生 checkpoint。blocked、失败、无效调用、未完成动作和 `finish` 控制调用不能产生可恢复 checkpoint。

### `I-Checkpoint-Atomic`

快照、manifest、事件指针和会话节点必须作为一个可验证的逻辑提交。任一组成部分缺失、损坏或未持久化时，Artifact 只能标记为 incomplete，不能被回退逻辑信任。

### `I-Rollback-Trigger`

rollback 只能由包含目标 checkpoint、来源 session node、理由和失败路径/用户请求引用的 typed `RollbackRequested` 触发。模型不能只凭自然语言或未经验证的路径参数触发恢复。第一版不默认在失败后自动回退。

### `I-Irreversible-Requires-Human`

外部 mutation 必须在执行前声明为 `irreversible`，并得到 L4 外部 handler 的明确人工允许。Policy allow、模型参数、默认模式和历史批准不能降级该要求。

### `I-Rollback-Scope`

rollback 只能修改工作区和会话状态。它不能执行网络补偿、外部 API、子进程、连接器动作或隐式 Git 操作。默认情况下，若 checkpoint 之后发生不可逆外部 mutation，则拒绝整次 rollback。

### `I-Rollback-Idempotent`

同一 `(checkpoint_id, rollback_id)` 的重复请求必须返回同一确定结果。已完成的恢复不能再次写文件、再次生成副作用或生成第二个成功终态。

### `I-Failed-Path-Not-Repeated`

失败路径必须被记录并在后续执行前检查。回退后的重新规划不得再次提交等价失败动作；重复请求必须被确定性阻断并留下审计记录。清除 failed-path 必须有显式的新 GoalContract/PlanNode 和审计理由。

### `I-No-Implicit-Git-Commit`

checkpoint 默认是 Pangu Artifact。不得隐式创建 Git commit、branch、tag、stash、index 修改或远程操作。Git backend 只有在用户显式选择、策略允许并完成审批时才能执行独立动作。

## 6. L1–L4 映射

| 层 | 提案职责 | 必须保持的现有边界 |
|---|---|---|
| L1 `GoalContract` | 冻结 checkpoint 开关、Artifact 根、快照限制、失败策略、rollback 模式和所有有效 digest | 模型不能动态放宽 roots、预算、审批或恢复范围 |
| L2 `Policy` | 评估内部 checkpoint/rollback capability；拒绝模型直接请求未声明的外部 mutation 或任意恢复 | deny 优先、default deny、规则不能被模型或 rollback 覆盖 |
| L3 `Sandbox` | 校验快照/恢复路径、canonical roots、symlink、禁止 glob、文件数/字节数、临时目录和原子恢复资源 | 这是应用层资源验证，不是 OS/VM/容器隔离 |
| L4 `Approval` | 对不可逆外部 mutation 和 rollback 的明确人工确认；`Never` 下拒绝而不是自动允许 | 模型不是批准来源；NoAnswer/超时 fail closed |
| Agent | 维护成功动作、session node、checkpoint 和 rollback 状态机；只通过私有 `VerifiedAction` 进入 Executor | 不直接从 Agent/CLI 调用文件系统或外部补偿 |
| Artifact store | 保存不可变 manifest/blob、执行受控恢复、维护 operation ledger | 不自行决定 Policy、Approval 或预算 |

### 6.1 checkpoint 与预算交互

checkpoint 和 rollback 属于内部 maintenance action，不产生模型 token 用量，因此不计 token 预算；其实际执行时间计入 `max_wall_clock_secs`。rollback 不重置已经消耗的 turn、输入/输出 token、费用或墙钟用量；资源上限失败按 `failure_policy` 处理，不能以回退、重试或新 session 名义绕过预算。

## 7. 执行流程

### 7.1 成功动作后的 checkpoint

```text
ToolExecutor::execute(&VerifiedAction)
  → ToolFinished(ok=true, event_id)
  → internal checkpoint capability
       assess → Policy → Sandbox → Approval → VerifiedAction
  → snapshot + session node commit
  → CheckpointCreated(event_ref, checkpoint_id, session_node_id)
```

规则：

- `ToolFinished` 的稳定事件 ID 是 checkpoint 的来源指针；
- checkpoint 事件自身不能替代成功动作的 evidence；
- checkpoint 失败时不能静默声称“已检查点”；
- 在 required 模式下，checkpoint 失败会使 run 进入明确失败/需输入状态；
- 已经发生的外部动作不能因 checkpoint 失败而被假定撤销；
- checkpoint/rollback 自身属于内部 maintenance action，不再递归触发新的 checkpoint；其状态变化仍要记录事件。

### 7.2 rollback

```text
RollbackRequested
  → validate checkpoint / boundary / session / failed path
  → reject if forbidden external effect occurred
  → Policy → Sandbox → Approval
  → internal rollback VerifiedAction
  → staged restore + compare-and-swap
  → atomic commit
  → RollbackApplied(rollback_id, checkpoint_id, session_node_id)
```

恢复前必须检查：

- checkpoint schema、hash、contract digest、policy digest 和 workspace 身份；
- 当前状态是否仍与 rollback 请求的 compare-and-swap 前置状态一致；
- 是否存在 checkpoint 之后的不可逆外部 effect；
- rollback ID 是否已经完成或正在执行；
- 所有目标路径是否仍在 L3 允许范围内。

恢复过程中不得调用 Git、网络、子进程或连接器。Journal、manifest 和 operation ledger 的审计写入是允许的 bookkeeping，不属于外部或业务副作用，但必须本身有界、原子且可审计。若实现选择 Git backend，Git 动作必须是独立、显式、可审批的 VerifiedAction，不能成为 rollback 的隐藏步骤。

若 rollback 在任一阶段失败，必须回到本次 `RollbackRequested` 前的逻辑状态，并按可恢复性进入 `Failed` 或 `NeedsInput` 终态；禁止对同一失败自动发起第二次 rollback。失败事件必须记录失败阶段、脱敏原因和可审计的失败上下文，不得把部分恢复伪装成成功。

### 7.3 重新规划

rollback 成功后创建新的 session node：

- parent 指向 rollback 前的节点或明确的 rollback transition node；
- 保留 failed-path ledger；
- 把新节点和 checkpoint 事件写入结构化事件流；
- 向模型只提供脱敏的失败类别、路径摘要和不可重复约束；
- Runtime 在执行前再次检查 failed-path，不能只依赖 prompt 遵守。

## 8. 事件契约提案

当前 `pangu-journal/v1` 事件枚举不包含 checkpoint/rollback 事件。建议启用该能力时引入 `pangu-journal/v2`，保留 v1 读取能力，不重写旧 Journal。

### 8.1 新事件

建议新增：

- `CheckpointCreated`；
- `CheckpointFailed`；
- `RollbackRequested`；
- `RollbackStarted`；
- `RollbackApplied`；
- `RollbackSkippedAlreadyApplied`；
- `RollbackFailed`；
- `FailedPathRecorded`。

### 8.2 现有事件扩展

`ToolFinished` 可增加可选字段：

```text
effect_scope
reversibility
action_digest
external_mutation
```

`RunStarted` 或 `JournalMeta` 增加 schema/version 标识。旧字段保持默认兼容；新字段必须脱敏并限长。

### 8.3 事件引用

优先增加稳定的 `event_id`，而不是依赖某个 sink 的内存位置。`event_ref` 至少包含：

```text
event_id
run_id
可选 journal_id / seq / sha
```

如果未来要求所有 sink 返回 Journal 的 sealed receipt，应以独立、向后兼容的 API 扩展 `EventSink`，不能破坏现有嵌入方的 `emit` 调用。

### 8.4 Replay 规则

Journal replay 只做：

- schema/序号/哈希验证；
- checkpoint、session node 和 failed-path 的关联展示；
- 恢复前生成计划所需的只读索引。

replay 不自动恢复文件、不执行 Git、不调用外部补偿，也不把 `RollbackApplied` 重放成第二次副作用。

## 9. 配置提案

建议新增可选配置，默认关闭：

```toml
[checkpoint]
enabled = false
backend = "artifact"
artifact_root = ".pangu/checkpoints"
max_snapshot_bytes = 67108864
max_snapshot_files = 10000
max_snapshot_file_bytes = 4194304
failure_policy = "fail_run"
rollback_requires_approval = true
```

约束：

- 老配置没有 `[checkpoint]` 时行为保持不变；
- `artifact_root` 必须是显式 writable root 内的 canonical 路径；
- Artifact 自身目录不进入工作区快照；
- 所有大小、文件数和路径限制进入有效 `GoalContract` digest；
- `backend = "git"` 只能是显式选择，不能由默认值触发 commit；
- 不允许通过模型参数改变 checkpoint 根目录、限制或 backend；
- 启用 checkpoint 后，旧的未绑定 contract 不得直接用于新 run。

## 10. 兼容性和迁移

### 配置

- `[checkpoint]` 采用 `serde(default)`，旧 TOML 可加载；
- 禁用时不应无意义地改变旧 boundary digest；启用时生成新的有效 contract digest；
- contract、policy、Artifact manifest 和 session state 都带 schema version；
- 旧 contract 不自动继承新 rollback 权限。

### Journal

- v1 Journal 保持只读兼容；
- v2 新事件不能被旧程序静默解释为普通 `Note`；
- 读取器应明确报告不支持的 schema，而不是跳过未知事件；
- 不对旧 Journal 追加新字段，不改变旧 hash。

### 公共 API

- `VerifiedAction` 仍保持字段私有和私有构造入口；
- `ToolAssessment` 的 effect metadata 应采用新增字段/访问器，未知旧 adapter 按 fail closed 处理；
- `Outcome` 若增加 checkpoint/session 信息，使用新增字段和默认值；
- `EventSink::emit` 保持兼容，event receipt 作为后续可选扩展。

## 11. 风险和缓解

| 风险 | 缓解 |
|---|---|
| 快照不完整导致错误恢复 | manifest/hash、完整逻辑快照、大小限制、损坏 fail closed |
| Artifact 存储耗尽或递归包含自身 | 独立排除根、quota、原子写入、失败不提交 |
| 回退覆盖用户在 checkpoint 后的新修改 | compare-and-swap、显式批准、显示差异、默认拒绝漂移 |
| 外部动作已发生但本地回退造成分裂 | 默认阻止整次 rollback；不实现隐式外部补偿 |
| failed-path 误阻断合法新尝试 | 指纹包含边界/资源/失败类别；显式新 GoalContract/PlanNode 才能清除 |
| Journal v1/v2 互操作错误 | 显式 schema、只读兼容、未知 schema fail closed |
| Git backend 偷偷修改仓库 | 默认 Artifact；Git 独立 capability、审批和事件 |
| 事件/会话日志泄密 | 边界脱敏、摘要化、限长、访问控制、保留期限 |
| 回退重试造成二次写入 | rollback ledger、原子 rename、稳定 operation ID、已应用短路 |

## 12. 替代方案

### 12.1 只使用 Git commit

不采用。Git 不是所有项目都已初始化，commit 不能表达 session node、事件指针、failed-path 和外部 effect 账本，也会把 Git hooks/历史语义带入 Pangu。

### 12.2 直接复制整个 workspace

不采用为默认实现。需要内容寻址、排除规则、大小限制、原子提交和跨平台路径测试，否则可能递归包含 Artifact 或覆盖新修改。

### 12.3 失败后自动回退

第一版不采用。自动回退仍然是状态修改，必须有明确触发条件、审批、幂等 ID 和失败处理；否则模型可以通过连续失败触发隐式写入。

### 12.4 允许 rollback 调用外部补偿 API

不采用。那会扩大 Pangu 的网络和凭据边界，也无法证明补偿动作本身可逆；应作为未来独立 connector capability 单独设计。

## 13. 实施顺序和验收门

1. 先取得本 ADR 的显式批准并记录批准版本，再确认默认关闭、整次 rollback 阻止和显式审批策略；
2. 在批准后增加 EffectDescriptor、checkpoint/session/failed-path 数据类型和 schema；
3. 实现 Artifact store、快照校验、原子恢复和 operation ledger；
4. 将 checkpoint/rollback 作为内部 capability 接入 Agent 状态机；
5. 增加事件、配置和旧 Journal 兼容读取；
6. 为每个拟新增不变量增加独立测试；
7. 更新 `BOUNDARY.md` 规范文本、`ARCHITECTURE.md` 当前实现说明和 README 用户说明；
8. 只有所有测试和兼容性检查通过后，才允许把配置默认或 CLI 行为公开。

## 14. 待确认事项

- checkpoint 是否默认关闭（提案：关闭）；
- 存在不可逆外部动作时是否阻止整次 rollback（提案：阻止）；
- rollback 是否始终需要 L4（提案：需要，`Never` 拒绝）；
- failed-path 第一版是否只覆盖可执行 ToolCall（提案：是）；
- Git backend 是否允许显式创建 commit（提案：允许，但必须是独立、显式、可审批动作）。

在这些问题确认并取得本 ADR 的显式批准、且对应代码与测试合入前，本 ADR 不授权实现者修改生效中的 `BOUNDARY.md` 语义、改变运行时行为或宣称当前版本已经支持 checkpoint/rollback。
