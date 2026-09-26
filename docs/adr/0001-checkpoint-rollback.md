# ADR-0001：Pangu Artifact 检查点与受限回退（提案）

> **状态：已批准 / 阶段二实现已存在 / 实验性 opt-in，未正式激活**
> **日期：2026-03-31**
> **批准记录：** 2026-09-24；批准者/评审记录：项目维护者（用户在当前会话明确回复“批准”）；批准版本：本文 2026-03-31 版本。
> **阶段二实现记录：** 2026-09-25；已加入 Artifact 内容寻址快照与恢复、session/operation/failed-path/effect ledger、Agent 成功动作后的 checkpoint、内部 rollback 状态机、Journal v2 receipt、CLI 子命令和独立/集成测试。checkpoint 仍默认关闭，Git backend 仍未实现；Windows 覆盖写入、崩溃遗留锁和并发 workspace writer 仍按本文的 operator recovery 限制处理。
> **范围：** `pangu-core`、`pangu-boundary`、`pangu-agent`、Artifact/session store、Journal、配置和文档
> **规范优先级：** 本文记录已批准的设计和阶段二实现状态，但不是默认启用承诺。`docs/BOUNDARY.md` 仍是唯一生效的边界规范；阶段二能力只能在显式启用、通过有效 contract 和 L1–L4 闸门后使用，不能被模型或默认配置隐式打开。

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

阶段二实现现在提供（但默认不激活）：

- 持久化的 session node、Artifact manifest/blob 和 operation ledger；
- 受限的工作区快照、compare-and-swap 恢复与幂等 rollback；
- checkpoint 与稳定 Journal v2 receipt 的绑定；
- failed-path ledger 和 checkpoint 之后的外部 effect ledger；
- `Agent::rollback(&RollbackRequest)` 与 CLI `rollback` 子命令。

本 ADR 规定这些能力的**设计边界和实现限制**，不把 Git commit 当作 checkpoint 的必要条件，也不把应用层文件恢复描述为 OS 级隔离。阶段二代码和测试已经存在，但在正式激活前仍按实验性能力处理。

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
10. 阶段二实现不改变默认运行行为：未显式启用时 checkpoint/rollback 不可用；启用后仍受本文和 `BOUNDARY.md` 的条件性不变量约束。

### 2.1 阶段二实现门槛（已满足的部分）

ADR 的批准门槛已经留下批准记录。阶段二实现还必须满足以下条件才可从“实验性 opt-in”升级为正式激活：

- 所有 workspace 测试、clippy、格式检查和 CLI 集成测试通过；
- 每个适用的 checkpoint/rollback 不变量都有独立测试，并同步到 `BOUNDARY.md`；
- 恢复失败、崩溃遗留锁、operation ledger 和重复请求的 operator recovery 流程有明确文档；
- v1 Journal、禁用 checkpoint 的旧配置和默认 Artifact backend 的兼容性得到保留；
- 文档不再把实现状态误写成默认支持。

阶段二实现已加入代码和测试，但本 ADR 仍不把实验性能力当作默认承诺。

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
- 不在本 ADR 中承诺多 Agent DAG、远程 Runner 或办公连接器实现。

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

## 5. 阶段二 checkpoint/rollback 不变量（实验性 opt-in）

以下 8 条规则已经由阶段二代码和测试实现，并同步列为 `BOUNDARY.md` 第 12–19 条的实验性/条件性不变量。它们只适用于显式启用 checkpoint、通过有效 contract 绑定的运行；在正式激活前，不能据此宣称默认 checkpoint/rollback 支持，也不改变第 1–11 条的语义。

- `I-Checkpoint-After-Verified-Action`：只有成功 `VerifiedAction` 对应的成功 `ToolFinished` 才能产生 checkpoint。
- `I-Checkpoint-Atomic`：快照、manifest、稳定事件指针、session node 和完成 marker 必须可验证；缺失或损坏的 checkpoint 不得成为回退源。
- `I-Rollback-Trigger`：rollback 只能由 typed `RollbackRequest` 触发，并绑定目标 checkpoint、来源 session node、理由和可选 failed-path 引用。
- `I-Irreversible-Requires-Human`：外部 mutation 必须在执行前声明、记账并取得明确人工允许。
- `I-Rollback-Scope`：rollback 只恢复工作区和 session 状态，不执行外部补偿、Git、网络、子进程或连接器。
- `I-Rollback-Idempotent`：同一 `(checkpoint_id, rollback_id)` 只产生一次状态变更；已完成 operation 的重试只修复缺失的 transition node/审计事件。
- `I-Failed-Path-Not-Repeated`：同一 run 中等价失败动作在执行前阻断；引用必须绑定当前 contract、policy、工具和资源摘要。
- `I-No-Implicit-Git-Commit`：默认只使用 Pangu Artifact；不得隐式创建或修改 Git commit、branch、tag、stash 或 index。

这些规则的实现和验收状态见 [`BOUNDARY.md`](../BOUNDARY.md) 第 4.1 节、测试矩阵和本文第 13 节。

### 实现注记

`commit_after_success` 会拒绝非 `ToolFinished`、非 v2 sealed receipt 或 effect metadata 与已验证 action 不一致的事件。带 session node 的 Artifact 只有写入 `COMMITTED` marker 后才可加载。`Agent::rollback` 在 Policy、Approval 和外部 effect 检查前短路已完成的 operation；恢复期间会在锁内再次检查 effect ledger 和 workspace digest。

## 6. L1–L4 映射

| 层 | 阶段二职责 | 必须保持的现有边界 |
|---|---|---|
| L1 `GoalContract` | 冻结 checkpoint 开关、Artifact 根、快照限制、失败策略、rollback 模式和所有有效 digest | 模型不能动态放宽 roots、预算、审批或恢复范围 |
| L2 `Policy` | 用 `evaluate_internal` 评估不可由模型命名的 checkpoint capability；正常 deny 优先，匹配的 allow/ask 仍生效；rollback 仍是显式 `rollback` capability | 没有匹配规则时内部 checkpoint 由 L1 显式开关授权；模型不能借此获得任意恢复权限 |
| L3 `Sandbox` | 由 `SnapshotRequest` 和 `Sandbox` 校验快照/恢复路径、canonical roots、symlink、禁止 glob、文件数/字节数和临时资源 | 这是应用层资源验证，不是 OS/VM/容器隔离 |
| L4 `Approval` | 对不可逆外部 mutation 始终要求明确人工允许；rollback 始终要求 L4；checkpoint 只有在 Policy 返回匹配 `ask` 时才进入 L4 | 模型不是批准来源；`Never`、NoAnswer、超时均 fail closed |
| Agent | 维护成功动作、session node、checkpoint 和 rollback 状态机；只通过私有 `VerifiedAction` 进入 Executor | 不直接从 Agent/CLI 调用文件系统或外部补偿 |
| Artifact store | 保存不可变 manifest/blob、执行受控恢复、维护 operation/session/failed-path/effect ledger | 不自行决定 Policy、Approval 或预算；崩溃遗留锁需 operator 检查，不自动猜测恢复 |

### 6.1 checkpoint 与预算交互

checkpoint 和 rollback 属于内部 maintenance action，不产生模型 token 用量，因此不计 token 预算；其实际执行时间计入 `max_wall_clock_secs`。rollback 不重置已经消耗的 turn、输入/输出 token、费用或墙钟用量；资源上限失败按 `failure_policy` 处理，不能以回退、重试或新 session 名义绕过预算。

## 7. 执行流程

### 7.1 成功动作后的 checkpoint

```text
ToolExecutor::execute(&VerifiedAction)
  → ToolStarted(receipt) → [external effect ledger before execute]
  → ToolFinished(ok=true, sealed v2 event_id)
  → internal checkpoint capability
       Policy::evaluate_internal → SnapshotRequest/Sandbox
       → Approval only when Policy returns ask
  → snapshot + session node + COMMITTED marker
  → CheckpointCreated(event_ref, checkpoint_id, session_node_id)
```

规则：

- `ToolFinished` 的稳定 v2 event ID、序号、hash 和 effect metadata 是 checkpoint 的来源指针；
- 外部 mutation 在执行前写入 effect ledger；工具失败或进程崩溃不会使 ledger 假定外部动作未发生；
- checkpoint 事件自身不能替代成功动作的 evidence；
- checkpoint 失败时不能静默声称“已检查点”；`fail_run` 进入失败，`needs_input` 进入需人工输入；
- 已经发生的外部动作不能因 checkpoint 失败而被假定撤销；
- checkpoint/rollback 自身属于内部 maintenance action，不再递归触发新的 checkpoint；其状态变化仍要记录事件。

### 7.2 rollback

```text
RollbackRequested
  → validate typed request / checkpoint / boundary / source session node
  → short-circuit an already-applied operation after source-digest binding
  → validate failed-path reference and reject if forbidden external effect occurred
  → Policy → Sandbox → Approval
  → durable RollbackStarted receipt + operation transition binding
  → staged restore + compare-and-swap + exact final digest
  → save transition session node
  → RollbackApplied(rollback_id, checkpoint_id, session_node_id)
```

恢复前必须检查：

- checkpoint schema、hash、contract digest、policy digest 和 workspace 身份；
- 当前状态是否仍与 rollback 请求的 compare-and-swap 前置状态一致；
- 是否存在 checkpoint 之后的不可逆外部 effect；
- rollback ID 是否已经完成或正在执行；
- 所有目标路径是否仍在 L3 允许范围内。

恢复过程中不得调用 Git、网络、子进程或连接器。Journal、manifest 和 operation ledger 的审计写入是允许的 bookkeeping，不属于外部或业务副作用，但必须本身有界、原子且可审计。若实现选择 Git backend，Git 动作必须是独立、显式、可审批的 VerifiedAction，不能成为 rollback 的隐藏步骤。

若 rollback 在 workspace mutation 前失败，逻辑状态保持不变；若 mutation 阶段失败，Artifact store 尝试撤销已安装路径、恢复原目录权限并重新检查 digest。operation ledger 会记录 `Failed`，同一失败不会自动重试。失败事件必须记录 `failure_stage`、脱敏原因和可审计的失败上下文，不得把部分恢复伪装成成功。

如果进程在 restore 已写入、但 operation/node/marker 尚未完成时崩溃，`.rollback-operation.lock` 会故意留下。新的操作不会猜测恢复；operator 必须先检查 checkpoint、operation、workspace digest、临时目录和 session ledger，再决定删除锁、标记失败或人工完成 transition。Windows 上的原子文件替换还受目标文件 rename hand-off 限制，operator 应把 replace-backup 临时文件视为恢复证据而不是自动清理。并发 workspace writer 不持有 Artifact lock 时，最终 digest/CAS 会拒绝不确定覆盖；实现不宣称提供文件系统级隔离。

### 7.3 重新规划

rollback 成功后创建新的 session node：

- parent 指向 rollback 前的节点或明确的 rollback transition node；
- 保留 failed-path ledger；
- 把新节点和 checkpoint 事件写入结构化事件流；
- 向模型只提供脱敏的失败类别、路径摘要和不可重复约束；
- Runtime 在执行前再次检查 failed-path，不能只依赖 prompt 遵守。

## 8. 事件契约设计

阶段二实现使用 `pangu-journal/v2` 承载 checkpoint/rollback 事件；`pangu-journal/v1` 的读取、字段和哈希兼容保留，不重写旧 Journal。启用 checkpoint 的运行从 v2 Journal receipt 开始；MemSink 也为测试生成同形状的稳定内存 receipt。

### 8.1 新事件

已实现的事件：

- `CheckpointCreated` / `CheckpointFailed`；
- `RollbackRequested` / `RollbackStarted` / `RollbackApplied`；
- `RollbackSkippedAlreadyApplied` / `RollbackFailed`；
- `FailedPathRecorded`。

v2 receipt 由 Journal/MemSink 在写入时封存，包含 schema、连续 `seq`、`prev_sha`、内容 `sha` 和由位置/内容计算的 `evt_<sha256>` ID。TeeSink 对多个带稳定 receipt 的 durable sink 比较这些字段，不一致即失败。

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

`EventSink::emit` 保持向后兼容；需要来源 receipt 的内部路径使用向后兼容的 `emit_with_receipt`。旧 sink 没有稳定 receipt 时不能被当作 checkpoint 来源。

### 8.4 Replay 规则

Journal replay 只做：

- schema/序号/哈希验证；
- checkpoint、session node 和 failed-path 的关联展示；
- 恢复前生成计划所需的只读索引。

replay 不自动恢复文件、不执行 Git、不调用外部补偿，也不把 `RollbackApplied` 重放成第二次副作用。

## 9. 配置设计

已实现的可选配置，默认关闭：

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
- `backend = "git"` 当前未实现；显式设置会在 runtime 启动时失败，不能由默认值触发 commit；
- 不允许通过模型参数改变 checkpoint 根目录、限制或 backend；
- 启用 checkpoint 后，旧的未绑定 contract 不得直接用于新 run。

CLI 的全局开关是 `--checkpoint`（可写 `--enable-checkpoint`），rollback 目标使用 `--checkpoint-id`/`--target-checkpoint`，避免与全局开关产生参数歧义。`rollback` 拒绝 unattended，并通过 stdin approval 请求一次明确确认。

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
- Operator 只读检查为**新增** API，不改变现有签名或语义：`pangu_core::inspect_artifact_root`、`ArtifactInspection`/`InspectionVerdict`/`InspectionProblem` 等报告类型，以及只读账本访问器 `ArtifactStore::effect_records` 与 `ArtifactStore::failed_path_ledger`。报告 schema 为新增的 `pangu-artifact-inspection/1`，版本不与 checkpoint/operation schema 混用。

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

### 13.1 当前阶段二进度

已实现并有测试覆盖的范围：

- `EffectDescriptor`、资源声明一致性和 Policy 前 fail-closed 校验；
- Artifact 内容寻址快照、manifest/blob 校验、临时目录发布、`COMMITTED` marker 和 session node 事务；
- 精确恢复、权限恢复、CAS/最终 digest、跨进程锁、幂等 operation ledger、Failed operation 不自动重试和 transition node 修复；
- 外部 effect ledger、failed-path ledger、同 run 等价失败阻断和脱敏失败事件；
- Agent 成功 `ToolFinished` 后的 checkpoint、内部 Policy/Sandbox/L4 链、typed rollback、预算检查和 source/target/session 绑定；
- Journal v1/v2、稳定 receipt、TeeSink receipt 一致性、CLI rollback 和真实子进程集成测试；
- symlink、特殊文件、损坏 blob/marker、路径穿越、stale lock、CLI flag 兼容和效果作用域测试；
- [`CHECKPOINT_RECOVERY.md`](../CHECKPOINT_RECOVERY.md) operator recovery 运行手册，覆盖证据保全、stale lock、failed operation、CAS drift、外部副作用和 Windows replacement hand-off。
- Operator 只读检查与演练：`pangu-core::inspect::inspect_artifact_root`（只读、复用 restore 的 `verify_checkpoint`、有界且脱敏、不注册为 capability），CLI `pangu artifact inspect`；`crates/pangu/tests/operator_drills.rs` 演练 stale lock、failed operation、CAS drift、外部 mutation、replacement backup、只读性与 CLI 退出码，并按平台记录差异（Windows hand-off 与 POSIX rename 语义不同），CI 在 ubuntu/windows 双平台运行并归档 drill 报告。

尚未宣称正式激活的原因：checkpoint 仍是默认关闭的实验性 opt-in。operator 证据收集与四个事故分支已有只读工具和可重复 drill，**跨平台验证也已完成**：CI run 36210280753（提交 `1b0245d`）在 `ubuntu-latest` 与 `windows-latest` 上通过 `fmt`/`check`/`test`/`clippy --all-features` 与 7 个 drill，两个平台的原始报告转录在 [`docs/evidence/`](../docs/evidence/)。但 POSIX 上 replacement hand-off 不成立（该项为 `not-applicable`），恢复期间的备份与审计可用性、无人工输入与并发 writer 的停止策略、以及激活批准仍需部署者书面确认。在这些证据齐备前，本文及 README 不把 checkpoint/rollback 描述为默认支持。

## 14. 已确认的设计决策与当前实现边界

本次批准确认以下设计选择；阶段二代码已经实现其中的 Artifact/Agent/CLI 路径，但仍保持实验性 opt-in：

- checkpoint 默认关闭；没有显式启用和有效 contract 不得创建 checkpoint；
- checkpoint 之后发生不可逆外部 mutation 时，默认阻止整次 rollback；不实现外部补偿；
- rollback 始终需要 L4 明确批准，`Never`/无答案/超时均拒绝；
- failed-path 第一版只覆盖可执行 `ToolCall`，不把自然语言计划当作稳定路径身份；
- Git backend 当前未实现，且永远不能成为 rollback 的隐藏步骤；未来若实现必须是独立、显式、可审批的 capability。

阶段二的恢复限制和 operator 流程已经写入第 7.2 节及 [`CHECKPOINT_RECOVERY.md`](../CHECKPOINT_RECOVERY.md)；在正式激活前，本文不把 checkpoint/rollback 描述为默认支持，也不允许模型直接触发它。
