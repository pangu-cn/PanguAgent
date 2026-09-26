# Checkpoint / Rollback Operator Recovery Runbook

> **状态：实验性 opt-in 的操作手册，不是自动恢复保证。**
>
> 本手册适用于 Pangu Artifact backend。checkpoint 默认关闭；Git backend 当前未实现。
> 任何步骤都不能把模型输出、自然语言指令或手工修改的 ledger 当成可信恢复证据。

## 1. 安全边界

operator 在整个恢复过程中必须遵守以下规则：

- 先停止会写入 workspace、Artifact store 或 Journal 的 Pangu 进程；确认没有其它 writer。
- 保留原始 workspace、Artifact root、Journal 和相关临时文件作为证据；不要先“清理干净再观察”。
- 不自动删除 `.rollback-operation.lock`、`.replace-backup-*`、`.tmp-*` 或失败 operation。
- 不手工创建或修改 `COMMITTED`、manifest、blob、session node、operation ledger、effect ledger 或 failed-path ledger。
- 不使用 Git、网络、子进程、连接器或外部补偿 API 来完成 rollback。
- 不强行覆盖 CAS digest，不把旧 checkpoint 的 digest 填入新的请求。
- 同一个 `(checkpoint_id, rollback_id)` 在 `Failed` 或 `InProgress` 状态下不自动重试；需要新的操作时必须重新建立证据、typed request 和人工批准。
- 任何无法证明来源、完整性或当前状态的情况都 fail closed；保留现场并升级给 operator。

## 2. 适用条件与前置资料

在开始任何恢复判断前，准备以下信息并保存到变更记录中：

1. 原始 run ID、session ID、目标 checkpoint ID、source session node ID 和 rollback ID（如已发生）。
2. 当时的配置文件、CLI overrides、GoalContract digest 和 Policy digest。
3. 对应 Journal（通常是 `pangu-journal/v2`）及其 sealed event receipt。
4. Artifact root、workspace 和 `.pangu` 目录的只读副本或校验记录。
5. 所有相关进程是否已停止，以及停止时间的时区记录。
6. operator、审批人、变更单号和回滚原因。

只有在明确这些资料后，才进入下面的 incident 分支。不要为了“试一下”而先运行一次新的 rollback。

## 3. 证据检查顺序

按以下顺序收集证据；任何一步失败都停止，不要跳到“尝试恢复”。

### 3.1 Journal 与事件

- 用 `pangu doctor --journal <journal>` 检查 Journal 可读性和摘要。
- 确认 `RunStarted`、成功的 `ToolFinished`、checkpoint 事件、rollback 事件和 terminal 事件的顺序。
- 核对 rollback source event、checkpoint event、transition event 的 event ID、seq、previous hash 和 content hash。
- 不接受孤立的手工 JSON 行；Journal 校验失败时保留原文件并升级。

### 3.2 Artifact

在 Artifact root 中只读检查：

- `<checkpoint_id>/manifest.json`
- `<checkpoint_id>/blobs/`
- `<checkpoint_id>/session-node.json`（如果该 checkpoint 声明了 session node）
- `<checkpoint_id>/COMMITTED`
- `sessions/<session_node_id>.json`
- `operations/<rollback_id>.json`（如果 rollback 已开始）
- `effects.jsonl` 和 `failed-paths.jsonl`

必须同时确认：

- manifest 的 checkpoint ID、contract digest、policy digest、workspace 和 schema 有效；
- 每个 blob 是 regular file，大小和 SHA-256 匹配；
- `COMMITTED` 存在且内容准确；
- embedded 与 standalone session node 一致；
- operation 的 rollback ID、checkpoint ID、status、transition binding 和 completed/error 字段自洽；
- Artifact 中的路径没有 symlink、特殊文件、越界路径或大小超限。

不要通过编辑文件来“修复”任何不一致。无法验证的 Artifact 只能隔离并标记为不可用。

### 3.3 Workspace 与 effect

- 停止 writer 后再计算当前 workspace digest。
- 将当前 digest 与 source checkpoint 的 workspace digest、operation 中记录的 digest 比较。
- 检查 `effects.jsonl` 中 checkpoint event 之后是否存在同一 run 的 external mutation。
- 检查临时 restore 目录和 Windows `.replace-backup-*` 是否存在；它们是证据，不是待自动删除的垃圾。

## 4. Incident 处理分支

### 4.1 存在 `.rollback-operation.lock`

1. 确认所有 Pangu writer 已停止。
2. 复制 lock、Artifact root 和 workspace；记录 lock 的 PID 仅作为线索，不把它当作进程仍存活的证明。
3. 检查对应 operation 是否存在以及状态为 `InProgress`、`Applied` 或 `Failed`。
4. 如果 operation 是 `InProgress`，或 workspace 处于 restore 中间状态，禁止删除 lock、启动新 rollback 或猜测“继续/回滚”。
5. 只有在确认没有活动进程、workspace 和 Artifact 证据已保存、且获得 operator/审批人的变更批准后，才可以由 operator 决定如何处置 lock。处置决定和理由必须进入变更记录。

runtime 的下一次操作仍会看到 lock 并 fail closed；本手册不授权自动恢复。

### 4.2 operation 是 `Applied`，但 session node 或 completion evidence 不完整

1. 保留 operation 文件和 transition binding，不重复执行 restore。
2. 核对 transition node ID、event ref、source checkpoint 和当前 source state。
3. 如果 binding 或 evidence 不完整，停止自动流程；不要把 operation 手工改成 `Applied` 或删除 node。
4. 只有受支持的 library/recovery API 在完整验证后能够补齐缺失 bookkeeping 时才可继续；当前 CLI 没有承诺通用自动 repair。
5. 在补齐或人工裁决前，workspace 状态必须被视为不确定，不能报告“回退成功”。

### 4.3 operation 是 `Failed`

1. 读取并保存脱敏的 failure stage、error 和 Journal terminal event。
2. 检查失败后的 workspace digest、临时目录、backup 文件和外部 effect ledger。
3. 不使用原 rollback ID 重试，也不删除失败 operation。
4. 如果需要新的恢复目标，重新执行完整的边界、Policy、Sandbox 和人工审批流程，并使用新的 rollback ID；先证明没有未处理的外部副作用。
5. 如果失败原因无法解释，停止并升级，不要以“再运行一次看看”为恢复策略。

### 4.4 CAS drift 或出现未知 writer

1. 立即停止所有 writer，保存 workspace 差异和时间线。
2. 不使用旧的 expected digest 强制恢复。
3. 查明新增/修改文件是否来自已记录动作、插件或外部进程。
4. 只有在重新建立可信 source session node、重新计算 digest 并完成新的审批后，才能发起新的 typed rollback。
5. 未知 writer 未查明前，状态按不确定处理。

### 4.5 checkpoint 之后存在 external mutation

- rollback 必须阻止。
- 不执行 Git、网络、子进程、连接器或外部补偿。
- 记录 effect event ref、event ID、run ID、scope 和 reversibility。
- 将后续处理转为独立的人工/业务事故流程；Pangu rollback 不把它伪装成可逆操作。

### 4.6 Windows replacement hand-off 中断

看到目标文件同目录下的 `<file>.replace-backup-*` 时：

1. 停止所有 writer，保留 backup、目标和 Artifact checkpoint 的原始证据。
2. 不删除 backup，不反复调用写入函数，不把 backup 当作已经验证的 checkpoint。
3. 对照目标文件、backup、manifest/blob hash 和 operation timeline，由 operator 判断哪一份是可信源。
4. 如需人工替换，使用组织批准的离线恢复流程和独立的变更审批；完成后重新计算 workspace digest，并保留恢复前后的证据。
5. 在 stale backup 未被人工裁决前，新的 Pangu restore 必须继续 fail closed。

## 5. 关闭事故的最低证据

事故只有在以下项目都有记录后才能关闭：

- 原因和影响范围；
- 使用的 checkpoint/source node/rollback ID；
- Journal event refs 与 receipt 校验结果；
- Artifact manifest/blob/marker/session node 校验结果；
- operation 状态和 transition binding；
- effect ledger 与 external mutation 结论；
- 恢复前、恢复后 workspace digest；
- Windows backup、stale lock、临时目录的最终处置；
- operator 与审批人的确认。

不要删除历史 Journal、operation、effect 或 failed-path 记录来“清理状态”。需要保留它们的期限由部署者的审计策略决定。

## 6. 当前实现限制

- `.rollback-operation.lock` 不会自动猜测恢复；这是故意的 fail-closed 行为。
- Windows 原子替换使用 backup/rename hand-off，运行时中断后需要 operator 介入。
- 不持有 Artifact lock 的并发 workspace writer 依赖最终 digest/CAS 检测；这不是 OS 或 VM 级隔离。
- snapshot 不记录 snapshot root 目录自身的权限/元数据，只记录 root 下的子项。
- Git backend 未实现，也不会隐式创建 commit、branch、tag、stash 或修改 index。
- checkpoint/rollback 仍是默认关闭的实验性 opt-in；本手册不是正式支持或默认激活承诺。

## 7. 激活前验收清单

在考虑把该能力从“实验性 opt-in”升级为正式激活前，部署者应保存以下证据：

- [ ] Windows、Unix 和目标部署平台分别通过 snapshot/restore、symlink、权限和 replacement 测试。
- [ ] 实际执行 stale lock、failed operation、CAS drift 和 Windows backup 的 operator drill。
- [ ] 恢复期间有可用的 workspace/Artifact 备份和独立审计记录。
- [ ] 明确并发 writer、外部 effect 和无人工输入时的停止策略。
- [ ] 配置、CLI、Journal、Artifact schema 和恢复手册版本相互匹配。
- [ ] 默认配置仍关闭 checkpoint，Git backend 仍明确未实现。
- [ ] Ubuntu/Windows CI 完成 `cargo check/test/clippy --workspace --all-targets --all-features`，并保存跨平台最终验收证据。
- [ ] 由 operator/发布负责人明确批准激活；未批准前继续保持实验性 opt-in。

相关设计边界见 [`BOUNDARY.md`](BOUNDARY.md)、[`ARCHITECTURE.md`](ARCHITECTURE.md) 和 [`adr/0001-checkpoint-rollback.md`](adr/0001-checkpoint-rollback.md)。
