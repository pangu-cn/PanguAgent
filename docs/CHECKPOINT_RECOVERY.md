# Checkpoint / Rollback Operator Recovery Runbook

> **状态：实验性 opt-in 的操作手册，不是自动恢复保证。**
>
> 本手册适用于 Pangu Artifact backend。checkpoint 默认关闭；Git backend 当前未实现。
> 任何步骤都不能把模型输出、自然语言指令或手工修改的 ledger 当成可信恢复证据。
> 第 3 节的证据收集已有只读工具（`pangu artifact inspect`），第 6 节是可重复演练；两者都只报告，不修复。

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

优先使用只读检查器收集本节证据，它不会创建、修复、删除或重试任何东西：

```bash
pangu artifact inspect --root <ARTIFACT_ROOT>            # 人类可读
pangu artifact inspect --root <ARTIFACT_ROOT> --json     # pangu-artifact-inspection/1
```

报告的 `verdict` 只有三种：

- `verified`：manifest、commit marker、blob hash、session node、operation 与账本全部通过校验；
- `operator_required`：可证明内部一致，但存在 runtime 故意不自行处理的事故条件（stale lock、`InProgress`/`Failed` operation、checkpoint 之后的外部 mutation、replacement backup、active failed-path）；
- `unverifiable`：无法完整证明（读不到、超限、hash/绑定不一致）。此时不得对 workspace 状态做任何结论。

`detail` 与 `subject` 已脱敏并限长，路径只保留相对形式；问题码自带 `unverifiable.*` / `operator.*` 前缀，报告 verdict 取最严重的一项。检查器退出码在非 `verified` 时非零。

检查器看不到的两件事：CAS 漂移是**请求相关**事实（需要 boundary roots），必须由 `pangu rollback` 的 compare-and-swap 判定；lock 文件里的 `pid=` 只是线索，不证明进程存活。替换与扫描达到上限时报告会标注截断，不能把不完整扫描当成完整结论。

在 Artifact root 中需要人工复核时，只读检查以下内容：

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

## 6. Operator drill（可重复演练）

本手册的分支可以被自动演练，避免“只有真正出事时才第一次看”。演练只证明 **fail closed 与证据存在**，不证明 Pangu 能自动恢复；恢复仍然是人的决定。

```bash
# 单个事故分支的回归测试（cargo test -p pangu --test operator_drills）
cargo test -p pangu --test operator_drills

# 产出可归档的逐平台证据；不设变量时直接打印到 stdout。
# PANGU_DRILL_REPORT 必须是绝对路径（cargo test 在包目录运行测试二进制）。
PANGU_DRILL_REPORT="$PWD/evidence.jsonl" PANGU_DRILL_COMMIT="$(git rev-parse HEAD)" \
  cargo test -p pangu --test operator_drills -- --nocapture
```

| Drill | 对应分支 | 断言 |
|-------|---------|------|
| `stale-lock` | §4.1 | 遗留 lock 同时阻断读与写；lock 不被删除；不产生 operation 记录；报告为 `operator_required` |
| `failed-operation` | §4.3 | 恢复中途失败记为 `Failed` 并带脱敏原因；同一 rollback id 不自动重试且不新增记录；workspace 回到失败前状态 |
| `cas-drift` | §4.4 | compare-and-swap 失败后新编辑原样保留、不产生 operation 记录；store 本身仍为 `verified` |
| `external-effect` | §4.5 | checkpoint 之后存在不可逆外部 mutation 时整次 rollback 被阻；不做任何外部补偿 |
| `replace-backup` | §4.6 | 遗留 `.replace-backup-*` 阻止新的 Artifact 写入且本身被保留；报告为 `operator_required` |
| `inspection-read-only` | §1 | 连续三次检查后 store 与 workspace 字节完全不变 |
| `cli-inspect` | §3 | CLI 文本与 `--json` 两种输出都报告事故，且退出码非零 |

平台差异按事实记录，不假装一致：

- `failed-operation` 需要“写到一半失败”。Windows 用“待移开目录内的文件以只读共享方式打开”（目录 rename 被拒），Unix 用“目标目录不可写”；以 root 运行时 Unix 机制无效，演练会记为 `skipped` 而不是伪装通过。
- `replace-backup` 只在 Windows 存在 hand-off。POSIX 上该文件对 runtime 无意义，演练记录 `not-applicable`，并只验证“证据被报告且未丢失”。
- CI 在 `ubuntu-latest` 与 `windows-latest` 上都运行该套演练，并把 `f7-drill-report.jsonl` 作为 artifact 上传（见 `.github/workflows/ci.yml`）。

## 7. 当前实现限制

- `.rollback-operation.lock` 不会自动猜测恢复；这是故意的 fail-closed 行为。
- Windows 原子替换使用 backup/rename hand-off，运行时中断后需要 operator 介入。
- 不持有 Artifact lock 的并发 workspace writer 依赖最终 digest/CAS 检测；这不是 OS 或 VM 级隔离。
- snapshot 不记录 snapshot root 目录自身的权限/元数据，只记录 root 下的子项。
- Git backend 未实现，也不会隐式创建 commit、branch、tag、stash 或修改 index。
- `pangu artifact inspect` 只读且有界：条目数、深度、checkpoint/operation 数量和 replacement backup 数量都有上限，截断时显式报告；它不判断 CAS 漂移，也不替代 `pangu rollback` 的前置校验。
- checkpoint/rollback 仍是默认关闭的实验性 opt-in；本手册不是正式支持或默认激活承诺。

## 8. 激活前验收清单

在考虑把该能力从“实验性 opt-in”升级为正式激活前，部署者应保存以下证据。已具备机器化手段和本地实测的项标为 `[x]`，仍需部署环境或人工签署的项保持 `[ ]`：

- [ ] Windows、Unix 和目标部署平台分别通过 snapshot/restore、symlink、权限和 replacement 测试。（Windows 已由本机 `cargo test --workspace --all-targets` 与第 6 节演练覆盖；Unix/其它平台待 CI 与部署环境证据）
- [x] stale lock、failed operation、CAS drift、Windows replacement backup 有可重复的 operator drill（第 6 节），且 replacement hand-off 与无锁并发 writer 的限制已写成本手册第 4、7 节。
- [x] 只读证据检查有工具（`pangu artifact inspect`）并有“不修改任何字节”的独立断言。
- [ ] 恢复期间有可用的 workspace/Artifact 备份和独立审计记录。（依赖部署环境）
- [ ] 明确并发 writer、外部 effect 和无人工输入时的停止策略。（需部署者书面确认）
- [x] 配置、CLI、Journal、Artifact schema、inspection schema 和恢复手册版本相互匹配，并在 ADR/ROADMAP/README 中一致标为实验性 opt-in。
- [x] 默认配置仍关闭 checkpoint，Git backend 仍明确未实现。
- [ ] Ubuntu/Windows CI 完成 `cargo check/test/clippy --workspace --all-targets --all-features` 并保存跨平台 drill 报告（CI 已配置 drill 步骤与 artifact 上传；等待真实 CI 运行结果，不以本机结果代替）。
- [ ] 由 operator/发布负责人明确批准激活；未批准前继续保持实验性 opt-in。

### 8.1 跨平台验收记录

每次验收把实际结果写在这里，不写推测。CI drill 报告作为 artifact 归档；本机运行的结果保存在 `docs/evidence/`。

| 平台 | 工具链 | 提交 | `cargo test --workspace --all-targets` | clippy `-D warnings` | operator drill（7 项） | 证据 |
|------|--------|------|-----------------------------------|--------------------|-------------------|------|
| Windows 10.0.26200 x86_64 | rustc 1.98.0 | `c7f5e39` | 通过（141 项，0 失败，含 `pangu --demo`） | 0 error / 0 warning | 7/7 pass | [`evidence/f7-drills-windows.jsonl`](evidence/f7-drills-windows.jsonl) |
| Ubuntu（CI） | 待 CI | 待 CI | 待 CI | 待 CI | 待 CI | 等待 CI artifact |

本机记录：2026-09-25 在 Windows 10.0.26200.9457 / x86_64 / rustc 1.98.0 上，针对提交 `c7f5e39` 运行 `cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets`、`cargo run -q -p pangu -- --demo` 与第 6 节的 7 个 drill，结果如上表；drill 报告由该提交自身产生，并记录了每次 drill 的平台与机制。

已知覆盖边界（不是待办，而是事实）：

- 本机只能提供 Windows 证据。**Ubuntu 结果必须来自真实 CI 运行**，不得由本机结果或推断代替；CI 已配置双平台 drill 步骤与 artifact 上传。
- `failed-operation` 在 Unix 以“不可写目录”阻断，root 环境下记为 `skipped`；因此 Ubuntu 报告可能不包含该机制，不代表通过。
- `replace-backup` 在 POSIX 无 hand-off 语义，Ubuntu 报告该项为 `not-applicable`，不能据此声称 Unix 也验证了 replacement 保护。
- drill 证明 fail closed 与证据存在，**不证明** Pangu 能自动完成恢复；并发 writer、无人工输入、外部副作用的处置仍需部署者按第 4 节人工裁决。

相关设计边界见 [`BOUNDARY.md`](BOUNDARY.md)、[`ARCHITECTURE.md`](ARCHITECTURE.md) 和 [`adr/0001-checkpoint-rollback.md`](adr/0001-checkpoint-rollback.md)。
