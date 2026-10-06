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
7. 当时的执行后端声明（`RunStarted` 载荷的 `execution_profile`/`execution_description`，见 BOUNDARY §3 C5；缺省即未声明/local）。

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

**权限变化也算 drift。** snapshot 的目录条目记录了权限位，并计入 workspace digest。所以在 Unix 上，为了“腾出写入权限”而 `chmod`，同样会让 compare-and-swap 失败——而且失败发生在写入任何 operation 记录之前，store 里不会留下失败痕迹。这不是可自动绕过的小障碍：operator 要先确认权限变化是否可接受，再重新建立 source session node 并发起新的 typed rollback，不要在原 rollback id 上重试。

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
- 目录权限计入 snapshot digest，因此 Unix 上的 `chmod`（包括为恢复而调整权限）会被当作 drift 拒绝，且拒绝发生在写 operation 记录之前（见第 4.4 节）。
- Git backend 未实现，也不会隐式创建 commit、branch、tag、stash 或修改 index。
- **symlink 与目录权限的验证只在 Unix 上存在**：相关测试是 `#[cfg(unix)]` 条件编译的，在 Windows 上根本不会被收集。因此 Windows 部署无论如何都拿不到这两栏证据（见 §9.1 的平台条件编译表）。判定"snapshot 会拒绝 symlink 而不是静默忽略"这类行为**只有 POSIX 证据**。
- 快照遍历整个工作区，`forbidden_globs` 默认只挡 `.git`/`.env`/secrets/私钥，**不挡构建产物**。仓库里若有巨大的 `target/`，checkpoint 会撞上 `max_snapshot_bytes` 并按 `failure_policy` 终止运行；错误信息会指出具体是哪个文件越界。处理办法是在 `checkpoint.exclude_roots` 里声明该目录，或调高上限。
  - 排除是有代价的，不是免费的性能开关：被排除的目录**不会被回退**，所以只能排除真正可重建的内容。排除前拍的旧 checkpoint 会在 restore 时**明确失败并指出是哪个排除根挡住的**，不会部分回退。
- `pangu artifact inspect` 只读且有界：条目数、深度、checkpoint/operation 数量和 replacement backup 数量都有上限，截断时显式报告；它不判断 CAS 漂移，也不替代 `pangu rollback` 的前置校验。
- checkpoint/rollback 仍是默认关闭的实验性 opt-in；本手册不是正式支持或默认激活承诺。

## 8. 激活前验收清单

在考虑把该能力从“实验性 opt-in”升级为正式激活前，部署者应保存以下证据。已具备机器化手段和本地实测的项标为 `[x]`，仍需部署环境或人工签署的项保持 `[ ]`。**每个 `[ ]` 项对应的操作程序见第 9 节**，留证要求在那里写死；没有证据的勾选不算勾选。

- [x] stale lock、failed operation、CAS drift、Windows replacement backup 有可重复的 operator drill（第 6 节），且 replacement hand-off 与无锁并发 writer 的限制已写成本手册第 4、7 节。
- [x] 只读证据检查有工具（`pangu artifact inspect`）并有“不修改任何字节”的独立断言。
- [ ] 恢复期间有可用的 workspace/Artifact 备份和独立审计记录。（依赖部署环境）→ **见 §9.3**
- [ ] 明确并发 writer、外部 effect 和无人工输入时的停止策略。（需部署者书面确认）→ **见 §9.2**
- [x] 配置、CLI、Journal、Artifact schema、inspection schema 和恢复手册版本相互匹配，并在 ADR/ROADMAP/README 中一致标为实验性 opt-in。
- [x] 默认配置仍关闭 checkpoint，Git backend 仍明确未实现。
- [x] Ubuntu 与 Windows CI 完成 `cargo fmt --check`、`cargo check/test/clippy --workspace --all-targets --all-features` 并保存跨平台 drill 报告（run 36210280753，提交 `1b0245d`，见 8.1）。
- [ ] **目标部署平台**单独通过 snapshot/restore、symlink、权限测试。（Windows 与 Ubuntu 已有 CI 证据；replacement hand-off 只在 Windows 成立，POSIX 上该 drill 为 `not-applicable`；symlink 与目录权限测试为 `#[cfg(unix)]`，Windows 上不存在，见 §9.1 的表）→ **见 §9.1**
- [ ] 由 operator/发布负责人明确批准激活；未批准前继续保持实验性 opt-in。→ **见 §9.4**

### 8.1 跨平台验收记录

每次验收把实际结果写在这里，不写推测。CI drill 报告作为 artifact 归档并同时发成可公开读取的注解；转录到 `docs/evidence/` 的内容只来自真实运行。

| 平台 | 工具链 | 提交 | `cargo test --workspace --all-targets --all-features` | clippy `-D warnings` | operator drill（7 项） | 证据 |
|------|--------|------|----------------------------------------------------|--------------------|-------------------|------|
| Windows（GitHub runner） | `dtolnay/rust-toolchain@stable` | `1b0245d` | 通过 | 0 error / 0 warning | 7 pass | [`evidence/f7-drills-windows.jsonl`](evidence/f7-drills-windows.jsonl) |
| Ubuntu（GitHub runner） | `dtolnay/rust-toolchain@stable` | `1b0245d` | 通过 | 0 error / 0 warning | 6 pass + 1 not-applicable | [`evidence/f7-drills-ubuntu.jsonl`](evidence/f7-drills-ubuntu.jsonl) |
| Windows 10.0.26200 x86_64（本机） | rustc 1.98.0 | `1b0245d` | 通过（142 项，0 失败） | 0 error / 0 warning | 7 pass | 同上（同一 commit） |
| Windows 10.0.19045 x86_64（本机） | rustc 1.98.1 | `3aa11da` | 通过（373 项，0 失败） | 0 error / 0 warning | 7 pass | [`evidence/f7-drills-windows-10.0.19045.jsonl`](evidence/f7-drills-windows-10.0.19045.jsonl) |
| Windows（GitHub runner） | `dtolnay/rust-toolchain@stable` | `105258e` | 通过 | 0 error / 0 warning | 7 pass | [`evidence/f7-drills-windows-105258e.jsonl`](evidence/f7-drills-windows-105258e.jsonl) |
| Ubuntu（GitHub runner） | `dtolnay/rust-toolchain@stable` | `105258e` | 通过 | 0 error / 0 warning | 6 pass + 1 not-applicable | [`evidence/f7-drills-ubuntu-105258e.jsonl`](evidence/f7-drills-ubuntu-105258e.jsonl) |

> 最后两行是 CI 在**修复 Ubuntu 测试失败之后**的第一次全绿运行（run [37398616832](https://github.com/pangu-cn/PanguAgent/actions/runs/37398616832)）。此前 `plan-a` 上每次 CI 都是 ubuntu 失败 / windows 通过（连续 7 次），提交 `1da46a0`、`7627b4d` 均如此；原因见 §11。
>
> `105258e` 行的 Ubuntu 与 Windows `failed-operation` 机制名不同（`read-only-directory` 对 `directory-rename-blocked-by-open-file`），这正是 8.1 已记录的平台差异，**属于同一分支的两种实现**，不是不一致的证据。

> 最后一行是 **2026-10-05 本机实测**，不是 CI 结论，也**不满足 §9.1**：它仍属"CI 已覆盖的两个平台"，不是目标部署平台。它的作用是证明该 drill 在当前提交上仍可复现，按 §9.1 的判读规则全部为 `pass`（本平台存在 replacement hand-off 机制，故无 `not-applicable`）。

本机记录（2026-09-25，Windows 10.0.26200.9457 / x86_64 / rustc 1.98.0）：`cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets --all-features -- -D warnings`、`cargo test --workspace --all-targets --all-features`（142 项，0 失败）与 7 个 drill 全部通过。

本机记录（2026-10-05，Windows 10.0.19045 / x86_64 / rustc 1.98.1，提交 `3aa11da`）：`cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --all-targets --no-fail-fast`（373 项，0 失败）与 7 个 drill 全部通过；drill 报告转录见 [`evidence/f7-drills-windows-10.0.19045.jsonl`](evidence/f7-drills-windows-10.0.19045.jsonl)。

CI 记录（run [36210280753](https://github.com/pangu-cn/PanguAgent/actions/runs/36210280753)，2026-09-26，提交 `1b0245d`）：`ubuntu-latest` 与 `windows-latest` 两个 job 全部步骤通过。`docs/evidence/` 下的两份报告是从该 run 的 drill 步骤产出的原始内容转录（GitHub artifact 下载需认证，CI 同时把每行发成可公开读取的注解）。

**关于工具链版本**：CI 用的是浮动的 `@stable`，本表不写 CI 的 rustc 具体版本——那只能从 run 日志读到，而 job 日志需要 admin 权限。本机行的 1.98.0 是实测值；按 1.98.0 构建于 2026-08-18、Rust 六周一个发布窗口推算，run 时的 stable 很可能仍是 1.98.0，但这是**推断**，不当作证据。

已知覆盖边界（不是待办，而是事实）：

- **Ubuntu 的 `replace-backup` 是 `not-applicable`，不是通过。** POSIX 的 `rename(2)` 没有 Windows 的 hand-off 窗口，因此 Unix 上不存在需要人工核验的 `.replace-backup-*`。不能据此声称 Unix 也验证了 replacement 保护；该保护只有 Windows 证据。
- **Ubuntu 的 `failed-operation` 用的是 `read-only-directory` 机制**（把 `nested` 设为不可写），Windows 用的是“只读共享句柄阻断目录 rename”。同一分支在两个平台的阻断方式不同，都必须落在 restore 内部才算演练到；机制名随报告一起记录。
- 该演练在以 root 运行的账户上记为 `skipped`（root 绕过目录权限）。CI runner 不是 root。
- drill 证明 fail closed 与证据存在，**不证明** Pangu 能自动完成恢复；并发 writer、无人工输入、外部副作用的处置仍需部署者按第 4 节人工裁决。
- 本机没有 Linux 环境，Ubuntu 侧的一切结论均以 CI 为准，本机运行不作为补充证据。

## 9. 激活门逐项操作程序

第 8 节列出"还缺什么"，本节给出"**怎么才算补齐**"。每一项都要求留证：没有证据的勾选不算勾选。

顺序不能颠倒：**9.2 的停止策略必须先书面定下来**，否则一次不可中断的 drill（9.1）或一次真实恢复（9.3）遇上并发 writer 时，operator 没有事先约定的处置依据，现场只能靠临场判断——那正是本手册 §1 要避免的东西。

### 9.1 目标部署平台自身的 snapshot/restore、symlink、权限验证

**为什么不能靠 CI 代替**：CI 的 Windows/Ubuntu runner 不是目标部署平台。§7 已记录平台差异（Unix 无 replacement hand-off、目录权限计入 digest），这些差异在目标平台上可能又不一样。

**两件事都要做，缺一不算完成**。只跑下面第 1 步会留下一个空洞：`operator_drills` 覆盖的是**事故分支**（stale lock、CAS drift…），并不覆盖清单第 219 行点名的 snapshot/restore 正常路径、symlink 与权限；这三项在第 2 步的测试里，且**部分是平台条件编译的**（见下表）。

```bash
# 第 1 步：事故分支演练，产出可归档的 jsonl 证据。
# 报告必须是绝对路径（cargo test 在包目录运行测试二进制）。
PANGU_DRILL_REPORT="/绝对路径/f7-drill-$(hostname)-$(date +%Y%m%d).jsonl" \
PANGU_DRILL_COMMIT="$(git rev-parse HEAD)" \
  cargo test -p pangu --test operator_drills -- --nocapture

# 第 2 步：snapshot/restore、symlink、权限——清单第 219 行点名的三项。
cargo test -p pangu-core --lib -- artifact::tests::restore_ \
                                       artifact::tests::corrupt_blob_fails_before_restore \
                                       artifact::tests::snapshot_rejects
cargo test -p pangu --test rollback_cli
```

第 2 步必须**看输出里的实际通过项数**，不能只看退出码为 0：条件编译的测试在被跳过的平台上根本不会被收集，过滤到一个空集合也会返回成功。至少要能对上表里适用本平台的条目。

**平台条件编译（实测，非推断）**——以下几项只在对应平台上编译，另一个平台**不可能**产出该证据：

| 测试 | 门槛 | Windows | Unix |
|------|------|---------|------|
| `artifact::tests::snapshot_rejects_symlinks_instead_of_silently_omitting_them` | `#[cfg(unix)]` | 不适用 | 应通过 |
| `artifact::tests::snapshot_rejects_special_filesystem_entries`（Unix socket 等） | `#[cfg(unix)]` | 不适用 | 应通过 |
| `artifact::tests::restore_applies_directory_permissions_after_children` | `#[cfg(unix)]` | 不适用 | 应通过 |
| `artifact::tests::restore_*`（其余 restore 用例）| 无 | 应通过 | 应通过 |
| `artifact::tests::corrupt_blob_fails_before_restore` | 无 | 应通过 | 应通过 |
| `rollback_cli::rollback_subcommand_restores_a_checkpoint_in_a_real_process` | 无 | 应通过 | 应通过 |

**因此**：如果在 Windows 上做本项验收，symlink 与目录权限两栏只能记 `not-applicable`（机制由 POSIX 语义定义），**不能记为通过**；要同时拿到这两栏的证据，必须在 Unix 目标平台上另跑一次。这与 §6 对 `replace-backup` 的处理是同一原则。

**判读规则（照抄 §6 的平台差异章节，不要"统一"成通过）**：

| 结果 | 含义 |
|------|------|
| `pass` | 该分支在目标平台被演练到 |
| `not-applicable` | 机制在该平台不存在（如 POSIX 的 replace-backup、Windows 上的 POSIX 目录权限）。**不是通过**，也不构成对其它平台该保护的验证 |
| `skipped` | 未能演练（如以 root 运行导致权限机制失效）。**不是通过**；换成非特权账户重跑 |

**留证**：把 jsonl 转录到 [`docs/evidence/`](evidence/)（格式见该目录 README），并在 §8.1 表格加一行；第 2 步的通过项数与平台条件编译的适用情况一并写进该行的说明。任何一个 drill 为 `not-applicable` 或 `skipped` 时，必须在该行注明原因，不能只写"通过"。

### 9.2 并发 writer、外部 effect、无人工输入时的停止策略（需部署者书面确认）

这是**唯一的纯人的决定**，无法用测试替代：它约束的是 Pangu 之外的世界。

必须在书面确认中明确回答：

1. **谁在写同一个 workspace**：Pangu 之外是否有编辑器、构建、同步盘（OneDrive/Dropbox）、CI 或其它 agent 在写同一目录？
2. **如何确保恢复期间没有 writer**：靠什么手段（停进程、卸载盘、独占锁）？§1 要求"先停止 writer"，但**没有工具能强制**它——Pangu 只会靠最终 digest/CAS 检测漂移，检测到即拒绝（§4.4）。**检测不是预防。**
3. **checkpoint 之后发生外部不可逆副作用时怎么办**：Pangu 会阻断整次 rollback 且不做外部补偿（§4.5）。谁负责手工补偿？谁批准？
4. **无人工输入时**：`--dangerously-unattended` 与 rollback 不兼容；无人值守下 rollback 一律 fail closed。确认部署中**不会**出现期望"无人值守自动回滚"的流程。
5. **升级路径**：出事时第一个联系谁、多久内响应（决定 §4 各分支能停多久）。

**第 2 题的一部分已经由代码回答，范围因此收窄**：子 Agent 委派现在持有 workspace 写锁（`BOUNDARY.md` 受限子 Agent 一节），所以**同一个 workspace 上并发的 Pangu 写入者会被串行化**——不是靠 operator 停进程,而是靠锁等待。这改变的是"Pangu 自己之间"的竞争，**不改变**下面两条，它们仍然是必须书面回答的部分：

- **Pangu 之外的写入者**（编辑器、构建、同步盘、CI、其它工具）不遵守这把锁。锁是协作机制，不是 OS 强制。对这些写入者，Pangu 仍只能靠 digest/CAS **检测**漂移，**检测不是预防**。
- **锁超时后的处置**：持锁进程崩溃会让锁文件永久残留，等待者到期后按失败关闭处理并把持锁者身份报出来（**不会**删除锁文件）。这一条落到 operator 流程上就是：**谁在看到这个错误后去核实并手工清理锁**，以及多久内响应。这是 §9.2 必须写明的第 5 题的一部分。

因此第 2 题现在的准确问法是：**除 Pangu 之外还有谁在写这个 workspace，以及你们靠什么流程保证恢复期间它们不在写。**

**留证**：一份带日期、部署环境标识和签署人的书面记录（变更单或仓库内文档均可），并在 §8.1 下方引用其位置。

### 9.3 恢复期间的备份与独立审计可用性（依赖部署环境）

在**真正需要恢复之前**验证，不是出事时才发现备份不可用。

**怎么做**：在目标平台造一次真实的 checkpoint，然后：

```bash
# 1. 留一份恢复前的只读副本与校验记录（Artifact root + workspace + Journal）。
pangu artifact inspect --root <artifact_root> --json > inspect-before.json

# 2. 执行一次真实 rollback（走完整 L1-L4，含人工批准）。

# 3. 再检查一次，确认 store 仍为 verified。
pangu artifact inspect --root <artifact_root> --json > inspect-after.json
```

**要确认的三件事**：

1. **备份可读**：副本能在**不依赖原机**的情况下打开，且 `artifact inspect` 在其上仍报 `verified`。
2. **审计独立于工作机**：Journal 与报告存到了工作机之外的位置。若两者都在同一块盘上，介质故障会同时带走恢复点和审计链——那等于没有审计。
3. **保留期**：§5 要求"不要删除历史记录来清理状态"。确认保留期长于事故响应窗口，且**不会被日志轮转或清理策略自动删掉**。

**留证**：三次 `artifact inspect --json` 的输出（before / after / 副本），加上备份位置与保留期的书面说明。

### 9.4 签署

前三项齐备后，由 operator/发布负责人明确批准。**未签署前继续标为实验性 opt-in**，README/BOUNDARY/ROADMAP 三处措辞不得提前改动（那是边界漂移）。

签署须同时更新：

- §8 的 `[ ]` → `[x]`，并在 §8.1 表格补齐平台行；
- `README.md` 的"实验性 Checkpoint / Rollback"小节（当前明确写"默认关闭，仍是实验性 opt-in"）；
- [`BOUNDARY.md`](BOUNDARY.md) §7 末段与第 4.1 节的适用范围说明；
- [`ROADMAP.md`](ROADMAP.md) F7 条目与 §0 的状态描述。

这四处是**同一个事实**的四种表述，必须一起改；只改一处即为边界漂移（BOUNDARY §7）。

## 10. 已知覆盖边界（不因激活而消失）

激活改变的是"默认开关与支持声明"，**不改变**以下事实，激活后仍须如实陈述：

- 应用层限制，不是 OS 级隔离；不承诺抵御蓄意恶意代码或内核权限对手。
- 不持有 Artifact lock 的并发 writer 只能被 digest/CAS **检测**，不能被阻止。
- rollback 不执行外部补偿、Git、网络、子进程或连接器。
- Windows replacement hand-off 与 stale lock 仍需 operator 介入，不自动猜测。
- Git backend 未实现；不会隐式创建 commit/branch/tag/stash 或改 index。

## 11. 验收中发现的平台差异：exclude_roots 的诊断措辞（已修复）

`plan-a` 上 CI 曾连续 7 次出现 **ubuntu 失败 / windows 通过**，失败的测试是 `test_support::tests::an_exclusion_outside_the_workspace_is_rejected`。这不是测试环境问题，是产品在两个平台上对同一份配置给出不同结论。

**根因**：`exclude_roots` 的校验先调用 `absolute_path_from`，而它对 `..` 一律报 `parent traversal is not allowed`，于是配置拼写里带 `..` 的规则会在"是否逃逸工作区"的包含性检查之前就返回。

**为什么只有 Linux 暴露**（最小 rust 程序实测，非推断）：

```text
canonicalize(".") = \\?\F:\github\dove-home-team\PanguAgent

base=\\?\F:\...\ws   join("../elsewhere") -> \\?\F:\...\elsewhere
  has ParentDir component = false        ← .. 被静默折叠
base=/tmp/ws         join("../elsewhere") -> /tmp/ws/../elsewhere
  has ParentDir component = true         ← 保留，提前被拒
```

Windows 的 `\\?\` verbatim 前缀让 `..` 在 `join()` 阶段就被折叠掉，因而走到包含性检查、拿到正确消息、测试通过——**而且是靠路径折叠碰巧通过的**；Linux 保留 `ParentDir`，提前被拒。

**修复**：在 join/canonicalize 之前，按配置里的**原始拼写**判断是否逃逸工作区；原始拼写的 components 来自字面量，两个平台一致，判读不再依赖宿主行为。只用 `..` 判定，**不能**用 `is_absolute()`——契约本身会把 `exclude_roots` 归一化成绝对路径再重新校验，拒绝绝对路径会打断所有合法配置（工作区**内部**的绝对路径是合法的）。

**没有放宽任何安全检查**：`absolute_path_from` 仍对 `..` 报错，traversal 相关测试仍全绿；改的只是该字段在"逃逸工作区"时的诊断措辞。

**遗留教训**：这个失败存在了 7 次运行才被处理，说明 CI 结果当时没有人在看。加验收清单不会改变这一点——**红灯必须有人负责**，否则清单只是纸面合规。

相关设计边界见 [`BOUNDARY.md`](BOUNDARY.md)、[`ARCHITECTURE.md`](ARCHITECTURE.md) 和 [`adr/0001-checkpoint-rollback.md`](adr/0001-checkpoint-rollback.md)。
