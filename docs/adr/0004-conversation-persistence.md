# ADR-0004：会话持久化与恢复（conversation persistence / resume）

- 状态：已批准（用户指示"走 A1b 路线"）
- 日期：2026-09-26
- 关联：A1 会话树与恢复；R1 完成门"不泄露 secret"与"崩溃后不重复副作用"
- 依赖：[ADR-0001](0001-checkpoint-rollback.md)（输出永远不是授权、默认拒绝）、[ADR-0002](0002-explain-policy-simulation.md)（解释不是授权）、[ADR-0003](0003-event-stream-contract.md)（派生投影不具权威）

## 1. 背景与问题

ROADMAP 把 A1 写成"支持 resume、branch、fork、compaction；每个节点可回放"。勘察后发现这个描述掩盖了两个不同的东西，其中一个**今天并不存在**：

**`SessionNode` 树记的是工作区快照，不是对话。** `SessionNode` 有完整的 `parent_session_node_id`/`checkpoint_id`/`event_ref`，`ArtifactStore` 也能存取节点。但 `Agent::run()` 的 `history` 每次都在内存里从零构造（`pangu-agent/src/lib.rs` 的 `let mut history = vec![...]`），**没有任何持久化**。所以：

- "恢复工作区到某状态"= F7 的 rollback，已经做完；
- "恢复对话继续聊"= **无法实现**，因为没有可续的消息历史。

**Journal 也不足以重建对话。** `ModelRequest` 只写 `messages=2 tools=7` 这样的计数，`ModelResponse` 只写 `"provider response received"`，都不带消息内容，也没有 `payload`。历史无法从 Journal 回放。

**附带发现：`history_digest` 是死字段。** `SessionNode` 声明并校验它（`pangu-core/src/checkpoint.rs`），但全仓库没有任何一处赋非 `None` 的值。本文曾写“本 ADR 开始给它真正的含义”——**这句是错的**：真正被赋值的是 `ConversationSnapshot.history_digest`，那是一个新结构上的新字段；`SessionNode.history_digest` 截至本文**依然没有任何非 `None` 赋值**，仍是死字段（现状见 §7 实现状态末尾）。

## 2. 决策

新增**可持久化的对话表示**，存进 Artifact store（不是新造一套存储），支持精确 resume 与**显式**压缩。

用户在 A1a/A1b 之间选择 A1b 直接做。本 ADR 仍依赖 A1a 的产出作为前提：**先能沿节点链回放，才谈得上压缩历史**。因此本 ADR 的第一阶段交付树导航（祖先/子节点/公共祖先/按 checkpoint 定位），因为压缩要记录"压缩了哪些节点"，没有链结构就无从记录。

### 2.1 存什么：全量消息 + 显式压缩

- **默认全量**。resume 后模型看到与原会话完全一致的上下文。
- **压缩必须是显式的、用户发起的**，并留下 `compacted_from_digest` 让压缩本身可验证。**绝不静默压缩**——静默压缩会毁掉可回放性，而可回放性是 A1 的核心承诺。
- 摘要由 provider 生成，但**摘要本身不是授权**：它只影响模型看到的上下文，不影响任何门禁。

## 3. 准入模板

```text
ID：A1 会话持久化与恢复
用户价值：任务中断后能继续，而不是从头再来（省钱省时）；长会话不被上下文窗口
      撑爆；会话可回放可审计；fork 出的分支能独立推进而不互相覆盖；

不做什么（价值之外）：不做跨机器/跨用户同步；不做协作编辑；不把对话历史当审计
      记录（审计仍是 Journal）；不做隐式自动压缩；不让 resume 跳过任何门禁；

影响面：新增 ConversationSnapshot 概念（pangu-core）+ Artifact store 存取方法
      + agent 侧 save/restore 钩子 + CLI；门禁路径零改动（resume 后仍走完整
      Policy → Sandbox → Approval）；`ConversationSnapshot.history_digest` 开始
      被真正赋值（`SessionNode.history_digest` 仍为死字段，见 §1 附带发现）；

数据/隐私：对话内容经 redact_text/redact_value 脱敏后存储；单条与总体积有界；
      不存凭据原值；导出时受 A5 的隐私检查约束；
失败/重试/恢复方式：写入失败整体失败，不静默；读取时 digest 不符即拒绝；
      损坏的历史不得被当作空历史继续运行（否则等于静默重置会话）；
威胁模型和红队用例：
  T1 用 resume 绕过门禁：恢复的历史只影响模型输入上下文，不携带任何已授权状态；
      invariants 断言恢复路径不产生已授权的 Decision/Effect；
  T2 篡改历史：ConversationSnapshot 带内容 digest，读时校验，不符即失败；
  T3 历史注入 secret：存储前脱敏，单测断言凭据不落盘；
  T4 损坏历史被当作空历史：这会让"恢复失败"变成"静默重开会话"，必须显式失败；
  T5 半截压缩：压缩必须原子，且记录 compacted_from_digest，压缩中途失败不留
      半成品。
兼容性：新增概念，不改 Journal 格式；SessionNode.schema_version 保持 1
      （新增字段全部 optional），旧节点仍可读。
验收 evidence：单元测试覆盖存取往返、digest 校验、篡改拒绝、脱敏、损坏拒绝、
      压缩记录出处；invariants 增加"resume 不携带授权"的断言；
      cargo test --workspace --all-targets --all-features 与 clippy 通过；CI 双平台通过。
许可证/第三方依赖审查：无新依赖。
```

## 4. 设计

### 4.1 存储位置

存进现有 Artifact store，新增 `ConversationSnapshot` artifact 类型，与 checkpoint 共用内容寻址、进程锁、`reject_symlink_components` 和 digest 机制。**不新造存储**：新存储意味着新的完整性语义，而复用 F7 那套已经过了 operator drill 的机制成本低得多、风险小得多。

### 4.2 数据形状

```text
ConversationSnapshot {
  schema_version, snapshot_id, session_node_id?, run_id,
  messages: Vec<Message>,          // 已脱敏
  history_digest,                  // 内容摘要，resume 时校验
  compacted_from_digest?,          // 压缩出处；非空即说明这是一次压缩的产物
  created_at
}
```

`history_digest` 由此**第一次**被真正赋值，`SessionNode.history_digest` 从死字段变成有效引用。

### 4.3 resume 的门禁保证（本 ADR 最重要的一条）

**恢复的历史只影响模型输入，不携带任何已授权状态。**

恢复出来的 `messages` 会进入 `history` 并被送进 provider，仅此而已。它不携带：
- 任何 `Decision`/`Effect`；
- 任何"这个工具已经被批准过"的记忆；
- 任何可以跳过 `Policy → Sandbox → Approval` 的凭据。

恢复后第一次发起工具调用，走的仍是完整四层。这与 ADR-0001、0002 的立场一致：**模型输出永远不是授权**，历史是模型的输入，因此历史也永远不是授权。

实现上必须保证 `messages` 只能流向 provider 的 `chat(history, specs)`，不能流向任何判定路径。invariants 断言这一点。

### 4.4 压缩

显式、原子、留痕：

1. 用户显式发起（CLI 或 API），无自动触发；
2. 生成摘要 + 保留尾部若干轮；
3. 写入新 `ConversationSnapshot`，带 `compacted_from_digest` 指向压缩前的内容摘要；
4. 失败则整体失败，不留半成品。

压缩后**原历史仍可从 Artifact store 读回**（内容寻址，不删除），所以压缩损失的是上下文体积，不是可审计性。

## 5. 与"模型输出永远不是授权"的关系

见 4.3。这是本 ADR 唯一真正危险的地方：resume 是最容易"看起来像可以信任的旧状态"的特性。因此 ADR 把它写成硬约束而不是设计描述，并由 invariants 守护。

## 6. 后续（不属于本 ADR）

- fork 的**工作区隔离**未在本 ADR 解决：两条 fork 分支共享同一工作区必然互相覆盖。要么给每个 fork 独立工作区（要动 checkpoint 的 workspace 绑定），要么明确限制 fork 只能在未改动状态下做。这是 A1 剩余的主要工作。
- 跨机器同步、协作编辑：明确不做。
- A5 的导出隐私检查会作用在 `ConversationSnapshot` 上。

## 7. 实现状态

### 7.1 第一阶段：对话表示

已实现（`crates/pangu-core/src/conversation.rs`，12 个单元测试含 3 个 store 往返测试）：

| 项 | 状态 | 证据 |
| --- | --- | --- |
| `ConversationSnapshot` 概念 | 完成 | 闭集 + `deny_unknown_fields`，`schema_version` |
| 存储前脱敏 | 完成 | `redact_messages` 覆盖四种 `Message` 变体，含 `ToolCall.args` 经 `redact_value`；单测断言凭据不落盘 |
| 内容 digest 读时校验 | 完成 | `digest_of` / `validate`；store 往返 + **磁盘篡改被拒**两例 |
| 空历史拒绝恢复 | 完成 | 单测 `an_empty_history_is_refused_rather_than_restored_as_a_fresh_session` |
| 快照不可变 | 完成 | 重复 `snapshot_id` 写入被拒，保护压缩出处链可解 |
| 显式压缩 + 出处 | 完成 | `compacted()` 产出新 `snapshot_id` 并记 `compacted_from_digest` / `dropped_messages` / `kept_messages` / `summary` |
| 压缩防空洞 | 完成 | 空摘要被拒；未丢弃任何内容的压缩被拒；伪造的 `dropped_messages: 0` 记录被拒 |
| store 存取 | 完成 | `save_conversation` / `load_conversation` / `list_conversations`，复用 store 的锁与 symlink 拒绝 |
| 体积与条数边界 | 完成 | 8 MiB 总量 / 10,000 条 / 单条 256 KiB |
| "恢复不携带授权"（表示层） | 完成 | `invariant_i_resumed_conversation_carries_no_authorization`：断言恢复值只有 `Message`、消息形状无 `effect`/`decision`/`approved` 等字段、把恢复文本喂回 `Policy::evaluate` 时判定仍来自规则或不变量而非历史内容 |


> **路线变更（2026-10-03，随 A6-3 落地）**：本 ADR 的"显式压缩 + 出处"不再是会话级主路线。`compacted()` API 与其测试保留，但语义降级为"某个切片摘要的一种降级模式"（ADR-0005 §3.1/§3.3 已确认）；重启路线由 ADR-0005 的切片组装取代。

**实现中发现并修正的一个真 API 缺陷**：`compacted()` 最初沿用原 `snapshot_id`，而 store 的不可变检查会直接拒绝——等于**压缩产物永远存不下来**，而这正是压缩存在的理由。已改为必须显式传入新的 `snapshot_id`（复用同一个 id 时直接报错），并在文档里说明原因：改写会毁掉新记录声称所来自的那份历史。

### 7.2 第二阶段：接入 agent 运行循环

第一阶段完成后，保存的对话没有任何东西会写入或读取它——`Agent::run()` 每次从零构造 history。现在这条链接通了。

| 项 | 状态 | 证据 |
| --- | --- | --- |
| 配置开关 | 完成 | `ConversationSection { enabled, artifact_root, save_every_turn }`；默认 `enabled: false`。`old_config_without_conversation_section_loads_with_defaults` 断言**缺段即关闭**——老配置升级后不会突然开始写文件 |
| contract 绑定 | 完成 | `GoalContract.conversation`，与 checkpoint 同样的 canonicalize 处理：仅当启用时解析 `artifact_root` |
| 运行期写入 | 完成 | `ConversationRuntime::save`，每轮 turn 结束（`save_every_turn`）与**终局无论成败**各存一次。错误上抛不静默 |
| 恢复入口 | 完成 | `Agent::resume_from(&ConversationSnapshot)` / `resume_latest` / `resumable_conversations`；恢复时**不再重复 seed** system+goal |
| 恢复前校验 | 完成 | `validate_resumable`：首条必须是 `Message::System`，空历史报错。缺 system 轮 = 恢复进一个从没被告知边界的上下文 |
| CLI | 完成 | `pangu conversation list` / `show [--json]`；未启用时明确报"关闭"而不是显示空列表 |
| "恢复不携带授权"（端到端） | 完成 | `invariant_i_resume_continues_the_conversation_but_re_evaluates_every_action`，三个性质一起断言（见下） |

**接进运行循环后抓到的两个真问题**：

1. **快照 id 里写进了未脱敏的目标文本。** 最初用 `self.contract.goal` 作 id 的一部分，于是 `conv_读取 Cargo.toml 并报告包名_...json` 这样的文件名出现在磁盘和 `ls` 输出里。journal 对 goal 明确做了 `redact_text`——把同一段文本原样放进**路径**等于撤销了那条规则。改为 `short_hash(redact_text(...))`。
2. **`max_turns = 1` 的运行会丢弃模型的第一条响应。** 写测试时发现存下来的历史只有 `[System, User]`。原因不在新代码：`run_inner` 在收到响应后、把它并入 history **之前**就检查 `budget_breaches(turn, ...)`，而 `Breach::Turns` 的判据是"已完成的轮数 >= 上限"，所以上限为 1 时第一条响应刚到手就被判定超预算并丢弃。测试改用 2。**未改动这处行为**——它是既有设计，且与本次目标无关，但记在这里以免下次再被绊住。

**"恢复不携带授权"的端到端证据**（`invariant_i_resume_continues_the_conversation_but_re_evaluates_every_action`）一次断言三个性质，缺一不可：

- **续上了，不是重开**：provider 被调用时收到的是**恰好 6 条**已存消息。恢复若偷偷重新 seed，发的会是 8 条（system+goal 又来一遍）。这一条从 provider 侧读实际看到的消息条数，不看"运行有输出"这种间接信号。
- **恢复后的动作重新过闸**：第一轮拿到 `AllowOnce` 写入了 `one`；恢复后的运行**没有**任何审批，规则是 `ask`。工作区仍是 `one`，且事件流里有 `ToolBlocked`（理由写明 `human approval was not granted`）、**没有** `ToolFinished`。
- **模型不能把被拒的运行说成完成**：恢复后的第二轮脚本调用了 `finish {"status": "complete"}`，运行仍报 `failed`、evidence 为空。

### 7.3 第三阶段：树导航与每节点回放

| 项 | 状态 | 证据 |
| --- | --- | --- |
| 账本列举 | 完成 | `ArtifactStore::list_session_nodes()`；`MAX_SESSION_NODES = 100_000` 上界。**解析失败即报错而不是跳过**——静默丢一条分支会让"这里发生过什么"答错 |
| 树导航 | 完成 | `session::SessionTree`（`crates/pangu-core/src/session.rs`，7 个单测）：`roots` / `children` / `ancestors` / `common_ancestor` / `by_checkpoint` / `render` |
| **环检测** | 完成 | `ancestors()` 双重限界：visited 集合 + 步数上限。账本是手改的 JSON 目录，`parent` 指回祖先就会让朴素遍历**永久挂死**；现在按损坏账本报错。`render()` 同样有环保护 |
| **孤儿不隐藏** | 完成 | `orphans()` + `ensure_complete()`。缺失的 parent **不提升为 root**——否则一次停在缺口上的遍历，看起来和一次走到历史开头完全一样 |
| 对话挂到节点 | 完成 | **接线前 `run_inner` 两处都传 `None`**，`session_node_id` 参数是死的。已接上 `checkpoint_state.session_node_id`；`invariant_i_a_saved_conversation_names_a_session_node_that_exists` 钉住 |
| 每节点回放 | 完成 | `ConversationRuntime::at_node` / `replay_at`；只返回 `Vec<Message>`，**不恢复工作区**（那是 `pangu rollback`），`invariant_i_replaying_a_node_restores_no_workspace_and_grants_nothing` |
| CLI | 完成 | `pangu session tree [--json]` / `pangu session replay NODE [--full] [--json]`；checkpoint 关闭时明确报错而非列空树 |

**抓到一个真实结构缺口：运行根节点从不落盘。**

`SessionNode` 只在**提交检查点**时写进账本，而 `node_root_…` 只存在于 `RunCheckpointState` 内存里。结果是每次普通运行产生的树都**恰好有一个孤儿**：首个提交的节点其 parent 指向一个不在账本里的 id。

- **不影响 rollback**：`rollback_transition_node_id` 是输入的确定性哈希（`hex_sha256(run_id:checkpoint_id:source_node:rollback_id)`），不查账本。账本原本就是为 rollback 记账设计的（见 `load_session_node_by_id` 的注释），不是为浏览而设计的。
- **修不了**：`EventRef.event_id` 是**写 Journal 时才分配**的（`events.rs:264`），运行开始时拿不到真实 event id。给根节点编一个就是在可审计结构里塞假值，所以不编。
- **处理方式**：`SessionTree` 如实报告缺口（`orphans()` / `ensure_complete()` / `render()` 标注 `orphan`），CLI 打 `WARNING`，`session replay` 直接拒绕。`invariant_i_a_session_tree_with_a_missing_root_is_reported_not_hidden` 钉住这个行为。
- **待决**：要么接受"运行起点不可回溯"（F7 契约不动），要么改 F7 让 `EventRef` 在事件发出时就分配 `event_id`（影响 Journal 写入路径，F7 仍为 `provisional`）。

**CLI 接线时发现的两个既有 bug（非本次引入，均已修）**：
- ① `demo()` 只应用了 `CliOverrides { unattended: true }`，**没应用 `--checkpoint` / `--no-checkpoint`**。用户要求了却没得到，**连警告都没有**，而且两个方向都错：`pangu --checkpoint --demo` 静默不开检查点，`--config cfg(enabled=true) --no-checkpoint --demo` 静默照开。
- ② 曾记为“自定义相对 `checkpoint.artifact_root` 会让 `--demo` 报 `checkpoint creation failed`”——**这条描述是错的，已纠正**。真实原因：快照遍历整个工作区，而默认 `forbidden_globs` 只有 `.git` / `.env` / secrets / 私钥，**不排除构建产物**，本仓库动辄数 GB 的 `target/` 必然撞上 64 MiB 上限。与 `artifact_root` 写相对还是绝对**无关**——用默认的 `.pangu/checkpoints` 一样失败。修法是新增 `checkpoint.exclude_roots`，并把超限错误改成指出具体是哪个文件越界。

**本阶段未做**：`branch` / `fork`。**fork 的工作区隔离完全未解决**，见第 6 节。`SessionNode.history_digest` 依然是死字段——现在有真实的节点与对话可供它记录，赋值仍待做。
