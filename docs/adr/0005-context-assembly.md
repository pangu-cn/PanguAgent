# ADR-0005：无限上下文（切片与组装）

- 状态：草案（未实现；§3.1 与 §3.3 已于 2026-10-03 经用户确认）
- 相关：[ADR-0001](./0001-checkpoint-rollback.md)、[ADR-0003](./0003-event-stream-contract.md)、[ADR-0004](./0004-conversation-persistence.md)
- ROADMAP：A6

---

## 1. 背景与问题

Pangu 今天的上下文处理不是裁剪，是**终止**。

`crates/pangu-agent/src/lib.rs` 有三处独立的预算检查点会推送 `Breach::InputTokens`：

| 位置 | 时机 |
| --- | --- |
| `:1289` | 每轮开始前，估算 `estimated_input` |
| `:1379` | 收到模型响应后、工具调用前 |
| `:1489` | 每轮结束时 |

任一命中即 `terminal = Some(GoalStatus::BudgetExhausted)` 并 `break`。默认阈值 `budget.max_input_tokens = 200_000`。

结果是：长任务只有两种结局——塞得下，或者死。没有"只发一部分"这个中间态。

存储侧也有硬界（`crates/pangu-core/src/conversation.rs`）：

```text
MAX_CONVERSATION_BYTES        = 8 MiB
MAX_CONVERSATION_MESSAGES     = 10_000
MAX_MESSAGE_CONTENT_BYTES     = 256 KiB
```

这些界是为了防止病态输入和静默截断，但它们和模型上下文窗口是两回事：用户想让**本地留存**不受模型窗口限制，而不是让运行在撞到窗口时终止。

## 2. 目标

1. 会话历史在本地全量留存，**不受模型上下文窗口限制**。
2. 每一轮只把**当前需要的**切片组装进 prompt。
3. 返回的内容能并回总上下文，且**可回溯、可审计、不可静默篡改**。

## 3. 决策

### 3.1 A6 为主路线，compaction 降级（**已确认**）

A1b 路线（全量 + 显式压缩）与 A6（全量留存 + 按需切片）是同一问题的两种解法：

| | A1b compaction | A6 切片组装 |
| --- | --- | --- |
| 性质 | 有损但连续 | 无损但非连续 |
| 原文 | 压缩后不再存在，只留 `compacted_from_digest` 指针 | 一直存在，可反复取不同切片 |
| 可回放 | 否（压缩前的内容没了） | 是（切片留在 store） |

**决策**：A6 为主路线。`ConversationSnapshot::compacted()` 降级为"某个切片摘要的一种降级模式"，不再是会话级一次性压缩。

> **已确认（2026-10-03，用户拍板）**。这条改变了已实现并已测试的 A1 语义：`compacted()` 的现有代码与测试保留，但它降级为切片摘要的一种降级模式，不再承担会话级压缩路线。实现 A6-3 时同步更新 ADR-0004 的相关表述。

### 3.2 "需要哪个"不由模型决定

**决策**：组装 = 不可协商强制集 + 模型请求集。

```text
assembled = FORCED ∪ requested(model)

FORCED = { system 轮, goal, 被拒路径 (failed paths),
           未完成的工具调用, 最近 N 轮 }
```

模型只能*请求*追加切片，**不能排除**任何切片。

理由：模型若能裁剪输入，就能裁掉 system 轮（边界指令所在），也能裁掉"上次这个操作被拒了"的历史然后重试——那正是 `invariant_i_failed_path_not_repeated` 存在的理由。"模型输出永远不是授权"（§1 硬约束）有一个镜像版本：**模型输入同样不该由模型裁剪**。

`AssemblyReport` 逐片记录：来源 `slice_id`、被选中的理由（`forced:<which>` / `requested` / `budget-降级链位置`）、估算 token。报告进事件流。

### 3.3 写回：本 ADR 采用读法 (a)，切片改写写回推迟到 B3（**已确认**）

"返回的上下文"有两种读法，档次差很多：

- (a) 模型的**正常新消息**（今天已有，`finish`/tool result 就是）；
- (b) 模型**改写后的切片内容**写回本地 store。

**决策（2026-10-03，用户拍板）：按读法 (a)。** 写回就是模型的正常新消息，沿用现有 append-only 的 history 追加路径，不需要新的存储原语。**A6-4 子阶段删除。**

(b) 没有消失，只是**推迟到 B3（受控记忆候选队列）一起议**：模型改写的切片内容是**候选**，不是事实，与 B3“模型只能提出，用户/策略确认后写入”是同一条原则，分开做会把同一套护栏写两遍。届时若实现 (b)，护栏必须是：

- 写回只能**追加**为新切片，原切片不可变；
- 每条写回记 `derived_from`（源 `slice_id` + 版本号）；
- 写回内容显式标 `unverified`——它没过 `Policy` / `Sandbox`；
- 扩展 `invariant_i_resumed_conversation_carries_no_authorization`，断言 `unverified` 切片不能单独构成"已验证"输入。

这些要求移入 B3 的准入条件，本 ADR 不再承载。`SliceEntry.unverified` 字段保留在 schema 里（恒为 `false`），为 (b) 预留，不实现行为。

### 3.4 `无限` 的诚实边界

**能给的**：本地留存不受模型上下文窗口限制。
**给不了的**：字面意义的"无上限"。

三个存储界改为**可配置且默认大幅提高**（建议 512 MiB / 100,000 条 / 单条 256 KiB 不变），但**保留上界**：

- 无上界则无法回答"这次运行花了多少"（G4 成本有界）；
- 保存失败要上抛（不静默截断），无上界意味着失败点不可预期；
- 病态循环可以写爆存储。

上界进 `pangu doctor` 报告。

**超出切片预算时仍然会终止。** 降级链是 `full → summary → omit-with-reason`，降到无可降级时必须死。**不允许存在"永不终止的运行"。**

同 §1 已有规矩（"不能把项目目录误认为安全沙箱；应用层限制不能宣传成 OS 级隔离"）："无限上下文"是**营销名**。README、CLI 输出、报告字段都不得出现暗示无界可验证性的措辞。

### 3.5 三个存储物：上下文文件、摘要文件、切片文件

切片机制是 **Pangu 自己的主要功能**，不是外部能力、不是模型能力。落成三个文件：

```text
<root>/contexts/<id>.json     ← 上下文文件：全量正文，一条消息一行（A6-0 布局）
<root>/summaries/<id>.json    ← 摘要文件：一条消息一个摘要条目
<root>/slices/<id>.json       ← 切片文件：映射表
```

**切片文件是映射表**——把全量上下文映射成切片，每条切片带自己的位置与摘要：

```text
SliceEntry {
  slice_id
  start_message / end_message   // 切片是 **span**，可跨多条消息
  start_line / end_line         // 消息内容内的行范围
  range_digest                  // 该范围字节的 digest
  kind                          // turn / refusal / tool_burst / phase …
  summary                       // 该切片的摘要
  derived_from                  // 引用了哪些 message_index（它覆盖哪些摘要条目）
  verbatim                      // 该 slice 是否逐字取用
  unverified                    // 仅模型写回内容为 true
}
```

摘要文件的条目是 `SummaryEntry { message_index, file_line, start_line, end_line, range_digest, kind, summary }`，一条消息一个。

**为什么是三层而不是一个文件**：三者**访问模式不同**，合成一个就有一方被迫整体载入。

| 存储物 | 谁读 | 访问方式 |
| --- | --- | --- |
| 摘要文件 | 粗筛 | 遍历**全部**条目，只读摘要 → 需要整体进内存，但要小且有明确上界 |
| 切片文件 | 组装 | 只读**选中**的几条 → 不需要整体载入 |
| 上下文文件 | 拼接 | 只读选中切片的行范围 → 按范围取，不载入全量 |

**切片是 span，不是单条消息。** 单条消息作为选择单元太细——一条 256 KiB 的工具输出、一次 `finish` 回执，都不是有意义的选择粒度。切片跨消息成段（一个 turn、一段工具调用风暴、一个被拒路径），`derived_from` 记录它由哪些 `message_index` 聚合而来，这正是"映射表"可审计的含义。

**digest 绑定语义：绑定"会话前缀"，不是"某个快照版本"（2026-10-03 已确认）。** 勘察后发现原文的写法不成立：`ConversationRuntime::save` 每次保存都生成**新的 snapshot_id**（时间戳+序号），`save_every_turn = true` 时上下文文件每轮换一份，若切片绑定单份文件的 `context_digest`，绑定**每轮失效**。

修正后的绑定：history 在运行内严格 append-only、行号只增不减，所以切片/摘要绑定的是**会话的消息前缀**——记录 `prefix_digest`（前 `message_count` 条逻辑消息的 `digest_of`）与 `message_count`，而非整份文件的 digest。加载时按前缀重算校验，对不上就报错——**不重新生成、不静默接受**。新追加的消息在 `message_count` 之后，不使既有切片失效；追加后需要新的摘要/切片时增量生成。摘要文件同样记 `prefix_digest` + `message_count`，与切片文件成对绑定。重新生成会掩盖"切片与正文对不上"，而那正是切片唯一可能说谎的地方。

落盘形态：`contexts/<id>.json` 沿用 A1 的快照文件（每次保存一份，不可变）；摘要/切片文件按会话 id（共享同一消息前缀的快照链）存放，加载时对**当时最新**快照重算前缀校验。

**两级寻址，不能只用行号**：`message_index` 解决"哪一条消息"；`start_line/end_line` 解决"这条消息内部"——单条工具输出可达 `MAX_MESSAGE_CONTENT_BYTES = 256 KiB`，一条消息一行的话仍然切不开。内容行是**读时按 `\n` 切分**得到的，确定性，不需要再改存储格式。

**取用流程**：切片文件选中条目 → 到上下文文件按范围取行 → 校验 `range_digest` → **衔接**拼接（接缝见 §3.7）。

**摘要器的质量规格**（升格为主要功能后要自己扛）：确定性、可复现、有单测、每条摘要带 `derived_from` 指向它描述的 `message_index`。它**不接触模型**。

### 3.6 laya 只能做短决策，所以它不承重

**已确认的限制：laya 只能做短决策。** 由此直接排除三件事：

1. **不能用 laya 生成摘要。** 把上下文装进一次短决策在物理上就不成立。摘要器必须是 Pangu 自己的确定性功能（§3.5）。
2. **不能用 laya 做粗筛。** 粗筛要遍历全量摘要，那不是短决策。粗筛是本地确定性逻辑（按 `kind` / 时间窗 / 被拒路径 / 最近 N 轮）。
3. **不能用 laya 决定强制集、写回或终止。** 同 §3.2/§3.3。

于是 laya 在整条链上只剩**一个位置，而且是最末端那一步**：

```text
粗筛（本地、确定性、便宜）：kind / 时间窗 / 被拒路径 / 最近 N 轮 → 短名单
    ↓
laya（短决策）：短名单里哪几片真的相关
    ↓
组装（本地、确定性）：FORCED ∪ laya 结果，逐片记选取理由
```

**关键性质：删掉 laya，上面整条链依然完整可用**，只是相关性从"模型判断"退化为"启发式"。粗筛产出的短名单就是合法输入，组装器不需要知道它从哪来。

这比 §B6 原有的"不得成为核心启动依赖"更强：B6 只要求 laya 不可用时能 fallback，这里要求**根本不需要它**。A6-6 因此是纯增强项，删掉它不损失任何能力。

**摘要是升格后的主要功能，规格自定**：确定性抽取（首 N 行 / 工具名 / 错误行 / 计数 / 失败类别），可复现、可测试、**不需要标 `unverified`**。不选模型生成，是为了避开"污染的摘要一路传播"这一整类问题——这个设计并不需要它。

### 3.7 衔接必须留可见接缝

把 turn 3 的片段和 turn 7 的片段拼成一条消息发给模型，模型会看到**一条从未发生过的连贯对话**。若 turn 7 的工具调用正好拼在 turn 3 的用户消息之后，模型可能以为自己已经执行过。

这是 §3.2 的**新变种**：不是模型裁掉自己的边界，而是我们**喂给它一段伪造的连贯历史**。

**决策**：

- 每个接缝显式标记，模型能看到这里是拼接的；
- 组装结果整体标 `derived: true` / `authoritative: false`（与 A2 事件流同一套纪律）；
- 不标接缝的话 `invariant_i_failed_path_not_repeated` 的证据链会断——被拒路径虽在强制集里，但周围被拼成一段看似正常的对话时，模型看到的就是"这里没发生过什么"。

### 3.8 配对完整性（勘察新发现的硬约束）

**问题**：OpenAI function-calling wire format 要求每条带 `tool_calls` 的 assistant 消息之后必须紧跟对应的 `Tool{call_id}` 结果消息。切片按 span 裁剪时，若保留了 assistant 的调用却裁掉了它的结果（或反过来），provider 直接返回 400——组装结果不只是"不连贯"，而是**协议非法**。

**决策（配对不变量）**：组装器必须保证每个 `tool_calls[i]` 与其 `Tool{call_id}` **同进同出**：

- 选中某切片时，若其含带 `tool_calls` 的 assistant 消息，必须同时包含对应的全部 `Tool` 结果消息（可能跨出原 span，需扩展选取范围并在 `AssemblyReport` 记为 `forced:pairing`）；
- 反之，孤立的 `Tool` 结果消息（其 assistant 调用未被选中）不得单独进入组装结果；
- 强制集里的"未完成的工具调用"是唯一允许的**有调用无结果**形态，且必须与真实 history 中的形态一致，不能由组装器伪造配对。

这条必须有独立不变量测试（构造跨切片边界的 tool burst，断言配对完整），否则 A6-2 不能验收。

### 3.9 组装器必须能纯内存工作

`conversation.enabled` 默认关闭。组装器不得依赖持久化：对当前内存 history 做与 `encode_linewise` 等价的逻辑编码即可计算前缀/范围 digest，摘要与切片的持久化只是跨运行复用的优化。**A6 不得隐式依赖一个默认关闭的功能。**

## 4. 现状勘察（实现前必须知道的）

- `crates/` 内**无任何**检索、嵌入或语义相似度能力。唯一的 `summary` 是 CLI 里的运行统计（`main.rs:385` `replay::Summary`），与语义摘要无关。
- `Message` 是无字段的 enum（`role` + 变体载荷），**没有 id、没有时间戳**。切片寻址需要新造，且必须是摘要而不是明文路径。
- 发送上下文的出口**只有一个**：`lib.rs:1312` `provider.chat(history.clone(), specs.clone())`。所有组装逻辑必须收敛到这一处，否则会出现第二个未经审计的出口。
- **快照落盘是 compact JSON，整个文件只有一行**（`save_conversation` 用 `serde_json::to_vec`；实测 1217 字节 / 1 行）。所以 §3.5 的"行位置"**目前还不存在**，必须先把落盘改成"一条消息一行"（`{"schema_version":…,"messages":[
{…},
{…}
]}`）。
  - **向后兼容**：JSON 对空白不敏感，`from_slice` 照常解析旧单行文件，**无需迁移**；新文件多行、旧文件单行可共存。
  - **摘要不受影响**：`digest_of` 哈希的是 `to_vec(messages)` 即**逻辑消息**，不是文件字节，所以换存储格式不作废任何已有摘要。
  - **行号稳定的前提已具备**：`save_conversation` 遇到重名直接报 `already exists and is immutable`，快照严格只写一次。
- **A6-0 已完成**：`conversation::encode_linewise` 让快照落盘变成「一条消息一行」，实测 6 条消息 = 8 行（头 + 6 + 尾）。**向后兼容已验证**：单测用旧编码器 `serde_json::to_vec` 造的文件仍能解析且 digest 完好，无需迁移，两种布局可共存于同一 store。`digest_of` 哈希逻辑消息，所以**没有作废任何已有摘要**。`HeaderRef` 镜像结构是**构造性的维护隐患**（新增字段漏写会静默从盘上消失），由 `header_ref_covers_every_field` 比较键集挡成测试失败。
- **范围完整性需要三道**（整份 digest 不够用）：
  1. 逐范围校验 `range_digest`——否则改了第 500 行，取到的切片是他改过的内容却挂着原摘要；
  2. `range_digest` 与 `summary_digest` 成对绑定——摘要描述 100–200 行，那段变了摘要就在说谎；
  3. 范围记录里带会话前缀 digest（`prefix_digest` + `message_count`，见 §3.5），取用时先对前缀——"不可变"是第一道防线，但不该是唯一一道。

## 5. 子阶段

| 阶段 | 内容 | 依赖 |
| --- | --- | --- |
| ~~A6-0~~ | ~~落盘改「一条消息一行」~~ **已做**（`conversation::encode_linewise`） | A1-1（已做） |
| ~~A6-1~~ | ~~**摘要器**~~ **已做**（`pangu-core::summary`：确定性抽取 + `SummaryEntry` + `prefix_digest`/`message_count` 绑定、三道校验、增量 `extend`；store 落 `summaries/<run_hash>.json`，上下文文件沿用 A1 的 `conversations/` 布局而非新建 `contexts/` 目录） | A6-0 |
| ~~A6-1b~~ | ~~**切片文件（映射表）**~~ **已做**（`pangu-core::slice`：`SliceEntry`、`derived_from`、前缀绑定、§3.8 配对校验、增量 `extend`；落 `slices/<run_hash>.json`） | A6-1 |
| ~~A6-2~~ | ~~组装器~~ **已做**（`pangu-core::assemble`：FORCED∪requested、`close_pairing` 配对闭包、接缝 System 标记 + `AssemblyReport`、`forced_over_budget` 兜底信号、纯内存） | A6-1 |
| ~~A6-3~~ | ~~概要模式：降级链 `full → summary → omit-with-reason`~~ **已做**（`degrade` 逐 slice 分配模式；forced-core 不得低于 Summary，recent/requested 可 Omitted 并入报告与接缝标记；存储界沿用 `conversation.enabled`，随 A6-5 接入） | A6-2 |
| ~~A6-4~~ | ~~写回~~ **已删除**（§3.3 已确认为读法 (a)；切片改写写回推迟到 B3） | — |
| ~~A6-5~~ | ~~接入运行循环：替代 `Breach::InputTokens` 的终止路径，**保留终止作兜底**~~ **已做**（每轮 `assemble` 出窗口送 `provider.chat`；组装失败与 `forced_over_budget` 分两条硬终止；`ContextAssembled` 事件进 Journal/A2 provisional 槽） | A6-3 |
| A6-6 | laya 接入为 A6-2 最末端的**短决策**（纯增强，**删掉不损失任何能力**；默认关闭）。**接缝已做**：`assemble_with(.., selector: Option<&dyn SecondStageSelector>)` + `CandidateSlice` 候选集 + `second_stage` 报告字段（`none`/`selector`/`fallback`）；laya 实现待 B6 | A6-2 + **B6**（未实现） |

A6-5 的关键约束：新组装器**不能**成为"永不终止"的来源。三层降级用尽后必须终止，且终止原因要能区分"上下文确实太大"与"组装器组装不出来"。

## 6. 与其它条目的关系

- **A1**：A6 分叉 A1b 路线（§3.1）。A1-3/6 的 tree 导航不是 A6 的前提——切片单位用 **turn**（一次 user/assistant/tool 交换）即可起步，tree 节点是更优雅的**后续**单位，届时 `SessionNode.history_digest` 死字段可能顺带打通。
- **F1 Repo Map**：F1 已经在做"生成可解释的、显示来源/时效/token budget 的上下文"，本质是"代码库这一类内容的切片"。**F1 应消费 A6 的组装接口**，不要两套"选什么进 prompt"的逻辑并行——那是最容易分叉的地方。
- **B3 受控记忆候选队列**：B3 的原则是"模型只能提出，用户/策略确认后写入"。§3.3 已确认 A6 采用读法 (a)，模型改写切片内容的写回**移交 B3 作为准入条件**——届时按候选处理，护栏清单见 §3.3。
- **A5 会话导出**：A5 扫 secret 时需要覆盖切片 store。
- **A2 事件流**：`AssemblyReport` 与切片选取理由应作为新 kind 进入 `pangu-stream/1`（只增不改）。
- **B6 本地 laya**：laya 在 A6 里只有**一个位置**——A6-2 的第二级相关性判断（A6-6）。B6 已有的约束直接适用且**不放宽**：不得成为核心启动依赖、不得直接创建 `VerifiedAction`、不得改 Policy/预算/审批模式、失败必须确定性 fallback 或 fail closed、请求与失败原因进脱敏事件流。**摘要不经过 laya**（§3.6），因为摘要是确定性抽取。

## 7. 非目标

- 跨机器同步、协作编辑、多 agent 共享上下文。
- 语义检索的"智能"程度（先做确定性可复现的选择；相关性优化是后续独立决策）。
- 替代 Journal 或 A2 事件流——组装是派生投影，**不带哈希链，自身无法自证**。
- 让运行永不终止（见 §3.4）。
- 把摘要做成模型生成的抽象式摘要（§3.6）——会引入"污染的摘要一路传播"这一整类问题，而这个设计不需要它。
- 让模型（laya 或任何模型）决定强制集、写回或终止（§3.2/§3.3/§3.6）。
- 模型改写后的切片内容写回本地 store（§3.3 读法 (b)）——移交 B3，本 ADR 不实现。

## 8. 实现状态

未实现。本文件是草案。§3.1（A6 为主路线）、§3.3（读法 (a)，A6-4 删除）、§3.5（前缀绑定语义）已于 2026-10-03 经用户确认；§3.8 配对不变量与 §3.9 纯内存工作是勘察后新增的硬约束。**A6-0、A6-1、A6-1b、A6-2、A6-3、A6-5 已做；A6-6 接缝已做（laya provider 待 B6）**（摘要器在 `pangu-core::summary`，切片器在 `pangu-core::slice`，摘要/切片文件分别落在 `summaries/` 与 `slices/`，上下文文件仍为 `conversations/`；§3.5 的 `contexts/` 目录本次未照搬——A1 已有布局即上下文文件，未新建第二棵树）。A6-6 本体（laya provider）**推迟**，待 B6 落地后实现 `SecondStageSelector` 即可，组装端不用再改。
