# ADR-0005：无限上下文（切片、组装与写回）

- 状态：草案（未实现）
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

### 3.1 A6 为主路线，compaction 降级（**待复核**）

A1b 路线（全量 + 显式压缩）与 A6（全量留存 + 按需切片）是同一问题的两种解法：

| | A1b compaction | A6 切片组装 |
| --- | --- | --- |
| 性质 | 有损但连续 | 无损但非连续 |
| 原文 | 压缩后不再存在，只留 `compacted_from_digest` 指针 | 一直存在，可反复取不同切片 |
| 可回放 | 否（压缩前的内容没了） | 是（切片留在 store） |

**决策**：A6 为主路线。`ConversationSnapshot::compacted()` 降级为"某个切片摘要的一种降级模式"，不再是会话级一次性压缩。

> **待复核**。这条改变了已实现并已测试的 A1 语义。用户已授权按此默认写入，但确认前不应开始实现 A6-3。

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

### 3.3 写回是 append-only，且标 `unverified`（**待复核**）

模型返回内容写回本地存储，等于**给了模型改本地状态的能力**。这是"模型输出不是授权"的加强版：不是授权了 `Effect`，是篡改了未来的输入。

**决策**：

- 写回只能**追加**为新切片，原切片不可变；
- 每条写回记 `derived_from`（源 `slice_id` + 版本号）；
- `ConversationSnapshot` 整体仍 append-only + digest 校验不变；
- 写回内容显式标 `unverified`——它没过 `Policy` / `Sandbox`；
- 扩展 `invariant_i_resumed_conversation_carries_no_authorization`，断言 `unverified` 切片不能单独构成"已验证"输入。

> **待复核**。"返回的上下文"有两种读法，档次差很多：
> - (a) 模型的**正常新消息**（今天已有，`finish`/tool result 就是）；
> - (b) 模型**改写后的切片内容**写回本地 store。
>
> (b) 才是上面这套护栏针对的场景，也是本 ADR 默认采用的解读。若实为 (a)，A6-4 整个子阶段可删，风险与工作量都低一档。

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

## 4. 现状勘察（实现前必须知道的）

- `crates/` 内**无任何**检索、嵌入或语义相似度能力。唯一的 `summary` 是 CLI 里的运行统计（`main.rs:385` `replay::Summary`），与语义摘要无关。
- `Message` 是无字段的 enum（`role` + 变体载荷），**没有 id、没有时间戳**。切片寻址需要新造，且必须是摘要而不是明文路径。
- 发送上下文的出口**只有一个**：`lib.rs:1312` `provider.chat(history.clone(), specs.clone())`。所有组装逻辑必须收敛到这一处，否则会出现第二个未经审计的出口。

## 5. 子阶段

| 阶段 | 内容 | 依赖 |
| --- | --- | --- |
| A6-1 | 切片存储：`ContextSlice { slice_id, kind, digest, full_body, summary?, derived_from?, verbatim, unverified }`，append-only，复用 `ArtifactStore`；补切片寻址 | A1-1（已做） |
| A6-2 | 组装器：`assemble(forced, requested, budget) -> (AssembledContext, AssemblyReport)`，逐片记选取理由 | A6-1 |
| A6-3 | 概要模式：降级链 `full → summary → omit-with-reason`；切片配置化存储界 | A6-2 |
| A6-4 | 写回：append-only + `derived_from` + `unverified` 标注 | A6-2；**若 §3.3 实为读法 (a) 则删除** |
| A6-5 | 接入运行循环：替代 `Breach::InputTokens` 的终止路径，**保留终止作兜底** | A6-3 / A6-4 |

A6-5 的关键约束：新组装器**不能**成为"永不终止"的来源。三层降级用尽后必须终止，且终止原因要能区分"上下文确实太大"与"组装器组装不出来"。

## 6. 与其它条目的关系

- **A1**：A6 分叉 A1b 路线（§3.1）。A1-3/6 的 tree 导航不是 A6 的前提——切片单位用 **turn**（一次 user/assistant/tool 交换）即可起步，tree 节点是更优雅的**后续**单位，届时 `SessionNode.history_digest` 死字段可能顺带打通。
- **F1 Repo Map**：F1 已经在做"生成可解释的、显示来源/时效/token budget 的上下文"，本质是"代码库这一类内容的切片"。**F1 应消费 A6 的组装接口**，不要两套"选什么进 prompt"的逻辑并行——那是最容易分叉的地方。
- **B3 受控记忆候选队列**：B3 的原则是"模型只能提出，用户/策略确认后写入"。同一原则延伸到 A6 的写回路径：模型改写的切片内容是**候选**，不是事实。
- **A5 会话导出**：A5 扫 secret 时需要覆盖切片 store 与写回内容。
- **A2 事件流**：`AssemblyReport` 与切片选取理由应作为新 kind 进入 `pangu-stream/1`（只增不改）。

## 7. 非目标

- 跨机器同步、协作编辑、多 agent 共享上下文。
- 语义检索的"智能"程度（先做确定性可复现的选择；相关性优化是后续独立决策）。
- 替代 Journal 或 A2 事件流——组装是派生投影，**不带哈希链，自身无法自证**。
- 让运行永不终止（见 §3.4）。

## 8. 实现状态

未实现。本文件是草案；§3.1 与 §3.3 标注为**待复核**，确认前不应开始实现。
