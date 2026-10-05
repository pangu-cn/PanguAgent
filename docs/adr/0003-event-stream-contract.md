# ADR-0003：结构化事件兼容层（稳定 NDJSON 事件流与迁移器）

- 状态：已批准（用户指示"开始后续计划 A"，A2 为计划 A 的第二项；A4 已先行完成）
- 日期：2026-09-26
- 关联：A2 结构化事件兼容层；R1 完成门"`doctor`/dry-run 能解释为什么允许/拒绝"；A4 遗留的"从 Journal 解释历史判定"
- 依赖：[ADR-0001](0001-checkpoint-rollback.md)（输出永远不是授权）、[ADR-0002](0002-explain-policy-simulation.md)（解释不是授权）

## 1. 背景与问题

Pangu 现在有 Journal，但它不是一个兼容层，而是一个**内部存储格式**：

- `Event` 是 18 个 `Option` 字段的扁平结构（`tool`/`call_id`/`verdict`/`risk`/`rule_id`/`invariant`/`duration_ms`/`usage`/`payload`/`effect_scope`/`reversibility`/`action_digest`/`external_mutation`/…）。任何新概念都要往这个结构上加字段，而 `#[serde(deny_unknown_fields)]` 意味着**旧消费者遇到新字段直接失败**。
- `schema: Option<String>`（`pangu-journal/v1`、`/v2`）描述的是**磁盘布局**，不是对外契约。它随内部实现变化而变化，却被外部工具读。
- `EventKind` 是 24 变体的闭枚举，没有"哪些是对外承诺的、哪些是内部的"之分。
- 整个文件被 `prev_sha`/`sha` 哈希链绑定。它是**审计记录**，不是"可以随便消费的事件流"。

结果是：外部工具（UI、Agent Server、CI 审计器）无法稳定消费 Pangu 的事件——它们要么绑死内部结构，要么把审计链当成数据流读。两者都不对。

同时 A4 明确留下一件事没做：**"从 Journal 解释历史判定"（"run X 里那次拒绝是哪条规则"）**，它依赖一个稳定的对外事件契约。

## 2. 决策

在 Journal **之外**新增一条独立的、版本化的 NDJSON 事件流，配套迁移器。

三条边界：

1. **事件流是派生产物，不是权威记录。** 审计权威始终是带哈希链的 Journal。事件流不带自己的哈希链，只通过 `origin` 字段引用来源 journal 事件。
2. **事件流不能改变任何判定。** 它是只读投影，不参与 `Policy → Sandbox → Approval`，不可被当作授权或完成证据。
3. **写入失败必须报错。** 与 `EventSink` 既有契约一致："审计失败不得被静默转成一次成功的运行"。

## 3. 准入模板

```text
ID：A2 结构化事件兼容层
用户价值：外部工具（UI / Agent Server / CI 审计器）能稳定消费 Pangu 事件而不绑死内部结构；
      旧事件流可在新版本 Pangu 上继续读取；A4 遗留的"解释历史判定"有了数据基础；

不做什么（价值之外）：不替换 Journal；不改任何门禁；不做实时推送（gRPC/WebSocket）；
      不把事件流做成可写回的 API；不承诺把所有内部事件都冻结；

影响面：新增模块 crates/pangu-core/src/stream.rs 与 CLI 子命令 `pangu events`；
      Journal 与 Agent 的判定路径零改动（只读投影）；新增 EventSink 实现一个；
数据/隐私：事件流内容与 Journal 同样过 redact_event + 限长；每条记录都带
      advisory/derived 标记；不含凭据、不含未脱敏的绝对路径（沿用运行时脱敏）；
失败/重试/恢复方式：写入失败即整体失败，不静默丢弃；读取时损坏行导致整体失败
      （不跳过、不猜测）；未知/未来 schema 一律拒绝而不是降级处理；
威胁模型和红队用例：
  T1 拿事件流当授权：派生标记 + 无判定语义 + invariants 断言；
  T2 事件流成为绕过审计的通道：Journal 仍是唯一权威，事件流无哈希链、不被任何
      判定路径读取；写事件流不能替代写 Journal；
  T3 用事件流泄露 secret：与 Journal 同一套 redact_event + 限长，并有单测；
  T4 半截结论：损坏行/未知版本整体失败，不返回部分结果；
  T5 静默截断：任何截断都必须显式报出（像 inspect 那样报 truncated 标志），
      绝不假装流是完整的；
兼容性与迁移策略：纯新增。v1 事件流上线后字段只增不改；要改必须发 pangu-stream/2
      并提供 v1→v2 迁移器。迁移器显式登记每个版本，链式升级。
验收 evidence：单元测试覆盖往返、v1→当前迁移、未知版本拒绝、损坏行失败、
      脱敏、边界截断显式上报、派生标记；invariants 增加"事件流不是授权"的断言；
      `cargo test --workspace --all-targets --all-features` 与 clippy 通过；CI 双平台通过。
许可证/第三方依赖审查：无新依赖。
```

## 4. 设计

### 4.1 三个版本概念，各管各的

| 概念 | 取值 | 含义 | 变更纪律 |
| --- | --- | --- | --- |
| Journal 磁盘格式 | `pangu-journal/v1`、`/v2` | 内部存储 + 哈希链 | 可演进；v1 保持字节兼容 |
| 事件流契约 | `pangu-stream/1` | 对外稳定契约 | **只增不改**；改则发 `/2` |
| 单条记录版本 | `StreamKind::stability()` | 该 kind 是否已冻结 | 见 4.3 |

这三者过去被一个 `schema` 字段混在一起，是外部工具读不懂的根因。

### 4.2 数据流

```text
Event (内部, 18 个 Option 字段, 哈希链)
   │  redact_event（与 Journal 同一套脱敏与限长）
   ▼
StreamEvent { schema, seq, at, kind, turn, data, origin }
   │
   ├──▶ NDJSON 文件（StreamWriter，EventSink 实现，失败即报错）
   └──▶ StreamReader（读 + 迁移 + 校验 + 计数 + 截断显式上报）
```

`StreamEvent.data` 是**闭集**（`tool`/`call_id`/`verdict`/`risk`/`rule_id`/`invariant`/`duration_ms`/`message`/`usage`/`effect`），不是 `serde_json::Value`。代价是新概念要发新版本；收益是消费者能对字段做穷尽匹配，且"字段消失"永远不会是静默的。

### 4.3 稳定性分级

不是所有 kind 都该现在就冻结。F7 的 checkpoint/rollback 事件还挂在"默认关闭的实验性 opt-in"上，现在冻结等于对还没定型的行为做兼容承诺。

- `Stable`：`RunStarted`…`Note` 这一组运行生命周期事件。冻结。
- `Provisional`：F7 引入的 `Checkpoint*` / `Rollback*` / `FailedPathRecorded`。可增删改，不做兼容承诺。
- 内部事件：不进事件流。

`StreamKind::stability()` 让消费者能自己决定要不要依赖某个 kind。

### 4.4 迁移器

```rust
EventMigrator::migrate_line(&str) -> Result<StreamEvent>
```

- `pangu-stream/1` → 恒等（仍要校验形状）
- `pangu-journal/v1` / `/v2` → 转换（这是"拿旧 Journal 当事件流读"的实际需求）
- **其它任何值 → `Error::Config`，硬失败**

关键是最后一条：未来版本（`/2`）写出的记录，用旧 Pangu 读必须失败，不能"尽力解析"。这与 `replay` 里"unknown schemas fail closed"的既有立场一致。

### 4.5 风险点：派生记录被当成权威

事件流不带哈希链，所以它**天然不能**证明任何事。防止误用的措施：

- 每条记录固定带 `derived: true` 和 `authoritative: false`；
- 顶层 `StreamSummary` 声明它是"派生投影，审计权威是 Journal"；
- `origin` 字段回指 journal 的 `seq`/`event_id`/`sha`，供需要回溯的人核对；
- invariants 断言：`stream` 不是工具名、报告不带可被读成 `Effect` 的字段。

### 4.6 `pangu events read --verify`：把"读回"与"校验"分开（补充，2026-10-05）

§4.5 的派生标记解决了"这条记录是不是权威"，但留下一个更细的歧义：**`origin.journal_sha` 是"文件里写的值"还是"重算通过的值"？**

投影层的实现是前者——它解析 JSON 并把 `sha` 字段原样搬运。于是这两种输出在视觉上完全一致：

```text
  hash chain verified: 15 event(s), head sha 70940634a7ca1df1 ...
  origin.journal_sha:  c5487e2894098098a26969be0ba76922...
```

而 `replay::read` 的实现是后者：它重算 `prev_sha` 链接与每条 `sha`，不匹配即报 `tamper detected at seq N`。

这不是"投影越权"，投影本身符合契约；但 README 把 `pangu events` 推荐给 **CI 审计器**消费，一个审计器仅凭 `events read` 拿不到任何完整性信号：把 journal 里某条记录的 `sha` 改成另一串同样合法的 64 位十六进制，`events read` 依然退出 0，并把这个伪造值当作 `origin.journal_sha` 打印出来。**检测能力存在（`replay::verify`），只是在这个入口上没有接线。**

决策：新增 `--verify`，在该开关下走真正的链校验，**默认行为不变**（保持向后兼容，不把一次只读投影升级成可能失败的校验）。

- 校验通过：正常输出，外加一行 `hash chain verified: N event(s) (pangu-journal/vX), head sha <recomputed>`；JSON 下多一个 `integrity` 对象（`verified` / `events_verified` / `head_sha` / `journal_format`）。
- 校验失败：非零退出，**且在任何记录被打印之前**失败——一个 CI 管道不能从被篡改的文件里取到半截输出。
- 对**没有哈希链**的输入（真正的 `pangu-stream/1` 投影）**fail closed**：报"projection 没有链可校验"，而不是报告一次没发生过的成功。这是本 ADR"不制造空洞结论"立场的延续。
- 不带 `--verify` 时，JSON 的 `integrity` 固定为 `null`，使消费者能区分"没查"与"查过且完好"——两者绝不能长得一样。

`crates/pangu-core/src/replay.rs` 新增 `JournalIntegrity` 与 `verify_journal`：前者是"一次检查的结果"而非"一个声明"，`verified: true` 只在重算发生后才存在；空 journal 会如实报告 `events_verified: 0` 与空 `head_sha`，并明说这**不构成**该文件写过的证据。


## 5. 与"模型输出永远不是授权"的关系

事件流是**单向**的内部→外部投影：只从 `Event` 流出，不回流到任何判定路径。没有写入 API，没有"由事件流驱动的动作"，因此不存在"事件流授权了某个动作"的可能。

`pangu events` 是只读 CLI 子命令，模型无法调用（不注册为工具）。

## 6. 后续（不属于本 ADR）

- A4 遗留的"从 Journal 解释历史判定"现在有了数据基础，但需要在事件流之上做**因果关联**（把一次 `ToolRequested` 和它的 `PolicyDecision` 串起来），属 A4 的后续或 A3；
- 实时推送（订阅式）不在本 ADR；
- `Provisional` kind 转正为 `Stable` 需要在 F7 激活门通过后单独决策。

## 7. 实现状态

已实现（`crates/pangu-core/src/stream.rs`，8 个单元测试；`tests/invariants.rs` 1 个不变式；CLI `pangu events read|contract`）：

| 项 | 状态 | 证据 |
| --- | --- | --- |
| `pangu-stream/1` 闭集契约 | 完成 | `StreamEvent` / `StreamData` / `StreamEffect` / `StreamOrigin`，全部 `deny_unknown_fields` |
| 迁移器与版本探测 | 完成 | `EventMigrator::migrate_line` 返回 `Migrated { event, from_journal }` |
| v1 journal 向前迁移 | 完成 | 实测：13 条记录的 v1 journal 迁移通过，报告 `migrated from journal format on read` |
| v2 journal 向前迁移 | 完成 | `origin.event_id` / `origin.journal_sha` 指向封存后的记录 |
| 未知/未来 schema 硬失败 | 完成 | `pangu-stream/2`、`someone-elses-format/1`、非 JSON 均报错 |
| 损坏行整体失败 | 完成 | 错误信息带行号（`stream line 2 failed to migrate`） |
| 脱敏与 Journal 同源 | 完成 | `StreamEvent::from_event` 先过 `redact_event`；单测断言凭据不出现 |
| 派生标记 | 完成 | `derived: true` / `authoritative: false`，`validate()` 拒绝声称权威的记录 |
| 稳定性分级 | 完成 | 运行生命周期 `stable`；F7 的 checkpoint/rollback `provisional`；`pangu events contract` 可查 |
| 显式上报截断 | 完成 | `StreamSummary.truncated`；CLI 遇截断返回非零而不是假装完整 |
| 链校验入口 | 完成（opt-in） | `pangu events read --verify`；`replay::verify_journal` + `JournalIntegrity`；篡改/损坏非零退出、无链输入 fail closed；见 §4.6 |

**实现中发现并修正的两个真问题**（均为本 ADR 设计直接导致的，值得记录）：

1. `migrated_from_journal` 最初写成“迁移后比较 `schema != v1`”。这是**永远为假的**——迁移后的记录已经带 v1 schema，来源信息被自己抹掉了。改为让迁移器显式返回来源，而不是从产物反推。产物不能承担自己出处的举证责任。
2. 迁移器最初要求每行都有 `schema` 字段，实测直接失败：`pangu-journal/v1` 记录**故意不写** `schema` 字段以保持字节兼容（`events.rs` 注释："Absent means the legacy pangu-journal/v1 format"）。原实现与内部既有约定冲突，等于无法读取它本该吸收的最老格式。已改为“无 `schema` 字段 = v1 journal”，并补 `a_v1_journal_migrates_forward_even_though_it_carries_no_schema_field` 覆盖——原测试只覆盖 v2，正是这个缺口让 bug 活了下来。

**未做**（详见第 6 节）：实时推送、写回 API、替代 Journal、Provisional kind 转正。
