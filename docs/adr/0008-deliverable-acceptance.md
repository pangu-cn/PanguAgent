# ADR-0008：产物管线与验收器（D3/D4）

- 状态：已实现（本 ADR 随实现一同提交）。
- 相关：[ADR-0006](./0006-memory-candidate-queue.md)（操作者签收的存储先例）、ADR-0001（artifact CAS）
- ROADMAP：D3（Artifact + Evidence 管线）、D4（产物验收器）；威胁模型 W-18（可验证输出可能被误读——生成 ≠ 事实正确）

---

## 1. 背景与问题

ROADMAP D3：产物导向的工作管线，支持报告、补丁、表格等结构化产物。D4：产物验收器——schema、测试、引用、数据版本、人工签收；**没有验收证据不能标记完成**。

Pangu 今天已有的部分：`complete` 需要 evidence（I-Honest-Terminal #9），verify 工具提供项目验证证据（F3），checkpoint artifact 提供工作区快照。缺的是**目标的"交付物"这一层**：哪个文件是产物、它的数据版本是什么、谁检查了什么、谁签收的。W-18 的风险正好落在这个层：一份"看起来完成"的报告可能内容错误、数据过期或格式非法——没有登记与签收，就无法区分"模型声称完成"与"产物被验收"。

## 2. 决策

### 2.1 交付物在目标里声明；complete 是验收闸门

```toml
[[goal.deliverable]]
name = "migration-report"
path = "out/report.md"       # workspace 相对；禁止 .pangu 与路径逃逸
kind = "report"              # 自由 slug：report/patch/table/data/...
acceptor = "manual"          # manual | verify | json | jsonl
min_bytes = 1                # 非空下界
```

- 声明冻结进 contract（`ContractDeliverables`）并携带进 digest；未声明的运行 digest 不变（compat 纪律与 fallback/memory/skills 一致）。
- **`complete` 必须通过每个交付物的运行时检查**：文件存在、≥ min_bytes、acceptor 检查（`json`/`jsonl` 解析、`verify` 要求本 run 有成功的 `verify:` evidence——复用 F3 证据链、`manual` 只登记不阻塞）。
- 检查失败 → finish 被拒，**失败详情回灌给模型**（哪个交付物、什么检查、怎么修）——Aider lint-loop 模式放在 finish 闸门上。模型可以修复产物后重试 `complete`，或诚实改口 `failed`。**没有静默完成**。
- 登记（写 store + `DeliverableRecorded` 事件）是 complete 的一部分：**未经审计的完成不是完成**——登记失败同样拒绝 complete。

### 2.2 数据版本与人工签收（W-18 的四要素落点）

- **数据版本**：complete 时把每个交付物的快照写入注册表——`path`、SHA-256（产物字节）、字节数、run 标识、时间（schema `pangu-deliverables/1`，位于 `<workspace>/.pangu/deliverables/`，工具 I/O 禁区）。同一产物被后续 run 重新交付 → 追加新记录，历史永不改写。
- **来源与时间**：记录携带 run 与 `recorded_at`；事件流里有对应的 `DeliverableRecorded`（provisional，pangu-stream/1，只含 digest 不含内容）。
- **校验规则**：acceptor 即声明的校验规则，检查结果在 Journal 可审计。
- **人工签收**：`pangu deliverable list|accept|reject <name>`——**只能作用于 run 外**。转换单向且审计：pending → accepted | rejected；模型没有任何签收路径。运行只产出"待签收"（pending）记录；"accepted" 是操作者的独立事实判断。
- 完整语义：`complete`（run 内自动检查全过）≠ `accepted`（人看过并认可事实正确）。CLI 输出与文档不得混用两者。

### 2.3 诚实的 v1 边界

ROADMAP D4 列的"schema、测试、引用、数据版本、人工签收"，v1 覆盖情况：

| 要素 | v1 状态 |
| --- | --- |
| 测试 | `verify` acceptor 复用 F3 验证命令证据 |
| 数据版本 | SHA-256 + 时间 + run，登记与事件双链 |
| 人工签收 | CLI accept/reject，单向审计 |
| schema | 仅 `json`/`jsonl` 格式校验；**完整 JSON Schema 校验未实现**（需引入 jsonschema 依赖，届时按准入模板另议） |
| 引用（产物内引用的文件/来源存在性） | **未实现**（属内容语义检查，需按 kind 定义规则） |

这些缺口如实写进 ROADMAP 与本 ADR，不做隐式宣称。

### 2.4 准入模板（ROADMAP §6）

```text
ID：D3/D4
用户价值：目标可以声明"做完长什么样"；产物有数据版本、审计与人工签收；
  模型不能靠一句 complete 混过交付
借鉴对象（只写能力模式）：Aider lint/test loop（失败回灌重试）、
  Cline checkpoint 的可回溯产物观念、WorkBuddy 产物导向
明确不做什么：完整 JSON Schema 校验（依赖另议）；引用存在性检查；产物内容
  的事实性校验（那是签收者的责任）；模型签收；云端产物库
新增 capability：无新模型工具——写文件用 write_file（L1-L4 照常），
  验收在 finish 闸门；accept/reject 无模型面
可读数据：workspace 产物文件（run 内检查读字节）；registry（CLI）
可写数据：<workspace>/.pangu/deliverables/deliverables.json（禁区内的
  pangu 自有存储；run 只在 complete 时登记，accept/reject 仅 CLI）
可访问网络：无
是否创建子 Agent：否
是否持久化记忆：registry 是持久数据；模型不可写（声明来自配置，非模型提议）
是否可无人值守：可——无人值守运行同样过验收闸门；签收是有人动作
是否为用户可选的本地服务：否
本地 endpoint、绑定地址和认证：不适用
模型/依赖来源、hash、许可证与更新策略：无新依赖
laya/服务不可用、超时或非法输出时的 fallback：不适用
父/子预算和 deadline：不适用；登记数量随 run 增长（审计面），无上界——
  产物按 goal 声明，量级是人配置的
审批与撤销方式：accept/reject（单向审计，同 memory 生命周期）；
  complete 的验收失败是模型可重试的闸门而非终态
事件和 Journal 变化：DeliverableRecorded（pangu-stream/1 provisional，
  digest only）；签收在 store transitions（run 外）
失败/重试/恢复方式：检查失败 → 回灌重试；登记失败 → complete 被拒；
  registry 损坏 → 硬错误；原子写
威胁模型和红队用例：W-18——模型虚报完成（→闸门拒+回灌）；产物缺失/空
  （→存在性+min_bytes）；格式非法（→json/jsonl）；绕过签收自认完成
  （→签收无模型路径）；声明后偷偷改产物再 finish（→检查在 finish 时点，
  记录的是最终 digest）
兼容性与迁移策略：无声明 = 行为与 digest 完全不变；声明进 digest
验收 evidence：complete 被拒回灌 → 修复后 complete 通过 → registry 记录
  + 事件；签收 CLI 状态机（测试锁定）
许可证/第三方依赖审查：无新增
```

## 3. 后果

- **正向**：交付物从"模型的口头声明"变成"contract 冻结 + 闸门检查 + digest 审计 + 人工签收"的四层结构；W-18 的数据版本与签收落点齐备；为 F5（issue-to-patch 评测）提供了 patch 验收的语义基础。
- **代价**：操作者多一个签收义务（同 B3 记忆签收——决定在人）；声明是配置工作。
- **风险**：操作者机械签收（同 B3 的橡皮图章风险）；json/jsonl 校验是格式级而非语义级——ADR 与 CLI 措辞明确"格式正确 ≠ 事实正确"。

## 4. 状态

- 实现：`pangu-core::deliverable`（registry + 检查）、`pangu-boundary`（声明校验 + contract 冻结）、`pangu-agent`（finish 闸门 + 登记 + 事件）、`pangu` CLI（`pangu deliverable list|accept|reject`）。
- 默认无声明：无交付物语义、无事件、digest 不变。
