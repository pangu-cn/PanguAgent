# ADR-0010：受限子 Agent（D1）

- 状态：已实现（本 ADR 随实现一同提交）。
- 相关：ADR-0003（事件流——中央 Journal 的载体）、ADR-0005（上下文装配——子 Agent 的全新上下文）、ADR-0008（产物登记——子产物经同一管线）、ADR-0009（评测——未来批处理 runner 的记录基础）
- ROADMAP：D1；R4 完成门（"子 Agent 的权限是父权限的交集，预算和 deadline 独立且可汇总"）；威胁模型 W-06（多 Agent 放大权限）、W-07（并行/委派放大费用）

---

## 1. 背景与问题

ROADMAP D1：受限子 Agent——子 Agent 只有父任务授予的 capability budget，**不能扩大权限**。参照对象（Hermes/WorkBuddy/DeepSeek Harness/OpenHands/Cline）的共同形态是：父模型把一个子任务交给一个拥有独立上下文的执行者。它们的共同警示也在这里：多 Agent 放大权限、费用和不确定性；子 Agent 常常拿到与父级相同的密钥、相同的文件权、相同的网络面，"委派"变成了"提权"。

Pangu 已有的部分：GoalContract 冻结一切边界（预算、根、策略、审批）；Journal 是中央审计流；`complete` 的证据下限与终态语义诚实。缺的是**委派本身**：父模型如何在边界内把一个子任务交给一个受限执行者，且子 Agent 的每一步仍然过 L1–L4、进同一个 Journal、花的钱算进父级账本。

## 2. 决策

### 2.1 委派是一个边界内控制工具，不是新执行模式

```toml
[boundary]
allow_delegation = false   # 默认关闭；开启才改变 digest
```

- `allow_delegation = true` 时，run 循环暴露 agent 持有的 `delegate_task` 控制工具（同 `finish`/`begin_act` 的地位：不经过 toolkit，无独立实现面）。参数：`task`（必填，≤ 16 KiB）、`max_turns`/`max_cost_usd`（可选收窄）。
- **子 contract 由运行时派生，模型永远不提供**：`GoalContract::derive_sub_contract(parent, task, clamped_budget)`。子 contract 复制父级的一切执行面字段（workspace、读写根、禁区、审批模式、网络、env、全部限额、verify 命令、价格、策略 digest、fallback 链），剥离一切 run 作用域特性（plan-first、memory、skills、deliverables、eval、checkpoint、conversation、**委派本身**）。子 contract 的 goal 文本带 `[delegated subtask]` 前缀——溯源在模型可见文本里。
- **交集由构造保证，拒绝加宽是纵深防御**：调用方（run 循环）先把预算钳到父级剩余（turns/cost/wall-clock），构造器再拒绝任何一维超过父级。结论：子 ⊆ 父在每条轴上成立，且数学上不可能从模型输入推出更宽的子 contract。

### 2.2 预算独立且可汇总（R4 完成门）

- 子预算 = 父剩余的钳制：`turns = min(grant, parent.max_turns − turn)`、`cost = min(grant, parent.max_cost − spent)`、`wall-clock = parent 剩余`。父级 turn=0 剩余、花费耗尽、时钟耗尽 → 拒绝委派，拒绝原因作为工具错误回灌（委派对父 run 永不致命）。
- 子运行结束（任何终态）后，子的 token **merge** 进父级 usage、成本**累加**进父级 spent：下一 turn 的父级预算检查覆盖子的全部消耗。父级不能靠委派逃出自己的预算；子的花费不可见地消失在结构上不可能。
- 子 run 自己也执行同样的预算检查：模型给的 `max_cost_usd = 0.05` 会让子 Agent 死于自己的预算，终态 `budget_exhausted` 如实回传给父模型。

### 2.3 中央 Journal、同一审批面、深度 1

- **同一个 event sink**：子 run 的全部事件（RunStarted/ToolRequested/PolicyDecision/…）写进与父 run 相同的 Journal——任意子 Agent 不能跳过中央 Journal（R4 完成门）。委派时父级发 `TaskDelegated` 事件（pangu-stream/1 provisional，tag `⇒ sub  `）：payload 携带 task **digest**（原文不进事件）、task 字节数、子 contract digest、钳制后的子预算。
- **同一个审批处理器**：子 run 的高风险动作走父级同一审批面（同一 stdin/同一 handler 实例）。委派不创建任何旁路授权。
- **深度 1，结构性**：子 contract 的 `allow_delegation = false` → `delegate_task` 不在子的工具表里，子的再委派调用被"未声明"拒绝；即使工厂实现有误返回了带委派面的 executor，`Agent::with_chain` 的 advertisement 校验（contract 标志 vs 工具表）也会拒绝启动。父级的 factory（`SubtoolFactory` trait，CLI 实现 = 全新 Toolkit{verify}）只决定子的工具面，且产物必须通过子 contract 的 freeze 校验——工厂不可能走私能力。

### 2.4 失败语义与产物

- 子 run 错误（provider 链耗尽、contract 校验失败）→ 工具错误回灌父模型；子 run 的 Journal 记录保留。
- 子终态 + 最后一条 assistant 文本（脱敏、截断 4000 字符）+ 统计（turns/tokens/cost）作为 `delegate_task` 的工具结果回给父模型。委派本身记一条 evidence：`delegate: <digest12> -> <status> (turns=N)`。
- 子写文件经 write_file 与 L1–L4，产物登记（若父目标声明）仍在父 run 的 complete 闸门做——子不持有 deliverable registry。

### 2.5 v1 诚实边界

- **深度 1**：子不能委派（结构性）；并行 DAG/多节点编排是 D2。
- **无跨 Agent 消息协议**：父↔子的全部通信 = task 文本 + 终态汇总。无流式转发、无共享 scratchpad。
- **根不收窄**：子的文件面与父级相同（同一 Sandbox 实例）。粒度更细的按子任务收窄（可写根减法）需要 sandbox 派生机制，本版不实现。
- **子不继承 run 作用域特性**：memory/skills/deliverables/eval/checkpoint 均剥离（见 §2.1）——这是最小能力选择，不是能力缺陷；需要时由父级自己完成该部分工作。
- **准入门 `[boundary] allow_delegation`**：默认关。开启即改变 boundary digest（条件性 digest 插入），关闭时历史 digest 与行为完全不变。

### 2.6 准入模板（ROADMAP §6）

```text
ID：D1
用户价值：父模型能把可分解的子任务交给受限执行者，获得全新上下文与
  隔离预算；委派可审计、可汇总、不可提权
借鉴对象（只写能力模式）：Hermes 的子 Agent/并行委派、WorkBuddy 的任务
  拆解、OpenHands/Cline 的多 Agent 形态
明确不做什么：并行 DAG（D2）；跨 Agent 消息协议；根级收窄；深度 > 1；
  子 Agent 的记忆/技能/交付物/评测面
新增 capability：delegate_task 控制工具（agent 持有，仅 allow_delegation
  时存在）；子 Agent 的工具面 = 工厂产物（CLI = 全新 Toolkit{verify}）
可读数据：与父级相同（同一 sandbox/policy）
可写数据：与父级相同；另有 .pangu 下子 Journal 事件（经中央 sink）
可访问网络：与父级相同（同一 contract 网络字段）
是否创建子 Agent：是——本特性即此；子 contract 由父 contract 派生，
  预算钳制到父剩余，深度 1
是否持久化记忆：无（子剥离 memory）
是否可无人值守：是——子继承父级 unattended 与审批模式
是否为用户可选的本地服务：否
本地 endpoint、绑定地址和认证：不适用
模型/依赖来源、hash、许可证与更新策略：无新依赖；子用父级同一 provider 链
laya/服务不可用、超时或非法输出时的 fallback：子继承父级 fallback 链；
  子 run 错误回灌为工具错误，父 run 不致命
父/子预算和 deadline：子的 turns/cost/wall-clock 独立且被钳到父剩余；
  子的花费聚合进父账本（R4 完成门）
审批与撤销方式：同一审批处理器实例；无旁路授权；委派本身是普通工具调用
事件和 Journal 变化：TaskDelegated（provisional）；子事件进同一 Journal
失败/重试/恢复方式：委派失败 = 工具错误，父模型可重试或改道；子终态
  如实回传；无 checkpoint/会话恢复（子剥离）
威胁模型和红队用例：W-06——子提权（→构造性交集 + 拒绝加宽 + advertisement
  校验）；W-07——委派逃预算（→钳制 + 聚合 + 每turn检查）；task 注入
  （→事件只带 digest；task 进子 goal 时带 [delegated subtask] 溯源前缀）
兼容性与迁移策略：allow_delegation 默认 false；关闭时 digest/行为不变
验收 evidence：集成测试（聚合/深度1/默认关/成本钳制）+ boundary 单测
  （派生收窄、拒绝加宽、条件 digest）
许可证/第三方依赖审查：无新增
```

## 3. 后果

- **正向**：R4 完成门的"权限交集 + 预算汇总 + 中央 Journal"三要素在单机版落地；D2（并行 DAG）可以直接复用 derive/钳制/聚合三个原语；委派成为可审计的普通工具调用。
- **代价**：委派开关多一个维护面；子 run 在父 turn 内串行执行（wall-clock 双重计时，父级检查兜底）；无跨 Agent 协议意味着复杂任务要靠父模型多轮委派。
- **风险**：把子 Agent 当作"更大权限的执行者"的误解——记录与文档反复声明子 ⊆ 父；task 文本本身的注入风险由溯源前缀 + digest-only 事件缓解，内容级校验属未来工作。

## 4. 状态

- 实现：`pangu-boundary`（`[boundary] allow_delegation` + `GoalContract::derive_sub_contract` + 条件 digest）、`pangu-agent`（`SubtoolFactory` trait、`with_delegation`、`handle_delegation`、TaskDelegated 事件、预算钳制与聚合）、`pangu` CLI（FreshToolkitFactory 接线）。
- 默认不声明：无委派工具、无子 Agent、digest 不变。
