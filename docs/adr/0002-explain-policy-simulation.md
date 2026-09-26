# ADR-0002：决策解释与策略模拟（`explain`）

- 状态：已批准（用户指示"开始后续计划 A"，A4 为计划 A 中无依赖项）
- 日期：2026-09-26
- 关联：A4 `doctor`/`explain`/策略模拟；R1 完成门"`doctor`/dry-run 能解释为什么允许/拒绝，不泄露 secret"
- 依赖：[ADR-0001](0001-checkpoint-rollback.md) 确立的"输出永远不是授权"与"默认拒绝"原则

## 1. 背景与问题

当前 `Config::explain()` 只打印配置摘要、boundary digest 和规则原文；`pangu doctor` 在此之上加一份 Journal 统计。两者都**不能回答操作者真正会遇到的问题**：

- 这条规则为什么没生效？
- 我写的这条 `allow` 为什么被前面的规则遮住了？
- 换成这个工具调用，边界会在哪一层拦下它？
- 照这个预算，任务会在第几步卡住？
- 这次拒绝到底是 deny 规则、路径穿越还是默认拒绝？

R1 明确要求"`doctor`/dry-run 能解释'为什么允许/拒绝'"。缺这条，配置错误只能在真实运行中以拒绝的形式暴露，而拒绝不会告诉操作者原因。

## 2. 决策

新增只读的 `explain` 能力：对一个**假想**动作，投影 L1–L4 各层的判定结果，给出规则命中顺序、遮蔽规则和预计阻塞点。

核心约束是**解释不是授权**。见第 5 节。

## 3. 准入模板

```text
ID：A4 doctor/explain/策略模拟
用户价值：配置作者在运行前看到"为什么会被拒"；operator 在事故中定位是哪条规则或哪一层拦截；
          CI 可以在不执行任何动作的前提下验证配置是否自洽（例如是否存在永远命不到的规则）。
借鉴对象（只写能力模式）：OpenHands 的 backend 状态检查；Cline/Codex 类工具的权限预览。不借鉴其
          默认自动批准行为。
明确不做什么：不执行任何工具；不写任何文件；不提供强制放行/忽略规则的开关；不评估模型输出的
          内容是否安全；不替代真实判定；不提供"预测通过就跳过审批"的路径。
新增 capability：无。explain 不注册为工具，模型无法调用；只有 CLI 子命令。
可读数据：配置文件、策略规则、预算配置、sandbox roots/globs、approval 模式，以及假想动作里
          调用者显式给出的参数（经边界脱敏并限长）。
可写数据：无。全程只读，不创建目录、不取锁、不写 Journal。
是否访问网络：无。
是否创建子 Agent：否。
是否持久化记忆：否。
是否可无人值守：可。它是纯函数式的本地计算，CI 可直接调用。
是否为用户可选的本地服务：否。
本地 endpoint、绑定地址和认证：不适用，无服务。
模型/依赖来源、hash、许可证与更新策略：不引入新依赖。
JEV/服务不可用、超时或非法输出时的 fallback：不适用，不依赖 JEV 或任何外部服务。
父/子预算和 deadline：explain 自身不消耗模型预算，不发起模型请求，不设 wall-clock 预算
          （纯本地计算，输入有大小上限）。
审批与撤销方式：不适用，无副作用可撤销。
事件和 Journal 变化：无。explain 不发事件。把它记入 Journal 会让"没有发生的事"出现在审计
          轨迹里，反而破坏审计可信度。
失败/重试/恢复方式：不可恢复也不需要恢复——它不改变任何状态。输入不合法时直接报错，不做部分
          解释（避免给出半截结论被误读为完整结论）。
威胁模型和红队用例：
  T1 把 explain 当授权：输出必须无法被下游当作 Decision 使用，且必须自我标注为非权威。
  T2 用 explain 探测 secret：参数回显必须走与运行时相同的脱敏与限长。
  T3 用 explain 反推边界：explain 的存在本身会暴露规则内容——这是它本来的用途（配置属主可见），
      因此不作为漏洞；但必须保证它不暴露凭据值本身。
  T4 半截结论：任一层输入缺失时整体失败，不返回部分结果。
  T5 影子规则：遮蔽检测只报告事实，不自动改配置。
兼容性与迁移策略：纯新增，无 schema 变更，无迁移。`pangu doctor` 保持原有输出不变。
验收 evidence：单元测试覆盖遮蔽检测、路径穿越优先级、Ask 升级、默认拒绝、脱敏；
      invariants 增加"explain 不得授权"的断言；`cargo test --workspace --all-targets --all-features`
      与 clippy 通过；CI 双平台通过。
许可证/第三方依赖审查：无新依赖。
```

## 4. 设计

### 4.1 数据流

```text
ExplainRequest { tool, args, paths, hosts, argv, risk? }
        │
        ├─ L1 GoalContract     配置是否允许该动作类别
        ├─ L2 Policy           逐条规则匹配轨迹 + 遮蔽分析
        ├─ L3 Sandbox          roots/glob/资源/网络投影（只读）
        └─ L4 Approval         模式投影（Never→拒 / Ask→需人 / Always→放行）
                │
                ▼
        ExplainReport { verdict: Would{Deny,Ask,Allow}, ... }
```

### 4.2 遮蔽分析

`Policy::evaluate` 的实际顺序是：路径穿越硬拒 → 首个匹配的 deny → 首个匹配的非 deny（`Allow` 且风险 ≥ Destructive 时升级为 `Ask`）→ 默认拒。因此：

- 非 deny 规则若前面已有匹配的非 deny 规则，则**永远不会被报告**（遮蔽）；
- deny 规则若前面已有匹配的 deny 规则，效果相同但 `rule_id` 与理由不同（被遮蔽）；
- 命中规则之后的匹配规则永远不会被检查（未到达）。

这三类都报告为事实，让配置作者看到"我写的这条规则是死规则"。

### 4.3 风险点：解释成为授权预言机

这是本 ADR 最大的设计风险，必须在类型层面挡住：

- verdict 命名为 `WouldDeny`/`WouldAsk`/`WouldAllow`，不使用 `Deny`/`Ask`/`Allow`；
- 报告序列化后固定携带 `advisory: true` 与 `authoritative: false`；
- `ExplainReport` **不实现** `From<ExplainReport> for Decision`，也不提供取用 `Decision` 的方法；
- `explain` 不接受 `--force`、`--assume-yes` 之类参数，也不返回可供下游解析后直接执行的字段；
- invariants 断言：explain 的 verdict 不能被转换成 `Effect`，且报告必须带非权威标记。

## 5. 与"模型输出永远不是授权"的关系

explain 由操作者/配置作者在运行**之前**调用，与模型无关。模型无法调用它（不注册为工具）。它也不产生任何授权：真实运行仍走完整的 `Policy → Sandbox → Approval → VerifiedAction → ToolExecutor`。explain 预测与真实结果不一致时，以真实判定为准，且这种不一致本身是应当报告的 bug。

## 6. 后续（不属于本 ADR）

- 从 Journal 解释**历史**判定（"run X 里那次拒绝是哪条规则"）依赖 A2 的稳定事件契约，留在 A2；
- 预算耗尽点预测需要成本模型，R1 完成门只要求解释 allow/deny，本期不实现；
- A3 的差异预览会复用 explain 的投影能力，但 A3 自身需独立 ADR。

## 7. 实现状态

已实现（`crates/pangu-boundary/src/explain.rs`，6 个单元测试 + `tests/invariants.rs` 1 个不变式）：

| 项 | 状态 | 证据 |
| --- | --- | --- |
| L2 `Policy` 投影 + 逐条规则轨迹 | 完成 | `trace_rules`；`decided` / `no_match` / `not_reached` 三态在实测输出中可见 |
| 遮蔽（死规则）分析 | 完成 | `RuleStatus::Shadowed` / `MatchedButRefused` + `ExplainReport::dead_rules` |
| L3 `Sandbox` 投影 | 完成 | 路径 glob/roots、host、argv 逐项检查，只读 |
| L4 `Approval` 投影 | 完成 | `Never` → `deny`（拒绝而非自动放行）、`DestructiveAndAbove` → 按风险、`Always` → 放行 |
| 参数回显脱敏与限长 | 完成 | 复用运行时同一套 `redact_text` + `one_line` + `truncate_middle`，上限 4096 字节 |
| 路径穿越归因 | 完成 | 报告显式声明"来自路径安全检查，不是任何规则"，`rule_id = None` |
| 缺失输入整体失败（T4） | 完成 | 空工具名、超限参数直接返回 `Error::Config`，不返回部分报告 |
| 报告自带非权威标记 | 完成 | `advisory: true` / `authoritative: false`，且不定义任何到 `Effect` 的转换 |

**L1 `GoalContract` 不是实时投影。** `ExplainContext` 只借用 `Policy` 与 `Sandbox`，`GoalContract` 依赖运行时构造，不在解释路径中。因此 L1 恒为 `not_applicable`，并在报告里明确说明原因与替代命令（`pangu doctor`），而不是伪造一个通过/拒绝。要做真实的 L1 投影需要把 `GoalContract` 引入 `ExplainContext`，属于后续变更。

**未做**：第 6 节列出的三项（历史判定解释、预算耗尽点预测、配置修改建议）均未实现，`ExplainReport` 只报告事实，从不改写配置（T5）。
