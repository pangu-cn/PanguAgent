# ADR-0009：Issue-to-patch 评测 profile（F5）

- 状态：已实现（本 ADR 随实现一同提交）。
- 相关：ADR-0003（事件流契约——trajectory 的载体）、ADR-0008（deliverable 登记——patch 的载体）、ADR-0005（上下文装配）
- ROADMAP：F5；威胁模型 W-31（benchmark 分数不能直接当生产安全证明）、W-32（trajectory 可能泄漏敏感上下文）、W-38（issue 文本本身是不可信外部输入）

---

## 1. 背景与问题

SWE-agent 把 issue→patch→test 固定为可复现实验：单配置文件管理模型、工具、环境与实验参数，输出完整 trajectory。ROADMAP 的采用决定（§2.9）是把这条流程做成**可选评测 profile**而不是默认执行模式；用 `GoalContract` 固定 issue、允许修改的 roots、测试命令、预算、deadline 和验收条件；trajectory 映射为结构化事件；**benchmark 分数、模型自评和自然语言总结都不能替代测试 evidence 与人工验收**。

Pangu 已有的部分：GoalContract 已经冻结一切边界；Journal/事件流就是结构化 trajectory（含脱敏）；`verify:` evidence 是测试证据（F3）；deliverable registry 提供 patch 的数据版本与人工签收（D3/D4）。缺的是把这些**钉成一个实验记录**：本次 run 用的是哪个 issue 的哪个版本、哪个仓库状态、哪个 contract，产出了哪个 patch（digest）、花了多少 token/钱——且可以对比与重跑。

## 2. 决策

### 2.1 评测是声明 + 记录，不是新执行模式

```toml
[eval]
profile = "issue-fix"        # 名字；空 = 无评测语义（digest、行为完全不变）
issue_path = "issues/001.md" # workspace 相对；安全路径校验同 deliverable
```

- `pangu eval run`：读 issue 文件 → **内容 SHA-256 在 run 开始时钉死** → goal 文本由固定模板合成（来源与 digest 标注进正文，W-38：issue 是外部输入，模型应看到它的来源）→ 走与 `pangu run` 完全相同的 contract/policy/sandbox/approval/journal 管线 → run 结束后把事实追加进评测注册表。
- **不引入新的执行语义**：eval run 的每一条规则（预算、审批、验证闸门、交付闸门）与普通 run 完全一致。评测 profile 只是"输入的钉取 + 事实的记录"。

### 2.2 EvalRecord（`pangu-eval/1`）

存于 `<workspace>/.pangu/eval/records.json`（工具禁区），追加式、原子写、损坏=硬错误、id 唯一——与 deliverables registry 同款纪律，历史永不改写。字段：

- **输入三元组**：`issue`（path + sha256）、`workspace_version`（run 前 `git rev-parse HEAD` 的观察，非 git 仓库如实记 `unknown`——这是环境观察不是验证事实）、`contract_digest`（冻结的边界；digest 不含 goal 文本，issue 内容由自己的 digest 单独钉取）。
- **机器事实**：`status`（终态）、`turns`、`input/output_tokens`、`cost_usd`（**None = 未定价，绝不与 0 混淆**）、`verify_evidence`（`verify:` 证据计数——F3 验证环成功次数）、`evidence_total`。
- **产物**：`deliverables`——本 run 登记的交付物快照（name/path/sha256/bytes/acceptance）；trajectory 指针 `journal`（Journal 文件名）。
- **固定免责声明**随每条记录写入 `notes`：*status/evidence are machine facts; they do not assert the issue is fixed. Acceptance = verify evidence + human deliverable sign-off.* —— **没有 score 字段**：跑分、模型自评、总结陈词都不进记录；"修复正确"由外部（测试集或人）判定。

### 2.3 验收的落点

- **`complete` ≠ 修复正确**：run 内的 complete 只说明声明的闸门全过（deliverable 检查 + evidence 下限）。
- **测试证据**：`verify_evidence` 计数来自 F3 验证命令的真实运行；想要更强的评测，就声明 `acceptor = "verify"` 的 patch 交付物（D4），让 complete 本身依赖 verify 成功。
- **人工签收**：`pangu deliverable accept/reject` 语义原样适用——评测记录是事实，签收是判断。
- v1 诚实边界：**无批处理 runner**（多 issue 批量跑是 F6/C4 的活）、**无内建测试集判定**（SWE-bench 式 pass/fail harness 属外部工具，Pangu 只提供事实与证据钩子）、run 中途 Err（如 provider 链耗尽）**只进 Journal 不进 eval 记录**（记录要求终态）。

### 2.4 准入模板（ROADMAP §6）

```text
ID：F5
用户价值：一次 run 成为一个可复现、可对比、可审计的实验；输入三元组 +
  产物 digest + 成本 + 证据计数全部落盘；评测与验收分层
借鉴对象（只写能力模式）：SWE-agent 的单配置实验与 trajectory、
  Cline/Aider 的 diff 观念（经 D4 产物登记落地）
明确不做什么：批处理 runner；内建 benchmark 判定；score 字段；云端实验库；
  非终态 run 的 eval 记录（Journal 兜底）
新增 capability：无新模型工具；eval 对模型完全不可见（goal 文本除外）
可读数据：issue 文档（run 前 CLI 读取，上限 256 KiB）；git HEAD 探测
  （只读 rev-parse）
可写数据：<workspace>/.pangu/eval/records.json（工具禁区，仅 CLI 写）
可访问网络：无新增
是否创建子 Agent：否
是否持久化记忆：eval 注册表是持久数据；模型不可写
是否可无人值守：是——unattended 评测照常走闸门与记录
是否为用户可选的本地服务：否
本地 endpoint、绑定地址和认证：不适用
模型/依赖来源、hash、许可证与更新策略：无新依赖
laya/服务不可用、超时或非法输出时的 fallback：不适用
父/子预算和 deadline：不适用
审批与撤销方式：无新审批面；评测记录追加后不改写（"撤销"= 追加新记录）
事件和 Journal 变化：无新事件 kind；eval 记录引用 Journal 文件名
失败/重试/恢复方式：issue 缺失/过大 → run 前 fail-fast；注册表损坏 →
  硬错误；重跑 = 同配置再跑一次（新记录）
威胁模型和红队用例：W-31——把 complete 当"修好了"（→记录免责 +
  无 score 字段 + 验收分层）；W-38——issue 文本注入（→来源标注进 goal、
  内容 digest 钉取）；成本误报（→未定价记 None 不是 0）
兼容性与迁移策略：不声明 [eval] = 行为与 digest 完全不变
验收 evidence：eval run 端到端（测试锁定 turn/cost/deliverable/verify
  计数与免责声明）；config 校验（半声明拒绝、digest 条件携带）
许可证/第三方依赖审查：无新增
```

## 3. 后果

- **正向**：可复现实验的最小闭环完成——输入三元组 + 事实 + 证据 + 产物 digest 落盘，评测与验收明确分层；F5 为 F6/C4 的批处理与远程评测提供了记录格式。
- **代价**：操作者多一个维护面（issue 文档 + [eval] 声明）；`git rev-parse` 是一次外部进程调用（只读，失败降级 unknown）。
- **风险**：评测记录被误读为验收结论——免责声明随每条记录、CLI 输出措辞"machine facts, not acceptance verdicts"；workspace_version 依赖 git 且可能 unknown——记录里如实标注而非猜测。

## 4. 状态

- 实现：`pangu-core::eval`（EvalRecord/EvalStore/EvalContext/EvalRunFacts）、`pangu-boundary`（`[eval]` 声明 + ContractEval 冻结 + 条件 digest）、`pangu-agent`（Outcome 增加 turns/cost_usd）、`pangu` CLI（`pangu eval run|list`）。
- 默认不声明：无评测语义、无记录、digest 不变。
