# ADR-0011：P0 快赢能力的 Pangu 式重写

- 状态：Proposed（2026-10-08）。本文件是决策，不是实现完成声明。
- 关联：ROADMAP A1、A2、A6、B1、B4、E1；补丁对象为 ADR-0004 与 ADR-0005。
- 来源：只吸收《分析报告-Agent横向对比》§8 的能力模式，不复制其权限模型。

## 1. 决策

八项全部保留，但每项都收成“不增加模型权限”的形式：

1. 上下文前缀是否稳定必须进入 `ContextAssembled`，不能只写在日志句子里。
2. 工具准入分成四级；等级只决定审查强度，不决定运行时放行。
3. 代码健康检查先告警。超限不代表功能错误，因此当前不阻断 CI。
4. 会话可以复制或分叉，但 v1 只复制已脱敏对话，不复制工作区、审批或 checkpoint。
5. 测试可以使用内存事件 sink 与内存 Artifact store；它们不是生产存储。
6. `simple_readonly_tool!` 只能生成只读声明。写入工具必须手写 `assess`。
7. `raw_tool_calls` 只改变 provider 如何取得工具调用；调用仍逐项走 L1–L4。
8. 1500 行是拆分红线，2000 行是当前告警线。现有超限文件先登记，不在本 ADR 中假装已经拆完。

## 2. 目标与非目标

| 项 | 做什么 | 不做什么 |
| --- | --- | --- |
| P0-1 | 记录首轮前缀是否保持稳定 | 不承诺 provider 真正命中 prompt cache |
| P0-2 | 写明四级工具准入和批准人 | 不自动安装工具或扩大 manifest |
| P0-3 | 统计 CC、行数、嵌套并告警 | 不因历史文件超限而让 CI 失败 |
| P0-4 | 提供 conversation clone 与 session fork 的对话分叉 | 不回滚、不复制工作区 |
| P0-5 | 提供无文件测试替身 | 不替换正式 Journal 或 Artifact 语义 |
| P0-6 | 生成只读工具样板 | 不生成执行器，不让宏批准写入 |
| P0-7 | 可选接收 provider 原生工具调用 | 不跳过 schema、Policy、Sandbox、Approval |
| P0-8 | 对 `sandbox.rs`、`lib.rs` 设拆分门槛 | 不在本 ADR 内做大重构 |

## 3. 准入结论

十五问的统一答案：八项都不让模型扩大权限，也不创建不可回溯状态。差异如下。

- P0-1：只读派生事件字段。无网络、无写入、无子 Agent、无记忆。失败时事件省略该字段即视为旧记录，不猜值。
- P0-2：文档与审查门。插件仍是未来 E1，当前没有加载器。
- P0-3：本地 CI 读取源码。告警不可作为产品能力，也不读取用户工作区。
- P0-4：读取并写入一条新的 conversation snapshot。源 snapshot 不改；同 ID 克隆失败。无审批继承。
- P0-5：进程内存。drop 后消失，不能恢复生产运行。
- P0-6：编译期声明。执行仍要求真实 `ToolExecutor` 和 VerifiedAction。
- P0-7：默认关闭。配置错误、原生解析缺失或 schema 不合法时 fail-closed，不退回猜测执行。
- P0-8：与 P0-3 同一检查，仅增加指定文件的 1500 行红线告警。

任一实现若出现“复制后沿用旧批准”或“原生工具调用直接执行”，按准入模板否决，不进入代码。

## 4. L1–L4 影响

| 项 | L1 | L2 | L3 | L4 | digest |
| --- | --- | --- | --- | --- | --- |
| P0-1 | untouched | untouched | untouched | untouched | 默认不变 |
| P0-2 | untouched | untouched | untouched | untouched | 不变 |
| P0-3 | untouched | untouched | untouched | untouched | 不变 |
| P0-4 | untouched | untouched | untouched | untouched | 源记录不变；新记录单独 ID |
| P0-5 | untouched | untouched | untouched | untouched | 不进入生产 digest |
| P0-6 | untouched | untouched | untouched | untouched | 宏本身不改 digest |
| P0-7 | touched | touched | touched | touched | 仅启用 opt-in 时进入配置 digest |
| P0-8 | untouched | untouched | untouched | untouched | 不变 |

P0-7 是唯一进入执行链的配置。关闭时字节级行为与 digest 必须保持当前结果。

## 5. 兼容

- `prefix_stable` 与 `SessionForked` 都是新增可选字段或 provisional kind。旧 Journal 不重写，缺失字段不得被回放器当成 false。
- conversation clone 使用现有 snapshot schema 和新 ID。它不修改 ADR-0004 的恢复语义：恢复对话不是恢复授权。
- `raw_tool_calls = false` 是默认值。旧配置不写该键，行为不变。
- 代码健康脚本不读取 Journal、Artifact 或 workspace 用户文件。

## 6. 文件级任务

| 项 | 改动点 | 状态 |
| --- | --- | --- |
| P0-1 | `pangu-agent` 组装事件、`pangu-core` 事件 payload | [待实现] |
| P0-2 | `docs/ROADMAP.md` §6 增补四级表 | [待实现] |
| P0-3 | `scripts/code_health/` 与 `.github/workflows/ci.yml` | [待实现] |
| P0-4 | `pangu conversation clone` 已有存储写入；`session fork` 与 `SessionForked` 仍需补齐 | [部分已实现，事件待核实] |
| P0-5 | `MemSink` 已存在；`MemArtifactStore` 尚无对应类型 | [待实现] |
| P0-6 | `pangu-toolkit` 增加只读声明宏及契约测试 | [待实现] |
| P0-7 | `pangu-boundary` 配置与 `pangu-provider` 响应解析 | [待核实：需读 provider 响应分支] |
| P0-8 | 与 P0-3 共用检查，并登记当前超限文件 | [待实现] |

当前实测超过 1500 行的文件包括 `pangu-agent/src/lib.rs`、`pangu-core/src/artifact.rs`、`pangu/src/main.rs`、`pangu-boundary/src/config.rs`、`pangu-toolkit/src/lib.rs`。行数会变化，脚本必须以当前文件重新计算。

## 7. 测试矩阵

| 项 | 契约测试 | 层级 |
| --- | --- | --- |
| P0-1 | 首轮 `prefix_stable=true`；工具结果进入后不再标记稳定 | 集成 |
| P0-2 | 文档表含四级且每级都写明“不能自行生效” | 文档契约 |
| P0-3 | 超限样例产生 warning，退出码仍为 0 | 单测 |
| P0-4 | clone 新 ID 且源 digest 不变；重复目标 ID fail-closed | 集成 |
| P0-5 | 内存 store 保存、读取、drop 后不可恢复 | 单测 |
| P0-6 | 宏生成 ReadOnly/NoEffect；写入宏不存在 | 单测 |
| P0-7 | 关闭时旧解析不变；开启但 schema 非法时拒绝 | 集成 |
| P0-8 | 指定红线文件超限只告警一次 | 单测 |

## 8. 验收与回滚

- P0-1：事件可机器读取；删除 payload 字段即回滚。
- P0-2：ROADMAP 有四级表；删除补丁即回滚。
- P0-3：CI 可见 warning；移除 workflow step 即回滚。
- P0-4：clone 不改变源 snapshot；禁用命令即回滚。fork 在事件未落地前不得称完成。
- P0-5：测试无需磁盘 Artifact；删除内存类型即回滚。
- P0-6：宏无法构造写入能力；删除宏即回滚。
- P0-7：默认关闭且有非法 schema 拒绝测试；关闭配置即回滚。
- P0-8：红线名单明确；移除名单即回滚，不触及运行时。

## 9. 永不做

延续报告 §8.7：不做自动写长期记忆、自动安装技能、默认 auto-approve、自动提交、无沙箱失败后直跑宿主机，以及默认开启 telemetry。上述行为即使由外部 Agent 提供现成实现，也不进入 Pangu。

## 附录：实施顺序

1. 先补测试替身与代码健康告警，因为它们不改变运行。
2. 再补 `prefix_stable`、`SessionForked` 和 fork 命令，保持旧记录可读。
3. 最后做 `raw_tool_calls`。它是唯一触及 L1–L4 的 opt-in，必须单独提交、单独回滚。
