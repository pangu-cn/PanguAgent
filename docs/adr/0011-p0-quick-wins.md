# ADR-0011：P0 快赢能力的 Pangu 式重写

- 状态：Proposed（2026-10-08）。本 ADR 只批准边界，不宣称八项都已实现。
- 关联：ROADMAP A1、A2、A6、B1、B4、E1；补丁对象为 ADR-0004、ADR-0005 与 ROADMAP §6。
- 来源：只吸收《分析报告-Agent横向对比》§8 的能力模式，不复制其权限模型。
- 当前事实：`MemSink` 与 `pangu conversation clone` 已存在。`prefix_stable`、`SessionForked`、`MemArtifactStore`、`simple_readonly_tool!`、`raw_tool_calls` 和 `scripts/code_health/` 尚未找到实现。

## 1. 状态与范围

八项可以做，因为它们都能保持“模型输出不是授权”。实施顺序必须先做无运行时影响的测试替身和代码健康告警，再做对话分叉，最后单独提交 opt-in 的原生工具调用解析。

## 2. 目标与非目标

### P0-1 前缀稳定性

做什么：给每次 `ContextAssembled` 增加派生字段 `prefix_stable`。首轮、工具集和 system 前缀未变化时为 true；出现降级、摘要、工具结果或工具集变化后为 false。

不做什么：不承诺上游 provider 命中 prompt cache，不推迟本轮已经批准的工具执行，也不为了缓存而隐藏安全提示。

### P0-2 四级准入

做什么：把 ROADMAP §6 增补为四层：内置 core、配置声明、skill 包、未来 E1 插件。每层写明批准人和 digest 位置。

不做什么：不新增加载器，不让配置、skill 或插件在缺少现有 L1–L4 路径时自动生效。

### P0-3 代码健康

做什么：新增仓库内脚本，统计函数圈复杂度、文件行数和嵌套深度。CI 对超限输出 warning，退出码保持 0。

不做什么：不把历史超限文件立刻改成 CI failure，不读取用户工作区或 Journal。

### P0-4 会话分叉

做什么：保留 conversation clone；补 session fork 动词和 provisional `SessionForked`。v1 明确打印“只复制对话，不复制工作区”。

不做什么：不调用 rollback，不复制 checkpoint、approval、effect ledger 或 workspace 文件。

### P0-5 内存测试替身

做什么：保留 `MemSink`，新增与正式 Artifact API 对齐的 `MemArtifactStore`，供单测和 SDK 测试使用。

不做什么：不把内存 store 用作生产恢复源，不在 drop 后声称数据仍可恢复。

### P0-6 只读工具宏

做什么：提供 `simple_readonly_tool!`，生成 `ReadOnly + Workspace + NoEffect` 的 spec 与 capability 样板。

不做什么：不生成 `execute`，不提供写入宏，不把样板当成已批准动作。

### P0-7 原生工具调用

做什么：增加默认关闭的 `[model] raw_tool_calls`。开启后只接受 provider 已解析且 schema 合法的调用，然后逐项进入 L1–L4。

不做什么：不从自由文本猜测工具调用，不跳过 Policy、Sandbox、Approval 或 VerifiedAction。

### P0-8 拆分红线

做什么：对 `crates/pangu-boundary/src/sandbox.rs` 和 `crates/pangu-agent/src/lib.rs` 使用 1500 行红线告警；通用文件告警线仍为 2000 行。

不做什么：不在本 ADR 中直接拆分这些文件，也不因当前超限阻断发布。

## 3. 准入分析

以下每项都按 ROADMAP §6 的十五问压缩记录。所有“模型能否自行扩权”的答案都是“否”；所有写入都有源记录或可重建来源。

| 项 | capability / 数据 | 网络 / 子 Agent / 记忆 | 无人值守 / 预算 | 失败恢复与威胁 |
| --- | --- | --- | --- | --- |
| P0-1 | 无 capability；只写派生 payload | 无 / 无 / 不持久化记忆 | 可无人值守；零成本 | 字段缺失保持未知，禁止猜测 |
| P0-2 | 无新 capability；只定义审查层级 | 无 / 无 / 无 | 不适用；无预算 | 未登记层级不得加载 |
| P0-3 | 无 runtime capability；只读源码 | 无 / 无 / 无 | CI 本地运行；无模型成本 | 脚本失败只告警，不改写代码 |
| P0-4 | 无模型 capability；CLI 写新 snapshot | 无 / 无 / 不写记忆 | 操作者命令；无模型预算 | 目标 ID 冲突 fail-closed |
| P0-5 | 测试 capability；内存读写 | 无 / 无 / 无 | 测试进程；无模型预算 | drop 即丢失，不恢复生产 |
| P0-6 | 只读声明；不可写 | 无 / 无 / 无 | 编译期；无预算 | 写入参数被宏拒绝 |
| P0-7 | 不新增工具；使用既有调用链 | 仅沿用原 provider 网络 | 默认关闭；沿用原预算 | 非法 schema fail-closed |
| P0-8 | 无 capability；只读指定源码 | 无 / 无 / 无 | CI 告警；无预算 | 行数统计失败不改变运行 |

P0-4 的批准与撤销不继承：新 run 对每个副作用重新走 L4。P0-7 的审批与撤销完全沿用被调用工具的原风险等级。两者都不存在“复制旧同意”或“解析即执行”。

兼容策略：旧配置缺省、旧 Journal 缺字段、旧 snapshot 都继续可读。迁移只追加新记录，不重写旧记录。

验收证据见第 7 节。第三方依赖方面，P0-3 不引入新依赖；P0-7 不新增模型供应商，只使用现有 OpenAI-compatible provider。其余项无新许可证审查对象。

## 4. L1–L4 影响

| 项 | L1 GoalContract | L2 Policy | L3 Sandbox | L4 Approval | 默认 digest |
| --- | --- | --- | --- | --- | --- |
| P0-1 | untouched | untouched | untouched | untouched | 不变 |
| P0-2 | untouched | untouched | untouched | untouched | 不变 |
| P0-3 | untouched | untouched | untouched | untouched | 不变 |
| P0-4 | untouched | untouched | untouched | untouched | 源 digest 不变 |
| P0-5 | untouched | untouched | untouched | untouched | 不进入生产 digest |
| P0-6 | untouched | untouched | untouched | untouched | 不变 |
| P0-7 | touched | touched | touched | touched | 关闭时不变 |
| P0-8 | untouched | untouched | untouched | untouched | 不变 |

P0-7 一旦设为 true，就属于 opt-in 配置并进入配置 digest。false 或缺省不得改变当前 digest。新 conversation 或 session 记录使用新 ID，不影响源记录 digest。

## 5. 事件、Journal 与配置兼容

- `prefix_stable` 是 `ContextAssembled.payload` 的新增可选字段，派生且非权威。旧事件没有该字段时，读取方必须报告“未知”，不能解释成 false。
- `SessionForked` 是 provisional kind。它记录 parent snapshot digest、new snapshot id 和 `workspace_copied=false`，不记录完整对话文本。
- Journal 只追加。不迁移、不重写、不改旧 hash。未知 kind 继续按现有前向兼容规则保留或拒绝，具体解码位置 [待核实：需读事件解码代码确认]。
- `raw_tool_calls` 缺省为 false。旧配置文件无需迁移。
- clone 使用现有 conversation schema 和新 snapshot id。源 snapshot、源 session node 和源 workspace 均保持不变。

## 6. 文件级任务

| 项 | crate / 文件 | 当前判断 |
| --- | --- | --- |
| P0-1 | `crates/pangu-agent/src/lib.rs`、`crates/pangu-core/src/events.rs` | 事件存在；字段待加 |
| P0-2 | `docs/ROADMAP.md` §6 | 十五问存在；四级表待加 |
| P0-3 | `scripts/code_health/`、`.github/workflows/ci.yml` | 脚本目录待建 |
| P0-4 | `crates/pangu/src/main.rs`、`crates/pangu-agent/src/conversation.rs`、`crates/pangu-core/src/events.rs` | clone 已有；fork/event 待加 |
| P0-5 | `crates/pangu-core/src/events.rs`、`crates/pangu-core/src/artifact.rs` | `MemSink` 已有；内存 Artifact 待加 |
| P0-6 | `crates/pangu-toolkit/src/lib.rs` 及对应测试 | 宏待加 |
| P0-7 | `crates/pangu-boundary/src/config.rs`、`crates/pangu-provider/src/lib.rs` | 响应解析位置 [待核实：需读 provider 分支确认] |
| P0-8 | `scripts/code_health/` 与 P0-3 共用 | 红线名单待加 |

当前超过 1500 行的已测文件包括 `pangu-agent/src/lib.rs`、`pangu-core/src/artifact.rs`、`pangu/src/main.rs`、`pangu-boundary/src/config.rs`、`pangu-toolkit/src/lib.rs`。这是本次测量结果，不是永久行号；脚本每次运行都重新计算。

## 7. 测试矩阵

| 项 | 行为契约与 fail-closed 用例 | 层级 |
| --- | --- | --- |
| P0-1 | 首轮为 true；工具结果后为 false；旧事件缺字段不误读 | 集成 |
| P0-2 | 四级表完整；未登记来源不能成为可加载工具 | 文档契约 |
| P0-3 | 超限样例产生 warning；脚本退出码为 0 | 单测 |
| P0-4 | 新 ID、源 digest 不变、workspace 不变；ID 冲突失败 | 集成 |
| P0-5 | 内存保存后可读；drop 后不可恢复 | 单测 |
| P0-6 | 宏生成 ReadOnly/NoEffect；写入声明无法生成 | 单测 |
| P0-7 | 默认解析不变；开启后非法 schema 被拒绝且无执行 | 集成 |
| P0-8 | 红线文件超限只告警一次；普通文件仍用 2000 行线 | 单测 |

P0-4 另需一个 CLI e2e：命令输出必须含“不复制工作区”。P0-7 另需一个 e2e：非法原生调用不能产生 tool evidence。

## 8. 验收门与回滚

| 项 | 完成标准 | 回滚 |
| --- | --- | --- |
| P0-1 | 字段有测试且旧 Journal 可读 | 删除 payload 字段 |
| P0-2 | ROADMAP 四级表与批准人完整 | 删除补丁段落 |
| P0-3 | CI 出现 warning 且不失败 | 移除 workflow step |
| P0-4 | clone/fork 均不改变源和 workspace | 隐藏命令并停止写新 kind |
| P0-5 | 测试不创建磁盘 Artifact | 删除内存类型 |
| P0-6 | 宏测试锁定只读边界 | 删除宏 |
| P0-7 | 默认关闭；非法调用 fail-closed | 强制配置回 false |
| P0-8 | 红线名单与告警测试存在 | 移除名单 |

八项可以独立回滚。P0-7 必须单独提交，避免与文档或测试替身混在同一次回滚里。

## 9. 永不做

按报告 §8.7，以下行为即使有现成外部实现也拒绝：

- 自动写长期记忆或自动接受记忆候选。
- 自动创建、下载或安装 skill。
- 默认 auto-approve、`--yolo` 或无人值守执行副作用。
- 自动 Git commit，或以 `--no-verify` 绕过 hooks。
- runtime 探测失败后退回宿主机直接执行。
- telemetry 默认开启。Pangu 事件默认留在本地，出站遥测必须另案 opt-in。

这些禁令优先于“快赢”。如果某项实现需要违反其中任何一条，该项从本 ADR 移除而不是放宽边界。

## 附录 A：实施任务

| 顺序 | 任务 | 影响面 | 回滚单位 |
| --- | --- | --- | --- |
| 1 | 内存 Artifact 与测试 | 仅测试 | 一个提交 |
| 2 | code health 告警与 1500 行红线 | CI | 一个提交 |
| 3 | 四级准入文档 | 文档 | 一个提交 |
| 4 | `prefix_stable` | 事件 payload | 一个提交 |
| 5 | session fork 与 `SessionForked` | CLI 与 Journal 追加 | 一个提交 |
| 6 | 只读工具宏 | toolkit API | 一个提交 |
| 7 | `raw_tool_calls` opt-in | provider 与 L1–L4 | 独立提交 |

## 附录 B：未核实项

- provider 当前在哪个函数把 `tool_calls` 转成 `ToolCall`，实施 P0-7 前需读取 `pangu-provider`。
- 旧事件解码器对未知 kind 的具体行为，实施 `SessionForked` 前需读取 `pangu-core` 的事件解码路径。
- `sandbox.rs` 的当前行数会随代码变化，不能写死为本 ADR 的验收数字；以脚本实测为准。
