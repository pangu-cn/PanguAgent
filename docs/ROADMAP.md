# Pangu Agent 未来开发路线图（草案）

> **状态：阶段二实验性实现已存在，F7 尚未正式激活** · **基线：v0.1** · **定位：以安全边界为核心吸收优秀 Agent 经验，而不是复制竞品**

本文把“Hermes Agent、Pi Agent、ZCode、WorkBuddy、DeepSeek Harness（DSH）、OpenHands、SWE-agent、Aider、Cline”作为第一组参照对象。这里的“所有 Agent”暂按用户点名的九类理解；不把宣传语当作已验证的竞品结论，也不进行没有统一基准的性能排名。

## 0. 先说结论

Pangu 当前最值得走的路线不是变成“功能最多的桌面助手”，而是：

> **先把 Agent 变成可审计、可恢复、可扩展、可组合的安全运行时，再逐步吸收长任务、记忆、技能、远程执行、多 Agent 和办公产物能力。**

建议的默认顺序是：

1. **会话与结构化事件**（可恢复、可回放、可嵌入）；
2. **扩展能力与供应链边界**（工具/技能不能绕过 L1–L4）；
3. **审批与差异预览**（让用户看得见、控得住）；
4. **受控记忆和技能学习**（只能提出变更，不能自行获得权限）；
5. **长任务、远程执行和多 Agent**（放在安全基础之后）；
6. **办公产物和连接器**（最后做，按数据权限逐项开放）。

第一批不应默认包含：任意 shell、自动执行的学习结果、无限记忆、无人值守的破坏性操作、未审计的多 Agent 编排和任意第三方连接器。

---

## 1. 当前基线与不可丢掉的约束

当前仓库已经具备：

- `pangu-core`：消息、事件、错误、Journal 和 replay；
- `pangu-boundary`：L1 `GoalContract`、L2 `Policy`、L3 `Sandbox`、L4 `Approval`、预算；
- `pangu-agent`：唯一的 provider/tool 回合编排和 `VerifiedAction` 入口；
- `pangu-toolkit`：读文件、列目录、搜索、写文件、有限 HTTP GET、只读命令 allow-list、`finish`；
- `pangu-provider`：OpenAI-compatible provider；
- CLI：配置导出、`doctor`、dry-run、demo、append-only JSONL Journal；
- G1–G5：诚实、可审计、自主但不越界、成本有界、可嵌入。

以下内容仍是后续设计的硬约束，而不是可选功能：

- 模型输出永远不是授权；任何副作用都必须经过 **Policy → Sandbox → Approval → VerifiedAction → ToolExecutor**；
- `complete` 必须有成功工具 evidence；失败、预算耗尽和无答案不能被改写成完成；
- Journal、错误、provider 日志、工具输出和会话数据必须在边界处脱敏并限长；
- 预算必须覆盖父任务、重试、并行任务和子 Agent；
- 不能把“项目目录”误认为安全沙箱；应用层限制不能宣传成 OS 级隔离；
- 不把通用 shell、任意删除、凭据读取、支付、发邮件和默认放行作为便利功能偷偷加入。

相关规范：[`BOUNDARY.md`](BOUNDARY.md)；实现结构：[`ARCHITECTURE.md`](ARCHITECTURE.md)。

---

## 2. 参照 Agent 的优点、缺点与可借鉴点

### 2.1 证据等级和阅读规则

为避免把竞品宣传误写成事实，本文使用三种口径：

- **公开明确**：官方 README、文档或代码明确声明的能力；
- **工程代价**：根据其公开架构可以推导出的复杂度、权限面或运维风险，不等于已验证漏洞；
- **待验证**：闭源服务、版本差异或需要实际账号/基准才能确认的内容。

产品迭代很快，下面比较的是“能力模式”，不是某个固定版本。真正落地前应固定版本、运行环境、模型和测试任务，并重新验证。

### 2.2 总览矩阵

| 参照对象 | 主要优势 | 主要缺点/风险 | 对 Pangu 的正确借鉴 |
|---|---|---|---|
| **Hermes Agent** | 记忆与经验学习、技能自创建、跨渠道 Gateway、定时任务、子 Agent/并行、多种运行后端和多模型接入 | 长时间自治会放大错误半径；自动写入记忆可能被污染；技能和脚本供应链风险；无人值守任务的网络、凭据和费用风险；部署面较大 | 借鉴“受控记忆、技能提议、Gateway、调度、子 Agent”，但所有学习和子任务都必须重新经过 Pangu 边界 |
| **Pi Agent** | 小而可组合的核心；TUI；会话树、分支、fork、compaction；JSONL/RPC/SDK；多 provider；扩展生态；容器化建议 | 官方明确说明没有内建文件/进程/网络权限系统，默认继承启动用户权限；扩展在进程内运行；会话和导出内容可能包含敏感数据；可扩展性带来较大供应链面 | 借鉴会话树、事件协议、扩展 API、RPC/SDK 和隔离部署；**不能照搬其权限模型** |
| **ZCode** | 桌面、浏览器、终端多形态；共享 UI/后端；本地 Web 服务；SSH/WSL 远程项目；Agent runtime 与发行包一体化 | 桌面/Web/Server/远程组合扩大认证、网络和供应链攻击面；本地服务 token、监听地址、远程同步需要严格控制；大型 monorepo 的构建、版本和兼容成本高 | 借鉴统一工作台、远程 runner、发行包和可嵌入客户端；先做安全认证和远程动作审计 |
| **WorkBuddy** | 面向办公场景；多 Agent 协作；强调从复杂目标拆解到报告、演示文稿、表格等可交付物；强调可验证结果 | 多 Agent 会放大权限、费用和不确定性；办公连接器可能接触敏感文件/企业数据；云服务、账号和模型依赖影响可嵌入性与可复现性；“可验证输出”仍需独立证据；闭源细节需实测 | 借鉴“产物优先、任务拆解、证据验收”的产品形态；连接器必须按数据域和副作用分级授权 |
| **DeepSeek Harness（DSH）** | MIT 开源；Everything is a Plugin；Web/headless/SDK/ACP/Desktop 多入口；append-only SessionEvent；能力 seam、可组合 profile、事件驱动扩展；本地 Web UI 和 SSH 启动 | 官方明确标注 developer preview、未经安全审计且可能有兼容性破坏；全插件架构和大量能力扩大供应链/配置/权限面；会话日志和多入口增加隐私、认证、迁移和运维复杂度；TypeScript/Cordis 架构不能直接等同于 Pangu 的 Rust 边界模型 | 借鉴事件溯源、能力 seam、profile、多入口和可逆插件生命周期；保留 Pangu 的中心安全闸门，不让插件替换 Policy/Sandbox/Approval |
| **OpenHands / Agent Canvas** | 自托管开发者控制中心；可在本地、Docker、VM、Kubernetes、远程或云端切换 Agent backend；SDK/Agent Server 提供 Python、TypeScript、REST API；支持 ACP、自动化、事件、workspace、skills/plugins 和多种模型 | 直接运行时拥有宿主文件、环境和网络权限；浏览器控制面、API key、远程 backend 和 webhook 自动化扩大认证与运维面；多仓库、多个运行组件和常驻服务增加版本/部署矩阵 | 借鉴控制平面与执行平面分离、backend capability、Agent Server、workspace/event API 和自动化幂等；远程执行默认进入沙箱，UI 不保存长期主密钥 |
| **SWE-agent** | 研究导向的自主软件工程 Agent；面向 GitHub issue 修复和 SWE-bench；free-flowing agency、单 YAML 配置、可扩展工具 bundle、完整 trajectory 和可复现实验配置 | 自主 shell、文件和网络操作权限很大；benchmark 结果不能直接代表生产任务；trajectory 可能记录敏感上下文；自定义工具的 `install.sh`/脚本是供应链入口；官方已提示 mini-SWE-agent 取代主项目 | 借鉴 issue contract、trajectory/replay、批处理评测和可配置工具包；仅在沙箱和预算内运行，工具必须经过 Pangu 中心边界，评测分数不能替代验收证据 |
| **Aider** | 终端协作编程；Repo Map 用依赖图和 token budget 选择代码上下文；Git 自动提交、dirty tree 保护和 `/undo`；编辑后自动 lint/test/compile；支持云端、本地模型、IDE、图像和网页上下文 | 自动提交和提交用户原有 dirty changes 可能改变 Git 工作流；默认跳过 pre-commit hook；Repo Map 会产生上下文、成本、隐私和时效问题；lint/test/run 命令及网页输入仍可能执行不可信内容 | 借鉴 Repo Map、Git-native checkpoint、测试证据闭环和可控上下文选择；Pangu 中默认不自动提交，所有测试/命令和外部内容都经过边界与脱敏 |
| **Cline** | IDE、CLI、Desktop、JetBrains 和 SDK 多入口；Plan/Act、diff、checkpoint/undo、人工审批；多 provider/本地模型；插件、MCP、多 Agent teams、定时任务、headless NDJSON 和聊天连接器 | CLI 默认可自动批准工具，`--yolo`/`--zen` 可无人值守；MCP/插件/连接器扩大供应链和凭据面；持久 teams/schedules 需要重放、预算和幂等控制；多端状态和 JetBrains 插件的开放范围需持续核验 | 借鉴 Plan/Act、审批 UX、checkpoint、NDJSON 事件和受限 teams；所有入口复用 Pangu 中心 Policy/Sandbox/Approval，默认禁止 yolo 式执行 |

### 2.3 Hermes Agent：学习闭环与长任务编排

**可确认的优点（公开资料）**

- 以“会随使用成长”为核心：记忆、会话搜索、技能创建和技能迭代形成闭环；
- CLI/TUI 与 Telegram、Discord、Slack、WhatsApp、Signal 等渠道结合，适合持续任务；
- 提供定时自动化、并行/委派子任务和多种终端/容器/远程后端；
- Provider 选择面较宽，减少对单一模型的锁定。

**缺点与警示**

- **W-01：自学习不等于自验证。** 模型可能把错误、恶意内容或一次性任务偏好写入长期记忆；必须有来源、置信度、来源事件和人工/策略校验。
- **W-02：无人值守会放大错误半径。** cron、Gateway 和远程后端若没有每次运行的 GoalContract、预算和审批，可能长期执行错误动作。
- **W-03：技能是代码和指令的混合体。** 技能附带脚本时，安装或自动生成都等价于引入供应链执行面。
- **W-04：多后端带来运维分叉。** 本地、Docker、SSH、云沙箱的路径、环境、凭据、网络和失败语义不同，测试矩阵会迅速扩大。
- **W-05：持久记忆涉及隐私。** 会话、用户画像和任务历史可能包含路径、凭据、商业信息；需要分层保留、导出、删除和脱敏策略。

**Pangu 的采用方式**

- 先做“记忆候选”和“技能候选”：模型只能提交 proposal；
- proposal 必须显示来源、影响范围、预计成本和可执行动作；
- 通过策略检查后才进入候选库，必要时仍需人工批准；
- 长任务使用独立 run contract，子 Agent 继承不了超出父任务的权限；
- 不提供“自动自我扩张边界”的工具。

### 2.4 Pi Agent：极简核心、会话树和可嵌入接口

**可确认的优点（官方文档）**

- “minimal, extensible”：核心小，资源和工作流可以按需扩展；
- 会话以树保存，支持继续、切换、fork、clone、compaction；
- 同一套运行时支持交互 TUI、print、JSON 事件流、RPC 和 TypeScript SDK；
- Provider、工具、扩展、事件和 UI 都有明确的扩展点；
- 官方提供多种隔离部署思路，并明确指出直接运行时继承操作系统权限。

**缺点与警示**

- **W-06：权限边界不是内建能力。** 官方文档明确指出工具和扩展使用启动进程的操作系统权限，项目 trust 不是工具沙箱；这与 Pangu 的 L1–L4 目标不同。
- **W-07：扩展是进程内代码。** 扩展能访问 prompt、tool call、文件、凭据和会话历史；第三方包必须锁版本、审代码、签名并最小权限加载。
- **W-08：持久化会话可能泄密。** 导出或分享前必须检查文件内容、命令输出、路径、凭据和隐藏上下文。
- **W-09：能力越多，宿主越难推理。** 动态工具、扩展 hook 和 compaction 可能让用户误判实际执行了什么；Pangu 必须保留结构化事件和最终计划快照。
- **W-10：生态便利性有供应商锁定代价。** npm 包、配置格式和扩展 API 变化会形成迁移成本。

**Pangu 的采用方式**

- 吸收 session tree、JSONL/RPC/SDK 的接口思想；
- 扩展只能注册 capability manifest，不能自行执行副作用；
- 所有自定义工具必须实现 `assess → execute(VerifiedAction)`，不能获得模型原始调用；
- 借鉴 Pi 的资源发现/信任决策，但把“信任项目文件”和“允许副作用”严格分开；
- 将容器/VM 作为可选执行后端，而不是把应用层检查冒充 OS 隔离。

### 2.5 ZCode：桌面、Web、CLI 和远程工作区一体化

**可确认的优点（公开仓库）**

- 同一产品覆盖桌面应用、浏览器界面和终端 Agent；
- 有共享 UI、后端、RPC/协议层和 Agent runtime，适合做工作台；
- 支持 SSH/WSL 等远程项目场景，能把本地体验延伸到远程工作区；
- 有发行包、校验摘要、安装脚本和 Web 启动方式，产品化链路较完整。

**缺点与警示**

- **W-11：多端同源不等于多端同安全。** 桌面、WebSocket、HTTP、文件上传和远程工作区每一个入口都要单独认证、授权、限流和审计。
- **W-12：本地服务暴露风险。** 监听 `0.0.0.0`、关闭 token、跨域访问和 WebSocket 连接都可能导致越权；默认应只监听 loopback，远端访问必须显式启用认证。
- **W-13：远程同步扩大数据面。** SSH/WSL 连接、文件传输、凭据注入和远程执行必须绑定到具体 run contract，不能只信任前端传来的 workspace。
- **W-14：大型发行链的维护成本。** 桌面、Web、后端、CLI、远程资源、签名和升级需要兼容矩阵；Pangu 不应在核心稳定前复制全部形态。
- **W-15：工作台容易把“显示成功”误当“动作完成”。** UI 状态必须来自 Journal/终态事件，不应由前端自行推断。

**Pangu 的采用方式**

- 先做 headless CLI + JSONL/RPC，再做可选 Web/TUI；
- 远程 runner 采用一次性能力令牌、最小挂载、短时凭据和全量事件回传；
- Web 端只发意图，不直接执行工具；所有执行仍回到 Agent 的中心边界；
- 发行包必须带版本、依赖锁、SBOM/第三方声明和可验证摘要。

### 2.6 WorkBuddy：办公产物与多 Agent 交付

**可确认的优点（公开定位）**

- 面向办公任务，而不是只面向代码编辑；
- 官方定位强调多 Agent 协作、自动拆解复杂任务；
- 强调报告、演示文稿、电子表格等可交付成果；
- 以“完成并可验证的结果”作为产品目标，而不是只展示聊天过程。

**缺点与警示**

- **W-16：办公连接器权限高。** 邮件、文档、云盘、表格和浏览器连接器可能读取或修改组织数据，必须按数据域、动作和租户隔离。
- **W-17：多 Agent 成本和不确定性叠加。** 子 Agent 数量、重试、并行度和模型选择都可能放大费用、延迟和错误结论。
- **W-18：可验证输出可能被误读。** 生成了一份报告或表格不等于事实正确；必须附来源、时间、数据版本、校验规则和人工签收。
- **W-19：云服务依赖影响可复现性。** 账号、模型、区域、服务策略和接口变化可能使同一任务无法复跑。
- **W-20：闭源和可嵌入性需要实测。** 在没有确认 API、数据处理、连接器授权和部署方式前，不应把其能力当作 Pangu 的依赖。

**Pangu 的采用方式**

- 先做“产物对象”而不是“办公账号”：
  - `Artifact`：文件类型、版本、来源、生成者、校验结果；
  - `Evidence`：工具证据、引用、测试和人工确认；
  - `Acceptance`：用户明确的验收条件；
- 连接器只能由宿主注册，且每次调用都走 Policy/Sandbox/Approval；
- 多 Agent 只能在任务 DAG 中使用受限子合同，不能互相转发未经验证的 `VerifiedAction`；
- 任何“完成”都必须能回溯到产物和证据，而不是只显示一段自然语言总结。

### 2.7 DeepSeek Harness（DSH）：插件化组合、事件溯源与多入口

**可确认的优点（官方仓库/架构文档）**

- 采用 “Everything is a Plugin” 的架构，基于 Cordis；模型适配器、工具、会话、Agent loop 等能力都以插件贡献，可通过配置替换或组合；
- 提供 profile/bundle 组合方式，以及 `web`、`headless`、`sdk`、`sdk-minimal`、`acp` 等入口，并有桌面端和 Python SDK；
- Web UI 默认从本机 loopback 地址启动，支持本地使用和 SSH 启动场景；
- 使用 append-only `SessionEvent` 作为会话事实源，模型可见上下文、fork、resume、transcript、telemetry 和 persistence 都从日志派生，并提供版本化迁移路径；
- 通过 typed events 和 capability seams 区分服务定义、服务提供者和消费者，工具、文件系统、子进程、sandbox、subagent 等能力有清晰的扩展接缝；
- 官方安全声明主动说明实验性质、主机访问风险和沙箱局限，这比把应用层审批包装成绝对安全边界更适合 Pangu 参考。

**这些优点对 Pangu 的价值**

- 事件溯源和“模型可见内容必须可从日志重建”直接强化 G2/G5，可作为 A1/A2 的实现参考；
- capability seam 适合 Pangu 的 `Provider`、`ToolExecutor`、`ApprovalHandler` 和事件 sink 分层，但 Pangu 的安全闸门仍应保持中心化、不可被普通插件替换；
- profile/多入口适合规划未来的 headless、SDK、Web、ACP 和远程 runner，但应先完成核心库和事件契约；
- 插件注册采用可撤销 effect 的思路，有助于热重载、隔离和回滚；Pangu 需要在此基础上增加签名、capability manifest 和供应链审查。

**缺点与警示**

- **W-21：Developer preview 和快速迭代。** 官方 README 明确警告尚未经过安全审计，并可能发生兼容性破坏；不能把当前 API 当作稳定公共协议；
- **W-22：Everything is a Plugin 会扩大供应链面。** 插件可贡献工具、模型、命令、会话和服务，配置叠加后很难判断最终实际能力；插件必须签名、锁版本、最小授权并可回滚；
- **W-23：能力范围广，宿主权限风险高。** 架构包含 shell、subprocess、SSH、terminal、browser/computer use、MCP、subagent、jobs、schedule 等能力；审批和 sandbox 只能降低风险，不能保证隔离；
- **W-24：Web/SDK/ACP/Desktop/SSH 多入口增加认证面。** loopback 默认绑定是必要条件，但远程启动、Host、WebSocket、桌面 IPC 和插件安装仍需分别做身份、来源、权限和审计控制；
- **W-25：持久会话日志带来隐私和迁移负担。** SessionEvent 可能保存 prompt、工具参数、输出和上下文；需要脱敏、访问控制、保留期限、导出检查和版本迁移策略；
- **W-26：技术栈迁移成本。** DSH 的 TypeScript/Cordis/Cordis patch 体系与 Pangu 的 Rust crate/L1–L4 设计不同，照搬会增加维护面；应吸收架构模式而不是整体移植。

**Pangu 的采用方式**

- 采用 append-only、版本化、可迁移的 session event 模型，并要求所有模型可见输入可回溯；
- 把插件限制在能力注册和适配层，Policy、Sandbox、Approval、预算和 `VerifiedAction` 构造器不能由普通插件替换；
- 先规划 `core`、`headless`、`web`、`sdk` 等 profile，再考虑 Desktop、ACP 和 SSH；每个入口复用同一中心执行链；
- 借鉴可逆插件 effect，但先实现静态加载、签名校验和可逆卸载，再考虑热重载或运行时自修改；
- 把 DSH 的安全声明作为路线门槛：任何实验性能力都必须标记状态、权限范围、迁移路径和禁用开关。

### 2.8 OpenHands / Agent Canvas：自托管控制平面与多后端执行

**资料边界**

当前 `OpenHands/OpenHands` 官方仓库的 README 主要描述 Agent Canvas；核心 Python SDK、Agent Server、workspace、事件和工具实现位于 `OpenHands/software-agent-sdk`。Pangu 应分别参考“控制台/控制平面”和“执行 SDK/Server”，不要把不同仓库边界混成一个组件。

**可确认的优点（官方仓库/文档）**

- Agent Canvas 是自托管的开发者控制中心，可在本地、Docker、VM、企业基础设施或云端 backend 之间切换；
- 可运行 OpenHands、Claude Code、Codex、Gemini 或其他 ACP-compatible Agent，并支持自带模型；
- SDK 提供 Python、TypeScript 和 REST API；Agent Server 支持本地 workspace 或 Docker/Kubernetes 等临时 workspace；
- 提供 conversation、workspace、event、REST/WebSocket、skills/plugins、MCP 和自动化接口；
- 自动化可以按计划或 webhook 触发，并连接 GitHub、Linear、Slack 等外部系统。

**缺点与警示**

- **W-27：直接运行可能拥有完整宿主权限。** 官方自托管文档明确警告，未使用 sandbox 时 Agent 可以读写宿主文件、执行 shell 并访问网络；远程 backend一旦被攻破，风险会转移到生产凭据所在机器；
- **W-28：控制平面会引入浏览器凭据风险。** 公开模式需要 API key，官方文档还提示同源的编辑器内容可能读取浏览器 `localStorage` 中的 backend key；长期主密钥不应直接交给前端；
- **W-29：自动化和 webhook 需要幂等语义。** 外部事件重投、重复消费、任务取消、网络重试和部分成功都可能造成重复副作用；schedule、webhook 和 backend dispatch 必须有独立 contract 与审计；
- **W-30：多仓库、多组件和常驻服务增加运维矩阵。** Canvas、SDK、Agent Server、automation、Ingress、WebSocket 和模型/工具依赖的版本漂移会改变安全边界，不能只升级单个包。

**Pangu 的采用方式**

- 将控制平面与执行平面分离：UI、API 和自动化只提交带版本的 run contract，不能直接执行工具；
- 远程 backend 必须先完成能力探测、身份认证、沙箱声明和 workspace 挂载检查，默认使用临时身份与最小挂载；
- 事件、REST/WebSocket、ACP 和 headless 输出统一进入 Pangu Journal，并为每个事件保留 schema 版本；
- 自动化任务必须有幂等键、截止时间、预算、取消、重试上限和人工签收规则；
- 不把 backend 长期 API key 写入浏览器存储，使用短时、限权、可撤销的会话凭据。

### 2.9 SWE-agent：研究型自主软件工程与可复现实验

**可确认的优点（官方仓库/文档）**

- 面向真实 GitHub issue 修复、漏洞研究和自定义软件工程任务，强调 free-flowing and generalizable 的自主循环；
- 以单个 YAML 配置管理模型、工具、 demonstrations、环境和实验参数，适合批量 benchmark 和复现实验；
- 自定义工具以 bundle 组织，包含接口配置、可执行脚本和可选安装脚本，扩展接口简单且适合研究；
- 输出完整 trajectory，记录 thought、action、observation、状态以及发送给模型的 query，可用于调试、回放和把成功轨迹转成 demonstration；
- 官方提供 SWE-bench 集成、批处理和多种模型/解析方式，且明确面向研究和可修改性。

**缺点与警示**

- **W-31：自主循环和 benchmark 结果不能直接当成生产安全证明。** “free-flowing”意味着模型可能连续调用 shell、编辑器和网络；SWE-bench 的任务分布也不能代表所有真实仓库、权限和组织流程；
- **W-32：trajectory 可能泄漏敏感上下文。** thought、query、命令输出、环境状态和文件内容可能包含源码、凭据、内部 URL 或个人信息；日志访问、保留和导出必须分级；
- **W-33：自定义工具 bundle 是代码供应链入口。** `bin/` 脚本、`install.sh`、环境变量和依赖安装都可能执行任意代码或改变实验环境，不能因“研究可修改性”而跳过签名、锁定和隔离；
- **W-34：项目状态和版本迁移需要持续核验。** 官方 README 已提示 mini-SWE-agent 取代 SWE-agent 并成为后续主要开发方向；旧配置、trajectory schema、模型默认值和 benchmark 流程不能默认兼容。

**Pangu 的采用方式**

- 把 SWE-agent 的 issue→patch→test 流程作为可选评测 profile，而不是默认的通用执行模式；
- 用 `GoalContract` 固定 issue、允许修改的 roots、测试命令、预算、deadline 和验收条件；
- 将 trajectory 映射为结构化事件和可回放摘要，原始上下文单独加密、脱敏并限制保留期限；
- 工具 bundle 只能注册 capability manifest，安装和执行均需经过签名检查、Sandbox 和 Approval；
- benchmark 分数、模型自评和自然语言总结都不能替代测试 evidence 与人工验收。

### 2.10 Aider：Repo Map、Git 事务和编辑后验证

**可确认的优点（官方文档）**

- 以终端 pair programming 为核心，支持云端模型、本地模型、IDE 监听、图片、网页和语音输入；
- Repo Map 为模型提供整个 Git 仓库的文件、关键类/函数、类型和调用签名，并通过依赖图排序和 token budget 选择相关上下文；
- 与 Git 深度集成：编辑后自动生成提交信息，支持 `/diff`、`/undo`、分支审查，并在 dirty tree 上采取保护策略；
- 每次修改后可自动运行 lint、test、编译和用户自定义命令，形成较短的“编辑—检查—修复”闭环；
- 支持大量语言和 Git 工作流，适合作为单仓库、低 ceremony 的编码 Agent。

**缺点与警示**

- **W-35：自动提交可能改变用户 Git 语义。** Aider 默认在编辑后提交，甚至会先提交已有 dirty changes；提交信息由较弱模型生成，可能污染历史、分支或 hooks 语义；
- **W-36：默认跳过 pre-commit hook 会削弱仓库门禁。** 官方 Git 文档说明默认使用 `--no-verify`；如果用户没有显式启用验证，AI 提交可能绕过项目既有检查；
- **W-37：Repo Map 仍会扩大上下文、成本和隐私面。** 大量源码/符号可能发送给外部模型，索引可能过期，图排序可能漏掉运行时关系；超大仓库会消耗上下文和费用；
- **W-38：验证命令和外部输入本身不可信。** lint、test、compile、`/run` 会执行项目代码，网页、图片、语音转写和 issue 文本可能包含提示注入或恶意内容；自动修复不能被视为安全验证。

**Pangu 的采用方式**

- 将 Repo Map 作为只读、可解释的 context selector，显示选取原因、来源文件和 token 成本，并允许用户排除路径；
- 用 Pangu Journal/Artifact 记录 Git diff、测试命令、退出码、测试摘要和恢复点；默认不自动 commit；
- 将“编辑后验证”做成可关闭的 verification loop，测试失败只能产生 evidence 或修复提议，不能自动宣称完成；
- 对外部网页、图片、语音和命令输出做内容隔离、脱敏和来源标记；
- Git 操作、测试命令和修复写入均回到 `Policy → Sandbox → Approval → VerifiedAction` 链。

### 2.11 Cline：Plan/Act、多入口协作与可组合 Agent 平台

**可确认的优点（官方仓库/文档）**

- 同一 Agent core 覆盖 VS Code、JetBrains、CLI、Desktop 和 SDK，适合做统一的工作台和多入口产品；
- Plan/Act 模式把探索/计划与执行分开；编辑以 diff 展示，checkpoint/undo 支持回退；
- 支持人工审批、多个云端 provider、OpenAI-compatible endpoint 和本地模型；
- SDK、插件、MCP、自定义工具和 lifecycle hook 可扩展日志、审计、策略和领域能力；
- 提供多 Agent teams、cron/event schedules、headless/JSON/NDJSON、聊天连接器和持久 session，适合研究自动化与 CI/CD 集成。

**缺点与警示**

- **W-39：不同入口的审批默认值不一致。** 官方 CLI 文档写明工具默认可自动批准；`--yolo` 和 `--zen` 会在没有人工介入时跳过审批，退出 CLI 后后台任务仍可能继续执行；不能把 IDE 中的 human-in-the-loop 体验推断为所有入口都安全；
- **W-40：MCP、插件和连接器是执行与凭据供应链。** 远程 server、stdio command、OAuth/token、云服务和领域 connector 可能获得文件、数据库、消息或部署权限；
- **W-41：持久 teams、schedules 和 connector session 需要状态机。** 任务重放、重复 webhook、跨入口恢复、并发 team、预算汇总和部分成功不能靠聊天文本推断；
- **W-42：多端发行和开放范围存在兼容性约束。** CLI、扩展、Desktop、SDK 的协议和状态可能不同步；官方 README 标注 JetBrains 插件当前并未开源，不能把所有界面行为都当作可审计的同源实现。

**Pangu 的采用方式**

- 借鉴 Plan/Act 的交互流程，但把计划、审批、执行和验证状态全部落到结构化事件；
- 默认所有副作用都需要显式审批，`yolo`/后台模式只能在临时 sandbox、短时 token 和固定 capability 内开启；
- 以 Pangu 的 capability manifest 统一约束 CLI、IDE、Web、Desktop、SDK 和 ACP 入口；
- 为 NDJSON、checkpoint、session、connector 和 team state 定义版本、幂等键、取消和恢复协议；
- MCP/插件只提供注册和适配层，不能替换 Policy、Sandbox、Approval、预算或 `VerifiedAction` 构造器。

---

## 3. 特性候选菜单（由用户勾选）

下面每一项都可以单独选择，也可以先不选。`风险`表示实现后需要重点防范的失败模式，不表示一定不能做。

标记说明：`[x]` 表示“需求已确认并写入 ADR”，不表示“已批准实现”。

### A. 核心交互、审计和恢复

- [ ] **A1 会话树与恢复**：借鉴 Pi/Hermes/DeepSeek Harness/OpenHands/Cline，支持 resume、branch、fork、compaction；每个节点可回放。
- [ ] **A2 结构化事件兼容层**：在现有 Journal 之外提供稳定的 JSONL/NDJSON 事件流、事件版本和迁移器；借鉴 Pi JSON/RPC、ZCode 协议层、DeepSeek Harness 的 SessionEvent、OpenHands Agent Server 和 Cline headless 模式。
- [ ] **A3 审批与差异预览**：显示文件 diff、命令预览、网络目标摘要、预计风险和影响范围；借鉴 Pi 的交互扩展点和 Cline 的 Plan/Act、checkpoint/undo。
- [ ] **A4 `doctor`/`explain`/策略模拟**：在不执行副作用的情况下解释配置、规则命中顺序、预算和预计阻塞点；扩展 Pangu 现有能力，并参考 OpenHands backend 状态检查。
- [ ] **A5 会话导出与隐私检查**：导出前扫描 secret、绝对路径、命令输出和大对象；借鉴 Pi session export、SWE-agent trajectory 和 Cline history。

### B. 扩展、技能和模型

- [ ] **B1 Capability Manifest**：借鉴 Pi/ZCode/DeepSeek Harness 的 capability seam，以及 OpenHands SDK、Cline SDK/MCP；插件/扩展声明工具、风险、读写 roots、网络 host、预算和版本，只能通过中心边界执行。
- [ ] **B2 技能注册表与签名包**：借鉴 Pi 的 Agent Skills、Hermes 的技能学习、DeepSeek Harness/OpenHands 的 skills/plugins 和 Cline 的 rules/skills，但默认只加载说明，脚本需显式批准。
- [ ] **B3 受控记忆候选队列**：借鉴 Hermes 的学习闭环；模型只能提出记忆，用户/策略确认后写入，保留来源和撤销能力。
- [ ] **B4 Provider Registry**：统一 OpenAI-compatible 之外的 provider 配置、能力探测、模型能力声明和成本表；借鉴 Pi、OpenHands、Cline 和 Aider 的多 provider/本地模型设计。
- [ ] **B5 Provider fallback 策略**：只有兼容性、价格、健康状态和用户策略均允许时才 fallback；禁止静默切换到更宽权限模型。
- [ ] **B6 本地部署 JEV（用户可选）**：支持把 JEV 作为本地决策服务/模型运行，用于 triage、gate、routing 等有界判断；默认关闭，由用户在配置或安装时显式开启。JEV 不得成为 Pangu 核心启动依赖，不得直接创建 `VerifiedAction`、修改 Policy/预算/审批模式或执行工具；服务默认仅绑定 loopback，模型下载、远程 endpoint 和数据出站必须分别显式配置。

### C. 长任务和交互体验

- [ ] **C1 交互式 TUI**：实时显示回合、工具、审批、预算和 Journal 状态；借鉴 Pi/Hermes/ZCode/Aider/Cline。
- [ ] **C2 Gateway 渠道**：CLI 之外增加 Web/API 或消息渠道适配器；借鉴 Hermes、OpenHands automation 和 Cline connectors；所有渠道共用同一 run contract。
- [ ] **C3 定时任务与持久任务**：借鉴 Hermes/OpenHands/Cline；每个任务独立 workspace、预算、审批策略、取消和过期时间。
- [ ] **C4 远程 Runner**：借鉴 ZCode 的 SSH/WSL 思路、OpenHands Agent Server 和 Cline SDK/ACP；支持临时挂载、短时令牌、断线恢复和完整审计。
- [ ] **C5 隔离执行配置**：借鉴 Pi 的容器/VM 思路、OpenHands 的 Docker/Kubernetes workspace 和 Cline 的 sandbox/data-dir；提供 local、container、remote profile，并明确每种 profile 的真实保护范围。

### D. 多 Agent 和产物

- [ ] **D1 受限子 Agent**：借鉴 Hermes/WorkBuddy/DeepSeek Harness/OpenHands/Cline；子 Agent 只有父任务授予的 capability budget，不能扩大权限。
- [ ] **D2 并行任务 DAG**：借鉴 OpenHands/Cline teams；每个节点独立预算、取消、超时、重试和终态，禁止无界 fan-out。
- [ ] **D3 Artifact + Evidence 管线**：借鉴 WorkBuddy 的产物导向、Aider 的 Git diff 和 Cline 的 checkpoint；支持报告、代码补丁、表格等结构化产物。
- [ ] **D4 产物验收器**：定义 schema、测试、引用、数据版本和人工签收；借鉴 Aider 的 lint/test loop 与 Cline 的 diff/checkpoint；没有验收证据不能标记完成。

### E. 连接器和办公工作台

- [ ] **E1 受限 MCP/Connector SDK**：只允许声明式、只读或显式高风险连接器；借鉴 OpenHands/Cline 的 MCP、插件和 connector 方向，不默认接入办公账号。
- [ ] **E2 报告/演示/表格适配器**：借鉴 WorkBuddy；先支持本地文件和可验证格式，再考虑云端服务。
- [ ] **E3 Web/Desktop 外壳**：借鉴 ZCode/WorkBuddy/DeepSeek Harness/OpenHands/Cline；UI 只提交目标和审批请求，不能持有工具执行权或长期 backend 主密钥。
- [ ] **E4 远程/移动端只读监控**：查看 Journal、预算和任务状态；默认不允许从移动端直接执行高风险动作。

### F. 编码工作流和评测（由用户勾选）

这些候选直接吸收 OpenHands、SWE-agent、Aider 和 Cline 的代码工作流优势；它们仍然必须服从 Pangu 的中心边界，不代表默认开放任意 shell 或自动提交。

- [ ] **F1 Repo Map / 代码库地图**：借鉴 Aider，生成可解释的文件、符号、依赖图和 token budget；默认只读，显示来源、时效和发送给模型的上下文。
- [ ] **F2 Git diff/undo 可选后端**：借鉴 Aider 和 Cline，保存可审查的 diff、恢复点和 Git 辅助信息；它不是 Pangu checkpoint 的必需实现，默认不自动 commit，不跳过项目 hooks。
- [ ] **F3 Lint/Test/Compile evidence loop**：借鉴 Aider、Cline 和 OpenHands，在编辑后运行受限验证命令，记录退出码、测试摘要和产物；失败不能自动改写为完成。
- [ ] **F4 Plan/Act 与逐步审批**：借鉴 Cline 和 OpenHands 的计划/执行分离；Plan 阶段只读探索，Act 阶段逐项显示 diff、命令和影响范围。
- [ ] **F5 Issue-to-patch 评测 profile**：借鉴 SWE-agent，把 issue、仓库版本、测试、patch、trajectory 和成本固定为可复现实验；benchmark 分数不替代验收。
- [ ] **F6 控制平面与 backend/automation profile**：借鉴 OpenHands Agent Canvas，支持本地、Docker、VM、远程 backend 和计划/webhook 任务；每个 backend 和任务都独立认证、限额、幂等和审计。
- [x] **F7 Pangu Artifact 检查点与受限回退（需求已确认；ADR 已批准；阶段二实现已存在；默认关闭、实验性 opt-in、未正式激活）**：已实现成功 VerifiedAction 后的工作区快照、稳定事件指针、session node、operation ledger、typed rollback、failed-path/effect ledger、Journal v2 receipt 和 CLI 子命令；回退只恢复文件系统/会话状态，不回退外部副作用；默认不自动 commit。详细实现边界见 [`docs/adr/0001-checkpoint-rollback.md`](adr/0001-checkpoint-rollback.md) 和 [`docs/ARCHITECTURE.md`](ARCHITECTURE.md)。当前不得把它描述为默认支持。

#### F7 阶段二映射（实现但实验性）

- **L1**：已将 checkpoint 开关、Artifact 根、大小/文件限制、失败策略、rollback 模式和有效 digest 冻结到 `GoalContract`；默认仍关闭。
- **L2**：固定 checkpoint capability 使用 `Policy::evaluate_internal`；正常 deny 优先，匹配 allow/ask 生效，模型不能直接请求任意路径恢复。rollback 仍由普通 Policy default deny 约束。
- **L3**：`SnapshotRequest`/`Sandbox` 校验快照和恢复只能访问已验证 roots，拒绝 symlink、越界、禁止 glob、外部路径、特殊文件和超限资源。
- **L4**：`external_mutation + irreversible` 和 rollback 都必须有明确人工确认；checkpoint 只有匹配 `ask` 才进入 L4；`Never` 拒绝而不是自动放行。
- **条件性不变量**：`I-Checkpoint-After-Verified-Action`、`I-Checkpoint-Atomic`、`I-Rollback-Trigger`、`I-Irreversible-Requires-Human`、`I-Rollback-Scope`、`I-Rollback-Idempotent`、`I-Failed-Path-Not-Repeated`、`I-No-Implicit-Git-Commit` 已实现并同步到 `BOUNDARY.md` 第 4.1 节。
- **事件契约**：已加入 checkpoint、rollback、failed-path 事件和稳定 v2 event receipt；旧 Journal 不重写，v1 读取兼容保留。
- **测试门**：已覆盖外部副作用、幂等、快照损坏、失败路径阻断、wall-clock budget、TeeSink receipt、真实 CLI 子进程、stale lock 和配置/事件兼容；operator 事故分支（stale lock、failed operation、CAS drift、外部 mutation、Windows replacement backup、只读性、CLI 退出码）另有 `crates/pangu/tests/operator_drills.rs` 可重复演练，并按平台记录机制差异。
- **正式激活门**：operator recovery 运行手册已补充，证据收集与四个事故分支已有只读工具（`pangu artifact inspect`）和可重复 drill，**跨平台 CI 已通过**（run 36210280753，提交 `1b0245d`，Ubuntu 与 Windows 的 drill 原始报告已转录到 `docs/evidence/`）；仍缺目标部署平台自身的验证、恢复期间的备份/审计可用性、无人工输入与并发 writer 的停止策略确认，以及 operator/发布负责人签署；在此之前不把 F7 描述为默认支持。详见 [`docs/CHECKPOINT_RECOVERY.md`](CHECKPOINT_RECOVERY.md)。

### 选择建议

如果没有特别偏好，建议先从下面这组开始：

```text
第一批：A1、A2、A3、A4、B1、B4、C5
代码场景可选：F1、F2、F3、F4
第二批：B2、B3、D3、D4、F5
按需：B6（仅在需要本地 JEV 时开启，默认关闭）、F6（需要远程/自动化控制面时）
阶段二实现已存在但仍为实验性 opt-in：F7（Artifact/Agent/CLI、事件和测试已完成；正式激活与支持声明仍受 operator recovery、跨平台和最终验收门约束）
暂缓：C2、C3、C4、D1、D2、E1、E2、E3
```

这不是替用户做决定，而是因为第一批能提升 Pangu 的可恢复性、可审计性和可嵌入性，同时不立即引入无人值守副作用和办公数据权限。

---

## 4. 分阶段路线与验收门

### R0：基线、竞品核验和威胁模型

**产出**

- 固定当前 v0.1 的事件、配置、Journal 和 capability schema；
- 为每个候选特性写一页 ADR：目标、非目标、权限、数据、成本、失败恢复；
- 固定参照 Agent 的版本和公开资料，形成“可复现实验”而不是印象比较；
- 为 F7 checkpoint/rollback 完成 ADR、边界不变量条件文本、事件/配置兼容方案和风险评估（ADR 已批准；阶段二实现已存在，仍需正式激活门）；
- 建立威胁模型：提示注入、恶意 skill、凭据泄漏、越权、供应链、DoS、成本耗尽、产物造假。

**完成门**

- 每个新特性都能说明它新增了什么权限、数据面和失败模式；
- 任何“借鉴”都先写成能力需求，不直接复制竞品代码；
- 许可证、第三方依赖和数据处理方式完成审查。

### R1：v0.2——可恢复、可解释、可扩展

**候选**：A1–A5、B1、B4、C5、F1、F2、F3；F7 阶段二实现已完成大部分验收，仍是默认关闭的实验性 opt-in，只有在条件性不变量、operator recovery 和跨平台最终验收完成后才可正式激活。

**完成门**

- 中断后可从 Journal/会话节点恢复，不能重复执行已完成的副作用；
- checkpoint 只在成功 VerifiedAction 后形成，回退只作用于工作区/会话状态；
- 外部不可逆副作用、失败路径阻断、快照原子性和 rollback 幂等性均有独立测试；
- stale lock、Windows replace hand-off 和无锁并发 writer 的 operator recovery 限制已经写入运行手册，且不会被自动猜测；
- 事件流能区分 `agent_start/turn/tool/terminal`，并有 schema 版本；
- `doctor`/dry-run 能解释“为什么允许/拒绝”，不泄露 secret；
- 扩展无法绕过 `assess → Policy → Sandbox → Approval → VerifiedAction`；
- 原有 `cargo test --workspace --all-targets`、clippy、demo 全部保持通过。

### R2：v0.3——受控技能和记忆

**候选**：B2、B3、B6（B6 为用户可选，不作为核心依赖）；可提前实现 A5。

**完成门**

- 技能有来源、版本、hash、签名状态、所需 capability 和风险声明；
- 记忆写入是显式 proposal，有来源、TTL、撤销和脱敏；
- 恶意或过期 skill 不能自动获得新权限；
- 用户可以查看“本轮用了哪些记忆/技能”及其对动作的影响；
- B6 未启用时不启动本地 JEV 进程、不发起 JEV 请求，Pangu 核心功能仍可独立运行；
- 启用 B6 时提供可审计的安装、启动、停止、状态和健康检查流程，endpoint 默认绑定 loopback，并校验认证、版本、模型/依赖 hash 和资源上限；
- JEV 只返回受限的结构化决策；超时、不可用、非法输出或低置信度时使用明确的确定性 fallback 或 fail closed，禁止静默切换到远程服务；
- JEV 的请求类型、结果、模型/配置 digest 和失败原因进入脱敏事件流，不得把原始敏感上下文写入普通日志。

### R3：v0.4——长任务与交互

**候选**：C1、C3、F4、F5；C2 只在渠道需求明确时做。

**完成门**

- 每个定时/长任务都有独立 GoalContract、预算、取消、过期和终态；
- 无人值守只允许预定义的 read-only/reversible 能力，不能绕过人工闸门；
- TUI 展示真实事件，不以模型文本或前端状态伪造执行结果；
- 任务恢复不会重复发送、写入或执行外部副作用。

### R4：v0.5——远程 Runner 和受限多 Agent

**候选**：C4、D1、D2、F6；仅在 R1–R3 稳定后进入。

**完成门**

- 远程环境使用临时身份、最小挂载、短时凭据和可撤销 token；
- 子 Agent 的权限是父权限的交集，预算和 deadline 独立且可汇总；
- fan-out、并发、重试和跨 Agent 消息都有硬上限；
- 任意子 Agent 不能传递伪造的 `VerifiedAction` 或跳过中心 Journal；
- 远程断线、超时、重复回调和部分成功都有确定状态。

### R5：v0.6——产物和办公连接

**候选**：D3、D4、E1–E4。

**完成门**

- 每个产物有 schema、版本、来源、生成 trace、校验结果和人工验收状态；
- 报告/表格中的事实可以回溯到证据或明确标记为推测；
- 连接器默认最小权限，读写、发送、发布、删除分级；
- 不把“云端服务返回成功”作为唯一验收依据；
- 数据保留、导出、删除和租户隔离可配置且有测试。

---

## 5. 外部 Agent 经验警示清单

这些不是对竞品的攻击性评价，而是 Pangu 以后引入同类能力时必须显示或测试的风险。

W-43~W-47 是 F7 的风险摘要；完整激活后具体控制以 [`ADR-0001`](adr/0001-checkpoint-rollback.md) 第 11 节为准；当前生效边界仍以 [`docs/BOUNDARY.md`](BOUNDARY.md) 为准。

| ID | 警示 | 触发场景 | 必须的控制 |
|---|---|---|---|
| W-01 | 自学习记忆会固化错误 | 自动总结、技能自改、长期用户画像 | proposal、来源、证据、TTL、人工/策略确认、可撤销 |
| W-02 | 无人值守会放大错误半径 | cron、Gateway、后台任务 | 独立 contract、预算、过期、取消、只读优先、禁止隐式扩权 |
| W-03 | 技能/扩展等价于供应链代码 | 安装脚本、动态扩展、第三方包 | 签名、锁版本、SBOM、最小 capability、隔离加载 |
| W-04 | “工作目录”不是安全边界 | 模型执行命令或扩展访问宿主 | OS/容器/VM profile、路径和网络限制、凭据隔离 |
| W-05 | 会话和导出可能泄密 | 分享 transcript、RPC、SDK 日志 | 脱敏、secret 扫描、选择性导出、访问控制、保留期限 |
| W-06 | 多 Agent 放大成本和不确定性 | 并行、互相委派、自动重试 | 每节点预算、全局预算、fan-out 上限、确定性终态 |
| W-07 | 插件能改变真实行为 | hook、动态工具、context 改写 | capability manifest、事件记录、不可变策略、签名 |
| W-08 | Web/桌面端扩大认证面 | 本地服务、token、远程监听 | loopback 默认、认证默认开启、CSRF/Origin 校验、限流 |
| W-09 | 远程执行扩大数据面 | SSH/WSL、云 runner、文件同步 | 临时身份、最小挂载、短期 token、传输审计、断线恢复 |
| W-10 | Provider fallback 可能改变语义和价格 | 自动切模型/端点 | 能力声明、价格校验、用户策略、显著变更提示、禁止静默切换 |
| W-11 | “可验证产物”可能只是外观完整 | 报告、表格、演示文稿 | schema、来源、测试、引用、人工签收、事实/推测标记 |
| W-12 | 连接器会接触组织数据 | 邮件、云盘、浏览器、数据库 | 租户/数据域隔离、动作分级、最小 token、撤销和审计 |
| W-13 | 版本和云策略变化破坏复现 | 依赖升级、账号/模型/区域变化 | 版本锁定、能力探测、实验快照、回归基准 |
| W-14 | 竞品优点不能直接等于本项目能力 | 复制 UI、协议或内部实现 | 先做独立需求和 ADR，审查许可证，再实现最小替代方案 |
| W-15 | 过度自动化损害用户控制 | 自动修复、自动发布、自动删除 | 默认 dry-run、预览、暂停/取消、显式提交、可回滚 |
| W-16 | 办公连接器权限高 | 邮件、云盘、浏览器、表格和文档连接器 | 数据域/租户隔离、动作分级、最小 token、撤销和审计 |
| W-17 | 多 Agent 成本和不确定性叠加 | 并行、互相委派、自动重试 | 每节点预算、全局预算、fan-out 上限、确定性终态 |
| W-18 | 本地 JEV 可能成为隐形决策 oracle 或单点故障 | 本地模型漂移、服务不可用、错误分类、静默 fallback | 默认关闭、版本/模型 hash、typed output、timeout/预算、确定性 fallback、禁止静默远程 fallback、完整事件记录 |
| W-19 | 本地模型和依赖下载成为供应链入口 | 自动下载模型、插件、运行时或更新包 | 显式来源、hash/签名/许可证、离线安装、版本锁定、用户确认下载和更新 |
| W-20 | 闭源能力和可嵌入性不能只靠宣传判断 | 账号、API、数据处理、连接器和部署依赖 | 以官方条款和实测为证据，明确支持范围、数据出站和退出/删除路径 |
| W-21 | Developer preview 和兼容性破坏 | 依赖未稳定 API、版本快速变化、实验性能力 | 标注 maturity、版本锁定、迁移器、feature flag、回归基准和回滚路径 |
| W-22 | 全插件架构扩大供应链和配置面 | 插件、profile、patch、动态注册和热加载 | 签名、SBOM、最小 capability、静态优先、可逆卸载、完整配置 dump |
| W-23 | 广泛工具能力超过宿主权限边界 | shell、SSH、browser/computer use、MCP、subagent、jobs | 能力分级、OS/VM 隔离、审批、预算、网络/凭据 allow-list，禁止插件自授权 |
| W-24 | 多入口扩大认证和远程攻击面 | Web、SDK、ACP、Desktop、SSH、WebSocket、IPC | loopback 默认、认证默认开启、来源校验、短期 token、限流和每入口审计 |
| W-25 | 持久 SessionEvent 可能泄漏敏感上下文 | prompt、工具参数、输出、文件内容和 fork/导出 | 边界脱敏、访问控制、保留期限、导出扫描、加密和版本迁移 |
| W-26 | 技术栈迁移可能破坏 Pangu 边界 | 直接移植 TypeScript/Cordis 插件体系 | 只吸收事件/seam/profile 模式，保留 Rust 核心和 L1–L4，做独立 ADR 与基准 |
| W-27 | 未沙箱的 Agent/backend 拥有完整宿主权限 | OpenHands 直接运行、远程 Agent Server、VM/容器配置错误 | 默认 sandbox/VM、最小挂载、网络和凭据隔离、backend capability 握手、远程前验收 |
| W-28 | 浏览器控制面可能泄漏长期 backend 凭据 | public mode、API key、同源编辑器/扩展、localStorage | 短时会话 token、服务端 broker、Origin/CSP 校验、不在前端保存长期主密钥、轮换和撤销 |
| W-29 | webhook、schedule 和重试造成重复副作用 | OpenHands automation、外部事件、取消/断线、部分成功 | 幂等键、事件去重、任务 contract、预算/deadline、重放窗口、确定性终态和人工签收 |
| W-30 | 控制平面与执行组件的版本漂移 | Canvas、SDK、Agent Server、Ingress、automation 分别升级 | 固定兼容矩阵、API/schema 版本、健康检查、灰度升级、回滚和可复现部署清单 |
| W-31 | 自由自主循环把 benchmark 结果误当生产安全 | SWE-agent 长时间 shell/编辑/网络操作、未知 issue | sandbox、工具/网络 allow-list、GoalContract、预算、超时、测试 evidence 和人工验收 |
| W-32 | trajectory/query 可能泄漏源码和凭据 | SWE-agent thought/action/observation/state/query 日志 | 脱敏、加密、访问控制、保留期限、字段级导出、原始上下文与摘要分离 |
| W-33 | 自定义工具 bundle 是供应链和安装执行入口 | SWE-agent `bin/`、`install.sh`、依赖安装和环境变量 | 签名、hash、SBOM、隔离安装、静态依赖审计、版本锁定、卸载和可回滚 |
| W-34 | Agent 项目状态和接口持续迁移 | SWE-agent 与 mini-SWE-agent、旧 YAML/trajectory/schema | 标注 maturity、固定版本、迁移器、feature flag、回归实验和回滚路径 |
| W-35 | 自动提交改变 Git 历史和用户工作流 | Aider 自动 commit、dirty tree 保护、模型生成 commit message | 默认不自动提交、显式 checkpoint、保留用户 dirty changes、审查 hooks、Artifact/diff 可回滚 |
| W-36 | 跳过 pre-commit hook 会削弱仓库门禁 | Aider 默认 `--no-verify`、项目自定义检查 | 显式启用 hooks、记录跳过原因、运行等价测试、禁止 AI 自行绕过 CI |
| W-37 | Repo Map 造成上下文、成本、隐私和时效问题 | 大仓库符号图、外部 provider、索引过期、图排序漏召回 | 只读索引、token/路径预算、来源和时效展示、脱敏、增量更新、用户排除和 fallback |
| W-38 | 验证命令和外部输入可能执行不可信内容 | Aider lint/test/compile/run、网页/图片/语音/issue 文本 | 命令 allow-list、sandbox、来源标记、提示注入隔离、内容脱敏、结果不可直接信任 |
| W-39 | Cline 不同入口的审批默认值不一致 | CLI 默认 auto-approve、`--yolo`、`--zen`、后台无人值守 | 默认人工审批、临时 sandbox/短时 token、显式 capability、可见终态、禁止静默升级 |
| W-40 | MCP、插件和连接器扩大供应链与凭据面 | Cline/OpenHands MCP、插件、OAuth、云服务、数据库 connector | 签名/allow-list、最小 token、数据域隔离、审计、撤销、版本锁定和安装前预览 |
| W-41 | 持久 teams/schedules/connector session 难以恢复 | Cline teams、cron/event schedule、聊天 webhook、跨入口 session | 状态机、幂等、取消/过期、预算汇总、部分成功标记、版本迁移和人工接管 |
| W-42 | 多端发行和开放范围不一致 | Cline CLI/IDE/Desktop/SDK、JetBrains 插件、协议漂移 | 公开支持矩阵、核心协议测试、客户端版本门槛、未开放组件不作为安全保证 |
| W-43 | 不完整或损坏的快照被当作可恢复状态 | 文件变化、Artifact 中断、hash/manifest 不一致、存储配额耗尽 | 原子提交、完整 manifest、内容 hash、大小限制、损坏 fail closed |
| W-44 | 回退覆盖 checkpoint 之后的新修改 | 用户继续编辑、并发任务、状态 compare-and-swap 失败 | 当前状态校验、差异预览、显式审批、漂移时拒绝，不静默覆盖 |
| W-45 | 事件指针或 session node 不可验证 | Journal v1/v2、会话恢复、事件重排、hash 链损坏 | 稳定 event ID、版本化引用、完整性校验、replay 只读且不执行副作用 |
| W-46 | failed-path 误阻断或被模型绕过 | 失败指纹、参数变化、重新规划、清空记录 | 规范化资源指纹、边界 digest、显式新 GoalContract/PlanNode、运行时强制检查 |
| W-47 | Artifact/Git backend 引入隐藏副作用或供应链风险 | checkpoint 存储、Git commit/index、插件/凭据、跨设备 Artifact | 默认 Pangu Artifact、Git 独立审批、路径/来源校验、quota、签名/版本和可回滚卸载 |

---

## 6. 每个新特性的准入模板

新增特性必须先回答以下问题：

```text
ID：
用户价值：
借鉴对象（只写能力模式）：
明确不做什么：
新增 capability：
可读数据：
可写数据：
可访问网络：
是否创建子 Agent：
是否持久化记忆：
是否可无人值守：
是否为用户可选的本地服务：
本地 endpoint、绑定地址和认证：
模型/依赖来源、hash、许可证与更新策略：
JEV/服务不可用、超时或非法输出时的 fallback：
父/子预算和 deadline：
审批与撤销方式：
事件和 Journal 变化：
失败/重试/恢复方式：
威胁模型和红队用例：
兼容性与迁移策略：
验收 evidence：
许可证/第三方依赖审查：
```

只要有一个问题的答案是“模型可以自行扩大权限”或“无法回溯”，该特性就不能进入实现阶段。

---

## 7. 用户选择单

请直接按编号选择，不需要一次决定全部：

```text
第一批必做：____________________
第一批可选：____________________
明确暂不做：__________________
希望优先解决的场景：代码 / 研究 / 办公 / 远程 / 自动化 / 其他
可接受的权限等级：只读 / 可逆写入 / 高风险需人工 / 无人值守只读
本地 JEV：关闭 / 仅本机 loopback / 允许显式远程 endpoint
是否允许下载模型和依赖：否 / 仅指定来源 / 指定来源并自动更新
```

建议第一次选择不超过 3–5 项。Pangu 会根据选择生成对应的 ADR、任务拆分、测试矩阵和下一版验收标准；在你确认之前，不默认加入多 Agent、后台自动化、办公连接器或远程执行。

---

## 8. 公开参考资料

以下链接用于建立第一版能力模型；版本、权限和商业策略变化后必须重新核验：

- [Hermes Agent 官方仓库](https://github.com/NousResearch/hermes-agent) / [官方文档](https://hermes-agent.nousresearch.com/docs/)
- [Pi Agent 官方仓库](https://github.com/earendil-works/pi) / [官方文档](https://pi.dev/docs/latest)
- [ZCode 官方仓库](https://github.com/zai-org/ZCode)
- [Tencent WorkBuddy 官方站点](https://www.workbuddy.ai/) / [官方文档入口](https://www.workbuddy.ai/docs/workbuddy/)
- [DeepSeek Harness 官方仓库](https://github.com/deepseek-ai/deepseek-harness) / [官方文档](https://deepseek-harness.github.io/deepseek-harness/) / [安全声明](https://github.com/deepseek-ai/deepseek-harness/blob/master/SAFETY.md)
- [OpenHands / Agent Canvas 官方仓库](https://github.com/OpenHands/OpenHands) / [Software Agent SDK](https://github.com/OpenHands/software-agent-sdk) / [SDK 文档](https://docs.openhands.dev/sdk) / [Self-hosting 指南](https://github.com/OpenHands/OpenHands/blob/main/docs/SELF_HOSTING.md)
- [SWE-agent 官方仓库](https://github.com/SWE-agent/SWE-agent) / [官方文档](https://swe-agent.com/latest/) / [mini-SWE-agent](https://github.com/SWE-agent/mini-swe-agent)
- [Aider 官方仓库](https://github.com/Aider-AI/aider) / [官方文档](https://aider.chat/docs/) / [Repo Map 说明](https://aider.chat/docs/repomap.html) / [Git 集成说明](https://aider.chat/docs/git.html)
- [Cline 官方仓库](https://github.com/cline/cline) / [官方文档](https://docs.cline.bot/) / [CLI 文档](https://github.com/cline/cline/blob/main/apps/cli/README.md)
- [Checkpoint/Rollback ADR](adr/0001-checkpoint-rollback.md)（已批准；阶段二实现已存在；默认关闭、实验性 opt-in、未正式激活）

WorkBuddy 的闭源部分应以实际产品、官方文档、隐私条款和可复现实验为准；DeepSeek Harness 当前处于 developer preview，官方明确提示尚未经过安全审计且可能发生兼容性破坏。OpenHands 当前将控制台与 SDK/Agent Server 分布在不同仓库；SWE-agent 官方 README 已提示 mini-SWE-agent 取代主项目；Cline 的多端能力和 JetBrains 插件开放范围也需按版本重新核验。在未完成核验前，本文只把这些项目的公开定位作为产品设计参考，不把营销描述、benchmark 分数或某入口的默认行为当作全系统安全或质量证明。F7 的 checkpoint/rollback 规则目前已记录在已批准 ADR、路线图准入映射、阶段二实现、`BOUNDARY.md` 条件性不变量和 [`CHECKPOINT_RECOVERY.md`](CHECKPOINT_RECOVERY.md) 中；在正式激活门、跨平台最终验收和 operator recovery 限制确认前，不应把它当作 v0.1 的默认能力。
