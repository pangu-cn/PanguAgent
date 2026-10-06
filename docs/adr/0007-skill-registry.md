# ADR-0007：技能注册表与签名包（B2）

- 状态：已实现（本 ADR 随实现一同提交）。
- 相关：[ADR-0006](./0006-memory-candidate-queue.md)（同为"操作者写入、模型只读/提议"的存储先例）
- ROADMAP：B2；威胁模型 W-03（技能 = 代码 + 指令的供应链面）、W-22（全插件架构扩大供应链与配置面）

---

## 1. 背景与问题

ROADMAP B2：借鉴 Pi 的 Agent Skills、Hermes 的技能学习、DeepSeek Harness/OpenHands 的 skills/plugins 和 Cline 的 rules/skills，但**默认只加载说明，脚本需显式批准**。

技能是"指令 + 可选脚本"的混合体（W-03）：把技能接进运行时等于引入一个供应链执行面——被替换的说明会引导模型做错事，被替换的脚本会直接执行。所以 B2 的设计问题不是"怎么加载技能"，而是"**加载了什么、谁装进来、内容被改了怎么发现、模型能碰多少**"。

## 2. 决策

### 2.1 技能 = 操作者安装的包；模型没有任何写入路径

包格式（目录）：

```text
<skill-name>/
  SKILL.toml   # manifest：schema/name/version/description/files/scripts
  SKILL.md     # 指令正文（files 必须声明）
  其他支持文件…
```

- 安装只经 `pangu skills install <dir>`（操作者动作）。技能源可以是磁盘上任何位置——复制进 `<workspace>/.pangu/skills/<name>/` 时**逐文件校验 + hash 锁定**。
- 安装时生成 `skill.lock`（schema `pangu-skill-lock/1`）：每文件 SHA-256 + 字节数 + 整包 `package_digest`（SBOM-lite）。清单里声明的每个文件（含脚本）都必须被 lock 覆盖——lock 之外的文件不被加载，lock 之内的文件不许缺失。
- `pangu skills remove` 可逆卸载（W-22"静态优先、可逆卸载"）；同名重复安装拒绝（先 remove 再 install）。

### 2.2 完整性 + 签名（ed25519）

- **每次运行时加载都重算 hash**：目录内容与 lock 逐字节比对，不匹配的技能被**拒绝加载并发 `Note` 事件**—— audible，绝不静默跳过。技能是增强不是边界，一个坏包不能拖垮整个 run，但也不能消失得无声无息。
- **签名可选、验签按需**：`pangu skills keygen` 生成 ed25519 密钥对；`pangu skills install --sign-key <file>` 对 lock 的 canonical JSON 签名；操作者在 `[skills] verify_key` 钉公钥后，运行时加载即验签。
- **四种诚实状态**（`SkillSignatureState`）：
  - `signed+verified`：签名存在且对钉住的 key 验证通过；
  - `signature-invalid`：签名存在、key 已钉、验证**失败**；
  - `signed-unverified`：签名存在但没钉 key——**未检验，不是无效**；
  - `unsigned`：没有签名。
  "invalid" 只在实际验证失败时宣称；没人查过的签名不许冒充任何信任级别。

### 2.3 运行时只加载说明；脚本零执行原语

- **索引注入**：新 run 的 system turn 追加技能索引（name/version/签名状态/一行描述），带上界（条数/字节），标注"operator-installed reference material / carry no permissions"。恢复的会话不重新注入（与 ADR-0006 同一纪律）。
- **`read_skill` 工具**：模型按名字读 `SKILL.md` 正文（有界）。这是模型能触达的**唯一**技能内容。
- **脚本永不执行**：`SKILL.toml` 里的 `scripts` 只登记 + hash。B2 不提供任何脚本执行原语——模型执行任何命令仍只能走 `run_command`（NeedsHuman + argv 白名单），而技能路径在 `.pangu` 禁区内，通用工具 I/O 同样够不着。"脚本需显式批准"由此成立：不是加了一个带批准的执行口，而是**执行口根本不存在**。
- **无权限**：索引与正文都明确"skills carry no permissions"——技能内容对 L1–L4 零影响，是待读的参考材料，不是配置或授权。

### 2.4 冻结与绑定（同 fallback/verify/memory 的纪律）

- `[skills] enabled = true` 时，contract 冻结**加载成功的技能集**（name/version/package_digest/signed）并携带进 digest；disabled 保持历史 digest 不变。
- `Agent::with_chain` 拒绝 toolkit 的 `read_skill` 广告与 contract 不一致的构建；run 启动时把实际 registry 与冻结集**逐位比对**（名称/版本/包 digest/签名状态），并拒绝未附 registry 的半接状态。
- install→freeze→run 之间技能被篡改（或 remove）→ run 启动即失败，报"does not match GoalContract frozen skill set"——带病技能集不可能进入运行。

### 2.5 准入模板（ROADMAP §6）

```text
ID：B2
用户价值：可复用、可审计的领域规程（发布流程、代码规范、部署手册），模型按需取用
借鉴对象（只写能力模式）：Pi Agent Skills 的"目录包 + 按需读说明"渐进披露
明确不做什么：脚本执行原语；模型安装/修改技能；自动信任（无 key 时如实标
  unsigned/signed-unverified）；网络分发/在线技能市场；向量检索
新增 capability：read_skill（risk=ReadOnly，effect=Workspace/NoEffect，
  reads=[.pangu/skills]）；keygen/install/remove 无模型面
可读数据：registry 目录（operator 安装，路径来自配置）
可写数据：仅安装/卸载时（CLI，operator 动作）；运行时零写入
可访问网络：无
是否创建子 Agent：否
是否持久化记忆：技能注册表本身是持久数据，但模型不可写（区别于 B3 的提议模式：
  技能是操作者投喂的规程，不是模型学到的经验）
是否可无人值守：运行可无人值守；安装/卸载是 operator CLI 动作
是否为用户可选的本地服务：否
本地 endpoint、绑定地址和认证：不适用
模型/依赖来源、hash、许可证与更新策略：新增 ed25519-dalek 2（纯 Rust，Apache/MIT）
  + getrandom 0.2（熵源）；无网络拉取
laya/服务不可用、超时或非法输出时的 fallback：不适用
父/子预算和 deadline：不适用；索引/正文/包大小全部有上界（G4）
审批与撤销方式：install/remove 即审批与撤销（operator CLI）；篡改在加载期被发现
事件和 Journal 变化：被拒技能发 Note（可听）；技能集冻结进 contract digest
失败/重试/恢复方式：坏包 → 拒载 + Note + CLI verify 可见；冻结集不一致 → run
  启动失败；签名验证失败 → 如实标 signature-invalid
威胁模型和红队用例：W-03 篡改说明/脚本（→ hash 锁定拒载）；未签名包冒充
  （→ 状态如实标注，无 key 不产生信任主张）；模型读脚本执行（→ 无执行原语 +
  .pangu 禁区）；模型改技能（→ 模型无写路径）
兼容性与迁移策略：默认 disabled（无工具/无注入/digest 不变）；.pangu 禁区已随
  B3 落地，本特性复用
验收 evidence：install→list→verify→run 注入索引→read_skill 读正文；
  篡改→拒载→run 拒启；签名 roundtrip + 篡改检测（测试锁定）
许可证/第三方依赖审查：ed25519-dalek（Apache-2.0/MIT）、getrandom（Apache-2.0/MIT），
  均为广泛审计的纯 Rust 实现
```

## 3. 后果

- **正向**：规程可复用且供应链可审计（hash 锁定 + 可选签名）；技能与权限结构性分离；冻结/绑定纪律覆盖技能集。
- **代价**：技能内容进 system prompt（索引有界）；操作者多一个 key 管理义务（可选——不钉 key 只是少了信任主张，不是故障）。
- **风险**：操作者读了恶意说明后照做——技能说明影响的是**模型**的行为，模型的每个动作仍过 L1–L4；说明无法绕过闸门。真正的执行风险在脚本，而脚本无执行原语。
- **留待 E1**：受控扩展 SDK 落地时，脚本执行若要做，必须以 capability manifest + 显式批准 + 隔离加载的形态重新过准入，本 ADR 的"无执行原语"不构成承诺。

## 4. 状态

- 实现：`pangu-core::skills`（包校验/lock/签名/registry）、`pangu-toolkit`（read_skill）、`pangu-agent`（冻结比对 + 索引注入 + Note）、`pangu` CLI（`pangu skills keygen|install|list|verify|remove`）。
- 默认关闭：`[skills] enabled = false`。开启方式与护栏见 BOUNDARY §3「技能注册表（B2）」。
