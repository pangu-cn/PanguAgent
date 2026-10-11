# ADR-0015：桌面端 Provider 密钥本机存储（放宽 ADR-0013 §4 / BOUNDARY §4b）

- 状态：**Accepted（2026-10-10 用户明确指示实现）**。代码、测试、本文件与两处规范修订按 §7 一并提交。
- 关联：ADR-0013（混合客户端外壳）、BOUNDARY §4b、BOUNDARY §6（放宽归属人）、§7（演进规则）。

## 1. 背景

桌面端自定义 Provider 最初按 ADR-0013 §4 实现：API Key 字段只存**环境变量名**，运行时从进程环境解析并轮询。用户实测后明确要求直接存 key（“apiKey 里面存的是变量，我想要存 key，不需要变量”）。BOUNDARY §6 规定边界放宽/收紧由人决定——**操作者已拍板**，本 ADR 记录这次放宽的确切范围、代价与未放松的部分。

## 2. 决策

- **D1**：`ProviderProfile.api_keys` 每行一个原始 key，落盘 `<app>/.pangu/config/providers.json`，运行与探测时按请求轮询。历史字段 `api_key_env`（环境变量名）**只读保留**：旧 profile 继续按变量解析；两者同时存在时 raw 优先，避免半迁移状态误发旧变量的值。
- **D2**：运行与「获取模型列表」探测都直接使用存储的 key（`OpenAiCompatibleProvider::with_keys`）。预设校验所需的单个 `model.api_key_env` 在只有 raw key 时写 `PANGU_PROFILE_API_KEY`——它说明凭据实际住在本地 profile 文件，而不是指向一个从未被读取的变量。
- **D3**：界面**明示落盘**：编辑器 hint 与设置窗标签都写明“明文保存在本机配置文件”。可编辑性要求明文可见，不做遮罩——遮罩会让人无法管理自己的 key。
- **D4**：预设预填的模型改为“首个覆盖内嵌默认输入预算（200K）的工具可用模型”，避免 openai 预填 gpt-4o（128K 窗口）撞上预算检查、首次执行即失败。**纯填充提示**：不触碰预算本身，budget 仍是操作者的字段。

## 3. 没有放宽的（逐条）

- **key 不进旁路**：事件流、Journal、日志、模型上下文、workspace 一律不进（I-Redact-At-Boundary 不变；Authorization header 仍 `set_sensitive`）。
- **文件位置**：`providers.json` 在**应用数据目录**（可执行文件旁的 `.pangu/config/`），不在 workspace、不进 git、模型经工具不可达。
- **CLI 不变**：`model.api_key_env` 仍只记环境变量名；CLI 不读 providers.json。
- **环境变量模式保留**：旧 profile 与手写配置继续走变量解析。

## 4. 风险评估（§7 第 4 项：放宽了什么）

- **放宽前**：长期密钥不可能以明文存在于应用自有文件。
- **放宽后**：密钥明文落盘于 `providers.json`。
- **残余风险（如实记录，不声称消除）**：以该 Windows/macOS 用户身份运行的任何进程可读该文件；备份、同步盘、整机镜像会复制它；编辑器界面明文可见。
- **明确不做**：OS 级文件权限加固。现有 `create_with_user_acl` 名不副实（仅建目录），加真实 ACL 需要新依赖或 `icacls` 子进程——列为后续可选项，**不假称已做**。
- **回退路径**：删掉 profile 里的 key、写回环境变量名，即恢复放宽前行为（代码路径仍完整保留并有测试守护）。

## 5. 验收

`crates/pangu-desktop` 单测（13 通过，本轮新增 4 个）：raw key 逐字使用且优先于 legacy 名；探测用首个存储 key；legacy-only 时未设置的变量整体失败、无 key 的 profile（本地 ollama）判空；raw key 满足预设的 key 要求且写合成 `api_key_env`；未知 profile 名不变成预设引用；预填模型覆盖默认预算。

## 6. 明确不做

- key 进入事件、Journal、日志、模型上下文或 workspace。
- 自动降低预算或自动改配置以让某个模型通过校验。
- 无 key 时默认编造 key；遮罩编辑（与管理自己的 key 冲突）。
