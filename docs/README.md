# Pangu Agent 文档索引

各文档的定位与建议阅读顺序。改动任何一份规范前，先读 [`BOUNDARY.md`](BOUNDARY.md) §7 的演进规则。

| 文档 | 定位 | 状态 |
|------|------|------|
| [`../README.md`](../README.md) | 快速开始、设计目标、有效边界、CLI 与配置入口 | 随实现更新 |
| [`BOUNDARY.md`](BOUNDARY.md) | **规范文本**：L1–L4 边界、上下文组装、不变量 I1–I19、非目标、决策权归属 | 生效中（v1） |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | 实现结构、状态机、事件与 Journal、Artifact store、不变量测试矩阵 | 随实现更新 |
| [`ROADMAP.md`](ROADMAP.md) | 竞品勘察、特性候选菜单（A/B/C/D/E/F）、分阶段验收门 | 草案，持续推进 |
| [`CHECKPOINT_RECOVERY.md`](CHECKPOINT_RECOVERY.md) | F7 checkpoint/rollback 的 operator 恢复手册、drill 与验收清单 | 实验性 opt-in |
| [`CAPABILITIES.md`](CAPABILITIES.md) | 十项扩展能力的实现状态、边界与诚实的限制（MCP、分层记忆、trace、审计、画布、skill） | 随实现更新 |
| [`adr/`](adr/) | 设计决策记录 0001–0013，每项含背景、决策、准入模板与非目标 | 各自标注状态 |
| [`evidence/`](evidence/) | operator drill 跨平台报告（CI 产物转录），schema 见该目录 README | 只追加 |

## 约定

- **"实验性 opt-in" 与 "默认支持" 必须在所有文档中区分**（ADR-0001 激活门；当前仅 checkpoint/rollback 处于前者）。
- 派生产物（`pangu events` 事件流、会话导出、上下文组装结果）一律带 `derived: true` / `authoritative: false`；审计与判定的权威只有 Journal 与真实运行。
- 文档与代码冲突时，先修文档或代码，不能把未声明行为当能力；只改一边视为边界漂移（BOUNDARY §7）。
- 事件/存储 schema 的变更规则：Journal 磁盘格式内部可演进；对外契约（`pangu-stream/*`、`pangu-export/1`、`pangu-artifact-inspection/1`）只增不改，改则发新版本并提供迁移器。
