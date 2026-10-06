# AGENTS.md — AI 助手在本仓库的工作规则

适用于所有在本仓库工作的 AI 编码助手（pi、Claude Code、Cursor、Copilot 等）。

## 硬性规则：不要在仓库根目录创建无关文件

**不得在仓库根目录新建任何文件**，除非该文件属于以下白名单之一且改动有明确目的：

```text
.gitignore  Cargo.toml  LICENSE  README.md  AGENTS.md
crates/  config/  docs/  src/  tests/  .github/
```

具体要求：

- 一次性脚本、临时配置、调试输出、草稿、修复文档用的补丁脚本，一律**不要**写进根目录，也不要提交进版本库。
  - 历史教训：`f7doc.py`（一次性文档补丁脚本，重跑会重复插入段落）、`ck-e2e.toml`、`ck-root.toml` 曾被提交到根目录，均无任何引用，2026-10-03 已清理。不要重复这类行为。
- 临时产物写到系统临时目录；确需放在仓库内时，写入 `target/`（已被 `.gitignore` 忽略），并在任务结束时清理。
- 需要长期保留的内容放对位置：文档放 `docs/`（索引与约定见 `docs/README.md`）；测试和测试夹具放对应 crate 的 `tests/`；配置样例放 `config/`。
- 如果认为根目录确实需要新文件，先说明理由，征得维护者同意后再创建。
- 每次任务结束前检查 `git status`：根目录不应出现白名单之外的未跟踪文件；有则删除或在答复中说明。

## 其它既有约定

- 文档索引与阅读顺序：[`docs/README.md`](docs/README.md)。
- 改动规范文本前先读 [`docs/BOUNDARY.md`](docs/BOUNDARY.md) §7 的演进规则：只改代码不改文档（或反之）视为边界漂移。
- 派生产物（事件流、导出、组装结果）必须带 `derived: true` / `authoritative: false`；文档描述不得超出代码已实现的事实——不要把实验性能力写成默认支持。
