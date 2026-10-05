# Operator drill 证据

本目录存放 F7 checkpoint/rollback operator drill 的跨平台报告。内容只来自真实运行（CI 产物或本机实测），由 [`CHECKPOINT_RECOVERY.md`](../CHECKPOINT_RECOVERY.md) §8.1 引用；不存放推测或计划中的结果。

现有报告：

| 文件 | 来源 | 提交 | 结果 |
|------|------|------|------|
| `f7-drills-windows.jsonl` | GitHub Actions `windows-latest` | `1b0245d` | 7 pass |
| `f7-drills-ubuntu.jsonl` | GitHub Actions `ubuntu-latest` | `1b0245d` | 6 pass + 1 not-applicable（`replace-backup`，POSIX 无 hand-off） |
| `f7-drills-windows-10.0.19045.jsonl` | 本机实测 Windows 10.0.19045 / rustc 1.98.1 | `3aa11da` | 7 pass |

`f7-drills-windows-10.0.19045.jsonl` 是**本机**记录，不是 CI 结论，也**不构成** §9.1 要求的"目标部署平台"验收——它只证明该套 drill 在该提交上可复现。条目格式仍严格遵循下面的 schema。

每行一条 JSON 记录，schema 为 `pangu-f7-drill/1`：

| 字段 | 含义 |
|------|------|
| `schema` | 固定 `pangu-f7-drill/1` |
| `drill` | 演练名：`stale-lock` / `failed-operation` / `cas-drift` / `external-effect` / `replace-backup` / `inspection-read-only` / `cli-inspect`（与 CHECKPOINT_RECOVERY §6 表格一一对应） |
| `outcome` | `pass`（通过）；`skipped`（机制在本环境不可用，如以 root 运行时 Unix 的 `failed-operation`）；`not-applicable`（平台不存在该机制，如 POSIX 没有 `.replace-backup-*` hand-off） |
| `os` / `arch` | 运行平台 |
| `commit` | 产生证据的提交 SHA |
| `detail` | 脱敏后的一句话说明 |

注意：

- `skipped` 与 `not-applicable` **不是通过**；平台差异按事实记录（见 CHECKPOINT_RECOVERY §8.1 的已知覆盖边界）。
- drill 证明 fail closed 与证据存在，**不证明** Pangu 能自动恢复。
- 生成方式：`PANGU_DRILL_REPORT=<绝对路径> PANGU_DRILL_COMMIT=$(git rev-parse HEAD) cargo test -p pangu --test operator_drills -- --nocapture`，详见 CHECKPOINT_RECOVERY §6。
