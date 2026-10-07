# Operator drill 证据

本目录存放 F7 checkpoint/rollback operator drill 的跨平台报告。内容只来自真实运行（CI 产物或本机实测），由 [`CHECKPOINT_RECOVERY.md`](../CHECKPOINT_RECOVERY.md) §8.1 引用；不存放推测或计划中的结果。

现有报告：

| 文件 | 来源 | 提交 | 结果 |
|------|------|------|------|
| `f7-drills-windows.jsonl` | GitHub Actions `windows-latest` | `1b0245d` | 7 pass |
| `f7-drills-ubuntu.jsonl` | GitHub Actions `ubuntu-latest` | `1b0245d` | 6 pass + 1 not-applicable（`replace-backup`，POSIX 无 hand-off） |
| `f7-drills-windows-10.0.19045.jsonl` | 本机实测 Windows 10.0.19045 / rustc 1.98.1 | `3aa11da` | 7 pass |
| `f7-drills-windows-105258e.jsonl` | GitHub Actions `windows-latest` | `105258e` | 7 pass |
| `f7-drills-ubuntu-105258e.jsonl` | GitHub Actions `ubuntu-latest` | `105258e` | 6 pass + 1 not-applicable |
| `f7-drills-windows-8f60878.jsonl` | 本机实测 Windows 10.0.19045 / x86_64 | `8f60878` | 7 pass |
| `f7-drills-windows-853017f.jsonl` | 本机实测 Windows 10.0.19045 / rustc 1.98.1 | `853017f` | 7 pass |

`105258e` 的两份是修复 Ubuntu 测试失败后的第一次全绿运行（run [37398616832](https://github.com/pangu-cn/PanguAgent/actions/runs/37398616832)）；此前 `plan-a` 上 ubuntu 侧连续 7 次失败，原因见 [`CHECKPOINT_RECOVERY.md`](../CHECKPOINT_RECOVERY.md) §11。

`f7-drills-windows-10.0.19045.jsonl` 是**本机**记录，不是 CI 结论，也**不构成** §9.1 要求的"目标部署平台"验收——它只证明该套 drill 在该提交上可复现。条目格式仍严格遵循下面的 schema。

`f7-drills-windows-8f60878.jsonl` 同样是**本机**记录，用于证明该套 drill 在 F8/F9 改动之后仍可复现（7 pass）。它**不构成** §9.1 的目标平台验收，理由同上。

`f7-drills-windows-853017f.jsonl` 是本表写入时最新的一份**本机**记录，对应当前 HEAD（修掉证据里 verbatim 路径的那次改动之后），同样**不构成** §9.1 的目标平台验收。每次改动 drill 或 checkpoint 相关代码后应**追加**新行，而不是改写旧行：旧行记录的是当时的提交，改写会让证据与提交的对应关系失真。

## F8 沙箱"真拉起执行"的证据

§9.3 之外，F8 的"真拉起执行"也需要可信证据，而它有个难点：目标机器上**可能没有可用
的容器运行时**（本机 Docker Desktop 的 Linux 引擎即不可用，见下）。

`crates/pangu-toolkit/tests/runtime_dispatch.rs` 与
`crates/pangu-boundary/tests/runtime_dispatch.rs` 用**记录 argv 的桩**替换运行时二进制，
桩放在 `PATH` 上、走真实的 `find_program` 查找，因此生产代码路径一字未改。实测记录：

```
RAN docker run --rm -i "--volume=<ws>:/workspace" "--workdir=/workspace" \
  "--cap-drop=ALL" "--security-opt=no-new-privileges" alpine:3.20 pwd
```

不声明运行时则记录为 `RAN pangu-local-wrapper`——**没有任何容器包装**，这条反向用例
防止"把每条命令都塞进运行时"的改法悄悄通过。

桩**不能**证明、也不声称：Docker 对这些标志的实现真的隔离了什么。那是运行时自身的
属性。

**本机的真实运行时状态（不是测试结论，是环境事实）**：

```
oci started but the probe command did not produce the expected output; saw:
docker: error during connect: ... open //./pipe/dockerDesktopLinuxEngine: Access is denied.
```

`docker version` 在本机 30s 无响应，Docker Desktop 的 Linux 引擎处于不可用状态；WSL
无发行版、无 Podman。因此**本机无法完成 OCI 运行时的真实容器内执行验证**，该验证在
CI 的 `ubuntu-latest` 上才有条件进行。

### 该验证已于 2026-10-07 在 Linux CI 上真实执行

| 项 | 值 |
| --- | --- |
| 提交 | `923826a` |
| run id | `37555456148` |
| 结论 | `success`（ubuntu-latest 与 windows-latest 均成功） |

`ubuntu-latest` 上 **全部步骤 success**，其中两项是本仓库历史上**第一次在 Linux 上
真正执行**：

```
success  Install a browser for the real-runtime tests
success  Run tests that need a real runtime
```

在此之前，ubuntu 每次都在 `Run all tests` 就失败，这两步一直是 `skipped` —— 也就是说
`browser_cdp.rs` 的 9 项 `#[ignore]` 测试与容器内执行路径**从未在 Linux 上跑过**，
只有本机桩证据。现在它们真的跑了。

为什么长期卡住：CI 一次只暴露一个失败，而每个失败都需要一次推送才能看到。真正的
成因是一类**夹具缺陷**（见下），逐个修必然绕圈子。这一轮改为先做全仓审计、再批量修复，
把八处同源缺陷一次清掉，ubuntu 才第一次通过。

**仍然成立**：桩不能证明 Docker 对隔离标志的实现是否正确，那属于运行时自身属性；
本机也仍无可用容器运行时。上面这条记录证明的是"命令确实被送进了真实运行时"。

## 夹具的临时目录必须规范化（一类 CI-only 失败）

同一类缺陷在 **9 个文件**里各出现一次，值得单独记下来，因为它每次都以
"本机全绿、CI 全红"的形式出现，且原因与被测代码毫无关系。

`journal::reject_symlink_components`（`journal.rs:215`）会从待检路径一路向上走到
文件系统根，**任何一层是符号链接就拒绝**；`artifact.rs` 同形。而
`Sandbox::from_config` 会规范化 workspace，`resolve_executable` 又拿规范化后的路径做
`starts_with` 比较。

Linux 容器镜像里 `/tmp` 常常是符号链接。于是 `std::env::temp_dir()` 直接拼出来的
夹具路径**在 CI 上必然被拒**，而在维护者本机必然通过 —— 本机 temp 目录是真目录。

已在本机用真实目录符号链接复现（不是推断）：

```
raw   = ...\slink\pangu-raw-journal.jsonl
raw   result = Err("journal path must not contain symlink components: ...\slink")

fixed = \\?\...\sreal\pangu-probe-...\journal.jsonl
fixed result = Ok("ok")
```

解法是一个共享实现 `pangu_core::testing::TempDir`（feature `test-support`），
而不是再抄一份 —— 本仓库此前已把同一个 helper 抄进 `config.rs`、`test_support.rs`、
`mcp_boundary.rs` 三处，而 `journal.rs`、`stream.rs` 等仍在用 raw 形式。

## 跨平台测试不要断言平台特有的路径语义

`a_verbatim_host_path_is_not_handed_to_the_runtime` 的第一版把 strip 逻辑放在
`#[cfg(windows)]` 里，然后断言"verbatim 会被去掉"。它在 Linux 上必然失败，两个原因：

- `#[cfg(windows)]` 块在 Linux 上根本不编译；
- `Path::new(r"\\?\C:\work\ws")` 在 Unix 上是**一个含反斜杠的文件名**，不是盘符路径。

改法不是给测试加 `cfg`，而是**消掉平台分支**：前缀处理本来就是文本规则，拆成
`strip_verbatim(&str)` 后两个平台跑同一份逻辑，测试在本地即可覆盖 CI 行为。
前面几轮反复栽在"Windows 走不到 Linux 的分支"，这次直接把分支去掉。

## §9.3 备份可读性 drill

`crates/pangu/tests/backup_drill.rs` 是 §9.3 要求的**可执行程序**，验证"恢复点搬到别处还能用"：

```bash
cargo test -p pangu --test backup_drill -- --nocapture
```

它证明四件事，缺任何一件结论都不成立：

1. 原始 store `artifact inspect` 报 `verified`；
2. store **复制到另一棵树**后，副本单独 `verified`；
3. **删掉原始目录后**副本仍 `verified`（否则第 2 步可能只是通过链接/共享 inode 读到了原件）；
4. 篡改副本一个字节后**必须被拒绝**——一个无法让自己失败的备份不是证据。

**该 drill 覆盖不到、仍需 operator 提供的部分**（它在运行输出里也会明说）：跨介质/异地副本、保留期长于响应窗口、不被日志轮转自动删除。这三项无法用单机测试代替。

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

## CI 注解的严重级别

CI 把每一行报告同时发成可公开读取的注解（`f7-drill-report.jsonl` 作为 artifact 需要认证下载，注解不需要）。**注解级别跟随 `outcome`**：

| `outcome` | 注解级别 | 理由 |
|-----------|---------|------|
| `pass` | `notice` | 这是证据，不是问题 |
| `skipped` / `not-applicable` | `warning` | 不是通过，也不等于失败；必须保持"未覆盖"可见，不能被读成通过 |
| 其它（含报告缺失） | `error` | `outcome` 是固定词表，出现别值说明报告本身有问题 |

这条区分是必要的：此前所有行一律发 `::error::`，于是**一次全绿的运行也带着约 14 条 error 注解**，"演练全部通过"与"演练失败"在界面上长得一模一样，只能靠解码载荷才能分辨。常亮的警报不携带信息，也会让真正的失败被淹没。

该分级已在 CI 上实测确认（提交 `7468262`，run [37402160742](https://github.com/pangu-cn/PanguAgent/actions/runs/37402160742)）：两个平台各 7 条 `notice`、0 条 `error`，Ubuntu 的 `replace-backup` 为 `warning`（`not-applicable`），Windows 无该项因而不产生该 warning。**0 条 error 就是这里的终态**——一旦出现 error，说明报告格式坏了（`outcome` 落在词表外）或报告没产出，而不是"演练失败"；演练失败本身会先让 `Run F7 checkpoint operator drills` 步骤以非零码退出。
