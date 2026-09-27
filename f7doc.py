import io

p = "docs/ROADMAP.md"
t = io.open(p, encoding="utf-8").read()

anchor = "- **事件契约**：已加入 checkpoint、rollback、failed-path 事件和稳定 v2 event receipt"
assert anchor in t
add = """- **`checkpoint.exclude_roots`**：快照遍历整个工作区，而默认 `forbidden_globs` 只挡 `.git`/`.env`/secrets/私钥，**不挡构建产物**。本仓库 6.3 GB 的 `target/` 会让任何 checkpoint 撞上 `max_snapshot_bytes` 并按 `fail_run` 终止整个运行。已新增配置项让用户声明可排除目录，**默认留空**——`.gitignore` 不是安全依据（很多项目把真实产出目录写进 `.gitignore`，自动排除会让 rollback 静默丢失这些数据），哪些是可重建的由用户判断。校验拒绝越出工作区、覆盖整个工作区、或等于 artifact_root 的排除根。超限错误现在会指出**具体是哪个文件越界**并给出两个补救办法。
"""
t = t.replace(anchor, add + anchor, 1)
io.open(p, "w", encoding="utf-8", newline="").write(t)
print("ROADMAP F7 段已补")
