import io

p = "docs/ROADMAP.md"
t = io.open(p, encoding="utf-8").read()

old = """  - **切片机制是 Pangu 自己的主要功能**，不是外部能力、不是模型能力。落成**两个存储物**：`<root>/contexts/<id>.json`（上下文文件，全量正文，一条消息一行）+ `<root>/summaries/<id>.json`（摘要文件，一条消息一个 `SummaryEntry { message_index, file_line, start_line, end_line, range_digest, kind, summary }`）。
  - **切片不是第三个存储物，是第三步动作**：从摘要文件选中条目 → 解析成行范围 → 到上下文文件按范围取行 → 校验 `range_digest` → **衔接**拼接。正文只有一份，切片只做索引与定位，避免两份内容要同步。
  - **为什么必须两个文件而不是一个**：选择阶段要读**全部**摘要但不需要正文；拼接阶段要读**少量**正文但不需要全量索引。合成一个，选择阶段就得把大文件整个读进内存。拆开后选择阶段只把摘要文件读进内存（有明确上界），拼接阶段按行范围读上下文文件。
  - **摘要文件是纯派生物**，绑定 `context_digest`，加载时校验对不上就报错——**不重新生成、不静默接受**。重新生成会掩盖“摘要与正文对不上”，而那正是切片唯一可能说谎的地方。"""

new = """  - **切片机制是 Pangu 自己的主要功能**，不是外部能力、不是模型能力。落成**三个存储物**：`<root>/contexts/<id>.json`（上下文文件，全量正文，一条消息一行）+ `<root>/summaries/<id>.json`（摘要文件，一条消息一个 `SummaryEntry { message_index, file_line, start_line, end_line, range_digest, kind, summary }`）+ `<root>/slices/<id>.json`（**切片文件，映射表**：`SliceEntry { slice_id, start_message, end_message, start_line, end_line, range_digest, kind, summary, derived_from, verbatim, unverified }`）。
  - **切片文件是映射表**：把全量上下文映射成切片，每条带位置与摘要。`derived_from` 记录它由哪些 `message_index` 聚合而来，这正是“映射表”可审计的含义。**切片是 span、可跳多条消息**，不是单条消息——单条消息作为选择单元太细（一条 256 KiB 工具输出、一次 `finish` 回执都不是有意义的选择粒度）。
  - **为什么是三层而不是一个文件**：三者**访问模式不同**，合成一个就有一方被迫整体载入。摘要文件 → 粗筛要**遍历全部**条目、只读摘要，所以需要整体进内存但必须小且有上界；切片文件 → 组装只读**选中**几条，不需要整体载入；上下文文件 → 拼接按行范围取，不载入全量。
  - **三方 digest 绑定**：切片文件同时记录 `context_digest` 与 `summaries_digest`，加载时两个都要校验，对不上就报错——**不重新生成、不静默接受**。重新生成会掩盖“切片与正文对不上”，而那正是切片唯一可能说谎的地方。
  - **取用流程**：切片文件选中条目 → 到上下文文件按范围取行 → 校验 `range_digest` → **衔接**拼接。"""
assert old in t
t = t.replace(old, new, 1)

old2 = "  - **子阶段**：~~A6-0 落盘改“一条消息一行”~~（**已做**）→ A6-1 切片存储（两级寻址 + 确定性摘要 + 三道校验）"
new2 = "  - **子阶段**：~~A6-0 落盘改“一条消息一行”~~（**已做**）→ A6-1 摘要器 + 上下文/摘要文件 → A6-1b 切片文件（映射表）"
assert old2 in t
t = t.replace(old2, new2, 1)

io.open(p, "w", encoding="utf-8", newline="").write(t)
print("ROADMAP A6 已改为三层")
