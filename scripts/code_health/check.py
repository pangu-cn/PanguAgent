from pathlib import Path

RED = {
    "crates/pangu-boundary/src/sandbox.rs",
    "crates/pangu-agent/src/lib.rs",
}

def scan(text: str) -> tuple[int, int]:
    complexity = 1
    depth = 0
    maximum = 0
    for token in text.replace("(", " ").replace(")", " ").split():
        if token in {"if", "for", "while", "match", "loop"}:
            complexity += 1
        depth += token.count("{") - token.count("}")
        maximum = max(maximum, depth)
    return complexity, maximum

for path in Path("crates").rglob("*.rs"):
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.count("\n") + 1
    complexity, depth = scan(text)
    limit = 1500 if path.as_posix() in RED else 2000
    if lines > limit or complexity > 20 or depth > 6:
        print(f"::warning title=code health::{path.as_posix()} lines={lines} cc~={complexity} nesting~={depth}")
