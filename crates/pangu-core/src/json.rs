//! 只读的 JSON 取值小工具：`a.b[0].c` 风格路径。
//!
//! 之所以自己实现而不引 `jsonpath`：策略规则的参数匹配是边界语义，
//! 越少依赖越容易保证它在版本间不变。

use crate::Value;

/// 取路径上的值。`a.b[0].c`；不存在返回 None。
pub fn get<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for token in split_path(path) {
        cur = match cur {
            Value::Object(map) => map.get(&token)?,
            Value::Array(arr) => {
                let idx: usize = token.parse().ok()?;
                arr.get(idx)?
            }
            _ => return None,
        };
    }
    Some(cur)
}

/// 路径上的值是否等于 `want`（字符串比较，宽松：数字/布尔也按显示形式比）。
pub fn path_eq(v: &Value, path: &str, want: &str) -> bool {
    match get(v, path) {
        Some(Value::String(s)) => s == want,
        Some(Value::Bool(b)) => b.to_string() == want,
        Some(Value::Number(n)) => n.to_string() == want,
        Some(Value::Array(items)) => items.iter().any(|item| value_text_eq(item, want)),
        _ => false,
    }
}

/// 路径上的文本（字符串，或字符串数组拼接）。用于 `command`/`path` 这类参数的内容匹配。
pub fn path_text(v: &Value, path: &str) -> Option<String> {
    match get(v, path)? {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) => {
            let joined = items
                .iter()
                .map(|i| match i {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect::<Vec<_>>()
                .join(" ");
            Some(joined)
        }
        other => Some(other.to_string()),
    }
}

fn value_text_eq(value: &Value, want: &str) -> bool {
    match value {
        Value::String(text) => text == want,
        Value::Bool(value) => value.to_string() == want,
        Value::Number(value) => value.to_string() == want,
        _ => false,
    }
}

pub fn as_string<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

pub fn as_u64(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(Value::as_u64)
}

pub fn as_bool(v: &Value, key: &str) -> Option<bool> {
    v.get(key).and_then(Value::as_bool)
}

pub fn as_str_array(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| match x {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn require_str<'a>(v: &'a Value, key: &str, tool: &str) -> crate::Result<&'a str> {
    as_string(v, key).ok_or_else(|| crate::Error::InvalidArgs {
        tool: tool.into(),
        detail: format!("`{key}` is required and must be a string"),
    })
}

pub fn optional_str<'a>(v: &'a Value, key: &str, default: &'a str) -> &'a str {
    as_string(v, key).unwrap_or(default)
}

/// `{"a":{"b":[1]}}` → ["a","b","0"]
fn split_path(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '.' => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            '[' => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                let mut idx = String::new();
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if n == ']' {
                        break;
                    }
                    idx.push(n);
                }
                if !idx.is_empty() {
                    out.push(idx);
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// 稳定的 JSON 文本（key 排序由 serde_json 的 BTreeMap 保证），用于配置摘要。
pub fn canonical(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "null".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_nested_paths() {
        let v = json!({"a": {"b": [{"c": "x"}]}});
        assert_eq!(get(&v, "a.b.0.c").and_then(Value::as_str), Some("x"));
        assert_eq!(get(&v, "a.b[0].c").and_then(Value::as_str), Some("x"));
        assert!(get(&v, "a.missing.c").is_none());
        assert!(get(&v, "a.b.9.c").is_none());
    }

    #[test]
    fn path_text_joins_arrays() {
        let v = json!({"command": ["git", "status"]});
        assert_eq!(path_text(&v, "command").as_deref(), Some("git status"));
    }

    #[test]
    fn path_eq_matches_array_membership() {
        let v = json!({"paths": ["src/a.rs", "README.md"]});
        assert!(path_eq(&v, "paths", "README.md"));
        assert!(!path_eq(&v, "paths", "docs/BOUNDARY.md"));
    }
}
