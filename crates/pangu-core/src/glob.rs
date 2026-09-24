//! Glob 匹配。策略规则与 `forbidden_globs` 都靠它，因此它的语义是**边界的一部分**：
//! 只做路径风格的匹配，不引入 shell 展开。
//!
//! 支持：`*`（不跨 `/`）、`**`（跨 `/`）、`?`（单字符，不跨 `/`）、
//! `[abc]` / `[a-z]`、`[!abc]`、`{a,b}` 交替。
//!
//! 匹配前统一把 `\` 归一为 `/`，并去掉 `./` 前缀。

use regex::Regex;

use crate::{Error, Result};

#[derive(Debug, Clone)]
pub struct Glob {
    source: String,
    re: Regex,
}

impl Glob {
    pub fn new(pattern: &str) -> Result<Self> {
        let translated = translate(pattern)?;
        let expression = if cfg!(windows) {
            format!("(?i){translated}")
        } else {
            translated
        };
        let re = Regex::new(&expression)
            .map_err(|e| Error::Config(format!("bad glob `{pattern}`: {e}")))?;
        Ok(Self {
            source: pattern.to_string(),
            re,
        })
    }

    pub fn is_match(&self, path: &str) -> bool {
        let p = normalize(path);
        if self.re.is_match(&p) {
            return true;
        }
        // 不含 `/` 的模式额外按 basename 匹配：`*.pem` 应当命中 `secrets/tls.pem`。
        if !self.source.contains('/') && !self.source.contains("**") {
            if let Some(base) = p.rsplit('/').next() {
                if self.re.is_match(base) {
                    return true;
                }
            }
        }
        false
    }

    pub fn pattern(&self) -> &str {
        &self.source
    }
}

pub fn normalize(path: &str) -> String {
    let mut s = path.replace('\\', "/");
    while let Some(stripped) = s.strip_prefix("./") {
        s = stripped.to_string();
    }
    s
}

pub fn matches(pattern: &str, path: &str) -> bool {
    Glob::new(pattern)
        .map(|g| g.is_match(path))
        .unwrap_or(false)
}

/// 任一模式命中即 true。空列表 = 永不命中。
pub fn matches_any(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|p| matches(p, path))
}

fn translate(pattern: &str) -> Result<String> {
    if pattern.len() > 4_096 {
        return Err(Error::Config("glob pattern exceeds 4096 bytes".into()));
    }
    let mut out = String::with_capacity(pattern.len() + 8);
    out.push('^');
    let bytes: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    let mut brace_depth = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            '*' => {
                // `**` 或 `/**/` 形式：跨目录。
                let dbl = bytes.get(i + 1) == Some(&'*');
                if dbl {
                    i += 2;
                    // `a/**` 应同时命中 `a`（常见习惯），所以用 (?:/? .*)
                    if bytes.get(i) == Some(&'/') {
                        i += 1;
                        out.push_str("(?:.*/)?");
                    } else {
                        out.push_str(".*");
                    }
                    // 吞掉随后又一个 `*`（`**/*` 之类）
                    continue;
                }
                out.push_str("[^/]*");
                i += 1;
            }
            '?' => {
                out.push_str("[^/]");
                i += 1;
            }
            '[' => {
                let end = match bytes[i..].iter().position(|&x| x == ']') {
                    Some(off) if off > 1 => i + off,
                    _ => {
                        out.push_str("\\[");
                        i += 1;
                        continue;
                    }
                };
                let mut cls = String::from("[");
                let mut j = i + 1;
                if bytes.get(j) == Some(&'!') {
                    cls.push('^');
                    j += 1;
                }
                while j < end {
                    cls.push(bytes[j]);
                    j += 1;
                }
                cls.push(']');
                out.push_str(&cls.replace('/', ""));
                i = end + 1;
            }
            '{' => {
                brace_depth += 1;
                out.push_str("(?:");
                i += 1;
            }
            '}' => {
                if brace_depth > 0 {
                    brace_depth = brace_depth.saturating_sub(1);
                }
                out.push(')');
                i += 1;
            }
            ',' if brace_depth > 0 => {
                out.push('|');
                i += 1;
            }
            '.' | '+' | '(' | ')' | '|' | '^' | '$' | '#' | '@' | '%' => {
                out.push('\\');
                out.push(c);
                i += 1;
            }
            '\\' => {
                // 转义下一个字符
                if let Some(n) = bytes.get(i + 1) {
                    if regex_meta(*n) {
                        out.push('\\');
                    }
                    out.push(*n);
                    i += 2;
                } else {
                    out.push_str("\\\\");
                    i += 1;
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    if brace_depth > 0 {
        return Err(Error::Config(format!(
            "unbalanced `{{` in glob `{pattern}`"
        )));
    }
    out.push('$');
    Ok(out)
}

fn regex_meta(c: char) -> bool {
    matches!(
        c,
        '.' | '+'
            | '*'
            | '?'
            | '('
            | ')'
            | '|'
            | '^'
            | '$'
            | '{'
            | '}'
            | '['
            | ']'
            | '\\'
            | '/'
            | '#'
            | '@'
            | '%'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_does_not_cross_dirs() {
        assert!(matches("*.rs", "main.rs"));
        assert!(matches("*.rs", "src/main.rs")); // bare basename patterns also match nested paths
        assert!(matches("src/*.rs", "src/main.rs"));
        assert!(!matches("src/*.rs", "src/a/main.rs"));
    }

    #[test]
    fn double_star_crosses_dirs() {
        assert!(matches("**/*.rs", "src/a/main.rs"));
        assert!(matches(".git/**", ".git/HEAD"));
        assert!(matches(".git/**", ".git/refs/heads/main"));
        assert!(matches("config/**/*.toml", "config/a/b.toml"));
    }

    #[test]
    fn bare_basename_pattern_matches_nested_paths() {
        assert!(matches("*.pem", "secrets/tls.pem"));
        assert!(matches("id_rsa*", ".ssh/id_rsa"));
        assert!(matches(".env", "sub/.env"));
    }

    #[test]
    fn classes_and_alternatives() {
        assert!(matches("src/{a,b}.rs", "src/b.rs"));
        assert!(!matches("src/{a,b}.rs", "src/c.rs"));
        assert!(matches("f[0-9].txt", "f7.txt"));
        assert!(matches("f[!0-9].txt", "fx.txt"));
        assert!(!matches("f[!0-9].txt", "f1.txt"));
    }

    #[test]
    fn windows_separators_are_normalized() {
        assert!(matches("**/secret*", "C:\\repo\\secret.txt"));
    }

    #[test]
    fn literal_dots_are_not_wildcards() {
        assert!(!matches("config.toml", "configXtoml"));
        assert!(matches("config.toml", "config.toml"));
    }
}
