//! F1: a read-only, explainable repository map.
//!
//! Deterministic and model-free. The map lists files, extracts the
//! top-level symbols from the source, records internal module edges, and
//! renders a view bounded by a token budget. Every rendered line carries
//! its source (`path:line`), so "what was sent to the model" is fully
//! reconstructible — the report includes the omitted files and the budget
//! watermark.
//!
//! It is a projection: `derived: true`, never authoritative, safe to
//! delete and rebuild.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{approx_tokens_of_chars, hex_sha256, Error, Result};

/// Directories never descended into. Not a .gitignore parser on purpose —
/// an exclusion list that can only shrink the scan is safe and explainable.
const IGNORED_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "dist",
    "build",
    ".pangu",
    ".idea",
    ".vscode",
];

const MAX_FILES: usize = 2_000;
const MAX_FILE_BYTES: u64 = 1_000_000;
const MAX_SYMBOLS_PER_FILE: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path relative to the scanned root, forward slashes.
    pub path: String,
    pub bytes: u64,
    /// Seconds since the epoch, when the platform reports an mtime.
    pub mtime: Option<u64>,
    pub symbols: Vec<Symbol>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoMap {
    pub root: String,
    pub files: Vec<FileEntry>,
    /// Internal edges `from -> to`, discovered from `mod x;` and
    /// `use crate::...` declarations in Rust sources. Heuristic by design.
    pub edges: Vec<(String, String)>,
    /// Files under the root that were not included (oversized, or
    /// unreadable as UTF-8). Explains the gaps.
    pub skipped: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapView {
    pub text: String,
    pub estimated_tokens: u64,
    pub included_files: usize,
    pub omitted_files: Vec<String>,
    pub truncated: bool,
}

fn language_of(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("rs") => "rust",
        Some("py") => "python",
        Some("js") | Some("mjs") | Some("cjs") => "javascript",
        Some("ts") | Some("tsx") | Some("jsx") => "typescript",
        Some("go") => "go",
        _ => "text",
    }
}

fn extract_symbols(lang: &str, text: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let candidate: Option<(&str, &str)> = match lang {
            "rust" => {
                if let Some(rest) = trimmed
                    .strip_prefix("pub fn ")
                    .or_else(|| trimmed.strip_prefix("fn "))
                    .or_else(|| trimmed.strip_prefix("pub async fn "))
                    .or_else(|| trimmed.strip_prefix("async fn "))
                {
                    Some(("fn", rest))
                } else if let Some(rest) = trimmed
                    .strip_prefix("pub struct ")
                    .or_else(|| trimmed.strip_prefix("struct "))
                {
                    Some(("struct", rest))
                } else if let Some(rest) = trimmed
                    .strip_prefix("pub enum ")
                    .or_else(|| trimmed.strip_prefix("enum "))
                {
                    Some(("enum", rest))
                } else if let Some(rest) = trimmed
                    .strip_prefix("pub trait ")
                    .or_else(|| trimmed.strip_prefix("trait "))
                {
                    Some(("trait", rest))
                } else if let Some(rest) = trimmed
                    .strip_prefix("mod ")
                    .or_else(|| trimmed.strip_prefix("pub mod "))
                {
                    Some(("mod", rest))
                } else {
                    None
                }
            }
            "python" => trimmed
                .strip_prefix("def ")
                .map(|rest| ("def", rest))
                .or_else(|| trimmed.strip_prefix("class ").map(|rest| ("class", rest))),
            "javascript" | "typescript" => trimmed
                .strip_prefix("function ")
                .map(|rest| ("function", rest))
                .or_else(|| trimmed.strip_prefix("class ").map(|rest| ("class", rest)))
                .or_else(|| {
                    trimmed
                        .strip_prefix("export function ")
                        .map(|rest| ("function", rest))
                }),
            "go" => trimmed.strip_prefix("func ").map(|rest| ("func", rest)),
            _ => None,
        };
        if let Some((kind, rest)) = candidate {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                symbols.push(Symbol {
                    name,
                    kind: kind.into(),
                    line: index + 1,
                });
            }
        }
        if symbols.len() >= MAX_SYMBOLS_PER_FILE {
            break;
        }
    }
    symbols
}

/// Resolve `use crate::a::b::c;` / `mod x;` to a sibling file, heuristically.
fn rust_internal_edges(path: &str, text: &str, files: &[FileEntry]) -> Vec<(String, String)> {
    let mut edges = Vec::new();
    let dir = Path::new(path).parent().map(|p| p.to_path_buf());
    for line in text.lines() {
        let trimmed = line.trim();
        let target_mod = if let Some(rest) = trimmed.strip_prefix("pub mod ") {
            Some(rest.trim_end_matches(';').trim())
        } else if let Some(rest) = trimmed.strip_prefix("mod ") {
            Some(rest.trim_end_matches(';').trim())
        } else if let Some(rest) = trimmed.strip_prefix("use crate::") {
            Some(rest.split("::").next().unwrap_or("").trim_end_matches(';'))
        } else {
            None
        };
        if let Some(module) = target_mod.and_then(|m| m.split([';', '{', ' ']).next()) {
            if module.is_empty() || module == "self" || module == "super" {
                continue;
            }
            let mut candidates = Vec::new();
            if let Some(dir) = &dir {
                candidates.push(dir.join(format!("{module}.rs")));
                candidates.push(dir.join(module).join("mod.rs"));
            }
            candidates.push(PathBuf::from(format!("src/{module}.rs")));
            for candidate in candidates {
                let as_string = candidate.to_string_lossy().replace('\\', "/");
                if files.iter().any(|f| f.path == as_string) && as_string != path {
                    edges.push((path.to_string(), as_string));
                    break;
                }
            }
        }
    }
    edges
}

pub struct RepoMapOptions {
    pub max_files: usize,
}

impl Default for RepoMapOptions {
    fn default() -> Self {
        Self {
            max_files: MAX_FILES,
        }
    }
}

/// Build the map. Read-only: never writes, never follows symlinks.
pub fn build(root: &Path, options: RepoMapOptions) -> Result<RepoMap> {
    let root_metadata = std::fs::symlink_metadata(root)
        .map_err(|e| Error::Other(format!("cannot read repo root: {e}")))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(Error::Other("repo root must be a real directory".into()));
    }
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => {
                skipped.push(format!("{} (read error: {error})", dir.display()));
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if IGNORED_DIRS.contains(&name.as_ref()) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            if files.len() >= options.max_files {
                skipped.push(format!("{} (file cap reached)", path.display()));
                continue;
            }
            if metadata.len() > MAX_FILE_BYTES {
                skipped.push(format!("{} (oversized)", path.display()));
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let lang = language_of(&path);
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(_) => {
                    skipped.push(format!("{relative} (not UTF-8)"));
                    continue;
                }
            };
            let mtime = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());
            files.push(FileEntry {
                symbols: extract_symbols(lang, &text),
                path: relative,
                bytes: metadata.len(),
                mtime,
            });
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let mut edges = Vec::new();
    for file in &files {
        if file.path.ends_with(".rs") {
            let full = root.join(&file.path);
            if let Ok(text) = std::fs::read_to_string(&full) {
                let mut found = rust_internal_edges(&file.path, &text, &files);
                edges.append(&mut found);
            }
        }
    }
    edges.sort();
    edges.dedup();
    Ok(RepoMap {
        root: root.to_string_lossy().replace('\\', "/"),
        files,
        edges,
        skipped,
    })
}

/// Render a token-budgeted view. Files are emitted in path order; when the
/// budget runs out, remaining files are listed by path only in
/// `omitted_files` — the view never silently drops information.
pub fn view(map: &RepoMap, budget_tokens: u64) -> MapView {
    let mut text = String::new();
    let mut included = 0usize;
    let mut omitted = Vec::new();
    let mut truncated = false;

    for file in &map.files {
        let mut block = format!("{} [{bytes}B]\n", file.path, bytes = file.bytes);
        for symbol in &file.symbols {
            block.push_str(&format!(
                "  {} {} (L{})\n",
                symbol.kind, symbol.name, symbol.line
            ));
        }
        let cost = approx_tokens_of_chars(block.chars().count() as u64);
        let used = approx_tokens_of_chars(text.chars().count() as u64);
        if used + cost > budget_tokens {
            omitted.push(file.path.clone());
            truncated = true;
            continue;
        }
        text.push_str(&block);
        included += 1;
    }

    let estimated = approx_tokens_of_chars(text.chars().count() as u64);
    MapView {
        text,
        estimated_tokens: estimated,
        included_files: included,
        omitted_files: omitted,
        truncated,
    }
}

/// A short digest of the map inputs so consumers can detect staleness.
pub fn fingerprint(map: &RepoMap) -> String {
    let mut rolling = String::new();
    for file in &map.files {
        rolling.push_str(&format!("{}:{}:", file.path, file.bytes));
        if let Some(mtime) = file.mtime {
            rolling.push_str(&format!("{mtime};"));
        }
    }
    hex_sha256(&rolling)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pangu-repomap-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn builds_files_and_symbols() {
        let root = tempdir("build");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/lib.rs"),
            "pub mod a;\n\npub struct Root;\npub fn entry() {}\n",
        )
        .unwrap();
        std::fs::write(root.join("src/a.rs"), "pub fn helper() {}\n").unwrap();
        std::fs::write(root.join("README.md"), "# hi\n").unwrap();

        let map = build(&root, RepoMapOptions::default()).expect("build");
        assert_eq!(map.files.len(), 3);
        let lib = map.files.iter().find(|f| f.path == "src/lib.rs").unwrap();
        assert!(lib
            .symbols
            .iter()
            .any(|s| s.name == "Root" && s.kind == "struct"));
        assert!(lib
            .symbols
            .iter()
            .any(|s| s.name == "entry" && s.kind == "fn"));
        assert!(map
            .edges
            .iter()
            .any(|(from, to)| from == "src/lib.rs" && to == "src/a.rs"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn view_respects_budget() {
        let root = tempdir("budget");
        std::fs::write(root.join("a.rs"), "pub fn one() {}\n").unwrap();
        std::fs::write(root.join("b.rs"), "pub fn two() {}\n").unwrap();
        let map = build(&root, RepoMapOptions::default()).expect("build");
        let wide = view(&map, 10_000);
        assert_eq!(wide.included_files, 2);
        assert!(!wide.truncated);
        let narrow = view(&map, 1);
        assert!(narrow.truncated);
        assert_eq!(narrow.omitted_files.len(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fingerprint_changes_with_files() {
        let root = tempdir("fp");
        std::fs::write(root.join("a.rs"), "pub fn one() {}\n").unwrap();
        let map_a = build(&root, RepoMapOptions::default()).expect("a");
        let fp_a = fingerprint(&map_a);
        std::fs::write(root.join("b.rs"), "pub fn two() {}\n").unwrap();
        let map_b = build(&root, RepoMapOptions::default()).expect("b");
        assert_ne!(fp_a, fingerprint(&map_b));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ignored_directories_are_not_scanned() {
        let root = tempdir("ignore");
        std::fs::create_dir_all(root.join("target/debug")).unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join("target/debug/x.rs"), "fn hidden() {}\n").unwrap();
        std::fs::write(root.join(".git/config.rs"), "fn hidden() {}\n").unwrap();
        std::fs::write(root.join("real.rs"), "fn visible() {}\n").unwrap();
        let map = build(&root, RepoMapOptions::default()).expect("build");
        assert_eq!(map.files.len(), 1);
        assert_eq!(map.files[0].path, "real.rs");
        let _ = std::fs::remove_dir_all(&root);
    }
}
