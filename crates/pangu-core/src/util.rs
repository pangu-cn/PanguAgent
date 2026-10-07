//! Small, side-effect-free helpers used at runtime boundaries.

use sha2::{Digest, Sha256};

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn short_hash(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex::encode(&h.finalize()[..8])
}

pub fn hex_sha256(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex::encode(h.finalize())
}

/// SHA-256 of arbitrary bytes (skill files are not necessarily UTF-8).
pub fn hex_sha256_bytes(input: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(input);
    hex::encode(h.finalize())
}

/// Keep both ends of a bounded tool result. The returned string is guaranteed
/// not to exceed `max_bytes` (apart from the explicitly returned empty string
/// for a zero-sized limit).
pub fn truncate_middle(s: &str, max_bytes: usize) -> String {
    if max_bytes == 0 {
        return String::new();
    }
    if s.len() <= max_bytes {
        return s.to_string();
    }

    let marker = "\n… [bytes elided] …\n";
    if max_bytes <= marker.len() {
        return floor_char_boundary(s, max_bytes);
    }

    let available = max_bytes - marker.len();
    let head = available.saturating_mul(3) / 5;
    let tail = available - head;
    let mut out = String::with_capacity(max_bytes);
    out.push_str(&floor_char_boundary(s, head));
    out.push_str(marker);
    let start = ceil_char_boundary(s, s.len().saturating_sub(tail));
    out.push_str(&s[start..]);
    debug_assert!(out.len() <= max_bytes);
    out
}

pub fn floor_char_boundary(s: &str, mut i: usize) -> String {
    if i >= s.len() {
        return s.to_string();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    s[..i].to_string()
}

pub fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

pub fn one_line(s: &str, max: usize) -> String {
    let flat: String = s.chars().map(|c| if c == '\n' { ' ' } else { c }).collect();
    if flat.len() <= max {
        flat
    } else if max <= 3 {
        ".".repeat(max)
    } else {
        format!("{}...", floor_char_boundary(&flat, max - 3))
    }
}

/// Escape a string as a JSON string without corrupting leading/trailing quotes.
pub fn escape_json(s: &str) -> String {
    let encoded = serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string());
    encoded
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(&encoded)
        .to_string()
}

/// Very rough token estimate. It is only a preflight heuristic.
pub fn approx_tokens_of_chars(chars: u64) -> u64 {
    chars.div_ceil(4)
}

/// A path rendered for a human or for a record, not for the Win32 API.
///
/// Paths that have been through `std::fs::canonicalize` come back in Windows'
/// *verbatim* form (`\\?\F:\ws`, or `\\?\UNC\server\share`), because that is what
/// addresses long paths without further normalization. It is the right form to
/// hand to the filesystem and the wrong form to show anyone: it does not work
/// pasted into a shell, and it means nothing on another machine.
///
/// This matters where output is archived as evidence. §9.3 of the recovery
/// manual has the operator save `artifact inspect --json` as the off-machine
/// record of what a store looked like; a `root` field in verbatim form is not
/// something a reader elsewhere can resolve or check.
///
/// Only the marker is removed — the UNC form keeps its double backslash, because
/// that *is* the share path other Windows programs expect.
pub fn displayable_path(path: &std::path::Path) -> String {
    let text = path.display().to_string();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        if !rest.is_empty() {
            return rest.to_string();
        }
    }
    text
}

pub fn human_bytes(n: usize) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_is_bounded_and_utf8_safe() {
        let s = "汉字".repeat(500);
        let out = truncate_middle(&s, 100);
        assert!(out.len() <= 100);
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
        assert!(out.contains("elided"));
    }

    #[test]
    fn escape_json_preserves_quotes_inside_content() {
        assert_eq!(escape_json("\"quoted\""), "\\\"quoted\\\"");
    }
}
