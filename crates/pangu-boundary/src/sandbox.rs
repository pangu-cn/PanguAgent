//! L3 resource checks.
//!
//! The sandbox is intentionally conservative: it resolves existing path
//! components without following symlinks, requires writable roots to be
//! descendants of the workspace, validates every path in a multi-target
//! action, and treats unresolved network hosts as denied.

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};

use pangu_core::{glob, Error, Result};
use url::Url;

use crate::config::BoundarySection;

#[derive(Debug, Clone, Default)]
pub struct ResourceRequest {
    pub read_paths: Vec<PathBuf>,
    pub write_paths: Vec<PathBuf>,
    pub hosts: Vec<String>,
    pub argv: Vec<String>,
    pub cwd: Option<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct ValidatedResources {
    pub read_paths: Vec<PathBuf>,
    pub write_paths: Vec<PathBuf>,
    pub hosts: Vec<String>,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
}

#[derive(Clone)]
pub struct Sandbox {
    pub workspace: PathBuf,
    pub readable_roots: Vec<PathBuf>,
    pub writable_roots: Vec<PathBuf>,
    pub forbidden_globs: Vec<pangu_core::Glob>,
    pub env_allow: Vec<String>,
    pub max_tool_output_bytes: usize,
    pub max_arg_bytes: usize,
    pub subprocess_timeout_secs: u64,
    pub subprocess_output_limit: usize,
    pub network_allowed_hosts: Vec<pangu_core::Glob>,
    pub allow_localhost: bool,
    pub max_paths_per_action: usize,
    pub max_write_bytes: usize,
}

impl Sandbox {
    pub fn from_config(config: &BoundarySection) -> Result<Self> {
        if config.max_tool_output_bytes < 256
            || config.max_tool_output_bytes > 16 * 1024 * 1024
            || config.max_arg_bytes == 0
            || config.max_write_bytes == 0
            || config.max_paths_per_action == 0
            || config.subprocess_timeout_secs == 0
            || config.subprocess_output_limit == 0
        {
            return Err(Error::Config(
                "sandbox resource limits must be positive".into(),
            ));
        }
        if config.env.allow.iter().any(|key| {
            sensitive_env_key(key)
                || key.trim().is_empty()
                || !key
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
                || key
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_digit())
        }) {
            return Err(Error::Config(
                "sensitive or empty environment key is not allowed".into(),
            ));
        }
        let workspace = canonical_root(&absolute_path(&config.workspace)?)?;
        // Keep the effective order and contents identical to the contract
        // builder. Config validation requires the workspace to be present in
        // readable_roots; prepending it here would make a valid roots list
        // such as [subdir, workspace] fail GoalContract::validate_against.
        let mut readable_roots = Vec::new();
        for root in &config.readable_roots {
            let root = canonical_root(&absolute_path_from(&workspace, root)?)?;
            if !readable_roots.contains(&root) {
                readable_roots.push(root);
            }
        }
        if readable_roots.is_empty() {
            readable_roots.push(workspace.clone());
        }
        let mut writable_roots = Vec::new();
        for root in &config.writable_roots {
            let root = canonical_root(&absolute_path_from(&workspace, root)?)?;
            if !root.starts_with(&workspace) {
                return Err(Error::Config(format!(
                    "writable root {} is outside workspace {}",
                    root.display(),
                    workspace.display()
                )));
            }
            if !writable_roots.contains(&root) {
                writable_roots.push(root);
            }
        }
        if writable_roots.is_empty() {
            writable_roots.push(workspace.clone());
        }

        let forbidden_globs = config
            .forbidden_globs
            .iter()
            .map(|pattern| {
                if pattern.chars().any(char::is_control) {
                    return Err(Error::Config(
                        "sandbox forbidden glob contains control characters".into(),
                    ));
                }
                glob::Glob::new(pattern)
            })
            .collect::<Result<Vec<_>>>()?;
        let network_allowed_hosts = config
            .network
            .hosts
            .iter()
            .map(|pattern| {
                if pattern.chars().any(char::is_control) {
                    return Err(Error::Config(
                        "sandbox network host contains control characters".into(),
                    ));
                }
                glob::Glob::new(pattern)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            workspace,
            readable_roots,
            writable_roots,
            forbidden_globs,
            env_allow: config.env.allow.clone(),
            max_tool_output_bytes: config.max_tool_output_bytes,
            max_arg_bytes: config.max_arg_bytes,
            subprocess_timeout_secs: config.subprocess_timeout_secs,
            subprocess_output_limit: config.subprocess_output_limit,
            network_allowed_hosts,
            allow_localhost: config.network.allow_localhost,
            max_paths_per_action: config.max_paths_per_action,
            max_write_bytes: config.max_write_bytes,
        })
    }

    pub fn resolve_read(&self, path: &Path) -> ResolveOutcome {
        let target = match absolute_path_from(&self.workspace, path) {
            Ok(target) => target,
            Err(error) => return ResolveOutcome::Error(error),
        };
        if has_symlink_component(&target) {
            return ResolveOutcome::Error(Error::Config(format!(
                "symlink path not allowed: {}",
                target.display()
            )));
        }
        let canonical = match std::fs::canonicalize(&target) {
            Ok(path) => path,
            Err(error) => return ResolveOutcome::Error(Error::Io(error)),
        };
        if let Some(forbidden) = self.forbidden_path(&canonical) {
            return ResolveOutcome::ForbiddenGlob(forbidden);
        }
        if self.root_contains(&canonical, &self.readable_roots) {
            ResolveOutcome::Allowed(canonical)
        } else {
            ResolveOutcome::OutsideRoot(format!(
                "{} is not in a readable root",
                canonical.display()
            ))
        }
    }

    pub fn resolve_write(&self, path: &Path) -> ResolveOutcome {
        let target = match absolute_path_from(&self.workspace, path) {
            Ok(target) => target,
            Err(error) => return ResolveOutcome::Error(error),
        };
        let Some(file_name) = target.file_name() else {
            return ResolveOutcome::Error(Error::Config("write target has no file name".into()));
        };
        let parent = match target.parent() {
            Some(parent) => parent,
            None => {
                return ResolveOutcome::Error(Error::Config("write target has no parent".into()))
            }
        };
        if has_symlink_component(parent) {
            return ResolveOutcome::Error(Error::Config(format!(
                "symlink path not allowed: {}",
                target.display()
            )));
        }
        let canonical_parent = match std::fs::canonicalize(parent) {
            Ok(path) => path,
            Err(error) => return ResolveOutcome::Error(Error::Io(error)),
        };
        let candidate = canonical_parent.join(file_name);
        if has_symlink_component(&candidate) {
            return ResolveOutcome::Error(Error::Config(format!(
                "symlink path not allowed: {}",
                candidate.display()
            )));
        }
        if let Some(forbidden) = self.forbidden_path(&candidate) {
            return ResolveOutcome::ForbiddenGlob(forbidden);
        }
        if self.root_contains(&candidate, &self.writable_roots) {
            ResolveOutcome::Allowed(candidate)
        } else {
            ResolveOutcome::OutsideRoot(format!(
                "{} is not in a writable root",
                candidate.display()
            ))
        }
    }

    pub fn root_contains(&self, target: &Path, roots: &[PathBuf]) -> bool {
        roots.iter().any(|root| target.starts_with(root))
    }

    pub fn validate_resources(&self, request: &ResourceRequest) -> Result<ValidatedResources> {
        let path_count = request
            .read_paths
            .len()
            .saturating_add(request.write_paths.len())
            .saturating_add(usize::from(request.cwd.is_some()));
        if path_count > self.max_paths_per_action {
            return Err(Error::Other(format!(
                "action touches {path_count} paths; limit is {}",
                self.max_paths_per_action
            )));
        }
        if request.hosts.len() > self.max_paths_per_action
            || request.argv.len() > self.max_paths_per_action
        {
            return Err(Error::Other(format!(
                "action has too many network or process targets; limit is {}",
                self.max_paths_per_action
            )));
        }
        let mut read_paths = Vec::with_capacity(request.read_paths.len());
        for path in &request.read_paths {
            read_paths.push(require_allowed(self.resolve_read(path), "read")?);
        }
        let mut write_paths = Vec::with_capacity(request.write_paths.len());
        for path in &request.write_paths {
            write_paths.push(require_allowed(self.resolve_write(path), "write")?);
        }

        let mut hosts = Vec::with_capacity(request.hosts.len());
        for host in &request.hosts {
            hosts.push(self.check_host(host)?);
        }
        if !request.argv.is_empty() {
            self.validate_argv(&request.argv)?;
        }

        let cwd = match &request.cwd {
            Some(path) => require_allowed(self.resolve_read(path), "cwd")?,
            None => self.workspace.clone(),
        };
        Ok(ValidatedResources {
            read_paths,
            write_paths,
            hosts,
            argv: request.argv.clone(),
            cwd,
        })
    }

    pub fn check_url(&self, raw_url: &str) -> Result<String> {
        if raw_url.len() > 2_048 || raw_url.chars().any(char::is_control) {
            return Err(Error::Config("invalid URL".into()));
        }
        let url = Url::parse(raw_url).map_err(|_| Error::Config("invalid URL".into()))?;
        let safe_target = safe_url_target(&url);
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(Error::EgressDenied { host: safe_target });
        }
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(Error::EgressDenied { host: safe_target });
        }
        if url.port() == Some(0) {
            return Err(Error::EgressDenied {
                host: "[port must be non-zero]".into(),
            });
        }
        if url.query_pairs().any(|(key, _)| {
            let key = key.to_ascii_lowercase();
            [
                "key",
                "token",
                "secret",
                "password",
                "passwd",
                "auth",
                "credential",
            ]
            .iter()
            .any(|part| key.contains(part))
        }) {
            return Err(Error::EgressDenied {
                host: "[query contains a sensitive parameter]".into(),
            });
        }
        let host = url
            .host_str()
            .ok_or_else(|| Error::EgressDenied {
                host: safe_target.clone(),
            })?
            .to_ascii_lowercase();
        let port = url.port_or_known_default().unwrap_or(443);
        let endpoint = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        self.check_host(&endpoint)?;
        Ok(url.to_string())
    }

    pub fn check_host(&self, host: &str) -> Result<String> {
        if host.len() > 2_048 || host.chars().any(char::is_control) {
            return Err(Error::EgressDenied {
                host: "[invalid host]".into(),
            });
        }
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() {
            return Err(Error::EgressDenied { host });
        }
        if host.chars().any(char::is_whitespace)
            || host
                .chars()
                .any(|character| matches!(character, '@' | '/' | '?' | '#'))
        {
            return Err(Error::EgressDenied {
                host: "[invalid host]".into(),
            });
        }
        let Some((name, port)) = split_host_port(&host) else {
            return Err(Error::EgressDenied {
                host: "[invalid host]".into(),
            });
        };
        if port == 0 {
            return Err(Error::EgressDenied { host });
        }
        if name == "169.254.169.254" {
            return Err(Error::EgressDenied { host });
        }
        let is_local = name == "localhost"
            || name.ends_with(".localhost")
            || name
                .parse::<IpAddr>()
                .map(|ip| is_blocked_ip(ip, self.allow_localhost))
                .unwrap_or(false);
        if is_local && !self.allow_localhost {
            return Err(Error::EgressDenied { host: host.clone() });
        }
        if let Ok(ip) = name.parse::<IpAddr>() {
            if is_always_blocked_ip(ip) || (!self.allow_localhost && is_blocked_ip(ip, false)) {
                return Err(Error::EgressDenied { host: host.clone() });
            }
        } else {
            let addresses = (name, port)
                .to_socket_addrs()
                .map_err(|_| Error::EgressDenied { host: host.clone() })?;
            let mut found = false;
            for address in addresses {
                found = true;
                if is_always_blocked_ip(address.ip())
                    || (!self.allow_localhost && is_blocked_ip(address.ip(), false))
                {
                    return Err(Error::EgressDenied { host: host.clone() });
                }
            }
            if !found {
                return Err(Error::EgressDenied { host: host.clone() });
            }
        }
        let allowed = self
            .network_allowed_hosts
            .iter()
            .any(|pattern| pattern.is_match(name) || pattern.is_match(&host));
        if !allowed {
            return Err(Error::EgressDenied { host });
        }
        Ok(host)
    }

    pub fn validate_argv(&self, argv: &[String]) -> Result<()> {
        if argv.is_empty() {
            return Err(Error::Config("argv must not be empty".into()));
        }
        let total = argv
            .iter()
            .try_fold(0usize, |sum, arg| sum.checked_add(arg.len()))
            .ok_or_else(|| Error::Config("argv length overflow".into()))?;
        if total > self.max_arg_bytes {
            return Err(Error::Config(format!(
                "argv is {total} bytes; limit is {}",
                self.max_arg_bytes
            )));
        }
        if argv.iter().any(|arg| arg.chars().any(char::is_control)) {
            return Err(Error::Config("argv contains control characters".into()));
        }
        let executable = Path::new(&argv[0]);
        if executable.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) || executable.to_string_lossy().contains('/')
            || executable.to_string_lossy().contains('\\')
        {
            return Err(Error::Config(
                "command executable must be a bare allow-listed name".into(),
            ));
        }
        let program = executable
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        const COMMANDS: &[&str] = &[
            "pwd",
            "cat",
            "ls",
            "head",
            "tail",
            "grep",
            "wc",
            "sort",
            "uniq",
            "diff",
            "md5sum",
            "sha256sum",
        ];
        if !COMMANDS.contains(&program) {
            return Err(Error::Config(format!(
                "command `{program}` is not on the read-only argv allow-list"
            )));
        }
        if !self
            .env_allow
            .iter()
            .any(|key| key.eq_ignore_ascii_case("PATH"))
        {
            return Err(Error::Config(
                "PATH must be allowed for command resolution".into(),
            ));
        }
        if Path::new(&argv[0]).is_absolute() {
            return Err(Error::Config(
                "absolute executable paths are not allowed".into(),
            ));
        }
        const SAFE_FLAGS: &[&str] = &[
            "--", "-n", "-i", "-E", "-F", "-e", "--regexp", "-l", "-w", "-c", "-m", "-r", "-u",
            "-d", "-q", "-a", "-1", "-h",
        ];
        for argument in argv.iter().skip(1) {
            let path = Path::new(argument);
            if path.is_absolute()
                || argument.contains("..")
                || (argument.starts_with('-')
                    && argument.len() > 1
                    && !SAFE_FLAGS.contains(&argument.as_str()))
            {
                return Err(Error::Config(format!(
                    "argv argument is not allowed: {argument}"
                )));
            }
        }
        Ok(())
    }

    pub fn can_exec(&self, command: &str) -> bool {
        matches!(
            command,
            "pwd"
                | "cat"
                | "ls"
                | "head"
                | "tail"
                | "grep"
                | "wc"
                | "sort"
                | "uniq"
                | "diff"
                | "md5sum"
                | "sha256sum"
        )
    }

    pub fn sanitize_env(&self, input: &HashMap<String, String>) -> HashMap<String, String> {
        self.env_allow
            .iter()
            .filter(|key| !sensitive_env_key(key))
            .filter_map(|key| input.get(key).map(|value| (key.clone(), value.clone())))
            .collect()
    }

    fn forbidden_path(&self, path: &Path) -> Option<String> {
        let absolute = path.to_string_lossy().replace('\\', "/");
        let relative = path
            .strip_prefix(&self.workspace)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        self.forbidden_globs.iter().find_map(|pattern| {
            if pattern.is_match(&absolute) || pattern.is_match(&relative) {
                Some(relative.clone())
            } else {
                None
            }
        })
    }
}

fn require_allowed(outcome: ResolveOutcome, operation: &str) -> Result<PathBuf> {
    match outcome {
        ResolveOutcome::Allowed(path) => Ok(path),
        ResolveOutcome::ForbiddenGlob(path) => Err(Error::PathOutsideBoundary {
            path,
            reason: format!("forbidden path ({operation})"),
        }),
        ResolveOutcome::OutsideRoot(reason) => Err(Error::PathOutsideBoundary {
            path: reason,
            reason: format!("outside boundary ({operation})"),
        }),
        ResolveOutcome::Error(error) => Err(error),
    }
}

#[derive(Debug)]
pub enum ResolveOutcome {
    Allowed(PathBuf),
    ForbiddenGlob(String),
    OutsideRoot(String),
    Error(Error),
}

impl ResolveOutcome {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed(_))
    }

    pub fn into_path(self) -> Option<PathBuf> {
        match self {
            Self::Allowed(path) => Some(path),
            _ => None,
        }
    }
}

pub(crate) fn absolute_path(path: &Path) -> Result<PathBuf> {
    let current = std::env::current_dir()?;
    absolute_path_from(&current, path)
}

pub(crate) fn absolute_path_from(base: &Path, path: &Path) -> Result<PathBuf> {
    let text = path.to_string_lossy();
    if text.contains('\0')
        || text.starts_with("//")
        || (text.starts_with("\\\\") && !text.starts_with("\\\\?\\"))
        || text.to_ascii_lowercase().starts_with("\\\\?\\unc\\")
    {
        return Err(Error::Config(format!(
            "path is not allowed: {}",
            path.display()
        )));
    }
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(Error::Config(format!(
                    "parent traversal is not allowed: {}",
                    path.display()
                )))
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str())
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(Error::Config("path must not be empty".into()));
    }
    Ok(normalized)
}

fn canonical_root(path: &Path) -> Result<PathBuf> {
    if has_symlink_component(path) {
        return Err(Error::Config(format!(
            "symlink root is not allowed: {}",
            path.display()
        )));
    }
    let canonical = std::fs::canonicalize(path)?;
    if !canonical.is_dir() {
        return Err(Error::Config(format!(
            "root is not a directory: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn has_symlink_component(path: &Path) -> bool {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                current.push(prefix.as_os_str());
                continue;
            }
            Component::RootDir => {
                current.push(component.as_os_str());
                continue;
            }
            Component::CurDir => {}
            Component::ParentDir => return true,
            Component::Normal(value) => current.push(value),
        }
        if current.as_os_str().is_empty() {
            continue;
        }
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return true,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return true,
        }
    }
    false
}

fn safe_url_target(url: &Url) -> String {
    let Some(host) = url.host_str() else {
        return "[URL without host]".into();
    };
    let host = host.to_ascii_lowercase();
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    }
}

fn split_host_port(value: &str) -> Option<(&str, u16)> {
    if let Ok(address) = value.parse::<IpAddr>() {
        return Some((value, if address.is_ipv4() { 80 } else { 443 }));
    }
    if let Some(rest) = value.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        if suffix.is_empty() {
            return Some((host, 443));
        }
        let port = suffix.strip_prefix(':')?.parse::<u16>().ok()?;
        return Some((host, port));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if host.is_empty() || host.contains(':') {
            return None;
        }
        return Some((host, port.parse::<u16>().ok()?));
    }
    Some((value, 443))
}

fn is_always_blocked_ip(ip: IpAddr) -> bool {
    if let IpAddr::V6(ip) = ip {
        if let Some(mapped) = ip.to_ipv4_mapped() {
            return is_always_blocked_ip(IpAddr::V4(mapped));
        }
    }
    match ip {
        IpAddr::V4(ip) => {
            ip.is_link_local() || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            ip.is_unspecified() || ip.is_multicast() || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn is_blocked_ip(ip: IpAddr, allow_localhost: bool) -> bool {
    if !allow_localhost {
        return match ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_broadcast()
                    || ip.is_documentation()
                    || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                    || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
                    || octets[0] >= 240
            }
            IpAddr::V6(ip) => {
                let segments = ip.segments();
                ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || (segments[0] & 0xfe00) == 0xfc00
                    || (segments[0] & 0xffc0) == 0xfe80
                    || ip
                        .to_ipv4_mapped()
                        .is_some_and(|mapped| is_blocked_ip(IpAddr::V4(mapped), allow_localhost))
            }
        };
    }
    is_always_blocked_ip(ip)
}

fn sensitive_env_key(key: &str) -> bool {
    let key = key.to_ascii_uppercase();
    [
        "KEY",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "AUTH",
        "CREDENTIAL",
    ]
    .iter()
    .any(|part| key.contains(part))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_workspace() -> PathBuf {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("pangu-sandbox-{}-{suffix}", std::process::id()))
    }

    #[test]
    fn paths_are_relative_to_workspace_and_new_files_are_checked() {
        let root = test_workspace();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("file.txt"), "ok").unwrap();
        fs::write(root.join(".env"), "SECRET=value").unwrap();
        let config = crate::config::BoundarySection {
            workspace: root.clone(),
            readable_roots: vec![root.clone()],
            writable_roots: vec![root.clone()],
            ..Default::default()
        };
        let sandbox = Sandbox::from_config(&config).unwrap();
        assert!(sandbox.resolve_read(Path::new("file.txt")).is_allowed());
        assert!(!sandbox
            .resolve_read(Path::new("../outside.txt"))
            .is_allowed());
        assert!(sandbox.resolve_write(Path::new("new.txt")).is_allowed());
        assert!(!sandbox.resolve_read(Path::new(".env")).is_allowed());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn traversal_unc_and_nul_paths_are_rejected() {
        let root = test_workspace();
        fs::create_dir_all(&root).unwrap();
        let config = crate::config::BoundarySection {
            workspace: root.clone(),
            readable_roots: vec![root.clone()],
            writable_roots: vec![root.clone()],
            ..Default::default()
        };
        let sandbox = Sandbox::from_config(&config).unwrap();
        assert!(!sandbox
            .resolve_read(Path::new("../outside.txt"))
            .is_allowed());
        assert!(absolute_path_from(&root, Path::new("../outside.txt")).is_err());
        assert!(!sandbox.resolve_read(Path::new("bad\0name")).is_allowed());
        assert!(absolute_path_from(&root, Path::new("bad\0name")).is_err());
        assert!(sandbox
            .validate_argv(&["cat".into(), "line\nname".into()])
            .is_err());
        assert!(!sandbox
            .resolve_read(Path::new(r"\\server\share\file"))
            .is_allowed());
        assert!(absolute_path_from(&root, Path::new(r"\\server\share\file")).is_err());
        assert!(sandbox
            .check_url("https://169.254.169.254/latest/meta-data")
            .is_err());
        let query_error = sandbox
            .check_url("https://example.com/?api_key=secret")
            .unwrap_err()
            .to_string();
        assert!(!query_error.contains("secret"));
        assert!(sandbox.check_url("file:///etc/passwd").is_err());
        let mut local_config = config.clone();
        local_config.network.allow_localhost = true;
        local_config.network.hosts = vec!["*".into()];
        let local_sandbox = Sandbox::from_config(&local_config).unwrap();
        assert!(local_sandbox
            .check_url("https://[::ffff:169.254.169.254]/")
            .is_err());
        assert!(local_sandbox.check_url("https://127.0.0.1/").is_ok());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn all_paths_in_a_multi_target_action_are_checked() {
        let root = test_workspace();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("safe.txt"), "ok").unwrap();
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/.env.local"), "secret").unwrap();
        let config = crate::config::BoundarySection {
            workspace: root.clone(),
            readable_roots: vec![root.clone()],
            writable_roots: vec![root.clone()],
            ..Default::default()
        };
        let sandbox = Sandbox::from_config(&config).unwrap();
        let result = sandbox.validate_resources(&ResourceRequest {
            read_paths: vec![
                PathBuf::from("safe.txt"),
                PathBuf::from("nested/.env.local"),
            ],
            ..Default::default()
        });
        assert!(result.is_err());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn command_argv_is_bounded_and_allow_listed() {
        let root = test_workspace();
        fs::create_dir_all(&root).unwrap();
        let config = crate::config::BoundarySection {
            workspace: root.clone(),
            readable_roots: vec![root.clone()],
            writable_roots: vec![root.clone()],
            ..Default::default()
        };
        let sandbox = Sandbox::from_config(&config).unwrap();
        assert!(sandbox
            .validate_argv(&["cat".into(), "safe.txt".into()])
            .is_ok());
        assert!(sandbox
            .validate_argv(&["powershell".into(), "-Command".into(), "Get-Process".into()])
            .is_err());
        assert!(sandbox.validate_argv(&["../cat".into()]).is_err());
        assert!(sandbox
            .validate_argv(&["cat".into(), "../outside".into()])
            .is_err());
        assert!(sandbox.validate_argv(&[]).is_err());
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_components_are_rejected() {
        let root = test_workspace();
        let outside = test_workspace();
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(outside.join("secret.txt"), root.join("link.txt")).unwrap();
        let config = crate::config::BoundarySection {
            workspace: root.clone(),
            readable_roots: vec![root.clone()],
            writable_roots: vec![root.clone()],
            ..Default::default()
        };
        let sandbox = Sandbox::from_config(&config).unwrap();
        assert!(!sandbox.resolve_read(Path::new("link.txt")).is_allowed());
        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(outside).ok();
    }
}
