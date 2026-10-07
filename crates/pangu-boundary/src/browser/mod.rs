//! Native browser control over the Chrome DevTools Protocol (CDP).
//!
//! # Why this is built in rather than delegated to an MCP server
//!
//! Browser automation was previously reachable only by pointing Pangu at an
//! external MCP server. That works, but it puts the browser outside every
//! guarantee this project makes: the session is a third-party process, whose
//! requests Pangu cannot attribute, gate, or bound.
//!
//! Driving CDP directly keeps browser actions inside the same L1–L4 chain as
//! every other tool. A click is an action with a risk, a target and an effect;
//! navigation reaches a *host*, so it is an outbound network action exactly like
//! `http_fetch`; a screenshot is a read of the page's contents.
//!
//! # What this module does and does not do
//!
//! It speaks the wire protocol: it starts a headless Chromium with a private
//! profile directory, discovers its WebSocket endpoint, and sends CDP commands.
//! It does **not** implement a general transport — see [`websocket`] for the
//! deliberately narrow frame codec.
//!
//! # Why the browser is launched as a subprocess here
//!
//! CDP is a socket protocol, so in principle the browser could be launched
//! elsewhere (inside the F8 runtime) and reached over TCP. That is what
//! [`BrowserConfig::launch`] supports when the operator attaches a sandbox
//! runtime: the browser is started inside the sandbox and the endpoint is
//! reached through its published port. When no runtime is declared, the browser
//! runs as an ordinary local process, and this module says so rather than
//! implying isolation it does not have.

pub mod cdp;
pub mod websocket;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pangu_core::Error;

pub use cdp::{BrowserSession, PageSnapshot};
pub use websocket::{WebSocket, WsFrame};

/// Seconds to wait for a freshly launched browser to publish its endpoint.
///
/// Bounded because a browser that fails to start must surface as a failure
/// rather than hang the run: Chromium can stall on a locked profile directory or
/// a missing shared library instead of exiting.
pub const LAUNCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Seconds to wait for a single CDP command's reply.
///
/// A page that never finishes loading must not block forever; the call times out
/// with a message that says which command did not answer.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Which browser binary to run, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserConfig {
    /// Absolute path to the Chromium/Chrome executable.
    pub executable: PathBuf,
    /// Private profile directory. Fresh per session: a shared profile carries
    /// cookies and logins between runs, which would make one run's state part of
    /// another's input.
    pub profile_dir: PathBuf,
    /// Whether the page may reach the network at all.
    ///
    /// `false` is not a sandbox — it is a restriction on what the page can do,
    /// layered under whatever [`crate::runtime`] provides.
    pub network: bool,
    /// Extra command-line flags, appended verbatim.
    pub extra_args: Vec<String>,
}

impl BrowserConfig {
    /// Locate a browser executable on this machine.
    ///
    /// Returns the first known candidate that exists, so a machine with only
    /// Edge installed still works. `None` means "no browser found", which the
    /// caller must report rather than silently degrade to a different tool.
    pub fn find_executable() -> Option<PathBuf> {
        default_candidates().into_iter().find(|path| path.is_file())
    }

    /// The arguments this configuration launches with.
    ///
    /// `--headless=new` rather than the old headless mode: the legacy mode is a
    /// separate implementation with different rendering, and screenshots taken
    /// under it do not match what a user would see.
    pub fn args(&self) -> Vec<String> {
        let mut args = vec![
            "--headless=new".to_string(),
            // A fixed window size, so screenshots are comparable between runs
            // instead of depending on whatever size the default happened to be.
            "--window-size=1280,800".to_string(),
            // No first-run UI, no default-browser prompts: these block startup.
            "--no-first-run".to_string(),
            "--no-default-browser-check".to_string(),
        ];
        if !self.network {
            // Navigation checks cannot stop a script from changing the page.
            // Disabling JavaScript removes that path while data and about pages
            // remain readable.
            args.push("--disable-javascript".to_string());
            args.push("--disable-background-networking".to_string());
        }
        args.extend(self.extra_args.iter().cloned());
        // Chromium lets a later switch override an earlier one. The profile and
        // debugger endpoint therefore come last, after operator-supplied args.
        args.push(format!("--user-data-dir={}", self.profile_dir.display()));
        args.push("--remote-debugging-port=0".to_string());
        args.push("--remote-debugging-address=127.0.0.1".to_string());
        args
    }
}

/// Candidate browser locations, most preferred first.
///
/// Chrome before Edge on Windows because Chrome is the more predictable CDP
/// target; both speak the same protocol.
fn default_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    #[cfg(windows)]
    {
        for base in [
            std::env::var_os("PROGRAMFILES"),
            std::env::var_os("PROGRAMFILES(X86)"),
            std::env::var_os("LOCALAPPDATA"),
        ]
        .into_iter()
        .flatten()
        {
            let base = PathBuf::from(base);
            candidates.push(base.join("Google/Chrome/Application/chrome.exe"));
            candidates.push(base.join("Microsoft/Edge/Application/msedge.exe"));
        }
    }
    #[cfg(target_os = "linux")]
    {
        for path in [
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/snap/bin/chromium",
        ] {
            candidates.push(PathBuf::from(path));
        }
    }
    #[cfg(target_os = "macos")]
    {
        candidates.push(PathBuf::from(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ));
        candidates.push(PathBuf::from(
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ));
    }
    candidates
}

/// Why a browser action could not be performed.
///
/// Separate from a generic error because "no browser is installed" and "the page
/// timed out" call for different operator responses, and collapsing them into
/// one message loses that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserUnavailable {
    /// No executable was found at any known location.
    NotInstalled { looked_for: Vec<String> },
    /// The executable exists but could not be started.
    LaunchFailed { reason: String },
    /// The browser started but published no endpoint within the bound.
    DidNotPublishEndpoint { waited_secs: u64 },
}

impl BrowserUnavailable {
    /// A message that says what to do about it.
    ///
    /// Every refusal names a remedy: a failure an operator cannot act on is only
    /// marginally better than a silent one.
    pub fn refusal(&self) -> Error {
        let message = match self {
            Self::NotInstalled { looked_for } => format!(
                "browser tooling is not usable: no Chromium-based browser was found. \
                 Install Chrome or Edge, or set [browser] executable. Looked for: {}",
                looked_for.join(", ")
            ),
            Self::LaunchFailed { reason } => {
                format!("browser tooling is not usable: the browser failed to start: {reason}")
            }
            Self::DidNotPublishEndpoint { waited_secs } => format!(
                "browser tooling is not usable: the browser started but published no debug \
                 endpoint within {waited_secs}s. A locked profile directory or a missing \
                 shared library is the usual cause"
            ),
        };
        Error::Config(message)
    }
}

/// A private, session-scoped profile directory under the given root.
///
/// Placed under the run's own storage so the browser's cookies, cache and
/// storage are cleaned up with the run rather than left in the operator's home
/// directory.
pub fn profile_dir_under(root: &Path, session: &str) -> PathBuf {
    root.join("browser").join(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_browser_is_reported_with_what_was_looked_for() {
        let error = BrowserUnavailable::NotInstalled {
            looked_for: vec!["chrome".into(), "msedge".into()],
        }
        .refusal()
        .to_string();
        assert!(error.contains("no Chromium-based browser was found"));
        // The remedy must be actionable, not just a statement of failure.
        assert!(error.contains("Install Chrome or Edge"), "{error}");
        assert!(error.contains("chrome, msedge"), "{error}");
    }

    #[test]
    fn a_launch_failure_names_the_reason() {
        let error = BrowserUnavailable::LaunchFailed {
            reason: "ENOENT".into(),
        }
        .refusal()
        .to_string();
        assert!(error.contains("ENOENT"), "{error}");
    }

    #[test]
    fn a_timeout_names_the_bound_it_exceeded() {
        let error = BrowserUnavailable::DidNotPublishEndpoint { waited_secs: 30 }
            .refusal()
            .to_string();
        assert!(error.contains("within 30s"), "{error}");
        // And a likely cause, so the operator has somewhere to start.
        assert!(error.contains("locked profile directory"), "{error}");
    }

    #[test]
    fn the_profile_directory_is_private_to_the_session() {
        let root = Path::new("/run");
        assert_eq!(
            profile_dir_under(root, "abc"),
            PathBuf::from("/run/browser/abc")
        );
        // Two sessions must not share a profile: shared cookies would make one
        // run's state part of another's input.
        assert_ne!(
            profile_dir_under(root, "abc"),
            profile_dir_under(root, "def")
        );
        assert!(
            !profile_dir_under(Path::new("/tmp/pangu-browser"), "abc")
                .components()
                .any(|component| component.as_os_str() == ".pangu"),
            "browser state must stay outside the checkpoint-excluded tree"
        );
    }

    #[test]
    fn launch_arguments_are_headless_and_use_a_private_profile() {
        let config = BrowserConfig {
            executable: PathBuf::from("/x/chrome"),
            profile_dir: PathBuf::from("/tmp/p"),
            network: true,
            extra_args: Vec::new(),
        };
        let args = config.args();
        assert!(args.iter().any(|a| a == "--headless=new"));
        assert!(args.iter().any(|a| a == "--user-data-dir=/tmp/p"));
        assert!(args.iter().any(|a| a == "--remote-debugging-port=0"));
        assert!(args
            .iter()
            .any(|argument| argument == "--remote-debugging-address=127.0.0.1"));
    }

    #[test]
    fn a_fixed_window_size_keeps_screenshots_comparable() {
        let config = BrowserConfig {
            executable: PathBuf::from("/x/chrome"),
            profile_dir: PathBuf::from("/tmp/p"),
            network: true,
            extra_args: Vec::new(),
        };
        assert!(config.args().iter().any(|a| a == "--window-size=1280,800"));
    }

    #[test]
    fn extra_arguments_are_appended_verbatim() {
        let config = BrowserConfig {
            executable: PathBuf::from("/x/chrome"),
            profile_dir: PathBuf::from("/tmp/p"),
            network: true,
            extra_args: vec!["--lang=en-US".into()],
        };
        let args = config.args();
        let extra = args.iter().position(|argument| argument == "--lang=en-US");
        let profile = args
            .iter()
            .position(|argument| argument.starts_with("--user-data-dir="));
        assert!(extra.is_some() && profile.is_some() && extra < profile);
    }

    #[test]
    fn the_executable_search_covers_more_than_one_browser() {
        // A machine with only Edge must still work, so the candidate list cannot
        // be a single path.
        let candidates = default_candidates();
        assert!(
            candidates.len() >= 2,
            "expected several candidates, got {}",
            candidates.len()
        );
        let all = candidates
            .iter()
            .map(|p| p.to_string_lossy().to_lowercase())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(all.contains("chrome"));
        assert!(all.contains("edge") || cfg!(not(windows)));
    }
}
