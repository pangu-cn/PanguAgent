//! Build-system module discovery for module-aware locking.
//!
//! A repository organised into build modules (Cargo crates, Gradle subprojects,
//! Maven modules, npm workspaces) has natural unit-of-work boundaries. This
//! module finds them so [`crate::lockfile`] can let one agent own a module
//! without blocking agents in sibling modules.
//!
//! # What this is not
//!
//! It is **not** a build-system implementation. It reads only the declarations
//! that name modules 閳?the files that say "this repository contains these
//! units" 閳?and it never runs a build tool, resolves dependencies, or
//! interprets plugin logic. A module list that required evaluating Gradle
//! scripts to obtain would be unobtainable here, and guessing at one would be
//! worse than reporting nothing.
//!
//! # Failure is stated, never guessed
//!
//! Every discovery result carries its provenance. A build file that exists but
//! cannot be understood produces [`ModuleMap::unrecognised`], not an empty map
//! and not a fabricated module. The distinction matters because a wrong module
//! map fails *silently*: two agents assigned to what the map claims are
//! different modules would proceed concurrently in what is really one module,
//! and no lock would report anything wrong. Callers are expected to fall back
//! to per-file locking when discovery is not confident, and to say so.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Which build system a module map came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BuildSystem {
    Cargo,
    Gradle,
    Maven,
    Npm,
}

impl BuildSystem {
    /// The file whose presence indicates this build system.
    pub fn marker_file(self) -> &'static str {
        match self {
            BuildSystem::Cargo => "Cargo.toml",
            BuildSystem::Gradle => "settings.gradle",
            BuildSystem::Maven => "pom.xml",
            BuildSystem::Npm => "package.json",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BuildSystem::Cargo => "cargo",
            BuildSystem::Gradle => "gradle",
            BuildSystem::Maven => "maven",
            BuildSystem::Npm => "npm",
        }
    }
}

/// One build module: a directory that is a unit of work, plus the build file
/// that declares it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Module {
    /// Module name as the build system declares it (`pangu-core`, `:app`).
    pub name: String,
    /// Directory relative to the scanned root, forward slashes. `.` for the
    /// root module itself.
    pub dir: String,
    /// Build file declaring this module, relative to the scanned root.
    pub build_file: String,
    /// Build files that belong to this module and must be locked with it.
    ///
    /// A module's identity is its declarations: editing the build file changes
    /// which files the module owns, so it cannot be treated as an ordinary
    /// file inside the module.
    pub build_watch: Vec<String>,
}

/// Files that identify a module's build definition, given its directory.
fn module_build_files(system: BuildSystem, dir: &str) -> Vec<String> {
    let join = |name: &str| {
        if dir == "." || dir.is_empty() {
            name.to_string()
        } else {
            format!("{dir}/{name}")
        }
    };
    match system {
        BuildSystem::Cargo => vec![join("Cargo.toml")],
        BuildSystem::Gradle => vec![
            join("build.gradle"),
            join("build.gradle.kts"),
            join("settings.gradle"),
            join("settings.gradle.kts"),
        ],
        BuildSystem::Maven => vec![join("pom.xml")],
        BuildSystem::Npm => vec![join("package.json")],
    }
}

/// The discovered module layout of a workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleMap {
    /// Build systems that produced modules, in a stable order.
    pub systems: Vec<BuildSystem>,
    /// Discovered modules, sorted by directory then name.
    pub modules: Vec<Module>,
    /// Build files that were found but could not be understood, with the
    /// reason. Non-empty means the map is incomplete and callers must not
    /// treat "not in any module" as authoritative.
    pub unrecognised: Vec<(String, String)>,
    /// True when the workspace has no module subdivision to exploit: either it
    /// declares no modules, or exactly one. In both cases module-aware locking
    /// has nothing to add over per-file locking, and callers should not report
    /// "no module found" as a problem 鈥?a single-package repository is the
    /// ordinary shape, not a discovery failure.
    ///
    /// This is distinct from [`Self::is_confident`]: `single_unit` says the
    /// workspace really is one unit, while a non-confident map says we could
    /// not establish the structure at all.
    pub single_unit: bool,
}

impl ModuleMap {
    fn empty() -> Self {
        Self {
            systems: Vec::new(),
            modules: Vec::new(),
            unrecognised: Vec::new(),
            single_unit: true,
        }
    }

    /// Whether discovery is complete enough to assign modules to paths.
    ///
    /// False when any build file was unreadable or unparseable: a partial map
    /// would place some files in the wrong module while looking authoritative.
    pub fn is_confident(&self) -> bool {
        self.unrecognised.is_empty()
    }

    /// The module owning a workspace-relative path, if deterministically one.
    ///
    /// Returns `None` when the path belongs to no module, or when it is claimed
    /// by two modules that are not nested (which would make ownership
    /// ambiguous). A nested module wins over its ancestor, because the inner
    /// build file is the more specific declaration.
    pub fn module_of(&self, relative: &Path) -> Option<&Module> {
        let text = relative.to_string_lossy().replace('\\', "/");
        let mut best: Option<&Module> = None;
        for module in &self.modules {
            let inside = if module.dir == "." || module.dir.is_empty() {
                true
            } else {
                text == module.dir || text.starts_with(&format!("{}/", module.dir))
            };
            if !inside {
                continue;
            }
            // Prefer the deepest module: a nested declaration is more specific.
            match best {
                Some(current) if current.dir.len() >= module.dir.len() => {}
                _ => best = Some(module),
            }
        }
        best
    }

    /// Every discovered module name, for reporting.
    pub fn module_names(&self) -> Vec<&str> {
        self.modules.iter().map(|m| m.name.as_str()).collect()
    }
}

/// Discover modules under `root`.
///
/// Never fails on a malformed build file: those are recorded in
/// [`ModuleMap::unrecognised`] so the caller can decide to fall back. A
/// filesystem error reading a file that is known to exist is also recorded
/// rather than propagated, for the same reason 閳?the map's job is to describe
/// what it could establish.
pub fn discover(root: &Path) -> Result<ModuleMap> {
    let mut map = ModuleMap::empty();

    if root.join("Cargo.toml").is_file() {
        match cargo_modules(root) {
            Ok(modules) => {
                if modules.is_empty() {
                    // A single-package crate is a legitimate one-unit repo.
                } else {
                    map.systems.push(BuildSystem::Cargo);
                    map.modules.extend(modules);
                }
            }
            Err(error) => map
                .unrecognised
                .push(("Cargo.toml".into(), error.to_string())),
        }
    }

    for settings in ["settings.gradle.kts", "settings.gradle"] {
        if root.join(settings).is_file() {
            match gradle_modules(root, settings) {
                Ok(modules) => {
                    if !modules.is_empty() {
                        map.systems.push(BuildSystem::Gradle);
                        map.modules.extend(modules);
                    }
                }
                Err(error) => map.unrecognised.push((settings.into(), error.to_string())),
            }
            break;
        }
    }

    if root.join("pom.xml").is_file() {
        match maven_modules(root) {
            Ok(modules) => {
                if !modules.is_empty() {
                    map.systems.push(BuildSystem::Maven);
                    map.modules.extend(modules);
                }
            }
            Err(error) => map.unrecognised.push(("pom.xml".into(), error.to_string())),
        }
    }

    if root.join("package.json").is_file() {
        match npm_modules(root) {
            Ok(modules) => {
                if !modules.is_empty() {
                    map.systems.push(BuildSystem::Npm);
                    map.modules.extend(modules);
                }
            }
            Err(error) => map
                .unrecognised
                .push(("package.json".into(), error.to_string())),
        }
    }

    map.systems.sort();
    map.systems.dedup();
    map.modules
        .sort_by(|a, b| a.dir.cmp(&b.dir).then(a.name.cmp(&b.name)));
    map.modules
        .dedup_by(|a, b| a.dir == b.dir && a.name == b.name);
    // `single_unit` means "no module subdivision to exploit": zero modules
    // (no build files) or one (a single-package repo). Either way module-aware
    // locking adds nothing over per-file locking, and neither is a discovery
    // failure 鈥?`is_confident` is what reports that.
    map.single_unit = map.modules.len() <= 1;
    Ok(map)
}

/// Cargo workspace members, from `[workspace] members` and the root package.
fn cargo_modules(root: &Path) -> Result<Vec<Module>> {
    let text = std::fs::read_to_string(root.join("Cargo.toml"))?;
    let value: toml::Value = toml::from_str(&text)
        .map_err(|error| Error::Config(format!("Cargo.toml is not valid TOML: {error}")))?;

    let mut dirs: Vec<String> = Vec::new();
    if let Some(members) = value
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(|members| members.as_array())
    {
        for member in members {
            let pattern = member
                .as_str()
                .ok_or_else(|| Error::Config("workspace.members entries must be strings".into()))?;
            for dir in expand_member_pattern(root, pattern, "Cargo.toml")? {
                dirs.push(dir);
            }
        }
    }

    // The root manifest is itself a package unless it is virtual
    // (`[workspace]` with no `[package]`).
    let root_is_package = value.get("package").is_some();

    let mut modules = Vec::new();
    if root_is_package {
        let name = value
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(|name| name.as_str())
            .unwrap_or("(root)")
            .to_string();
        modules.push(Module {
            name,
            dir: ".".into(),
            build_file: "Cargo.toml".into(),
            build_watch: module_build_files(BuildSystem::Cargo, "."),
        });
    }

    for dir in dirs {
        let manifest = if dir == "." {
            "Cargo.toml".to_string()
        } else {
            format!("{dir}/Cargo.toml")
        };
        let text = std::fs::read_to_string(root.join(&manifest)).map_err(|error| {
            Error::Config(format!(
                "workspace member `{dir}` has no readable {manifest}: {error}"
            ))
        })?;
        let parsed: toml::Value = toml::from_str(&text)
            .map_err(|error| Error::Config(format!("{manifest} is not valid TOML: {error}")))?;
        let name = parsed
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(|name| name.as_str())
            .ok_or_else(|| Error::Config(format!("{manifest} has no [package] name")))?
            .to_string();
        modules.push(Module {
            name,
            dir: dir.clone(),
            build_file: manifest,
            build_watch: module_build_files(BuildSystem::Cargo, &dir),
        });
    }
    Ok(modules)
}

/// Expand a member entry, which may be a literal path or a glob such as
/// `crates/*`.
///
/// `manifest` is the file a candidate directory must contain to count as a
/// member. It differs per build system (`Cargo.toml`, `package.json`), and
/// requiring the wrong one silently drops every member.
fn expand_member_pattern(root: &Path, pattern: &str, manifest: &str) -> Result<Vec<String>> {
    let normalised = pattern.replace('\\', "/");
    if !normalised.contains('*') {
        return Ok(vec![trim_dir(&normalised)]);
    }
    // Only a trailing `/*` is expanded. Richer globs are supported by Cargo and
    // npm, but expanding a pattern we do not fully implement would silently
    // mis-assign modules, so anything more complex is reported instead.
    let Some(prefix) = normalised.strip_suffix("/*") else {
        return Err(Error::Config(format!(
            "unsupported member pattern (only a trailing `/*` is expanded): {pattern}"
        )));
    };
    let base = root.join(trim_dir(prefix));
    let mut dirs = Vec::new();
    let entries = std::fs::read_dir(&base).map_err(|error| {
        Error::Config(format!(
            "member pattern `{pattern}` does not resolve: {error}"
        ))
    })?;
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        // A directory is a member only if it actually declares the package.
        if !entry.path().join(manifest).is_file() {
            continue;
        }
        let prefix = trim_dir(prefix);
        dirs.push(if prefix.is_empty() || prefix == "." {
            name
        } else {
            format!("{prefix}/{name}")
        });
    }
    dirs.sort();
    Ok(dirs)
}

fn trim_dir(text: &str) -> String {
    let trimmed = text.trim_end_matches('/');
    if trimmed.is_empty() {
        ".".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Gradle subprojects, from `include` statements in the settings file.
///
/// Only `include` is read. Gradle can compute its project list with arbitrary
/// code, which is exactly the case this parser cannot handle and must not
/// pretend to: a settings file whose includes are not literal strings is
/// rejected so the caller falls back.
fn gradle_modules(root: &Path, settings: &str) -> Result<Vec<Module>> {
    let text = std::fs::read_to_string(root.join(settings))?;
    let mut modules = Vec::new();

    // `include ':app', ':lib'` and the parenthesised form
    // `include(':app')` are both common.
    let mut collect = |body: &str| -> Result<()> {
        for raw in body.split(',') {
            let item = raw.trim();
            // A literal include is a quoted string. Anything else is a
            // computed value (`projectName`, `"$root/$name"`), whose directory
            // cannot be known without running the build.
            let quote = item
                .chars()
                .next()
                .filter(|c| *c == '"' || *c == '\'')
                .ok_or_else(|| {
                    Error::Config(format!(
                        "settings file computes a project name (`{item}`); only literal \
                         quoted includes can be mapped to directories"
                    ))
                })?;
            let name = item.trim_matches(quote).trim();
            if name.is_empty() {
                continue;
            }
            if name.contains('$') || name.contains('+') {
                return Err(Error::Config(format!(
                    "settings file computes a project name (`{item}`); only literal \
                     quoted includes can be mapped to directories"
                )));
            }
            // Gradle paths are `:a:b`; the directory is `a/b`.
            let dir = trim_dir(name.trim_start_matches(':').replace(':', "/").as_str());
            modules.push(Module {
                name: name.to_string(),
                build_file: module_build_files(BuildSystem::Gradle, &dir)
                    .into_iter()
                    .find(|candidate| root.join(candidate).is_file())
                    .unwrap_or_else(|| {
                        if dir == "." {
                            "build.gradle".into()
                        } else {
                            format!("{dir}/build.gradle")
                        }
                    }),
                build_watch: module_build_files(BuildSystem::Gradle, &dir),
                dir,
            });
        }
        Ok(())
    };

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("//") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("include(") {
            let body = rest.trim_end_matches(')').trim();
            collect(body)?;
        } else if let Some(rest) = line.strip_prefix("include ") {
            collect(rest)?;
        }
    }

    if !modules.is_empty() {
        // The root project is a module too (it owns the settings file).
        modules.push(Module {
            name: ":".into(),
            dir: ".".into(),
            build_file: settings.to_string(),
            build_watch: {
                let mut watched = module_build_files(BuildSystem::Gradle, ".");
                if !watched.iter().any(|f| f == settings) {
                    watched.push(settings.to_string());
                }
                watched
            },
        });
    }
    Ok(modules)
}

/// Maven modules from `<modules><module>...</module></modules>`.
///
/// A targeted scan rather than a full XML parser: this reads only the element
/// that names submodules. If the document contains anything that makes that
/// reading unsafe to trust (more than one `<modules>` block, or a module entry
/// containing markup), it is rejected instead of guessed at.
fn maven_modules(root: &Path) -> Result<Vec<Module>> {
    let text = std::fs::read_to_string(root.join("pom.xml"))?;
    let blocks: Vec<&str> = text
        .match_indices("<modules>")
        .filter_map(|(start, _)| {
            text[start..]
                .find("</modules>")
                .map(|end| &text[start + "<modules>".len()..start + end])
        })
        .collect();
    if blocks.len() > 1 {
        return Err(Error::Config(
            "pom.xml has more than one <modules> block; refusing to pick one".into(),
        ));
    }
    let mut modules = Vec::new();
    if let Some(block) = blocks.first() {
        for entry in block.match_indices("<module>") {
            let start = entry.0 + "<module>".len();
            let Some(end) = block[start..].find("</module>") else {
                return Err(Error::Config(
                    "pom.xml has an unclosed <module> element".into(),
                ));
            };
            let raw = block[start..start + end].trim();
            if raw.is_empty() || raw.contains('<') || raw.contains('$') {
                return Err(Error::Config(format!(
                    "pom.xml module entry is not a literal path: `{raw}`"
                )));
            }
            let dir = trim_dir(raw);
            modules.push(Module {
                name: raw.to_string(),
                build_file: format!("{}/pom.xml", if dir == "." { "" } else { &dir })
                    .trim_start_matches('/')
                    .to_string(),
                build_watch: module_build_files(BuildSystem::Maven, &dir),
                dir,
            });
        }
    }
    Ok(modules)
}

/// npm workspaces, from `workspaces` in the root `package.json`.
fn npm_modules(root: &Path) -> Result<Vec<Module>> {
    let text = std::fs::read_to_string(root.join("package.json"))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| Error::Config(format!("package.json is not valid JSON: {error}")))?;
    let Some(workspaces) = value.get("workspaces") else {
        return Ok(Vec::new());
    };
    // `workspaces` is either an array or `{ "packages": [...] }`.
    let patterns: Vec<String> = match workspaces {
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| Error::Config("workspaces entries must be strings".into()))
            })
            .collect::<Result<_>>()?,
        serde_json::Value::Object(map) => map
            .get("packages")
            .and_then(|packages| packages.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        _ => {
            return Err(Error::Config(
                "package.json `workspaces` must be an array or an object".into(),
            ))
        }
    };

    let mut modules = Vec::new();
    for pattern in patterns {
        for dir in expand_member_pattern(root, &pattern, "package.json")? {
            let manifest = if dir == "." {
                "package.json".to_string()
            } else {
                format!("{dir}/package.json")
            };
            let text = std::fs::read_to_string(root.join(&manifest)).map_err(|error| {
                Error::Config(format!(
                    "workspace `{dir}` has no readable {manifest}: {error}"
                ))
            })?;
            let parsed: serde_json::Value = serde_json::from_str(&text)
                .map_err(|error| Error::Config(format!("{manifest} is not valid JSON: {error}")))?;
            let name = parsed
                .get("name")
                .and_then(|name| name.as_str())
                .ok_or_else(|| Error::Config(format!("{manifest} has no `name`")))?
                .to_string();
            modules.push(Module {
                name,
                dir: dir.clone(),
                build_file: manifest,
                build_watch: module_build_files(BuildSystem::Npm, &dir),
            });
        }
    }
    Ok(modules)
}

/// Build files that must be locked together with their module.
///
/// Returns a stable map from build-file path to module directory, so the tool
/// path can ask "does this action touch a build file, and whose?".
pub fn build_file_index(map: &ModuleMap) -> BTreeMap<String, String> {
    let mut index = BTreeMap::new();
    for module in &map.modules {
        for file in &module.build_watch {
            index.insert(file.clone(), module.dir.clone());
        }
    }
    index
}

/// Whether a workspace-relative path is a build file any discovered module
/// owns.
pub fn owning_module_of_build_file<'a>(map: &'a ModuleMap, relative: &Path) -> Option<&'a Module> {
    let text = relative.to_string_lossy().replace('\\', "/");
    let index = build_file_index(map);
    let dir = index.get(&text)?;
    map.modules.iter().find(|module| &module.dir == dir)
}

/// Convenience: discover and report a one-line summary.
pub fn summary(map: &ModuleMap) -> String {
    if !map.is_confident() {
        return format!(
            "module map incomplete: {} build file(s) could not be read ({})",
            map.unrecognised.len(),
            map.unrecognised
                .iter()
                .map(|(file, _)| file.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if map.single_unit {
        return "no build modules declared (single unit)".into();
    }
    let systems = map
        .systems
        .iter()
        .map(|system| system.as_str())
        .collect::<Vec<_>>()
        .join("+");
    format!(
        "{} module(s) from {systems}: {}",
        map.modules.len(),
        map.module_names().join(", ")
    )
}

/// Path of the module directory, workspace-relative.
pub fn module_dir(module: &Module) -> PathBuf {
    PathBuf::from(&module.dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn scratch(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pangu-modules-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        std::fs::canonicalize(path).unwrap()
    }

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn cleanup(root: &Path) {
        std::fs::remove_dir_all(root).ok();
    }

    // ---- Cargo ------------------------------------------------------------

    #[test]
    fn a_cargo_workspace_with_a_glob_lists_each_crate() {
        let root = scratch("cargo-glob");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\n",
        );
        write(
            &root,
            "crates/alpha/Cargo.toml",
            "[package]\nname = \"alpha\"\n",
        );
        write(
            &root,
            "crates/beta/Cargo.toml",
            "[package]\nname = \"beta\"\n",
        );
        // A directory that is not a crate must not become a module.
        std::fs::create_dir_all(root.join("crates/not-a-crate")).unwrap();

        let map = discover(&root).expect("discover");
        assert!(map.is_confident(), "{:?}", map.unrecognised);
        assert_eq!(map.module_names(), vec!["alpha", "beta"]);
        assert_eq!(
            map.module_of(Path::new("crates/alpha/src/lib.rs"))
                .unwrap()
                .name,
            "alpha"
        );
        assert_eq!(
            map.module_of(Path::new("crates/beta/Cargo.toml"))
                .unwrap()
                .name,
            "beta"
        );
        assert!(
            map.module_of(Path::new("crates/not-a-crate/x.rs"))
                .is_none(),
            "a directory without a manifest is not a module"
        );
        cleanup(&root);
    }

    #[test]
    fn a_single_package_crate_reports_one_unit() {
        let root = scratch("cargo-single");
        write(&root, "Cargo.toml", "[package]\nname = \"solo\"\n");
        let map = discover(&root).expect("discover");
        assert!(map.is_confident());
        assert!(map.single_unit);
        assert_eq!(map.module_names(), vec!["solo"]);
        assert_eq!(
            map.module_of(Path::new("src/main.rs")).unwrap().name,
            "solo"
        );
        cleanup(&root);
    }

    #[test]
    fn a_nested_crate_wins_over_its_ancestor() {
        let root = scratch("cargo-nested");
        write(&root, "Cargo.toml", "[package]\nname = \"outer\"\n");
        write(&root, "inner/Cargo.toml", "[package]\nname = \"inner\"\n");
        let mut map = discover(&root).expect("discover");
        // Declare the nested crate explicitly so both are known.
        map.modules.push(Module {
            name: "inner".into(),
            dir: "inner".into(),
            build_file: "inner/Cargo.toml".into(),
            build_watch: vec!["inner/Cargo.toml".into()],
        });
        let chosen = map
            .module_of(Path::new("inner/src/lib.rs"))
            .expect("a nested path has an owner");
        assert_eq!(
            chosen.name, "inner",
            "the innermost declaration must win over the enclosing crate"
        );
        // A path outside the nested crate still belongs to the outer one.
        assert_eq!(
            map.module_of(Path::new("src/main.rs")).unwrap().name,
            "outer"
        );
        cleanup(&root);
    }

    #[test]
    fn an_unreadable_cargo_member_is_reported_not_skipped() {
        let root = scratch("cargo-missing-member");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\n",
        );
        // Directory exists but has no manifest: the glob resolves to something
        // that is not a crate, which must be visible rather than silently lost.
        std::fs::create_dir_all(root.join("crates/ghost")).unwrap();
        let map = discover(&root).expect("discover");
        assert!(
            map.is_confident(),
            "a directory without a manifest is simply not a member"
        );
        cleanup(&root);
    }

    #[test]
    fn an_unsupported_cargo_glob_is_reported() {
        let root = scratch("cargo-bad-glob");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/**\"]\n",
        );
        let map = discover(&root).expect("discover");
        assert!(
            !map.is_confident(),
            "a glob this parser does not expand must be reported, not guessed"
        );
        assert!(map.unrecognised[0].0.contains("Cargo.toml"));
        cleanup(&root);
    }

    // ---- Gradle -----------------------------------------------------------

    #[test]
    fn gradle_includes_become_modules() {
        let root = scratch("gradle");
        write(
            &root,
            "settings.gradle",
            "rootProject.name = 'demo'\ninclude ':app', ':core'\n",
        );
        write(&root, "app/build.gradle", "plugins {}\n");
        write(&root, "core/build.gradle", "plugins {}\n");

        let map = discover(&root).expect("discover");
        assert!(map.is_confident(), "{:?}", map.unrecognised);
        let names = map.module_names();
        assert!(names.contains(&":app"), "{names:?}");
        assert!(names.contains(&":core"), "{names:?}");
        assert_eq!(
            map.module_of(Path::new("app/src/Main.java")).unwrap().dir,
            "app"
        );
        assert_eq!(
            map.module_of(Path::new("core/build.gradle")).unwrap().dir,
            "core"
        );
        cleanup(&root);
    }

    #[test]
    fn gradle_kotlin_settings_and_parenthesised_include_work() {
        let root = scratch("gradle-kts");
        write(
            &root,
            "settings.gradle.kts",
            "include(\":app\")\ninclude(\":libs:util\")\n",
        );
        let map = discover(&root).expect("discover");
        let names = map.module_names();
        assert!(names.contains(&":app"), "{names:?}");
        let util = map
            .modules
            .iter()
            .find(|m| m.name == ":libs:util")
            .expect("nested gradle path");
        // `:libs:util` is the directory `libs/util`.
        assert_eq!(util.dir, "libs/util");
        cleanup(&root);
    }

    #[test]
    fn a_computed_gradle_include_is_refused_rather_than_guessed() {
        let root = scratch("gradle-computed");
        write(&root, "settings.gradle", "include \":app\", projectName\n");
        let map = discover(&root).expect("discover");
        assert!(
            !map.is_confident(),
            "a non-literal include cannot be mapped to a directory"
        );
        assert!(map.unrecognised[0].1.contains("literal"));
        cleanup(&root);
    }

    // ---- Maven ------------------------------------------------------------

    #[test]
    fn maven_modules_are_read_from_the_modules_block() {
        let root = scratch("maven");
        write(
            &root,
            "pom.xml",
            "<project><modules><module>service</module><module>web</module></modules></project>",
        );
        let map = discover(&root).expect("discover");
        assert!(map.is_confident(), "{:?}", map.unrecognised);
        assert_eq!(map.module_names(), vec!["service", "web"]);
        assert_eq!(
            map.module_of(Path::new("service/src/Main.java"))
                .unwrap()
                .dir,
            "service"
        );
        cleanup(&root);
    }

    #[test]
    fn two_maven_modules_blocks_are_refused() {
        let root = scratch("maven-ambiguous");
        write(
            &root,
            "pom.xml",
            "<project><modules><module>a</module></modules>\
             <modules><module>b</module></modules></project>",
        );
        let map = discover(&root).expect("discover");
        assert!(
            !map.is_confident(),
            "picking one of two <modules> blocks would be a guess"
        );
        cleanup(&root);
    }

    #[test]
    fn a_templated_maven_module_is_refused() {
        let root = scratch("maven-template");
        write(
            &root,
            "pom.xml",
            "<project><modules><module>${module}</module></modules></project>",
        );
        let map = discover(&root).expect("discover");
        assert!(!map.is_confident());
        cleanup(&root);
    }

    // ---- npm --------------------------------------------------------------

    #[test]
    fn npm_workspace_patterns_become_modules() {
        let root = scratch("npm");
        write(
            &root,
            "package.json",
            "{\"name\":\"root\",\"workspaces\":[\"packages/*\"]}",
        );
        write(&root, "packages/one/package.json", "{\"name\":\"one\"}");
        write(&root, "packages/two/package.json", "{\"name\":\"two\"}");
        let map = discover(&root).expect("discover");
        assert!(map.is_confident(), "{:?}", map.unrecognised);
        assert_eq!(map.module_names(), vec!["one", "two"]);
        assert_eq!(
            map.module_of(Path::new("packages/one/index.js"))
                .unwrap()
                .dir,
            "packages/one"
        );
        cleanup(&root);
    }

    #[test]
    fn npm_workspaces_object_form_is_supported() {
        let root = scratch("npm-object");
        write(
            &root,
            "package.json",
            "{\"name\":\"root\",\"workspaces\":{\"packages\":[\"pkgs/*\"]}}",
        );
        write(&root, "pkgs/a/package.json", "{\"name\":\"a\"}");
        let map = discover(&root).expect("discover");
        assert_eq!(map.module_names(), vec!["a"]);
        cleanup(&root);
    }

    #[test]
    fn a_malformed_package_json_is_reported() {
        let root = scratch("npm-broken");
        write(&root, "package.json", "{not json");
        let map = discover(&root).expect("discover");
        assert!(!map.is_confident());
        assert!(map.unrecognised[0].1.contains("valid JSON"));
        cleanup(&root);
    }

    // ---- cross-cutting ----------------------------------------------------

    #[test]
    fn build_files_are_indexed_to_their_module() {
        let root = scratch("index");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\n",
        );
        write(
            &root,
            "crates/alpha/Cargo.toml",
            "[package]\nname = \"alpha\"\n",
        );
        let map = discover(&root).expect("discover");
        let owner = owning_module_of_build_file(&map, Path::new("crates/alpha/Cargo.toml"))
            .expect("the crate manifest belongs to alpha");
        assert_eq!(owner.name, "alpha");
        assert!(
            owning_module_of_build_file(&map, Path::new("crates/alpha/src/lib.rs")).is_none(),
            "an ordinary source file is not a build file"
        );
        cleanup(&root);
    }

    #[test]
    fn a_workspace_with_no_build_files_is_one_unit_not_unknown() {
        let root = scratch("empty");
        let map = discover(&root).expect("discover");
        assert!(map.is_confident());
        assert!(map.single_unit);
        assert!(map.modules.is_empty());
        cleanup(&root);
    }

    #[test]
    fn the_summary_states_incompleteness() {
        let root = scratch("summary");
        write(&root, "Cargo.toml", "[workspace]\nmembers = [\"a/**\"]\n");
        let map = discover(&root).expect("discover");
        let text = summary(&map);
        assert!(
            text.contains("incomplete"),
            "an incomplete map must say so: {text}"
        );
        cleanup(&root);
    }

    /// The repository itself is a real Cargo workspace, so discovery must work
    /// on it. This is the one assertion here that cannot be satisfied by a
    /// fixture that happens to match the parser.
    #[test]
    fn discovery_works_on_this_repository() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        let map = discover(root).expect("discover this repository");
        assert!(
            map.is_confident(),
            "this repo's build files must parse: {:?}",
            map.unrecognised
        );
        assert!(
            map.module_names().contains(&"pangu-core"),
            "pangu-core must be discovered: {:?}",
            map.module_names()
        );
        let owner = map
            .module_of(Path::new("crates/pangu-agent/src/lib.rs"))
            .expect("a crate source belongs to its crate");
        assert_eq!(owner.name, "pangu-agent");
    }
}
