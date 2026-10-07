//! The shipped skill packages are real packages, not documentation.
//!
//! Every skill under `skills/` must install and load through the actual
//! registry: a manifest that does not parse, or a document that does not hash
//! into the lock, is a broken package regardless of how good its prose is. This
//! test is what stops the shipped skills from rotting as the format changes.

use std::path::{Path, PathBuf};

use pangu_core::skills::{compute_lock, SkillLimits, SkillManifest, SkillRegistry};

/// Read a skill's instruction document.
///
/// The registry's `read_doc` is the real path, but it needs a loaded registry;
/// for the on-disk checks here a bounded read is equivalent and keeps the test
/// independent of the loader it is separately exercising.
fn doc_of(package: &Path) -> String {
    let path = package.join("SKILL.md");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn manifest_of(package: &Path) -> SkillManifest {
    let path = package.join("SKILL.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    toml::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

/// The repository root, derived from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/pangu -> repository root")
        .to_path_buf()
}

fn skills_dir() -> PathBuf {
    repo_root().join("skills")
}

/// Each shipped skill directory, sorted for a stable report.
fn shipped() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(skills_dir())
        .expect("skills/ exists")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    out.sort();
    out
}

#[test]
fn the_shipped_skill_directory_is_not_empty() {
    // An empty or missing directory would make every other test in this file
    // vacuously pass, which is the failure mode this guards.
    let packages = shipped();
    assert!(
        packages.len() >= 5,
        "expected the shipped skills, found {}: {packages:?}",
        packages.len()
    );
}

#[test]
fn every_shipped_skill_computes_a_lock() {
    for package in shipped() {
        let name = package.file_name().unwrap().to_string_lossy().to_string();
        // A malformed manifest or a missing SKILL.md fails here rather than in
        // an operator's terminal.
        let lock = compute_lock(&package, &SkillLimits::default())
            .unwrap_or_else(|error| panic!("skill `{name}` does not compute a lock: {error}"));
        assert_eq!(
            lock.name, name,
            "the manifest name must match its directory"
        );
        assert!(
            lock.files.iter().any(|file| file.path == "SKILL.md"),
            "skill `{name}` must lock its SKILL.md"
        );
        assert!(
            !lock.files.iter().any(|file| file.path.is_empty()),
            "skill `{name}` has an empty file path in its lock"
        );
    }
}

#[test]
fn every_shipped_skill_loads_through_the_registry() {
    // Install into a scratch directory the way `pangu skills install` does, then
    // load it through the real registry so the load path is exercised too.
    let sandbox = std::env::temp_dir().join(format!(
        "pangu-shipped-skills-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let registry_dir = sandbox.join("skills");
    std::fs::create_dir_all(&registry_dir).expect("create the scratch registry");

    let limits = SkillLimits::default();
    let mut expected: Vec<String> = Vec::new();
    for package in shipped() {
        let name = package.file_name().unwrap().to_string_lossy().to_string();
        expected.push(name.clone());

        let lock = compute_lock(&package, &limits).expect("lock");
        let target = registry_dir.join(&lock.name);
        std::fs::create_dir_all(&target).expect("create the installed directory");
        for file in &lock.files {
            let from = package.join(file.path.replace('/', std::path::MAIN_SEPARATOR_STR));
            let to = target.join(file.path.replace('/', std::path::MAIN_SEPARATOR_STR));
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent).expect("create parent");
            }
            std::fs::copy(&from, &to)
                .unwrap_or_else(|error| panic!("copy {}: {error}", from.display()));
        }
        // The lock is written last, as the installer does: a crash mid-copy
        // leaves an unloadable directory rather than a verified one with files
        // missing.
        std::fs::write(
            target.join("skill.lock"),
            serde_json::to_string_pretty(&lock).expect("serialise lock"),
        )
        .expect("write the lock");
    }

    let registry = SkillRegistry::load(&registry_dir, &limits, None).expect("load the registry");

    // A rejected skill means the package is broken; report which and why rather
    // than just counting.
    let rejected: Vec<String> = registry
        .rejected()
        .iter()
        .map(|entry| format!("{}: {}", entry.dir_name, entry.reason))
        .collect();
    assert!(
        rejected.is_empty(),
        "shipped skills were rejected: {rejected:?}"
    );

    for name in &expected {
        assert!(
            registry.find(name).is_some(),
            "shipped skill `{name}` did not load"
        );
    }
    assert_eq!(registry.skills().len(), expected.len());

    std::fs::remove_dir_all(&sandbox).ok();
}

#[test]
fn every_shipped_skill_has_a_non_trivial_description() {
    // The index the run injects carries the description. A description that
    // says nothing would leave the model unable to decide whether to read the
    // document, which defeats the index.
    let limits = SkillLimits::default();
    for package in shipped() {
        let lock = compute_lock(&package, &limits).expect("lock");
        let _ = lock;
        let manifest = manifest_of(&package);
        assert!(
            manifest.description.len() >= 60,
            "skill `{}` has a description too short to be useful: {:?}",
            manifest.name,
            manifest.description
        );
        // The description must not be a restatement of the name.
        assert!(
            !manifest
                .description
                .to_lowercase()
                .starts_with(&manifest.name.replace('-', " ")),
            "skill `{}` describes itself with its own name",
            manifest.name
        );
    }
}

#[test]
fn every_shipped_skill_document_is_substantial() {
    // A SKILL.md of a few lines is a placeholder; the run injects it as the
    // instruction document, so it has to actually instruct.
    let limits = SkillLimits::default();
    for package in shipped() {
        let lock = compute_lock(&package, &limits).expect("lock");
        let doc = doc_of(&package);
        assert!(
            doc.len() >= 1500,
            "skill `{}` has a {}-byte document; too thin to guide anything",
            lock.name,
            doc.len()
        );
        assert!(
            doc.starts_with('#'),
            "skill `{}` document must start with a heading",
            lock.name
        );
    }
}

#[test]
fn every_shipped_skill_declares_no_scripts() {
    // B2 provides no execution primitive for declared scripts, so declaring one
    // would advertise a capability that does not exist. If a shipped skill ever
    // needs a script, this test is where that decision gets recorded.
    for package in shipped() {
        let manifest = manifest_of(&package);
        assert!(
            manifest.scripts.is_empty(),
            "skill `{}` declares scripts; Pangu has no primitive to run them",
            manifest.name
        );
    }
}

#[test]
fn the_shipped_documents_carry_the_review_discipline() {
    // These documents are instructions the model reads. A document that tells
    // the model to report results it did not observe would be shipping a
    // harmful instruction, so check the ones that state the rule do so
    // explicitly.
    let root = skills_dir();
    let mut checked = 0;
    for entry in ["commit-craft", "incident-triage", "diff-review"] {
        let path = root.join(entry).join("SKILL.md");
        let doc = std::fs::read_to_string(&path).expect("read a shipped document");
        assert!(
            doc.contains("not run") || doc.contains("did not run"),
            "skill `{entry}` must state the rule about unobserved commands"
        );
        checked += 1;
    }
    assert_eq!(checked, 3);
}

#[test]
fn boundary_check_says_it_is_advisory() {
    // This is the one shipped skill that reasons about authorization, so its
    // document must be explicit that it grants none. If a future edit removed
    // that, the skill would read as a permission oracle.
    let doc = std::fs::read_to_string(skills_dir().join("boundary-check").join("SKILL.md"))
        .expect("read SKILL.md");
    assert!(
        doc.contains("advisory") && doc.contains("authorizes nothing"),
        "boundary-check must state that it authorizes nothing"
    );
    assert!(
        doc.contains("L4") || doc.contains("Approval"),
        "boundary-check must describe the approval layer"
    );
}
