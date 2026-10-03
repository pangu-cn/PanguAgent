//! B2: the skill registry and signed skill packages.
//!
//! A skill is an operator-installed directory: a `SKILL.toml` manifest, a
//! `SKILL.md` instruction document, and optional support files plus declared
//! (but never executed) scripts. Installation computes a per-file SHA-256
//! lock file (`pangu-skill-lock/1`, an SBOM-lite manifest) and can sign it
//! with an ed25519 key.
//!
//! Threat model (W-03/W-22): skills are code-plus-instructions and therefore
//! a supply-chain surface. The guardrails, in order:
//! - **default-off**: with `[skills] enabled = false` nothing loads, nothing
//!   is advertised, nothing is injected, digests are unchanged;
//! - **only instructions load**: the run injects a bounded index (name,
//!   version, description, signing status) and the model can read the
//!   `SKILL.md` body via the `read_skill` tool — nothing else;
//! - **scripts are never executed by B2**: declared scripts are registered
//!   and hashed, but Pangu provides no execution primitive for them. The
//!   model's only way to run anything is `run_command` (NeedsHuman +
//!   argv allow-list), and skill paths live under the `.pangu` forbidden
//!   glob, so generic tool I/O cannot reach them either;
//! - **integrity is checked on every load**: hashes are recomputed against
//!   the lock; a mismatched skill is rejected with an audible `Note`, never
//!   silently skipped;
//! - **signatures are verified when configured**: the operator pins an
//!   ed25519 public key in `[skills] verify_key`; unsigned packages load
//!   with an honest `unsigned` marker instead of a fake trust claim.
//!
//! Skills are installed by the operator only; the model has no install or
//! modify path (the registry lives under `.pangu`, like the memory queue).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::util::{hex_sha256, now_rfc3339};

/// Schema tag of `SKILL.toml`.
pub const SKILL_MANIFEST_SCHEMA: &str = "pangu-skill-manifest/1";
/// Schema tag of the generated `skill.lock` integrity file.
pub const SKILL_LOCK_SCHEMA: &str = "pangu-skill-lock/1";
pub const SKILL_MANIFEST_FILE: &str = "SKILL.toml";
pub const SKILL_DOC_FILE: &str = "SKILL.md";
pub const SKILL_LOCK_FILE: &str = "skill.lock";

/// Bounded registry behavior, mirroring the memory limits discipline: the
/// bounds must themselves be bounded (G4), both at install time and load time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SkillLimits {
    pub max_skills: usize,
    pub max_files: usize,
    pub max_file_bytes: usize,
    pub max_doc_bytes: usize,
    pub max_index_skills: usize,
    pub max_index_bytes: usize,
}

impl Default for SkillLimits {
    fn default() -> Self {
        Self {
            max_skills: 64,
            max_files: 64,
            max_file_bytes: 262_144,
            max_doc_bytes: 65_536,
            max_index_skills: 48,
            max_index_bytes: 8_192,
        }
    }
}

/// `SKILL.toml`: the operator-authored manifest of one skill package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SkillManifest {
    pub schema: String,
    pub name: String,
    pub version: String,
    pub description: String,
    /// Content files (relative, `/`-separated) covered by the lock. Must
    /// include `SKILL.md`; the manifest itself is always covered.
    #[serde(default)]
    pub files: Vec<String>,
    /// Declared scripts. Registration and hashing only — B2 provides no
    /// execution primitive for them (see module docs).
    #[serde(default)]
    pub scripts: Vec<String>,
}

/// One hashed file entry inside `skill.lock`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SkillFileEntry {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// `skill.lock`: the integrity record of one installed skill. The `signature`
/// field covers the canonical JSON of the lock without the signature itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SkillLock {
    pub schema: String,
    pub name: String,
    pub version: String,
    /// SHA-256 over the canonical JSON of the file entries — the package
    /// digest shown in `pangu skills list` and frozen into the contract.
    pub package_digest: String,
    pub files: Vec<SkillFileEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scripts: Vec<String>,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// The four honest trust states of a loaded skill. "Invalid" is only
/// claimed when a key was actually pinned and verification failed - a
/// signature nobody checked is "unverified", never "invalid".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillSignatureState {
    /// Signature present and verifies against the pinned key.
    Verified,
    /// Signature present, key pinned, verification failed.
    Invalid,
    /// Signature present, no key pinned - unchecked, reported as such.
    Unverified,
    /// No signature at all.
    Unsigned,
}

impl SkillSignatureState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "signed+verified",
            Self::Invalid => "signature-invalid",
            Self::Unverified => "signed-unverified",
            Self::Unsigned => "unsigned",
        }
    }
}

/// One successfully loaded skill.
#[derive(Debug, Clone)]
pub struct LoadedSkill {
    pub name: String,
    pub version: String,
    pub description: String,
    pub dir: PathBuf,
    pub lock: SkillLock,
    pub signature_state: SkillSignatureState,
}

impl LoadedSkill {
    /// `true` only in the fully verified state. This is what the contract
    /// freezes as `signed`.
    pub fn signature_verified(&self) -> bool {
        self.signature_state == SkillSignatureState::Verified
    }
}

/// One skill rejected at load time. Rejection is audible (`Note` event at
/// run start, visible in `pangu skills list`), never silent.
#[derive(Debug, Clone, PartialEq)]
pub struct RejectedSkill {
    pub dir_name: String,
    pub reason: String,
}

/// The loaded registry: `dir` is `<workspace>/.pangu/skills`.
#[derive(Debug, Clone)]
pub struct SkillRegistry {
    dir: PathBuf,
    limits: SkillLimits,
    skills: Vec<LoadedSkill>,
    rejected: Vec<RejectedSkill>,
}

impl SkillRegistry {
    /// Load and verify every skill under `dir`. Load failures of the
    /// directory itself are hard errors; a corrupt individual skill is
    /// rejected (audible), not fatal — skills are an enhancement, not a
    /// boundary, and one bad package must not take the run down.
    pub fn load(dir: &Path, limits: &SkillLimits, verify_key: Option<&str>) -> Result<Self> {
        if !dir.exists() {
            return Ok(Self {
                dir: dir.to_path_buf(),
                limits: limits.clone(),
                skills: Vec::new(),
                rejected: Vec::new(),
            });
        }
        let mut skills = Vec::new();
        let mut rejected = Vec::new();
        let entries = std::fs::read_dir(dir)
            .map_err(|error| Error::Config(format!("cannot read skills dir: {error}")))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| Error::Config(format!("cannot read skills dir: {error}")))?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let dir_name = path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default();
            match load_skill(&path, &dir_name, limits, verify_key) {
                Ok(skill) => skills.push(skill),
                Err(reason) => rejected.push(RejectedSkill { dir_name, reason }),
            }
        }
        if skills.len() > limits.max_skills {
            return Err(Error::Config(format!(
                "skills registry holds {} skills, over the limit of {}",
                skills.len(),
                limits.max_skills
            )));
        }
        skills.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Self {
            dir: dir.to_path_buf(),
            limits: limits.clone(),
            skills,
            rejected,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn skills(&self) -> &[LoadedSkill] {
        &self.skills
    }

    pub fn rejected(&self) -> &[RejectedSkill] {
        &self.rejected
    }

    pub fn find(&self, name: &str) -> Option<&LoadedSkill> {
        self.skills.iter().find(|skill| skill.name == name)
    }

    /// The injected index: one bounded line per skill (name, version,
    /// signing status, description). Explicitly labeled operator-installed
    /// data. Truncation is honest.
    pub fn index_block(&self) -> Option<String> {
        if self.skills.is_empty() {
            return None;
        }
        let mut block =
            String::from("## Installed skills (operator-installed reference material)\n");
        block.push_str(
            "Read a skill's full instructions with the read_skill tool before relying \
             on it. Skills carry no permissions; everything you do still passes the \
             same boundary, policy, approval, and budget gates.\n",
        );
        for (index, skill) in self.skills.iter().enumerate() {
            if index >= self.limits.max_index_skills {
                block.push_str(&format!(
                    "- … {} more skills omitted (index limit reached)\n",
                    self.skills.len() - index
                ));
                break;
            }
            let line = format!(
                "- {} v{} [{}] {}\n",
                skill.name,
                skill.version,
                skill.signature_state.as_str(),
                skill.description
            );
            if block.len() + line.len() > self.limits.max_index_bytes {
                block.push_str(&format!(
                    "- … {} more skills omitted (index size limit reached)\n",
                    self.skills.len() - index
                ));
                break;
            }
            block.push_str(&line);
        }
        Some(block)
    }

    pub fn limits(&self) -> &SkillLimits {
        &self.limits
    }

    /// The `SKILL.md` body of one skill, bounded. This is the only skill
    /// content the model can reach.
    pub fn read_doc(&self, name: &str) -> Result<String> {
        let skill = self
            .find(name)
            .ok_or_else(|| Error::Other(format!("unknown skill `{name}`")))?;
        let doc_path = skill.dir.join(SKILL_DOC_FILE);
        let raw = std::fs::read_to_string(&doc_path).map_err(|error| {
            Error::Other(format!("cannot read {SKILL_DOC_FILE} of `{name}`: {error}"))
        })?;
        if raw.len() > self.limits.max_doc_bytes {
            return Err(Error::Other(format!(
                "skill doc of `{name}` exceeds the load limit"
            )));
        }
        Ok(raw)
    }
}

/// Load and verify one skill directory.
fn load_skill(
    dir: &Path,
    dir_name: &str,
    limits: &SkillLimits,
    verify_key: Option<&str>,
) -> std::result::Result<LoadedSkill, String> {
    let manifest_path = dir.join(SKILL_MANIFEST_FILE);
    let lock_path = dir.join(SKILL_LOCK_FILE);
    if !manifest_path.is_file() || !lock_path.is_file() {
        return Err(format!(
            "{dir_name}: missing {SKILL_MANIFEST_FILE} or {SKILL_LOCK_FILE}"
        ));
    }
    let manifest_raw = std::fs::read_to_string(&manifest_path)
        .map_err(|error| format!("{dir_name}: cannot read manifest: {error}"))?;
    let manifest: SkillManifest = toml::from_str(&manifest_raw)
        .map_err(|error| format!("{dir_name}: invalid manifest: {error}"))?;
    if manifest.schema != SKILL_MANIFEST_SCHEMA {
        return Err(format!(
            "{dir_name}: unknown manifest schema {} (expected {SKILL_MANIFEST_SCHEMA})",
            manifest.schema
        ));
    }
    let lock_raw = std::fs::read_to_string(&lock_path)
        .map_err(|error| format!("{dir_name}: cannot read lock: {error}"))?;
    let mut lock: SkillLock = serde_json::from_str(&lock_raw)
        .map_err(|error| format!("{dir_name}: invalid lock: {error}"))?;
    if lock.schema != SKILL_LOCK_SCHEMA {
        return Err(format!(
            "{dir_name}: unknown lock schema {} (expected {SKILL_LOCK_SCHEMA})",
            lock.schema
        ));
    }
    if lock.name != manifest.name || lock.version != manifest.version {
        return Err(format!(
            "{dir_name}: lock identity ({}, v{}) does not match manifest ({}, v{})",
            lock.name, lock.version, manifest.name, manifest.version
        ));
    }
    if manifest.name != dir_name {
        return Err(format!(
            "{dir_name}: manifest name `{}` does not match the directory name",
            manifest.name
        ));
    }
    // Recompute every hash. The lock says what was installed; the directory
    // must still match it, byte for byte.
    let mut entries = Vec::with_capacity(lock.files.len());
    let mut covered = std::collections::HashSet::new();
    for file in &lock.files {
        let path = dir.join(file.path.replace('/', std::path::MAIN_SEPARATOR_STR));
        let bytes = std::fs::read(&path)
            .map_err(|error| format!("{dir_name}: locked file `{}` missing: {error}", file.path))?;
        let digest = crate::util::hex_sha256_bytes(&bytes);
        if digest != file.sha256 || bytes.len() as u64 != file.bytes {
            return Err(format!(
                "{dir_name}: integrity check failed for `{}` (hash mismatch)",
                file.path
            ));
        }
        covered.insert(file.path.clone());
        entries.push(SkillFileEntry {
            path: file.path.clone(),
            sha256: digest,
            bytes: bytes.len() as u64,
        });
    }
    if entries.len() > limits.max_files {
        return Err(format!("{dir_name}: too many files"));
    }
    // Every declared content file must be covered by the lock, and every
    // declared script too (registered, hashed — never executed by B2).
    for declared in manifest.files.iter().chain(manifest.scripts.iter()) {
        if !covered.contains(declared) {
            return Err(format!(
                "{dir_name}: declared file `{declared}` is not covered by the lock"
            ));
        }
    }
    let signature = lock.signature.take();
    let signature_state = match (&signature, verify_key) {
        (Some(sig), Some(key)) => {
            if verify_lock_signature(&lock, sig, key).unwrap_or(false) {
                SkillSignatureState::Verified
            } else {
                SkillSignatureState::Invalid
            }
        }
        (Some(_), None) => SkillSignatureState::Unverified,
        (None, _) => SkillSignatureState::Unsigned,
    };
    lock.signature = signature;
    Ok(LoadedSkill {
        name: manifest.name,
        version: manifest.version,
        description: manifest.description,
        dir: dir.to_path_buf(),
        lock,
        signature_state,
    })
}

/// Validate a manifest at install time and compute its lock. `dir` is the
/// source package (anywhere on disk — the operator chose it; installation
/// copies it under the registry).
pub fn compute_lock(dir: &Path, limits: &SkillLimits) -> Result<SkillLock> {
    let manifest_path = dir.join(SKILL_MANIFEST_FILE);
    let manifest_raw = std::fs::read_to_string(&manifest_path)
        .map_err(|error| Error::Config(format!("cannot read {SKILL_MANIFEST_FILE}: {error}")))?;
    let manifest: SkillManifest = toml::from_str(&manifest_raw)
        .map_err(|error| Error::Config(format!("invalid {SKILL_MANIFEST_FILE}: {error}")))?;
    if manifest.schema != SKILL_MANIFEST_SCHEMA {
        return Err(Error::Config(format!(
            "unknown manifest schema {} (expected {SKILL_MANIFEST_SCHEMA})",
            manifest.schema
        )));
    }
    validate_manifest(&manifest, limits)?;
    let mut files = Vec::new();
    // The manifest itself is always covered.
    let mut all_files = vec![SKILL_MANIFEST_FILE.to_string()];
    all_files.extend(manifest.files.iter().cloned());
    all_files.sort();
    all_files.dedup();
    if all_files.len() > limits.max_files {
        return Err(Error::Config(format!(
            "skill declares {} files, over the limit of {}",
            all_files.len(),
            limits.max_files
        )));
    }
    for relative in &all_files {
        validate_relative_path(relative)?;
        let path = dir.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
        let bytes = std::fs::read(&path).map_err(|error| {
            Error::Config(format!("declared file `{relative}` is missing: {error}"))
        })?;
        if bytes.len() > limits.max_file_bytes {
            return Err(Error::Config(format!(
                "file `{relative}` is {} bytes, over the limit of {}",
                bytes.len(),
                limits.max_file_bytes
            )));
        }
        files.push(SkillFileEntry {
            path: relative.clone(),
            sha256: crate::util::hex_sha256_bytes(&bytes),
            bytes: bytes.len() as u64,
        });
    }
    for relative in &manifest.scripts {
        validate_relative_path(relative)?;
        let path = dir.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
        let bytes = std::fs::read(&path).map_err(|error| {
            Error::Config(format!("declared script `{relative}` is missing: {error}"))
        })?;
        if bytes.len() > limits.max_file_bytes {
            return Err(Error::Config(format!(
                "script `{relative}` is {} bytes, over the limit of {}",
                bytes.len(),
                limits.max_file_bytes
            )));
        }
        files.push(SkillFileEntry {
            path: relative.clone(),
            sha256: crate::util::hex_sha256_bytes(&bytes),
            bytes: bytes.len() as u64,
        });
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let package_digest = package_digest_of(&files);
    Ok(SkillLock {
        schema: SKILL_LOCK_SCHEMA.to_string(),
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        package_digest,
        files,
        scripts: manifest.scripts.clone(),
        created_at: now_rfc3339(),
        signature: None,
    })
}

/// Ed25519 signature over the canonical JSON of the lock without its
/// `signature` field.
pub fn sign_lock(lock: &SkillLock, seed_hex: &str) -> Result<SkillLock> {
    use ed25519_dalek::Signer;
    let seed = decode_seed(seed_hex)?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let mut unsigned = lock.clone();
    unsigned.signature = None;
    let message = canonical_lock_json(&unsigned)?;
    let signature = signing.sign(message.as_bytes());
    let mut signed = unsigned;
    signed.signature = Some(hex::encode(signature.to_bytes()));
    Ok(signed)
}

/// Verify a lock signature against a pinned public key (hex, 32 bytes).
/// Returns `Ok(false)` for a malformed signature rather than an error —
/// verification failure is a trust answer, not an operational fault.
pub fn verify_lock_signature(lock: &SkillLock, signature_hex: &str, key_hex: &str) -> Result<bool> {
    let key_bytes = decode_hex(key_hex, 32)
        .map_err(|error| Error::Config(format!("invalid verify_key: {error}")))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    let verifying = match ed25519_dalek::VerifyingKey::from_bytes(&key) {
        Ok(key) => key,
        Err(_) => return Ok(false),
    };
    let sig_bytes = match decode_hex(signature_hex, 64) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(false),
    };
    let signature = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
        Ok(signature) => signature,
        Err(_) => return Ok(false),
    };
    let mut unsigned = lock.clone();
    unsigned.signature = None;
    use ed25519_dalek::Verifier;
    let message = canonical_lock_json(&unsigned)?;
    Ok(verifying.verify(message.as_bytes(), &signature).is_ok())
}

/// Generate an ed25519 keypair; returns `(seed_hex, public_key_hex)`.
pub fn keygen() -> Result<(String, String)> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|error| Error::Other(format!("keygen entropy failure: {error}")))?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    Ok((
        hex::encode(seed),
        hex::encode(signing.verifying_key().as_bytes()),
    ))
}

fn decode_seed(seed_hex: &str) -> Result<[u8; 32]> {
    let bytes = decode_hex(seed_hex, 32)
        .map_err(|error| Error::Config(format!("invalid signing key: {error}")))?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn decode_hex(input: &str, expected: usize) -> std::result::Result<Vec<u8>, String> {
    let trimmed = input.trim();
    if trimmed.len() != expected * 2 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("expected {expected} bytes of hex"));
    }
    (0..expected)
        .map(|index| {
            u8::from_str_radix(&trimmed[index * 2..index * 2 + 2], 16)
                .map_err(|error| error.to_string())
        })
        .collect()
}

/// Canonical JSON of the lock for digest and signing: the struct serialized
/// with sorted keys (serde_json maps preserve insertion order, and the
/// struct fields are in a fixed order — good enough and stable per schema).
fn canonical_lock_json(lock: &SkillLock) -> Result<String> {
    serde_json::to_string(lock).map_err(|error| Error::Other(format!("lock serialize: {error}")))
}

fn package_digest_of(files: &[SkillFileEntry]) -> String {
    let joined: Vec<String> = files
        .iter()
        .map(|file| format!("{}:{}", file.path, file.sha256))
        .collect();
    hex_sha256(&joined.join("\n"))
}

fn validate_manifest(manifest: &SkillManifest, limits: &SkillLimits) -> Result<()> {
    let name = &manifest.name;
    let valid_name = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if !valid_name {
        return Err(Error::Config(format!(
            "skill name `{name}` is invalid (lowercase letters, digits, hyphen; 1-64 chars)"
        )));
    }
    if manifest.version.trim().is_empty() || manifest.version.len() > 32 {
        return Err(Error::Config("skill version must be 1-32 chars".into()));
    }
    if manifest.description.trim().is_empty() || manifest.description.len() > 256 {
        return Err(Error::Config(
            "skill description must be 1-256 chars".into(),
        ));
    }
    if manifest.files.is_empty() {
        return Err(Error::Config("skill must declare at least SKILL.md".into()));
    }
    if !manifest.files.iter().any(|file| file == SKILL_DOC_FILE) {
        return Err(Error::Config(format!(
            "skill must declare {SKILL_DOC_FILE} in files"
        )));
    }
    if manifest.files.len() > limits.max_files || manifest.scripts.len() > limits.max_files {
        return Err(Error::Config("too many declared files".into()));
    }
    Ok(())
}

fn validate_relative_path(relative: &str) -> Result<()> {
    if relative.is_empty()
        || relative.starts_with('/')
        || relative.ends_with('/')
        || relative.contains('\\')
        || relative.contains("..")
        || relative.contains('\0')
        || relative
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(Error::Config(format!(
            "skill path `{relative}` is not a safe relative path"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("pangu-skills-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    /// Build a minimal valid skill package on disk and return its dir.
    fn write_package(root: &Path, name: &str, description: &str) -> PathBuf {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(
            dir.join(SKILL_MANIFEST_FILE),
            format!(
                "schema = \"pangu-skill-manifest/1\"\nname = \"{name}\"\nversion = \"1.0.0\"\ndescription = \"{description}\"\nfiles = [\"SKILL.md\"]\nscripts = []\n"
            ),
        )
        .expect("manifest");
        std::fs::write(
            dir.join(SKILL_DOC_FILE),
            format!("# {name}\n\nStep one. Step two.\n"),
        )
        .expect("doc");
        dir
    }

    fn install(root: &Path, name: &str, description: &str) -> SkillLock {
        let dir = write_package(root, name, description);
        compute_lock(&dir, &SkillLimits::default()).expect("lock")
    }

    fn place_installed(root: &Path, name: &str, lock: &SkillLock) {
        let target = root.join("skills").join(name);
        std::fs::create_dir_all(&target).expect("target");
        // Copy the package files.
        let source = root.join(name);
        for file in ["SKILL.toml", "SKILL.md"] {
            std::fs::copy(source.join(file), target.join(file)).expect("copy");
        }
        std::fs::write(
            target.join(SKILL_LOCK_FILE),
            serde_json::to_string_pretty(lock).expect("lock json"),
        )
        .expect("write lock");
    }

    #[test]
    fn install_computes_a_lock_covering_manifest_and_doc() {
        let root = temp_root("install");
        let lock = install(&root, "demo-skill", "does demo things");
        assert_eq!(lock.name, "demo-skill");
        assert_eq!(lock.files.len(), 2); // SKILL.toml + SKILL.md
        assert!(lock.files.iter().any(|file| file.path == SKILL_DOC_FILE));
        assert_eq!(lock.package_digest.len(), 64);
        assert!(lock.signature.is_none());
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn registry_loads_and_read_doc_works() {
        let root = temp_root("load");
        let lock = install(&root, "demo-skill", "does demo things");
        place_installed(&root, "demo-skill", &lock);
        let registry =
            SkillRegistry::load(&root.join("skills"), &SkillLimits::default(), None).expect("load");
        assert_eq!(registry.skills().len(), 1);
        assert!(registry.rejected().is_empty());
        assert_eq!(
            registry.skills()[0].signature_state,
            SkillSignatureState::Unsigned
        );
        let doc = registry.read_doc("demo-skill").expect("doc");
        assert!(doc.contains("Step one"));
        assert!(registry.find("nope").is_none());
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn tampered_files_are_rejected_audibly() {
        let root = temp_root("tamper");
        let lock = install(&root, "demo-skill", "does demo things");
        place_installed(&root, "demo-skill", &lock);
        // Tamper with the doc after installation.
        let doc_path = root.join("skills").join("demo-skill").join(SKILL_DOC_FILE);
        std::fs::write(&doc_path, "# replaced by an attacker\n").expect("tamper");
        let registry =
            SkillRegistry::load(&root.join("skills"), &SkillLimits::default(), None).expect("load");
        assert!(registry.skills().is_empty());
        assert_eq!(registry.rejected().len(), 1);
        assert!(
            registry.rejected()[0]
                .reason
                .contains("integrity check failed"),
            "{}",
            registry.rejected()[0].reason
        );
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper_detection() {
        let root = temp_root("sign");
        let lock = install(&root, "demo-skill", "does demo things");
        let (seed_hex, public_hex) = keygen().expect("keygen");
        let signed = sign_lock(&lock, &seed_hex).expect("sign");
        assert!(signed.signature.is_some());
        assert!(
            verify_lock_signature(&signed, signed.signature.as_deref().unwrap(), &public_hex)
                .expect("verify")
        );
        // Tampering with the lock content invalidates the signature.
        let mut forged = signed.clone();
        forged.version = "9.9.9".into();
        assert!(
            !verify_lock_signature(&forged, signed.signature.as_deref().unwrap(), &public_hex)
                .expect("verify")
        );
        // A wrong key does not verify either.
        let (_other_seed, other_public) = keygen().expect("keygen");
        assert!(!verify_lock_signature(
            &signed,
            signed.signature.as_deref().unwrap(),
            &other_public
        )
        .expect("verify"));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn registry_verifies_signatures_when_a_key_is_pinned() {
        let root = temp_root("pin");
        let lock = install(&root, "demo-skill", "does demo things");
        let (seed_hex, public_hex) = keygen().expect("keygen");
        let signed = sign_lock(&lock, &seed_hex).expect("sign");
        place_installed(&root, "demo-skill", &signed);

        let registry = SkillRegistry::load(
            &root.join("skills"),
            &SkillLimits::default(),
            Some(&public_hex),
        )
        .expect("load");
        assert_eq!(
            registry.skills()[0].signature_state,
            SkillSignatureState::Verified
        );

        // Without the pinned key the same package loads as unsigned.
        let anonymous =
            SkillRegistry::load(&root.join("skills"), &SkillLimits::default(), None).expect("load");
        assert_eq!(
            anonymous.skills()[0].signature_state,
            SkillSignatureState::Unverified
        );
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn index_block_is_labeled_and_bounded() {
        let root = temp_root("index");
        for index in 0..3 {
            let lock = install(
                &root,
                &format!("skill-{index}"),
                &format!("skill number {index}"),
            );
            place_installed(&root, &format!("skill-{index}"), &lock);
        }
        let registry =
            SkillRegistry::load(&root.join("skills"), &SkillLimits::default(), None).expect("load");
        let block = registry.index_block().expect("index");
        assert!(block.contains("operator-installed"));
        assert!(block.contains("no permissions"));
        assert!(block.contains("skill-0 v1.0.0 [unsigned] skill number 0"));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn invalid_manifests_fail_closed() {
        let root = temp_root("invalid");
        // Path escape in files.
        let dir = write_package(&root, "bad-skill", "escape attempt");
        std::fs::write(
            dir.join(SKILL_MANIFEST_FILE),
            "schema = \"pangu-skill-manifest/1\"\nname = \"bad-skill\"\nversion = \"1\"\ndescription = \"x\"\nfiles = [\"../evil.md\", \"SKILL.md\"]\n",
        )
        .expect("manifest");
        assert!(compute_lock(&dir, &SkillLimits::default()).is_err());

        // Missing doc file.
        let dir = write_package(&root, "no-doc", "missing doc");
        std::fs::remove_file(dir.join(SKILL_DOC_FILE)).expect("remove");
        assert!(compute_lock(&dir, &SkillLimits::default()).is_err());

        // Invalid name.
        let dir = write_package(&root, "Bad_Name", "invalid name");
        assert!(compute_lock(&dir, &SkillLimits::default()).is_err());
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn unknown_schema_and_identity_mismatch_are_rejected() {
        let root = temp_root("schema");
        let lock = install(&root, "demo-skill", "does demo things");
        place_installed(&root, "demo-skill", &lock);
        // Wrong manifest schema.
        let manifest = root
            .join("skills")
            .join("demo-skill")
            .join(SKILL_MANIFEST_FILE);
        let raw = std::fs::read_to_string(&manifest).expect("read");
        std::fs::write(
            &manifest,
            raw.replace("pangu-skill-manifest/1", "pangu-skill-manifest/9"),
        )
        .expect("write");
        let registry =
            SkillRegistry::load(&root.join("skills"), &SkillLimits::default(), None).expect("load");
        assert_eq!(registry.rejected().len(), 1);
        assert!(registry.rejected()[0]
            .reason
            .contains("unknown manifest schema"));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn empty_registry_is_not_an_error() {
        let root = temp_root("empty");
        let registry =
            SkillRegistry::load(&root.join("does-not-exist"), &SkillLimits::default(), None)
                .expect("load");
        assert!(registry.skills().is_empty());
        assert!(registry.index_block().is_none());
        std::fs::remove_dir_all(root).ok();
    }
}
