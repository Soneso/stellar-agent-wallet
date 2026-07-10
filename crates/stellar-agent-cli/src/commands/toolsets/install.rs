//! `toolsets install` subcommand.
//!
//! Installs a toolset from a signed `.tar.gz` package file.  The attestation gate
//! flags `--attestation-file`, `--auditor-trust-set`, and `--override-attestation`
//! govern the auditor-attestation check for key-touching toolsets.

use std::path::PathBuf;

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::profile::schema::default_toolsets_dir;
use stellar_agent_toolsets_install::{
    InstallOptions, MAX_ATTESTATION_BYTES, ToolsetAttestation, install_toolset_from_path,
};

use crate::common::render::render_json;

/// Arguments for `toolsets install`.
#[derive(Debug, Args)]
pub struct ToolsetInstallArgs {
    /// Package specification in `<name>@<version>` format.
    ///
    /// Example: `my-toolset@1.0.0`
    #[arg(value_name = "PKG@VERSION")]
    pub pkg_at_version: String,

    /// Path to the `.tar.gz` package file to install.
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    /// Expected SHA-256 hex digest of the package file (64 lowercase hex chars).
    #[arg(long, value_name = "HEX")]
    pub shasum: String,

    /// Publisher ed25519 signature over the canonical preimage (128 lowercase hex chars = 64 bytes).
    #[arg(long, value_name = "HEX")]
    pub signature: String,

    /// Publisher ed25519 public key as a Stellar G-strkey.
    #[arg(long, value_name = "G-STRKEY")]
    pub publisher: String,

    /// Path to the trust-set file (default: `<toolsets_dir>/trust.txt`).
    #[arg(long, value_name = "PATH")]
    pub trust_set: Option<PathBuf>,

    /// Override the toolsets root directory (default: OS-conventional toolsets dir).
    #[arg(long, value_name = "PATH")]
    pub toolsets_dir: Option<PathBuf>,

    /// Reinstall even if already installed.
    #[arg(long)]
    pub force: bool,

    /// Allow installing an older version over a newer one.
    ///
    /// Only effective with `--force`.
    #[arg(long)]
    pub allow_downgrade: bool,

    /// Path to a JSON file containing a `ToolsetAttestation` (as produced by the
    /// auditor tool).
    ///
    /// The file must contain a `ToolsetAttestation` serialised as JSON (hex-encoded
    /// `auditor_pubkey` and `signature` fields, plus the full capability set the
    /// auditor signed over).  The gate verifies the struct's `auditor_pubkey` against
    /// the auditor trust set and runs `verify_strict` over the struct's `signature`.
    ///
    /// Required for toolsets that declare a key-touching capability (e.g. `sign-payment`),
    /// unless `--override-attestation` is set.
    #[arg(long, value_name = "PATH")]
    pub attestation_file: Option<PathBuf>,

    /// Path to the auditor trust-set file (default: `<toolsets_dir>/auditor-trust.txt`).
    ///
    /// Distinct from the publisher trust-set (`--trust-set` / `trust.txt`).
    /// An absent or empty auditor trust set causes the attestation gate to fail
    /// closed for key-touching toolsets.
    #[arg(long, value_name = "PATH")]
    pub auditor_trust_set: Option<PathBuf>,

    /// Bypass the attestation gate for key-touching toolsets.
    ///
    /// When set for a key-touching toolset with no valid attestation, the gate is
    /// skipped with a structured `warn!` audit line and the JSON outcome reports
    /// `"attestation": "overridden"`.
    ///
    /// This is the ONLY sanctioned bypass — no other input skips the gate.
    /// The toolset is still installed with `sign-payment` capability INERT in the
    /// pin; the first-invoke and per-action approval gates still fire at runtime.
    #[arg(long)]
    pub override_attestation: bool,
}

/// JSON success payload for `toolsets install`, carried under the envelope
/// `data` field.
#[derive(Debug, Serialize)]
struct InstallResult {
    /// Package name.
    package: String,
    /// Installed version.
    version: String,
    /// Attestation gate outcome.
    ///
    /// - `"attested"` — a valid attestation from a trusted auditor was verified.
    /// - `"overridden"` — the gate was bypassed via `--override-attestation`
    ///   (only set when the override actually suppressed a firing gate, i.e. the
    ///   toolset is key-touching).
    /// - `"not-required"` — the toolset has no key-touching capabilities (the gate
    ///   never fired, regardless of flags).
    ///
    /// This field reflects the ACTUAL gate decision returned by
    /// `install_toolset_from_path`, not an inference from CLI flags.
    attestation: &'static str,
}

/// Runs the `toolsets install` subcommand.
///
/// # Exit codes
///
/// - `0` on success (`{ ok: true, data: { package, version, attestation },
///   request_id }`).
/// - `1` on any error (`{ ok: false, error: { code, message }, request_id }`).
///   `code` is `"toolsets.install_failed"` for every refusal reason (parse,
///   attestation-gate, or install-library failure); the distinguishing detail
///   is in `message`.
pub async fn run(args: &ToolsetInstallArgs) -> i32 {
    match run_inner(args) {
        Ok(result) => {
            render_json(&Envelope::ok(result));
            0
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "toolsets.install_failed",
                e.to_string(),
            ));
            1
        }
    }
}

fn run_inner(args: &ToolsetInstallArgs) -> Result<InstallResult, Box<dyn std::error::Error>> {
    // Parse `<name>@<version>`.
    let (package, version) = parse_pkg_at_version(&args.pkg_at_version)?;

    // Decode the publisher signature (128 hex chars → 64 bytes).
    let sig_bytes = decode_sig_hex(&args.signature)?;

    // Decode the publisher public key from G-strkey.
    let pk_bytes = decode_publisher_key(&args.publisher)?;

    // Resolve toolsets root.
    let toolsets_root = match &args.toolsets_dir {
        Some(p) => p.clone(),
        None => default_toolsets_dir().map_err(|_| "cannot resolve toolsets directory")?,
    };

    // Resolve publisher trust-set path.
    let trust_set_path = match &args.trust_set {
        Some(p) => p.clone(),
        None => toolsets_root.join("trust.txt"),
    };

    // Resolve auditor trust-set path (distinct from publisher trust.txt).
    let auditor_trust_set_path = match &args.auditor_trust_set {
        Some(p) => p.clone(),
        None => toolsets_root.join("auditor-trust.txt"),
    };

    // Load the ToolsetAttestation from a JSON file if provided.
    //
    // The auditor tool produces a JSON-serialised `ToolsetAttestation` that carries
    // the full capability set the auditor signed over.  The gate's field cross-check
    // compares att.capabilities against the signature-verified TOOLSET.md parse; a
    // correctly-produced attestation file always passes for the artefact it covers.
    //
    // The file path is attacker-controllable, so the read is capped at
    // MAX_ATTESTATION_BYTES (16 KiB) via `take`, mirroring the trust-set and
    // package-file caps elsewhere in this codebase.
    let attestation_owned: Option<ToolsetAttestation> = match &args.attestation_file {
        Some(path) => {
            use std::io::Read as _;

            let file = std::fs::File::open(path)
                .map_err(|e| format!("cannot open attestation file: {e}"))?;
            let mut limited = file.take((MAX_ATTESTATION_BYTES as u64) + 1);
            let mut content = String::new();
            limited
                .read_to_string(&mut content)
                .map_err(|e| format!("cannot read attestation file: {e}"))?;

            if content.len() > MAX_ATTESTATION_BYTES {
                return Err(format!(
                    "attestation file exceeds the {MAX_ATTESTATION_BYTES}-byte cap; \
                     a valid ToolsetAttestation JSON is well under 1 KiB"
                )
                .into());
            }

            let att: ToolsetAttestation = serde_json::from_str(&content)
                .map_err(|e| format!("invalid attestation JSON: {e}"))?;
            Some(att)
        }
        None => None,
    };

    let opts = InstallOptions {
        force: args.force,
        allow_downgrade: args.allow_downgrade,
        override_attestation: args.override_attestation,
    };

    // Use install_toolset_from_path so the streaming cap (MAX_PACKAGE_BYTES) is
    // applied on the OS file handle BEFORE materialising the buffer — a
    // multi-GB or FIFO source cannot OOM the process.
    let outcome = install_toolset_from_path(
        &package,
        &version,
        &args.file,
        &args.shasum,
        &sig_bytes,
        &pk_bytes,
        &toolsets_root,
        &trust_set_path,
        attestation_owned.as_ref(),
        &auditor_trust_set_path,
        &opts,
    )?;

    Ok(InstallResult {
        package,
        version,
        // Report the ACTUAL gate decision returned by the library, not an inference
        // from CLI flags.  --override-attestation on a non-key-touching toolset must
        // report "not-required" (the gate never fires), not "overridden".
        attestation: outcome.as_str(),
    })
}

/// Parses `<name>@<version>` into `(name, version)`.
fn parse_pkg_at_version(spec: &str) -> Result<(String, String), String> {
    let (name, version) = spec
        .split_once('@')
        .ok_or_else(|| format!("invalid package spec '{spec}': expected '<name>@<version>'"))?;

    if name.is_empty() {
        return Err("package name is empty in spec".to_owned());
    }
    if version.is_empty() {
        return Err("version is empty in spec".to_owned());
    }

    Ok((name.to_owned(), version.to_owned()))
}

/// Decodes a 128-char hex string into a 64-byte ed25519 publisher signature.
fn decode_sig_hex(hex_str: &str) -> Result<[u8; 64], String> {
    if hex_str.len() != 128 {
        return Err(format!(
            "signature must be 128 hex chars (64 bytes), got {}",
            hex_str.len()
        ));
    }
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid signature hex: {e}"))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| "signature hex does not decode to 64 bytes".to_owned())?;
    Ok(arr)
}

/// Decodes a Stellar G-strkey into 32 raw ed25519 public key bytes.
fn decode_publisher_key(strkey: &str) -> Result<[u8; 32], String> {
    use stellar_strkey::ed25519::PublicKey;
    PublicKey::from_string(strkey)
        .map(|pk| pk.0)
        .map_err(|e| format!("invalid publisher G-strkey: {e}"))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::io::Write as _;
    use std::path::Path;

    use ed25519_dalek::{Signer, SigningKey};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use sha2::{Digest, Sha256};
    use stellar_agent_toolsets::parse_capability_value_pub;
    use stellar_agent_toolsets_install::attestation::build_attestation_preimage;
    use stellar_agent_toolsets_install::signature::build_preimage;
    use stellar_strkey::ed25519::PublicKey as StrPublicKey;
    use tempfile::TempDir;

    use super::*;

    // ── Test seeds (NEVER mainnet keys) ───────────────────────────────────────

    const PUBLISHER_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    const AUDITOR_SEED: [u8; 32] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f, 0x40,
    ];

    // ── Fixture helpers ───────────────────────────────────────────────────────

    fn sha256_hex(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        hex::encode(h.finalize())
    }

    fn make_toolset_tar_gz(package_name: &str, toolset_md_content: &str) -> Vec<u8> {
        let mut ar = tar::Builder::new(Vec::new());
        let mut dir_hdr = tar::Header::new_gnu();
        dir_hdr.set_entry_type(tar::EntryType::Directory);
        dir_hdr.set_path(format!("{package_name}/")).unwrap();
        dir_hdr.set_size(0);
        dir_hdr.set_mode(0o755);
        dir_hdr.set_cksum();
        ar.append(&dir_hdr, &[][..]).unwrap();
        let content = toolset_md_content.as_bytes();
        let mut file_hdr = tar::Header::new_gnu();
        file_hdr.set_entry_type(tar::EntryType::Regular);
        file_hdr
            .set_path(format!("{package_name}/TOOLSET.md"))
            .unwrap();
        file_hdr.set_size(content.len() as u64);
        file_hdr.set_mode(0o644);
        file_hdr.set_cksum();
        ar.append(&file_hdr, content).unwrap();
        let tar_bytes = ar.into_inner().unwrap();
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    fn toolset_md_sign_payment(name: &str) -> String {
        format!(
            "---\nname: {name}\ndescription: test.\nmetadata:\n  \
             stellar-agent-capabilities: sign-payment\n---\n\nBody.\n"
        )
    }

    fn toolset_md_no_caps(name: &str) -> String {
        format!("---\nname: {name}\ndescription: test.\n---\n\nBody.\n")
    }

    /// Writes a publisher trust file; returns its path.
    fn write_publisher_trust(dir: &Path, publisher_pk: [u8; 32]) -> PathBuf {
        let ps: String = StrPublicKey(publisher_pk).to_string().as_str().to_owned();
        let path = dir.join("trust.txt");
        std::fs::write(&path, format!("{ps}\n")).unwrap();
        path
    }

    /// Writes an auditor trust file; returns its path.
    fn write_auditor_trust(dir: &Path, auditor_pk: [u8; 32]) -> PathBuf {
        let ks: String = StrPublicKey(auditor_pk).to_string().as_str().to_owned();
        let path = dir.join("auditor-trust.txt");
        std::fs::write(&path, format!("{ks}\n")).unwrap();
        path
    }

    /// Writes an attestation JSON file; returns its path.
    fn write_attestation_file(
        dir: &Path,
        auditor_sk: &SigningKey,
        auditor_pk: [u8; 32],
        package: &str,
        version: &str,
        shasum: &str,
        caps_str: &str,
    ) -> PathBuf {
        let caps = parse_capability_value_pub(caps_str).unwrap();
        let preimage = build_attestation_preimage(package, version, shasum, &caps);
        let sig: [u8; 64] = auditor_sk.sign(&preimage).to_bytes();
        let att = ToolsetAttestation {
            package: package.to_owned(),
            version: version.to_owned(),
            shasum: shasum.to_owned(),
            capabilities: caps,
            auditor_pubkey: auditor_pk,
            signature: sig,
        };
        let json = serde_json::to_string_pretty(&att).unwrap();
        let path = dir.join("attestation.json");
        std::fs::write(&path, json).unwrap();
        path
    }

    /// Builds a publisher signature as a lowercase hex string.
    fn publisher_sig_hex(sk: &SigningKey, package: &str, version: &str, shasum: &str) -> String {
        let preimage = build_preimage(package, version, shasum);
        hex::encode(sk.sign(&preimage).to_bytes())
    }

    // ── `run_inner` end-to-end assertions ─────────────────────────────────────
    //
    // These tests drive `run_inner` end-to-end asserting the JSON `attestation`
    // field for four cases.

    #[test]
    fn tfixture_key_touching_with_attestation_file_reports_attested() {
        // Key-touching + valid --attestation-file → "attested".
        let publisher_sk = SigningKey::from_bytes(&PUBLISHER_SEED);
        let publisher_pk = publisher_sk.verifying_key().to_bytes();
        let auditor_sk = SigningKey::from_bytes(&AUDITOR_SEED);
        let auditor_pk = auditor_sk.verifying_key().to_bytes();

        let tmp = TempDir::new().unwrap();
        let toolsets_root = tmp.path().join("toolsets");
        std::fs::create_dir_all(&toolsets_root).unwrap();

        let pkg_bytes =
            make_toolset_tar_gz("sign-toolset", &toolset_md_sign_payment("sign-toolset"));
        let shasum = sha256_hex(&pkg_bytes);
        let pkg_path = tmp.path().join("sign-toolset-1.0.0.tar.gz");
        std::fs::write(&pkg_path, &pkg_bytes).unwrap();

        let trust_path = write_publisher_trust(tmp.path(), publisher_pk);
        let auditor_trust_path = write_auditor_trust(tmp.path(), auditor_pk);
        let att_path = write_attestation_file(
            tmp.path(),
            &auditor_sk,
            auditor_pk,
            "sign-toolset",
            "1.0.0",
            &shasum,
            "sign-payment",
        );

        let args = ToolsetInstallArgs {
            pkg_at_version: "sign-toolset@1.0.0".to_owned(),
            file: pkg_path,
            shasum: shasum.clone(),
            signature: publisher_sig_hex(&publisher_sk, "sign-toolset", "1.0.0", &shasum),
            publisher: StrPublicKey(publisher_pk).to_string().as_str().to_owned(),
            trust_set: Some(trust_path),
            toolsets_dir: Some(toolsets_root),
            force: false,
            allow_downgrade: false,
            attestation_file: Some(att_path),
            auditor_trust_set: Some(auditor_trust_path),
            override_attestation: false,
        };

        let result = run_inner(&args).expect("attested install must succeed");
        assert_eq!(
            result.attestation, "attested",
            "key-touching + valid attestation-file must report 'attested'"
        );
    }

    #[test]
    fn tfixture_key_touching_no_attestation_returns_error() {
        // Key-touching + no attestation → AttestationRequired error.
        let publisher_sk = SigningKey::from_bytes(&PUBLISHER_SEED);
        let publisher_pk = publisher_sk.verifying_key().to_bytes();
        let auditor_sk = SigningKey::from_bytes(&AUDITOR_SEED);
        let auditor_pk = auditor_sk.verifying_key().to_bytes();

        let tmp = TempDir::new().unwrap();
        let toolsets_root = tmp.path().join("toolsets");
        std::fs::create_dir_all(&toolsets_root).unwrap();

        let pkg_bytes =
            make_toolset_tar_gz("sign-toolset", &toolset_md_sign_payment("sign-toolset"));
        let shasum = sha256_hex(&pkg_bytes);
        let pkg_path = tmp.path().join("sign-toolset-1.0.0.tar.gz");
        std::fs::write(&pkg_path, &pkg_bytes).unwrap();

        let trust_path = write_publisher_trust(tmp.path(), publisher_pk);
        let auditor_trust_path = write_auditor_trust(tmp.path(), auditor_pk);
        let _ = (auditor_sk, auditor_pk); // unused — no attestation in this test

        let args = ToolsetInstallArgs {
            pkg_at_version: "sign-toolset@1.0.0".to_owned(),
            file: pkg_path,
            shasum: shasum.clone(),
            signature: publisher_sig_hex(&publisher_sk, "sign-toolset", "1.0.0", &shasum),
            publisher: StrPublicKey(publisher_pk).to_string().as_str().to_owned(),
            trust_set: Some(trust_path),
            toolsets_dir: Some(toolsets_root),
            force: false,
            allow_downgrade: false,
            attestation_file: None,
            auditor_trust_set: Some(auditor_trust_path),
            override_attestation: false,
        };

        let err = run_inner(&args).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("attestation required"),
            "no attestation must return AttestationRequired error; got: {msg}"
        );
    }

    #[test]
    fn tfixture_key_touching_with_override_reports_overridden() {
        // Key-touching + --override-attestation → "overridden".
        let publisher_sk = SigningKey::from_bytes(&PUBLISHER_SEED);
        let publisher_pk = publisher_sk.verifying_key().to_bytes();

        let tmp = TempDir::new().unwrap();
        let toolsets_root = tmp.path().join("toolsets");
        std::fs::create_dir_all(&toolsets_root).unwrap();

        let pkg_bytes =
            make_toolset_tar_gz("sign-toolset", &toolset_md_sign_payment("sign-toolset"));
        let shasum = sha256_hex(&pkg_bytes);
        let pkg_path = tmp.path().join("sign-toolset-1.0.0.tar.gz");
        std::fs::write(&pkg_path, &pkg_bytes).unwrap();

        let trust_path = write_publisher_trust(tmp.path(), publisher_pk);
        // No auditor-trust.txt — would fail the gate if it fires; override bypasses it.
        let auditor_trust_path = tmp.path().join("auditor-trust.txt");

        let args = ToolsetInstallArgs {
            pkg_at_version: "sign-toolset@1.0.0".to_owned(),
            file: pkg_path,
            shasum: shasum.clone(),
            signature: publisher_sig_hex(&publisher_sk, "sign-toolset", "1.0.0", &shasum),
            publisher: StrPublicKey(publisher_pk).to_string().as_str().to_owned(),
            trust_set: Some(trust_path),
            toolsets_dir: Some(toolsets_root),
            force: false,
            allow_downgrade: false,
            attestation_file: None,
            auditor_trust_set: Some(auditor_trust_path),
            override_attestation: true,
        };

        let result = run_inner(&args).expect("override install must succeed");
        assert_eq!(
            result.attestation, "overridden",
            "key-touching + override must report 'overridden'; got: {}",
            result.attestation
        );
    }

    #[test]
    fn tfixture_non_key_touching_with_override_flag_reports_not_required() {
        // Non-key-touching + --override-attestation → "not-required" (gate never fires).
        // The ACTUAL gate decision is returned from the lib, not inferred from flags.
        let publisher_sk = SigningKey::from_bytes(&PUBLISHER_SEED);
        let publisher_pk = publisher_sk.verifying_key().to_bytes();

        let tmp = TempDir::new().unwrap();
        let toolsets_root = tmp.path().join("toolsets");
        std::fs::create_dir_all(&toolsets_root).unwrap();

        let pkg_bytes = make_toolset_tar_gz("read-toolset", &toolset_md_no_caps("read-toolset"));
        let shasum = sha256_hex(&pkg_bytes);
        let pkg_path = tmp.path().join("read-toolset-1.0.0.tar.gz");
        std::fs::write(&pkg_path, &pkg_bytes).unwrap();

        let trust_path = write_publisher_trust(tmp.path(), publisher_pk);
        let auditor_trust_path = tmp.path().join("auditor-trust.txt"); // absent; fine for no-gate

        let args = ToolsetInstallArgs {
            pkg_at_version: "read-toolset@1.0.0".to_owned(),
            file: pkg_path,
            shasum: shasum.clone(),
            signature: publisher_sig_hex(&publisher_sk, "read-toolset", "1.0.0", &shasum),
            publisher: StrPublicKey(publisher_pk).to_string().as_str().to_owned(),
            trust_set: Some(trust_path),
            toolsets_dir: Some(toolsets_root),
            force: false,
            allow_downgrade: false,
            attestation_file: None,
            auditor_trust_set: Some(auditor_trust_path),
            override_attestation: true, // set but must be a no-op for non-key-touching
        };

        let result = run_inner(&args).expect("non-key-touching install must succeed");
        assert_eq!(
            result.attestation, "not-required",
            "non-key-touching + override flag must report 'not-required'; got: {}",
            result.attestation
        );
    }

    #[test]
    fn tfixture_attestation_file_with_untrusted_auditor_refused() {
        // `--attestation-file` whose `auditor_pubkey` is NOT in the auditor
        // trust set → install refused with AuditorUntrusted; no partial install.
        let publisher_sk = SigningKey::from_bytes(&PUBLISHER_SEED);
        let publisher_pk = publisher_sk.verifying_key().to_bytes();
        let auditor_sk = SigningKey::from_bytes(&AUDITOR_SEED);
        let auditor_pk = auditor_sk.verifying_key().to_bytes();

        // A DIFFERENT auditor — NOT placed in the auditor trust file.
        let untrusted_seed = [0xeeu8; 32];
        let untrusted_sk = SigningKey::from_bytes(&untrusted_seed);
        let untrusted_pk = untrusted_sk.verifying_key().to_bytes();

        let tmp = TempDir::new().unwrap();
        let toolsets_root = tmp.path().join("toolsets");
        std::fs::create_dir_all(&toolsets_root).unwrap();

        let pkg_bytes =
            make_toolset_tar_gz("sign-toolset", &toolset_md_sign_payment("sign-toolset"));
        let shasum = sha256_hex(&pkg_bytes);
        let pkg_path = tmp.path().join("sign-toolset-1.0.0.tar.gz");
        std::fs::write(&pkg_path, &pkg_bytes).unwrap();

        // Only `auditor_pk` is in the trust file; `untrusted_pk` is NOT.
        let trust_path = write_publisher_trust(tmp.path(), publisher_pk);
        let auditor_trust_path = write_auditor_trust(tmp.path(), auditor_pk);

        // Attestation is signed by the untrusted key and names it as auditor_pubkey.
        let att_path = write_attestation_file(
            tmp.path(),
            &untrusted_sk,
            untrusted_pk,
            "sign-toolset",
            "1.0.0",
            &shasum,
            "sign-payment",
        );

        let args = ToolsetInstallArgs {
            pkg_at_version: "sign-toolset@1.0.0".to_owned(),
            file: pkg_path,
            shasum: shasum.clone(),
            signature: publisher_sig_hex(&publisher_sk, "sign-toolset", "1.0.0", &shasum),
            publisher: StrPublicKey(publisher_pk).to_string().as_str().to_owned(),
            trust_set: Some(trust_path),
            toolsets_dir: Some(toolsets_root.clone()),
            force: false,
            allow_downgrade: false,
            attestation_file: Some(att_path),
            auditor_trust_set: Some(auditor_trust_path),
            override_attestation: false,
        };

        let err = run_inner(&args).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("auditor untrusted"),
            "untrusted auditor_pubkey in attestation file must give AuditorUntrusted; \
             got: {msg}"
        );

        // No partial install.
        assert!(
            !toolsets_root.join("sign-toolset").exists(),
            "no partial install after AuditorUntrusted refusal"
        );
    }
}
