//! Adversarial archive battery.
//!
//! Each test verifies that a crafted `.tar.gz` is rejected with the correct
//! error variant WITHOUT escaping the toolsets directory or exhausting resources.
//!
//! Archives are built programmatically using the `tar` and `flate2` crates.
//! For traversal/absolute-path tests, raw tar blocks are crafted directly to
//! bypass the tar builder's own path validation (the builder validates, so
//! we must write raw bytes to exercise the extractor's checks).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::type_complexity,
    clippy::manual_repeat_n,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::io::Write;

use ed25519_dalek::{Signer, SigningKey};
use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};
use stellar_agent_toolsets_install::signature::build_preimage;
use stellar_agent_toolsets_install::{
    InstallOptions, ToolsetInstallError, install_toolset, uninstall_toolset,
};
use stellar_strkey::ed25519::PublicKey as StrPublicKey;
use tempfile::TempDir;

// ── Raw tar building helpers ──────────────────────────────────────────────────

/// Creates a 512-byte POSIX tar header for a file/directory entry.
/// `name` must be at most 99 bytes (+ NUL).
/// `type_flag`: b'0' = regular file, b'5' = directory, b'2' = symlink, b'1' = hardlink,
///              b'6' = FIFO.
fn tar_header(name: &[u8], size: usize, type_flag: u8, link_name: &[u8]) -> [u8; 512] {
    let mut block = [0u8; 512];

    // Name field (0-99).
    let nlen = name.len().min(99);
    block[..nlen].copy_from_slice(&name[..nlen]);

    // File mode (100-107).
    block[100..108].copy_from_slice(b"0000755\0");

    // UID (108-115), GID (116-123).
    block[108..116].copy_from_slice(b"0000000\0");
    block[116..124].copy_from_slice(b"0000000\0");

    // File size (124-135, octal).
    let size_str = format!("{:011o}\0", size);
    block[124..136].copy_from_slice(size_str.as_bytes());

    // Modification time (136-147).
    block[136..148].copy_from_slice(b"00000000000\0");

    // Checksum placeholder (148-155) — set to spaces before calculation.
    block[148..156].copy_from_slice(b"        ");

    // Type flag (156).
    block[156] = type_flag;

    // Link name (157-256) for symlink/hardlink.
    if !link_name.is_empty() {
        let llen = link_name.len().min(99);
        block[157..157 + llen].copy_from_slice(&link_name[..llen]);
    }

    // Magic (257-262) = "ustar\0".
    block[257..263].copy_from_slice(b"ustar\0");
    // Version (263-264) = "00".
    block[263..265].copy_from_slice(b"00");

    // Compute checksum.
    let sum: u32 = block.iter().map(|&b| b as u32).sum();
    let cksum = format!("{:06o}\0 ", sum);
    block[148..156].copy_from_slice(cksum.as_bytes());

    block
}

/// Pads `data` to a multiple of 512 bytes.
fn pad_to_512(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let rem = out.len() % 512;
    if rem != 0 {
        out.extend(std::iter::repeat(0u8).take(512 - rem));
    }
    out
}

/// Creates a raw tar archive from `(name, size, type_flag, link_name, content)` entries.
fn make_raw_tar(entries: &[(&[u8], &[u8], u8, &[u8])]) -> Vec<u8> {
    let mut ar = Vec::new();
    for (name, content, type_flag, link_name) in entries {
        ar.extend_from_slice(&tar_header(name, content.len(), *type_flag, link_name));
        if !content.is_empty() {
            ar.extend_from_slice(&pad_to_512(content));
        }
    }
    // End-of-archive: two zero blocks.
    ar.extend(vec![0u8; 1024]);
    ar
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = GzEncoder::new(&mut out, Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap();
    out
}

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Builds a minimal valid `.tar.gz` for `package_name`.
fn make_valid_tar_gz(package_name: &str, toolset_md_content: &str) -> Vec<u8> {
    let dir_name = format!("{package_name}/");
    let file_name = format!("{package_name}/TOOLSET.md");
    let content = toolset_md_content.as_bytes();

    let ar = make_raw_tar(&[
        (dir_name.as_bytes(), b"", b'5', b""),
        (file_name.as_bytes(), content, b'0', b""),
    ]);
    gzip(&ar)
}

fn minimal_toolset_md(name: &str) -> String {
    format!(
        "---\nname: {name}\ndescription: A test toolset for install tests.\n---\n\nTest toolset body.\n"
    )
}

fn make_trust_setup() -> (SigningKey, [u8; 32], std::path::PathBuf, TempDir) {
    let seed = [0xabu8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    let strkey_heapless = StrPublicKey(pk).to_string();
    let strkey: std::string::String = strkey_heapless.as_str().to_owned();

    let tmp = TempDir::new().unwrap();
    let trust_path = tmp.path().join("trust.txt");
    std::fs::write(&trust_path, format!("{strkey}\n")).unwrap();

    (sk, pk, trust_path, tmp)
}

/// Calls [`install_toolset`] for tests that do NOT declare key-touching
/// capabilities.  Passes `None` for attestation and a non-existent auditor
/// trust path (the gate does not fire for non-key-touching toolsets, so the
/// path is never opened).
///
/// Returns `Ok(())` on success (discards the `AttestationOutcome`; these tests
/// only care about pass/fail, not the gate outcome).
#[allow(clippy::too_many_arguments)]
fn install_no_attestation(
    package: &str,
    version: &str,
    pkg_bytes: &[u8],
    shasum: &str,
    sig: &[u8; 64],
    pk: &[u8; 32],
    toolsets_root: &std::path::Path,
    trust_path: &std::path::Path,
    options: &InstallOptions,
) -> Result<(), ToolsetInstallError> {
    let auditor_trust_path = trust_path.with_file_name("auditor-trust.txt");
    install_toolset(
        package,
        version,
        pkg_bytes,
        shasum,
        sig,
        pk,
        toolsets_root,
        trust_path,
        None,
        &auditor_trust_path,
        options,
    )
    .map(|_outcome| ())
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn sign_package(package: &str, version: &str, data: &[u8], sk: &SigningKey) -> ([u8; 64], String) {
    let shasum = sha256_hex(data);
    let preimage = build_preimage(package, version, &shasum);
    let sig: [u8; 64] = sk.sign(&preimage).to_bytes();
    (sig, shasum)
}

fn install_expecting_err(
    package: &str,
    version: &str,
    pkg_bytes: &[u8],
    sk: &SigningKey,
    pk: &[u8; 32],
    trust_path: &std::path::Path,
    toolsets_root: &std::path::Path,
) -> ToolsetInstallError {
    let (sig, shasum) = sign_package(package, version, pkg_bytes, sk);
    let opts = InstallOptions::default();
    // Toolsets in adversarial tests do not declare sign-payment (no key-touching
    // capability), so the attestation gate does not fire.  The auditor trust
    // path is kept adjacent to the publisher trust file but will not be read.
    let auditor_trust_path = trust_path.with_file_name("auditor-trust.txt");
    install_toolset(
        package,
        version,
        pkg_bytes,
        &shasum,
        &sig,
        pk,
        toolsets_root,
        trust_path,
        None,
        &auditor_trust_path,
        &opts,
    )
    .unwrap_err()
}

// ── 1. Path traversal: `..` component ─────────────────────────────────────────

#[test]
fn traversal_dotdot_rejected() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Raw tar with `my-toolset/../etc/passwd` entry.
    let ar = make_raw_tar(&[
        (b"my-toolset/\0", b"", b'5', b""),
        (b"my-toolset/../etc/passwd\0", b"evil", b'0', b""),
    ]);
    let gz_bytes = gzip(&ar);

    let err = install_expecting_err(
        "my-toolset",
        "1.0.0",
        &gz_bytes,
        &sk,
        &pk,
        &trust_path,
        &toolsets_root,
    );
    assert!(
        matches!(
            err,
            ToolsetInstallError::ArchivePathTraversal { .. }
                | ToolsetInstallError::ArchiveBadTopLevel { .. }
                | ToolsetInstallError::ArchiveEntryNameInvalid { .. }
        ),
        "expected traversal error, got: {err:?}"
    );
}

// ── 2. Absolute path ──────────────────────────────────────────────────────────

#[test]
fn absolute_path_entry_rejected() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Raw tar with `/etc/passwd` as an entry.
    let ar = make_raw_tar(&[
        (b"my-toolset/\0", b"", b'5', b""),
        (b"/etc/passwd\0", b"evil", b'0', b""),
    ]);
    let gz_bytes = gzip(&ar);

    let err = install_expecting_err(
        "my-toolset",
        "1.0.0",
        &gz_bytes,
        &sk,
        &pk,
        &trust_path,
        &toolsets_root,
    );
    assert!(
        matches!(
            err,
            ToolsetInstallError::ArchivePathTraversal { .. }
                | ToolsetInstallError::ArchiveBadTopLevel { .. }
                | ToolsetInstallError::ArchiveEntryNameInvalid { .. }
        ),
        "expected path safety error, got: {err:?}"
    );
}

// ── 3. Symlink entry ──────────────────────────────────────────────────────────

#[test]
fn symlink_entry_rejected() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Raw tar with a symlink entry (type b'2').
    let ar = make_raw_tar(&[
        (b"my-toolset/\0", b"", b'5', b""),
        (b"my-toolset/link\0", b"", b'2', b"/etc/passwd\0"),
    ]);
    let gz_bytes = gzip(&ar);

    let err = install_expecting_err(
        "my-toolset",
        "1.0.0",
        &gz_bytes,
        &sk,
        &pk,
        &trust_path,
        &toolsets_root,
    );
    assert!(
        matches!(err, ToolsetInstallError::ArchiveDisallowedEntryType),
        "expected ArchiveDisallowedEntryType for symlink, got: {err:?}"
    );
}

// ── 4. Hardlink entry ─────────────────────────────────────────────────────────

#[test]
fn hardlink_entry_rejected() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Raw tar with a hardlink entry (type b'1').
    let ar = make_raw_tar(&[
        (b"my-toolset/\0", b"", b'5', b""),
        (
            b"my-toolset/hardlink\0",
            b"",
            b'1',
            b"my-toolset/TOOLSET.md\0",
        ),
    ]);
    let gz_bytes = gzip(&ar);

    let err = install_expecting_err(
        "my-toolset",
        "1.0.0",
        &gz_bytes,
        &sk,
        &pk,
        &trust_path,
        &toolsets_root,
    );
    assert!(
        matches!(err, ToolsetInstallError::ArchiveDisallowedEntryType),
        "expected ArchiveDisallowedEntryType for hardlink, got: {err:?}"
    );
}

// ── 5. FIFO entry ─────────────────────────────────────────────────────────────

#[test]
fn fifo_entry_rejected() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Raw tar with a FIFO entry (type b'6').
    let ar = make_raw_tar(&[
        (b"my-toolset/\0", b"", b'5', b""),
        (b"my-toolset/fifo\0", b"", b'6', b""),
    ]);
    let gz_bytes = gzip(&ar);

    let err = install_expecting_err(
        "my-toolset",
        "1.0.0",
        &gz_bytes,
        &sk,
        &pk,
        &trust_path,
        &toolsets_root,
    );
    assert!(
        matches!(err, ToolsetInstallError::ArchiveDisallowedEntryType),
        "expected ArchiveDisallowedEntryType for FIFO, got: {err:?}"
    );
}

// ── 6. Zero-entry archive ─────────────────────────────────────────────────────

#[test]
fn zero_entry_archive_rejected() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Empty tar (just end-of-archive blocks).
    let ar = vec![0u8; 1024];
    let gz_bytes = gzip(&ar);

    let err = install_expecting_err(
        "my-toolset",
        "1.0.0",
        &gz_bytes,
        &sk,
        &pk,
        &trust_path,
        &toolsets_root,
    );
    assert!(
        matches!(err, ToolsetInstallError::ArchiveBadTopLevel { .. }),
        "expected ArchiveBadTopLevel for empty archive, got: {err:?}"
    );
}

// ── 7. Wrong top-level directory name ─────────────────────────────────────────

#[test]
fn wrong_top_level_dir_rejected() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Archive has "other-toolset/" as top level but package is "my-toolset".
    let pkg_bytes = make_valid_tar_gz("other-toolset", &minimal_toolset_md("other-toolset"));
    let err = install_expecting_err(
        "my-toolset",
        "1.0.0",
        &pkg_bytes,
        &sk,
        &pk,
        &trust_path,
        &toolsets_root,
    );
    assert!(
        matches!(err, ToolsetInstallError::ArchiveBadTopLevel { .. }),
        "expected ArchiveBadTopLevel, got: {err:?}"
    );
}

// ── 8. Over-count ─────────────────────────────────────────────────────────────

#[test]
fn over_count_archive_rejected() {
    use stellar_agent_toolsets_install::MAX_ENTRIES;

    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Build a tar with > MAX_ENTRIES entries.
    let mut ar_entries: Vec<(Vec<u8>, Vec<u8>, u8, Vec<u8>)> = Vec::new();
    ar_entries.push((b"my-toolset/".to_vec(), b"".to_vec(), b'5', b"".to_vec()));
    for i in 0..=(MAX_ENTRIES + 4) {
        let name = format!("my-toolset/file{i:05}.txt\0");
        ar_entries.push((name.into_bytes(), b"x".to_vec(), b'0', b"".to_vec()));
    }

    let mut ar = Vec::new();
    for (name, content, type_flag, link_name) in &ar_entries {
        ar.extend_from_slice(&tar_header(name, content.len(), *type_flag, link_name));
        if !content.is_empty() {
            ar.extend_from_slice(&pad_to_512(content));
        }
    }
    ar.extend(vec![0u8; 1024]);
    let gz_bytes = gzip(&ar);

    let err = install_expecting_err(
        "my-toolset",
        "1.0.0",
        &gz_bytes,
        &sk,
        &pk,
        &trust_path,
        &toolsets_root,
    );
    assert!(
        matches!(err, ToolsetInstallError::ArchiveTooManyEntries { .. }),
        "expected ArchiveTooManyEntries, got: {err:?}"
    );
}

// ── 9. NFC/case collision ─────────────────────────────────────────────────────

#[test]
fn case_collision_rejected() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Two entries that differ only in case.
    let ar = make_raw_tar(&[
        (b"my-toolset/\0", b"", b'5', b""),
        (b"my-toolset/readme.txt\0", b"text", b'0', b""),
        (b"my-toolset/README.txt\0", b"text", b'0', b""),
    ]);
    let gz_bytes = gzip(&ar);

    let err = install_expecting_err(
        "my-toolset",
        "1.0.0",
        &gz_bytes,
        &sk,
        &pk,
        &trust_path,
        &toolsets_root,
    );
    assert!(
        matches!(err, ToolsetInstallError::ArchiveDuplicateEntry { .. }),
        "expected ArchiveDuplicateEntry for case collision, got: {err:?}"
    );
}

// ── 10. Package too large ─────────────────────────────────────────────────────

#[test]
fn package_too_large_rejected() {
    use stellar_agent_toolsets_install::MAX_PACKAGE_BYTES;

    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    let big = vec![0u8; MAX_PACKAGE_BYTES + 1];
    let shasum = sha256_hex(&big);
    let preimage = build_preimage("my-toolset", "1.0.0", &shasum);
    let sig: [u8; 64] = sk.sign(&preimage).to_bytes();
    let opts = InstallOptions::default();

    let err = install_no_attestation(
        "my-toolset",
        "1.0.0",
        &big,
        &shasum,
        &sig,
        &pk,
        &toolsets_root,
        &trust_path,
        &opts,
    )
    .unwrap_err();

    assert!(
        matches!(err, ToolsetInstallError::PackageTooLarge { .. }),
        "expected PackageTooLarge, got: {err:?}"
    );
}

// ── 11. Hash mismatch ─────────────────────────────────────────────────────────

#[test]
fn hash_mismatch_rejected() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    let pkg_bytes = make_valid_tar_gz("my-toolset", &minimal_toolset_md("my-toolset"));
    let wrong_shasum = "b".repeat(64);
    let preimage = build_preimage("my-toolset", "1.0.0", &wrong_shasum);
    let sig: [u8; 64] = sk.sign(&preimage).to_bytes();
    let opts = InstallOptions::default();

    let err = install_no_attestation(
        "my-toolset",
        "1.0.0",
        &pkg_bytes,
        &wrong_shasum,
        &sig,
        &pk,
        &toolsets_root,
        &trust_path,
        &opts,
    )
    .unwrap_err();

    assert!(
        matches!(err, ToolsetInstallError::HashMismatch),
        "expected HashMismatch, got: {err:?}"
    );
}

// ── 12. Untrusted publisher ───────────────────────────────────────────────────

#[test]
fn untrusted_publisher_rejected() {
    let (sk, _pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    let _ = sk;
    let other_seed = [0xCDu8; 32];
    let other_sk = SigningKey::from_bytes(&other_seed);
    let other_pk = other_sk.verifying_key().to_bytes();

    let pkg_bytes = make_valid_tar_gz("my-toolset", &minimal_toolset_md("my-toolset"));
    let (sig, shasum) = sign_package("my-toolset", "1.0.0", &pkg_bytes, &other_sk);
    let opts = InstallOptions::default();

    let err = install_no_attestation(
        "my-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &other_pk,
        &toolsets_root,
        &trust_path,
        &opts,
    )
    .unwrap_err();

    assert!(
        matches!(err, ToolsetInstallError::UntrustedPublisher { .. }),
        "expected UntrustedPublisher, got: {err:?}"
    );
}

// ── 13. Empty trust set ───────────────────────────────────────────────────────

#[test]
fn empty_trust_set_rejected() {
    let seed = [0xabu8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();

    let tmp = TempDir::new().unwrap();
    let trust_path = tmp.path().join("trust.txt");
    std::fs::write(&trust_path, b"# no keys here\n").unwrap();

    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    let pkg_bytes = make_valid_tar_gz("my-toolset", &minimal_toolset_md("my-toolset"));
    let (sig, shasum) = sign_package("my-toolset", "1.0.0", &pkg_bytes, &sk);
    let opts = InstallOptions::default();

    let err = install_no_attestation(
        "my-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &pk,
        &toolsets_root,
        &trust_path,
        &opts,
    )
    .unwrap_err();

    assert!(
        matches!(err, ToolsetInstallError::TrustSetEmpty),
        "expected TrustSetEmpty, got: {err:?}"
    );
}

// ── 14. Already installed ─────────────────────────────────────────────────────

#[test]
fn already_installed_without_force_rejected() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    let toolset_md = minimal_toolset_md("my-toolset");
    let pkg_bytes = make_valid_tar_gz("my-toolset", &toolset_md);
    let (sig, shasum) = sign_package("my-toolset", "1.0.0", &pkg_bytes, &sk);
    let opts = InstallOptions::default();

    install_no_attestation(
        "my-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &pk,
        &toolsets_root,
        &trust_path,
        &opts,
    )
    .unwrap();

    let err = install_no_attestation(
        "my-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &pk,
        &toolsets_root,
        &trust_path,
        &opts,
    )
    .unwrap_err();

    assert!(
        matches!(err, ToolsetInstallError::AlreadyInstalled { .. }),
        "expected AlreadyInstalled, got: {err:?}"
    );
}

// ── 15. Force reinstall succeeds ──────────────────────────────────────────────

#[test]
fn force_reinstall_same_version_succeeds() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    let toolset_md = minimal_toolset_md("my-toolset");
    let pkg_bytes = make_valid_tar_gz("my-toolset", &toolset_md);
    let (sig, shasum) = sign_package("my-toolset", "1.0.0", &pkg_bytes, &sk);

    install_no_attestation(
        "my-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &pk,
        &toolsets_root,
        &trust_path,
        &InstallOptions::default(),
    )
    .unwrap();

    install_no_attestation(
        "my-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &pk,
        &toolsets_root,
        &trust_path,
        &InstallOptions {
            force: true,
            allow_downgrade: false,
            override_attestation: false,
        },
    )
    .unwrap();
}

// ── 16. Downgrade refused without allow-downgrade ────────────────────────────

#[test]
fn downgrade_without_flag_rejected() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    let toolset_md = minimal_toolset_md("my-toolset");
    let pkg_bytes = make_valid_tar_gz("my-toolset", &toolset_md);

    let (sig2, shasum2) = sign_package("my-toolset", "2.0.0", &pkg_bytes, &sk);
    install_no_attestation(
        "my-toolset",
        "2.0.0",
        &pkg_bytes,
        &shasum2,
        &sig2,
        &pk,
        &toolsets_root,
        &trust_path,
        &InstallOptions::default(),
    )
    .unwrap();

    let (sig1, shasum1) = sign_package("my-toolset", "1.0.0", &pkg_bytes, &sk);
    let err = install_no_attestation(
        "my-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum1,
        &sig1,
        &pk,
        &toolsets_root,
        &trust_path,
        &InstallOptions {
            force: true,
            allow_downgrade: false,
            override_attestation: false,
        },
    )
    .unwrap_err();

    assert!(
        matches!(err, ToolsetInstallError::VersionDowngrade { .. }),
        "expected VersionDowngrade, got: {err:?}"
    );
}

// ── 17. Downgrade with allow-downgrade succeeds ───────────────────────────────

#[test]
fn downgrade_with_flag_allowed() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    let toolset_md = minimal_toolset_md("my-toolset");
    let pkg_bytes = make_valid_tar_gz("my-toolset", &toolset_md);

    let (sig2, shasum2) = sign_package("my-toolset", "2.0.0", &pkg_bytes, &sk);
    install_no_attestation(
        "my-toolset",
        "2.0.0",
        &pkg_bytes,
        &shasum2,
        &sig2,
        &pk,
        &toolsets_root,
        &trust_path,
        &InstallOptions::default(),
    )
    .unwrap();

    let (sig1, shasum1) = sign_package("my-toolset", "1.0.0", &pkg_bytes, &sk);
    install_no_attestation(
        "my-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum1,
        &sig1,
        &pk,
        &toolsets_root,
        &trust_path,
        &InstallOptions {
            force: true,
            allow_downgrade: true,
            override_attestation: false,
        },
    )
    .unwrap();
}

// ── 18. Uninstall removes dir and pin ─────────────────────────────────────────

#[test]
fn uninstall_removes_dir_and_pin() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    let toolset_md = minimal_toolset_md("my-toolset");
    let pkg_bytes = make_valid_tar_gz("my-toolset", &toolset_md);
    let (sig, shasum) = sign_package("my-toolset", "1.0.0", &pkg_bytes, &sk);

    install_no_attestation(
        "my-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &pk,
        &toolsets_root,
        &trust_path,
        &InstallOptions::default(),
    )
    .unwrap();

    assert!(toolsets_root.join("my-toolset").exists());
    assert!(
        toolsets_root
            .join("my-toolset")
            .join(".stellar-agent-toolset-pin.json")
            .exists()
    );

    uninstall_toolset("my-toolset", &toolsets_root).unwrap();

    assert!(!toolsets_root.join("my-toolset").exists());
}

// ── 19. Uninstall absent toolset ────────────────────────────────────────────────

#[test]
fn uninstall_absent_returns_not_installed() {
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    let err = uninstall_toolset("my-toolset", &toolsets_root).unwrap_err();
    assert!(
        matches!(err, ToolsetInstallError::NotInstalled { .. }),
        "expected NotInstalled, got: {err:?}"
    );
}

// ── 20. No-panic table: truncated / garbage inputs ────────────────────────────

#[test]
fn truncated_input_does_not_panic() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    for bad_input in &[
        b"".as_ref(),
        b"\x00\x01\x02".as_ref(),
        b"\x1f\x8b".as_ref(),
        &b"A".repeat(100) as &[u8],
    ] {
        let shasum = sha256_hex(bad_input);
        let preimage = build_preimage("my-toolset", "1.0.0", &shasum);
        let sig: [u8; 64] = sk.sign(&preimage).to_bytes();
        let opts = InstallOptions::default();
        let _ = install_no_attestation(
            "my-toolset",
            "1.0.0",
            bad_input,
            &shasum,
            &sig,
            &pk,
            &toolsets_root,
            &trust_path,
            &opts,
        );
    }
}

// ── 21. Valid install end-to-end ──────────────────────────────────────────────

#[test]
fn valid_install_end_to_end() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    let toolset_md = minimal_toolset_md("my-toolset");
    let pkg_bytes = make_valid_tar_gz("my-toolset", &toolset_md);
    let (sig, shasum) = sign_package("my-toolset", "1.0.0", &pkg_bytes, &sk);
    let opts = InstallOptions::default();

    install_no_attestation(
        "my-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &pk,
        &toolsets_root,
        &trust_path,
        &opts,
    )
    .unwrap();

    let pin_path = toolsets_root
        .join("my-toolset")
        .join(".stellar-agent-toolset-pin.json");
    assert!(
        pin_path.exists(),
        "pin record must be written after install"
    );

    let pin: stellar_agent_toolsets_install::ToolsetPinRecord =
        serde_json::from_str(&std::fs::read_to_string(&pin_path).unwrap()).unwrap();
    assert_eq!(pin.package, "my-toolset");
    assert_eq!(pin.version, "1.0.0");
    assert_eq!(pin.shasum, shasum);

    // The pin must record the SHA-256 of the extracted TOOLSET.md so the dispatch
    // path can detect later manifest tampering.  Assert it is present and equals
    // the digest of the bytes actually on disk (not None, not a stale value).
    let on_disk_toolset_md =
        std::fs::read(toolsets_root.join("my-toolset").join("TOOLSET.md")).unwrap();
    let expected_toolset_md_shasum = {
        let mut h = Sha256::new();
        h.update(&on_disk_toolset_md);
        hex::encode(h.finalize())
    };
    assert_eq!(
        pin.toolset_md_shasum,
        Some(expected_toolset_md_shasum),
        "pin must record the SHA-256 of the extracted TOOLSET.md for tamper detection"
    );
}

// ── 22. Multi-member gzip rejected as ArchiveTrailingData ─────────────────────
// Verifies that a two-member concatenated gzip is rejected as ArchiveTrailingData.
// The fix uses `flate2::bufread::GzDecoder` whose `into_inner()` correctly
// positions the cursor at the byte after the first member's footer, unlike
// `read::GzDecoder` which silently accepted multi-member archives.

#[test]
fn two_member_gzip_rejected_as_trailing_data() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Build a valid first member (real tar.gz of the package).
    let first_member = make_valid_tar_gz("my-toolset", &minimal_toolset_md("my-toolset"));
    // Build a second gzip member (a minimal valid gzip of the same content).
    let second_member = gzip(b"second member data");

    // Concatenate: first || second (standard gzip multi-member format).
    let mut two_member = first_member.clone();
    two_member.extend_from_slice(&second_member);

    let err = install_expecting_err(
        "my-toolset",
        "1.0.0",
        &two_member,
        &sk,
        &pk,
        &trust_path,
        &toolsets_root,
    );
    assert!(
        matches!(err, ToolsetInstallError::ArchiveTrailingData),
        "expected ArchiveTrailingData for two-member gzip, got: {err:?}"
    );
}

// ── 23. Trailing non-magic garbage after gzip rejected ────────────────────────
// A valid gzip member followed by non-gzip-magic garbage bytes.
// Any non-zero trailing byte after the first gzip member is rejected.

#[test]
fn non_magic_trailing_garbage_rejected_as_trailing_data() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    let mut pkg = make_valid_tar_gz("my-toolset", &minimal_toolset_md("my-toolset"));
    // Append non-magic garbage (not a gzip header).
    pkg.extend_from_slice(b"\xDE\xAD\xBE\xEF\x42\x00\x00\x00");

    let err = install_expecting_err(
        "my-toolset",
        "1.0.0",
        &pkg,
        &sk,
        &pk,
        &trust_path,
        &toolsets_root,
    );
    assert!(
        matches!(err, ToolsetInstallError::ArchiveTrailingData),
        "expected ArchiveTrailingData for trailing garbage, got: {err:?}"
    );
}

// ── 24. Decompression bomb (per-entry size cap) ───────────────────────────────

#[test]
fn decompression_bomb_per_entry_rejected() {
    use stellar_agent_toolsets_install::MAX_ENTRY_BYTES;

    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Build a tar with a single file > MAX_ENTRY_BYTES.
    // We build raw bytes to avoid the tar builder's own limit.
    let big_content = vec![b'A'; MAX_ENTRY_BYTES + 1];
    let ar = make_raw_tar(&[
        (b"my-toolset/\0", b"", b'5', b""),
        (b"my-toolset/big.txt\0", big_content.as_slice(), b'0', b""),
    ]);
    let gz_bytes = gzip(&ar);

    let err = install_expecting_err(
        "my-toolset",
        "1.0.0",
        &gz_bytes,
        &sk,
        &pk,
        &trust_path,
        &toolsets_root,
    );
    assert!(
        matches!(
            err,
            ToolsetInstallError::ArchiveEntryTooLarge { .. }
                | ToolsetInstallError::ArchiveTooLarge { .. }
        ),
        "expected ArchiveEntryTooLarge or ArchiveTooLarge for bomb entry, got: {err:?}"
    );
}

// ── 25. Top-level regular file rejected as ArchiveBadTopLevel ─────────────────
// A top-level regular file named `package` is rejected as ArchiveBadTopLevel.

#[test]
fn top_level_regular_file_rejected() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Build a tar where the top-level entry is a regular file, not a dir.
    let ar = make_raw_tar(&[(b"my-toolset\0", b"file content", b'0', b"")]);
    let gz_bytes = gzip(&ar);

    let err = install_expecting_err(
        "my-toolset",
        "1.0.0",
        &gz_bytes,
        &sk,
        &pk,
        &trust_path,
        &toolsets_root,
    );
    assert!(
        matches!(err, ToolsetInstallError::ArchiveBadTopLevel { .. }),
        "expected ArchiveBadTopLevel for top-level regular file, got: {err:?}"
    );
}

// ── 26. Malformed TOOLSET.md is rolled back (no partial install) ────────────────

#[test]
fn malformed_toolset_md_rolled_back_no_partial_install() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Build a tar with a TOOLSET.md that will fail to parse.
    let bad_toolset_md = "not yaml frontmatter at all\n---\n";
    let pkg_bytes = make_valid_tar_gz("my-toolset", bad_toolset_md);
    let err = install_expecting_err(
        "my-toolset",
        "1.0.0",
        &pkg_bytes,
        &sk,
        &pk,
        &trust_path,
        &toolsets_root,
    );
    assert!(
        matches!(err, ToolsetInstallError::ToolsetFormat(..)),
        "expected ToolsetFormat, got: {err:?}"
    );
    // Verify no partial install: toolsets_root/my-toolset must NOT exist.
    assert!(
        !toolsets_root.join("my-toolset").exists(),
        "partial install found after ToolsetFormat error; staging was not rolled back"
    );
}

// ── 27. Device-type entries rejected ─────────────────────────────────────────

#[test]
fn char_device_entry_rejected() {
    let (sk, pk, trust_path, tmp) = make_trust_setup();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Type b'3' = Char device.
    let ar = make_raw_tar(&[
        (b"my-toolset/\0", b"", b'5', b""),
        (b"my-toolset/dev\0", b"", b'3', b""),
    ]);
    let gz_bytes = gzip(&ar);

    let err = install_expecting_err(
        "my-toolset",
        "1.0.0",
        &gz_bytes,
        &sk,
        &pk,
        &trust_path,
        &toolsets_root,
    );
    assert!(
        matches!(err, ToolsetInstallError::ArchiveDisallowedEntryType),
        "expected ArchiveDisallowedEntryType for char device, got: {err:?}"
    );
}

// ── 28. Uninstall with symlink toolset dir refuses ──────────────────────────────

#[cfg(unix)]
#[test]
fn uninstall_with_symlink_toolset_dir_refuses() {
    use stellar_agent_toolsets_install::uninstall_toolset;

    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Create a legitimate directory somewhere else.
    let real_dir = tmp.path().join("real-toolset-dir");
    std::fs::create_dir_all(&real_dir).unwrap();

    // Place a symlink at toolsets_root/my-toolset → real-toolset-dir.
    let symlink_path = toolsets_root.join("my-toolset");
    std::os::unix::fs::symlink(&real_dir, &symlink_path).unwrap();

    // Write a pin record (directly, bypassing the install flow).
    // ToolsetPinRecord is #[non_exhaustive]; construct via JSON serialisation.
    let pkg_dir = toolsets_root.join("my-toolset");
    // The pin path is inside the symlink destination, but we write via the link.
    std::fs::create_dir_all(&pkg_dir).unwrap(); // creates inside real_dir via symlink
    let pin_json = serde_json::json!({
        "package": "my-toolset",
        "version": "1.0.0",
        "shasum": "a".repeat(64),
        "publisher": "GABCDEFG...",
        "installed_at": "2026-06-01T00:00:00Z"
    });
    let pin_path = pkg_dir.join(".stellar-agent-toolset-pin.json");
    std::fs::write(&pin_path, serde_json::to_string(&pin_json).unwrap()).unwrap();

    // Uninstall must refuse (symlink leaf on toolset dir).
    let err = uninstall_toolset("my-toolset", &toolsets_root).unwrap_err();
    assert!(
        matches!(err, ToolsetInstallError::PinRecordMalformed { .. }),
        "expected PinRecordMalformed for symlink toolset dir, got: {err:?}"
    );

    // The real directory must still exist (no deletion through symlink).
    assert!(real_dir.exists(), "real dir must not have been removed");
}
