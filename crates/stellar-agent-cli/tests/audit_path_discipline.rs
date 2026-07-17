//! Source-scan regression tests for the audit-writer `(path, key)`
//! discipline.
//!
//! `AuditWriterRegistry` pins one `(path, hmac_key)` pair per profile name
//! for the process lifetime: the first open wins, and any later open with a
//! divergent pair fails (`PathMismatch`/`HmacKeyMismatch`), bricking audit
//! acquisition for that profile name until the process restarts. Every
//! production call site must therefore register the profile's configured
//! `audit_log_path` under the profile's audit chain-root key discipline —
//! never a name-derived default path.

#![allow(clippy::expect_used, clippy::panic, reason = "test-only")]

fn production_half(source: &str) -> &str {
    source.split("#[cfg(test)]").next().unwrap_or(source)
}

fn walk(dir: &std::path::Path, needle: &str, hits: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            walk(&path, needle, hits);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let source = std::fs::read_to_string(&path).expect("read source");
            if production_half(&source).contains(needle) {
                hits.push((path.display().to_string(), source));
            }
        }
    }
}

/// Every production `AuditWriterRegistry::get_or_open` call site registers
/// the profile's configured `audit_log_path`. A new call site in a file
/// outside the allow-set fails this test until its discipline is verified
/// and the file is added here.
#[test]
fn every_audit_writer_open_registers_the_profile_path() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits = Vec::new();
    walk(&src, "AuditWriterRegistry::get_or_open", &mut hits);

    assert!(
        !hits.is_empty(),
        "expected at least the value_audit.rs call sites"
    );

    const ALLOWED: &[&str] = &[
        "commands/value_audit.rs",
        "commands/profile/audit_emit.rs",
        "commands/accounts/deploy_c.rs",
        "commands/credentials/add_passkey.rs",
    ];

    for (path, source) in &hits {
        let production = production_half(source);
        assert!(
            ALLOWED.iter().any(|suffix| path.ends_with(suffix)),
            "{path}: unexpected AuditWriterRegistry::get_or_open call site — register \
             profile.audit_log_path (or route through the value_audit helpers) and add \
             the file to this test's allow-set"
        );
        assert!(
            production.contains("&profile.audit_log_path"),
            "{path}: every open must register the profile's configured audit_log_path"
        );
        assert!(
            !production.contains("default_audit_log_path_for("),
            "{path}: production code must not register a name-derived default path"
        );
    }
}

/// The only production caller of `default_audit_log_path_for` in this crate
/// is the startup advisory in main.rs, which READS the per-profile default
/// location without a loaded profile and never registers a writer for a
/// real profile name.
#[test]
fn default_path_derivation_is_confined_to_the_startup_advisory() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits = Vec::new();
    walk(&src, "default_audit_log_path_for(", &mut hits);

    for (path, _source) in &hits {
        assert!(
            path.ends_with("src/main.rs"),
            "{path}: default_audit_log_path_for must not be used outside the startup \
             advisory — commands resolve the audit path from the loaded profile"
        );
    }
}

/// The two on-chain smart-account signing verbs acquire the audit writer as
/// a fail-closed PRE-FLIGHT: the acquisition must appear before the signing
/// key is loaded and before the submit call in each source file.
#[test]
fn signing_verbs_acquire_the_writer_before_submit() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    for (file, signer_load, submit_call) in [
        (
            "commands/smart_account/execute.rs",
            "resolve_software_signer_from_env(",
            "submit_signed_invoke(",
        ),
        (
            "commands/smart_account/multicall.rs",
            "resolve_signer(",
            "submit_multicall_bundle(",
        ),
    ] {
        let source = std::fs::read_to_string(src.join(file)).expect("read source");
        let production = production_half(&source);
        let acquire = production
            .find("open_profile_audit_writer(")
            .unwrap_or_else(|| panic!("{file}: missing the audit pre-flight"));
        let signer = production
            .find(signer_load)
            .unwrap_or_else(|| panic!("{file}: missing the signer load"));
        let submit = production
            .find(submit_call)
            .unwrap_or_else(|| panic!("{file}: missing the submit call"));
        assert!(
            acquire < signer,
            "{file}: the audit writer must be acquired BEFORE the signing key \
             is loaded (fail-closed pre-flight)"
        );
        assert!(
            acquire < submit,
            "{file}: the audit writer must be acquired BEFORE the submit call \
             (fail-closed pre-flight), not after"
        );
    }
}
