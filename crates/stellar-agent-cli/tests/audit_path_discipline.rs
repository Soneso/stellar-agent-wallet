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

/// No production code in this crate derives an audit-log path from a profile
/// name. Every reader, the startup advisory included, takes the path from the
/// loaded profile's `audit_log_path`, so a profile configuring a non-default
/// location is scanned and written at that location only.
#[test]
fn no_production_code_derives_the_default_audit_path() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits = Vec::new();
    walk(&src, "default_audit_log_path_for(", &mut hits);

    let paths: Vec<&str> = hits.iter().map(|(path, _)| path.as_str()).collect();
    assert!(
        paths.is_empty(),
        "default_audit_log_path_for must not be called from production code; resolve \
         the audit path from the loaded profile. Call sites: {paths:?}"
    );
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

/// Deny-first ordering: on every reordered value verb, the operator policy
/// gate runs BEFORE the audit pre-flight (a policy denial is a clean refusal
/// that signs and submits nothing, so it must not require a minted audit
/// chain key), and the pre-flight still precedes the stage's signing step.
///
/// EVERY pre-flight call site is checked: for each occurrence (staged files
/// have several — sign-only, submit-only, full pipeline), a policy-eval CALL
/// (definitions excluded) must appear between the previous pre-flight and
/// this one, and a signing step must follow it before the next pre-flight.
#[test]
fn value_verbs_evaluate_policy_before_the_audit_preflight() {
    fn call_indices(hay: &str, needles: &[&str]) -> Vec<usize> {
        let mut out = Vec::new();
        for needle in needles {
            let mut at = 0;
            while let Some(rel) = hay[at..].find(needle) {
                let i = at + rel;
                // Exclude fn definitions and rustdoc mentions.
                let prefix = &hay[..i];
                if !prefix.ends_with("fn ") && !prefix.ends_with("async fn ") {
                    let line_start = prefix.rfind('\n').map_or(0, |p| p + 1);
                    if !hay[line_start..i].trim_start().starts_with("///")
                        && !hay[line_start..i].trim_start().starts_with("//")
                    {
                        out.push(i);
                    }
                }
                at = i + needle.len();
            }
        }
        out.sort_unstable();
        out
    }

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    for (file, policy_calls, preflight_calls, sign_calls) in [
        (
            "commands/pay.rs",
            &["evaluate_pay_policy(", "evaluate_staged_pay_policy("][..],
            &["value_audit::require_value_audit_writer_for_origin("][..],
            &["sign_envelope(", "submit_envelope("][..],
        ),
        (
            "commands/claim.rs",
            &["evaluate_claim_policy(", "evaluate_staged_claim_policy("][..],
            &["value_audit::require_value_audit_writer_for_origin("][..],
            &["sign_envelope(", "submit_envelope("][..],
        ),
        (
            "commands/trustline.rs",
            &["evaluate_value_moving_policy("][..],
            &["value_audit::require_value_audit_writer("][..],
            &["signer_from_keyring("][..],
        ),
        (
            "commands/accounts/create.rs",
            &["evaluate_create_policy("][..],
            &["value_audit::require_value_audit_writer_for_origin("][..],
            &["sponsored_create("][..],
        ),
    ] {
        let source = std::fs::read_to_string(src.join(file)).expect("read source");
        let production = production_half(&source);
        let policies = call_indices(production, policy_calls);
        let preflights = call_indices(production, preflight_calls);
        let signs = call_indices(production, sign_calls);
        assert!(
            !preflights.is_empty(),
            "{file}: no audit pre-flight call found"
        );

        let mut prev_preflight = 0usize;
        for &preflight in &preflights {
            assert!(
                policies
                    .iter()
                    .any(|&p| p > prev_preflight && p < preflight),
                "{file}: the pre-flight at byte {preflight} has no policy-eval \
                 call in its own stage before it (deny-first violated)"
            );
            assert!(
                signs.iter().any(|&s| s > preflight),
                "{file}: the pre-flight at byte {preflight} has no signing \
                 step after it"
            );
            prev_preflight = preflight;
        }
    }
}

/// The two `tx` verbs acquire the audit writer the same way the value verbs
/// do: fail-closed on a persisted profile, best-effort on the synthesized one.
///
/// A submission on a zero-config profile leaves a receipt holding its source
/// account's sequence. If the verbs that settle it refused on a profile with
/// no audit key, that hold would have nothing able to free it and every later
/// payment from that account would be refused as a duplicate.
#[test]
fn the_tx_verbs_acquire_the_audit_writer_by_profile_origin() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for file in ["commands/tx/status.rs", "commands/tx/receipt.rs"] {
        // The Windows checkout is CRLF; the scan is substring-based, so the
        // normalisation only keeps the reported source readable.
        let source = std::fs::read_to_string(src.join(file))
            .expect("read source")
            .replace("\r\n", "\n");
        assert!(
            source.contains("value_audit::require_value_audit_writer_for_origin("),
            "{file}: the audit writer must be acquired by profile origin"
        );
        assert!(
            source.contains("load_profile_or_synthesize_testnet("),
            "{file}: the profile must be resolved the way the value verbs resolve it"
        );
    }
}
