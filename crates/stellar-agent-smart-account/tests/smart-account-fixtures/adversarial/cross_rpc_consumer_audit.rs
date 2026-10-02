//! Adversarial fixture: `cross_rpc_consumer_audit`.
//!
//! Compile-asserted enumeration of cross-RPC divergence primitive consumers.
//! Adding a new cross-RPC call site (one that emits
//! `SaError::NetworkRpcDivergence`) REQUIRES updating
//! `CROSS_RPC_CONSUMER_SITES` below, which forces operator review of the
//! new security-edge code path.
//!
//! # Security coverage
//!
//! The cross-RPC divergence primitive must be consumed by BOTH the
//! signer-set divergence detection AND the wasm-hash drift detection paths
//! (different ledger-entry key shapes — C-account signer-set storage vs
//! verifier-contract instance-storage). A single divergent-secondary fixture
//! targeting one key shape only catches one consumer. This audit fixture
//! enumerates ALL consumers + regression-locks via source-grep, so
//! adding a new cross-RPC consumer (e.g., `timelock::list_pending`) MUST
//! update the canonical list here.
//!
//! # Coverage relationship to existing per-consumer fixtures
//!
//! The per-consumer divergent-secondary-RPC fixtures cover the individual
//! consumers in isolation:
//! - `signer_set_divergence_rpc_suppression.rs` and
//!   `rpc_divergence_before.rs`: the signer-set observation's rule
//!   disagreement (`signer_set_rpc_divergence`). Mock tests in
//!   `tests/execute_path_drift_check_mock.rs` pin its other disagreements:
//!   the policy list
//!   (`the_endpoints_disagreeing_on_the_policy_list_refuse_with_rpc_divergence`),
//!   the simple-threshold value
//!   (`the_endpoints_disagreeing_on_the_threshold_refuse_with_rpc_divergence`)
//!   and the rule after a repeated observation
//!   (`endpoints_that_disagree_after_a_repeated_observation_refuse_at_stage_observe`).
//! - `verifier_drift_rpc_suppression.rs` — wasm-hash drift consumer.
//! - `verifier_identification_rpc_divergence.rs` +
//!   `threshold_policy_identification_rpc_divergence.rs`: the executable
//!   read of a verifier or a policy (`fetch_observed_executable`).
//!
//! This audit fixture adds a source-grep regression-lock that catches
//! a future cross-RPC consumer added without a corresponding
//! divergent-secondary-RPC adversarial fixture. It is materially stronger
//! than `cargo expand` because it surfaces in regular `cargo test` and
//! forces explicit list updates.
//!
//! # Invariant
//!
//! The cross-RPC divergence primitive is shared by all enumerated consumers.
//! Every consumer must construct `SaError::NetworkRpcDivergence` to signal
//! that responses from the two RPC endpoints disagree.

use std::fs;
use std::path::{Path, PathBuf};

/// Canonical list of cross-RPC divergence primitive consumer call sites.
///
/// Each entry is `(file_path, fn_name)` identifying a function that
/// constructs a `SaError::NetworkRpcDivergence`. Adding a new cross-RPC
/// consumer REQUIRES adding an entry here AND adding a per-consumer
/// divergent-secondary-RPC adversarial fixture.
const CROSS_RPC_CONSUMER_SITES: &[(&str, &str)] = &[
    // Signer-set observation: 1 consumer in signers.rs. Every disagreement of
    // the observation (the two endpoints' rules, including their policy
    // lists, and their thresholds) is built by this one helper, which
    // `list_signers`, `refresh_signer_baseline`,
    // `verify_signer_set_against_chain` and the signer verbs reach through
    // `observe_signer_set_v2`.
    (
        "crates/stellar-agent-smart-account/src/managers/signers.rs",
        "signer_set_rpc_divergence",
    ),
    // Spending-limit-policy identification: 1 consumer in signers.rs;
    // a two-RPC wasm-hash agreement check against a single-entry allowlist.
    (
        "crates/stellar-agent-smart-account/src/managers/signers.rs",
        "identify_spending_limit_policy",
    ),
    // Weighted-threshold-policy identification: 1 consumer in signers.rs;
    // mirrors identify_spending_limit_policy's two-RPC wasm-hash agreement
    // check against a single-entry allowlist.
    (
        "crates/stellar-agent-smart-account/src/managers/signers.rs",
        "identify_weighted_threshold_policy",
    ),
    // Executable identification and drift detection; 1 consumer in signers.rs
    (
        "crates/stellar-agent-smart-account/src/managers/signers.rs",
        "fetch_observed_executable",
    ),
    // Contract mutability detection — 1 consumer in verifiers.rs
    (
        "crates/stellar-agent-smart-account/src/managers/verifiers.rs",
        "detect_contract_mutability",
    ),
    // Timelock ready-window race guard.
    // query_operation_state_cross_rpc is called
    // from both `execute()` (pre-submit guard) and `list_pending()` (state validation).
    (
        "crates/stellar-agent-smart-account/src/timelock.rs",
        "query_operation_state_cross_rpc",
    ),
    // Dual-RPC defence-in-depth for event confirmation.
    // cross_confirm_event requires the expected OZ
    // ContractEvent (OperationScheduled / OperationCancelled / OperationExecuted) be
    // present in BOTH RPC getTransaction meta responses. Mismatch → NetworkRpcDivergence.
    (
        "crates/stellar-agent-smart-account/src/timelock.rs",
        "cross_confirm_event",
    ),
    // Dual-RPC defence-in-depth for hash_operation simulate.
    // simulate_hash_operation simulates hash_operation on
    // both RPCs and asserts byte-identical hashes. Mismatch → NetworkRpcDivergence.
    (
        "crates/stellar-agent-smart-account/src/timelock.rs",
        "simulate_hash_operation",
    ),
];

/// Walks the workspace root by ascending from `CARGO_MANIFEST_DIR` until
/// the workspace `Cargo.toml` is found. Used to anchor source-file paths
/// for the audit grep below.
fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = p.join("Cargo.toml");
        if let Ok(contents) = fs::read_to_string(&candidate)
            && contents.lines().any(|l| l.trim() == "[workspace]")
        {
            // Line-anchored match — substring `[workspace]`
            // also matches `[workspace.metadata]` / `[workspace.dependencies]` /
            // `[workspace.package]` and could halt the ascent at the wrong dir if a
            // member crate ever gains a `[workspace.*]` table.
            return p;
        }
        if !p.pop() {
            panic!("workspace Cargo.toml not found from CARGO_MANIFEST_DIR ascent");
        }
    }
}

/// Counts source-line occurrences of the `SaError::NetworkRpcDivergence`
/// variant constructor in `file_path` relative to workspace root, reading
/// the lines before the file's `#[cfg(test)]` unit-test module. Filters
/// out rustdoc + line-comment + string-literal-looking lines to avoid
/// false positives on the doc-link form `[`SaError::NetworkRpcDivergence`]`.
///
/// The broader `SaError::NetworkRpcDivergence` match catches all constructor
/// patterns:
/// (a) `Err(SaError::NetworkRpcDivergence{..}.into())` returned via `?`,
/// (b) `let err = SaError::NetworkRpcDivergence{..}; return Err(err);`,
/// (c) `bail!(SaError::NetworkRpcDivergence{..})` if `thiserror` macros
/// are later adopted.
/// The comment-line prefilter avoids rustdoc false positives.
fn count_emit_sites(workspace: &Path, file_path: &str) -> usize {
    let full = workspace.join(file_path);
    let contents =
        fs::read_to_string(&full).unwrap_or_else(|e| panic!("read {full:?} failed: {e}"));
    let lines: Vec<_> = contents.lines().collect();
    lines[..test_module_cut(&lines)]
        .iter()
        .filter(|line| {
            let trimmed = line.trim_start();
            // Skip rustdoc + line comments + block-comment continuations.
            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                return false;
            }
            // Constructor-shape match: variant + opening brace, AND the
            // closing brace is on a DIFFERENT line. Real emit sites are
            // multi-line struct expressions; destructuring patterns
            // (`Err(SaError::NetworkRpcDivergence { rule_id: 1, .. })`) and
            // the doc-link form (`[SaError::NetworkRpcDivergence]`) close
            // on the same line and are filtered out.
            line.contains("SaError::NetworkRpcDivergence {")
                && !line.contains("})")
                && !line.contains(", ..")
        })
        .count()
}

/// The last in-file test module bounds production text, matching
/// `.github/scripts/check-no-direct-sasignersetbaselined-emit.sh`.
fn test_module_cut(lines: &[&str]) -> usize {
    lines
        .iter()
        .enumerate()
        .rfind(|(index, line)| {
            if **line != "#[cfg(test)]" {
                return false;
            }
            let mut following = lines[index + 1..].iter().copied();
            let mut next = following.next();
            while next.is_some_and(|line| line.starts_with("#[allow(")) {
                while next.is_some_and(|line| !line.trim_end().ends_with(")]")) {
                    next = following.next();
                }
                next = following.next();
            }
            next.is_some_and(|line| {
                let declaration = line
                    .strip_prefix("pub(crate) ")
                    .or_else(|| line.strip_prefix("pub "))
                    .unwrap_or(line);
                declaration
                    .strip_prefix("mod ")
                    .and_then(|tail| tail.split_once(" {"))
                    .is_some_and(|(name, _)| {
                        !name.is_empty()
                            && name
                                .bytes()
                                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                    })
            })
        })
        .map_or(lines.len(), |(index, _)| index)
}

#[test]
fn cross_rpc_consumer_after_cfg_test_item_is_scanned() {
    let workspace = tempfile::tempdir().expect("fixture directory");
    for item in [
        "static TEST_FLAG: bool = true;",
        "fn test_helper() {}",
        "use std::sync::Mutex;",
    ] {
        let source = format!(
            "#[cfg(test)]\n{item}\n\
             fn production_consumer() {{\n\
                 let error = SaError::NetworkRpcDivergence {{\n\
                     rule_id: 1,\n\
                 }};\n\
             }}\n\
             #[cfg(test)]\n\
             mod tests {{}}\n"
        );
        fs::write(workspace.path().join("fixture.rs"), source).expect("fixture source");
        assert_eq!(
            count_emit_sites(workspace.path(), "fixture.rs"),
            1,
            "production consumer after cfg(test) item must be scanned: {item}"
        );
    }
}

#[test]
fn cross_rpc_consumer_in_final_test_module_is_not_scanned() {
    let workspace = tempfile::tempdir().expect("fixture directory");
    for attributes in [
        "",
        "#[allow(dead_code)]\n",
        "#[allow(\n    dead_code,\n)]\n#[allow(unused_imports)]\n",
    ] {
        let source = format!(
            "fn production() {{}}\n\
             #[cfg(test)]\n{attributes}\
             mod checks {{\n\
                 fn test_pattern() {{\n\
                     let SaError::NetworkRpcDivergence {{\n\
                         rule_id, ..\n\
                     }} = error;\n\
                 }}\n\
             }}\n"
        );
        fs::write(workspace.path().join("fixture.rs"), source).expect("fixture source");
        assert_eq!(
            count_emit_sites(workspace.path(), "fixture.rs"),
            0,
            "final test module must be excluded with attributes: {attributes}"
        );
    }
}

#[test]
fn cross_rpc_consumer_between_test_modules_is_scanned() {
    let workspace = tempfile::tempdir().expect("fixture directory");
    let source = "#[cfg(test)]\n\
                  mod early {}\n\
                  fn production_consumer() {\n\
                      let error = SaError::NetworkRpcDivergence {\n\
                          rule_id: 1,\n\
                      };\n\
                  }\n\
                  #[cfg(test)]\n\
                  mod tests {\n\
                      fn test_consumer() {\n\
                          let error = SaError::NetworkRpcDivergence {\n\
                              rule_id: 2,\n\
                          };\n\
                      }\n\
                  }\n";
    let lines: Vec<_> = source.lines().collect();
    let final_module = lines
        .iter()
        .position(|line| *line == "mod tests {")
        .expect("final test module");
    assert_eq!(
        test_module_cut(&lines),
        final_module - 1,
        "the cut must land at the final test module's cfg(test) attribute"
    );
    fs::write(workspace.path().join("fixture.rs"), source).expect("fixture source");
    assert_eq!(
        count_emit_sites(workspace.path(), "fixture.rs"),
        1,
        "the production consumer between test modules must be counted and the final module excluded"
    );
}

// ── Audit-list completeness ───────────────────────────────────────────────────

/// Asserts every cross-RPC consumer call site enumerated in
/// `CROSS_RPC_CONSUMER_SITES` matches the actual source-grep count.
///
/// There are 4 `SaError::NetworkRpcDivergence` emit sites in `signers.rs`
/// (`signer_set_rpc_divergence`, `identify_spending_limit_policy`,
/// `identify_weighted_threshold_policy`, `fetch_observed_executable`), 1 in
/// `verifiers.rs`, and 3 in `timelock.rs`
/// (`query_operation_state_cross_rpc`, `cross_confirm_event`, `simulate_hash_operation`)
/// = 8 total. The `CROSS_RPC_CONSUMER_SITES` list above MUST account for all 8.
///
/// A new cross-RPC consumer MUST add an entry here, OR this test fails.
#[test]
fn cross_rpc_consumer_audit_list_matches_source_grep() {
    let workspace = workspace_root();

    let signers_emit_count = count_emit_sites(
        &workspace,
        "crates/stellar-agent-smart-account/src/managers/signers.rs",
    );
    let verifiers_emit_count = count_emit_sites(
        &workspace,
        "crates/stellar-agent-smart-account/src/managers/verifiers.rs",
    );
    let timelock_emit_count = count_emit_sites(
        &workspace,
        "crates/stellar-agent-smart-account/src/timelock.rs",
    );

    let total_observed = signers_emit_count + verifiers_emit_count + timelock_emit_count;
    let total_canonical = CROSS_RPC_CONSUMER_SITES.len();

    assert_eq!(
        total_observed, total_canonical,
        "cross-RPC divergence primitive consumer count mismatch: \
         source-grep observed {total_observed} ({signers_emit_count} in signers.rs + \
         {verifiers_emit_count} in verifiers.rs + {timelock_emit_count} in timelock.rs) \
         vs CROSS_RPC_CONSUMER_SITES has {total_canonical}. A new consumer was added \
         without updating the canonical list at `tests/smart-account-fixtures/adversarial/\
         cross_rpc_consumer_audit.rs` — add the (file_path, fn_name) entry + \
         file a per-consumer divergent-secondary-RPC adversarial fixture.",
    );
}

/// Asserts that EVERY canonical list entry's `fn_name` actually appears
/// in the cited `file_path` (catches stale entries when a function is
/// renamed or removed).
#[test]
fn cross_rpc_consumer_audit_entries_are_not_stale() {
    let workspace = workspace_root();

    for (file_path, fn_name) in CROSS_RPC_CONSUMER_SITES {
        let full = workspace.join(file_path);
        let contents =
            fs::read_to_string(&full).unwrap_or_else(|e| panic!("read {full:?} failed: {e}"));
        // Match the function definition pattern with whitespace around the name
        // to avoid prefix-collision false positives
        // (e.g., `fn list_signers(` matches the enumerated `list_signers` but
        // NOT a hypothetical `fn list_signersx(` which carries no space-then-
        // exact-name-then-paren sequence).
        let needle_space = format!(" fn {fn_name}(");
        let needle_async = format!(" async fn {fn_name}(");
        let found = contents.lines().any(|line| {
            // Skip rustdoc / line comments / block-comment continuations to
            // avoid matching `/// see [`fn_name`]` style references.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                return false;
            }
            line.contains(&needle_space) || line.contains(&needle_async)
        });
        assert!(
            found,
            "canonical entry `{fn_name}` no longer exists in `{file_path}` — \
             function was renamed or removed; update CROSS_RPC_CONSUMER_SITES",
        );
    }
}

/// Asserts the audit list covers all three consumer families
/// (signer-set divergence, wasm-hash/mutability, timelock ready-window),
/// so a future consumer is not silently slotted into the wrong family.
/// Signer-set divergence, wasm-hash drift, AND timelock state validation
/// consumers must all be present.
#[test]
fn cross_rpc_consumer_audit_covers_both_threat_surfaces() {
    let signers_count = CROSS_RPC_CONSUMER_SITES
        .iter()
        .filter(|(file, _)| file.contains("signers.rs"))
        .count();
    let verifiers_count = CROSS_RPC_CONSUMER_SITES
        .iter()
        .filter(|(file, _)| file.contains("verifiers.rs"))
        .count();
    let timelock_count = CROSS_RPC_CONSUMER_SITES
        .iter()
        .filter(|(file, _)| file.contains("timelock.rs"))
        .count();

    assert!(
        signers_count >= 4,
        "signers.rs must have ≥4 cross-RPC consumers \
         (signer_set_rpc_divergence + identify_spending_limit_policy + \
         identify_weighted_threshold_policy + fetch_observed_executable); \
         got {signers_count}",
    );
    assert!(
        verifiers_count >= 1,
        "contract mutability detection must have ≥1 cross-RPC consumer \
         (detect_contract_mutability); got {verifiers_count}",
    );
    assert!(
        timelock_count >= 3,
        "timelock consumers must have ≥3 cross-RPC consumers \
         (query_operation_state_cross_rpc + cross_confirm_event + simulate_hash_operation); \
         got {timelock_count}",
    );

    // The fetch_observed_executable consumer (executable drift) lives in
    // signers.rs (not verifiers.rs) — so the signers_count includes it.
    let has_wasm_hash_consumer = CROSS_RPC_CONSUMER_SITES
        .iter()
        .any(|(_, fn_name)| *fn_name == "fetch_observed_executable");
    assert!(
        has_wasm_hash_consumer,
        "executable drift detection must have its `fetch_observed_executable` \
         consumer enumerated",
    );

    // The signer-set observation's consumer must be enumerated explicitly,
    // not merely covered by the >= bound above.
    let has_signer_set_consumer = CROSS_RPC_CONSUMER_SITES
        .iter()
        .any(|(_, fn_name)| *fn_name == "signer_set_rpc_divergence");
    assert!(
        has_signer_set_consumer,
        "the signer-set observation must have its `signer_set_rpc_divergence` \
         consumer enumerated",
    );

    // The spending-limit-policy identification consumer must be enumerated
    // explicitly, not merely covered by the >= bound above.
    let has_spending_limit_consumer = CROSS_RPC_CONSUMER_SITES
        .iter()
        .any(|(_, fn_name)| *fn_name == "identify_spending_limit_policy");
    assert!(
        has_spending_limit_consumer,
        "spending-limit-policy identification must have its \
         `identify_spending_limit_policy` consumer enumerated",
    );

    // The weighted-threshold-policy identification consumer must be
    // enumerated explicitly, not merely covered by the >= bound above.
    let has_weighted_threshold_consumer = CROSS_RPC_CONSUMER_SITES
        .iter()
        .any(|(_, fn_name)| *fn_name == "identify_weighted_threshold_policy");
    assert!(
        has_weighted_threshold_consumer,
        "weighted-threshold-policy identification must have its \
         `identify_weighted_threshold_policy` consumer enumerated",
    );
}
