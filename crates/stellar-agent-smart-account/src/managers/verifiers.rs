//! Verifier-contract mutability detection.
//!
//! Implements [`MutabilityStatus`] and
//! [`detect_contract_mutability`][fn@detect_contract_mutability] — the
//! off-chain helper that determines whether a deployed Soroban contract has an
//! active admin / owner storage key that would allow post-deploy code upgrades.
//!
//! # Architectural note — instance storage
//!
//! OpenZeppelin `stellar-contracts` v0.7.2 stores admin / owner roles in
//! **instance storage** (`e.storage().instance().set/get`), which Soroban
//! embeds as the `storage: Option<ScMap>` field of the
//! `ScContractInstance` value inside the contract's `LedgerKeyContractInstance`
//! ledger entry.
//!
//! Canonical sources:
//! - `packages/access/src/ownable/storage.rs:13-16` (SHA `a9c4216`) —
//!   `OwnableStorageKey::{ Owner, PendingOwner }`, stored via
//!   `e.storage().instance().get/set`.
//! - `packages/access/src/access_control/storage.rs:20-29` (SHA `a9c4216`) —
//!   `AccessControlStorageKey::Admin`, stored via `e.storage().instance().get/set`.
//! - `soroban-sdk`, `storage.rs` testutils (`Storage::instance` read-back path) —
//!   confirms that instance storage is embedded in `ScContractInstance.storage`
//!   (the `LedgerKeyContractInstance` entry's `ScContractInstance.storage` field).
//!
//! Consequence: instance-storage keys are NOT separate `LedgerKey::ContractData`
//! entries. They live inside `ScContractInstance.storage: Option<ScMap>`, which
//! is returned alongside the contract executable when fetching the instance
//! entry via `getLedgerEntries`.  The implementation therefore:
//! 1. Fetches the contract instance entry using the shared
//!    `managers::rules::contract_instance_key` helper (same constructor used by
//!    `fetch_contract_wasm_hashes` in `signers.rs`).
//! 2. Decodes `ScContractInstance.storage` as the instance-storage map.
//! 3. Searches the map for a key `ScVal::Vec([ScVal::Symbol("Admin")])` or
//!    `ScVal::Vec([ScVal::Symbol("Owner")])`.
//!
//! A `#[contracttype]` unit enum variant `Foo` serialises as
//! `ScVal::Vec(Some(ScVec([ScVal::Symbol("Foo")])))` when used as a
//! storage-map key.  The macro expands to `(ScVal::Symbol("Foo"),).try_into()`
//! (a one-element `ScVec`) at the `into_xdr` level, then wraps in
//! `ScVal::Vec(Some(...))` at the `TryFrom<Enum> for ScVal` level.
//! Confirmed from `soroban-sdk-macros` (`derive_enum.rs`):
//!
//! - `map_empty_variant` `into_xdr` arm — `let val = ScVal::Symbol(symbol);
//!   (val,).try_into()?` → `ScVec([Symbol])`.
//! - `TryFrom<&Enum> for ScVal` impl — `ScVal::Vec(Some(val.try_into()?))` wraps
//!   the `ScVec`.
//!
//! So the on-wire key for `AccessControlStorageKey::Admin` is
//! `ScVal::Vec(Some(ScVec([ScVal::Symbol("Admin")])))`, NOT a bare
//! `ScVal::Symbol("Admin")`.
//!
//! # OZ Admin / Owner survey result
//!
//! Surveyed OZ `stellar-contracts` v0.7.2 (SHA `a9c4216`):
//!
//! | Contract path | Storage key enum | Variant | On-wire `ScVal` map key |
//! |---|---|---|---|
//! | `packages/access/src/ownable/storage.rs:14` | `OwnableStorageKey` | `Owner` | `Vec([Symbol("Owner")])` |
//! | `packages/access/src/ownable/storage.rs:15` | `OwnableStorageKey` | `PendingOwner` | `Vec([Symbol("PendingOwner")])` |
//! | `packages/access/src/access_control/storage.rs:27` | `AccessControlStorageKey` | `Admin` | `Vec([Symbol("Admin")])` |
//! | `packages/access/src/access_control/storage.rs:28` | `AccessControlStorageKey` | `PendingAdmin` | `Vec([Symbol("PendingAdmin")])` |
//! | `packages/contract-utils/src/upgradeable/storage.rs:4-6` | `UpgradeableStorageKey` | `SchemaVersion` | `"SchemaVersion"` (not admin) |
//!
//! **Smart-account-adjacent contracts in `packages/accounts/`:**
//! - `threshold-policy` (example at `examples/multisig-smart-account/`): no
//!   admin / owner key. Uses only `SimpleThresholdStorageKey::AccountContext(sa, rule_id)`.
//!   Confirmed at `examples/multisig-smart-account/threshold-policy/src/contract.rs` (SHA `a9c4216`).
//! - `packages/accounts/src/smart_account/`: no top-level admin / owner key.
//!   Uses `SmartAccountStorageKey` variants (`Count`, `NextId`, `SignerData(u32)`, etc.) —
//!   confirmed at `packages/accounts/src/smart_account/storage.rs:27-94` (SHA `a9c4216`).
//!
//! **Conclusion:** canonical OZ convention is Pascal-case: `"Admin"` and `"Owner"`.
//! No `"admin"`, `"owner"`, `"Upgrader"`, `"Governance"`, or `"Pauser"` variants
//! found in smart-account-adjacent contracts. `"Upgrader"` appears only in
//! doc-comment examples of the upgradeable module, not as a stored key.
//! The heuristic covers `"Admin"` and `"Owner"` (closed-set per survey).
//! Expanding to additional names requires extending the `AdminOrOwnerKey` enum.
//!
//! # Two-RPC consultation
//!
//! Both `detect_contract_mutability` and `fetch_contract_instance_storage`
//! follow the `tokio::join!` + `NetworkRpcDivergence` pattern established in
//! `managers/signers.rs:1195-1240`.
//!

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sha2::{Digest as _, Sha256};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::health::AuditWriterHealthHandle;
use stellar_agent_core::audit_log::reader::{AuditReader, PinnedHashesRecord};
use stellar_agent_core::audit_log::schema::ContractKind;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::{RedactedStrkey, redact_strkey_first5_last5};
use stellar_agent_network::StellarRpcClient;
use stellar_xdr::{LedgerKey, ScAddress, ScVal};
use tracing::{debug, warn};

use crate::managers::rules::{
    ContextRuleDefinition, ContextRuleSignerInput, contract_instance_key,
    xdr_scaddress_to_strkey_or_sentinel,
};
use crate::managers::signers::SignersManager;
use crate::{AdminOrOwnerKey, SaError};

// ── PinResult ─────────────────────────────────────────────────────────────────

/// Output of [`pin_referenced_contracts`] for one rule.
///
/// Carries the pinned wasm hashes and mutability/unknown override flags,
/// embedded into the `EventKind::SaContextRuleCreated` audit row by
/// `ContextRuleManager::install_rule`.
///
/// # Redaction
///
/// Full 32-byte hashes are stored here (returned to the caller for JSON
/// envelope emission via `--output json`).  The audit row stores only the
/// first-8-hex projection.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PinResult {
    /// Pinned wasm hashes for each verifier referenced by `External` signers
    /// in the rule definition.  Empty if no external verifier was found.
    /// One `(contract_address, hash)` pair per distinct verifier address.
    pub pinned_verifier_wasm_hashes: Vec<(ScAddress, [u8; 32])>,
    /// Pinned wasm hashes for each policy attached to the rule definition.
    /// Empty if the rule has no policies.  One `(contract_address, hash)` per
    /// distinct policy address.
    pub pinned_policy_wasm_hashes: Vec<(ScAddress, [u8; 32])>,
    /// `true` if `accept_mutable_verifier` was set and a mutable contract
    /// was pinned anyway.
    /// Per-contract identification of which specific verifier/policy contract
    /// triggered the override is in the `SaMutableContractOverride` audit rows;
    /// this field is the rule-level aggregate.
    pub mutable_override: bool,
    /// `true` if `accept_unknown_verifier` was set and an unknown-wasm-hash
    /// contract was pinned anyway.
    /// Per-contract identification of which specific verifier/policy contract
    /// triggered the override is in the `SaUnknownContractOverride` audit rows;
    /// this field is the rule-level aggregate.
    pub unknown_override: bool,
}

impl PinResult {
    /// Returns the pinned verifier wasm hashes as first-8-hex strings for
    /// audit-log emission.
    ///
    /// The order matches `pinned_verifier_wasm_hashes`.
    #[must_use]
    pub fn pinned_verifier_hashes_first8(&self) -> Vec<String> {
        self.pinned_verifier_wasm_hashes
            .iter()
            .map(|(_, h)| h[..8].iter().map(|b| format!("{b:02x}")).collect())
            .collect()
    }

    /// Returns the pinned policy wasm hashes as first-8-hex strings for
    /// audit-log emission.
    ///
    /// The order matches `pinned_policy_wasm_hashes`.
    #[must_use]
    pub fn pinned_policy_hashes_first8(&self) -> Vec<String> {
        self.pinned_policy_wasm_hashes
            .iter()
            .map(|(_, h)| h[..8].iter().map(|b| format!("{b:02x}")).collect())
            .collect()
    }
}

// ── pin_referenced_contracts ──────────────────────────────────────────────────

/// Pin all verifier and policy contracts referenced by a rule definition.
///
/// Called at rule-install time (between the divergence check and
/// `install_rule_inner` submission) to enforce the wasm-hash pinning
/// invariant:
///
/// 1. **Verifier identification** — for each `External` signer in
///    `rule_definition.signers`, calls `SignersManager::identify_verifier`
///    (two-RPC wasm-hash fetch + allowlist match).  On unknown-wasm-hash:
///    returns `SaError::VerifierWasmNotInAllowlist` UNLESS `accept_unknown_verifier`
///    is set, in which case emits `EventKind::SaUnknownContractOverride` and
///    records the hash with `unknown_override = true`.
///
/// 2. **Policy identification** — for each policy in
///    `rule_definition.policies`, calls `SignersManager::identify_threshold_policy`
///    (two-RPC wasm-hash fetch + allowlist match) using the policy contract
///    address. Same override semantics as above.
///
/// 3. **Mutability detection** — for every identified contract (verifier +
///    policy), calls [`detect_contract_mutability`] (two-RPC instance-storage
///    probe).  On mutable contract: returns `SaError::VerifierMutable`
///    (verifier) or `SaError::PolicyMutable` (policy) UNLESS
///    `accept_mutable_verifier` is set, in which case emits
///    `EventKind::SaMutableContractOverride` and records `mutable_override = true`.
///
/// 4. **Override audit rows** — emitted via the shared `audit_writer` BEFORE
///    the install transaction is submitted.  Override rows carry the same
///    `request_id` as the subsequent `SaContextRuleCreated` row for forensic
///    correlation.
///
/// 5. Returns a [`PinResult`] with all pinned hashes + override flags.
///
/// # Arguments
///
/// - `signers_manager` — provides `identify_verifier` + `pub(crate)` RPC client
///   accessors for `detect_contract_mutability` and `identify_policy_wasm_hash` calls.
/// - `audit_writer` — shared writer for override-row emission.
/// - `smart_account` — the smart-account being configured (for audit fields).
/// - `rule_definition` — the rule to be installed.
/// - `smart_account_redacted` — pre-computed first-5-last-5 of the smart-account
///   strkey (passed in to avoid re-deriving from `smart_account` here).
/// - `rule_id` — placeholder `0` (pre-install; rule ID not yet assigned on-chain).
///   Used only for forensic audit fields; a separate drift-detection step re-pins
///   at post-install audit time with the real rule_id.
/// - `source_account_strkey` — G-strkey of the fee-paying account (passed
///   through to `identify_verifier` for API symmetry).
/// - `accept_mutable_verifier` — when `true`, mutable contracts proceed with
///   an override audit row instead of returning an error.
/// - `accept_unknown_verifier` — when `true`, unknown-wasm-hash contracts
///   proceed with an override audit row instead of returning an error.
/// - `chain_id` — network identifier forwarded to override audit-row constructors
///   for testnet-vs-mainnet provenance (e.g. `"stellar:testnet"`).
/// - `request_id` — caller-supplied UUID for forensic correlation.
///
/// # Errors
///
/// - [`SaError::VerifierMutable`] — verifier has a non-zero admin key and
///   `accept_mutable_verifier` is `false`.
/// - [`SaError::PolicyMutable`] — policy has a non-zero admin key and
///   `accept_mutable_verifier` is `false`.
/// - [`SaError::VerifierWasmNotInAllowlist`] — verifier wasm hash not in
///   allowlist and `accept_unknown_verifier` is `false`.
/// - [`SaError::PolicyWasmNotInAllowlist`] — policy wasm hash not in
///   allowlist and `accept_unknown_verifier` is `false`.
/// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPC disagree.
/// - [`SaError::DeploymentFailed`] — RPC fetch failed.
///
#[allow(
    clippy::too_many_arguments,
    reason = "irreducible param set: smart-account context + rule + two override flags + audit + chain_id + request_id"
)]
pub async fn pin_referenced_contracts(
    signers_manager: &SignersManager,
    audit_writer: Option<&Arc<Mutex<AuditWriter>>>,
    smart_account: ScAddress,
    smart_account_redacted: &str,
    rule_definition: &ContextRuleDefinition,
    rule_id: u32,
    source_account_strkey: &str,
    accept_mutable_verifier: bool,
    accept_unknown_verifier: bool,
    chain_id: &str,
    request_id: String,
) -> Result<PinResult, SaError> {
    let mut pinned_verifier_wasm_hashes: Vec<(ScAddress, [u8; 32])> = Vec::new();
    let mut pinned_policy_wasm_hashes: Vec<(ScAddress, [u8; 32])> = Vec::new();
    let mut mutable_override = false;
    let mut unknown_override = false;

    // ── Step 1: Verifier identification + mutability detection ────────────────
    // Collect unique verifier addresses from External signers in the rule.
    let verifier_addrs: Vec<ScAddress> = rule_definition
        .signers
        .iter()
        .filter_map(|s| {
            if let ContextRuleSignerInput::External { verifier, .. } = s {
                Some(verifier.clone())
            } else {
                None
            }
        })
        .collect();

    // Deduplicate: multiple External signers may reference the same verifier.
    // Use index-based dedup (ScAddress has no Hash impl; compare via strkey).
    let mut seen_verifier_strkeys: std::collections::HashSet<String> = Default::default();

    for verifier_addr in verifier_addrs {
        let verifier_strkey = xdr_scaddress_to_strkey_or_sentinel(&verifier_addr);
        if !seen_verifier_strkeys.insert(verifier_strkey.clone()) {
            continue; // already processed this address
        }

        // identify_verifier: two-RPC wasm-hash fetch + allowlist match.
        // Returns SaError::VerifierWasmNotInAllowlist on zero-match.
        let hash_result = signers_manager
            .identify_verifier(
                smart_account.clone(),
                verifier_addr.clone(),
                rule_id,
                source_account_strkey,
                request_id.clone(),
            )
            .await;

        let wasm_hash = match hash_result {
            Ok(h) => h,
            Err(SaError::VerifierWasmNotInAllowlist {
                observed_hash_first8,
                ..
            }) => {
                if accept_unknown_verifier {
                    // Fetch the REAL wasm hash via two-RPC (without allowlist enforcement).
                    // Store the actual observed hash, not a zero sentinel.
                    // A zero pin would always mismatch a real wasm hash at drift-check time,
                    // permanently bricking signing against this rule.
                    use crate::managers::signers::fetch_observed_wasm_hash;
                    let real_hash = fetch_observed_wasm_hash(
                        signers_manager.primary_rpc_client(),
                        signers_manager.secondary_rpc_client(),
                        &verifier_addr,
                        rule_id,
                        smart_account_redacted,
                        &request_id,
                    )
                    .await?
                    .unwrap_or([0u8; 32]); // absent entry ⇒ zero sentinel (edge case)

                    unknown_override = true;
                    let verifier_redacted = redact_strkey_first5_last5(&verifier_strkey);
                    let now_ts = stellar_agent_core::timefmt::current_iso8601_utc();
                    let override_entry = AuditEntry::new_sa_unknown_contract_override(
                        rule_id,
                        RedactedStrkey::from_already_redacted(smart_account_redacted),
                        RedactedStrkey::from_already_redacted(&verifier_redacted),
                        ContractKind::Verifier,
                        &now_ts,
                        &observed_hash_first8,
                        chain_id,
                        &request_id,
                    );
                    let health = signers_manager.health_handle();
                    emit_override_row(
                        audit_writer,
                        override_entry,
                        "pin_referenced_contracts: SaUnknownContractOverride (verifier)",
                        true,
                        Some(&health),
                    )?;
                    warn!(
                        verifier_redacted = %verifier_redacted,
                        observed_hash_first8 = %observed_hash_first8,
                        rule_id,
                        "pin_referenced_contracts: unknown verifier wasm hash; \
                         proceeding with --accept-unknown-verifier override"
                    );
                    real_hash
                } else {
                    return Err(SaError::VerifierWasmNotInAllowlist {
                        rule_id,
                        smart_account_redacted: RedactedStrkey::from_already_redacted(
                            smart_account_redacted,
                        ),
                        observed_hash_first8,
                        request_id,
                    });
                }
            }
            Err(e) => return Err(e),
        };

        // Mutability detection for this verifier address.
        let mutability = detect_contract_mutability(
            signers_manager.primary_rpc_client(),
            signers_manager.secondary_rpc_client(),
            &verifier_addr,
            rule_id,
            smart_account_redacted,
            &request_id,
        )
        .await?;

        if let MutabilityStatus::Mutable {
            admin_or_owner_key,
            holder_redacted,
        } = &mutability
        {
            let verifier_redacted = redact_strkey_first5_last5(&verifier_strkey);
            if accept_mutable_verifier {
                mutable_override = true;
                let now_ts = stellar_agent_core::timefmt::current_iso8601_utc();
                warn!(
                    verifier_redacted = %verifier_redacted,
                    admin_key = %admin_or_owner_key,
                    holder_redacted = %holder_redacted,
                    rule_id,
                    "pin_referenced_contracts: mutable verifier contract; \
                     proceeding with --accept-mutable-verifier override"
                );
                let override_entry = AuditEntry::new_sa_mutable_contract_override(
                    rule_id,
                    RedactedStrkey::from_already_redacted(smart_account_redacted),
                    RedactedStrkey::from_already_redacted(&verifier_redacted),
                    ContractKind::Verifier,
                    &now_ts,
                    chain_id,
                    &request_id,
                );
                let health = signers_manager.health_handle();
                emit_override_row(
                    audit_writer,
                    override_entry,
                    "pin_referenced_contracts: SaMutableContractOverride (verifier)",
                    true,
                    Some(&health),
                )?;
            } else {
                return Err(SaError::VerifierMutable {
                    rule_id,
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        smart_account_redacted,
                    ),
                    contract_address_redacted: RedactedStrkey::from_already_redacted(
                        verifier_redacted,
                    ),
                    admin_or_owner_key: *admin_or_owner_key,
                    request_id,
                });
            }
        }

        pinned_verifier_wasm_hashes.push((verifier_addr, wasm_hash));
    }

    // ── Step 2: Policy identification + mutability detection ──────────────────
    let mut seen_policy_strkeys: std::collections::HashSet<String> = Default::default();

    for policy in &rule_definition.policies {
        let policy_strkey = xdr_scaddress_to_strkey_or_sentinel(&policy.policy_address);
        if !seen_policy_strkeys.insert(policy_strkey.clone()) {
            continue;
        }

        // For policies, we use identify_threshold_policy to get the wasm hash.
        // identify_threshold_policy fetches via the rule's on-chain policy list,
        // but here we have the policy address directly from the rule definition.
        // We need to identify the wasm hash from the policy address.
        // Since we are pre-install (the rule doesn't exist on-chain yet), we
        // cannot use identify_threshold_policy (which reads the on-chain rule).
        //
        // Instead: fetch the wasm hash directly using the same
        // fetch_contract_wasm_hashes helper (two-RPC).  Then check against
        // THRESHOLD_POLICY_WASM_HASHES (not VERIFIER_ALLOWLIST).
        //
        // For each policy in the rule's policies list: fetch the wasm hash
        // against `THRESHOLD_POLICY_WASM_HASHES` + detect_contract_mutability on
        // the address. Since we have the address already, we go directly to the
        // wasm-hash fetch + allowlist check.
        let policy_hash_result = identify_policy_wasm_hash(
            signers_manager,
            &policy.policy_address,
            rule_id,
            smart_account_redacted,
            &request_id,
        )
        .await;

        let policy_hash = match policy_hash_result {
            Ok(h) => h,
            Err(SaError::PolicyWasmNotInAllowlist {
                observed_hash_first8,
                ..
            }) => {
                if accept_unknown_verifier {
                    // Fetch the REAL wasm hash via two-RPC (without allowlist enforcement).
                    use crate::managers::signers::fetch_observed_wasm_hash;
                    let real_hash = fetch_observed_wasm_hash(
                        signers_manager.primary_rpc_client(),
                        signers_manager.secondary_rpc_client(),
                        &policy.policy_address,
                        rule_id,
                        smart_account_redacted,
                        &request_id,
                    )
                    .await?
                    .unwrap_or([0u8; 32]); // absent entry ⇒ zero sentinel (edge case)

                    unknown_override = true;
                    let policy_redacted = redact_strkey_first5_last5(&policy_strkey);
                    let now_ts = stellar_agent_core::timefmt::current_iso8601_utc();
                    warn!(
                        policy_redacted = %policy_redacted,
                        observed_hash_first8 = %observed_hash_first8,
                        rule_id,
                        "pin_referenced_contracts: unknown policy wasm hash; \
                         proceeding with --accept-unknown-verifier override"
                    );
                    let override_entry = AuditEntry::new_sa_unknown_contract_override(
                        rule_id,
                        RedactedStrkey::from_already_redacted(smart_account_redacted),
                        RedactedStrkey::from_already_redacted(&policy_redacted),
                        ContractKind::Policy,
                        &now_ts,
                        &observed_hash_first8,
                        chain_id,
                        &request_id,
                    );
                    let health = signers_manager.health_handle();
                    emit_override_row(
                        audit_writer,
                        override_entry,
                        "pin_referenced_contracts: SaUnknownContractOverride (policy)",
                        true,
                        Some(&health),
                    )?;
                    real_hash
                } else {
                    return Err(SaError::PolicyWasmNotInAllowlist {
                        rule_id,
                        smart_account_redacted: RedactedStrkey::from_already_redacted(
                            smart_account_redacted,
                        ),
                        observed_hash_first8,
                        request_id,
                    });
                }
            }
            Err(e) => return Err(e),
        };

        // Mutability detection for this policy.
        let policy_mutability = detect_contract_mutability(
            signers_manager.primary_rpc_client(),
            signers_manager.secondary_rpc_client(),
            &policy.policy_address,
            rule_id,
            smart_account_redacted,
            &request_id,
        )
        .await?;

        if let MutabilityStatus::Mutable {
            admin_or_owner_key,
            holder_redacted,
        } = &policy_mutability
        {
            let policy_redacted = redact_strkey_first5_last5(&policy_strkey);
            if accept_mutable_verifier {
                mutable_override = true;
                let now_ts = stellar_agent_core::timefmt::current_iso8601_utc();
                warn!(
                    policy_redacted = %policy_redacted,
                    admin_key = %admin_or_owner_key,
                    holder_redacted = %holder_redacted,
                    rule_id,
                    "pin_referenced_contracts: mutable policy contract; \
                     proceeding with --accept-mutable-verifier override"
                );
                let override_entry = AuditEntry::new_sa_mutable_contract_override(
                    rule_id,
                    RedactedStrkey::from_already_redacted(smart_account_redacted),
                    RedactedStrkey::from_already_redacted(&policy_redacted),
                    ContractKind::Policy,
                    &now_ts,
                    chain_id,
                    &request_id,
                );
                let health = signers_manager.health_handle();
                emit_override_row(
                    audit_writer,
                    override_entry,
                    "pin_referenced_contracts: SaMutableContractOverride (policy)",
                    true,
                    Some(&health),
                )?;
            } else {
                return Err(SaError::PolicyMutable {
                    rule_id,
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        smart_account_redacted,
                    ),
                    contract_address_redacted: RedactedStrkey::from_already_redacted(
                        policy_redacted,
                    ),
                    admin_or_owner_key: *admin_or_owner_key,
                    request_id,
                });
            }
        }

        pinned_policy_wasm_hashes.push((policy.policy_address.clone(), policy_hash));
    }

    Ok(PinResult {
        pinned_verifier_wasm_hashes,
        pinned_policy_wasm_hashes,
        mutable_override,
        unknown_override,
    })
}

// ── Private helpers for pin_referenced_contracts ──────────────────────────────

/// Emits an override audit row via the shared `Arc<Mutex<AuditWriter>>` fallback,
/// propagating write failures fail-closed.
///
/// Returns `Ok(())` when the write succeeds or when `audit_writer` is `None`
/// (the test-only / dry-run path where no writer is configured).  Returns
/// `Err(SaError::AuditLog(...))` when the writer is present but the write fails —
/// the caller must propagate this error before proceeding with the install.
///
/// # Writer routing constraint
///
/// Override rows for mutable and unknown-wasm contracts are emitted via the
/// `self.audit_writer` fallback arc only, NOT via the per-method
/// `Option<&mut AuditWriter>`.  Routing the per-method writer through the async
/// boundary of `pin_referenced_contracts` would require lifetime gymnastics that
/// outweigh the benefit: production code always configures `self.audit_writer`
/// via `with_audit_writer` as part of the same construction step that wires
/// `with_signers_manager`.  A `debug_assert!` in `install_rule` catches any
/// developer-time regression where an override flag is set but `self.audit_writer`
/// is `None`.
///
/// # Errors
///
/// - [`SaError::AuditLog`] — write to the audit log failed (I/O or chain-hash
///   error), OR the mutex is poisoned and `override_requested` is `true`.
fn emit_override_row(
    audit_writer: Option<&Arc<Mutex<AuditWriter>>>,
    entry: AuditEntry,
    op_label: &'static str,
    override_requested: bool,
    health: Option<&AuditWriterHealthHandle>,
) -> Result<(), SaError> {
    if let Some(arc) = audit_writer {
        match arc.lock() {
            Ok(mut guard) => {
                if let Err(e) = guard.write_entry(entry) {
                    warn!(error = %e, op = %op_label, "pin_referenced_contracts: audit write failed");
                    // Route WriterError through VerifyError::Io so SaError::AuditLog can carry it.
                    // WriterError is not directly convertible to AuditLogIntegrityError (VerifyError)
                    // because WriterError has additional variants (Hash, Serialise, PartialRotation)
                    // that do not correspond 1:1.  Display-string roundtrip via other() is
                    // intentional: it preserves the human-readable message for the wire
                    // `sa.audit_log` envelope while keeping the type system clean.
                    let io_err = std::io::Error::other(e.to_string());
                    return Err(SaError::AuditLog(
                        stellar_agent_core::audit_log::AuditLogIntegrityError::Io(io_err),
                    ));
                }
            }
            Err(_poison) => {
                // Mutex poisoned: mark session degraded, warn, and treat as audit-log
                // failure (mutex poisoned; override audit row cannot be written).
                if let Some(h) = health {
                    h.mark_degraded();
                }
                warn!(
                    target: "stellar_agent::audit",
                    op = %op_label,
                    "audit-writer mutex poisoned; override audit row dropped"
                );
                if override_requested {
                    let io_err = std::io::Error::other(format!(
                        "{op_label}: audit writer poisoned; override row not written"
                    ));
                    return Err(SaError::AuditLog(
                        stellar_agent_core::audit_log::AuditLogIntegrityError::Io(io_err),
                    ));
                }
                return Ok(());
            }
        }
    } else if override_requested {
        return Err(SaError::AuditLog(
            stellar_agent_core::audit_log::AuditLogIntegrityError::Io(std::io::Error::other(
                format!("{op_label}: override requested but no audit writer configured"),
            )),
        ));
    }
    Ok(())
}

pub(crate) fn scaddress_cache_key(addr: &ScAddress) -> Result<Vec<u8>, SaError> {
    use stellar_xdr::WriteXdr;

    addr.to_xdr(stellar_xdr::Limits::none())
        .map_err(|e| SaError::ScAddressEncodingFailed {
            redacted_reason: format!("ScAddress XDR cache-key encoding failed: {e}"),
        })
}

// ── Drift-detection re-fetch at signing time ──────────────────────────────────

/// Reads the pinned verifier and policy wasm-hash record for
/// `(rule_id, smart_account_redacted)` from the audit log.
///
/// Wraps [`AuditReader::find_latest_context_rule_pinned_hashes`] with the
/// shared `Arc<Mutex<AuditWriter>>` from `SignersManager`.
///
/// # Returns
///
/// - `Ok(Some(record))` — the rule's `SaContextRuleCreated` row was found;
///   the returned [`PinnedHashesRecord`] carries first-8-hex strings of the
///   pinned hashes plus install-time override flags.
/// - `Ok(None)` — no matching rule entry found; drift-detection is skipped.
///
/// # Errors
///
/// - [`SaError::AuditLog`] — audit-log integrity error (chain break, rotation gap,
///   HMAC mismatch, parse error, I/O failure).
///
pub(crate) fn read_pinned_hashes_for_rule(
    signers_manager: &SignersManager,
    rule_id: u32,
    smart_account_redacted: &str,
) -> Result<Option<PinnedHashesRecord>, SaError> {
    let reader = AuditReader::new(signers_manager.audit_writer(), None);
    reader
        .find_latest_context_rule_pinned_hashes(rule_id, smart_account_redacted)
        .map_err(SaError::AuditLog)
}

/// First-8-hex projection of a 32-byte wasm hash.
///
/// Mirrors the projection used in [`PinResult::pinned_verifier_hashes_first8`].
fn hash_first8_hex(hash: &[u8; 32]) -> String {
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify a rule's pinned verifier wasm hash against the live on-chain
/// contract at signing time.
///
/// Reads the pinned hash from the audit log (the `SaContextRuleCreated` entry
/// for `rule_id` via the audit-log-derived expectation pattern).
/// Calls [`fetch_observed_wasm_hash`][crate::managers::signers::fetch_observed_wasm_hash]
/// to fetch the live wasm hash via two-RPC consultation (no allowlist
/// enforcement — drift detection compares the live hash against the pinned
/// value only; allowlist enforcement belongs at install time).
/// Compares the first-8-hex projections.
///
/// The per-call `wasm_hash_cache` prevents redundant two-RPC fetches when
/// multiple operations within one signing call reference the same verifier
/// address.  Pass a mutable reference to the
/// same `HashMap` across all calls within a signing invocation.
///
/// # Arguments
///
/// - `signers_manager` — provides RPC clients and audit writer.
/// - `verifier_addr` — the verifier contract address to check.
/// - `rule_id` — the context rule whose pinned verifier hash to compare.
/// - `smart_account_redacted` — pre-computed first-5-last-5 of the
///   smart-account strkey (for audit fields).
/// - `request_id` — caller-supplied UUID for forensic correlation.
/// - `wasm_hash_cache` — shared per-call cache keyed by verifier `ScAddress`
///   XDR bytes.
///
/// # Returns
///
/// - `Ok(())` — no drift detected; signing may proceed.
///
/// # Errors
///
/// - [`SaError::NetworkRpcDivergence`] — RPCs disagree before drift check.
/// - [`SaError::VerifierHashDrift`] — pinned and observed first-8-hex differ.
/// - [`SaError::AuditLog`] — audit-log integrity error.
/// - [`SaError::DeploymentFailed`] — RPC fetch failed.
///
/// Emits [`EventKind::SaVerifierHashDrift`] on the drift path via the shared
/// `Arc<Mutex<AuditWriter>>` from `signers_manager`.
///
pub(crate) async fn verify_pinned_verifier_against_chain(
    signers_manager: &SignersManager,
    verifier_addr: ScAddress,
    rule_id: u32,
    smart_account_redacted: &str,
    request_id: &str,
    wasm_hash_cache: &mut HashMap<Vec<u8>, [u8; 32]>,
) -> Result<(), SaError> {
    let verifier_strkey = xdr_scaddress_to_strkey_or_sentinel(&verifier_addr);
    let verifier_redacted = redact_strkey_first5_last5(&verifier_strkey);
    let verifier_cache_key = scaddress_cache_key(&verifier_addr)?;

    // Read pinned first-8-hex from the audit log.
    let Some(record) =
        read_pinned_hashes_for_rule(signers_manager, rule_id, smart_account_redacted)?
    else {
        // No SaContextRuleCreated row found — rule was installed via a
        // non-wallet path or before wasm-hash pinning was introduced.
        // The wallet does not pin against non-wallet installs; skip drift-detect.
        debug!(
            rule_id,
            verifier_redacted = %verifier_redacted,
            "verify_pinned_verifier_against_chain: no SaContextRuleCreated row for rule_id; \
             drift-detection skipped (rule may have been installed without a pinned record)"
        );
        return Ok(());
    };
    let verifier_hashes_first8 = &record.pinned_verifier_first8;

    if verifier_hashes_first8.is_empty() {
        // Rule was installed without External signers (no verifier pin).
        debug!(
            rule_id,
            verifier_redacted = %verifier_redacted,
            "verify_pinned_verifier_against_chain: no pinned verifier hashes for rule_id; \
             drift-detection skipped"
        );
        return Ok(());
    }

    // Multi-verifier indexing guard.
    //
    // The implementation currently supports exactly one distinct verifier address per rule.
    // If a rule has been installed with multiple distinct verifier pins, the caller
    // passes one `verifier_addr` per iteration, but the pin list position would not
    // align correctly with `[0]` for the second and subsequent distinct verifiers.
    // Fail closed to avoid silently checking the wrong pin (a false-negative security risk).
    if verifier_hashes_first8.len() > 1 {
        return Err(SaError::MultiplePinnedHashesUnsupported {
            kind: "verifier",
            rule_id,
            count: verifier_hashes_first8.len(),
            smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
            request_id: request_id.to_owned(),
        });
    }
    let pinned_hash_first8 = verifier_hashes_first8[0].clone();

    // Per-call cache prevents redundant two-RPC fetches.
    //
    // Use fetch_observed_wasm_hash (no allowlist enforcement) instead
    // of identify_verifier (which enforces VERIFIER_ALLOWLIST).  At signing time,
    // drift detection compares the live hash against the pinned value — any hash
    // mismatch is a security event regardless of whether the live hash is in the
    // allowlist.  Allowlist enforcement belongs at install time only.
    let observed_hash: [u8; 32] = if let Some(&cached) = wasm_hash_cache.get(&verifier_cache_key) {
        cached
    } else {
        use crate::managers::signers::fetch_observed_wasm_hash;
        let maybe_hash = fetch_observed_wasm_hash(
            signers_manager.primary_rpc_client(),
            signers_manager.secondary_rpc_client(),
            &verifier_addr,
            rule_id,
            smart_account_redacted,
            request_id,
        )
        .await?;
        // If the contract is absent, use zero-sentinel so comparison against
        // a zero pin (from accept-unknown-verifier path that stored zero due to
        // an absent contract) passes cleanly.
        let hash = maybe_hash.unwrap_or([0u8; 32]);
        wasm_hash_cache.insert(verifier_cache_key, hash);
        hash
    };

    let observed_hash_first8 = hash_first8_hex(&observed_hash);

    if observed_hash_first8 == pinned_hash_first8 {
        debug!(
            rule_id,
            verifier_redacted = %verifier_redacted,
            observed_hash_first8 = %observed_hash_first8,
            "verify_pinned_verifier_against_chain: hash match (no drift)"
        );
        return Ok(());
    }

    // Drift detected: emit SaVerifierHashDrift audit row and return typed error.
    warn!(
        rule_id,
        smart_account_redacted,
        verifier_redacted = %verifier_redacted,
        pinned_hash_first8 = %pinned_hash_first8,
        observed_hash_first8 = %observed_hash_first8,
        "verify_pinned_verifier_against_chain: wasm-hash DRIFT detected; aborting signing"
    );

    let drift_entry = AuditEntry::new_sa_verifier_hash_drift(
        rule_id,
        RedactedStrkey::from_already_redacted(smart_account_redacted),
        RedactedStrkey::from_already_redacted(&verifier_redacted),
        &pinned_hash_first8,
        &observed_hash_first8,
        signers_manager.chain_id(),
        request_id,
    );

    {
        let writer_arc = signers_manager.audit_writer();
        match writer_arc.lock() {
            Ok(mut writer) => {
                if let Err(e) = writer.write_entry(drift_entry) {
                    warn!(
                        error = %e,
                        "verify_pinned_verifier_against_chain: SaVerifierHashDrift audit write failed"
                    );
                }
            }
            Err(_poison) => {
                // Mutex poisoned: mark session degraded; SaVerifierHashDrift row cannot be written.
                signers_manager.mark_audit_writer_degraded();
                warn!(
                    target: "stellar_agent::audit",
                    rule_id,
                    "audit-writer mutex poisoned; SaVerifierHashDrift row dropped"
                );
            }
        }
    }

    Err(SaError::VerifierHashDrift {
        rule_id,
        smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
        deploy_address_redacted: RedactedStrkey::from_already_redacted(verifier_redacted),
        pinned_hash_first8,
        observed_hash_first8,
        request_id: request_id.to_owned(),
    })
}

/// Verify a rule's pinned policy wasm hash against the live on-chain contract
/// at signing time (drift-detection re-fetch — policy path).
///
/// Parallel to [`verify_pinned_verifier_against_chain`] for the
/// threshold-policy contract path.
///
/// # Arguments
///
/// - `signers_manager` — provides RPC clients and audit writer.
/// - `policy_addr` — the policy contract address to verify.
/// - `rule_id` — the context rule whose pinned policy hash to compare.
/// - `smart_account_redacted` — pre-computed first-5-last-5 of the
///   smart-account strkey (for audit fields).
/// - `request_id` — caller-supplied UUID for forensic correlation.
/// - `wasm_hash_cache` — shared per-call cache keyed by policy `ScAddress` XDR
///   bytes.
///
/// # Returns / Errors
///
/// Same as [`verify_pinned_verifier_against_chain`] with `Policy*` variants.
///
/// Emits [`EventKind::SaPolicyHashDrift`] on the drift path.
///
pub(crate) async fn verify_pinned_policy_against_chain(
    signers_manager: &SignersManager,
    policy_addr: ScAddress,
    rule_id: u32,
    smart_account_redacted: &str,
    request_id: &str,
    wasm_hash_cache: &mut HashMap<Vec<u8>, [u8; 32]>,
) -> Result<(), SaError> {
    use crate::managers::signers::fetch_observed_wasm_hash;
    use crate::signers::policy_identification::THRESHOLD_POLICY_WASM_HASHES;

    let policy_strkey = xdr_scaddress_to_strkey_or_sentinel(&policy_addr);
    let policy_redacted = redact_strkey_first5_last5(&policy_strkey);
    let policy_cache_key = scaddress_cache_key(&policy_addr)?;

    // Read pinned first-8-hex from the audit log.
    let Some(record) =
        read_pinned_hashes_for_rule(signers_manager, rule_id, smart_account_redacted)?
    else {
        debug!(
            rule_id,
            policy_redacted = %policy_redacted,
            "verify_pinned_policy_against_chain: no SaContextRuleCreated row for rule_id; \
             drift-detection skipped"
        );
        return Ok(());
    };
    let policy_hashes_first8 = &record.pinned_policy_first8;

    if policy_hashes_first8.is_empty() {
        debug!(
            rule_id,
            policy_redacted = %policy_redacted,
            "verify_pinned_policy_against_chain: no pinned policy hashes for rule_id; \
             drift-detection skipped"
        );
        return Ok(());
    }

    // Multi-policy indexing guard (parallel to verifier path above).
    // The implementation currently supports at most one distinct policy address per rule.
    // SaError::MultiplePinnedHashesUnsupported is the correct typed variant for a
    // signing-time guard (not a deployment failure).
    if policy_hashes_first8.len() > 1 {
        return Err(SaError::MultiplePinnedHashesUnsupported {
            kind: "policy",
            rule_id,
            count: policy_hashes_first8.len(),
            smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
            request_id: request_id.to_owned(),
        });
    }
    let pinned_hash_first8 = policy_hashes_first8[0].clone();

    // Per-call cache prevents redundant two-RPC fetches.
    //
    // Use fetch_observed_wasm_hash (no allowlist enforcement) — drift detection
    // compares the live hash against the pinned value only.  The allowlist was
    // enforced at install time.  If the live hash differs from the pin (even if
    // both are outside the allowlist) that is a security event worth aborting for.
    let observed_hash: [u8; 32] = if let Some(&cached) = wasm_hash_cache.get(&policy_cache_key) {
        cached
    } else {
        let maybe_hash = fetch_observed_wasm_hash(
            signers_manager.primary_rpc_client(),
            signers_manager.secondary_rpc_client(),
            &policy_addr,
            rule_id,
            smart_account_redacted,
            request_id,
        )
        .await?;

        // If the contract is absent, use zero-sentinel so comparison against
        // a zero pin (from accept-unknown-verifier path that stored zero due to
        // an absent contract) passes cleanly.
        let hash = maybe_hash.unwrap_or([0u8; 32]);

        // Log if hash not in allowlist (informational — signing continues if hash matches pin).
        if !THRESHOLD_POLICY_WASM_HASHES.iter().any(|h| h == &hash) {
            warn!(
                rule_id,
                policy_redacted = %policy_redacted,
                observed_hash_first8 = %hash_first8_hex(&hash),
                "verify_pinned_policy_against_chain: observed policy wasm hash not in allowlist \
                 (will still check against pinned value)"
            );
        }

        wasm_hash_cache.insert(policy_cache_key, hash);
        hash
    };

    let observed_hash_first8 = hash_first8_hex(&observed_hash);

    if observed_hash_first8 == pinned_hash_first8 {
        debug!(
            rule_id,
            policy_redacted = %policy_redacted,
            observed_hash_first8 = %observed_hash_first8,
            "verify_pinned_policy_against_chain: hash match (no drift)"
        );
        return Ok(());
    }

    // Drift detected.
    warn!(
        rule_id,
        smart_account_redacted,
        policy_redacted = %policy_redacted,
        pinned_hash_first8 = %pinned_hash_first8,
        observed_hash_first8 = %observed_hash_first8,
        "verify_pinned_policy_against_chain: wasm-hash DRIFT detected; aborting signing"
    );

    let drift_entry = AuditEntry::new_sa_policy_hash_drift(
        rule_id,
        RedactedStrkey::from_already_redacted(smart_account_redacted),
        RedactedStrkey::from_already_redacted(&policy_redacted),
        &pinned_hash_first8,
        &observed_hash_first8,
        signers_manager.chain_id(),
        request_id,
    );

    {
        let writer_arc = signers_manager.audit_writer();
        match writer_arc.lock() {
            Ok(mut writer) => {
                if let Err(e) = writer.write_entry(drift_entry) {
                    warn!(
                        error = %e,
                        "verify_pinned_policy_against_chain: SaPolicyHashDrift audit write failed"
                    );
                }
            }
            Err(_poison) => {
                // Mutex poisoned: mark session degraded; SaPolicyHashDrift row cannot be written.
                signers_manager.mark_audit_writer_degraded();
                warn!(
                    target: "stellar_agent::audit",
                    rule_id,
                    "audit-writer mutex poisoned; SaPolicyHashDrift row dropped"
                );
            }
        }
    }

    Err(SaError::PolicyHashDrift {
        rule_id,
        smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
        deploy_address_redacted: RedactedStrkey::from_already_redacted(policy_redacted),
        pinned_hash_first8,
        observed_hash_first8,
        request_id: request_id.to_owned(),
    })
}

/// Identifies the wasm hash of a policy contract by direct address lookup
/// (pre-install path — the rule does not yet exist on-chain so
/// `identify_threshold_policy` cannot be used).
///
/// Performs two-RPC `getLedgerEntries`, extracts the wasm hash, and checks it
/// against [`THRESHOLD_POLICY_WASM_HASHES`].
///
/// # Errors
///
/// - [`SaError::PolicyWasmNotInAllowlist`] — wasm hash not in allowlist.
/// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPCs disagree.
/// - [`SaError::DeploymentFailed`] — RPC fetch failed.
async fn identify_policy_wasm_hash(
    signers_manager: &SignersManager,
    policy_addr: &ScAddress,
    rule_id: u32,
    smart_account_redacted: &str,
    request_id: &str,
) -> Result<[u8; 32], SaError> {
    use crate::signers::policy_identification::THRESHOLD_POLICY_WASM_HASHES;

    signers_manager
        .identify_contract_wasm_hash(
            policy_addr,
            THRESHOLD_POLICY_WASM_HASHES,
            rule_id,
            smart_account_redacted,
            request_id,
            |ctx| SaError::PolicyWasmNotInAllowlist {
                rule_id: ctx.rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    ctx.smart_account_redacted,
                ),
                observed_hash_first8: ctx.observed_hash_first8,
                request_id: ctx.request_id,
            },
        )
        .await
}

// ── Admin / Owner key names surveyed from OZ v0.7.2 ──────────────────────────

/// Closed-set of admin-equivalent instance-storage key names surveyed from OZ
/// `stellar-contracts` v0.7.2 (SHA `a9c4216`).
///
/// Survey result per `packages/access/src/ownable/storage.rs:14` and
/// `packages/access/src/access_control/storage.rs:27` — Pascal-case on the wire.
///
/// Expanding this set requires extending the `AdminOrOwnerKey` enum.
const ADMIN_KEY_NAMES: &[AdminOrOwnerKey] = &[AdminOrOwnerKey::Admin, AdminOrOwnerKey::Owner];

// ── MutabilityStatus ──────────────────────────────────────────────────────────

/// Mutability status of a deployed Soroban contract.
///
/// Reflects whether the contract's instance storage contains an admin / owner
/// / upgrader key with a non-zero `ScVal::Address` value.  Used at rule-install
/// time to refuse pinning against mutable contracts unless
/// `--accept-mutable-verifier` is set.
///
/// # OZ instance storage
///
/// OZ `stellar-contracts` v0.7.2 embeds admin keys in `ScContractInstance.storage`
/// (instance storage), not as separate `LedgerKey::ContractData` entries.
/// Confirmed at `packages/access/src/ownable/storage.rs:27,50` and
/// `packages/access/src/access_control/storage.rs:57,156` (SHA `a9c4216`).
///
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MutabilityStatus {
    /// Contract has no admin / owner / upgrader instance-storage key with a
    /// non-zero value.  Safe to pin against — upgrades require on-chain
    /// governance rather than a single privileged key.
    Immutable,
    /// Contract has at least one admin-equivalent instance-storage key set to a
    /// non-zero `Address`.  Its holder can upgrade the contract's WASM, silently
    /// changing verification logic without triggering wasm-hash drift detection.
    Mutable {
        /// Instance-storage key name (`Admin` or `Owner`).
        ///
        /// Closed-set per OZ v0.7.2 survey (see module-level doc).
        admin_or_owner_key: AdminOrOwnerKey,
        /// First-5-last-5 redacted strkey of the admin / owner holder.
        ///
        /// Derived via
        /// [`stellar_agent_core::observability::redact_strkey_first5_last5`]
        /// at the call site.  Not secret (admin identity is on-chain public
        /// data), but trimmed to avoid accidental log
        /// correlation of chain-wide key reuse patterns.
        holder_redacted: String,
    },
}

// ── Public detection helper ───────────────────────────────────────────────────

/// Detect whether a contract is mutable (has a non-zero admin / owner key).
///
/// # Two-RPC consultation
///
/// Fetches the contract instance entry from both primary and secondary RPC
/// endpoints in parallel (`tokio::join!`) and compares their `ScContractInstance`
/// results.  If primary and secondary disagree, returns
/// `SaError::NetworkRpcDivergence` — a compromised primary cannot suppress a
/// mutable-admin key that the secondary correctly reports.
///
/// # Instance-storage probe
///
/// Inspects `ScContractInstance.storage` (the OZ instance-storage map embedded
/// inside the contract instance ledger entry) for `ScVal::Symbol("Admin")` or
/// `ScVal::Symbol("Owner")` keys with non-zero `ScVal::Address` values.
///
/// Survey source: `packages/access/src/ownable/storage.rs:14` and
/// `packages/access/src/access_control/storage.rs:27` (SHA `a9c4216` tag v0.7.2).
///
/// # Return value
///
/// - `Ok(MutabilityStatus::Immutable)` — no admin key with a non-zero address.
/// - `Ok(MutabilityStatus::Mutable { admin_or_owner_key, holder_redacted })` —
///   at least one admin key present.  The first match in `ADMIN_KEY_NAMES` order
///   wins; `holder_redacted` is first-5-last-5 of the holder strkey.
///
/// # Errors
///
/// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPC disagree on
///   the contract's instance storage.
/// - [`SaError::DeploymentFailed`] (phase `"simulate"`) — either RPC fetch fails
///   (network error, malformed response, contract address not found).
pub async fn detect_contract_mutability(
    primary: &StellarRpcClient,
    secondary: &StellarRpcClient,
    contract_addr: &ScAddress,
    rule_id: u32,
    smart_account_redacted: &str,
    request_id: &str,
) -> Result<MutabilityStatus, SaError> {
    let instance_key = contract_instance_key(contract_addr);
    let keys = std::slice::from_ref(&instance_key);

    // Two-RPC parallel fetch (mirrors identify_verifier:1350-1353 in signers.rs).
    let (primary_result, secondary_result) = tokio::join!(
        fetch_contract_instance_storage(primary, keys),
        fetch_contract_instance_storage(secondary, keys),
    );

    let primary_storages = primary_result.map_err(|e| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!(
            "primary RPC getLedgerEntries failed (request_id={request_id}): {e}"
        ),
    })?;
    let secondary_storages = secondary_result.map_err(|e| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!(
            "secondary RPC getLedgerEntries failed (request_id={request_id}): {e}"
        ),
    })?;

    // Two-RPC agreement check (mirrors identify_verifier:1365-1395 in signers.rs).
    // We digest the raw ScMap XDR from each side to compare them.
    if primary_storages != secondary_storages {
        let digest_bytes = |storages: &[Option<Vec<u8>>]| {
            let concatenated: Vec<u8> = storages
                .iter()
                .flat_map(|s| {
                    s.as_deref()
                        .unwrap_or(&[])
                        .iter()
                        .copied()
                        .chain(std::iter::once(0u8)) // null separator to prevent prefix collision
                })
                .collect();
            let d: [u8; 32] = Sha256::digest(&concatenated).into();
            d[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        let primary_first8 = digest_bytes(&primary_storages);
        let secondary_first8 = digest_bytes(&secondary_storages);
        return Err(SaError::NetworkRpcDivergence {
            rule_id,
            smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
            primary_view_digest_first8: primary_first8,
            secondary_view_digest_first8: secondary_first8,
            request_id: request_id.to_owned(),
        });
    }

    // Both RPCs agree; use primary result.
    // primary_storages is Vec<Option<Vec<u8>>> aligned with `keys`.
    // We requested exactly one key, so there is at most one entry.
    let storage_xdr_opt: Option<Vec<u8>> = primary_storages.into_iter().next().flatten();

    let status = inspect_storage_for_admin_key(storage_xdr_opt, smart_account_redacted)?;

    debug!(
        rule_id,
        smart_account_redacted,
        mutability = ?status,
        "detect_contract_mutability: result"
    );

    Ok(status)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Fetches the raw instance-storage `ScMap` XDR bytes from a contract's instance
/// entry via `getLedgerEntries`.
///
/// Returns `Vec<Option<Vec<u8>>>` aligned with `keys`:
/// - `Some(bytes)` when the key resolved to a WASM contract instance that has
///   a non-`None` `ScContractInstance.storage` map (raw XDR of `ScVal::Map`).
/// - `None` when the key was absent from the ledger, resolved to a non-WASM
///   entry, or the instance has no instance storage (`storage == None`).
///
/// # Why raw bytes?
///
/// We need to compare primary vs secondary responses for the two-RPC agreement
/// check.  Raw XDR bytes are the cheapest comparable representation — no `ScMap`
/// `PartialEq` or clone needed.
///
/// # Byte-layout citation
///
/// `LedgerEntryResult.xdr` contains `LedgerEntryData` XDR (not full
/// `LedgerEntry`), confirmed from `stellar-rpc-client` (rs-stellar-rpc-client)
/// `LedgerEntryResult` struct.
/// `LedgerEntryResult.key` contains `LedgerKey` XDR, used for position matching.
///
/// `ScContractInstance.storage` is `Option<ScMap>` per `stellar-xdr` v27.0.0
/// `xdr/curr/Stellar-contract.x` `SCContractInstance` definition.
async fn fetch_contract_instance_storage(
    client: &StellarRpcClient,
    keys: &[LedgerKey],
) -> Result<Vec<Option<Vec<u8>>>, String> {
    use stellar_xdr::{
        ContractExecutable, LedgerEntryData, LedgerKey as XdrLedgerKey, ReadXdr, WriteXdr,
    };

    if keys.is_empty() {
        return Ok(vec![]);
    }

    let response = client
        .get_ledger_entries(keys)
        .await
        .map_err(|e| format!("get_ledger_entries failed: {e}"))?;

    let raw_entries = response.entries.unwrap_or_default();

    // Build a position-keyed map: key_index → raw ScMap XDR bytes (or None).
    let mut storage_by_key_pos: std::collections::HashMap<usize, Vec<u8>> =
        std::collections::HashMap::new();

    for entry_result in &raw_entries {
        // Decode the response key to match it against our request keys by position.
        let response_key = match XdrLedgerKey::from_xdr_base64(
            &entry_result.key,
            stellar_agent_xdr_limits::untrusted_decode_limits(entry_result.key.len()),
        ) {
            Ok(k) => k,
            Err(_) => continue, // skip malformed key — safe, only loses one entry
        };

        let Some(pos) = keys.iter().position(|k| k == &response_key) else {
            continue; // response entry not in our request — skip
        };

        // Decode LedgerEntryData XDR.
        // `stellar-rpc-client` (rs-stellar-rpc-client) decodes `LedgerEntryResult.xdr`
        // as `LedgerEntryData` via `LedgerEntryData::from_xdr_base64`.
        let entry_data = match LedgerEntryData::from_xdr_base64(
            &entry_result.xdr,
            stellar_agent_xdr_limits::untrusted_decode_limits(entry_result.xdr.len()),
        ) {
            Ok(d) => d,
            Err(_) => continue, // skip malformed entry — safe
        };

        if let LedgerEntryData::ContractData(cd) = &entry_data {
            if let stellar_xdr::ScVal::ContractInstance(instance) = &cd.val
                && matches!(instance.executable, ContractExecutable::Wasm(_))
            {
                // `instance.storage` is `Option<ScMap>`.
                // Serialise the ScMap to raw XDR bytes for comparison; use empty vec for None.
                let storage_bytes: Vec<u8> = match &instance.storage {
                    Some(scmap) => {
                        // Wrap in ScVal::Map for a self-describing XDR encoding.
                        ScVal::Map(Some(scmap.clone()))
                            .to_xdr(stellar_xdr::Limits::none())
                            .unwrap_or_default()
                    }
                    None => vec![],
                };
                storage_by_key_pos.insert(pos, storage_bytes);
            } else {
                // Malformed contract-data value for the requested instance key:
                // preserve the discriminant so inspect_storage_for_admin_key can
                // fail closed instead of silently treating it as absent.
                storage_by_key_pos.insert(
                    pos,
                    cd.val
                        .to_xdr(stellar_xdr::Limits::none())
                        .unwrap_or_default(),
                );
            }
        }
    }

    // Build the aligned result vector: Some(bytes) for resolved keys, None for missing.
    Ok((0..keys.len())
        .map(|i| storage_by_key_pos.get(&i).cloned())
        .collect())
}

/// Inspects raw instance-storage XDR bytes for an admin / owner key.
///
/// `storage_xdr_opt` is `Some(ScVal::Map(...) XDR)` when the contract has
/// instance storage, `None` when absent.
///
/// Returns:
/// - `Ok(MutabilityStatus::Immutable)` — no admin key with a non-zero address.
/// - `Ok(MutabilityStatus::Mutable { admin_or_owner_key, holder_redacted })` —
///   first `ADMIN_KEY_NAMES` match with a non-zero `ScVal::Address`.
///
/// # Errors
///
/// Returns `SaError::DeploymentFailed` if the XDR is present but cannot be
/// decoded — indicates a corrupt or unexpected RPC response.
fn inspect_storage_for_admin_key(
    storage_xdr_opt: Option<Vec<u8>>,
    smart_account_redacted: &str,
) -> Result<MutabilityStatus, SaError> {
    use stellar_xdr::{ReadXdr, ScMap, ScVal, ScVec};
    // redact_strkey_first5_last5 is already imported at the module top (line 85).

    let Some(storage_xdr) = storage_xdr_opt else {
        // No instance storage (or contract absent) → Immutable.
        return Ok(MutabilityStatus::Immutable);
    };

    if storage_xdr.is_empty() {
        // Contract instance has `storage: None` → Immutable.
        return Ok(MutabilityStatus::Immutable);
    }

    // Decode the raw bytes as `ScVal::Map(Some(ScMap))`.
    let map: ScMap = match ScVal::from_xdr(
        &storage_xdr,
        stellar_agent_xdr_limits::untrusted_decode_limits(storage_xdr.len()),
    ) {
        Ok(ScVal::Map(Some(m))) => m,
        Ok(_) => {
            // Unexpected storage shape: fail closed so a malformed or evasive
            // instance-storage value cannot bypass mutability refusal.
            // Keep this branch aligned with the non-map instance-storage
            // fail-closed path asserted by the mutability adversarial fixtures.
            return Ok(MutabilityStatus::Mutable {
                admin_or_owner_key: AdminOrOwnerKey::Admin,
                holder_redacted: "[non-map-instance-storage]".to_owned(),
            });
        }
        Err(e) => {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!(
                    "contract instance storage XDR decode failed for {smart_account_redacted}: {e}"
                ),
            });
        }
    };

    // Search the instance-storage ScMap for each surveyed admin-key name.
    //
    // `#[contracttype]` unit variant `Admin` encodes as
    // `ScVal::Vec(Some(ScVec([ScVal::Symbol("Admin")])))` when used as a map key:
    //   - `map_empty_variant` `into_xdr` arm (`soroban-sdk-macros`, `derive_enum.rs`):
    //     `(ScVal::Symbol("Admin"),).try_into()` → `ScVec([ScSymbol("Admin")])`.
    //   - `TryFrom<&Enum> for ScVal` (`soroban-sdk-macros`, `derive_enum.rs`):
    //     `ScVal::Vec(Some(scvec))` wraps the single-element vec.
    // The key is therefore NOT a bare `ScVal::Symbol("Admin")`.
    for &key_name in ADMIN_KEY_NAMES {
        let key_name_str = key_name.to_string();
        let symbol =
            ScVal::Symbol(stellar_xdr::ScSymbol(
                key_name_str.as_bytes().to_vec().try_into().map_err(|_| {
                    SaError::DeploymentFailed {
                        phase: "simulate",
                        redacted_reason: format!(
                            "admin key name '{key_name}' too long for ScSymbol (impossible)"
                        ),
                    }
                })?,
            ));
        let target_key = ScVal::Vec(Some(ScVec(vec![symbol].try_into().map_err(|_| {
            SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!(
                    "admin key ScVec construction failed for '{key_name}' (impossible)"
                ),
            }
        })?)));

        for entry in map.iter() {
            if entry.key != target_key {
                continue;
            }

            // Found the key; check whether its value is a non-zero ScVal::Address.
            match &entry.val {
                ScVal::Address(holder_addr) => {
                    // Non-zero address → Mutable.
                    let holder_strkey = xdr_scaddress_to_strkey_or_sentinel(holder_addr);
                    let holder_redacted = redact_strkey_first5_last5(&holder_strkey);
                    return Ok(MutabilityStatus::Mutable {
                        admin_or_owner_key: key_name,
                        holder_redacted,
                    });
                }
                ScVal::Void => {
                    // Void = explicitly cleared / null → treat as absent → continue search.
                    continue;
                }
                _ => {
                    // Unexpected ScVal discriminant for an admin/owner key.
                    // fail-CLOSED: a non-Address value at a key OZ canonically stores as
                    // Address indicates either contract drift or an evasion attempt. Treat as
                    // Mutable defensively — pin-refusal at install is recoverable via
                    // --accept-mutable-verifier; missed mutability is not.
                    return Ok(MutabilityStatus::Mutable {
                        admin_or_owner_key: key_name,
                        holder_redacted: "[non-address-admin-value]".to_owned(),
                    });
                }
            }
        }
    }

    Ok(MutabilityStatus::Immutable)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; asserts via expect/unwrap/panic are intentional"
    )]

    use stellar_xdr::{ContractId, Hash};

    use super::*;

    /// Builds the correct on-wire `ScVal` map key for a `#[contracttype]` unit
    /// variant named `name` (e.g. `"Admin"`, `"Owner"`).
    ///
    /// The encoding is `ScVal::Vec(Some(ScVec([ScVal::Symbol(name)])))`.
    /// Canonical source: `soroban-sdk-macros`, `derive_enum.rs`,
    /// `map_empty_variant` `into_xdr` arm and `TryFrom<&Enum> for ScVal`.
    fn contracttype_unit_key(name: &[u8]) -> stellar_xdr::ScVal {
        use stellar_xdr::{ScSymbol, ScVal, ScVec};
        let symbol = ScVal::Symbol(ScSymbol(name.to_vec().try_into().expect("key name fits")));
        ScVal::Vec(Some(ScVec(
            vec![symbol].try_into().expect("single-element ScVec fits"),
        )))
    }

    // ── MutabilityStatus unit tests ───────────────────────────────────────────

    /// `MutabilityStatus::Immutable` when storage XDR is None (absent instance storage).
    #[test]
    fn mutability_status_immutable_for_no_storage() {
        let result = inspect_storage_for_admin_key(None, "CAAAA...ABSC4");
        assert_eq!(
            result.unwrap(),
            MutabilityStatus::Immutable,
            "absent instance storage must yield Immutable"
        );
    }

    /// `MutabilityStatus::Immutable` when storage XDR is present but empty
    /// (contract instance has `storage: None`).
    #[test]
    fn mutability_status_immutable_for_empty_storage_bytes() {
        let result = inspect_storage_for_admin_key(Some(vec![]), "CAAAA...ABSC4");
        assert_eq!(
            result.unwrap(),
            MutabilityStatus::Immutable,
            "empty storage bytes must yield Immutable"
        );
    }

    /// `MutabilityStatus::Immutable` when instance storage map has no Admin or Owner key.
    #[test]
    fn mutability_status_immutable_for_no_admin_key() {
        use stellar_xdr::WriteXdr;

        // Build a ScVal::Map with an unrelated key.
        let entry = stellar_xdr::ScMapEntry {
            key: stellar_xdr::ScVal::Symbol(stellar_xdr::ScSymbol(
                b"SomeOtherKey".to_vec().try_into().unwrap(),
            )),
            val: stellar_xdr::ScVal::U64(42),
        };
        let map: stellar_xdr::ScMap = vec![entry].try_into().expect("map entry fits");
        let xdr_bytes = stellar_xdr::ScVal::Map(Some(map))
            .to_xdr(stellar_xdr::Limits::none())
            .unwrap();

        let result = inspect_storage_for_admin_key(Some(xdr_bytes), "CAAAA...ABSC4");
        assert_eq!(
            result.unwrap(),
            MutabilityStatus::Immutable,
            "storage with no Admin/Owner key must yield Immutable"
        );
    }

    /// `MutabilityStatus::Mutable` when instance storage map has an `Admin` key
    /// with a non-zero `ScVal::Address`.
    #[test]
    fn mutability_status_mutable_for_admin_key_set() {
        use stellar_xdr::WriteXdr;

        // A non-zero Ed25519 address: all 0x11 bytes.
        let admin_bytes = [0x11u8; 32];
        let admin_addr = stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(admin_bytes)),
        ));

        let entry = stellar_xdr::ScMapEntry {
            key: contracttype_unit_key(b"Admin"),
            val: stellar_xdr::ScVal::Address(admin_addr),
        };
        let map: stellar_xdr::ScMap = vec![entry].try_into().expect("map entry fits");
        let xdr_bytes = stellar_xdr::ScVal::Map(Some(map))
            .to_xdr(stellar_xdr::Limits::none())
            .unwrap();

        let result = inspect_storage_for_admin_key(Some(xdr_bytes), "CAAAA...ABSC4").unwrap();
        assert!(
            matches!(
                &result,
                MutabilityStatus::Mutable {
                    admin_or_owner_key: AdminOrOwnerKey::Admin,
                    ..
                }
            ),
            "Admin key with non-zero address must yield Mutable; got {result:?}"
        );
    }

    /// `MutabilityStatus::Mutable` when instance storage map has an `Owner` key
    /// with a non-zero contract address.
    #[test]
    fn mutability_status_mutable_for_owner_key_set() {
        use stellar_xdr::WriteXdr;

        let owner_addr = stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(
            stellar_xdr::Hash([0x22u8; 32]),
        ));
        let entry = stellar_xdr::ScMapEntry {
            key: contracttype_unit_key(b"Owner"),
            val: stellar_xdr::ScVal::Address(owner_addr),
        };
        let map: stellar_xdr::ScMap = vec![entry].try_into().expect("map entry fits");
        let xdr_bytes = stellar_xdr::ScVal::Map(Some(map))
            .to_xdr(stellar_xdr::Limits::none())
            .unwrap();

        let result = inspect_storage_for_admin_key(Some(xdr_bytes), "CAAAA...ABSC4").unwrap();
        assert!(
            matches!(
                &result,
                MutabilityStatus::Mutable {
                    admin_or_owner_key: AdminOrOwnerKey::Owner,
                    ..
                }
            ),
            "Owner key with non-zero address must yield Mutable; got {result:?}"
        );
    }

    /// `Admin` takes precedence over `Owner` when both keys are present
    /// (first-match-wins per `ADMIN_KEY_NAMES` order).
    #[test]
    fn mutability_status_admin_key_takes_precedence_over_owner() {
        use stellar_xdr::WriteXdr;

        let admin_addr = stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(
            stellar_xdr::Hash([0x11u8; 32]),
        ));
        let owner_addr = stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(
            stellar_xdr::Hash([0x22u8; 32]),
        ));
        let entries = vec![
            stellar_xdr::ScMapEntry {
                key: contracttype_unit_key(b"Admin"),
                val: stellar_xdr::ScVal::Address(admin_addr),
            },
            stellar_xdr::ScMapEntry {
                key: contracttype_unit_key(b"Owner"),
                val: stellar_xdr::ScVal::Address(owner_addr),
            },
        ];
        // ScMap entries must be sorted by key for XDR validity.
        // Both keys are ScVal::Vec([Symbol(...)]) — the byte-order of the XDR-encoded
        // vecs determines sort order; Admin sorts before Owner in practice.
        let map: stellar_xdr::ScMap = entries.try_into().expect("map entries fit");
        let xdr_bytes = stellar_xdr::ScVal::Map(Some(map))
            .to_xdr(stellar_xdr::Limits::none())
            .unwrap();

        let result = inspect_storage_for_admin_key(Some(xdr_bytes), "CAAAA...ABSC4").unwrap();
        assert!(
            matches!(
                &result,
                MutabilityStatus::Mutable {
                    admin_or_owner_key: AdminOrOwnerKey::Admin,
                    ..
                }
            ),
            "Admin must win when both Admin and Owner are present; got {result:?}"
        );
    }

    /// `MutabilityStatus::Immutable` when the `Admin` key value is `ScVal::Void`
    /// (explicitly cleared / null).
    #[test]
    fn mutability_status_immutable_for_admin_key_void() {
        use stellar_xdr::WriteXdr;

        let entry = stellar_xdr::ScMapEntry {
            key: contracttype_unit_key(b"Admin"),
            val: stellar_xdr::ScVal::Void,
        };
        let map: stellar_xdr::ScMap = vec![entry].try_into().expect("map entry fits");
        let xdr_bytes = stellar_xdr::ScVal::Map(Some(map))
            .to_xdr(stellar_xdr::Limits::none())
            .unwrap();

        let result = inspect_storage_for_admin_key(Some(xdr_bytes), "CAAAA...ABSC4").unwrap();
        assert_eq!(
            result,
            MutabilityStatus::Immutable,
            "Admin key with Void value must yield Immutable"
        );
    }

    #[test]
    fn mutability_status_mutable_for_non_address_admin_value() {
        use stellar_xdr::WriteXdr;

        let entry = stellar_xdr::ScMapEntry {
            key: contracttype_unit_key(b"Admin"),
            val: stellar_xdr::ScVal::U32(0),
        };
        let map: stellar_xdr::ScMap = vec![entry].try_into().expect("map entry fits");
        let xdr_bytes = stellar_xdr::ScVal::Map(Some(map))
            .to_xdr(stellar_xdr::Limits::none())
            .unwrap();

        let result = inspect_storage_for_admin_key(Some(xdr_bytes), "CAAAA...ABSC4").unwrap();
        assert_eq!(
            result,
            MutabilityStatus::Mutable {
                admin_or_owner_key: AdminOrOwnerKey::Admin,
                holder_redacted: "[non-address-admin-value]".to_owned(),
            },
            "non-address Admin value must fail closed as Mutable"
        );
    }

    #[test]
    fn mutability_status_mutable_for_non_map_instance_storage() {
        use stellar_xdr::WriteXdr;

        let xdr_bytes =
            stellar_xdr::ScVal::Bytes(stellar_xdr::ScBytes(vec![0xde, 0xad].try_into().unwrap()))
                .to_xdr(stellar_xdr::Limits::none())
                .unwrap();

        let result = inspect_storage_for_admin_key(Some(xdr_bytes), "CAAAA...ABSC4").unwrap();
        assert_eq!(
            result,
            MutabilityStatus::Mutable {
                admin_or_owner_key: AdminOrOwnerKey::Admin,
                holder_redacted: "[non-map-instance-storage]".to_owned(),
            },
            "non-map instance storage must fail closed as Mutable"
        );
    }

    #[test]
    fn emit_override_row_without_writer_fails_closed_when_override_requested() {
        let entry = AuditEntry::new_sa_mutable_contract_override(
            7,
            RedactedStrkey::from_already_redacted("CAAAA...ABSC4"),
            RedactedStrkey::from_already_redacted("CBBBB...BBBBB"),
            ContractKind::Verifier,
            "2026-05-20T00:00:00Z",
            "stellar:testnet",
            "req-override",
        );

        let err = emit_override_row(None, entry, "test override row", true, None).unwrap_err();
        assert_eq!(err.wire_code(), "sa.audit_log");
    }

    // ── detect_contract_mutability async integration tests ────────────────────

    /// `MutabilityStatus::Immutable` when both RPCs return a contract instance
    /// with no Admin / Owner key in instance storage.
    #[tokio::test]
    async fn mutability_status_immutable_for_no_admin_key_rpc() {
        use wiremock::{
            Mock, MockServer,
            matchers::{method, path},
        };

        // Re-use the test-fixture infrastructure from the adversarial fixture harness.
        // We need a contract instance ledger entry with no instance storage.
        let contract_addr = ScAddress::Contract(ContractId(Hash([0x03u8; 32])));
        let contract_addr_clone = contract_addr.clone();

        // Build a contract instance entry XDR with empty storage (None map).
        let instance_key_xdr = build_contract_instance_key_xdr(&contract_addr);
        let instance_entry_xdr = build_contract_instance_entry_xdr_no_storage(&contract_addr);
        let entries_response = serde_json::json!({
            "entries": [{ "key": instance_key_xdr, "xdr": instance_entry_xdr, "lastModifiedLedgerSeq": 100 }],
            "latestLedger": 1000
        });

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(canned_ledger_entries_responder(entries_response))
            .mount(&server)
            .await;

        let rpc = StellarRpcClient::new(&server.uri()).expect("RPC client");

        let result = detect_contract_mutability(
            &rpc,
            &rpc,
            &contract_addr_clone,
            1,
            "CAAAA...ABSC4",
            "test-request-id",
        )
        .await;

        assert_eq!(
            result.unwrap(),
            MutabilityStatus::Immutable,
            "contract with no instance storage must yield Immutable"
        );
    }

    /// `MutabilityStatus::Mutable` when both RPCs return a contract instance
    /// with an `Admin` key in instance storage.
    #[tokio::test]
    async fn mutability_status_mutable_for_admin_key_set_rpc() {
        use wiremock::{
            Mock, MockServer,
            matchers::{method, path},
        };

        let contract_addr = ScAddress::Contract(ContractId(Hash([0x03u8; 32])));
        let admin_addr = stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256([0x11u8; 32])),
        ));

        let instance_key_xdr = build_contract_instance_key_xdr(&contract_addr);
        let instance_entry_xdr =
            build_contract_instance_entry_xdr_with_admin(&contract_addr, &admin_addr, "Admin");
        let entries_response = serde_json::json!({
            "entries": [{ "key": instance_key_xdr, "xdr": instance_entry_xdr, "lastModifiedLedgerSeq": 100 }],
            "latestLedger": 1000
        });

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(canned_ledger_entries_responder(entries_response))
            .mount(&server)
            .await;

        let rpc = StellarRpcClient::new(&server.uri()).expect("RPC client");

        let result = detect_contract_mutability(
            &rpc,
            &rpc,
            &contract_addr,
            1,
            "CAAAA...ABSC4",
            "test-request-id",
        )
        .await;

        assert!(
            matches!(
                &result,
                Ok(MutabilityStatus::Mutable {
                    admin_or_owner_key: AdminOrOwnerKey::Admin,
                    ..
                })
            ),
            "Admin key present → Mutable; got {result:?}"
        );
    }

    /// `SaError::NetworkRpcDivergence` when primary and secondary RPCs disagree
    /// on the contract's instance storage.
    #[tokio::test]
    async fn mutability_status_rpc_divergence() {
        use wiremock::{
            Mock, MockServer,
            matchers::{method, path},
        };

        let contract_addr = ScAddress::Contract(ContractId(Hash([0x03u8; 32])));
        let admin_addr = stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256([0x11u8; 32])),
        ));

        // Primary: contract instance WITH Admin key.
        let instance_key_xdr = build_contract_instance_key_xdr(&contract_addr);
        let primary_entry_xdr =
            build_contract_instance_entry_xdr_with_admin(&contract_addr, &admin_addr, "Admin");
        let primary_response = serde_json::json!({
            "entries": [{ "key": instance_key_xdr.clone(), "xdr": primary_entry_xdr, "lastModifiedLedgerSeq": 100 }],
            "latestLedger": 1000
        });

        // Secondary: contract instance WITHOUT Admin key.
        let secondary_entry_xdr = build_contract_instance_entry_xdr_no_storage(&contract_addr);
        let secondary_response = serde_json::json!({
            "entries": [{ "key": instance_key_xdr, "xdr": secondary_entry_xdr, "lastModifiedLedgerSeq": 100 }],
            "latestLedger": 1000
        });

        let primary_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(canned_ledger_entries_responder(primary_response))
            .mount(&primary_server)
            .await;

        let secondary_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(canned_ledger_entries_responder(secondary_response))
            .mount(&secondary_server)
            .await;

        let primary_rpc = StellarRpcClient::new(&primary_server.uri()).expect("primary RPC client");
        let secondary_rpc =
            StellarRpcClient::new(&secondary_server.uri()).expect("secondary RPC client");

        let result = detect_contract_mutability(
            &primary_rpc,
            &secondary_rpc,
            &contract_addr,
            1,
            "CAAAA...ABSC4",
            "test-request-id",
        )
        .await;

        assert!(
            matches!(
                result,
                Err(SaError::NetworkRpcDivergence { rule_id: 1, .. })
            ),
            "diverging RPCs must return NetworkRpcDivergence; got {result:?}"
        );
        assert_eq!(
            result.unwrap_err().wire_code(),
            "network.rpc_divergence",
            "wire_code must be 'network.rpc_divergence'"
        );
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    /// Builds the XDR-base64 of a `LedgerKey::ContractData(LedgerKeyContractInstance)`.
    fn build_contract_instance_key_xdr(addr: &ScAddress) -> String {
        use stellar_xdr::WriteXdr;
        use stellar_xdr::{ContractDataDurability, LedgerKeyContractData};
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: addr.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        })
        .to_xdr_base64(stellar_xdr::Limits::none())
        .expect("LedgerKey XDR must encode")
    }

    /// Builds a `LedgerEntryData::ContractData(ContractInstance)` XDR with no
    /// instance storage (`storage: None`).
    fn build_contract_instance_entry_xdr_no_storage(contract: &ScAddress) -> String {
        use stellar_xdr::{
            ContractDataDurability, ContractDataEntry, ContractExecutable, ExtensionPoint,
            ScContractInstance,
        };
        use stellar_xdr::{LedgerEntryData, WriteXdr};
        let instance = ScContractInstance {
            executable: ContractExecutable::Wasm(Hash([0x42u8; 32])),
            storage: None,
        };
        LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: contract.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: stellar_xdr::ScVal::ContractInstance(instance),
        })
        .to_xdr_base64(stellar_xdr::Limits::none())
        .expect("ContractInstance XDR must encode")
    }

    /// Builds a `LedgerEntryData::ContractData(ContractInstance)` XDR with an
    /// instance storage map containing `key_name -> admin_addr`.
    fn build_contract_instance_entry_xdr_with_admin(
        contract: &ScAddress,
        admin_addr: &stellar_xdr::ScAddress,
        key_name: &str,
    ) -> String {
        use stellar_xdr::{
            ContractDataDurability, ContractDataEntry, ContractExecutable, ExtensionPoint,
            ScContractInstance, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec,
        };
        use stellar_xdr::{LedgerEntryData, WriteXdr};

        // `#[contracttype]` unit variant `Foo` on the wire is
        // `ScVal::Vec(Some(ScVec([ScVal::Symbol("Foo")])))` — not a bare Symbol.
        // See `soroban-sdk-macros`, `derive_enum.rs` (`map_empty_variant` +
        // `TryFrom<&Enum> for ScVal`).
        let symbol = ScVal::Symbol(ScSymbol(
            key_name
                .as_bytes()
                .to_vec()
                .try_into()
                .expect("key name fits"),
        ));
        let entry = ScMapEntry {
            key: ScVal::Vec(Some(ScVec(
                vec![symbol].try_into().expect("single-element ScVec fits"),
            ))),
            val: ScVal::Address(admin_addr.clone()),
        };
        let storage_map: ScMap = vec![entry].try_into().expect("map entry fits");
        let instance = ScContractInstance {
            executable: ContractExecutable::Wasm(Hash([0x42u8; 32])),
            storage: Some(storage_map),
        };
        LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: contract.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: stellar_xdr::ScVal::ContractInstance(instance),
        })
        .to_xdr_base64(stellar_xdr::Limits::none())
        .expect("ContractInstance XDR must encode")
    }

    /// Creates a `wiremock::Respond` impl that returns a canned
    /// `getLedgerEntries` result.
    fn canned_ledger_entries_responder(result: serde_json::Value) -> impl wiremock::Respond {
        struct CannedResponder(serde_json::Value);
        impl wiremock::Respond for CannedResponder {
            fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
                let body: serde_json::Value =
                    serde_json::from_slice(&request.body).unwrap_or(serde_json::json!({}));
                let req_id = body.get("id").cloned().unwrap_or(serde_json::json!(1));
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": self.0
                    }))
                    .insert_header("content-type", "application/json")
            }
        }
        CannedResponder(result)
    }

    // ── PinResult projection tests ────────────────────────────────────────────

    /// `pinned_verifier_hashes_first8` returns the correct first-8-hex for each
    /// pinned verifier wasm hash in order.
    ///
    /// Correctness: the expected values are the first 8 bytes of the respective
    /// hash arrays rendered as lowercase hex, derived independently of the
    /// implementation under test.
    #[test]
    fn pin_result_pinned_verifier_hashes_first8_returns_correct_projections() {
        let addr_a = ScAddress::Contract(ContractId(Hash([0x0au8; 32])));
        let addr_b = ScAddress::Contract(ContractId(Hash([0x0bu8; 32])));
        let hash_a: [u8; 32] = {
            let mut h = [0u8; 32];
            h[0] = 0xde;
            h[1] = 0xad;
            h[2] = 0xbe;
            h[3] = 0xef;
            h[4] = 0x01;
            h[5] = 0x02;
            h[6] = 0x03;
            h[7] = 0x04;
            h
        };
        let hash_b: [u8; 32] = {
            let mut h = [0xffu8; 32];
            h[0] = 0xaa;
            h[1] = 0xbb;
            h
        };
        let pin = PinResult {
            pinned_verifier_wasm_hashes: vec![(addr_a, hash_a), (addr_b, hash_b)],
            pinned_policy_wasm_hashes: vec![],
            mutable_override: false,
            unknown_override: false,
        };

        let result = pin.pinned_verifier_hashes_first8();

        // Expected: first 8 bytes of hash_a and hash_b as lowercase hex.
        assert_eq!(result.len(), 2, "two verifier hashes → two projections");
        assert_eq!(
            result[0], "deadbeef01020304",
            "first hash projection must match first 8 bytes of hash_a"
        );
        assert_eq!(
            result[1], "aabbffffffffffff",
            "second hash projection must match first 8 bytes of hash_b"
        );
    }

    /// `pinned_policy_hashes_first8` returns the correct first-8-hex for each
    /// pinned policy wasm hash in order.
    #[test]
    fn pin_result_pinned_policy_hashes_first8_returns_correct_projections() {
        let addr_p = ScAddress::Contract(ContractId(Hash([0x0cu8; 32])));
        let hash_p: [u8; 32] = {
            let mut h = [0x00u8; 32];
            h[0] = 0x11;
            h[1] = 0x22;
            h[2] = 0x33;
            h[3] = 0x44;
            h[4] = 0x55;
            h[5] = 0x66;
            h[6] = 0x77;
            h[7] = 0x88;
            h
        };
        let pin = PinResult {
            pinned_verifier_wasm_hashes: vec![],
            pinned_policy_wasm_hashes: vec![(addr_p, hash_p)],
            mutable_override: false,
            unknown_override: false,
        };

        let result = pin.pinned_policy_hashes_first8();

        assert_eq!(result.len(), 1, "one policy hash → one projection");
        assert_eq!(
            result[0], "1122334455667788",
            "policy hash projection must match first 8 bytes"
        );
    }

    /// Empty `PinResult` — both projections return empty vecs.
    #[test]
    fn pin_result_empty_both_projections_are_empty() {
        let pin = PinResult {
            pinned_verifier_wasm_hashes: vec![],
            pinned_policy_wasm_hashes: vec![],
            mutable_override: false,
            unknown_override: false,
        };
        assert!(
            pin.pinned_verifier_hashes_first8().is_empty(),
            "empty verifier hashes → empty projection"
        );
        assert!(
            pin.pinned_policy_hashes_first8().is_empty(),
            "empty policy hashes → empty projection"
        );
    }

    // ── scaddress_cache_key tests ─────────────────────────────────────────────

    /// `scaddress_cache_key` returns a non-empty byte slice for a valid contract address.
    ///
    /// The exact byte sequence is the XDR encoding of the ScAddress.  We verify
    /// the length matches independent XDR serialisation rather than hard-coding
    /// the encoding here.
    #[test]
    fn scaddress_cache_key_returns_xdr_bytes_for_contract() {
        use stellar_xdr::WriteXdr;

        let addr = ScAddress::Contract(ContractId(Hash([0x42u8; 32])));
        let expected = addr
            .to_xdr(stellar_xdr::Limits::none())
            .expect("XDR encode must succeed");

        let result = scaddress_cache_key(&addr).expect("scaddress_cache_key must succeed");

        assert_eq!(
            result, expected,
            "cache key must equal the raw XDR bytes of the address"
        );
    }

    /// Two distinct addresses produce different cache keys.
    #[test]
    fn scaddress_cache_key_distinct_addresses_produce_distinct_keys() {
        let addr_a = ScAddress::Contract(ContractId(Hash([0x01u8; 32])));
        let addr_b = ScAddress::Contract(ContractId(Hash([0x02u8; 32])));

        let key_a = scaddress_cache_key(&addr_a).expect("must succeed");
        let key_b = scaddress_cache_key(&addr_b).expect("must succeed");

        assert_ne!(
            key_a, key_b,
            "distinct addresses must produce distinct cache keys"
        );
    }

    /// Same address encodes to the same cache key (deterministic).
    #[test]
    fn scaddress_cache_key_is_deterministic() {
        let addr = ScAddress::Contract(ContractId(Hash([0x55u8; 32])));
        let key1 = scaddress_cache_key(&addr).expect("must succeed");
        let key2 = scaddress_cache_key(&addr).expect("must succeed");
        assert_eq!(key1, key2, "same address must produce identical cache keys");
    }

    // ── emit_override_row additional path tests ───────────────────────────────

    /// `emit_override_row` succeeds when a real `AuditWriter` is provided and
    /// the entry can be written (no I/O error).
    #[test]
    fn emit_override_row_with_real_writer_succeeds() {
        use std::sync::{Arc, Mutex};

        use stellar_agent_core::audit_log::entry::AuditEntry;
        use stellar_agent_core::audit_log::schema::ContractKind;
        use stellar_agent_core::audit_log::writer::AuditWriter;

        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("audit").join("test.jsonl");
        let writer = AuditWriter::open(path, None).expect("AuditWriter::open");
        let arc = Arc::new(Mutex::new(writer));

        let entry = AuditEntry::new_sa_mutable_contract_override(
            1,
            RedactedStrkey::from_already_redacted("CAAAA...12345"),
            RedactedStrkey::from_already_redacted("CBBBB...67890"),
            ContractKind::Verifier,
            "2026-06-23T00:00:00Z",
            "stellar:testnet",
            "req-emit-test",
        );

        let result = emit_override_row(Some(&arc), entry, "test-op", true, None);

        assert!(
            result.is_ok(),
            "emit_override_row with real writer must succeed; got {result:?}"
        );
    }

    /// `emit_override_row` returns `Ok(())` when no writer is provided AND
    /// `override_requested` is `false` — the non-override, no-writer path.
    #[test]
    fn emit_override_row_without_writer_ok_when_not_override_requested() {
        let entry = AuditEntry::new_sa_mutable_contract_override(
            5,
            RedactedStrkey::from_already_redacted("CAAAA...ABSC4"),
            RedactedStrkey::from_already_redacted("CCCCC...CCCCC"),
            ContractKind::Policy,
            "2026-06-23T00:00:00Z",
            "stellar:testnet",
            "req-no-override",
        );

        // override_requested=false + no writer → Ok(())
        let result = emit_override_row(None, entry, "test-no-override", false, None);
        assert!(
            result.is_ok(),
            "emit_override_row with no writer and no override must return Ok(())"
        );
    }

    /// `emit_override_row` returns `SaError::AuditLog` when the mutex is
    /// poisoned and `override_requested` is `true`.
    ///
    /// The poisoned-mutex path must fail closed (not silently swallow the error)
    /// because an override audit row that cannot be written is a security gap.
    #[test]
    fn emit_override_row_with_poisoned_mutex_fails_closed_when_override_requested() {
        use std::sync::{Arc, Mutex};

        use stellar_agent_core::audit_log::writer::AuditWriter;

        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("audit").join("poison.jsonl");
        let writer = AuditWriter::open(path, None).expect("AuditWriter::open");
        let arc: Arc<Mutex<AuditWriter>> = Arc::new(Mutex::new(writer));

        // Poison the mutex by panicking inside a lock guard.
        let arc_clone = Arc::clone(&arc);
        let _ = std::panic::catch_unwind(|| {
            let _guard = arc_clone.lock().unwrap();
            panic!("intentional poison");
        });
        assert!(arc.is_poisoned(), "mutex must be poisoned after the panic");

        let entry = AuditEntry::new_sa_mutable_contract_override(
            9,
            RedactedStrkey::from_already_redacted("CAAAA...ABSC4"),
            RedactedStrkey::from_already_redacted("CDDDD...DDDDD"),
            ContractKind::Verifier,
            "2026-06-23T00:00:00Z",
            "stellar:testnet",
            "req-poison",
        );

        let result = emit_override_row(Some(&arc), entry, "test-poison", true, None);

        let err = result.expect_err("poisoned mutex + override_requested must fail closed");
        assert_eq!(
            err.wire_code(),
            "sa.audit_log",
            "wire_code must be sa.audit_log on poisoned mutex"
        );
    }

    /// `emit_override_row` returns `Ok(())` when the mutex is poisoned but
    /// `override_requested` is `false` — the non-override poisoned-mutex path
    /// does NOT fail the caller.
    #[test]
    fn emit_override_row_with_poisoned_mutex_ok_when_not_override_requested() {
        use std::sync::{Arc, Mutex};

        use stellar_agent_core::audit_log::writer::AuditWriter;

        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("audit").join("poison2.jsonl");
        let writer = AuditWriter::open(path, None).expect("AuditWriter::open");
        let arc: Arc<Mutex<AuditWriter>> = Arc::new(Mutex::new(writer));

        let arc_clone = Arc::clone(&arc);
        let _ = std::panic::catch_unwind(|| {
            let _guard = arc_clone.lock().unwrap();
            panic!("intentional poison");
        });
        assert!(arc.is_poisoned(), "mutex must be poisoned");

        let entry = AuditEntry::new_sa_mutable_contract_override(
            10,
            RedactedStrkey::from_already_redacted("CAAAA...ABSC4"),
            RedactedStrkey::from_already_redacted("CEEEE...EEEEE"),
            ContractKind::Policy,
            "2026-06-23T00:00:00Z",
            "stellar:testnet",
            "req-poison-ok",
        );

        // override_requested=false + poisoned mutex → Ok(())
        let result = emit_override_row(Some(&arc), entry, "test-poison-no-override", false, None);
        assert!(
            result.is_ok(),
            "poisoned mutex with override_requested=false must return Ok(())"
        );
    }

    // ── inspect_storage_for_admin_key error-path tests ────────────────────────

    /// `inspect_storage_for_admin_key` returns `SaError::DeploymentFailed` when
    /// the XDR bytes are present but are not a valid XDR encoding at all (corrupt
    /// data).
    ///
    /// This path is distinct from the non-map path: here decoding fails entirely.
    #[test]
    fn inspect_storage_for_admin_key_returns_error_on_corrupt_xdr() {
        // Random bytes that cannot decode as any valid XDR ScVal.
        let corrupt_bytes: Vec<u8> = vec![0xffu8; 17]; // odd length + bad discriminant

        let result = inspect_storage_for_admin_key(Some(corrupt_bytes), "CAAAA...ABSC4");

        assert!(
            matches!(
                result,
                Err(SaError::DeploymentFailed {
                    phase: "simulate",
                    ..
                })
            ),
            "corrupt XDR must return DeploymentFailed(simulate); got {result:?}"
        );
    }

    /// `inspect_storage_for_admin_key` returns `Mutable` (fail-closed) when the
    /// XDR decodes to a valid ScVal but it is `ScVal::U64` (not `ScVal::Map`).
    ///
    /// The non-map path is the fail-closed branch for evasion attempts.
    #[test]
    fn inspect_storage_for_admin_key_fails_closed_for_u64_scval() {
        use stellar_xdr::WriteXdr;

        // Encode a valid ScVal::U64 — decodes successfully, but is not a Map.
        let xdr_bytes = stellar_xdr::ScVal::U64(0xdead)
            .to_xdr(stellar_xdr::Limits::none())
            .expect("ScVal::U64 XDR encode must succeed");

        let result = inspect_storage_for_admin_key(Some(xdr_bytes), "CAAAA...ABSC4")
            .expect("must not error");

        assert_eq!(
            result,
            MutabilityStatus::Mutable {
                admin_or_owner_key: AdminOrOwnerKey::Admin,
                holder_redacted: "[non-map-instance-storage]".to_owned(),
            },
            "a non-map ScVal must fail closed as Mutable"
        );
    }

    /// `inspect_storage_for_admin_key` returns `Immutable` when the instance
    /// storage map contains the `Owner` key with `ScVal::Void` value, then
    /// finds no other admin key.
    ///
    /// This covers the Void-skip path for the second `ADMIN_KEY_NAMES` entry
    /// (`Owner`), after `Admin` is absent.
    #[test]
    fn mutability_status_immutable_for_owner_key_void() {
        use stellar_xdr::WriteXdr;

        let entry = stellar_xdr::ScMapEntry {
            key: contracttype_unit_key(b"Owner"),
            val: stellar_xdr::ScVal::Void,
        };
        let map: stellar_xdr::ScMap = vec![entry].try_into().expect("map entry fits");
        let xdr_bytes = stellar_xdr::ScVal::Map(Some(map))
            .to_xdr(stellar_xdr::Limits::none())
            .unwrap();

        let result = inspect_storage_for_admin_key(Some(xdr_bytes), "CAAAA...ABSC4").unwrap();
        assert_eq!(
            result,
            MutabilityStatus::Immutable,
            "Owner key with Void value must yield Immutable (no admin found)"
        );
    }

    /// `inspect_storage_for_admin_key` returns `Mutable` when the `Owner` key
    /// has a non-Address value (fail-closed defensive branch for `Owner`).
    #[test]
    fn mutability_status_mutable_for_non_address_owner_value() {
        use stellar_xdr::WriteXdr;

        let entry = stellar_xdr::ScMapEntry {
            key: contracttype_unit_key(b"Owner"),
            val: stellar_xdr::ScVal::I64(-1),
        };
        let map: stellar_xdr::ScMap = vec![entry].try_into().expect("map entry fits");
        let xdr_bytes = stellar_xdr::ScVal::Map(Some(map))
            .to_xdr(stellar_xdr::Limits::none())
            .unwrap();

        let result = inspect_storage_for_admin_key(Some(xdr_bytes), "CAAAA...ABSC4").unwrap();
        assert_eq!(
            result,
            MutabilityStatus::Mutable {
                admin_or_owner_key: AdminOrOwnerKey::Owner,
                holder_redacted: "[non-address-admin-value]".to_owned(),
            },
            "non-address Owner value must fail closed as Mutable with Owner key"
        );
    }

    // ── fetch_contract_instance_storage edge-path tests via RPC mock ──────────

    /// `detect_contract_mutability` handles a response entry that carries a
    /// non-Wasm `ContractData` value (e.g. `ScVal::U64` instead of
    /// `ScVal::ContractInstance`).  The code preserves the discriminant bytes
    /// so `inspect_storage_for_admin_key` can fail closed.
    ///
    /// Both RPCs agree on this malformed response → the non-map fail-closed path
    /// in `inspect_storage_for_admin_key` triggers → `Mutable` is returned.
    #[tokio::test]
    async fn detect_mutability_non_wasm_contract_data_fails_closed_as_mutable() {
        use stellar_xdr::{
            ContractDataDurability, ContractDataEntry, ExtensionPoint, LedgerEntryData, WriteXdr,
        };
        use wiremock::{
            Mock, MockServer,
            matchers::{method, path},
        };

        let contract_addr = ScAddress::Contract(ContractId(Hash([0x07u8; 32])));

        // Build a ContractData entry whose `val` is ScVal::U64 (not ContractInstance).
        // This reaches the `else` branch in fetch_contract_instance_storage.
        let instance_key_xdr = build_contract_instance_key_xdr(&contract_addr);
        let non_wasm_entry_xdr = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: contract_addr.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::U64(0xdeadbeef),
        })
        .to_xdr_base64(stellar_xdr::Limits::none())
        .expect("ContractDataEntry XDR must encode");

        let entries_response = serde_json::json!({
            "entries": [{ "key": instance_key_xdr, "xdr": non_wasm_entry_xdr, "lastModifiedLedgerSeq": 100 }],
            "latestLedger": 1000
        });

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(canned_ledger_entries_responder(entries_response))
            .mount(&server)
            .await;

        let rpc = StellarRpcClient::new(&server.uri()).expect("RPC client");

        let result = detect_contract_mutability(
            &rpc,
            &rpc,
            &contract_addr,
            2,
            "CAAAA...ABSC4",
            "req-non-wasm",
        )
        .await
        .expect("detect_contract_mutability must not return Err");

        // The non-Wasm ContractData val (ScVal::U64) gets XDR-encoded as storage bytes
        // and passed to inspect_storage_for_admin_key, which decodes it as ScVal::U64
        // (not ScVal::Map(Some(_))) → fail-closed Mutable branch.
        assert_eq!(
            result,
            MutabilityStatus::Mutable {
                admin_or_owner_key: AdminOrOwnerKey::Admin,
                holder_redacted: "[non-map-instance-storage]".to_owned(),
            },
            "non-Wasm ContractData must fail closed as Mutable; got {result:?}"
        );
    }

    /// `detect_contract_mutability` returns `Immutable` when the RPC returns no
    /// entries for the requested key (contract absent from ledger).
    #[tokio::test]
    async fn detect_mutability_absent_contract_returns_immutable() {
        use wiremock::{
            Mock, MockServer,
            matchers::{method, path},
        };

        let contract_addr = ScAddress::Contract(ContractId(Hash([0x08u8; 32])));

        // Empty `entries` array: the contract does not exist on the ledger.
        let entries_response = serde_json::json!({
            "entries": [],
            "latestLedger": 1000
        });

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(canned_ledger_entries_responder(entries_response))
            .mount(&server)
            .await;

        let rpc = StellarRpcClient::new(&server.uri()).expect("RPC client");

        let result = detect_contract_mutability(
            &rpc,
            &rpc,
            &contract_addr,
            3,
            "CAAAA...ABSC4",
            "req-absent",
        )
        .await
        .expect("absent contract must yield Immutable, not an error");

        assert_eq!(
            result,
            MutabilityStatus::Immutable,
            "absent contract (no entries) must yield Immutable"
        );
    }

    /// `detect_contract_mutability` returns `Mutable` with `Owner` key when the
    /// RPC response contains a contract instance whose instance-storage map has
    /// an `Owner` key set to a non-zero address (distinct from the Admin key path
    /// tested by `mutability_status_mutable_for_admin_key_set_rpc`).
    #[tokio::test]
    async fn detect_mutability_owner_key_returns_mutable_via_rpc() {
        use wiremock::{
            Mock, MockServer,
            matchers::{method, path},
        };

        let contract_addr = ScAddress::Contract(ContractId(Hash([0x09u8; 32])));
        let owner_addr = stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(
            stellar_xdr::Hash([0x33u8; 32]),
        ));

        let instance_key_xdr = build_contract_instance_key_xdr(&contract_addr);
        let instance_entry_xdr =
            build_contract_instance_entry_xdr_with_admin(&contract_addr, &owner_addr, "Owner");
        let entries_response = serde_json::json!({
            "entries": [{ "key": instance_key_xdr, "xdr": instance_entry_xdr, "lastModifiedLedgerSeq": 100 }],
            "latestLedger": 1000
        });

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(canned_ledger_entries_responder(entries_response))
            .mount(&server)
            .await;

        let rpc = StellarRpcClient::new(&server.uri()).expect("RPC client");

        let result = detect_contract_mutability(
            &rpc,
            &rpc,
            &contract_addr,
            4,
            "CAAAA...ABSC4",
            "req-owner-key",
        )
        .await
        .expect("detect_contract_mutability must not error");

        assert!(
            matches!(
                &result,
                MutabilityStatus::Mutable {
                    admin_or_owner_key: AdminOrOwnerKey::Owner,
                    ..
                }
            ),
            "Owner key present → Mutable with Owner variant; got {result:?}"
        );
    }

    /// `detect_contract_mutability` skips a response entry whose key is malformed
    /// (not valid XDR).  The malformed entry is ignored and the result is
    /// `Immutable` (the key is absent after skipping).
    ///
    /// This covers the `Err(_) => continue` branch in `fetch_contract_instance_storage`
    /// that fires when `XdrLedgerKey::from_xdr_base64` fails.
    #[tokio::test]
    async fn detect_mutability_skips_malformed_response_key() {
        use wiremock::{
            Mock, MockServer,
            matchers::{method, path},
        };

        let contract_addr = ScAddress::Contract(ContractId(Hash([0x0au8; 32])));

        // The response entry has a key that is not valid base64 XDR, so
        // `XdrLedgerKey::from_xdr_base64` will fail → `continue`.
        let entries_response = serde_json::json!({
            "entries": [{
                "key": "!!!INVALID-XDR-BASE64!!!",
                "xdr": "AAAAAA==",
                "lastModifiedLedgerSeq": 100
            }],
            "latestLedger": 1000
        });

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(canned_ledger_entries_responder(entries_response))
            .mount(&server)
            .await;

        let rpc = StellarRpcClient::new(&server.uri()).expect("RPC client");

        let result = detect_contract_mutability(
            &rpc,
            &rpc,
            &contract_addr,
            5,
            "CAAAA...ABSC4",
            "req-malformed-key",
        )
        .await
        .expect("malformed key must be skipped, not errored");

        // After skipping the malformed entry, no key resolved → absent → Immutable.
        assert_eq!(
            result,
            MutabilityStatus::Immutable,
            "malformed response key must be skipped; result is Immutable"
        );
    }

    /// `detect_contract_mutability` skips a response entry whose `xdr` field is
    /// not valid `LedgerEntryData` XDR.  The entry is silently ignored and the
    /// result is `Immutable`.
    ///
    /// This covers the `Err(_) => continue` branch in `fetch_contract_instance_storage`
    /// that fires when `LedgerEntryData::from_xdr_base64` fails.
    #[tokio::test]
    async fn detect_mutability_skips_malformed_response_xdr() {
        use wiremock::{
            Mock, MockServer,
            matchers::{method, path},
        };

        let contract_addr = ScAddress::Contract(ContractId(Hash([0x0bu8; 32])));
        let instance_key_xdr = build_contract_instance_key_xdr(&contract_addr);

        // The key decodes correctly but the XDR payload is invalid LedgerEntryData.
        let entries_response = serde_json::json!({
            "entries": [{
                "key": instance_key_xdr,
                "xdr": "bm90dmFsaWR4ZHI=",  // base64("notvalidxdr") — parses as base64 but not LedgerEntryData
                "lastModifiedLedgerSeq": 100
            }],
            "latestLedger": 1000
        });

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(canned_ledger_entries_responder(entries_response))
            .mount(&server)
            .await;

        let rpc = StellarRpcClient::new(&server.uri()).expect("RPC client");

        let result = detect_contract_mutability(
            &rpc,
            &rpc,
            &contract_addr,
            6,
            "CAAAA...ABSC4",
            "req-malformed-xdr",
        )
        .await
        .expect("malformed XDR must be skipped, not errored");

        // After skipping the malformed entry, no position resolved → None → Immutable.
        assert_eq!(
            result,
            MutabilityStatus::Immutable,
            "malformed response XDR must be skipped; result is Immutable"
        );
    }

    /// `detect_contract_mutability` skips a response entry whose key decodes to
    /// a valid `LedgerKey` but does not match any key in the request set.
    ///
    /// This covers the `None => continue` branch for `keys.iter().position(...)`.
    #[tokio::test]
    async fn detect_mutability_skips_response_entry_not_in_request_set() {
        use wiremock::{
            Mock, MockServer,
            matchers::{method, path},
        };

        let contract_addr = ScAddress::Contract(ContractId(Hash([0x0cu8; 32])));
        // Unrelated contract — the response contains a key for a different address.
        let other_addr = ScAddress::Contract(ContractId(Hash([0xeeu8; 32])));
        let other_key_xdr = build_contract_instance_key_xdr(&other_addr);
        let other_entry_xdr = build_contract_instance_entry_xdr_no_storage(&other_addr);

        let entries_response = serde_json::json!({
            "entries": [{
                "key": other_key_xdr,
                "xdr": other_entry_xdr,
                "lastModifiedLedgerSeq": 100
            }],
            "latestLedger": 1000
        });

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(canned_ledger_entries_responder(entries_response))
            .mount(&server)
            .await;

        let rpc = StellarRpcClient::new(&server.uri()).expect("RPC client");

        let result = detect_contract_mutability(
            &rpc,
            &rpc,
            &contract_addr,
            7,
            "CAAAA...ABSC4",
            "req-unrelated-entry",
        )
        .await
        .expect("unrelated entry must be skipped, not errored");

        // The entry for `other_addr` is not in our request set → skipped → Immutable.
        assert_eq!(
            result,
            MutabilityStatus::Immutable,
            "response entry not in request set must be skipped; result is Immutable"
        );
    }

    /// `inspect_storage_for_admin_key` correctly identifies the `holder_redacted`
    /// value for an Admin holder.  The redacted strkey is the first-5-last-5
    /// of the holder's strkey string representation.
    ///
    /// This test verifies the exact holder_redacted content rather than using `..`
    /// to elide it — confirming that the redaction logic is correct for the
    /// concrete address used in related tests.
    #[test]
    fn mutability_status_mutable_admin_holder_redacted_is_correctly_formatted() {
        use stellar_xdr::WriteXdr;

        // [0x11u8; 32] → ed25519 public key; independently compute the strkey
        // using the production stellar_strkey crate (not the function under test).
        let admin_bytes = [0x11u8; 32];
        let admin_addr = stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(admin_bytes)),
        ));

        // Independently compute the expected redacted strkey using stellar_strkey directly.
        let strkey = stellar_strkey::ed25519::PublicKey(admin_bytes).to_string();
        assert!(
            strkey.chars().count() > 10,
            "strkey must be long enough to redact"
        );
        let first5: String = strkey.chars().take(5).collect();
        let last5: String = strkey
            .chars()
            .rev()
            .take(5)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let expected_redacted = format!("{first5}...{last5}");

        let entry = stellar_xdr::ScMapEntry {
            key: contracttype_unit_key(b"Admin"),
            val: stellar_xdr::ScVal::Address(admin_addr),
        };
        let map: stellar_xdr::ScMap = vec![entry].try_into().expect("map entry fits");
        let xdr_bytes = stellar_xdr::ScVal::Map(Some(map))
            .to_xdr(stellar_xdr::Limits::none())
            .unwrap();

        let result = inspect_storage_for_admin_key(Some(xdr_bytes), "CAAAA...ABSC4").unwrap();
        match &result {
            MutabilityStatus::Mutable {
                admin_or_owner_key,
                holder_redacted,
            } => {
                assert_eq!(
                    *admin_or_owner_key,
                    AdminOrOwnerKey::Admin,
                    "key must be Admin"
                );
                assert_eq!(
                    holder_redacted, &expected_redacted,
                    "holder_redacted must match first-5-last-5 of the admin strkey"
                );
            }
            other => panic!("expected Mutable; got {other:?}"),
        }
    }
}

// ── Test-helper re-exports (feature-gated) ────────────────────────────────────

/// Public re-exports of signing-time drift-detection helpers for use in
/// integration-test adversarial fixtures.
///
/// Enabled only when the `test-helpers` feature is active.  NEVER included in
/// production builds.  Test-only public helpers must be feature-gated with
/// `#[cfg(any(test, feature = "test-helpers"))]` to prevent inclusion in
/// production binaries.
///
/// # Usage
///
/// ```toml
/// # Cargo.toml dev-dependency or integration-test invocation:
/// cargo test --features test-helpers
/// ```
#[doc(hidden)]
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use std::collections::HashMap;

    use stellar_xdr::ScAddress;

    use crate::SaError;
    use crate::managers::signers::SignersManager;
    use stellar_agent_core::audit_log::reader::PinnedHashesRecord;

    /// Exposed version of [`super::read_pinned_hashes_for_rule`] for
    /// adversarial fixture tests.
    ///
    /// # Errors
    ///
    /// Same as [`super::read_pinned_hashes_for_rule`].
    #[doc(hidden)]
    pub fn read_pinned_hashes_for_rule(
        signers_manager: &SignersManager,
        rule_id: u32,
        smart_account_redacted: &str,
    ) -> Result<Option<PinnedHashesRecord>, SaError> {
        super::read_pinned_hashes_for_rule(signers_manager, rule_id, smart_account_redacted)
    }

    /// Exposed version of [`super::verify_pinned_verifier_against_chain`] for
    /// adversarial fixture tests.
    ///
    /// # Errors
    ///
    /// Same as [`super::verify_pinned_verifier_against_chain`].
    #[doc(hidden)]
    pub async fn verify_pinned_verifier_against_chain(
        signers_manager: &SignersManager,
        verifier_addr: ScAddress,
        rule_id: u32,
        smart_account_redacted: &str,
        request_id: &str,
        wasm_hash_cache: &mut HashMap<Vec<u8>, [u8; 32]>,
    ) -> Result<(), SaError> {
        super::verify_pinned_verifier_against_chain(
            signers_manager,
            verifier_addr,
            rule_id,
            smart_account_redacted,
            request_id,
            wasm_hash_cache,
        )
        .await
    }

    /// Exposed version of [`super::verify_pinned_policy_against_chain`] for
    /// adversarial fixture tests.
    ///
    /// # Errors
    ///
    /// Same as [`super::verify_pinned_policy_against_chain`].
    #[doc(hidden)]
    pub async fn verify_pinned_policy_against_chain(
        signers_manager: &SignersManager,
        policy_addr: ScAddress,
        rule_id: u32,
        smart_account_redacted: &str,
        request_id: &str,
        wasm_hash_cache: &mut HashMap<Vec<u8>, [u8; 32]>,
    ) -> Result<(), SaError> {
        super::verify_pinned_policy_against_chain(
            signers_manager,
            policy_addr,
            rule_id,
            smart_account_redacted,
            request_id,
            wasm_hash_cache,
        )
        .await
    }
}
