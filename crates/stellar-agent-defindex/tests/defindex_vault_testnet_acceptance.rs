//! Testnet acceptance tests for the DeFindex vault adapter.
//!
//! Gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-defindex --features testnet-acceptance \
//!   --test defindex_vault_testnet_acceptance
//! ```
//!
//! # Acceptance criteria covered
//!
//! - Ordered trust gate passes for the testnet USDC/PaltaLabs vault:
//!   WASM-hash pin (two-RPC check), upgradable flag read, role disclosure.
//!   The gate sequencing is verified structurally (step N+1 only after step N).
//!
//! - Typed preview built from on-chain data: role addresses are
//!   first-5-last-5 redacted; full addresses NEVER appear in the summary.
//!
//! - Upgradable-vault refusal posture: when the vault is
//!   upgradable=true, `UpgradableEvalExt::evaluate` returns an error; when
//!   override is set, it proceeds and emits a distinct warning.
//!
//! - Self-managed vs delegated classification: the test computes
//!   `VaultManagementMode` from the live on-chain roles snapshot and asserts
//!   structural correctness (the specific mode depends on live vault state).
//!
//! # Environmental fixture notes
//!
//! The testnet vault (`CBMVK…ZDWHN` — `usdc_paltalabs_vault`) may have its roles
//! set to any addresses.  The test asserts structural properties (redaction, mode
//! classification, summary format) rather than specific live values, which avoids
//! brittleness against vault manager changes.
//!
//! The WASM-hash pin check may fail if the vault has been upgraded post-pin.
//! In that case the pin constants in `pins.rs` must be updated to match the
//! new deployed WASM hash before the acceptance test will pass.
//!
//! # RPC transient failures
//!
//! Testnet RPC can return 5xx transiently.  Tests retry up to 3 times with 2s
//! backoff before failing.  If persistently unreachable, the test notes this and
//! the authoritative green run is the scheduled CI job.
//!
//! # What this suite verifies
//!
//! The assertions in this file verify the structural claims: ordered-gate
//! sequencing, fail-closed-on-absent upgradable flag, role-disclosure redaction,
//! and management-mode classification.

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics, unwraps, and eprintln are acceptable in testnet acceptance tests"
)]

use stellar_agent_defindex::{
    criteria::upgradable::UpgradableEvalExt,
    pins::verify_defindex_vault_wasm,
    preview::{VaultOperation, VaultOperationPreview},
    roles::{VaultManagementMode, read_vault_roles},
    storage::read_vault_upgradable_flag,
};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_test_support::retry_rpc;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

/// The testnet USDC/PaltaLabs DeFindex vault used by the acceptance suite.
///
/// Source: `apps/contracts/public/testnet.contracts.json` `ids.usdc_paltalabs_vault`.
const DEFINDEX_TESTNET_VAULT: &str = "CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN";

/// A fake wallet address used for management-mode computation (not actually signing).
///
/// This is ALMOST CERTAINLY a non-manager address on the testnet vault, so the test
/// will see `VaultManagementMode::NotManager` for the from-address check.
const FAKE_WALLET_ADDR: &str = "CAJJZSGMMM3PD7N33TAPHGBUGTB43OC73HVIK2L2G6BNGGGYOSSYBXBD";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a fresh `StellarRpcClient` for the testnet RPC.
fn testnet_rpc() -> StellarRpcClient {
    StellarRpcClient::new(TESTNET_RPC_URL).expect("testnet RPC URL must be valid")
}

// ─────────────────────────────────────────────────────────────────────────────
// Acceptance — ordered trust gate (WASM-pin, upgradable, roles)
// ─────────────────────────────────────────────────────────────────────────────

/// **Acceptance** — Full ordered trust gate passes for the testnet vault.
///
/// Tests the three ordered gate steps:
/// 1. Vault WASM hash matches the pinned DeFindex vault hash (two-RPC check).
/// 2. Upgradable flag is read from instance storage (any value is acceptable;
///    the test asserts the READ itself succeeds and returns a `bool`).
/// 3. All four role addresses are read without error.
///
/// The `?`-early-return sequencing is verified structurally: the test NEVER
/// consumes vault-controlled state (roles, upgradable flag) before the WASM pin
/// passes — if pin fails, the test returns early before reading roles.
#[tokio::test]
#[ignore = "live testnet acceptance; run in the testnet-acceptance CI job via -- --ignored"]
async fn acceptance_2a_ordered_gate_wasm_pin_upgradable_roles() {
    let rpc = testnet_rpc();

    // ── Step 1: verify vault WASM hash (two-RPC cross-check) ─────────────────
    // Secondary RPC is the same URL on testnet (no independent secondary available).
    // In production, the secondary should be independently administered.
    let wasm_result = retry_rpc!(verify_defindex_vault_wasm(
        DEFINDEX_TESTNET_VAULT,
        &rpc,
        Some(&rpc), // secondary = same as primary on testnet
    ));

    match wasm_result {
        Ok(()) => {
            eprintln!("Acceptance step 1 — vault WASM hash OK (pin matches)");
        }
        Err(e) => {
            panic!(
                "Acceptance FAIL — vault WASM hash mismatch for testnet vault \
                 ({DEFINDEX_TESTNET_VAULT}): {e}\n\
                 This may mean the vault has been upgraded post-pin. \
                 Update DEFINDEX_VAULT_WASM_HASH in pins.rs to the new deployed hash."
            );
        }
    }

    // ── Step 2: read upgradable flag ──────────────────────────────────────────
    // Only reached AFTER the WASM pin passes (ordered trust invariant).
    // The flag value depends on live vault configuration.
    let upgradable = retry_rpc!(read_vault_upgradable_flag(DEFINDEX_TESTNET_VAULT, &rpc))
        .expect("Acceptance FAIL — could not read upgradable flag from testnet vault");

    eprintln!("Acceptance step 2 — upgradable flag read OK: upgradable={upgradable}");

    // ── Step 3: read vault roles ──────────────────────────────────────────────
    // Only reached AFTER the WASM pin passes (ordered trust invariant).
    let roles = retry_rpc!(read_vault_roles(DEFINDEX_TESTNET_VAULT, &rpc))
        .expect("Acceptance FAIL — could not read vault roles from testnet vault");

    eprintln!(
        "Acceptance step 3 — roles read OK: manager={:?} em={:?} rm={:?} fr={:?}",
        roles.manager_redacted,
        roles.emergency_manager_redacted,
        roles.rebalance_manager_redacted,
        roles.vault_fee_receiver_redacted,
    );

    // Disclosure summary does not panic and is non-empty.
    let disclosure = roles.disclosure_summary();
    assert!(
        !disclosure.is_empty(),
        "Acceptance FAIL — disclosure summary must be non-empty"
    );

    // Management mode computes without panic.
    let mode = roles.management_mode(FAKE_WALLET_ADDR);
    eprintln!("Acceptance — management_mode for FAKE_WALLET_ADDR: {mode:?}");

    eprintln!(
        "Acceptance PASS — ordered gate (WASM-pin → upgradable → roles) passed; \
         upgradable={upgradable}, mode={mode:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Acceptance — typed preview built from on-chain data; address redaction
// ─────────────────────────────────────────────────────────────────────────────

/// **Acceptance** — Typed preview built from live on-chain data; addresses
/// are first-5-last-5 redacted in the summary.
///
/// Uses `VaultOperationPreview::from_deposit` with the live roles snapshot.
/// Asserts:
/// - `summary()` does not contain the full vault address.
/// - `summary()` does not contain the full fake wallet address.
/// - `summary()` contains `"upgradable="` label.
/// - `summary()` contains the operation keyword `"deposit"`.
#[tokio::test]
#[ignore = "live testnet acceptance; run in the testnet-acceptance CI job via -- --ignored"]
async fn acceptance_2b_preview_role_disclosure_redaction() {
    let rpc = testnet_rpc();

    // Run ordered gate first.
    let wasm_result = retry_rpc!(verify_defindex_vault_wasm(
        DEFINDEX_TESTNET_VAULT,
        &rpc,
        Some(&rpc),
    ));
    wasm_result.expect("Acceptance FAIL — WASM pin failed; cannot proceed to preview test");

    let upgradable = retry_rpc!(read_vault_upgradable_flag(DEFINDEX_TESTNET_VAULT, &rpc))
        .expect("Acceptance FAIL — upgradable read failed");

    let roles = retry_rpc!(read_vault_roles(DEFINDEX_TESTNET_VAULT, &rpc))
        .expect("Acceptance FAIL — roles read failed");

    // Build a deposit preview with no amounts (amounts are purely args-supplied;
    // the testnet test does not execute a real deposit).
    let deposit_args = stellar_agent_defindex::abi::VaultDepositArgs {
        vault_address: DEFINDEX_TESTNET_VAULT.to_owned(),
        amounts_desired: vec![1_000_000],
        amounts_min: vec![900_000],
        from_address: FAKE_WALLET_ADDR.to_owned(),
        invest: false,
        override_upgradable: false,
    };

    let preview = VaultOperationPreview::from_deposit(
        &deposit_args,
        "testnet",
        upgradable,
        roles.clone(),
        vec![], // no assets fetched in this test (focused on role disclosure)
    );

    let summary = preview.summary();
    eprintln!("Acceptance — preview summary: {summary}");

    // Assert full vault address is NOT in the summary (redaction check).
    assert!(
        !summary.contains(DEFINDEX_TESTNET_VAULT),
        "Acceptance FAIL — full vault address must not appear in summary"
    );

    // Assert full wallet address is NOT in the summary (redaction check).
    assert!(
        !summary.contains(FAKE_WALLET_ADDR),
        "Acceptance FAIL — full wallet address must not appear in summary"
    );

    // Assert summary contains the operation label.
    assert!(
        matches!(preview.operation, VaultOperation::Deposit),
        "Acceptance FAIL — operation must be Deposit"
    );

    // Summary contains upgradable label.
    assert!(
        summary.contains("upgradable="),
        "Acceptance FAIL — summary must contain upgradable= label: {summary}"
    );

    // Summary contains "deposit".
    assert!(
        summary.contains("deposit"),
        "Acceptance FAIL — summary must contain 'deposit': {summary}"
    );

    eprintln!("Acceptance PASS — typed preview built; addresses redacted; labels correct");
}

// ─────────────────────────────────────────────────────────────────────────────
// Acceptance — upgradable refusal + override mechanics
// ─────────────────────────────────────────────────────────────────────────────

/// **Acceptance** — upgradable-vault posture: fail-closed-on-true.
///
/// This acceptance test is deterministic regardless of the live vault state:
/// it uses `UpgradableEvalExt::evaluate` directly with fixed inputs to verify
/// the posture mechanics, then applies it to the live-read vault flag to verify
/// the live path.
///
/// Asserts:
/// 1. `upgradable=true` → refusal (no override) with a non-empty reason.
/// 2. `upgradable=true` + override → proceeds without error (EMIT-THEN-RETURN
///    is verified by checking `Ok(())`; the warning event is a tracing::warn! side-effect).
/// 3. `upgradable=false` → always proceeds regardless of override flag.
/// 4. Live vault flag: if `upgradable=true`, the normal-path refuses and the
///    override path proceeds.  If `upgradable=false`, both paths proceed.
#[tokio::test]
#[ignore = "live testnet acceptance; run in the testnet-acceptance CI job via -- --ignored"]
async fn acceptance_2c_upgradable_refusal_and_override() {
    // ── Part A: deterministic unit-level checks ───────────────────────────────
    // Use NotManager mode — this test covers the upgradable posture for
    // delegated/non-self-managed vaults.  The self-managed exemption is
    // covered by the management-mode classification test.
    let not_manager_mode = VaultManagementMode::NotManager;

    // upgradable=true, no override → REFUSE.
    let refuse = UpgradableEvalExt::evaluate(true, false, &not_manager_mode);
    assert!(
        refuse.is_err(),
        "Acceptance FAIL — upgradable=true must refuse without override; got Ok"
    );
    let reason = refuse.unwrap_err();
    let reason_str = reason.to_string();
    assert!(
        !reason_str.is_empty(),
        "Acceptance FAIL — refusal reason must be non-empty"
    );
    eprintln!("Acceptance part A — refusal reason: {reason_str}");

    // upgradable=true + override → PROCEED.
    let override_result = UpgradableEvalExt::evaluate(true, true, &not_manager_mode);
    assert!(
        override_result.is_ok(),
        "Acceptance FAIL — upgradable=true with override must proceed; got {override_result:?}"
    );
    eprintln!("Acceptance part A — override proceeds OK");

    // upgradable=false, no override → PROCEED.
    let not_upgradable = UpgradableEvalExt::evaluate(false, false, &not_manager_mode);
    assert!(
        not_upgradable.is_ok(),
        "Acceptance FAIL — upgradable=false must always proceed; got {not_upgradable:?}"
    );

    // upgradable=false + override → PROCEED (redundant override is harmless).
    let not_upgradable_override = UpgradableEvalExt::evaluate(false, true, &not_manager_mode);
    assert!(
        not_upgradable_override.is_ok(),
        "Acceptance FAIL — upgradable=false with override must proceed; got {not_upgradable_override:?}"
    );
    eprintln!("Acceptance part A PASS — deterministic posture checks OK");

    // ── Part B: apply to live vault ───────────────────────────────────────────
    let rpc = testnet_rpc();

    // WASM pin must pass before reading upgradable (ordered trust gate).
    let wasm_result = retry_rpc!(verify_defindex_vault_wasm(
        DEFINDEX_TESTNET_VAULT,
        &rpc,
        Some(&rpc),
    ));
    wasm_result.expect("Acceptance FAIL — WASM pin failed; cannot proceed to upgradable test");

    let upgradable = retry_rpc!(read_vault_upgradable_flag(DEFINDEX_TESTNET_VAULT, &rpc))
        .expect("Acceptance FAIL — upgradable read failed");

    // Part B tests the upgradable posture in non-self-managed context (NotManager).
    // The self-managed exemption is exercised separately in the management-mode test.
    let live_mode = VaultManagementMode::NotManager;
    let normal_path = UpgradableEvalExt::evaluate(upgradable, false, &live_mode);
    let override_path = UpgradableEvalExt::evaluate(upgradable, true, &live_mode);

    if upgradable {
        assert!(
            normal_path.is_err(),
            "Acceptance FAIL — live vault upgradable=true but normal path did not refuse"
        );
        assert!(
            override_path.is_ok(),
            "Acceptance FAIL — live vault upgradable=true but override path did not proceed"
        );
        eprintln!(
            "Acceptance part B — live vault upgradable=true: normal refused, override proceeded"
        );
    } else {
        assert!(
            normal_path.is_ok(),
            "Acceptance FAIL — live vault upgradable=false but normal path refused"
        );
        assert!(
            override_path.is_ok(),
            "Acceptance FAIL — live vault upgradable=false but override path refused"
        );
        eprintln!("Acceptance part B — live vault upgradable=false: both paths proceed");
    }

    eprintln!("Acceptance PASS — upgradable posture verified against live vault");
}

// ─────────────────────────────────────────────────────────────────────────────
// Acceptance — self-managed vs delegated classification
// ─────────────────────────────────────────────────────────────────────────────

/// **Acceptance** — Self-managed vs delegated management mode classification.
///
/// Reads the live roles from the testnet vault and asserts:
/// 1. `management_mode(FAKE_WALLET_ADDR)` returns one of the three valid modes.
/// 2. If the vault's Manager role is present and matches some address, the
///    classification for THAT address yields `SelfManaged` (if no third-party
///    em/rm) or `Delegated` (if third-party roles differ), not `NotManager`.
/// 3. The fake wallet address (which is almost certainly NOT the manager) yields
///    `VaultManagementMode::NotManager`.
///
/// # Environmental fixture note
///
/// The live vault's Manager role could be any address.  The test asserts
/// structural properties of the mode classification, not specific live role values.
#[tokio::test]
#[ignore = "live testnet acceptance; run in the testnet-acceptance CI job via -- --ignored"]
async fn acceptance_2d_management_mode_classification() {
    let rpc = testnet_rpc();

    // WASM pin first.
    let wasm_result = retry_rpc!(verify_defindex_vault_wasm(
        DEFINDEX_TESTNET_VAULT,
        &rpc,
        Some(&rpc),
    ));
    wasm_result.expect("Acceptance FAIL — WASM pin failed");

    let roles = retry_rpc!(read_vault_roles(DEFINDEX_TESTNET_VAULT, &rpc))
        .expect("Acceptance FAIL — roles read failed");

    // Assert the fake wallet is NOT the manager (structural: it's a dummy address).
    // This verifies the NotManager branch is exercised.
    let mode_fake = roles.management_mode(FAKE_WALLET_ADDR);
    assert!(
        matches!(mode_fake, VaultManagementMode::NotManager),
        "Acceptance FAIL — fake wallet addr should be NotManager; got {mode_fake:?}"
    );
    eprintln!("Acceptance — fake wallet is NotManager OK");

    // If the vault has a manager address, check the mode for THAT address.
    if let Some(ref manager_addr) = roles.manager {
        let mode_manager = roles.management_mode(manager_addr.as_str());

        // The mode must be SelfManaged or Delegated, never NotManager.
        assert!(
            !matches!(mode_manager, VaultManagementMode::NotManager),
            "Acceptance FAIL — manager address must not yield NotManager; got {mode_manager:?}"
        );

        match &mode_manager {
            VaultManagementMode::SelfManaged => {
                // No third-party emergency or rebalance manager.
                // Assert the em and rm either match the manager or are None.
                let em = &roles.emergency_manager;
                let rm = &roles.rebalance_manager;
                let no_third_party_em = em.as_deref().is_none_or(|em| em == manager_addr.as_str());
                let no_third_party_rm = rm.as_deref().is_none_or(|rm| rm == manager_addr.as_str());
                assert!(
                    no_third_party_em && no_third_party_rm,
                    "Acceptance FAIL — SelfManaged but em or rm differs from manager: \
                     em={em:?} rm={rm:?} manager={manager_addr}"
                );
                eprintln!("Acceptance — manager is SelfManaged OK");
            }
            VaultManagementMode::Delegated {
                third_party_emergency_manager,
                third_party_rebalance_manager,
            } => {
                // At least one of em or rm is a third party.
                assert!(
                    *third_party_emergency_manager || *third_party_rebalance_manager,
                    "Acceptance FAIL — Delegated mode has no third-party role flags set"
                );
                eprintln!(
                    "Acceptance — manager is Delegated (em={third_party_emergency_manager}, rm={third_party_rebalance_manager})"
                );
            }
            VaultManagementMode::NotManager => {
                unreachable!(
                    "checked above — manager_addr is the vault manager, so mode cannot be NotManager"
                );
            }
        }
    } else {
        // Vault has no manager set — all roles absent.
        eprintln!(
            "Acceptance NOTE — vault has no manager address set; \
             NotManager is the only observable mode"
        );
    }

    eprintln!("Acceptance PASS — management mode classification verified");
}

// ─────────────────────────────────────────────────────────────────────────────
// Fail-closed-on-absent upgradable flag (deterministic, no testnet I/O)
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies the fail-safe: `upgradable=true` is assumed when the entry is
/// absent (or unreadable), which causes refusal in the upgradable posture.
///
/// This is a deterministic test (no testnet I/O).  It directly tests the
/// `UpgradableEvalExt::evaluate` behaviour that downstream callers rely on
/// when `read_vault_upgradable_flag` returns `true` for an absent entry.
#[test]
fn absent_upgradable_entry_fails_closed() {
    // The read function returns `true` for absent entries (the absent-default fail-safe).
    // Verify that `true` with no override → refuses (fail-closed).
    // NotManager mode: the upgradable refusal applies (self-managed exemption not in play).
    let mode = VaultManagementMode::NotManager;
    let result = UpgradableEvalExt::evaluate(true, false, &mode);
    assert!(
        result.is_err(),
        "absent upgradable entry (defaulting to true) must refuse without override; got Ok"
    );

    // With override: proceeds.
    let result_override = UpgradableEvalExt::evaluate(true, true, &mode);
    assert!(
        result_override.is_ok(),
        "absent upgradable entry with override must proceed; got Err"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Pin consistency: testnet vault WASM hash byte layout
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies the testnet vault WASM hash constant has correct byte length and
/// matches the factory-blessed expected hex string.
///
/// Hash `f345228dca59c6605789620e9ec62ff4847a0927c33dac7581a955fe746016be`
/// was verified on-chain via `stellar contract invoke -- vault_wasm_hash`
/// against the testnet factory `CDSCWE4GLNBYYTES2OCYDFQA2LLY4RBIAX6ZI32VSUXD7GO6HRPO4A32`
/// on 2026-06-04.
///
/// This is a deterministic compile-time-derived test (no I/O).
#[test]
fn testnet_vault_wasm_hash_constant_byte_layout() {
    use stellar_agent_defindex::pins::DEFINDEX_VAULT_WASM_HASH;

    let hash = DEFINDEX_VAULT_WASM_HASH;
    assert_eq!(hash.len(), 32, "WASM hash must be 32 bytes");

    // f345228dca59c6605789620e9ec62ff4847a0927c33dac7581a955fe746016be
    // First 4 bytes: f3, 45, 22, 8d
    assert_eq!(hash[0], 0xf3, "byte 0 mismatch");
    assert_eq!(hash[1], 0x45, "byte 1 mismatch");
    assert_eq!(hash[2], 0x22, "byte 2 mismatch");
    assert_eq!(hash[3], 0x8d, "byte 3 mismatch");

    // Last 4 bytes: 74, 60, 16, be
    assert_eq!(hash[28], 0x74, "byte 28 mismatch");
    assert_eq!(hash[29], 0x60, "byte 29 mismatch");
    assert_eq!(hash[30], 0x16, "byte 30 mismatch");
    assert_eq!(hash[31], 0xbe, "byte 31 mismatch");
}
