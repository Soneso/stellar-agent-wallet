//! Cross-crate parity assertions for the OZ per-rule hard caps.
//!
//! Cross-crate parity assertions for the OZ per-rule hard caps.
//!
//! The wallet-side constants
//! [`stellar_agent_smart_account::managers::rules::OZ_MAX_SIGNERS`] and
//! [`stellar_agent_smart_account::managers::rules::OZ_MAX_POLICIES`] are
//! mirrors of the OZ on-chain canonical values at
//! `packages/accounts/src/smart_account/mod.rs:524-526` SHA `a9c4216`:
//!
//! ```text
//! pub const MAX_POLICIES: u32 = 5;
//! pub const MAX_SIGNERS:  u32 = 15;
//! ```
//!
//! If the OZ canonical is updated (e.g. a future on-chain upgrade raises the
//! signer cap), the wallet constants must be updated in the same commit that
//! advances the OZ pin. These tests fail CI so the pin-advancement review
//! cannot silently miss the drift.
//!
//! On-chain panic discriminants (`TooManySigners = 3010`,
//! `TooManyPolicies = 3011`, `mod.rs:558-560`) are the authoritative
//! last-line defence when the CLI cap check is bypassed; they are exercised
//! by `oz_panic_discriminant_mapping_mock.rs`.
//!
//! # Coverage
//!
//! Covers the per-rule signer and policy caps enforced by the wallet CLI
//! and backed by on-chain panic discriminants.

use stellar_agent_smart_account::managers::rules::{OZ_MAX_POLICIES, OZ_MAX_SIGNERS};

/// Asserts that `OZ_MAX_SIGNERS` matches the OZ canonical value.
///
/// OZ source: `packages/accounts/src/smart_account/mod.rs:526` SHA `a9c4216`
/// (`pub const MAX_SIGNERS: u32 = 15`).
///
/// On-chain enforcement: `SmartAccountError::TooManySigners = 3010`
/// (`mod.rs:558`, SHA `a9c4216`).
#[test]
fn oz_max_signers_parity_with_canonical() {
    assert_eq!(
        OZ_MAX_SIGNERS, 15,
        "OZ_MAX_SIGNERS parity violation: wallet constant is {} but OZ canonical \
         (packages/accounts/src/smart_account/mod.rs:526 SHA a9c4216) is 15. \
         Update OZ_MAX_SIGNERS in managers/rules.rs to match the canonical, \
         then re-verify the CLI cap check sites.",
        OZ_MAX_SIGNERS,
    );
}

/// Asserts that `OZ_MAX_POLICIES` matches the OZ canonical value.
///
/// OZ source: `packages/accounts/src/smart_account/mod.rs:524` SHA `a9c4216`
/// (`pub const MAX_POLICIES: u32 = 5`).
///
/// On-chain enforcement: `SmartAccountError::TooManyPolicies = 3011`
/// (`mod.rs:560`, SHA `a9c4216`).
#[test]
fn oz_max_policies_parity_with_canonical() {
    assert_eq!(
        OZ_MAX_POLICIES, 5,
        "OZ_MAX_POLICIES parity violation: wallet constant is {} but OZ canonical \
         (packages/accounts/src/smart_account/mod.rs:524 SHA a9c4216) is 5. \
         Update OZ_MAX_POLICIES in managers/rules.rs to match the canonical, \
         then re-verify the CLI cap check sites.",
        OZ_MAX_POLICIES,
    );
}
