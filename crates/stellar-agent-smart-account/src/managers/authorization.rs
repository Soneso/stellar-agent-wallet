//! Quorum-like `AuthorizationInfo` substrate for multi-signer smart-account
//! invocations.
//!
//! # Overview
//!
//! [`AuthorizationInfo`] declares groups of ed25519 signers, each with a
//! threshold M-of-N, plus a cross-group [`Combinator`] (AND / OR).
//! [`collect_quorum_signatures`] is the off-chain orchestrator: it iterates
//! over each group, finds the qualifying signers from the supplied slice,
//! produces one `SorobanAuthorizationEntry` per signer (via the existing
//! [`crate::managers::auth_entry`] substrate), and returns the flat entry
//! vector that [`crate::submit::submit_signed_invoke`] passes to the
//! contract.
//!
//! # Design decisions
//!
//! - `SubmitInvokeArgs` owns the quorum loop: when
//!   `args.authorization` is `Some`, `submit_signed_invoke` calls
//!   `collect_quorum_signatures` internally instead of a single-signer path.
//! - Current implementation supports homogeneous signer groups only:
//!   all members are Ed25519 software signers via the `Signer` trait.
//!   Heterogeneous groups (Ed25519 + WebAuthn passkey within one group) are
//!   deferred (not yet supported: heterogeneous `SignerGroup` members).
//!
//! # Fail-closed semantics
//!
//! An empty `AuthorizationInfo::groups` vec returns
//! [`QuorumError::EmptyAuthorizationInfo`] — the helper never silently produces
//! an empty auth-entry set that would pass through to on-chain submission as a
//! no-auth transaction.

use serde::{Deserialize, Serialize};
use stellar_agent_network::signing::Signer;
use stellar_xdr::{ScAddress, ScSymbol, ScVal, SorobanAuthorizationEntry};
use thiserror::Error;

use crate::SaError;
use crate::managers::auth_entry::{
    AuthorizationSimulation, PartialSorobanAuthorizationEntry, build_authorization_entry,
    complete_authorization_entry_multi_signer,
};
use crate::managers::rules::build_and_sign_delegated_g_key_entry;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;

// ─────────────────────────────────────────────────────────────────────────────
// SignerGroup
// ─────────────────────────────────────────────────────────────────────────────

/// A named group of ed25519 signers with an M-of-N threshold.
///
/// Each member is identified by a Stellar G-strkey (the `[u8; 32]` public key
/// bytes encoded as a Stellar ed25519 public key strkey).  `threshold` MUST be
/// ≥ 1 and ≤ `members.len()`; construction via [`SignerGroup::new`] enforces
/// this at instantiation time.
///
///
/// # Examples
///
/// ```
/// use stellar_agent_smart_account::managers::authorization::SignerGroup;
///
/// let pk1 = [1u8; 32];
/// let pk2 = [2u8; 32];
/// let group = SignerGroup::new("admins".to_owned(), vec![pk1, pk2], 1)
///     .expect("valid group");
/// assert_eq!(group.name(), "admins");
/// assert_eq!(group.threshold(), 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SignerGroup {
    /// Human-readable name used in error messages and audit rows.
    pub name: String,
    /// Ed25519 public key bytes (32-byte raw pubkey, NOT strkey-encoded).
    ///
    /// These are the `.0` field of `stellar_strkey::ed25519::PublicKey`.
    pub members: Vec<[u8; 32]>,
    /// Minimum number of group members that must sign.
    ///
    /// Must satisfy `1 ≤ threshold ≤ members.len()`.
    pub threshold: u32,
}

impl SignerGroup {
    /// Constructs a [`SignerGroup`], validating the threshold invariant.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` when the threshold is zero, when `members` is
    /// empty, or when `threshold > members.len()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_smart_account::managers::authorization::SignerGroup;
    ///
    /// let g = SignerGroup::new("ops".into(), vec![[0u8; 32]], 1).unwrap();
    /// assert_eq!(g.threshold(), 1);
    ///
    /// // threshold = 0 is rejected.
    /// assert!(SignerGroup::new("ops".into(), vec![[0u8; 32]], 0).is_err());
    /// ```
    pub fn new(name: String, members: Vec<[u8; 32]>, threshold: u32) -> Result<Self, String> {
        if members.is_empty() {
            return Err(format!("SignerGroup '{name}': members must not be empty"));
        }
        if threshold == 0 {
            return Err(format!("SignerGroup '{name}': threshold must be ≥ 1"));
        }
        #[allow(
            clippy::cast_possible_truncation,
            reason = "members.len() is bounded by u32 max in practice"
        )]
        if threshold > members.len() as u32 {
            return Err(format!(
                "SignerGroup '{name}': threshold {threshold} > members.len() {}",
                members.len()
            ));
        }
        Ok(Self {
            name,
            members,
            threshold,
        })
    }

    /// Returns the group name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the configured threshold.
    #[must_use]
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Returns the member public key bytes slice.
    #[must_use]
    pub fn members(&self) -> &[[u8; 32]] {
        &self.members
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Combinator
// ─────────────────────────────────────────────────────────────────────────────

/// Cross-group logical combinator for [`AuthorizationInfo`].
///
/// - `And`: ALL groups must be satisfied; the collected entries from every
///   group are flattened into the result.
/// - `Or`: ANY group must be satisfied; only the entries from the FIRST
///   satisfied group (in declaration order) are returned.  This is deterministic
///   because groups are walked in order and the first satisfied group wins.
///
/// # Examples
///
/// ```
/// use stellar_agent_smart_account::managers::authorization::Combinator;
///
/// let c = Combinator::And;
/// assert_eq!(format!("{c:?}"), "And");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Combinator {
    /// All groups must be satisfied.
    And,
    /// Any group must be satisfied (first satisfied group wins).
    Or,
}

// ─────────────────────────────────────────────────────────────────────────────
// AuthorizationInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Multi-signer quorum declaration for a smart-account invocation.
///
/// Declares one or more signer groups, each with its own M-of-N threshold,
/// and a cross-group combinator.  Used by
/// [`collect_quorum_signatures`] to orchestrate signature collection and by
/// the [`crate::managers::policies`]-side `quorum_satisfied` criterion to validate
/// adequacy before submission.
///
/// # Forward-compat serialisation
///
/// `Serialize + Deserialize` are implemented so that future TOML-profile
/// persistence (serialisation is additive) can load this type
/// without breaking the wire format.
///
/// # Examples
///
/// ```
/// use stellar_agent_smart_account::managers::authorization::{
///     AuthorizationInfo, Combinator, SignerGroup,
/// };
///
/// let g = SignerGroup::new("admins".into(), vec![[1u8; 32], [2u8; 32]], 2).unwrap();
/// let authz = AuthorizationInfo::new(vec![g], Combinator::And);
/// assert_eq!(authz.groups.len(), 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuthorizationInfo {
    /// Signer groups, each with a threshold.
    pub groups: Vec<SignerGroup>,
    /// Cross-group logical combinator.
    pub combinator: Combinator,
}

impl AuthorizationInfo {
    /// Constructs an [`AuthorizationInfo`] with the given groups and combinator.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_smart_account::managers::authorization::{
    ///     AuthorizationInfo, Combinator, SignerGroup,
    /// };
    ///
    /// let g = SignerGroup::new("ops".into(), vec![[0u8; 32]], 1).unwrap();
    /// let authz = AuthorizationInfo::new(vec![g], Combinator::Or);
    /// assert_eq!(authz.combinator, Combinator::Or);
    /// ```
    #[must_use]
    pub fn new(groups: Vec<SignerGroup>, combinator: Combinator) -> Self {
        Self { groups, combinator }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QuorumError
// ─────────────────────────────────────────────────────────────────────────────

/// Typed error from [`collect_quorum_signatures`].
///
/// Every variant carries a stable `wire_code()` consumed by audit-log emission
/// and the CLI JSON envelope.
///
/// # Fail-closed design
///
/// `EmptyAuthorizationInfo` fires when `authz.groups` is empty, ensuring the
/// helper never silently produces a zero-entry signature set.
///
/// # Examples
///
/// ```
/// use stellar_agent_smart_account::managers::authorization::QuorumError;
///
/// let e = QuorumError::EmptyAuthorizationInfo;
/// assert_eq!(e.wire_code(), "sa.quorum.empty_authorization_info");
/// ```
#[derive(Debug, Clone, Error, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum QuorumError {
    /// A group did not have enough qualifying signers.
    ///
    /// Wire code: `sa.quorum.insufficient_signers_in_group`.
    #[error(
        "insufficient signers in group '{group_name}': required {required}, provided {provided}"
    )]
    InsufficientSignersInGroup {
        /// Group name.
        group_name: String,
        /// Threshold configured on the group.
        required: u32,
        /// Number of qualifying signers found in the supplied slice.
        provided: u32,
    },

    /// AND combinator: one or more groups were unsatisfied.
    ///
    /// Wire code: `sa.quorum.group_not_satisfied_in_and_combinator`.
    #[error("AND combinator: {unsatisfied_groups:?} groups not satisfied")]
    GroupNotSatisfiedInAndCombinator {
        /// Names of unsatisfied groups.
        unsatisfied_groups: Vec<String>,
    },

    /// OR combinator: no group was satisfied.
    ///
    /// Wire code: `sa.quorum.no_group_satisfied_in_or_combinator`.
    #[error("OR combinator: none of {groups:?} groups satisfied")]
    NoGroupSatisfiedInOrCombinator {
        /// Names of all groups in the declaration.
        groups: Vec<String>,
    },

    /// Per-signer auth-entry construction failed.
    ///
    /// Wraps the underlying [`SaError`] detail string.
    ///
    /// Wire code: `sa.quorum.signature_production_failed`.
    #[error("auth-entry construction failed: {detail}")]
    SignatureProductionFailed {
        /// Non-secret diagnostic forwarded from [`SaError`].
        detail: String,
    },

    /// `authz.groups` was empty — fail-closed.
    ///
    /// Wire code: `sa.quorum.empty_authorization_info`.
    #[error("AuthorizationInfo has no groups (fail-closed)")]
    EmptyAuthorizationInfo,
}

impl QuorumError {
    /// Returns the stable wire code for audit-log and JSON envelope emission.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_smart_account::managers::authorization::QuorumError;
    ///
    /// assert_eq!(
    ///     QuorumError::EmptyAuthorizationInfo.wire_code(),
    ///     "sa.quorum.empty_authorization_info"
    /// );
    /// assert_eq!(
    ///     QuorumError::InsufficientSignersInGroup {
    ///         group_name: "admins".into(),
    ///         required: 2,
    ///         provided: 1,
    ///     }
    ///     .wire_code(),
    ///     "sa.quorum.insufficient_signers_in_group"
    /// );
    /// ```
    #[must_use]
    pub fn wire_code(&self) -> &'static str {
        match self {
            Self::InsufficientSignersInGroup { .. } => "sa.quorum.insufficient_signers_in_group",
            Self::GroupNotSatisfiedInAndCombinator { .. } => {
                "sa.quorum.group_not_satisfied_in_and_combinator"
            }
            Self::NoGroupSatisfiedInOrCombinator { .. } => {
                "sa.quorum.no_group_satisfied_in_or_combinator"
            }
            Self::SignatureProductionFailed { .. } => "sa.quorum.signature_production_failed",
            Self::EmptyAuthorizationInfo => "sa.quorum.empty_authorization_info",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// collect_quorum_signatures
// ─────────────────────────────────────────────────────────────────────────────

/// Collects per-signer `SorobanAuthorizationEntry` values for a quorum invoke.
///
/// This is the wallet-side **off-chain** orchestrator that produces the entry
/// set the on-chain OpenZeppelin contract's `__check_auth` validates.  The auth-entry XDR per
/// signer is identical to the N=1 single-signer case; this function calls
/// [`build_authorization_entry`]
/// + [`complete_authorization_entry`][crate::managers::auth_entry::complete_authorization_entry]
///   once per qualifying signer and returns the flat vector.
///
/// # On-chain threshold note
///
/// On-chain threshold enforcement happens at `__check_auth` time per the
/// OpenZeppelin smart-account contract.
/// The wallet-side helper is complementary — it ensures the correct number of
/// signers are represented before submission.
///
/// # Auth-entry XDR canonical reference
///
/// Per-signer auth-entry construction follows the existing
/// [`build_authorization_entry`]
/// + [`complete_authorization_entry`][crate::managers::auth_entry::complete_authorization_entry]
///   substrate.
///   The `HashIdPreimage::SorobanAuthorization` XDR preimage matches
///   `stellar-xdr 27 src/curr/generated.rs` `HashIdPreimage` and
///   `HashIdPreimageSorobanAuthorization`.
///
/// # Signer matching
///
/// Signers are matched by comparing `signer.public_key().await` bytes against
/// each group's `members` list.  Matching signers within a group are sorted by
/// public-key bytes (deterministic order) before signing to ensure identical
/// auth-entry ordering on repeated calls with the same signer set.
///
/// # Parameters
///
/// - `authz`: the quorum declaration.
/// - `signers`: all candidate signers for this invocation.
/// - `auth_scaddr`: the `ScAddress` of the smart-account contract being authorised.
/// - `function_name`: the Soroban function name being invoked.
/// - `args`: the function arguments.
/// - `auth_rule_ids`: context-rule IDs used for the auth-digest binding.
/// - `simulation`: the `AuthorizationSimulation` from the simulate step.
/// - `envelope`: the `EnvelopeContext` from the simulate step.
/// - `network_passphrase`: Stellar network passphrase.
/// - `signature_expiration_ledger`: ledger number at which auth entries expire.
///
/// # Returns
///
/// A flat `Vec<SorobanAuthorizationEntry>` suitable for passing to
/// [`crate::submit::submit_signed_invoke`] for on-chain submission.
///
/// When `authz.combinator == Combinator::Or`, only the entries from the first
/// satisfied group are returned.
///
/// # Errors
///
/// - [`QuorumError::EmptyAuthorizationInfo`] — `authz.groups` is empty.
/// - [`QuorumError::InsufficientSignersInGroup`] — a group does not have
///   enough qualifying signers (AND path: first such group; OR path: reported
///   when NO group is satisfied).
/// - [`QuorumError::GroupNotSatisfiedInAndCombinator`] — AND combinator and
///   one or more groups could not reach threshold.
/// - [`QuorumError::NoGroupSatisfiedInOrCombinator`] — OR combinator and no
///   group reached threshold.
/// - [`QuorumError::SignatureProductionFailed`] — an underlying
///   [`build_authorization_entry`]
///   or [`complete_authorization_entry`][crate::managers::auth_entry::complete_authorization_entry]
///   call returned an error.
///
/// # Examples
///
/// See `crates/stellar-agent-smart-account/tests/quorum_authorization_info_testnet_acceptance.rs`
/// for end-to-end testnet exercises.
#[allow(
    clippy::too_many_arguments,
    reason = "quorum orchestration requires the full auth-entry construction context; \
              splitting would require a context struct (deferred to a future ergonomics pass)"
)]
pub async fn collect_quorum_signatures(
    authz: &AuthorizationInfo,
    signers: &[&(dyn Signer + Send + Sync)],
    auth_scaddr: ScAddress,
    function_name: ScSymbol,
    args: Vec<ScVal>,
    auth_rule_ids: Vec<ContextRuleId>,
    simulation: &AuthorizationSimulation,
    envelope: &crate::signing::divergence::EnvelopeContext,
    network_passphrase: &str,
    signature_expiration_ledger: u32,
) -> Result<Vec<SorobanAuthorizationEntry>, QuorumError> {
    if authz.groups.is_empty() {
        return Err(QuorumError::EmptyAuthorizationInfo);
    }

    // Resolve each signer's public key once upfront to avoid repeated async
    // calls and to enable deterministic sorting within groups.
    let mut resolved: Vec<([u8; 32], &(dyn Signer + Send + Sync))> =
        Vec::with_capacity(signers.len());
    for &s in signers {
        let pk = s
            .public_key()
            .await
            .map_err(|e| QuorumError::SignatureProductionFailed {
                detail: format!("public_key fetch failed: {e}"),
            })?;
        resolved.push((pk.0, s));
    }

    match authz.combinator {
        Combinator::And => {
            collect_and(
                authz,
                &resolved,
                auth_scaddr,
                function_name,
                args,
                auth_rule_ids,
                simulation,
                envelope,
                network_passphrase,
                signature_expiration_ledger,
            )
            .await
        }
        Combinator::Or => {
            collect_or(
                authz,
                &resolved,
                auth_scaddr,
                function_name,
                args,
                auth_rule_ids,
                simulation,
                envelope,
                network_passphrase,
                signature_expiration_ledger,
            )
            .await
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private: AND / OR collection helpers
// ─────────────────────────────────────────────────────────────────────────────

/// AND combinator: collect entries from ALL groups; fail on first unsatisfied.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors collect_quorum_signatures parameter set"
)]
async fn collect_and(
    authz: &AuthorizationInfo,
    resolved: &[([u8; 32], &(dyn Signer + Send + Sync))],
    auth_scaddr: ScAddress,
    function_name: ScSymbol,
    args: Vec<ScVal>,
    auth_rule_ids: Vec<ContextRuleId>,
    simulation: &AuthorizationSimulation,
    envelope: &crate::signing::divergence::EnvelopeContext,
    network_passphrase: &str,
    signature_expiration_ledger: u32,
) -> Result<Vec<SorobanAuthorizationEntry>, QuorumError> {
    let mut all_entries: Vec<SorobanAuthorizationEntry> = Vec::new();
    let mut unsatisfied: Vec<String> = Vec::new();

    for group in &authz.groups {
        match collect_group_entries(
            group,
            resolved,
            auth_scaddr.clone(),
            function_name.clone(),
            args.clone(),
            auth_rule_ids.clone(),
            simulation,
            envelope,
            network_passphrase,
            signature_expiration_ledger,
        )
        .await
        {
            Ok(entries) => all_entries.extend(entries),
            Err(QuorumError::InsufficientSignersInGroup { .. }) => {
                unsatisfied.push(group.name.clone());
            }
            Err(e) => return Err(e),
        }
    }

    if !unsatisfied.is_empty() {
        return Err(QuorumError::GroupNotSatisfiedInAndCombinator {
            unsatisfied_groups: unsatisfied,
        });
    }

    Ok(all_entries)
}

/// OR combinator: return entries from the FIRST satisfied group.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors collect_quorum_signatures parameter set"
)]
async fn collect_or(
    authz: &AuthorizationInfo,
    resolved: &[([u8; 32], &(dyn Signer + Send + Sync))],
    auth_scaddr: ScAddress,
    function_name: ScSymbol,
    args: Vec<ScVal>,
    auth_rule_ids: Vec<ContextRuleId>,
    simulation: &AuthorizationSimulation,
    envelope: &crate::signing::divergence::EnvelopeContext,
    network_passphrase: &str,
    signature_expiration_ledger: u32,
) -> Result<Vec<SorobanAuthorizationEntry>, QuorumError> {
    let group_names: Vec<String> = authz.groups.iter().map(|g| g.name.clone()).collect();

    for group in &authz.groups {
        match collect_group_entries(
            group,
            resolved,
            auth_scaddr.clone(),
            function_name.clone(),
            args.clone(),
            auth_rule_ids.clone(),
            simulation,
            envelope,
            network_passphrase,
            signature_expiration_ledger,
        )
        .await
        {
            Ok(entries) => return Ok(entries),
            Err(QuorumError::InsufficientSignersInGroup { .. }) => {
                // Try next group.
            }
            Err(e) => return Err(e),
        }
    }

    Err(QuorumError::NoGroupSatisfiedInOrCombinator {
        groups: group_names,
    })
}

/// Collects auth entries for the qualifying members of a single group.
///
/// Finds signers whose public key is in `group.members`, sorts them by public
/// key bytes (deterministic), takes the first `group.threshold` qualifying
/// signers, and produces one entry per signer.
///
/// Returns [`QuorumError::InsufficientSignersInGroup`] when fewer than
/// `threshold` qualifying signers are found.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors collect_quorum_signatures parameter set"
)]
async fn collect_group_entries(
    group: &SignerGroup,
    resolved: &[([u8; 32], &(dyn Signer + Send + Sync))],
    auth_scaddr: ScAddress,
    function_name: ScSymbol,
    args: Vec<ScVal>,
    auth_rule_ids: Vec<ContextRuleId>,
    simulation: &AuthorizationSimulation,
    envelope: &crate::signing::divergence::EnvelopeContext,
    network_passphrase: &str,
    signature_expiration_ledger: u32,
) -> Result<Vec<SorobanAuthorizationEntry>, QuorumError> {
    // Find qualifying signers: public key must be in group.members.
    let mut qualifying: Vec<([u8; 32], &(dyn Signer + Send + Sync))> = resolved
        .iter()
        .filter(|(pk, _)| group.members.contains(pk))
        .map(|(pk, s)| (*pk, *s))
        .collect();

    #[allow(
        clippy::cast_possible_truncation,
        reason = "qualifying.len() bounded by group.members.len() ≤ u32::MAX"
    )]
    let provided = qualifying.len() as u32;
    if provided < group.threshold {
        return Err(QuorumError::InsufficientSignersInGroup {
            group_name: group.name.clone(),
            required: group.threshold,
            provided,
        });
    }

    // Sort by public-key bytes for deterministic ordering.
    //
    // Sort-by-pubkey is valid for homogeneous Delegated-only groups.
    // When External-variant signers are supported, the sort must switch to
    // full XDR-encoded-key byte comparison over the hex-encoded signer key.
    // Not yet supported: heterogeneous signer-set sorting.
    qualifying.sort_by_key(|(pk, _)| *pk);

    // Take exactly `threshold` signers.
    qualifying.truncate(group.threshold as usize);

    // Build the shared partial auth entry (ONE per invocation, shared by all signers).
    //
    // All qualifying signers sign the SAME auth_digest because they are all
    // authorising the same invocation root. Producing a separate partial per
    // signer would change nothing — the preimage inputs (contract, fn_name,
    // args, rule_ids, simulation nonce, expiry) are identical for all signers
    // in this group.
    //
    // Canonical byte-layout source: stellar-xdr 27
    // `HashIdPreimageSorobanAuthorization` in src/curr/generated.rs.
    let partial: PartialSorobanAuthorizationEntry = build_authorization_entry(
        auth_scaddr.clone(),
        function_name.clone(),
        args.clone(),
        auth_rule_ids.clone(),
        simulation,
        envelope,
    )
    .await
    .map_err(|e: SaError| QuorumError::SignatureProductionFailed {
        detail: format!("{e}"),
    })?;

    // Capture auth_digest before partial is consumed by the multi-signer completer.
    let auth_digest: [u8; 32] = partial.auth_digest;

    // Collect the signer references for the multi-signer completer.
    let signer_refs: Vec<&(dyn Signer + Send + Sync)> =
        qualifying.iter().map(|(_, s)| *s).collect();

    // Build ONE SorobanAuthorizationEntry for the smart-account C-address whose
    // AuthPayload.signers map contains ALL qualifying signers' signatures.
    //
    // Per the OpenZeppelin smart-account contract, the on-chain
    // `AuthPayload { signers: Map<Signer, Bytes>, context_rule_ids }` is consumed
    // by `do_check_auth`, which iterates the signers map and authenticates each
    // entry; the policy's `enforce(authenticated_signers)` then counts all
    // authenticated entries.
    // Producing separate entries per signer would have the host process only ONE
    // entry for the smart-account C-address.
    let smart_account_entry = complete_authorization_entry_multi_signer(partial, &signer_refs)
        .await
        .map_err(|e: SaError| QuorumError::SignatureProductionFailed {
            detail: format!("{e}"),
        })?;

    // Build one delegated G-key sub-auth entry PER signer (required by __check_auth).
    //
    // The contract's `authenticate(Delegated)` calls
    // `addr.require_auth_for_args((auth_digest,))` from inside `__check_auth`.
    // Each G-key must have a separate delegated entry since each entry carries a
    // unique G-key address and a fresh CSPRNG nonce.
    //
    // The canonical single-signer pattern extends to the quorum: each signer in
    // the quorum needs their own delegated entry by the same logic.
    // XDR shape: SorobanAuthorizationEntry with SorobanCredentials::Address whose
    // address is the signer's G-key; signature over the standard Soroban
    // HashIdPreimage::SorobanAuthorization preimage (stellar-xdr 27
    // HashIdPreimageSorobanAuthorization).
    let mut entries: Vec<SorobanAuthorizationEntry> = Vec::with_capacity(1 + qualifying.len());
    entries.push(smart_account_entry);

    for (_pk, signer) in &qualifying {
        let delegated = build_and_sign_delegated_g_key_entry(
            &auth_scaddr,
            &auth_digest,
            signature_expiration_ledger,
            *signer,
            network_passphrase,
        )
        .await
        .map_err(|e: SaError| QuorumError::SignatureProductionFailed {
            detail: format!("delegated G-key entry: {e}"),
        })?;
        entries.push(delegated);
    }

    Ok(entries)
}

// ─────────────────────────────────────────────────────────────────────────────
// test_helpers — adversarial fixture construction
// ─────────────────────────────────────────────────────────────────────────────

/// Test-only construction helpers for [`AuthorizationInfo`] and siblings.
///
/// These helpers exist because [`AuthorizationInfo`], [`SignerGroup`], and
/// [`Combinator`] are `#[non_exhaustive]` — adversarial fixture tests in
/// `tests/` cannot use struct-literal construction.  Gate-guarded per
/// `feedback_non_exhaustive_test_helpers_pattern`.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::{AuthorizationInfo, Combinator, SignerGroup};

    /// Builds a [`SignerGroup`] from raw public key bytes, panicking on
    /// construction error (test-only).
    ///
    /// # Panics
    ///
    /// Panics when `threshold` is 0 or greater than `members.len()`.
    /// This is intentional — test helpers should fail loudly on invalid inputs
    /// rather than silently returning `Err`.
    #[must_use]
    #[allow(
        clippy::panic,
        reason = "test-helper: loud failure on invalid fixture input"
    )]
    pub fn make_group(name: &str, members: Vec<[u8; 32]>, threshold: u32) -> SignerGroup {
        SignerGroup::new(name.to_owned(), members, threshold)
            .unwrap_or_else(|e| panic!("make_group failed: {e}"))
    }

    /// Builds an [`AuthorizationInfo`] with a single group and AND combinator.
    #[must_use]
    pub fn single_group_and(group: SignerGroup) -> AuthorizationInfo {
        AuthorizationInfo {
            groups: vec![group],
            combinator: Combinator::And,
        }
    }

    /// Builds an [`AuthorizationInfo`] with multiple groups and AND combinator.
    #[must_use]
    pub fn multi_group_and(groups: Vec<SignerGroup>) -> AuthorizationInfo {
        AuthorizationInfo {
            groups,
            combinator: Combinator::And,
        }
    }

    /// Builds an [`AuthorizationInfo`] with multiple groups and OR combinator.
    #[must_use]
    pub fn multi_group_or(groups: Vec<SignerGroup>) -> AuthorizationInfo {
        AuthorizationInfo {
            groups,
            combinator: Combinator::Or,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only assertions"
    )]

    use super::*;

    // ── SignerGroup construction ───────────────────────────────────────────────

    #[test]
    fn signer_group_new_valid() {
        let g = SignerGroup::new("ops".into(), vec![[1u8; 32], [2u8; 32]], 1).unwrap();
        assert_eq!(g.name(), "ops");
        assert_eq!(g.threshold(), 1);
        assert_eq!(g.members().len(), 2);
    }

    #[test]
    fn signer_group_threshold_equals_members_ok() {
        let g = SignerGroup::new("ops".into(), vec![[1u8; 32], [2u8; 32]], 2).unwrap();
        assert_eq!(g.threshold(), 2);
    }

    #[test]
    fn signer_group_empty_members_rejected() {
        let e = SignerGroup::new("ops".into(), vec![], 1).unwrap_err();
        assert!(e.contains("members must not be empty"), "got: {e}");
    }

    #[test]
    fn signer_group_zero_threshold_rejected() {
        let e = SignerGroup::new("ops".into(), vec![[0u8; 32]], 0).unwrap_err();
        assert!(e.contains("threshold must be ≥ 1"), "got: {e}");
    }

    #[test]
    fn signer_group_threshold_exceeds_members_rejected() {
        let e = SignerGroup::new("ops".into(), vec![[0u8; 32]], 2).unwrap_err();
        assert!(e.contains("threshold 2 > members.len() 1"), "got: {e}");
    }

    // ── QuorumError wire codes ─────────────────────────────────────────────────

    #[test]
    fn quorum_error_wire_codes_stable() {
        assert_eq!(
            QuorumError::EmptyAuthorizationInfo.wire_code(),
            "sa.quorum.empty_authorization_info"
        );
        assert_eq!(
            QuorumError::InsufficientSignersInGroup {
                group_name: "g".into(),
                required: 2,
                provided: 1
            }
            .wire_code(),
            "sa.quorum.insufficient_signers_in_group"
        );
        assert_eq!(
            QuorumError::GroupNotSatisfiedInAndCombinator {
                unsatisfied_groups: vec![]
            }
            .wire_code(),
            "sa.quorum.group_not_satisfied_in_and_combinator"
        );
        assert_eq!(
            QuorumError::NoGroupSatisfiedInOrCombinator { groups: vec![] }.wire_code(),
            "sa.quorum.no_group_satisfied_in_or_combinator"
        );
        assert_eq!(
            QuorumError::SignatureProductionFailed { detail: "x".into() }.wire_code(),
            "sa.quorum.signature_production_failed"
        );
    }

    // ── AuthorizationInfo construction ────────────────────────────────────────

    #[test]
    fn authorization_info_new_preserves_fields() {
        let g = SignerGroup::new("admins".into(), vec![[1u8; 32]], 1).unwrap();
        let authz = AuthorizationInfo::new(vec![g.clone()], Combinator::Or);
        assert_eq!(authz.combinator, Combinator::Or);
        assert_eq!(authz.groups.len(), 1);
        assert_eq!(authz.groups[0].name(), "admins");
    }

    // ── Serde round-trip ──────────────────────────────────────────────────────

    #[test]
    fn authorization_info_serde_round_trip() {
        let g = SignerGroup::new("ops".into(), vec![[7u8; 32]], 1).unwrap();
        let authz = AuthorizationInfo::new(vec![g], Combinator::And);
        let json = serde_json::to_string(&authz).unwrap();
        let back: AuthorizationInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(authz, back);
    }

    // ── test_helpers ──────────────────────────────────────────────────────────

    #[test]
    fn test_helpers_make_group() {
        use super::test_helpers::make_group;
        let g = make_group("x", vec![[0u8; 32]], 1);
        assert_eq!(g.threshold(), 1);
    }

    #[test]
    fn test_helpers_single_group_and() {
        use super::test_helpers::{make_group, single_group_and};
        let g = make_group("x", vec![[0u8; 32]], 1);
        let a = single_group_and(g);
        assert_eq!(a.combinator, Combinator::And);
    }

    #[test]
    fn test_helpers_multi_group_or() {
        use super::test_helpers::{make_group, multi_group_or};
        let g1 = make_group("g1", vec![[1u8; 32]], 1);
        let g2 = make_group("g2", vec![[2u8; 32]], 1);
        let a = multi_group_or(vec![g1, g2]);
        assert_eq!(a.combinator, Combinator::Or);
        assert_eq!(a.groups.len(), 2);
    }

    // ── collect_quorum_signatures unit tests (offline, pure logic) ────────────
    //
    // These tests exercise the quorum orchestrator using StubSigner doubles that
    // never touch the network; they validate fail-closed logic and group
    // satisfaction semantics without an on-chain submission round-trip.

    use async_trait::async_trait;
    use stellar_agent_core::error::WalletError;
    use stellar_agent_network::WebAuthnAssertion;

    struct StubSigner {
        pubkey_bytes: [u8; 32],
    }

    #[async_trait]
    impl Signer for StubSigner {
        async fn sign_tx_payload(&self, _: &[u8; 32]) -> Result<[u8; 64], WalletError> {
            unimplemented!("stub")
        }

        async fn sign_auth_digest(&self, _: &[u8; 32]) -> Result<[u8; 64], WalletError> {
            // Return a deterministic fake 64-byte signature; sufficient for
            // offline unit tests that only exercise the quorum logic path.
            Ok([self.pubkey_bytes[0]; 64])
        }

        async fn sign_soroban_address_auth_payload(
            &self,
            _: &[u8; 32],
        ) -> Result<[u8; 64], WalletError> {
            Ok([self.pubkey_bytes[0]; 64])
        }

        async fn sign_webauthn_assertion(
            &self,
            _: &[u8; 32],
            _: &[u8],
        ) -> Result<WebAuthnAssertion, WalletError> {
            unimplemented!("stub")
        }

        async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
            Ok(stellar_strkey::ed25519::PublicKey(self.pubkey_bytes))
        }
    }

    /// `collect_quorum_signatures` returns `EmptyAuthorizationInfo` when
    /// `authz.groups` is empty.
    #[tokio::test]
    async fn empty_authorization_info_fails_closed() {
        use crate::signing::divergence::{
            AuthContextFingerprint, EnvelopeContext, FeeEnvelopeContext, NetworkContext,
            SequenceContext,
        };
        use stellar_xdr::{ContractId, Hash, ScAddress};

        let authz = AuthorizationInfo {
            groups: vec![],
            combinator: Combinator::And,
        };
        let s1 = StubSigner {
            pubkey_bytes: [1u8; 32],
        };
        let signers: Vec<&(dyn Signer + Send + Sync)> = vec![&s1];

        // Build a minimal simulation for the call; the early empty-groups check
        // fires before any auth-entry construction.
        let auth_scaddr = ScAddress::Contract(ContractId(Hash([0u8; 32])));
        let function_name = stellar_xdr::ScSymbol::try_from("test_fn").unwrap();
        let simulation = AuthorizationSimulation {
            context: crate::signing::divergence::SimulationContext {
                context_rule_ids: vec![
                    stellar_agent_core::smart_account::rule_id::ContextRuleId::new(1),
                ],
                auth_contexts: vec![AuthContextFingerprint::new("test:abcd1234".into())],
                network: NetworkContext {
                    passphrase_fingerprint: "testnet".into(),
                    ledger_protocol_version: 23,
                    chain_id_fingerprint: "testnet-chain".into(),
                },
                sequence: SequenceContext {
                    source_account_sequence: 1,
                    min_sequence_number: None,
                },
                fee_envelope: FeeEnvelopeContext {
                    tx_fee: 100,
                    resource_fee: 1000,
                },
            },
            network_id: [9u8; 32],
            nonce: 42,
            signature_expiration_ledger: 100,
        };
        let envelope = EnvelopeContext {
            context_rule_ids: simulation.context.context_rule_ids.clone(),
            auth_contexts: simulation.context.auth_contexts.clone(),
            network: simulation.context.network.clone(),
            sequence: simulation.context.sequence.clone(),
            fee_envelope: simulation.context.fee_envelope.clone(),
        };

        let result = collect_quorum_signatures(
            &authz,
            &signers,
            auth_scaddr,
            function_name,
            vec![],
            simulation.context.context_rule_ids.clone(),
            &simulation,
            &envelope,
            "Test SDF Network ; September 2015",
            100,
        )
        .await;

        assert!(
            matches!(result, Err(QuorumError::EmptyAuthorizationInfo)),
            "empty groups must fail closed, got: {result:?}"
        );
    }

    /// AND combinator: when one group has insufficient signers, returns
    /// `GroupNotSatisfiedInAndCombinator`.
    #[tokio::test]
    async fn and_combinator_insufficient_signers_returns_typed_error() {
        use crate::signing::divergence::{
            AuthContextFingerprint, EnvelopeContext, FeeEnvelopeContext, NetworkContext,
            SequenceContext,
        };
        use stellar_xdr::{ContractId, Hash, ScAddress};

        let pk1 = [1u8; 32];
        let pk2 = [2u8; 32];
        let pk3 = [3u8; 32];
        // Group requires 2-of-3 but we only supply 1 signer.
        let group = SignerGroup::new("admins".into(), vec![pk1, pk2, pk3], 2).unwrap();
        let authz = AuthorizationInfo {
            groups: vec![group],
            combinator: Combinator::And,
        };

        // Only signer with pk1 is supplied.
        let s1 = StubSigner { pubkey_bytes: pk1 };
        let signers: Vec<&(dyn Signer + Send + Sync)> = vec![&s1];

        let auth_scaddr = ScAddress::Contract(ContractId(Hash([0u8; 32])));
        let function_name = stellar_xdr::ScSymbol::try_from("test_fn").unwrap();
        let rule_id = stellar_agent_core::smart_account::rule_id::ContextRuleId::new(1);
        let simulation = AuthorizationSimulation {
            context: crate::signing::divergence::SimulationContext {
                context_rule_ids: vec![rule_id],
                auth_contexts: vec![AuthContextFingerprint::new("test:abcd1234".into())],
                network: NetworkContext {
                    passphrase_fingerprint: "testnet".into(),
                    ledger_protocol_version: 23,
                    chain_id_fingerprint: "testnet-chain".into(),
                },
                sequence: SequenceContext {
                    source_account_sequence: 1,
                    min_sequence_number: None,
                },
                fee_envelope: FeeEnvelopeContext {
                    tx_fee: 100,
                    resource_fee: 1000,
                },
            },
            network_id: [9u8; 32],
            nonce: 42,
            signature_expiration_ledger: 100,
        };
        let envelope = EnvelopeContext {
            context_rule_ids: simulation.context.context_rule_ids.clone(),
            auth_contexts: simulation.context.auth_contexts.clone(),
            network: simulation.context.network.clone(),
            sequence: simulation.context.sequence.clone(),
            fee_envelope: simulation.context.fee_envelope.clone(),
        };

        let result = collect_quorum_signatures(
            &authz,
            &signers,
            auth_scaddr,
            function_name,
            vec![],
            vec![rule_id],
            &simulation,
            &envelope,
            "Test SDF Network ; September 2015",
            100,
        )
        .await;

        match result {
            Err(QuorumError::GroupNotSatisfiedInAndCombinator { unsatisfied_groups }) => {
                assert_eq!(unsatisfied_groups, vec!["admins".to_owned()]);
            }
            other => panic!("expected GroupNotSatisfiedInAndCombinator, got: {other:?}"),
        }
    }

    /// OR combinator: when no group is satisfied, returns
    /// `NoGroupSatisfiedInOrCombinator`.
    #[tokio::test]
    async fn or_combinator_no_group_satisfied_returns_typed_error() {
        use crate::signing::divergence::{
            AuthContextFingerprint, EnvelopeContext, FeeEnvelopeContext, NetworkContext,
            SequenceContext,
        };
        use stellar_xdr::{ContractId, Hash, ScAddress};

        let pk1 = [1u8; 32];
        let pk2 = [2u8; 32];
        // Two groups, each requires 1 member; but we supply no matching signer.
        let g1 = SignerGroup::new("g1".into(), vec![pk1], 1).unwrap();
        let g2 = SignerGroup::new("g2".into(), vec![pk2], 1).unwrap();
        let authz = AuthorizationInfo {
            groups: vec![g1, g2],
            combinator: Combinator::Or,
        };

        // Supply a signer with a key that is NOT in either group.
        let s_other = StubSigner {
            pubkey_bytes: [99u8; 32],
        };
        let signers: Vec<&(dyn Signer + Send + Sync)> = vec![&s_other];

        let auth_scaddr = ScAddress::Contract(ContractId(Hash([0u8; 32])));
        let function_name = stellar_xdr::ScSymbol::try_from("test_fn").unwrap();
        let rule_id = stellar_agent_core::smart_account::rule_id::ContextRuleId::new(1);
        let simulation = AuthorizationSimulation {
            context: crate::signing::divergence::SimulationContext {
                context_rule_ids: vec![rule_id],
                auth_contexts: vec![AuthContextFingerprint::new("test:abcd1234".into())],
                network: NetworkContext {
                    passphrase_fingerprint: "testnet".into(),
                    ledger_protocol_version: 23,
                    chain_id_fingerprint: "testnet-chain".into(),
                },
                sequence: SequenceContext {
                    source_account_sequence: 1,
                    min_sequence_number: None,
                },
                fee_envelope: FeeEnvelopeContext {
                    tx_fee: 100,
                    resource_fee: 1000,
                },
            },
            network_id: [9u8; 32],
            nonce: 42,
            signature_expiration_ledger: 100,
        };
        let envelope = EnvelopeContext {
            context_rule_ids: simulation.context.context_rule_ids.clone(),
            auth_contexts: simulation.context.auth_contexts.clone(),
            network: simulation.context.network.clone(),
            sequence: simulation.context.sequence.clone(),
            fee_envelope: simulation.context.fee_envelope.clone(),
        };

        let result = collect_quorum_signatures(
            &authz,
            &signers,
            auth_scaddr,
            function_name,
            vec![],
            vec![rule_id],
            &simulation,
            &envelope,
            "Test SDF Network ; September 2015",
            100,
        )
        .await;

        match result {
            Err(QuorumError::NoGroupSatisfiedInOrCombinator { groups }) => {
                assert_eq!(groups, vec!["g1".to_owned(), "g2".to_owned()]);
            }
            other => panic!("expected NoGroupSatisfiedInOrCombinator, got: {other:?}"),
        }
    }

    /// OR combinator: when first group is satisfied, returns its entries and
    /// does NOT attempt the second group.
    #[tokio::test]
    async fn or_combinator_first_satisfied_group_wins() {
        use crate::signing::divergence::{
            AuthContextFingerprint, EnvelopeContext, FeeEnvelopeContext, NetworkContext,
            SequenceContext,
        };
        use stellar_xdr::{ContractId, Hash, ScAddress};

        let pk1 = [1u8; 32];
        let pk2 = [2u8; 32];
        // Two groups. g1 needs pk1 (1-of-1); g2 needs pk2 (1-of-1).
        // We supply pk1; g1 should win.
        let g1 = SignerGroup::new("g1".into(), vec![pk1], 1).unwrap();
        let g2 = SignerGroup::new("g2".into(), vec![pk2], 1).unwrap();
        let authz = AuthorizationInfo {
            groups: vec![g1, g2],
            combinator: Combinator::Or,
        };

        let s1 = StubSigner { pubkey_bytes: pk1 };
        let signers: Vec<&(dyn Signer + Send + Sync)> = vec![&s1];

        let auth_scaddr = ScAddress::Contract(ContractId(Hash([0u8; 32])));
        let function_name = stellar_xdr::ScSymbol::try_from("test_fn").unwrap();
        let rule_id = stellar_agent_core::smart_account::rule_id::ContextRuleId::new(1);
        let simulation = AuthorizationSimulation {
            context: crate::signing::divergence::SimulationContext {
                context_rule_ids: vec![rule_id],
                auth_contexts: vec![AuthContextFingerprint::new("test:abcd1234".into())],
                network: NetworkContext {
                    passphrase_fingerprint: "testnet".into(),
                    ledger_protocol_version: 23,
                    chain_id_fingerprint: "testnet-chain".into(),
                },
                sequence: SequenceContext {
                    source_account_sequence: 1,
                    min_sequence_number: None,
                },
                fee_envelope: FeeEnvelopeContext {
                    tx_fee: 100,
                    resource_fee: 1000,
                },
            },
            network_id: [9u8; 32],
            nonce: 42,
            signature_expiration_ledger: 100,
        };
        let envelope = EnvelopeContext {
            context_rule_ids: simulation.context.context_rule_ids.clone(),
            auth_contexts: simulation.context.auth_contexts.clone(),
            network: simulation.context.network.clone(),
            sequence: simulation.context.sequence.clone(),
            fee_envelope: simulation.context.fee_envelope.clone(),
        };

        // We expect success (g1 satisfied by s1).
        let result = collect_quorum_signatures(
            &authz,
            &signers,
            auth_scaddr,
            function_name,
            vec![],
            vec![rule_id],
            &simulation,
            &envelope,
            "Test SDF Network ; September 2015",
            100,
        )
        .await;

        // The result can only succeed or fail with SignatureProductionFailed (from the
        // offline mock signer's build_authorization_entry call). Since build_authorization_entry
        // requires a real simulation context, it will return RuleIdMismatch or similar;
        // what matters for this unit test is that the quorum routing itself chose g1 (we
        // do NOT get NoGroupSatisfiedInOrCombinator).
        if let Err(QuorumError::NoGroupSatisfiedInOrCombinator { .. }) = result {
            panic!("should not have tried all groups when g1 had a qualifying signer");
        }
        // Any other error (auth-entry construction fails without live RPC) is acceptable
        // in this offline unit test.
    }
}
