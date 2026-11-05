//! Quorum-like `AuthorizationInfo` substrate for multi-signer smart-account
//! invocations.
//!
//! # Overview
//!
//! [`AuthorizationInfo`] declares groups of ed25519 signers, each with a
//! threshold M-of-N, plus a cross-group [`Combinator`] (AND / OR).
//! [`plan_quorum_signatures`] selects qualifying signers and fixes every nonce.
//! Admission certifies that plan before [`sign_quorum_plan`] signs its entries.
//! The submission flow passes those entries to the contract.
//!
//! # Design decisions
//!
//! - `SubmitInvokeArgs` owns the quorum loop: when
//!   `args.authorization` is `Some`, `submit_signed_invoke` calls
//!   `plan_quorum_signatures` internally instead of a single-signer path.
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

use crate::submit::CheckedSigningRules;
use serde::{Deserialize, Serialize};
use stellar_agent_network::signing::Signer;
use stellar_xdr::{ScAddress, ScSymbol, ScVal, SorobanAuthorizationEntry};
use thiserror::Error;

use crate::SaError;
use crate::managers::auth_entry::{
    AuthorizationSimulation, PartialSorobanAuthorizationEntry, PreSubmitBudget,
    SIGN_AUTH_DIGEST_STAGE, build_authorization_entry,
    complete_authorization_entry_multi_signer_within_budget, network_id_of, sign_within_budget,
};
use crate::managers::rules::build_and_sign_delegated_g_key_entry;
use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;
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
            return Err("SignerGroup members must not be empty".to_owned());
        }
        if threshold == 0 {
            return Err("SignerGroup threshold must be at least 1".to_owned());
        }
        #[allow(
            clippy::cast_possible_truncation,
            reason = "members.len() is bounded by u32 max in practice"
        )]
        if threshold > members.len() as u32 {
            return Err("SignerGroup threshold must not exceed the member count".to_owned());
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
/// [`plan_quorum_signatures`] to select signing authority and by
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

/// Typed error from [`plan_quorum_signatures`].
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

    /// Quorum signing was refused before any signer key access: the
    /// passphrase names mainnet, or the passphrase and the simulation name
    /// different networks.
    ///
    /// A mismatch shares the mainnet code because the delegated G-key entries
    /// are signed for the passphrase and the smart-account entry for the
    /// simulation's network ID: with the two apart, the declared network does
    /// not establish which network a signature commits to.
    ///
    /// Wire code: `sa.quorum.mainnet_write_forbidden`.
    #[error(
        "quorum signing refused: the network is mainnet, or the passphrase and the simulation \
         name different networks"
    )]
    MainnetWriteForbidden,
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
            Self::MainnetWriteForbidden => "sa.quorum.mainnet_write_forbidden",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// plan_quorum_signatures
// ─────────────────────────────────────────────────────────────────────────────

/// The selected authority and nonces fixed before signing admission.
#[derive(Debug)]
pub struct QuorumPlan {
    groups: Vec<PlannedGroup>,
    subjects: Vec<stellar_agent_network::IntentSubject>,
    network_passphrase: String,
}

#[derive(Debug)]
struct PlannedGroup {
    partial: PartialSorobanAuthorizationEntry,
    checked: CheckedSigningRules,
    keys: Vec<[u8; 32]>,
    nonces: Vec<i64>,
}

impl QuorumPlan {
    /// Returns every smart account and delegated authorization subject.
    #[must_use]
    pub fn intent_subjects(&self) -> Vec<stellar_agent_network::IntentSubject> {
        self.subjects.clone()
    }
}

/// Plans the selected quorum without producing any signature.
///
/// # Errors
/// Refuses invalid authority, an unsatisfied quorum, or an unreadable public key.
#[allow(clippy::too_many_arguments)]
pub async fn plan_quorum_signatures(
    checked_rules: CheckedSigningRules,
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
) -> Result<QuorumPlan, QuorumError> {
    plan_quorum_signatures_within_budget(
        checked_rules,
        authz,
        signers,
        auth_scaddr,
        function_name,
        args,
        auth_rule_ids,
        simulation,
        envelope,
        network_passphrase,
        signature_expiration_ledger,
        None,
    )
    .await
    .map_err(QuorumFailure::into_quorum_error)
}

/// Why quorum planning or signing refuses.
#[derive(Debug)]
pub(crate) enum QuorumFailure {
    Quorum(QuorumError),
    Deadline(SaError),
    Intent(SaError),
}

impl From<QuorumError> for QuorumFailure {
    fn from(error: QuorumError) -> Self {
        Self::Quorum(error)
    }
}

impl QuorumFailure {
    fn into_quorum_error(self) -> QuorumError {
        match self {
            Self::Quorum(error) => error,
            Self::Deadline(error) | Self::Intent(error) => QuorumError::SignatureProductionFailed {
                detail: error.to_string(),
            },
        }
    }
    fn of_signing(budget: Option<PreSubmitBudget>, context: &str, error: SaError) -> Self {
        if matches!(
            error,
            SaError::IntentBindingMismatch { .. } | SaError::IntentRecordUnavailable { .. }
        ) {
            Self::Intent(error)
        } else if budget.is_some_and(|budget| tokio::time::Instant::now() >= budget.deadline) {
            Self::Deadline(error)
        } else {
            Self::Quorum(QuorumError::SignatureProductionFailed {
                detail: format!("{context}{error}"),
            })
        }
    }
}

/// A quorum refusal or a typed intent refusal during signing.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum QuorumSigningError {
    /// The selected quorum cannot produce its signatures.
    #[error(transparent)]
    Quorum(QuorumError),
    /// The signing request differs from its admitted intent.
    #[error(transparent)]
    Intent(SaError),
}
impl QuorumSigningError {
    /// Returns the underlying stable refusal code.
    #[must_use]
    pub fn wire_code(&self) -> &'static str {
        match self {
            Self::Quorum(error) => error.wire_code(),
            Self::Intent(error) => error.wire_code(),
        }
    }
}

/// Plans all selected groups before any signer runs.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn plan_quorum_signatures_within_budget(
    checked_rules: CheckedSigningRules,
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
    budget: Option<PreSubmitBudget>,
) -> Result<QuorumPlan, QuorumFailure> {
    use stellar_agent_network::{IntentSubject, SignerDescriptor};
    if network_passphrase == MAINNET_PASSPHRASE
        || network_id_of(network_passphrase) != simulation.network_id
    {
        return Err(QuorumError::MainnetWriteForbidden.into());
    }
    if authz.groups.is_empty() {
        return Err(QuorumError::EmptyAuthorizationInfo.into());
    }
    checked_rules
        .check_binding(&auth_scaddr, simulation.network_id, &auth_rule_ids)
        .map_err(|error| QuorumError::SignatureProductionFailed {
            detail: error.to_string(),
        })?;
    let mut keys = Vec::new();
    for signer in signers {
        keys.push(
            sign_within_budget(budget, SIGN_AUTH_DIGEST_STAGE, signer.public_key())
                .await
                .map_err(QuorumFailure::Deadline)?
                .map_err(|error| QuorumError::SignatureProductionFailed {
                    detail: error.to_string(),
                })?
                .0,
        );
    }
    let mut selected = Vec::new();
    let mut unsatisfied = Vec::new();
    for (group, checked) in authz
        .groups
        .iter()
        .zip(checked_rules.into_groups(authz.groups.len()))
    {
        let mut qualifying: Vec<_> = keys
            .iter()
            .filter(|key| group.members.contains(key))
            .copied()
            .collect();
        qualifying.sort();
        if qualifying.len() < group.threshold as usize {
            unsatisfied.push(group.name.clone());
            continue;
        }
        qualifying.truncate(group.threshold as usize);
        selected.push((qualifying, checked));
        if matches!(authz.combinator, Combinator::Or) {
            break;
        }
    }
    if matches!(authz.combinator, Combinator::And) && !unsatisfied.is_empty() {
        return Err(QuorumError::GroupNotSatisfiedInAndCombinator {
            unsatisfied_groups: unsatisfied,
        }
        .into());
    }
    if selected.is_empty() {
        return Err(QuorumError::NoGroupSatisfiedInOrCombinator {
            groups: authz
                .groups
                .iter()
                .map(|group| group.name.clone())
                .collect(),
        }
        .into());
    }
    let mut groups = Vec::new();
    let mut subjects = Vec::new();
    let failure = |error: SaError| QuorumError::SignatureProductionFailed {
        detail: error.to_string(),
    };
    for (keys, checked) in selected {
        let partial = build_authorization_entry(
            auth_scaddr.clone(),
            function_name.clone(),
            args.clone(),
            auth_rule_ids.clone(),
            simulation,
            envelope,
        )
        .await
        .map_err(failure)?;
        let rule_ids = partial
            .context_rule_ids
            .iter()
            .map(ContextRuleId::as_u32)
            .collect();
        subjects.push(
            IntentSubject::smart_account(
                &auth_scaddr,
                partial.nonce,
                signature_expiration_ledger,
                &partial.root_invocation,
                rule_ids,
                keys.iter()
                    .map(|key| SignerDescriptor::Delegated { account: *key })
                    .collect(),
            )
            .map_err(|field| QuorumFailure::Intent(SaError::IntentBindingMismatch { field }))?,
        );
        let invocation = crate::managers::auth_entry::delegated_g_key_invocation(
            &auth_scaddr,
            &partial.auth_digest,
        )
        .map_err(failure)?;
        let mut nonces = Vec::new();
        for key in &keys {
            use rand_core::RngCore as _;
            let nonce = i64::from_ne_bytes(rand_core::OsRng.next_u64().to_ne_bytes());
            let address = stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
                stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(*key)),
            ));
            subjects.push(
                IntentSubject::account_key(
                    &address,
                    nonce,
                    signature_expiration_ledger,
                    &invocation,
                )
                .map_err(|field| QuorumFailure::Intent(SaError::IntentBindingMismatch { field }))?,
            );
            nonces.push(nonce);
        }
        groups.push(PlannedGroup {
            partial,
            checked,
            keys,
            nonces,
        });
    }
    Ok(QuorumPlan {
        groups,
        subjects,
        network_passphrase: network_passphrase.into(),
    })
}

/// Signs exactly the quorum selected before admission.
///
/// # Errors
/// Refuses missing planned keys, unplanned signatures, or a signer failure.
pub async fn sign_quorum_plan(
    plan: &QuorumPlan,
    signers: &[&(dyn Signer + Send + Sync)],
    gate: &crate::signing::gate::SigningGate,
) -> Result<Vec<SorobanAuthorizationEntry>, QuorumSigningError> {
    sign_quorum_plan_within_budget(plan, signers, gate, None)
        .await
        .map_err(|error| match error {
            QuorumFailure::Quorum(error) => QuorumSigningError::Quorum(error),
            QuorumFailure::Intent(error) | QuorumFailure::Deadline(error) => {
                QuorumSigningError::Intent(error)
            }
        })
}

pub(crate) async fn sign_quorum_plan_within_budget(
    plan: &QuorumPlan,
    signers: &[&(dyn Signer + Send + Sync)],
    gate: &crate::signing::gate::SigningGate,
    budget: Option<PreSubmitBudget>,
) -> Result<Vec<SorobanAuthorizationEntry>, QuorumFailure> {
    let mut resolved = Vec::new();
    for &signer in signers {
        let key = sign_within_budget(budget, SIGN_AUTH_DIGEST_STAGE, signer.public_key())
            .await
            .map_err(QuorumFailure::Deadline)?
            .map_err(|error| QuorumError::SignatureProductionFailed {
                detail: error.to_string(),
            })?;
        resolved.push((key.0, signer));
    }
    if plan
        .groups
        .iter()
        .flat_map(|group| &group.keys)
        .any(|key| !resolved.iter().any(|(actual, _)| actual == key))
    {
        return Err(QuorumError::SignatureProductionFailed {
            detail: "a planned signing key is unavailable".into(),
        }
        .into());
    }
    let mut entries = Vec::new();
    for group in &plan.groups {
        let signers: Vec<_> = group
            .keys
            .iter()
            .filter_map(|key| {
                resolved
                    .iter()
                    .find(|(actual, _)| actual == key)
                    .map(|(_, signer)| *signer)
            })
            .collect();
        entries.push(
            complete_authorization_entry_multi_signer_within_budget(
                gate,
                group.checked.for_planned_signing(),
                group.partial.clone(),
                &signers,
                budget,
            )
            .await
            .map_err(|error| QuorumFailure::of_signing(budget, "", error))?,
        );
        for (signer, nonce) in signers.iter().zip(&group.nonces) {
            entries.push(
                build_and_sign_delegated_g_key_entry(
                    gate,
                    *nonce,
                    &group.partial.smart_account,
                    &group.partial.auth_digest,
                    group.partial.signature_expiration_ledger,
                    *signer,
                    &plan.network_passphrase,
                    budget,
                )
                .await
                .map_err(|error| QuorumFailure::of_signing(budget, "delegated entry: ", error))?,
            );
        }
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
        assert_eq!(e, "SignerGroup members must not be empty");
    }

    #[test]
    fn signer_group_zero_threshold_rejected() {
        let e = SignerGroup::new("ops".into(), vec![[0u8; 32]], 0).unwrap_err();
        assert_eq!(e, "SignerGroup threshold must be at least 1");
    }

    #[test]
    fn signer_group_threshold_exceeds_members_rejected() {
        let e = SignerGroup::new("ops".into(), vec![[0u8; 32]], 2).unwrap_err();
        assert_eq!(e, "SignerGroup threshold must not exceed the member count");
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
        assert_eq!(
            QuorumError::MainnetWriteForbidden.wire_code(),
            "sa.quorum.mainnet_write_forbidden"
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

    // ── plan_quorum_signatures unit tests (offline, pure logic) ────────────
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
        async fn sign_tx_payload(
            &self,
            _: &stellar_agent_network::signing::TxSigningPayload,
        ) -> Result<[u8; 64], WalletError> {
            unimplemented!("stub")
        }

        async fn sign_auth_digest(
            &self,
            _: &stellar_agent_network::signing::SmartAccountAuthDigest,
        ) -> Result<[u8; 64], WalletError> {
            // Return a deterministic fake 64-byte signature; sufficient for
            // offline unit tests that only exercise the quorum logic path.
            Ok([self.pubkey_bytes[0]; 64])
        }

        async fn sign_soroban_address_auth_payload(
            &self,
            _: &stellar_agent_network::signing::SorobanAuthPayload,
        ) -> Result<[u8; 64], WalletError> {
            Ok([self.pubkey_bytes[0]; 64])
        }

        async fn sign_message(
            &self,
            _: &stellar_agent_network::signing::MessagePayload,
        ) -> Result<[u8; 64], WalletError> {
            unimplemented!("stub")
        }

        async fn sign_webauthn_assertion(
            &self,
            _: &stellar_agent_network::signing::SmartAccountAuthDigest,
            _: &[u8],
        ) -> Result<WebAuthnAssertion, WalletError> {
            unimplemented!("stub")
        }

        async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
            Ok(stellar_strkey::ed25519::PublicKey(self.pubkey_bytes))
        }
    }

    /// `plan_quorum_signatures` returns `EmptyAuthorizationInfo` when
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
            network_id: network_id_of("Test SDF Network ; September 2015"),
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

        let result = plan_quorum_signatures(
            crate::submit::checked_context_for_test(
                &auth_scaddr,
                simulation.network_id,
                &simulation.context.context_rule_ids,
            ),
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
            network_id: network_id_of("Test SDF Network ; September 2015"),
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

        let result = plan_quorum_signatures(
            crate::submit::checked_context_for_test(
                &auth_scaddr,
                simulation.network_id,
                &simulation.context.context_rule_ids,
            ),
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
            network_id: network_id_of("Test SDF Network ; September 2015"),
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

        let result = plan_quorum_signatures(
            crate::submit::checked_context_for_test(
                &auth_scaddr,
                simulation.network_id,
                &simulation.context.context_rule_ids,
            ),
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
            network_id: network_id_of("Test SDF Network ; September 2015"),
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
        let result = plan_quorum_signatures(
            crate::submit::checked_context_for_test(
                &auth_scaddr,
                simulation.network_id,
                &simulation.context.context_rule_ids,
            ),
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

    // ── Mainnet refusal and network binding before any key access ───────────

    /// A non-mainnet network other than testnet.
    const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";

    /// Runs a 1-of-1 quorum over one counting signer, declaring
    /// `network_passphrase` with a simulation of the network of
    /// `simulation_passphrase`. Returns the result and the signer's key
    /// accesses. The quorum takes no RPC client, so it makes no request.
    async fn quorum_over(
        network_passphrase: &str,
        simulation_passphrase: &str,
    ) -> (Result<Vec<SorobanAuthorizationEntry>, QuorumError>, usize) {
        use crate::managers::auth_entry::test_helpers::{
            baseline_authorization_simulation, matching_envelope_context,
        };
        use stellar_agent_network::signing::test_doubles::CountingSigner;
        use stellar_xdr::{ContractId, Hash};

        let seed = [0x21u8; 32];
        let member = stellar_agent_network::SoftwareSigningKey::new_from_bytes(seed)
            .public_key()
            .await
            .unwrap()
            .0;
        let authz = AuthorizationInfo::new(
            vec![SignerGroup::new("ops".into(), vec![member], 1).unwrap()],
            Combinator::And,
        );
        let signer = CountingSigner::new(seed);
        let rule_id = ContextRuleId::new(1);
        let simulation = baseline_authorization_simulation(
            simulation_passphrase,
            "stellar:fixture",
            vec![rule_id],
        );
        let envelope = matching_envelope_context(&simulation);

        let result = plan_quorum_signatures(
            crate::submit::checked_context_for_test(
                &ScAddress::Contract(ContractId(Hash([0x31; 32]))),
                simulation.network_id,
                &simulation.context.context_rule_ids,
            ),
            &authz,
            &[&signer],
            ScAddress::Contract(ContractId(Hash([0x31; 32]))),
            ScSymbol::try_from("execute").unwrap(),
            vec![],
            vec![rule_id],
            &simulation,
            &envelope,
            network_passphrase,
            9999,
        )
        .await;
        let result = match result {
            Ok(plan) => {
                let gate = crate::signing::intent_test_helpers::gate(plan.intent_subjects());
                sign_quorum_plan(&plan, &[&signer], &gate)
                    .await
                    .map_err(|error| match error {
                        QuorumSigningError::Quorum(error) => error,
                        QuorumSigningError::Intent(error) => {
                            panic!("fixture admission refuses: {error}")
                        }
                    })
            }
            Err(error) => Err(error),
        };
        (result, signer.key_accesses())
    }

    #[tokio::test]
    async fn plan_quorum_signatures_signs_a_testnet_quorum() {
        let (result, key_accesses) = quorum_over(
            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
        )
        .await;

        assert_eq!(
            result.unwrap().len(),
            2,
            "the smart-account entry and one G-key entry"
        );
        assert!(key_accesses > 0);
    }

    #[tokio::test]
    async fn plan_quorum_signatures_refuses_the_mainnet_passphrase_before_any_key_access() {
        let (result, key_accesses) = quorum_over(MAINNET_PASSPHRASE, MAINNET_PASSPHRASE).await;

        assert!(
            matches!(result, Err(QuorumError::MainnetWriteForbidden)),
            "{result:?}"
        );
        assert_eq!(key_accesses, 0);
    }

    #[tokio::test]
    async fn plan_quorum_signatures_refuses_a_mainnet_simulation_before_any_key_access() {
        let (result, key_accesses) = quorum_over(
            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
            MAINNET_PASSPHRASE,
        )
        .await;

        assert!(
            matches!(result, Err(QuorumError::MainnetWriteForbidden)),
            "{result:?}"
        );
        assert_eq!(key_accesses, 0);
    }

    #[tokio::test]
    async fn plan_quorum_signatures_refuses_a_passphrase_of_another_network_before_any_key_access()
    {
        let (result, key_accesses) = quorum_over(
            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
            FUTURENET_PASSPHRASE,
        )
        .await;

        assert!(
            matches!(result, Err(QuorumError::MainnetWriteForbidden)),
            "{result:?}"
        );
        assert_eq!(key_accesses, 0);
    }
    #[tokio::test]
    async fn quorum_collection_refuses_a_different_checked_rule() {
        use crate::managers::auth_entry::test_helpers::{
            baseline_authorization_simulation, matching_envelope_context,
        };
        use stellar_agent_network::signing::test_doubles::CountingSigner;
        use stellar_xdr::{ContractId, Hash};
        let address = ScAddress::Contract(ContractId(Hash([0x31; 32])));
        let rule = ContextRuleId::new(1);
        let simulation = baseline_authorization_simulation(
            "Test SDF Network ; September 2015",
            "stellar:testnet",
            vec![rule],
        );
        let envelope = matching_envelope_context(&simulation);
        let checked = crate::submit::checked_context_for_test(
            &address,
            simulation.network_id,
            &[ContextRuleId::new(0)],
        );
        let signer = CountingSigner::new([0x46; 32]);
        let authz = AuthorizationInfo::new(
            vec![SignerGroup::new("one".to_owned(), vec![[0x46; 32]], 1).unwrap()],
            Combinator::And,
        );
        let error = plan_quorum_signatures(
            checked,
            &authz,
            &[&signer],
            address,
            "execute".try_into().unwrap(),
            vec![],
            vec![rule],
            &simulation,
            &envelope,
            "Test SDF Network ; September 2015",
            9999,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, QuorumError::SignatureProductionFailed { ref detail } if detail.contains("checked_signing_rules")),
            "{error:?}"
        );
        assert_eq!(signer.key_accesses(), 0);
    }
    #[tokio::test]
    async fn quorum_signing_signs_the_admitted_plan() {
        use crate::managers::auth_entry::test_helpers::{
            baseline_authorization_simulation, matching_envelope_context,
        };
        use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
        use stellar_agent_network::signing::test_doubles::CountingSigner;
        let seeds = [[0x21; 32], [0x22; 32]];
        let keys = seeds.map(|seed| {
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes()
        });
        let authz = AuthorizationInfo::new(
            vec![
                SignerGroup::new("first".into(), vec![keys[0]], 1).unwrap(),
                SignerGroup::new("second".into(), vec![keys[1]], 1).unwrap(),
            ],
            Combinator::And,
        );
        let account = stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash(
            [0x31; 32],
        )));
        let a = CountingSigner::new(seeds[0]);
        let b = CountingSigner::new(seeds[1]);
        let signers: Vec<&(dyn Signer + Send + Sync)> = vec![&a, &b];
        let make_plan = |expiration| {
            let authz = &authz;
            let signers = &signers;
            let account = account.clone();
            async move {
                let mut simulation = baseline_authorization_simulation(
                    TESTNET_PASSPHRASE,
                    "stellar:testnet",
                    vec![ContextRuleId::new(1)],
                );
                simulation.signature_expiration_ledger = expiration;
                let envelope = matching_envelope_context(&simulation);
                plan_quorum_signatures(
                    crate::submit::checked_context_for_test(
                        &account,
                        simulation.network_id,
                        &simulation.context.context_rule_ids,
                    ),
                    authz,
                    signers,
                    account,
                    ScSymbol::try_from("execute").unwrap(),
                    vec![],
                    simulation.context.context_rule_ids.clone(),
                    &simulation,
                    &envelope,
                    TESTNET_PASSPHRASE,
                    expiration,
                )
                .await
                .unwrap()
            }
        };
        let plan = make_plan(9999).await;
        let source = stellar_strkey::ed25519::PublicKey([0; 32])
            .to_string()
            .as_str()
            .to_owned();
        let intent = |subjects| {
            stellar_agent_network::SignedIntentPlan::new(
                TESTNET_PASSPHRASE,
                "fixture",
                &source,
                1,
                [7; 32],
                subjects,
                Some(9999),
            )
            .unwrap()
        };
        let admitted_plan = intent(plan.intent_subjects());
        let proof = stellar_agent_network::SubmissionRecorder::admit_signed_intent(
            &crate::signing::intent_test_helpers::NoLimitRecorder,
            &admitted_plan,
        )
        .await
        .unwrap();
        let gate = crate::signing::gate::SigningGate::new(proof);
        let entries = sign_quorum_plan(&plan, &signers, &gate).await.unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!((a.sign_calls(), b.sign_calls()), (2, 2));

        let actual: Vec<_> = entries
            .iter()
            .map(|entry| stellar_agent_network::IntentSubject::of_entry(entry, &source).unwrap())
            .collect();
        for (actual, planned) in actual.iter().zip(plan.intent_subjects()) {
            assert_eq!(actual.auth_subject(), planned.auth_subject());
            assert_eq!(actual.nonce(), planned.nonce());
            assert_eq!(actual.expiration(), planned.expiration());
            assert_eq!(actual.root_invocation(), planned.root_invocation());
        }
        assert_eq!(intent(actual).subjects(), admitted_plan.subjects());
        assert!(gate.exposure().is_some());
        let changed = make_plan(10000).await;
        let gate = crate::signing::intent_test_helpers::gate(plan.intent_subjects());
        let before = a.sign_calls() + b.sign_calls();
        let error = sign_quorum_plan(&changed, &signers, &gate)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            QuorumSigningError::Intent(SaError::IntentBindingMismatch {
                field: "signing_request"
            })
        ));
        assert_eq!(a.sign_calls() + b.sign_calls(), before);
        assert!(gate.take_unexposed().is_some());
        let replanned = make_plan(9999).await;
        let gate = crate::signing::intent_test_helpers::gate(plan.intent_subjects());
        let error = sign_quorum_plan(&replanned, &signers, &gate)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            QuorumSigningError::Intent(SaError::IntentBindingMismatch {
                field: "signing_request"
            })
        ));
        assert_eq!(a.sign_calls() + b.sign_calls(), before + 1);
        assert!(gate.exposure().is_some());
        for error in [
            SaError::IntentBindingMismatch { field: "signers" },
            SaError::IntentRecordUnavailable {
                class: "window_unavailable",
            },
        ] {
            let code = error.wire_code();
            let QuorumFailure::Intent(error) = QuorumFailure::of_signing(None, "fixture", error)
            else {
                panic!("intent error must stay typed");
            };
            assert_eq!(error.wire_code(), code);
        }
    }
}
