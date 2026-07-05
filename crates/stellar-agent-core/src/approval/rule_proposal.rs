//! Resolved-definition snapshot for an agent-proposed context-rule approval.
//!
//! [`ContextRuleProposalSnapshot`] is the `ApprovalKind::RuleProposalSimulated`
//! payload (Package D, GH issue #8): the FULLY-RESOLVED `add_context_rule`
//! definition an agent proposed, captured at propose time so the operator's
//! consent binds to EXACTLY what will be installed at commit — every signer
//! as resolved bytes (never a credential-name reference), every policy as
//! `{policy_address, params_xdr_b64}`, the context type, name, expiry, and
//! `auth_rule_ids`.
//!
//! # No `stellar-agent-smart-account` dependency
//!
//! `stellar-agent-core` cannot depend on `stellar-agent-smart-account` (the
//! latter already depends on the former), so this module carries no
//! `stellar-xdr` type (`ScAddress`, `ScVal`, ...): addresses are canonical
//! strkeys, wasm hashes are hex, and policy params are base64-encoded XDR
//! bytes rather than typed values. The `stellar-agent-smart-account` crate
//! converts between this snapshot and its own `ContextRuleDefinition` /
//! `ContextRuleSignerInput` / `ContextRulePolicy` types, and computes the
//! `proposal_sha256` digest (see [`super::attestation::compute_rule_proposal_digest`]).

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Bounds — mirrored from OZ on-chain caps
// ─────────────────────────────────────────────────────────────────────────────

/// Schema version for [`ContextRuleProposalSnapshot`].
///
/// Bumped on any additive-or-breaking field-shape change so an old on-disk
/// snapshot cannot silently reinterpret under a new layout. `1` is the
/// initial shape (Package D, GH issue #8).
pub const CONTEXT_RULE_PROPOSAL_SNAPSHOT_VERSION: u32 = 1;

/// Maximum number of signers per proposed context rule.
///
/// Mirrors OZ `stellar-contracts` v0.7.2
/// `packages/accounts/src/smart_account/mod.rs:526` SHA `a9c4216`
/// (`pub const MAX_SIGNERS: u32 = 15`). `stellar-agent-core` cannot import
/// the `stellar-agent-smart-account` crate's own `OZ_MAX_SIGNERS` constant
/// (dependency direction), so the bound is re-declared here for early,
/// fail-closed rejection of a malformed snapshot; the authoritative
/// enforcement remains on-chain and in the smart-account crate's own
/// construction path.
pub const RULE_PROPOSAL_MAX_SIGNERS: usize = 15;

/// Maximum number of policies per proposed context rule.
///
/// Mirrors OZ `stellar-contracts` v0.7.2
/// `packages/accounts/src/smart_account/mod.rs:524` SHA `a9c4216`
/// (`pub const MAX_POLICIES: u32 = 5`). See [`RULE_PROPOSAL_MAX_SIGNERS`]
/// for why this is re-declared rather than imported.
pub const RULE_PROPOSAL_MAX_POLICIES: usize = 5;

/// Maximum byte length of a proposed context-rule name.
///
/// Mirrors OZ `stellar-contracts` v0.7.2
/// `packages/accounts/src/smart_account/mod.rs:528` SHA `a9c4216`
/// (`pub const MAX_NAME_SIZE: u32 = 20`).
pub const RULE_PROPOSAL_MAX_NAME_BYTES: usize = 20;

/// Maximum byte length of an `External` signer's `pubkey_data` payload.
///
/// Mirrors OZ `stellar-contracts` v0.7.2
/// `packages/accounts/src/smart_account/mod.rs:530` SHA `a9c4216`
/// (`pub const MAX_EXTERNAL_KEY_SIZE: u32 = 256`).
pub const RULE_PROPOSAL_MAX_EXTERNAL_KEY_BYTES: usize = 256;

/// Maximum number of `auth_rule_ids` entries on a proposal.
///
/// Matches the OZ MultiSig context-rule batch limit — same bound as
/// `SignWithPasskey::rule_ids` / `RegisterPasskey::rule_ids` in
/// `super::store`.
pub const RULE_PROPOSAL_MAX_AUTH_RULE_IDS: usize = 8;

/// Maximum decoded byte length of a policy's `params_xdr_b64` payload.
///
/// Not an OZ on-chain constant — a wallet-side defensive cap bounding the
/// on-disk pending-approval store against an oversized policy-params blob.
/// 8 KiB is well above any realistic policy parameter payload (e.g. a
/// spending-limit policy's `SimpleThresholdAccountParams` is a handful of
/// bytes).
pub const RULE_PROPOSAL_MAX_POLICY_PARAMS_BYTES: usize = 8192;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Context type of a proposed rule, mirroring the on-chain `ContextRuleType`
/// (OZ `stellar-accounts` v0.7.2), but carrying only strkey/hex primitives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleProposalContextType {
    /// Rule authorizes any context — account-wide authority. Rendered
    /// PROMINENTLY on every approval surface (Leg 3).
    Default,
    /// Rule scoped to invocations of one specific contract.
    CallContract {
        /// Target contract C-strkey.
        contract: String,
    },
    /// Rule scoped to creating a contract with one specific wasm hash.
    CreateContract {
        /// 64 lowercase-hex characters (32-byte wasm hash).
        wasm_hash_hex: String,
    },
}

/// Discriminator for [`RuleProposalSigner`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleProposalSignerKind {
    /// Built-in ed25519 (or contract-mediated) delegated signer.
    Delegated,
    /// External signer verified by a verifier contract (e.g. WebAuthn).
    External,
}

/// One resolved signer entry in a [`ContextRuleProposalSnapshot`].
///
/// Resolved to raw bytes at propose time — never a credential-NAME
/// reference — so the operator's consent binds to the exact bytes that will
/// be installed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RuleProposalSigner {
    /// Which signer shape this entry carries.
    pub kind: RuleProposalSignerKind,
    /// `Delegated` signer's on-chain address (G- or C-strkey — an
    /// ed25519-keyed delegate uses a G-strkey, a contract-mediated signer
    /// uses a C-strkey). `None` for `External`.
    pub address: Option<String>,
    /// `External` signer's verifier-contract C-strkey. `None` for `Delegated`.
    pub verifier: Option<String>,
    /// `External` signer's raw verifier-specific public-key bytes (e.g. the
    /// OZ canonical `pubkey_65 || credential_id` WebAuthn layout,
    /// `verifiers/webauthn.rs:373-377` in `stellar-agent-smart-account`).
    /// `None` for `Delegated`.
    pub pubkey_data: Option<Vec<u8>>,
    /// `true` when this signer IS the proposing agent's own signing key —
    /// resolved by comparing pubkey bytes against the agent profile's
    /// signing identity at propose time. Rendered as an explicit tag on
    /// every approval surface (Leg 3).
    ///
    /// Wallet-computed DISPLAY metadata only: it is NOT an input to
    /// `proposal_sha256` (see `compute_context_rule_proposal_sha256`) and is
    /// NOT itself an authorization input, so it cannot be used to forge or
    /// influence what gets authorized. It exists purely to help the
    /// operator visually identify their own key in the rendered signer
    /// table.
    pub is_proposer: bool,
}

impl RuleProposalSigner {
    /// Constructs a `Delegated` signer entry.
    #[must_use]
    pub fn delegated(address: String, is_proposer: bool) -> Self {
        Self {
            kind: RuleProposalSignerKind::Delegated,
            address: Some(address),
            verifier: None,
            pubkey_data: None,
            is_proposer,
        }
    }

    /// Constructs an `External` signer entry.
    #[must_use]
    pub fn external(verifier: String, pubkey_data: Vec<u8>, is_proposer: bool) -> Self {
        Self {
            kind: RuleProposalSignerKind::External,
            address: None,
            verifier: Some(verifier),
            pubkey_data: Some(pubkey_data),
            is_proposer,
        }
    }
}

/// One resolved policy entry in a [`ContextRuleProposalSnapshot`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RuleProposalPolicy {
    /// On-chain policy-contract C-strkey.
    pub policy_address: String,
    /// Base64 (URL-safe, no pad) XDR encoding of the policy's `ScVal` params.
    pub params_xdr_b64: String,
}

impl RuleProposalPolicy {
    /// Constructs a policy entry (the struct is `#[non_exhaustive]` so
    /// external crates cannot use struct-expression syntax).
    #[must_use]
    pub fn new(policy_address: String, params_xdr_b64: String) -> Self {
        Self {
            policy_address,
            params_xdr_b64,
        }
    }
}

/// A [`RuleProposalPolicy`] whose `params_xdr_b64` was recognized as the OZ
/// `SpendingLimitAccountParams` shape and decoded to typed values, for
/// display on an approval surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedSpendingLimitParams {
    /// The configured spending limit, in stroops.
    pub limit_stroops: i128,
    /// The rolling-window length, in ledgers.
    pub period_ledgers: u32,
}

/// Best-effort, structural recognition of a policy's `params_xdr_b64` as the
/// OZ `SpendingLimitAccountParams { spending_limit: i128, period_ledgers: u32 }`
/// install-parameter shape, for rendering "typed params where recognized" on
/// every approval surface (CLI, loopback UI, remote UI — Package D, GH issue
/// #8, Leg 3).
///
/// Recognition is purely STRUCTURAL (an exact two-entry `ScVal::Map` keyed by
/// the `period_ledgers`/`spending_limit` Symbols, in that order, with the
/// expected `U32`/`I128` value types) — not by comparing `policy_address`
/// against a network's registered spending-limit policy. This lets every
/// approval surface render typed params without depending on
/// `stellar-agent-smart-account` (whose `VerifierRegistry` a network lookup
/// would require) or making network I/O from a render path. A non-matching
/// shape (any other policy contract's params, or a mangled blob) returns
/// `None`, and the caller falls back to raw `policy_address` +
/// `params_xdr_b64` display — this function never affects whether the
/// proposal renders, only how richly.
///
/// The encoding this recognizes is built by
/// `stellar-agent-smart-account::spending_limit_policy::build_spending_limit_install_param`;
/// the two are independent, symmetric implementations (this crate cannot
/// depend on `stellar-agent-smart-account`) — if the OZ install-parameter
/// shape ever changes, both must be updated together.
#[must_use]
pub fn try_decode_spending_limit_params(
    params_xdr_b64: &str,
) -> Option<DecodedSpendingLimitParams> {
    use base64::Engine as _;
    use stellar_xdr::{Int128Parts, ReadXdr, ScSymbol, ScVal};

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(params_xdr_b64)
        .ok()?;
    let limits = stellar_agent_xdr_limits::untrusted_decode_limits(bytes.len());
    let scval = ScVal::from_xdr(&bytes, limits).ok()?;

    let ScVal::Map(Some(map)) = scval else {
        return None;
    };
    if map.0.len() != 2 {
        return None;
    }

    let period_sym = ScSymbol::try_from("period_ledgers").ok()?;
    let limit_sym = ScSymbol::try_from("spending_limit").ok()?;

    // Canonical ScMap key order (byte-lexicographic over Symbol names):
    // "period_ledgers" ('p') precedes "spending_limit" ('s').
    let period_entry = &map.0[0];
    let limit_entry = &map.0[1];

    if period_entry.key != ScVal::Symbol(period_sym) {
        return None;
    }
    let ScVal::U32(period_ledgers) = period_entry.val else {
        return None;
    };

    if limit_entry.key != ScVal::Symbol(limit_sym) {
        return None;
    }
    let ScVal::I128(Int128Parts { hi, lo }) = limit_entry.val else {
        return None;
    };
    let limit_stroops = (i128::from(hi) << 64) | i128::from(lo);

    Some(DecodedSpendingLimitParams {
        limit_stroops,
        period_ledgers,
    })
}

/// The fully-resolved `add_context_rule` definition an agent proposed.
///
/// `snapshot_version` is bumped on any additive-or-breaking field-shape
/// change; see [`CONTEXT_RULE_PROPOSAL_SNAPSHOT_VERSION`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ContextRuleProposalSnapshot {
    /// Snapshot schema version — see [`CONTEXT_RULE_PROPOSAL_SNAPSHOT_VERSION`].
    pub snapshot_version: u32,
    /// Context-type variant the rule applies to.
    pub context_type: RuleProposalContextType,
    /// Operator-facing rule name.
    pub name: String,
    /// Optional ledger sequence at which the rule expires. `None` means permanent.
    ///
    /// `#[serde(default)]`: TOML has no `null` literal, so an omitted key is
    /// the only on-disk representation of `None`.
    #[serde(default)]
    pub valid_until: Option<u32>,
    /// Resolved signer set, in on-chain order.
    pub signers: Vec<RuleProposalSigner>,
    /// Resolved policy set.
    ///
    /// `#[serde(default)]`: a rule with no policies is a legitimate,
    /// common shape; an omitted key on-disk means "no policies" rather
    /// than a structural error.
    #[serde(default)]
    pub policies: Vec<RuleProposalPolicy>,
    /// Context-rule IDs under which THIS install call is authorized.
    pub auth_rule_ids: Vec<u32>,
    /// Proposer-set override: mutable verifier/policy contracts do not block
    /// install. Rendered as a warning line on every approval surface (Leg 3).
    pub accept_mutable_verifier: bool,
    /// Proposer-set override: unknown-wasm-hash verifier/policy contracts do
    /// not block install. Rendered as a warning line on every approval
    /// surface (Leg 3).
    pub accept_unknown_verifier: bool,
}

impl ContextRuleProposalSnapshot {
    /// Constructs a new snapshot at [`CONTEXT_RULE_PROPOSAL_SNAPSHOT_VERSION`]
    /// (the struct is `#[non_exhaustive]` so external crates cannot use
    /// struct-expression syntax).
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible resolved-definition field set (mirrors ContextRuleDefinition::new \
                  in stellar-agent-smart-account)"
    )]
    pub fn new(
        context_type: RuleProposalContextType,
        name: String,
        valid_until: Option<u32>,
        signers: Vec<RuleProposalSigner>,
        policies: Vec<RuleProposalPolicy>,
        auth_rule_ids: Vec<u32>,
        accept_mutable_verifier: bool,
        accept_unknown_verifier: bool,
    ) -> Self {
        Self {
            snapshot_version: CONTEXT_RULE_PROPOSAL_SNAPSHOT_VERSION,
            context_type,
            name,
            valid_until,
            signers,
            policies,
            auth_rule_ids,
            accept_mutable_verifier,
            accept_unknown_verifier,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Validates a full canonical strkey shape: 56 characters, the given prefix
/// letter, base32 `[A-Z2-7]` body.
fn validate_strkey_shape(s: &str, prefix: char, field: &str) -> Result<(), String> {
    let valid = s.len() == 56
        && s.starts_with(prefix)
        && s[1..].chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7'));
    if valid {
        Ok(())
    } else {
        Err(format!(
            "{field} must be a valid {prefix}-strkey (56 chars, ^{prefix}[A-Z2-7]{{55}}$)"
        ))
    }
}

/// Validates that `s` is a G-strkey or a C-strkey (a `Delegated` signer's
/// `address` may be either — an ed25519-keyed delegate uses a G-strkey, a
/// contract-mediated signer uses a C-strkey).
fn validate_g_or_c_strkey(s: &str, field: &str) -> Result<(), String> {
    if validate_strkey_shape(s, 'G', field).is_ok() || validate_strkey_shape(s, 'C', field).is_ok()
    {
        Ok(())
    } else {
        Err(format!(
            "{field} must be a valid G-strkey or C-strkey (56 chars)"
        ))
    }
}

/// Runs all [`ContextRuleProposalSnapshot`] field invariants and returns the
/// first failing reason.
///
/// Invoked from both `PendingApproval::new_rule_proposal_pending` and the
/// custom `Deserialize<PendingApproval>` impl in `super::store` so tampered
/// on-disk entries are rejected at load time — same discipline as every
/// other `ApprovalKind` arm's `validate_*_invariants` helper.
pub(crate) fn validate_context_rule_proposal_snapshot(
    snapshot: &ContextRuleProposalSnapshot,
) -> Result<(), String> {
    if snapshot.snapshot_version != CONTEXT_RULE_PROPOSAL_SNAPSHOT_VERSION {
        return Err(format!(
            "snapshot_version must be {CONTEXT_RULE_PROPOSAL_SNAPSHOT_VERSION}, got {}",
            snapshot.snapshot_version
        ));
    }

    match &snapshot.context_type {
        RuleProposalContextType::Default => {}
        RuleProposalContextType::CallContract { contract } => {
            validate_strkey_shape(contract, 'C', "context_type.contract")?;
        }
        RuleProposalContextType::CreateContract { wasm_hash_hex } => {
            if wasm_hash_hex.len() != 64 || !wasm_hash_hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "context_type.wasm_hash_hex must be exactly 64 hex characters, got {} \
                     characters",
                    wasm_hash_hex.len()
                ));
            }
        }
    }

    if snapshot.name.is_empty() || snapshot.name.len() > RULE_PROPOSAL_MAX_NAME_BYTES {
        return Err(format!(
            "name must be 1-{RULE_PROPOSAL_MAX_NAME_BYTES} bytes, got {} bytes",
            snapshot.name.len()
        ));
    }

    if snapshot.signers.is_empty() {
        return Err(
            "signers must be non-empty (a rule with no signers can never authorize)".to_owned(),
        );
    }
    if snapshot.signers.len() > RULE_PROPOSAL_MAX_SIGNERS {
        return Err(format!(
            "signers must have at most {RULE_PROPOSAL_MAX_SIGNERS} entries (OZ MAX_SIGNERS), \
             got {}",
            snapshot.signers.len()
        ));
    }
    for (idx, signer) in snapshot.signers.iter().enumerate() {
        validate_rule_proposal_signer(signer)
            .map_err(|reason| format!("signers[{idx}]: {reason}"))?;
    }

    if snapshot.policies.len() > RULE_PROPOSAL_MAX_POLICIES {
        return Err(format!(
            "policies must have at most {RULE_PROPOSAL_MAX_POLICIES} entries (OZ MAX_POLICIES), \
             got {}",
            snapshot.policies.len()
        ));
    }
    for (idx, policy) in snapshot.policies.iter().enumerate() {
        validate_rule_proposal_policy(policy)
            .map_err(|reason| format!("policies[{idx}]: {reason}"))?;
    }

    if snapshot.auth_rule_ids.is_empty() {
        return Err(
            "auth_rule_ids must be non-empty (at least one context rule ID required)".to_owned(),
        );
    }
    if snapshot.auth_rule_ids.len() > RULE_PROPOSAL_MAX_AUTH_RULE_IDS {
        return Err(format!(
            "auth_rule_ids must have at most {RULE_PROPOSAL_MAX_AUTH_RULE_IDS} entries, got {}",
            snapshot.auth_rule_ids.len()
        ));
    }

    Ok(())
}

fn validate_rule_proposal_signer(signer: &RuleProposalSigner) -> Result<(), String> {
    match signer.kind {
        RuleProposalSignerKind::Delegated => {
            let Some(address) = &signer.address else {
                return Err("Delegated signer must carry `address`".to_owned());
            };
            validate_g_or_c_strkey(address, "address")?;
            if signer.verifier.is_some() || signer.pubkey_data.is_some() {
                return Err(
                    "Delegated signer must not carry `verifier` or `pubkey_data`".to_owned(),
                );
            }
        }
        RuleProposalSignerKind::External => {
            let Some(verifier) = &signer.verifier else {
                return Err("External signer must carry `verifier`".to_owned());
            };
            validate_strkey_shape(verifier, 'C', "verifier")?;
            let Some(pubkey_data) = &signer.pubkey_data else {
                return Err("External signer must carry `pubkey_data`".to_owned());
            };
            if pubkey_data.len() > RULE_PROPOSAL_MAX_EXTERNAL_KEY_BYTES {
                return Err(format!(
                    "pubkey_data must be at most {RULE_PROPOSAL_MAX_EXTERNAL_KEY_BYTES} bytes \
                     (OZ MAX_EXTERNAL_KEY_SIZE), got {}",
                    pubkey_data.len()
                ));
            }
            if signer.address.is_some() {
                return Err("External signer must not carry `address`".to_owned());
            }
        }
    }
    Ok(())
}

fn validate_rule_proposal_policy(policy: &RuleProposalPolicy) -> Result<(), String> {
    validate_strkey_shape(&policy.policy_address, 'C', "policy_address")?;
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&policy.params_xdr_b64)
        .map_err(|e| format!("params_xdr_b64 is not valid URL-safe base64: {e}"))?;
    if decoded.len() > RULE_PROPOSAL_MAX_POLICY_PARAMS_BYTES {
        return Err(format!(
            "params_xdr_b64 decodes to at most {RULE_PROPOSAL_MAX_POLICY_PARAMS_BYTES} bytes, \
             got {} bytes",
            decoded.len()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    const C_ADDR: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const G_ADDR: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn valid_snapshot() -> ContextRuleProposalSnapshot {
        ContextRuleProposalSnapshot::new(
            RuleProposalContextType::Default,
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(G_ADDR.to_owned(), true)],
            vec![],
            vec![0],
            false,
            false,
        )
    }

    #[test]
    fn valid_snapshot_passes() {
        validate_context_rule_proposal_snapshot(&valid_snapshot()).unwrap();
    }

    #[test]
    fn rejects_wrong_snapshot_version() {
        let mut s = valid_snapshot();
        s.snapshot_version = 999;
        let err = validate_context_rule_proposal_snapshot(&s).unwrap_err();
        assert!(err.contains("snapshot_version"));
    }

    #[test]
    fn rejects_empty_name() {
        let mut s = valid_snapshot();
        s.name = String::new();
        assert!(validate_context_rule_proposal_snapshot(&s).is_err());
    }

    #[test]
    fn rejects_oversized_name() {
        let mut s = valid_snapshot();
        s.name = "a".repeat(RULE_PROPOSAL_MAX_NAME_BYTES + 1);
        assert!(validate_context_rule_proposal_snapshot(&s).is_err());
    }

    #[test]
    fn rejects_empty_signers() {
        let mut s = valid_snapshot();
        s.signers = vec![];
        let err = validate_context_rule_proposal_snapshot(&s).unwrap_err();
        assert!(err.contains("signers"));
    }

    #[test]
    fn rejects_too_many_signers() {
        let mut s = valid_snapshot();
        s.signers = (0..=RULE_PROPOSAL_MAX_SIGNERS)
            .map(|_| RuleProposalSigner::delegated(G_ADDR.to_owned(), false))
            .collect();
        assert!(validate_context_rule_proposal_snapshot(&s).is_err());
    }

    #[test]
    fn rejects_delegated_signer_with_verifier_field() {
        let mut s = valid_snapshot();
        s.signers = vec![RuleProposalSigner {
            kind: RuleProposalSignerKind::Delegated,
            address: Some(G_ADDR.to_owned()),
            verifier: Some(C_ADDR.to_owned()),
            pubkey_data: None,
            is_proposer: false,
        }];
        assert!(validate_context_rule_proposal_snapshot(&s).is_err());
    }

    #[test]
    fn accepts_external_signer() {
        let mut s = valid_snapshot();
        s.signers = vec![RuleProposalSigner::external(
            C_ADDR.to_owned(),
            vec![0u8; 65],
            false,
        )];
        validate_context_rule_proposal_snapshot(&s).unwrap();
    }

    #[test]
    fn rejects_external_signer_oversized_pubkey() {
        let mut s = valid_snapshot();
        s.signers = vec![RuleProposalSigner::external(
            C_ADDR.to_owned(),
            vec![0u8; RULE_PROPOSAL_MAX_EXTERNAL_KEY_BYTES + 1],
            false,
        )];
        assert!(validate_context_rule_proposal_snapshot(&s).is_err());
    }

    #[test]
    fn rejects_external_signer_missing_verifier() {
        let mut s = valid_snapshot();
        s.signers = vec![RuleProposalSigner {
            kind: RuleProposalSignerKind::External,
            address: None,
            verifier: None,
            pubkey_data: Some(vec![0u8; 65]),
            is_proposer: false,
        }];
        assert!(validate_context_rule_proposal_snapshot(&s).is_err());
    }

    #[test]
    fn rejects_too_many_policies() {
        use base64::Engine as _;
        let params_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"params");
        let mut s = valid_snapshot();
        s.policies = (0..=RULE_PROPOSAL_MAX_POLICIES)
            .map(|_| RuleProposalPolicy::new(C_ADDR.to_owned(), params_b64.clone()))
            .collect();
        assert!(validate_context_rule_proposal_snapshot(&s).is_err());
    }

    #[test]
    fn rejects_policy_invalid_base64() {
        let mut s = valid_snapshot();
        s.policies = vec![RuleProposalPolicy::new(
            C_ADDR.to_owned(),
            "not valid base64!!".to_owned(),
        )];
        assert!(validate_context_rule_proposal_snapshot(&s).is_err());
    }

    #[test]
    fn rejects_policy_oversized_params() {
        use base64::Engine as _;
        let oversized = vec![0u8; RULE_PROPOSAL_MAX_POLICY_PARAMS_BYTES + 1];
        let params_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(oversized);
        let mut s = valid_snapshot();
        s.policies = vec![RuleProposalPolicy::new(C_ADDR.to_owned(), params_b64)];
        assert!(validate_context_rule_proposal_snapshot(&s).is_err());
    }

    #[test]
    fn rejects_empty_auth_rule_ids() {
        let mut s = valid_snapshot();
        s.auth_rule_ids = vec![];
        assert!(validate_context_rule_proposal_snapshot(&s).is_err());
    }

    #[test]
    fn rejects_too_many_auth_rule_ids() {
        let mut s = valid_snapshot();
        s.auth_rule_ids = (0..=RULE_PROPOSAL_MAX_AUTH_RULE_IDS as u32).collect();
        assert!(validate_context_rule_proposal_snapshot(&s).is_err());
    }

    #[test]
    fn context_type_serializes_with_type_tag() {
        let json = serde_json::to_value(RuleProposalContextType::CallContract {
            contract: C_ADDR.to_owned(),
        })
        .unwrap();
        assert_eq!(json["type"], "call_contract");
        assert_eq!(json["contract"], C_ADDR);
    }

    #[test]
    fn signer_kind_serializes_snake_case() {
        let json = serde_json::to_value(RuleProposalSignerKind::External).unwrap();
        assert_eq!(json, "external");
    }

    // ── try_decode_spending_limit_params ──────────────────────────────────────

    /// Builds the exact ScVal shape
    /// `stellar-agent-smart-account::spending_limit_policy::build_spending_limit_install_param`
    /// produces, base64-encodes it, and returns the encoded params.
    fn encode_spending_limit_params_xdr_b64(limit_stroops: i128, period_ledgers: u32) -> String {
        use base64::Engine as _;
        use stellar_xdr::{Int128Parts, ScMap, ScMapEntry, ScSymbol, ScVal, WriteXdr};

        #[allow(
            clippy::cast_possible_truncation,
            reason = "test mirrors the production i128 -> Int128Parts split"
        )]
        let limit_parts = Int128Parts {
            hi: (limit_stroops >> 64) as i64,
            lo: limit_stroops as u64,
        };
        let entries: Vec<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("period_ledgers").unwrap()),
                val: ScVal::U32(period_ledgers),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("spending_limit").unwrap()),
                val: ScVal::I128(limit_parts),
            },
        ];
        let scval = ScVal::Map(Some(ScMap(entries.try_into().unwrap())));
        let bytes = scval.to_xdr(stellar_xdr::Limits::none()).unwrap();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn try_decode_spending_limit_params_round_trips() {
        let params_b64 = encode_spending_limit_params_xdr_b64(10_000_000, 17_280);
        let decoded = try_decode_spending_limit_params(&params_b64).unwrap();
        assert_eq!(decoded.limit_stroops, 10_000_000);
        assert_eq!(decoded.period_ledgers, 17_280);
    }

    #[test]
    fn try_decode_spending_limit_params_round_trips_negative_and_large_i128() {
        let params_b64 = encode_spending_limit_params_xdr_b64(i128::MAX, u32::MAX);
        let decoded = try_decode_spending_limit_params(&params_b64).unwrap();
        assert_eq!(decoded.limit_stroops, i128::MAX);
        assert_eq!(decoded.period_ledgers, u32::MAX);
    }

    #[test]
    fn try_decode_spending_limit_params_rejects_non_matching_shape() {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not a spending limit");
        assert!(try_decode_spending_limit_params(&raw).is_none());
    }

    #[test]
    fn try_decode_spending_limit_params_rejects_wrong_key_order() {
        use base64::Engine as _;
        use stellar_xdr::{Int128Parts, ScMap, ScMapEntry, ScSymbol, ScVal, WriteXdr};

        // spending_limit BEFORE period_ledgers — violates canonical ScMap
        // key order, so this is not a valid on-chain encoding of the shape;
        // recognition must not accept it.
        let entries: Vec<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("spending_limit").unwrap()),
                val: ScVal::I128(Int128Parts { hi: 0, lo: 100 }),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("period_ledgers").unwrap()),
                val: ScVal::U32(17_280),
            },
        ];
        let scval = ScVal::Map(Some(ScMap(entries.try_into().unwrap())));
        let bytes = scval.to_xdr(stellar_xdr::Limits::none()).unwrap();
        let params_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        assert!(try_decode_spending_limit_params(&params_b64).is_none());
    }

    #[test]
    fn try_decode_spending_limit_params_rejects_invalid_base64() {
        assert!(try_decode_spending_limit_params("not valid base64!!").is_none());
    }
}
