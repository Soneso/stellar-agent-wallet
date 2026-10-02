//! Typed error tree for the smart-account orchestration layer.
//!
//! Wire-code vocabulary is a closed set; new wire codes require an explicit
//! `SaError` variant plus a `#[non_exhaustive]` mapper update at the
//! consumer site.
//!
//! # Strkey redaction discipline
//!
//! `SaError` fields that carry contract addresses (e.g.
//! `SaError::VerifierHashDrift::contract`) MUST receive already-redacted
//! strings (first-5-last-5 strkey form) at the call site.
//! The type itself does NOT redact; it trusts callers to apply
//! `stellar_agent_core::observability::redact_strkey_first5_last5` before
//! constructing a variant. This discipline is enforced at the call site and
//! audited by a CI gate.

use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::signers::types::{ThresholdAffectingOp, WasmHashSummary};
use stellar_agent_core::audit_log::schema::ContractKind;
use stellar_agent_core::audit_log::signer_set::SignerSetView;
pub use stellar_agent_core::error::AuthMismatchReason;
use stellar_agent_core::observability::RedactedStrkey;

/// Storage key or instance shape that prevents establishing immutability.
///
/// `Admin`, `Owner` and `ExternalRefExecutable` populate the
/// `admin_or_owner_key` field on [`SaError::VerifierMutable`] and
/// [`SaError::PolicyMutable`]: the operator can admit such a contract with
/// `--accept-mutable-verifier`. `UndecodableInstance`, `NonWasmExecutable`,
/// `ExternalRefUnresolved` and `ExecutableChanged` populate the `reason` field
/// on [`SaError::ContractInstanceUnsupported`], which no flag overrides.
///
/// # Wire format
///
/// Storage keys retain the canonical OZ names `"Admin"` and `"Owner"`.
/// Probe failures identify the instance shape that cannot establish immutability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AdminOrOwnerKey {
    /// `AccessControl::Admin` storage key (OZ access_control/storage.rs:26).
    Admin,
    /// `Ownable::Owner` storage key (OZ ownable/storage.rs).
    Owner,
    /// A returned entry cannot be decoded as contract-instance data, or
    /// cannot be matched to a requested key, whether its key does not decode
    /// or was not requested.
    UndecodableInstance,
    /// The instance executable is not Wasm.
    NonWasmExecutable,
    /// The instance executable is a CAP-85 external reference: the owner
    /// named in the instance decides, and can change at any time, which Wasm
    /// runs. The wallet pins the owner, the tag and the resolved hash and
    /// refuses to sign when any of them changes; the owner's authority makes
    /// the contract mutable in the same sense as an admin key.
    ExternalRefExecutable,
    /// The instance executable is a CAP-85 external reference but the owner's
    /// tag entry is not live (archived or expired), so there is no hash the
    /// wallet can pin.
    ExternalRefUnresolved,
    /// The executable observed while identifying the contract and the one
    /// observed by the mutability probe differ in kind or in external
    /// reference, so the install has no single observation to pin.
    ExecutableChanged,
}

impl AdminOrOwnerKey {
    /// Returns `true` for an instance whose code the wallet cannot pin.
    ///
    /// An existing instance that does not decode as a Wasm contract instance
    /// has no Wasm hash to pin, and the signing-time drift check compares
    /// against the zero hash, so a later code change stays invisible. An
    /// external reference with no live tag entry resolves to no hash. An
    /// executable that changed between the identification fetch and the
    /// mutability probe leaves no single observation to pin. Rule install
    /// refuses such a contract with no override.
    ///
    /// An external reference that resolves is pinnable: the pin records the
    /// owner, the tag and the resolved hash, and the drift check compares all
    /// three.
    #[must_use]
    pub fn is_unpinnable_instance(self) -> bool {
        match self {
            Self::UndecodableInstance
            | Self::NonWasmExecutable
            | Self::ExternalRefUnresolved
            | Self::ExecutableChanged => true,
            Self::Admin | Self::Owner | Self::ExternalRefExecutable => false,
        }
    }
}

impl std::fmt::Display for AdminOrOwnerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admin => f.write_str("Admin"),
            Self::Owner => f.write_str("Owner"),
            Self::UndecodableInstance => f.write_str("undecodable instance"),
            Self::NonWasmExecutable => f.write_str("non-Wasm executable"),
            Self::ExternalRefExecutable => f.write_str("owner-managed external reference"),
            Self::ExternalRefUnresolved => f.write_str("external reference with no live tag entry"),
            Self::ExecutableChanged => f.write_str("executable changed during install"),
        }
    }
}

/// Renders an optional rule id as a ` for rule <id>` Display suffix, or
/// nothing when absent.
fn rule_suffix(rule_id: &Option<u32>) -> String {
    rule_id.map_or_else(String::new, |rule_id| format!(" for rule {rule_id}"))
}

/// Renders an optional rule id as its number, or `none` when absent.
fn rule_id_or_none(rule_id: &Option<u32>) -> String {
    rule_id.map_or_else(|| "none".to_owned(), |rule_id| rule_id.to_string())
}

/// Renders [`SaError::InstallStateMismatch`]: the confirmed transaction, the
/// failed check and the two ways to settle the unbaselined rule. A rule whose
/// id could not be read is found with `rules list` first.
fn install_state_mismatch_message(
    rule_id: &Option<u32>,
    smart_account_redacted: &RedactedStrkey,
    tx_hash: &str,
) -> String {
    match rule_id {
        Some(rule_id) => format!(
            "install on {smart_account_redacted} confirmed in transaction {tx_hash} but the \
             observed rule {rule_id} does not match the authorized definition; the rule is not \
             baselined; inspect it with 'smart-account rules get --rule-id {rule_id}' and either \
             delete it with 'smart-account rules delete --rule-id {rule_id} --auth-rule-id 0' or \
             accept it with 'smart-account signers refresh --rule-id {rule_id}'"
        ),
        None => format!(
            "install on {smart_account_redacted} confirmed in transaction {tx_hash} but the new \
             rule's id could not be read; the rule is not baselined; find it with \
             'smart-account rules list', then either delete it with \
             'smart-account rules delete --rule-id N --auth-rule-id 0' or accept it with \
             'smart-account signers refresh --rule-id N'"
        ),
    }
}

/// Renders an optional transaction hash as an ` after transaction <hash>`
/// Display suffix, or nothing when absent.
fn after_transaction_suffix(tx_hash: &Option<String>) -> String {
    tx_hash
        .as_deref()
        .map_or_else(String::new, |hash| format!(" after transaction {hash}"))
}

/// Renders an optional bounded detail as a parenthesised Display suffix, or
/// nothing when absent.
fn paren_suffix(detail: &Option<String>) -> String {
    detail
        .as_deref()
        .map_or_else(String::new, |detail| format!(" ({detail})"))
}

/// Byte cap of [`SaError::PinCheckUnavailable`]'s `reason`.
pub const PIN_CHECK_REASON_MAX_BYTES: usize = 256;

/// Returns `msg` unchanged when it fits in `max_bytes` bytes, otherwise its
/// longest prefix ending on a character boundary followed by `"..."`, the
/// whole at most `max_bytes` bytes. A cap too small to hold the ellipsis
/// yields an empty string.
///
/// Bounds an error text that embeds an inner error's Display, which can
/// carry RPC-supplied bytes of any length.
pub(crate) fn truncate_to_byte_cap(msg: &str, max_bytes: usize) -> String {
    const ELLIPSIS: &str = "...";
    if msg.len() <= max_bytes {
        return msg.to_owned();
    }
    if max_bytes < ELLIPSIS.len() {
        return String::new();
    }
    let mut end = max_bytes - ELLIPSIS.len();
    while end > 0 && !msg.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{ELLIPSIS}", &msg[..end])
}

/// Stage of [`SaError::BaselineWriteFailed`] for a post-confirmation
/// observation that did not produce a validated state.
pub(crate) const BASELINE_WRITE_STAGE_OBSERVE: &str = "observe";

/// Stage of [`SaError::BaselineWriteFailed`] for a state row the audit log
/// refused.
pub(crate) const BASELINE_WRITE_STAGE_WRITE: &str = "write";

/// The closed set of [`SaError::BaselineWriteFailed`] stages.
pub const BASELINE_WRITE_STAGES: [&str; 2] =
    [BASELINE_WRITE_STAGE_OBSERVE, BASELINE_WRITE_STAGE_WRITE];

/// Byte cap of [`SaError::BaselineWriteFailed`]'s `reason`.
pub const BASELINE_WRITE_REASON_MAX_BYTES: usize = 256;

/// Builds the `reason` of a [`SaError::BaselineWriteFailed`] at stage
/// `observe` from the error that stopped the observation: its wire code, a
/// colon and its Display, capped at [`BASELINE_WRITE_REASON_MAX_BYTES`] bytes.
pub(crate) fn baseline_observe_reason(inner: &SaError) -> String {
    truncate_to_byte_cap(
        &format!("{}: {inner}", inner.wire_code()),
        BASELINE_WRITE_REASON_MAX_BYTES,
    )
}

/// Caps a writer error's Display for [`SaError::BaselineWriteFailed`] at
/// stage `write` to [`BASELINE_WRITE_REASON_MAX_BYTES`] bytes.
pub(crate) fn baseline_write_reason(detail: &str) -> String {
    truncate_to_byte_cap(detail, BASELINE_WRITE_REASON_MAX_BYTES)
}

/// Builds the `reason` of [`SaError::PinCheckUnavailable`] from the error
/// that stopped the check: its wire code, a colon and its Display, capped at
/// [`PIN_CHECK_REASON_MAX_BYTES`] bytes. The wire code comes first so the cap
/// never removes it.
pub(crate) fn pin_check_reason(inner: &SaError) -> String {
    truncate_to_byte_cap(
        &format!("{}: {inner}", inner.wire_code()),
        PIN_CHECK_REASON_MAX_BYTES,
    )
}

/// Typed post-submit verification failure kind for multicall bundles.
///
/// Stored inside [`SaError::MulticallFailed`] when
/// `phase == "post_submit_verification"` so audit routing does not parse the
/// human-readable `redacted_reason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PostSubmitVerificationKind {
    /// Router return is `ScVal::Vec(None)` (empty / null).
    XdrEmptyVec,
    /// Router return is not an `ScVal::Vec`; the actual discriminant is recorded.
    XdrUnexpectedShape {
        /// Observed `ScVal` discriminant name.
        observed_discriminant: &'static str,
    },
    /// Router returned a different number of inner results than submitted.
    InnerCountMismatch {
        /// Number of inner results observed on-chain.
        observed_inner_count: u32,
    },
}

/// Smart-account orchestration error.
///
/// # Wire codes
///
/// `SaError::wire_code()` returns the stable `&'static str` consumed by:
/// - the audit log `EventKind::SaRawInvocation { wire_code, ... }` payload,
/// - the CLI JSON envelope `{ "kind": "<wire_code>", ... }` shape,
/// - the MCP tool error envelope.
///
/// The wire-code set is closed. Adding a new code requires a new variant
/// here, a new arm in `wire_code()`, coordinated updates to CLI mappers,
/// MCP envelopes, and the audit-log `EventKind::SaRawInvocation` schema.
///
/// # Serialisation
///
/// `SaError` derives `serde::Serialize` using an adjacently-tagged
/// representation:
/// - tag field: `"wire_code"` — contains the stable `&'static str` wire code.
/// - content field: `"context"` — contains the variant's fields.
///
/// This produces envelopes of the shape
/// `{ "wire_code": "sa.rule_id_mismatch", "context": { ... } }`,
/// which the CLI mapper and MCP tool error handler consume directly.
///
/// # Examples
///
/// ```
/// use stellar_agent_smart_account::SaError;
///
/// let err = SaError::RuleIdMismatch { expected_len: 3, observed_len: 2 };
/// let json = serde_json::to_string(&err).expect("SaError must serialise");
/// assert!(json.contains("\"wire_code\""));
/// assert!(json.contains("sa.rule_id_mismatch"));
/// ```
#[derive(Debug, Error, serde::Serialize)]
#[serde(tag = "wire_code", content = "context")]
#[non_exhaustive]
// `SignerSetDiverged` carries two `SignerSetView` values (each holding a
// `Vec` of signers) plus the optional transaction hash and forensic `String`
// fields, which exceeds the 128-byte default threshold. Boxing the views would
// degrade call-site ergonomics for a type that is always heap-allocated as a
// `Box<dyn Error>` at log time anyway. The `SaError` enum is explicitly large
// by design: it carries the full signer-set diagnostic state so operators can
// reconstruct divergence context without querying the audit log separately.
#[allow(
    clippy::result_large_err,
    reason = "SignerSetDiverged carries two SignerSetView values + forensic strings by design; \
              variant size is intentional diagnostic richness"
)]
pub enum SaError {
    /// Removing or adding a signer would produce an unreachable threshold.
    ///
    /// Fired when the requested `requested_op` would leave the rule with fewer
    /// available signers than the current `current_threshold`, making future
    /// authorisation impossible.  The `safe_ordering_hint` field carries a
    /// human-readable description of the safe two-command sequence the operator
    /// should run instead (e.g. lower threshold first, then remove signer).
    ///
    /// # Redaction
    ///
    /// `smart_account_redacted` MUST be passed through
    /// `stellar_agent_core::observability::redact_strkey_first5_last5` at the
    /// call site.
    #[error(
        "threshold unreachable: rule {rule_id} has {current_signer_count} signers / \
         threshold {current_threshold}; requested op {requested_op:?} would brick; \
         {safe_ordering_hint}"
    )]
    #[serde(rename = "sa.threshold_unreachable")]
    ThresholdUnreachable {
        /// Context-rule identifier for which the op was refused.
        rule_id: u32,
        /// Current signer count on the rule.
        current_signer_count: u32,
        /// Current threshold that would become unreachable.
        current_threshold: u32,
        /// The operation that triggered the refusal.
        requested_op: ThresholdAffectingOp,
        /// Human-readable safe ordering hint for the two-command sequence.
        ///
        /// Example: `"run 'smart-account signers set-threshold --rule-id 1 --threshold 2' \
        /// first, then retry 'smart-account signers remove --rule-id 1 --signer 3'"`
        safe_ordering_hint: String,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        smart_account_redacted: RedactedStrkey,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// On-chain verifier wasm hash drifted from the rule-install pinned hash.
    ///
    /// Fired when `VerifiersManager::verify_pinned_verifier_against_chain` finds
    /// that the live two-RPC re-fetch of the deployed verifier contract disagrees
    /// with the hash pinned at rule-install time.  Signing is aborted; the
    /// operator must inspect the `deploy_address_redacted` contract on-chain and
    /// re-install the rule with the updated hash if the upgrade is legitimate.
    ///
    /// # Forensic spine
    ///
    /// `smart_account_redacted` and `deploy_address_redacted` MUST be passed
    /// through `stellar_agent_core::observability::redact_strkey_first5_last5`
    /// at the call site.  `pinned_hash_first8` and
    /// `observed_hash_first8` carry the first-8 hex chars (16 hex characters)
    /// of the respective 32-byte wasm hashes — sufficient for forensic
    /// correlation without leaking the full preimage.
    #[error(
        "verifier wasm-hash drift detected for rule {rule_id}: \
         pinned={pinned_hash_first8}, observed={observed_hash_first8}{}",
        paren_suffix(.observed_executable)
    )]
    #[serde(rename = "sa.verifier_hash_drift")]
    VerifierHashDrift {
        /// Context-rule identifier for which drift was detected.
        rule_id: u32,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        smart_account_redacted: RedactedStrkey,
        /// Redacted deploy address of the drifted verifier contract
        /// (first-5-last-5 C-strkey).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        deploy_address_redacted: RedactedStrkey,
        /// First-8 hex chars of the wasm hash pinned at rule-install time.
        pinned_hash_first8: String,
        /// First-8 hex chars of the effective hash observed on-chain via
        /// two-RPC re-fetch: the Wasm hash, the hash an external reference
        /// resolved to, or the zero hash for no code or an unresolved
        /// reference.
        observed_hash_first8: String,
        /// Bounded summary of the observed executable (`wasm`, `no code`, or
        /// `external reference owner <redacted> tag "<bounded>" resolved
        /// <first-8 or unset>`); appended to the Display when present.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        observed_executable: Option<String>,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// On-chain threshold-policy wasm hash drifted from the rule-install pinned hash.
    ///
    /// Parallel to [`SaError::VerifierHashDrift`] for the policy contract path.
    /// Fired when `VerifiersManager::verify_pinned_policy_against_chain` finds
    /// that the live two-RPC re-fetch of the deployed threshold-policy contract
    /// disagrees with the hash pinned at rule-install time.
    ///
    /// # Forensic spine
    ///
    /// `smart_account_redacted` and `deploy_address_redacted` MUST be passed
    /// through `stellar_agent_core::observability::redact_strkey_first5_last5`
    /// at the call site.
    #[error(
        "policy wasm-hash drift detected for rule {rule_id}: \
         pinned={pinned_hash_first8}, observed={observed_hash_first8}{}",
        paren_suffix(.observed_executable)
    )]
    #[serde(rename = "sa.policy_hash_drift")]
    PolicyHashDrift {
        /// Context-rule identifier for which drift was detected.
        rule_id: u32,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        smart_account_redacted: RedactedStrkey,
        /// Redacted deploy address of the drifted policy contract
        /// (first-5-last-5 C-strkey).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        deploy_address_redacted: RedactedStrkey,
        /// First-8 hex chars of the wasm hash pinned at rule-install time.
        pinned_hash_first8: String,
        /// First-8 hex chars of the effective hash observed on-chain via
        /// two-RPC re-fetch: the Wasm hash, the hash an external reference
        /// resolved to, or the zero hash for no code or an unresolved
        /// reference.
        observed_hash_first8: String,
        /// Bounded summary of the observed executable (`wasm`, `no code`, or
        /// `external reference owner <redacted> tag "<bounded>" resolved
        /// <first-8 or unset>`); appended to the Display when present.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        observed_executable: Option<String>,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// A rule has more than one distinct pinned wasm hash for the same verifier
    /// or policy kind, which is not yet supported (single hash only).
    ///
    /// Fired at signing time by `verify_pinned_verifier_against_chain` or
    /// `verify_pinned_policy_against_chain` when the audit-log pin record for
    /// `(rule_id, smart_account_redacted)` contains more than one entry in the
    /// `pinned_verifier_wasm_hashes_first8` or `pinned_policy_wasm_hashes_first8`
    /// list.  Multi-hash rules can arise if a future install path creates
    /// multiple distinct verifier or policy addresses in a single rule.
    ///
    /// # Why a typed variant instead of `DeploymentFailed { phase: "pin_check" }`
    ///
    /// `SaError::DeploymentFailed.phase` has a compile-time closed 7-value set
    /// (`build`, `simulate`, `upload`, `deploy`, `constructor`, `submit`,
    /// `post_deploy_verification`) enforced by `phase_string_constant_set_is_closed`.
    /// This failure occurs at **signing time**, not deployment time, so
    /// `DeploymentFailed` is the wrong semantic.  A typed variant gives structured
    /// forensic fields and keeps the `DeploymentFailed.phase` invariant intact.
    ///
    /// # Forensic spine
    ///
    /// `smart_account_redacted` MUST be passed through
    /// `stellar_agent_core::observability::redact_strkey_first5_last5`
    /// at the call site.
    #[error(
        "multiple pinned {kind} hashes unsupported for rule {rule_id} (found {count}); \
         multi-verifier substrate not yet supported"
    )]
    #[serde(rename = "sa.multiple_pinned_hashes_unsupported")]
    MultiplePinnedHashesUnsupported {
        /// Whether the excess pins are on the `"verifier"` or `"policy"` kind.
        kind: &'static str,
        /// Context-rule identifier for which the excess pins were detected.
        rule_id: u32,
        /// Number of pinned hashes found (always > 1 when this variant fires).
        count: usize,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        smart_account_redacted: RedactedStrkey,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// The rule's pin record holds policy pins while the rule has no policy on
    /// chain.
    ///
    /// Fired at signing time by the pinned-hash drift check, and reported as
    /// a `drift` policy status by `verify_rule_wasm_pins`. The pin record is
    /// the wallet's knowledge of the rule's shape: a policy removed outside
    /// the wallet changes what the rule authorizes, so the rule is refused
    /// before anything is signed. An `add_policy` authorized under rule 0,
    /// which replaces the stale pins with the added policy's pin, or a
    /// reinstall of the rule clears the state.
    ///
    /// # Forensic spine
    ///
    /// `smart_account_redacted` MUST be passed through
    /// `stellar_agent_core::observability::redact_strkey_first5_last5`
    /// at the call site.
    #[error(
        "pin record holds {pinned_count} policy pin(s) for rule {rule_id} but the rule has no \
         policy on chain"
    )]
    #[serde(rename = "sa.pinned_policy_absent")]
    PinnedPolicyAbsent {
        /// Context-rule identifier whose record holds the policy pins.
        rule_id: u32,
        /// Number of policy pins in the record (always > 0 when this variant
        /// fires).
        pinned_count: usize,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        smart_account_redacted: RedactedStrkey,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// The rule holds a live `External` signer while its pin record pins no
    /// verifier.
    ///
    /// Fired at signing time by the pinned-hash drift check, and reported as
    /// a `drift` verifier status by `verify_rule_wasm_pins`. The pin record is
    /// the wallet's knowledge of the rule's shape: a verifier the record does
    /// not pin would sign unchecked, so the rule is refused before anything is
    /// signed. The state arises from a signer-set state row written without
    /// its pin rows, or from a submission whose outcome was never resolved.
    /// It also arises from a verb interrupted between its confirmation and
    /// its pin rows, or from an `External` signer added through another
    /// client. `signers refresh`
    /// pins the live verifier and clears the state.
    ///
    /// # Forensic spine
    ///
    /// `smart_account_redacted` and `verifier_redacted` MUST be passed through
    /// `stellar_agent_core::observability::redact_strkey_first5_last5`
    /// at the call site.
    #[error(
        "rule {rule_id} holds the live External verifier {verifier_redacted} and its pin record \
         pins no verifier; run 'smart-account signers refresh --rule-id {rule_id}' to pin it"
    )]
    #[serde(rename = "sa.pinned_verifier_absent")]
    PinnedVerifierAbsent {
        /// Context-rule identifier whose record pins no verifier.
        rule_id: u32,
        /// Redacted address of the live verifier the record does not pin
        /// (first-5-last-5 C-strkey).
        verifier_redacted: RedactedStrkey,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        smart_account_redacted: RedactedStrkey,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// The pre-signing drift check of a rule-authorized submission could not
    /// run to a verdict.
    ///
    /// Fired by `submit::submit_signed_invoke` when fetching a rule's
    /// verifier and policy addresses, or checking one of them against the
    /// rule's pin record, fails for any reason other than a refusal the check
    /// reached: an RPC failure or divergence, an audit-log integrity error, a
    /// pin record with more than one verifier or policy pin
    /// (`sa.multiple_pinned_hashes_unsupported`), an unpinnable instance, or
    /// the check exceeding the pre-submit budget. Nothing is signed. The
    /// check's own refusals, [`SaError::VerifierHashDrift`],
    /// [`SaError::PolicyHashDrift`], [`SaError::PinnedPolicyAbsent`] and
    /// [`SaError::PinnedVerifierAbsent`], propagate as themselves and are
    /// never folded into this variant. The
    /// signer-set steps that run beside the pin check propagate as themselves
    /// too: [`SaError::SignerSetMissingBaseline`],
    /// [`SaError::SignerSetDiverged`], [`SaError::NetworkRpcDivergence`] and
    /// [`SaError::AuditLog`] from the baseline read or the comparison, and
    /// [`SaError::AuthEntryConstructionFailed`] at the lock and signer-set
    /// stages. The baseline read scans the audit log before the pin check
    /// does, so an audit-log integrity error under a rule other than rule 0
    /// is reported as [`SaError::AuditLog`]; under the migrating rule of a
    /// verifier migration, which has no baseline read, it is reported here.
    ///
    /// `reason` is the inner error's wire code, a colon and its Display,
    /// capped at [`PIN_CHECK_REASON_MAX_BYTES`] bytes.
    ///
    /// # Forensic spine
    ///
    /// `smart_account_redacted` MUST be passed through
    /// `stellar_agent_core::observability::redact_strkey_first5_last5`
    /// at the call site.
    #[error(
        "pin check unavailable for rule {rule_id} (smart_account={smart_account_redacted}): \
         {reason}; nothing was signed"
    )]
    #[serde(rename = "sa.pin_check_unavailable")]
    PinCheckUnavailable {
        /// Context-rule identifier whose check could not run.
        rule_id: u32,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        smart_account_redacted: RedactedStrkey,
        /// The inner error's wire code and bounded Display.
        reason: String,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// Verifier contract has an active admin key or an owner-managed
    /// executable (mutable).
    ///
    /// Fired at rule-install time when `managers::verifiers::detect_contract_mutability`
    /// reports an active `Admin` or `Owner` key on the verifier, or an
    /// external-reference executable whose owner can repoint it. Either can
    /// change the code the verifier runs. The wallet requires the operator's
    /// `--accept-mutable-verifier` acknowledgement. An instance that cannot be
    /// pinned is refused with [`SaError::ContractInstanceUnsupported`].
    ///
    /// # Forensic spine
    ///
    /// `smart_account_redacted` and `contract_address_redacted` MUST be passed
    /// through `stellar_agent_core::observability::redact_strkey_first5_last5`
    /// at the call site.  `admin_or_owner_key` is a typed storage key, not secret.
    #[error(
        "verifier contract is mutable{}: \
         contract={contract_address_redacted}, reason={admin_or_owner_key}{}; \
         --accept-mutable-verifier is required",
        rule_suffix(.rule_id),
        paren_suffix(.detail)
    )]
    #[serde(rename = "sa.verifier_mutable")]
    VerifierMutable {
        /// Context-rule identifier for which mutability was detected; absent
        /// when the refusal is raised before install, when the rule has no
        /// on-chain id yet.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule_id: Option<u32>,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        smart_account_redacted: RedactedStrkey,
        /// Redacted address of the mutable verifier contract
        /// (first-5-last-5 C-strkey).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        contract_address_redacted: RedactedStrkey,
        /// Why the contract is mutable: an active `Admin` or `Owner` storage
        /// key, or an `ExternalRefExecutable`.
        admin_or_owner_key: AdminOrOwnerKey,
        /// Bounded detail appended to the Display when present: the redacted
        /// holder of an admin or owner key, or `owner <redacted>, tag
        /// "<bounded>"` for an external reference.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// Policy contract has an active admin key or an owner-managed executable
    /// (mutable).
    ///
    /// Parallel to [`SaError::VerifierMutable`] for the threshold-policy contract
    /// path.  Fired at rule-install time when
    /// `managers::verifiers::detect_contract_mutability` reports a live `Admin`
    /// or `Owner` key in the policy contract's instance storage, or an
    /// external-reference executable.
    ///
    /// # Forensic spine
    ///
    /// `smart_account_redacted` and `contract_address_redacted` MUST be passed
    /// through `stellar_agent_core::observability::redact_strkey_first5_last5`
    /// at the call site.
    #[error(
        "policy contract is mutable{}: \
         contract={contract_address_redacted}, reason={admin_or_owner_key}{}; \
         --accept-mutable-verifier is required",
        rule_suffix(.rule_id),
        paren_suffix(.detail)
    )]
    #[serde(rename = "sa.policy_mutable")]
    PolicyMutable {
        /// Context-rule identifier for which mutability was detected; absent
        /// when the refusal is raised before install, when the rule has no
        /// on-chain id yet.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule_id: Option<u32>,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        smart_account_redacted: RedactedStrkey,
        /// Redacted address of the mutable policy contract
        /// (first-5-last-5 C-strkey).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        contract_address_redacted: RedactedStrkey,
        /// Why the contract is mutable: an active `Admin` or `Owner` storage
        /// key, or an `ExternalRefExecutable`.
        admin_or_owner_key: AdminOrOwnerKey,
        /// Bounded detail appended to the Display when present: the redacted
        /// holder of an admin or owner key, or `owner <redacted>, tag
        /// "<bounded>"` for an external reference.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// Verifier or policy contract instance has no code the wallet can pin.
    ///
    /// Fired at rule-install time when `managers::verifiers::detect_contract_mutability`
    /// finds an existing instance entry that does not decode as contract-instance
    /// data or whose executable is not Wasm, or a response entry that cannot be
    /// matched to a requested key, whether its key does not decode or was not
    /// requested (reason `UndecodableInstance`); when identification finds an
    /// external reference whose owner holds no live tag entry, and when the
    /// identification fetch and the mutability probe observe different
    /// executables; and whenever the verifier or policy executable fetch
    /// (install-time identification and signing-time drift) finds an
    /// undecodable instance. Such a contract has no hash the wallet can pin,
    /// so the signing-time drift check could not observe a change to its
    /// code. No flag overrides this refusal; `--accept-mutable-verifier`
    /// covers only [`SaError::VerifierMutable`] and [`SaError::PolicyMutable`],
    /// and `--accept-unknown-verifier` covers only an allowlist miss.
    ///
    /// # Forensic spine
    ///
    /// `smart_account_redacted` and `contract_address_redacted` MUST be passed
    /// through `stellar_agent_core::observability::redact_strkey_first5_last5`
    /// at the call site.  `contract_kind` and `reason` are typed closed sets,
    /// not secret.
    #[error(
        "{contract_kind} contract instance is unsupported{}: \
         contract={contract_address_redacted}, reason={reason}; \
         the wallet cannot pin this contract's code",
        rule_suffix(.rule_id)
    )]
    #[serde(rename = "sa.contract_instance_unsupported")]
    ContractInstanceUnsupported {
        /// Context-rule identifier for which the instance was probed; absent
        /// when the refusal is raised before install, when the rule has no
        /// on-chain id yet.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule_id: Option<u32>,
        /// Whether the contract is referenced as a verifier or a policy.
        contract_kind: ContractKind,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        smart_account_redacted: RedactedStrkey,
        /// Redacted address of the unsupported contract (first-5-last-5 C-strkey).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        contract_address_redacted: RedactedStrkey,
        /// Instance shape that prevents pinning (`UndecodableInstance`,
        /// `NonWasmExecutable`, `ExternalRefUnresolved` or
        /// `ExecutableChanged`).
        reason: AdminOrOwnerKey,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// Verifier wasm hash is not in the `VERIFIER_ALLOWLIST` allowlist (fail-closed).
    ///
    /// Fired when the wallet pins a verifier whose deployed wasm hash does not
    /// match any entry in the compile-time `VERIFIER_ALLOWLIST`
    /// (`crates/stellar-agent-smart-account/src/verifier_allowlist.rs`). That
    /// happens at rule install and at a signer add of a verifier the rule
    /// does not use yet. It also happens at a `signers refresh` that pins the
    /// live verifier of a pin record that pins none. The wallet refuses
    /// unless the operator passes `--accept-unknown-verifier`.
    ///
    /// # Forensic spine
    ///
    /// `smart_account_redacted` MUST be passed through
    /// `stellar_agent_core::observability::redact_strkey_first5_last5` at the
    /// call site.  `observed_hash_first8` carries the first-8
    /// hex chars of the observed wasm hash.
    ///
    /// # Forensic sentinels
    ///
    /// `observed_hash_first8 = "none"` signals that the ledger entry for the
    /// verifier contract is absent or not a deployed contract instance (i.e. the
    /// rule references a contract that was never deployed at that address).
    /// A hex value signals that the contract IS deployed but its wasm hash is
    /// not in the wallet's `VERIFIER_ALLOWLIST`.
    #[error(
        "verifier wasm hash not in VERIFIER_ALLOWLIST{}: \
         observed={observed_hash_first8}; --accept-unknown-verifier is required",
        rule_suffix(.rule_id)
    )]
    #[serde(rename = "sa.verifier_wasm_not_in_allowlist")]
    VerifierWasmNotInAllowlist {
        /// Context-rule identifier for which the allowlist check failed;
        /// absent when the refusal is raised before install, when the rule
        /// has no on-chain id yet.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule_id: Option<u32>,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        smart_account_redacted: RedactedStrkey,
        /// First-8 hex chars of the wasm hash observed on-chain but absent
        /// from the allowlist.
        observed_hash_first8: String,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// Policy wasm hash is not a policy Wasm the wallet vendors (fail closed).
    ///
    /// Parallel to [`SaError::VerifierWasmNotInAllowlist`] for policies.
    /// Fired when the policy contract's deployed wasm hash is not the hash of
    /// a vendored policy Wasm (simple-threshold, weighted-threshold,
    /// spending-limit): when a rule is installed with the policy, and when
    /// the policy is added to a rule that has a pin record. The wallet
    /// refuses unless the operator passes `--accept-unknown-verifier`.
    ///
    /// # Forensic spine
    ///
    /// `smart_account_redacted` MUST be passed through
    /// `stellar_agent_core::observability::redact_strkey_first5_last5` at the
    /// call site.
    ///
    /// # Forensic sentinels
    ///
    /// `observed_hash_first8 = "none"` signals that the ledger entry for the
    /// policy contract is absent or not a deployed contract instance.
    /// A hex value signals that the contract IS deployed but its wasm hash is
    /// not the hash of a vendored policy Wasm.
    #[error(
        "policy wasm hash is not a policy Wasm the wallet vendors{}: \
         observed={observed_hash_first8}; --accept-unknown-verifier is required",
        rule_suffix(.rule_id)
    )]
    #[serde(rename = "sa.policy_wasm_not_in_allowlist")]
    PolicyWasmNotInAllowlist {
        /// Context-rule identifier for which the allowlist check failed;
        /// absent when the refusal is raised before install, when the rule
        /// has no on-chain id yet.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule_id: Option<u32>,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        smart_account_redacted: RedactedStrkey,
        /// First-8 hex chars of the wasm hash observed on-chain but absent
        /// from the allowlist.
        observed_hash_first8: String,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// `context_rule_ids` length or ordering mismatch with `auth_contexts`.
    #[error("context rule-ID mismatch: expected len {expected_len}, observed len {observed_len}")]
    #[serde(rename = "sa.rule_id_mismatch")]
    RuleIdMismatch {
        /// Expected `context_rule_ids` vector length.
        expected_len: usize,
        /// Observed `context_rule_ids` vector length.
        observed_len: usize,
    },

    /// Pre-signing simulation context diverges from the to-be-submitted envelope.
    ///
    /// Signing aborts before signature bytes are produced when simulation context
    /// and the envelope-to-sign disagree. Guards against context-rule-ID binding
    /// tampering and Soroban auth-entry manipulation between simulate and sign.
    #[error("simulation divergence: {sub_code:?} ({redacted_reason})")]
    #[serde(rename = "simulation.divergence")]
    SimulationDivergence {
        /// Which simulation-divergence axis fired.
        sub_code: SimulationDivergenceSubCode,
        /// Operator-facing redacted reason; raw simulation bytes are never carried.
        redacted_reason: String,
    },

    /// The on-chain signer set differs from the state the wallet expected.
    ///
    /// Raised in three places, each after both RPC endpoints agreed on the
    /// on-chain set:
    ///
    /// - the comparison with the audit-log baseline that precedes a signer
    ///   mutation, a rule write verb or a passkey signature (`tx_hash`
    ///   absent; nothing was submitted);
    /// - `signers refresh` without `--accept-divergence` on a rule whose
    ///   chain state differs from its baseline, or whose version-1 baseline
    ///   cannot be compared with the chain (`tx_hash` absent);
    /// - after a signer mutation confirmed, when the confirmed set is not the
    ///   intended change (`tx_hash` names the confirmed transaction).
    ///
    /// `expected` and `observed` carry the full [`SignerSetView`] of each
    /// side, tagged with its snapshot version. Both sides have the same
    /// version, except for the `signers refresh` refusal of a version-1
    /// baseline that cannot be compared, which carries the version-1 baseline
    /// and the version-2 observation.
    ///
    /// # Display
    ///
    /// Each side renders as `v{version} count={n} threshold={t|none}`, which
    /// includes no signer identity. The message names the inspection command
    /// and the command that accepts the current chain state.
    #[error(
        "signer-set diverged on rule {rule_id} \
         (sa={smart_account_redacted}, req={request_id}): \
         expected {expected}, observed {observed}{}; \
         inspect with 'smart-account signers list --rule-id {rule_id}'; \
         accept the current chain state with \
         'smart-account signers refresh --rule-id {rule_id} --accept-divergence'",
        after_transaction_suffix(.tx_hash)
    )]
    #[serde(rename = "sa.signer_set_diverged")]
    SignerSetDiverged {
        /// Context-rule identifier for which divergence was detected.
        rule_id: u32,
        /// The expected signer-set state: the audit-log baseline, or the
        /// intended result of a confirmed signer mutation.
        expected: SignerSetView,
        /// The signer-set state both RPC endpoints observed.
        observed: SignerSetView,
        /// Hash of the confirmed transaction after which the set was
        /// observed; absent when nothing was submitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tx_hash: Option<String>,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        ///
        /// MUST be passed through
        /// `stellar_agent_core::observability::redact_strkey_first5_last5` at
        /// the call site.
        smart_account_redacted: RedactedStrkey,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// Per-rule `MAX_SIGNERS=15` / `MAX_POLICIES=5` caps hit.
    ///
    /// `kind` is one of `"signers"` or `"policies"`.
    /// Constants are defined on-chain in OZ `stellar-contracts` v0.7.2 (SHA `a9c4216`).
    #[error("context-rule caps exceeded: kind={kind} cur={cur} max={max}")]
    #[serde(rename = "sa.context_rule_caps_exceeded")]
    ContextRuleCapsExceeded {
        /// Capacity kind: `"signers"` or `"policies"`.
        kind: &'static str,
        /// Current count at the time of the cap check.
        cur: u32,
        /// Maximum allowed count per on-chain constant.
        max: u32,
    },

    /// Session-rule expiry (`valid_until` < current ledger).
    #[error("rule expired: rule_id={rule_id} valid_until={valid_until} current={current}")]
    #[serde(rename = "sa.rule_expired")]
    RuleExpired {
        /// Rule identifier that expired.
        rule_id: u32,
        /// Ledger sequence at which the rule was valid until.
        valid_until: u32,
        /// Current ledger sequence at the time of the check.
        current: u32,
    },

    /// Session-rule horizon exceeded at install or update.
    ///
    /// `valid_until - current_ledger` exceeds the per-profile maximum
    /// (`DEFAULT_SESSION_RULE_HORIZON_LEDGERS = 1000` by default;
    /// overridable via `session_rule_max_horizon_ledgers` in the profile,
    /// up to `UPPER_BOUND_HORIZON_LEDGERS = 10_000`).
    ///
    /// The OZ on-chain contract (SHA `a9c4216`)
    /// only rejects `valid_until < current_ledger`; the horizon cap is
    /// a wallet-side discipline. The surfaced
    /// [`stellar_agent_core::error::WalletError`] carries this via
    /// `WalletError::Validation(ValidationError::SessionRuleHorizonExceeded)`.
    ///
    /// `rule_id_or_pending = None` for the install path (rule not yet
    /// created); `Some(id)` for the update path.
    #[error(
        "session-rule horizon exceeded: requested {requested_horizon} ledgers \
         exceeds max {max_horizon}"
    )]
    #[serde(rename = "sa.horizon_exceeded")]
    HorizonExceeded {
        /// `None` on the install path; `Some(id)` on the update path.
        rule_id_or_pending: Option<u32>,
        /// Computed `valid_until - current_ledger` in ledgers.
        requested_horizon: u32,
        /// Effective maximum horizon in ledgers.
        max_horizon: u32,
    },

    /// Deployment failed at one of seven phases.
    ///
    /// The `phase` discriminator tells the operator whether the failure occurred
    /// pre-submission (build / simulate), at wasm-upload, at contract-creation,
    /// at constructor execution, at submission, or at post-deploy verification.
    ///
    /// # Phase set (closed — 7 values)
    ///
    /// - `"build"` — pre-simulate construction failures (RPC server / substrate
    ///   client / baselib `Account::new`).
    /// - `"simulate"` — `simulate_transaction_envelope` or transaction-assembly
    ///   failures, including the malformed-simulation-response panic-insulation pre-check.
    /// - `"upload"` — conditional `UploadContractWasm` pre-flight or assembly failures.
    /// - `"deploy"` — on-chain `CreateContractV2` result-code failures, surfaced
    ///   via `getTransaction` poll.
    /// - `"constructor"` — constructor-arg `ScVal` encoding or on-chain
    ///   `__constructor` execution failures.
    /// - `"submit"` — `send_transaction` / submission-layer failures, including the
    ///   `TxBadSeq` sequence-race case (Debug-formatted `TransactionResultCode`
    ///   variant in `SubmissionError::TxMalformed::detail`).
    /// - `"post_deploy_verification"` — `verify_post_deploy_wasm_hash` helper
    ///   outcomes (nine call sites: `get_ledger_entries`-rpc-failure,
    ///   panic-insulation, no-entry, non-`ContractData`, non-`ContractInstance`,
    ///   `StellarAsset`-not-Wasm, non-parseable-expected-hex, hash-mismatch,
    ///   c-strkey-decode).
    ///
    /// # Security
    ///
    /// `phase` is drawn from a compile-time closed set enforced by
    /// `deployment::ALL_EMITTED_PHASES` + the `phase_string_constant_set_is_closed`
    /// test in `error.rs::tests`. `redacted_reason` is pre-redacted at the call
    /// site (no raw account-id, contract-id, signature bytes, or hash prefix
    /// exceeding 8 hex chars, except for the documented `post_deploy_verification`
    /// mismatch case which carries first-8 hex prefixes of both observed and
    /// expected for operator triage).
    #[error("smart-account deployment failed at phase {phase}: {redacted_reason}")]
    #[serde(rename = "sa.deployment_failed")]
    DeploymentFailed {
        /// Deployment phase in which the failure occurred.
        ///
        /// Closed compile-time 7-value set — see variant-level rustdoc for the
        /// full enumeration. The field uses `&'static str` for zero-allocation
        /// construction on the error path (audit-log consumer allocates an owned
        /// `String` at write time).
        phase: &'static str,
        /// Pre-redacted human-readable failure reason.
        ///
        /// The caller is responsible for passing a reason free of secret material.
        /// Call sites use
        /// `stellar_agent_core::observability::redact_strkey_first5_last5` before
        /// placing any account-id or contract-id into this field.
        redacted_reason: String,
    },

    /// The submission was sent and its outcome is not known, or it was refused
    /// before the send because the wallet could not record it.
    ///
    /// Kept distinct from [`Self::DeploymentFailed`] with `phase = "submit"`,
    /// which reports a submission that definitively did not apply. This
    /// variant reports one that may have: the agent's next step is to
    /// reconcile `tx_hash` against the chain, never to rebuild and re-submit.
    ///
    /// # Field semantics
    ///
    /// `kind` selects the wire code, so the surface reports the same
    /// `submission.*` code the classic paths report for the same condition.
    /// `tx_hash` and `envelope_hash` are public identifiers carried in full so
    /// the caller can place them in structured response data; `message` is the
    /// redacted operator-facing text.
    #[error("{message}")]
    #[serde(rename = "sa.submission_unresolved")]
    SubmissionUnresolved {
        /// Which submission condition this is.
        kind: SubmissionUnresolvedKind,
        /// Redacted operator-facing message from the submission layer.
        message: String,
        /// Full transaction hash to reconcile against, when one exists.
        tx_hash: Option<String>,
        /// Full envelope hash naming the submission record, when one exists.
        envelope_hash: Option<String>,
        /// The submission timeout in seconds, on the one condition that has
        /// one: a confirmation that did not arrive in time.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u64>,
    },

    /// Operator policy refused the operation.
    ///
    /// Distinct from [`Self::DeploymentFailed`] with `phase = "submit"`, which
    /// reports a submission the network turned down: this one reports the
    /// wallet's own refusal, decided before anything was sent.
    ///
    /// `wire_code()` returns the criterion's own `policy.deny.*` code, so the
    /// surface reports the refusal exactly as the policy gate reports the same
    /// decision. The serde tag stays `sa.policy_denied`, as
    /// [`Self::SubmissionUnresolved`]'s stays `sa.submission_unresolved`.
    #[error("this operation was denied by operator policy ({})", reason.wire_code())]
    #[serde(rename = "sa.policy_denied")]
    PolicyDenied {
        /// The typed denial, as the governing criterion produced it.
        reason: Box<stellar_agent_core::policy::DenyReason>,
    },

    /// Local `ScAddress` XDR encoding failed while building an injective cache key.
    ///
    /// This is a local encoding failure, not a deployment or simulation failure.
    #[error("ScAddress encoding failed: {redacted_reason}")]
    #[serde(rename = "sa.scaddress_encoding_failed")]
    ScAddressEncodingFailed {
        /// Pre-redacted human-readable failure reason.
        redacted_reason: String,
    },

    /// The in-memory vendored WebAuthn-verifier WASM bytes do not hash to the pinned
    /// `WEBAUTHN_VERIFIER_WASM_SHA256` constant.
    ///
    /// Fires when the runtime SHA-256 re-check of `WEBAUTHN_VERIFIER_WASM`
    /// (performed at the start of `deploy_webauthn_verifier` before any submission)
    /// disagrees with `WEBAUTHN_VERIFIER_WASM_SHA256`.  It is the second line of
    /// defence after the `cargo test` compile-time gate
    /// (`tests::webauthn_verifier_wasm_sha256_matches_provenance` in `webauthn_verifier.rs`).
    ///
    /// # Security
    ///
    /// `expected` and `actual` carry 64-char lowercase hex strings of SHA-256 digests.
    /// SHA-256 digests are not secret; no key material is present.
    #[error(
        "WebAuthn-verifier WASM provenance mismatch: \
         expected sha256 {expected}, actual sha256 {actual}"
    )]
    #[serde(rename = "sa.webauthn_verifier_provenance_mismatch")]
    WebAuthnVerifierProvenanceMismatch {
        /// The SHA-256 hex string recorded in `WEBAUTHN_VERIFIER_WASM_SHA256`.
        expected: String,
        /// The SHA-256 hex string actually computed from the in-memory WASM bytes.
        actual: String,
    },

    /// The verifier registry already contains an entry for the given network with a
    /// DIFFERENT `wasm_sha256`.  Refuses to overwrite silently.
    ///
    /// Operator action: re-vendor the WASM (update `vendor/oz-webauthn-verifier/v0.7.2/`),
    /// update `WEBAUTHN_VERIFIER_WASM_SHA256`, and re-run `smart-account deploy-webauthn-verifier`
    /// so the registry entry and the pinned SHA-256 stay in sync.
    ///
    /// `network` is the Stellar network passphrase (not secret).
    /// `recorded` and `attempted` are 64-char lowercase hex SHA-256 digests (not secret).
    #[error(
        "WebAuthn-verifier sha256 drift for network {network}: \
         registry records {recorded}, attempted deployment uses {attempted}"
    )]
    #[serde(rename = "sa.webauthn_verifier_sha256_drift")]
    WebAuthnVerifierSha256Drift {
        /// The Stellar network passphrase for which the registry entry exists.
        network: String,
        /// The SHA-256 hex string already recorded in the registry for this network.
        recorded: String,
        /// The SHA-256 hex string of the WASM that the caller attempted to record.
        attempted: String,
    },

    /// The runtime SHA gate for the Ed25519-verifier WASM (performed at the start
    /// of `deploy_ed25519_verifier` before any submission) disagrees with
    /// `ED25519_VERIFIER_WASM_SHA256`.  Second line of defence after the
    /// `cargo test` compile-time gate
    /// (`tests::ed25519_verifier_wasm_sha256_matches_provenance` in
    /// `ed25519_verifier.rs`).
    ///
    /// # Security
    ///
    /// `expected` and `actual` carry 64-char lowercase hex strings of SHA-256
    /// digests.  SHA-256 digests are not secret; no key material is present.
    #[error(
        "Ed25519-verifier WASM provenance mismatch: \
         expected sha256 {expected}, actual sha256 {actual}"
    )]
    #[serde(rename = "sa.ed25519_verifier_provenance_mismatch")]
    Ed25519VerifierProvenanceMismatch {
        /// The SHA-256 hex string recorded in `ED25519_VERIFIER_WASM_SHA256`.
        expected: String,
        /// The SHA-256 hex string actually computed from the in-memory WASM bytes.
        actual: String,
    },

    /// The verifier registry already contains an Ed25519-verifier entry for the
    /// given network with a DIFFERENT `wasm_sha256`.  Refuses to overwrite
    /// silently.
    ///
    /// Operator action: re-vendor the WASM (update `vendor/oz-ed25519-verifier/v0.7.2/`),
    /// update `ED25519_VERIFIER_WASM_SHA256`, and re-run
    /// `smart-account deploy-ed25519-verifier` so the registry entry and the
    /// pinned SHA-256 stay in sync.
    ///
    /// `network` is the Stellar network passphrase (not secret).
    /// `recorded` and `attempted` are 64-char lowercase hex SHA-256 digests (not secret).
    #[error(
        "Ed25519-verifier sha256 drift for network {network}: \
         registry records {recorded}, attempted deployment uses {attempted}"
    )]
    #[serde(rename = "sa.ed25519_verifier_sha256_drift")]
    Ed25519VerifierSha256Drift {
        /// The Stellar network passphrase for which the registry entry exists.
        network: String,
        /// The SHA-256 hex string already recorded in the registry for this network.
        recorded: String,
        /// The SHA-256 hex string of the WASM that the caller attempted to record.
        attempted: String,
    },

    /// The runtime SHA gate for the spending-limit-policy WASM (performed at the
    /// start of `deploy_spending_limit_policy` before any submission) disagrees
    /// with `SPENDING_LIMIT_POLICY_WASM_SHA256`.  Second line of defence after
    /// the `cargo test` compile-time gate
    /// (`tests::spending_limit_policy_wasm_sha256_matches_provenance` in
    /// `spending_limit_policy.rs`).
    ///
    /// # Security
    ///
    /// `expected` and `actual` carry 64-char lowercase hex strings of SHA-256
    /// digests.  SHA-256 digests are not secret; no key material is present.
    #[error(
        "spending-limit-policy WASM provenance mismatch: \
         expected sha256 {expected}, actual sha256 {actual}"
    )]
    #[serde(rename = "sa.spending_limit_policy_provenance_mismatch")]
    SpendingLimitPolicyProvenanceMismatch {
        /// The SHA-256 hex string recorded in `SPENDING_LIMIT_POLICY_WASM_SHA256`.
        expected: String,
        /// The SHA-256 hex string actually computed from the in-memory WASM bytes.
        actual: String,
    },

    /// The registry already contains a spending-limit-policy entry for the given
    /// network with a DIFFERENT `wasm_sha256`.  Refuses to overwrite silently.
    ///
    /// Operator action: re-vendor the WASM (update `vendor/oz-spending-limit-policy/v0.7.2/`),
    /// update `SPENDING_LIMIT_POLICY_WASM_SHA256`, and re-run
    /// `smart-account deploy-spending-limit-policy` so the registry entry and the
    /// pinned SHA-256 stay in sync.
    ///
    /// `network` is the Stellar network passphrase (not secret).
    /// `recorded` and `attempted` are 64-char lowercase hex SHA-256 digests (not secret).
    #[error(
        "spending-limit-policy sha256 drift for network {network}: \
         registry records {recorded}, attempted deployment uses {attempted}"
    )]
    #[serde(rename = "sa.spending_limit_policy_sha256_drift")]
    SpendingLimitPolicySha256Drift {
        /// The Stellar network passphrase for which the registry entry exists.
        network: String,
        /// The SHA-256 hex string already recorded in the registry for this network.
        recorded: String,
        /// The SHA-256 hex string of the WASM that the caller attempted to record.
        attempted: String,
    },

    /// A typed spending-limit policy install was refused client-side before any
    /// simulate/submit.  Fires when the target rule's context type is not
    /// `CallContract` (OZ `install` rejects non-`CallContract` rules with
    /// `OnlyCallContractAllowed`, `spending_limit.rs:376-377`, SHA `a9c4216`),
    /// when `limit <= 0` or `period == 0` (OZ `InvalidLimitOrPeriod`,
    /// `spending_limit.rs:380-381`, SHA `a9c4216`), or when the wallet cannot
    /// build the install parameter.  Catching this off-chain avoids a wasted
    /// round-trip and names the constraint.
    ///
    /// `reason` is a human-readable description with no secret material.
    #[error("spending-limit policy install refused: {reason}")]
    #[serde(rename = "sa.spending_limit_install_refused")]
    SpendingLimitInstallRefused {
        /// Human-readable description of why the install was refused.
        reason: String,
    },

    /// No accessible spending-limit policy for `(rule_id, smart_account)`.
    ///
    /// Fired by two independent call sites:
    ///
    /// - `SignersManager::identify_spending_limit_policy` — the rule's
    ///   `policies` list is empty, or none of the attached policies' wasm-hash
    ///   matches `SPENDING_LIMIT_POLICY_WASM_SHA256` (client-side, before any
    ///   read of the policy's storage).
    /// - `SignersManager::get_spending_limit_data` — the identified policy
    ///   contract's on-chain view call panics `SpendingLimitError::SmartAccountNotInstalled`
    ///   (code 3220, `packages/accounts/src/policies/spending_limit.rs:124-127`,
    ///   SHA `a9c4216`), meaning `install` was never called for this
    ///   `(smart_account, rule_id)` pair on the per-network singleton policy
    ///   contract (defense in depth: the identification step can succeed on a
    ///   raw-attached policy address whose storage was never initialised).
    ///
    /// Both call sites surface the same wire code: from the operator's
    /// perspective, "no spending-limit policy usable for this rule" is a
    /// single actionable situation regardless of which layer detected it.
    ///
    /// `smart_account_redacted` MUST be pre-redacted (first-5-last-5 C-strkey)
    /// at the call site.
    #[error(
        "spending-limit policy not installed for rule {rule_id} (smart_account={smart_account_redacted}); \
         run 'smart-account rules add-policy --rule-id {rule_id} --kind spending-limit' to install one"
    )]
    #[serde(rename = "sa.spending_limit_not_installed")]
    SpendingLimitNotInstalled {
        /// Context-rule identifier for which no spending-limit policy was found.
        rule_id: u32,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        smart_account_redacted: RedactedStrkey,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// Spending-limit-policy identification found more than one attached
    /// policy matching `SPENDING_LIMIT_POLICY_WASM_SHA256`.
    ///
    /// Fired by `SignersManager::identify_spending_limit_policy` when the
    /// rule's `policies` list contains two or more addresses whose observed
    /// wasm-hash matches the single-entry allowlist — ambiguous, fail-closed.
    /// Unlike the zero-match case (`SaError::SpendingLimitNotInstalled`), a
    /// multi-match means a policy IS installed but the wallet cannot safely
    /// pick which attached address to operate on; the operator must remove
    /// the duplicate attachment via `smart-account rules remove-policy`.
    ///
    /// `observed_wasm_hashes_summary` carries `count` (number of policies
    /// observed on the rule) and `first_first8` (first 8 bytes of the first
    /// observed hash) for forensic correlation without leaking full hash
    /// preimages.
    ///
    /// `smart_account_redacted` MUST be pre-redacted (first-5-last-5 C-strkey)
    /// at the call site.
    #[error(
        "spending-limit-policy identification failed on rule {rule_id}: \
         observed {observed_wasm_hashes_summary}"
    )]
    #[serde(rename = "sa.spending_limit_policy_identification_failed")]
    SpendingLimitPolicyIdentificationFailed {
        /// Context-rule identifier for which identification failed.
        rule_id: u32,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        smart_account_redacted: RedactedStrkey,
        /// Summary of observed wasm-hashes for forensic correlation.
        observed_wasm_hashes_summary: WasmHashSummary,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// A typed simple-threshold policy install was refused client-side before
    /// any simulate/submit.  Fires when `threshold == 0` (OZ `install` panics
    /// `InvalidThreshold`, `simple_threshold.rs:97-101`, SHA `a9c4216`) or
    /// when the wallet cannot build the install parameter. It also fires when
    /// the install parameter of an install or an attach of the
    /// simple-threshold policy is not the one-entry `{ threshold: u32 }` map
    /// with a non-zero threshold.
    ///
    /// `reason` is a human-readable description with no secret material.
    #[error("simple-threshold policy install refused: {reason}")]
    #[serde(rename = "sa.simple_threshold_install_refused")]
    SimpleThresholdInstallRefused {
        /// Human-readable description of why the install was refused.
        reason: String,
    },

    /// A typed weighted-threshold policy install was refused client-side
    /// before any simulate/submit.  Fires when `signer_weights` is empty, any
    /// weight is `0`, `threshold == 0`, the checked sum of weights overflows
    /// `u32`, or `threshold` exceeds the checked sum of weights (OZ `install`
    /// panics `InvalidThreshold` (3211) or `MathOverflow` (3212),
    /// `weighted_threshold.rs:482-512`, SHA `a9c4216`), or when the wallet
    /// cannot build the install parameter.
    ///
    /// `reason` is a human-readable description with no secret material.
    #[error("weighted-threshold policy install refused: {reason}")]
    #[serde(rename = "sa.weighted_threshold_install_refused")]
    WeightedThresholdInstallRefused {
        /// Human-readable description of why the install was refused.
        reason: String,
    },

    /// The in-memory `THRESHOLD_POLICY_WASM` bytes do not match the
    /// compile-time `THRESHOLD_POLICY_WASM_HASHES[0]` pin at deploy time.
    ///
    /// Mirrors [`SaError::SpendingLimitPolicyProvenanceMismatch`] for the
    /// simple-threshold-policy deploy path
    /// (`smart-account deploy-policy --kind simple-threshold`).
    ///
    /// # Security
    ///
    /// `expected` and `actual` carry 64-char lowercase hex strings of SHA-256
    /// digests.  SHA-256 digests are not secret; no key material is present.
    #[error(
        "simple-threshold-policy WASM provenance mismatch: \
         expected sha256 {expected}, actual sha256 {actual}"
    )]
    #[serde(rename = "sa.simple_threshold_policy_provenance_mismatch")]
    SimpleThresholdPolicyProvenanceMismatch {
        /// The SHA-256 hex string recorded in `THRESHOLD_POLICY_WASM_HASHES[0]`.
        expected: String,
        /// The SHA-256 hex string actually computed from the in-memory WASM bytes.
        actual: String,
    },

    /// The registry already contains a simple-threshold-policy entry for the
    /// given network with a DIFFERENT `wasm_sha256`.  Refuses to overwrite
    /// silently.
    ///
    /// Mirrors [`SaError::SpendingLimitPolicySha256Drift`] for the
    /// simple-threshold-policy deploy path.
    ///
    /// `network` is the Stellar network passphrase (not secret).
    /// `recorded` and `attempted` are 64-char lowercase hex SHA-256 digests (not secret).
    #[error(
        "simple-threshold-policy sha256 drift for network {network}: \
         registry records {recorded}, attempted deployment uses {attempted}"
    )]
    #[serde(rename = "sa.simple_threshold_policy_sha256_drift")]
    SimpleThresholdPolicySha256Drift {
        /// The Stellar network passphrase for which the registry entry exists.
        network: String,
        /// The SHA-256 hex string already recorded in the registry for this network.
        recorded: String,
        /// The SHA-256 hex string of the WASM that the caller attempted to record.
        attempted: String,
    },

    /// The in-memory `WEIGHTED_THRESHOLD_POLICY_WASM` bytes do not match the
    /// compile-time `WEIGHTED_THRESHOLD_POLICY_WASM_SHA256` pin at deploy time.
    ///
    /// Mirrors [`SaError::SpendingLimitPolicyProvenanceMismatch`] for the
    /// weighted-threshold-policy deploy path
    /// (`smart-account deploy-policy --kind weighted-threshold`).
    ///
    /// # Security
    ///
    /// `expected` and `actual` carry 64-char lowercase hex strings of SHA-256
    /// digests.  SHA-256 digests are not secret; no key material is present.
    #[error(
        "weighted-threshold-policy WASM provenance mismatch: \
         expected sha256 {expected}, actual sha256 {actual}"
    )]
    #[serde(rename = "sa.weighted_threshold_policy_provenance_mismatch")]
    WeightedThresholdPolicyProvenanceMismatch {
        /// The SHA-256 hex string recorded in `WEIGHTED_THRESHOLD_POLICY_WASM_SHA256`.
        expected: String,
        /// The SHA-256 hex string actually computed from the in-memory WASM bytes.
        actual: String,
    },

    /// The registry already contains a weighted-threshold-policy entry for
    /// the given network with a DIFFERENT `wasm_sha256`.  Refuses to
    /// overwrite silently.
    ///
    /// Mirrors [`SaError::SpendingLimitPolicySha256Drift`] for the
    /// weighted-threshold-policy deploy path.
    ///
    /// `network` is the Stellar network passphrase (not secret).
    /// `recorded` and `attempted` are 64-char lowercase hex SHA-256 digests (not secret).
    #[error(
        "weighted-threshold-policy sha256 drift for network {network}: \
         registry records {recorded}, attempted deployment uses {attempted}"
    )]
    #[serde(rename = "sa.weighted_threshold_policy_sha256_drift")]
    WeightedThresholdPolicySha256Drift {
        /// The Stellar network passphrase for which the registry entry exists.
        network: String,
        /// The SHA-256 hex string already recorded in the registry for this network.
        recorded: String,
        /// The SHA-256 hex string of the WASM that the caller attempted to record.
        attempted: String,
    },

    /// No accessible weighted-threshold policy for `(rule_id, smart_account)`.
    ///
    /// Fired by two independent call sites:
    ///
    /// - `SignersManager::identify_weighted_threshold_policy` — the rule's
    ///   `policies` list is empty, or none of the attached policies' wasm-hash
    ///   matches `WEIGHTED_THRESHOLD_POLICY_WASM_HASHES` (client-side, before
    ///   any read of the policy's storage).
    /// - `SignersManager::get_weighted_threshold_data` — the identified
    ///   policy contract's on-chain view call panics
    ///   `WeightedThresholdError::SmartAccountNotInstalled` (code 3210,
    ///   `packages/accounts/src/policies/weighted_threshold.rs:180-196`, SHA
    ///   `a9c4216`), meaning `install` was never called for this
    ///   `(smart_account, rule_id)` pair.
    ///
    /// Mirrors [`SaError::SpendingLimitNotInstalled`].
    ///
    /// `smart_account_redacted` MUST be pre-redacted (first-5-last-5 C-strkey)
    /// at the call site.
    #[error(
        "weighted-threshold policy not installed for rule {rule_id} (smart_account={smart_account_redacted}); \
         run 'smart-account deploy-policy --kind weighted-threshold' then \
         'smart-account rules add-policy --rule-id {rule_id} --kind weighted-threshold' to install one"
    )]
    #[serde(rename = "sa.weighted_threshold_not_installed")]
    WeightedThresholdNotInstalled {
        /// Context-rule identifier for which no weighted-threshold policy was found.
        rule_id: u32,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        smart_account_redacted: RedactedStrkey,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// Weighted-threshold-policy identification found more than one attached
    /// policy matching `WEIGHTED_THRESHOLD_POLICY_WASM_HASHES`.
    ///
    /// Fired by `SignersManager::identify_weighted_threshold_policy` when the
    /// rule's `policies` list contains two or more addresses whose observed
    /// wasm-hash matches the single-entry allowlist — ambiguous, fail-closed.
    /// Mirrors [`SaError::SpendingLimitPolicyIdentificationFailed`].
    ///
    /// `smart_account_redacted` MUST be pre-redacted (first-5-last-5 C-strkey)
    /// at the call site.
    #[error(
        "weighted-threshold-policy identification failed on rule {rule_id}: \
         observed {observed_wasm_hashes_summary}"
    )]
    #[serde(rename = "sa.weighted_threshold_policy_identification_failed")]
    WeightedThresholdPolicyIdentificationFailed {
        /// Context-rule identifier for which identification failed.
        rule_id: u32,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        smart_account_redacted: RedactedStrkey,
        /// Summary of observed wasm-hashes for forensic correlation.
        observed_wasm_hashes_summary: WasmHashSummary,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// A batch signer-add was refused client-side before any simulate/submit.
    ///
    /// Fired by `SignersManager::batch_add_signers` when the batch is empty
    /// (nothing to add) — a public-API guard, not merely a CLI-layer
    /// convenience: the manager function itself refuses, regardless of caller.
    #[error("batch signer add refused: {reason}")]
    #[serde(rename = "sa.batch_signer_add_refused")]
    BatchSignerAddRefused {
        /// Human-readable description of why the batch was refused.
        reason: String,
    },

    /// File I/O error reading or writing `<canonical_data_root>/networks.toml`
    /// (or the `STELLAR_AGENT_NETWORKS_TOML` override path).
    ///
    /// `path` is the filesystem path that failed; `source` is the underlying
    /// `std::io::Error`.  Neither carries secret material.
    #[error("networks.toml I/O error at {path}: {source}")]
    #[serde(rename = "sa.networks_toml_io")]
    NetworksTomlIo {
        /// The `io::Error` from the failed filesystem operation.
        ///
        /// Serialised as a human-readable string because `io::Error` does not
        /// implement `serde::Serialize`.
        #[source]
        #[serde(serialize_with = "serialize_display")]
        source: io::Error,
        /// Filesystem path on which the operation failed.
        path: PathBuf,
    },

    /// The audit-log writer could not be opened for a smart-account manager
    /// (directory creation or [`AuditWriterRegistry`] failure).
    ///
    /// Distinct from [`SaError::NetworksTomlIo`]: the failing path here is the
    /// audit log (`audit/<profile>.jsonl`), never `networks.toml`.  Routing an
    /// audit-writer failure through `NetworksTomlIo` misattributes the failing
    /// subsystem in the operator-facing message (a Windows audit-log
    /// collision would otherwise surface as `"networks.toml I/O error at
    /// .../audit/<profile>.jsonl: ..."`).
    ///
    /// `path` is the audit-log path that failed; `detail` is the underlying
    /// `io::Error` or `WriterError` rendered as a string (neither carries
    /// secret material).
    ///
    /// [`AuditWriterRegistry`]: stellar_agent_core::audit_log::writer::AuditWriterRegistry
    #[error("audit writer setup error at {path}: {detail}")]
    #[serde(rename = "sa.audit_writer_io")]
    AuditWriterIo {
        /// Human-readable I/O diagnostic (`io::Error` or `WriterError`
        /// display text).
        detail: String,
        /// Filesystem path of the audit log that failed to open.
        path: PathBuf,
    },

    /// TOML parse error reading `<canonical_data_root>/networks.toml`
    /// (or the `STELLAR_AGENT_NETWORKS_TOML` override path).
    ///
    /// `path` is the filesystem path that failed to parse; `source` is the
    /// underlying `toml::de::Error`.  Neither carries secret material.
    #[error("networks.toml TOML parse error at {path}: {source}")]
    #[serde(rename = "sa.networks_toml_parse")]
    NetworksTomlParse {
        /// The `toml::de::Error` describing the parse failure.
        ///
        /// Serialised as a human-readable string because `toml::de::Error` does not
        /// implement `serde::Serialize`.
        #[source]
        #[serde(serialize_with = "serialize_display")]
        source: toml::de::Error,
        /// Filesystem path whose contents failed to parse.
        path: PathBuf,
    },

    /// Off-chain pre-verifier rejected the WebAuthn assertion before chain-submission.
    ///
    /// Reason taxonomy (sub-codes routed through `wire_code()`):
    ///
    /// - `wrong_type` — `clientDataJSON.type != "webauthn.get"` per W3C step 11
    ///   (on-chain `webauthn.rs:121-126`).
    /// - `challenge_mismatch` — `clientDataJSON.challenge != base64url(auth_digest[0..32])`
    ///   per W3C step 12 (on-chain `webauthn.rs:151-163`).
    /// - `wrong_rp_id` — wallet-only defence-in-depth RP-ID-hash check;
    ///   the on-chain OZ verifier omits this check (docstring at
    ///   `webauthn.rs:9-15`).
    /// - `auth_data_too_short` — authenticator_data is shorter than the
    ///   37-byte minimum needed to read RP-ID hash, flags, and counter.
    /// - `up_unset` — UP bit (`authenticator_data[32] & 0x01`) not set per
    ///   W3C step 16 (on-chain `webauthn.rs:184-189`).
    /// - `uv_unset` — UV bit (`authenticator_data[32] & 0x04`) not set per
    ///   W3C step 17 **unconditionally** (on-chain `webauthn.rs:217-221`, `:346`).
    /// - `be_bs_invalid` — backed-up-but-not-eligible flag combination per
    ///   OZ `webauthn.rs:222-261`, `:347` (BE=0 && BS=1 is invalid).
    /// - `signature_invalid` — secp256r1 verification failed per W3C steps
    ///   19+20 (on-chain `webauthn.rs:350-356`).
    /// - `malformed_client_data_json` — client_data_json is not parseable as
    ///   UTF-8 JSON with the required `type` and `challenge` fields.
    ///
    /// # Wire code
    ///
    /// `sa.webauthn_assertion_invalid::<sub_code>` per `SaError::wire_code()` routing.
    #[error("WebAuthn assertion invalid: {reason:?}")]
    #[serde(rename = "sa.webauthn_assertion_invalid")]
    WebAuthnAssertionInvalid {
        /// Sub-code identifying which verification step failed.
        reason: WebAuthnInvalidReason,
    },

    /// Wallet-internal XDR-encoding or container-conversion failure encountered
    /// while assembling the `SorobanAuthorizationEntry` pre-signature state.
    ///
    /// This variant carries wallet-side encoder failures that surface DURING
    /// auth-entry construction, before any signing-pipeline byte is produced.
    /// It is distinct from [`SaError::SimulationDivergence`], which attributes
    /// to sponsor / RPC tampering between simulation and the envelope-to-sign.
    /// Folding both classes onto a single wire-code prefix would pollute the
    /// operator-forensic attribution surface that the `simulation.divergence.*`
    /// sub-codes were carved out to provide.
    ///
    /// # Stage set (closed; `ALL_AUTH_ENTRY_STAGES`)
    ///
    /// - `"context_rule_ids"` — `encode_context_rule_ids(rule_ids).to_xdr(env)`
    ///   failure (the `EncodeContextRuleIdsError` arm). Surfaces from the
    ///   rule-IDs ScVal-vector encoding step in
    ///   `managers/auth_entry.rs::build_authorization_entry`.
    /// - `"auth_contexts_args"` — `Vec<ScVal>::try_into::<VecM<ScVal>>()`
    ///   conversion overflow when the args vector exceeds `VecM`'s `u32`
    ///   capacity. Surfaces from
    ///   `managers/auth_entry.rs::root_contract_invocation`.
    /// - `"signature_payload"` — `HashIdPreimage::SorobanAuthorization(...).to_xdr(Limits::none())`
    ///   encode failure. Surfaces from
    ///   `managers/auth_entry.rs::compute_signature_payload`.
    /// - `"auth_payload"` — AuthPayload assembly failure: signer `public_key()`
    ///   fetch, `sign_auth_digest` invocation, or one of the bounded
    ///   ScVal/ScMap/VecM/BytesM conversions used to build the on-chain canonical
    ///   AuthPayload shape. Surfaces from
    ///   `managers/auth_entry.rs::complete_authorization_entry` and from the
    ///   External-arm WebAuthn encoder at
    ///   `webauthn/sig_data.rs::encode_webauthn_sig_data_scval`
    ///   (bounded ScSymbol/BytesM/VecM conversions for the `WebAuthnSigData`
    ///   ScVal::Map).
    /// - `"strkey_parse"` — signer public-key strkey parse failure during
    ///   auth-entry construction. Surfaces from
    ///   `managers/signers.rs`.
    /// - `"quorum_external_contract_guard"` — external-contract quorum guard
    ///   failure (reject if any quorum entry is an unregistered external contract).
    ///   Surfaces from `submit.rs`.
    /// - `"quorum_signatures"` — quorum-signature collection failure (too few
    ///   registered signers could sign). Surfaces from `submit.rs`.
    /// - `"pin_check_required"`: a submission authorized by a rule other than
    ///   rule 0 carries no pinned-hash drift check. Surfaces from `submit.rs`
    ///   before any network I/O.
    /// - `"migrating_rule_mismatch"`: a drift check that exempts a migrating
    ///   rule's verifiers names authorizing rules other than exactly that
    ///   rule. Surfaces from `submit.rs` before any network I/O.
    /// - `"multicall_check_undeclared"`: a multicall check without
    ///   `"multicall"` in the declared required checks. Surfaces from
    ///   `submit.rs` before any network I/O.
    /// - `"rule_locks_without_pin_check"`: a held rule-lock context supplied
    ///   without a pinned-hash drift check. Surfaces from `submit.rs` before
    ///   any network I/O.
    /// - `"rule_lock"`: a rule's lock was not acquired before the pre-submit
    ///   deadline, or the manager's timeout for a verb that locks the rule
    ///   itself. Surfaces from `managers/signers.rs`.
    /// - `"rule_lock_missing"`: a submission names a rule the caller's
    ///   held-lock context holds no lock for. Surfaces from `submit.rs`
    ///   before any network I/O.
    /// - `"baseline_read"`: the pre-submit deadline elapsed during or right
    ///   after a rule's signer-set baseline read. Surfaces from `submit.rs`
    ///   and `managers/credentials.rs`.
    /// - `"signer_set_compare"`: the pre-submit deadline elapsed during a
    ///   rule's signer-set comparison. Surfaces from `submit.rs` and
    ///   `managers/credentials.rs`.
    ///
    /// # Security
    ///
    /// `stage` is drawn from a compile-time closed set enforced by
    /// `ALL_AUTH_ENTRY_STAGES` + the `auth_entry_stage_string_constant_set_is_closed`
    /// test in `error.rs::tests`. `redacted_reason` is pre-redacted at the call
    /// site — call sites pass operator-safe encoder error summaries, never raw
    /// simulation bytes, secret material, or unredacted strkeys.
    #[error("auth-entry construction failed at stage {stage}: {redacted_reason}")]
    #[serde(rename = "sa.auth_entry_construction_failed")]
    AuthEntryConstructionFailed {
        /// Construction stage at which the failure occurred.
        ///
        /// Closed compile-time set; see the variant-level rustdoc for the
        /// full enumeration. The field uses `&'static str` for zero-allocation
        /// construction on the error path; the audit-log consumer allocates an
        /// owned `String` at write time.
        stage: &'static str,
        /// Pre-redacted operator-facing failure reason.
        ///
        /// The caller is responsible for passing a reason free of secret material.
        redacted_reason: String,
    },

    /// The rule's `policies` list is empty; no threshold policy is installed.
    ///
    /// Fired by the signers manager's signer-set observation when a
    /// comparison with a version-1 baseline needs a threshold and the rule
    /// has no policy, and by `set_threshold` on a rule whose observation has
    /// no simple-threshold policy. The operator deploys and attaches a
    /// simple-threshold policy via `smart-account deploy-policy --kind
    /// simple-threshold` followed by `smart-account rules add-policy --kind
    /// simple-threshold` before the threshold can be changed.
    ///
    /// `smart_account_redacted` MUST be pre-redacted (first-5-last-5 C-strkey)
    /// at the call site.
    #[error(
        "threshold-policy not installed: rule {rule_id} has empty policies list; \
         run 'smart-account deploy-policy --kind simple-threshold' then \
         'smart-account rules add-policy --rule-id {rule_id} --kind simple-threshold' \
         to install one"
    )]
    #[serde(rename = "sa.threshold_policy_not_installed")]
    ThresholdPolicyNotInstalled {
        /// Context-rule identifier for which the policies list was empty.
        rule_id: u32,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        smart_account_redacted: RedactedStrkey,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// No audit-log baseline exists for the `(rule_id, smart_account)` pair.
    ///
    /// Fired when a signing attempt against a context rule finds no signer-set
    /// state row (a baseline, signer add, signer removal or threshold change
    /// row of either snapshot version) for this `(rule_id, smart_account)`
    /// pair. `smart-account signers list --rule-id <N>` records the baseline
    /// on first sight of the rule.
    ///
    /// Wire code: `sa.signer_set_missing_baseline`.
    ///
    /// `smart_account_redacted` MUST be pre-redacted (first-5-last-5 C-strkey)
    /// at the call site.
    #[error(
        "signer-set missing baseline: rule {rule_id} has no audit-log baseline; \
         run 'smart-account signers list --rule-id {rule_id}' to record one"
    )]
    #[serde(rename = "sa.signer_set_missing_baseline")]
    SignerSetMissingBaseline {
        /// Context-rule identifier for which no baseline exists.
        rule_id: u32,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        smart_account_redacted: RedactedStrkey,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// The rule's newest signer-set state row is version 1, and a signer
    /// mutation compares only against a version-2 state.
    ///
    /// Fired by `add_signer`, `remove_signer`, `set_threshold` and
    /// `batch_add_signers` before any RPC. `smart-account signers refresh
    /// --rule-id <N>` compares the chain with the version-1 baseline and, when
    /// they match, records a version-2 baseline; a changed or incomparable set
    /// needs `--accept-divergence` on that command.
    ///
    /// Wire code: `sa.signer_set_baseline_legacy`.
    ///
    /// `smart_account_redacted` MUST be pre-redacted (first-5-last-5 C-strkey)
    /// at the call site.
    #[error(
        "signer-set baseline of rule {rule_id} (sa={smart_account_redacted}, \
         req={request_id}) is version 1; \
         run 'smart-account signers refresh --rule-id {rule_id}' to compare the chain with it \
         and record a version 2 baseline"
    )]
    #[serde(rename = "sa.signer_set_baseline_legacy")]
    SignerSetBaselineLegacy {
        /// Context-rule identifier whose baseline is version 1.
        rule_id: u32,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        smart_account_redacted: RedactedStrkey,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// A signer-set state row was not written.
    ///
    /// `stage` is one of [`BASELINE_WRITE_STAGES`]:
    ///
    /// - `observe`: after a signer mutation confirmed, the resulting set could
    ///   not be observed and validated, for example because an endpoint stayed
    ///   behind the confirmation ledger for the whole recording budget, the
    ///   endpoints disagreed or a read failed;
    /// - `write`: the audit log refused the row (a write error or a poisoned
    ///   writer) after the observation was validated.
    ///
    /// `tx_hash` names the confirmed transaction for a signer mutation and is
    /// absent for the baseline writes of `signers list` and `signers refresh`,
    /// which submit nothing. The audit log keeps the state it held before;
    /// `smart-account signers refresh --rule-id <N> --accept-divergence`
    /// records the current chain state. `reason` is the cause's wire code, a
    /// colon and its Display, or the writer's error, capped at
    /// [`BASELINE_WRITE_REASON_MAX_BYTES`] bytes.
    ///
    /// Wire code: `sa.baseline_write_failed`.
    ///
    /// `smart_account_redacted` MUST be pre-redacted (first-5-last-5 C-strkey)
    /// at the call site.
    #[error(
        "signer-set state of rule {rule_id} (sa={smart_account_redacted}, req={request_id}) \
         was not recorded{}: {stage} failed: {reason}; \
         record the current chain state with \
         'smart-account signers refresh --rule-id {rule_id} --accept-divergence'",
        after_transaction_suffix(.tx_hash)
    )]
    #[serde(rename = "sa.baseline_write_failed")]
    BaselineWriteFailed {
        /// Context-rule identifier whose state row was not written.
        rule_id: u32,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        smart_account_redacted: RedactedStrkey,
        /// Hash of the confirmed transaction; absent when nothing was
        /// submitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tx_hash: Option<String>,
        /// The step that failed; one of [`BASELINE_WRITE_STAGES`].
        stage: &'static str,
        /// The bounded wire code and Display of the cause.
        reason: String,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// A rule install confirmed, and the installed rule was not recorded as
    /// its signer-set baseline.
    ///
    /// Either the observed rule does not match the authorized definition
    /// (`rule_id` names it), or the transaction's return value did not
    /// carry the new rule's id (`rule_id` is absent). The rule exists on
    /// chain without a baseline, so every verb that compares it refuses with
    /// `sa.signer_set_missing_baseline`. The Display names the transaction
    /// and the two ways to settle the rule: delete it under rule 0, or
    /// accept its observed state with `signers refresh`.
    ///
    /// Wire code: `sa.install_state_mismatch`.
    ///
    /// `smart_account_redacted` MUST be pre-redacted (first-5-last-5 C-strkey)
    /// at the call site.
    #[error("{}", install_state_mismatch_message(.rule_id, .smart_account_redacted, .tx_hash))]
    #[serde(rename = "sa.install_state_mismatch")]
    InstallStateMismatch {
        /// The installed rule's id; absent when the transaction's return
        /// value did not carry it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule_id: Option<u32>,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        smart_account_redacted: RedactedStrkey,
        /// Hash of the confirmed install transaction.
        tx_hash: String,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// Smart-account manager operation requires a configured signers manager.
    ///
    /// Fired before any RPC when the manager was constructed without
    /// `with_signers_manager`, by the operations that need two-RPC signer and
    /// contract consultation. These are rule install and its simulation, the
    /// policy verbs, the pin verification, and a submission authorized by a
    /// rule other than rule 0. `rule_id` is the rule the operation is scoped
    /// to, and is absent for an install, whose rule has no id yet.
    ///
    /// Wire code: `sa.signers_manager_not_configured`.
    #[error(
        "signers manager not configured for smart-account manager operation on rule_id={} (smart_account={smart_account_redacted})",
        rule_id_or_none(.rule_id)
    )]
    #[serde(rename = "sa.signers_manager_not_configured")]
    SignersManagerNotConfigured {
        /// Context-rule identifier the manager operation was scoped to;
        /// absent for an install.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule_id: Option<u32>,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        smart_account_redacted: RedactedStrkey,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// Threshold-policy identification failed: no or multiple allowlist matches.
    ///
    /// Fired by the signers manager's signer-set observation in three cases:
    ///
    /// - more than one attached policy matches `THRESHOLD_POLICY_WASM_HASHES`;
    /// - a comparison with a version-1 baseline needs a threshold, and the
    ///   rule's policies include none that matches;
    /// - `remove_signer` finds a rule whose policies include none that
    ///   matches. Another policy decides which signers suffice there, so the
    ///   removal cannot be checked;
    /// - attaching the simple-threshold policy to a rule that already has
    ///   one: the only change an attach records is from no threshold to one;
    /// - detaching a policy whose executable identified as the
    ///   simple-threshold policy before the rule's observation, when the
    ///   observation names another policy or none;
    /// - detaching from a rule with two or more matching policies, unless
    ///   exactly two match and the detached policy is one of them, which
    ///   leaves the rule with one.
    ///
    /// The refusal fails closed; the operator must ensure exactly one
    /// recognized policy hash is attached to the rule.
    ///
    /// `observed_wasm_hashes_summary` carries `count` (number of policies
    /// observed) and `first_first8` (first 8 bytes of the first observed hash,
    /// typed `Option<[u8; 8]>`) for forensic correlation without leaking full
    /// hash preimages.
    ///
    /// `smart_account_redacted` MUST be pre-redacted (first-5-last-5 C-strkey)
    /// at the call site.
    #[error(
        "threshold-policy identification failed on rule {rule_id}: \
         observed {observed_wasm_hashes_summary}"
    )]
    #[serde(rename = "sa.threshold_policy_identification_failed")]
    ThresholdPolicyIdentificationFailed {
        /// Context-rule identifier for which identification failed.
        rule_id: u32,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        smart_account_redacted: RedactedStrkey,
        /// Summary of observed wasm-hashes for forensic correlation.
        observed_wasm_hashes_summary: WasmHashSummary,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// `get_threshold` RPC call failed after the threshold-policy address was
    /// identified.
    ///
    /// Fired by the signers manager's signer-set observation when the
    /// `get_threshold(rule_id, smart_account)` simulation call returns an
    /// error or an unexpected `ScVal` type (fail closed: no threshold is
    /// inferred from the signer count).
    ///
    /// `source_kind` is a `&'static str` tag indicating which RPC endpoint
    /// produced the failure (`"primary"` or `"secondary"`).
    ///
    /// `smart_account_redacted` MUST be pre-redacted (first-5-last-5 C-strkey)
    /// at the call site.
    #[error(
        "threshold read failed on rule {rule_id} via {source_kind}: \
         request {request_id}"
    )]
    #[serde(rename = "sa.threshold_read_failed")]
    ThresholdReadFailed {
        /// Context-rule identifier for which the threshold read failed.
        rule_id: u32,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        smart_account_redacted: RedactedStrkey,
        /// Which RPC or decode step produced the failure.
        source_kind: &'static str,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// Primary and secondary RPC disagreed on the on-chain view before any signer-set check.
    ///
    /// Fired when the two-RPC consultation finds divergent `(signer_count, threshold)`
    /// or policy wasm-hash responses from the primary and secondary RPCs.  Aborts
    /// BEFORE the `sa.signer_set_diverged` check fires; the ordering invariant is:
    /// audit-log read → two-RPC check → audit-vs-chain comparison.
    ///
    /// `primary_view_digest_first8` and `secondary_view_digest_first8` carry a
    /// short per-RPC view fingerprint for operator triage.  The exact form is
    /// producer-specific: the storage-view divergence paths emit the first
    /// 8 hex chars of a SHA-256 digest of the raw view; the WASM-hash fetch
    /// path (`fetch_observed_executable`, delegating to
    /// `stellar_agent_network::fetch_contract_wasm_hash`) emits the first
    /// 8 hex chars of the observed WASM hash itself, the literal sentinel
    /// `<SAC>` / `<Absent>`, or a bounded external-reference summary (redacted
    /// owner, bounded tag, resolved first-8) when that side's view is not a
    /// plain-WASM contract.
    /// Consumers treat the field as an opaque comparison token; the two sides
    /// of one error are always produced the same way and are directly
    /// comparable to each other.
    ///
    /// `smart_account_redacted` MUST be pre-redacted (first-5-last-5 C-strkey)
    /// at the call site.
    #[error(
        "network RPC divergence{}: \
         primary view first8 {primary_view_digest_first8}, \
         secondary first8 {secondary_view_digest_first8}",
        rule_suffix(.rule_id)
    )]
    #[serde(rename = "network.rpc_divergence")]
    NetworkRpcDivergence {
        /// Context-rule identifier for which the divergence was detected;
        /// absent when the divergence is observed before a rule exists or on
        /// a query that is not scoped to a rule (timelock queries).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule_id: Option<u32>,
        /// Redacted smart-account contract address (first-5-last-5 C-strkey).
        smart_account_redacted: RedactedStrkey,
        /// First-8 hex chars of the primary RPC's view digest.
        primary_view_digest_first8: String,
        /// First-8 hex chars of the secondary RPC's view digest.
        secondary_view_digest_first8: String,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// Audit-log integrity check failed; propagated from the reader path.
    ///
    /// Wraps `stellar_agent_core::audit_log::AuditLogIntegrityError` — any
    /// integrity violation discovered while reading the audit log to derive the
    /// expected signer-set baseline aborts the divergence check before the
    /// on-chain comparison fires.
    ///
    /// Inner wire codes (`audit.chain_broken`, `audit.rotation_gap`, etc.) are
    /// loggable at `debug!` while the outer `sa.audit_log` code is info-visible,
    /// preserving operator-facing indistinguishability for non-integrity wire paths.
    ///
    /// `From<AuditLogIntegrityError>` routes directly into this variant.
    /// `From<SignerSetCanonicalBodyError>` routes into this variant via the
    /// inner `VerifyError::SignerSetCanonicalBody` arm (wire code
    /// `audit.signer_set_canonical_body`), not `ParseError { line: 0 }`.
    #[error("audit-log integrity check failed: {0}")]
    #[serde(rename = "sa.audit_log")]
    AuditLog(
        /// The underlying audit-log integrity error.
        ///
        /// Serialised via `serialize_display` because `VerifyError` does not
        /// implement `serde::Serialize` (it carries `io::Error` variants).
        #[source]
        #[serde(serialize_with = "serialize_display")]
        stellar_agent_core::audit_log::AuditLogIntegrityError,
    ),

    // ── Verifier diversification ──────────────────────────────────────────────
    /// Diversification guard refused signing because only a single verifier wasm
    /// hash is installed on a high-value rule.
    ///
    /// Fired when `sign_with_passkey_rule` detects that the rule references a
    /// single verifier wasm hash AND the rule's policy criteria declares a
    /// `value_threshold` exceeding the wallet-wide high-value threshold (default:
    /// USD-equivalent 10,000 as a compile-time stroop constant in
    /// `managers/policies.rs`).
    ///
    /// The `accept_single_verifier` opt-in of `sign_with_passkey_rule`
    /// (per-invocation) bypasses the refusal; that path emits
    /// `EventKind::SaVerifierDiversificationOverride` and returns `Ok(...)`
    /// instead.
    ///
    /// # Forensic spine
    ///
    /// `smart_account_redacted` MUST be passed through
    /// `stellar_agent_core::observability::redact_strkey_first5_last5` at the
    /// call site. `verifier_hash_first8` carries the first-8 hex chars of the
    /// single verifier wasm hash for operator correlation.
    /// `observed_value_threshold_stroops` is the stroop amount extracted from
    /// the active policy criteria by the value-threshold extractor.
    ///
    /// # Empty verifier_hash_first8
    ///
    /// `verifier_hash_first8 == ""` is reserved for the `no baseline row found`
    /// triage path. A populated value is the lower-hex first-8 hash projection
    /// for active verifier drift correlation. Both paths share this variant so
    /// operator tooling can group diversification failures by envelope type.
    #[error(
        "verifier diversification required for rule_id={rule_id} on high-value account \
         (smart_account={smart_account_redacted}, observed_value_threshold_stroops={})",
        if *observed_value_threshold_stroops
            == crate::managers::diversification::DiversificationCheck::SENTINEL_OBSERVED_VALUE_THRESHOLD_STROOPS
        {
            "undetermined".to_owned()
        } else {
            observed_value_threshold_stroops.to_string()
        }
    )]
    #[serde(rename = "sa.verifier_diversification_required")]
    VerifierDiversificationRequired {
        /// Context-rule identifier the diversification check fired on.
        rule_id: u32,
        /// Redacted smart-account C-strkey (first-5-last-5).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        smart_account_redacted: RedactedStrkey,
        /// First-8-hex of the single verifier wasm hash referenced by the rule.
        ///
        /// The first-8-hex projection is sufficient for forensic operator triage
        /// without leaking the full 32-byte hash preimage.
        ///
        /// Empty string indicates `no baseline row found` triage path; populated
        /// 16-char lower-hex first-8 indicates active drift. Both paths share
        /// the same envelope variant for operator-side forensic correlation.
        verifier_hash_first8: String,
        /// Observed value_threshold from policy criteria (stroops).
        ///
        /// The check is against stroops at the SaError layer; USD conversion
        /// happens at the policy-engine layer.
        observed_value_threshold_stroops: i64,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// Verifier wasm hash is allowlisted but flagged as Revoked.
    ///
    /// Fired at install-time and at `migrate-verifier --to <hash>` destination
    /// validation when the wasm hash is in `VERIFIER_ALLOWLIST` with
    /// `VerifierAuditStatus::Revoked { revoked_at, reason }`. Unconditional
    /// refusal — no opt-in flag overrides a Revoked entry. The operator response
    /// is `smart-account migrate-verifier` to a non-revoked hash, NOT bypass.
    ///
    /// # Forensic spine
    ///
    /// `smart_account_redacted` MUST be passed through
    /// `stellar_agent_core::observability::redact_strkey_first5_last5` at the
    /// call site. `verifier_hash_first8` is the first-8 hex chars of the revoked
    /// hash. `revoked_reason` is the string from
    /// `VerifierAuditStatus::Revoked { reason }` — owned because envelope
    /// serialisation is producer-side.
    #[error(
        "verifier wasm hash flagged as revoked for rule_id={rule_id}: \
         hash_first8={verifier_hash_first8}, reason='{revoked_reason}'"
    )]
    #[serde(rename = "sa.verifier_wasm_revoked")]
    VerifierWasmRevoked {
        /// Context-rule identifier for which the revoked check fired.
        rule_id: u32,
        /// Redacted smart-account C-strkey (first-5-last-5).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        smart_account_redacted: RedactedStrkey,
        /// First-8 hex chars of the revoked verifier wasm hash.
        verifier_hash_first8: String,
        /// Reason string from `VerifierAuditStatus::Revoked { reason }`.
        ///
        /// Owned (not `&'static str`) because envelope serialisation is
        /// producer-side; the allowlist `reason` field is `&'static str` but
        /// the error variant must own the data for `serde::Serialize`.
        revoked_reason: String,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// Verifier wasm hash flagged as Retired — 24-month rotation past Revoked.
    ///
    /// Fired at install-time and at migration-destination time. Unconditional
    /// refusal — Retired status retains the startup-advisory + install-time gate
    /// behaviour of Revoked. The long-form revocation reason text is absent from
    /// `VerifierAuditStatus::Retired`, so this variant carries only the
    /// audit-status class and hash projection.
    ///
    /// # Forensic spine
    ///
    /// `smart_account_redacted` MUST be passed through
    /// `stellar_agent_core::observability::redact_strkey_first5_last5` at the
    /// call site.
    #[error(
        "verifier wasm hash flagged as retired for rule_id={rule_id}: \
         hash_first8={verifier_hash_first8}"
    )]
    #[serde(rename = "sa.verifier_wasm_retired")]
    VerifierWasmRetired {
        /// Context-rule identifier for which the retired check fired.
        rule_id: u32,
        /// Redacted smart-account C-strkey (first-5-last-5).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        smart_account_redacted: RedactedStrkey,
        /// First-8 hex chars of the retired verifier wasm hash.
        verifier_hash_first8: String,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// `smart-account migrate-verifier` failed at a named phase.
    ///
    /// Fired by the migration planner and the submission path. The `phase` is a
    /// closed-set `&'static str` discriminator naming the failure stage.
    /// Production code constructs `phase` exclusively from the `MIGRATION_PHASES`
    /// constant set defined below.
    ///
    /// # Phase set (closed — 5 values)
    ///
    /// See `MIGRATION_PHASES` and the closed-set test
    /// `migration_phase_constant_set_is_closed` for the canonical enumeration.
    ///
    /// - `"preflight_destination_unknown"` — destination hash not in
    ///   `VERIFIER_ALLOWLIST`.
    /// - `"preflight_destination_mutable"` — destination contract is
    ///   upgradeable (mutability detected via `detect_contract_mutability`).
    /// - `"plan_build"` — rule-discovery or audit-log read failed during
    ///   `MigrationPlan::build`.
    /// - `"submit_simulate"` — on-chain simulation of the migration
    ///   `ExecutionEntryPoint::execute` call failed.
    /// - `"submit_send"` — on-chain submission of the migration transaction
    ///   failed after simulation succeeded.
    ///
    /// # Security
    ///
    /// `phase` is drawn from `MIGRATION_PHASES` + enforced by
    /// `migration_phase_constant_set_is_closed`. `detail` is pre-redacted at
    /// the call site (no raw strkeys, secret bytes, or hash preimages beyond
    /// 8 hex chars).
    #[error(
        "verifier migration failed at phase '{phase}' for smart_account={smart_account_redacted}: {detail}"
    )]
    #[serde(rename = "sa.verifier_migration_failed")]
    VerifierMigrationFailed {
        /// Closed-set phase discriminator.
        ///
        /// MUST be one of the 5 values in `MIGRATION_PHASES`. `&'static str`
        /// for zero-allocation construction on the error path; the audit-log
        /// consumer allocates an owned `String` at write time.
        phase: &'static str,
        /// Redacted smart-account C-strkey (first-5-last-5).
        ///
        /// MUST be redacted at the call site via
        /// `stellar_agent_core::observability::redact_strkey_first5_last5`.
        smart_account_redacted: RedactedStrkey,
        /// Pre-redacted human-readable failure detail.
        ///
        /// Opaque to consumers; used for operator log triage. Must not contain
        /// secret material or full strkeys. Per-rule callers must prefix the
        /// relevant `rule_id` in this string when applicable; `plan_build`
        /// can cover multiple rules and therefore has no single rule field.
        detail: String,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// `VERIFIER_ALLOWLIST` is empty at startup-advisory init.
    ///
    /// Defence-in-depth guard. The closed-set test
    /// `verifier_allowlist_has_at_least_one_audited_entry` asserts the invariant
    /// at compile-time (test time), but the startup-advisory check verifies at
    /// runtime so any pre-release artefact-substitution attack that delivers an
    /// empty allowlist binary fails closed rather than silently disabling the
    /// advisory.
    #[error("verifier allowlist is empty at startup-advisory init (invariant violation)")]
    #[serde(rename = "sa.verifier_allowlist_empty")]
    VerifierAllowlistEmpty {
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    // ── submit.rs free-function extraction ────────────────────────────────────
    /// A required option-typed check was `None` at submit time (fail-CLOSED
    /// enforcement).
    ///
    /// Fired by [`crate::submit::submit_signed_invoke`] when a caller declares a
    /// check name in `required_checks` but passes `None` for the corresponding
    /// `Option<*Check>` parameter. This is a programming-error fast-path: callers
    /// who forget to wire a check for a host function that demands it receive a
    /// typed refusal before any signing or submission takes place.
    ///
    /// Enforces fail-CLOSED behaviour: a caller who forgets to wire
    /// `multicall_check` for a multicall host-function gets a typed refusal.
    #[error(
        "required submit check '{required_check}' is None for host_function_kind '{host_function_kind}'"
    )]
    #[serde(rename = "sa.submit_check_missing")]
    SubmitCheckMissing {
        /// Name of the check that was required but absent.
        ///
        /// One of: `"multicall"`. `&'static str` for zero-allocation
        /// construction on the refusal path.
        required_check: &'static str,
        /// Caller-supplied description of the host-function kind that
        /// requires the check.
        ///
        /// Typically a short string like `"InvokeContract"` or
        /// `"multicall_bundle"`. `&'static str` for zero-allocation
        /// construction on the refusal path.
        host_function_kind: &'static str,
    },

    // ── Multicall host-side surface ───────────────────────────────────────────
    /// A multicall bundle submission failed at a specific phase.
    ///
    /// `phase` identifies where in the 8-step submit flow the failure occurred.
    /// The closed 7-value set is enforced by a repo gate script
    /// and the compile-time constant
    /// `stellar_agent_smart_account::multicall::MULTICALL_FAILED_PHASES`.
    ///
    /// # Phase values (closed 7-set)
    ///
    /// - `"build"` — bundle shape validation (Step 1).
    /// - `"policy_gate"` — policy engine `evaluate_bundle` denial (Step 2).
    /// - `"rpc_divergence"` — cross-RPC trust-anchor 4-way equality failure (Step 4).
    /// - `"simulate"` — Soroban RPC simulate error (Step 2 of submit sub-flow).
    /// - `"sign"` — auth-entry signing failure (Step 3 of submit sub-flow).
    /// - `"submit"` — on-chain submission failure (Step 4 of submit sub-flow).
    /// - `"post_submit_verification"` — return-value / inner-count mismatch after
    ///   successful submission (Step 8).
    ///
    /// # Strkey redaction
    ///
    /// `redacted_reason` MUST NOT contain full C-strkeys; apply
    /// `stellar_agent_core::observability::redact_strkey_first5_last5` at
    /// the call site.
    #[error("multicall bundle failed at phase '{phase}': {redacted_reason}")]
    #[serde(rename = "sa.multicall_failed")]
    MulticallFailed {
        /// Phase from the closed 7-value set.
        ///
        /// `&'static str` for zero-allocation construction on the hot
        /// denial path.
        phase: &'static str,
        /// Human-readable description of the failure with all strkeys
        /// pre-redacted (strkeys appear in first-5-last-5 form).
        redacted_reason: String,
        /// Typed post-submit verification sub-discriminator.
        ///
        /// `Some(_)` only when `phase == "post_submit_verification"`;
        /// otherwise `None`.
        post_submit_kind: Option<PostSubmitVerificationKind>,
    },

    /// The multicall router WASM SHA-256 drifted from the expected binary const.
    ///
    /// Fired at register-time, lookup-time, or cross-RPC trust-anchor check when
    /// the WASM hash does not byte-exactly equal
    /// `stellar_agent_smart_account::multicall::MULTICALL_WASM_SHA256`.
    ///
    /// # Fields
    ///
    /// - `attempted` — the SHA-256 that was presented (hex, 64 chars).
    /// - `expected` — the binary const from `MULTICALL_WASM_SHA256` (hex, 64 chars).
    /// - `existing` — the SHA-256 already in the registry, if any (hex or None).
    #[error(
        "multicall WASM SHA-256 drift: attempted {attempted} \
         does not match expected {expected}"
    )]
    #[serde(rename = "sa.multicall_sha256_drift")]
    MulticallSha256Drift {
        /// SHA-256 that was presented at register/lookup/check time (lowercase hex).
        attempted: String,
        /// The expected binary const from `MULTICALL_WASM_SHA256` (lowercase hex).
        expected: String,
        /// SHA-256 already stored in the registry for this network, if any.
        ///
        /// `None` when there was no pre-existing entry (register-time first conflict).
        /// `Some(sha)` when an existing entry had a different SHA (re-register drift).
        existing: Option<String>,
    },

    /// No multicall router is registered for the given network safename.
    ///
    /// Fired by `MulticallRegistry::lookup` when the networks.toml does not
    /// contain a `[multicall.<network_safename>]` section for the requested
    /// network passphrase, and by `submit_multicall_bundle` when the lookup
    /// returns `Ok(None)`.
    ///
    /// # Fix
    ///
    /// Run `smart-account register-multicall --network-passphrase <passphrase>
    /// --address <C-strkey>` to register the router address.
    #[error(
        "no multicall router registered for network '{network_safename}'; \
         run 'smart-account register-multicall' to register the router address"
    )]
    #[serde(rename = "sa.multicall_registry_entry_not_found")]
    MulticallRegistryEntryNotFound {
        /// Network safename (TOML key form of the network passphrase).
        ///
        /// Derived via `network_safename_from_passphrase(passphrase)` so
        /// operators can correlate with the `[multicall.<safename>]` TOML key.
        network_safename: String,
    },

    // ── Upgrade timelock surface ──────────────────────────────────────────────
    /// A `Timelock::schedule` call failed.
    ///
    /// `failure_reason` is a typed discriminator identifying the OZ-level cause.
    /// `redacted_reason` is a human-readable description with all strkeys
    /// pre-redacted.
    ///
    /// Wire-code is `sa.timelock_schedule_failed`. The `failure_reason` sub-code
    /// is surfaced in the JSON `context` envelope per the adjacently-tagged pattern
    /// (same as `SaError::MulticallFailed`).
    #[error("timelock schedule failed ({failure_reason}): {redacted_reason}")]
    #[serde(rename = "sa.timelock_schedule_failed")]
    TimelockScheduleFailed {
        /// Typed discriminator identifying the schedule failure sub-cause.
        failure_reason: TimelockScheduleFailureReason,
        /// Human-readable description with all strkeys pre-redacted.
        redacted_reason: String,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// A `Timelock::cancel` call failed.
    ///
    /// `failure_reason` is a typed discriminator identifying the OZ-level cause.
    /// `operation_id_redacted` carries the first-8-last-8 hex of the operation
    /// identifier that failed to cancel.
    ///
    /// Wire-code is `sa.timelock_cancel_failed`.
    #[error(
        "timelock cancel failed ({failure_reason}) for op {operation_id_redacted}: {redacted_reason}"
    )]
    #[serde(rename = "sa.timelock_cancel_failed")]
    TimelockCancelFailed {
        /// Typed discriminator identifying the cancel failure sub-cause.
        failure_reason: TimelockCancelFailureReason,
        /// Human-readable description with all strkeys pre-redacted.
        redacted_reason: String,
        /// Redacted operation identifier (first-8-last-8 hex).
        operation_id_redacted: String,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// A `Timelock::execute` call failed.
    ///
    /// `failure_reason` is a typed discriminator identifying the OZ-level cause.
    /// `operation_id_redacted` carries the first-8-last-8 hex of the operation
    /// identifier that failed to execute.
    ///
    /// Wire-code is `sa.timelock_execute_failed`.
    #[error(
        "timelock execute failed ({failure_reason}) for op {operation_id_redacted}: {redacted_reason}"
    )]
    #[serde(rename = "sa.timelock_execute_failed")]
    TimelockExecuteFailed {
        /// Typed discriminator identifying the execute failure sub-cause.
        failure_reason: TimelockExecuteFailureReason,
        /// Human-readable description with all strkeys pre-redacted.
        redacted_reason: String,
        /// Redacted operation identifier (first-8-last-8 hex).
        operation_id_redacted: String,
        /// Per-request correlation identifier (UUIDv4).
        request_id: String,
    },

    /// The `list_pending` read-only query failed before returning results.
    ///
    /// Distinct from [`SaError::DeploymentFailed`] (which covers the upload /
    /// deploy / constructor lifecycle) and from the three
    /// `Timelock*Failed` variants (which cover write-path submission failures).
    /// `list_pending` is a read-only audit-log + RPC query; using
    /// `DeploymentFailed { phase: "simulate" }` for this path would be a semantic
    /// misclassification that violates the closed-set invariant on `phase`.
    ///
    /// The fail-CLOSED contract: if the primary RPC cannot confirm the current
    /// ledger, all pending operations would have stale `Waiting` state instead
    /// of potentially `Ready` — silently degrading operator visibility.
    /// Returning this error forces the operator to address RPC reachability before
    /// acting on the list.
    ///
    /// Wire-code is `sa.timelock_list_pending_failed`.
    #[error("timelock list_pending failed: {redacted_reason}")]
    #[serde(rename = "sa.timelock_list_pending_failed")]
    TimelockListPendingFailed {
        /// Human-readable description with all URLs and paths pre-redacted.
        ///
        /// Callers MUST NOT embed full RPC URLs. Use host-only strings or
        /// static messages describing the failure class.
        redacted_reason: String,
    },

    // ── Simulation-audit mismatch ─────────────────────────────────────────────
    /// A Soroban auth-entry fingerprint check failed before submission.
    ///
    /// Fired by the internal tripwire in `submit_signed_invoke` when
    /// `verify_auth_entries_unchanged` detects that the auth-entry subtree of
    /// `final_signed_xdr` does not equal the fingerprint captured at end-of-signing.
    ///
    /// # Why a typed variant instead of `DeploymentFailed { phase: "submit" }`
    ///
    /// `SaError::DeploymentFailed.phase` has a compile-time closed 7-value set
    /// (`build`, `simulate`, `upload`, `deploy`, `constructor`, `submit`,
    /// `post_deploy_verification`) per `phase_string_constant_set_is_closed`.
    /// A simulation-audit mismatch is NOT a "deployment phase" failure — it is
    /// a signed-auth-entry integrity failure — so `DeploymentFailed` is the wrong
    /// semantic.  A typed variant mirrors the
    /// `MultiplePinnedHashesUnsupported` precedent.
    ///
    /// # Secret-material policy
    ///
    /// `reason` is an [`AuthMismatchReason`] closed-set enum — structurally
    /// incapable of carrying auth-entry bytes or signatures.  The only
    /// information surfaced is the diagnostic class of the mismatch.
    ///
    /// # Wire code
    ///
    /// `sa.auth_mismatch`
    #[error("simulation-audit auth-entry fingerprint mismatch: reason={}", reason.label())]
    #[serde(rename = "sa.auth_mismatch")]
    AuthMismatch {
        /// The closed-set reason for the mismatch.
        ///
        /// Carries no secret material — see [`AuthMismatchReason`] type docs.
        reason: AuthMismatchReason,
    },
}

/// Lifts an [`stellar_agent_core::audit_log::AuditLogIntegrityError`] into
/// [`SaError::AuditLog`].
///
/// Used by the signer-set baseline read when the audit-log reader returns an
/// integrity violation before the on-chain comparison runs.
impl From<stellar_agent_core::audit_log::AuditLogIntegrityError> for SaError {
    fn from(err: stellar_agent_core::audit_log::AuditLogIntegrityError) -> Self {
        Self::AuditLog(err)
    }
}

/// Lifts a [`stellar_agent_core::audit_log::signer_set::SignerSetCanonicalBodyError`]
/// into [`SaError::AuditLog`].
///
/// `SignerSetCanonicalBodyError` signals malformed stored data inside an audit
/// row (e.g. an `External` signer whose `verifier_contract` is not a valid
/// C-strkey, or length-parity failures in `ObservedSignerSet` fields). These
/// are routed through the `AuditLog` envelope so the wire chain stays
/// consistent with the audit-log integrity error taxonomy.
///
/// Routes via the dedicated `VerifyError::SignerSetCanonicalBody` variant
/// (wire code `audit.signer_set_canonical_body`), which is distinct from
/// `ParseError` (wire code `audit.parse_error`). This distinction matters for
/// forensic correlation: `ParseError` signals JSON decode failure at a known
/// log line; `SignerSetCanonicalBody` signals malformed canonical-body
/// computation with no associated log-line number.
impl From<stellar_agent_core::audit_log::signer_set::SignerSetCanonicalBodyError> for SaError {
    fn from(err: stellar_agent_core::audit_log::signer_set::SignerSetCanonicalBodyError) -> Self {
        // Route through the dedicated SignerSetCanonicalBody variant, not
        // ParseError { line: 0 }. The former carries the error by value and
        // produces wire code `audit.signer_set_canonical_body`; the latter's
        // line-0 sentinel made the two integrity classes indistinguishable in
        // wire logs (canonical-body computation failure vs JSON decode failure).
        Self::AuditLog(
            stellar_agent_core::audit_log::AuditLogIntegrityError::SignerSetCanonicalBody(err),
        )
    }
}

/// Canonical closed set for `SaError::VerifierMigrationFailed::phase`.
///
/// Every production emit site MUST use a string from this set. The test
/// `migration_phase_constant_set_is_closed` verifies the set has exactly 5
/// values, mirroring the `KNOWN_PHASES` / `phase_string_constant_set_is_closed`
/// discipline for `SaError::DeploymentFailed`.
///
/// `pub(crate)` so the migration planner and submission path
/// can import from the same source of truth; the test module also reads it.
///
pub(crate) const MIGRATION_PHASES: &[&str] = &[
    "preflight_destination_unknown",
    "preflight_destination_mutable",
    "plan_build",
    "submit_simulate",
    "submit_send",
];

/// Canonical inventory of every `SaError::AuthEntryConstructionFailed::stage`
/// literal emitted across the crate's production source files.
///
/// Maintained alongside the substance code as new emit sites land.
/// The `auth_entry_stage_string_constant_set_is_closed` test in
/// `error.rs::tests` scans all `src/**/*.rs` files at test time and asserts
/// that every `stage: "<literal>"` occurrence outside `#[cfg(test)]` blocks
/// is present in this set. Any undocumented stage value causes that test to
/// fail with the stray literal named in the assertion message.
///
/// `pub(crate)` + `#[cfg(test)]` — the only consumer is the in-crate
/// `#[cfg(test)]` module in `error.rs`.
#[cfg(test)]
pub(crate) const ALL_AUTH_ENTRY_STAGES: &[&str] = &[
    "context_rule_ids",
    "auth_contexts_args",
    "signature_payload",
    "auth_payload",
    "strkey_parse",
    "quorum_external_contract_guard",
    "quorum_signatures",
    "ed25519_rule_signer_quorum_guard",
    "rule_proposal_digest",
    "pin_check_required",
    "migrating_rule_mismatch",
    "multicall_check_undeclared",
    "rule_locks_without_pin_check",
    "rule_lock",
    "rule_lock_missing",
    "baseline_read",
    "signer_set_compare",
];

/// Which unresolved-submission condition [`SaError::SubmissionUnresolved`]
/// reports.
///
/// Each maps to the same `submission.*` wire code the classic submit paths
/// return for that condition, so an agent reads one vocabulary whatever verb
/// it called.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SubmissionUnresolvedKind {
    /// The transaction was accepted for inclusion and was not confirmed
    /// within the submission timeout. It may still apply.
    Timeout,
    /// A pending record already holds this transaction's source account and
    /// sequence, so the submission was refused before anything was sent.
    AlreadySubmitted,
    /// The endpoint reported a transaction hash that does not describe the
    /// transaction that was sent.
    HashMismatch,
    /// The submission could not be durably recorded, so nothing was sent.
    RecordUnavailable,
}

impl SubmissionUnresolvedKind {
    /// Returns the stable wire code for this condition.
    #[must_use]
    pub fn wire_code(self) -> &'static str {
        match self {
            Self::Timeout => "submission.tx_timeout",
            Self::AlreadySubmitted => "submission.tx_already_submitted",
            Self::HashMismatch => "submission.hash_mismatch",
            Self::RecordUnavailable => "submission.record_unavailable",
        }
    }
}

/// Pre-signing simulation-divergence attribution sub-code.
///
/// These values refine [`SaError::SimulationDivergence`] without changing the
/// serde wire tag, which remains the bare `simulation.divergence` envelope
/// kind. The public `SaError::wire_code()` accessor returns the sub-coded
/// operational string for audit-log and CLI/MCP routing.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SimulationDivergenceSubCode {
    /// `context_rule_ids` order or membership differs between simulation and
    /// the to-be-submitted envelope.
    ContextRuleIds,
    /// `auth_contexts` array (per-context invocation list) differs.
    AuthContexts,
    /// Network identity (passphrase + ledger-version + chain-id) differs.
    Network,
    /// Sequence-number range (`source_account.sequence` window) differs.
    Sequence,
    /// `tx.fee` and / or `tx.fee_bump_resource_fee` envelope fields differ.
    ///
    /// Scope is fee fields only. Network passphrase belongs
    /// to [`SimulationDivergenceSubCode::Network`].
    FeeEnvelope,
}

/// Sub-code for [`SaError::WebAuthnAssertionInvalid`] identifying which
/// pre-verification step failed.
///
/// Variant names use the natural failure mode for the violated check rather
/// than a single grammar convention: malformed client-data, field mismatch,
/// unset flag, invalid flag combination, and invalid signature are distinct
/// operator-facing diagnostics.
///
/// All variants are operator-safe: no secret material, no raw signature bytes,
/// no unredacted strkeys.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WebAuthnInvalidReason {
    /// `clientDataJSON.type != "webauthn.get"` (W3C step 11;
    /// on-chain `webauthn.rs:121-126`).
    WrongType,
    /// `clientDataJSON.challenge != base64url(auth_digest[0..32])`
    /// (W3C step 12; on-chain `webauthn.rs:151-163`).
    ChallengeMismatch,
    /// `authenticator_data[0..32] != rp_id_hash` — wallet-only defence-in-depth;
    /// the on-chain OZ verifier omits this check (docstring at `webauthn.rs:9-15`).
    WrongRpId,
    /// `authenticator_data` is shorter than the 37-byte W3C minimum needed
    /// to read RP-ID hash, flags, and the 4-byte counter. Split out from
    /// `WrongRpId` to disambiguate the length-precondition failure from
    /// RP-ID-hash mismatch.
    AuthDataTooShort,
    /// UP bit (`authenticator_data[32] & 0x01`) is not set (W3C step 16;
    /// on-chain `webauthn.rs:184-189`).
    UpUnset,
    /// UV bit (`authenticator_data[32] & 0x04`) is not set (W3C step 17
    /// **unconditionally**; on-chain `webauthn.rs:217-221`, `:346`).
    UvUnset,
    /// BE=0 && BS=1 is an invalid flag combination (on-chain
    /// `webauthn.rs:222-261`, `:347`).
    BeBsInvalid,
    /// secp256r1 verification failed (W3C steps 19+20; on-chain
    /// `webauthn.rs:350-356`).
    ///
    /// This intentionally collapses malformed public-key input, adapter errors,
    /// and genuine bad signatures into the single OZ-compatible rejection class
    /// to avoid exposing verifier-internal detail to callers.
    SignatureInvalid,
    /// `client_data_json` is not parseable as UTF-8 JSON with the required
    /// `type` and `challenge` string fields.
    MalformedClientDataJson,
}

impl std::fmt::Display for WebAuthnInvalidReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::WrongType => "wrong_type",
            Self::ChallengeMismatch => "challenge_mismatch",
            Self::WrongRpId => "wrong_rp_id",
            Self::AuthDataTooShort => "auth_data_too_short",
            Self::UpUnset => "up_unset",
            Self::UvUnset => "uv_unset",
            Self::BeBsInvalid => "be_bs_invalid",
            Self::SignatureInvalid => "signature_invalid",
            Self::MalformedClientDataJson => "malformed_client_data_json",
        };
        f.write_str(s)
    }
}

/// Lifts a [`WebAuthnInvalidReason`] sub-code into a
/// [`SaError::WebAuthnAssertionInvalid`].
///
/// Lets call sites in `webauthn::pre_verifier` use `.into()` and
/// `.ok_or(WebAuthnInvalidReason::X)?` rather than spelling the variant
/// constructor at every site. Wire format unchanged.
impl From<WebAuthnInvalidReason> for SaError {
    fn from(reason: WebAuthnInvalidReason) -> Self {
        Self::WebAuthnAssertionInvalid { reason }
    }
}

// ── Typed failure-reason discriminators ──────────────────────────────────────

/// Typed sub-cause for [`SaError::TimelockScheduleFailed`].
///
/// Each variant maps to a specific OZ `TimelockError` code or a wallet-side
/// detection path. The variant name is used in the adjacently-tagged JSON
/// `context` envelope; renaming is a breaking change to the wire contract.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TimelockScheduleFailureReason {
    /// The caller does not hold `PROPOSER_ROLE` on the timelock contract.
    ///
    /// Maps to OZ `TimelockError::Unauthorized` (code 4004).
    Unauthorized,
    /// An operation with the same ID is already scheduled on-chain.
    ///
    /// Maps to OZ `TimelockError::OperationAlreadyScheduled` (code 4000).
    OperationAlreadyScheduled,
    /// The requested delay is shorter than the on-chain minimum delay.
    ///
    /// Maps to OZ `TimelockError::InsufficientDelay` (code 4001).
    InsufficientDelay,
    /// The Soroban simulation step failed before reaching the OZ contract logic.
    SimulationFailed,
    /// The `OperationScheduled` OZ event was absent from the transaction meta.
    ///
    /// Fired when the event-emission integrity check detects no confirmation event.
    /// Currently best-effort: tx-meta event extraction is limited by RPC support.
    EventConfirmationMissing,
    /// An unrecognised error was returned by the OZ contract or RPC.
    Other,
    /// The shared `AuditWriter` mutex was poisoned during `SaTimelockScheduled` emission.
    ///
    /// If the audit log cannot be written, the schedule call is considered
    /// failed (fail-CLOSED). See `AuditWriterPoisonContext::TimelockScheduleEmission`.
    AuditWriterPoisoned,
}

impl std::fmt::Display for TimelockScheduleFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Unauthorized => "unauthorized",
            Self::OperationAlreadyScheduled => "operation_already_scheduled",
            Self::InsufficientDelay => "insufficient_delay",
            Self::SimulationFailed => "simulation_failed",
            Self::EventConfirmationMissing => "event_confirmation_missing",
            Self::Other => "other",
            Self::AuditWriterPoisoned => "audit_writer_poisoned",
        };
        f.write_str(s)
    }
}

/// Typed sub-cause for [`SaError::TimelockCancelFailed`].
///
/// Each variant maps to a specific OZ `TimelockError` code or a wallet-side
/// detection path.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TimelockCancelFailureReason {
    /// The caller does not hold `CANCELLER_ROLE` on the timelock contract.
    ///
    /// Maps to OZ `TimelockError::Unauthorized` (code 4004).
    Unauthorized,
    /// The operation state does not permit cancellation (e.g. already executed).
    ///
    /// Maps to OZ `TimelockError::InvalidOperationState` (code 4002).
    InvalidOperationState,
    /// The operation ID was not found in the on-chain scheduling state.
    ///
    /// Maps to OZ `TimelockError::OperationNotScheduled` (code 4006).
    /// Unreachable from the canonical `cancel_operation` path; retained for
    /// classifier completeness.
    OperationNotScheduled,
    /// The Soroban simulation step failed before reaching the OZ contract logic.
    SimulationFailed,
    /// The `OperationCancelled` OZ event was absent from the transaction meta.
    ///
    /// Fired when the event-emission integrity check detects no confirmation event.
    EventConfirmationMissing,
    /// An unrecognised error was returned by the OZ contract or RPC.
    Other,
    /// The shared `AuditWriter` mutex was poisoned during `SaTimelockCancelled` emission.
    ///
    /// If the audit log cannot be written, the cancel call is considered
    /// failed (fail-CLOSED). See `AuditWriterPoisonContext::TimelockCancelEmission`.
    AuditWriterPoisoned,
}

impl std::fmt::Display for TimelockCancelFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Unauthorized => "unauthorized",
            Self::InvalidOperationState => "invalid_operation_state",
            Self::OperationNotScheduled => "operation_not_scheduled",
            Self::SimulationFailed => "simulation_failed",
            Self::EventConfirmationMissing => "event_confirmation_missing",
            Self::Other => "other",
            Self::AuditWriterPoisoned => "audit_writer_poisoned",
        };
        f.write_str(s)
    }
}

/// Typed sub-cause for [`SaError::TimelockExecuteFailed`].
///
/// Each variant maps to a specific OZ `TimelockError` code or a wallet-side
/// detection path (including the ready-window race pre-check).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TimelockExecuteFailureReason {
    /// The operation state is not `Ready` at pre-check time.
    ///
    /// Fired by the cross-RPC pre-check BEFORE submitting the execute transaction.
    /// The fields carry context for operator triage.
    OperationNotReady {
        /// The observed operation state name (`"Waiting"` or `"Unset"`).
        observed_state: String,
        /// Current ledger sequence at the time of the pre-check query.
        ///
        /// `None` when the operation state was `Unset` (never scheduled or
        /// already cancelled) and no meaningful current-ledger value exists.
        /// `Some(n)` when the operation is `Waiting` and the current ledger
        /// was successfully fetched from the RPC at pre-check time.
        /// `Option<u32>` is used so `Unset` is distinguishable from a
        /// ledger-0 value without a sentinel.
        current_ledger: Option<u32>,
        /// Ledger at which the operation becomes `Ready`.
        ///
        /// `0` when the operation state was `Unset` (no ready ledger was ever set).
        ready_ledger: u32,
    },
    /// The operation state does not permit execution (e.g. already `Done`).
    ///
    /// Maps to OZ `TimelockError::InvalidOperationState` (code 4002).
    InvalidOperationState,
    /// A predecessor operation has not yet been executed.
    ///
    /// Maps to OZ `TimelockError::UnexecutedPredecessor` (code 4003).
    UnexecutedPredecessor,
    /// The Soroban simulation step failed before reaching the OZ contract logic.
    SimulationFailed,
    /// The `OperationExecuted` OZ event was absent from the transaction meta.
    ///
    /// Fired when the event-emission integrity check detects no confirmation event.
    EventConfirmationMissing,
    /// An unrecognised error was returned by the OZ contract or RPC.
    Other,
    /// The shared `AuditWriter` mutex was poisoned during `SaTimelockExecuted` emission.
    ///
    /// If the audit log cannot be written, the execute call is considered
    /// failed (fail-CLOSED). See `AuditWriterPoisonContext::TimelockExecuteEmission`.
    AuditWriterPoisoned,

    /// The caller-supplied `--operation-id` does not match the authoritative
    /// operation_id derived by simulating `hash_operation` on-chain.
    ///
    /// Indicates the user supplied an incorrect hex string for the operation they
    /// intend to execute. The execute call is aborted before submission.
    OperationIdMismatch {
        /// The operation_id supplied by the caller (64-char hex).
        user_supplied: String,
        /// The authoritative operation_id derived by simulating `hash_operation`
        /// on-chain (64-char hex).
        simulate_derived: String,
    },
}

impl std::fmt::Display for TimelockExecuteFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OperationNotReady {
                observed_state,
                current_ledger,
                ready_ledger,
            } => {
                let cl = current_ledger.map_or_else(|| "unknown".to_owned(), |n| n.to_string());
                write!(
                    f,
                    "operation_not_ready(state={observed_state},\
                     current={cl},ready={ready_ledger})"
                )
            }
            Self::InvalidOperationState => f.write_str("invalid_operation_state"),
            Self::UnexecutedPredecessor => f.write_str("unexecuted_predecessor"),
            Self::SimulationFailed => f.write_str("simulation_failed"),
            Self::EventConfirmationMissing => f.write_str("event_confirmation_missing"),
            Self::Other => f.write_str("other"),
            Self::AuditWriterPoisoned => f.write_str("audit_writer_poisoned"),
            Self::OperationIdMismatch {
                user_supplied,
                simulate_derived,
            } => write!(
                f,
                "operation_id_mismatch(user={user_supplied},derived={simulate_derived})"
            ),
        }
    }
}

/// Serialises a `Display`-implementing value as a string for `serde`.
///
/// Used for error fields whose types (e.g. `io::Error`, `toml::de::Error`) do
/// not implement `serde::Serialize`.  The resulting JSON context carries a
/// human-readable message string in place of a structured representation.
fn serialize_display<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: std::fmt::Display,
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}

impl SaError {
    /// Returns the stable wire-code identifier for this error variant.
    ///
    /// Wire codes are part of the public JSON envelope contract. Changes require
    /// coordinated updates across CLI mappers, MCP envelopes, and the audit-log
    /// `EventKind::SaRawInvocation` schema.
    ///
    /// Wire-code accessor returns `&'static str` (no allocation on the hot
    /// signing path) because the audit-log consumer at
    /// `EventKind::SaRawInvocation { wire_code: String, ... }` allocates the
    /// owned `String` at write time, not at error-construction time. The
    /// asymmetric type (borrowed at the source, owned at the sink) is
    /// intentional: serde-deserialise of the audit log requires owned data
    /// (lifetime-parametric variants are infectious through every `match`
    /// arm); the source-side `&'static str` keeps the `SaError` construction
    /// allocation-free.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_smart_account::SaError;
    ///
    /// let err = SaError::RuleIdMismatch { expected_len: 3, observed_len: 2 };
    /// assert_eq!(err.wire_code(), "sa.rule_id_mismatch");
    /// ```
    #[must_use]
    pub fn wire_code(&self) -> &'static str {
        match self {
            Self::ThresholdUnreachable { .. } => "sa.threshold_unreachable",
            Self::VerifierHashDrift { .. } => "sa.verifier_hash_drift",
            Self::PolicyHashDrift { .. } => "sa.policy_hash_drift",
            Self::MultiplePinnedHashesUnsupported { .. } => "sa.multiple_pinned_hashes_unsupported",
            Self::PinnedPolicyAbsent { .. } => "sa.pinned_policy_absent",
            Self::PinnedVerifierAbsent { .. } => "sa.pinned_verifier_absent",
            Self::PinCheckUnavailable { .. } => "sa.pin_check_unavailable",
            Self::VerifierMutable { .. } => "sa.verifier_mutable",
            Self::PolicyMutable { .. } => "sa.policy_mutable",
            Self::ContractInstanceUnsupported { .. } => "sa.contract_instance_unsupported",
            Self::VerifierWasmNotInAllowlist { .. } => "sa.verifier_wasm_not_in_allowlist",
            Self::PolicyWasmNotInAllowlist { .. } => "sa.policy_wasm_not_in_allowlist",
            Self::RuleIdMismatch { .. } => "sa.rule_id_mismatch",
            Self::SimulationDivergence { sub_code, .. } => match sub_code {
                SimulationDivergenceSubCode::ContextRuleIds => {
                    "simulation.divergence.context_rule_ids"
                }
                SimulationDivergenceSubCode::AuthContexts => "simulation.divergence.auth_contexts",
                SimulationDivergenceSubCode::Network => "simulation.divergence.network",
                SimulationDivergenceSubCode::Sequence => "simulation.divergence.sequence",
                SimulationDivergenceSubCode::FeeEnvelope => "simulation.divergence.fee_envelope",
            },
            Self::SignerSetDiverged { .. } => "sa.signer_set_diverged",
            Self::ContextRuleCapsExceeded { .. } => "sa.context_rule_caps_exceeded",
            Self::RuleExpired { .. } => "sa.rule_expired",
            Self::DeploymentFailed { .. } => "sa.deployment_failed",
            Self::SubmissionUnresolved { kind, .. } => kind.wire_code(),
            Self::PolicyDenied { reason } => reason.wire_code(),
            Self::ScAddressEncodingFailed { .. } => "sa.scaddress_encoding_failed",
            Self::AuthEntryConstructionFailed { .. } => "sa.auth_entry_construction_failed",
            Self::WebAuthnVerifierProvenanceMismatch { .. } => {
                "sa.webauthn_verifier_provenance_mismatch"
            }
            Self::WebAuthnVerifierSha256Drift { .. } => "sa.webauthn_verifier_sha256_drift",
            Self::Ed25519VerifierProvenanceMismatch { .. } => {
                "sa.ed25519_verifier_provenance_mismatch"
            }
            Self::Ed25519VerifierSha256Drift { .. } => "sa.ed25519_verifier_sha256_drift",
            Self::SpendingLimitPolicyProvenanceMismatch { .. } => {
                "sa.spending_limit_policy_provenance_mismatch"
            }
            Self::SpendingLimitPolicySha256Drift { .. } => "sa.spending_limit_policy_sha256_drift",
            Self::SpendingLimitInstallRefused { .. } => "sa.spending_limit_install_refused",
            Self::SpendingLimitNotInstalled { .. } => "sa.spending_limit_not_installed",
            Self::SpendingLimitPolicyIdentificationFailed { .. } => {
                "sa.spending_limit_policy_identification_failed"
            }
            Self::SimpleThresholdInstallRefused { .. } => "sa.simple_threshold_install_refused",
            Self::WeightedThresholdInstallRefused { .. } => "sa.weighted_threshold_install_refused",
            Self::SimpleThresholdPolicyProvenanceMismatch { .. } => {
                "sa.simple_threshold_policy_provenance_mismatch"
            }
            Self::SimpleThresholdPolicySha256Drift { .. } => {
                "sa.simple_threshold_policy_sha256_drift"
            }
            Self::WeightedThresholdPolicyProvenanceMismatch { .. } => {
                "sa.weighted_threshold_policy_provenance_mismatch"
            }
            Self::WeightedThresholdPolicySha256Drift { .. } => {
                "sa.weighted_threshold_policy_sha256_drift"
            }
            Self::WeightedThresholdNotInstalled { .. } => "sa.weighted_threshold_not_installed",
            Self::WeightedThresholdPolicyIdentificationFailed { .. } => {
                "sa.weighted_threshold_policy_identification_failed"
            }
            Self::BatchSignerAddRefused { .. } => "sa.batch_signer_add_refused",
            Self::NetworksTomlIo { .. } => "sa.networks_toml_io",
            Self::AuditWriterIo { .. } => "sa.audit_writer_io",
            Self::NetworksTomlParse { .. } => "sa.networks_toml_parse",
            Self::WebAuthnAssertionInvalid { reason } => match reason {
                WebAuthnInvalidReason::WrongType => "sa.webauthn_assertion_invalid:wrong_type",
                WebAuthnInvalidReason::ChallengeMismatch => {
                    "sa.webauthn_assertion_invalid:challenge_mismatch"
                }
                WebAuthnInvalidReason::WrongRpId => "sa.webauthn_assertion_invalid:wrong_rp_id",
                WebAuthnInvalidReason::AuthDataTooShort => {
                    "sa.webauthn_assertion_invalid:auth_data_too_short"
                }
                WebAuthnInvalidReason::UpUnset => "sa.webauthn_assertion_invalid:up_unset",
                WebAuthnInvalidReason::UvUnset => "sa.webauthn_assertion_invalid:uv_unset",
                WebAuthnInvalidReason::BeBsInvalid => "sa.webauthn_assertion_invalid:be_bs_invalid",
                WebAuthnInvalidReason::SignatureInvalid => {
                    "sa.webauthn_assertion_invalid:signature_invalid"
                }
                WebAuthnInvalidReason::MalformedClientDataJson => {
                    "sa.webauthn_assertion_invalid:malformed_client_data_json"
                }
            },
            Self::ThresholdPolicyNotInstalled { .. } => "sa.threshold_policy_not_installed",
            Self::SignerSetMissingBaseline { .. } => "sa.signer_set_missing_baseline",
            Self::SignerSetBaselineLegacy { .. } => "sa.signer_set_baseline_legacy",
            Self::BaselineWriteFailed { .. } => "sa.baseline_write_failed",
            Self::InstallStateMismatch { .. } => "sa.install_state_mismatch",
            Self::SignersManagerNotConfigured { .. } => "sa.signers_manager_not_configured",
            Self::ThresholdPolicyIdentificationFailed { .. } => {
                "sa.threshold_policy_identification_failed"
            }
            Self::ThresholdReadFailed { .. } => "sa.threshold_read_failed",
            Self::NetworkRpcDivergence { .. } => "network.rpc_divergence",
            Self::AuditLog(_) => "sa.audit_log",
            // Verifier diversification.
            Self::VerifierDiversificationRequired { .. } => "sa.verifier_diversification_required",
            Self::VerifierWasmRevoked { .. } => "sa.verifier_wasm_revoked",
            Self::VerifierWasmRetired { .. } => "sa.verifier_wasm_retired",
            Self::VerifierMigrationFailed { .. } => "sa.verifier_migration_failed",
            Self::VerifierAllowlistEmpty { .. } => "sa.verifier_allowlist_empty",
            // Session-rule horizon enforcement.
            Self::HorizonExceeded { .. } => "sa.horizon_exceeded",
            // Submit.rs free-function extraction.
            Self::SubmitCheckMissing { .. } => "sa.submit_check_missing",
            // Multicall host-side surface.
            Self::MulticallFailed { .. } => "sa.multicall_failed",
            Self::MulticallSha256Drift { .. } => "sa.multicall_sha256_drift",
            Self::MulticallRegistryEntryNotFound { .. } => "sa.multicall_registry_entry_not_found",
            // Upgrade timelock surface.
            Self::TimelockScheduleFailed { .. } => "sa.timelock_schedule_failed",
            Self::TimelockCancelFailed { .. } => "sa.timelock_cancel_failed",
            Self::TimelockExecuteFailed { .. } => "sa.timelock_execute_failed",
            Self::TimelockListPendingFailed { .. } => "sa.timelock_list_pending_failed",
            // Simulation-audit mismatch.
            Self::AuthMismatch { .. } => "sa.auth_mismatch",
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(
        clippy::panic,
        reason = "test-only: panics are the correct failure mode"
    )]

    use std::path::PathBuf;

    use stellar_agent_core::audit_log::signer_set::{
        ObservedSignerSet, SignerEntryV2, SignerIdentityV2, SignerPubkey, SignerSetSnapshotV2,
        SignerSetView, ThresholdObservation,
    };
    use stellar_agent_core::audit_log::verify::VerifyError;

    use crate::signers::types::{ThresholdAffectingOp, WasmHashSummary};

    use super::*;

    /// Asserts that `wire_code()` returns the correct stable string for each variant.
    ///
    /// Any change here is a breaking change to the CLI/MCP JSON envelope contract.
    #[test]
    fn wire_code_returns_correct_string_for_each_variant() {
        let cases: &[(&str, SaError)] = &[
            (
                "sa.threshold_unreachable",
                SaError::ThresholdUnreachable {
                    rule_id: 1,
                    current_signer_count: 3,
                    current_threshold: 3,
                    requested_op: ThresholdAffectingOp::RemoveSigner { signer_id: 2 },
                    safe_ordering_hint: "run 'smart-account signers set-threshold --rule-id 1 \
                        --threshold 2' first, then retry remove"
                        .to_owned(),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-001".to_owned(),
                },
            ),
            (
                "sa.verifier_hash_drift",
                SaError::VerifierHashDrift {
                    rule_id: 1,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    deploy_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
                    pinned_hash_first8: "aabbccdd".to_owned(),
                    observed_hash_first8: "11223344".to_owned(),
                    observed_executable: None,
                    request_id: "test-req-drift-001".to_owned(),
                },
            ),
            (
                "sa.policy_hash_drift",
                SaError::PolicyHashDrift {
                    rule_id: 2,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    deploy_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
                    pinned_hash_first8: "aabbccdd".to_owned(),
                    observed_hash_first8: "11223344".to_owned(),
                    observed_executable: None,
                    request_id: "test-req-drift-002".to_owned(),
                },
            ),
            (
                "sa.verifier_mutable",
                SaError::VerifierMutable {
                    rule_id: Some(3),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    contract_address_redacted: RedactedStrkey::from_already_redacted(
                        "CBBBB...YYYYY",
                    ),
                    admin_or_owner_key: AdminOrOwnerKey::Admin,
                    detail: None,
                    request_id: "test-req-mut-001".to_owned(),
                },
            ),
            (
                "sa.policy_mutable",
                SaError::PolicyMutable {
                    rule_id: Some(4),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    contract_address_redacted: RedactedStrkey::from_already_redacted(
                        "CBBBB...YYYYY",
                    ),
                    admin_or_owner_key: AdminOrOwnerKey::Owner,
                    detail: None,
                    request_id: "test-req-mut-002".to_owned(),
                },
            ),
            (
                "sa.contract_instance_unsupported",
                SaError::ContractInstanceUnsupported {
                    rule_id: Some(4),
                    contract_kind: ContractKind::Verifier,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    contract_address_redacted: RedactedStrkey::from_already_redacted(
                        "CBBBB...YYYYY",
                    ),
                    reason: AdminOrOwnerKey::NonWasmExecutable,
                    request_id: "test-req-unsupported-001".to_owned(),
                },
            ),
            (
                "sa.multiple_pinned_hashes_unsupported",
                SaError::MultiplePinnedHashesUnsupported {
                    kind: "verifier",
                    rule_id: 7,
                    count: 3,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-multi-001".to_owned(),
                },
            ),
            (
                "sa.pinned_policy_absent",
                SaError::PinnedPolicyAbsent {
                    rule_id: 7,
                    pinned_count: 1,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-policy-absent-001".to_owned(),
                },
            ),
            (
                "sa.pinned_verifier_absent",
                SaError::PinnedVerifierAbsent {
                    rule_id: 7,
                    verifier_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-verifier-absent-001".to_owned(),
                },
            ),
            (
                "sa.pin_check_unavailable",
                SaError::PinCheckUnavailable {
                    rule_id: 7,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    reason: "sa.deployment_failed: rpc unreachable".to_owned(),
                    request_id: "test-req-pin-check-001".to_owned(),
                },
            ),
            (
                "sa.verifier_wasm_not_in_allowlist",
                SaError::VerifierWasmNotInAllowlist {
                    rule_id: Some(5),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    observed_hash_first8: "deadbeef".to_owned(),
                    request_id: "test-req-allow-001".to_owned(),
                },
            ),
            (
                "sa.policy_wasm_not_in_allowlist",
                SaError::PolicyWasmNotInAllowlist {
                    rule_id: Some(6),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    observed_hash_first8: "cafebabe".to_owned(),
                    request_id: "test-req-allow-002".to_owned(),
                },
            ),
            (
                "sa.rule_id_mismatch",
                SaError::RuleIdMismatch {
                    expected_len: 3,
                    observed_len: 2,
                },
            ),
            (
                "simulation.divergence.context_rule_ids",
                SaError::SimulationDivergence {
                    sub_code: SimulationDivergenceSubCode::ContextRuleIds,
                    redacted_reason: "simulation and envelope context_rule_ids differ".to_owned(),
                },
            ),
            (
                "simulation.divergence.auth_contexts",
                SaError::SimulationDivergence {
                    sub_code: SimulationDivergenceSubCode::AuthContexts,
                    redacted_reason: "simulation and envelope auth_contexts differ".to_owned(),
                },
            ),
            (
                "simulation.divergence.network",
                SaError::SimulationDivergence {
                    sub_code: SimulationDivergenceSubCode::Network,
                    redacted_reason: "simulation and envelope network identity differ".to_owned(),
                },
            ),
            (
                "simulation.divergence.sequence",
                SaError::SimulationDivergence {
                    sub_code: SimulationDivergenceSubCode::Sequence,
                    redacted_reason: "simulation and envelope sequence window differ".to_owned(),
                },
            ),
            (
                "simulation.divergence.fee_envelope",
                SaError::SimulationDivergence {
                    sub_code: SimulationDivergenceSubCode::FeeEnvelope,
                    redacted_reason: "simulation and envelope fee fields differ".to_owned(),
                },
            ),
            (
                "sa.signer_set_diverged",
                SaError::SignerSetDiverged {
                    rule_id: 1,
                    expected: SignerSetView::V1(ObservedSignerSet {
                        signer_count: 3,
                        threshold: 3,
                        signer_ids: vec![0, 1, 2],
                        signer_pubkeys: vec![
                            SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
                            SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
                            SignerPubkey::Ed25519 { pubkey: [3u8; 32] },
                        ],
                    }),
                    observed: SignerSetView::V1(ObservedSignerSet {
                        signer_count: 2,
                        threshold: 3,
                        signer_ids: vec![0, 1],
                        signer_pubkeys: vec![
                            SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
                            SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
                        ],
                    }),
                    tx_hash: None,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-div-001".to_owned(),
                },
            ),
            (
                "sa.signer_set_baseline_legacy",
                SaError::SignerSetBaselineLegacy {
                    rule_id: 4,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-legacy-001".to_owned(),
                },
            ),
            (
                "sa.baseline_write_failed",
                SaError::BaselineWriteFailed {
                    rule_id: 4,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    tx_hash: None,
                    stage: BASELINE_WRITE_STAGE_WRITE,
                    reason: "audit writer poisoned".to_owned(),
                    request_id: "test-req-bwf-001".to_owned(),
                },
            ),
            (
                "sa.context_rule_caps_exceeded",
                SaError::ContextRuleCapsExceeded {
                    kind: "signers",
                    cur: 15,
                    max: 15,
                },
            ),
            (
                "sa.rule_expired",
                SaError::RuleExpired {
                    rule_id: 7,
                    valid_until: 100,
                    current: 101,
                },
            ),
            (
                "sa.deployment_failed",
                SaError::DeploymentFailed {
                    phase: "simulate",
                    redacted_reason: "rpc returned malformed simulation response".to_owned(),
                },
            ),
            (
                "sa.scaddress_encoding_failed",
                SaError::ScAddressEncodingFailed {
                    redacted_reason: "ScAddress XDR cache-key encoding failed".to_owned(),
                },
            ),
            (
                "sa.auth_entry_construction_failed",
                SaError::AuthEntryConstructionFailed {
                    stage: "context_rule_ids",
                    redacted_reason: "context_rule_ids XDR encode failed before signing".to_owned(),
                },
            ),
            (
                "sa.webauthn_assertion_invalid:wrong_type",
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::WrongType,
                },
            ),
            (
                "sa.webauthn_assertion_invalid:challenge_mismatch",
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::ChallengeMismatch,
                },
            ),
            (
                "sa.webauthn_assertion_invalid:wrong_rp_id",
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::WrongRpId,
                },
            ),
            (
                "sa.webauthn_assertion_invalid:auth_data_too_short",
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::AuthDataTooShort,
                },
            ),
            (
                "sa.webauthn_assertion_invalid:up_unset",
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::UpUnset,
                },
            ),
            (
                "sa.webauthn_assertion_invalid:uv_unset",
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::UvUnset,
                },
            ),
            (
                "sa.webauthn_assertion_invalid:be_bs_invalid",
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::BeBsInvalid,
                },
            ),
            (
                "sa.webauthn_assertion_invalid:signature_invalid",
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::SignatureInvalid,
                },
            ),
            (
                "sa.webauthn_assertion_invalid:malformed_client_data_json",
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::MalformedClientDataJson,
                },
            ),
            (
                "sa.webauthn_verifier_provenance_mismatch",
                SaError::WebAuthnVerifierProvenanceMismatch {
                    expected: "abc".to_owned(),
                    actual: "def".to_owned(),
                },
            ),
            (
                "sa.webauthn_verifier_sha256_drift",
                SaError::WebAuthnVerifierSha256Drift {
                    network: "Test SDF Network ; September 2015".to_owned(),
                    recorded: "abc".to_owned(),
                    attempted: "def".to_owned(),
                },
            ),
            (
                "sa.ed25519_verifier_provenance_mismatch",
                SaError::Ed25519VerifierProvenanceMismatch {
                    expected: "abc".to_owned(),
                    actual: "def".to_owned(),
                },
            ),
            (
                "sa.ed25519_verifier_sha256_drift",
                SaError::Ed25519VerifierSha256Drift {
                    network: "Test SDF Network ; September 2015".to_owned(),
                    recorded: "abc".to_owned(),
                    attempted: "def".to_owned(),
                },
            ),
            (
                "sa.spending_limit_policy_provenance_mismatch",
                SaError::SpendingLimitPolicyProvenanceMismatch {
                    expected: "abc".to_owned(),
                    actual: "def".to_owned(),
                },
            ),
            (
                "sa.spending_limit_policy_sha256_drift",
                SaError::SpendingLimitPolicySha256Drift {
                    network: "Test SDF Network ; September 2015".to_owned(),
                    recorded: "abc".to_owned(),
                    attempted: "def".to_owned(),
                },
            ),
            (
                "sa.spending_limit_install_refused",
                SaError::SpendingLimitInstallRefused {
                    reason: "test".to_owned(),
                },
            ),
            (
                "sa.spending_limit_not_installed",
                SaError::SpendingLimitNotInstalled {
                    rule_id: 1,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-sl-001".to_owned(),
                },
            ),
            (
                "sa.spending_limit_policy_identification_failed",
                SaError::SpendingLimitPolicyIdentificationFailed {
                    rule_id: 1,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    observed_wasm_hashes_summary: WasmHashSummary {
                        count: 2,
                        first_first8: Some([0xabu8; 8]),
                    },
                    request_id: "test-req-sl-002".to_owned(),
                },
            ),
            (
                "sa.simple_threshold_install_refused",
                SaError::SimpleThresholdInstallRefused {
                    reason: "test".to_owned(),
                },
            ),
            (
                "sa.weighted_threshold_install_refused",
                SaError::WeightedThresholdInstallRefused {
                    reason: "test".to_owned(),
                },
            ),
            (
                "sa.simple_threshold_policy_provenance_mismatch",
                SaError::SimpleThresholdPolicyProvenanceMismatch {
                    expected: "abc".to_owned(),
                    actual: "def".to_owned(),
                },
            ),
            (
                "sa.simple_threshold_policy_sha256_drift",
                SaError::SimpleThresholdPolicySha256Drift {
                    network: "Test SDF Network ; September 2015".to_owned(),
                    recorded: "abc".to_owned(),
                    attempted: "def".to_owned(),
                },
            ),
            (
                "sa.weighted_threshold_policy_provenance_mismatch",
                SaError::WeightedThresholdPolicyProvenanceMismatch {
                    expected: "abc".to_owned(),
                    actual: "def".to_owned(),
                },
            ),
            (
                "sa.weighted_threshold_policy_sha256_drift",
                SaError::WeightedThresholdPolicySha256Drift {
                    network: "Test SDF Network ; September 2015".to_owned(),
                    recorded: "abc".to_owned(),
                    attempted: "def".to_owned(),
                },
            ),
            (
                "sa.weighted_threshold_not_installed",
                SaError::WeightedThresholdNotInstalled {
                    rule_id: 1,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-wt-001".to_owned(),
                },
            ),
            (
                "sa.weighted_threshold_policy_identification_failed",
                SaError::WeightedThresholdPolicyIdentificationFailed {
                    rule_id: 1,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    observed_wasm_hashes_summary: WasmHashSummary {
                        count: 2,
                        first_first8: Some([0xabu8; 8]),
                    },
                    request_id: "test-req-wt-002".to_owned(),
                },
            ),
            (
                "sa.batch_signer_add_refused",
                SaError::BatchSignerAddRefused {
                    reason: "test".to_owned(),
                },
            ),
            (
                "sa.networks_toml_io",
                SaError::NetworksTomlIo {
                    source: io::Error::other("mock io error"),
                    path: PathBuf::from("/mock/path"),
                },
            ),
            (
                "sa.audit_writer_io",
                SaError::AuditWriterIo {
                    detail: "mock io error".to_owned(),
                    path: PathBuf::from("/mock/path/audit/default.jsonl"),
                },
            ),
            (
                "sa.networks_toml_parse",
                SaError::NetworksTomlParse {
                    source: toml::from_str::<toml::Value>("invalid = ").unwrap_err(),
                    path: PathBuf::from("/mock/path"),
                },
            ),
            (
                "sa.install_state_mismatch",
                SaError::InstallStateMismatch {
                    rule_id: Some(4),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    tx_hash: "ab".repeat(32),
                    request_id: "test-req-ism-001".to_owned(),
                },
            ),
            (
                "sa.signers_manager_not_configured",
                SaError::SignersManagerNotConfigured {
                    rule_id: Some(7),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-manager-001".to_owned(),
                },
            ),
            (
                "sa.threshold_read_failed",
                SaError::ThresholdReadFailed {
                    rule_id: 5,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    source_kind: "primary",
                    request_id: "test-req-006".to_owned(),
                },
            ),
            // Verifier diversification.
            (
                "sa.verifier_diversification_required",
                SaError::VerifierDiversificationRequired {
                    rule_id: 1,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    verifier_hash_first8: "deadbeef".to_owned(),
                    observed_value_threshold_stroops: 100_000_000_000,
                    request_id: "req-div-req-001".to_owned(),
                },
            ),
            (
                "sa.verifier_wasm_revoked",
                SaError::VerifierWasmRevoked {
                    rule_id: 2,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    verifier_hash_first8: "cafebabe".to_owned(),
                    revoked_reason: "critical vulnerability in signature verification".to_owned(),
                    request_id: "req-rev-001".to_owned(),
                },
            ),
            (
                "sa.verifier_wasm_retired",
                SaError::VerifierWasmRetired {
                    rule_id: 3,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    verifier_hash_first8: "11223344".to_owned(),
                    request_id: "req-ret-001".to_owned(),
                },
            ),
            (
                "sa.verifier_migration_failed",
                SaError::VerifierMigrationFailed {
                    phase: "preflight_destination_unknown",
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    detail: "destination hash not in VERIFIER_ALLOWLIST".to_owned(),
                    request_id: "req-mig-001".to_owned(),
                },
            ),
            (
                "sa.verifier_allowlist_empty",
                SaError::VerifierAllowlistEmpty {
                    request_id: "req-empty-001".to_owned(),
                },
            ),
            // Session-rule horizon enforcement.
            (
                "sa.horizon_exceeded",
                SaError::HorizonExceeded {
                    rule_id_or_pending: None,
                    requested_horizon: 2_000,
                    max_horizon: 1_000,
                },
            ),
            (
                "sa.horizon_exceeded",
                SaError::HorizonExceeded {
                    rule_id_or_pending: Some(7),
                    requested_horizon: 5_000,
                    max_horizon: 1_000,
                },
            ),
            // Submit check enforcement.
            (
                "sa.submit_check_missing",
                SaError::SubmitCheckMissing {
                    required_check: "multicall",
                    host_function_kind: "InvokeContract",
                },
            ),
            // Multicall host-side surface.
            (
                "sa.multicall_failed",
                SaError::MulticallFailed {
                    phase: "build",
                    redacted_reason: "bundle empty".to_owned(),
                    post_submit_kind: None,
                },
            ),
            (
                "sa.multicall_sha256_drift",
                SaError::MulticallSha256Drift {
                    attempted: "aabbccdd".to_owned(),
                    expected: "267e94a0".to_owned(),
                    existing: None,
                },
            ),
            (
                "sa.multicall_registry_entry_not_found",
                SaError::MulticallRegistryEntryNotFound {
                    network_safename: "test-sdf-network---september-2015".to_owned(),
                },
            ),
            // Upgrade timelock surface.
            (
                "sa.timelock_schedule_failed",
                SaError::TimelockScheduleFailed {
                    failure_reason: TimelockScheduleFailureReason::Unauthorized,
                    redacted_reason: "proposer lacks PROPOSER_ROLE".to_owned(),
                    request_id: "test-req-tl-sched-001".to_owned(),
                },
            ),
            (
                "sa.timelock_cancel_failed",
                SaError::TimelockCancelFailed {
                    failure_reason: TimelockCancelFailureReason::SimulationFailed,
                    redacted_reason: "simulate returned error".to_owned(),
                    operation_id_redacted: "deadbeef...cafebabe".to_owned(),
                    request_id: "test-req-tl-cancel-001".to_owned(),
                },
            ),
            (
                "sa.timelock_execute_failed",
                SaError::TimelockExecuteFailed {
                    failure_reason: TimelockExecuteFailureReason::SimulationFailed,
                    redacted_reason: "simulate returned error".to_owned(),
                    operation_id_redacted: "deadbeef...cafebabe".to_owned(),
                    request_id: "test-req-tl-exec-001".to_owned(),
                },
            ),
            // list_pending RPC failure.
            (
                "sa.timelock_list_pending_failed",
                SaError::TimelockListPendingFailed {
                    redacted_reason: "primary RPC unreachable".to_owned(),
                },
            ),
            // Simulation-audit mismatch.
            (
                "sa.auth_mismatch",
                SaError::AuthMismatch {
                    reason: AuthMismatchReason::EntryMutated,
                },
            ),
        ];

        for (expected_code, err) in cases {
            assert_eq!(
                err.wire_code(),
                *expected_code,
                "wire_code mismatch for variant: {err:?}"
            );
        }
    }

    /// Verifies the `serde::Serialize` adjacently-tagged envelope shape for each variant.
    ///
    /// The envelope contract requires:
    /// `{ "wire_code": "<sa.variant_name>", "context": { <fields> } }`
    ///
    /// Field names in `"context"` are load-bearing for CLI mapper and MCP
    /// tool error consumers. A future variant rename or serde-attribute change
    /// will fail here before reaching production.
    #[test]
    fn serde_serialise_envelope_shape() {
        use serde_json::Value;

        let cases: &[(&str, SaError, &[&str])] = &[
            (
                "sa.threshold_unreachable",
                SaError::ThresholdUnreachable {
                    rule_id: 1,
                    current_signer_count: 3,
                    current_threshold: 3,
                    requested_op: ThresholdAffectingOp::RemoveSigner { signer_id: 2 },
                    safe_ordering_hint: "run set-threshold first, then retry remove".to_owned(),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-001".to_owned(),
                },
                &[
                    "rule_id",
                    "current_signer_count",
                    "current_threshold",
                    "requested_op",
                    "safe_ordering_hint",
                    "smart_account_redacted",
                    "request_id",
                ],
            ),
            (
                "sa.verifier_hash_drift",
                SaError::VerifierHashDrift {
                    rule_id: 1,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    deploy_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
                    pinned_hash_first8: "aabbccdd".to_owned(),
                    observed_hash_first8: "11223344".to_owned(),
                    observed_executable: None,
                    request_id: "test-req-drift-001".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "deploy_address_redacted",
                    "pinned_hash_first8",
                    "observed_hash_first8",
                    "request_id",
                ],
            ),
            (
                "sa.policy_hash_drift",
                SaError::PolicyHashDrift {
                    rule_id: 2,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    deploy_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
                    pinned_hash_first8: "aabbccdd".to_owned(),
                    observed_hash_first8: "11223344".to_owned(),
                    observed_executable: None,
                    request_id: "test-req-drift-002".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "deploy_address_redacted",
                    "pinned_hash_first8",
                    "observed_hash_first8",
                    "request_id",
                ],
            ),
            (
                "sa.verifier_mutable",
                SaError::VerifierMutable {
                    rule_id: Some(3),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    contract_address_redacted: RedactedStrkey::from_already_redacted(
                        "CBBBB...YYYYY",
                    ),
                    admin_or_owner_key: AdminOrOwnerKey::Admin,
                    detail: None,
                    request_id: "test-req-mut-001".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "contract_address_redacted",
                    "admin_or_owner_key",
                    "request_id",
                ],
            ),
            (
                "sa.policy_mutable",
                SaError::PolicyMutable {
                    rule_id: Some(4),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    contract_address_redacted: RedactedStrkey::from_already_redacted(
                        "CBBBB...YYYYY",
                    ),
                    admin_or_owner_key: AdminOrOwnerKey::Owner,
                    detail: None,
                    request_id: "test-req-mut-002".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "contract_address_redacted",
                    "admin_or_owner_key",
                    "request_id",
                ],
            ),
            (
                "sa.verifier_hash_drift",
                SaError::VerifierHashDrift {
                    rule_id: 1,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    deploy_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
                    pinned_hash_first8: "aabbccdd00112233".to_owned(),
                    observed_hash_first8: "aabbccdd00112233".to_owned(),
                    observed_executable: Some("wasm".to_owned()),
                    request_id: "test-req-drift-003".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "deploy_address_redacted",
                    "pinned_hash_first8",
                    "observed_hash_first8",
                    "observed_executable",
                    "request_id",
                ],
            ),
            (
                "sa.policy_hash_drift",
                SaError::PolicyHashDrift {
                    rule_id: 2,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    deploy_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
                    pinned_hash_first8: "aabbccdd00112233".to_owned(),
                    observed_hash_first8: "0000000000000000".to_owned(),
                    observed_executable: Some("no code".to_owned()),
                    request_id: "test-req-drift-004".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "deploy_address_redacted",
                    "pinned_hash_first8",
                    "observed_hash_first8",
                    "observed_executable",
                    "request_id",
                ],
            ),
            (
                "sa.verifier_mutable",
                SaError::VerifierMutable {
                    rule_id: Some(3),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    contract_address_redacted: RedactedStrkey::from_already_redacted(
                        "CBBBB...YYYYY",
                    ),
                    admin_or_owner_key: AdminOrOwnerKey::ExternalRefExecutable,
                    detail: Some("owner GAAAA...AAWHF, tag \"v1\"".to_owned()),
                    request_id: "test-req-mut-003".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "contract_address_redacted",
                    "admin_or_owner_key",
                    "detail",
                    "request_id",
                ],
            ),
            (
                "sa.policy_mutable",
                SaError::PolicyMutable {
                    rule_id: Some(4),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    contract_address_redacted: RedactedStrkey::from_already_redacted(
                        "CBBBB...YYYYY",
                    ),
                    admin_or_owner_key: AdminOrOwnerKey::Owner,
                    detail: Some("GCCCC...CCCCC".to_owned()),
                    request_id: "test-req-mut-004".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "contract_address_redacted",
                    "admin_or_owner_key",
                    "detail",
                    "request_id",
                ],
            ),
            (
                "sa.contract_instance_unsupported",
                SaError::ContractInstanceUnsupported {
                    rule_id: Some(4),
                    contract_kind: ContractKind::Policy,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    contract_address_redacted: RedactedStrkey::from_already_redacted(
                        "CBBBB...YYYYY",
                    ),
                    reason: AdminOrOwnerKey::UndecodableInstance,
                    request_id: "test-req-unsupported-002".to_owned(),
                },
                &[
                    "rule_id",
                    "contract_kind",
                    "smart_account_redacted",
                    "contract_address_redacted",
                    "reason",
                    "request_id",
                ],
            ),
            (
                "sa.multiple_pinned_hashes_unsupported",
                SaError::MultiplePinnedHashesUnsupported {
                    kind: "policy",
                    rule_id: 77,
                    count: 2,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-multi-002".to_owned(),
                },
                &[
                    "kind",
                    "rule_id",
                    "count",
                    "smart_account_redacted",
                    "request_id",
                ],
            ),
            (
                "sa.pinned_policy_absent",
                SaError::PinnedPolicyAbsent {
                    rule_id: 77,
                    pinned_count: 2,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-policy-absent-002".to_owned(),
                },
                &[
                    "rule_id",
                    "pinned_count",
                    "smart_account_redacted",
                    "request_id",
                ],
            ),
            (
                "sa.pinned_verifier_absent",
                SaError::PinnedVerifierAbsent {
                    rule_id: 77,
                    verifier_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-verifier-absent-002".to_owned(),
                },
                &[
                    "rule_id",
                    "verifier_redacted",
                    "smart_account_redacted",
                    "request_id",
                ],
            ),
            (
                "sa.pin_check_unavailable",
                SaError::PinCheckUnavailable {
                    rule_id: 77,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    reason: "sa.audit_log: audit log parse error".to_owned(),
                    request_id: "test-req-pin-check-002".to_owned(),
                },
                &["rule_id", "smart_account_redacted", "reason", "request_id"],
            ),
            (
                "sa.verifier_wasm_not_in_allowlist",
                SaError::VerifierWasmNotInAllowlist {
                    rule_id: Some(5),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    observed_hash_first8: "deadbeef".to_owned(),
                    request_id: "test-req-allow-001".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "observed_hash_first8",
                    "request_id",
                ],
            ),
            (
                "sa.policy_wasm_not_in_allowlist",
                SaError::PolicyWasmNotInAllowlist {
                    rule_id: Some(6),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    observed_hash_first8: "cafebabe".to_owned(),
                    request_id: "test-req-allow-002".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "observed_hash_first8",
                    "request_id",
                ],
            ),
            (
                "sa.rule_id_mismatch",
                SaError::RuleIdMismatch {
                    expected_len: 3,
                    observed_len: 2,
                },
                &["expected_len", "observed_len"],
            ),
            (
                "simulation.divergence",
                SaError::SimulationDivergence {
                    sub_code: SimulationDivergenceSubCode::ContextRuleIds,
                    redacted_reason: "simulation and envelope context_rule_ids differ".to_owned(),
                },
                &["sub_code", "redacted_reason"],
            ),
            (
                "sa.signer_set_diverged",
                SaError::SignerSetDiverged {
                    rule_id: 1,
                    expected: SignerSetView::V1(ObservedSignerSet {
                        signer_count: 3,
                        threshold: 3,
                        signer_ids: vec![0, 1, 2],
                        signer_pubkeys: vec![
                            SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
                            SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
                            SignerPubkey::Ed25519 { pubkey: [3u8; 32] },
                        ],
                    }),
                    observed: SignerSetView::V1(ObservedSignerSet {
                        signer_count: 2,
                        threshold: 3,
                        signer_ids: vec![0, 1],
                        signer_pubkeys: vec![
                            SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
                            SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
                        ],
                    }),
                    tx_hash: None,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-div-001".to_owned(),
                },
                &[
                    "rule_id",
                    "expected",
                    "observed",
                    "smart_account_redacted",
                    "request_id",
                ],
            ),
            (
                "sa.signer_set_baseline_legacy",
                SaError::SignerSetBaselineLegacy {
                    rule_id: 4,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-legacy-001".to_owned(),
                },
                &["rule_id", "smart_account_redacted", "request_id"],
            ),
            (
                "sa.baseline_write_failed",
                SaError::BaselineWriteFailed {
                    rule_id: 4,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    tx_hash: Some("ab".repeat(32)),
                    stage: BASELINE_WRITE_STAGE_OBSERVE,
                    reason: "network.rpc_divergence: views differ".to_owned(),
                    request_id: "test-req-bwf-001".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "tx_hash",
                    "stage",
                    "reason",
                    "request_id",
                ],
            ),
            (
                "sa.install_state_mismatch",
                SaError::InstallStateMismatch {
                    rule_id: Some(4),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    tx_hash: "ab".repeat(32),
                    request_id: "test-req-ism-001".to_owned(),
                },
                &["rule_id", "smart_account_redacted", "tx_hash", "request_id"],
            ),
            (
                "sa.install_state_mismatch",
                SaError::InstallStateMismatch {
                    rule_id: None,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    tx_hash: "ab".repeat(32),
                    request_id: "test-req-ism-002".to_owned(),
                },
                &["smart_account_redacted", "tx_hash", "request_id"],
            ),
            (
                "sa.signers_manager_not_configured",
                SaError::SignersManagerNotConfigured {
                    rule_id: Some(7),
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-manager-001".to_owned(),
                },
                &["rule_id", "smart_account_redacted", "request_id"],
            ),
            (
                "sa.signers_manager_not_configured",
                SaError::SignersManagerNotConfigured {
                    rule_id: None,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-manager-002".to_owned(),
                },
                &["smart_account_redacted", "request_id"],
            ),
            (
                "sa.context_rule_caps_exceeded",
                SaError::ContextRuleCapsExceeded {
                    kind: "signers",
                    cur: 15,
                    max: 15,
                },
                &["kind", "cur", "max"],
            ),
            (
                "sa.rule_expired",
                SaError::RuleExpired {
                    rule_id: 7,
                    valid_until: 100,
                    current: 101,
                },
                &["rule_id", "valid_until", "current"],
            ),
            (
                "sa.deployment_failed",
                SaError::DeploymentFailed {
                    phase: "simulate",
                    redacted_reason: "rpc returned malformed simulation response".to_owned(),
                },
                &["phase", "redacted_reason"],
            ),
            (
                "sa.scaddress_encoding_failed",
                SaError::ScAddressEncodingFailed {
                    redacted_reason: "ScAddress XDR cache-key encoding failed".to_owned(),
                },
                &["redacted_reason"],
            ),
            (
                "sa.auth_entry_construction_failed",
                SaError::AuthEntryConstructionFailed {
                    stage: "context_rule_ids",
                    redacted_reason: "context_rule_ids XDR encode failed before signing".to_owned(),
                },
                &["stage", "redacted_reason"],
            ),
            (
                "sa.webauthn_assertion_invalid",
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::WrongType,
                },
                &["reason"],
            ),
            (
                "sa.webauthn_verifier_provenance_mismatch",
                SaError::WebAuthnVerifierProvenanceMismatch {
                    expected: "abc".to_owned(),
                    actual: "def".to_owned(),
                },
                &["expected", "actual"],
            ),
            (
                "sa.webauthn_verifier_sha256_drift",
                SaError::WebAuthnVerifierSha256Drift {
                    network: "Test SDF Network ; September 2015".to_owned(),
                    recorded: "abc".to_owned(),
                    attempted: "def".to_owned(),
                },
                &["network", "recorded", "attempted"],
            ),
            (
                "sa.ed25519_verifier_provenance_mismatch",
                SaError::Ed25519VerifierProvenanceMismatch {
                    expected: "abc".to_owned(),
                    actual: "def".to_owned(),
                },
                &["expected", "actual"],
            ),
            (
                "sa.ed25519_verifier_sha256_drift",
                SaError::Ed25519VerifierSha256Drift {
                    network: "Test SDF Network ; September 2015".to_owned(),
                    recorded: "abc".to_owned(),
                    attempted: "def".to_owned(),
                },
                &["network", "recorded", "attempted"],
            ),
            (
                "sa.spending_limit_policy_provenance_mismatch",
                SaError::SpendingLimitPolicyProvenanceMismatch {
                    expected: "abc".to_owned(),
                    actual: "def".to_owned(),
                },
                &["expected", "actual"],
            ),
            (
                "sa.spending_limit_policy_sha256_drift",
                SaError::SpendingLimitPolicySha256Drift {
                    network: "Test SDF Network ; September 2015".to_owned(),
                    recorded: "abc".to_owned(),
                    attempted: "def".to_owned(),
                },
                &["network", "recorded", "attempted"],
            ),
            (
                "sa.spending_limit_install_refused",
                SaError::SpendingLimitInstallRefused {
                    reason: "test".to_owned(),
                },
                &["reason"],
            ),
            (
                "sa.spending_limit_not_installed",
                SaError::SpendingLimitNotInstalled {
                    rule_id: 1,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-sl-001".to_owned(),
                },
                &["rule_id", "smart_account_redacted", "request_id"],
            ),
            (
                "sa.spending_limit_policy_identification_failed",
                SaError::SpendingLimitPolicyIdentificationFailed {
                    rule_id: 1,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    observed_wasm_hashes_summary: WasmHashSummary {
                        count: 2,
                        first_first8: Some([0xabu8; 8]),
                    },
                    request_id: "test-req-sl-002".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "observed_wasm_hashes_summary",
                    "request_id",
                ],
            ),
            (
                "sa.simple_threshold_install_refused",
                SaError::SimpleThresholdInstallRefused {
                    reason: "test".to_owned(),
                },
                &["reason"],
            ),
            (
                "sa.weighted_threshold_install_refused",
                SaError::WeightedThresholdInstallRefused {
                    reason: "test".to_owned(),
                },
                &["reason"],
            ),
            (
                "sa.simple_threshold_policy_provenance_mismatch",
                SaError::SimpleThresholdPolicyProvenanceMismatch {
                    expected: "abc".to_owned(),
                    actual: "def".to_owned(),
                },
                &["expected", "actual"],
            ),
            (
                "sa.simple_threshold_policy_sha256_drift",
                SaError::SimpleThresholdPolicySha256Drift {
                    network: "Test SDF Network ; September 2015".to_owned(),
                    recorded: "abc".to_owned(),
                    attempted: "def".to_owned(),
                },
                &["network", "recorded", "attempted"],
            ),
            (
                "sa.weighted_threshold_policy_provenance_mismatch",
                SaError::WeightedThresholdPolicyProvenanceMismatch {
                    expected: "abc".to_owned(),
                    actual: "def".to_owned(),
                },
                &["expected", "actual"],
            ),
            (
                "sa.weighted_threshold_policy_sha256_drift",
                SaError::WeightedThresholdPolicySha256Drift {
                    network: "Test SDF Network ; September 2015".to_owned(),
                    recorded: "abc".to_owned(),
                    attempted: "def".to_owned(),
                },
                &["network", "recorded", "attempted"],
            ),
            (
                "sa.weighted_threshold_not_installed",
                SaError::WeightedThresholdNotInstalled {
                    rule_id: 1,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    request_id: "test-req-wt-001".to_owned(),
                },
                &["rule_id", "smart_account_redacted", "request_id"],
            ),
            (
                "sa.weighted_threshold_policy_identification_failed",
                SaError::WeightedThresholdPolicyIdentificationFailed {
                    rule_id: 1,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    observed_wasm_hashes_summary: WasmHashSummary {
                        count: 2,
                        first_first8: Some([0xabu8; 8]),
                    },
                    request_id: "test-req-wt-002".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "observed_wasm_hashes_summary",
                    "request_id",
                ],
            ),
            (
                "sa.batch_signer_add_refused",
                SaError::BatchSignerAddRefused {
                    reason: "test".to_owned(),
                },
                &["reason"],
            ),
            (
                "sa.networks_toml_io",
                SaError::NetworksTomlIo {
                    source: io::Error::other("mock io error"),
                    path: PathBuf::from("/mock/path"),
                },
                &["source", "path"],
            ),
            (
                "sa.audit_writer_io",
                SaError::AuditWriterIo {
                    detail: "mock io error".to_owned(),
                    path: PathBuf::from("/mock/path/audit/default.jsonl"),
                },
                &["detail", "path"],
            ),
            (
                "sa.networks_toml_parse",
                SaError::NetworksTomlParse {
                    source: toml::from_str::<toml::Value>("invalid = ").unwrap_err(),
                    path: PathBuf::from("/mock/path"),
                },
                &["source", "path"],
            ),
            (
                "sa.threshold_read_failed",
                SaError::ThresholdReadFailed {
                    rule_id: 5,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    source_kind: "primary",
                    request_id: "test-req-006".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "source_kind",
                    "request_id",
                ],
            ),
            // Verifier diversification.
            (
                "sa.verifier_diversification_required",
                SaError::VerifierDiversificationRequired {
                    rule_id: 1,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    verifier_hash_first8: "deadbeef".to_owned(),
                    observed_value_threshold_stroops: 100_000_000_000,
                    request_id: "req-div-req-001".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "verifier_hash_first8",
                    "observed_value_threshold_stroops",
                    "request_id",
                ],
            ),
            (
                "sa.verifier_wasm_revoked",
                SaError::VerifierWasmRevoked {
                    rule_id: 2,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    verifier_hash_first8: "cafebabe".to_owned(),
                    revoked_reason: "critical vulnerability in signature verification".to_owned(),
                    request_id: "req-rev-001".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "verifier_hash_first8",
                    "revoked_reason",
                    "request_id",
                ],
            ),
            (
                "sa.verifier_wasm_retired",
                SaError::VerifierWasmRetired {
                    rule_id: 3,
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    verifier_hash_first8: "11223344".to_owned(),
                    request_id: "req-ret-001".to_owned(),
                },
                &[
                    "rule_id",
                    "smart_account_redacted",
                    "verifier_hash_first8",
                    "request_id",
                ],
            ),
            (
                "sa.verifier_migration_failed",
                SaError::VerifierMigrationFailed {
                    phase: "preflight_destination_unknown",
                    smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                    detail: "destination hash not in VERIFIER_ALLOWLIST".to_owned(),
                    request_id: "req-mig-001".to_owned(),
                },
                &["phase", "smart_account_redacted", "detail", "request_id"],
            ),
            (
                "sa.verifier_allowlist_empty",
                SaError::VerifierAllowlistEmpty {
                    request_id: "req-empty-001".to_owned(),
                },
                &["request_id"],
            ),
            // Session-rule horizon enforcement.
            (
                "sa.horizon_exceeded",
                SaError::HorizonExceeded {
                    rule_id_or_pending: None,
                    requested_horizon: 2_000,
                    max_horizon: 1_000,
                },
                &["rule_id_or_pending", "requested_horizon", "max_horizon"],
            ),
            (
                "sa.horizon_exceeded",
                SaError::HorizonExceeded {
                    rule_id_or_pending: Some(7),
                    requested_horizon: 5_000,
                    max_horizon: 1_000,
                },
                &["rule_id_or_pending", "requested_horizon", "max_horizon"],
            ),
            // Submit-check surface.
            (
                "sa.submit_check_missing",
                SaError::SubmitCheckMissing {
                    required_check: "multicall",
                    host_function_kind: "InvokeContract",
                },
                &["required_check", "host_function_kind"],
            ),
            // Multicall host-side surface.
            (
                "sa.multicall_failed",
                SaError::MulticallFailed {
                    phase: "build",
                    redacted_reason: "bundle empty".to_owned(),
                    post_submit_kind: None,
                },
                &["phase", "redacted_reason", "post_submit_kind"],
            ),
            (
                "sa.multicall_sha256_drift",
                SaError::MulticallSha256Drift {
                    attempted: "aabbccdd".to_owned(),
                    expected: "267e94a0".to_owned(),
                    existing: Some("deadbeef".to_owned()),
                },
                &["attempted", "expected", "existing"],
            ),
            (
                "sa.multicall_registry_entry_not_found",
                SaError::MulticallRegistryEntryNotFound {
                    network_safename: "test-sdf-network---september-2015".to_owned(),
                },
                &["network_safename"],
            ),
        ];

        for (expected_code, err, context_fields) in cases {
            let json = serde_json::to_string(err).unwrap_or_else(|e| {
                panic!("SaError::{expected_code} must serialise without error: {e}")
            });
            let value: Value = serde_json::from_str(&json).unwrap_or_else(|e| {
                panic!("SaError::{expected_code} must round-trip to JSON: {e}")
            });

            // Verify adjacently-tagged shape: top-level "wire_code" tag field.
            assert_eq!(
                value.get("wire_code").and_then(|v| v.as_str()),
                Some(*expected_code),
                "wire_code tag field mismatch for {expected_code}: full json={json}"
            );

            // Verify "context" content object is present.
            let context = value.get("context").unwrap_or_else(|| {
                panic!("SaError::{expected_code} envelope missing \"context\" field: {json}")
            });

            // Verify each expected field exists in the context object.
            for field in *context_fields {
                assert!(
                    context.get(field).is_some(),
                    "SaError::{expected_code} context missing field \"{field}\": {json}"
                );
            }
        }
    }

    /// `detail`, `observed_executable` and the optional `rule_id` are omitted
    /// from the context when `None` and serialised when `Some`; a present
    /// detail is appended to the Display in parentheses and a present rule id
    /// as ` for rule <id>`.
    #[test]
    fn optional_detail_fields_serialise_and_render_only_when_present() {
        let mutable = |detail: Option<&str>| SaError::VerifierMutable {
            rule_id: Some(3),
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            contract_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
            admin_or_owner_key: AdminOrOwnerKey::ExternalRefExecutable,
            detail: detail.map(ToOwned::to_owned),
            request_id: "req".to_owned(),
        };
        let drift = |observed: Option<&str>| SaError::PolicyHashDrift {
            rule_id: 2,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            deploy_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
            pinned_hash_first8: "1111111111111111".to_owned(),
            observed_hash_first8: "1111111111111111".to_owned(),
            observed_executable: observed.map(ToOwned::to_owned),
            request_id: "req".to_owned(),
        };

        let without = serde_json::to_value(mutable(None)).unwrap();
        assert!(without["context"].get("detail").is_none(), "{without}");
        assert_eq!(
            mutable(None).to_string(),
            "verifier contract is mutable for rule 3: contract=CBBBB...YYYYY, \
             reason=owner-managed external reference; --accept-mutable-verifier is required"
        );
        let detail = "owner GAAAA...AAWHF, tag \"v1\"";
        let with = serde_json::to_value(mutable(Some(detail))).unwrap();
        assert_eq!(with["context"]["detail"], detail);
        assert_eq!(
            mutable(Some(detail)).to_string(),
            "verifier contract is mutable for rule 3: contract=CBBBB...YYYYY, \
             reason=owner-managed external reference (owner GAAAA...AAWHF, tag \"v1\"); \
             --accept-mutable-verifier is required"
        );

        let without = serde_json::to_value(drift(None)).unwrap();
        assert!(
            without["context"].get("observed_executable").is_none(),
            "{without}"
        );
        assert_eq!(
            drift(None).to_string(),
            "policy wasm-hash drift detected for rule 2: \
             pinned=1111111111111111, observed=1111111111111111"
        );
        let with = serde_json::to_value(drift(Some("wasm"))).unwrap();
        assert_eq!(with["context"]["observed_executable"], "wasm");
        assert_eq!(
            drift(Some("wasm")).to_string(),
            "policy wasm-hash drift detected for rule 2: \
             pinned=1111111111111111, observed=1111111111111111 (wasm)"
        );

        // The optional rule id of the pre-install refusals.
        let verifier_mutable = |rule_id: Option<u32>| SaError::VerifierMutable {
            rule_id,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            contract_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
            admin_or_owner_key: AdminOrOwnerKey::Admin,
            detail: None,
            request_id: "req".to_owned(),
        };
        let policy_mutable = |rule_id: Option<u32>| SaError::PolicyMutable {
            rule_id,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            contract_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
            admin_or_owner_key: AdminOrOwnerKey::Owner,
            detail: None,
            request_id: "req".to_owned(),
        };
        let unsupported = |rule_id: Option<u32>| SaError::ContractInstanceUnsupported {
            rule_id,
            contract_kind: ContractKind::Policy,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            contract_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
            reason: AdminOrOwnerKey::UndecodableInstance,
            request_id: "req".to_owned(),
        };
        let verifier_not_allowlisted = |rule_id: Option<u32>| SaError::VerifierWasmNotInAllowlist {
            rule_id,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            observed_hash_first8: "deadbeef".to_owned(),
            request_id: "req".to_owned(),
        };
        let policy_not_allowlisted = |rule_id: Option<u32>| SaError::PolicyWasmNotInAllowlist {
            rule_id,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            observed_hash_first8: "cafebabe".to_owned(),
            request_id: "req".to_owned(),
        };
        let rpc_divergence = |rule_id: Option<u32>| SaError::NetworkRpcDivergence {
            rule_id,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            primary_view_digest_first8: "aabbccdd".to_owned(),
            secondary_view_digest_first8: "11223344".to_owned(),
            request_id: "req".to_owned(),
        };
        // A constructor for one rule id, then the Display without and with it.
        type RuleIdCase = (fn(Option<u32>) -> SaError, &'static str, &'static str);
        let cases: [RuleIdCase; 6] = [
            (
                verifier_mutable,
                "verifier contract is mutable: contract=CBBBB...YYYYY, reason=Admin; \
                 --accept-mutable-verifier is required",
                "verifier contract is mutable for rule 7: contract=CBBBB...YYYYY, \
                 reason=Admin; --accept-mutable-verifier is required",
            ),
            (
                policy_mutable,
                "policy contract is mutable: contract=CBBBB...YYYYY, reason=Owner; \
                 --accept-mutable-verifier is required",
                "policy contract is mutable for rule 7: contract=CBBBB...YYYYY, \
                 reason=Owner; --accept-mutable-verifier is required",
            ),
            (
                unsupported,
                "policy contract instance is unsupported: contract=CBBBB...YYYYY, \
                 reason=undecodable instance; the wallet cannot pin this contract's code",
                "policy contract instance is unsupported for rule 7: \
                 contract=CBBBB...YYYYY, reason=undecodable instance; \
                 the wallet cannot pin this contract's code",
            ),
            (
                verifier_not_allowlisted,
                "verifier wasm hash not in VERIFIER_ALLOWLIST: observed=deadbeef; \
                 --accept-unknown-verifier is required",
                "verifier wasm hash not in VERIFIER_ALLOWLIST for rule 7: observed=deadbeef; \
                 --accept-unknown-verifier is required",
            ),
            (
                policy_not_allowlisted,
                "policy wasm hash is not a policy Wasm the wallet vendors: observed=cafebabe; \
                 --accept-unknown-verifier is required",
                "policy wasm hash is not a policy Wasm the wallet vendors for rule 7: \
                 observed=cafebabe; --accept-unknown-verifier is required",
            ),
            (
                rpc_divergence,
                "network RPC divergence: primary view first8 aabbccdd, \
                 secondary first8 11223344",
                "network RPC divergence for rule 7: primary view first8 aabbccdd, \
                 secondary first8 11223344",
            ),
        ];
        for (build, display_none, display_some) in cases {
            let none = build(None);
            let json = serde_json::to_value(&none).unwrap();
            assert!(json["context"].get("rule_id").is_none(), "{json}");
            assert_eq!(none.to_string(), display_none);

            let some = build(Some(7));
            let json = serde_json::to_value(&some).unwrap();
            assert_eq!(json["context"]["rule_id"], 7, "{json}");
            assert_eq!(some.to_string(), display_some);
        }
    }

    /// A text within the cap is returned unchanged; a longer one is cut on
    /// a character boundary and suffixed with `"..."`, the whole never
    /// exceeding the cap, for single-byte and multi-byte text alike.
    #[test]
    fn truncate_to_byte_cap_bounds_the_text_on_a_char_boundary() {
        assert_eq!(truncate_to_byte_cap("short warning", 256), "short warning");
        let exact = "x".repeat(256);
        assert_eq!(truncate_to_byte_cap(&exact, 256), exact);

        let long = "x".repeat(300);
        let cut = truncate_to_byte_cap(&long, 256);
        assert_eq!(cut.len(), 256);
        assert!(cut.ends_with("..."));

        // Four-byte characters: the boundary search must step back so the
        // result stays within the cap and is valid UTF-8.
        let wide = "\u{1F600}".repeat(100);
        for cap in [256, 255, 254, 253, 10, 4, 3] {
            let cut = truncate_to_byte_cap(&wide, cap);
            assert!(cut.len() <= cap, "cap {cap}: {} bytes", cut.len());
            assert!(cut.ends_with("..."), "cap {cap}");
        }

        // A cap that cannot hold the ellipsis yields an empty string.
        for cap in [0, 1, 2] {
            assert_eq!(truncate_to_byte_cap(&long, cap), "", "cap {cap}");
            assert_eq!(truncate_to_byte_cap(&wide, cap), "", "cap {cap}");
        }
    }

    /// The absent-policy refusal names the pin count and the rule.
    #[test]
    fn pinned_policy_absent_display_names_the_count_and_the_rule() {
        let err = SaError::PinnedPolicyAbsent {
            rule_id: 3,
            pinned_count: 2,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            request_id: "req".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "pin record holds 2 policy pin(s) for rule 3 but the rule has no policy on chain"
        );
    }

    /// The absent-verifier refusal names the rule, the verifier and the
    /// refresh that repairs the record.
    #[test]
    fn pinned_verifier_absent_display_names_the_verifier_and_the_refresh() {
        let err = SaError::PinnedVerifierAbsent {
            rule_id: 3,
            verifier_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            request_id: "req".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "rule 3 holds the live External verifier CBBBB...YYYYY and its pin record pins no \
             verifier; run 'smart-account signers refresh --rule-id 3' to pin it"
        );
    }

    /// The pin-check reason leads with the inner wire code, carries the
    /// inner Display, and is capped at `PIN_CHECK_REASON_MAX_BYTES`.
    #[test]
    fn pin_check_reason_carries_the_inner_code_and_is_capped() {
        let inner = SaError::MultiplePinnedHashesUnsupported {
            kind: "verifier",
            rule_id: 3,
            count: 2,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            request_id: "req".to_owned(),
        };
        let reason = pin_check_reason(&inner);
        assert!(
            reason.starts_with("sa.multiple_pinned_hashes_unsupported: multiple pinned verifier"),
            "{reason}"
        );

        let long = SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: "r".repeat(1_000),
        };
        let reason = pin_check_reason(&long);
        assert!(reason.starts_with("sa.deployment_failed: "), "{reason}");
        assert!(reason.len() <= PIN_CHECK_REASON_MAX_BYTES);
        assert!(reason.ends_with("..."));
    }

    /// Verifies the wire-code closed set has no duplicates and covers every variant.
    ///
    /// The variant list is a slice literal the compiler does not check
    /// against the enum. The literal count is the completeness check: a new
    /// variant updates the list, the expected codes and the count together.
    /// The duplicate check enforces that every wire code is unique.
    #[test]
    fn wire_code_set_has_no_duplicates_and_correct_count() {
        // Construct one instance of each variant and collect its wire_code.
        // The list is a slice literal, so the compiler does not check it
        // against the enum: the literal count below and the order check
        // against `expected_codes` are what enforce that every variant is
        // represented. A new variant updates the list, the codes and the
        // count together.
        let variants: &[SaError] = &[
            SaError::ThresholdUnreachable {
                rule_id: 1,
                current_signer_count: 3,
                current_threshold: 3,
                requested_op: ThresholdAffectingOp::RemoveSigner { signer_id: 2 },
                safe_ordering_hint: "run set-threshold first, then retry remove".to_owned(),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                request_id: "test-req-001".to_owned(),
            },
            SaError::VerifierHashDrift {
                rule_id: 1,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                deploy_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
                pinned_hash_first8: "aabbccdd".to_owned(),
                observed_hash_first8: "11223344".to_owned(),
                observed_executable: None,
                request_id: "test-req-drift-001".to_owned(),
            },
            SaError::PolicyHashDrift {
                rule_id: 2,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                deploy_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
                pinned_hash_first8: "aabbccdd".to_owned(),
                observed_hash_first8: "11223344".to_owned(),
                observed_executable: None,
                request_id: "test-req-drift-002".to_owned(),
            },
            SaError::MultiplePinnedHashesUnsupported {
                kind: "verifier",
                rule_id: 88,
                count: 4,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                request_id: "test-req-multi-003".to_owned(),
            },
            SaError::PinnedPolicyAbsent {
                rule_id: 88,
                pinned_count: 1,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                request_id: "test-req-policy-absent-003".to_owned(),
            },
            SaError::PinnedVerifierAbsent {
                rule_id: 88,
                verifier_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                request_id: "test-req-verifier-absent-003".to_owned(),
            },
            SaError::PinCheckUnavailable {
                rule_id: 88,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                reason: "sa.deployment_failed: rpc unreachable".to_owned(),
                request_id: "test-req-pin-check-003".to_owned(),
            },
            SaError::VerifierMutable {
                rule_id: Some(3),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                contract_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
                admin_or_owner_key: AdminOrOwnerKey::Admin,
                detail: None,
                request_id: "test-req-mut-001".to_owned(),
            },
            SaError::PolicyMutable {
                rule_id: Some(4),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                contract_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
                admin_or_owner_key: AdminOrOwnerKey::Owner,
                detail: None,
                request_id: "test-req-mut-002".to_owned(),
            },
            SaError::ContractInstanceUnsupported {
                rule_id: Some(4),
                contract_kind: ContractKind::Verifier,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                contract_address_redacted: RedactedStrkey::from_already_redacted("CBBBB...YYYYY"),
                reason: AdminOrOwnerKey::UndecodableInstance,
                request_id: "test-req-unsupported-001".to_owned(),
            },
            SaError::VerifierWasmNotInAllowlist {
                rule_id: Some(5),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                observed_hash_first8: "deadbeef".to_owned(),
                request_id: "test-req-allow-001".to_owned(),
            },
            SaError::PolicyWasmNotInAllowlist {
                rule_id: Some(6),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                observed_hash_first8: "cafebabe".to_owned(),
                request_id: "test-req-allow-002".to_owned(),
            },
            SaError::RuleIdMismatch {
                expected_len: 3,
                observed_len: 2,
            },
            SaError::SimulationDivergence {
                sub_code: SimulationDivergenceSubCode::ContextRuleIds,
                redacted_reason: "simulation and envelope context_rule_ids differ".to_owned(),
            },
            SaError::SimulationDivergence {
                sub_code: SimulationDivergenceSubCode::AuthContexts,
                redacted_reason: "simulation and envelope auth_contexts differ".to_owned(),
            },
            SaError::SimulationDivergence {
                sub_code: SimulationDivergenceSubCode::Network,
                redacted_reason: "simulation and envelope network identity differ".to_owned(),
            },
            SaError::SimulationDivergence {
                sub_code: SimulationDivergenceSubCode::Sequence,
                redacted_reason: "simulation and envelope sequence window differ".to_owned(),
            },
            SaError::SimulationDivergence {
                sub_code: SimulationDivergenceSubCode::FeeEnvelope,
                redacted_reason: "simulation and envelope fee fields differ".to_owned(),
            },
            SaError::SignerSetDiverged {
                rule_id: 1,
                expected: SignerSetView::V1(ObservedSignerSet {
                    signer_count: 3,
                    threshold: 3,
                    signer_ids: vec![0, 1, 2],
                    signer_pubkeys: vec![
                        SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
                        SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
                        SignerPubkey::Ed25519 { pubkey: [3u8; 32] },
                    ],
                }),
                observed: SignerSetView::V1(ObservedSignerSet {
                    signer_count: 2,
                    threshold: 3,
                    signer_ids: vec![0, 1],
                    signer_pubkeys: vec![
                        SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
                        SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
                    ],
                }),
                tx_hash: None,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                request_id: "test-req-div-001".to_owned(),
            },
            SaError::ContextRuleCapsExceeded {
                kind: "signers",
                cur: 15,
                max: 15,
            },
            SaError::RuleExpired {
                rule_id: 7,
                valid_until: 100,
                current: 101,
            },
            SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: "rpc returned malformed simulation response".to_owned(),
            },
            SaError::ScAddressEncodingFailed {
                redacted_reason: "ScAddress XDR cache-key encoding failed".to_owned(),
            },
            SaError::AuthEntryConstructionFailed {
                stage: "context_rule_ids",
                redacted_reason: "context_rule_ids XDR encode failed before signing".to_owned(),
            },
            SaError::WebAuthnAssertionInvalid {
                reason: WebAuthnInvalidReason::WrongType,
            },
            SaError::WebAuthnAssertionInvalid {
                reason: WebAuthnInvalidReason::ChallengeMismatch,
            },
            SaError::WebAuthnAssertionInvalid {
                reason: WebAuthnInvalidReason::WrongRpId,
            },
            SaError::WebAuthnAssertionInvalid {
                reason: WebAuthnInvalidReason::AuthDataTooShort,
            },
            SaError::WebAuthnAssertionInvalid {
                reason: WebAuthnInvalidReason::UpUnset,
            },
            SaError::WebAuthnAssertionInvalid {
                reason: WebAuthnInvalidReason::UvUnset,
            },
            SaError::WebAuthnAssertionInvalid {
                reason: WebAuthnInvalidReason::BeBsInvalid,
            },
            SaError::WebAuthnAssertionInvalid {
                reason: WebAuthnInvalidReason::SignatureInvalid,
            },
            SaError::WebAuthnAssertionInvalid {
                reason: WebAuthnInvalidReason::MalformedClientDataJson,
            },
            SaError::WebAuthnVerifierProvenanceMismatch {
                expected: "abc".to_owned(),
                actual: "def".to_owned(),
            },
            SaError::WebAuthnVerifierSha256Drift {
                network: "Test SDF Network ; September 2015".to_owned(),
                recorded: "abc".to_owned(),
                attempted: "def".to_owned(),
            },
            SaError::Ed25519VerifierProvenanceMismatch {
                expected: "abc".to_owned(),
                actual: "def".to_owned(),
            },
            SaError::Ed25519VerifierSha256Drift {
                network: "Test SDF Network ; September 2015".to_owned(),
                recorded: "abc".to_owned(),
                attempted: "def".to_owned(),
            },
            SaError::SpendingLimitPolicyProvenanceMismatch {
                expected: "abc".to_owned(),
                actual: "def".to_owned(),
            },
            SaError::SpendingLimitPolicySha256Drift {
                network: "Test SDF Network ; September 2015".to_owned(),
                recorded: "abc".to_owned(),
                attempted: "def".to_owned(),
            },
            SaError::SpendingLimitInstallRefused {
                reason: "test".to_owned(),
            },
            SaError::SpendingLimitNotInstalled {
                rule_id: 1,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                request_id: "test-req-sl-001".to_owned(),
            },
            SaError::SpendingLimitPolicyIdentificationFailed {
                rule_id: 1,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                observed_wasm_hashes_summary: WasmHashSummary {
                    count: 2,
                    first_first8: Some([0xabu8; 8]),
                },
                request_id: "test-req-sl-002".to_owned(),
            },
            SaError::SimpleThresholdInstallRefused {
                reason: "test".to_owned(),
            },
            SaError::WeightedThresholdInstallRefused {
                reason: "test".to_owned(),
            },
            SaError::SimpleThresholdPolicyProvenanceMismatch {
                expected: "abc".to_owned(),
                actual: "def".to_owned(),
            },
            SaError::SimpleThresholdPolicySha256Drift {
                network: "Test SDF Network ; September 2015".to_owned(),
                recorded: "abc".to_owned(),
                attempted: "def".to_owned(),
            },
            SaError::WeightedThresholdPolicyProvenanceMismatch {
                expected: "abc".to_owned(),
                actual: "def".to_owned(),
            },
            SaError::WeightedThresholdPolicySha256Drift {
                network: "Test SDF Network ; September 2015".to_owned(),
                recorded: "abc".to_owned(),
                attempted: "def".to_owned(),
            },
            SaError::WeightedThresholdNotInstalled {
                rule_id: 1,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                request_id: "test-req-wt-001".to_owned(),
            },
            SaError::WeightedThresholdPolicyIdentificationFailed {
                rule_id: 1,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                observed_wasm_hashes_summary: WasmHashSummary {
                    count: 2,
                    first_first8: Some([0xabu8; 8]),
                },
                request_id: "test-req-wt-002".to_owned(),
            },
            SaError::BatchSignerAddRefused {
                reason: "test".to_owned(),
            },
            SaError::NetworksTomlIo {
                source: io::Error::other("mock io error"),
                path: PathBuf::from("/mock/path"),
            },
            SaError::AuditWriterIo {
                detail: "mock io error".to_owned(),
                path: PathBuf::from("/mock/path/audit/default.jsonl"),
            },
            SaError::NetworksTomlParse {
                source: toml::from_str::<toml::Value>("invalid = ").unwrap_err(),
                path: PathBuf::from("/mock/path"),
            },
            SaError::ThresholdPolicyNotInstalled {
                rule_id: 1,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                request_id: "test-req-002".to_owned(),
            },
            SaError::SignerSetMissingBaseline {
                rule_id: 2,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                request_id: "test-req-003".to_owned(),
            },
            SaError::SignerSetBaselineLegacy {
                rule_id: 2,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                request_id: "test-req-legacy-002".to_owned(),
            },
            SaError::BaselineWriteFailed {
                rule_id: 2,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                tx_hash: Some("ef".repeat(32)),
                stage: BASELINE_WRITE_STAGE_OBSERVE,
                reason: "network.rpc_divergence: views differ".to_owned(),
                request_id: "test-req-bwf-002".to_owned(),
            },
            SaError::InstallStateMismatch {
                rule_id: None,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                tx_hash: "cd".repeat(32),
                request_id: "test-req-ism-003".to_owned(),
            },
            SaError::SignersManagerNotConfigured {
                rule_id: Some(7),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                request_id: "test-req-manager-001".to_owned(),
            },
            SaError::ThresholdPolicyIdentificationFailed {
                rule_id: 3,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                observed_wasm_hashes_summary: WasmHashSummary {
                    count: 1,
                    first_first8: Some([0xabu8; 8]),
                },
                request_id: "test-req-004".to_owned(),
            },
            SaError::NetworkRpcDivergence {
                rule_id: Some(4),
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                primary_view_digest_first8: "aabbccdd".to_owned(),
                secondary_view_digest_first8: "11223344".to_owned(),
                request_id: "test-req-005".to_owned(),
            },
            SaError::ThresholdReadFailed {
                rule_id: 5,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                source_kind: "primary",
                request_id: "test-req-006".to_owned(),
            },
            SaError::AuditLog(VerifyError::ChainBroken {
                line: 0,
                file: "test.jsonl".to_owned(),
                reason: "mock chain break",
            }),
            // Verifier diversification.
            SaError::VerifierDiversificationRequired {
                rule_id: 1,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                verifier_hash_first8: "deadbeef".to_owned(),
                observed_value_threshold_stroops: 100_000_000_000,
                request_id: "req-div-req-001".to_owned(),
            },
            SaError::VerifierWasmRevoked {
                rule_id: 2,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                verifier_hash_first8: "cafebabe".to_owned(),
                revoked_reason: "critical vulnerability in signature verification".to_owned(),
                request_id: "req-rev-001".to_owned(),
            },
            SaError::VerifierWasmRetired {
                rule_id: 3,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                verifier_hash_first8: "11223344".to_owned(),
                request_id: "req-ret-001".to_owned(),
            },
            SaError::VerifierMigrationFailed {
                phase: "preflight_destination_unknown",
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                detail: "destination hash not in VERIFIER_ALLOWLIST".to_owned(),
                request_id: "req-mig-001".to_owned(),
            },
            SaError::VerifierAllowlistEmpty {
                request_id: "req-empty-001".to_owned(),
            },
            // Session-rule horizon enforcement.
            SaError::HorizonExceeded {
                rule_id_or_pending: None,
                requested_horizon: 2_000,
                max_horizon: 1_000,
            },
            // Submit-check surface.
            SaError::SubmitCheckMissing {
                required_check: "multicall",
                host_function_kind: "InvokeContract",
            },
            // Multicall host-side surface.
            SaError::MulticallFailed {
                phase: "build",
                redacted_reason: "bundle empty".to_owned(),
                post_submit_kind: None,
            },
            SaError::MulticallSha256Drift {
                attempted: "aabbccdd".to_owned(),
                expected: "267e94a0".to_owned(),
                existing: None,
            },
            SaError::MulticallRegistryEntryNotFound {
                network_safename: "test-sdf-network---september-2015".to_owned(),
            },
            // Upgrade timelock surface.
            SaError::TimelockScheduleFailed {
                failure_reason: TimelockScheduleFailureReason::Unauthorized,
                redacted_reason: "proposer does not hold PROPOSER_ROLE".to_owned(),
                request_id: "test-req-tl-sched-001".to_owned(),
            },
            SaError::TimelockCancelFailed {
                failure_reason: TimelockCancelFailureReason::OperationNotScheduled,
                redacted_reason: "operation not found on-chain".to_owned(),
                operation_id_redacted: "deadbeef...cafebabe".to_owned(),
                request_id: "test-req-tl-cancel-001".to_owned(),
            },
            SaError::TimelockExecuteFailed {
                failure_reason: TimelockExecuteFailureReason::InvalidOperationState,
                redacted_reason: "operation already executed".to_owned(),
                operation_id_redacted: "deadbeef...cafebabe".to_owned(),
                request_id: "test-req-tl-exec-001".to_owned(),
            },
            // list_pending RPC failure.
            SaError::TimelockListPendingFailed {
                redacted_reason: "primary RPC unreachable".to_owned(),
            },
            // Simulation-audit mismatch.
            SaError::AuthMismatch {
                reason: AuthMismatchReason::EntryMutated,
            },
        ];

        // Verify each variant's wire_code matches the exhaustive closed set.
        let expected_codes = [
            "sa.threshold_unreachable",
            "sa.verifier_hash_drift",
            "sa.policy_hash_drift",
            "sa.multiple_pinned_hashes_unsupported",
            "sa.pinned_policy_absent",
            "sa.pinned_verifier_absent",
            "sa.pin_check_unavailable",
            "sa.verifier_mutable",
            "sa.policy_mutable",
            "sa.contract_instance_unsupported",
            "sa.verifier_wasm_not_in_allowlist",
            "sa.policy_wasm_not_in_allowlist",
            "sa.rule_id_mismatch",
            "simulation.divergence.context_rule_ids",
            "simulation.divergence.auth_contexts",
            "simulation.divergence.network",
            "simulation.divergence.sequence",
            "simulation.divergence.fee_envelope",
            "sa.signer_set_diverged",
            "sa.context_rule_caps_exceeded",
            "sa.rule_expired",
            "sa.deployment_failed",
            "sa.scaddress_encoding_failed",
            "sa.auth_entry_construction_failed",
            "sa.webauthn_assertion_invalid:wrong_type",
            "sa.webauthn_assertion_invalid:challenge_mismatch",
            "sa.webauthn_assertion_invalid:wrong_rp_id",
            "sa.webauthn_assertion_invalid:auth_data_too_short",
            "sa.webauthn_assertion_invalid:up_unset",
            "sa.webauthn_assertion_invalid:uv_unset",
            "sa.webauthn_assertion_invalid:be_bs_invalid",
            "sa.webauthn_assertion_invalid:signature_invalid",
            "sa.webauthn_assertion_invalid:malformed_client_data_json",
            "sa.webauthn_verifier_provenance_mismatch",
            "sa.webauthn_verifier_sha256_drift",
            "sa.ed25519_verifier_provenance_mismatch",
            "sa.ed25519_verifier_sha256_drift",
            "sa.spending_limit_policy_provenance_mismatch",
            "sa.spending_limit_policy_sha256_drift",
            "sa.spending_limit_install_refused",
            "sa.spending_limit_not_installed",
            "sa.spending_limit_policy_identification_failed",
            "sa.simple_threshold_install_refused",
            "sa.weighted_threshold_install_refused",
            "sa.simple_threshold_policy_provenance_mismatch",
            "sa.simple_threshold_policy_sha256_drift",
            "sa.weighted_threshold_policy_provenance_mismatch",
            "sa.weighted_threshold_policy_sha256_drift",
            "sa.weighted_threshold_not_installed",
            "sa.weighted_threshold_policy_identification_failed",
            "sa.batch_signer_add_refused",
            "sa.networks_toml_io",
            "sa.audit_writer_io",
            "sa.networks_toml_parse",
            "sa.threshold_policy_not_installed",
            "sa.signer_set_missing_baseline",
            "sa.signer_set_baseline_legacy",
            "sa.baseline_write_failed",
            "sa.install_state_mismatch",
            "sa.signers_manager_not_configured",
            "sa.threshold_policy_identification_failed",
            "network.rpc_divergence",
            "sa.threshold_read_failed",
            "sa.audit_log",
            // Verifier diversification.
            "sa.verifier_diversification_required",
            "sa.verifier_wasm_revoked",
            "sa.verifier_wasm_retired",
            "sa.verifier_migration_failed",
            "sa.verifier_allowlist_empty",
            // Session-rule horizon enforcement.
            "sa.horizon_exceeded",
            // Submit check enforcement.
            "sa.submit_check_missing",
            // Multicall host-side surface.
            "sa.multicall_failed",
            "sa.multicall_sha256_drift",
            "sa.multicall_registry_entry_not_found",
            // Upgrade timelock surface.
            "sa.timelock_schedule_failed",
            "sa.timelock_cancel_failed",
            "sa.timelock_execute_failed",
            // list_pending read-path error.
            "sa.timelock_list_pending_failed",
            // Simulation-audit mismatch.
            "sa.auth_mismatch",
        ];

        assert_eq!(
            variants.len(),
            expected_codes.len(),
            "variant count must equal expected code count"
        );

        let mut seen = std::collections::HashSet::new();
        for (variant, expected_code) in variants.iter().zip(expected_codes.iter()) {
            let actual_code = variant.wire_code();
            assert_eq!(
                actual_code, *expected_code,
                "wire_code ordering mismatch: got {actual_code}, expected {expected_code}"
            );
            assert!(
                seen.insert(actual_code),
                "duplicate wire code in closed set: {actual_code}"
            );
        }

        assert_eq!(seen.len(), 79, "closed set must have exactly 79 wire codes");
    }

    /// Verifies the sub-code closed set is exhaustively matched by tests.
    ///
    /// Adding a new `SimulationDivergenceSubCode` variant without extending this
    /// match produces a non-exhaustive-pattern compile error.
    #[test]
    fn simulation_divergence_subcode_exhaustiveness_guard() {
        let sub_codes = [
            SimulationDivergenceSubCode::ContextRuleIds,
            SimulationDivergenceSubCode::AuthContexts,
            SimulationDivergenceSubCode::Network,
            SimulationDivergenceSubCode::Sequence,
            SimulationDivergenceSubCode::FeeEnvelope,
        ];

        for sub_code in &sub_codes {
            let stable_name = match sub_code {
                SimulationDivergenceSubCode::ContextRuleIds => "context_rule_ids",
                SimulationDivergenceSubCode::AuthContexts => "auth_contexts",
                SimulationDivergenceSubCode::Network => "network",
                SimulationDivergenceSubCode::Sequence => "sequence",
                SimulationDivergenceSubCode::FeeEnvelope => "fee_envelope",
            };
            assert!(!stable_name.is_empty());
        }
    }

    /// Verifies that every `phase` literal the deployment module emits is in the
    /// canonical 7-value closed set, and that the canonical set has exactly 7 entries.
    ///
    /// Imports `deployment::ALL_EMITTED_PHASES` (the compile-time inventory
    /// maintained alongside the substance code) and asserts each entry is a known
    /// phase. A typo'd `phase: "deplooy"` registered in `ALL_EMITTED_PHASES` will
    /// fail here; a new emit site added without registration in
    /// `ALL_EMITTED_PHASES` surfaces at code review against the diff.
    ///
    /// `pub(crate)` on `ALL_EMITTED_PHASES` is correct — it is consumed only by
    /// this in-crate `#[cfg(test)]` module, not by external integration tests, so
    /// no `#[cfg(any(test, feature = "test-helpers"))]` gate is required.
    #[test]
    fn phase_string_constant_set_is_closed() {
        /// Canonical 7-value closed set for `SaError::DeploymentFailed::phase`.
        /// MUST match the rustdoc enumeration on the variant verbatim.
        const KNOWN_PHASES: &[&str] = &[
            "build",
            "simulate",
            "upload",
            "deploy",
            "constructor",
            "submit",
            "post_deploy_verification",
        ];

        // Assert every literal the deployment module COULD emit is in the
        // canonical KNOWN_PHASES set.
        use crate::deployment::ALL_EMITTED_PHASES;
        for emitted in ALL_EMITTED_PHASES {
            assert!(
                KNOWN_PHASES.contains(emitted),
                "deployment module emits phase {emitted:?} which is not in canonical set"
            );
        }

        // Also assert the canonical set itself has the documented size.
        assert_eq!(KNOWN_PHASES.len(), 7, "canonical phase set is 7 values");

        // Assert ALL_EMITTED_PHASES covers the full canonical set at substance
        // completion (fewer would mean the substance code omits a phase path).
        assert!(
            ALL_EMITTED_PHASES.len() >= 7,
            "deployment module should emit all 7 canonical phases at substance completion"
        );
    }

    /// All `AdminOrOwnerKey` variants that production code can emit.
    /// Includes canonical storage keys and instance-probe failures.
    const ALL_EMITTED_ADMIN_OR_OWNER_KEYS: &[&str] = &[
        "Admin",
        "Owner",
        "undecodable instance",
        "non-Wasm executable",
        "owner-managed external reference",
        "external reference with no live tag entry",
        "executable changed during install",
    ];

    #[test]
    fn admin_or_owner_key_constant_set_is_closed() {
        let rendered: Vec<String> = [
            AdminOrOwnerKey::Admin,
            AdminOrOwnerKey::Owner,
            AdminOrOwnerKey::UndecodableInstance,
            AdminOrOwnerKey::NonWasmExecutable,
            AdminOrOwnerKey::ExternalRefExecutable,
            AdminOrOwnerKey::ExternalRefUnresolved,
            AdminOrOwnerKey::ExecutableChanged,
        ]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
        let expected: Vec<String> = ALL_EMITTED_ADMIN_OR_OWNER_KEYS
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(
            rendered, expected,
            "mutability reason Display output must match the emitted reason set"
        );
    }

    /// Storage keys and a resolved external reference are overridable
    /// mutability findings; instance shapes with no code to pin are not.
    #[test]
    fn admin_or_owner_key_unpinnable_instance_covers_probe_failures_only() {
        assert!(!AdminOrOwnerKey::Admin.is_unpinnable_instance());
        assert!(!AdminOrOwnerKey::Owner.is_unpinnable_instance());
        assert!(!AdminOrOwnerKey::ExternalRefExecutable.is_unpinnable_instance());
        assert!(AdminOrOwnerKey::UndecodableInstance.is_unpinnable_instance());
        assert!(AdminOrOwnerKey::NonWasmExecutable.is_unpinnable_instance());
        assert!(AdminOrOwnerKey::ExternalRefUnresolved.is_unpinnable_instance());
        assert!(AdminOrOwnerKey::ExecutableChanged.is_unpinnable_instance());
    }

    /// Verifies that every `stage: "<literal>"` emit site in the crate's
    /// production source files is registered in `ALL_AUTH_ENTRY_STAGES`.
    ///
    /// The test walks all `src/**/*.rs` files from `CARGO_MANIFEST_DIR` at
    /// test time, extracts every `stage: "<literal>"` occurrence outside
    /// comment lines, skips lines that appear inside `#[cfg(test)]`-annotated
    /// blocks (tracked via a conservative brace-depth counter seeded when
    /// `mod tests {` or a `#[cfg(test)]`+`{` combination is detected), and
    /// asserts each remaining literal is present in `ALL_AUTH_ENTRY_STAGES`.
    /// Any stray literal is named in the failure message. This makes the test
    /// self-enforcing: a new emit site that omits its stage value from
    /// `ALL_AUTH_ENTRY_STAGES` causes the test to fail with the exact
    /// undocumented literal.
    ///
    /// Detection strategy: when either `mod tests {` appears on a single line
    /// or `#[cfg(test` is seen followed (eventually) by a line containing `{`,
    /// the brace depth counter is seeded with the net `{`-count of that
    /// trigger line. Depth decrements with each `}` and increments with each
    /// `{` until depth reaches zero again. Lines at depth > 0 are skipped.
    #[test]
    fn auth_entry_stage_string_constant_set_is_closed() {
        use std::fs;
        use std::path::Path;

        /// Recursively collect all `.rs` files under `dir`.
        fn collect_rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    collect_rs_files(&path, out);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }

        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let src_dir = Path::new(manifest_dir).join("src");

        let mut rs_files = Vec::new();
        collect_rs_files(&src_dir, &mut rs_files);
        assert!(!rs_files.is_empty(), "no .rs files found under src/");

        // Collect all stage literals found in production (non-test) code.
        let mut stray_literals: Vec<String> = Vec::new();

        for file_path in &rs_files {
            let content = fs::read_to_string(file_path).unwrap_or_default();

            // Build a per-line view annotated with brace depth.
            // `test_depth` tracks how many brace levels deep we are inside a
            // test-only block. Lines at test_depth > 0 are skipped.
            let mut test_depth: i64 = 0;
            // `pending_cfg_test` is set when we see `#[cfg(test` without a `{`
            // on the same line; the NEXT line that opens a brace seeds the depth.
            let mut pending_cfg_test = false;

            for raw_line in content.lines() {
                let trimmed = raw_line.trim();

                // Count net brace delta on this line (ignoring string literals
                // for our conservative heuristic — false positives are safe).
                let opens = trimmed.chars().filter(|&c| c == '{').count() as i64;
                let closes = trimmed.chars().filter(|&c| c == '}').count() as i64;
                let net = opens - closes;

                // Detect test-context entry points:
                // 1. `mod tests {` (or `mod test {`) on the same line — common pattern.
                // 2. `#[cfg(test` annotation line.
                let is_mod_tests_open = (trimmed.contains("mod tests")
                    || trimmed.contains("mod test"))
                    && trimmed.contains('{');
                let is_cfg_test_attr = trimmed.contains("#[cfg(test");

                if is_mod_tests_open {
                    // Enter the test block; seed depth with the net brace count
                    // of this line so we exit at the matching `}`.
                    test_depth += net.max(1);
                    pending_cfg_test = false;
                    continue; // The `mod tests {` line itself is not code.
                }

                if is_cfg_test_attr {
                    pending_cfg_test = true;
                    // Do not count braces yet — the annotation itself has none.
                    continue;
                }

                if pending_cfg_test {
                    // This line follows a `#[cfg(test` annotation.
                    // If it opens a block, enter the test context.
                    if opens > 0 {
                        test_depth += net.max(1);
                        pending_cfg_test = false;
                        continue;
                    } else if !trimmed.is_empty() && !trimmed.starts_with("//") {
                        // Non-block line (e.g. `#[test]` between attr and fn).
                        // Keep pending until we see the block open.
                        // But reset if we see another non-test, non-empty line.
                        if !trimmed.starts_with("#[") {
                            pending_cfg_test = false;
                        }
                    }
                }

                if test_depth > 0 {
                    // Adjust depth and skip.
                    test_depth += net;
                    if test_depth < 0 {
                        test_depth = 0;
                    }
                    continue;
                }

                // Outside any test block. Skip comment lines — they are never
                // production emit sites.
                if trimmed.starts_with("//") {
                    continue;
                }

                // Scan for `stage: "<literal>"` in this production line.
                let mut search = trimmed;
                while let Some(pos) = search.find("stage: \"") {
                    let after = &search[pos + 8..];
                    if let Some(end) = after.find('"') {
                        let literal = &after[..end];
                        // Skip empty strings and obvious placeholder text
                        // (angle brackets, ellipses, spaces, slashes).
                        if !literal.is_empty()
                            && !literal.contains(' ')
                            && !literal.contains('/')
                            && !literal.contains('<')
                            && !literal.contains('.')
                            && !ALL_AUTH_ENTRY_STAGES.contains(&literal)
                        {
                            stray_literals.push(format!("{}: {}", file_path.display(), literal));
                        }
                        search = &search[pos + 8 + end + 1..];
                    } else {
                        break;
                    }
                }
            }
        }

        assert!(
            stray_literals.is_empty(),
            "production source files contain stage literals not in ALL_AUTH_ENTRY_STAGES:\n{}",
            stray_literals.join("\n")
        );

        // Also assert that ALL_AUTH_ENTRY_STAGES has the expected 17 entries
        // so a silent truncation of the const is caught.
        assert_eq!(
            ALL_AUTH_ENTRY_STAGES.len(),
            17,
            "ALL_AUTH_ENTRY_STAGES must contain exactly 17 entries"
        );
    }

    // ── Signer-set and audit-log variant tests ────────────────────────────────

    /// Constructs `SignerSetDiverged` with a non-trivial `ObservedSignerSet`
    /// (3 signers: Ed25519 + External + WebAuthn variants), asserts the
    /// wire code, and verifies a serde round-trip.
    #[test]
    fn signer_set_diverged_round_trip_with_observed_signer_set() {
        let expected = ObservedSignerSet {
            signer_count: 3,
            threshold: 2,
            signer_ids: vec![0, 1, 2],
            signer_pubkeys: vec![
                SignerPubkey::Ed25519 {
                    pubkey: [0xaau8; 32],
                },
                SignerPubkey::External {
                    verifier_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
                        .to_owned(),
                    key_data_first16: [0xbbu8; 16],
                },
                SignerPubkey::WebAuthn {
                    credential_id_first16: [0xccu8; 16],
                },
            ],
        };
        let observed = ObservedSignerSet {
            signer_count: 2,
            threshold: 2,
            signer_ids: vec![0, 1],
            signer_pubkeys: vec![
                SignerPubkey::Ed25519 {
                    pubkey: [0xaau8; 32],
                },
                SignerPubkey::External {
                    verifier_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
                        .to_owned(),
                    key_data_first16: [0xbbu8; 16],
                },
            ],
        };
        let err = SaError::SignerSetDiverged {
            rule_id: 7,
            expected: SignerSetView::V1(expected.clone()),
            observed: SignerSetView::V1(observed.clone()),
            tx_hash: None,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            request_id: "req-test-ssd".to_owned(),
        };
        assert_eq!(err.wire_code(), "sa.signer_set_diverged");

        let json = serde_json::to_string(&err).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value.get("wire_code").and_then(|v| v.as_str()),
            Some("sa.signer_set_diverged")
        );
        let ctx = value.get("context").unwrap();
        assert_eq!(ctx.get("rule_id").and_then(|v| v.as_u64()), Some(7));
        assert_eq!(ctx["expected"]["version"], "v1", "{json}");
        assert_eq!(ctx["expected"]["signer_count"], 3, "{json}");
        assert_eq!(ctx["observed"]["version"], "v1", "{json}");
        assert_eq!(ctx["observed"]["signer_count"], 2, "{json}");
        assert!(
            ctx.get("tx_hash").is_none(),
            "an absent transaction hash is omitted: {json}"
        );
        let message = err.to_string();
        assert!(
            message.contains("expected v1 count=3 threshold=2, observed v1 count=2 threshold=2;"),
            "{message}"
        );
        assert!(!message.contains("after transaction"), "{message}");
        assert!(
            message.contains("'smart-account signers list --rule-id 7'"),
            "{message}"
        );
        assert!(
            message.contains("'smart-account signers refresh --rule-id 7 --accept-divergence'"),
            "{message}"
        );
    }

    /// A version-2 `SignerSetDiverged` after a confirmed transaction carries
    /// the hash on the wire and in its Display, and renders an absent
    /// threshold as `none`.
    #[test]
    fn signer_set_diverged_after_a_transaction_names_the_hash() {
        let snapshot = |threshold: Option<u32>| SignerSetSnapshotV2 {
            signers: vec![SignerEntryV2 {
                id: 0,
                identity: SignerIdentityV2::Ed25519 { pubkey: [0x11; 32] },
            }],
            threshold: threshold.map(|threshold| ThresholdObservation {
                policy: [0x22; 32],
                threshold,
            }),
        };
        let hash = "ab".repeat(32);
        let err = SaError::SignerSetDiverged {
            rule_id: 2,
            expected: SignerSetView::V2(snapshot(Some(1))),
            observed: SignerSetView::V2(snapshot(None)),
            tx_hash: Some(hash.clone()),
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            request_id: "req-test-ssd-v2".to_owned(),
        };
        let value = serde_json::to_value(&err).unwrap();
        assert_eq!(value["context"]["tx_hash"], hash.as_str());
        assert_eq!(value["context"]["expected"]["version"], "v2");
        assert_eq!(
            value["context"]["observed"]["threshold"],
            serde_json::Value::Null
        );
        let message = err.to_string();
        assert!(
            message.contains(&format!(
                "expected v2 count=1 threshold=1, observed v2 count=1 threshold=none \
                 after transaction {hash};"
            )),
            "{message}"
        );
    }

    /// The legacy-baseline refusal names the refresh command for its rule.
    #[test]
    fn signer_set_baseline_legacy_names_the_refresh_command() {
        let err = SaError::SignerSetBaselineLegacy {
            rule_id: 9,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            request_id: "req-legacy".to_owned(),
        };
        assert_eq!(err.wire_code(), "sa.signer_set_baseline_legacy");
        let message = err.to_string();
        assert!(message.contains("is version 1"), "{message}");
        assert!(
            message.contains("'smart-account signers refresh --rule-id 9'"),
            "{message}"
        );
    }

    /// `BaselineWriteFailed` names its stage, the transaction when present
    /// and the refresh command that records the chain state; the hash is
    /// omitted from the wire when absent.
    #[test]
    fn baseline_write_failed_names_stage_transaction_and_recovery() {
        let failed = |tx_hash: Option<String>| SaError::BaselineWriteFailed {
            rule_id: 5,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            tx_hash,
            stage: BASELINE_WRITE_STAGE_WRITE,
            reason: "audit writer poisoned".to_owned(),
            request_id: "req-bwf".to_owned(),
        };
        let hash = "cd".repeat(32);
        let with_hash = failed(Some(hash.clone()));
        let message = with_hash.to_string();
        assert!(
            message.contains(&format!(
                "was not recorded after transaction {hash}: write failed"
            )),
            "{message}"
        );
        assert!(
            message.contains("'smart-account signers refresh --rule-id 5 --accept-divergence'"),
            "{message}"
        );
        assert_eq!(
            serde_json::to_value(&with_hash).unwrap()["context"]["tx_hash"],
            hash.as_str()
        );
        let without_hash = failed(None);
        assert!(!without_hash.to_string().contains("after transaction"));
        assert!(
            serde_json::to_value(&without_hash).unwrap()["context"]
                .get("tx_hash")
                .is_none()
        );
    }

    /// The observe-stage reason leads with the inner wire code and is capped.
    #[test]
    fn baseline_observe_reason_carries_the_inner_code_and_is_capped() {
        let inner = SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: "x".repeat(4 * BASELINE_WRITE_REASON_MAX_BYTES),
        };
        let reason = baseline_observe_reason(&inner);
        assert!(reason.starts_with("sa.deployment_failed: "), "{reason}");
        assert!(reason.len() <= BASELINE_WRITE_REASON_MAX_BYTES);
        assert!(reason.ends_with("..."));
    }

    /// The `BaselineWriteFailed` stage set is closed: exactly `observe` and
    /// `write`, and every production construction of the variant in this
    /// crate takes its stage from a named stage constant, never a string
    /// literal outside that set.
    #[test]
    fn baseline_write_stage_set_is_closed() {
        assert_eq!(BASELINE_WRITE_STAGES, ["observe", "write"]);

        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut constructions = 0usize;
        let mut stack = vec![src];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap().replace('\r', "");
                let production: Vec<&str> = text
                    .lines()
                    .take_while(|line| line.trim() != "#[cfg(test)]")
                    .collect();
                for (i, line) in production.iter().enumerate() {
                    if !line.contains("SaError::BaselineWriteFailed {") || line.contains("..") {
                        continue;
                    }
                    constructions += 1;
                    let stage_line = production[i..]
                        .iter()
                        .find(|l| l.trim_start().starts_with("stage"))
                        .unwrap_or_else(|| panic!("{}:{}: no stage field", path.display(), i + 1));
                    assert!(
                        stage_line.contains("BASELINE_WRITE_STAGE_OBSERVE")
                            || stage_line.contains("BASELINE_WRITE_STAGE_WRITE"),
                        "{}:{}: stage must come from a stage constant: {stage_line}",
                        path.display(),
                        i + 1
                    );
                }
            }
        }
        assert!(
            constructions >= 2,
            "the production sources construct BaselineWriteFailed at both stages"
        );
    }

    /// Verifies that a `ThresholdPolicyNotInstalled` error round-trips via serde
    /// and has the correct wire code.
    #[test]
    fn threshold_policy_not_installed_round_trip() {
        let err = SaError::ThresholdPolicyNotInstalled {
            rule_id: 5,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            request_id: "req-abc".to_owned(),
        };
        assert_eq!(err.wire_code(), "sa.threshold_policy_not_installed");
        let json = serde_json::to_string(&err).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value.get("wire_code").and_then(|v| v.as_str()),
            Some("sa.threshold_policy_not_installed")
        );
    }

    /// The `ThresholdPolicyNotInstalled` hint names the REAL verb
    /// (`smart-account deploy-policy --kind simple-threshold`), not the
    /// phantom `smart-account deploy-threshold-policy` verb that never
    /// existed (issue #4's live half).
    #[test]
    fn threshold_policy_not_installed_hint_names_real_verb() {
        let err = SaError::ThresholdPolicyNotInstalled {
            rule_id: 5,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            request_id: "req-abc".to_owned(),
        };
        let message = err.to_string();
        assert!(
            message.contains("smart-account deploy-policy --kind simple-threshold"),
            "hint must name the real deploy verb, got: {message}"
        );
        assert!(
            !message.contains("deploy-threshold-policy"),
            "hint must not reference the phantom deploy-threshold-policy verb, got: {message}"
        );
    }

    /// Verifies that a `SignerSetMissingBaseline` error round-trips via serde
    /// and has the correct wire code.
    #[test]
    fn signer_set_missing_baseline_round_trip() {
        let err = SaError::SignerSetMissingBaseline {
            rule_id: 3,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            request_id: "req-def".to_owned(),
        };
        assert_eq!(err.wire_code(), "sa.signer_set_missing_baseline");
        let json = serde_json::to_string(&err).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value.get("wire_code").and_then(|v| v.as_str()),
            Some("sa.signer_set_missing_baseline")
        );
    }

    #[test]
    fn signers_manager_not_configured_round_trip() {
        let err = SaError::SignersManagerNotConfigured {
            rule_id: Some(11),
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            request_id: "req-manager".to_owned(),
        };
        assert_eq!(err.wire_code(), "sa.signers_manager_not_configured");
        let json = serde_json::to_string(&err).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value.get("wire_code").and_then(|v| v.as_str()),
            Some("sa.signers_manager_not_configured")
        );
    }

    /// `SignersManagerNotConfigured` keeps the bare rule number on the wire
    /// for a scoped rule and omits the key for an install; the Display
    /// renders the absent rule as `none`.
    #[test]
    fn signers_manager_not_configured_rule_id_is_optional() {
        let err = |rule_id: Option<u32>| SaError::SignersManagerNotConfigured {
            rule_id,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            request_id: "req-manager".to_owned(),
        };

        let scoped = serde_json::to_value(err(Some(7))).unwrap();
        assert_eq!(
            scoped["context"]["rule_id"],
            serde_json::json!(7),
            "{scoped}"
        );
        let install = serde_json::to_value(err(None)).unwrap();
        assert!(install["context"].get("rule_id").is_none(), "{install}");
        assert_eq!(install["context"]["request_id"], "req-manager", "{install}");

        assert_eq!(
            err(Some(7)).to_string(),
            "signers manager not configured for smart-account manager operation on \
             rule_id=7 (smart_account=CAAAA...ZZZZZ)"
        );
        assert_eq!(
            err(None).to_string(),
            "signers manager not configured for smart-account manager operation on \
             rule_id=none (smart_account=CAAAA...ZZZZZ)"
        );
    }

    /// `InstallStateMismatch` names the confirmed transaction in both forms.
    /// With the rule id it names the rule in the inspect, delete and refresh
    /// commands; without it, it sends the operator to `rules list` first.
    /// The delete command authorizes under rule 0, because an unbaselined
    /// rule cannot authorize its own removal.
    #[test]
    fn install_state_mismatch_display_and_wire_shape_per_rule_id_form() {
        let hash = "ab".repeat(32);
        let err = |rule_id: Option<u32>| SaError::InstallStateMismatch {
            rule_id,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            tx_hash: hash.clone(),
            request_id: "req-ism".to_owned(),
        };

        let observed = err(Some(4)).to_string();
        assert_eq!(
            observed,
            format!(
                "install on CAAAA...ZZZZZ confirmed in transaction {hash} but the observed rule 4 \
                 does not match the authorized definition; the rule is not baselined; inspect it \
                 with 'smart-account rules get --rule-id 4' and either delete it with \
                 'smart-account rules delete --rule-id 4 --auth-rule-id 0' or accept it with \
                 'smart-account signers refresh --rule-id 4'"
            )
        );
        assert!(
            observed.contains("--rule-id 4 --auth-rule-id 0"),
            "{observed}"
        );

        let unread = err(None).to_string();
        assert_eq!(
            unread,
            format!(
                "install on CAAAA...ZZZZZ confirmed in transaction {hash} but the new rule's id \
                 could not be read; the rule is not baselined; find it with \
                 'smart-account rules list', then either delete it with \
                 'smart-account rules delete --rule-id N --auth-rule-id 0' or accept it with \
                 'smart-account signers refresh --rule-id N'"
            )
        );
        assert!(unread.contains("--rule-id N --auth-rule-id 0"), "{unread}");

        let with_id = serde_json::to_value(err(Some(4))).unwrap();
        assert_eq!(with_id["wire_code"], "sa.install_state_mismatch");
        assert_eq!(
            with_id["context"]["rule_id"],
            serde_json::json!(4),
            "{with_id}"
        );
        assert_eq!(with_id["context"]["tx_hash"], hash.as_str(), "{with_id}");
        let without_id = serde_json::to_value(err(None)).unwrap();
        assert!(
            without_id["context"].get("rule_id").is_none(),
            "{without_id}"
        );
        assert_eq!(
            without_id["context"]["tx_hash"],
            hash.as_str(),
            "{without_id}"
        );
    }

    /// Verifies that a `ThresholdPolicyIdentificationFailed` error round-trips
    /// via serde and has the correct wire code.
    #[test]
    fn threshold_policy_identification_failed_round_trip() {
        let err = SaError::ThresholdPolicyIdentificationFailed {
            rule_id: 2,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            observed_wasm_hashes_summary: WasmHashSummary {
                count: 2,
                first_first8: Some([0x11u8; 8]),
            },
            request_id: "req-ghi".to_owned(),
        };
        assert_eq!(err.wire_code(), "sa.threshold_policy_identification_failed");
        let json = serde_json::to_string(&err).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value.get("wire_code").and_then(|v| v.as_str()),
            Some("sa.threshold_policy_identification_failed")
        );
    }

    /// Verifies that a `SpendingLimitNotInstalled` error round-trips via
    /// serde and has the correct wire code.
    #[test]
    fn spending_limit_not_installed_round_trip() {
        let err = SaError::SpendingLimitNotInstalled {
            rule_id: 5,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            request_id: "req-sl-001".to_owned(),
        };
        assert_eq!(err.wire_code(), "sa.spending_limit_not_installed");
        let json = serde_json::to_string(&err).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value.get("wire_code").and_then(|v| v.as_str()),
            Some("sa.spending_limit_not_installed")
        );
        let ctx = value.get("context").unwrap();
        assert_eq!(ctx.get("rule_id").and_then(|v| v.as_u64()), Some(5));
    }

    /// Verifies that a `SpendingLimitPolicyIdentificationFailed` error
    /// round-trips via serde and has the correct wire code.
    #[test]
    fn spending_limit_policy_identification_failed_round_trip() {
        let err = SaError::SpendingLimitPolicyIdentificationFailed {
            rule_id: 2,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            observed_wasm_hashes_summary: WasmHashSummary {
                count: 2,
                first_first8: Some([0x11u8; 8]),
            },
            request_id: "req-sl-002".to_owned(),
        };
        assert_eq!(
            err.wire_code(),
            "sa.spending_limit_policy_identification_failed"
        );
        let json = serde_json::to_string(&err).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value.get("wire_code").and_then(|v| v.as_str()),
            Some("sa.spending_limit_policy_identification_failed")
        );
    }

    /// Verifies that a `WeightedThresholdNotInstalled` error round-trips via
    /// serde and has the correct wire code.
    #[test]
    fn weighted_threshold_not_installed_round_trip() {
        let err = SaError::WeightedThresholdNotInstalled {
            rule_id: 5,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            request_id: "req-wt-001".to_owned(),
        };
        assert_eq!(err.wire_code(), "sa.weighted_threshold_not_installed");
        let json = serde_json::to_string(&err).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value.get("wire_code").and_then(|v| v.as_str()),
            Some("sa.weighted_threshold_not_installed")
        );
        let ctx = value.get("context").unwrap();
        assert_eq!(ctx.get("rule_id").and_then(|v| v.as_u64()), Some(5));
    }

    /// Verifies that a `WeightedThresholdPolicyIdentificationFailed` error
    /// round-trips via serde and has the correct wire code.
    #[test]
    fn weighted_threshold_policy_identification_failed_round_trip() {
        let err = SaError::WeightedThresholdPolicyIdentificationFailed {
            rule_id: 2,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            observed_wasm_hashes_summary: WasmHashSummary {
                count: 2,
                first_first8: Some([0x11u8; 8]),
            },
            request_id: "req-wt-002".to_owned(),
        };
        assert_eq!(
            err.wire_code(),
            "sa.weighted_threshold_policy_identification_failed"
        );
        let json = serde_json::to_string(&err).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value.get("wire_code").and_then(|v| v.as_str()),
            Some("sa.weighted_threshold_policy_identification_failed")
        );
    }

    /// Verifies that a `NetworkRpcDivergence` error round-trips via serde
    /// and has the correct wire code.
    #[test]
    fn network_rpc_divergence_round_trip() {
        let err = SaError::NetworkRpcDivergence {
            rule_id: Some(1),
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            primary_view_digest_first8: "aabbccdd".to_owned(),
            secondary_view_digest_first8: "11223344".to_owned(),
            request_id: "req-jkl".to_owned(),
        };
        assert_eq!(err.wire_code(), "network.rpc_divergence");
        let json = serde_json::to_string(&err).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value.get("wire_code").and_then(|v| v.as_str()),
            Some("network.rpc_divergence")
        );
    }

    /// Verifies that `From<AuditLogIntegrityError>` routes to the `AuditLog`
    /// variant with wire code `sa.audit_log`.
    #[test]
    fn from_audit_log_integrity_error_routes_to_audit_log_variant() {
        let inner = VerifyError::ChainBroken {
            line: 42,
            file: "default.jsonl".to_owned(),
            reason: "hash mismatch",
        };
        let err: SaError = inner.into();
        assert_eq!(err.wire_code(), "sa.audit_log");
        assert!(matches!(err, SaError::AuditLog(_)));
    }

    /// Verifies that `From<SignerSetCanonicalBodyError>` routes through the
    /// `AuditLog` envelope with wire code `sa.audit_log` AND that the inner
    /// variant is `SignerSetCanonicalBody` (not `ParseError { line: 0 }`).
    ///
    /// The inner-variant distinction matters for forensic correlation:
    /// `ParseError` identifies JSON decode failure at a specific log line;
    /// `SignerSetCanonicalBody` identifies malformed canonical-body computation
    /// that has no associated log-line number.
    #[test]
    fn from_signer_set_canonical_body_error_routes_to_audit_log() {
        use stellar_agent_core::audit_log::verify::VerifyError;

        let inner =
            stellar_agent_core::audit_log::signer_set::SignerSetCanonicalBodyError::MalformedObservedSignerSet {
                reason: "signer_ids.len() != signer_pubkeys.len()",
            };
        let err: SaError = inner.into();
        assert_eq!(err.wire_code(), "sa.audit_log");
        // Inner must be SignerSetCanonicalBody, not ParseError { line: 0 }.
        assert!(
            matches!(
                err,
                SaError::AuditLog(VerifyError::SignerSetCanonicalBody(_))
            ),
            "inner must be VerifyError::SignerSetCanonicalBody: {err:?}"
        );

        // Also verify via InvalidVerifierContract path.
        let inner2 = stellar_agent_core::audit_log::signer_set::SignerSetCanonicalBodyError::InvalidVerifierContract {
            strkey: "not_a_valid_cstrkey".to_owned(),
            source: stellar_strkey::Contract::from_string("not_a_valid_cstrkey").unwrap_err(),
        };
        let err2: SaError = inner2.into();
        assert_eq!(err2.wire_code(), "sa.audit_log");
        assert!(
            matches!(
                err2,
                SaError::AuditLog(VerifyError::SignerSetCanonicalBody(_))
            ),
            "inner must be VerifyError::SignerSetCanonicalBody: {err2:?}"
        );
    }

    // ── Verifier diversification round-trip tests ─────────────────────────────

    /// Verifies that `VerifierDiversificationRequired` round-trips via serde
    /// and has the correct wire code.
    #[test]
    fn verifier_diversification_required_round_trip() {
        let err = SaError::VerifierDiversificationRequired {
            rule_id: 4,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            verifier_hash_first8: "deadbeef".to_owned(),
            observed_value_threshold_stroops: 200_000_000_000_i64,
            request_id: "req-div-rt-001".to_owned(),
        };
        assert_eq!(err.wire_code(), "sa.verifier_diversification_required");
        let json = serde_json::to_string(&err).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value.get("wire_code").and_then(|v| v.as_str()),
            Some("sa.verifier_diversification_required"),
            "wire_code must match: {json}"
        );
        let ctx = value.get("context").unwrap();
        assert_eq!(ctx.get("rule_id").and_then(|v| v.as_u64()), Some(4));
        assert!(ctx.get("smart_account_redacted").is_some());
        assert!(ctx.get("verifier_hash_first8").is_some());
        assert!(ctx.get("observed_value_threshold_stroops").is_some());
        assert!(ctx.get("request_id").is_some());
    }

    /// Verifies that the `Display` formatter maps
    /// `observed_value_threshold_stroops` sentinel to the literal
    /// `"undetermined"` text rather than emitting the bare numeric sentinel.
    #[test]
    fn verifier_diversification_required_display_maps_minus_one_to_undetermined() {
        let err = SaError::VerifierDiversificationRequired {
            rule_id: 7,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            verifier_hash_first8: String::new(),
            observed_value_threshold_stroops:
                crate::managers::diversification::DiversificationCheck::SENTINEL_OBSERVED_VALUE_THRESHOLD_STROOPS,
            request_id: "req-div-display-001".to_owned(),
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains("observed_value_threshold_stroops=undetermined"),
            "Display must render -1 as 'undetermined'; got: {rendered}"
        );
        assert!(
            !rendered.contains("observed_value_threshold_stroops=-1"),
            "Display must NOT leak the bare -1 sentinel; got: {rendered}"
        );
    }

    /// Verifies that `VerifierWasmRevoked` round-trips via serde and has the
    /// correct wire code.
    #[test]
    fn verifier_wasm_revoked_round_trip() {
        let err = SaError::VerifierWasmRevoked {
            rule_id: 2,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            verifier_hash_first8: "cafebabe".to_owned(),
            revoked_reason: "critical vulnerability in signature verification".to_owned(),
            request_id: "req-rev-rt-001".to_owned(),
        };
        assert_eq!(err.wire_code(), "sa.verifier_wasm_revoked");
        let json = serde_json::to_string(&err).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value.get("wire_code").and_then(|v| v.as_str()),
            Some("sa.verifier_wasm_revoked"),
            "wire_code must match: {json}"
        );
        let ctx = value.get("context").unwrap();
        assert_eq!(ctx.get("rule_id").and_then(|v| v.as_u64()), Some(2));
        assert!(ctx.get("revoked_reason").is_some());
        // revoked_reason value must be preserved verbatim.
        assert_eq!(
            ctx.get("revoked_reason").and_then(|v| v.as_str()),
            Some("critical vulnerability in signature verification"),
            "revoked_reason must round-trip: {json}"
        );
    }

    /// Verifies that `VerifierWasmRetired` round-trips via serde and has the
    /// correct wire code.
    #[test]
    fn verifier_wasm_retired_round_trip() {
        let err = SaError::VerifierWasmRetired {
            rule_id: 3,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            verifier_hash_first8: "11223344".to_owned(),
            request_id: "req-ret-rt-001".to_owned(),
        };
        assert_eq!(err.wire_code(), "sa.verifier_wasm_retired");
        let json = serde_json::to_string(&err).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value.get("wire_code").and_then(|v| v.as_str()),
            Some("sa.verifier_wasm_retired"),
            "wire_code must match: {json}"
        );
        let ctx = value.get("context").unwrap();
        assert_eq!(ctx.get("rule_id").and_then(|v| v.as_u64()), Some(3));
        assert!(ctx.get("verifier_hash_first8").is_some());
    }

    /// Verifies that `VerifierMigrationFailed` round-trips via serde and has
    /// the correct wire code. Also verifies all five closed-set phase values.
    #[test]
    fn verifier_migration_failed_round_trip() {
        for phase in MIGRATION_PHASES {
            let err = SaError::VerifierMigrationFailed {
                phase,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                detail: format!("test detail for phase {phase}"),
                request_id: "req-mig-rt-001".to_owned(),
            };
            assert_eq!(
                err.wire_code(),
                "sa.verifier_migration_failed",
                "wire_code mismatch for phase {phase}"
            );
            let json = serde_json::to_string(&err).unwrap();
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(
                value.get("wire_code").and_then(|v| v.as_str()),
                Some("sa.verifier_migration_failed"),
                "wire_code must match for phase {phase}: {json}"
            );
            let ctx = value.get("context").unwrap();
            assert_eq!(
                ctx.get("phase").and_then(|v| v.as_str()),
                Some(*phase),
                "phase must round-trip for {phase}: {json}"
            );
            assert!(ctx.get("smart_account_redacted").is_some());
            assert!(ctx.get("detail").is_some());
        }
    }

    /// Verifies that `VerifierAllowlistEmpty` round-trips via serde and has
    /// the correct wire code.
    #[test]
    fn verifier_allowlist_empty_round_trip() {
        let err = SaError::VerifierAllowlistEmpty {
            request_id: "req-empty-rt-001".to_owned(),
        };
        assert_eq!(err.wire_code(), "sa.verifier_allowlist_empty");
        let json = serde_json::to_string(&err).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value.get("wire_code").and_then(|v| v.as_str()),
            Some("sa.verifier_allowlist_empty"),
            "wire_code must match: {json}"
        );
        assert!(
            value.get("context").is_some(),
            "context field must be present: {json}"
        );
    }

    /// Verifies the `MIGRATION_PHASES` closed set has exactly 5 entries and
    /// covers the documented phase discriminators.
    ///
    /// Mirrors `phase_string_constant_set_is_closed` for `DeploymentFailed`.
    /// A typo'd phase literal registered in `MIGRATION_PHASES` will fail here.
    #[test]
    fn migration_phase_constant_set_is_closed() {
        /// Canonical 5-value closed set for `SaError::VerifierMigrationFailed::phase`.
        const KNOWN_MIGRATION_PHASES: &[&str] = &[
            "preflight_destination_unknown",
            "preflight_destination_mutable",
            "plan_build",
            "submit_simulate",
            "submit_send",
        ];

        for emitted in MIGRATION_PHASES {
            assert!(
                KNOWN_MIGRATION_PHASES.contains(emitted),
                "MIGRATION_PHASES contains phase {emitted:?} not in canonical set"
            );
        }

        assert_eq!(
            KNOWN_MIGRATION_PHASES.len(),
            5,
            "canonical migration-phase set is 5 values"
        );
        assert_eq!(
            MIGRATION_PHASES.len(),
            5,
            "MIGRATION_PHASES must have exactly 5 entries"
        );
    }
}
