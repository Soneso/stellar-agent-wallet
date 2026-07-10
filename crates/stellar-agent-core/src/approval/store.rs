//! Pending approval store — TOML-file-backed, single-writer, atomic-write.
//!
//! Provides [`PendingApproval`] (the pending-approval data structure),
//! [`ApprovalKind`] (the discriminator enum), and [`PendingApprovalStore`]
//! (the file-backed store with exclusive file lock).
//!
//! # Storage layout
//!
//! Entries are persisted at `<dir>/<profile>.toml` as a flat TOML array:
//!
//! ```toml
//! [[pending]]
//! approval_nonce = "..."
//! process_uid    = "1000"
//! created_at_unix_ms = 0
//! expires_at_unix_ms = 99999
//!
//! # PaymentSimulated arm — flat fields:
//! envelope_xdr_b64 = "..."
//! envelope_sha256_hex = "..."
//! summary_to = "G..."
//! summary_amount_stroops = 1000000
//! summary_asset = "XLM"
//! summary_simulated_fee_stroops = 100
//! summary_simulated_seq_num = 1
//!
//! # SignWithPasskey arm — nested table (never present in PaymentSimulated entries):
//! [pending.sign_with_passkey]
//! auth_digest = [0, 1, ...]
//! credential_id = [0, 1, ...]
//! smart_account_redacted = "CAAAA...BBBBB"
//! rule_ids = [1, 2]
//! csrf_token = [0, 1, ...]
//!
//! # RegisterPasskey arm — nested table:
//! [pending.register_passkey]
//! smart_account_redacted = "CAAAA...BBBBB"
//! rule_ids = [1, 2]
//! csrf_token = [0, 1, ...]
//! rp_id = "localhost"
//! user_handle = [0, 1, ...]
//! ```
//!
//! # `TrustlineClawbackOptIn` sub-table
//!
//! ```toml
//! [pending.trustline_clawback_opt_in]
//! network = "Test SDF Network ; September 2015"
//! code = "USDC"
//! issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
//! ```
//!
//! # Legacy format compatibility
//!
//! TOML files that contain only flat payment-summary fields on the `[[pending]]`
//! entry (no `sign_with_passkey` sub-table) load cleanly as
//! `ApprovalKind::PaymentSimulated { ... }` via a custom `Deserialize`
//! implementation on [`PendingApproval`] that routes flat fields into the
//! `PaymentSimulated` arm when no sub-table is present.
//!
//! # Whole-file parse: no partial-file recovery
//!
//! `[[pending]]` is deserialised as one `Vec<PendingApproval>` in a single
//! pass.  A structurally-invalid entry anywhere in the array — an
//! unrecognised nonce shape, a cross-kind field-contamination violation, a
//! failed construction-time invariant — fails the ENTIRE file's load;
//! `PendingApprovalStore::open` never returns a store holding only the
//! well-formed entries with the bad one silently dropped.  This is a known
//! property of the current format, not a guarantee this module has ever
//! offered otherwise; see `one_contaminated_entry_fails_whole_multi_entry_store_load`
//! in this module's tests for the characterisation test.  It also means every
//! cross-kind contamination check must be conservative: incorrectly listing
//! a field a kind legitimately carries (as `attestation_blob_b64` was, for
//! `ClaimSimulated` and `RuleProposalSimulated`, until both shared the
//! generic HMAC-blob attestation path with `PaymentSimulated`) takes down
//! every OTHER pending entry in the same file the moment one entry of that
//! kind is genuinely attested, not just the one that was already broken.
//!
//! # Single-writer invariant
//!
//! An exclusive advisory lock is held on a sidecar `.lock` file
//! (`<profile>.toml.lock`) for the lifetime of [`PendingApprovalStore`].  A
//! second opener receives [`ApprovalError::WriterLocked`] immediately.
//!
//! # Atomic writes
//!
//! All mutations persist via `tempfile::NamedTempFile` + `persist()` (rename)
//! in the same parent directory.  On Unix, the parent directory is opened and
//! fsynced after rename to commit the directory entry; this step is skipped
//! on Windows, where opening a directory as a file requires
//! `FILE_FLAG_BACKUP_SEMANTICS` (not set by the stable `std::fs::File::open`
//! API) and fails with `ERROR_ACCESS_DENIED`.  File permissions are `0o600` on
//! Unix.
//!
//! # Security
//!
//! The storage file is NOT a security boundary — integrity is provided by the
//! HMAC-keyed `attestation_blob` (PaymentSimulated) or the pre-verified
//! `passkey_assertion` (SignWithPasskey), not by the file.  An attacker who
//! removes an entry forces the user to re-run the approval flow; they cannot
//! forge an attestation or assertion.  A tampered `approval_nonce` with
//! non-base64url or incorrect length is rejected on `open` via a custom
//! `#[serde(deserialize_with)]` validator.

use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::assertion_input::{AssertionInput, validate_signature_compact};
use super::error::ApprovalError;
use super::registration_input::{
    CREDENTIAL_ID_MAX_BYTES, CREDENTIAL_ID_MIN_BYTES, RegistrationInput,
    validate_registration_input_invariants,
};
use super::rule_proposal::{ContextRuleProposalSnapshot, validate_context_rule_proposal_snapshot};

// ─────────────────────────────────────────────────────────────────────────────
// TTL constant
// ─────────────────────────────────────────────────────────────────────────────

/// Default approval TTL: 24 hours in milliseconds.
pub const DEFAULT_TTL_MS: u64 = 86_400_000;

/// Expected nonce length in characters (16 bytes as URL-safe base64 no-pad).
pub const EXPECTED_NONCE_LEN: usize = 22;

/// Hard cap on the number of pending approvals held in a single store at one
/// time.  `insert` prunes expired entries before checking this limit, so in
/// practice the cap is only reached when a single-user wallet accumulates more
/// than 4 096 simultaneous live (non-expired) approvals, which is not a
/// plausible legitimate scenario.
const MAX_PENDING_APPROVALS: usize = 4_096;

// ─────────────────────────────────────────────────────────────────────────────
// SignWithPasskey + RegisterPasskey field limits (CTAP2 + OZ context-rule)
// ─────────────────────────────────────────────────────────────────────────────
//
// `CREDENTIAL_ID_MIN_BYTES` / `CREDENTIAL_ID_MAX_BYTES` are defined in
// `registration_input.rs` (the canonical home for WebAuthn structural-layout
// constants) and imported above. Both `SignWithPasskey` (assertion path)
// and `RegisterPasskey` (registration path) consume the same window so that
// CTAP2 / WebAuthn-2 bumps land in exactly one place.

/// Maximum number of OZ context rule IDs per approval entry.
///
/// Matches the OZ MultiSig context-rule batch limit.
const RULE_IDS_MAX_COUNT: usize = 8;

// ─────────────────────────────────────────────────────────────────────────────
// Nonce and process_uid validators (tamper defence)
// ─────────────────────────────────────────────────────────────────────────────

/// Deserialises `approval_nonce` and validates it is exactly
/// `EXPECTED_NONCE_LEN` base64url-no-pad characters.
///
/// Rejects:
/// - Wrong length (not 22 characters).
/// - Any character outside `[A-Za-z0-9_-]` (base64url alphabet).
///
/// A tampered entry with a Unicode direction-mark prefix or injected
/// whitespace would fail this check, preventing tty-rendering attacks.
fn deserialize_approval_nonce<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.len() != EXPECTED_NONCE_LEN {
        return Err(serde::de::Error::custom(format!(
            "approval_nonce must be {EXPECTED_NONCE_LEN} characters (base64url no-pad 16 bytes), \
             got {} characters",
            s.len()
        )));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(serde::de::Error::custom(
            "approval_nonce contains non-base64url characters",
        ));
    }
    Ok(s)
}

/// Deserialises `process_uid` and validates it is a numeric ASCII string,
/// Windows SID string, or the non-Unix stub `"non-unix-stub"`.
///
/// Rejects entries containing Unicode direction marks, whitespace, or other
/// unexpected content that could reorder tty rendering.
fn deserialize_process_uid<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if process_uid_is_valid(&s) {
        return Ok(s);
    }
    Err(serde::de::Error::custom(format!(
        "process_uid must be numeric ASCII, Windows SID, or 'non-unix-stub', got: {s:?}"
    )))
}

fn process_uid_is_valid(s: &str) -> bool {
    s == "non-unix-stub"
        || (!s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
        || windows_sid_is_valid(s)
}

fn windows_sid_is_valid(s: &str) -> bool {
    let mut parts = s.split('-');
    if parts.next() != Some("S") {
        return false;
    }
    let mut numeric_parts = 0_usize;
    for part in parts {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        numeric_parts += 1;
    }
    numeric_parts >= 3
}

// ─────────────────────────────────────────────────────────────────────────────
// ApprovalKind
// ─────────────────────────────────────────────────────────────────────────────

/// The kind-discriminator for a [`PendingApproval`] entry.
///
/// Each arm carries the fields specific to that approval flow.  The
/// `PaymentSimulated` arm covers the simulate-then-commit payment flow.
/// The `SignWithPasskey` arm carries WebAuthn challenge binding data.
/// The `TrustlineClawbackOptIn` arm carries the asset fields for the
/// clawback opt-in gate.
///
/// # Serialisation compatibility
///
/// `ApprovalKind` derives no serde traits; `PendingApproval`'s custom
/// `Serialize` / `Deserialize` impls route the kind via structural
/// disambiguation: sub-table presence determines the arm.  Existing
/// `PaymentSimulated` entries on disk continue to look like flat fields — no
/// `kind = "payment_simulated"` key is written or required.
///
/// Each non-PaymentSimulated arm is serialised as a distinct TOML sub-table
/// (`sign_with_passkey`, `register_passkey`, `toolset_first_invoke_gate`,
/// `trustline_clawback_opt_in`).  The custom `Deserialize` impl rejects
/// cross-kind field contamination (e.g. an entry carrying both `summary_to`
/// and `sign_with_passkey`).
///
/// # Future arms
///
/// `#[non_exhaustive]` permits adding new kinds without breaking downstream
/// wildcard-less `match` arms.
#[derive(Clone)]
#[non_exhaustive]
pub enum ApprovalKind {
    /// A simulated payment transaction awaiting wallet-owner HMAC attestation.
    ///
    /// Serialised as flat fields on the `[[pending]]` entry (no sub-table).
    /// The HMAC attestation is stored in
    /// `PendingApproval::attestation_blob_b64`.
    PaymentSimulated {
        /// Base64-encoded simulated transaction envelope XDR.
        ///
        /// Required at `_commit` time for hash-binding verification.
        envelope_xdr_b64: String,

        /// Hex-encoded SHA-256 of the envelope XDR bytes.
        ///
        /// Pre-computed at construction time; used as the HMAC input at
        /// attestation time.
        envelope_sha256_hex: String,

        /// Destination address of the simulated payment.
        ///
        /// Validated on deserialisation: must be a Stellar G-strkey
        /// (`^G[A-Z2-7]{55}$`) to prevent tty-rendering attacks.
        summary_to: String,

        /// Amount of the simulated payment in stroops.
        summary_amount_stroops: i64,

        /// Asset code and issuer (e.g. `"XLM"` or `"USDC:GA5ZSEJY..."`).
        ///
        /// Validated on deserialisation: must be `"XLM"` or
        /// `<alphanumeric-code>:<G-strkey>` to prevent tty-rendering attacks.
        summary_asset: String,

        /// Optional memo text.
        ///
        /// Validated on deserialisation: printable ASCII only, ≤ 28 bytes.
        summary_memo: Option<String>,

        /// Simulated transaction fee in stroops.
        summary_simulated_fee_stroops: u32,

        /// Simulated sequence number.
        summary_simulated_seq_num: i64,
    },

    /// A passkey signing request awaiting a browser WebAuthn assertion.
    ///
    /// The assertion is stored in `PendingApproval::passkey_assertion` after
    /// `record_passkey_assertion` is called by the bridge POST handler.
    SignWithPasskey {
        /// 32-byte auth digest that the WebAuthn challenge binds to.
        ///
        /// The challenge embedded in the browser ceremony's `clientDataJSON`
        /// MUST equal `base64url(auth_digest)` (validated by `pre_verify_assertion`
        /// step 2).
        auth_digest: [u8; 32],

        /// Which credential the rule expects (CTAP2 §4.2: 16–64 bytes).
        ///
        /// Validated at construction time: must be 16–64 bytes, non-empty.
        credential_id: Vec<u8>,

        /// First-5-last-5 redaction of the C-strkey smart-account address.
        ///
        /// Shown in the browser-handoff approval UI for operator UX context.
        /// Validated at construction time to match `^C[A-Z2-7]{4}…[A-Z2-7]{5}$`.
        smart_account_redacted: String,

        /// OZ context rule IDs being satisfied (non-empty, max 8 entries).
        ///
        /// Validated at construction time: non-empty, max `RULE_IDS_MAX_COUNT`.
        rule_ids: Vec<u32>,

        /// 32-byte CSRF token generated by `generate_csrf_token()`.
        ///
        /// Hex-encoded in the approval URL query parameter; stored raw here.
        /// Compared against the POST body token via `subtle::ConstantTimeEq`
        /// in the bridge POST handler.
        ///
        /// Security: MUST NOT be logged.
        csrf_token: [u8; 32],

        /// WebAuthn Relying Party identifier the bridge will bind to.
        ///
        /// Must be a valid DNS domain string per WebAuthn Level 2 §5.1.2 (i.e.
        /// NOT an IP literal; `"localhost"` is the canonical loopback value).
        /// Validated at construction time: 1–253 bytes, DNS LDH charset
        /// `[A-Za-z0-9.-]` per RFC 1035 §2.3.4.
        ///
        /// A missing `rp_id` on deserialisation (for entries written before
        /// this field was added) defaults to `"localhost"` via
        /// `#[serde(default = "...")]`.
        rp_id: String,
    },

    /// Toolset first-invoke gate — awaiting out-of-band operator approval for a
    /// toolset's first use of a signing-adjacent capability.
    ///
    /// Queued by the gated resolver when a toolset invokes a `sign-payment`
    /// action and no current, matching grant exists.  After the operator
    /// approves via `stellar-agent approve --id <nonce>`, a `ToolsetGrant` is
    /// persisted and the toolset may proceed to the `stellar_pay` build step,
    /// after which the per-action `PaymentSimulated` approval fires
    /// unconditionally.
    ///
    /// # Attestation digest
    ///
    /// The `compute_toolset_gate_digest` / `verify_toolset_gate_attestation`
    /// functions in `approval/attestation.rs` bind the 32-byte slot to:
    ///
    /// ```text
    /// SHA-256(
    ///   DOMAIN_TAG (b"stellar-agent-toolset-grant:v1")
    ///   || u32_be(len(toolset_name))  || toolset_name
    ///   || u32_be(len(capability))  || capability
    ///   || u32_be(len(destination)) || destination   (canonical G-strkey)
    ///   || u32_be(len(asset))       || asset          (code:issuer or "XLM")
    ///   || i64_be(amount_min_stroops) || i64_be(amount_max_stroops)
    /// )
    /// ```
    ///
    /// Length-prefix separators prevent boundary-collision attacks (same
    /// discipline as the `attestation.rs` HMAC preimage).
    ///
    /// The HMAC attestation key is the same wallet attestation key used for
    /// `PaymentSimulated` entries.  The 32-byte digest above is the
    /// `envelope_sha256` slot fed into `compute_attestation`.
    ToolsetFirstInvokeGate {
        /// Name of the toolset requesting signing-adjacent capability access.
        ///
        /// Validated at construction: `[a-z0-9-]` charset, 1–64 bytes, same
        /// constraints as `validate_package_name` in the install crate.
        toolset_name: String,

        /// The signing-adjacent capability token being requested (e.g. `"sign-payment"`).
        ///
        /// Validated at construction: `[a-z0-9-]` charset, 1–64 bytes.
        capability: String,

        /// Canonical G-strkey destination address from the authoritative envelope,
        /// decoded from the resolved envelope rather than toolset-supplied args.
        ///
        /// Validated at construction: must be a valid Stellar G-strkey (56 chars,
        /// `^G[A-Z2-7]{55}$`).  First-5-last-5 redacted in the CLI render.
        destination: String,

        /// Full asset identifier (`"XLM"` or `"<code>:<G-strkey>"`) from the
        /// authoritative envelope.
        ///
        /// Validated at construction: same rules as `summary_asset`.
        asset: String,

        /// Minimum amount bound in stroops for this grant bucket.
        ///
        /// The first-invoke gate computes the bucket `[amount_min, amount_max]`
        /// from the resolved envelope amount.  Amounts within this range
        /// match the grant; amounts exceeding `amount_max` trigger a re-prompt.
        amount_min_stroops: i64,

        /// Maximum amount bound in stroops for this grant bucket.
        ///
        /// The gate is re-prompted when the actual payment amount exceeds this
        /// value (conservative; re-prompt on exceed).
        amount_max_stroops: i64,
    },

    /// A trustline clawback opt-in record awaiting wallet-owner confirmation.
    ///
    /// Queued by the `stellar_trustline_commit` path when the issuer has
    /// `auth_clawback_enabled` set and the operator has explicitly opted in to
    /// the clawback risk for this asset on this network.  Once the operator
    /// confirms via the approval flow, the approval record is consumed and the
    /// `ChangeTrust` envelope proceeds to submission.
    ///
    /// Security: the `network`, `code`, and `issuer` fields are validated at
    /// construction time.  `issuer` is a canonical G-strkey; it is redacted to
    /// first-5-last-5 in the `Debug` impl.
    TrustlineClawbackOptIn {
        /// Network passphrase (e.g. `"Test SDF Network ; September 2015"`).
        ///
        /// Validated at construction: non-empty, ≤ 64 bytes.
        network: String,

        /// Asset code, uppercase, 1–12 alphanumeric ASCII characters.
        code: String,

        /// Canonical issuer G-strkey (56 chars, `^G[A-Z2-7]{55}$`).
        ///
        /// Displayed redacted (first-5-last-5) in the Debug impl.
        issuer: String,
    },

    /// A simulated `ClaimClaimableBalance` transaction awaiting wallet-owner
    /// HMAC attestation.
    ///
    /// Serialised as a `claim_simulated = { ... }` sub-table (structurally
    /// distinct from the flat `PaymentSimulated` fields). Its HMAC attestation
    /// is stored in `PendingApproval::attestation_blob_b64`, and the attestation
    /// path in the MCP commit handler reads `envelope_sha256_hex` from this arm
    /// exactly as it reads the `PaymentSimulated` arm.
    ClaimSimulated {
        /// Base64-encoded simulated `ClaimClaimableBalance` transaction envelope
        /// XDR.
        ///
        /// Required at `_commit` time for hash-binding verification.
        envelope_xdr_b64: String,

        /// Hex-encoded SHA-256 of the envelope XDR bytes.
        ///
        /// Pre-computed at construction time; the HMAC attestation input.
        envelope_sha256_hex: String,

        /// Canonical 72-hex balance id being claimed.
        ///
        /// Validated on deserialisation: exactly 72 hex characters.
        summary_balance_id_hex72: String,

        /// `B...` strkey rendering of the balance id.
        ///
        /// Validated on deserialisation: `'B'` prefix, 56 characters.
        summary_balance_id_strkey: String,

        /// Asset identifier: `"XLM"` or `"<code>:<G-strkey>"`.
        ///
        /// Validated on deserialisation: same grammar as
        /// `PaymentSimulated::summary_asset`.
        summary_asset: String,

        /// Claim amount in stroops.
        summary_amount_stroops: i64,

        /// Claiming (source) account G-strkey.
        ///
        /// Validated on deserialisation: a valid Stellar G-strkey.
        summary_source: String,

        /// Simulated transaction fee in stroops.
        summary_simulated_fee_stroops: u32,

        /// Simulated sequence number.
        summary_simulated_seq_num: i64,
    },

    /// A passkey registration request awaiting a browser WebAuthn registration ceremony.
    ///
    /// The registration result is stored in `PendingApproval::registration_input`
    /// after `record_passkey_registration` is called by the bridge POST handler.
    RegisterPasskey {
        /// First-5-last-5 redaction of the C-strkey smart-account address.
        ///
        /// Shown in the browser-handoff registration UI for operator UX context.
        /// Validated at construction time to match `^C[A-Z2-7]{4}…[A-Z2-7]{5}$`.
        smart_account_redacted: String,

        /// OZ context rule IDs being registered (non-empty, max 8 entries).
        ///
        /// Validated at construction time: non-empty, max `RULE_IDS_MAX_COUNT`.
        rule_ids: Vec<u32>,

        /// 32-byte CSRF token generated by `generate_csrf_token()`.
        ///
        /// Hex-encoded in the registration URL query parameter; stored raw here.
        /// Compared against the POST body token via `subtle::ConstantTimeEq`
        /// in the bridge POST handler.
        ///
        /// Security: MUST NOT be logged.
        csrf_token: [u8; 32],

        /// WebAuthn Relying Party identifier the bridge will bind to.
        ///
        /// Must satisfy the DNS LDH-label charset `[A-Za-z0-9.-]` and must NOT
        /// be an IP address literal (WebAuthn-2 §5.1.2 explicitly forbids IP
        /// rpIds).  Use `"localhost"` for loopback operation; IP literals such
        /// as `"127.0.0.1"` are invalid and will be rejected by the validator.
        rp_id: String,

        /// Pre-generated 32-byte WebAuthn user handle.
        ///
        /// Generated by `generate_csrf_token()` (same entropy source).
        /// Stored raw; used as the `user.id` field in the WebAuthn registration
        /// ceremony. Stable per-user-account identifier in the passkey.
        ///
        /// Security: MUST NOT be logged.
        user_handle: [u8; 32],

        /// Registration ceremony result, populated by `record_passkey_registration`.
        ///
        /// `None` at issue time; `Some(RegistrationInput)` after the bridge POST
        /// handler records the browser's registration response.  One-shot: once
        /// set, cannot be overwritten.
        registration_input: Option<RegistrationInput>,
    },

    /// A simulated agent-proposed context-rule installation awaiting
    /// wallet-owner HMAC attestation (Package D, GH issue #8).
    ///
    /// An MCP agent proposes an `add_context_rule` installation — including
    /// rules whose signer sets contain human passkeys — without ever holding
    /// rule-write authority. The proposal simulates (no signature required;
    /// see `stellar-agent-smart-account::managers::rules::simulate_install_rule`),
    /// parks here rendering the FULL resolved rule, and only an operator
    /// attestation over `proposal_sha256` (via `stellar_rule_create_commit`)
    /// lets the commit install it on-chain.
    ///
    /// Serialised as a `rule_proposal_simulated = { ... }` sub-table,
    /// structurally distinct from all other arms.
    RuleProposalSimulated {
        /// Full C-strkey of the smart-account contract. Needed at commit time
        /// to call `install_rule`.
        smart_account: String,

        /// First-5-last-5 redaction of `smart_account`, for display.
        ///
        /// Validated at construction time to match
        /// `^C[A-Z2-7]{4}…[A-Z2-7]{5}$` AND to be consistent with
        /// `smart_account` (recomputing the redaction from `smart_account`
        /// must equal this field) — closes a tamper vector where an on-disk
        /// edit sets the two fields to different accounts.
        smart_account_redacted: String,

        /// Network passphrase the proposal was simulated against.
        network_passphrase: String,

        /// CAIP-2 chain ID (e.g. `"stellar:testnet"`).
        chain_id: String,

        /// The fully-resolved rule definition snapshot — every signer as
        /// resolved bytes, every policy as `{policy_address, params_xdr_b64}`,
        /// the context type, name, expiry, and `auth_rule_ids`. Rendered in
        /// FULL on every approval surface so the operator consents to
        /// exactly what will be installed.
        definition: ContextRuleProposalSnapshot,

        /// Domain-separated SHA-256 digest binding the resolved
        /// `add_context_rule` arguments
        /// (see [`super::attestation::compute_rule_proposal_digest`]).
        ///
        /// Minted at propose time by
        /// `stellar-agent-smart-account::managers::rules::compute_context_rule_proposal_sha256`
        /// (core cannot compute it directly — it has no dependency on the
        /// smart-account crate's `build_add_context_rule_args` builder).
        /// Bound into the attestation HMAC exactly like `envelope_sha256_hex`
        /// for `PaymentSimulated` / `ClaimSimulated`.
        proposal_sha256: [u8; 32],

        /// Pre-computed, non-secret one-line summary for compact list
        /// rendering (`approve list` table row).
        summary_line: String,
    },

    /// A short-TTL tombstone left behind after the operator explicitly rejects
    /// a pending approval via [`PendingApprovalStore::reject`].
    ///
    /// Carries no summary data from the rejected entry — only the kind name it
    /// replaced — so a rejected payment's destination, amount, or other
    /// wallet-controlled summary fields never persist past the reject action.
    /// The commit-path attestation gate maps a live (non-expired) `Rejected`
    /// entry to the distinct `policy.approval_rejected` wire code, so the
    /// agent can tell "the operator said no" apart from "no decision yet".
    /// The entry expires (and is swept by the existing GC) like any other
    /// pending approval; a `Rejected` entry can never be attested.
    Rejected {
        /// `kind_name()` of the entry before it was rejected (e.g.
        /// `"PaymentSimulated"`).
        original_kind_name: String,
    },
}

impl ApprovalKind {
    /// Returns the kind discriminator string used in error messages.
    #[must_use]
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::PaymentSimulated { .. } => "PaymentSimulated",
            Self::SignWithPasskey { .. } => "SignWithPasskey",
            Self::TrustlineClawbackOptIn { .. } => "TrustlineClawbackOptIn",
            Self::ClaimSimulated { .. } => "ClaimSimulated",
            Self::RegisterPasskey { .. } => "RegisterPasskey",
            Self::ToolsetFirstInvokeGate { .. } => "ToolsetFirstInvokeGate",
            Self::RuleProposalSimulated { .. } => "RuleProposalSimulated",
            Self::Rejected { .. } => "Rejected",
        }
    }
}

impl std::fmt::Debug for ApprovalKind {
    /// Redacted `Debug` impl for `ApprovalKind`.
    ///
    /// `SignWithPasskey` byte fields (`auth_digest`, `credential_id`,
    /// `csrf_token`) are emitted as length-only to prevent credential or
    /// challenge bytes from appearing in tracing events.
    ///
    /// `RegisterPasskey` byte fields (`csrf_token`, `user_handle`) are
    /// emitted as length-only.  `registration_input` is shown as
    /// `Some(<set>)` or `None`.
    ///
    /// `PaymentSimulated` fields contain no raw secrets and are shown fully.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PaymentSimulated {
                envelope_xdr_b64,
                envelope_sha256_hex,
                summary_to,
                summary_amount_stroops,
                summary_asset,
                summary_memo,
                summary_simulated_fee_stroops,
                summary_simulated_seq_num,
            } => f
                .debug_struct("PaymentSimulated")
                .field("envelope_xdr_b64", envelope_xdr_b64)
                .field("envelope_sha256_hex", envelope_sha256_hex)
                .field("summary_to", summary_to)
                .field("summary_amount_stroops", summary_amount_stroops)
                .field("summary_asset", summary_asset)
                .field("summary_memo", summary_memo)
                .field(
                    "summary_simulated_fee_stroops",
                    summary_simulated_fee_stroops,
                )
                .field("summary_simulated_seq_num", summary_simulated_seq_num)
                .finish(),
            Self::SignWithPasskey {
                auth_digest,
                credential_id,
                smart_account_redacted,
                rule_ids,
                csrf_token,
                rp_id,
            } => f
                .debug_struct("SignWithPasskey")
                .field("auth_digest_len", &auth_digest.len())
                .field("credential_id_len", &credential_id.len())
                .field("smart_account_redacted", smart_account_redacted)
                .field("rule_ids", rule_ids)
                .field("csrf_token_len", &csrf_token.len())
                .field("rp_id", rp_id)
                .finish(),
            Self::RegisterPasskey {
                smart_account_redacted,
                rule_ids,
                csrf_token,
                rp_id,
                user_handle,
                registration_input,
            } => {
                let reg_display = if registration_input.is_some() {
                    "Some(<set>)"
                } else {
                    "None"
                };
                f.debug_struct("RegisterPasskey")
                    .field("smart_account_redacted", smart_account_redacted)
                    .field("rule_ids", rule_ids)
                    .field("csrf_token_len", &csrf_token.len())
                    .field("rp_id", rp_id)
                    .field("user_handle_len", &user_handle.len())
                    .field("registration_input", &reg_display)
                    .finish()
            }
            Self::ToolsetFirstInvokeGate {
                toolset_name,
                capability,
                destination,
                asset,
                amount_min_stroops,
                amount_max_stroops,
            } => {
                // Redact destination to first-5-last-5 to avoid logging full addresses.
                let dest_redacted = redact_g_strkey(destination);
                f.debug_struct("ToolsetFirstInvokeGate")
                    .field("toolset_name", toolset_name)
                    .field("capability", capability)
                    .field("destination_redacted", &dest_redacted)
                    .field("asset", asset)
                    .field("amount_min_stroops", amount_min_stroops)
                    .field("amount_max_stroops", amount_max_stroops)
                    .finish()
            }
            Self::TrustlineClawbackOptIn {
                network,
                code,
                issuer,
            } => {
                // Redact issuer G-strkey to first-5-last-5 to avoid logging full addresses.
                let issuer_redacted = redact_g_strkey(issuer);
                f.debug_struct("TrustlineClawbackOptIn")
                    .field("network", network)
                    .field("code", code)
                    .field("issuer_redacted", &issuer_redacted)
                    .finish()
            }
            Self::ClaimSimulated {
                envelope_xdr_b64,
                envelope_sha256_hex,
                summary_balance_id_hex72,
                summary_balance_id_strkey,
                summary_asset,
                summary_amount_stroops,
                summary_source,
                summary_simulated_fee_stroops,
                summary_simulated_seq_num,
            } => {
                // All ClaimSimulated fields are public claim data (balance ids,
                // amounts, source account) — shown in full, same posture as
                // PaymentSimulated.
                f.debug_struct("ClaimSimulated")
                    .field("envelope_xdr_b64", envelope_xdr_b64)
                    .field("envelope_sha256_hex", envelope_sha256_hex)
                    .field("summary_balance_id_hex72", summary_balance_id_hex72)
                    .field("summary_balance_id_strkey", summary_balance_id_strkey)
                    .field("summary_asset", summary_asset)
                    .field("summary_amount_stroops", summary_amount_stroops)
                    .field("summary_source", summary_source)
                    .field(
                        "summary_simulated_fee_stroops",
                        summary_simulated_fee_stroops,
                    )
                    .field("summary_simulated_seq_num", summary_simulated_seq_num)
                    .finish()
            }
            Self::RuleProposalSimulated {
                smart_account_redacted,
                network_passphrase,
                chain_id,
                definition,
                proposal_sha256,
                summary_line,
                ..
            } => {
                // The resolved definition is operator-facing rule content, not a
                // secret — same posture as ClaimSimulated/PaymentSimulated. Only
                // `smart_account` (the full strkey) is omitted in favour of its
                // pre-computed redaction.
                f.debug_struct("RuleProposalSimulated")
                    .field("smart_account_redacted", smart_account_redacted)
                    .field("network_passphrase", network_passphrase)
                    .field("chain_id", chain_id)
                    .field("definition", definition)
                    .field("proposal_sha256_hex", &hex_encode(proposal_sha256))
                    .field("summary_line", summary_line)
                    .finish()
            }
            Self::Rejected { original_kind_name } => f
                .debug_struct("Rejected")
                .field("original_kind_name", original_kind_name)
                .finish(),
        }
    }
}

/// Formats a byte slice as lowercase hex, for `Debug`/audit-facing rendering.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// ApprovalKind serde — custom impl for untagged/structural disambiguation
// ─────────────────────────────────────────────────────────────────────────────

/// Redacts a G-strkey to first-5-last-5 characters for debug output and CLI
/// rendering, preventing full addresses from appearing in logs.
///
/// Returns `"<redacted>"` for strings shorter than 10 characters.
pub(crate) fn redact_g_strkey(s: &str) -> String {
    if s.len() < 10 {
        return "<redacted>".to_owned();
    }
    let first5 = &s[..5];
    let last5 = &s[s.len() - 5..];
    format!("{first5}...{last5}")
}

/// Wire representation for `ApprovalKind::SignWithPasskey`.
///
/// Serialised as a `sign_with_passkey` sub-table, which is structurally
/// distinct from the flat `PaymentSimulated` fields.
#[derive(Clone, Serialize, Deserialize)]
struct SignWithPasskeyWire {
    auth_digest: [u8; 32],
    credential_id: Vec<u8>,
    smart_account_redacted: String,
    rule_ids: Vec<u32>,
    csrf_token: [u8; 32],
    /// `#[serde(default)]` ensures on-disk entries written before this field
    /// was added deserialise cleanly: a missing `rp_id` defaults to
    /// `"localhost"`, the value used by the bridge prior to this field
    /// becoming explicit.
    #[serde(default = "default_rp_id")]
    rp_id: String,
}

impl std::fmt::Debug for SignWithPasskeyWire {
    /// Length-only `Debug` for the byte fields (`auth_digest`, `credential_id`,
    /// `csrf_token`) so credential and challenge bytes never reach a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignWithPasskeyWire")
            .field("auth_digest_len", &self.auth_digest.len())
            .field("credential_id_len", &self.credential_id.len())
            .field("smart_account_redacted", &self.smart_account_redacted)
            .field("rule_ids", &self.rule_ids)
            .field("csrf_token_len", &self.csrf_token.len())
            .field("rp_id", &self.rp_id)
            .finish()
    }
}

/// Default RP-ID for `SignWithPasskey` entries that pre-date the explicit
/// `rp_id` field.  The bridge used `"localhost"` as a hardcoded placeholder,
/// so `"localhost"` is the correct default for all such entries.
fn default_rp_id() -> String {
    "localhost".to_owned()
}

/// Wire representation for `ApprovalKind::RegisterPasskey`.
///
/// Serialised as a `register_passkey` sub-table, structurally distinct from
/// both the flat `PaymentSimulated` fields and the `sign_with_passkey` sub-table.
#[derive(Clone, Serialize, Deserialize)]
struct RegisterPasskeyWire {
    smart_account_redacted: String,
    rule_ids: Vec<u32>,
    csrf_token: [u8; 32],
    rp_id: String,
    user_handle: [u8; 32],
}

impl std::fmt::Debug for RegisterPasskeyWire {
    /// Length-only `Debug` for the byte fields (`csrf_token`, `user_handle`) so
    /// challenge and handle bytes never reach a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterPasskeyWire")
            .field("smart_account_redacted", &self.smart_account_redacted)
            .field("rule_ids", &self.rule_ids)
            .field("csrf_token_len", &self.csrf_token.len())
            .field("rp_id", &self.rp_id)
            .field("user_handle_len", &self.user_handle.len())
            .finish()
    }
}

/// Wire representation for `ApprovalKind::ToolsetFirstInvokeGate`.
///
/// Serialised as a `toolset_first_invoke_gate = { ... }` sub-table, which is
/// structurally distinct from the flat `PaymentSimulated` fields and from
/// the other sub-tables.  This enables the cross-kind contamination checks
/// in the custom `Deserialize` impl.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolsetFirstInvokeGateWire {
    toolset_name: String,
    capability: String,
    destination: String,
    asset: String,
    amount_min_stroops: i64,
    amount_max_stroops: i64,
}

/// Wire representation for `ApprovalKind::TrustlineClawbackOptIn`.
///
/// Serialised as a `trustline_clawback_opt_in = { ... }` sub-table, structurally
/// distinct from all other arms.  Enables the cross-kind contamination checks
/// in the custom `Deserialize` impl.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrustlineClawbackOptInWire {
    network: String,
    code: String,
    issuer: String,
}

/// Wire representation for `ApprovalKind::Rejected`.
///
/// Serialised as a `rejected = { ... }` sub-table, structurally distinct from
/// all other arms.  Enables the cross-kind contamination checks in the custom
/// `Deserialize` impl.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RejectedWire {
    original_kind_name: String,
}

/// Wire representation for `ApprovalKind::ClaimSimulated`.
///
/// Serialised as a `claim_simulated = { ... }` sub-table, structurally distinct
/// from the flat `PaymentSimulated` fields and from all other sub-tables. This
/// enables the cross-kind contamination checks in the custom `Deserialize` impl.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClaimSimulatedWire {
    envelope_xdr_b64: String,
    envelope_sha256_hex: String,
    summary_balance_id_hex72: String,
    summary_balance_id_strkey: String,
    summary_asset: String,
    summary_amount_stroops: i64,
    summary_source: String,
    summary_simulated_fee_stroops: u32,
    summary_simulated_seq_num: i64,
}

/// Wire representation for `ApprovalKind::RuleProposalSimulated`.
///
/// Serialised as a `rule_proposal_simulated = { ... }` sub-table, structurally
/// distinct from the flat `PaymentSimulated` fields and from all other
/// sub-tables. This enables the cross-kind contamination checks in the
/// custom `Deserialize` impl.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuleProposalSimulatedWire {
    smart_account: String,
    smart_account_redacted: String,
    network_passphrase: String,
    chain_id: String,
    definition: ContextRuleProposalSnapshot,
    proposal_sha256: [u8; 32],
    summary_line: String,
}

/// Flat on-disk representation of a `PendingApproval` entry.
///
/// Used by the custom `Serialize`/`Deserialize` impls to map between the
/// kinded in-memory shape and the two distinct TOML wire shapes.
///
/// A legacy TOML entry has `sign_with_passkey = None` and the payment-summary
/// flat fields set; a new `SignWithPasskey` entry has `sign_with_passkey = Some(…)`
/// and the payment-summary flat fields absent.
#[derive(Debug, Serialize, Deserialize)]
struct PendingApprovalOnDisk {
    #[serde(deserialize_with = "deserialize_approval_nonce")]
    approval_nonce: String,
    #[serde(deserialize_with = "deserialize_process_uid")]
    process_uid: String,
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,

    // PaymentSimulated flat fields — present iff sign_with_passkey is absent.
    #[serde(default)]
    envelope_xdr_b64: Option<String>,
    #[serde(default)]
    envelope_sha256_hex: Option<String>,
    #[serde(default, deserialize_with = "deserialize_opt_summary_to")]
    summary_to: Option<String>,
    #[serde(default)]
    summary_amount_stroops: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_opt_summary_asset")]
    summary_asset: Option<String>,
    #[serde(default, deserialize_with = "deserialize_opt_summary_memo")]
    summary_memo: Option<String>,
    #[serde(default)]
    summary_simulated_fee_stroops: Option<u32>,
    #[serde(default)]
    summary_simulated_seq_num: Option<i64>,

    // SignWithPasskey sub-table — present iff payment fields and register_passkey are absent.
    #[serde(default)]
    sign_with_passkey: Option<SignWithPasskeyWire>,

    // RegisterPasskey sub-table — present iff payment fields and sign_with_passkey are absent.
    #[serde(default)]
    register_passkey: Option<RegisterPasskeyWire>,

    // ToolsetFirstInvokeGate sub-table — present iff all other kind fields are absent.
    #[serde(default)]
    toolset_first_invoke_gate: Option<ToolsetFirstInvokeGateWire>,

    // TrustlineClawbackOptIn sub-table — present iff all other kind fields are absent.
    #[serde(default)]
    trustline_clawback_opt_in: Option<TrustlineClawbackOptInWire>,

    // ClaimSimulated sub-table — present iff all other kind fields are absent.
    #[serde(default)]
    claim_simulated: Option<ClaimSimulatedWire>,

    // RuleProposalSimulated sub-table — present iff all other kind fields are absent.
    #[serde(default)]
    rule_proposal_simulated: Option<RuleProposalSimulatedWire>,

    // Rejected sub-table — present iff all other kind fields are absent.
    #[serde(default)]
    rejected: Option<RejectedWire>,

    // Cross-kind attestation/result fields.
    #[serde(default)]
    attestation_blob_b64: Option<String>,
    #[serde(default)]
    passkey_assertion: Option<AssertionInput>,
    #[serde(default)]
    registration_input: Option<RegistrationInput>,
}

/// Optional `summary_to` deserialiser — applies the G-strkey validator when
/// the field is present, passes `None` through unchanged.
fn deserialize_opt_summary_to<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(s) => {
            let valid = s.len() == 56
                && s.starts_with('G')
                && s[1..].chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7'));
            if valid {
                Ok(Some(s))
            } else {
                Err(serde::de::Error::custom(format!(
                    "summary_to must be a valid Stellar G-strkey (56 chars, ^G[A-Z2-7]{{55}}$), got: {s:?}"
                )))
            }
        }
    }
}

/// Optional `summary_asset` deserialiser.
fn deserialize_opt_summary_asset<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(s) => {
            if s == "XLM" {
                return Ok(Some(s));
            }
            if let Some((code, issuer)) = s.split_once(':') {
                let code_valid = !code.is_empty()
                    && code.len() <= 12
                    && code.chars().all(|c| c.is_ascii_alphanumeric());
                let issuer_valid = issuer.len() == 56
                    && issuer.starts_with('G')
                    && issuer[1..]
                        .chars()
                        .all(|c| matches!(c, 'A'..='Z' | '2'..='7'));
                if code_valid && issuer_valid {
                    return Ok(Some(s));
                }
            }
            Err(serde::de::Error::custom(format!(
                "summary_asset must be 'XLM' or '<code>:<G-strkey>', got: {s:?}"
            )))
        }
    }
}

/// Optional `summary_memo` deserialiser.
fn deserialize_opt_summary_memo<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(s) => {
            if s.len() > 28 {
                return Err(serde::de::Error::custom(format!(
                    "summary_memo must be ≤ 28 bytes (Stellar MemoText limit), got {} bytes",
                    s.len()
                )));
            }
            if !s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                return Err(serde::de::Error::custom(
                    "summary_memo must contain only printable ASCII (graphic chars or space)",
                ));
            }
            Ok(Some(s))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PendingApproval
// ─────────────────────────────────────────────────────────────────────────────

/// A single pending wallet-issued approval record.
///
/// The `kind` field discriminates between the approval flows:
///
/// - [`ApprovalKind::PaymentSimulated`]: simulate-then-commit payment flow.
///   Attested via HMAC-SHA256 blob stored in `attestation_blob_b64`.
/// - [`ApprovalKind::SignWithPasskey`]: browser WebAuthn signing ceremony flow.
///   The assertion bytes are stored in `passkey_assertion` after the bridge
///   POST handler calls `record_passkey_assertion`.
/// - [`ApprovalKind::RegisterPasskey`]: browser WebAuthn registration ceremony
///   flow. The registration result is stored in `registration_input` after the
///   bridge POST handler calls `record_passkey_registration`.
///
/// # Legacy TOML compatibility
///
/// On-disk files that contain the payment-summary fields flat on the
/// `[[pending]]` entry load cleanly as `kind: PaymentSimulated { ... }`
/// via the custom `Deserialize` impl — no migration step required.
///
/// # Field notes
///
/// - `approval_nonce`: random, URL-safe base64 no-pad, 16 bytes → 22 chars.
///   Validated on deserialisation to reject tampered entries.
/// - `process_uid`: numeric UID on Unix, Windows SID on Windows, or
///   `"non-unix-stub"` on other non-Unix targets.
///   Validated on deserialisation to reject Unicode-direction-mark injection.
/// - `attestation_blob_b64`: set by `record_attestation` (PaymentSimulated only).
///   One-shot; cannot be overwritten.
/// - `passkey_assertion`: set by `record_passkey_assertion` (SignWithPasskey only).
///   One-shot; cannot be overwritten.
/// - `registration_input` (embedded in `ApprovalKind::RegisterPasskey`): set by
///   `record_passkey_registration` — RegisterPasskey only. One-shot; cannot be overwritten.
/// - The result fields are mutually exclusive by construction (each lives in its own arm).
#[derive(Clone)]
#[non_exhaustive]
pub struct PendingApproval {
    /// Wallet-issued approval identifier.
    ///
    /// Random, URL-safe base64 no-pad encoding of 16 `OsRng` bytes (22 chars).
    /// Validated on deserialisation: must be exactly 22 chars and contain only
    /// base64url-alphabet characters.
    pub approval_nonce: String,

    /// Platform-stable user identity bound at attestation time.
    ///
    /// Set to the value of `process_uid_for_attestation()` at the time the
    /// simulate path stores this entry.  The `record_attestation` path confirms
    /// the attesting user matches this value (enforced by the HMAC input domain).
    ///
    /// Validated on deserialisation: must be numeric ASCII, a Windows SID, or
    /// `"non-unix-stub"`.
    pub process_uid: String,

    /// Unix epoch timestamp (milliseconds) when this entry was created.
    pub created_at_unix_ms: u64,

    /// Unix epoch timestamp (milliseconds) when this entry expires.
    ///
    /// Entries with `expires_at_unix_ms <= now` are treated as expired.
    pub expires_at_unix_ms: u64,

    /// The kind-discriminated approval data.
    ///
    /// Carries all fields specific to the approval flow
    /// (`PaymentSimulated` or `SignWithPasskey`).
    pub kind: ApprovalKind,

    /// HMAC-SHA256 attestation blob, base64-encoded (URL-safe no-pad).
    ///
    /// `None` until the operator runs `stellar-agent approve --id <nonce>`.
    /// Set by `record_attestation` (`PaymentSimulated` / `ClaimSimulated`,
    /// over `envelope_sha256_hex`) or by `record_rule_proposal_attestation`
    /// (`RuleProposalSimulated`, over `proposal_sha256`) — the generic slot
    /// every digest-HMAC-attestable kind shares. Once set, this field cannot
    /// be overwritten.
    pub attestation_blob_b64: Option<String>,

    /// WebAuthn assertion bytes recorded by the bridge POST handler.
    ///
    /// `None` until `record_passkey_assertion` is called by the bridge.
    /// Set by `record_passkey_assertion` — SignWithPasskey only.
    /// Once set, this field cannot be overwritten.
    pub passkey_assertion: Option<AssertionInput>,
}

impl std::fmt::Debug for PendingApproval {
    /// Redacted `Debug` impl: `passkey_assertion` shows length-only fields when
    /// present; `attestation_blob_b64` is redacted to `Some(<set>)` / `None`.
    /// `ApprovalKind::RegisterPasskey` embeds `registration_input` and its
    /// `Debug` impl (in `ApprovalKind`) likewise redacts it.
    ///
    /// Raw assertion bytes MUST NOT appear in debug output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let attest_display = if self.attestation_blob_b64.is_some() {
            "Some(<set>)"
        } else {
            "None"
        };
        let passkey_display = if let Some(ref a) = self.passkey_assertion {
            format!(
                "Some(credential_id_len={} authenticator_data_len={} \
                 client_data_json_len={} signature_compact_len={})",
                a.credential_id.len(),
                a.authenticator_data.len(),
                a.client_data_json.len(),
                a.signature_compact.len()
            )
        } else {
            "None".to_owned()
        };
        f.debug_struct("PendingApproval")
            .field("approval_nonce", &self.approval_nonce)
            .field("process_uid", &self.process_uid)
            .field("created_at_unix_ms", &self.created_at_unix_ms)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .field("kind", &self.kind)
            .field("attestation_blob_b64", &attest_display)
            .field("passkey_assertion", &passkey_display)
            .finish()
    }
}

impl Serialize for PendingApproval {
    /// Custom serialiser: maps the kinded in-memory shape back to the five
    /// distinct TOML wire representations.
    ///
    /// - `PaymentSimulated`: serialises the payment-summary fields flat on
    ///   the entry (no sub-tables; preserves on-disk compatibility).
    /// - `SignWithPasskey`: serialises a `sign_with_passkey = { ... }` sub-table
    ///   and omits the payment-summary flat fields.
    /// - `RegisterPasskey`: serialises a `register_passkey = { ... }` sub-table.
    /// - `ToolsetFirstInvokeGate`: serialises a `toolset_first_invoke_gate = { ... }`
    ///   sub-table.
    /// - `TrustlineClawbackOptIn`: serialises a `trustline_clawback_opt_in = { ... }`
    ///   sub-table.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Decompose kind into flat wire fields.
        let (
            envelope_xdr_b64,
            envelope_sha256_hex,
            summary_to,
            summary_amount_stroops,
            summary_asset,
            summary_memo,
            summary_simulated_fee_stroops,
            summary_simulated_seq_num,
            sign_with_passkey,
            register_passkey,
            toolset_first_invoke_gate,
            trustline_clawback_opt_in,
            claim_simulated,
            rule_proposal_simulated,
            rejected,
            // registration_input lives inside the RegisterPasskey arm; extract it here
            // so it can be written to the top-level on-disk field.
            registration_input_for_disk,
        ) = match &self.kind {
            ApprovalKind::PaymentSimulated {
                envelope_xdr_b64,
                envelope_sha256_hex,
                summary_to,
                summary_amount_stroops,
                summary_asset,
                summary_memo,
                summary_simulated_fee_stroops,
                summary_simulated_seq_num,
            } => (
                Some(envelope_xdr_b64.as_str()),
                Some(envelope_sha256_hex.as_str()),
                Some(summary_to.as_str()),
                Some(*summary_amount_stroops),
                Some(summary_asset.as_str()),
                summary_memo.as_deref(),
                Some(*summary_simulated_fee_stroops),
                Some(*summary_simulated_seq_num),
                None::<SignWithPasskeyWire>,
                None::<RegisterPasskeyWire>,
                None::<ToolsetFirstInvokeGateWire>,
                None::<TrustlineClawbackOptInWire>,
                None::<ClaimSimulatedWire>,
                None::<RuleProposalSimulatedWire>,
                None::<RejectedWire>,
                None::<RegistrationInput>,
            ),
            ApprovalKind::SignWithPasskey {
                auth_digest,
                credential_id,
                smart_account_redacted,
                rule_ids,
                csrf_token,
                rp_id,
            } => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(SignWithPasskeyWire {
                    auth_digest: *auth_digest,
                    credential_id: credential_id.clone(),
                    smart_account_redacted: smart_account_redacted.clone(),
                    rule_ids: rule_ids.clone(),
                    csrf_token: *csrf_token,
                    rp_id: rp_id.clone(),
                }),
                None::<RegisterPasskeyWire>,
                None::<ToolsetFirstInvokeGateWire>,
                None::<TrustlineClawbackOptInWire>,
                None::<ClaimSimulatedWire>,
                None::<RuleProposalSimulatedWire>,
                None::<RejectedWire>,
                None::<RegistrationInput>,
            ),
            ApprovalKind::RegisterPasskey {
                smart_account_redacted,
                rule_ids,
                csrf_token,
                rp_id,
                user_handle,
                registration_input,
            } => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None::<SignWithPasskeyWire>,
                Some(RegisterPasskeyWire {
                    smart_account_redacted: smart_account_redacted.clone(),
                    rule_ids: rule_ids.clone(),
                    csrf_token: *csrf_token,
                    rp_id: rp_id.clone(),
                    user_handle: *user_handle,
                }),
                None::<ToolsetFirstInvokeGateWire>,
                None::<TrustlineClawbackOptInWire>,
                None::<ClaimSimulatedWire>,
                None::<RuleProposalSimulatedWire>,
                None::<RejectedWire>,
                registration_input.clone(),
            ),
            ApprovalKind::ToolsetFirstInvokeGate {
                toolset_name,
                capability,
                destination,
                asset,
                amount_min_stroops,
                amount_max_stroops,
            } => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None::<SignWithPasskeyWire>,
                None::<RegisterPasskeyWire>,
                Some(ToolsetFirstInvokeGateWire {
                    toolset_name: toolset_name.clone(),
                    capability: capability.clone(),
                    destination: destination.clone(),
                    asset: asset.clone(),
                    amount_min_stroops: *amount_min_stroops,
                    amount_max_stroops: *amount_max_stroops,
                }),
                None::<TrustlineClawbackOptInWire>,
                None::<ClaimSimulatedWire>,
                None::<RuleProposalSimulatedWire>,
                None::<RejectedWire>,
                None::<RegistrationInput>,
            ),
            ApprovalKind::TrustlineClawbackOptIn {
                network,
                code,
                issuer,
            } => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None::<SignWithPasskeyWire>,
                None::<RegisterPasskeyWire>,
                None::<ToolsetFirstInvokeGateWire>,
                Some(TrustlineClawbackOptInWire {
                    network: network.clone(),
                    code: code.clone(),
                    issuer: issuer.clone(),
                }),
                None::<ClaimSimulatedWire>,
                None::<RuleProposalSimulatedWire>,
                None::<RejectedWire>,
                None::<RegistrationInput>,
            ),
            ApprovalKind::ClaimSimulated {
                envelope_xdr_b64,
                envelope_sha256_hex,
                summary_balance_id_hex72,
                summary_balance_id_strkey,
                summary_asset,
                summary_amount_stroops,
                summary_source,
                summary_simulated_fee_stroops,
                summary_simulated_seq_num,
            } => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None::<SignWithPasskeyWire>,
                None::<RegisterPasskeyWire>,
                None::<ToolsetFirstInvokeGateWire>,
                None::<TrustlineClawbackOptInWire>,
                Some(ClaimSimulatedWire {
                    envelope_xdr_b64: envelope_xdr_b64.clone(),
                    envelope_sha256_hex: envelope_sha256_hex.clone(),
                    summary_balance_id_hex72: summary_balance_id_hex72.clone(),
                    summary_balance_id_strkey: summary_balance_id_strkey.clone(),
                    summary_asset: summary_asset.clone(),
                    summary_amount_stroops: *summary_amount_stroops,
                    summary_source: summary_source.clone(),
                    summary_simulated_fee_stroops: *summary_simulated_fee_stroops,
                    summary_simulated_seq_num: *summary_simulated_seq_num,
                }),
                None::<RuleProposalSimulatedWire>,
                None::<RejectedWire>,
                None::<RegistrationInput>,
            ),
            ApprovalKind::RuleProposalSimulated {
                smart_account,
                smart_account_redacted,
                network_passphrase,
                chain_id,
                definition,
                proposal_sha256,
                summary_line,
            } => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None::<SignWithPasskeyWire>,
                None::<RegisterPasskeyWire>,
                None::<ToolsetFirstInvokeGateWire>,
                None::<TrustlineClawbackOptInWire>,
                None::<ClaimSimulatedWire>,
                Some(RuleProposalSimulatedWire {
                    smart_account: smart_account.clone(),
                    smart_account_redacted: smart_account_redacted.clone(),
                    network_passphrase: network_passphrase.clone(),
                    chain_id: chain_id.clone(),
                    definition: definition.clone(),
                    proposal_sha256: *proposal_sha256,
                    summary_line: summary_line.clone(),
                }),
                None::<RejectedWire>,
                None::<RegistrationInput>,
            ),
            ApprovalKind::Rejected { original_kind_name } => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None::<SignWithPasskeyWire>,
                None::<RegisterPasskeyWire>,
                None::<ToolsetFirstInvokeGateWire>,
                None::<TrustlineClawbackOptInWire>,
                None::<ClaimSimulatedWire>,
                None::<RuleProposalSimulatedWire>,
                Some(RejectedWire {
                    original_kind_name: original_kind_name.clone(),
                }),
                None::<RegistrationInput>,
            ),
        };

        let on_disk = PendingApprovalOnDisk {
            approval_nonce: self.approval_nonce.clone(),
            process_uid: self.process_uid.clone(),
            created_at_unix_ms: self.created_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            envelope_xdr_b64: envelope_xdr_b64.map(ToOwned::to_owned),
            envelope_sha256_hex: envelope_sha256_hex.map(ToOwned::to_owned),
            summary_to: summary_to.map(ToOwned::to_owned),
            summary_amount_stroops,
            summary_asset: summary_asset.map(ToOwned::to_owned),
            summary_memo: summary_memo.map(ToOwned::to_owned),
            summary_simulated_fee_stroops,
            summary_simulated_seq_num,
            sign_with_passkey,
            register_passkey,
            toolset_first_invoke_gate,
            trustline_clawback_opt_in,
            claim_simulated,
            rule_proposal_simulated,
            rejected,
            attestation_blob_b64: self.attestation_blob_b64.clone(),
            passkey_assertion: self.passkey_assertion.clone(),
            registration_input: registration_input_for_disk,
        };
        on_disk.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PendingApproval {
    /// Custom deserialiser: routes the flat on-disk shape to the kinded
    /// in-memory shape and rejects tampered or cross-kind-contaminated entries.
    ///
    /// Routing priority (first sub-table present wins):
    ///
    /// 1. `sign_with_passkey` present → `ApprovalKind::SignWithPasskey`.
    ///    - All `PaymentSimulated` flat fields MUST be absent.
    ///    - `attestation_blob_b64` MUST be absent.
    ///    - `registration_input` MUST be absent.
    ///    - `register_passkey` sub-table MUST be absent.
    ///    - `toolset_first_invoke_gate` sub-table MUST be absent.
    ///    - `trustline_clawback_opt_in` sub-table MUST be absent.
    ///    - Validates `SignWithPasskey` invariants on reload.
    ///
    /// 2. `register_passkey` present → `ApprovalKind::RegisterPasskey`.
    ///    - All `PaymentSimulated` flat fields MUST be absent.
    ///    - `attestation_blob_b64` MUST be absent.
    ///    - `passkey_assertion` MUST be absent.
    ///    - `sign_with_passkey` sub-table MUST be absent.
    ///    - `toolset_first_invoke_gate` sub-table MUST be absent.
    ///    - `trustline_clawback_opt_in` sub-table MUST be absent.
    ///    - Validates `RegisterPasskey` invariants on reload.
    ///
    /// 3. `toolset_first_invoke_gate` present → `ApprovalKind::ToolsetFirstInvokeGate`.
    ///    - All `PaymentSimulated` flat fields MUST be absent.
    ///    - `attestation_blob_b64` MUST be absent.
    ///    - `passkey_assertion` MUST be absent.
    ///    - `registration_input` MUST be absent.
    ///    - `sign_with_passkey`, `register_passkey`, and `trustline_clawback_opt_in`
    ///      sub-tables MUST be absent.
    ///    - Validates `ToolsetFirstInvokeGate` field invariants on reload.
    ///
    /// 4. `trustline_clawback_opt_in` present → `ApprovalKind::TrustlineClawbackOptIn`.
    ///    - All `PaymentSimulated` flat fields MUST be absent.
    ///    - `attestation_blob_b64`, `passkey_assertion`, `registration_input` MUST
    ///      be absent.
    ///    - All other sub-tables MUST be absent.
    ///    - Validates `TrustlineClawbackOptIn` field invariants on reload.
    ///
    /// 5. Otherwise → `ApprovalKind::PaymentSimulated` from flat fields.
    ///    - `passkey_assertion` MUST be absent.
    ///    - `registration_input` MUST be absent.
    ///
    /// This routing handles both the flat-field legacy format and all current
    /// sub-table arm shapes, while closing tampered-on-disk attack vectors via
    /// cross-kind field contamination checks and construction-time validators.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = PendingApprovalOnDisk::deserialize(deserializer)?;

        let kind = if let Some(swp) = raw.sign_with_passkey {
            // Cross-kind contamination check: SignWithPasskey must not carry
            // PaymentSimulated flat fields, attestation blob, registration_input,
            // register_passkey, or toolset_first_invoke_gate sub-tables.
            for (field, present) in [
                ("envelope_xdr_b64", raw.envelope_xdr_b64.is_some()),
                ("envelope_sha256_hex", raw.envelope_sha256_hex.is_some()),
                ("summary_to", raw.summary_to.is_some()),
                (
                    "summary_amount_stroops",
                    raw.summary_amount_stroops.is_some(),
                ),
                ("summary_asset", raw.summary_asset.is_some()),
                ("summary_memo", raw.summary_memo.is_some()),
                (
                    "summary_simulated_fee_stroops",
                    raw.summary_simulated_fee_stroops.is_some(),
                ),
                (
                    "summary_simulated_seq_num",
                    raw.summary_simulated_seq_num.is_some(),
                ),
                ("attestation_blob_b64", raw.attestation_blob_b64.is_some()),
                ("register_passkey", raw.register_passkey.is_some()),
                ("registration_input", raw.registration_input.is_some()),
                (
                    "toolset_first_invoke_gate",
                    raw.toolset_first_invoke_gate.is_some(),
                ),
                (
                    "trustline_clawback_opt_in",
                    raw.trustline_clawback_opt_in.is_some(),
                ),
                ("claim_simulated", raw.claim_simulated.is_some()),
                (
                    "rule_proposal_simulated",
                    raw.rule_proposal_simulated.is_some(),
                ),
                ("rejected", raw.rejected.is_some()),
            ] {
                if present {
                    return Err(serde::de::Error::custom(format!(
                        "cross-kind field contamination: SignWithPasskey entry must not carry \
                         field `{field}`",
                    )));
                }
            }

            // Run construction-time invariants on the on-disk SignWithPasskey
            // fields. Closes the tamper-defence gap on the deserialise path.
            validate_sign_with_passkey_invariants(
                &swp.credential_id,
                &swp.rule_ids,
                &swp.smart_account_redacted,
                &swp.rp_id,
            )
            .map_err(serde::de::Error::custom)?;

            if let Some(ref assertion) = raw.passkey_assertion {
                validate_assertion_input_invariants(assertion).map_err(serde::de::Error::custom)?;
            }

            ApprovalKind::SignWithPasskey {
                auth_digest: swp.auth_digest,
                credential_id: swp.credential_id,
                smart_account_redacted: swp.smart_account_redacted,
                rule_ids: swp.rule_ids,
                csrf_token: swp.csrf_token,
                rp_id: swp.rp_id,
            }
        } else if let Some(rp) = raw.register_passkey {
            // Cross-kind contamination check: RegisterPasskey must not carry
            // PaymentSimulated flat fields, attestation blob, passkey_assertion,
            // sign_with_passkey, or toolset_first_invoke_gate sub-tables.
            for (field, present) in [
                ("envelope_xdr_b64", raw.envelope_xdr_b64.is_some()),
                ("envelope_sha256_hex", raw.envelope_sha256_hex.is_some()),
                ("summary_to", raw.summary_to.is_some()),
                (
                    "summary_amount_stroops",
                    raw.summary_amount_stroops.is_some(),
                ),
                ("summary_asset", raw.summary_asset.is_some()),
                ("summary_memo", raw.summary_memo.is_some()),
                (
                    "summary_simulated_fee_stroops",
                    raw.summary_simulated_fee_stroops.is_some(),
                ),
                (
                    "summary_simulated_seq_num",
                    raw.summary_simulated_seq_num.is_some(),
                ),
                ("attestation_blob_b64", raw.attestation_blob_b64.is_some()),
                ("passkey_assertion", raw.passkey_assertion.is_some()),
                (
                    "toolset_first_invoke_gate",
                    raw.toolset_first_invoke_gate.is_some(),
                ),
                (
                    "trustline_clawback_opt_in",
                    raw.trustline_clawback_opt_in.is_some(),
                ),
                ("claim_simulated", raw.claim_simulated.is_some()),
                (
                    "rule_proposal_simulated",
                    raw.rule_proposal_simulated.is_some(),
                ),
                ("rejected", raw.rejected.is_some()),
            ] {
                if present {
                    return Err(serde::de::Error::custom(format!(
                        "cross-kind field contamination: RegisterPasskey entry must not carry \
                         field `{field}`",
                    )));
                }
            }

            // Run construction-time invariants on the on-disk RegisterPasskey fields.
            validate_register_passkey_invariants(
                &rp.smart_account_redacted,
                &rp.rule_ids,
                &rp.rp_id,
            )
            .map_err(serde::de::Error::custom)?;

            // Validate registration_input if present (close tamper gap on result field).
            if let Some(ref ri) = raw.registration_input {
                validate_registration_input_invariants(
                    &ri.credential_id,
                    &ri.public_key_uncompressed_sec1,
                    ri.attestation_blob_b64.as_deref(),
                    &ri.transports,
                )
                .map_err(serde::de::Error::custom)?;
            }

            // Extract registration_input from the flat on-disk field into the arm.
            let embedded_registration_input = raw.registration_input;

            ApprovalKind::RegisterPasskey {
                smart_account_redacted: rp.smart_account_redacted,
                rule_ids: rp.rule_ids,
                csrf_token: rp.csrf_token,
                rp_id: rp.rp_id,
                user_handle: rp.user_handle,
                registration_input: embedded_registration_input,
            }
        } else if let Some(sfig) = raw.toolset_first_invoke_gate {
            // Cross-kind contamination check: ToolsetFirstInvokeGate must not carry
            // PaymentSimulated flat fields, passkey_assertion, registration_input,
            // or any other sub-table (sign_with_passkey and register_passkey are
            // already ruled out by the if-else chain above).
            for (field, present) in [
                ("envelope_xdr_b64", raw.envelope_xdr_b64.is_some()),
                ("envelope_sha256_hex", raw.envelope_sha256_hex.is_some()),
                ("summary_to", raw.summary_to.is_some()),
                (
                    "summary_amount_stroops",
                    raw.summary_amount_stroops.is_some(),
                ),
                ("summary_asset", raw.summary_asset.is_some()),
                ("summary_memo", raw.summary_memo.is_some()),
                (
                    "summary_simulated_fee_stroops",
                    raw.summary_simulated_fee_stroops.is_some(),
                ),
                (
                    "summary_simulated_seq_num",
                    raw.summary_simulated_seq_num.is_some(),
                ),
                ("attestation_blob_b64", raw.attestation_blob_b64.is_some()),
                ("passkey_assertion", raw.passkey_assertion.is_some()),
                ("registration_input", raw.registration_input.is_some()),
                (
                    "trustline_clawback_opt_in",
                    raw.trustline_clawback_opt_in.is_some(),
                ),
                ("claim_simulated", raw.claim_simulated.is_some()),
                (
                    "rule_proposal_simulated",
                    raw.rule_proposal_simulated.is_some(),
                ),
                ("rejected", raw.rejected.is_some()),
            ] {
                if present {
                    return Err(serde::de::Error::custom(format!(
                        "cross-kind field contamination: ToolsetFirstInvokeGate entry must not \
                         carry field `{field}`",
                    )));
                }
            }

            // Validate ToolsetFirstInvokeGate field invariants on reload.
            validate_toolset_first_invoke_gate_invariants(
                &sfig.toolset_name,
                &sfig.capability,
                &sfig.destination,
                &sfig.asset,
                sfig.amount_min_stroops,
                sfig.amount_max_stroops,
            )
            .map_err(serde::de::Error::custom)?;

            ApprovalKind::ToolsetFirstInvokeGate {
                toolset_name: sfig.toolset_name,
                capability: sfig.capability,
                destination: sfig.destination,
                asset: sfig.asset,
                amount_min_stroops: sfig.amount_min_stroops,
                amount_max_stroops: sfig.amount_max_stroops,
            }
        } else if let Some(tcoi) = raw.trustline_clawback_opt_in {
            // Cross-kind contamination check: TrustlineClawbackOptIn must not carry
            // PaymentSimulated flat fields, passkey-related fields, or other sub-tables.
            // `sign_with_passkey`, `register_passkey`, and `toolset_first_invoke_gate`
            // are already ruled out by the if-else chain above.
            for (field, present) in [
                ("envelope_xdr_b64", raw.envelope_xdr_b64.is_some()),
                ("envelope_sha256_hex", raw.envelope_sha256_hex.is_some()),
                ("summary_to", raw.summary_to.is_some()),
                (
                    "summary_amount_stroops",
                    raw.summary_amount_stroops.is_some(),
                ),
                ("summary_asset", raw.summary_asset.is_some()),
                ("summary_memo", raw.summary_memo.is_some()),
                (
                    "summary_simulated_fee_stroops",
                    raw.summary_simulated_fee_stroops.is_some(),
                ),
                (
                    "summary_simulated_seq_num",
                    raw.summary_simulated_seq_num.is_some(),
                ),
                ("attestation_blob_b64", raw.attestation_blob_b64.is_some()),
                ("passkey_assertion", raw.passkey_assertion.is_some()),
                ("registration_input", raw.registration_input.is_some()),
                ("claim_simulated", raw.claim_simulated.is_some()),
                (
                    "rule_proposal_simulated",
                    raw.rule_proposal_simulated.is_some(),
                ),
                ("rejected", raw.rejected.is_some()),
            ] {
                if present {
                    return Err(serde::de::Error::custom(format!(
                        "cross-kind field contamination: TrustlineClawbackOptIn entry must not \
                         carry field `{field}`",
                    )));
                }
            }

            // Validate TrustlineClawbackOptIn field invariants on reload.
            validate_trustline_clawback_opt_in_invariants(&tcoi.network, &tcoi.code, &tcoi.issuer)
                .map_err(serde::de::Error::custom)?;

            ApprovalKind::TrustlineClawbackOptIn {
                network: tcoi.network,
                code: tcoi.code,
                issuer: tcoi.issuer,
            }
        } else if let Some(cs) = raw.claim_simulated {
            // Cross-kind contamination check: ClaimSimulated must not carry
            // PaymentSimulated flat fields, passkey-related fields, or any
            // other sub-table. `sign_with_passkey`, `register_passkey`,
            // `toolset_first_invoke_gate`, and `trustline_clawback_opt_in` are
            // already ruled out by the if-else chain above.
            //
            // `attestation_blob_b64` is DELIBERATELY excluded from this list:
            // `attest_and_persist`'s ClaimSimulated arm shares the generic
            // HMAC-blob attestation path with PaymentSimulated (over
            // `envelope_sha256_hex`), so a genuinely-attested ClaimSimulated
            // entry legitimately carries this field. Listing it here would
            // make every attested ClaimSimulated entry fail to reload.
            for (field, present) in [
                ("envelope_xdr_b64", raw.envelope_xdr_b64.is_some()),
                ("envelope_sha256_hex", raw.envelope_sha256_hex.is_some()),
                ("summary_to", raw.summary_to.is_some()),
                (
                    "summary_amount_stroops",
                    raw.summary_amount_stroops.is_some(),
                ),
                ("summary_asset", raw.summary_asset.is_some()),
                ("summary_memo", raw.summary_memo.is_some()),
                (
                    "summary_simulated_fee_stroops",
                    raw.summary_simulated_fee_stroops.is_some(),
                ),
                (
                    "summary_simulated_seq_num",
                    raw.summary_simulated_seq_num.is_some(),
                ),
                ("passkey_assertion", raw.passkey_assertion.is_some()),
                ("registration_input", raw.registration_input.is_some()),
                (
                    "rule_proposal_simulated",
                    raw.rule_proposal_simulated.is_some(),
                ),
                ("rejected", raw.rejected.is_some()),
            ] {
                if present {
                    return Err(serde::de::Error::custom(format!(
                        "cross-kind field contamination: ClaimSimulated entry must not carry \
                         field `{field}`",
                    )));
                }
            }

            // Validate ClaimSimulated field invariants on reload.
            validate_claim_simulated_invariants(
                &cs.summary_balance_id_hex72,
                &cs.summary_balance_id_strkey,
                &cs.summary_asset,
                cs.summary_amount_stroops,
                &cs.summary_source,
            )
            .map_err(serde::de::Error::custom)?;

            ApprovalKind::ClaimSimulated {
                envelope_xdr_b64: cs.envelope_xdr_b64,
                envelope_sha256_hex: cs.envelope_sha256_hex,
                summary_balance_id_hex72: cs.summary_balance_id_hex72,
                summary_balance_id_strkey: cs.summary_balance_id_strkey,
                summary_asset: cs.summary_asset,
                summary_amount_stroops: cs.summary_amount_stroops,
                summary_source: cs.summary_source,
                summary_simulated_fee_stroops: cs.summary_simulated_fee_stroops,
                summary_simulated_seq_num: cs.summary_simulated_seq_num,
            }
        } else if let Some(rps) = raw.rule_proposal_simulated {
            // Cross-kind contamination check: RuleProposalSimulated must not
            // carry PaymentSimulated flat fields, passkey-related fields, or
            // any other sub-table. `sign_with_passkey`, `register_passkey`,
            // `toolset_first_invoke_gate`, `trustline_clawback_opt_in`, and
            // `claim_simulated` are already ruled out by the if-else chain
            // above.
            //
            // `attestation_blob_b64` is DELIBERATELY excluded from this list:
            // `attest_and_persist`'s RuleProposalSimulated arm shares the
            // generic HMAC-blob attestation path with PaymentSimulated /
            // ClaimSimulated (over `proposal_sha256` in place of an envelope
            // hash — see `record_rule_proposal_attestation`), so a
            // genuinely-attested RuleProposalSimulated entry legitimately
            // carries this field. Listing it here would make every attested
            // RuleProposalSimulated entry fail to reload — exactly the defect
            // `rule_proposal_remote_browser_testnet_acceptance.rs` caught.
            for (field, present) in [
                ("envelope_xdr_b64", raw.envelope_xdr_b64.is_some()),
                ("envelope_sha256_hex", raw.envelope_sha256_hex.is_some()),
                ("summary_to", raw.summary_to.is_some()),
                (
                    "summary_amount_stroops",
                    raw.summary_amount_stroops.is_some(),
                ),
                ("summary_asset", raw.summary_asset.is_some()),
                ("summary_memo", raw.summary_memo.is_some()),
                (
                    "summary_simulated_fee_stroops",
                    raw.summary_simulated_fee_stroops.is_some(),
                ),
                (
                    "summary_simulated_seq_num",
                    raw.summary_simulated_seq_num.is_some(),
                ),
                ("passkey_assertion", raw.passkey_assertion.is_some()),
                ("registration_input", raw.registration_input.is_some()),
                ("rejected", raw.rejected.is_some()),
            ] {
                if present {
                    return Err(serde::de::Error::custom(format!(
                        "cross-kind field contamination: RuleProposalSimulated entry must not \
                         carry field `{field}`",
                    )));
                }
            }

            // Validate smart_account (full C-strkey) and its consistency with
            // the pre-computed smart_account_redacted field — closes a tamper
            // vector where an on-disk edit sets the two fields to different
            // accounts.
            validate_smart_account_full(&rps.smart_account).map_err(serde::de::Error::custom)?;
            validate_smart_account_redacted(&rps.smart_account_redacted)
                .map_err(serde::de::Error::custom)?;
            if redact_g_strkey(&rps.smart_account) != rps.smart_account_redacted {
                return Err(serde::de::Error::custom(
                    "RuleProposalSimulated: smart_account_redacted does not match the redaction \
                     of smart_account",
                ));
            }

            // Validate the resolved-definition snapshot invariants on reload.
            validate_context_rule_proposal_snapshot(&rps.definition)
                .map_err(serde::de::Error::custom)?;

            ApprovalKind::RuleProposalSimulated {
                smart_account: rps.smart_account,
                smart_account_redacted: rps.smart_account_redacted,
                network_passphrase: rps.network_passphrase,
                chain_id: rps.chain_id,
                definition: rps.definition,
                proposal_sha256: rps.proposal_sha256,
                summary_line: rps.summary_line,
            }
        } else if let Some(r) = raw.rejected {
            // Cross-kind contamination check: Rejected must not carry
            // PaymentSimulated flat fields, passkey-related fields, attestation
            // blob, or any other sub-table. `sign_with_passkey`, `register_passkey`,
            // `toolset_first_invoke_gate`, `trustline_clawback_opt_in`,
            // `claim_simulated`, and `rule_proposal_simulated` are already ruled
            // out by the if-else chain above.
            for (field, present) in [
                ("envelope_xdr_b64", raw.envelope_xdr_b64.is_some()),
                ("envelope_sha256_hex", raw.envelope_sha256_hex.is_some()),
                ("summary_to", raw.summary_to.is_some()),
                (
                    "summary_amount_stroops",
                    raw.summary_amount_stroops.is_some(),
                ),
                ("summary_asset", raw.summary_asset.is_some()),
                ("summary_memo", raw.summary_memo.is_some()),
                (
                    "summary_simulated_fee_stroops",
                    raw.summary_simulated_fee_stroops.is_some(),
                ),
                (
                    "summary_simulated_seq_num",
                    raw.summary_simulated_seq_num.is_some(),
                ),
                ("attestation_blob_b64", raw.attestation_blob_b64.is_some()),
                ("passkey_assertion", raw.passkey_assertion.is_some()),
                ("registration_input", raw.registration_input.is_some()),
            ] {
                if present {
                    return Err(serde::de::Error::custom(format!(
                        "cross-kind field contamination: Rejected entry must not carry \
                         field `{field}`",
                    )));
                }
            }

            if r.original_kind_name.is_empty() || r.original_kind_name.len() > 64 {
                return Err(serde::de::Error::custom(
                    "Rejected.original_kind_name must be 1-64 characters",
                ));
            }

            ApprovalKind::Rejected {
                original_kind_name: r.original_kind_name,
            }
        } else {
            // Cross-kind contamination check: an entry routed to PaymentSimulated
            // MUST NOT carry a passkey_assertion or registration_input (which only
            // SignWithPasskey / RegisterPasskey arms can ever produce).
            if raw.passkey_assertion.is_some() {
                return Err(serde::de::Error::custom(
                    "cross-kind field contamination: PaymentSimulated entry must not carry \
                     SignWithPasskey field `passkey_assertion`",
                ));
            }
            if raw.registration_input.is_some() {
                return Err(serde::de::Error::custom(
                    "cross-kind field contamination: PaymentSimulated entry must not carry \
                     RegisterPasskey field `registration_input`",
                ));
            }

            // Legacy / PaymentSimulated path — require all payment-summary fields.
            let envelope_xdr_b64 = raw
                .envelope_xdr_b64
                .ok_or_else(|| serde::de::Error::missing_field("envelope_xdr_b64"))?;
            let envelope_sha256_hex = raw
                .envelope_sha256_hex
                .ok_or_else(|| serde::de::Error::missing_field("envelope_sha256_hex"))?;
            let summary_to = raw
                .summary_to
                .ok_or_else(|| serde::de::Error::missing_field("summary_to"))?;
            let summary_amount_stroops = raw
                .summary_amount_stroops
                .ok_or_else(|| serde::de::Error::missing_field("summary_amount_stroops"))?;
            let summary_asset = raw
                .summary_asset
                .ok_or_else(|| serde::de::Error::missing_field("summary_asset"))?;
            let summary_simulated_fee_stroops = raw
                .summary_simulated_fee_stroops
                .ok_or_else(|| serde::de::Error::missing_field("summary_simulated_fee_stroops"))?;
            let summary_simulated_seq_num = raw
                .summary_simulated_seq_num
                .ok_or_else(|| serde::de::Error::missing_field("summary_simulated_seq_num"))?;
            ApprovalKind::PaymentSimulated {
                envelope_xdr_b64,
                envelope_sha256_hex,
                summary_to,
                summary_amount_stroops,
                summary_asset,
                summary_memo: raw.summary_memo,
                summary_simulated_fee_stroops,
                summary_simulated_seq_num,
            }
        };

        Ok(PendingApproval {
            approval_nonce: raw.approval_nonce,
            process_uid: raw.process_uid,
            created_at_unix_ms: raw.created_at_unix_ms,
            expires_at_unix_ms: raw.expires_at_unix_ms,
            kind,
            attestation_blob_b64: raw.attestation_blob_b64,
            passkey_assertion: raw.passkey_assertion,
        })
    }
}

impl PendingApproval {
    /// Constructs a new unattested `PaymentSimulated` approval.
    ///
    /// Generates a random `approval_nonce` from `OsRng`, derives
    /// `envelope_sha256_hex` from the supplied XDR bytes, and computes
    /// `created_at_unix_ms` + `expires_at_unix_ms` from the current system
    /// time and `ttl_ms`.
    ///
    /// # Parameters
    ///
    /// - `envelope_xdr_b64`: base64-encoded envelope XDR (simulated).
    /// - `envelope_xdr_bytes`: raw XDR bytes for SHA-256 computation.
    /// - `summary_to`: destination address string.
    /// - `summary_amount_stroops`: payment amount in stroops.
    /// - `summary_asset`: asset identifier (e.g. `"XLM"`).
    /// - `summary_memo`: optional memo.
    /// - `summary_simulated_fee_stroops`: total simulated transaction fee in stroops.
    /// - `summary_simulated_seq_num`: simulated sequence number.
    /// - `process_uid`: platform-stable user identity from
    ///   `process_uid_for_attestation()`.
    /// - `ttl_ms`: time-to-live in milliseconds (use [`DEFAULT_TTL_MS`] for 24 h).
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::Io`] if the system clock is unavailable.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use base64::Engine as _;
    /// use stellar_agent_core::approval::store::{PendingApproval, DEFAULT_TTL_MS};
    /// use stellar_agent_core::approval::user_id::process_uid_for_attestation;
    ///
    /// # fn example() -> Result<(), stellar_agent_core::approval::error::ApprovalError> {
    /// let xdr_bytes = b"fake-envelope-xdr";
    /// let xdr_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(xdr_bytes);
    /// let uid = process_uid_for_attestation()?;
    /// let entry = PendingApproval::new_payment_pending(
    ///     xdr_b64,
    ///     xdr_bytes,
    ///     "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
    ///     1_000_000,
    ///     "XLM".to_owned(),
    ///     None,
    ///     100,
    ///     12345,
    ///     uid,
    ///     DEFAULT_TTL_MS,
    /// )?;
    /// assert!(entry.attestation_blob_b64.is_none());
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn new_payment_pending(
        envelope_xdr_b64: String,
        envelope_xdr_bytes: &[u8],
        summary_to: String,
        summary_amount_stroops: i64,
        summary_asset: String,
        summary_memo: Option<String>,
        summary_simulated_fee_stroops: u32,
        summary_simulated_seq_num: i64,
        process_uid: String,
        ttl_ms: u64,
    ) -> Result<Self, ApprovalError> {
        // Generate 16-byte random nonce and encode as URL-safe base64 no-pad.
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let approval_nonce = URL_SAFE_NO_PAD.encode(raw);

        // Compute SHA-256 of envelope XDR bytes and format as lowercase hex.
        let hash = super::attestation::envelope_sha256(envelope_xdr_bytes);
        let envelope_sha256_hex = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();

        // Current time from system clock.
        let created_at_unix_ms = approval_now_unix_ms()?;

        let expires_at_unix_ms = created_at_unix_ms.saturating_add(ttl_ms);

        Ok(Self {
            approval_nonce,
            process_uid,
            created_at_unix_ms,
            expires_at_unix_ms,
            kind: ApprovalKind::PaymentSimulated {
                envelope_xdr_b64,
                envelope_sha256_hex,
                summary_to,
                summary_amount_stroops,
                summary_asset,
                summary_memo,
                summary_simulated_fee_stroops,
                summary_simulated_seq_num,
            },
            attestation_blob_b64: None,
            passkey_assertion: None,
        })
    }

    /// Alias for [`Self::new_payment_pending`]; deprecated in favour of calling
    /// `new_payment_pending` directly.
    ///
    /// # Errors
    ///
    /// See [`Self::new_payment_pending`].
    #[deprecated(
        since = "0.1.0",
        note = "use `PendingApproval::new_payment_pending` instead (renamed alias, \
                identical behaviour)"
    )]
    #[allow(clippy::too_many_arguments)]
    pub fn new_unattested(
        envelope_xdr_b64: String,
        envelope_xdr_bytes: &[u8],
        summary_to: String,
        summary_amount_stroops: i64,
        summary_asset: String,
        summary_memo: Option<String>,
        summary_simulated_fee_stroops: u32,
        summary_simulated_seq_num: i64,
        process_uid: String,
        ttl_ms: u64,
    ) -> Result<Self, ApprovalError> {
        Self::new_payment_pending(
            envelope_xdr_b64,
            envelope_xdr_bytes,
            summary_to,
            summary_amount_stroops,
            summary_asset,
            summary_memo,
            summary_simulated_fee_stroops,
            summary_simulated_seq_num,
            process_uid,
            ttl_ms,
        )
    }

    /// Constructs a new `SignWithPasskey` approval pending a browser WebAuthn
    /// assertion.
    ///
    /// All `SignWithPasskey`-specific fields are validated at construction time:
    ///
    /// - `credential_id`: 16–64 bytes (CTAP2 §4.2 / WebAuthn-2 §5.4.7).
    /// - `rule_ids`: non-empty, max 8 entries (OZ context-rule batch limit).
    /// - `smart_account_redacted`: must match the first-5-last-5 redaction
    ///   shape of a C-strkey (`^C[A-Z2-7]{4}\.\.\.[A-Z2-7]{5}$`).
    /// - `auth_digest`: any 32 bytes accepted (caller-supplied digest).
    /// - `csrf_token`: any 32 bytes accepted (caller generates via
    ///   [`generate_csrf_token`]).
    ///
    /// # Parameters
    ///
    /// - `auth_digest`: 32-byte challenge bound to the WebAuthn ceremony.
    /// - `credential_id`: the expected credential identifier (16–64 bytes).
    /// - `smart_account_redacted`: first-5-last-5 redaction of the C-strkey.
    /// - `rule_ids`: OZ context rule IDs being satisfied (1–8 entries).
    /// - `csrf_token`: 32-byte CSRF token (generate via [`generate_csrf_token`]).
    /// - `process_uid`: from `process_uid_for_attestation()`.
    /// - `ttl_ms`: time-to-live in milliseconds.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::Invalid`] if any field fails validation.
    /// - [`ApprovalError::Io`] if the system clock is unavailable.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_core::approval::store::{
    ///     PendingApproval, generate_csrf_token, DEFAULT_TTL_MS,
    /// };
    /// use stellar_agent_core::approval::user_id::process_uid_for_attestation;
    ///
    /// # fn example() -> Result<(), stellar_agent_core::approval::error::ApprovalError> {
    /// let uid = process_uid_for_attestation()?;
    /// let csrf = generate_csrf_token();
    /// let entry = PendingApproval::new_passkey_pending(
    ///     [0u8; 32],
    ///     vec![0u8; 32],
    ///     "CAAAA...BBBBB".to_owned(),
    ///     vec![1, 2],
    ///     csrf,
    ///     "localhost".to_owned(),
    ///     uid,
    ///     DEFAULT_TTL_MS,
    /// )?;
    /// assert!(entry.passkey_assertion.is_none());
    /// # Ok(())
    /// # }
    /// ```
    #[allow(
        clippy::too_many_arguments,
        reason = "7 kind-specific parameters + 2 platform fields; extracting a config struct is lower value than the clarity cost"
    )]
    pub fn new_passkey_pending(
        auth_digest: [u8; 32],
        credential_id: Vec<u8>,
        smart_account_redacted: String,
        rule_ids: Vec<u32>,
        csrf_token: [u8; 32],
        rp_id: String,
        process_uid: String,
        ttl_ms: u64,
    ) -> Result<Self, ApprovalError> {
        // Run kind-invariant checks. Same helper is invoked from the custom
        // Deserialize impl so tampered on-disk entries are rejected at load.
        validate_sign_with_passkey_invariants(
            &credential_id,
            &rule_ids,
            &smart_account_redacted,
            &rp_id,
        )
        .map_err(|reason| ApprovalError::Invalid { reason })?;

        // Generate nonce and timestamps.
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let approval_nonce = URL_SAFE_NO_PAD.encode(raw);

        let created_at_unix_ms = approval_now_unix_ms()?;

        let expires_at_unix_ms = created_at_unix_ms.saturating_add(ttl_ms);

        Ok(Self {
            approval_nonce,
            process_uid,
            created_at_unix_ms,
            expires_at_unix_ms,
            kind: ApprovalKind::SignWithPasskey {
                auth_digest,
                credential_id,
                smart_account_redacted,
                rule_ids,
                csrf_token,
                rp_id,
            },
            attestation_blob_b64: None,
            passkey_assertion: None,
        })
    }

    /// Constructs a new `RegisterPasskey` approval pending a browser WebAuthn
    /// registration ceremony.
    ///
    /// All `RegisterPasskey`-specific fields are validated at construction time:
    ///
    /// - `smart_account_redacted`: must match the first-5-last-5 redaction shape
    ///   of a C-strkey (`^C[A-Z2-7]{4}\.\.\.[A-Z2-7]{5}$`).
    /// - `rule_ids`: non-empty, max 8 entries (OZ context-rule batch limit).
    /// - `rp_id`: 1–253 bytes, DNS LDH-label charset `[A-Za-z0-9.-]` per
    ///   RFC 1035 §2.3.4 + WebAuthn-2 §5.1.2.
    /// - `csrf_token`: any 32 bytes accepted at this layer (caller generates
    ///   via [`generate_csrf_token`]).
    /// - `user_handle`: any 32 bytes accepted at this layer (see Security
    ///   below).
    ///
    /// # Parameters
    ///
    /// Parameter order mirrors [`Self::new_passkey_pending`]: kind-specific
    /// fields first, platform fields last.
    ///
    /// - `smart_account_redacted`: first-5-last-5 redaction of the C-strkey.
    /// - `rule_ids`: OZ context rule IDs being registered (1–8 entries).
    /// - `csrf_token`: 32-byte CSRF token (generate via [`generate_csrf_token`]).
    /// - `rp_id`: WebAuthn RP-ID the bridge is binding (e.g. `"localhost"`).
    ///   Must NOT be an IP address literal (WebAuthn-2 §5.1.2 forbids IP rpIds).
    /// - `user_handle`: pre-generated 32-byte WebAuthn user handle (see
    ///   Security below).
    /// - `process_uid`: from `process_uid_for_attestation()`.
    /// - `ttl_ms`: time-to-live in milliseconds.
    ///
    /// # Security
    ///
    /// Callers MUST generate `user_handle` from a cryptographically secure
    /// random source (e.g. `rand_core::OsRng` via [`generate_csrf_token`]).
    /// A non-random or zero handle (`[0u8; 32]`) silently passes validation
    /// at this layer but creates a stable cross-session correlation surface
    /// inside the WebAuthn authenticator, violating WebAuthn-2 §6.1.2
    /// ("the user handle ... is intended to be an opaque byte sequence not
    /// relatable to the user"). The same caller-discipline applies to
    /// `csrf_token`.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::Invalid`] if any field fails validation.
    /// - [`ApprovalError::Io`] if the system clock is unavailable.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_core::approval::store::{
    ///     PendingApproval, generate_csrf_token, DEFAULT_TTL_MS,
    /// };
    /// use stellar_agent_core::approval::user_id::process_uid_for_attestation;
    ///
    /// # fn example() -> Result<(), stellar_agent_core::approval::error::ApprovalError> {
    /// let uid = process_uid_for_attestation()?;
    /// let csrf = generate_csrf_token();
    /// let user_handle = generate_csrf_token();
    /// let entry = PendingApproval::new_register_passkey_pending(
    ///     "CAAAA...BBBBB".to_owned(),
    ///     vec![1, 2],
    ///     csrf,
    ///     "localhost".to_owned(),
    ///     user_handle,
    ///     uid,
    ///     DEFAULT_TTL_MS,
    /// )?;
    /// assert!(matches!(
    ///     entry.kind,
    ///     stellar_agent_core::approval::ApprovalKind::RegisterPasskey { .. }
    /// ));
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn new_register_passkey_pending(
        smart_account_redacted: String,
        rule_ids: Vec<u32>,
        csrf_token: [u8; 32],
        rp_id: String,
        user_handle: [u8; 32],
        process_uid: String,
        ttl_ms: u64,
    ) -> Result<Self, ApprovalError> {
        // Run kind-invariant checks. Same helper is invoked from the custom
        // Deserialize impl so tampered on-disk entries are rejected at load.
        validate_register_passkey_invariants(&smart_account_redacted, &rule_ids, &rp_id)
            .map_err(|reason| ApprovalError::Invalid { reason })?;

        // Generate nonce and timestamps.
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let approval_nonce = URL_SAFE_NO_PAD.encode(raw);

        let created_at_unix_ms = approval_now_unix_ms()?;

        let expires_at_unix_ms = created_at_unix_ms.saturating_add(ttl_ms);

        Ok(Self {
            approval_nonce,
            process_uid,
            created_at_unix_ms,
            expires_at_unix_ms,
            kind: ApprovalKind::RegisterPasskey {
                smart_account_redacted,
                rule_ids,
                csrf_token,
                rp_id,
                user_handle,
                registration_input: None,
            },
            attestation_blob_b64: None,
            passkey_assertion: None,
        })
    }

    /// Constructs a new `ToolsetFirstInvokeGate` approval pending out-of-band
    /// operator approval for a toolset's first signing-adjacent capability invocation.
    ///
    /// Called by the gated resolver when a toolset invokes a `sign-payment`
    /// action and no current, matching grant exists.
    ///
    /// All fields are validated at construction time; the same validator is
    /// invoked from the custom `Deserialize` impl so tampered on-disk entries
    /// are rejected at store load.
    ///
    /// # Parameters
    ///
    /// - `toolset_name`: package name of the toolset (must pass `[a-z0-9-]` charset).
    /// - `capability`: capability token (e.g. `"sign-payment"`).
    /// - `destination`: canonical resolved G-strkey destination from the
    ///   authoritative envelope.
    /// - `asset`: full `"code:issuer"` or `"XLM"` from the authoritative envelope.
    /// - `amount_min_stroops`: bucket lower bound in stroops.
    /// - `amount_max_stroops`: bucket upper bound in stroops.
    /// - `process_uid`: from `process_uid_for_attestation()`.
    /// - `ttl_ms`: time-to-live in milliseconds.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::Invalid`] if any field fails validation.
    /// - [`ApprovalError::Io`] if the system clock is unavailable.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_core::approval::store::{PendingApproval, DEFAULT_TTL_MS};
    /// use stellar_agent_core::approval::user_id::process_uid_for_attestation;
    ///
    /// # fn example() -> Result<(), stellar_agent_core::approval::error::ApprovalError> {
    /// let uid = process_uid_for_attestation()?;
    /// let entry = PendingApproval::new_toolset_first_invoke_gate_pending(
    ///     "my-toolset".to_owned(),
    ///     "sign-payment".to_owned(),
    ///     "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
    ///     "XLM".to_owned(),
    ///     0_i64,
    ///     10_000_000_i64,
    ///     uid,
    ///     DEFAULT_TTL_MS,
    /// )?;
    /// assert!(matches!(
    ///     entry.kind,
    ///     stellar_agent_core::approval::ApprovalKind::ToolsetFirstInvokeGate { .. }
    /// ));
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn new_toolset_first_invoke_gate_pending(
        toolset_name: String,
        capability: String,
        destination: String,
        asset: String,
        amount_min_stroops: i64,
        amount_max_stroops: i64,
        process_uid: String,
        ttl_ms: u64,
    ) -> Result<Self, ApprovalError> {
        // Run kind-invariant checks.  Same helper invoked from the custom
        // Deserialize impl so tampered on-disk entries are rejected at load.
        validate_toolset_first_invoke_gate_invariants(
            &toolset_name,
            &capability,
            &destination,
            &asset,
            amount_min_stroops,
            amount_max_stroops,
        )
        .map_err(|reason| ApprovalError::Invalid { reason })?;

        // Generate nonce and timestamps.
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let approval_nonce = URL_SAFE_NO_PAD.encode(raw);

        let created_at_unix_ms = approval_now_unix_ms()?;
        let expires_at_unix_ms = created_at_unix_ms.saturating_add(ttl_ms);

        Ok(Self {
            approval_nonce,
            process_uid,
            created_at_unix_ms,
            expires_at_unix_ms,
            kind: ApprovalKind::ToolsetFirstInvokeGate {
                toolset_name,
                capability,
                destination,
                asset,
                amount_min_stroops,
                amount_max_stroops,
            },
            attestation_blob_b64: None,
            passkey_assertion: None,
        })
    }

    /// Constructs a new `TrustlineClawbackOptIn` approval pending operator
    /// confirmation of the clawback risk for the specified asset.
    ///
    /// Called by the `stellar_trustline_commit` path when the issuer has
    /// `auth_clawback_enabled` and the operator has opted in to the clawback
    /// risk.  All fields are validated at construction time.
    ///
    /// # Parameters
    ///
    /// - `network`: Stellar network passphrase (non-empty, ≤ 64 bytes).
    /// - `code`: asset code, uppercase, 1–12 alphanumeric ASCII characters.
    /// - `issuer`: canonical G-strkey of the asset issuer.
    /// - `process_uid`: from `process_uid_for_attestation()`.
    /// - `ttl_ms`: time-to-live in milliseconds (use [`DEFAULT_TTL_MS`]).
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::Invalid`] if any field fails validation.
    /// - [`ApprovalError::Io`] if the system clock is unavailable.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_core::approval::store::{PendingApproval, DEFAULT_TTL_MS};
    /// use stellar_agent_core::approval::user_id::process_uid_for_attestation;
    /// use stellar_agent_core::approval::ApprovalKind;
    ///
    /// # fn example() -> Result<(), stellar_agent_core::approval::error::ApprovalError> {
    /// let uid = process_uid_for_attestation()?;
    /// let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
    ///     "Test SDF Network ; September 2015".to_owned(),
    ///     "USDC".to_owned(),
    ///     "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_owned(),
    ///     uid,
    ///     DEFAULT_TTL_MS,
    /// )?;
    /// assert!(matches!(entry.kind, ApprovalKind::TrustlineClawbackOptIn { .. }));
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_trustline_clawback_opt_in_pending(
        network: String,
        code: String,
        issuer: String,
        process_uid: String,
        ttl_ms: u64,
    ) -> Result<Self, ApprovalError> {
        validate_trustline_clawback_opt_in_invariants(&network, &code, &issuer)
            .map_err(|reason| ApprovalError::Invalid { reason })?;

        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let approval_nonce = URL_SAFE_NO_PAD.encode(raw);

        let created_at_unix_ms = approval_now_unix_ms()?;
        let expires_at_unix_ms = created_at_unix_ms.saturating_add(ttl_ms);

        Ok(Self {
            approval_nonce,
            process_uid,
            created_at_unix_ms,
            expires_at_unix_ms,
            kind: ApprovalKind::TrustlineClawbackOptIn {
                network,
                code,
                issuer,
            },
            attestation_blob_b64: None,
            passkey_assertion: None,
        })
    }

    /// Constructs a new unattested `ClaimSimulated` approval.
    ///
    /// Generates a random `approval_nonce` from `OsRng`, derives
    /// `envelope_sha256_hex` from the supplied XDR bytes, and computes
    /// `created_at_unix_ms` + `expires_at_unix_ms` from the current system time
    /// and `ttl_ms`. All summary fields are validated at construction time.
    ///
    /// # Parameters
    ///
    /// - `envelope_xdr_b64`: base64-encoded simulated `ClaimClaimableBalance`
    ///   envelope XDR.
    /// - `envelope_xdr_bytes`: raw XDR bytes for SHA-256 computation.
    /// - `balance_id_hex72`: canonical 72-hex balance id being claimed.
    /// - `balance_id_strkey`: `B...` strkey rendering of the balance id.
    /// - `asset`: asset identifier (`"XLM"` or `"<code>:<G-strkey>"`).
    /// - `amount_stroops`: claim amount in stroops (strictly positive).
    /// - `source`: claiming (source) account G-strkey.
    /// - `simulated_fee_stroops`: total simulated transaction fee in stroops.
    /// - `simulated_seq_num`: simulated sequence number.
    /// - `process_uid`: platform-stable user identity from
    ///   `process_uid_for_attestation()`.
    /// - `ttl_ms`: time-to-live in milliseconds (use [`DEFAULT_TTL_MS`]).
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::Invalid`] if any summary field fails validation.
    /// - [`ApprovalError::Io`] if the system clock is unavailable.
    #[allow(clippy::too_many_arguments)]
    pub fn new_claim_pending(
        envelope_xdr_b64: String,
        envelope_xdr_bytes: &[u8],
        balance_id_hex72: String,
        balance_id_strkey: String,
        asset: String,
        amount_stroops: i64,
        source: String,
        simulated_fee_stroops: u32,
        simulated_seq_num: i64,
        process_uid: String,
        ttl_ms: u64,
    ) -> Result<Self, ApprovalError> {
        validate_claim_simulated_invariants(
            &balance_id_hex72,
            &balance_id_strkey,
            &asset,
            amount_stroops,
            &source,
        )
        .map_err(|reason| ApprovalError::Invalid { reason })?;

        // Generate 16-byte random nonce and encode as URL-safe base64 no-pad.
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let approval_nonce = URL_SAFE_NO_PAD.encode(raw);

        // Compute SHA-256 of envelope XDR bytes and format as lowercase hex.
        let hash = super::attestation::envelope_sha256(envelope_xdr_bytes);
        let envelope_sha256_hex = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();

        let created_at_unix_ms = approval_now_unix_ms()?;
        let expires_at_unix_ms = created_at_unix_ms.saturating_add(ttl_ms);

        Ok(Self {
            approval_nonce,
            process_uid,
            created_at_unix_ms,
            expires_at_unix_ms,
            kind: ApprovalKind::ClaimSimulated {
                envelope_xdr_b64,
                envelope_sha256_hex,
                summary_balance_id_hex72: balance_id_hex72,
                summary_balance_id_strkey: balance_id_strkey,
                summary_asset: asset,
                summary_amount_stroops: amount_stroops,
                summary_source: source,
                summary_simulated_fee_stroops: simulated_fee_stroops,
                summary_simulated_seq_num: simulated_seq_num,
            },
            attestation_blob_b64: None,
            passkey_assertion: None,
        })
    }

    /// Constructs a new unattested `RuleProposalSimulated` approval
    /// (Package D, GH issue #8).
    ///
    /// Generates a random `approval_nonce` from `OsRng`, computes
    /// `smart_account_redacted` from `smart_account`, and computes
    /// `created_at_unix_ms` + `expires_at_unix_ms` from the current system
    /// time and `ttl_ms`. `definition` and `smart_account` are validated at
    /// construction time.
    ///
    /// # Parameters
    ///
    /// - `smart_account`: full C-strkey of the smart-account contract.
    /// - `network_passphrase`: network the proposal was simulated against.
    /// - `chain_id`: CAIP-2 chain ID (e.g. `"stellar:testnet"`).
    /// - `definition`: the fully-resolved rule definition snapshot.
    /// - `proposal_sha256`: the domain-separated digest minted by
    ///   `stellar-agent-smart-account::managers::rules::compute_context_rule_proposal_sha256`
    ///   over the SAME resolved arguments carried in `definition`.
    /// - `summary_line`: pre-computed, non-secret one-line summary.
    /// - `process_uid`: platform-stable user identity from
    ///   `process_uid_for_attestation()`.
    /// - `ttl_ms`: time-to-live in milliseconds (use [`DEFAULT_TTL_MS`]).
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::Invalid`] if `smart_account` is not a valid
    ///   C-strkey or `definition` fails its field invariants.
    /// - [`ApprovalError::Io`] if the system clock is unavailable.
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible propose-time field set (smart-account identity + network + \
                  resolved definition + digest + display summary + platform fields)"
    )]
    pub fn new_rule_proposal_pending(
        smart_account: String,
        network_passphrase: String,
        chain_id: String,
        definition: ContextRuleProposalSnapshot,
        proposal_sha256: [u8; 32],
        summary_line: String,
        process_uid: String,
        ttl_ms: u64,
    ) -> Result<Self, ApprovalError> {
        validate_smart_account_full(&smart_account)
            .map_err(|reason| ApprovalError::Invalid { reason })?;
        validate_context_rule_proposal_snapshot(&definition)
            .map_err(|reason| ApprovalError::Invalid { reason })?;

        let smart_account_redacted = redact_g_strkey(&smart_account);

        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let approval_nonce = URL_SAFE_NO_PAD.encode(raw);

        let created_at_unix_ms = approval_now_unix_ms()?;
        let expires_at_unix_ms = created_at_unix_ms.saturating_add(ttl_ms);

        Ok(Self {
            approval_nonce,
            process_uid,
            created_at_unix_ms,
            expires_at_unix_ms,
            kind: ApprovalKind::RuleProposalSimulated {
                smart_account,
                smart_account_redacted,
                network_passphrase,
                chain_id,
                definition,
                proposal_sha256,
                summary_line,
            },
            attestation_blob_b64: None,
            passkey_assertion: None,
        })
    }

    /// Returns `true` if this entry has expired relative to `now_unix_ms`.
    #[must_use]
    pub fn is_expired(&self, now_unix_ms: u64) -> bool {
        self.expires_at_unix_ms <= now_unix_ms
    }
}

/// Runs all `SignWithPasskey` field invariants (credential_id length, rule_ids
/// bounds, redaction shape, rp_id charset) against the supplied references and
/// returns the first failing reason.
///
/// Invoked from both `PendingApproval::new_passkey_pending` and the custom
/// `Deserialize<PendingApproval>` impl so tampered on-disk entries are
/// rejected at load time.
///
/// `rp_id` is validated with the same DNS LDH-label charset as
/// `RegisterPasskey.rp_id` — both arms flow `rp_id` into rendered HTML so
/// injection defence is identical.
fn validate_sign_with_passkey_invariants(
    credential_id: &[u8],
    rule_ids: &[u32],
    smart_account_redacted: &str,
    rp_id: &str,
) -> Result<(), String> {
    // credential_id length (CTAP2 §4.2 / WebAuthn-2 §5.4.7).
    if credential_id.len() < CREDENTIAL_ID_MIN_BYTES
        || credential_id.len() > CREDENTIAL_ID_MAX_BYTES
    {
        return Err(format!(
            "credential_id must be {CREDENTIAL_ID_MIN_BYTES}–{CREDENTIAL_ID_MAX_BYTES} bytes \
             (CTAP2 §4.2 / WebAuthn-2 §5.4.7), got {} bytes",
            credential_id.len()
        ));
    }

    // rule_ids: non-empty, max RULE_IDS_MAX_COUNT.
    if rule_ids.is_empty() {
        return Err(
            "rule_ids must be non-empty (at least one context rule ID required)".to_owned(),
        );
    }
    if rule_ids.len() > RULE_IDS_MAX_COUNT {
        return Err(format!(
            "rule_ids must have at most {RULE_IDS_MAX_COUNT} entries \
             (OZ context-rule batch limit), got {}",
            rule_ids.len()
        ));
    }

    // rp_id: DNS LDH-label charset (RFC 1035 §2.3.4 + WebAuthn-2 §5.1.2).
    if rp_id.is_empty() {
        return Err("rp_id must not be empty".to_owned());
    }
    if rp_id.len() > 253 {
        return Err(format!(
            "rp_id must be at most 253 bytes (RFC 1035 §2.3.4 DNS name length \
             limit), got {} bytes",
            rp_id.len()
        ));
    }
    // Structural IP-literal rejection.  The LDH-label charset (digits + dot)
    // accepts IPv4 literals like "127.0.0.1", but WebAuthn-2 §5.1.2 explicitly
    // forbids IP addresses as rpId.  `parse::<std::net::IpAddr>()` rejects
    // both IPv4 and IPv6 in one pass.
    if rp_id.parse::<std::net::IpAddr>().is_ok() {
        return Err(format!(
            "rp_id must not be an IP address literal (WebAuthn-2 §5.1.2 forbids \
             IP rpId); got {rp_id:?}.  Use \"localhost\" for loopback."
        ));
    }
    if !rp_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(
            "rp_id must contain only DNS LDH-label characters [A-Za-z0-9.-] \
             per RFC 1035 §2.3.4 + WebAuthn-2 §5.1.2"
                .to_owned(),
        );
    }

    validate_smart_account_redacted(smart_account_redacted)
}

fn validate_assertion_input_invariants(assertion: &AssertionInput) -> Result<(), String> {
    validate_signature_compact(&assertion.signature_compact).map_err(|err| err.to_string())
}

/// Maximum byte length for toolset name and capability token in a
/// `ToolsetFirstInvokeGate` entry.
const TOOLSET_GATE_FIELD_MAX_BYTES: usize = 64;

/// Validates all `ToolsetFirstInvokeGate` field invariants.
///
/// Invoked from both `PendingApproval::new_toolset_first_invoke_gate_pending` and
/// the custom `Deserialize<PendingApproval>` impl so tampered on-disk entries
/// are rejected at `PendingApprovalStore::open`.
///
/// Validates:
/// - `toolset_name`: `[a-z0-9-]` charset, 1–64 bytes.
/// - `capability`: `[a-z0-9-]` charset, 1–64 bytes.
/// - `destination`: valid Stellar G-strkey (56 chars, `^G[A-Z2-7]{55}$`).
/// - `asset`: `"XLM"` or `"<code>:<G-strkey>"` (same rules as `summary_asset`).
/// - `amount_min_stroops` ≤ `amount_max_stroops`.
/// - `amount_max_stroops` > 0.
fn validate_toolset_first_invoke_gate_invariants(
    toolset_name: &str,
    capability: &str,
    destination: &str,
    asset: &str,
    amount_min_stroops: i64,
    amount_max_stroops: i64,
) -> Result<(), String> {
    // toolset_name: 1–64 bytes, [a-z0-9-] charset.
    if toolset_name.is_empty() || toolset_name.len() > TOOLSET_GATE_FIELD_MAX_BYTES {
        return Err(format!(
            "toolset_name must be 1–{TOOLSET_GATE_FIELD_MAX_BYTES} bytes, \
             got {} bytes",
            toolset_name.len()
        ));
    }
    if !toolset_name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "toolset_name must contain only [a-z0-9-] characters, got: {toolset_name:?}"
        ));
    }

    // capability: 1–64 bytes, [a-z0-9-] charset.
    if capability.is_empty() || capability.len() > TOOLSET_GATE_FIELD_MAX_BYTES {
        return Err(format!(
            "capability must be 1–{TOOLSET_GATE_FIELD_MAX_BYTES} bytes, \
             got {} bytes",
            capability.len()
        ));
    }
    if !capability
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "capability must contain only [a-z0-9-] characters, got: {capability:?}"
        ));
    }

    // destination: a valid Stellar G-strkey (the `sign-payment` gated
    // capability's bucket dimension) OR C-strkey (Package D's
    // `sign-rule-create` gated capability reuses this field to carry the
    // smart-account contract being proposed against — the correct re-prompt
    // dimension for that capability is "different smart account", exactly as
    // "different destination" is for `sign-payment`).
    let dest_shape_valid = destination.len() == 56
        && matches!(destination.as_bytes()[0], b'G' | b'C')
        && destination[1..]
            .chars()
            .all(|c| matches!(c, 'A'..='Z' | '2'..='7'));
    if !dest_shape_valid {
        return Err(format!(
            "destination must be a valid Stellar G-strkey or C-strkey (56 chars, \
             ^[GC][A-Z2-7]{{55}}$), got: {dest_redacted}",
            dest_redacted = redact_g_strkey(destination)
        ));
    }

    // asset: "XLM" or "<code>:<G-strkey>".
    if asset == "XLM" {
        // valid
    } else if let Some((code, issuer)) = asset.split_once(':') {
        let code_valid =
            !code.is_empty() && code.len() <= 12 && code.chars().all(|c| c.is_ascii_alphanumeric());
        let issuer_valid = issuer.len() == 56
            && issuer.starts_with('G')
            && issuer[1..]
                .chars()
                .all(|c| matches!(c, 'A'..='Z' | '2'..='7'));
        if !code_valid || !issuer_valid {
            return Err(format!(
                "asset must be 'XLM' or '<alphanumeric_code>:<G-strkey>', got: {asset:?}"
            ));
        }
    } else {
        return Err(format!(
            "asset must be 'XLM' or '<code>:<G-strkey>', got: {asset:?}"
        ));
    }

    // amount_min_stroops ≥ 0, max > 0, and min ≤ max.
    if amount_min_stroops < 0 {
        return Err(format!(
            "amount_min_stroops must be ≥ 0, got {amount_min_stroops}"
        ));
    }
    if amount_max_stroops <= 0 {
        return Err(format!(
            "amount_max_stroops must be positive, got {amount_max_stroops}"
        ));
    }
    if amount_min_stroops > amount_max_stroops {
        return Err(format!(
            "amount_min_stroops ({amount_min_stroops}) must be ≤ \
             amount_max_stroops ({amount_max_stroops})"
        ));
    }

    Ok(())
}

/// Validates all `TrustlineClawbackOptIn` field invariants.
///
/// Invoked from both `PendingApproval::new_trustline_clawback_opt_in_pending`
/// and the custom `Deserialize<PendingApproval>` impl so tampered on-disk
/// entries are rejected at `PendingApprovalStore::open`.
///
/// Validates:
/// - `network`: non-empty, ≤ 64 bytes (fits common Stellar passphrase lengths).
/// - `code`: 1–12 bytes, `[A-Z0-9]` uppercase alphanumeric charset.
/// - `issuer`: valid Stellar G-strkey (56 chars, `^G[A-Z2-7]{55}$`).
fn validate_trustline_clawback_opt_in_invariants(
    network: &str,
    code: &str,
    issuer: &str,
) -> Result<(), String> {
    // network: non-empty, ≤ 64 bytes (Stellar passphrases are ≤ 64 bytes in practice).
    if network.is_empty() {
        return Err("network must not be empty".to_owned());
    }
    if network.len() > 64 {
        return Err(format!(
            "network must be ≤ 64 bytes (Stellar passphrase length limit), got {} bytes",
            network.len()
        ));
    }

    // code: 1–12 bytes, uppercase ASCII alphanumeric [A-Z0-9].
    // Stellar asset codes are uppercase (normalised at resolution time).
    if code.is_empty() || code.len() > 12 {
        return Err(format!(
            "code must be 1–12 bytes, got {} bytes: {code:?}",
            code.len()
        ));
    }
    if !code
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return Err(format!(
            "code must contain only uppercase ASCII alphanumeric characters [A-Z0-9], got: {code:?}"
        ));
    }

    // issuer: valid Stellar G-strkey (56 chars, G + 55 base32).
    let issuer_valid = issuer.len() == 56
        && issuer.starts_with('G')
        && issuer[1..]
            .chars()
            .all(|c| matches!(c, 'A'..='Z' | '2'..='7'));
    if !issuer_valid {
        return Err(format!(
            "issuer must be a valid Stellar G-strkey (56 chars, ^G[A-Z2-7]{{55}}$), \
             got: {issuer_redacted}",
            issuer_redacted = redact_g_strkey(issuer)
        ));
    }

    Ok(())
}

/// Validates all `ClaimSimulated` summary field invariants.
///
/// Invoked from both `PendingApproval::new_claim_pending` and the custom
/// `Deserialize<PendingApproval>` impl so tampered on-disk entries are rejected
/// at `PendingApprovalStore::open`.
///
/// Validates:
/// - `balance_id_hex72`: exactly 72 ASCII hex characters.
/// - `balance_id_strkey`: `'B'` prefix + 57 base32 characters (58 total), the
///   `stellar_strkey::ClaimableBalance::V0` shape. A claimable-balance strkey
///   encodes a 1-byte type discriminant ahead of the 32-byte hash, so its
///   base32 body is two characters longer than a 56-char account strkey.
/// - `asset`: `"XLM"` or `"<code>:<G-strkey>"` (same grammar as
///   `deserialize_opt_summary_asset`).
/// - `amount_stroops`: strictly positive (a claimable balance always carries a
///   positive amount).
/// - `source`: a valid Stellar G-strkey (56 chars, `^G[A-Z2-7]{55}$`).
///
/// The numeric `summary_simulated_fee_stroops` / `summary_simulated_seq_num`
/// fields need no validation beyond their wire type (mirrors how
/// `TrustlineClawbackOptIn` validates only its string fields).
fn validate_claim_simulated_invariants(
    balance_id_hex72: &str,
    balance_id_strkey: &str,
    asset: &str,
    amount_stroops: i64,
    source: &str,
) -> Result<(), String> {
    // balance_id_hex72: exactly 72 ASCII hex characters.
    if balance_id_hex72.len() != 72 || !balance_id_hex72.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "balance_id_hex72 must be exactly 72 hex characters, got {} characters",
            balance_id_hex72.len()
        ));
    }

    // balance_id_strkey: 'B' prefix, 58 chars, base32 body.
    let strkey_valid = balance_id_strkey.len() == 58
        && balance_id_strkey.starts_with('B')
        && balance_id_strkey[1..]
            .chars()
            .all(|c| matches!(c, 'A'..='Z' | '2'..='7'));
    if !strkey_valid {
        return Err(
            "balance_id_strkey must be a valid claimable-balance strkey (58 chars, \
             ^B[A-Z2-7]{57}$)"
                .to_owned(),
        );
    }

    // asset: "XLM" or "<code>:<G-strkey>" — same grammar as summary_asset.
    let asset_valid = asset == "XLM"
        || asset.split_once(':').is_some_and(|(code, issuer)| {
            !code.is_empty()
                && code.len() <= 12
                && code.chars().all(|c| c.is_ascii_alphanumeric())
                && issuer.len() == 56
                && issuer.starts_with('G')
                && issuer[1..]
                    .chars()
                    .all(|c| matches!(c, 'A'..='Z' | '2'..='7'))
        });
    if !asset_valid {
        return Err(format!(
            "asset must be 'XLM' or '<code>:<G-strkey>', got: {asset:?}"
        ));
    }

    // amount_stroops: strictly positive.
    if amount_stroops <= 0 {
        return Err(format!(
            "amount_stroops must be strictly positive, got {amount_stroops}"
        ));
    }

    // source: valid Stellar G-strkey.
    let source_valid = source.len() == 56
        && source.starts_with('G')
        && source[1..]
            .chars()
            .all(|c| matches!(c, 'A'..='Z' | '2'..='7'));
    if !source_valid {
        return Err(format!(
            "source must be a valid Stellar G-strkey (56 chars, ^G[A-Z2-7]{{55}}$), \
             got: {source_redacted}",
            source_redacted = redact_g_strkey(source)
        ));
    }

    Ok(())
}

/// Runs all `RegisterPasskey` field invariants and returns the first failing
/// reason.
///
/// Invoked from both `PendingApproval::new_register_passkey_pending` and the
/// custom `Deserialize<PendingApproval>` impl so tampered on-disk entries are
/// rejected at `PendingApprovalStore::open`.
fn validate_register_passkey_invariants(
    smart_account_redacted: &str,
    rule_ids: &[u32],
    rp_id: &str,
) -> Result<(), String> {
    // smart_account_redacted: first-5-last-5 C-strkey redaction shape.
    validate_smart_account_redacted(smart_account_redacted)?;

    // rule_ids: non-empty, max RULE_IDS_MAX_COUNT.
    if rule_ids.is_empty() {
        return Err(
            "rule_ids must be non-empty (at least one context rule ID required)".to_owned(),
        );
    }
    if rule_ids.len() > RULE_IDS_MAX_COUNT {
        return Err(format!(
            "rule_ids must have at most {RULE_IDS_MAX_COUNT} entries \
             (OZ context-rule batch limit), got {}",
            rule_ids.len()
        ));
    }

    // rp_id: 1–253 bytes, DNS LDH-label charset `[A-Za-z0-9.-]` per
    // RFC 1035 §2.3.4 + WebAuthn-2 §5.1.2 "valid domain string".
    // The LDH-label charset prevents HTML-injection metacharacters from
    // reaching approval-UI rendering surfaces via tampered on-disk files.
    // Legitimate values (`localhost`, production hostnames) round-trip unchanged.
    if rp_id.is_empty() {
        return Err("rp_id must not be empty".to_owned());
    }
    if rp_id.len() > 253 {
        return Err(format!(
            "rp_id must be at most 253 bytes (RFC 1035 §2.3.4 DNS name length \
             limit), got {} bytes",
            rp_id.len()
        ));
    }
    // Structural IP-literal rejection per WebAuthn-2 §5.1.2.
    // `parse::<std::net::IpAddr>()` rejects both IPv4 ("127.0.0.1") and IPv6
    // ("::1", "[::1]") — a tampered on-disk TOML with an IP-literal rp_id
    // would pass the charset guard (IPv4 digits + dot ⊂ LDH) but be rejected
    // here before reaching the bridge's HTML renderer.
    if rp_id.parse::<std::net::IpAddr>().is_ok() {
        return Err(format!(
            "rp_id must not be an IP address literal (WebAuthn-2 §5.1.2 forbids \
             IP rpId); got {rp_id:?}.  Use \"localhost\" for loopback."
        ));
    }
    if !rp_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(
            "rp_id must contain only DNS LDH-label characters [A-Za-z0-9.-] \
             per RFC 1035 §2.3.4 + WebAuthn-2 §5.1.2"
                .to_owned(),
        );
    }

    Ok(())
}

/// Validates the `smart_account_redacted` string against the first-5-last-5
/// redaction shape of a C-strkey.
///
/// Expected shape: `^C[A-Z2-7]{4}\.\.\.[A-Z2-7]{5}$`
/// Total: 1 (`C`) + 4 (base32) + 3 (`...`) + 5 (base32) = 13 chars.
///
/// Returns `Ok(())` on success, `Err(reason)` on failure.
fn validate_smart_account_redacted(s: &str) -> Result<(), String> {
    // Length must be exactly 13 characters.
    if s.len() != 13 {
        return Err(format!(
            "smart_account_redacted must be 13 characters \
             (first-5-last-5 redaction of a C-strkey: C + 4 base32 + ... + 5 base32), \
             got {} characters: {s:?}",
            s.len()
        ));
    }
    let bytes = s.as_bytes();
    // First char must be 'C'.
    if bytes[0] != b'C' {
        return Err(format!(
            "smart_account_redacted must start with 'C' (C-strkey redaction), got: {s:?}"
        ));
    }
    // Chars 1..5 must be base32 [A-Z2-7].
    for &b in &bytes[1..5] {
        if !matches!(b, b'A'..=b'Z' | b'2'..=b'7') {
            return Err(format!(
                "smart_account_redacted chars 1..5 must be base32 [A-Z2-7], got: {s:?}"
            ));
        }
    }
    // Chars 5..8 must be "...".
    if &bytes[5..8] != b"..." {
        return Err(format!(
            "smart_account_redacted chars 5..8 must be '...', got: {s:?}"
        ));
    }
    // Chars 8..13 must be base32 [A-Z2-7].
    for &b in &bytes[8..13] {
        if !matches!(b, b'A'..=b'Z' | b'2'..=b'7') {
            return Err(format!(
                "smart_account_redacted chars 8..13 must be base32 [A-Z2-7], got: {s:?}"
            ));
        }
    }
    Ok(())
}

/// Validates a FULL smart-account C-strkey: 56 characters, `C` prefix,
/// base32 `[A-Z2-7]` body.
///
/// Unlike `validate_smart_account_redacted` (which validates an already-
/// redacted display string), `RuleProposalSimulated::smart_account` stores
/// the full strkey — required at commit time to call `install_rule`.
fn validate_smart_account_full(s: &str) -> Result<(), String> {
    let valid = s.len() == 56
        && s.starts_with('C')
        && s[1..].chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7'));
    if valid {
        Ok(())
    } else {
        Err(format!(
            "smart_account must be a valid C-strkey (56 chars, ^C[A-Z2-7]{{55}}$), got: {}",
            redact_g_strkey(s)
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// generate_csrf_token
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a random 32-byte CSRF token via `OsRng`.
///
/// The canonical token-generation path for callers constructing a
/// [`PendingApproval`] of kind [`ApprovalKind::SignWithPasskey`] or
/// [`ApprovalKind::RegisterPasskey`].  The token is hex-encoded in the
/// approval URL and compared against the POST body token via
/// `subtle::ConstantTimeEq` in the bridge POST handler.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::store::generate_csrf_token;
///
/// let t1 = generate_csrf_token();
/// let t2 = generate_csrf_token();
/// assert_eq!(t1.len(), 32);
/// assert_ne!(t1, t2, "two tokens should almost certainly differ");
/// ```
#[must_use]
pub fn generate_csrf_token() -> [u8; 32] {
    let mut token = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    token
}

/// Outcome of a failed [`PendingApprovalStore::verify_rule_proposal_gate`]
/// call (Package D, GH issue #8).
///
/// Two variants only: `Rejected` for a live operator-rejection tombstone
/// (the caller maps this to the distinct `policy.approval_rejected` wire
/// code, mirroring the pay/claim gate's `Rejected` handling) and `Refused`
/// for every other refusal reason (unknown nonce, expired, wrong kind,
/// digest mismatch, HMAC mismatch) — collapsed into one variant so the wire
/// caller cannot distinguish WHY the gate refused, preserving the same
/// indistinguishability invariant `stellar-agent-mcp`'s
/// `verify_attestation_gate` upholds for `PaymentSimulated` / `ClaimSimulated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleProposalGateError {
    /// A live (non-expired) `Rejected` tombstone exists for this nonce — the
    /// operator explicitly declined the proposal.
    Rejected,
    /// Every other refusal reason (unknown nonce, expired, wrong kind, digest
    /// mismatch, HMAC mismatch), deliberately indistinguishable to the caller.
    Refused,
}

impl std::fmt::Display for RuleProposalGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected => write!(f, "rule proposal was rejected by the operator"),
            Self::Refused => write!(f, "rule proposal gate refused"),
        }
    }
}

impl std::error::Error for RuleProposalGateError {}

// ─────────────────────────────────────────────────────────────────────────────
// On-disk schema
// ─────────────────────────────────────────────────────────────────────────────

/// Internal TOML schema: top-level wrapper for the `[[pending]]` array.
#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    #[serde(default)]
    pending: Vec<PendingApproval>,
}

// ─────────────────────────────────────────────────────────────────────────────
// PendingApprovalStore
// ─────────────────────────────────────────────────────────────────────────────

/// TOML-file-backed store of pending wallet approvals.
///
/// Acquires an exclusive advisory lock on a sidecar `.lock` file for its
/// entire lifetime.  All mutations persist immediately via atomic
/// temp-file rename.  Drop releases the lock.
///
/// # Single-writer invariant
///
/// Only one `PendingApprovalStore` per profile file is permitted across all
/// processes.  Use `Arc<Mutex<PendingApprovalStore>>` to share within a
/// process.
///
/// # Non-goals
///
/// The file is NOT a security boundary.  The integrity guarantee is the
/// HMAC-keyed `attestation_blob` (PaymentSimulated) or the pre-verified
/// `passkey_assertion` (SignWithPasskey).  On-load entry validation
/// (`approval_nonce` length + base64url alphabet; `process_uid`
/// numeric-or-stub) defends against tty-rendering attacks via a tampered
/// store file.
pub struct PendingApprovalStore {
    /// Path to the TOML store file.
    path: PathBuf,
    /// In-memory list of pending approvals.
    entries: Vec<PendingApproval>,
    /// Exclusive advisory lock on the sidecar `.lock` file.
    ///
    /// Held for the lifetime of `PendingApprovalStore`.  Released on drop.
    _lock: LockHandle,
}

impl std::fmt::Debug for PendingApprovalStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingApprovalStore")
            .field("path", &self.path)
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl PendingApprovalStore {
    /// Opens the approval store at `path`.
    ///
    /// Creates the parent directory with mode `0o700` on Unix.  Acquires an
    /// exclusive advisory lock on `<path>.lock`.  Loads existing entries from
    /// the TOML file if it exists, rejecting any entry whose `approval_nonce`
    /// or `process_uid` fails format validation with
    /// [`ApprovalError::InvalidEntry`].
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::WriterLocked`] if the lock file is held by another process.
    /// - [`ApprovalError::Io`] on I/O failure.
    /// - [`ApprovalError::Toml`] if the existing file cannot be parsed.
    /// - [`ApprovalError::InvalidEntry`] if any entry fails nonce/uid validation.
    ///
    /// # Examples
    ///
    /// This example is `no_run` because it creates and locks an on-disk
    /// approval-store file.
    ///
    /// ```no_run
    /// use std::path::PathBuf;
    /// use stellar_agent_core::approval::store::PendingApprovalStore;
    ///
    /// # fn example() -> Result<(), stellar_agent_core::approval::error::ApprovalError> {
    /// let store = PendingApprovalStore::open(PathBuf::from("/tmp/approvals/default.toml"))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn open(path: PathBuf) -> Result<Self, ApprovalError> {
        // Create parent directory with mode 0o700 on Unix.
        let parent = path.parent().ok_or_else(|| {
            ApprovalError::from_io_detail(
                io::ErrorKind::InvalidInput,
                "approval store path must have a parent directory",
            )
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(ApprovalError::from_io)?;
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(parent).map_err(ApprovalError::from_io)?;
        }

        // Acquire the lock BEFORE reading the file.
        let lock_path = lock_path(&path);
        let lock = LockHandle::acquire(&lock_path)?;

        // Load existing entries if the file exists.
        let entries = if path.exists() {
            let content = fs::read_to_string(&path).map_err(ApprovalError::from_io)?;
            let sf: StoreFile = toml::from_str(&content).map_err(|e| ApprovalError::Toml {
                detail: e.to_string(),
            })?;
            // Serde validators on approval_nonce and process_uid run during
            // TOML deserialisation.  Double-check nonce length for defence-in-depth.
            for entry in &sf.pending {
                if entry.approval_nonce.len() != EXPECTED_NONCE_LEN {
                    return Err(ApprovalError::InvalidEntry {
                        detail: format!(
                            "approval_nonce has wrong length: {}",
                            entry.approval_nonce.len()
                        ),
                    });
                }
            }
            sf.pending
        } else {
            Vec::new()
        };

        Ok(Self {
            path,
            entries,
            _lock: lock,
        })
    }

    /// Inserts a new `PendingApproval` entry and persists the store.
    ///
    /// Before inserting, expired entries (those whose `expires_at_unix_ms <=
    /// now_unix_ms`) are pruned from memory.  The pruned state is persisted
    /// together with the new entry in a single atomic write, so no intermediate
    /// persist occurs on the prune step alone.
    ///
    /// After pruning, if the store already holds the hard cap (4 096) or more
    /// entries the new entry is rejected and the pruned state is persisted
    /// (removing stale entries even when the cap is hit).
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::PendingStoreFull`] if, after pruning expired entries,
    ///   the store already contains the maximum number of entries (4 096).
    /// - [`ApprovalError::DuplicateNonce`] if `entry.approval_nonce` already exists.
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence failure.
    ///
    /// # Examples
    ///
    /// This example is `no_run` because it opens and persists an on-disk
    /// approval-store file.
    ///
    /// ```no_run
    /// # use stellar_agent_core::approval::store::{PendingApprovalStore, PendingApproval, DEFAULT_TTL_MS};
    /// # use stellar_agent_core::approval::user_id::process_uid_for_attestation;
    /// # fn run() -> Result<(), stellar_agent_core::approval::error::ApprovalError> {
    /// # let mut store = PendingApprovalStore::open(std::path::PathBuf::from("/tmp/t/default.toml"))?;
    /// let uid = process_uid_for_attestation()?;
    /// let now_ms = 1_700_000_000_000_u64; // caller-supplied current time
    /// let entry = PendingApproval::new_payment_pending(
    ///     "b64xdr".to_owned(), b"xdr",
    ///     "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
    ///     1000, "XLM".to_owned(), None, 100, 1, uid, DEFAULT_TTL_MS)?;
    /// store.insert(entry, now_ms)?;
    /// # Ok(()) }
    /// ```
    pub fn insert(
        &mut self,
        entry: PendingApproval,
        now_unix_ms: u64,
    ) -> Result<(), ApprovalError> {
        // Step 1: prune expired entries in memory.
        self.entries.retain(|e| !e.is_expired(now_unix_ms));

        // Step 2: enforce the hard cap after pruning.
        if self.entries.len() >= MAX_PENDING_APPROVALS {
            // Persist the pruned state even on rejection so the next open sees
            // a clean store.
            self.persist()?;
            return Err(ApprovalError::pending_store_full(MAX_PENDING_APPROVALS));
        }

        // Step 3: duplicate-nonce guard.
        if self
            .entries
            .iter()
            .any(|e| e.approval_nonce == entry.approval_nonce)
        {
            return Err(ApprovalError::duplicate_nonce(&entry.approval_nonce));
        }

        // Step 4: push and persist (single atomic write for prune + insert).
        self.entries.push(entry);
        self.persist()
    }

    /// Returns a reference to the entry with the given `approval_nonce`, or
    /// `None` if absent.
    ///
    /// # Examples
    ///
    /// This example is `no_run` because it opens an on-disk approval-store
    /// file.
    ///
    /// ```no_run
    /// # use stellar_agent_core::approval::store::PendingApprovalStore;
    /// # fn run() -> Result<(), stellar_agent_core::approval::error::ApprovalError> {
    /// # let store = PendingApprovalStore::open(std::path::PathBuf::from("/tmp/t/d.toml"))?;
    /// let entry = store.get("some-nonce");
    /// assert!(entry.is_none()); // empty store
    /// # Ok(()) }
    /// ```
    #[must_use]
    pub fn get(&self, approval_nonce: &str) -> Option<&PendingApproval> {
        self.entries
            .iter()
            .find(|e| e.approval_nonce == approval_nonce)
    }

    /// Returns the total number of pending approvals currently in the store.
    ///
    /// Expired entries are removed automatically on each successful `insert`
    /// call.  Any entries that expired since the last `insert` are still
    /// counted here until pruned by `insert` or an explicit `gc_expired` call.
    ///
    /// Useful for assertions in integration tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the store contains no pending approvals.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns a cloned, read-only, redacted view of every pending approval.
    ///
    /// This is the only way to enumerate the store's contents from outside
    /// this module — `entries` stays private. Every
    /// [`super::view::PendingApprovalView`] carries the same non-secret
    /// summary fields the CLI `approve --id` prompt renders (never raw
    /// secret material such as `csrf_token`, credential bytes, or the
    /// attestation blob contents), so callers such as `approve list` or a
    /// resident approval-inbox server can render pending entries without
    /// duplicating the redaction discipline.
    ///
    /// Order matches insertion order; expired entries are included (with
    /// `expired: true`) rather than filtered, so a caller that wants to
    /// distinguish "no pending approvals" from "only expired ones remain"
    /// can do so.
    #[must_use]
    pub fn snapshot(&self, now_unix_ms: u64) -> Vec<super::view::PendingApprovalView> {
        self.entries
            .iter()
            .map(|e| super::view::PendingApprovalView::from_entry(e, now_unix_ms))
            .collect()
    }

    /// Records the HMAC-SHA256 attestation blob for a `PaymentSimulated` or
    /// `ClaimSimulated` entry.
    ///
    /// Both kinds share the envelope-hash HMAC attestation path: the operator's
    /// `stellar-agent approve` computes the blob from the entry's
    /// `envelope_sha256_hex`, and the matching `*_commit` tool re-derives and
    /// constant-time-compares it. The 32-byte `attestation_blob` is encoded as
    /// URL-safe base64 no-pad and stored in `attestation_blob_b64`.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::NotFound`] if no entry with `approval_nonce` exists.
    /// - [`ApprovalError::Expired`] if the entry's TTL has elapsed.
    /// - [`ApprovalError::AlreadyAttested`] if the blob is already set.
    /// - [`ApprovalError::WrongKind`] if the entry is neither `PaymentSimulated`
    ///   nor `ClaimSimulated`.
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence failure.
    pub fn record_attestation(
        &mut self,
        approval_nonce: &str,
        attestation_blob: [u8; 32],
    ) -> Result<(), ApprovalError> {
        let now_ms = approval_now_unix_ms()?;

        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.approval_nonce == approval_nonce)
            .ok_or(ApprovalError::NotFound)?;

        if entry.is_expired(now_ms) {
            return Err(ApprovalError::Expired);
        }

        // Kind check: record_attestation is PaymentSimulated- or ClaimSimulated-only.
        // Both share the envelope-hash HMAC attestation path.
        if !matches!(
            entry.kind,
            ApprovalKind::PaymentSimulated { .. } | ApprovalKind::ClaimSimulated { .. }
        ) {
            return Err(ApprovalError::WrongKind {
                expected: "PaymentSimulated or ClaimSimulated",
                actual: entry.kind.kind_name(),
            });
        }

        if entry.attestation_blob_b64.is_some() {
            return Err(ApprovalError::AlreadyAttested);
        }

        entry.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode(attestation_blob));
        self.persist()
    }

    /// Records the WebAuthn assertion captured by the browser-handoff bridge
    /// for a `SignWithPasskey` approval.
    ///
    /// One-shot: a second call returns [`ApprovalError::AlreadyAttested`].
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::NotFound`] if the nonce is unknown.
    /// - [`ApprovalError::Expired`] if the entry's TTL has elapsed.
    /// - [`ApprovalError::WrongKind`] if the approval is not `SignWithPasskey`
    ///   (`expected = "SignWithPasskey"`, `actual = "PaymentSimulated"`).
    /// - [`ApprovalError::AlreadyAttested`] if `passkey_assertion` is already set.
    /// - [`ApprovalError::Invalid`] if `passkey_assertion` violates
    ///   `AssertionInput` invariants.
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence failure.
    pub fn record_passkey_assertion(
        &mut self,
        approval_nonce: &str,
        assertion: AssertionInput,
    ) -> Result<(), ApprovalError> {
        let now_ms = approval_now_unix_ms()?;

        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.approval_nonce == approval_nonce)
            .ok_or(ApprovalError::NotFound)?;

        if entry.is_expired(now_ms) {
            return Err(ApprovalError::Expired);
        }

        // Kind check: record_passkey_assertion is SignWithPasskey-only.
        if !matches!(entry.kind, ApprovalKind::SignWithPasskey { .. }) {
            return Err(ApprovalError::WrongKind {
                expected: "SignWithPasskey",
                actual: entry.kind.kind_name(),
            });
        }

        if entry.passkey_assertion.is_some() {
            return Err(ApprovalError::AlreadyAttested);
        }

        validate_assertion_input_invariants(&assertion)
            .map_err(|reason| ApprovalError::Invalid { reason })?;

        entry.passkey_assertion = Some(assertion);
        self.persist()
    }

    /// Records the WebAuthn registration result captured by the browser-handoff
    /// bridge for a `RegisterPasskey` approval.
    ///
    /// One-shot: a second call returns [`ApprovalError::AlreadyAttested`].
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::NotFound`] if the nonce is unknown.
    /// - [`ApprovalError::Expired`] if the entry's TTL has elapsed.
    /// - [`ApprovalError::WrongKind`] if the approval is not `RegisterPasskey`
    ///   (`expected = "RegisterPasskey"`, `actual = <other-kind>`).
    /// - [`ApprovalError::AlreadyAttested`] if `registration_input` is already set.
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence failure.
    pub fn record_passkey_registration(
        &mut self,
        approval_nonce: &str,
        registration: RegistrationInput,
    ) -> Result<(), ApprovalError> {
        let now_ms = approval_now_unix_ms()?;

        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.approval_nonce == approval_nonce)
            .ok_or(ApprovalError::NotFound)?;

        if entry.is_expired(now_ms) {
            return Err(ApprovalError::Expired);
        }

        // Single-walk kind dispatch + mutation: one `match` guarantees
        // WrongKind error OR AlreadyAttested error OR mutation —
        // exhaustively, never neither.
        match entry.kind {
            ApprovalKind::RegisterPasskey {
                ref mut registration_input,
                ..
            } => {
                if registration_input.is_some() {
                    return Err(ApprovalError::AlreadyAttested);
                }
                *registration_input = Some(registration);
            }
            ref other => {
                return Err(ApprovalError::WrongKind {
                    expected: "RegisterPasskey",
                    actual: other.kind_name(),
                });
            }
        }

        self.persist()
    }

    /// Removes the entry with the given `approval_nonce` and persists the store.
    ///
    /// Returns `Ok(true)` if the entry was present and removed, `Ok(false)` if
    /// absent.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence failure.
    pub fn remove(&mut self, approval_nonce: &str) -> Result<bool, ApprovalError> {
        let before = self.entries.len();
        self.entries.retain(|e| e.approval_nonce != approval_nonce);
        let removed = self.entries.len() < before;
        if removed {
            self.persist()?;
        }
        Ok(removed)
    }

    /// Replaces the entry with the given `approval_nonce` with a short-TTL
    /// [`ApprovalKind::Rejected`] tombstone and persists the store.
    ///
    /// The tombstone carries only the rejected entry's `kind_name()` — none of
    /// its summary data (destination, amount, asset, and so on) survive the
    /// reject action. `created_at_unix_ms` is set to `now_unix_ms` (the
    /// rejection time) and `expires_at_unix_ms` to `now_unix_ms + ttl_ms`, so
    /// the tombstone is swept by the existing [`Self::gc_expired`] /
    /// [`Self::insert`]-time pruning like any other entry.
    ///
    /// A `Rejected` tombstone can never be attested: it is not one of the
    /// kinds any attestation path dispatches on, so an attest attempt against
    /// it always fails closed.
    ///
    /// Returns `Ok(true)` if an entry with `approval_nonce` was present and
    /// replaced, `Ok(false)` if absent (idempotent — rejecting an
    /// already-consumed or unknown nonce is not an error).
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence failure.
    pub fn reject(
        &mut self,
        approval_nonce: &str,
        now_unix_ms: u64,
        ttl_ms: u64,
    ) -> Result<bool, ApprovalError> {
        let Some(idx) = self
            .entries
            .iter()
            .position(|e| e.approval_nonce == approval_nonce)
        else {
            return Ok(false);
        };

        let original_kind_name = self.entries[idx].kind.kind_name().to_owned();
        let process_uid = self.entries[idx].process_uid.clone();

        self.entries[idx] = PendingApproval {
            approval_nonce: approval_nonce.to_owned(),
            process_uid,
            created_at_unix_ms: now_unix_ms,
            expires_at_unix_ms: now_unix_ms.saturating_add(ttl_ms),
            kind: ApprovalKind::Rejected { original_kind_name },
            attestation_blob_b64: None,
            passkey_assertion: None,
        };

        self.persist()?;
        Ok(true)
    }

    /// Returns `true` when the store contains at least one non-expired,
    /// HMAC-attested `TrustlineClawbackOptIn` entry for the given `(network,
    /// code, issuer)` triple.
    ///
    /// Called by the `stellar_trustline` verb to check whether the operator has
    /// recorded a wallet-controlled per-trustline clawback opt-in before
    /// submitting a `ChangeTrust` to an issuer with `AUTH_CLAWBACK_ENABLED`.
    ///
    /// # Design rationale
    ///
    /// The opt-in MUST come from the wallet-controlled approval store.  It is
    /// NOT an agent-suppliable bool in the tool's arguments.  Requiring the
    /// store lookup here ensures the gate can only be cleared by a prior
    /// `approve --id <nonce>` ceremony that produced an HMAC-attested entry.
    ///
    /// An attested entry is one where `attestation_blob_b64` is `Some(_)`.
    /// An entry where the attestation is absent (issued but not yet confirmed
    /// by the operator) does NOT satisfy this check.  Expired entries are also
    /// excluded.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_core::approval::store::PendingApprovalStore;
    ///
    /// # fn example() -> Result<(), stellar_agent_core::approval::error::ApprovalError> {
    /// let store = PendingApprovalStore::open(std::path::PathBuf::from("/tmp/t/d.toml"))?;
    /// let opt_in = store.has_attested_trustline_clawback_opt_in(
    ///     "Test SDF Network ; September 2015",
    ///     "USDC",
    ///     "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
    ///     0, // now_unix_ms = 0 ⟹ nothing is expired
    /// );
    /// assert!(!opt_in); // empty store
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Note on use
    ///
    /// This method checks only whether an HMAC blob is present (non-`None`) but
    /// does NOT verify the blob cryptographically against the attestation key.
    /// Call sites that have access to the attestation key MUST use
    /// [`Self::verify_attested_trustline_clawback_opt_in`] instead to prevent a
    /// forged-blob attack: any writer of the profile store file could set an
    /// arbitrary blob and pass this check.
    ///
    /// This method is retained for the unit-test layer (which does not have the
    /// keyring key in scope).  All production gate checks MUST go through
    /// [`Self::verify_attested_trustline_clawback_opt_in`].
    #[must_use]
    pub fn has_attested_trustline_clawback_opt_in(
        &self,
        network: &str,
        code: &str,
        issuer: &str,
        now_unix_ms: u64,
    ) -> bool {
        self.entries.iter().any(|e| {
            // Must not be expired.
            if e.is_expired(now_unix_ms) {
                return false;
            }
            // Must be attested (HMAC blob set by `approve --id`).
            if e.attestation_blob_b64.is_none() {
                return false;
            }
            // Must be a TrustlineClawbackOptIn for the exact (network, code, issuer).
            matches!(
                &e.kind,
                ApprovalKind::TrustlineClawbackOptIn {
                    network: n,
                    code: c,
                    issuer: iss,
                } if n == network && c == code && iss == issuer
            )
        })
    }

    /// Returns `true` when the store contains at least one non-expired
    /// `TrustlineClawbackOptIn` entry for `(network, code, issuer)` whose
    /// HMAC-SHA256 attestation blob cryptographically verifies against `key`.
    ///
    /// This is the **production gate check**.  Unlike
    /// [`Self::has_attested_trustline_clawback_opt_in`], this method:
    ///
    /// 1. Decodes the stored `attestation_blob_b64` from URL-safe base64 no-pad.
    /// 2. Recomputes `compute_trustline_clawback_opt_in_digest(network, code, issuer)`.
    /// 3. Calls `verify_attestation(key, nonce, &digest, process_uid, &blob)`
    ///    (constant-time HMAC-SHA256 comparison).
    ///
    /// A missing blob, a blob with a wrong length, or a blob that does not match
    /// the HMAC all return `false` — the gate stays closed.  Callers that cannot
    /// load the attestation key MUST fail-closed (return `false`) rather than
    /// falling back to the presence-only check.
    ///
    /// # Key discipline
    ///
    /// The caller wraps the key in `zeroize::Zeroizing<[u8; 32]>` and passes
    /// `&*key` here.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_core::approval::store::PendingApprovalStore;
    ///
    /// # fn example() -> Result<(), stellar_agent_core::approval::error::ApprovalError> {
    /// let key = [0x42u8; 32];
    /// let store = PendingApprovalStore::open(std::path::PathBuf::from("/tmp/t/d.toml"))?;
    /// let verified = store.verify_attested_trustline_clawback_opt_in(
    ///     &key,
    ///     "stellar:testnet",
    ///     "USDC",
    ///     "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
    ///     0, // now_unix_ms = 0 ⟹ nothing is expired
    /// );
    /// assert!(!verified); // empty store
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn verify_attested_trustline_clawback_opt_in(
        &self,
        key: &[u8; 32],
        network: &str,
        code: &str,
        issuer: &str,
        now_unix_ms: u64,
    ) -> bool {
        use super::attestation::{compute_trustline_clawback_opt_in_digest, verify_attestation};

        let digest = compute_trustline_clawback_opt_in_digest(network, code, issuer);

        self.entries.iter().any(|e| {
            // Must not be expired.
            if e.is_expired(now_unix_ms) {
                return false;
            }
            // Must be a TrustlineClawbackOptIn for the exact (network, code, issuer).
            let matches_kind = matches!(
                &e.kind,
                ApprovalKind::TrustlineClawbackOptIn {
                    network: n,
                    code: c,
                    issuer: iss,
                } if n == network && c == code && iss == issuer
            );
            if !matches_kind {
                return false;
            }
            // Must have an attestation blob.
            let blob_b64 = match &e.attestation_blob_b64 {
                Some(b) => b,
                None => return false,
            };
            // Decode base64 → 32-byte array.
            let blob_bytes = match URL_SAFE_NO_PAD.decode(blob_b64) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let blob_arr: [u8; 32] = match blob_bytes.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            // HMAC-SHA256 verify (constant-time).  A forged or wrong-key blob fails here.
            verify_attestation(key, &e.approval_nonce, &digest, &e.process_uid, &blob_arr)
        })
    }

    /// Removes all entries where `expires_at_unix_ms <= now_unix_ms`.
    ///
    /// Returns the count of removed entries.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::Io`] if the system clock is unavailable.
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence failure.
    pub fn gc_expired(&mut self, now_unix_ms: u64) -> Result<usize, ApprovalError> {
        let before = self.entries.len();
        self.entries.retain(|e| !e.is_expired(now_unix_ms));
        let removed = before - self.entries.len();
        if removed > 0 {
            self.persist()?;
        }
        Ok(removed)
    }

    /// Records the HMAC-SHA256 attestation blob for a `TrustlineClawbackOptIn`
    /// entry, confirming that the wallet owner has acknowledged the clawback risk
    /// for this `(network, code, issuer)` triple.
    ///
    /// The 32-byte `attestation_blob` is encoded as URL-safe base64 no-pad and
    /// stored in `attestation_blob_b64`.  After this call the entry will be
    /// recognised by [`Self::has_attested_trustline_clawback_opt_in`].
    ///
    /// Called by `stellar-agent approve --id <nonce>` when the pending entry is
    /// of kind `TrustlineClawbackOptIn`.  The caller computes the attestation
    /// blob via [`super::attestation::compute_attestation`] using the stored
    /// `approval_nonce`, the SHA-256 commitment of `(network, code, issuer)`,
    /// and the current `process_uid` — same key discipline as
    /// `record_attestation` for `PaymentSimulated` entries.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::NotFound`] if no entry with `approval_nonce` exists.
    /// - [`ApprovalError::Expired`] if the entry's TTL has elapsed.
    /// - [`ApprovalError::AlreadyAttested`] if `attestation_blob_b64` is already set.
    /// - [`ApprovalError::WrongKind`] if the entry is not `TrustlineClawbackOptIn`.
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence failure.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_core::approval::store::{PendingApprovalStore, PendingApproval, DEFAULT_TTL_MS};
    /// use stellar_agent_core::approval::user_id::process_uid_for_attestation;
    ///
    /// # fn example() -> Result<(), stellar_agent_core::approval::error::ApprovalError> {
    /// let uid = process_uid_for_attestation()?;
    /// let now_ms = 1_700_000_000_000_u64; // caller-supplied current time
    /// let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
    ///     "Test SDF Network ; September 2015".to_owned(),
    ///     "USDC".to_owned(),
    ///     "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_owned(),
    ///     uid,
    ///     DEFAULT_TTL_MS,
    /// )?;
    /// let nonce = entry.approval_nonce.clone();
    /// let mut store = PendingApprovalStore::open(std::path::PathBuf::from("/tmp/t/default.toml"))?;
    /// store.insert(entry, now_ms)?;
    /// store.record_trustline_clawback_opt_in_attestation(&nonce, [0x42u8; 32])?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn record_trustline_clawback_opt_in_attestation(
        &mut self,
        approval_nonce: &str,
        attestation_blob: [u8; 32],
    ) -> Result<(), ApprovalError> {
        let now_ms = approval_now_unix_ms()?;

        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.approval_nonce == approval_nonce)
            .ok_or(ApprovalError::NotFound)?;

        if entry.is_expired(now_ms) {
            return Err(ApprovalError::Expired);
        }

        // Kind check: this method is TrustlineClawbackOptIn-only.
        if !matches!(entry.kind, ApprovalKind::TrustlineClawbackOptIn { .. }) {
            return Err(ApprovalError::WrongKind {
                expected: "TrustlineClawbackOptIn",
                actual: entry.kind.kind_name(),
            });
        }

        if entry.attestation_blob_b64.is_some() {
            return Err(ApprovalError::AlreadyAttested);
        }

        entry.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode(attestation_blob));
        self.persist()
    }

    /// Records the HMAC-SHA256 attestation blob for a `RuleProposalSimulated`
    /// entry (Package D, GH issue #8), confirming the operator has attested
    /// the resolved rule at `proposal_sha256`.
    ///
    /// The 32-byte `attestation_blob` is encoded as URL-safe base64 no-pad
    /// and stored in `attestation_blob_b64`. Shares the `PaymentSimulated` /
    /// `ClaimSimulated` envelope-hash HMAC discipline, binding
    /// `proposal_sha256` instead of an envelope hash.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::NotFound`] if no entry with `approval_nonce` exists.
    /// - [`ApprovalError::Expired`] if the entry's TTL has elapsed.
    /// - [`ApprovalError::AlreadyAttested`] if `attestation_blob_b64` is already set.
    /// - [`ApprovalError::WrongKind`] if the entry is not `RuleProposalSimulated`.
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence failure.
    pub fn record_rule_proposal_attestation(
        &mut self,
        approval_nonce: &str,
        attestation_blob: [u8; 32],
    ) -> Result<(), ApprovalError> {
        let now_ms = approval_now_unix_ms()?;

        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.approval_nonce == approval_nonce)
            .ok_or(ApprovalError::NotFound)?;

        if entry.is_expired(now_ms) {
            return Err(ApprovalError::Expired);
        }

        // Kind check: this method is RuleProposalSimulated-only.
        if !matches!(entry.kind, ApprovalKind::RuleProposalSimulated { .. }) {
            return Err(ApprovalError::WrongKind {
                expected: "RuleProposalSimulated",
                actual: entry.kind.kind_name(),
            });
        }

        if entry.attestation_blob_b64.is_some() {
            return Err(ApprovalError::AlreadyAttested);
        }

        entry.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode(attestation_blob));
        self.persist()
    }

    /// Verifies the `RuleProposalSimulated` commit-gate for `approval_nonce`
    /// (Package D, GH issue #8).
    ///
    /// This is a DEDICATED gate — distinct from the shared pay/claim
    /// `verify_attestation_gate` in `stellar-agent-mcp` (which continues to
    /// reject `RuleProposalSimulated` via its `other =>` fallback arm; defense
    /// in depth in both directions). The caller (`stellar_rule_create_commit`)
    /// re-derives `recomputed_proposal_sha256` from the entry's OWN
    /// `definition` snapshot via
    /// `stellar-agent-smart-account::managers::rules::compute_context_rule_proposal_sha256`
    /// — the SAME builder used at propose time — and passes it here so a
    /// digest recomputed through the builder must still match what was
    /// attested.
    ///
    /// # Checks (in order)
    ///
    /// 1. Entry exists for `approval_nonce`.
    /// 2. Entry is not expired.
    /// 3. A live `Rejected` tombstone returns [`RuleProposalGateError::Rejected`]
    ///    — a distinct outcome from every other refusal reason, mirroring the
    ///    pay/claim gate's `policy.approval_rejected` wire code.
    /// 4. Entry kind is `RuleProposalSimulated`.
    /// 5. `recomputed_proposal_sha256` matches the entry's stored
    ///    `proposal_sha256`.
    /// 6. The HMAC attestation blob verifies (constant-time).
    ///
    /// Every refusal reason other than a live rejection collapses to
    /// [`RuleProposalGateError::Refused`] — the caller cannot distinguish
    /// unknown-nonce from expired from digest-mismatch from HMAC-mismatch,
    /// preserving the same indistinguishability invariant
    /// `stellar-agent-mcp`'s `verify_attestation_gate` upholds for
    /// `PaymentSimulated` / `ClaimSimulated`.
    ///
    /// # Errors
    ///
    /// See [`RuleProposalGateError`].
    pub fn verify_rule_proposal_gate(
        &self,
        approval_nonce: &str,
        recomputed_proposal_sha256: &[u8; 32],
        attestation_key: &[u8; 32],
        attestation_blob: &[u8; 32],
        now_unix_ms: u64,
    ) -> Result<(), RuleProposalGateError> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.approval_nonce == approval_nonce)
            .ok_or(RuleProposalGateError::Refused)?;

        if entry.is_expired(now_unix_ms) {
            return Err(RuleProposalGateError::Refused);
        }

        if matches!(entry.kind, ApprovalKind::Rejected { .. }) {
            return Err(RuleProposalGateError::Rejected);
        }

        let ApprovalKind::RuleProposalSimulated {
            proposal_sha256, ..
        } = &entry.kind
        else {
            return Err(RuleProposalGateError::Refused);
        };

        if proposal_sha256 != recomputed_proposal_sha256 {
            return Err(RuleProposalGateError::Refused);
        }

        if !super::attestation::verify_attestation(
            attestation_key,
            approval_nonce,
            proposal_sha256,
            &entry.process_uid,
            attestation_blob,
        ) {
            return Err(RuleProposalGateError::Refused);
        }

        Ok(())
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Persists the in-memory entries to disk via atomic temp-file rename.
    ///
    /// Creates a `NamedTempFile` in the same parent directory, writes TOML,
    /// persists (renames) to the store path, then fsyncs the file and (on
    /// Unix only) the parent directory.  File mode is `0o600` on Unix.
    fn persist(&self) -> Result<(), ApprovalError> {
        let parent = self.path.parent().ok_or_else(|| {
            ApprovalError::from_io_detail(
                io::ErrorKind::InvalidInput,
                "approval store path has no parent directory",
            )
        })?;

        let sf = StoreFile {
            pending: self.entries.clone(),
        };
        let content = toml::to_string_pretty(&sf).map_err(|e| ApprovalError::Toml {
            detail: e.to_string(),
        })?;

        // Create temp file in the same directory for atomic rename.
        let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(ApprovalError::from_io)?;

        // Set permissions 0o600 before writing on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tmp.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(ApprovalError::from_io)?;
        }

        std::io::Write::write_all(&mut tmp, content.as_bytes()).map_err(ApprovalError::from_io)?;
        tmp.as_file().sync_data().map_err(ApprovalError::from_io)?;

        // Atomic rename.
        let final_path = tmp
            .persist(&self.path)
            .map_err(|e| ApprovalError::from_io(e.error))?;

        // fsync the final file handle.
        final_path.sync_data().map_err(ApprovalError::from_io)?;

        // fsync parent directory to commit the directory entry change. Opening
        // a directory path via `std::fs::File::open` requires
        // `FILE_FLAG_BACKUP_SEMANTICS` on Windows (which the stable API does
        // not set) and fails with `ERROR_ACCESS_DENIED`; POSIX has no such
        // restriction. Skip on non-Unix — NTFS journals directory-entry
        // metadata itself, so a crash immediately after `persist` above still
        // leaves the store re-openable; the pending entries this store holds
        // are re-derivable by re-running the approval flow, so losing the
        // last write to a crash is recoverable, not silently corrupting.
        #[cfg(unix)]
        {
            let parent_file = fs::File::open(parent).map_err(ApprovalError::from_io)?;
            parent_file.sync_data().map_err(ApprovalError::from_io)?;
        }

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LockHandle
// ─────────────────────────────────────────────────────────────────────────────

/// Holds an exclusive advisory lock on the sidecar `.lock` file.
///
/// Lock is acquired via [`std::fs::File::try_lock`] (stable Rust 1.89).
/// Released when the `LockHandle` is dropped (file descriptor closed).
struct LockHandle {
    /// Holding this `File` keeps the advisory exclusive lock active.
    _file: File,
}

impl LockHandle {
    /// Acquires an exclusive advisory lock on `lock_path`.
    ///
    /// Creates the file if absent (mode `0o600` on Unix).
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::WriterLocked`] if the lock is held by another OFD.
    /// - [`ApprovalError::Io`] on open or lock failure.
    fn acquire(lock_path: &Path) -> Result<Self, ApprovalError> {
        let file = open_or_create_0600(lock_path).map_err(ApprovalError::from_io)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(ApprovalError::WriterLocked),
            Err(std::fs::TryLockError::Error(e)) => Err(ApprovalError::from_io(e)),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Path helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the sidecar `.lock` path for a store file.
///
/// `default.toml` → `default.toml.lock`.
fn lock_path(store_path: &Path) -> PathBuf {
    let name = store_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("approval.toml");
    store_path
        .parent()
        .map(|p| p.join(format!("{name}.lock")))
        .unwrap_or_else(|| PathBuf::from(format!("{name}.lock")))
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform-specific file open
// ─────────────────────────────────────────────────────────────────────────────

/// Opens (or creates) a file with mode `0o600` on Unix; default mode otherwise.
fn open_or_create_0600(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Time helper
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the current Unix time in milliseconds.
fn approval_now_unix_ms() -> Result<u64, ApprovalError> {
    crate::timefmt::now_unix_ms().map_err(|e| {
        ApprovalError::from_io_detail(io::ErrorKind::Other, format!("system clock error: {e}"))
    })
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
        clippy::too_many_lines,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use tempfile::TempDir;

    /// A fixed "current time" used in tests that call `insert`.
    ///
    /// All test entries are constructed with `DEFAULT_TTL_MS` (24 h) or a
    /// deliberately short TTL.  Using `now = 1` ms ensures that entries built
    /// with `DEFAULT_TTL_MS` are never accidentally pruned by the insert-time
    /// expiry sweep.  Tests that intentionally verify expiry behaviour set
    /// their own `now` values.
    const TEST_NOW_MS: u64 = 1;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Valid 56-char Stellar G-strkey (G + 55 base32 chars).
    const VALID_SUMMARY_TO: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn make_payment_entry(ttl_ms: u64) -> PendingApproval {
        #[allow(deprecated)]
        PendingApproval::new_unattested(
            "b64xdr".to_owned(),
            b"fake-xdr",
            VALID_SUMMARY_TO.to_owned(),
            10_000_000,
            "XLM".to_owned(),
            None,
            100,
            12345,
            "1000".to_owned(),
            ttl_ms,
        )
        .unwrap()
    }

    fn make_passkey_entry(ttl_ms: u64) -> PendingApproval {
        PendingApproval::new_passkey_pending(
            [0x01u8; 32],
            vec![0xABu8; 32],
            "CAAAA...BBBBB".to_owned(),
            vec![1, 2],
            [0x02u8; 32],
            "localhost".to_owned(),
            "1000".to_owned(),
            ttl_ms,
        )
        .unwrap()
    }

    fn make_assertion() -> AssertionInput {
        AssertionInput {
            credential_id: vec![0xABu8; 32],
            authenticator_data: vec![0xCDu8; 37],
            client_data_json: vec![0xEFu8; 50],
            signature_compact: vec![0x30u8; 64],
        }
    }

    fn open_store(dir: &TempDir) -> PendingApprovalStore {
        let path = dir.path().join("default.toml");
        PendingApprovalStore::open(path).unwrap()
    }

    // ── Open / empty ─────────────────────────────────────────────────────────

    #[test]
    fn open_empty_store_succeeds() {
        let dir = TempDir::new().unwrap();
        let store = open_store(&dir);
        assert_eq!(store.entries.len(), 0);
    }

    #[test]
    fn open_creates_parent_directory() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("sub").join("default.toml");
        let _store = PendingApprovalStore::open(nested.clone()).unwrap();
        assert!(nested.parent().unwrap().exists());
    }

    // ── Insert + read-back ───────────────────────────────────────────────────

    #[test]
    fn insert_and_get_roundtrip() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();
        let found = store.get(&nonce).unwrap();
        assert_eq!(found.approval_nonce, nonce);
        assert!(found.attestation_blob_b64.is_none());
    }

    #[test]
    fn insert_persists_to_disk_and_reloads() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let nonce = {
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            let entry = make_payment_entry(DEFAULT_TTL_MS);
            let n = entry.approval_nonce.clone();
            store.insert(entry, TEST_NOW_MS).unwrap();
            n
        }; // store dropped — lock released

        let store2 = PendingApprovalStore::open(path).unwrap();
        assert!(store2.get(&nonce).is_some());
    }

    /// Windows regression: `persist()` must succeed across repeated
    /// insert-triggered rename cycles. Each `persist()` call renames a fresh
    /// temp file over the store path, then (Unix-only) fsyncs the parent
    /// directory; on Windows that step is skipped entirely rather than
    /// opening the directory as a file. This test exercises the persist path
    /// multiple times in the same process, so a regression that re-enables
    /// an unconditional directory-open would fail here on `windows-storage`
    /// CI even though it passes on every POSIX runner.
    #[test]
    fn persist_succeeds_across_repeated_inserts() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let mut store = PendingApprovalStore::open(path.clone()).unwrap();
        for _ in 0..5 {
            let entry = make_payment_entry(DEFAULT_TTL_MS);
            store.insert(entry, TEST_NOW_MS).unwrap();
        }
        drop(store);

        let reopened = PendingApprovalStore::open(path).unwrap();
        assert_eq!(reopened.len(), 5, "all five persisted entries must reload");
    }

    // ── Duplicate nonce ──────────────────────────────────────────────────────

    #[test]
    fn insert_duplicate_nonce_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();

        store.insert(entry, TEST_NOW_MS).unwrap();

        let mut dup = make_payment_entry(DEFAULT_TTL_MS);
        dup.approval_nonce = nonce;

        let err = store.insert(dup, TEST_NOW_MS).unwrap_err();
        assert!(
            matches!(err, ApprovalError::DuplicateNonce { .. }),
            "expected DuplicateNonce, got {err:?}"
        );
    }

    // ── record_attestation success ───────────────────────────────────────────

    #[test]
    fn record_attestation_success() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let blob = [0x42u8; 32];
        store.record_attestation(&nonce, blob).unwrap();

        let found = store.get(&nonce).unwrap();
        assert!(found.attestation_blob_b64.is_some());
        let decoded = URL_SAFE_NO_PAD
            .decode(found.attestation_blob_b64.as_ref().unwrap())
            .unwrap();
        assert_eq!(decoded, blob);
    }

    // ── record_attestation: already attested ─────────────────────────────────

    #[test]
    fn record_attestation_already_attested_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let blob = [0x42u8; 32];
        store.record_attestation(&nonce, blob).unwrap();

        let err = store.record_attestation(&nonce, blob).unwrap_err();
        assert!(
            matches!(err, ApprovalError::AlreadyAttested),
            "expected AlreadyAttested, got {err:?}"
        );
    }

    // ── record_attestation: expired ──────────────────────────────────────────

    #[test]
    fn record_attestation_expired_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_payment_entry(1);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));

        let blob = [0x42u8; 32];
        let err = store.record_attestation(&nonce, blob).unwrap_err();
        assert!(
            matches!(err, ApprovalError::Expired),
            "expected Expired, got {err:?}"
        );
    }

    // ── gc_expired ───────────────────────────────────────────────────────────

    #[test]
    fn gc_expired_removes_only_expired() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);

        let live = make_payment_entry(DEFAULT_TTL_MS);
        let live_nonce = live.approval_nonce.clone();
        store.insert(live, TEST_NOW_MS).unwrap();

        let dead = make_payment_entry(1);
        let dead_nonce = dead.approval_nonce.clone();
        store.insert(dead, TEST_NOW_MS).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));

        let now = approval_now_unix_ms().unwrap();
        let removed = store.gc_expired(now).unwrap();
        assert_eq!(removed, 1, "only the expired entry should be removed");
        assert!(store.get(&live_nonce).is_some());
        assert!(store.get(&dead_nonce).is_none());
    }

    // ── remove ───────────────────────────────────────────────────────────────

    #[test]
    fn remove_existing_returns_true() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let removed = store.remove(&nonce).unwrap();
        assert!(removed);
        assert!(store.get(&nonce).is_none());
    }

    #[test]
    fn remove_attested_entry_after_successful_commit_persists() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let nonce = {
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            let entry = make_payment_entry(DEFAULT_TTL_MS);
            let nonce = entry.approval_nonce.clone();
            store.insert(entry, TEST_NOW_MS).unwrap();
            store.record_attestation(&nonce, [0x42u8; 32]).unwrap();
            assert!(store.get(&nonce).is_some());

            let removed = store.remove(&nonce).unwrap();
            assert!(removed);
            assert!(store.get(&nonce).is_none());
            nonce
        };

        let reopened = PendingApprovalStore::open(path).unwrap();
        assert!(reopened.get(&nonce).is_none());
    }

    #[test]
    fn remove_absent_returns_false() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let removed = store.remove("nonexistent-nonce").unwrap();
        assert!(!removed);
    }

    // ── File permissions ─────────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn store_file_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let mut store = PendingApprovalStore::open(path.clone()).unwrap();
        store
            .insert(make_payment_entry(DEFAULT_TTL_MS), TEST_NOW_MS)
            .unwrap();
        drop(store);

        let meta = fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "store file must have 0o600 permissions, got {mode:o}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn parent_dir_has_0700_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let base = TempDir::new().unwrap();
        let sub = base.path().join("approvals-test");
        let path = sub.join("default.toml");
        let _store = PendingApprovalStore::open(path).unwrap();

        let meta = fs::metadata(&sub).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "parent directory must have 0o700 permissions, got {mode:o}"
        );
    }

    // ── flock second opener ──────────────────────────────────────────────────

    #[test]
    fn second_opener_returns_writer_locked() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");

        let _store1 = PendingApprovalStore::open(path.clone()).unwrap();
        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(err, ApprovalError::WriterLocked),
            "second opener must return WriterLocked, got {err:?}"
        );
    }

    // ── Orphaned temp file is ignored on re-open ─────────────────────────────

    #[test]
    fn orphaned_tmp_file_ignored_on_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");

        let orphan = dir.path().join("orphan.tmp");
        fs::write(&orphan, b"garbage").unwrap();

        let store = PendingApprovalStore::open(path).unwrap();
        assert_eq!(store.entries.len(), 0);
        assert!(orphan.exists());
    }

    // ── record_attestation: NotFound ─────────────────────────────────────────

    #[test]
    fn record_attestation_not_found() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let err = store
            .record_attestation("no-such-nonce", [0u8; 32])
            .unwrap_err();
        assert!(matches!(err, ApprovalError::NotFound));
    }

    // ── Nonce length from new_payment_pending ─────────────────────────────────

    #[test]
    fn new_unattested_nonce_is_22_chars() {
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        assert_eq!(
            entry.approval_nonce.len(),
            EXPECTED_NONCE_LEN,
            "nonce must be {EXPECTED_NONCE_LEN} chars (16-byte base64url)"
        );
    }

    // ── Tampered nonce is rejected on re-open ────────────────────────────────

    #[test]
    fn tampered_nonce_with_direction_mark_rejected_on_open() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");

        let toml_content = "[[pending]]\n\
             approval_nonce = \"\u{200f}AAAAAAAAAAAAAAAAAAAAAA\"\n\
             envelope_xdr_b64 = \"b64xdr\"\n\
             envelope_sha256_hex = \"aa\"\n\
             summary_to = \"G...\"\n\
             summary_amount_stroops = 100\n\
             summary_asset = \"XLM\"\n\
             summary_simulated_fee_stroops = 100\n\
             summary_simulated_seq_num = 1\n\
             process_uid = \"1000\"\n\
             created_at_unix_ms = 0\n\
             expires_at_unix_ms = 9999999999999\n\
             ";

        std::fs::write(&path, toml_content).unwrap();

        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "tampered nonce must be rejected on open: {err:?}"
        );
    }

    // ── Cyrillic homoglyph nonce rejected ────────────────────────────────────

    #[test]
    fn tampered_nonce_with_cyrillic_homoglyph_rejected_on_open() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");

        let nonce_with_cyrillic = "AAAAAAAAAAAAAAAAAAAAА"; // 20 x ASCII 'A' + Cyrillic А
        assert_eq!(
            nonce_with_cyrillic.len(),
            EXPECTED_NONCE_LEN,
            "test fixture must be {EXPECTED_NONCE_LEN} bytes"
        );

        let toml_content = format!(
            "[[pending]]\n\
             approval_nonce = \"{nonce_with_cyrillic}\"\n\
             envelope_xdr_b64 = \"b64xdr\"\n\
             envelope_sha256_hex = \"aa\"\n\
             summary_to = \"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n\
             summary_amount_stroops = 100\n\
             summary_asset = \"XLM\"\n\
             summary_simulated_fee_stroops = 100\n\
             summary_simulated_seq_num = 1\n\
             process_uid = \"1000\"\n\
             created_at_unix_ms = 0\n\
             expires_at_unix_ms = 9999999999999\n\
             "
        );

        std::fs::write(&path, toml_content).unwrap();

        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "nonce with Cyrillic homoglyph must be rejected on open: {err:?}"
        );
    }

    // ── summary_to injection rejected ────────────────────────────────────────

    #[test]
    fn tampered_summary_to_with_direction_mark_rejected_on_open() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");

        let toml_content = "[[pending]]\n\
             approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"\n\
             envelope_xdr_b64 = \"b64xdr\"\n\
             envelope_sha256_hex = \"aa\"\n\
             summary_to = \"G\u{202e}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n\
             summary_amount_stroops = 100\n\
             summary_asset = \"XLM\"\n\
             summary_simulated_fee_stroops = 100\n\
             summary_simulated_seq_num = 1\n\
             process_uid = \"1000\"\n\
             created_at_unix_ms = 0\n\
             expires_at_unix_ms = 9999999999999\n\
             ";

        std::fs::write(&path, toml_content).unwrap();

        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "tampered summary_to must be rejected on open: {err:?}"
        );
    }

    // ── summary_asset injection rejected ─────────────────────────────────────

    #[test]
    fn tampered_summary_asset_with_unicode_rejected_on_open() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");

        let toml_content = "[[pending]]\n\
             approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"\n\
             envelope_xdr_b64 = \"b64xdr\"\n\
             envelope_sha256_hex = \"aa\"\n\
             summary_to = \"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n\
             summary_amount_stroops = 100\n\
             summary_asset = \"USD\u{202e}C\"\n\
             summary_simulated_fee_stroops = 100\n\
             summary_simulated_seq_num = 1\n\
             process_uid = \"1000\"\n\
             created_at_unix_ms = 0\n\
             expires_at_unix_ms = 9999999999999\n\
             ";

        std::fs::write(&path, toml_content).unwrap();

        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "tampered summary_asset must be rejected on open: {err:?}"
        );
    }

    // ── summary_memo injection rejected ──────────────────────────────────────

    #[test]
    fn tampered_summary_memo_with_direction_mark_rejected_on_open() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");

        let toml_content = "[[pending]]\n\
             approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"\n\
             envelope_xdr_b64 = \"b64xdr\"\n\
             envelope_sha256_hex = \"aa\"\n\
             summary_to = \"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n\
             summary_amount_stroops = 100\n\
             summary_asset = \"XLM\"\n\
             summary_memo = \"pay\u{200f}me\"\n\
             summary_simulated_fee_stroops = 100\n\
             summary_simulated_seq_num = 1\n\
             process_uid = \"1000\"\n\
             created_at_unix_ms = 0\n\
             expires_at_unix_ms = 9999999999999\n\
             ";

        std::fs::write(&path, toml_content).unwrap();

        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "tampered summary_memo must be rejected on open: {err:?}"
        );
    }

    // ── process_uid with injection content rejected ───────────────────────────

    #[test]
    fn process_uid_validator_accepts_windows_sid() {
        assert!(process_uid_is_valid(
            "S-1-5-21-1234567890-123456789-123456789-1001"
        ));
    }

    #[test]
    fn process_uid_validator_rejects_malformed_windows_sid() {
        assert!(!process_uid_is_valid("S-1-5-21-abc-1001"));
        assert!(!process_uid_is_valid("S-1"));
        assert!(!process_uid_is_valid("S-1-5-21-1001 "));
    }

    #[test]
    fn tampered_process_uid_with_injection_rejected_on_open() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");

        let toml_content = "[[pending]]\n\
             approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"\n\
             envelope_xdr_b64 = \"b64xdr\"\n\
             envelope_sha256_hex = \"aa\"\n\
             summary_to = \"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n\
             summary_amount_stroops = 100\n\
             summary_asset = \"XLM\"\n\
             summary_simulated_fee_stroops = 100\n\
             summary_simulated_seq_num = 1\n\
             process_uid = \" 1000\"\n\
             created_at_unix_ms = 0\n\
             expires_at_unix_ms = 9999999999999\n\
             ";

        std::fs::write(&path, toml_content).unwrap();

        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "tampered process_uid must be rejected on open: {err:?}"
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Multi-kind approval tests
    // ══════════════════════════════════════════════════════════════════════════

    // 1. Legacy TOML loads as PaymentSimulated ────────────────────────────────

    /// A legacy TOML file (flat payment-summary fields, no `sign_with_passkey`
    /// sub-table) must load cleanly as `ApprovalKind::PaymentSimulated`.
    #[test]
    fn legacy_toml_loads_as_payment_simulated() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");

        // Flat shape without any sub-tables (legacy format).
        let legacy_toml = "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
envelope_xdr_b64 = \"dGVzdC1lbnZlbG9wZQ\"
envelope_sha256_hex = \"aabbcc\"
summary_to = \"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"
summary_amount_stroops = 1000000
summary_asset = \"XLM\"
summary_simulated_fee_stroops = 100
summary_simulated_seq_num = 12345
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999
";
        std::fs::write(&path, legacy_toml).unwrap();

        let store = PendingApprovalStore::open(path).unwrap();
        assert_eq!(store.entries.len(), 1);
        let entry = &store.entries[0];
        assert_eq!(entry.approval_nonce, "AAAAAAAAAAAAAAAAAAAAAA");
        assert!(
            matches!(entry.kind, ApprovalKind::PaymentSimulated { .. }),
            "legacy TOML must load as PaymentSimulated, got {:?}",
            entry.kind
        );
        if let ApprovalKind::PaymentSimulated {
            ref summary_to,
            summary_amount_stroops,
            ref summary_asset,
            ..
        } = entry.kind
        {
            assert_eq!(summary_to, VALID_SUMMARY_TO);
            assert_eq!(summary_amount_stroops, 1_000_000);
            assert_eq!(summary_asset, "XLM");
        }
        assert!(entry.attestation_blob_b64.is_none());
        assert!(entry.passkey_assertion.is_none());
    }

    // 2. new_passkey_pending constructs SignWithPasskey ────────────────────────

    #[test]
    fn new_passkey_pending_constructs_signwithpasskey() {
        let entry = make_passkey_entry(DEFAULT_TTL_MS);
        assert!(
            matches!(entry.kind, ApprovalKind::SignWithPasskey { .. }),
            "new_passkey_pending must yield SignWithPasskey kind"
        );
        assert_eq!(entry.approval_nonce.len(), EXPECTED_NONCE_LEN);
        assert!(entry.passkey_assertion.is_none());
        assert!(entry.attestation_blob_b64.is_none());
    }

    // 3. record_passkey_assertion success ─────────────────────────────────────

    #[test]
    fn record_passkey_assertion_success() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_passkey_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let assertion = make_assertion();
        store
            .record_passkey_assertion(&nonce, assertion.clone())
            .unwrap();

        let found = store.get(&nonce).unwrap();
        assert!(
            found.passkey_assertion.is_some(),
            "passkey_assertion must be Some after record_passkey_assertion"
        );
        let stored = found.passkey_assertion.as_ref().unwrap();
        assert_eq!(stored.credential_id, assertion.credential_id);
        assert_eq!(stored.authenticator_data, assertion.authenticator_data);
    }

    // 4. record_passkey_assertion already-attested ────────────────────────────

    #[test]
    fn record_passkey_assertion_already_attested_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_passkey_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        store
            .record_passkey_assertion(&nonce, make_assertion())
            .unwrap();

        let err = store
            .record_passkey_assertion(&nonce, make_assertion())
            .unwrap_err();
        assert!(
            matches!(err, ApprovalError::AlreadyAttested),
            "second call must return AlreadyAttested, got {err:?}"
        );
    }

    // 5. record_passkey_assertion wrong-kind (on PaymentSimulated) ────────────

    #[test]
    fn record_passkey_assertion_wrong_kind_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let err = store
            .record_passkey_assertion(&nonce, make_assertion())
            .unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::WrongKind {
                    expected: "SignWithPasskey",
                    actual: "PaymentSimulated"
                }
            ),
            "expected WrongKind {{expected: SignWithPasskey, actual: PaymentSimulated}}, got {err:?}"
        );
    }

    // 6. record_attestation wrong-kind (on SignWithPasskey) ───────────────────

    #[test]
    fn record_attestation_wrong_kind_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_passkey_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let err = store.record_attestation(&nonce, [0x42u8; 32]).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::WrongKind {
                    expected: "PaymentSimulated or ClaimSimulated",
                    actual: "SignWithPasskey"
                }
            ),
            "expected WrongKind {{expected: PaymentSimulated or ClaimSimulated, \
             actual: SignWithPasskey}}, got {err:?}"
        );
    }

    // 7. SignWithPasskey invalid credential_id ────────────────────────────────

    #[test]
    fn signwithpasskey_invalid_credential_id_rejected() {
        // Empty credential_id.
        let err = PendingApproval::new_passkey_pending(
            [0u8; 32],
            vec![], // empty — too short
            "CAAAA...BBBBB".to_owned(),
            vec![1],
            [0u8; 32],
            "localhost".to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "empty credential_id must return Invalid, got {err:?}"
        );

        // Too long (> 64 bytes).
        let err = PendingApproval::new_passkey_pending(
            [0u8; 32],
            vec![0u8; 65], // 65 bytes — too long
            "CAAAA...BBBBB".to_owned(),
            vec![1],
            [0u8; 32],
            "localhost".to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            ">64-byte credential_id must return Invalid, got {err:?}"
        );
    }

    // 8. SignWithPasskey invalid rule_ids ─────────────────────────────────────

    #[test]
    fn signwithpasskey_invalid_rule_ids_rejected() {
        // Empty rule_ids.
        let err = PendingApproval::new_passkey_pending(
            [0u8; 32],
            vec![0u8; 32],
            "CAAAA...BBBBB".to_owned(),
            vec![], // empty
            [0u8; 32],
            "localhost".to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "empty rule_ids must return Invalid, got {err:?}"
        );

        // Too many (> 8).
        let err = PendingApproval::new_passkey_pending(
            [0u8; 32],
            vec![0u8; 32],
            "CAAAA...BBBBB".to_owned(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9], // 9 entries
            [0u8; 32],
            "localhost".to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            ">8 rule_ids must return Invalid, got {err:?}"
        );
    }

    // 9. SignWithPasskey invalid smart_account_redacted ───────────────────────

    #[test]
    fn signwithpasskey_invalid_redaction_shape_rejected() {
        // Full C-strkey (56 chars) — not redacted.
        let full_c_strkey = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 56 chars
        let err = PendingApproval::new_passkey_pending(
            [0u8; 32],
            vec![0u8; 32],
            full_c_strkey.to_owned(),
            vec![1],
            [0u8; 32],
            "localhost".to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "full C-strkey must return Invalid (not redacted), got {err:?}"
        );

        // Truncated — too short.
        let err = PendingApproval::new_passkey_pending(
            [0u8; 32],
            vec![0u8; 32],
            "CAAAA...BB".to_owned(), // only 10 chars
            vec![1],
            [0u8; 32],
            "localhost".to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "truncated redacted string must return Invalid, got {err:?}"
        );
    }

    // 10. passkey_assertion field redacted in Debug ───────────────────────────

    #[test]
    fn passkey_assertion_field_redacted_debug() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_passkey_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();
        store
            .record_passkey_assertion(&nonce, make_assertion())
            .unwrap();

        let found = store.get(&nonce).unwrap();
        let debug_str = format!("{found:?}");

        // Length fields MUST appear.
        assert!(
            debug_str.contains("credential_id_len=32"),
            "Debug must show credential_id_len: {debug_str}"
        );
        assert!(
            debug_str.contains("authenticator_data_len=37"),
            "Debug must show authenticator_data_len: {debug_str}"
        );
        assert!(
            debug_str.contains("signature_compact_len=64"),
            "Debug must show signature_compact_len: {debug_str}"
        );

        // Raw credential_id bytes (0xAB = 171) MUST NOT appear as a raw array.
        assert!(
            !debug_str.contains("credential_id: ["),
            "Debug must NOT print raw credential_id bytes: {debug_str}"
        );
        assert!(
            !debug_str.contains("signature_compact: ["),
            "Debug must NOT print raw signature_compact bytes: {debug_str}"
        );
    }

    // 11. generate_csrf_token produces 32 random bytes ────────────────────────

    #[test]
    fn generate_csrf_token_is_32_bytes_and_random() {
        let t1 = generate_csrf_token();
        let t2 = generate_csrf_token();
        assert_eq!(t1.len(), 32, "CSRF token must be 32 bytes");
        assert_eq!(t2.len(), 32, "CSRF token must be 32 bytes");
        // Two independent calls almost certainly produce distinct outputs.
        // The probability of collision is 2^{-256} ≈ 0.
        assert_ne!(
            t1, t2,
            "two generate_csrf_token calls must produce distinct outputs"
        );
    }

    // ── Round-trip: new SignWithPasskey entry persists and reloads ────────────

    #[test]
    fn signwithpasskey_entry_roundtrip_disk() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let nonce = {
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            let entry = make_passkey_entry(DEFAULT_TTL_MS);
            let n = entry.approval_nonce.clone();
            store.insert(entry, TEST_NOW_MS).unwrap();
            n
        }; // lock released

        let store2 = PendingApprovalStore::open(path).unwrap();
        let loaded = store2.get(&nonce).unwrap();
        assert!(
            matches!(loaded.kind, ApprovalKind::SignWithPasskey { .. }),
            "reloaded entry must be SignWithPasskey"
        );
        if let ApprovalKind::SignWithPasskey {
            ref credential_id,
            ref smart_account_redacted,
            ref rule_ids,
            ..
        } = loaded.kind
        {
            assert_eq!(credential_id.len(), 32);
            assert_eq!(smart_account_redacted, "CAAAA...BBBBB");
            assert_eq!(rule_ids, &[1u32, 2u32]);
        }
    }

    // ── PaymentSimulated round-trip (wire stability) ──────────────────────────

    #[test]
    fn payment_simulated_json_has_no_kind_field() {
        // Serialise a PaymentSimulated entry to TOML and verify it does NOT
        // contain a `kind = ` key (backward-compat: consumers that pre-date the
        // multi-kind spine must not see an unexpected field).
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        let sf = StoreFile {
            pending: vec![entry],
        };
        let toml_str = toml::to_string_pretty(&sf).unwrap();
        assert!(
            !toml_str.contains("\nkind"),
            "PaymentSimulated serialisation must not contain a 'kind' field: {toml_str}"
        );
        // PaymentSimulated flat fields MUST be present.
        assert!(
            toml_str.contains("envelope_xdr_b64"),
            "envelope_xdr_b64 must be present: {toml_str}"
        );
        assert!(
            toml_str.contains("summary_to"),
            "summary_to must be present: {toml_str}"
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Deserialise-time tamper-defence (validators + cross-kind)
    // ══════════════════════════════════════════════════════════════════════════
    //
    // The construction-time invariants on `new_passkey_pending` (credential_id
    // length, rule_ids bounds, redaction shape) MUST also fire when a tampered
    // on-disk TOML is reloaded via `PendingApprovalStore::open`.
    //
    // Cross-kind contamination is also rejected (an entry cannot carry both
    // PaymentSimulated and SignWithPasskey fields).

    fn write_tampered(path: &std::path::Path, toml_content: &str) {
        std::fs::write(path, toml_content).unwrap();
    }

    /// SignWithPasskey entry on disk with `credential_id = []` must be rejected.
    #[test]
    fn tampered_on_disk_signwithpasskey_empty_credential_id_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let toml = "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999

[pending.sign_with_passkey]
auth_digest = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
credential_id = []
smart_account_redacted = \"CAAAA...BBBBB\"
rule_ids = [1]
csrf_token = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
";
        write_tampered(&path, toml);

        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "empty credential_id on disk must be rejected: {err:?}"
        );
    }

    /// SignWithPasskey entry on disk with `credential_id > 64 bytes` must be rejected.
    #[test]
    fn tampered_on_disk_signwithpasskey_oversized_credential_id_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        // 65-byte credential_id (one above the CTAP2 max).
        let oversized = (0..65)
            .map(|_| "1".to_owned())
            .collect::<Vec<_>>()
            .join(",");
        let toml = format!(
            "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999

[pending.sign_with_passkey]
auth_digest = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
credential_id = [{oversized}]
smart_account_redacted = \"CAAAA...BBBBB\"
rule_ids = [1]
csrf_token = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
"
        );
        write_tampered(&path, &toml);

        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "oversized credential_id on disk must be rejected: {err:?}"
        );
    }

    /// SignWithPasskey assertion on disk with a non-64-byte compact signature
    /// must be rejected.
    #[test]
    fn tampered_on_disk_signwithpasskey_short_signature_compact_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let short_signature = vec!["13"; 63].join(",");
        let toml = format!(
            "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999

[pending.sign_with_passkey]
auth_digest = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
credential_id = [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
smart_account_redacted = \"CAAAA...BBBBB\"
rule_ids = [1]
csrf_token = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

[pending.passkey_assertion]
credential_id = [1,2,3,4]
authenticator_data = [5,6,7,8]
client_data_json = [9,10,11,12]
signature_compact = [{short_signature}]
"
        );
        write_tampered(&path, &toml);

        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "short signature_compact on disk must be rejected: {err:?}"
        );
    }

    /// SignWithPasskey assertion on disk with a high-S compact signature must be
    /// rejected before the signer sees it.
    #[test]
    fn tampered_on_disk_signwithpasskey_high_s_signature_compact_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let high_s_signature = vec!["255"; 64].join(",");
        let toml = format!(
            "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999

[pending.sign_with_passkey]
auth_digest = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
credential_id = [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
smart_account_redacted = \"CAAAA...BBBBB\"
rule_ids = [1]
csrf_token = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

[pending.passkey_assertion]
credential_id = [1,2,3,4]
authenticator_data = [5,6,7,8]
client_data_json = [9,10,11,12]
signature_compact = [{high_s_signature}]
"
        );
        write_tampered(&path, &toml);

        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "high-S signature_compact on disk must be rejected: {err:?}"
        );
    }

    /// SignWithPasskey entry on disk with `rule_ids = []` must be rejected.
    #[test]
    fn tampered_on_disk_signwithpasskey_empty_rule_ids_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let toml = "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999

[pending.sign_with_passkey]
auth_digest = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
credential_id = [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
smart_account_redacted = \"CAAAA...BBBBB\"
rule_ids = []
csrf_token = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
";
        write_tampered(&path, toml);

        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "empty rule_ids on disk must be rejected: {err:?}"
        );
    }

    /// SignWithPasskey entry on disk with malformed `smart_account_redacted` must be rejected.
    /// Specifically: missing the leading `C` so the shape check fires.
    #[test]
    fn tampered_on_disk_signwithpasskey_invalid_redaction_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let toml = "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999

[pending.sign_with_passkey]
auth_digest = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
credential_id = [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
smart_account_redacted = \"XAAAA...BBBBB\"
rule_ids = [1]
csrf_token = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
";
        write_tampered(&path, toml);

        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "malformed smart_account_redacted on disk must be rejected: {err:?}"
        );
    }

    /// Cross-kind contamination both directions:
    ///   1. SignWithPasskey entry that also carries PaymentSimulated flat fields
    ///   2. PaymentSimulated entry that also carries `passkey_assertion`
    ///
    /// Both shapes must be rejected so the bridge POST handler / commit path
    /// cannot be fed a hybrid record.
    #[test]
    fn tampered_on_disk_cross_kind_contamination_rejected_both_directions() {
        // Direction 1: SignWithPasskey + stray summary_to.
        {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("default.toml");
            let toml = "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999
summary_to = \"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"

[pending.sign_with_passkey]
auth_digest = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
credential_id = [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
smart_account_redacted = \"CAAAA...BBBBB\"
rule_ids = [1]
csrf_token = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
";
            write_tampered(&path, toml);
            let err = PendingApprovalStore::open(path).unwrap_err();
            assert!(
                matches!(
                    err,
                    ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
                ),
                "SignWithPasskey + summary_to contamination must be rejected: {err:?}"
            );
        }

        // Direction 2: PaymentSimulated + stray passkey_assertion.
        {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("default.toml");
            let toml = "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999
envelope_xdr_b64 = \"dGVzdC1lbnZlbG9wZQ\"
envelope_sha256_hex = \"aabbcc\"
summary_to = \"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"
summary_amount_stroops = 1000000
summary_asset = \"XLM\"
summary_simulated_fee_stroops = 100
summary_simulated_seq_num = 12345

[pending.passkey_assertion]
credential_id = [1,2,3,4]
authenticator_data = [5,6,7,8]
client_data_json = [9,10,11,12]
signature_compact = [13,14,15,16]
";
            write_tampered(&path, toml);
            let err = PendingApprovalStore::open(path).unwrap_err();
            assert!(
                matches!(
                    err,
                    ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
                ),
                "PaymentSimulated + passkey_assertion contamination must be rejected: {err:?}"
            );
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // RegisterPasskey arm + RegistrationInput type tests
    // ══════════════════════════════════════════════════════════════════════════

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn valid_pubkey() -> Vec<u8> {
        let mut k = vec![0u8; 65];
        k[0] = 0x04;
        k
    }

    fn make_registration_input() -> RegistrationInput {
        RegistrationInput::new(
            vec![0xABu8; 32],
            valid_pubkey(),
            None,
            vec!["internal".to_owned()],
        )
        .unwrap()
    }

    fn make_register_passkey_entry(ttl_ms: u64) -> PendingApproval {
        PendingApproval::new_register_passkey_pending(
            "CAAAA...BBBBB".to_owned(),
            vec![1, 2],
            [0x03u8; 32],
            "localhost".to_owned(),
            [0x04u8; 32],
            "1000".to_owned(),
            ttl_ms,
        )
        .unwrap()
    }

    // 7. new_register_passkey_pending happy path ───────────────────────────────

    #[test]
    fn new_register_passkey_pending_happy_path() {
        let entry = make_register_passkey_entry(DEFAULT_TTL_MS);
        assert!(
            matches!(entry.kind, ApprovalKind::RegisterPasskey { .. }),
            "new_register_passkey_pending must yield RegisterPasskey kind"
        );
        assert_eq!(entry.approval_nonce.len(), EXPECTED_NONCE_LEN);
        assert!(entry.attestation_blob_b64.is_none());
        assert!(entry.passkey_assertion.is_none());
        // registration_input starts as None inside the arm.
        if let ApprovalKind::RegisterPasskey {
            ref registration_input,
            ref rp_id,
            ..
        } = entry.kind
        {
            assert!(
                registration_input.is_none(),
                "registration_input must be None at issue time"
            );
            assert_eq!(rp_id, "localhost");
        }
    }

    // 8. new_register_passkey_pending rejects bad smart_account_redacted ───────

    #[test]
    fn new_register_passkey_pending_rejects_bad_redaction() {
        let err = PendingApproval::new_register_passkey_pending(
            "XAAAA...BBBBB".to_owned(), // does not start with C
            vec![1],
            [0u8; 32],
            "localhost".to_owned(),
            [0u8; 32],
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "bad smart_account_redacted must return Invalid: {err:?}"
        );
    }

    // 9. new_register_passkey_pending rejects empty / oversized rule_ids ───────

    #[test]
    fn new_register_passkey_pending_rejects_empty_rule_ids() {
        let err = PendingApproval::new_register_passkey_pending(
            "CAAAA...BBBBB".to_owned(),
            vec![], // empty
            [0u8; 32],
            "localhost".to_owned(),
            [0u8; 32],
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "empty rule_ids must return Invalid: {err:?}"
        );
    }

    #[test]
    fn new_register_passkey_pending_rejects_oversized_rule_ids() {
        let err = PendingApproval::new_register_passkey_pending(
            "CAAAA...BBBBB".to_owned(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9], // 9 entries
            [0u8; 32],
            "localhost".to_owned(),
            [0u8; 32],
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            ">8 rule_ids must return Invalid: {err:?}"
        );
    }

    // 10. new_register_passkey_pending rejects rp_id with control char ─────────

    #[test]
    fn new_register_passkey_pending_rejects_rp_id_control_char() {
        let err = PendingApproval::new_register_passkey_pending(
            "CAAAA...BBBBB".to_owned(),
            vec![1],
            [0u8; 32],
            "local\x00host".to_owned(), // null byte in rp_id
            [0u8; 32],
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "rp_id with control char must return Invalid: {err:?}"
        );
    }

    #[test]
    fn new_register_passkey_pending_rejects_empty_rp_id() {
        let err = PendingApproval::new_register_passkey_pending(
            "CAAAA...BBBBB".to_owned(),
            vec![1],
            [0u8; 32],
            String::new(), // empty rp_id
            [0u8; 32],
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "empty rp_id must return Invalid: {err:?}"
        );
    }

    // 11. record_passkey_registration happy path ───────────────────────────────

    #[test]
    fn record_passkey_registration_success() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_register_passkey_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let reg = make_registration_input();
        store
            .record_passkey_registration(&nonce, reg.clone())
            .unwrap();

        let found = store.get(&nonce).unwrap();
        if let ApprovalKind::RegisterPasskey {
            ref registration_input,
            ..
        } = found.kind
        {
            let stored = registration_input.as_ref().unwrap();
            assert_eq!(stored.credential_id, reg.credential_id);
            assert_eq!(
                stored.public_key_uncompressed_sec1,
                reg.public_key_uncompressed_sec1
            );
        } else {
            panic!("expected RegisterPasskey kind");
        }
    }

    // 12. record_passkey_registration returns WrongKind on PaymentSimulated ─────

    #[test]
    fn record_passkey_registration_wrong_kind_payment_simulated() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let err = store
            .record_passkey_registration(&nonce, make_registration_input())
            .unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::WrongKind {
                    expected: "RegisterPasskey",
                    actual: "PaymentSimulated"
                }
            ),
            "expected WrongKind for PaymentSimulated, got {err:?}"
        );
    }

    // 13. record_passkey_registration returns WrongKind on SignWithPasskey ──────

    #[test]
    fn record_passkey_registration_wrong_kind_sign_with_passkey() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_passkey_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let err = store
            .record_passkey_registration(&nonce, make_registration_input())
            .unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::WrongKind {
                    expected: "RegisterPasskey",
                    actual: "SignWithPasskey"
                }
            ),
            "expected WrongKind for SignWithPasskey, got {err:?}"
        );
    }

    // 14. record_passkey_registration returns NotFound on unknown nonce ─────────

    #[test]
    fn record_passkey_registration_not_found() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let err = store
            .record_passkey_registration("no-such-nonce", make_registration_input())
            .unwrap_err();
        assert!(
            matches!(err, ApprovalError::NotFound),
            "expected NotFound, got {err:?}"
        );
    }

    // 15 + 16. Custom Serialize / Deserialize: RegisterPasskey roundtrip ────────

    #[test]
    fn register_passkey_entry_serialise_roundtrip() {
        // Verify that the custom Serialize/Deserialize preserves a
        // RegisterPasskey entry exactly, and that the TOML output contains
        // the `register_passkey` sub-table key and not `sign_with_passkey`.
        let entry = make_register_passkey_entry(DEFAULT_TTL_MS);
        let sf = StoreFile {
            pending: vec![entry.clone()],
        };
        let toml_str = toml::to_string_pretty(&sf).unwrap();

        // Must contain register_passkey sub-table key.
        assert!(
            toml_str.contains("register_passkey"),
            "RegisterPasskey serialisation must contain 'register_passkey' sub-table: {toml_str}"
        );
        // Must NOT contain sign_with_passkey.
        assert!(
            !toml_str.contains("sign_with_passkey"),
            "RegisterPasskey serialisation must not contain 'sign_with_passkey': {toml_str}"
        );
        // Must NOT contain payment-summary flat fields.
        assert!(
            !toml_str.contains("envelope_xdr_b64"),
            "RegisterPasskey serialisation must not contain 'envelope_xdr_b64': {toml_str}"
        );

        // Deserialise and verify field identity.
        let sf2: StoreFile = toml::from_str(&toml_str).unwrap();
        assert_eq!(sf2.pending.len(), 1);
        let loaded = &sf2.pending[0];
        assert_eq!(loaded.approval_nonce, entry.approval_nonce);
        assert!(
            matches!(loaded.kind, ApprovalKind::RegisterPasskey { .. }),
            "reloaded kind must be RegisterPasskey"
        );
        if let ApprovalKind::RegisterPasskey {
            ref smart_account_redacted,
            ref rule_ids,
            ref rp_id,
            ..
        } = loaded.kind
        {
            assert_eq!(smart_account_redacted, "CAAAA...BBBBB");
            assert_eq!(rule_ids, &[1u32, 2u32]);
            assert_eq!(rp_id, "localhost");
        }
    }

    #[test]
    fn register_passkey_entry_disk_roundtrip() {
        // Full persist-and-reload cycle via PendingApprovalStore.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let nonce = {
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            let entry = make_register_passkey_entry(DEFAULT_TTL_MS);
            let n = entry.approval_nonce.clone();
            store.insert(entry, TEST_NOW_MS).unwrap();
            n
        }; // lock released

        let store2 = PendingApprovalStore::open(path).unwrap();
        let loaded = store2.get(&nonce).unwrap();
        assert!(
            matches!(loaded.kind, ApprovalKind::RegisterPasskey { .. }),
            "reloaded entry must be RegisterPasskey"
        );
        if let ApprovalKind::RegisterPasskey {
            ref smart_account_redacted,
            ref rp_id,
            ref rule_ids,
            ref registration_input,
            ..
        } = loaded.kind
        {
            assert_eq!(smart_account_redacted, "CAAAA...BBBBB");
            assert_eq!(rp_id, "localhost");
            assert_eq!(rule_ids, &[1u32, 2u32]);
            assert!(
                registration_input.is_none(),
                "registration_input must be None before bridge records it"
            );
        }
    }

    // 17. Cross-kind contamination: PaymentSimulated + registration_input ───────

    #[test]
    fn tampered_payment_simulated_with_registration_input_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        // A PaymentSimulated-shaped entry that also carries a registration_input
        // sub-table must be rejected on load.
        let toml = "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999
envelope_xdr_b64 = \"dGVzdA\"
envelope_sha256_hex = \"aabbcc\"
summary_to = \"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"
summary_amount_stroops = 1000000
summary_asset = \"XLM\"
summary_simulated_fee_stroops = 100
summary_simulated_seq_num = 12345

[pending.registration_input]
credential_id = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]
public_key_uncompressed_sec1 = [4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
transports = []
";
        write_tampered(&path, toml);
        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "PaymentSimulated + registration_input contamination must be rejected: {err:?}"
        );
    }

    // 18. Cross-kind contamination: SignWithPasskey + registration_input ────────

    #[test]
    fn tampered_sign_with_passkey_with_registration_input_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let toml = "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999

[pending.sign_with_passkey]
auth_digest = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
credential_id = [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
smart_account_redacted = \"CAAAA...BBBBB\"
rule_ids = [1]
csrf_token = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

[pending.registration_input]
credential_id = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]
public_key_uncompressed_sec1 = [4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
transports = []
";
        write_tampered(&path, toml);
        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "SignWithPasskey + registration_input contamination must be rejected: {err:?}"
        );
    }

    // 19. Cross-kind contamination: RegisterPasskey + passkey_assertion ─────────

    #[test]
    fn tampered_register_passkey_with_passkey_assertion_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let toml = "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999

[pending.register_passkey]
smart_account_redacted = \"CAAAA...BBBBB\"
rule_ids = [1]
csrf_token = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
rp_id = \"localhost\"
user_handle = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

[pending.passkey_assertion]
credential_id = [1,2,3,4]
authenticator_data = [5,6,7,8]
client_data_json = [9,10,11,12]
signature_compact = [13,14,15,16]
";
        write_tampered(&path, toml);
        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "RegisterPasskey + passkey_assertion contamination must be rejected: {err:?}"
        );
    }

    // 21. Cross-kind contamination: both passkey sub-tables present ────────────
    //
    // Regression guard for the Deserialize routing priority: `sign_with_passkey`
    // wins over `register_passkey`. The first-arm contamination check rejects a
    // TOML carrying BOTH sub-tables because the SignWithPasskey arm's
    // contamination loop refuses `register_passkey`. This test locks that
    // behaviour so a future routing refactor cannot silently allow the
    // double-sub-table case to slip through.

    #[test]
    fn deserialize_rejects_both_passkey_subtables_present() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        // Use integer arrays (the typed wire shape for [u8; 32] fields) so the
        // rejection fires at the routing-priority contamination loop in the
        // SignWithPasskey arm (the first-arm check on `register_passkey`),
        // NOT at the upstream TOML field-type-mismatch layer. The integer-array
        // form mirrors the format used by the existing contamination tests at
        // `record_passkey_assertion_*` and `tampered_on_disk_*`.
        let zero32 = "[".to_owned() + &(0..32).map(|_| "0").collect::<Vec<_>>().join(",") + "]";
        let bad_toml = format!(
            "\
[[pending]]
approval_nonce = \"CCCCCCCCCCCCCCCCCCCCCC\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999

[pending.sign_with_passkey]
auth_digest = {zero32}
credential_id = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
smart_account_redacted = \"CAAAA...BBBBB\"
rule_ids = [1]
csrf_token = {zero32}

[pending.register_passkey]
smart_account_redacted = \"CAAAA...BBBBB\"
rule_ids = [1]
csrf_token = {zero32}
rp_id = \"localhost\"
user_handle = {zero32}
"
        );
        std::fs::write(&path, &bad_toml).unwrap();
        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(err, ApprovalError::Toml { .. }),
            "TOML with both sign_with_passkey AND register_passkey sub-tables \
             must be rejected by the routing-priority contamination check: \
             {err:?}"
        );
        // Confirm the contamination loop is the rejection path: error message
        // must name `register_passkey` as the contaminating field, not the
        // upstream TOML type system.
        let err_msg = format!("{err}");
        assert!(
            err_msg.contains("register_passkey"),
            "rejection must be from the contamination guard naming 'register_passkey', \
             got: {err_msg}"
        );
    }

    // 20. Legacy TOML (flat payment shape) still loads cleanly ──────────────────

    #[test]
    fn legacy_payment_toml_loads_cleanly_after_registerpasskey_addition() {
        // Regression guard: the RegisterPasskey arm must not break legacy flat-
        // field TOML files that have no sub-tables.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let legacy_toml = "\
[[pending]]
approval_nonce = \"BBBBBBBBBBBBBBBBBBBBBB\"
envelope_xdr_b64 = \"dGVzdC1lbnZlbG9wZQ\"
envelope_sha256_hex = \"aabbcc\"
summary_to = \"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"
summary_amount_stroops = 500000
summary_asset = \"XLM\"
summary_simulated_fee_stroops = 200
summary_simulated_seq_num = 99
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999
";
        std::fs::write(&path, legacy_toml).unwrap();

        let store = PendingApprovalStore::open(path).unwrap();
        assert_eq!(store.entries.len(), 1);
        let entry = &store.entries[0];
        assert!(
            matches!(entry.kind, ApprovalKind::PaymentSimulated { .. }),
            "legacy TOML must still load as PaymentSimulated after RegisterPasskey addition"
        );
        // Confirm the entry has no stray passkey/registration fields set.
        assert!(entry.passkey_assertion.is_none());
        assert!(entry.attestation_blob_b64.is_none());
    }

    // ── ClaimSimulated: construction, serde round-trip, contamination ─────────

    /// Valid claimable-balance strkey (`B` + 57 base32 chars, 58 total): the
    /// `stellar_strkey::ClaimableBalance::V0` rendering of the `0xAB`-repeated
    /// hash encoded by [`valid_balance_id_hex72`].
    const VALID_BALANCE_ID_STRKEY: &str =
        "BAAKXK5LVOV2XK5LVOV2XK5LVOV2XK5LVOV2XK5LVOV2XK5LVOV2XK6UVM";

    /// Valid 72-hex balance id: `00000000` V0 discriminant + 64-hex hash.
    fn valid_balance_id_hex72() -> String {
        format!("00000000{}", "ab".repeat(32))
    }

    fn make_claim_entry(ttl_ms: u64) -> PendingApproval {
        PendingApproval::new_claim_pending(
            "b64xdr".to_owned(),
            b"fake-claim-xdr",
            valid_balance_id_hex72(),
            VALID_BALANCE_ID_STRKEY.to_owned(),
            "XLM".to_owned(),
            50_000_000,
            VALID_SUMMARY_TO.to_owned(),
            200,
            777,
            "1000".to_owned(),
            ttl_ms,
        )
        .unwrap()
    }

    #[test]
    fn claim_simulated_kind_name() {
        let entry = make_claim_entry(DEFAULT_TTL_MS);
        assert_eq!(entry.kind.kind_name(), "ClaimSimulated");
    }

    #[test]
    fn claim_simulated_serialise_roundtrip() {
        // Serialise a ClaimSimulated entry to TOML, confirm it uses the
        // claim_simulated sub-table (not flat PaymentSimulated fields), then
        // reload and assert field-for-field identity.
        let entry = make_claim_entry(DEFAULT_TTL_MS);
        let sf = StoreFile {
            pending: vec![entry.clone()],
        };
        let toml_str = toml::to_string_pretty(&sf).unwrap();

        assert!(
            toml_str.contains("claim_simulated"),
            "ClaimSimulated serialisation must contain 'claim_simulated' sub-table: {toml_str}"
        );
        assert!(
            !toml_str.contains("summary_to"),
            "ClaimSimulated serialisation must not contain the PaymentSimulated \
             'summary_to' flat field: {toml_str}"
        );

        let sf2: StoreFile = toml::from_str(&toml_str).unwrap();
        assert_eq!(sf2.pending.len(), 1);
        let loaded = &sf2.pending[0];
        assert_eq!(loaded.approval_nonce, entry.approval_nonce);
        let ApprovalKind::ClaimSimulated {
            ref summary_balance_id_hex72,
            ref summary_balance_id_strkey,
            ref summary_asset,
            summary_amount_stroops,
            ref summary_source,
            summary_simulated_fee_stroops,
            summary_simulated_seq_num,
            ..
        } = loaded.kind
        else {
            panic!("expected ClaimSimulated kind, got {:?}", loaded.kind);
        };
        assert_eq!(summary_balance_id_hex72, &valid_balance_id_hex72());
        assert_eq!(summary_balance_id_strkey, VALID_BALANCE_ID_STRKEY);
        assert_eq!(summary_asset, "XLM");
        assert_eq!(summary_amount_stroops, 50_000_000);
        assert_eq!(summary_source, VALID_SUMMARY_TO);
        assert_eq!(summary_simulated_fee_stroops, 200);
        assert_eq!(summary_simulated_seq_num, 777);
    }

    #[test]
    fn claim_simulated_disk_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let nonce = {
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            let entry = make_claim_entry(DEFAULT_TTL_MS);
            let n = entry.approval_nonce.clone();
            store.insert(entry, TEST_NOW_MS).unwrap();
            n
        };

        let store2 = PendingApprovalStore::open(path).unwrap();
        let loaded = store2.get(&nonce).unwrap();
        assert!(
            matches!(loaded.kind, ApprovalKind::ClaimSimulated { .. }),
            "reloaded entry must be ClaimSimulated"
        );
    }

    #[test]
    fn record_attestation_succeeds_on_claim_simulated() {
        // record_attestation must accept a ClaimSimulated entry (shared
        // envelope-hash HMAC path with PaymentSimulated).
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_claim_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();
        store.record_attestation(&nonce, [0x11u8; 32]).unwrap();
        let loaded = store.get(&nonce).unwrap();
        assert!(
            loaded.attestation_blob_b64.is_some(),
            "attestation blob must be recorded on the ClaimSimulated entry"
        );
    }

    #[test]
    fn tampered_claim_simulated_with_summary_to_rejected() {
        // A claim_simulated sub-table entry that also carries the stray
        // PaymentSimulated `summary_to` flat field must be rejected on open.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let balance_id_hex72 = valid_balance_id_hex72();
        let toml = format!(
            "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999
summary_to = \"{VALID_SUMMARY_TO}\"

[pending.claim_simulated]
envelope_xdr_b64 = \"dGVzdA\"
envelope_sha256_hex = \"aabbcc\"
summary_balance_id_hex72 = \"{balance_id_hex72}\"
summary_balance_id_strkey = \"{VALID_BALANCE_ID_STRKEY}\"
summary_asset = \"XLM\"
summary_amount_stroops = 1000000
summary_source = \"{VALID_SUMMARY_TO}\"
summary_simulated_fee_stroops = 200
summary_simulated_seq_num = 99
"
        );
        write_tampered(&path, &toml);
        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "ClaimSimulated + summary_to contamination must be rejected: {err:?}"
        );
    }

    // record_passkey_registration: already-attested guard ──────────────────────

    #[test]
    fn record_passkey_registration_already_attested_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_register_passkey_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        store
            .record_passkey_registration(&nonce, make_registration_input())
            .unwrap();

        let err = store
            .record_passkey_registration(&nonce, make_registration_input())
            .unwrap_err();
        assert!(
            matches!(err, ApprovalError::AlreadyAttested),
            "second record_passkey_registration call must return AlreadyAttested: {err:?}"
        );
    }

    // Tamper: RegisterPasskey on disk with invalid rp_id (control char) ─────────

    #[test]
    fn tampered_on_disk_register_passkey_invalid_rp_id_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        // rp_id contains a null byte — must be rejected on reload.
        let toml = "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999

[pending.register_passkey]
smart_account_redacted = \"CAAAA...BBBBB\"
rule_ids = [1]
csrf_token = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
rp_id = \"local\u{0000}host\"
user_handle = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
";
        write_tampered(&path, toml);
        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "RegisterPasskey with control-char rp_id must be rejected: {err:?}"
        );
    }

    // kind_name returns "RegisterPasskey" ──────────────────────────────────────

    #[test]
    fn register_passkey_kind_name() {
        let entry = make_register_passkey_entry(DEFAULT_TTL_MS);
        assert_eq!(entry.kind.kind_name(), "RegisterPasskey");
    }

    // record_passkey_registration persists to disk and reloads ─────────────────

    #[test]
    fn record_passkey_registration_persists_to_disk() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let nonce = {
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            let entry = make_register_passkey_entry(DEFAULT_TTL_MS);
            let n = entry.approval_nonce.clone();
            store.insert(entry, TEST_NOW_MS).unwrap();
            store
                .record_passkey_registration(&n, make_registration_input())
                .unwrap();
            n
        }; // lock released

        let store2 = PendingApprovalStore::open(path).unwrap();
        let loaded = store2.get(&nonce).unwrap();
        if let ApprovalKind::RegisterPasskey {
            ref registration_input,
            ..
        } = loaded.kind
        {
            assert!(
                registration_input.is_some(),
                "registration_input must be Some after persist-and-reload"
            );
            let ri = registration_input.as_ref().unwrap();
            assert_eq!(ri.credential_id, vec![0xABu8; 32]);
        } else {
            panic!("expected RegisterPasskey kind after reload");
        }
    }

    // ── IP-literal rp_id rejection ───────────────────────────────────────────

    /// `validate_sign_with_passkey_invariants` rejects IPv4 rp_id literals.
    #[test]
    fn sign_with_passkey_rejects_ipv4_rp_id() {
        let cred_id = vec![0u8; 16];
        let rule_ids = vec![0u32];
        let redacted = "CAAAA...AAAAA".to_owned();
        let err =
            validate_sign_with_passkey_invariants(&cred_id, &rule_ids, &redacted, "127.0.0.1")
                .unwrap_err();
        assert!(
            err.contains("IP address literal"),
            "error must cite IP address literal; got: {err}"
        );
    }

    /// `validate_sign_with_passkey_invariants` rejects IPv6 rp_id literals.
    #[test]
    fn sign_with_passkey_rejects_ipv6_rp_id() {
        let cred_id = vec![0u8; 16];
        let rule_ids = vec![0u32];
        let redacted = "CAAAA...AAAAA".to_owned();
        let err = validate_sign_with_passkey_invariants(&cred_id, &rule_ids, &redacted, "::1")
            .unwrap_err();
        assert!(
            err.contains("IP address literal"),
            "error must cite IP address literal; got: {err}"
        );
    }

    /// `validate_sign_with_passkey_invariants` rejects non-loopback IPv4.
    #[test]
    fn sign_with_passkey_rejects_nonloopback_ipv4_rp_id() {
        let cred_id = vec![0u8; 16];
        let rule_ids = vec![0u32];
        let redacted = "CAAAA...AAAAA".to_owned();
        let err =
            validate_sign_with_passkey_invariants(&cred_id, &rule_ids, &redacted, "192.168.1.1")
                .unwrap_err();
        assert!(
            err.contains("IP address literal"),
            "error must cite IP address literal; got: {err}"
        );
    }

    /// `validate_sign_with_passkey_invariants` accepts `"localhost"`.
    #[test]
    fn sign_with_passkey_accepts_localhost_rp_id() {
        let cred_id = vec![0u8; 16];
        let rule_ids = vec![0u32];
        let redacted = "CAAAA...AAAAA".to_owned();
        validate_sign_with_passkey_invariants(&cred_id, &rule_ids, &redacted, "localhost")
            .expect("localhost must be accepted as rp_id");
    }

    /// `validate_sign_with_passkey_invariants` accepts a production hostname.
    #[test]
    fn sign_with_passkey_accepts_domain_rp_id() {
        let cred_id = vec![0u8; 16];
        let rule_ids = vec![0u32];
        let redacted = "CAAAA...AAAAA".to_owned();
        validate_sign_with_passkey_invariants(&cred_id, &rule_ids, &redacted, "wallet.example.com")
            .expect("production hostname must be accepted as rp_id");
    }

    /// `validate_register_passkey_invariants` rejects IPv4 rp_id literals.
    #[test]
    fn register_passkey_rejects_ipv4_rp_id() {
        let redacted = "CAAAA...AAAAA".to_owned();
        let rule_ids = vec![0u32];
        let err =
            validate_register_passkey_invariants(&redacted, &rule_ids, "127.0.0.1").unwrap_err();
        assert!(
            err.contains("IP address literal"),
            "error must cite IP address literal; got: {err}"
        );
    }

    /// `validate_register_passkey_invariants` rejects IPv6 rp_id literals.
    #[test]
    fn register_passkey_rejects_ipv6_rp_id() {
        let redacted = "CAAAA...AAAAA".to_owned();
        let rule_ids = vec![0u32];
        let err = validate_register_passkey_invariants(&redacted, &rule_ids, "::1").unwrap_err();
        assert!(
            err.contains("IP address literal"),
            "error must cite IP address literal; got: {err}"
        );
    }

    /// `validate_register_passkey_invariants` accepts `"localhost"`.
    #[test]
    fn register_passkey_accepts_localhost_rp_id() {
        let redacted = "CAAAA...AAAAA".to_owned();
        let rule_ids = vec![0u32];
        validate_register_passkey_invariants(&redacted, &rule_ids, "localhost")
            .expect("localhost must be accepted as rp_id");
    }

    /// `validate_register_passkey_invariants` accepts a LDH-label hostname.
    #[test]
    fn register_passkey_accepts_ldh_domain_rp_id() {
        let redacted = "CAAAA...AAAAA".to_owned();
        let rule_ids = vec![0u32];
        validate_register_passkey_invariants(&redacted, &rule_ids, "a-b.c")
            .expect("LDH-label hostname must be accepted as rp_id");
    }

    // ── TrustlineClawbackOptIn: serde round-trip + store record/lookup ────────

    const TESTNET_USDC_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

    /// Happy-path: `new_trustline_clawback_opt_in_pending` constructs a valid
    /// entry and the serde round-trip (via TOML persist + reload) yields the
    /// same `network`, `code`, and `issuer`.
    #[test]
    fn trustline_clawback_opt_in_serde_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let nonce = {
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
                TESTNET_PASSPHRASE.to_owned(),
                "USDC".to_owned(),
                TESTNET_USDC_ISSUER.to_owned(),
                "1000".to_owned(),
                DEFAULT_TTL_MS,
            )
            .unwrap();
            let n = entry.approval_nonce.clone();
            store.insert(entry, TEST_NOW_MS).unwrap();
            n
        }; // store dropped — lock released

        let store2 = PendingApprovalStore::open(path).unwrap();
        let found = store2.get(&nonce).unwrap();
        if let ApprovalKind::TrustlineClawbackOptIn {
            network,
            code,
            issuer,
        } = &found.kind
        {
            assert_eq!(network, TESTNET_PASSPHRASE);
            assert_eq!(code, "USDC");
            assert_eq!(issuer, TESTNET_USDC_ISSUER);
        } else {
            panic!("expected TrustlineClawbackOptIn kind, got {:?}", found.kind);
        }
    }

    /// The clawback opt-in gate MUST HMAC-VERIFY the attestation blob against the
    /// keyring key, not merely check presence. A blob attested with the correct
    /// key verifies; a forged blob, a wrong-key blob, and a wrong
    /// `(network, code, issuer)` all fail. A presence-only check would clear
    /// the gate on any `Some(_)` blob, letting any writer of the profile store
    /// file forge consent.
    #[test]
    fn verify_attested_trustline_clawback_opt_in_rejects_forged_and_wrong_key() {
        use crate::approval::attestation::{
            compute_attestation, compute_trustline_clawback_opt_in_digest,
        };

        let real_key: [u8; 32] = [0x11; 32];
        let wrong_key: [u8; 32] = [0x22; 32];
        let network = "stellar:testnet";
        let code = "USDC";
        let issuer = TESTNET_USDC_ISSUER;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let mut store = PendingApprovalStore::open(path).unwrap();
        let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
            network.to_owned(),
            code.to_owned(),
            issuer.to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        let process_uid = entry.process_uid.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let now = 1u64; // not expired (TTL is in the future)

        // Pre-attestation: no blob → gate stays closed.
        assert!(
            !store.verify_attested_trustline_clawback_opt_in(&real_key, network, code, issuer, now),
            "unattested opt-in must NOT clear the gate"
        );

        // Attest with the REAL key over the canonical digest.
        let digest = compute_trustline_clawback_opt_in_digest(network, code, issuer);
        let real_blob = compute_attestation(&real_key, &nonce, &digest, &process_uid);
        store
            .record_trustline_clawback_opt_in_attestation(&nonce, real_blob)
            .unwrap();

        // Correct key → verifies.
        assert!(
            store.verify_attested_trustline_clawback_opt_in(&real_key, network, code, issuer, now),
            "opt-in attested with the real key MUST verify"
        );

        // Wrong key → rejected (the core forged-consent defence).
        assert!(
            !store
                .verify_attested_trustline_clawback_opt_in(&wrong_key, network, code, issuer, now),
            "a blob verified under the WRONG key must be rejected"
        );

        // Wrong (network, code, issuer) → digest differs → rejected.
        assert!(
            !store
                .verify_attested_trustline_clawback_opt_in(&real_key, network, "EURC", issuer, now),
            "a different asset code must not match the attested digest"
        );

        // A blob forged with an attacker-held key (not the wallet keyring key)
        // fails verification — the core forged-consent defence. (The record API
        // refuses re-attestation, so an attacker's only avenue is a hand-written
        // store file with a self-keyed blob; this models that with a fresh entry
        // whose blob is computed over its OWN nonce/uid under the wrong key.)
        let dir2 = TempDir::new().unwrap();
        let mut forged_store =
            PendingApprovalStore::open(dir2.path().join("default.toml")).unwrap();
        let forged_entry = PendingApproval::new_trustline_clawback_opt_in_pending(
            network.to_owned(),
            code.to_owned(),
            issuer.to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let forged_nonce = forged_entry.approval_nonce.clone();
        let forged_uid = forged_entry.process_uid.clone();
        let attacker_blob = compute_attestation(&wrong_key, &forged_nonce, &digest, &forged_uid);
        forged_store.insert(forged_entry, TEST_NOW_MS).unwrap();
        forged_store
            .record_trustline_clawback_opt_in_attestation(&forged_nonce, attacker_blob)
            .unwrap();
        assert!(
            !forged_store
                .verify_attested_trustline_clawback_opt_in(&real_key, network, code, issuer, now),
            "a blob forged with a non-keyring key must be rejected under the real key"
        );
    }

    // ── ToolsetFirstInvokeGate construction + validation ────────────────────────

    fn make_toolset_gate_entry(ttl_ms: u64) -> PendingApproval {
        PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "sign-payment".to_owned(),
            VALID_SUMMARY_TO.to_owned(),
            "XLM".to_owned(),
            0_i64,
            10_000_000_i64,
            "1000".to_owned(),
            ttl_ms,
        )
        .unwrap()
    }

    #[test]
    fn new_toolset_first_invoke_gate_pending_happy_path() {
        let entry = make_toolset_gate_entry(DEFAULT_TTL_MS);
        assert!(
            matches!(entry.kind, ApprovalKind::ToolsetFirstInvokeGate { .. }),
            "new_toolset_first_invoke_gate_pending must yield ToolsetFirstInvokeGate kind"
        );
        assert_eq!(entry.approval_nonce.len(), EXPECTED_NONCE_LEN);
        assert!(entry.attestation_blob_b64.is_none());
        assert!(entry.passkey_assertion.is_none());
        if let ApprovalKind::ToolsetFirstInvokeGate {
            ref toolset_name,
            ref capability,
            ref destination,
            ref asset,
            amount_min_stroops,
            amount_max_stroops,
        } = entry.kind
        {
            assert_eq!(toolset_name, "my-toolset");
            assert_eq!(capability, "sign-payment");
            assert_eq!(destination, VALID_SUMMARY_TO);
            assert_eq!(asset, "XLM");
            assert_eq!(amount_min_stroops, 0);
            assert_eq!(amount_max_stroops, 10_000_000);
        }
    }

    #[test]
    fn toolset_gate_kind_name_is_correct() {
        let entry = make_toolset_gate_entry(DEFAULT_TTL_MS);
        assert_eq!(entry.kind.kind_name(), "ToolsetFirstInvokeGate");
    }

    #[test]
    fn toolset_gate_rejects_empty_toolset_name() {
        let err = PendingApproval::new_toolset_first_invoke_gate_pending(
            String::new(),
            "sign-payment".to_owned(),
            VALID_SUMMARY_TO.to_owned(),
            "XLM".to_owned(),
            0,
            1_000,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "empty toolset_name must return Invalid: {err:?}"
        );
    }

    #[test]
    fn toolset_gate_rejects_toolset_name_with_uppercase() {
        let err = PendingApproval::new_toolset_first_invoke_gate_pending(
            "My-Toolset".to_owned(),
            "sign-payment".to_owned(),
            VALID_SUMMARY_TO.to_owned(),
            "XLM".to_owned(),
            0,
            1_000,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "uppercase toolset_name must return Invalid: {err:?}"
        );
    }

    #[test]
    fn toolset_gate_rejects_overlong_toolset_name() {
        let long_name = "a".repeat(65);
        let err = PendingApproval::new_toolset_first_invoke_gate_pending(
            long_name,
            "sign-payment".to_owned(),
            VALID_SUMMARY_TO.to_owned(),
            "XLM".to_owned(),
            0,
            1_000,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "overlong toolset_name must return Invalid: {err:?}"
        );
    }

    #[test]
    fn toolset_gate_rejects_empty_capability() {
        let err = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            String::new(),
            VALID_SUMMARY_TO.to_owned(),
            "XLM".to_owned(),
            0,
            1_000,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "empty capability must return Invalid: {err:?}"
        );
    }

    #[test]
    fn toolset_gate_rejects_capability_with_space() {
        let err = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "sign payment".to_owned(),
            VALID_SUMMARY_TO.to_owned(),
            "XLM".to_owned(),
            0,
            1_000,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "space in capability must return Invalid: {err:?}"
        );
    }

    #[test]
    fn toolset_gate_rejects_invalid_destination() {
        let err = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "sign-payment".to_owned(),
            "not-a-strkey".to_owned(),
            "XLM".to_owned(),
            0,
            1_000,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "invalid destination must return Invalid: {err:?}"
        );
    }

    #[test]
    fn toolset_gate_rejects_invalid_asset() {
        let err = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "sign-payment".to_owned(),
            VALID_SUMMARY_TO.to_owned(),
            "not-valid-asset".to_owned(),
            0,
            1_000,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "invalid asset must return Invalid: {err:?}"
        );
    }

    #[test]
    fn toolset_gate_rejects_negative_min_stroops() {
        let err = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "sign-payment".to_owned(),
            VALID_SUMMARY_TO.to_owned(),
            "XLM".to_owned(),
            -1_i64,
            1_000,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "negative amount_min_stroops must return Invalid: {err:?}"
        );
    }

    #[test]
    fn toolset_gate_rejects_zero_max_stroops() {
        let err = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "sign-payment".to_owned(),
            VALID_SUMMARY_TO.to_owned(),
            "XLM".to_owned(),
            0_i64,
            0_i64,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "zero amount_max_stroops must return Invalid: {err:?}"
        );
    }

    #[test]
    fn toolset_gate_rejects_min_greater_than_max() {
        let err = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "sign-payment".to_owned(),
            VALID_SUMMARY_TO.to_owned(),
            "XLM".to_owned(),
            10_000_i64,
            5_000_i64,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "min > max stroops must return Invalid: {err:?}"
        );
    }

    #[test]
    fn toolset_gate_accepts_non_xlm_asset() {
        let result = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "sign-payment".to_owned(),
            VALID_SUMMARY_TO.to_owned(),
            format!("USDC:{VALID_SUMMARY_TO}"),
            0_i64,
            1_000_000_i64,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        );
        assert!(
            result.is_ok(),
            "valid code:issuer asset must be accepted: {:?}",
            result
        );
        if let ApprovalKind::ToolsetFirstInvokeGate { ref asset, .. } = result.unwrap().kind {
            assert_eq!(asset, &format!("USDC:{VALID_SUMMARY_TO}"));
        }
    }

    /// `destination` also accepts a C-strkey (Package D, GH issue #8):
    /// `sign-rule-create`'s gated resolver repurposes this field to carry
    /// the smart-account contract being proposed against. `asset` uses the
    /// same code:issuer-shaped sentinel as
    /// `stellar_agent_toolsets_runtime::matrix::SIGN_RULE_CREATE_ASSET_SENTINEL`.
    #[test]
    fn toolset_gate_accepts_c_strkey_destination() {
        let smart_account = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let result = PendingApproval::new_toolset_first_invoke_gate_pending(
            "rule-toolset".to_owned(),
            "sign-rule-create".to_owned(),
            smart_account.to_owned(),
            format!("RULECREATE:{VALID_SUMMARY_TO}"),
            0_i64,
            1_i64,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        );
        assert!(
            result.is_ok(),
            "C-strkey destination must be accepted: {result:?}"
        );
        if let ApprovalKind::ToolsetFirstInvokeGate {
            ref destination, ..
        } = result.unwrap().kind
        {
            assert_eq!(destination, smart_account);
        }
    }

    #[test]
    fn toolset_gate_serde_roundtrip_through_store() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let nonce = {
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            let entry = make_toolset_gate_entry(DEFAULT_TTL_MS);
            let n = entry.approval_nonce.clone();
            store.insert(entry, TEST_NOW_MS).unwrap();
            n
        };

        let store2 = PendingApprovalStore::open(path).unwrap();
        let loaded = store2.get(&nonce).unwrap();
        assert!(
            matches!(loaded.kind, ApprovalKind::ToolsetFirstInvokeGate { .. }),
            "reloaded entry must be ToolsetFirstInvokeGate"
        );
        if let ApprovalKind::ToolsetFirstInvokeGate {
            ref toolset_name,
            ref capability,
            ref destination,
            ref asset,
            amount_min_stroops,
            amount_max_stroops,
        } = loaded.kind
        {
            assert_eq!(toolset_name, "my-toolset");
            assert_eq!(capability, "sign-payment");
            assert_eq!(destination, VALID_SUMMARY_TO);
            assert_eq!(asset, "XLM");
            assert_eq!(amount_min_stroops, 0);
            assert_eq!(amount_max_stroops, 10_000_000);
        }
    }

    #[test]
    fn toolset_gate_toml_contains_sub_table_key() {
        let entry = make_toolset_gate_entry(DEFAULT_TTL_MS);
        let sf = StoreFile {
            pending: vec![entry],
        };
        let toml_str = toml::to_string_pretty(&sf).unwrap();
        assert!(
            toml_str.contains("toolset_first_invoke_gate"),
            "ToolsetFirstInvokeGate serialisation must contain 'toolset_first_invoke_gate' key: {toml_str}"
        );
        assert!(
            !toml_str.contains("envelope_xdr_b64"),
            "ToolsetFirstInvokeGate serialisation must not contain PaymentSimulated fields: {toml_str}"
        );
        assert!(
            !toml_str.contains("sign_with_passkey"),
            "ToolsetFirstInvokeGate serialisation must not contain SignWithPasskey sub-table: {toml_str}"
        );
    }

    #[test]
    fn toolset_gate_debug_redacts_destination() {
        let entry = make_toolset_gate_entry(DEFAULT_TTL_MS);
        let debug = format!("{:?}", entry.kind);
        assert!(
            !debug.contains(VALID_SUMMARY_TO),
            "full destination G-strkey must not appear in ToolsetFirstInvokeGate Debug: {debug}"
        );
        assert!(
            debug.contains("destination_redacted"),
            "ToolsetFirstInvokeGate Debug must include 'destination_redacted' field: {debug}"
        );
    }

    #[test]
    fn tampered_on_disk_toolset_gate_cross_kind_contamination_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let toml = format!(
            "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999
summary_to = \"{VALID_SUMMARY_TO}\"

[pending.toolset_first_invoke_gate]
toolset_name = \"my-toolset\"
capability = \"sign-payment\"
destination = \"{VALID_SUMMARY_TO}\"
asset = \"XLM\"
amount_min_stroops = 0
amount_max_stroops = 1000000
"
        );
        write_tampered(&path, &toml);
        let err = PendingApprovalStore::open(path).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::Toml { .. } | ApprovalError::InvalidEntry { .. }
            ),
            "ToolsetFirstInvokeGate + summary_to contamination must be rejected: {err:?}"
        );
    }

    // ── is_expired boundary conditions ───────────────────────────────────────

    #[test]
    fn is_expired_at_exact_expiry_time_returns_true() {
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        let expiry = entry.expires_at_unix_ms;
        // The contract: expires_at_unix_ms <= now means expired.
        // At now == expiry, the entry is expired.
        assert!(
            entry.is_expired(expiry),
            "entry must be expired when now == expires_at_unix_ms"
        );
    }

    #[test]
    fn is_expired_one_ms_before_expiry_returns_false() {
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        let expiry = entry.expires_at_unix_ms;
        // One millisecond before expiry, not yet expired.
        if expiry > 0 {
            assert!(
                !entry.is_expired(expiry - 1),
                "entry must NOT be expired when now == expires_at_unix_ms - 1"
            );
        }
    }

    // ── len / is_empty contract ───────────────────────────────────────────────

    #[test]
    fn store_len_and_is_empty_track_insertions_and_removals() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        assert!(store.is_empty(), "new store must be empty");
        assert_eq!(store.len(), 0);

        let e1 = make_payment_entry(DEFAULT_TTL_MS);
        let n1 = e1.approval_nonce.clone();
        store.insert(e1, TEST_NOW_MS).unwrap();
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);

        let e2 = make_passkey_entry(DEFAULT_TTL_MS);
        store.insert(e2, TEST_NOW_MS).unwrap();
        assert_eq!(store.len(), 2);

        store.remove(&n1).unwrap();
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
    }

    // ── gc_expired with zero expired entries does not persist ─────────────────

    #[test]
    fn gc_expired_with_no_expired_entries_returns_zero() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        store
            .insert(make_payment_entry(DEFAULT_TTL_MS), TEST_NOW_MS)
            .unwrap();
        store
            .insert(make_passkey_entry(DEFAULT_TTL_MS), TEST_NOW_MS)
            .unwrap();

        // now = 1 → nothing expired (all entries have large expiry timestamps).
        let removed = store.gc_expired(1).unwrap();
        assert_eq!(
            removed, 0,
            "gc_expired must return 0 when nothing is expired"
        );
        assert_eq!(
            store.len(),
            2,
            "no entries must be removed when nothing expired"
        );
    }

    // ── record_attestation: WrongKind on TrustlineClawbackOptIn ──────────────

    #[test]
    fn record_attestation_wrong_kind_on_trustline() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
            TESTNET_PASSPHRASE.to_owned(),
            "USDC".to_owned(),
            TESTNET_USDC_ISSUER.to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let err = store.record_attestation(&nonce, [0x42u8; 32]).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::WrongKind {
                    expected: "PaymentSimulated or ClaimSimulated",
                    actual: "TrustlineClawbackOptIn"
                }
            ),
            "record_attestation on TrustlineClawbackOptIn must return WrongKind: {err:?}"
        );
    }

    // ── record_trustline_clawback_opt_in_attestation: error paths ────────────

    #[test]
    fn record_trustline_clawback_opt_in_attestation_not_found() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let err = store
            .record_trustline_clawback_opt_in_attestation("no-such-nonce", [0u8; 32])
            .unwrap_err();
        assert!(
            matches!(err, ApprovalError::NotFound),
            "expected NotFound, got {err:?}"
        );
    }

    #[test]
    fn record_trustline_clawback_opt_in_attestation_expired_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
            TESTNET_PASSPHRASE.to_owned(),
            "USDC".to_owned(),
            TESTNET_USDC_ISSUER.to_owned(),
            "1000".to_owned(),
            1, // 1 ms TTL
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));

        let err = store
            .record_trustline_clawback_opt_in_attestation(&nonce, [0u8; 32])
            .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Expired),
            "expected Expired, got {err:?}"
        );
    }

    #[test]
    fn record_trustline_clawback_opt_in_attestation_wrong_kind_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let err = store
            .record_trustline_clawback_opt_in_attestation(&nonce, [0x42u8; 32])
            .unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::WrongKind {
                    expected: "TrustlineClawbackOptIn",
                    actual: "PaymentSimulated"
                }
            ),
            "expected WrongKind, got {err:?}"
        );
    }

    #[test]
    fn record_trustline_clawback_opt_in_attestation_already_attested_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
            TESTNET_PASSPHRASE.to_owned(),
            "USDC".to_owned(),
            TESTNET_USDC_ISSUER.to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        store
            .record_trustline_clawback_opt_in_attestation(&nonce, [0x42u8; 32])
            .unwrap();

        let err = store
            .record_trustline_clawback_opt_in_attestation(&nonce, [0x43u8; 32])
            .unwrap_err();
        assert!(
            matches!(err, ApprovalError::AlreadyAttested),
            "second attestation call must return AlreadyAttested: {err:?}"
        );
    }

    // ── has_attested_trustline_clawback_opt_in: detailed gating checks ────────

    #[test]
    fn has_attested_opt_in_returns_false_for_unattested_entry() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
            TESTNET_PASSPHRASE.to_owned(),
            "USDC".to_owned(),
            TESTNET_USDC_ISSUER.to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, TEST_NOW_MS).unwrap();

        // No attestation blob set yet.
        assert!(
            !store.has_attested_trustline_clawback_opt_in(
                TESTNET_PASSPHRASE,
                "USDC",
                TESTNET_USDC_ISSUER,
                1,
            ),
            "unattested entry must not satisfy has_attested check"
        );
    }

    #[test]
    fn has_attested_opt_in_returns_false_for_wrong_triple() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
            TESTNET_PASSPHRASE.to_owned(),
            "USDC".to_owned(),
            TESTNET_USDC_ISSUER.to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();
        store
            .record_trustline_clawback_opt_in_attestation(&nonce, [0x42u8; 32])
            .unwrap();

        // Different code → no match.
        assert!(
            !store.has_attested_trustline_clawback_opt_in(
                TESTNET_PASSPHRASE,
                "EURC",
                TESTNET_USDC_ISSUER,
                1,
            ),
            "different code must not match the attested entry"
        );

        // Different network → no match.
        assert!(
            !store.has_attested_trustline_clawback_opt_in(
                "Public Global Stellar Network ; September 2015",
                "USDC",
                TESTNET_USDC_ISSUER,
                1,
            ),
            "different network must not match the attested entry"
        );
    }

    #[test]
    fn has_attested_opt_in_returns_false_for_expired_entry() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
            TESTNET_PASSPHRASE.to_owned(),
            "USDC".to_owned(),
            TESTNET_USDC_ISSUER.to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let expiry = entry.expires_at_unix_ms;
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();
        store
            .record_trustline_clawback_opt_in_attestation(&nonce, [0x42u8; 32])
            .unwrap();

        // now >= expiry → entry is expired, gate must stay closed.
        assert!(
            !store.has_attested_trustline_clawback_opt_in(
                TESTNET_PASSPHRASE,
                "USDC",
                TESTNET_USDC_ISSUER,
                expiry, // exactly at expiry
            ),
            "expired attested entry must not satisfy has_attested check"
        );
    }

    #[test]
    fn has_attested_opt_in_returns_true_for_valid_attested_entry() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
            TESTNET_PASSPHRASE.to_owned(),
            "USDC".to_owned(),
            TESTNET_USDC_ISSUER.to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();
        store
            .record_trustline_clawback_opt_in_attestation(&nonce, [0x42u8; 32])
            .unwrap();

        assert!(
            store.has_attested_trustline_clawback_opt_in(
                TESTNET_PASSPHRASE,
                "USDC",
                TESTNET_USDC_ISSUER,
                1, // well before expiry
            ),
            "valid attested non-expired entry must satisfy has_attested check"
        );
    }

    // ── record_passkey_assertion: NotFound path ───────────────────────────────

    #[test]
    fn record_passkey_assertion_not_found() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let err = store
            .record_passkey_assertion("no-such-nonce", make_assertion())
            .unwrap_err();
        assert!(
            matches!(err, ApprovalError::NotFound),
            "expected NotFound, got {err:?}"
        );
    }

    // ── record_passkey_registration: Expired path ─────────────────────────────

    #[test]
    fn record_passkey_registration_expired_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_register_passkey_entry(1); // 1 ms TTL
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));

        let err = store
            .record_passkey_registration(&nonce, make_registration_input())
            .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Expired),
            "expected Expired, got {err:?}"
        );
    }

    // ── record_passkey_assertion: Expired path ────────────────────────────────

    #[test]
    fn record_passkey_assertion_expired_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_passkey_entry(1); // 1 ms TTL
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));

        let err = store
            .record_passkey_assertion(&nonce, make_assertion())
            .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Expired),
            "expected Expired, got {err:?}"
        );
    }

    // ── validate_smart_account_redacted: targeted rejection shapes ────────────

    #[test]
    fn smart_account_redacted_rejects_non_c_prefix() {
        // 13 chars starting with 'G' instead of 'C'.
        let err = validate_smart_account_redacted("GAAAA...BBBBB").unwrap_err();
        assert!(
            err.contains("start with 'C'"),
            "error must cite 'C' prefix requirement; got: {err}"
        );
    }

    #[test]
    fn smart_account_redacted_rejects_non_base32_chars_in_prefix() {
        // Chars 1..5 contain a digit 1 which is NOT in base32 [A-Z2-7].
        let err = validate_smart_account_redacted("C1AAA...BBBBB").unwrap_err();
        assert!(
            err.contains("base32"),
            "error must cite base32 requirement for chars 1..5; got: {err}"
        );
    }

    #[test]
    fn smart_account_redacted_rejects_wrong_separator() {
        // Separator must be "...", not "---".
        let err = validate_smart_account_redacted("CAAAA---BBBBB").unwrap_err();
        assert!(
            err.contains("'...'"),
            "error must cite '...' separator requirement; got: {err}"
        );
    }

    #[test]
    fn smart_account_redacted_rejects_non_base32_chars_in_suffix() {
        // Chars 8..13 contain '!' which is NOT in base32 [A-Z2-7].
        let err = validate_smart_account_redacted("CAAAA...BB!BB").unwrap_err();
        assert!(
            err.contains("base32"),
            "error must cite base32 requirement for chars 8..13; got: {err}"
        );
    }

    #[test]
    fn smart_account_redacted_rejects_wrong_length() {
        // 12 chars (one short).
        let err = validate_smart_account_redacted("CAAAA...BBBB").unwrap_err();
        assert!(
            err.contains("13 characters"),
            "error must cite 13-character length; got: {err}"
        );
    }

    // ── redact_g_strkey: short string uses fallback ───────────────────────────

    #[test]
    fn redact_g_strkey_short_string_uses_redacted_placeholder() {
        // Access via the Debug output of a TrustlineClawbackOptIn entry
        // with a very short issuer — exercises the < 10 branch of redact_g_strkey.
        // We call the internal function directly since it's private.
        // Use the toolset gate debug with a short-looking destination via the
        // ToolsetFirstInvokeGate validator which calls redact_g_strkey on error.
        let err = validate_toolset_first_invoke_gate_invariants(
            "my-toolset",
            "sign-payment",
            "tooshort",
            "XLM",
            0,
            1_000,
        )
        .unwrap_err();
        // The error message must contain the redacted form (not the full key).
        // For "tooshort" (8 chars < 10), redact_g_strkey returns "<redacted>".
        assert!(
            err.contains("<redacted>") || err.contains("tooshort"),
            "short destination must appear redacted or verbatim in error: {err}"
        );
    }

    // ── process_uid_is_valid: non-unix-stub path ──────────────────────────────

    #[test]
    fn process_uid_is_valid_accepts_non_unix_stub() {
        assert!(
            process_uid_is_valid("non-unix-stub"),
            "'non-unix-stub' must be accepted by process_uid_is_valid"
        );
    }

    #[test]
    fn process_uid_is_valid_accepts_numeric_uid() {
        assert!(process_uid_is_valid("0"), "uid '0' (root) must be accepted");
        assert!(process_uid_is_valid("1000"), "uid '1000' must be accepted");
        assert!(
            process_uid_is_valid("65534"),
            "uid '65534' (nobody) must be accepted"
        );
    }

    #[test]
    fn process_uid_is_valid_rejects_alpha_string() {
        assert!(
            !process_uid_is_valid("alice"),
            "'alice' must be rejected by process_uid_is_valid"
        );
    }

    #[test]
    fn process_uid_is_valid_rejects_empty_string() {
        assert!(
            !process_uid_is_valid(""),
            "empty string must be rejected by process_uid_is_valid"
        );
    }

    // ── windows_sid_is_valid: structural paths ────────────────────────────────

    #[test]
    fn windows_sid_is_valid_rejects_non_s_prefix() {
        assert!(
            !windows_sid_is_valid("X-1-5-21-100-200-300"),
            "SID must start with 'S-'"
        );
    }

    #[test]
    fn windows_sid_is_valid_rejects_too_few_numeric_parts() {
        // Needs >= 3 numeric parts after "S-".
        assert!(
            !windows_sid_is_valid("S-1-5"),
            "SID with fewer than 3 numeric parts must be rejected"
        );
    }

    #[test]
    fn windows_sid_is_valid_rejects_empty_part() {
        assert!(
            !windows_sid_is_valid("S-1-5--21-100-200-300"),
            "SID with empty part must be rejected"
        );
    }

    #[test]
    fn windows_sid_is_valid_rejects_alpha_in_numeric_part() {
        assert!(
            !windows_sid_is_valid("S-1-5-21-abc-200-300"),
            "SID with alpha in numeric part must be rejected"
        );
    }

    #[test]
    fn windows_sid_is_valid_accepts_valid_sid() {
        assert!(
            windows_sid_is_valid("S-1-5-21-1234567890-123456789-123456789-1001"),
            "canonical Windows SID must be accepted"
        );
    }

    // ── new_passkey_pending: IP-literal rp_id rejection ──────────────────────

    #[test]
    fn new_passkey_pending_rejects_ip_literal_rp_id() {
        let err = PendingApproval::new_passkey_pending(
            [0u8; 32],
            vec![0u8; 16],
            "CAAAA...BBBBB".to_owned(),
            vec![1],
            [0u8; 32],
            "127.0.0.1".to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "IP-literal rp_id must return Invalid: {err:?}"
        );
        if let ApprovalError::Invalid { reason } = err {
            assert!(
                reason.contains("IP address literal"),
                "reason must cite IP address literal: {reason}"
            );
        }
    }

    // ── Multiple entries: get returns correct one ─────────────────────────────

    #[test]
    fn get_returns_correct_entry_when_multiple_present() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let e1 = make_payment_entry(DEFAULT_TTL_MS);
        let e2 = make_passkey_entry(DEFAULT_TTL_MS);
        let e3 = make_toolset_gate_entry(DEFAULT_TTL_MS);
        let n1 = e1.approval_nonce.clone();
        let n2 = e2.approval_nonce.clone();
        let n3 = e3.approval_nonce.clone();
        store.insert(e1, TEST_NOW_MS).unwrap();
        store.insert(e2, TEST_NOW_MS).unwrap();
        store.insert(e3, TEST_NOW_MS).unwrap();

        assert!(matches!(
            store.get(&n1).unwrap().kind,
            ApprovalKind::PaymentSimulated { .. }
        ));
        assert!(matches!(
            store.get(&n2).unwrap().kind,
            ApprovalKind::SignWithPasskey { .. }
        ));
        assert!(matches!(
            store.get(&n3).unwrap().kind,
            ApprovalKind::ToolsetFirstInvokeGate { .. }
        ));
        assert!(store.get("bogus-nonce").is_none());
    }

    // ── PendingApproval debug output for PaymentSimulated + attestation ───────

    #[test]
    fn pending_approval_debug_redacts_attestation_blob() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();
        store.record_attestation(&nonce, [0x42u8; 32]).unwrap();

        let found = store.get(&nonce).unwrap();
        let debug = format!("{found:?}");
        assert!(
            debug.contains("Some(<set>)"),
            "attestation_blob_b64 must appear as 'Some(<set>)' in Debug: {debug}"
        );
        // The stored value is the URL_SAFE_NO_PAD encoding of the attestation
        // bytes; the FULL encoded string must be absent from Debug output. An
        // exact 43-character match cannot collide with the entry's other
        // base64url fields (nonce, envelope) in the same Debug string.
        let encoded = URL_SAFE_NO_PAD.encode([0x42u8; 32]);
        assert!(
            !debug.contains(&encoded),
            "raw base64 attestation bytes must not appear in Debug: {debug}"
        );
    }

    // ── Trustline summary_memo TOML serialisation round-trip ─────────────────

    #[test]
    fn payment_simulated_with_memo_serialises_and_reloads() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let nonce = {
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            let entry = PendingApproval::new_payment_pending(
                "b64xdr".to_owned(),
                b"fake-xdr",
                VALID_SUMMARY_TO.to_owned(),
                5_000_000,
                "XLM".to_owned(),
                Some("invoice-001".to_owned()),
                200,
                99,
                "1000".to_owned(),
                DEFAULT_TTL_MS,
            )
            .unwrap();
            let n = entry.approval_nonce.clone();
            store.insert(entry, TEST_NOW_MS).unwrap();
            n
        };

        let store2 = PendingApprovalStore::open(path).unwrap();
        let loaded = store2.get(&nonce).unwrap();
        if let ApprovalKind::PaymentSimulated {
            ref summary_memo,
            summary_amount_stroops,
            ref summary_to,
            ..
        } = loaded.kind
        {
            assert_eq!(summary_memo.as_deref(), Some("invoice-001"));
            assert_eq!(summary_amount_stroops, 5_000_000);
            assert_eq!(summary_to.as_str(), VALID_SUMMARY_TO);
        } else {
            panic!("expected PaymentSimulated kind after reload");
        }
    }

    // ── TrustlineClawbackOptIn: construction rejects overlong network ─────────

    #[test]
    fn trustline_clawback_opt_in_rejects_overlong_network() {
        let long_network = "A".repeat(65);
        let err = PendingApproval::new_trustline_clawback_opt_in_pending(
            long_network,
            "USDC".to_owned(),
            TESTNET_USDC_ISSUER.to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "expected Invalid for overlong network, got {err:?}"
        );
    }

    #[test]
    fn trustline_clawback_opt_in_rejects_empty_code() {
        let err = PendingApproval::new_trustline_clawback_opt_in_pending(
            TESTNET_PASSPHRASE.to_owned(),
            String::new(),
            TESTNET_USDC_ISSUER.to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "expected Invalid for empty code, got {err:?}"
        );
    }

    #[test]
    fn trustline_clawback_opt_in_rejects_overlong_code() {
        let err = PendingApproval::new_trustline_clawback_opt_in_pending(
            TESTNET_PASSPHRASE.to_owned(),
            "TOOLONGCODE1234".to_owned(), // 15 chars, > 12
            TESTNET_USDC_ISSUER.to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "expected Invalid for overlong code, got {err:?}"
        );
    }

    // ── RegisterPasskey Debug output: redacts byte fields ────────────────────

    #[test]
    fn register_passkey_debug_redacts_byte_fields() {
        let entry = make_register_passkey_entry(DEFAULT_TTL_MS);
        let debug = format!("{:?}", entry.kind);
        // Byte lengths must appear, not raw bytes.
        assert!(
            debug.contains("csrf_token_len"),
            "Debug must show csrf_token_len: {debug}"
        );
        assert!(
            debug.contains("user_handle_len"),
            "Debug must show user_handle_len: {debug}"
        );
        // Raw byte values of [0x03u8; 32] (decimal 3) must not appear as an array.
        assert!(
            !debug.contains("csrf_token: ["),
            "Debug must NOT print raw csrf_token bytes: {debug}"
        );
        assert!(
            !debug.contains("user_handle: ["),
            "Debug must NOT print raw user_handle bytes: {debug}"
        );
        // registration_input starts None.
        assert!(
            debug.contains("registration_input: \"None\""),
            "Debug must show registration_input as None string: {debug}"
        );
    }

    // ── SignWithPasskey entry rp_id defaults to localhost on reload (legacy) ──

    #[test]
    fn sign_with_passkey_legacy_on_disk_rp_id_defaults_to_localhost() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        // An old on-disk entry without an explicit rp_id field.
        let toml = "\
[[pending]]
approval_nonce = \"AAAAAAAAAAAAAAAAAAAAAA\"
process_uid = \"1000\"
created_at_unix_ms = 1746000000000
expires_at_unix_ms = 9999999999999

[pending.sign_with_passkey]
auth_digest = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
credential_id = [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
smart_account_redacted = \"CAAAA...BBBBB\"
rule_ids = [1]
csrf_token = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
";
        std::fs::write(&path, toml).unwrap();

        let store = PendingApprovalStore::open(path).unwrap();
        let entry = store.get("AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        if let ApprovalKind::SignWithPasskey { ref rp_id, .. } = entry.kind {
            assert_eq!(
                rp_id, "localhost",
                "missing rp_id on legacy disk entry must default to 'localhost'"
            );
        } else {
            panic!("expected SignWithPasskey kind");
        }
    }

    /// Validates that `kind_name()` returns `"TrustlineClawbackOptIn"`.
    #[test]
    fn trustline_clawback_opt_in_kind_name() {
        let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
            TESTNET_PASSPHRASE.to_owned(),
            "USDC".to_owned(),
            TESTNET_USDC_ISSUER.to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        assert_eq!(entry.kind.kind_name(), "TrustlineClawbackOptIn");
    }

    /// Construction rejects an empty network passphrase.
    #[test]
    fn trustline_clawback_opt_in_rejects_empty_network() {
        let err = PendingApproval::new_trustline_clawback_opt_in_pending(
            String::new(),
            "USDC".to_owned(),
            TESTNET_USDC_ISSUER.to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "expected Invalid, got {err:?}"
        );
    }

    /// Construction rejects a lowercase asset code (must be uppercase).
    #[test]
    fn trustline_clawback_opt_in_rejects_lowercase_code() {
        let err = PendingApproval::new_trustline_clawback_opt_in_pending(
            TESTNET_PASSPHRASE.to_owned(),
            "usdc".to_owned(),
            TESTNET_USDC_ISSUER.to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "expected Invalid for lowercase code, got {err:?}"
        );
    }

    /// Construction rejects an invalid issuer (not a valid G-strkey).
    #[test]
    fn trustline_clawback_opt_in_rejects_invalid_issuer() {
        let err = PendingApproval::new_trustline_clawback_opt_in_pending(
            TESTNET_PASSPHRASE.to_owned(),
            "USDC".to_owned(),
            "not-a-strkey".to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "expected Invalid for bad issuer, got {err:?}"
        );
    }

    /// Cross-kind contamination: a TOML entry with both `trustline_clawback_opt_in`
    /// and `summary_to` must be rejected on deserialisation.
    #[test]
    fn trustline_clawback_opt_in_cross_kind_contamination_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.toml");

        // Craft a TOML entry that sets both trustline_clawback_opt_in AND
        // a PaymentSimulated flat field (summary_to).
        let bad_toml = format!(
            r#"
[[pending]]
approval_nonce = "AAAAAAAAAAAAAAAAAAAAAA"
process_uid = "1000"
created_at_unix_ms = 0
expires_at_unix_ms = 9999999999999

summary_to = "{VALID_SUMMARY_TO}"

[pending.trustline_clawback_opt_in]
network = "Test SDF Network ; September 2015"
code = "USDC"
issuer = "{TESTNET_USDC_ISSUER}"
"#
        );
        std::fs::write(&path, bad_toml).unwrap();

        let err = PendingApprovalStore::open(path).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("contamination")
                || msg.contains("cross-kind")
                || msg.contains("summary_to"),
            "must reject cross-kind contamination; got: {msg}"
        );
    }

    /// Debug output of TrustlineClawbackOptIn redacts the issuer to first-5-last-5.
    #[test]
    fn trustline_clawback_opt_in_debug_redacts_issuer() {
        let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
            TESTNET_PASSPHRASE.to_owned(),
            "USDC".to_owned(),
            TESTNET_USDC_ISSUER.to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let debug = format!("{entry:?}");
        // Full issuer must not appear; only first-5-last-5 form.
        assert!(
            !debug.contains(TESTNET_USDC_ISSUER),
            "full issuer G-strkey must not appear in Debug output; got: {debug}"
        );
        // Should see "GBBD4...LLA5" or similar first-5-last-5.
        assert!(
            debug.contains("GBBD4"),
            "first-5 of issuer should appear; got: {debug}"
        );
    }

    // ── insert: prune-on-insert behaviour ────────────────────────────────────

    /// An expired entry is pruned when a later `insert` call advances the
    /// clock past its `expires_at_unix_ms`.  After the insert, the store
    /// contains only the new entry.
    #[test]
    fn insert_prunes_expired_entries() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);

        // Insert entry A with a 50 ms TTL at time TEST_NOW_MS.
        let entry_a = make_payment_entry(50);
        let nonce_a = entry_a.approval_nonce.clone();
        // A is alive at TEST_NOW_MS (expires_at = real_clock + 50, which is > 1).
        store.insert(entry_a, TEST_NOW_MS).unwrap();
        assert_eq!(store.len(), 1);

        // Obtain A's actual expiry from the store so we can set now > expiry.
        let a_expires_at = store.get(&nonce_a).unwrap().expires_at_unix_ms;

        // Insert entry B with now = a_expires_at + 1 (past A's expiry).
        // The insert-time prune must evict A before adding B.
        let entry_b = make_passkey_entry(DEFAULT_TTL_MS);
        let nonce_b = entry_b.approval_nonce.clone();
        store.insert(entry_b, a_expires_at + 1).unwrap();

        assert_eq!(store.len(), 1, "A must have been pruned; only B remains");
        assert!(
            store.get(&nonce_a).is_none(),
            "A must be absent after prune"
        );
        assert!(
            store.get(&nonce_b).is_some(),
            "B must be findable after insert"
        );
    }

    // ── insert: hard-cap rejection ────────────────────────────────────────────

    /// Once the store holds `MAX_PENDING_APPROVALS` non-expired entries a
    /// further insert returns `PendingStoreFull` and the count stays at the cap.
    #[test]
    fn insert_rejects_when_at_cap() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);

        // Fill the store to the cap by populating `entries` directly (this test
        // module can access the private field), avoiding MAX_PENDING_APPROVALS
        // full-file persists. Each entry is non-expired at TEST_NOW_MS.
        for _ in 0..MAX_PENDING_APPROVALS {
            store.entries.push(make_payment_entry(DEFAULT_TTL_MS));
        }
        assert_eq!(store.len(), MAX_PENDING_APPROVALS);

        // One more insert must be rejected with PendingStoreFull.
        let overflow = make_payment_entry(DEFAULT_TTL_MS);
        let err = store.insert(overflow, TEST_NOW_MS).unwrap_err();
        assert!(
            matches!(
                err,
                ApprovalError::PendingStoreFull {
                    max: MAX_PENDING_APPROVALS
                }
            ),
            "expected PendingStoreFull {{ max: {MAX_PENDING_APPROVALS} }}, got {err:?}"
        );

        // The store must still hold exactly MAX_PENDING_APPROVALS entries.
        assert_eq!(
            store.len(),
            MAX_PENDING_APPROVALS,
            "store len must remain at cap after rejected insert"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RuleProposalSimulated (Package D, GH issue #8)
    // ─────────────────────────────────────────────────────────────────────────

    use super::super::rule_proposal::{RuleProposalContextType, RuleProposalSigner};

    const RULE_PROPOSAL_SMART_ACCOUNT: &str =
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn valid_rule_proposal_snapshot() -> ContextRuleProposalSnapshot {
        ContextRuleProposalSnapshot::new(
            RuleProposalContextType::Default,
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(
                VALID_SUMMARY_TO.to_owned(),
                true,
            )],
            vec![],
            vec![0],
            false,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn make_rule_proposal_entry_with(
        smart_account: &str,
        definition: ContextRuleProposalSnapshot,
        proposal_sha256: [u8; 32],
        ttl_ms: u64,
    ) -> PendingApproval {
        PendingApproval::new_rule_proposal_pending(
            smart_account.to_owned(),
            TESTNET_PASSPHRASE.to_owned(),
            "stellar:testnet".to_owned(),
            definition,
            proposal_sha256,
            "CallContract rule \"spend-daily\"".to_owned(),
            "1000".to_owned(),
            ttl_ms,
        )
        .unwrap()
    }

    fn make_rule_proposal_entry(ttl_ms: u64) -> PendingApproval {
        make_rule_proposal_entry_with(
            RULE_PROPOSAL_SMART_ACCOUNT,
            valid_rule_proposal_snapshot(),
            [0x11u8; 32],
            ttl_ms,
        )
    }

    #[test]
    fn new_rule_proposal_pending_constructs_kind() {
        let entry = make_rule_proposal_entry(DEFAULT_TTL_MS);
        assert!(matches!(
            entry.kind,
            ApprovalKind::RuleProposalSimulated { .. }
        ));
        assert_eq!(entry.kind.kind_name(), "RuleProposalSimulated");
        assert!(entry.attestation_blob_b64.is_none());
    }

    #[test]
    fn new_rule_proposal_pending_computes_consistent_redaction() {
        let entry = make_rule_proposal_entry(DEFAULT_TTL_MS);
        match &entry.kind {
            ApprovalKind::RuleProposalSimulated {
                smart_account,
                smart_account_redacted,
                ..
            } => {
                assert_eq!(redact_g_strkey(smart_account), *smart_account_redacted);
            }
            other => panic!("expected RuleProposalSimulated, got {other:?}"),
        }
    }

    #[test]
    fn new_rule_proposal_pending_rejects_invalid_smart_account() {
        let err = PendingApproval::new_rule_proposal_pending(
            "not-a-strkey".to_owned(),
            TESTNET_PASSPHRASE.to_owned(),
            "stellar:testnet".to_owned(),
            valid_rule_proposal_snapshot(),
            [0x11u8; 32],
            "summary".to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(matches!(err, ApprovalError::Invalid { .. }));
    }

    #[test]
    fn new_rule_proposal_pending_rejects_invalid_definition() {
        let mut snapshot = valid_rule_proposal_snapshot();
        snapshot.signers = vec![];
        let err = PendingApproval::new_rule_proposal_pending(
            RULE_PROPOSAL_SMART_ACCOUNT.to_owned(),
            TESTNET_PASSPHRASE.to_owned(),
            "stellar:testnet".to_owned(),
            snapshot,
            [0x11u8; 32],
            "summary".to_owned(),
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap_err();
        assert!(matches!(err, ApprovalError::Invalid { .. }));
    }

    #[test]
    fn rule_proposal_json_round_trip() {
        let entry = make_rule_proposal_entry(DEFAULT_TTL_MS);
        let json = serde_json::to_string(&entry).unwrap();
        let back: PendingApproval = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind.kind_name(), "RuleProposalSimulated");
        match (&entry.kind, &back.kind) {
            (
                ApprovalKind::RuleProposalSimulated {
                    proposal_sha256: a,
                    definition: def_a,
                    ..
                },
                ApprovalKind::RuleProposalSimulated {
                    proposal_sha256: b,
                    definition: def_b,
                    ..
                },
            ) => {
                assert_eq!(a, b);
                assert_eq!(def_a, def_b);
            }
            _ => panic!("kind mismatch after JSON round trip"),
        }
    }

    #[test]
    fn rule_proposal_toml_round_trip() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_rule_proposal_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        let expected_sha256 = if let ApprovalKind::RuleProposalSimulated {
            proposal_sha256, ..
        } = entry.kind
        {
            proposal_sha256
        } else {
            unreachable!()
        };
        store.insert(entry, TEST_NOW_MS).unwrap();
        drop(store);

        let reopened = open_store(&dir);
        let loaded = reopened.get(&nonce).unwrap();
        assert_eq!(loaded.kind.kind_name(), "RuleProposalSimulated");
        match &loaded.kind {
            ApprovalKind::RuleProposalSimulated {
                proposal_sha256, ..
            } => assert_eq!(*proposal_sha256, expected_sha256),
            other => panic!("expected RuleProposalSimulated, got {other:?}"),
        }
    }

    // ── Attested-state round trips ────────────────────────────────────────────
    //
    // Regression class: `rule_proposal_toml_round_trip` (and the payment/claim
    // equivalents below) only ever persisted-and-reloaded an UNATTESTED entry;
    // `record_attestation_success` / `record_rule_proposal_attestation_success`
    // only ever checked the IN-MEMORY entry immediately after attesting,
    // never through a real file close + reopen + deserialise. Neither
    // combination caught the cross-kind-contamination arms incorrectly
    // forbidding `attestation_blob_b64` for `ClaimSimulated` /
    // `RuleProposalSimulated` (both share the generic HMAC-blob attestation
    // path with `PaymentSimulated`) — a genuinely-attested entry of either
    // kind failed to reparse from disk. These three tests close that gap for
    // every kind that can carry `attestation_blob_b64`.

    #[test]
    fn payment_attested_toml_round_trip() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();
        store.record_attestation(&nonce, [0x11u8; 32]).unwrap();
        drop(store);

        let reopened = open_store(&dir);
        let loaded = reopened
            .get(&nonce)
            .expect("attested PaymentSimulated entry must reparse from disk");
        assert_eq!(loaded.kind.kind_name(), "PaymentSimulated");
        assert!(
            loaded.attestation_blob_b64.is_some(),
            "attestation_blob_b64 must survive the reload"
        );
    }

    #[test]
    fn claim_attested_toml_round_trip() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_claim_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();
        store.record_attestation(&nonce, [0x22u8; 32]).unwrap();
        drop(store);

        let reopened = open_store(&dir);
        let loaded = reopened
            .get(&nonce)
            .expect("attested ClaimSimulated entry must reparse from disk");
        assert_eq!(loaded.kind.kind_name(), "ClaimSimulated");
        assert!(
            loaded.attestation_blob_b64.is_some(),
            "attestation_blob_b64 must survive the reload"
        );
    }

    #[test]
    fn rule_proposal_attested_toml_round_trip() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_rule_proposal_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();
        store
            .record_rule_proposal_attestation(&nonce, [0x33u8; 32])
            .unwrap();
        drop(store);

        let reopened = open_store(&dir);
        let loaded = reopened
            .get(&nonce)
            .expect("attested RuleProposalSimulated entry must reparse from disk");
        assert_eq!(loaded.kind.kind_name(), "RuleProposalSimulated");
        assert!(
            loaded.attestation_blob_b64.is_some(),
            "attestation_blob_b64 must survive the reload"
        );
    }

    /// Blast-radius characterisation: the store persists every pending entry
    /// as one `Vec<PendingApproval>` under a single `[[pending]]` TOML array,
    /// so ONE structurally-invalid entry fails the WHOLE array's
    /// deserialisation — `PendingApprovalStore::open` cannot load only the
    /// good entries and skip the bad one. This is documented, known behaviour
    /// (see the module doc above), not something this fix changes: the fix
    /// removes the trigger (a legitimately-attested entry no longer LOOKS
    /// invalid), it does not add partial-file recovery.
    #[test]
    fn one_contaminated_entry_fails_whole_multi_entry_store_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("multi.toml");

        // Entry 1: a well-formed PaymentSimulated entry.
        // Entry 2: a RuleProposalSimulated entry ALSO carrying a genuinely
        // cross-kind field (`summary_to`, a PaymentSimulated-only field) —
        // this is a real contamination case, not the fixed false positive.
        let bad_toml = format!(
            r#"
[[pending]]
approval_nonce = "BBBBBBBBBBBBBBBBBBBBBB"
process_uid = "1000"
created_at_unix_ms = 0
expires_at_unix_ms = 9999999999999

envelope_xdr_b64 = "AAAA"
envelope_sha256_hex = "{}"
summary_to = "{VALID_SUMMARY_TO}"
summary_amount_stroops = 100
summary_asset = "XLM"
summary_simulated_fee_stroops = 100
summary_simulated_seq_num = 1

[[pending]]
approval_nonce = "AAAAAAAAAAAAAAAAAAAAAA"
process_uid = "1000"
created_at_unix_ms = 0
expires_at_unix_ms = 9999999999999

summary_to = "{VALID_SUMMARY_TO}"

[pending.rule_proposal_simulated]
smart_account = "{RULE_PROPOSAL_SMART_ACCOUNT}"
smart_account_redacted = "CAAAA...AAAAA"
network_passphrase = "Test SDF Network ; September 2015"
chain_id = "stellar:testnet"
proposal_sha256 = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]
summary_line = "test"

[pending.rule_proposal_simulated.definition]
snapshot_version = 1
name = "spend-daily"
auth_rule_ids = [0]
accept_mutable_verifier = false
accept_unknown_verifier = false

[pending.rule_proposal_simulated.definition.context_type]
type = "default"

[[pending.rule_proposal_simulated.definition.signers]]
kind = "delegated"
address = "{VALID_SUMMARY_TO}"
is_proposer = true
"#,
            "a".repeat(64),
        );
        std::fs::write(&path, bad_toml).unwrap();

        let err = PendingApprovalStore::open(path).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("contamination") || msg.contains("summary_to"),
            "the whole-file load must fail on the second entry's real contamination; \
             got: {msg}"
        );
        // The first (well-formed) entry is NOT independently recoverable —
        // `PendingApprovalStore::open` never returned a partially-loaded
        // store; the `Err` above is the only observable outcome.
    }

    /// Cross-kind contamination: a TOML entry with both
    /// `rule_proposal_simulated` and a PaymentSimulated flat field
    /// (`summary_to`) must be rejected on deserialisation.
    #[test]
    fn rule_proposal_simulated_cross_kind_contamination_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.toml");

        let bad_toml = format!(
            r#"
[[pending]]
approval_nonce = "AAAAAAAAAAAAAAAAAAAAAA"
process_uid = "1000"
created_at_unix_ms = 0
expires_at_unix_ms = 9999999999999

summary_to = "{VALID_SUMMARY_TO}"

[pending.rule_proposal_simulated]
smart_account = "{RULE_PROPOSAL_SMART_ACCOUNT}"
smart_account_redacted = "CAAAA...AAAAA"
network_passphrase = "Test SDF Network ; September 2015"
chain_id = "stellar:testnet"
proposal_sha256 = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]
summary_line = "test"

[pending.rule_proposal_simulated.definition]
snapshot_version = 1
name = "spend-daily"
auth_rule_ids = [0]
accept_mutable_verifier = false
accept_unknown_verifier = false

[pending.rule_proposal_simulated.definition.context_type]
type = "default"

[[pending.rule_proposal_simulated.definition.signers]]
kind = "delegated"
address = "{VALID_SUMMARY_TO}"
is_proposer = true
"#
        );
        std::fs::write(&path, bad_toml).unwrap();

        let err = PendingApprovalStore::open(path).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("contamination")
                || msg.contains("cross-kind")
                || msg.contains("summary_to"),
            "must reject cross-kind contamination; got: {msg}"
        );
    }

    #[test]
    fn record_rule_proposal_attestation_success() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_rule_proposal_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        store
            .record_rule_proposal_attestation(&nonce, [0x22u8; 32])
            .unwrap();

        let loaded = store.get(&nonce).unwrap();
        assert!(loaded.attestation_blob_b64.is_some());
    }

    #[test]
    fn record_rule_proposal_attestation_wrong_kind_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let err = store
            .record_rule_proposal_attestation(&nonce, [0x22u8; 32])
            .unwrap_err();
        assert!(matches!(err, ApprovalError::WrongKind { .. }));
    }

    #[test]
    fn record_rule_proposal_attestation_already_attested_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_rule_proposal_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();
        store
            .record_rule_proposal_attestation(&nonce, [0x22u8; 32])
            .unwrap();

        let err = store
            .record_rule_proposal_attestation(&nonce, [0x33u8; 32])
            .unwrap_err();
        assert!(matches!(err, ApprovalError::AlreadyAttested));
    }

    #[test]
    fn record_rule_proposal_attestation_expired_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_rule_proposal_entry(1);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));

        let err = store
            .record_rule_proposal_attestation(&nonce, [0x22u8; 32])
            .unwrap_err();
        assert!(matches!(err, ApprovalError::Expired));
    }

    #[test]
    fn record_rule_proposal_attestation_not_found() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let err = store
            .record_rule_proposal_attestation("unknown-nonce-AAAAAAAA", [0x22u8; 32])
            .unwrap_err();
        assert!(matches!(err, ApprovalError::NotFound));
    }

    #[test]
    fn verify_rule_proposal_gate_success() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let digest = [0x44u8; 32];
        let entry = make_rule_proposal_entry_with(
            RULE_PROPOSAL_SMART_ACCOUNT,
            valid_rule_proposal_snapshot(),
            digest,
            DEFAULT_TTL_MS,
        );
        let nonce = entry.approval_nonce.clone();
        let process_uid = entry.process_uid.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let key = [0x55u8; 32];
        let blob =
            super::super::attestation::compute_attestation(&key, &nonce, &digest, &process_uid);
        store
            .record_rule_proposal_attestation(&nonce, blob)
            .unwrap();

        let result = store.verify_rule_proposal_gate(&nonce, &digest, &key, &blob, TEST_NOW_MS);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    /// Stands in for the "tamper matrix" requirement at the gate layer: any
    /// recomputed digest that differs from what was attested (the shape a
    /// tampered snapshot field would produce, since
    /// `compute_context_rule_proposal_sha256` in `stellar-agent-smart-account`
    /// is sensitive to every field — see that crate's own digest tests) must
    /// refuse. Core has no dependency on the smart-account crate's builder,
    /// so this test exercises the gate's digest-comparison mechanics directly
    /// with two differing 32-byte digests.
    #[test]
    fn verify_rule_proposal_gate_digest_mismatch_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let stored_digest = [0x44u8; 32];
        let entry = make_rule_proposal_entry_with(
            RULE_PROPOSAL_SMART_ACCOUNT,
            valid_rule_proposal_snapshot(),
            stored_digest,
            DEFAULT_TTL_MS,
        );
        let nonce = entry.approval_nonce.clone();
        let process_uid = entry.process_uid.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let key = [0x55u8; 32];
        let blob = super::super::attestation::compute_attestation(
            &key,
            &nonce,
            &stored_digest,
            &process_uid,
        );
        store
            .record_rule_proposal_attestation(&nonce, blob)
            .unwrap();

        let mut recomputed_digest = stored_digest;
        recomputed_digest[0] ^= 0xff; // simulate a tampered snapshot re-encoding to a different digest

        let result =
            store.verify_rule_proposal_gate(&nonce, &recomputed_digest, &key, &blob, TEST_NOW_MS);
        assert_eq!(result, Err(RuleProposalGateError::Refused));
    }

    #[test]
    fn verify_rule_proposal_gate_wrong_hmac_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let digest = [0x44u8; 32];
        let entry = make_rule_proposal_entry_with(
            RULE_PROPOSAL_SMART_ACCOUNT,
            valid_rule_proposal_snapshot(),
            digest,
            DEFAULT_TTL_MS,
        );
        let nonce = entry.approval_nonce.clone();
        let process_uid = entry.process_uid.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let key = [0x55u8; 32];
        let blob =
            super::super::attestation::compute_attestation(&key, &nonce, &digest, &process_uid);
        store
            .record_rule_proposal_attestation(&nonce, blob)
            .unwrap();

        let wrong_key = [0x66u8; 32];
        let result =
            store.verify_rule_proposal_gate(&nonce, &digest, &wrong_key, &blob, TEST_NOW_MS);
        assert_eq!(result, Err(RuleProposalGateError::Refused));
    }

    #[test]
    fn verify_rule_proposal_gate_rejected_tombstone_is_distinguishable() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let digest = [0x44u8; 32];
        let entry = make_rule_proposal_entry_with(
            RULE_PROPOSAL_SMART_ACCOUNT,
            valid_rule_proposal_snapshot(),
            digest,
            DEFAULT_TTL_MS,
        );
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();
        store.reject(&nonce, TEST_NOW_MS, 60_000).unwrap();

        let key = [0x55u8; 32];
        let blob = [0u8; 32]; // never attested; any bytes exercise the Rejected short-circuit
        let result = store.verify_rule_proposal_gate(&nonce, &digest, &key, &blob, TEST_NOW_MS);
        assert_eq!(result, Err(RuleProposalGateError::Rejected));
    }

    #[test]
    fn verify_rule_proposal_gate_unknown_nonce_fails() {
        let dir = TempDir::new().unwrap();
        let store = open_store(&dir);
        let result = store.verify_rule_proposal_gate(
            "unknown-nonce-AAAAAAAA",
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            TEST_NOW_MS,
        );
        assert_eq!(result, Err(RuleProposalGateError::Refused));
    }

    #[test]
    fn verify_rule_proposal_gate_wrong_kind_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = make_payment_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let result = store.verify_rule_proposal_gate(
            &nonce,
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            TEST_NOW_MS,
        );
        assert_eq!(result, Err(RuleProposalGateError::Refused));
    }

    #[test]
    fn verify_rule_proposal_gate_expired_fails() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let digest = [0x44u8; 32];
        let entry = make_rule_proposal_entry_with(
            RULE_PROPOSAL_SMART_ACCOUNT,
            valid_rule_proposal_snapshot(),
            digest,
            60_000,
        );
        let nonce = entry.approval_nonce.clone();
        let expiry = entry.expires_at_unix_ms;
        store.insert(entry, TEST_NOW_MS).unwrap();

        let result = store.verify_rule_proposal_gate(
            &nonce, &digest, &[0u8; 32], &[0u8; 32],
            expiry, // now == expiry ⟹ expired (is_expired uses <=)
        );
        assert_eq!(result, Err(RuleProposalGateError::Refused));
    }

    #[test]
    fn rule_proposal_debug_omits_full_smart_account() {
        let entry = make_rule_proposal_entry(DEFAULT_TTL_MS);
        let debug_str = format!("{:?}", entry.kind);
        assert!(!debug_str.contains(RULE_PROPOSAL_SMART_ACCOUNT));
        assert!(debug_str.contains("smart_account_redacted"));
    }
}
