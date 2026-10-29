//! Shared attest path for a pending approval.
//!
//! The `stellar-agent approve --id <nonce> --profile <name>` CLI command and
//! server-driven approval surfaces share this canonical path.
//! [`load_and_validate_entry`] checks the nonce, expiry, attestation state, and
//! process UID. [`attest_and_persist`] dispatches each kind to its HMAC and
//! persistence path. The CLI crate owns the tty prompt, exit-code mapping,
//! and JSON rendering.
//!
//! # Layering note: the `ToolsetFirstInvokeGate` grant step
//!
//! `stellar-agent-toolsets-runtime` (which owns `record_first_invoke_grant`,
//! the durable-grant persistence path) depends on `stellar-agent-core`, not
//! the reverse — core calling into it directly would be an illegal dependency
//! cycle. [`attest_and_persist`] therefore takes the grant-persistence step as
//! an injected closure (`persist_toolset_grant`). Core owns the validation,
//! the per-kind dispatch, the sequencing (write the consent row, persist the
//! grant, then consume the pending entry), and the audit emission. Only the
//! literal `record_first_invoke_grant` call is supplied by the caller, which
//! already depends on `stellar-agent-toolsets-runtime`.
//!
//! # Consent row before the approval
//!
//! [`attest_and_persist`] writes the consent row through a required
//! [`ConsentAudit`] sink before it persists anything. A sink that refuses
//! refuses the approval with nothing persisted.
//!
//! # Mainnet consent
//!
//! A mainnet binding admits only [`ConsentAuthorization::Mainnet`]: a
//! [`VerifiedMainnetPresence`] and the current owner-signed policy. A
//! [`ConsentAuthorization::Standard`] approver refuses with
//! `approval.presence_required` before the key is read, a row is written or
//! anything is persisted, in every build. The mainnet path rechecks the
//! locked entry against the challenged snapshot, reloads the current policy,
//! verifies the receipt again, checks both challenge deadlines immediately
//! before the row, and records a version 5 attestation with its receipt.
//! After the row is durable, the keyring anchor advance and store record can
//! wait on the keyring, and every consumer rechecks the entry's expiry and
//! the current policy at consumption.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keyring_core::Entry as KeyringEntry;
use zeroize::Zeroizing;

use crate::audit_log::entry::AuditEntry;
use crate::audit_log::outbox::{AuditOutbox, PreparedOutboxAppend};
use crate::audit_log::writer::{
    AuditWriter, PreparedAuditEntry, WriterError, audit_writer_refusal,
};
use crate::error::{ApprovalFailure, WalletError};
use crate::keyring_errors::{KeyringOperation, map_keyring_operation_error};
use crate::profile::schema::KeyringEntryRef;
use crate::timefmt;

use crate::envelope_decode::{ClassicSummary, ClassicTransactionKind, classic_summary};

use super::attestation::{
    AttestedApprover, compute_attestation_v4, compute_attestation_v5,
    compute_trustline_clawback_opt_in_digest,
};
use super::error::ApprovalError;
use super::presence::{MAINNET_CHAIN_ID, VerifiedMainnetPresence};
use super::store::{ApprovalKind, PendingApproval, PendingApprovalStore};
use super::subject::approval_subject_classic;
use super::user_id::ApproverIdentity;
use crate::mainnet::verified_policy::VerifiedPolicy;

// ─────────────────────────────────────────────────────────────────────────────
// Surface
// ─────────────────────────────────────────────────────────────────────────────

/// Which UI surface drove an attest or reject action.
///
/// Carried into the `ApprovalAttested` / `ApprovalRejected` audit events so
/// the forensic record distinguishes the interactive CLI path from a
/// server-driven approve surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Surface {
    /// Interactive typed-profile mainnet confirmation.
    CliMainnetConfirm,
    /// The `stellar-agent approve --id <nonce> --profile <name>` CLI command.
    Cli,
    /// A resident, server-driven approve surface bound to loopback.
    Serve,
    /// A resident, server-driven approve surface reachable from beyond
    /// loopback, authenticated by a passkey-authenticated
    /// [`super::user_id::ApproverIdentity::PasskeyCredential`] identity
    /// rather than the OS process boundary.
    ServeRemote,
}

impl Surface {
    /// Returns the wire string for this surface (`"cli"`, `"serve"`, or
    /// `"serve-remote"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::CliMainnetConfirm => "cli-mainnet-confirm",
            Self::Serve => "serve",
            Self::ServeRemote => "serve-remote",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolsetGrantRequest — injected-closure parameters for the grant step
// ─────────────────────────────────────────────────────────────────────────────

/// Parameters for the caller-supplied `persist_toolset_grant` closure passed
/// to [`attest_and_persist`].
///
/// The caller forwards all fields, including `binding`, `process_uid`,
/// `now_unix_ms`, and the attestation key into
/// `stellar_agent_toolsets_runtime::record_first_invoke_grant`.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ToolsetGrantRequest<'a> {
    /// Profile and chain binding forwarded to the grant attester.
    pub binding: &'a super::AttestationBinding<'a>,
    /// Name of the toolset requesting signing-adjacent capability access.
    pub toolset_name: &'a str,
    /// The signing-adjacent capability token being requested.
    pub capability: &'a str,
    /// Canonical G-strkey destination address from the authoritative envelope.
    pub destination: &'a str,
    /// Full asset identifier (`"XLM"` or `"<code>:<G-strkey>"`).
    pub asset: &'a str,
    /// Minimum amount bound in stroops for this grant bucket.
    pub amount_min_stroops: i64,
    /// Maximum amount bound in stroops for this grant bucket.
    pub amount_max_stroops: i64,
    /// Platform-stable user identity bound into the grant.
    pub process_uid: &'a str,
    /// Current time, read once by [`attest_and_persist`] so the grant and any
    /// subsequent store mutation share a single clock read.
    pub now_unix_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// load_and_validate_entry
// ─────────────────────────────────────────────────────────────────────────────

/// Loads the pending approval entry for `nonce`, validating expiry,
/// already-attested state, and the caller's identity binding.
///
/// `identity` is an [`ApproverIdentity`] rather than a raw `process_uid: &str`
/// so a remote-approval mode can bind a different identity kind without
/// changing this signature. For [`ApproverIdentity::OsUid`],
/// [`ApproverIdentity::is_authorized_for_entry`] compares against the stored
/// entry's `process_uid` exactly as the pre-abstraction `process_uid: &str`
/// parameter was — byte-identical wire behaviour, and `allowed_credentials`
/// is not consulted. For [`ApproverIdentity::PasskeyCredential`], the check
/// instead requires the identity's credential ID to be non-empty and present
/// in `allowed_credentials` — the profile's operator-approval allowlist —
/// AND the identity's verified-assertion witness to be bound to this exact
/// entry's nonce, regardless of the entry's stored `process_uid`. The
/// nonce-binding check is what prevents a witness verified for one pending
/// entry's per-action challenge from ever authorizing a different entry.
/// Passing an empty `allowed_credentials` slice is the correct call for any
/// surface that only ever constructs `OsUid` identities (the CLI and the
/// loopback serve surface today): the slice is simply never read on that
/// path.
///
/// # Errors
///
/// Returns [`WalletError::Approval`] when: the nonce is unknown
/// (`approval.not_found`); the entry has expired (`approval.expired`); the
/// entry is already attested (`approval.already_attested`); or the
/// caller's identity is not authorized against the entry
/// (`approval.user_mismatch`).
pub fn load_and_validate_entry(
    store: &PendingApprovalStore,
    nonce: &str,
    identity: &ApproverIdentity,
    allowed_credentials: &[String],
) -> Result<PendingApproval, WalletError> {
    let entry = store.get(nonce).cloned().ok_or_else(|| {
        // This operator-run path names a missing entry.
        // The MCP commit path reports missing and expired approvals as
        // `policy.approval_required`.
        WalletError::Approval(ApprovalFailure::NotFound {
            detail: "no pending approval with that nonce".to_owned(),
        })
    })?;

    let now_ms = timefmt::now_unix_ms().map_err(|e| map_clock_error(&e))?;
    if entry.is_expired(now_ms) {
        return Err(WalletError::Approval(ApprovalFailure::Expired {
            detail: "this pending approval has expired".to_owned(),
        }));
    }

    if entry.attestation_blob_b64.is_some() {
        return Err(WalletError::Approval(ApprovalFailure::AlreadyAttested {
            detail: "this pending approval has already been attested".to_owned(),
        }));
    }

    if !identity.is_authorized_for_entry(
        &entry.process_uid,
        &entry.approval_nonce,
        allowed_credentials,
    ) {
        return Err(WalletError::Approval(ApprovalFailure::UserMismatch {
            detail: "this pending approval was created by a different \
                     local user (process_uid mismatch), or the presented passkey credential is \
                     not authorized for this profile; this caller cannot attest it"
                .to_owned(),
        }));
    }

    Ok(entry)
}

fn map_clock_error(err: &crate::wallet::WalletLifecycleError) -> WalletError {
    WalletError::Approval(ApprovalFailure::ClockError {
        detail: format!("system clock error: {err}"),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// decode_sha256_hex
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes a lowercase-hex SHA-256 string into a `[u8; 32]`.
///
/// # Errors
///
/// Returns `approval.sha256_hex_error` if `hex` is not exactly 64 characters
/// or contains non-hex-digit bytes.
pub fn decode_sha256_hex(hex: &str) -> Result<[u8; 32], WalletError> {
    if hex.len() != 64 {
        return Err(WalletError::Approval(ApprovalFailure::Sha256HexError {
            detail: format!("expected 64 hex chars, got {}", hex.len()),
        }));
    }

    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk).map_err(|_| {
            WalletError::Approval(ApprovalFailure::Sha256HexError {
                detail: "non-UTF8 in hex string".to_owned(),
            })
        })?;
        out[i] = u8::from_str_radix(byte_str, 16).map_err(|_| {
            WalletError::Approval(ApprovalFailure::Sha256HexError {
                detail: format!("invalid hex byte '{byte_str}'"),
            })
        })?;
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// classic_entry_summary
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes the transaction a classic pending approval holds, after checking
/// that its stored digest is the SHA-256 of its stored envelope.
///
/// Returns `None` for a kind that holds no classic envelope. For a
/// `PaymentSimulated`, `TrustlineSimulated` or `ClaimSimulated` entry the
/// attestation binds only the stored digest, so the envelope that digest
/// names is the one transaction an approval surface may show and the
/// attestation may approve. Every approval surface renders the returned
/// [`ClassicSummary`] rather than the entry's stored `summary_*` fields, and
/// [`attest_and_persist`] refuses an entry for which this returns an error.
///
/// # Errors
///
/// `approval.entry_inconsistent` when the stored digest is not the digest of
/// the stored envelope, or the envelope does not decode as the entry's kind
/// (see [`classic_summary`]).
#[must_use]
pub fn classic_entry_summary(kind: &ApprovalKind) -> Option<Result<ClassicSummary, WalletError>> {
    let (envelope_xdr_b64, envelope_sha256_hex, classic_kind) = match kind {
        ApprovalKind::PaymentSimulated {
            envelope_xdr_b64,
            envelope_sha256_hex,
            ..
        } => (
            envelope_xdr_b64,
            envelope_sha256_hex,
            ClassicTransactionKind::Payment,
        ),
        ApprovalKind::TrustlineSimulated {
            envelope_xdr_b64,
            envelope_sha256_hex,
            ..
        } => (
            envelope_xdr_b64,
            envelope_sha256_hex,
            ClassicTransactionKind::Trustline,
        ),
        ApprovalKind::ClaimSimulated {
            envelope_xdr_b64,
            envelope_sha256_hex,
            ..
        } => (
            envelope_xdr_b64,
            envelope_sha256_hex,
            ClassicTransactionKind::Claim,
        ),
        _ => return None,
    };
    let digest_matches = decode_sha256_hex(envelope_sha256_hex)
        .is_ok_and(|stored| stored == approval_subject_classic(envelope_xdr_b64));
    if !digest_matches {
        return Some(Err(entry_inconsistent(
            "the stored digest is not the digest of the stored envelope",
        )));
    }
    Some(
        classic_summary(envelope_xdr_b64, classic_kind).map_err(|error| {
            entry_inconsistent(&format!("the stored envelope does not decode: {error}"))
        }),
    )
}

fn entry_inconsistent(reason: &str) -> WalletError {
    WalletError::Approval(ApprovalFailure::EntryInconsistent {
        detail: format!("this pending approval cannot be approved: {reason}"),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// load_attestation_key
// ─────────────────────────────────────────────────────────────────────────────

/// Loads the attestation HMAC key from the platform keyring.
///
/// The platform keyring store must already be initialised (via
/// `stellar_agent_network::keyring::init_platform_keyring_store` or
/// equivalent) before calling this function — that bootstrap step stays with
/// the caller, since it is a process-wide, one-time registration rather than
/// part of the per-approval attest path.
///
/// A coordinate in the owner key namespace is refused before any keyring read,
/// and a loaded key equal to the owner public key at a coordinate of `owner`
/// is refused after decoding. Both refusals are
/// [`crate::error::ValidationError::KeyMatchesOwnerPublicKey`] for
/// `attestation_key_id`.
///
/// # Errors
///
/// Returns a [`WalletError`] when the keyring entry is missing or contains
/// invalid base64/wrong-length data, when the key is or may be the owner
/// public key, or when an owner entry cannot be read.
pub fn load_attestation_key(
    entry_ref: &KeyringEntryRef,
    owner: &crate::profile::owner_key::OwnerKeyContext,
) -> Result<Zeroizing<Vec<u8>>, WalletError> {
    crate::profile::owner_key::refuse_owner_key_coordinate(entry_ref, ATTESTATION_KEY_FIELD)?;
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        tracing::debug!(
            service = %entry_ref.service,
            "keyring Entry::new failed for attestation key"
        );
        map_keyring_operation_error(&e, KeyringOperation::Construct, &entry_ref.service)
    })?;

    let secret_b64 = Zeroizing::new(entry.get_password().map_err(|e| {
        tracing::debug!(
            service = %entry_ref.service,
            "get_password failed for attestation key"
        );
        map_keyring_operation_error(&e, KeyringOperation::Read, &entry_ref.service)
    })?);

    let key_bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(secret_b64.as_bytes()).map_err(|e| {
        tracing::debug!(error = %e, "attestation key base64 decode failed");
        WalletError::Approval(ApprovalFailure::KeyDecodeFailed {
            detail: "attestation key is not valid base64".to_owned(),
        })
    })?);

    if key_bytes.len() != 32 {
        return Err(WalletError::Approval(ApprovalFailure::KeyLengthError {
            detail: format!("attestation key must be 32 bytes, got {}", key_bytes.len()),
        }));
    }

    crate::profile::owner_key::refuse_owner_public_key(&key_bytes, owner, ATTESTATION_KEY_FIELD)?;
    Ok(key_bytes)
}

/// The profile field an attestation-key refusal names.
pub const ATTESTATION_KEY_FIELD: &str = "attestation_key_id";

// ─────────────────────────────────────────────────────────────────────────────
// ConsentAudit
// ─────────────────────────────────────────────────────────────────────────────

/// Where [`attest_and_persist`] writes the consent row.
///
/// The row is durable in the log or in the log's outbox before the approval
/// takes effect, and a sink that refuses refuses the approval.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConsentAudit<'a> {
    /// Append the row through the audit writer this process holds. A
    /// draining writer drains the outbox before the row.
    Writer(&'a mut AuditWriter),
    /// Queue the row in the audit outbox, for the draining writer in another
    /// process that holds the log. That writer appends it before any process
    /// loads a signing key for the approved action.
    Outbox(&'a AuditOutbox),
}

impl ConsentAudit<'_> {
    fn prepare(&mut self) -> Result<PreparedConsentAudit<'_>, WriterError> {
        match self {
            Self::Writer(writer) => writer.prepare_entry().map(PreparedConsentAudit::Writer),
            Self::Outbox(outbox) => outbox.prepare_append().map(PreparedConsentAudit::Outbox),
        }
    }

    fn write(&mut self, entry: AuditEntry) -> Result<(), WriterError> {
        match self {
            Self::Writer(writer) => writer.write_entry(entry),
            Self::Outbox(outbox) => outbox.append(&entry),
        }
    }
}

/// A consent sink with its pre-row waits complete.
enum PreparedConsentAudit<'a> {
    Writer(PreparedAuditEntry<'a>),
    Outbox(PreparedOutboxAppend<'a>),
}

impl PreparedConsentAudit<'_> {
    fn write(self, entry: AuditEntry) -> Result<(), WriterError> {
        match self {
            Self::Writer(writer) => writer.write(entry),
            Self::Outbox(outbox) => outbox.append(&entry),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConsentAuthorization
// ─────────────────────────────────────────────────────────────────────────────

/// What authorizes a consent.
///
/// Not `Clone`: a [`Self::Mainnet`] value carries a verified presence that
/// one attestation consumes.
#[derive(Debug)]
#[non_exhaustive]
#[allow(
    clippy::large_enum_variant,
    reason = "one value is built per consent and moved straight into the attester"
)]
pub enum ConsentAuthorization<'a> {
    /// The approver the approving surface verified, for a testnet binding.
    /// A mainnet binding refuses it with `approval.presence_required`.
    Standard(&'a AttestedApprover),
    /// A verified WebAuthn presence and the current owner-signed policy the
    /// caller loaded after its waits, for a mainnet binding.
    Mainnet {
        /// The verified ceremony, consumed by the attestation.
        presence: VerifiedMainnetPresence,
        /// The current verified policy.
        policy: &'a VerifiedPolicy,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// attest_and_persist
// ─────────────────────────────────────────────────────────────────────────────

/// Computes and persists the operator's attestation (or recorded consent) for
/// a pending approval, dispatching on [`ApprovalKind`].
///
/// Returns `Some(base64url_blob)` for `PaymentSimulated`, `ClaimSimulated`, `TrustlineSimulated`,
/// `RuleProposalSimulated`, and `MppChargeSimulated`: the attestation the agent
/// surface presents as `approval_attestation` to the matching `*_commit` tool,
/// or that the MPP gate reads from the store. Returns `None` for
/// `ToolsetFirstInvokeGate` and `TrustlineClawbackOptIn`, whose gates read the
/// recorded consent from the store directly and take no attestation argument.
///
/// Every arm runs in the same order:
///
/// 1. Re-read the entry from the locked `store` and refuse unless it is the
///    same pending entry the caller validated, with the code the store would
///    give for the same condition. One clock read serves this check and the
///    store's own expiry check.
/// 2. Write the consent row through `audit`: `ApprovalAttested` for a
///    [`AttestedApprover::Local`] approver, or `ApprovalAttestedRemote` with
///    the operator's redacted credential pseudonym for a
///    [`AttestedApprover::Remote`] one. The row is fatal: when the sink
///    refuses, nothing is persisted and the sink's error is returned.
/// 3. Persist the attestation, the grant, or the consent. A pending-record
///    attestation is the version 4 HMAC over the record and `approver`,
///    stored together with `approver` in one replacement. A persist failure
///    after the row returns that failure, and the row then records a consent
///    that did not take effect.
///
/// `authorization` is what the approving surface verified, never a value
/// read from request input. For [`ConsentAuthorization::Standard`],
/// [`Surface::ServeRemote`] requires a [`AttestedApprover::Remote`] approver
/// and every other surface requires [`AttestedApprover::Local`]; any other
/// pairing refuses with `approval.user_mismatch` before anything is written.
/// A mainnet binding refuses `Standard` with `approval.presence_required`
/// before anything else. [`ConsentAuthorization::Mainnet`] is admitted on a
/// mainnet binding only, from every surface but [`Surface::ServeRemote`],
/// for a payment, claim, trustline, x402 payment or trustline clawback
/// opt-in; the module documentation describes its checks.
///
/// # Errors
///
/// Returns a [`WalletError`] in each of these cases:
///
/// - Approval: a key-length mismatch (`approval.key_length_error`), a hash-decode
///   failure (`approval.sha256_hex_error`), a binding mismatch
///   (`approval.binding_mismatch`), an unattestable `entry.kind`
///   (`approval.wrong_kind`), or a classic entry whose stored digest is not
///   the digest of its envelope or whose envelope does not decode
///   (`approval.entry_inconsistent`).
///   `ApprovalKind::Rejected` and `ApprovalKind::Consumed` are tombstones and
///   can never be attested.
/// - A surface and approver that do not belong together, or a remote
///   approver whose credential ID is malformed (`approval.user_mismatch`).
/// - An entry that changed since validation: `approval.not_found`,
///   `approval.expired`, `approval.already_attested`, `approval.rejected`,
///   `approval.consumed`, or `approval.wrong_kind`.
/// - A refused consent row, with the `audit.*` code of the refusal.
/// - A store or `persist_toolset_grant` failure after the row.
/// - On mainnet: `approval.presence_required` for a standard approver,
///   `approval.mainnet_remote_unsupported` from the remote surface,
///   `approval.presence_policy_unavailable` when the current policy cannot be
///   loaded or differs from the challenged one, `approval.presence_expired`
///   past a challenge deadline, and `approval.presence_invalid` for a receipt
///   that does not verify again. A mainnet authorization on another chain
///   refuses with `approval.binding_mismatch`.
#[allow(
    clippy::too_many_arguments,
    reason = "every attester passes the store, the entry, the key, the binding and the surface explicitly"
)]
#[allow(
    clippy::too_many_lines,
    reason = "one arm per attestable kind, each in the re-read, row, persist order"
)]
pub fn attest_and_persist(
    store: &mut PendingApprovalStore,
    entry: &PendingApproval,
    key_bytes: &[u8],
    binding: &super::AttestationBinding<'_>,
    surface: Surface,
    mut audit: ConsentAudit<'_>,
    authorization: ConsentAuthorization<'_>,
    persist_toolset_grant: impl FnOnce(&ToolsetGrantRequest<'_>, &[u8; 32]) -> Result<(), String>,
) -> Result<Option<String>, WalletError> {
    let approver = match authorization {
        ConsentAuthorization::Standard(_) if binding.chain_id == MAINNET_CHAIN_ID => {
            return Err(WalletError::Approval(ApprovalFailure::PresenceRequired));
        }
        ConsentAuthorization::Standard(approver) => approver,
        ConsentAuthorization::Mainnet { presence, policy } => {
            let gated_tool = mainnet_gated_tool(&entry.kind)?;
            return attest_mainnet_presence(
                store, entry, key_bytes, binding, surface, &mut audit, presence, policy, gated_tool,
            );
        }
    };
    let operator_credential_id_b64url = approver_matches_surface(surface, approver)?;
    let (key_arr, now_ms) = prepare_attestation(store, entry, key_bytes, binding)?;
    let profile = binding.profile_name;

    // `Some(blob)` is the attestation the agent surface must present to the
    // matching `*_commit` tool; `None` for approval kinds whose gate reads the
    // recorded consent from the store and takes no attestation argument.
    //
    // Every arm writes the consent row before it persists anything, so an
    // approval never takes effect without its row.
    let surfaced_attestation: Option<String> = match &entry.kind {
        ApprovalKind::X402Payment {
            intent_digest,
            root_invocation_xdr,
            home_domain,
            ..
        } => {
            if surface != Surface::Cli {
                return Err(WalletError::Approval(ApprovalFailure::WrongKind {
                    detail: "x402 payments require CLI approval".to_owned(),
                }));
            }
            let chain: crate::profile::caip2::Caip2 = binding.chain_id.parse().map_err(|_| {
                WalletError::Approval(ApprovalFailure::BindingMismatch {
                    detail: "approval chain is invalid".to_owned(),
                })
            })?;
            let subject = super::subject::verified_x402_subject(
                intent_digest,
                root_invocation_xdr,
                home_domain.as_deref(),
                chain.network_passphrase(),
            )?;
            attest_envelope_and_persist(
                store,
                entry,
                key_arr,
                binding,
                &mut audit,
                surface,
                approver,
                now_ms,
                &crate::hex::encode(&subject),
                "X402Payment",
                "stellar_x402_create_payment",
            )?
        }

        ApprovalKind::PaymentSimulated {
            envelope_sha256_hex,
            ..
        } => attest_envelope_and_persist(
            store,
            entry,
            key_arr,
            binding,
            &mut audit,
            surface,
            approver,
            now_ms,
            envelope_sha256_hex,
            "PaymentSimulated",
            "stellar_pay_commit",
        )?,
        ApprovalKind::TrustlineSimulated {
            envelope_sha256_hex,
            ..
        } => attest_envelope_and_persist(
            store,
            entry,
            key_arr,
            binding,
            &mut audit,
            surface,
            approver,
            now_ms,
            envelope_sha256_hex,
            "TrustlineSimulated",
            "stellar_trustline_commit",
        )?,
        ApprovalKind::ClaimSimulated {
            envelope_sha256_hex,
            ..
        } => attest_envelope_and_persist(
            store,
            entry,
            key_arr,
            binding,
            &mut audit,
            surface,
            approver,
            now_ms,
            envelope_sha256_hex,
            "ClaimSimulated",
            "stellar_claim_commit",
        )?,
        ApprovalKind::ToolsetFirstInvokeGate {
            toolset_name,
            capability,
            destination,
            asset,
            amount_min_stroops,
            amount_max_stroops,
        } => {
            // A `ToolsetFirstInvokeGate` entry MUST NOT use `record_attestation_on_store`
            // (which calls `store.record_attestation` and returns `WrongKind`
            // for this variant) and MUST NOT set
            // `attestation_blob_b64` on the entry (the ToolsetFirstInvokeGate
            // deserialiser rejects it as cross-kind contamination on the next
            // store reload).
            //
            // Correct flow for ToolsetFirstInvokeGate approval:
            //   1. Write the consent row.
            //   2. Build and persist the ToolsetGrant via the caller-injected
            //      `persist_toolset_grant` closure (see module docs for why this
            //      step cannot be a direct core-internal call).
            //   3. CONSUME (remove) the pending entry so it cannot be re-used.
            let request = ToolsetGrantRequest {
                binding,
                toolset_name,
                capability,
                destination,
                asset,
                amount_min_stroops: *amount_min_stroops,
                amount_max_stroops: *amount_max_stroops,
                process_uid: &entry.process_uid,
                now_unix_ms: now_ms,
            };
            emit_attested_audit(
                &mut audit,
                profile,
                "ToolsetFirstInvokeGate",
                &format!("toolset:{toolset_name}:{capability}"),
                None,
                &entry.approval_nonce,
                surface,
                operator_credential_id_b64url,
            )?;
            persist_toolset_grant(&request, key_arr)
                .map_err(|e| WalletError::Approval(ApprovalFailure::GrantPersist { detail: e }))?;

            // Step 3: CONSUME the pending entry so it cannot be replayed.
            // A failure to remove is best-effort (the grant is already persisted).
            // Log a warning; the entry will expire via gc regardless.
            if let Err(e) = store.remove(&entry.approval_nonce) {
                tracing::warn!(
                    nonce = %entry.approval_nonce,
                    error = %e,
                    "ToolsetFirstInvokeGate: pending entry remove failed after grant persist; \
                     entry will expire via gc"
                );
            }

            tracing::debug!(
                toolset = %toolset_name,
                capability = %capability,
                "ToolsetFirstInvokeGate: grant persisted; pending entry consumed"
            );

            // The first-invoke gate reads the persisted grant from the grant
            // store at re-invoke time; the agent presents no attestation here.
            None
        }
        ApprovalKind::TrustlineClawbackOptIn {
            network,
            code,
            issuer,
        } => {
            // The commitment is the domain-separated SHA-256 of the
            // (network, code, issuer) triple — same domain-tag discipline as
            // ToolsetFirstInvokeGate.  The HMAC blob is written to
            // `attestation_blob_b64` on the pending entry; the trustline gate
            // clears only when `verify_attested_trustline_clawback_opt_in`
            // recomputes the digest and verifies this blob against the keyring key.
            let digest = compute_trustline_clawback_opt_in_digest(network, code, issuer);
            let attestation_blob = compute_attestation_v4(
                key_arr,
                binding,
                &entry.approval_nonce,
                &digest,
                &entry.process_uid,
                &entry.attested_lifetime(),
                approver,
            );
            emit_attested_audit(
                &mut audit,
                profile,
                "TrustlineClawbackOptIn",
                "stellar_trustline_commit",
                None,
                &entry.approval_nonce,
                surface,
                operator_credential_id_b64url,
            )?;
            store
                .record_trustline_clawback_opt_in_attestation_at(
                    &entry.approval_nonce,
                    attestation_blob,
                    approver.clone(),
                    now_ms,
                )
                .map_err(|e| record_error(&e))?;

            // The trustline clawback opt-in gate recomputes the digest and
            // verifies the stored blob; the agent presents no attestation here.
            None
        }
        ApprovalKind::RuleProposalSimulated {
            proposal_sha256, ..
        } => {
            // RuleProposalSimulated shares the digest-HMAC attestation path
            // with PaymentSimulated/ClaimSimulated: the blob binds
            // `proposal_sha256`, the nonce, and the process UID, and is
            // surfaced to `stellar_rule_create_commit`.
            let attestation_blob = compute_attestation_v4(
                key_arr,
                binding,
                &entry.approval_nonce,
                proposal_sha256,
                &entry.process_uid,
                &entry.attested_lifetime(),
                approver,
            );
            let proposal_sha256_hex = proposal_sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            emit_attested_audit(
                &mut audit,
                profile,
                "RuleProposalSimulated",
                "stellar_rule_create_commit",
                Some(proposal_sha256_hex),
                &entry.approval_nonce,
                surface,
                operator_credential_id_b64url,
            )?;
            store
                .record_rule_proposal_attestation_at(
                    &entry.approval_nonce,
                    attestation_blob,
                    approver.clone(),
                    now_ms,
                )
                .map_err(|e| record_error(&e))?;
            Some(URL_SAFE_NO_PAD.encode(attestation_blob))
        }
        ApprovalKind::MppChargeSimulated {
            prepared_artifact_hash,
            authorization_fingerprint,
            ..
        } => {
            super::mpp::verify_mpp_entry_terms(&entry.kind)?;
            let attestation_blob = compute_attestation_v4(
                key_arr,
                binding,
                &entry.approval_nonce,
                &super::mpp::approval_subject(authorization_fingerprint, prepared_artifact_hash),
                &entry.process_uid,
                &entry.attested_lifetime(),
                approver,
            );
            emit_attested_audit(
                &mut audit,
                profile,
                "MppChargeSimulated",
                "stellar_mpp_charge_commit",
                Some(
                    prepared_artifact_hash
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                ),
                &entry.approval_nonce,
                surface,
                operator_credential_id_b64url,
            )?;
            record_attestation_on_store(
                store,
                &entry.approval_nonce,
                attestation_blob,
                approver,
                now_ms,
            )?;
            Some(URL_SAFE_NO_PAD.encode(attestation_blob))
        }
        ApprovalKind::Rejected { .. } => {
            return Err(rejected_error());
        }
        ApprovalKind::Consumed { .. } => {
            return Err(consumed_error());
        }
        other => {
            return Err(WalletError::Approval(ApprovalFailure::WrongKind {
                detail: format!(
                    "attest_and_persist does not support {}, \
                     expected PaymentSimulated, ClaimSimulated, TrustlineSimulated, MppChargeSimulated, \
                     ToolsetFirstInvokeGate, TrustlineClawbackOptIn, or RuleProposalSimulated",
                    other.kind_name()
                ),
            }));
        }
    };

    Ok(surfaced_attestation)
}

fn rejected_error() -> WalletError {
    WalletError::Approval(ApprovalFailure::Rejected {
        detail: "this pending approval was rejected by the operator \
                 and cannot be attested"
            .to_owned(),
    })
}

fn consumed_error() -> WalletError {
    WalletError::Approval(ApprovalFailure::Consumed {
        detail: "this pending approval was already spent on a \
                 submission and cannot be attested"
            .to_owned(),
    })
}

/// Checks that `approver` is the approver `surface` verifies and returns the
/// credential ID the consent row attributes the approval to.
///
/// The remote listener is the only surface that authenticates an operator
/// credential, so [`Surface::ServeRemote`] requires a well-formed
/// [`AttestedApprover::Remote`] and every other surface requires
/// [`AttestedApprover::Local`].
fn approver_matches_surface(
    surface: Surface,
    approver: &AttestedApprover,
) -> Result<Option<&str>, WalletError> {
    let mismatch = |detail: &str| {
        WalletError::Approval(ApprovalFailure::UserMismatch {
            detail: detail.to_owned(),
        })
    };
    match (surface, approver) {
        (
            Surface::ServeRemote,
            AttestedApprover::Remote {
                credential_id_b64url,
            },
        ) if approver.is_well_formed() => Ok(Some(credential_id_b64url.as_str())),
        (Surface::ServeRemote, _) => Err(mismatch(
            "a remote approval requires a verified operator credential",
        )),
        (_, AttestedApprover::Local) => Ok(None),
        (_, _) => Err(mismatch(
            "only the remote-approval listener attests for an operator credential",
        )),
    }
}

/// Runs the checks every attestation runs before it matches the entry's kind.
///
/// In order: the entry's own profile and chain, for the kinds that record
/// them, equal the binding's; the key is 32 bytes, borrowed from `key_bytes`
/// so that no copy of the secret outlives the caller's zeroizing buffer; one
/// clock read; and [`refuse_unless_still_pending`] at that time. The clock
/// read is returned so the store's own expiry check uses the same instant.
fn prepare_attestation<'k>(
    store: &PendingApprovalStore,
    entry: &PendingApproval,
    key_bytes: &'k [u8],
    binding: &super::AttestationBinding<'_>,
) -> Result<(&'k [u8; 32], u64), WalletError> {
    let binding_matches = match &entry.kind {
        ApprovalKind::RuleProposalSimulated { chain_id, .. } => chain_id == binding.chain_id,
        ApprovalKind::MppChargeSimulated {
            profile, chain_id, ..
        } => profile == binding.profile_name && chain_id == binding.chain_id,
        _ => true,
    };
    if !binding_matches {
        return Err(WalletError::Approval(ApprovalFailure::BindingMismatch {
            detail: "this request belongs to another profile or network".to_owned(),
        }));
    }
    let key: &[u8; 32] = key_bytes.try_into().map_err(|_| {
        WalletError::Approval(ApprovalFailure::KeyLengthError {
            detail: format!("attestation key must be 32 bytes, got {}", key_bytes.len()),
        })
    })?;
    let now_ms = timefmt::now_unix_ms().map_err(|e| map_clock_error(&e))?;
    refuse_unless_still_pending(store, entry, now_ms)?;
    Ok((key, now_ms))
}

/// Refuses unless the locked `store` still holds the pending entry the caller
/// validated.
///
/// The caller validated `validated` earlier, possibly through another store
/// handle, and another process may have attested, rejected, consumed, or
/// replaced it since. The same pending entry means the whole `kind` value,
/// the `process_uid`, and both lifetime fields are equal. Each refusal carries the code
/// [`record_attestation_on_store`] gives for the same condition, so a caller
/// maps both the same way. No row is written for a refused entry.
fn refuse_unless_still_pending(
    store: &PendingApprovalStore,
    validated: &PendingApproval,
    now_ms: u64,
) -> Result<(), WalletError> {
    let Some(current) = store.get(&validated.approval_nonce) else {
        return Err(record_error(&ApprovalError::NotFound));
    };
    if current.kind != validated.kind
        || current.process_uid != validated.process_uid
        || current.created_at_unix_ms != validated.created_at_unix_ms
        || current.expires_at_unix_ms != validated.expires_at_unix_ms
    {
        return Err(match current.kind {
            ApprovalKind::Rejected { .. } => rejected_error(),
            ApprovalKind::Consumed { .. } => consumed_error(),
            _ => WalletError::Approval(ApprovalFailure::WrongKind {
                detail: "the pending approval changed between validation \
                         and the attest"
                    .to_owned(),
            }),
        });
    }
    if current.is_expired(now_ms) {
        return Err(record_error(&ApprovalError::Expired));
    }
    if current.created_at_unix_ms > now_ms {
        return Err(WalletError::Approval(ApprovalFailure::Expired {
            detail: "approval creation time is after the attestation clock".to_owned(),
        }));
    }
    if current.attestation_blob_b64.is_some() {
        return Err(record_error(&ApprovalError::AlreadyAttested));
    }
    Ok(())
}

/// Attests a direct mainnet confirmation of a classic transaction with its
/// verified presence, after rechecking the pending record.
///
/// The consent is the version 5 attestation [`attest_and_persist`] records
/// for [`ConsentAuthorization::Mainnet`], under [`Surface::CliMainnetConfirm`]
/// and `gated_tool`; the row is durable before the attestation is persisted.
///
/// # Errors
/// `approval.wrong_kind` for a kind other than a payment, claim or trustline;
/// otherwise the errors of the mainnet path of [`attest_and_persist`].
#[allow(
    clippy::too_many_arguments,
    reason = "the store, entry, key, binding, sink, tool, policy and proof are each explicit"
)]
pub fn attest_mainnet_confirmation(
    store: &mut PendingApprovalStore,
    entry: &PendingApproval,
    key_bytes: &[u8],
    binding: &super::AttestationBinding<'_>,
    mut audit: ConsentAudit<'_>,
    gated_tool: &str,
    policy: &VerifiedPolicy,
    presence: VerifiedMainnetPresence,
) -> Result<(), WalletError> {
    if !matches!(
        entry.kind,
        ApprovalKind::PaymentSimulated { .. }
            | ApprovalKind::ClaimSimulated { .. }
            | ApprovalKind::TrustlineSimulated { .. }
    ) {
        return Err(WalletError::Approval(ApprovalFailure::WrongKind {
            detail: "mainnet confirmation requires a classic transaction".to_owned(),
        }));
    }
    attest_mainnet_presence(
        store,
        entry,
        key_bytes,
        binding,
        Surface::CliMainnetConfirm,
        &mut audit,
        presence,
        policy,
        gated_tool,
    )
    .map(|_| ())
}

/// The commit tool a mainnet consent to `kind` gates.
fn mainnet_gated_tool(kind: &ApprovalKind) -> Result<&'static str, WalletError> {
    match kind {
        ApprovalKind::PaymentSimulated { .. } => Ok("stellar_pay_commit"),
        ApprovalKind::ClaimSimulated { .. } => Ok("stellar_claim_commit"),
        ApprovalKind::TrustlineSimulated { .. } | ApprovalKind::TrustlineClawbackOptIn { .. } => {
            Ok("stellar_trustline_commit")
        }
        ApprovalKind::X402Payment { .. } => Ok("stellar_x402_create_payment"),
        ApprovalKind::Rejected { .. } => Err(rejected_error()),
        ApprovalKind::Consumed { .. } => Err(consumed_error()),
        _ => Err(WalletError::Approval(ApprovalFailure::WrongKind {
            detail: super::presence::UNSUPPORTED_KIND_MESSAGE.to_owned(),
        })),
    }
}

/// The mainnet consent path of [`attest_and_persist`].
///
/// In order, all before the row:
///
/// 1. The surface is local, the binding is mainnet and names the profile and
///    chain the challenge bound, and `entry` is the challenged entry.
/// 2. The key is 32 bytes, and the audit sink completes its acquisition,
///    drain and state waits; the locked store still holds the challenged
///    snapshot: same nonce, kind, process UID and both lifetime fields,
///    unattested and live.
/// 3. The current owner-signed policy, loaded again without advancing the
///    pin, is `policy` and is the policy the challenge bound.
/// 4. The receipt verifies again over the locked entry: the recomputed
///    subject and challenge, the raw assertion under the signed key.
/// 5. Both challenge deadlines are still live, checked immediately before
///    the row because the keyring, policy and audit waits can cross them.
///
/// Then the row, then one store replacement with the version 5 blob, the
/// mainnet passkey approver and the receipt.
#[allow(
    clippy::too_many_arguments,
    reason = "the store, entry, key, binding, surface, sink, proof, policy and tool are each explicit"
)]
fn attest_mainnet_presence(
    store: &mut PendingApprovalStore,
    entry: &PendingApproval,
    key_bytes: &[u8],
    binding: &super::AttestationBinding<'_>,
    surface: Surface,
    audit: &mut ConsentAudit<'_>,
    presence: VerifiedMainnetPresence,
    policy: &VerifiedPolicy,
    gated_tool: &str,
) -> Result<Option<String>, WalletError> {
    if surface == Surface::ServeRemote {
        return Err(WalletError::Approval(
            ApprovalFailure::MainnetRemoteUnsupported,
        ));
    }
    let mismatch = || {
        WalletError::Approval(ApprovalFailure::BindingMismatch {
            detail: "this request belongs to another profile or network".to_owned(),
        })
    };
    if binding.chain_id != MAINNET_CHAIN_ID {
        return Err(mismatch());
    }
    let parts = presence.into_parts();
    if parts.profile_name != binding.profile_name
        || parts.chain_id != binding.chain_id
        || parts.entry.approval_nonce != entry.approval_nonce
    {
        return Err(mismatch());
    }
    let key: &[u8; 32] = key_bytes.try_into().map_err(|_| {
        WalletError::Approval(ApprovalFailure::KeyLengthError {
            detail: format!("attestation key must be 32 bytes, got {}", key_bytes.len()),
        })
    })?;
    let audit = audit
        .prepare()
        .map_err(|error| audit_writer_refusal(binding.profile_name, &error))?;
    let now_ms = timefmt::now_unix_ms().map_err(|e| map_clock_error(&e))?;
    refuse_unless_still_pending(store, &parts.entry, now_ms)?;
    let current = store
        .get(&parts.entry.approval_nonce)
        .cloned()
        .ok_or_else(|| record_error(&ApprovalError::NotFound))?;

    let loaded =
        super::presence_policy::MainnetApprovalAuthority::for_profile(binding.profile_name)?
            .load_current_compare_only()?;
    if !loaded.is(policy) || !super::presence_policy::same_policy(policy, &parts.policy) {
        return Err(WalletError::Approval(
            ApprovalFailure::PresencePolicyUnavailable,
        ));
    }

    let subject = super::presence::mainnet_consent_subject(&current, binding)?;
    let stored =
        super::presence::verify_receipt(&current, &parts.receipt, binding, policy, now_ms)?;
    let approver = AttestedApprover::MainnetPasskey {
        credential_id_b64url: parts.receipt.credential_id_b64url(),
    };
    let attestation_blob = compute_attestation_v5(
        key,
        binding,
        &current.approval_nonce,
        &subject,
        &current.process_uid,
        &current.attested_lifetime(),
        &approver,
        &parts.receipt,
    );
    let envelope_sha256_hex = match &current.kind {
        ApprovalKind::PaymentSimulated {
            envelope_sha256_hex,
            ..
        }
        | ApprovalKind::ClaimSimulated {
            envelope_sha256_hex,
            ..
        }
        | ApprovalKind::TrustlineSimulated {
            envelope_sha256_hex,
            ..
        } => Some(envelope_sha256_hex.clone()),
        ApprovalKind::X402Payment { .. } => Some(crate::hex::encode(&subject)),
        _ => None,
    };

    let row_ms = timefmt::now_unix_ms().map_err(|e| map_clock_error(&e))?;
    if std::time::Instant::now() >= parts.deadline
        || row_ms < parts.receipt.issued_at_unix_ms()
        || row_ms >= parts.receipt.expires_at_unix_ms()
    {
        return Err(WalletError::Approval(ApprovalFailure::PresenceExpired));
    }
    let row = AuditEntry::new_mainnet_approval_attested(
        current.kind.kind_name(),
        gated_tool,
        envelope_sha256_hex,
        &current.approval_nonce,
        surface.as_str(),
        parts.receipt.request_id(),
        binding.chain_id,
        super::presence::presence_audit(&stored, &parts.receipt),
    );
    audit.write(row).map_err(|e| {
        tracing::warn!(
            error = %e,
            approval_kind = current.kind.kind_name(),
            "mainnet approval attest: the consent row was not written; nothing is persisted"
        );
        audit_writer_refusal(binding.profile_name, &e)
    })?;
    store
        .record_mainnet_attestation_at(
            &current.approval_nonce,
            attestation_blob,
            approver,
            parts.receipt,
            row_ms,
        )
        .map_err(|e| record_error(&e))?;
    Ok(match current.kind {
        ApprovalKind::TrustlineClawbackOptIn { .. } => None,
        _ => Some(URL_SAFE_NO_PAD.encode(attestation_blob)),
    })
}

/// Maps a pending-store failure to its `approval.*` refusal.
///
/// `NotFound`, `Expired` and `AlreadyAttested` keep their own codes; every
/// other store failure is `approval.record_failed` with the store's message.
#[must_use]
pub fn record_error(e: &ApprovalError) -> WalletError {
    match e {
        ApprovalError::NotFound => WalletError::Approval(ApprovalFailure::NotFound {
            detail: "entry disappeared between lookup and record".to_owned(),
        }),
        ApprovalError::Expired => WalletError::Approval(ApprovalFailure::Expired {
            detail: "entry expired between check and record".to_owned(),
        }),
        ApprovalError::AlreadyAttested => WalletError::Approval(ApprovalFailure::AlreadyAttested {
            detail: "entry was attested by a concurrent process".to_owned(),
        }),
        other => WalletError::Approval(ApprovalFailure::RecordFailed {
            detail: other.to_string(),
        }),
    }
}

/// Attests an envelope digest, writes its consent row, and persists the blob.
///
/// A classic entry is refused with `approval.entry_inconsistent`, before the
/// row, unless its stored digest is the digest of its stored envelope and
/// that envelope decodes (see [`classic_entry_summary`]); the digest an
/// attestation binds is then always the digest of the transaction the
/// approval surfaces showed.
#[allow(
    clippy::too_many_arguments,
    reason = "shared envelope attestation uses the caller's binding and consent context"
)]
fn attest_envelope_and_persist(
    store: &mut PendingApprovalStore,
    entry: &PendingApproval,
    key: &[u8; 32],
    binding: &super::AttestationBinding<'_>,
    audit: &mut ConsentAudit<'_>,
    surface: Surface,
    approver: &AttestedApprover,
    now_ms: u64,
    envelope_sha256_hex: &str,
    kind_name: &str,
    gated_tool: &str,
) -> Result<Option<String>, WalletError> {
    let operator_credential_id_b64url = approver_matches_surface(surface, approver)?;
    if let Some(consistency) = classic_entry_summary(&entry.kind) {
        consistency?;
    }
    let presented_sha256 = decode_sha256_hex(envelope_sha256_hex)?;
    let attestation_blob = compute_attestation_v4(
        key,
        binding,
        &entry.approval_nonce,
        &presented_sha256,
        &entry.process_uid,
        &entry.attested_lifetime(),
        approver,
    );
    emit_attested_audit(
        audit,
        binding.profile_name,
        kind_name,
        gated_tool,
        Some(envelope_sha256_hex.to_owned()),
        &entry.approval_nonce,
        surface,
        operator_credential_id_b64url,
    )?;
    record_attestation_on_store(
        store,
        &entry.approval_nonce,
        attestation_blob,
        approver,
        now_ms,
    )?;
    Ok(Some(URL_SAFE_NO_PAD.encode(attestation_blob)))
}

/// Helper: records an HMAC attestation blob and its approver on the store
/// entry.
fn record_attestation_on_store(
    store: &mut PendingApprovalStore,
    approval_nonce: &str,
    attestation_blob: [u8; 32],
    approver: &AttestedApprover,
    now_ms: u64,
) -> Result<(), WalletError> {
    store
        .record_attestation_at(approval_nonce, attestation_blob, approver.clone(), now_ms)
        .map_err(|e| record_error(&e))
}

/// Writes the consent row through `audit`, fatally.
///
/// A refusal is returned as the [`WalletError`] that names the condition. It
/// uses the variants and wire codes of the value verbs' audit pre-flight: a
/// tip-anchor mismatch, a condition about the log led by its `audit.*`
/// sub-code, or an open failure. The caller then persists nothing.
#[allow(
    clippy::too_many_arguments,
    reason = "flat row fields mirror the ApprovalAttested event schema"
)]
fn emit_attested_audit(
    audit: &mut ConsentAudit<'_>,
    profile: &str,
    approval_kind: &str,
    gated_tool: &str,
    envelope_sha256_hex: Option<String>,
    approval_nonce: &str,
    surface: Surface,
    operator_credential_id_b64url: Option<&str>,
) -> Result<(), WalletError> {
    let entry = match operator_credential_id_b64url {
        Some(cred_id) => AuditEntry::new_approval_attested_remote(
            approval_kind,
            gated_tool,
            envelope_sha256_hex,
            approval_nonce,
            cred_id,
            uuid::Uuid::new_v4().to_string(),
        ),
        None => AuditEntry::new_approval_attested(
            approval_kind,
            gated_tool,
            envelope_sha256_hex,
            approval_nonce,
            surface.as_str(),
            uuid::Uuid::new_v4().to_string(),
        ),
    };
    audit.write(entry).map_err(|e| {
        tracing::warn!(
            error = %e,
            approval_kind,
            "approval attest: the consent row was not written; nothing is persisted"
        );
        audit_writer_refusal(profile, &e)
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
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use crate::approval::fixtures;
    use crate::approval::store::DEFAULT_TTL_MS;
    use crate::approval::user_id::process_uid_for_attestation;
    use stellar_agent_test_support::keyring_mock;
    use tempfile::TempDir;

    fn seed_key_32(service: &str, account: &str) -> [u8; 32] {
        let key = [0xABu8; 32];
        let encoded = URL_SAFE_NO_PAD.encode(key);
        let entry = KeyringEntry::new(service, account).unwrap();
        entry.set_password(&encoded).unwrap();
        key
    }

    const SOURCE: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    const DEST: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
    const USDC_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

    fn make_entry(ttl_ms: u64) -> PendingApproval {
        fixtures::payment_pending(
            SOURCE,
            DEST,
            "XLM",
            2_500_000,
            None,
            100,
            1_234_567,
            process_uid_for_attestation().expect("UID available on test host"),
            ttl_ms,
        )
    }

    fn trustline_entry() -> PendingApproval {
        fixtures::trustline_pending(
            SOURCE,
            "USDC",
            USDC_ISSUER,
            None,
            100,
            42,
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
    }

    /// Opens an unkeyed audit writer on a log inside `dir`.
    fn test_audit_writer(dir: &TempDir) -> AuditWriter {
        AuditWriter::open(dir.path().join("audit").join("audit.jsonl"), None).unwrap()
    }

    #[test]
    fn decode_sha256_hex_valid() {
        let hex = "a".repeat(64);
        assert!(decode_sha256_hex(&hex).is_ok());
    }

    #[test]
    fn decode_sha256_hex_wrong_length_fails() {
        let err = decode_sha256_hex("abcd").unwrap_err();
        assert_eq!(err.code(), "approval.sha256_hex_error");
        assert!(err.to_string().contains("64"));
    }

    #[test]
    fn attest_passkey_kind_refuses_with_wrong_kind_code() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = TempDir::new()?;
        let store_path = dir.path().join("approvals.toml");
        let mut store = PendingApprovalStore::open(store_path.clone())?;
        let entry = PendingApproval::new_passkey_pending(
            [0x11; 32],
            vec![0x22; 32],
            "CAAAA...BBBBB".to_owned(),
            vec![1],
            [0x33; 32],
            "localhost".to_owned(),
            process_uid_for_attestation()?,
            DEFAULT_TTL_MS,
        )?;
        store.insert(entry.clone(), timefmt::now_unix_ms()?)?;
        let mut writer = test_audit_writer(&dir);
        let mut grant_persisted = false;
        let err = attest_and_persist(
            &mut store,
            &entry,
            &[0x42; 32],
            &binding(),
            Surface::Cli,
            ConsentAudit::Writer(&mut writer),
            ConsentAuthorization::Standard(&AttestedApprover::Local),
            |_, _| {
                grant_persisted = true;
                Ok(())
            },
        )
        .err()
        .ok_or("passkey approval must refuse HMAC attestation")?;
        assert_eq!(err.code(), "approval.wrong_kind");
        assert!(!grant_persisted);
        assert!(consent_rows(&dir).is_empty());
        drop(store);
        let reopened = PendingApprovalStore::open(store_path)?;
        let pending = reopened
            .get(&entry.approval_nonce)
            .ok_or("pending entry must exist")?;
        assert!(pending.attestation_blob_b64.is_none());
        Ok(())
    }

    #[test]
    fn record_attestation_persist_failure_has_record_failed_code()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let store_path = dir.path().join("approvals.toml");
        let mut store = PendingApprovalStore::open(store_path.clone())?;
        let entry = make_entry(DEFAULT_TTL_MS);
        let now_ms = timefmt::now_unix_ms()?;
        store.insert(entry.clone(), now_ms)?;
        std::fs::remove_file(&store_path)?;
        std::fs::create_dir(&store_path)?;
        let err = record_attestation_on_store(
            &mut store,
            &entry.approval_nonce,
            [0x42; 32],
            &AttestedApprover::Local,
            now_ms,
        )
        .err()
        .ok_or("persisting over a directory must refuse")?;
        assert_eq!(err.code(), "approval.record_failed");
        assert!(store_path.is_dir());
        Ok(())
    }

    /// The owner context of the profile these loader tests name.
    fn test_owner() -> crate::profile::owner_key::OwnerKeyContext {
        crate::profile::owner_key::OwnerKeyContext::for_profile_name("core-test")
    }

    #[test]
    #[serial_test::serial]
    fn load_attestation_key_success() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-load";
        seed_key_32(svc, "default");
        let entry_ref = KeyringEntryRef::new(svc, "default");
        let key = load_attestation_key(&entry_ref, &test_owner()).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    #[serial_test::serial]
    fn load_attestation_key_invalid_base64_has_decode_code()
    -> Result<(), Box<dyn std::error::Error>> {
        keyring_mock::install()?;
        let entry_ref = KeyringEntryRef::new("stellar-agent-attestation-invalid-base64", "default");
        KeyringEntry::new(&entry_ref.service, &entry_ref.account)?.set_password("not!base64")?;
        let err = load_attestation_key(&entry_ref, &test_owner())
            .err()
            .ok_or("invalid base64 must refuse")?;
        assert_eq!(err.code(), "approval.key_decode_failed");
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn load_attestation_key_31_bytes_has_length_code() -> Result<(), Box<dyn std::error::Error>> {
        keyring_mock::install()?;
        let entry_ref = KeyringEntryRef::new("stellar-agent-attestation-short-key", "default");
        KeyringEntry::new(&entry_ref.service, &entry_ref.account)?
            .set_password(&URL_SAFE_NO_PAD.encode([0xAB; 31]))?;
        let err = load_attestation_key(&entry_ref, &test_owner())
            .err()
            .ok_or("a 31-byte key must refuse")?;
        assert_eq!(err.code(), "approval.key_length_error");
        Ok(())
    }

    /// An attestation key equal to the profile's owner public key in the older
    /// form refuses after decoding.
    #[test]
    #[serial_test::serial]
    fn load_attestation_key_refuses_the_owner_public_key() {
        use base64::Engine as _;
        keyring_mock::install().unwrap();
        let owner_bytes = [0x2b_u8; 32];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(owner_bytes);
        let owner = KeyringEntryRef::default_owner_key("core-test");
        let attestation = KeyringEntryRef::new("stellar-agent-attestation-core-test", "default");
        for coordinate in [&owner, &attestation] {
            keyring_core::Entry::new(&coordinate.service, &coordinate.account)
                .unwrap()
                .set_password(&encoded)
                .unwrap();
        }
        let Err(err) = load_attestation_key(&attestation, &test_owner()) else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "validation.key_matches_owner_public_key");
        assert!(err.to_string().contains("attestation_key_id"));
    }

    /// A G-strkey owner value at the attestation coordinate decodes to 42
    /// bytes and is refused by the length rule.
    #[test]
    #[serial_test::serial]
    fn load_attestation_key_refuses_a_g_strkey_owner_value() {
        keyring_mock::install().unwrap();
        let attestation = KeyringEntryRef::new("stellar-agent-attestation-core-strkey", "default");
        keyring_core::Entry::new(&attestation.service, &attestation.account)
            .unwrap()
            .set_password(&crate::profile::owner_key::encode_owner_public_key(
                &[0x2b; 32],
            ))
            .unwrap();
        let Err(err) = load_attestation_key(&attestation, &test_owner()) else {
            panic!("the load refuses");
        };
        assert!(
            err.to_string()
                .contains("attestation key must be 32 bytes, got 42"),
            "{err}"
        );
    }

    /// A profile whose `policy_owner_key_id.account` is not `default` still
    /// compares against the owner entry the engine reads,
    /// `default_owner_key(name)`.
    #[test]
    #[serial_test::serial]
    fn load_attestation_key_compares_the_engine_coordinate_for_a_non_default_account() {
        use base64::Engine as _;
        keyring_mock::install().unwrap();
        let mut profile = crate::profile::schema::Profile::builder_testnet_named(
            "core-owner-acct",
            "s",
            "a",
            "n",
            "a",
        )
        .build();
        profile.policy_owner_key_id =
            KeyringEntryRef::new("stellar-agent-owner-core-owner-acct", "operator");
        let owner =
            crate::profile::owner_key::OwnerKeyContext::for_profile("core-owner-acct", &profile);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x3c_u8; 32]);
        let engine_coordinate = KeyringEntryRef::default_owner_key("core-owner-acct");
        let attestation =
            KeyringEntryRef::new("stellar-agent-attestation-core-owner-acct", "default");
        for coordinate in [&engine_coordinate, &attestation] {
            keyring_core::Entry::new(&coordinate.service, &coordinate.account)
                .unwrap()
                .set_password(&encoded)
                .unwrap();
        }
        let Err(err) = load_attestation_key(&attestation, &owner) else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "validation.key_matches_owner_public_key");
    }

    /// An attestation coordinate in another profile's owner namespace refuses
    /// before any keyring read: an error planted there is still pending.
    #[test]
    #[serial_test::serial]
    fn load_attestation_key_refuses_an_owner_coordinate_without_a_read() {
        keyring_mock::install().unwrap();
        let other_owner = KeyringEntryRef::new("stellar-agent-owner-B", "default");
        keyring_mock::inject_error(
            &other_owner.service,
            &other_owner.account,
            keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other("planted"))),
        )
        .unwrap();
        let Err(err) = load_attestation_key(&other_owner, &test_owner()) else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "validation.key_matches_owner_public_key");
        let pending = keyring_core::Entry::new(&other_owner.service, &other_owner.account)
            .unwrap()
            .get_password()
            .unwrap_err();
        assert!(
            matches!(pending, keyring_core::Error::PlatformFailure(_)),
            "the planted error is still pending, so no read happened: {pending:?}"
        );
    }

    /// A non-interactive Windows session (the `ERROR_NO_SUCH_LOGON_SESSION`
    /// shape injected at the attestation-key coordinates) must surface as
    /// `auth.keyring_interactive_session_required`, not `auth.keyring_not_found`.
    #[test]
    #[serial_test::serial]
    fn load_attestation_key_surfaces_interactive_session_required() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-no-logon";
        keyring_mock::inject_no_logon_session(svc, "default").unwrap();
        let entry_ref = KeyringEntryRef::new(svc, "default");
        let Err(err) = load_attestation_key(&entry_ref, &test_owner()) else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "auth.keyring_interactive_session_required");
    }

    /// A platform-store failure at the attestation-key coordinates must surface
    /// as `auth.keyring_platform_error`, not `auth.keyring_not_found`.
    #[test]
    #[serial_test::serial]
    fn load_attestation_key_surfaces_platform_error() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-platform-err";
        keyring_mock::inject_error(
            svc,
            "default",
            keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other(
                "simulated platform failure",
            ))),
        )
        .unwrap();
        let entry_ref = KeyringEntryRef::new(svc, "default");
        let Err(err) = load_attestation_key(&entry_ref, &test_owner()) else {
            panic!("the load refuses");
        };
        assert_eq!(err.code(), "auth.keyring_platform_error");
    }

    #[test]
    #[serial_test::serial]
    fn load_and_validate_entry_success() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        let uid = entry.process_uid.clone();
        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let validated =
            load_and_validate_entry(&store, &nonce, &ApproverIdentity::OsUid(uid), &[]).unwrap();
        assert_eq!(validated.approval_nonce, nonce);
    }

    #[test]
    #[serial_test::serial]
    fn load_and_validate_entry_user_mismatch_fails() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let err = load_and_validate_entry(
            &store,
            &nonce,
            &ApproverIdentity::OsUid("different-uid".to_owned()),
            &[],
        )
        .unwrap_err();
        assert_eq!(err.code(), "approval.user_mismatch");
    }

    /// GATE-IS-REAL: a `PasskeyCredential` identity reaching
    /// `load_and_validate_entry` — the single production gate every approve
    /// surface funnels through — is refused when its credential ID is not in
    /// `allowed_credentials`, even though the entry itself is otherwise valid
    /// (unexpired, unattested) and the identity carries a verified-assertion
    /// witness. This pins the fix for the fail-open risk of an always-true
    /// gate arm: a future regression that stops threading the allowlist (or
    /// reintroduces an unconditional pass) fails this test.
    #[test]
    #[serial_test::serial]
    fn load_and_validate_entry_refuses_non_allowlisted_passkey_credential() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let identity = ApproverIdentity::from_verified_passkey_assertion(
            "attacker-controlled-cred-id",
            crate::approval::user_id::VerifiedPasskeyAssertion::new_for_test(&nonce),
        );
        let allowed = vec!["enrolled-operator-cred-id".to_owned()];
        let err = load_and_validate_entry(&store, &nonce, &identity, &allowed).unwrap_err();
        assert!(
            err.code() == "approval.user_mismatch",
            "unexpected error: {err}"
        );
    }

    /// GATE-IS-REAL, positive case: the same gate authorizes a
    /// `PasskeyCredential` identity whose credential ID IS present in
    /// `allowed_credentials`, proving the check is a genuine membership test
    /// rather than always refusing (which would make the earlier test
    /// vacuous).
    #[test]
    #[serial_test::serial]
    fn load_and_validate_entry_accepts_allowlisted_passkey_credential() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let identity = ApproverIdentity::from_verified_passkey_assertion(
            "enrolled-operator-cred-id",
            crate::approval::user_id::VerifiedPasskeyAssertion::new_for_test(&nonce),
        );
        let allowed = vec!["enrolled-operator-cred-id".to_owned()];
        let validated = load_and_validate_entry(&store, &nonce, &identity, &allowed).unwrap();
        assert_eq!(validated.approval_nonce, nonce);
    }

    /// ENTRY-BINDING at the `load_and_validate_entry` layer: an allowlisted
    /// `PasskeyCredential` identity whose witness is bound to a DIFFERENT
    /// nonce than the entry being loaded is refused, even though the
    /// credential itself is allowlisted. Proves cross-entry replay is
    /// impossible through the production gate, not just through the
    /// `ApproverIdentity` unit tests in `user_id.rs`.
    #[test]
    #[serial_test::serial]
    fn load_and_validate_entry_refuses_witness_bound_to_different_entry() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let identity = ApproverIdentity::from_verified_passkey_assertion(
            "enrolled-operator-cred-id",
            // Bound to a different (well-formed but unrelated) nonce, not `nonce`.
            crate::approval::user_id::VerifiedPasskeyAssertion::new_for_test(
                "ZZZZZZZZZZZZZZZZZZZZZZ",
            ),
        );
        let allowed = vec!["enrolled-operator-cred-id".to_owned()];
        let err = load_and_validate_entry(&store, &nonce, &identity, &allowed).unwrap_err();
        assert!(
            err.code() == "approval.user_mismatch",
            "unexpected error: {err}"
        );
    }

    fn assert_cross_bindings_refused(
        key: &[u8; 32],
        entry: &PendingApproval,
        digest: &[u8; 32],
        blob: &[u8; 32],
    ) {
        let scope = entry.attestation_scope().unwrap();
        for binding in [
            crate::approval::AttestationBinding::new("b", "stellar:testnet"),
            crate::approval::AttestationBinding::new("a", "stellar:mainnet"),
        ] {
            assert!(!crate::approval::verify_attestation(
                key,
                &binding,
                &entry.approval_nonce,
                digest,
                &entry.process_uid,
                &scope,
                blob
            ));
        }
    }

    #[test]
    #[serial_test::serial]
    fn attest_and_persist_payment_records_hmac_and_surfaces_blob() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-payment";
        let raw_key = seed_key_32(svc, "default");

        let dir = TempDir::new().unwrap();
        let mut audit_writer = test_audit_writer(&dir);
        let path = dir.path().join("default.toml");
        let mut store = PendingApprovalStore::open(path).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        let process_uid = entry.process_uid.clone();

        let envelope_sha256_hex = if let ApprovalKind::PaymentSimulated {
            envelope_sha256_hex,
            ..
        } = &entry.kind
        {
            envelope_sha256_hex.clone()
        } else {
            unreachable!("make_entry always produces PaymentSimulated")
        };

        store
            .insert(entry.clone(), timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let surfaced = attest_and_persist(
            &mut store,
            &entry,
            &raw_key,
            &crate::approval::AttestationBinding::new("a", "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            ConsentAuthorization::Standard(&AttestedApprover::Local),
            |_req, _key| Err("must not be called for PaymentSimulated".to_owned()),
        )
        .unwrap();
        let surfaced_blob = surfaced.expect("PaymentSimulated must surface its attestation blob");

        let final_entry = store.get(&nonce).unwrap();
        let blob_b64 = final_entry.attestation_blob_b64.as_ref().unwrap();
        assert_eq!(surfaced_blob, *blob_b64);

        let sha256_bytes = decode_sha256_hex(&envelope_sha256_hex).unwrap();
        let expected = compute_attestation_v4(
            &raw_key,
            &crate::approval::AttestationBinding::new("a", "stellar:testnet"),
            &nonce,
            &sha256_bytes,
            &process_uid,
            &final_entry.attested_lifetime(),
            &AttestedApprover::Local,
        );
        let persisted_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(blob_b64)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(persisted_bytes, expected);
        assert_cross_bindings_refused(&raw_key, final_entry, &sha256_bytes, &persisted_bytes);
    }

    #[test]
    #[serial_test::serial]
    fn attest_and_persist_rejected_tombstone_fails_closed() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-rejected";
        let raw_key = seed_key_32(svc, "default");

        let dir = TempDir::new().unwrap();
        let mut audit_writer = test_audit_writer(&dir);
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        let now_ms = timefmt::now_unix_ms().expect("clock");
        store.insert(entry, now_ms).unwrap();
        store.reject(&nonce, now_ms, 60_000).unwrap();

        let rejected_entry = store.get(&nonce).unwrap().clone();
        let err = attest_and_persist(
            &mut store,
            &rejected_entry,
            &raw_key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            ConsentAuthorization::Standard(&AttestedApprover::Local),
            |_req, _key| Err("must not be called".to_owned()),
        )
        .unwrap_err();
        assert_eq!(err.code(), "approval.rejected", "unexpected error: {err}");
    }

    #[test]
    #[serial_test::serial]
    fn attest_and_persist_toolset_gate_invokes_closure_and_consumes_entry() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-toolset";
        let raw_key = seed_key_32(svc, "default");

        let dir = TempDir::new().unwrap();
        let mut audit_writer = test_audit_writer(&dir);
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let uid = process_uid_for_attestation().unwrap();
        let entry = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "sign-payment".to_owned(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "XLM".to_owned(),
            0,
            1_000_000,
            uid,
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        let now_ms = timefmt::now_unix_ms().expect("clock");
        store.insert(entry.clone(), now_ms).unwrap();

        let surfaced = attest_and_persist(
            &mut store,
            &entry,
            &raw_key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            ConsentAuthorization::Standard(&AttestedApprover::Local),
            |req, _key| {
                assert_eq!(req.toolset_name, "my-toolset");
                assert_eq!(req.capability, "sign-payment");
                Ok(())
            },
        );
        assert!(
            surfaced.unwrap().is_none(),
            "ToolsetFirstInvokeGate surfaces no attestation"
        );
        assert!(
            store.get(&nonce).is_none(),
            "ToolsetFirstInvokeGate entry must be consumed after grant persist"
        );
    }

    #[test]
    #[serial_test::serial]
    fn attest_and_persist_toolset_gate_closure_failure_propagates_and_keeps_entry() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-toolset-fail";
        let raw_key = seed_key_32(svc, "default");

        let dir = TempDir::new().unwrap();
        let mut audit_writer = test_audit_writer(&dir);
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let uid = process_uid_for_attestation().unwrap();
        let entry = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "sign-payment".to_owned(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "XLM".to_owned(),
            0,
            1_000_000,
            uid,
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        let now_ms = timefmt::now_unix_ms().expect("clock");
        store.insert(entry.clone(), now_ms).unwrap();

        let err = attest_and_persist(
            &mut store,
            &entry,
            &raw_key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            ConsentAuthorization::Standard(&AttestedApprover::Local),
            |_req, _key| Err("grant store unavailable".to_owned()),
        )
        .unwrap_err();
        assert_eq!(err.code(), "approval.grant_persist");
        assert!(
            store.get(&nonce).is_some(),
            "entry must survive a failed grant persist"
        );
    }

    fn make_rule_proposal_entry(ttl_ms: u64) -> PendingApproval {
        use crate::approval::rule_proposal::{
            ContextRuleProposalSnapshot, RuleProposalContextType, RuleProposalSigner,
        };

        let definition = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::Default,
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                true,
            )],
            vec![],
            vec![0],
            false,
            false,
        );
        PendingApproval::new_rule_proposal_pending(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            "stellar:testnet".to_owned(),
            definition,
            [0x77u8; 32],
            "CallContract rule \"spend-daily\"".to_owned(),
            process_uid_for_attestation().expect("UID available on test host"),
            ttl_ms,
        )
        .unwrap()
    }

    #[test]
    #[serial_test::serial]
    fn attest_and_persist_rule_proposal_records_hmac_and_surfaces_blob() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-rule-proposal";
        let raw_key = seed_key_32(svc, "default");

        let dir = TempDir::new().unwrap();
        let mut audit_writer = test_audit_writer(&dir);
        let path = dir.path().join("default.toml");
        let mut store = PendingApprovalStore::open(path).unwrap();
        let entry = make_rule_proposal_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        let process_uid = entry.process_uid.clone();

        let proposal_sha256 = if let ApprovalKind::RuleProposalSimulated {
            proposal_sha256, ..
        } = &entry.kind
        {
            *proposal_sha256
        } else {
            unreachable!("make_rule_proposal_entry always produces RuleProposalSimulated")
        };

        store
            .insert(entry.clone(), timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let surfaced = attest_and_persist(
            &mut store,
            &entry,
            &raw_key,
            &crate::approval::AttestationBinding::new("a", "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            ConsentAuthorization::Standard(&AttestedApprover::Local),
            |_req, _key| Err("must not be called for RuleProposalSimulated".to_owned()),
        )
        .unwrap();
        let surfaced_blob =
            surfaced.expect("RuleProposalSimulated must surface its attestation blob");

        let final_entry = store.get(&nonce).unwrap();
        let blob_b64 = final_entry.attestation_blob_b64.as_ref().unwrap();
        assert_eq!(surfaced_blob, *blob_b64);

        let expected = compute_attestation_v4(
            &raw_key,
            &crate::approval::AttestationBinding::new("a", "stellar:testnet"),
            &nonce,
            &proposal_sha256,
            &process_uid,
            &final_entry.attested_lifetime(),
            &AttestedApprover::Local,
        );
        let persisted_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(blob_b64)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(persisted_bytes, expected);
        assert_cross_bindings_refused(&raw_key, final_entry, &proposal_sha256, &persisted_bytes);
    }

    #[test]
    #[serial_test::serial]
    fn attest_and_persist_rule_proposal_rejected_tombstone_fails_closed() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-core-test-rule-proposal-rejected";
        let raw_key = seed_key_32(svc, "default");

        let dir = TempDir::new().unwrap();
        let mut audit_writer = test_audit_writer(&dir);
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = make_rule_proposal_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        let now_ms = timefmt::now_unix_ms().expect("clock");
        store.insert(entry, now_ms).unwrap();
        store.reject(&nonce, now_ms, 60_000).unwrap();

        let rejected_entry = store.get(&nonce).unwrap().clone();
        let err = attest_and_persist(
            &mut store,
            &rejected_entry,
            &raw_key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            ConsentAuthorization::Standard(&AttestedApprover::Local),
            |_req, _key| Err("must not be called".to_owned()),
        )
        .unwrap_err();
        assert_eq!(err.code(), "approval.rejected", "unexpected error: {err}");
    }

    #[test]
    fn attest_rule_refuses_stored_chain_mismatch() {
        let dir = TempDir::new().unwrap();
        let mut audit_writer = test_audit_writer(&dir);
        let mut store = PendingApprovalStore::open(dir.path().join("a.toml")).unwrap();
        let mut entry = make_rule_proposal_entry(DEFAULT_TTL_MS);
        let ApprovalKind::RuleProposalSimulated { chain_id, .. } = &mut entry.kind else {
            unreachable!()
        };
        "stellar:mainnet".clone_into(chain_id);
        store
            .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
            .unwrap();
        let error = attest_and_persist(
            &mut store,
            &entry,
            &[0x42; 32],
            &crate::approval::AttestationBinding::new("a", "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            ConsentAuthorization::Standard(&AttestedApprover::Local),
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "approval.binding_mismatch");
        assert!(
            store
                .get(&entry.approval_nonce)
                .unwrap()
                .attestation_blob_b64
                .is_none()
        );
    }

    #[test]
    fn attest_mpp_refuses_stored_profile_and_chain_mismatch() {
        for mismatch_profile in [true, false] {
            let dir = TempDir::new().unwrap();
            let mut audit_writer = test_audit_writer(&dir);
            let mut store = PendingApprovalStore::open(dir.path().join("a.toml")).unwrap();
            let now = timefmt::now_unix_ms().unwrap();
            let mut entry = crate::approval::fixtures::bind_mpp_entry(
                PendingApproval::new_mpp_charge_pending(
                    [0x11; 32],
                    [0x22; 32],
                    if mismatch_profile { "other" } else { "a" }.to_owned(),
                    "stellar:testnet".to_owned(),
                    "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                    "mcp".to_owned(),
                    "merchant".to_owned(),
                    "tools/charge".to_owned(),
                    "1000000".to_owned(),
                    "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
                    "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                    now / 1_000 + 3_600,
                    1_100,
                    "1000".to_owned(),
                    DEFAULT_TTL_MS,
                )
                .unwrap(),
            );
            store.insert(entry.clone(), now).unwrap();
            if !mismatch_profile
                && let ApprovalKind::MppChargeSimulated { chain_id, .. } = &mut entry.kind
            {
                *chain_id = "stellar:mainnet".to_owned();
            }
            let error = attest_and_persist(
                &mut store,
                &entry,
                &[0x42; 32],
                &crate::approval::AttestationBinding::new("a", "stellar:testnet"),
                Surface::Cli,
                ConsentAudit::Writer(&mut audit_writer),
                ConsentAuthorization::Standard(&AttestedApprover::Local),
                |_, _| Ok(()),
            )
            .unwrap_err();
            assert_eq!(error.code(), "approval.binding_mismatch");
            assert!(
                store
                    .get(&entry.approval_nonce)
                    .unwrap()
                    .attestation_blob_b64
                    .is_none()
            );
        }
    }

    // ── The consent row before the persist, per kind ─────────────────────────

    const BINDING_PROFILE: &str = "a";

    fn binding() -> crate::approval::AttestationBinding<'static> {
        crate::approval::AttestationBinding::new(BINDING_PROFILE, "stellar:testnet")
    }

    /// One pending entry of every attestable kind, labelled.
    fn every_attestable_kind() -> Vec<(&'static str, PendingApproval)> {
        let uid = process_uid_for_attestation().unwrap();
        let now = timefmt::now_unix_ms().unwrap();
        vec![
            ("PaymentSimulated", make_entry(DEFAULT_TTL_MS)),
            ("X402Payment", x402_entry(None)),
            ("TrustlineSimulated", trustline_entry()),
            (
                "ClaimSimulated",
                fixtures::claim_pending(
                    SOURCE,
                    [0x0a; 32],
                    Some(("XLM", 500)),
                    100,
                    1,
                    uid.clone(),
                    DEFAULT_TTL_MS,
                ),
            ),
            (
                "ToolsetFirstInvokeGate",
                PendingApproval::new_toolset_first_invoke_gate_pending(
                    "my-toolset".to_owned(),
                    "sign-payment".to_owned(),
                    "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                    "XLM".to_owned(),
                    0,
                    1_000_000,
                    uid.clone(),
                    DEFAULT_TTL_MS,
                )
                .unwrap(),
            ),
            (
                "TrustlineClawbackOptIn",
                PendingApproval::new_trustline_clawback_opt_in_pending(
                    "stellar:testnet".to_owned(),
                    "USDC".to_owned(),
                    "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_owned(),
                    uid,
                    DEFAULT_TTL_MS,
                )
                .unwrap(),
            ),
            (
                "RuleProposalSimulated",
                make_rule_proposal_entry(DEFAULT_TTL_MS),
            ),
            (
                "MppChargeSimulated",
                crate::approval::fixtures::bind_mpp_entry(
                    PendingApproval::new_mpp_charge_pending(
                        [0x11; 32],
                        [0x22; 32],
                        BINDING_PROFILE.to_owned(),
                        "stellar:testnet".to_owned(),
                        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                        "mcp".to_owned(),
                        "merchant".to_owned(),
                        "tools/charge".to_owned(),
                        "1000000".to_owned(),
                        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
                        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                        now / 1_000 + 3_600,
                        1_100,
                        "1000".to_owned(),
                        DEFAULT_TTL_MS,
                    )
                    .unwrap(),
                ),
            ),
        ]
    }

    /// Whether the store at `path`, read back from disk, still holds `nonce`
    /// as an unattested pending entry.
    fn still_pending(path: &std::path::Path, nonce: &str) -> bool {
        let store = PendingApprovalStore::open(path.to_path_buf()).unwrap();
        store
            .get(nonce)
            .is_some_and(|entry| entry.attestation_blob_b64.is_none())
    }

    fn consent_rows(dir: &TempDir) -> Vec<serde_json::Value> {
        std::fs::read_to_string(dir.path().join("audit").join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|row| row["kind"] == "approval_attested")
            .collect()
    }

    #[test]
    fn a_refusing_writer_sink_persists_nothing_for_any_kind() {
        for (kind, entry) in every_attestable_kind() {
            let dir = TempDir::new().unwrap();
            let store_path = dir.path().join("a.toml");
            let mut store = PendingApprovalStore::open(store_path.clone()).unwrap();
            let nonce = entry.approval_nonce.clone();
            store
                .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
                .unwrap();
            let mut writer = test_audit_writer(&dir);
            writer.set_appends_before_fault(Some(0));
            let mut grant_persisted = false;
            let err = attest_and_persist(
                &mut store,
                &entry,
                &[0x42; 32],
                &binding(),
                Surface::Cli,
                ConsentAudit::Writer(&mut writer),
                ConsentAuthorization::Standard(&AttestedApprover::Local),
                |_, _| {
                    grant_persisted = true;
                    Ok(())
                },
            )
            .unwrap_err();
            assert_eq!(err.code(), "audit.chain_key_unavailable", "{kind}: {err}");
            assert!(err.to_string().contains("audit.io_error"), "{kind}: {err}");
            drop(store);
            assert!(
                still_pending(&store_path, &nonce),
                "{kind}: nothing persisted"
            );
            assert!(!grant_persisted, "{kind}: no grant persisted");
            assert!(consent_rows(&dir).is_empty(), "{kind}");
        }
    }

    #[test]
    fn a_failing_outbox_sink_persists_nothing_for_any_kind() {
        for (kind, entry) in every_attestable_kind() {
            let dir = TempDir::new().unwrap();
            let store_path = dir.path().join("a.toml");
            let mut store = PendingApprovalStore::open(store_path.clone()).unwrap();
            let nonce = entry.approval_nonce.clone();
            store
                .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
                .unwrap();
            let outbox = AuditOutbox::for_log(
                &dir.path().join("audit").join("audit.jsonl"),
                std::sync::Arc::new(crate::audit_log::tip_anchor::InMemoryTipAnchorStore::new()),
            );
            crate::audit_log::outbox::test_seam::arm_partial_write(outbox.path(), 9);
            let mut grant_persisted = false;
            let result = attest_and_persist(
                &mut store,
                &entry,
                &[0x42; 32],
                &binding(),
                Surface::Cli,
                ConsentAudit::Outbox(&outbox),
                ConsentAuthorization::Standard(&AttestedApprover::Local),
                |_, _| {
                    grant_persisted = true;
                    Ok(())
                },
            );
            crate::audit_log::outbox::test_seam::disarm(outbox.path());
            let err = result.unwrap_err();
            assert_eq!(err.code(), "audit.chain_key_unavailable", "{kind}: {err}");
            drop(store);
            assert!(
                still_pending(&store_path, &nonce),
                "{kind}: nothing persisted"
            );
            assert!(!grant_persisted, "{kind}: no grant persisted");
            assert_eq!(
                std::fs::read(outbox.path()).unwrap_or_default(),
                Vec::<u8>::new(),
                "{kind}: the refused append leaves no line"
            );
        }
    }

    /// The row is durable before the persist runs: a persist that fails after
    /// it leaves the row and returns the failure.
    #[cfg(unix)]
    #[test]
    fn the_consent_row_precedes_the_persist_for_every_kind() {
        use std::os::unix::fs::PermissionsExt as _;

        for (kind, entry) in every_attestable_kind() {
            let dir = TempDir::new().unwrap();
            let store_dir = dir.path().join("store");
            std::fs::create_dir(&store_dir).unwrap();
            let store_path = store_dir.join("a.toml");
            let mut store = PendingApprovalStore::open(store_path.clone()).unwrap();
            store
                .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
                .unwrap();
            let mut writer = test_audit_writer(&dir);
            let audit_path = dir.path().join("audit").join("audit.jsonl");
            // The store cannot persist; the grant closure observes the log.
            std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
            let mut row_before_grant = None;
            let result = attest_and_persist(
                &mut store,
                &entry,
                &[0x42; 32],
                &binding(),
                Surface::Cli,
                ConsentAudit::Writer(&mut writer),
                ConsentAuthorization::Standard(&AttestedApprover::Local),
                |_, _| {
                    row_before_grant = Some(
                        std::fs::read_to_string(&audit_path)
                            .unwrap_or_default()
                            .contains(r#""kind":"approval_attested""#),
                    );
                    Err("grant store unavailable".to_owned())
                },
            );
            std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(result.is_err(), "{kind}: the persist failure is returned");
            let rows = consent_rows(&dir);
            assert_eq!(rows.len(), 1, "{kind}: the row was written first");
            assert_eq!(rows[0]["approval_kind"], kind);
            if kind == "TrustlineSimulated" {
                assert_eq!(rows[0]["gated_tool"], "stellar_trustline_commit");
            }
            if kind == "ToolsetFirstInvokeGate" {
                assert_eq!(row_before_grant, Some(true), "the row precedes the grant");
            }
        }
    }

    /// The store resolves the entry after the caller validated its copy. The
    /// mutation goes through the same locked handle `attest_and_persist`
    /// receives, which holds exactly what a fresh handle would read after
    /// another process wrote it.
    #[test]
    fn an_entry_attested_by_another_handle_since_validation_refuses_with_no_row() {
        for (kind, entry) in every_attestable_kind() {
            let dir = TempDir::new().unwrap();
            let mut store = PendingApprovalStore::open(dir.path().join("a.toml")).unwrap();
            store
                .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
                .unwrap();
            // `entry` is the validated copy. The store then resolves it.
            let expected_code = match kind {
                "TrustlineClawbackOptIn" => {
                    store
                        .record_trustline_clawback_opt_in_attestation(
                            &entry.approval_nonce,
                            [0x01; 32],
                            AttestedApprover::Local,
                        )
                        .unwrap();
                    "approval.already_attested"
                }
                "RuleProposalSimulated" => {
                    store
                        .record_rule_proposal_attestation(
                            &entry.approval_nonce,
                            [0x01; 32],
                            AttestedApprover::Local,
                        )
                        .unwrap();
                    "approval.already_attested"
                }
                "ToolsetFirstInvokeGate" => {
                    store.remove(&entry.approval_nonce).unwrap();
                    "approval.not_found"
                }
                _ => {
                    store
                        .record_attestation(
                            &entry.approval_nonce,
                            [0x01; 32],
                            AttestedApprover::Local,
                        )
                        .unwrap();
                    "approval.already_attested"
                }
            };
            let mut writer = test_audit_writer(&dir);
            let mut grant_persisted = false;
            let err = attest_and_persist(
                &mut store,
                &entry,
                &[0x42; 32],
                &binding(),
                Surface::Cli,
                ConsentAudit::Writer(&mut writer),
                ConsentAuthorization::Standard(&AttestedApprover::Local),
                |_, _| {
                    grant_persisted = true;
                    Ok(())
                },
            )
            .unwrap_err();
            assert_eq!(err.code(), expected_code, "{kind}: {err}");
            assert!(consent_rows(&dir).is_empty(), "{kind}: no row is written");
            assert!(!grant_persisted, "{kind}");
        }
    }

    /// Calls `attest_and_persist` with the validated copy `entry` against
    /// `store`, which already holds whatever another handle left there, and
    /// returns the refusal. A grant persisted on the way fails the test.
    fn attest_validated_copy(
        dir: &TempDir,
        store: &mut PendingApprovalStore,
        entry: &PendingApproval,
    ) -> WalletError {
        let mut writer = test_audit_writer(dir);
        let mut grant_persisted = false;
        let err = attest_and_persist(
            store,
            entry,
            &[0x42; 32],
            &binding(),
            Surface::Cli,
            ConsentAudit::Writer(&mut writer),
            ConsentAuthorization::Standard(&AttestedApprover::Local),
            |_, _| {
                grant_persisted = true;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(!grant_persisted, "no grant is persisted");
        err
    }

    /// The entry expired after the caller validated it. The re-read refuses
    /// before the row, so no row records a consent the store then refuses.
    #[test]
    fn an_entry_that_expired_since_validation_refuses_with_no_row() {
        for (kind, mut entry) in every_attestable_kind() {
            let dir = TempDir::new().unwrap();
            let store_path = dir.path().join("a.toml");
            let mut store = PendingApprovalStore::open(store_path.clone()).unwrap();
            entry.expires_at_unix_ms = entry.created_at_unix_ms + 1;
            store
                .insert(entry.clone(), entry.created_at_unix_ms)
                .unwrap();
            while !entry.is_expired(timefmt::now_unix_ms().unwrap()) {
                std::thread::yield_now();
            }

            let err = attest_validated_copy(&dir, &mut store, &entry);
            assert_eq!(err.code(), "approval.expired", "{kind}: {err}");
            assert!(consent_rows(&dir).is_empty(), "{kind}: no row is written");
            drop(store);
            let reopened = PendingApprovalStore::open(store_path).unwrap();
            let left = reopened.get(&entry.approval_nonce);
            assert!(
                left.is_some_and(|e| e.attestation_blob_b64.is_none()),
                "{kind}: nothing is persisted"
            );
        }
    }

    /// Another process replaced the entry under the same nonce with one of
    /// another lifetime. The attestation binds the lifetime, so the re-read
    /// compares both lifetime fields and refuses before the row; otherwise the
    /// stored entry would carry a blob over a lifetime it does not have.
    #[test]
    fn an_entry_whose_lifetime_changed_since_validation_refuses_with_no_row() {
        for (kind, entry) in every_attestable_kind() {
            for field in ["created", "expires"] {
                let dir = TempDir::new().unwrap();
                let store_path = dir.path().join("a.toml");
                let mut store = PendingApprovalStore::open(store_path.clone()).unwrap();
                let mut stored = entry.clone();
                if field == "created" {
                    stored.created_at_unix_ms -= 1;
                } else {
                    stored.expires_at_unix_ms += 1;
                }
                store
                    .insert(stored, timefmt::now_unix_ms().unwrap())
                    .unwrap();
                let err = attest_validated_copy(&dir, &mut store, &entry);
                assert_eq!(err.code(), "approval.wrong_kind", "{kind} {field}: {err}");
                assert!(consent_rows(&dir).is_empty(), "{kind} {field}");
                drop(store);
                assert!(
                    still_pending(&store_path, &entry.approval_nonce),
                    "{kind} {field}"
                );
            }
        }
    }

    /// Another process replaced the entry under the same nonce with one bound
    /// to another user. The re-read compares the `process_uid` as well as the
    /// kind, and refuses before the row.
    #[test]
    fn an_entry_whose_process_uid_changed_since_validation_refuses_with_no_row() {
        for (kind, entry) in every_attestable_kind() {
            let dir = TempDir::new().unwrap();
            let mut store = PendingApprovalStore::open(dir.path().join("a.toml")).unwrap();
            let mut stored = entry.clone();
            stored.process_uid = "4242424242".to_owned();
            assert_ne!(stored.process_uid, entry.process_uid);
            store
                .insert(stored, timefmt::now_unix_ms().unwrap())
                .unwrap();

            let err = attest_validated_copy(&dir, &mut store, &entry);
            assert_eq!(err.code(), "approval.wrong_kind", "{kind}: {err}");
            assert!(consent_rows(&dir).is_empty(), "{kind}: no row is written");
            let left = store.get(&entry.approval_nonce).unwrap();
            assert!(left.attestation_blob_b64.is_none(), "{kind}");
        }
    }

    #[test]
    fn a_rejected_entry_since_validation_refuses_with_its_own_code() {
        let entry = make_entry(DEFAULT_TTL_MS);
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("a.toml")).unwrap();
        store
            .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
            .unwrap();
        store
            .reject(
                &entry.approval_nonce,
                timefmt::now_unix_ms().unwrap(),
                60_000,
            )
            .unwrap();
        let err = attest_validated_copy(&dir, &mut store, &entry);
        assert_eq!(err.code(), "approval.rejected", "{err}");
        assert!(consent_rows(&dir).is_empty());
    }

    /// Another handle attested the entry and a commit spent it after the
    /// caller validated its unattested copy.
    #[test]
    fn a_consumed_entry_since_validation_refuses_with_its_own_code() {
        let entry = make_entry(DEFAULT_TTL_MS);
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("a.toml")).unwrap();
        store
            .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
            .unwrap();
        store
            .record_attestation(&entry.approval_nonce, [0x01; 32], AttestedApprover::Local)
            .unwrap();
        store
            .consume(
                &entry.approval_nonce,
                &"ab".repeat(32),
                crate::approval::ConsumedOutcome::Confirmed,
            )
            .unwrap();
        let err = attest_validated_copy(&dir, &mut store, &entry);
        assert_eq!(err.code(), "approval.consumed", "{err}");
        assert!(consent_rows(&dir).is_empty());
    }

    #[test]
    fn trustline_attest_persist_reload_returns_verifiable_blob() {
        for operator in [None, Some("dHJ1c3RsaW5lLW9wZXJhdG9y")] {
            let approver = match operator {
                Some(id) => AttestedApprover::Remote {
                    credential_id_b64url: id.to_owned(),
                },
                None => AttestedApprover::Local,
            };
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("trustline.toml");
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            let entry = trustline_entry();
            store
                .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
                .unwrap();
            let mut writer = test_audit_writer(&dir);
            let key = [42; 32];
            let binding = crate::approval::AttestationBinding::new("default", "stellar:testnet");
            let blob = attest_and_persist(
                &mut store,
                &entry,
                &key,
                &binding,
                if operator.is_some() {
                    Surface::ServeRemote
                } else {
                    Surface::Cli
                },
                ConsentAudit::Writer(&mut writer),
                ConsentAuthorization::Standard(&approver),
                |_, _| panic!("trustlines do not mint grants"),
            )
            .unwrap()
            .unwrap();
            drop(store);
            let reopened = PendingApprovalStore::open(path).unwrap();
            let persisted = reopened.get(&entry.approval_nonce).unwrap();
            assert_eq!(persisted.attestation_blob_b64.as_ref(), Some(&blob));
            assert_eq!(persisted.attestation_version, 4);
            assert!(persisted.attested_approver.as_ref() == Some(&approver));
            let bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(&blob).unwrap().try_into().unwrap();
            let ApprovalKind::TrustlineSimulated {
                envelope_xdr_b64, ..
            } = &entry.kind
            else {
                unreachable!()
            };
            let expected_digest = crate::approval::envelope_sha256(envelope_xdr_b64.as_bytes());
            assert!(crate::approval::verify_attestation(
                &key,
                &binding,
                &entry.approval_nonce,
                &expected_digest,
                &entry.process_uid,
                &persisted.attestation_scope().unwrap(),
                &bytes
            ));
            let log = std::fs::read_to_string(dir.path().join("audit/audit.jsonl")).unwrap();
            let rows: Vec<serde_json::Value> = log
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .filter(|row| {
                    row["kind"] == "approval_attested" || row["kind"] == "approval_attested_remote"
                })
                .collect();
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row["approval_kind"], "TrustlineSimulated");
            assert_eq!(row["gated_tool"], "stellar_trustline_commit");
            assert_eq!(
                row["envelope_sha256_hex"],
                expected_digest
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            assert_eq!(row["nonce_prefix"], entry.approval_nonce[..8]);
            if let Some(operator) = operator {
                assert_eq!(row["kind"], "approval_attested_remote");
                let digest = crate::approval::envelope_sha256(operator.as_bytes());
                assert_eq!(
                    row["operator_credential_id_redacted"],
                    digest[..4]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                );
                assert!(!log.contains(operator));
            } else {
                assert_eq!(row["kind"], "approval_attested");
                assert_eq!(row["origin"], "cli");
            }
        }
    }

    #[test]
    fn attest_refuses_creation_after_its_clock() {
        for (kind, mut entry) in every_attestable_kind() {
            entry.created_at_unix_ms = timefmt::now_unix_ms().unwrap() + 86_400_000;
            entry.expires_at_unix_ms = entry.created_at_unix_ms + DEFAULT_TTL_MS;
            let dir = TempDir::new().unwrap();
            let mut store = PendingApprovalStore::open(dir.path().join("pending.toml")).unwrap();
            store
                .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
                .unwrap();
            assert_eq!(
                attest_validated_copy(&dir, &mut store, &entry).code(),
                "approval.expired",
                "{kind}"
            );
            assert!(consent_rows(&dir).is_empty());
            assert!(
                store
                    .get(&entry.approval_nonce)
                    .unwrap()
                    .attestation_blob_b64
                    .is_none()
            );
        }
    }

    /// The direct mainnet confirmation rechecks the locked entry against the
    /// challenged snapshot: a changed process UID, an attestation by another
    /// handle, or a changed lifetime refuses with no row.
    #[test]
    #[serial_test::serial]
    fn mainnet_confirmation_rechecks_the_pending_entry() {
        use crate::approval::mainnet_fixtures::{ATTESTATION_KEY, MainnetConsentFixture};
        let fixture = MainnetConsentFixture::new("confirm");
        let policy = fixture.current_policy();
        for (kind, entry) in classic_entries() {
            for case in 0..3 {
                let dir = TempDir::new().unwrap();
                let mut store =
                    PendingApprovalStore::open(dir.path().join("pending.toml")).unwrap();
                let mut current = entry.clone();
                let expected = match case {
                    0 => {
                        current.process_uid = "999999".into();
                        "approval.wrong_kind"
                    }
                    1 => {
                        current.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode([1; 32]));
                        "approval.already_attested"
                    }
                    _ => {
                        current.expires_at_unix_ms -= 1;
                        "approval.wrong_kind"
                    }
                };
                store.insert(current, entry.created_at_unix_ms).unwrap();
                let presence = fixture.presence(&entry, &policy);
                let mut writer = test_audit_writer(&dir);
                assert_eq!(
                    attest_mainnet_confirmation(
                        &mut store,
                        &entry,
                        &ATTESTATION_KEY,
                        &fixture.binding(),
                        ConsentAudit::Writer(&mut writer),
                        "stellar_pay",
                        &policy,
                        presence,
                    )
                    .unwrap_err()
                    .code(),
                    expected,
                    "{kind} case {case}"
                );
                assert!(consent_rows(&dir).is_empty(), "{kind} case {case}");
            }
        }
    }

    /// The direct mainnet confirmation admits only classic transactions.
    #[test]
    #[serial_test::serial]
    fn mainnet_confirmation_refuses_non_classic_kinds() {
        use crate::approval::mainnet_fixtures::{ATTESTATION_KEY, MainnetConsentFixture};
        let fixture = MainnetConsentFixture::new("confirm");
        let policy = fixture.current_policy();
        let payment = fixture.payment(DEFAULT_TTL_MS);
        let presence = fixture.presence(&payment, &policy);
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("pending.toml")).unwrap();
        let opt_in = PendingApproval::new_trustline_clawback_opt_in_pending(
            "stellar:mainnet".to_owned(),
            "USDC".to_owned(),
            USDC_ISSUER.to_owned(),
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store
            .insert(opt_in.clone(), opt_in.created_at_unix_ms)
            .unwrap();
        let error = attest_mainnet_confirmation(
            &mut store,
            &opt_in,
            &ATTESTATION_KEY,
            &fixture.binding(),
            ConsentAudit::Writer(&mut test_audit_writer(&dir)),
            "stellar_trustline_commit",
            &policy,
            presence,
        )
        .unwrap_err();
        assert_eq!(error.code(), "approval.wrong_kind");
        assert!(consent_rows(&dir).is_empty());
    }

    fn x402_root(amount: i128) -> stellar_xdr::SorobanAuthorizedInvocation {
        use stellar_xdr::{
            AccountId, ContractId, Hash, InvokeContractArgs, PublicKey, ScAddress, ScVal,
            SorobanAuthorizedFunction, SorobanAuthorizedInvocation, Uint256,
        };
        let account = |byte| {
            ScVal::Address(ScAddress::Account(AccountId(
                PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32])),
            )))
        };
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([3; 32]))),
                function_name: "transfer".try_into().unwrap(),
                args: vec![account(4), account(5), ScVal::from(amount)]
                    .try_into()
                    .unwrap(),
            }),
            sub_invocations: vec![].try_into().unwrap(),
        }
    }

    fn x402_entry(domain: Option<&str>) -> PendingApproval {
        use sha2::{Digest as _, Sha256};
        PendingApproval::new_x402_pending(
            &Sha256::digest(
                crate::profile::caip2::Caip2::Testnet
                    .network_passphrase()
                    .as_bytes(),
            )
            .into(),
            &x402_root(10),
            domain.map(str::to_owned),
            "1000".into(),
            DEFAULT_TTL_MS,
        )
        .unwrap()
    }

    fn x402_attest(
        store: &mut PendingApprovalStore,
        entry: &PendingApproval,
        writer: &mut AuditWriter,
        surface: Surface,
    ) -> Result<(), WalletError> {
        attest_and_persist(
            store,
            entry,
            &[0x42; 32],
            &binding(),
            surface,
            ConsentAudit::Writer(writer),
            ConsentAuthorization::Standard(&AttestedApprover::Local),
            |_, _| panic!("no grant"),
        )
        .map(|_| ())
    }

    /// Whether the stored attestation of `entry` verifies over `subject`
    /// under the test key and binding.
    fn x402_verify(entry: &PendingApproval, subject: [u8; 32]) -> bool {
        let blob: [u8; 32] = URL_SAFE_NO_PAD
            .decode(entry.attestation_blob_b64.as_ref().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        crate::approval::verify_attestation(
            &[0x42; 32],
            &binding(),
            &entry.approval_nonce,
            &subject,
            &entry.process_uid,
            &entry.attestation_scope().unwrap(),
            &blob,
        )
    }

    /// The subject of a stored x402 entry on the test binding's network.
    fn x402_stored_subject(entry: &PendingApproval) -> Result<[u8; 32], WalletError> {
        let ApprovalKind::X402Payment {
            intent_digest,
            root_invocation_xdr,
            home_domain,
            ..
        } = &entry.kind
        else {
            unreachable!()
        };
        crate::approval::subject::verified_x402_subject(
            intent_digest,
            root_invocation_xdr,
            home_domain.as_deref(),
            crate::profile::caip2::Caip2::Testnet.network_passphrase(),
        )
    }

    #[test]
    #[serial_test::serial]
    fn x402_approval_round_trip() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pending.toml");
        let mut store = PendingApprovalStore::open(path.clone()).unwrap();
        let entry = x402_entry(None);
        let ApprovalKind::X402Payment { intent_digest, .. } = &entry.kind else {
            unreachable!()
        };
        let subject = crate::approval::subject::approval_subject_x402(intent_digest);
        store
            .insert(entry.clone(), entry.created_at_unix_ms)
            .unwrap();
        x402_attest(
            &mut store,
            &entry,
            &mut test_audit_writer(&dir),
            Surface::Cli,
        )
        .unwrap();
        drop(store);
        let store = PendingApprovalStore::open(path).unwrap();
        let entry = store.get(&entry.approval_nonce).unwrap();
        assert_eq!(x402_stored_subject(entry).unwrap(), subject);
        assert!(x402_verify(entry, subject));
        assert_eq!(
            consent_rows(&dir)[0]["gated_tool"],
            "stellar_x402_create_payment"
        );
    }

    #[test]
    #[serial_test::serial]
    fn x402_home_domain_selects_authenticated_subject() {
        keyring_mock::install().unwrap();
        for domain in [None, Some("merchant.example.invalid")] {
            let dir = TempDir::new().unwrap();
            let mut store = PendingApprovalStore::open(dir.path().join("pending.toml")).unwrap();
            let entry = x402_entry(domain);
            let ApprovalKind::X402Payment { intent_digest, .. } = &entry.kind else {
                unreachable!()
            };
            let subject = match domain {
                Some(domain) => crate::approval::subject::approval_subject_x402_authenticated(
                    intent_digest,
                    domain,
                ),
                None => crate::approval::subject::approval_subject_x402(intent_digest),
            };
            store
                .insert(entry.clone(), entry.created_at_unix_ms)
                .unwrap();
            x402_attest(
                &mut store,
                &entry,
                &mut test_audit_writer(&dir),
                Surface::Cli,
            )
            .unwrap();
            let stored = store.get(&entry.approval_nonce).unwrap();
            assert_eq!(x402_stored_subject(stored).unwrap(), subject);
            assert!(x402_verify(stored, subject));
        }
    }

    #[test]
    #[serial_test::serial]
    fn x402_home_domain_edit_breaks_attestation() {
        keyring_mock::install().unwrap();
        for (before, after) in [
            (None, Some("merchant.example.invalid")),
            (Some("merchant.example.invalid"), None),
            (
                Some("merchant.example.invalid"),
                Some("other.example.invalid"),
            ),
        ] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("pending.toml");
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            let entry = x402_entry(before);
            store
                .insert(entry.clone(), entry.created_at_unix_ms)
                .unwrap();
            x402_attest(
                &mut store,
                &entry,
                &mut test_audit_writer(&dir),
                Surface::Cli,
            )
            .unwrap();
            let attested = store.get(&entry.approval_nonce).unwrap().clone();
            assert!(x402_verify(
                &attested,
                x402_stored_subject(&attested).unwrap()
            ));
            let mut edited = attested.clone();
            let ApprovalKind::X402Payment { home_domain, .. } = &mut edited.kind else {
                unreachable!()
            };
            *home_domain = after.map(str::to_owned);
            let subject = x402_stored_subject(&edited).unwrap();
            assert!(!x402_verify(&edited, subject));
        }
    }

    #[test]
    #[serial_test::serial]
    fn x402_stored_digest_mismatch_refuses() {
        use stellar_xdr::WriteXdr as _;
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pending.toml");
        let mut store = PendingApprovalStore::open(path.clone()).unwrap();
        let entry = x402_entry(None);
        let ApprovalKind::X402Payment { intent_digest, .. } = &entry.kind else {
            unreachable!()
        };
        let subject = crate::approval::subject::approval_subject_x402(intent_digest);
        store
            .insert(entry.clone(), entry.created_at_unix_ms)
            .unwrap();
        x402_attest(
            &mut store,
            &entry,
            &mut test_audit_writer(&dir),
            Surface::Cli,
        )
        .unwrap();
        let attested = store.get(&entry.approval_nonce).unwrap().clone();
        assert_eq!(x402_stored_subject(&attested).unwrap(), subject);
        assert!(x402_verify(&attested, subject));
        drop(store);

        let mut edited = attested.clone();
        let ApprovalKind::X402Payment {
            root_invocation_xdr,
            ..
        } = &mut edited.kind
        else {
            unreachable!()
        };
        *root_invocation_xdr = x402_root(11)
            .to_xdr_base64(stellar_xdr::Limits::none())
            .unwrap();
        let error = x402_stored_subject(&edited).unwrap_err();
        assert_eq!(error.code(), "approval.attestation_invalid");
        assert!(
            error
                .to_string()
                .contains("the stored x402 invocation does not match its digest"),
            "{error}"
        );

        let mut pending = PendingApprovalStore::open(dir.path().join("unattested.toml")).unwrap();
        let mut unattested = x402_entry(None);
        let ApprovalKind::X402Payment { intent_digest, .. } = &mut unattested.kind else {
            unreachable!()
        };
        *intent_digest = [9; 32];
        pending
            .insert(unattested.clone(), unattested.created_at_unix_ms)
            .unwrap();
        let rows_before = consent_rows(&dir).len();
        assert_eq!(
            x402_attest(
                &mut pending,
                &unattested,
                &mut test_audit_writer(&dir),
                Surface::Cli
            )
            .unwrap_err()
            .code(),
            "approval.attestation_invalid"
        );
        assert!(
            pending
                .get(&unattested.approval_nonce)
                .unwrap()
                .attestation_blob_b64
                .is_none()
        );
        assert_eq!(consent_rows(&dir).len(), rows_before);
    }

    #[test]
    fn serve_refuses_x402_attest() {
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("pending.toml")).unwrap();
        let entry = x402_entry(None);
        store
            .insert(entry.clone(), entry.created_at_unix_ms)
            .unwrap();
        assert_eq!(
            x402_attest(
                &mut store,
                &entry,
                &mut test_audit_writer(&dir),
                Surface::Serve
            )
            .unwrap_err()
            .code(),
            "approval.wrong_kind"
        );
        assert!(
            store
                .get(&entry.approval_nonce)
                .unwrap()
                .attestation_blob_b64
                .is_none()
        );
        assert!(consent_rows(&dir).is_empty());
    }

    // ── The envelope the digest names ────────────────────────────────────────

    fn classic_entries() -> Vec<(&'static str, PendingApproval)> {
        vec![
            ("PaymentSimulated", make_entry(DEFAULT_TTL_MS)),
            ("TrustlineSimulated", trustline_entry()),
            (
                "ClaimSimulated",
                fixtures::claim_pending(
                    SOURCE,
                    [0x0a; 32],
                    None,
                    100,
                    1,
                    process_uid_for_attestation().unwrap(),
                    DEFAULT_TTL_MS,
                ),
            ),
        ]
    }

    /// Replaces the stored envelope of a classic entry and keeps its stored
    /// digest, so the digest no longer names the stored envelope.
    fn swap_envelope(entry: &mut PendingApproval, envelope: &str) {
        match &mut entry.kind {
            ApprovalKind::PaymentSimulated {
                envelope_xdr_b64, ..
            }
            | ApprovalKind::TrustlineSimulated {
                envelope_xdr_b64, ..
            }
            | ApprovalKind::ClaimSimulated {
                envelope_xdr_b64, ..
            } => envelope.clone_into(envelope_xdr_b64),
            other => panic!("not a classic entry: {}", other.kind_name()),
        }
    }

    /// A classic entry whose stored digest is not the digest of its stored
    /// envelope is refused before the consent row, and nothing is persisted:
    /// the surface would show one transaction while the attestation approves
    /// another.
    #[test]
    fn attestation_refuses_an_entry_whose_digest_is_not_its_envelopes() {
        let other =
            fixtures::payment_envelope(SOURCE, USDC_ISSUER, "XLM", 99_000_000, None, 100, 9);
        for (kind, mut entry) in classic_entries() {
            swap_envelope(&mut entry, &other);
            let dir = TempDir::new().unwrap();
            let store_path = dir.path().join("a.toml");
            let mut store = PendingApprovalStore::open(store_path.clone()).unwrap();
            store
                .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
                .unwrap();
            let err = attest_validated_copy(&dir, &mut store, &entry);
            assert_eq!(err.code(), "approval.entry_inconsistent", "{kind}: {err}");
            assert!(
                err.to_string()
                    .contains("the stored digest is not the digest of the stored envelope"),
                "{kind}: {err}"
            );
            drop(store);
            assert!(still_pending(&store_path, &entry.approval_nonce), "{kind}");
            assert!(consent_rows(&dir).is_empty(), "{kind}");
        }
    }

    /// An envelope that does not decode as the entry's kind is refused even
    /// when the stored digest is its digest, on the approve path and by the
    /// mainnet consent subject.
    #[test]
    fn attestation_refuses_an_entry_whose_envelope_does_not_decode() {
        let uid = process_uid_for_attestation().unwrap();
        let undecodable = PendingApproval::new_payment_pending(
            "AAAA".to_owned(),
            b"AAAA",
            DEST.to_owned(),
            1,
            "XLM".to_owned(),
            None,
            100,
            1,
            uid.clone(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let trust = fixtures::change_trust_envelope(SOURCE, "USDC", USDC_ISSUER, None, 100, 1);
        let wrong_operation = PendingApproval::new_payment_pending(
            trust.clone(),
            trust.as_bytes(),
            DEST.to_owned(),
            1,
            "XLM".to_owned(),
            None,
            100,
            1,
            uid,
            DEFAULT_TTL_MS,
        )
        .unwrap();
        for entry in [undecodable, wrong_operation] {
            let dir = TempDir::new().unwrap();
            let mut store = PendingApprovalStore::open(dir.path().join("a.toml")).unwrap();
            store
                .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
                .unwrap();
            let err = attest_validated_copy(&dir, &mut store, &entry);
            assert_eq!(err.code(), "approval.entry_inconsistent", "{err}");
            assert!(
                err.to_string()
                    .contains("the stored envelope does not decode"),
                "{err}"
            );
            let err = crate::approval::mainnet_consent_subject(
                &entry,
                &crate::approval::AttestationBinding::new(BINDING_PROFILE, "stellar:mainnet"),
            )
            .unwrap_err();
            assert_eq!(err.code(), "approval.entry_inconsistent", "{err}");
            assert!(consent_rows(&dir).is_empty());
            assert!(
                store
                    .get(&entry.approval_nonce)
                    .unwrap()
                    .attestation_blob_b64
                    .is_none()
            );
        }
    }

    /// An unedited entry of each kind attests its stored digest exactly as
    /// the attestation verifier expects.
    #[test]
    fn unedited_entries_attest_their_stored_subject() {
        let mut entries = classic_entries();
        entries.push(("X402Payment", x402_entry(None)));
        for (kind, entry) in entries {
            let subject = match &entry.kind {
                ApprovalKind::X402Payment {
                    intent_digest,
                    root_invocation_xdr,
                    home_domain,
                    ..
                } => crate::approval::subject::verified_x402_subject(
                    intent_digest,
                    root_invocation_xdr,
                    home_domain.as_deref(),
                    crate::profile::caip2::Caip2::Testnet.network_passphrase(),
                )
                .unwrap(),
                ApprovalKind::PaymentSimulated {
                    envelope_sha256_hex,
                    ..
                }
                | ApprovalKind::TrustlineSimulated {
                    envelope_sha256_hex,
                    ..
                }
                | ApprovalKind::ClaimSimulated {
                    envelope_sha256_hex,
                    ..
                } => decode_sha256_hex(envelope_sha256_hex).unwrap(),
                other => panic!("{}", other.kind_name()),
            };
            let dir = TempDir::new().unwrap();
            let mut store = PendingApprovalStore::open(dir.path().join("a.toml")).unwrap();
            store
                .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
                .unwrap();
            let blob = attest_and_persist(
                &mut store,
                &entry,
                &[0x42; 32],
                &binding(),
                Surface::Cli,
                ConsentAudit::Writer(&mut test_audit_writer(&dir)),
                ConsentAuthorization::Standard(&AttestedApprover::Local),
                |_, _| panic!("no grant"),
            )
            .unwrap()
            .unwrap();
            let blob: [u8; 32] = URL_SAFE_NO_PAD.decode(&blob).unwrap().try_into().unwrap();
            let stored = store.get(&entry.approval_nonce).unwrap();
            assert_eq!(
                blob,
                compute_attestation_v4(
                    &[0x42; 32],
                    &binding(),
                    &entry.approval_nonce,
                    &subject,
                    &entry.process_uid,
                    &stored.attested_lifetime(),
                    &AttestedApprover::Local,
                ),
                "{kind}"
            );
            let rows = consent_rows(&dir);
            assert_eq!(rows.len(), 1, "{kind}");
            assert_eq!(rows[0]["approval_kind"], kind);
        }
    }
    fn assert_edited_mpp_refused(edit_amount: bool) {
        let dir = TempDir::new().unwrap();
        let mut audit_writer = test_audit_writer(&dir);
        let mut store = PendingApprovalStore::open(dir.path().join("a.toml")).unwrap();
        let mut entry = super::super::fixtures::mpp_pending();
        if let ApprovalKind::MppChargeSimulated {
            amount, recipient, ..
        } = &mut entry.kind
        {
            if edit_amount {
                *amount = "7".to_owned();
            } else {
                *recipient = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned();
            }
        }
        store
            .insert(entry.clone(), entry.created_at_unix_ms)
            .unwrap();
        let error = attest_and_persist(
            &mut store,
            &entry,
            &[0x42; 32],
            &crate::approval::AttestationBinding::new("a", "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            ConsentAuthorization::Standard(&AttestedApprover::Local),
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "approval.entry_inconsistent");
        assert!(
            store
                .get(&entry.approval_nonce)
                .unwrap()
                .attestation_blob_b64
                .is_none()
        );
    }
    #[test]
    fn edited_mpp_amount_is_refused_at_attestation() {
        assert_edited_mpp_refused(true);
    }
    #[test]
    fn edited_mpp_recipient_is_refused_at_attestation() {
        assert_edited_mpp_refused(false);
    }
}
