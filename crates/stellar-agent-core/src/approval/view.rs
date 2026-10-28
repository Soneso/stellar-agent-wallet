//! Read-only, redacted snapshot views over [`PendingApproval`] entries.
//!
//! [`PendingApprovalStore::snapshot`](super::store::PendingApprovalStore::snapshot)
//! is the only way to enumerate the store's contents from outside this crate
//! — `entries` stays private on the store itself. Every field exposed here is
//! either public on-chain data or already redacted, matching the CLI
//! `approve --id <nonce> --profile <name>` wallet-controlled summary. The CLI and
//! resident approval-inbox servers share this non-secret rendering.

use serde::Serialize;

use crate::envelope_decode::{ClassicMemo, ClassicOperation, ClassicSummary};

use super::attest::classic_entry_summary;
use super::rule_proposal::ContextRuleProposalSnapshot;
use super::store::{ApprovalKind, PendingApproval, redact_g_strkey, redact_tx_hash};

/// Read-only, non-secret view of a single pending approval entry.
///
/// Never carries raw secret material: `SignWithPasskey` / `RegisterPasskey`
/// byte fields (`auth_digest`, `credential_id`, `csrf_token`, `user_handle`)
/// and the `attestation_blob_b64` contents never appear here — only the same
/// redacted / summary fields the CLI `approve --id <nonce> --profile <name>` prompt renders.
///
/// `Serialize` renders every field as JSON with no additional redaction: the
/// fields on this type are already the non-secret, wallet-controlled summary
/// (the same discipline as [`super::attestation`]'s digest-only surfaces), so
/// this is the direct wire shape for `approve list` and any future
/// approval-inbox surface.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct PendingApprovalView {
    /// Wallet-issued approval identifier
    /// (see [`PendingApproval::approval_nonce`]).
    pub approval_nonce: String,

    /// [`ApprovalKind::kind_name`] discriminator string.
    pub kind_name: &'static str,

    /// Unix epoch timestamp (milliseconds) when this entry was created — or,
    /// for an [`ApprovalKind::Rejected`] tombstone, when it was rejected.
    pub created_at_unix_ms: u64,

    /// Unix epoch timestamp (milliseconds) when this entry expires.
    pub expires_at_unix_ms: u64,

    /// Rule-provided explanation for requiring operator approval.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// `true` if `expires_at_unix_ms <= now_unix_ms` at snapshot time.
    pub expired: bool,

    /// `true` if the entry already carries a recorded operator consent: an
    /// HMAC attestation (`PaymentSimulated` / `ClaimSimulated` / `TrustlineSimulated` /
    /// `TrustlineClawbackOptIn` / `RuleProposalSimulated` / `MppChargeSimulated`)
    /// or a WebAuthn result (`SignWithPasskey` /
    /// `RegisterPasskey`).
    ///
    /// Always `false` for `ToolsetFirstInvokeGate` (approval consumes the
    /// entry immediately, so an entry of this kind in a snapshot is by
    /// definition not yet approved) and for `Rejected` (a rejection, not an
    /// attestation).
    pub attested: bool,

    /// Kind-specific, non-secret summary fields.
    pub summary: ApprovalSummaryView,
}

/// Kind-specific summary fields rendered for [`PendingApprovalView::summary`].
///
/// Mirrors the wallet-controlled rendering in the CLI `approve --id <nonce> --profile <name>` prompt:
/// every field here is either public on-chain data or already redacted.
///
/// Serialises as a JSON object tagged with a `"kind"` discriminator
/// (`"payment"`, `"trustline"`, `"claim"`, `"inconsistent"`, `"sign_with_passkey"`,
/// `"register_passkey"`, `"toolset_first_invoke_gate"`, `"trustline_clawback_opt_in"`,
/// `"rule_proposal"`, `"rejected"`), the same tagging convention as
/// `stellar_agent_stablecoin::preview::GateDecisionView`.
///
/// Every value-denominated field (`amount_stroops`, `fee_stroops`,
/// `limit_stroops`, `amount_min_stroops`, `amount_max_stroops`) is encoded as a decimal
/// string via [`crate::wire_stroops`]: a JSON number backed by `f64` cannot
/// represent an `i64`/`u32` stroop amount exactly once it exceeds `2^53`.
/// `seq_num` and rule id lists are counts/ids, not value-denominated, and
/// stay plain JSON numbers. The internal Rust field types are unchanged —
/// only the served wire encoding differs — so the store schema and every
/// in-crate consumer of these variants by field access are unaffected.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ApprovalSummaryView {
    /// An x402 payment intent and its authenticated domain.
    ///
    /// The payee, the amount and the token contract are decoded from the
    /// stored invocation, and all three are absent when that invocation is
    /// not one `transfer(from, to, amount)` call.
    X402Payment {
        /// Payee address.
        payee: Option<String>,
        /// Decimal token amount.
        amount: Option<String>,
        /// Token contract address.
        asset: Option<String>,
        /// Authenticated home domain.
        home_domain: Option<String>,
    },

    /// [`ApprovalKind::PaymentSimulated`] summary, decoded from the envelope.
    ///
    /// Covers payments, path payments and account creation; for an account
    /// creation `to` is the new account, `amount_stroops` its starting
    /// balance and `asset` is `"XLM"`.
    Payment {
        /// Effective source G-strkey.
        source: String,
        /// Destination as the envelope names it: a G-strkey, or an M-strkey
        /// for a muxed destination.
        to: String,
        /// Amount the source pays in stroops, decimal-string encoded on the
        /// wire (see [`stellar_agent_core::wire_stroops`](crate::wire_stroops)).
        /// For a path payment, the most it pays.
        #[serde(with = "crate::wire_stroops::i64")]
        amount_stroops: i64,
        /// Asset the source pays (`"XLM"` or `"<code>:<issuer>"`).
        asset: String,
        /// For a path payment, the asset the destination receives.
        #[serde(skip_serializing_if = "Option::is_none")]
        dest_asset: Option<String>,
        /// For a path payment, the amount the destination receives (at least
        /// this much for a strict send), decimal-string encoded.
        #[serde(
            with = "crate::wire_stroops::i64_opt",
            skip_serializing_if = "Option::is_none"
        )]
        dest_amount_stroops: Option<i64>,
        /// The signed memo with its type preserved.
        memo: ClassicMemo,
        /// Transaction fee in stroops, decimal-string encoded.
        #[serde(with = "crate::wire_stroops::u32")]
        fee_stroops: u32,
        /// Transaction sequence number.
        seq_num: i64,
    },

    /// [`ApprovalKind::TrustlineSimulated`] summary, decoded from the
    /// envelope.
    Trustline {
        /// Trustline holder: the effective source G-strkey.
        holder: String,
        /// Asset code.
        asset_code: String,
        /// Full issuer G-strkey the operator consents to trust.
        asset_issuer: String,
        /// Exact limit in stroops; `None` means unlimited.
        #[serde(with = "crate::wire_stroops::i64_opt")]
        limit_stroops: Option<i64>,
        /// Transaction fee in stroops.
        #[serde(with = "crate::wire_stroops::u32")]
        fee_stroops: u32,
        /// Transaction sequence number.
        seq_num: i64,
        /// The signed memo and its type.
        memo: ClassicMemo,
    },

    /// [`ApprovalKind::ClaimSimulated`] summary, decoded from the envelope.
    ///
    /// The envelope names the balance by id only; the balance's asset and
    /// amount are ledger state the signed transaction does not carry.
    Claim {
        /// `B...` strkey rendering of the balance id.
        balance_id_strkey: String,
        /// Claiming account: the effective source G-strkey.
        source: String,
        /// Transaction fee in stroops, decimal-string encoded.
        #[serde(with = "crate::wire_stroops::u32")]
        fee_stroops: u32,
        /// Transaction sequence number.
        seq_num: i64,
        /// The signed memo and its type.
        memo: ClassicMemo,
    },

    /// A classic or MPP entry
    /// whose stored digest is not the digest of its stored envelope, or whose
    /// envelope does not decode, or whose MPP terms fail fingerprint verification.
    /// It cannot be approved; it can be rejected.
    Inconsistent {
        /// `kind_name()` of the entry.
        original_kind_name: String,
        /// Why the entry cannot be shown or approved.
        reason: String,
    },

    /// [`ApprovalKind::SignWithPasskey`] summary fields.
    SignWithPasskey {
        /// First-5-last-5 redacted smart-account C-strkey.
        smart_account_redacted: String,
        /// OZ context rule IDs being satisfied.
        rule_ids: Vec<u32>,
        /// WebAuthn Relying Party identifier.
        rp_id: String,
    },

    /// [`ApprovalKind::RegisterPasskey`] summary fields.
    RegisterPasskey {
        /// First-5-last-5 redacted smart-account C-strkey.
        smart_account_redacted: String,
        /// OZ context rule IDs being registered.
        rule_ids: Vec<u32>,
        /// WebAuthn Relying Party identifier.
        rp_id: String,
    },

    /// [`ApprovalKind::ToolsetFirstInvokeGate`] summary fields.
    ToolsetFirstInvokeGate {
        /// Toolset name requesting the capability.
        toolset_name: String,
        /// Signing-adjacent capability token requested.
        capability: String,
        /// First-5-last-5 redacted destination G-strkey.
        destination_redacted: String,
        /// Asset identifier.
        asset: String,
        /// Minimum grant-bucket bound in stroops, decimal-string encoded.
        #[serde(with = "crate::wire_stroops::i64")]
        amount_min_stroops: i64,
        /// Maximum grant-bucket bound in stroops, decimal-string encoded.
        #[serde(with = "crate::wire_stroops::i64")]
        amount_max_stroops: i64,
    },

    /// [`ApprovalKind::TrustlineClawbackOptIn`] summary fields.
    TrustlineClawbackOptIn {
        /// CAIP-2 chain id.
        network: String,
        /// Asset code.
        code: String,
        /// First-5-last-5 redacted issuer G-strkey.
        issuer_redacted: String,
    },

    /// [`ApprovalKind::RuleProposalSimulated`] summary fields (Package D, GH
    /// issue #8).
    ///
    /// Carries the FULL resolved rule definition (`definition`) — not just a
    /// flattened summary — because Leg 3's approval surfaces render every
    /// operator-relevant field (context type, every signer with its
    /// proposer tag, every policy, the override flags) so the operator
    /// consents to exactly what will be installed. This is the same "shown
    /// in full, non-secret" posture as `Payment` / `Claim`: every field here
    /// is either public on-chain data or already redacted (`smart_account`
    /// itself is never exposed — only its redaction).
    RuleProposal {
        /// First-5-last-5 redacted smart-account C-strkey.
        smart_account_redacted: String,
        /// Network passphrase the proposal was simulated against.
        network_passphrase: String,
        /// CAIP-2 chain ID.
        chain_id: String,
        /// The fully-resolved rule definition snapshot.
        definition: ContextRuleProposalSnapshot,
        /// Hex-encoded `proposal_sha256` digest.
        proposal_sha256_hex: String,
        /// Pre-computed, non-secret one-line summary.
        summary_line: String,
    },

    /// [`ApprovalKind::MppChargeSimulated`] operator-visible terms.
    MppCharge {
        /// Owning wallet profile.
        profile: String,
        /// CAIP-2 chain identifier.
        chain_id: String,
        /// First-5-last-5 redacted payer G-strkey.
        payer_redacted: String,
        /// Bound request transport.
        transport: String,
        /// Bound HTTPS authority or MCP server identifier.
        authority: String,
        /// Bound HTTP path or MCP operation name.
        target: String,
        /// Canonical token amount.
        amount: String,
        /// Asset-contract C-strkey.
        currency: String,
        /// First-5-last-5 redacted recipient G- or C-strkey.
        recipient_redacted: String,
        /// Challenge expiry as Unix seconds.
        challenge_expires_at_unix: u64,
        /// Simulated transaction fee in stroops, decimal-string encoded.
        #[serde(with = "crate::wire_stroops::u32")]
        simulated_fee_stroops: u32,
    },

    /// [`ApprovalKind::Rejected`] tombstone — carries no summary data, only
    /// the kind name of the entry that was rejected.
    Rejected {
        /// `kind_name()` of the entry before it was rejected.
        original_kind_name: String,
    },

    /// [`ApprovalKind::Consumed`] tombstone — carries no summary data, only
    /// the kind name of the entry that was consumed, the transaction it was
    /// spent on, and what is known about that transaction.
    Consumed {
        /// `kind_name()` of the entry before it was consumed.
        original_kind_name: String,
        /// First-8-last-8 redaction of the transaction hash the approval was
        /// spent on.
        tx_hash_redacted: String,
        /// `confirmed` when the transaction reached a ledger, `unknown` while
        /// its outcome is still to be reconciled.
        outcome: String,
    },
}

/// Formats a trustline limit for wallet-controlled approval surfaces.
#[must_use]
pub fn format_trustline_limit(limit_stroops: Option<i64>) -> String {
    match limit_stroops {
        None => "unlimited".to_owned(),
        Some(0) => "0 stroops (removes the trustline)".to_owned(),
        Some(n) => format!("{n} stroops"),
    }
}

/// The summary of a classic entry, decoded from its envelope, or
/// [`ApprovalSummaryView::Inconsistent`] when the entry fails
/// [`classic_entry_summary`].
fn classic_summary_view(kind: &ApprovalKind) -> ApprovalSummaryView {
    let inconsistent = |reason: String| ApprovalSummaryView::Inconsistent {
        original_kind_name: kind.kind_name().to_owned(),
        reason,
    };
    let summary = match classic_entry_summary(kind) {
        Some(Ok(summary)) => summary,
        Some(Err(error)) => return inconsistent(error.message()),
        None => return inconsistent("the entry holds no classic transaction".to_owned()),
    };
    let ClassicSummary {
        source,
        fee_stroops,
        seq_num,
        memo,
        operation,
    } = summary;
    // `classic_entry_summary` decodes each kind with the operations that kind
    // accepts, so the operation determines the view.
    match operation {
        ClassicOperation::Payment {
            destination,
            asset,
            amount_stroops,
        } => ApprovalSummaryView::Payment {
            source,
            to: destination,
            amount_stroops,
            asset,
            dest_asset: None,
            dest_amount_stroops: None,
            memo,
            fee_stroops,
            seq_num,
        },
        ClassicOperation::PathPayment {
            destination,
            send_asset,
            send_amount_stroops,
            dest_asset,
            dest_amount_stroops,
        } => ApprovalSummaryView::Payment {
            source,
            to: destination,
            amount_stroops: send_amount_stroops,
            asset: send_asset,
            dest_asset: Some(dest_asset),
            dest_amount_stroops: Some(dest_amount_stroops),
            memo,
            fee_stroops,
            seq_num,
        },
        ClassicOperation::CreateAccount {
            destination,
            starting_balance_stroops,
        } => ApprovalSummaryView::Payment {
            source,
            to: destination,
            amount_stroops: starting_balance_stroops,
            asset: "XLM".to_owned(),
            dest_asset: None,
            dest_amount_stroops: None,
            memo,
            fee_stroops,
            seq_num,
        },
        ClassicOperation::ChangeTrust {
            asset_code,
            asset_issuer,
            limit_stroops,
        } => ApprovalSummaryView::Trustline {
            holder: source,
            asset_code,
            asset_issuer,
            limit_stroops,
            fee_stroops,
            seq_num,
            memo,
        },
        ClassicOperation::ClaimClaimableBalance {
            balance_id_strkey, ..
        } => ApprovalSummaryView::Claim {
            balance_id_strkey,
            source,
            fee_stroops,
            seq_num,
            memo,
        },
    }
}

impl PendingApprovalView {
    /// Builds a redacted view from a stored entry.
    ///
    /// A classic entry's summary is decoded from its envelope; its stored
    /// `summary_*` fields are not read.
    pub(super) fn from_entry(entry: &PendingApproval, now_unix_ms: u64) -> Self {
        let attested = match &entry.kind {
            ApprovalKind::X402Payment { .. }
            | ApprovalKind::PaymentSimulated { .. }
            | ApprovalKind::ClaimSimulated { .. }
            | ApprovalKind::TrustlineSimulated { .. }
            | ApprovalKind::TrustlineClawbackOptIn { .. }
            | ApprovalKind::RuleProposalSimulated { .. }
            | ApprovalKind::MppChargeSimulated { .. } => entry.attestation_blob_b64.is_some(),
            ApprovalKind::SignWithPasskey { .. } => entry.passkey_assertion.is_some(),
            ApprovalKind::RegisterPasskey {
                registration_input, ..
            } => registration_input.is_some(),
            ApprovalKind::ToolsetFirstInvokeGate { .. }
            | ApprovalKind::Rejected { .. }
            | ApprovalKind::Consumed { .. } => false,
        };

        let summary = if let Err(error) = super::mpp::verify_mpp_entry_terms(&entry.kind) {
            ApprovalSummaryView::Inconsistent {
                original_kind_name: entry.kind.kind_name().to_owned(),
                reason: error.message(),
            }
        } else {
            match &entry.kind {
                ApprovalKind::X402Payment {
                    root_invocation_xdr,
                    home_domain,
                    ..
                } => {
                    use stellar_xdr::ReadXdr as _;
                    let terms = stellar_xdr::SorobanAuthorizedInvocation::from_xdr_base64(
                        root_invocation_xdr,
                        stellar_agent_xdr_limits::untrusted_decode_limits(
                            root_invocation_xdr.len(),
                        ),
                    )
                    .ok()
                    .as_ref()
                    .and_then(super::store::x402_transfer_terms);
                    ApprovalSummaryView::X402Payment {
                        payee: terms.as_ref().map(|terms| terms.payee.clone()),
                        amount: terms.as_ref().map(|terms| terms.amount.to_string()),
                        asset: terms.map(|terms| terms.asset),
                        home_domain: home_domain.clone(),
                    }
                }

                ApprovalKind::PaymentSimulated { .. }
                | ApprovalKind::TrustlineSimulated { .. }
                | ApprovalKind::ClaimSimulated { .. } => classic_summary_view(&entry.kind),
                ApprovalKind::SignWithPasskey {
                    smart_account_redacted,
                    rule_ids,
                    rp_id,
                    ..
                } => ApprovalSummaryView::SignWithPasskey {
                    smart_account_redacted: smart_account_redacted.clone(),
                    rule_ids: rule_ids.clone(),
                    rp_id: rp_id.clone(),
                },
                ApprovalKind::RegisterPasskey {
                    smart_account_redacted,
                    rule_ids,
                    rp_id,
                    ..
                } => ApprovalSummaryView::RegisterPasskey {
                    smart_account_redacted: smart_account_redacted.clone(),
                    rule_ids: rule_ids.clone(),
                    rp_id: rp_id.clone(),
                },
                ApprovalKind::ToolsetFirstInvokeGate {
                    toolset_name,
                    capability,
                    destination,
                    asset,
                    amount_min_stroops,
                    amount_max_stroops,
                } => ApprovalSummaryView::ToolsetFirstInvokeGate {
                    toolset_name: toolset_name.clone(),
                    capability: capability.clone(),
                    destination_redacted: redact_g_strkey(destination),
                    asset: asset.clone(),
                    amount_min_stroops: *amount_min_stroops,
                    amount_max_stroops: *amount_max_stroops,
                },
                ApprovalKind::TrustlineClawbackOptIn {
                    network,
                    code,
                    issuer,
                } => ApprovalSummaryView::TrustlineClawbackOptIn {
                    network: network.clone(),
                    code: code.clone(),
                    issuer_redacted: redact_g_strkey(issuer),
                },
                ApprovalKind::RuleProposalSimulated {
                    smart_account_redacted,
                    network_passphrase,
                    chain_id,
                    definition,
                    proposal_sha256,
                    summary_line,
                    ..
                } => ApprovalSummaryView::RuleProposal {
                    smart_account_redacted: smart_account_redacted.clone(),
                    network_passphrase: network_passphrase.clone(),
                    chain_id: chain_id.clone(),
                    definition: definition.clone(),
                    proposal_sha256_hex: proposal_sha256
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect(),
                    summary_line: summary_line.clone(),
                },
                ApprovalKind::MppChargeSimulated {
                    profile,
                    chain_id,
                    payer,
                    transport,
                    authority,
                    target,
                    amount,
                    currency,
                    recipient,
                    challenge_expires_at_unix,
                    simulated_fee_stroops,
                    ..
                } => ApprovalSummaryView::MppCharge {
                    profile: profile.clone(),
                    chain_id: chain_id.clone(),
                    payer_redacted: redact_g_strkey(payer),
                    transport: transport.clone(),
                    authority: authority.clone(),
                    target: target.clone(),
                    amount: amount.clone(),
                    currency: currency.clone(),
                    recipient_redacted: redact_g_strkey(recipient),
                    challenge_expires_at_unix: *challenge_expires_at_unix,
                    simulated_fee_stroops: *simulated_fee_stroops,
                },
                ApprovalKind::Rejected { original_kind_name } => ApprovalSummaryView::Rejected {
                    original_kind_name: original_kind_name.clone(),
                },
                ApprovalKind::Consumed {
                    original_kind_name,
                    tx_hash,
                    outcome,
                } => ApprovalSummaryView::Consumed {
                    original_kind_name: original_kind_name.clone(),
                    tx_hash_redacted: redact_tx_hash(tx_hash),
                    outcome: outcome.label().to_owned(),
                },
            }
        };

        Self {
            approval_nonce: entry.approval_nonce.clone(),
            kind_name: entry.kind.kind_name(),
            created_at_unix_ms: entry.created_at_unix_ms,
            expires_at_unix_ms: entry.expires_at_unix_ms,
            reason: entry.reason.clone(),
            expired: entry.is_expired(now_unix_ms),
            attested,
            summary,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    // ChangeTrust with transaction source [1; 32] and operation source [2; 32].
    const CHANGE_TRUST_ENVELOPE: &str = concat!(
        "AAAAAgAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAGQAAAAAAAAAAQAAAAAA",
        "AAAAAAAAAQAAAAEAAAAAAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAAAAGAAAAAVVT",
        "REMAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAR//////////wAAAAAAAAAA",
    );

    use super::super::fixtures;
    use super::super::store::{DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore};
    use super::super::user_id::process_uid_for_attestation;
    use super::*;
    use tempfile::TempDir;

    const TEST_NOW_MS: u64 = 1_700_000_000_000;
    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
    const TESTNET_USDC_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
    const SOURCE: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    const DEST: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
    const OTHER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    /// The operation source of `CHANGE_TRUST_ENVELOPE`: the key `[2; 32]`.
    const OP_SOURCE: &str = "GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA";
    /// The issuer of `CHANGE_TRUST_ENVELOPE`: the key `[4; 32]`.
    const ISSUER_04: &str = "GACAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAJJHP";

    fn uid() -> String {
        process_uid_for_attestation().expect("UID available on test host")
    }

    fn open_store(dir: &TempDir) -> PendingApprovalStore {
        PendingApprovalStore::open(dir.path().join("default.toml")).unwrap()
    }

    #[test]
    fn snapshot_of_empty_store_is_empty() {
        let dir = TempDir::new().unwrap();
        let store = open_store(&dir);
        assert!(store.snapshot(TEST_NOW_MS).is_empty());
    }

    #[test]
    fn snapshot_renders_payment_simulated() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = fixtures::payment_pending(
            SOURCE,
            DEST,
            "XLM",
            2_500_000,
            Some("hello"),
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        );
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let views = store.snapshot(TEST_NOW_MS);
        assert_eq!(views.len(), 1);
        let view = &views[0];
        assert_eq!(view.approval_nonce, nonce);
        assert_eq!(view.kind_name, "PaymentSimulated");
        assert!(!view.expired);
        assert!(!view.attested);
        assert_eq!(
            view.summary,
            ApprovalSummaryView::Payment {
                source: SOURCE.to_owned(),
                to: DEST.to_owned(),
                amount_stroops: 2_500_000,
                asset: "XLM".to_owned(),
                dest_asset: None,
                dest_amount_stroops: None,
                memo: ClassicMemo::Text("hello".to_owned()),
                fee_stroops: 100,
                seq_num: 1,
            }
        );
    }

    #[test]
    fn snapshot_marks_payment_attested_after_record_attestation() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = fixtures::payment_pending(
            SOURCE,
            DEST,
            "XLM",
            1_000,
            None,
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        );
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();
        store.record_attestation(&nonce, [0x11u8; 32]).unwrap();

        let views = store.snapshot(TEST_NOW_MS);
        assert!(
            views[0].attested,
            "attested payment must report attested=true"
        );
    }

    #[test]
    fn snapshot_renders_claim_simulated() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = fixtures::claim_pending(
            SOURCE,
            [0x0a; 32],
            Some(("XLM", 500)),
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        );
        store.insert(entry, TEST_NOW_MS).unwrap();

        let views = store.snapshot(TEST_NOW_MS);
        assert_eq!(views[0].kind_name, "ClaimSimulated");
        assert_eq!(
            views[0].summary,
            ApprovalSummaryView::Claim {
                balance_id_strkey: fixtures::balance_ids([0x0a; 32]).1,
                source: SOURCE.to_owned(),
                fee_stroops: 100,
                seq_num: 1,
                memo: ClassicMemo::None,
            }
        );
    }

    #[test]
    fn snapshot_renders_sign_with_passkey() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = PendingApproval::new_passkey_pending(
            [0x01u8; 32],
            vec![0u8; 32],
            "CAAAA...BBBBB".to_owned(),
            vec![0],
            [0x02u8; 32],
            "localhost".to_owned(),
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let views = store.snapshot(TEST_NOW_MS);
        assert_eq!(views[0].kind_name, "SignWithPasskey");
        assert!(!views[0].attested);
        assert!(matches!(
            views[0].summary,
            ApprovalSummaryView::SignWithPasskey { .. }
        ));
    }

    #[test]
    fn snapshot_renders_register_passkey() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = PendingApproval::new_register_passkey_pending(
            "CAAAA...BBBBB".to_owned(),
            vec![0],
            [0x03u8; 32],
            "localhost".to_owned(),
            [0x04u8; 32],
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let views = store.snapshot(TEST_NOW_MS);
        assert_eq!(views[0].kind_name, "RegisterPasskey");
        assert!(matches!(
            views[0].summary,
            ApprovalSummaryView::RegisterPasskey { .. }
        ));
    }

    #[test]
    fn snapshot_renders_toolset_first_invoke_gate() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "sign-payment".to_owned(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "XLM".to_owned(),
            0,
            1_000_000,
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let views = store.snapshot(TEST_NOW_MS);
        assert_eq!(views[0].kind_name, "ToolsetFirstInvokeGate");
        assert!(!views[0].attested);
        match &views[0].summary {
            ApprovalSummaryView::ToolsetFirstInvokeGate {
                toolset_name,
                destination_redacted,
                ..
            } => {
                assert_eq!(toolset_name, "my-toolset");
                assert!(destination_redacted.contains("..."));
            }
            other => panic!("expected ToolsetFirstInvokeGate summary, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_renders_trustline_clawback_opt_in() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
            TESTNET_PASSPHRASE.to_owned(),
            "USDC".to_owned(),
            TESTNET_USDC_ISSUER.to_owned(),
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let views = store.snapshot(TEST_NOW_MS);
        assert_eq!(views[0].kind_name, "TrustlineClawbackOptIn");
        match &views[0].summary {
            ApprovalSummaryView::TrustlineClawbackOptIn {
                issuer_redacted, ..
            } => {
                assert!(issuer_redacted.contains("..."));
                assert!(!issuer_redacted.contains(TESTNET_USDC_ISSUER));
            }
            other => panic!("expected TrustlineClawbackOptIn summary, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_renders_rejected_tombstone_with_no_summary_data() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = fixtures::payment_pending(
            SOURCE,
            DEST,
            "XLM",
            1_000,
            None,
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        );
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();
        store.reject(&nonce, TEST_NOW_MS, 60_000).unwrap();

        let views = store.snapshot(TEST_NOW_MS);
        assert_eq!(views[0].kind_name, "Rejected");
        assert!(!views[0].attested);
        match &views[0].summary {
            ApprovalSummaryView::Rejected { original_kind_name } => {
                assert_eq!(original_kind_name, "PaymentSimulated");
            }
            other => panic!("expected Rejected summary, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_renders_rule_proposal_simulated() {
        use super::super::rule_proposal::{
            ContextRuleProposalSnapshot, RuleProposalContextType, RuleProposalSigner,
        };

        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
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
        let entry = PendingApproval::new_rule_proposal_pending(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            TESTNET_PASSPHRASE.to_owned(),
            "stellar:testnet".to_owned(),
            definition,
            [0x99u8; 32],
            "CallContract rule \"spend-daily\"".to_owned(),
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let views = store.snapshot(TEST_NOW_MS);
        assert_eq!(views[0].kind_name, "RuleProposalSimulated");
        assert!(!views[0].attested);
        match &views[0].summary {
            ApprovalSummaryView::RuleProposal {
                smart_account_redacted,
                definition,
                proposal_sha256_hex,
                ..
            } => {
                assert!(smart_account_redacted.contains("..."));
                assert_eq!(definition.name, "spend-daily");
                assert_eq!(proposal_sha256_hex.len(), 64);
            }
            other => panic!("expected RuleProposal summary, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_flags_expired_entries() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = fixtures::payment_pending(SOURCE, DEST, "XLM", 1_000, None, 100, 1, uid(), 1);
        let expiry = entry.expires_at_unix_ms;
        store.insert(entry, TEST_NOW_MS).unwrap();

        let views = store.snapshot(expiry);
        assert!(
            views[0].expired,
            "entry at exactly its expiry must be flagged expired"
        );

        let views_before = store.snapshot(expiry - 1);
        assert!(
            !views_before[0].expired,
            "entry one ms before expiry must not be flagged expired"
        );
    }

    #[test]
    fn summary_view_serializes_with_snake_case_kind_tag() {
        let payment = ApprovalSummaryView::Payment {
            source: "GSOURCE".to_owned(),
            to: "GAAA".to_owned(),
            amount_stroops: 1,
            asset: "XLM".to_owned(),
            dest_asset: None,
            dest_amount_stroops: None,
            memo: ClassicMemo::None,
            fee_stroops: 100,
            seq_num: 1,
        };
        let json = serde_json::to_value(&payment).unwrap();
        assert_eq!(json["kind"], "payment");
        assert!(json.get("dest_asset").is_none());
        assert!(json.get("dest_amount_stroops").is_none());
        assert_eq!(
            json["amount_stroops"], "1",
            "amount_stroops must serialize as a decimal string"
        );
        assert_eq!(
            json["fee_stroops"], "100",
            "fee_stroops must serialize as a decimal string"
        );

        let rejected = ApprovalSummaryView::Rejected {
            original_kind_name: "PaymentSimulated".to_owned(),
        };
        let json = serde_json::to_value(&rejected).unwrap();
        assert_eq!(json["kind"], "rejected");
        assert_eq!(json["original_kind_name"], "PaymentSimulated");
    }

    #[test]
    fn path_payment_summary_view_encodes_stroop_fields_as_strings() {
        let payment = ApprovalSummaryView::Payment {
            source: "GSOURCE".to_owned(),
            to: "GAAA".to_owned(),
            amount_stroops: 9_007_199_254_740_993_i64, // 2^53 + 1
            asset: "XLM".to_owned(),
            dest_asset: Some("USDC:GISSUER".to_owned()),
            dest_amount_stroops: Some(9_007_199_254_740_995_i64),
            memo: ClassicMemo::None,
            fee_stroops: 100,
            seq_num: 1,
        };
        let json = serde_json::to_value(&payment).unwrap();
        assert_eq!(json["amount_stroops"], "9007199254740993");
        assert_eq!(json["dest_amount_stroops"], "9007199254740995");
        assert_eq!(json["dest_asset"], "USDC:GISSUER");

        let inconsistent = ApprovalSummaryView::Inconsistent {
            original_kind_name: "ClaimSimulated".to_owned(),
            reason: "the stored digest is not the digest of the stored envelope".to_owned(),
        };
        let json = serde_json::to_value(&inconsistent).unwrap();
        assert_eq!(json["kind"], "inconsistent");
        assert_eq!(json["original_kind_name"], "ClaimSimulated");
    }

    #[test]
    fn toolset_first_invoke_gate_summary_view_encodes_stroop_fields_as_strings() {
        let gate = ApprovalSummaryView::ToolsetFirstInvokeGate {
            toolset_name: "my-toolset".to_owned(),
            capability: "sign-payment".to_owned(),
            destination_redacted: "GAAAA...ZZZZZ".to_owned(),
            asset: "XLM".to_owned(),
            amount_min_stroops: 0,
            amount_max_stroops: i64::MAX,
        };
        let json = serde_json::to_value(&gate).unwrap();
        assert_eq!(json["amount_min_stroops"], "0");
        assert_eq!(json["amount_max_stroops"], "9223372036854775807");
    }

    #[test]
    fn pending_approval_view_serializes_expected_top_level_fields() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = fixtures::payment_pending(
            SOURCE,
            DEST,
            "XLM",
            1_000,
            None,
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        );
        store.insert(entry, TEST_NOW_MS).unwrap();

        let views = store.snapshot(TEST_NOW_MS);
        let json = serde_json::to_value(&views[0]).unwrap();
        assert!(json["approval_nonce"].is_string());
        assert_eq!(json["kind_name"], "PaymentSimulated");
        assert_eq!(json["expired"], false);
        assert_eq!(json["attested"], false);
        assert_eq!(json["summary"]["kind"], "payment");
        assert_eq!(json["summary"]["source"], SOURCE);
    }

    #[test]
    fn mpp_summary_is_short_lived_and_redacts_accounts() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let now = crate::timefmt::now_unix_ms().unwrap();
        let payer = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let recipient = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let entry = crate::approval::fixtures::bind_mpp_entry(
            PendingApproval::new_mpp_charge_pending(
                [0x11; 32],
                [0x22; 32],
                "default".to_owned(),
                "stellar:testnet".to_owned(),
                payer.to_owned(),
                "http".to_owned(),
                "merchant.example".to_owned(),
                "/checkout".to_owned(),
                "1000000".to_owned(),
                recipient.to_owned(),
                recipient.to_owned(),
                now / 1_000 + 3_600,
                1_100,
                uid(),
                DEFAULT_TTL_MS,
            )
            .unwrap(),
        );
        assert!(entry.expires_at_unix_ms <= entry.created_at_unix_ms + 5 * 60 * 1_000);
        store.insert(entry, now).unwrap();

        let view = &store.snapshot(now)[0];
        let ApprovalSummaryView::MppCharge {
            payer_redacted,
            recipient_redacted,
            amount,
            currency,
            ..
        } = &view.summary
        else {
            panic!("expected MPP summary")
        };
        assert_eq!(payer_redacted, "GAAAA...AAAAA");
        assert_eq!(recipient_redacted, "CAAAA...AD2KM");
        assert_eq!(amount, "1000000");
        assert_eq!(currency, recipient);
        let json = serde_json::to_string(view).unwrap();
        assert!(!json.contains(payer));
        assert!(!json.contains(&["11"; 32].concat()));
        assert!(!json.contains(&["22"; 32].concat()));
    }

    fn trustline_entry(limit: Option<i64>) -> PendingApproval {
        PendingApproval::new_trustline_pending(
            CHANGE_TRUST_ENVELOPE.to_owned(),
            CHANGE_TRUST_ENVELOPE.as_bytes(),
            OP_SOURCE.to_owned(),
            "USDC".to_owned(),
            ISSUER_04.to_owned(),
            limit,
            100,
            1,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap()
    }

    #[test]
    fn snapshot_renders_trustline_simulated() {
        for limit in [None, Some(0), Some(i64::MAX - 1)] {
            let mut entry = fixtures::trustline_pending(
                SOURCE,
                "USDC",
                TESTNET_USDC_ISSUER,
                limit,
                100,
                42,
                "1000".to_owned(),
                DEFAULT_TTL_MS,
            );
            entry.attestation_blob_b64 = Some("blob".to_owned());
            let view = PendingApprovalView::from_entry(&entry, TEST_NOW_MS);
            assert!(view.attested);
            assert_eq!(view.kind_name, "TrustlineSimulated");
            let json = serde_json::to_value(view).unwrap();
            assert_eq!(json["summary"]["kind"], "trustline");
            assert_eq!(json["summary"]["holder"], SOURCE);
            assert_eq!(json["summary"]["asset_issuer"], TESTNET_USDC_ISSUER);
            assert_eq!(json["summary"]["asset_code"], "USDC");
            assert_eq!(
                json["summary"]["limit_stroops"],
                serde_json::json!(limit.map(|n| n.to_string()))
            );
            assert_eq!(json["summary"]["fee_stroops"], "100");
            assert_eq!(json["summary"]["seq_num"], 42);
        }
    }

    /// The holder is the operation source, which overrides the transaction
    /// source, and the unlimited `i64::MAX` limit reads as `None`.
    #[test]
    fn trustline_snapshot_holder_is_the_operation_source() {
        let view = PendingApprovalView::from_entry(&trustline_entry(None), TEST_NOW_MS);
        assert_eq!(
            view.summary,
            ApprovalSummaryView::Trustline {
                holder: OP_SOURCE.to_owned(),
                asset_code: "USDC".to_owned(),
                asset_issuer: ISSUER_04.to_owned(),
                limit_stroops: None,
                fee_stroops: 100,
                seq_num: 1,
                memo: ClassicMemo::None,
            }
        );
    }

    /// Sets every stored `summary_*` field of a classic entry to name another
    /// transaction than its envelope holds; the digest still names the
    /// envelope.
    fn edit_stored_summary(entry: &mut PendingApproval) {
        match &mut entry.kind {
            ApprovalKind::PaymentSimulated {
                summary_to,
                summary_amount_stroops,
                summary_asset,
                summary_memo,
                summary_simulated_fee_stroops,
                summary_simulated_seq_num,
                ..
            } => {
                OTHER.clone_into(summary_to);
                *summary_amount_stroops = 1;
                "XLM".clone_into(summary_asset);
                *summary_memo = Some("refund".to_owned());
                *summary_simulated_fee_stroops = 1;
                *summary_simulated_seq_num = 1;
            }
            ApprovalKind::TrustlineSimulated {
                summary_holder,
                summary_asset_code,
                summary_asset_issuer,
                summary_limit_stroops,
                summary_simulated_fee_stroops,
                summary_simulated_seq_num,
                ..
            } => {
                OTHER.clone_into(summary_holder);
                "EURT".clone_into(summary_asset_code);
                OTHER.clone_into(summary_asset_issuer);
                *summary_limit_stroops = Some(1);
                *summary_simulated_fee_stroops = 1;
                *summary_simulated_seq_num = 1;
            }
            ApprovalKind::ClaimSimulated {
                summary_balance_id_hex72,
                summary_balance_id_strkey,
                summary_asset,
                summary_amount_stroops,
                summary_source,
                summary_simulated_fee_stroops,
                summary_simulated_seq_num,
                ..
            } => {
                let (hex72, strkey) = fixtures::balance_ids([0x0b; 32]);
                *summary_balance_id_hex72 = hex72;
                *summary_balance_id_strkey = strkey;
                *summary_asset = Some("XLM".to_owned());
                *summary_amount_stroops = Some(1);
                OTHER.clone_into(summary_source);
                *summary_simulated_fee_stroops = 1;
                *summary_simulated_seq_num = 1;
            }
            other => panic!("not a classic entry: {}", other.kind_name()),
        }
    }

    /// Every payment, trustline and claim field of the view is the
    /// envelope's, whatever the stored summary fields say.
    #[test]
    fn classic_summaries_come_from_the_envelope_not_the_stored_fields() {
        let mut payment = fixtures::payment_pending(
            SOURCE,
            DEST,
            &format!("USDC:{TESTNET_USDC_ISSUER}"),
            987_654_321,
            Some("invoice 7"),
            300,
            77,
            uid(),
            DEFAULT_TTL_MS,
        );
        edit_stored_summary(&mut payment);
        assert_eq!(
            PendingApprovalView::from_entry(&payment, TEST_NOW_MS).summary,
            ApprovalSummaryView::Payment {
                source: SOURCE.to_owned(),
                to: DEST.to_owned(),
                amount_stroops: 987_654_321,
                asset: format!("USDC:{TESTNET_USDC_ISSUER}"),
                dest_asset: None,
                dest_amount_stroops: None,
                memo: ClassicMemo::Text("invoice 7".to_owned()),
                fee_stroops: 300,
                seq_num: 77,
            }
        );

        let mut trustline = fixtures::trustline_pending(
            SOURCE,
            "USDC",
            TESTNET_USDC_ISSUER,
            Some(5_000_000),
            200,
            78,
            uid(),
            DEFAULT_TTL_MS,
        );
        edit_stored_summary(&mut trustline);
        assert_eq!(
            PendingApprovalView::from_entry(&trustline, TEST_NOW_MS).summary,
            ApprovalSummaryView::Trustline {
                holder: SOURCE.to_owned(),
                asset_code: "USDC".to_owned(),
                asset_issuer: TESTNET_USDC_ISSUER.to_owned(),
                limit_stroops: Some(5_000_000),
                fee_stroops: 200,
                seq_num: 78,
                memo: ClassicMemo::None,
            }
        );

        let mut claim = fixtures::claim_pending(
            SOURCE,
            [0x0a; 32],
            Some(("XLM", 500)),
            400,
            79,
            uid(),
            DEFAULT_TTL_MS,
        );
        edit_stored_summary(&mut claim);
        assert_eq!(
            PendingApprovalView::from_entry(&claim, TEST_NOW_MS).summary,
            ApprovalSummaryView::Claim {
                balance_id_strkey: fixtures::balance_ids([0x0a; 32]).1,
                source: SOURCE.to_owned(),
                fee_stroops: 400,
                seq_num: 79,
                memo: ClassicMemo::None,
            }
        );
    }

    /// An unedited entry renders the values it was created with, for every
    /// classic kind; the x402 view is pinned by
    /// `x402_view_renders_invocation_terms`.
    #[test]
    fn unedited_classic_entries_render_their_stored_values() {
        let payment = fixtures::payment_pending(
            SOURCE,
            DEST,
            "XLM",
            12_345,
            Some("thanks"),
            100,
            5,
            uid(),
            DEFAULT_TTL_MS,
        );
        let ApprovalKind::PaymentSimulated {
            summary_to,
            summary_amount_stroops,
            summary_asset,
            summary_memo,
            summary_simulated_fee_stroops,
            summary_simulated_seq_num,
            ..
        } = &payment.kind
        else {
            unreachable!()
        };
        assert_eq!(
            PendingApprovalView::from_entry(&payment, TEST_NOW_MS).summary,
            ApprovalSummaryView::Payment {
                source: SOURCE.to_owned(),
                to: summary_to.clone(),
                amount_stroops: *summary_amount_stroops,
                asset: summary_asset.clone(),
                dest_asset: None,
                dest_amount_stroops: None,
                memo: summary_memo
                    .clone()
                    .map_or(ClassicMemo::None, ClassicMemo::Text),
                fee_stroops: *summary_simulated_fee_stroops,
                seq_num: *summary_simulated_seq_num,
            }
        );

        let trustline = fixtures::trustline_pending(
            SOURCE,
            "USDC",
            TESTNET_USDC_ISSUER,
            None,
            100,
            6,
            uid(),
            DEFAULT_TTL_MS,
        );
        let ApprovalKind::TrustlineSimulated {
            summary_holder,
            summary_asset_code,
            summary_asset_issuer,
            summary_limit_stroops,
            summary_simulated_fee_stroops,
            summary_simulated_seq_num,
            ..
        } = &trustline.kind
        else {
            unreachable!()
        };
        assert_eq!(
            PendingApprovalView::from_entry(&trustline, TEST_NOW_MS).summary,
            ApprovalSummaryView::Trustline {
                holder: summary_holder.clone(),
                asset_code: summary_asset_code.clone(),
                asset_issuer: summary_asset_issuer.clone(),
                limit_stroops: *summary_limit_stroops,
                fee_stroops: *summary_simulated_fee_stroops,
                seq_num: *summary_simulated_seq_num,
                memo: ClassicMemo::None,
            }
        );

        let claim =
            fixtures::claim_pending(SOURCE, [0x0c; 32], None, 100, 7, uid(), DEFAULT_TTL_MS);
        let ApprovalKind::ClaimSimulated {
            summary_balance_id_strkey,
            summary_source,
            summary_simulated_fee_stroops,
            summary_simulated_seq_num,
            ..
        } = &claim.kind
        else {
            unreachable!()
        };
        assert_eq!(
            PendingApprovalView::from_entry(&claim, TEST_NOW_MS).summary,
            ApprovalSummaryView::Claim {
                balance_id_strkey: summary_balance_id_strkey.clone(),
                source: summary_source.clone(),
                fee_stroops: *summary_simulated_fee_stroops,
                seq_num: *summary_simulated_seq_num,
                memo: ClassicMemo::None,
            }
        );
    }

    /// An envelope that is not the one the stored digest names, and an
    /// envelope that does not decode, both render as inconsistent.
    #[test]
    fn inconsistent_classic_entries_render_as_inconsistent() {
        let mut swapped =
            fixtures::payment_pending(SOURCE, DEST, "XLM", 1_000, None, 100, 1, uid(), 60_000);
        let other = fixtures::payment_envelope(SOURCE, OTHER, "XLM", 9_000, None, 100, 1);
        let ApprovalKind::PaymentSimulated {
            envelope_xdr_b64, ..
        } = &mut swapped.kind
        else {
            unreachable!()
        };
        *envelope_xdr_b64 = other;
        let view = PendingApprovalView::from_entry(&swapped, TEST_NOW_MS);
        let ApprovalSummaryView::Inconsistent {
            original_kind_name,
            reason,
        } = &view.summary
        else {
            panic!("{:?}", view.summary)
        };
        assert_eq!(original_kind_name, "PaymentSimulated");
        assert!(reason.contains("stored digest"), "{reason}");
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains(OTHER), "{json}");
        assert!(!json.contains(DEST), "{json}");

        let undecodable = PendingApproval::new_trustline_pending(
            "AAAA".to_owned(),
            b"AAAA",
            SOURCE.to_owned(),
            "USDC".to_owned(),
            TESTNET_USDC_ISSUER.to_owned(),
            None,
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let ApprovalSummaryView::Inconsistent {
            original_kind_name,
            reason,
        } = PendingApprovalView::from_entry(&undecodable, TEST_NOW_MS).summary
        else {
            panic!("undecodable envelope")
        };
        assert_eq!(original_kind_name, "TrustlineSimulated");
        assert!(reason.contains("does not decode"), "{reason}");

        // A claim entry whose envelope holds a payment.
        let payment_envelope = fixtures::payment_envelope(SOURCE, DEST, "XLM", 1, None, 100, 1);
        let (hex72, strkey) = fixtures::balance_ids([1; 32]);
        let wrong_operation = PendingApproval::new_claim_pending_unvalued(
            payment_envelope.clone(),
            payment_envelope.as_bytes(),
            hex72,
            strkey,
            SOURCE.to_owned(),
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        assert!(matches!(
            PendingApprovalView::from_entry(&wrong_operation, TEST_NOW_MS).summary,
            ApprovalSummaryView::Inconsistent { .. }
        ));
    }

    /// A path payment shows both legs, an account creation its starting
    /// balance, and a muxed destination its M-strkey.
    #[test]
    fn payment_views_show_path_payments_account_creation_and_muxed_destinations() {
        use stellar_xdr::{
            CreateAccountOp, Memo, MuxedAccount, MuxedAccountMed25519, OperationBody,
            PathPaymentStrictSendOp, Uint256,
        };
        let key = |g: &str| {
            stellar_strkey::ed25519::PublicKey::from_string(g)
                .unwrap()
                .0
        };
        let pending = |envelope: String| {
            PendingApproval::new_payment_pending(
                envelope.clone(),
                envelope.as_bytes(),
                DEST.to_owned(),
                1,
                "XLM".to_owned(),
                None,
                100,
                3,
                uid(),
                DEFAULT_TTL_MS,
            )
            .unwrap()
        };

        let path = fixtures::envelope(
            SOURCE,
            OperationBody::PathPaymentStrictSend(PathPaymentStrictSendOp {
                send_asset: stellar_xdr::Asset::Native,
                send_amount: 50_000_000,
                destination: MuxedAccount::Ed25519(Uint256(key(DEST))),
                dest_asset: stellar_xdr::Asset::Native,
                dest_min: 49_000_000,
                path: vec![].try_into().unwrap(),
            }),
            Memo::Id(42),
            100,
            3,
        );
        let ApprovalSummaryView::Payment {
            amount_stroops,
            dest_asset,
            dest_amount_stroops,
            memo,
            ..
        } = PendingApprovalView::from_entry(&pending(path), TEST_NOW_MS).summary
        else {
            panic!("path payment")
        };
        assert_eq!(amount_stroops, 50_000_000);
        assert_eq!(dest_asset.as_deref(), Some("XLM"));
        assert_eq!(dest_amount_stroops, Some(49_000_000));
        assert_eq!(memo, ClassicMemo::Id(42));

        let create = fixtures::envelope(
            SOURCE,
            OperationBody::CreateAccount(CreateAccountOp {
                destination: stellar_xdr::AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(
                    Uint256(key(OTHER)),
                )),
                starting_balance: 20_000_000,
            }),
            Memo::None,
            100,
            3,
        );
        let ApprovalSummaryView::Payment {
            to,
            amount_stroops,
            asset,
            memo,
            ..
        } = PendingApprovalView::from_entry(&pending(create), TEST_NOW_MS).summary
        else {
            panic!("account creation")
        };
        assert_eq!(
            (to.as_str(), amount_stroops, asset.as_str()),
            (OTHER, 20_000_000, "XLM")
        );
        assert_eq!(memo, ClassicMemo::None);

        let muxed = fixtures::envelope(
            SOURCE,
            OperationBody::Payment(stellar_xdr::PaymentOp {
                destination: MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
                    id: 7,
                    ed25519: Uint256(key(DEST)),
                }),
                asset: stellar_xdr::Asset::Native,
                amount: 1,
            }),
            Memo::None,
            100,
            3,
        );
        let ApprovalSummaryView::Payment { to, .. } =
            PendingApprovalView::from_entry(&pending(muxed), TEST_NOW_MS).summary
        else {
            panic!("muxed payment")
        };
        assert!(to.starts_with('M'), "{to}");
        assert_eq!(
            to,
            stellar_strkey::ed25519::MuxedAccount {
                ed25519: key(DEST),
                id: 7
            }
            .to_string()
            .to_string()
        );
    }

    #[test]
    fn x402_view_renders_invocation_terms() {
        use stellar_xdr::{
            AccountId, ContractId, Hash, InvokeContractArgs, PublicKey, ScAddress, ScVal,
            SorobanAuthorizedFunction, SorobanAuthorizedInvocation, Uint256, WriteXdr as _,
        };
        let account = |byte| {
            ScVal::Address(ScAddress::Account(AccountId(
                PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32])),
            )))
        };
        let root = |function: &str| SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([7; 32]))),
                function_name: function.try_into().unwrap(),
                args: vec![account(4), account(5), ScVal::from(1_234_i128)]
                    .try_into()
                    .unwrap(),
            }),
            sub_invocations: vec![].try_into().unwrap(),
        };
        let mut entry = PendingApproval::new_x402_pending(
            &[1; 32],
            &root("transfer"),
            Some("merchant.example.invalid".into()),
            "1000".into(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let ApprovalKind::X402Payment {
            payee,
            amount,
            asset,
            ..
        } = &mut entry.kind
        else {
            unreachable!()
        };
        "stored-payee".clone_into(payee);
        "999".clone_into(amount);
        "stored-asset".clone_into(asset);
        let ApprovalSummaryView::X402Payment {
            payee,
            amount,
            asset,
            home_domain,
        } = PendingApprovalView::from_entry(&entry, TEST_NOW_MS).summary
        else {
            panic!("x402")
        };
        assert_eq!(
            payee,
            Some(
                stellar_strkey::ed25519::PublicKey([5; 32])
                    .to_string()
                    .to_string()
            )
        );
        assert_eq!(amount.as_deref(), Some("1234"));
        assert_eq!(
            asset,
            Some(stellar_strkey::Contract([7; 32]).to_string().to_string())
        );
        assert_eq!(home_domain.as_deref(), Some("merchant.example.invalid"));

        let ApprovalKind::X402Payment {
            root_invocation_xdr,
            ..
        } = &mut entry.kind
        else {
            unreachable!()
        };
        *root_invocation_xdr = root("approve")
            .to_xdr_base64(stellar_xdr::Limits::none())
            .unwrap();
        let ApprovalSummaryView::X402Payment {
            payee,
            amount,
            asset,
            ..
        } = PendingApprovalView::from_entry(&entry, TEST_NOW_MS).summary
        else {
            panic!("x402")
        };
        assert_eq!((payee, amount, asset), (None, None, None));
    }
    #[test]
    fn mpp_view_checks_every_fingerprinted_term_and_the_binding_digests() {
        // Transport, authority and target enter the fingerprint only through
        // the context digest; the MPP commit compares them with the prepared
        // request context.
        for field in [
            "profile",
            "chain",
            "payer",
            "amount",
            "currency",
            "recipient",
            "expiry",
            "context_digest",
            "challenge_digest",
            "passphrase_hash",
            "missing_digests",
        ] {
            let mut entry = fixtures::mpp_pending();
            if let ApprovalKind::MppChargeSimulated {
                profile,
                chain_id,
                payer,
                amount,
                currency,
                recipient,
                challenge_expires_at_unix,
                authorization_context,
                ..
            } = &mut entry.kind
            {
                match field {
                    "profile" => profile.push('x'),
                    "chain" => chain_id.push('x'),
                    "payer" => payer.push('x'),
                    "amount" => amount.push('0'),
                    "currency" => currency.push('x'),
                    "recipient" => recipient.push('x'),
                    "expiry" => *challenge_expires_at_unix += 1,
                    "context_digest" => {
                        authorization_context.as_mut().unwrap().context_digest[0] ^= 1;
                    }
                    "challenge_digest" => {
                        authorization_context.as_mut().unwrap().challenge_digest[0] ^= 1;
                    }
                    "passphrase_hash" => {
                        authorization_context
                            .as_mut()
                            .unwrap()
                            .network_passphrase_hash[0] ^= 1;
                    }
                    "missing_digests" => *authorization_context = None,
                    _ => unreachable!(),
                }
            }
            assert!(
                matches!(
                    PendingApprovalView::from_entry(&entry, entry.created_at_unix_ms).summary,
                    ApprovalSummaryView::Inconsistent { .. }
                ),
                "{field}"
            );
        }
    }
}
