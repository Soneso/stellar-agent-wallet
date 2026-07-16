//! Read-only, redacted snapshot views over [`PendingApproval`] entries.
//!
//! [`PendingApprovalStore::snapshot`](super::store::PendingApprovalStore::snapshot)
//! is the only way to enumerate the store's contents from outside this crate
//! — `entries` stays private on the store itself. Every field exposed here is
//! either public on-chain data or already redacted, mirroring the CLI
//! `approve --id` wallet-controlled summary discipline, so every consumer of
//! a snapshot (the CLI, a resident approval-inbox server) shares one
//! non-secret rendering instead of re-deriving it from the raw entry.

use serde::Serialize;

use super::rule_proposal::ContextRuleProposalSnapshot;
use super::store::{ApprovalKind, PendingApproval, redact_g_strkey};

/// Read-only, non-secret view of a single pending approval entry.
///
/// Never carries raw secret material: `SignWithPasskey` / `RegisterPasskey`
/// byte fields (`auth_digest`, `credential_id`, `csrf_token`, `user_handle`)
/// and the `attestation_blob_b64` contents never appear here — only the same
/// redacted / summary fields the CLI `approve --id` prompt renders.
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

    /// `true` if `expires_at_unix_ms <= now_unix_ms` at snapshot time.
    pub expired: bool,

    /// `true` if the entry already carries a recorded operator consent: an
    /// HMAC attestation (`PaymentSimulated` / `ClaimSimulated` /
    /// `TrustlineClawbackOptIn`) or a WebAuthn result (`SignWithPasskey` /
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
/// Mirrors the wallet-controlled rendering in the CLI `approve --id` prompt:
/// every field here is either public on-chain data or already redacted.
///
/// Serialises as a JSON object tagged with a `"kind"` discriminator
/// (`"payment"`, `"claim"`, `"sign_with_passkey"`, `"register_passkey"`,
/// `"toolset_first_invoke_gate"`, `"trustline_clawback_opt_in"`,
/// `"rule_proposal"`, `"rejected"`), the same tagging convention as
/// `stellar_agent_stablecoin::preview::GateDecisionView`.
///
/// Every value-denominated field (`amount_stroops`, `fee_stroops`,
/// `amount_min_stroops`, `amount_max_stroops`) is encoded as a decimal
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
    /// [`ApprovalKind::PaymentSimulated`] summary fields.
    Payment {
        /// Destination G-strkey.
        to: String,
        /// Amount in stroops, decimal-string encoded on the wire (see
        /// [`stellar_agent_core::wire_stroops`](crate::wire_stroops)).
        #[serde(with = "crate::wire_stroops::i64")]
        amount_stroops: i64,
        /// Asset identifier (`"XLM"` or `"<code>:<issuer>"`).
        asset: String,
        /// Optional memo text.
        memo: Option<String>,
        /// Simulated transaction fee in stroops, decimal-string encoded.
        #[serde(with = "crate::wire_stroops::u32")]
        fee_stroops: u32,
        /// Simulated sequence number.
        seq_num: i64,
    },

    /// [`ApprovalKind::ClaimSimulated`] summary fields.
    Claim {
        /// `B...` strkey rendering of the balance id.
        balance_id_strkey: String,
        /// Asset identifier.
        asset: String,
        /// Claim amount in stroops, decimal-string encoded.
        #[serde(with = "crate::wire_stroops::i64")]
        amount_stroops: i64,
        /// Claiming (source) account G-strkey.
        source: String,
        /// Simulated transaction fee in stroops, decimal-string encoded.
        #[serde(with = "crate::wire_stroops::u32")]
        fee_stroops: u32,
        /// Simulated sequence number.
        seq_num: i64,
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
        /// Network passphrase.
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
}

impl PendingApprovalView {
    /// Builds a redacted view from a stored entry.
    pub(super) fn from_entry(entry: &PendingApproval, now_unix_ms: u64) -> Self {
        let attested = match &entry.kind {
            ApprovalKind::PaymentSimulated { .. }
            | ApprovalKind::ClaimSimulated { .. }
            | ApprovalKind::TrustlineClawbackOptIn { .. }
            | ApprovalKind::RuleProposalSimulated { .. }
            | ApprovalKind::MppChargeSimulated { .. } => entry.attestation_blob_b64.is_some(),
            ApprovalKind::SignWithPasskey { .. } => entry.passkey_assertion.is_some(),
            ApprovalKind::RegisterPasskey {
                registration_input, ..
            } => registration_input.is_some(),
            ApprovalKind::ToolsetFirstInvokeGate { .. } | ApprovalKind::Rejected { .. } => false,
        };

        let summary = match &entry.kind {
            ApprovalKind::PaymentSimulated {
                summary_to,
                summary_amount_stroops,
                summary_asset,
                summary_memo,
                summary_simulated_fee_stroops,
                summary_simulated_seq_num,
                ..
            } => ApprovalSummaryView::Payment {
                to: summary_to.clone(),
                amount_stroops: *summary_amount_stroops,
                asset: summary_asset.clone(),
                memo: summary_memo.clone(),
                fee_stroops: *summary_simulated_fee_stroops,
                seq_num: *summary_simulated_seq_num,
            },
            ApprovalKind::ClaimSimulated {
                summary_balance_id_strkey,
                summary_asset,
                summary_amount_stroops,
                summary_source,
                summary_simulated_fee_stroops,
                summary_simulated_seq_num,
                ..
            } => ApprovalSummaryView::Claim {
                balance_id_strkey: summary_balance_id_strkey.clone(),
                asset: summary_asset.clone(),
                amount_stroops: *summary_amount_stroops,
                source: summary_source.clone(),
                fee_stroops: *summary_simulated_fee_stroops,
                seq_num: *summary_simulated_seq_num,
            },
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
                proposal_sha256_hex: proposal_sha256.iter().map(|b| format!("{b:02x}")).collect(),
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
        };

        Self {
            approval_nonce: entry.approval_nonce.clone(),
            kind_name: entry.kind.kind_name(),
            created_at_unix_ms: entry.created_at_unix_ms,
            expires_at_unix_ms: entry.expires_at_unix_ms,
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

    use super::super::store::{DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore};
    use super::super::user_id::process_uid_for_attestation;
    use super::*;
    use tempfile::TempDir;

    const TEST_NOW_MS: u64 = 1_700_000_000_000;
    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
    const TESTNET_USDC_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

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
        let entry = PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr-bytes",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            2_500_000,
            "XLM".to_owned(),
            Some("hello".to_owned()),
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let views = store.snapshot(TEST_NOW_MS);
        assert_eq!(views.len(), 1);
        let view = &views[0];
        assert_eq!(view.approval_nonce, nonce);
        assert_eq!(view.kind_name, "PaymentSimulated");
        assert!(!view.expired);
        assert!(!view.attested);
        match &view.summary {
            ApprovalSummaryView::Payment {
                to,
                amount_stroops,
                asset,
                memo,
                ..
            } => {
                assert_eq!(
                    to,
                    "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                );
                assert_eq!(*amount_stroops, 2_500_000);
                assert_eq!(asset, "XLM");
                assert_eq!(memo.as_deref(), Some("hello"));
            }
            other => panic!("expected Payment summary, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_marks_payment_attested_after_record_attestation() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let entry = PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr-bytes",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            1_000,
            "XLM".to_owned(),
            None,
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
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
        let entry = PendingApproval::new_claim_pending(
            "b64xdr".to_owned(),
            b"fake-xdr-bytes",
            "a".repeat(72),
            "B".to_owned() + &"A".repeat(57),
            "XLM".to_owned(),
            500,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let views = store.snapshot(TEST_NOW_MS);
        assert_eq!(views[0].kind_name, "ClaimSimulated");
        assert!(matches!(
            views[0].summary,
            ApprovalSummaryView::Claim { .. }
        ));
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
        let entry = PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr-bytes",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            1_000,
            "XLM".to_owned(),
            None,
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
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
        let entry = PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr-bytes",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            1_000,
            "XLM".to_owned(),
            None,
            100,
            1,
            uid(),
            1,
        )
        .unwrap();
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
            to: "GAAA".to_owned(),
            amount_stroops: 1,
            asset: "XLM".to_owned(),
            memo: None,
            fee_stroops: 100,
            seq_num: 1,
        };
        let json = serde_json::to_value(&payment).unwrap();
        assert_eq!(json["kind"], "payment");
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
    fn claim_summary_view_encodes_stroop_fields_as_strings() {
        let claim = ApprovalSummaryView::Claim {
            balance_id_strkey: "B".to_owned() + &"A".repeat(57),
            asset: "XLM".to_owned(),
            amount_stroops: 9_007_199_254_740_993_i64, // 2^53 + 1
            source: "GAAA".to_owned(),
            fee_stroops: 100,
            seq_num: 1,
        };
        let json = serde_json::to_value(&claim).unwrap();
        assert_eq!(
            json["amount_stroops"], "9007199254740993",
            "amount_stroops must survive the f64 precision boundary as a string"
        );
        assert_eq!(json["fee_stroops"], "100");
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
        let entry = PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr-bytes",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            1_000,
            "XLM".to_owned(),
            None,
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, TEST_NOW_MS).unwrap();

        let views = store.snapshot(TEST_NOW_MS);
        let json = serde_json::to_value(&views[0]).unwrap();
        assert!(json["approval_nonce"].is_string());
        assert_eq!(json["kind_name"], "PaymentSimulated");
        assert_eq!(json["expired"], false);
        assert_eq!(json["attested"], false);
        assert_eq!(json["summary"]["kind"], "payment");
    }

    #[test]
    fn mpp_summary_is_short_lived_and_redacts_accounts() {
        let dir = TempDir::new().unwrap();
        let mut store = open_store(&dir);
        let now = crate::timefmt::now_unix_ms().unwrap();
        let payer = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let recipient = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let entry = PendingApproval::new_mpp_charge_pending(
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
        .unwrap();
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
}
