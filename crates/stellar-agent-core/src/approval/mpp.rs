//! Binding between the displayed terms of an MPP charge approval and the
//! authorization it commits.
//!
//! The authorization fingerprint is the source of the MPP store's
//! `authorization_id` and of the approval binding, so its bytes are fixed.
//! Reuse and replay of a challenge key on its challenge identity, which the
//! store derives separately. The fingerprint uses the tag
//! `stellar-agent-mpp-authorization:v1\0`, then the profile, the SHA-256 of
//! the network passphrase, the payer, the request-context digest, the
//! challenge digest, the scheme constants `stellar`, `charge` and
//! `sponsored_pull`, the amount, the currency, the recipient and the effective
//! challenge expiry, each prefixed with its big-endian `u64` byte length.
//!
//! A pending MPP entry stores its displayed terms beside the three digests, so
//! [`verify_mpp_entry_terms`] can recompute the fingerprint from what a surface
//! shows. The network is checked through the passphrase hash. Transport,
//! authority and target enter the fingerprint only through the context
//! digest, so the MPP commit compares them with the authenticated record's
//! request context before it accepts the attestation.

use std::str::FromStr as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::store::ApprovalKind;
use crate::error::{ApprovalFailure, WalletError};
use crate::profile::caip2::Caip2;

/// Domain tag of the authorization fingerprint.
const FINGERPRINT_TAG: &[u8] = b"stellar-agent-mpp-authorization:v1\0";

/// The digests a pending MPP entry stores so that its displayed terms can be
/// checked against its authorization fingerprint.
///
/// The digests reveal no request parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MppAuthorizationContext {
    /// Digest of the normalized request context.
    pub context_digest: [u8; 32],
    /// SHA-256 of the network passphrase.
    pub network_passphrase_hash: [u8; 32],
    /// Digest of the exact selected challenge.
    pub challenge_digest: [u8; 32],
}

/// The charge terms the authorization fingerprint covers directly.
#[derive(Debug, Clone, Copy)]
pub struct MppChargeTerms<'a> {
    /// Wallet profile.
    pub profile: &'a str,
    /// Payer account.
    pub payer: &'a str,
    /// Canonical decimal token amount.
    pub amount: &'a str,
    /// Token contract.
    pub currency: &'a str,
    /// Recipient account or contract.
    pub recipient: &'a str,
    /// Effective challenge expiry in Unix seconds.
    pub effective_expires_at_unix: i64,
}

/// Computes the authorization fingerprint of `terms` under `context`.
///
/// The MPP store keys authorization records by this value, and pending
/// approvals are checked against it; the byte layout is the one the module
/// documentation states.
#[must_use]
pub fn authorization_fingerprint(
    terms: &MppChargeTerms<'_>,
    context: &MppAuthorizationContext,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FINGERPRINT_TAG);
    for value in [
        terms.profile.as_bytes(),
        &context.network_passphrase_hash,
        terms.payer.as_bytes(),
        &context.context_digest,
        &context.challenge_digest,
        b"stellar",
        b"charge",
        b"sponsored_pull",
        terms.amount.as_bytes(),
        terms.currency.as_bytes(),
        terms.recipient.as_bytes(),
        &terms.effective_expires_at_unix.to_be_bytes(),
    ] {
        hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(value);
    }
    hash.finalize().into()
}

/// Checks that the terms an MPP charge entry displays are the terms its
/// authorization fingerprint covers.
///
/// The entry's chain id must name a known network whose passphrase hashes to
/// the stored passphrase hash, and the fingerprint recomputed from the
/// displayed profile, payer, amount, currency, recipient and expiry with the
/// stored digests must equal the stored fingerprint. Entries of other kinds
/// pass unchecked.
///
/// # Errors
///
/// Returns `approval.entry_inconsistent` when the entry holds no binding
/// digests, when its chain id and passphrase hash disagree, or when a
/// displayed term differs from the fingerprinted one.
pub fn verify_mpp_entry_terms(kind: &ApprovalKind) -> Result<(), WalletError> {
    let ApprovalKind::MppChargeSimulated {
        authorization_fingerprint: stored,
        authorization_context,
        profile,
        chain_id,
        payer,
        amount,
        currency,
        recipient,
        challenge_expires_at_unix,
        ..
    } = kind
    else {
        return Ok(());
    };
    let context = authorization_context.as_ref().ok_or_else(|| {
        inconsistent(
            "it holds no authorization binding digests; prepare the charge again to approve it",
        )
    })?;
    let network_matches = Caip2::from_str(chain_id).is_ok_and(|chain| {
        <[u8; 32]>::from(Sha256::digest(chain.network_passphrase().as_bytes()))
            == context.network_passphrase_hash
    });
    if !network_matches {
        return Err(inconsistent(
            "the network it shows is not the network it would authorize on",
        ));
    }
    let effective_expires_at_unix = i64::try_from(*challenge_expires_at_unix)
        .map_err(|_| inconsistent("what it shows does not match what it would authorize"))?;
    let terms = MppChargeTerms {
        profile,
        payer,
        amount,
        currency,
        recipient,
        effective_expires_at_unix,
    };
    if authorization_fingerprint(&terms, context) != *stored {
        return Err(inconsistent(
            "what it shows does not match what it would authorize",
        ));
    }
    Ok(())
}

fn inconsistent(reason: &str) -> WalletError {
    WalletError::Approval(ApprovalFailure::EntryInconsistent {
        detail: format!("this pending approval cannot be approved: {reason}"),
    })
}

/// Binds operator consent to both the authorization fingerprint and the
/// prepared transaction artifact.
#[must_use]
pub fn approval_subject(fingerprint: &[u8; 32], artifact: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"stellar-agent-mpp-approval:v1\0");
    hash.update(fingerprint);
    hash.update(artifact);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use crate::approval::fixtures;
    use crate::profile::caip2::{MAINNET_PASSPHRASE, TESTNET_PASSPHRASE};

    fn hex32(hex: &str) -> [u8; 32] {
        crate::hex::decode_hex32(hex).unwrap()
    }

    /// The known-answer vector of the MPP store's fingerprint: the inputs of
    /// the MPP crate's prepared-charge test fixture at Unix time
    /// 1_700_000_000, under profile `default` on testnet.
    #[test]
    fn authorization_fingerprint_known_answer() {
        let context = MppAuthorizationContext {
            context_digest: hex32(
                "b9697959fd30b5d96b0be426f5f0bec1c4cf32504fef9835e994134015075319",
            ),
            network_passphrase_hash: Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into(),
            challenge_digest: hex32(
                "dd476260bd5e92b6f66f1fa14076dba13a99ef9ae71016498c079273a9829b2e",
            ),
        };
        let terms = MppChargeTerms {
            profile: "default",
            payer: "GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR",
            amount: "10000000",
            currency: "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
            recipient: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            effective_expires_at_unix: 1_700_000_300,
        };
        assert_eq!(
            crate::hex::encode(&authorization_fingerprint(&terms, &context)),
            "79d368c1aeb6b1f89a1bf84a56bea75bb7ca6e138c252cafa18e24c013fd1768"
        );
    }

    fn set_chain(entry: &mut crate::approval::PendingApproval, value: &str) {
        let ApprovalKind::MppChargeSimulated { chain_id, .. } = &mut entry.kind else {
            unreachable!()
        };
        value.clone_into(chain_id);
    }

    fn set_passphrase_hash(entry: &mut crate::approval::PendingApproval, passphrase: &str) {
        let ApprovalKind::MppChargeSimulated {
            authorization_context: Some(context),
            ..
        } = &mut entry.kind
        else {
            unreachable!()
        };
        context.network_passphrase_hash = Sha256::digest(passphrase.as_bytes()).into();
    }

    fn assert_inconsistent(entry: &crate::approval::PendingApproval, reason: &str) {
        let error = verify_mpp_entry_terms(&entry.kind).unwrap_err();
        assert_eq!(error.code(), "approval.entry_inconsistent");
        assert!(error.message().contains(reason), "{}", error.message());
    }

    #[test]
    fn a_bound_entry_verifies() {
        verify_mpp_entry_terms(&fixtures::mpp_pending().kind).unwrap();
    }

    /// The chain id an entry displays must be the network whose passphrase
    /// the fingerprint binds; the fingerprint itself does not cover the chain
    /// id string.
    #[test]
    fn the_displayed_chain_must_match_the_bound_passphrase() {
        let mut mainnet = fixtures::mpp_pending();
        set_chain(&mut mainnet, "stellar:mainnet");
        assert_inconsistent(&mainnet, "the network it shows");

        let mut unknown = fixtures::mpp_pending();
        set_chain(&mut unknown, "stellar:futurenet");
        assert_inconsistent(&unknown, "the network it shows");

        let mut foreign_hash = fixtures::mpp_pending();
        set_passphrase_hash(&mut foreign_hash, "Standalone Network ; February 2017");
        assert_inconsistent(&foreign_hash, "the network it shows");

        let mut mainnet_hash = fixtures::mpp_pending();
        set_passphrase_hash(&mut mainnet_hash, MAINNET_PASSPHRASE);
        assert_inconsistent(&mainnet_hash, "the network it shows");
    }

    #[test]
    fn an_entry_without_binding_digests_is_inconsistent() {
        let mut entry = fixtures::mpp_pending();
        let ApprovalKind::MppChargeSimulated {
            authorization_context,
            ..
        } = &mut entry.kind
        else {
            unreachable!()
        };
        *authorization_context = None;
        assert_inconsistent(&entry, "prepare the charge again");
    }

    #[test]
    fn non_mpp_entries_pass() {
        let payment = fixtures::payment_pending(
            "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
            "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            "XLM",
            10,
            None,
            100,
            1,
            "1000".to_owned(),
            60_000,
        );
        verify_mpp_entry_terms(&payment.kind).unwrap();
    }
}
