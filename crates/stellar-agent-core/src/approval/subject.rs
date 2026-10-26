//! The subjects an approval attests, and the Soroban intent digests the
//! x402 subjects are built from.
//!
//! Each subject is the 32-byte value an approval's attestation binds in its
//! envelope-digest slot. The conventions are frozen here, and the mainnet
//! authorization store and resolvers consume them by these names:
//!
//! | Approval | Subject |
//! |---|---|
//! | classic transaction | `SHA256(unsigned base64 envelope text bytes)` |
//! | x402 payment | `SHA256("stellar-agent-x402-intent:v1" \|\| intent_digest)` |
//! | authenticated x402 payment | see below |
//!
//! The authenticated x402 subject also binds the home domain:
//!
//! ```text
//! SHA256("stellar-agent-x402-authenticated-intent:v1" || intent_digest
//!        || u32be(len(home_domain)) || home_domain)
//! ```
//!
//! The classic subject hashes the base64 text exactly as the approval record
//! stores it, not the decoded XDR; the network transaction hash of the same
//! envelope is a different digest.
//!
//! The Soroban intent digest names a payment's authorized invocation tree on
//! one network:
//!
//! ```text
//! SHA256("stellar-agent-soroban-intent:v1" || network_id || u32be(len(root_xdr)) || root_xdr)
//! ```
//!
//! where `root_xdr` is the XDR of the root `SorobanAuthorizedInvocation`:
//! the contract, function, arguments, and ordered sub-invocations. The
//! credentials' nonce, signature expiration, and signature, and the
//! simulation's ledger and resource data, are outside the root and do not
//! enter the digest. The root digest names the same tree without a network:
//!
//! ```text
//! SHA256("stellar-agent-soroban-root:v1" || u32be(len(root_xdr)) || root_xdr)
//! ```

use sha2::{Digest as _, Sha256};
use stellar_xdr::{Limits, SorobanAuthorizedInvocation, WriteXdr as _};

use crate::error::{ProtocolError, WalletError};

/// Domain label of the x402 approval subject.
pub const X402_INTENT_LABEL: &[u8] = b"stellar-agent-x402-intent:v1";

/// Domain label of the authenticated x402 approval subject.
pub const X402_AUTHENTICATED_INTENT_LABEL: &[u8] = b"stellar-agent-x402-authenticated-intent:v1";

/// Domain label of the Soroban intent digest.
pub const SOROBAN_INTENT_LABEL: &[u8] = b"stellar-agent-soroban-intent:v1";

/// Domain label of the Soroban root invocation digest.
pub const SOROBAN_ROOT_LABEL: &[u8] = b"stellar-agent-soroban-root:v1";

/// Appends a big-endian u32 length and its bytes to a SHA-256 input.
///
/// Shared with the network crate's digest layouts, so it is public, but it is
/// not part of the documented API.
#[doc(hidden)]
pub fn length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
}

/// The approval subject of a classic transaction: SHA-256 of the unsigned
/// envelope's base64 text bytes, as the approval record stores it.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::subject::approval_subject_classic;
/// use stellar_agent_core::approval::envelope_sha256;
///
/// assert_eq!(approval_subject_classic("AAAA"), envelope_sha256(b"AAAA"));
/// ```
#[must_use]
pub fn approval_subject_classic(unsigned_envelope_b64: &str) -> [u8; 32] {
    Sha256::digest(unsigned_envelope_b64.as_bytes()).into()
}

/// The approval subject of an x402 payment whose intent digest is
/// `intent_digest`.
#[must_use]
pub fn approval_subject_x402(intent_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(X402_INTENT_LABEL);
    hasher.update(intent_digest);
    hasher.finalize().into()
}

/// The approval subject of an authenticated x402 payment: the intent digest
/// and the home domain the payment authenticates to.
///
/// Distinct from [`approval_subject_x402`] for the same intent, so an
/// approval of an unauthenticated payment never stands for an authenticated
/// one.
#[must_use]
pub fn approval_subject_x402_authenticated(
    intent_digest: &[u8; 32],
    home_domain: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(X402_AUTHENTICATED_INTENT_LABEL);
    hasher.update(intent_digest);
    length_prefixed(&mut hasher, home_domain.as_bytes());
    hasher.finalize().into()
}

pub(crate) fn x402_kind_subject(intent_digest: &[u8; 32], home_domain: Option<&str>) -> [u8; 32] {
    match home_domain {
        Some(domain) => approval_subject_x402_authenticated(intent_digest, domain),
        None => approval_subject_x402(intent_digest),
    }
}

/// The subject of a stored x402 approval, after checking that its intent
/// digest is the digest of its stored invocation on the network of
/// `passphrase`.
///
/// # Errors
///
/// `approval.attestation_invalid` when the invocation does not decode or its
/// digest differs from `intent_digest`.
pub(crate) fn verified_x402_subject(
    intent_digest: &[u8; 32],
    root_invocation_xdr: &str,
    home_domain: Option<&str>,
    passphrase: &str,
) -> Result<[u8; 32], WalletError> {
    use crate::error::ApprovalFailure;
    use stellar_xdr::ReadXdr as _;
    let invalid = || {
        WalletError::Approval(ApprovalFailure::AttestationInvalid {
            detail: "the stored x402 invocation does not match its digest".to_owned(),
        })
    };
    let root = SorobanAuthorizedInvocation::from_xdr_base64(
        root_invocation_xdr,
        stellar_agent_xdr_limits::untrusted_decode_limits(root_invocation_xdr.len()),
    )
    .map_err(|_| invalid())?;
    let network_id = Sha256::digest(passphrase.as_bytes()).into();
    if soroban_intent_digest(&network_id, &root)? != *intent_digest {
        return Err(invalid());
    }
    Ok(x402_kind_subject(intent_digest, home_domain))
}

fn root_xdr(root: &SorobanAuthorizedInvocation) -> Result<Vec<u8>, WalletError> {
    root.to_xdr(Limits::none()).map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("the authorized invocation does not encode: {e}"),
        })
    })
}

/// The Soroban intent digest of the authorized invocation tree `root` on the
/// network whose id is `network_id`.
///
/// # Errors
///
/// `protocol.xdr_codec_failed` when `root` does not encode as XDR.
pub fn soroban_intent_digest(
    network_id: &[u8; 32],
    root: &SorobanAuthorizedInvocation,
) -> Result<[u8; 32], WalletError> {
    let xdr = root_xdr(root)?;
    let mut hasher = Sha256::new();
    hasher.update(SOROBAN_INTENT_LABEL);
    hasher.update(network_id);
    length_prefixed(&mut hasher, &xdr);
    Ok(hasher.finalize().into())
}

/// The root invocation digest of the authorized invocation tree `root`.
///
/// # Errors
///
/// `protocol.xdr_codec_failed` when `root` does not encode as XDR.
pub fn root_invocation_digest(root: &SorobanAuthorizedInvocation) -> Result<[u8; 32], WalletError> {
    let xdr = root_xdr(root)?;
    let mut hasher = Sha256::new();
    hasher.update(SOROBAN_ROOT_LABEL);
    length_prefixed(&mut hasher, &xdr);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use stellar_xdr::{
        ContractId, Hash, InvokeContractArgs, ReadXdr as _, ScAddress, ScSymbol,
        SorobanAuthorizedFunction,
    };

    /// The root of a transfer on the contract `[1; 32]` with no arguments
    /// and no sub-invocations.
    fn root() -> SorobanAuthorizedInvocation {
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([1; 32]))),
                function_name: ScSymbol("transfer".try_into().unwrap()),
                args: Vec::new().try_into().unwrap(),
            }),
            sub_invocations: Vec::new().try_into().unwrap(),
        }
    }

    /// The root's XDR, encoded independently by the XDR toolchain.
    const ROOT_XDR_B64: &str =
        "AAAAAAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAAh0cmFuc2ZlcgAAAAAAAAAA";

    #[test]
    fn the_root_fixture_encodes_to_the_independent_xdr() {
        let decoded =
            SorobanAuthorizedInvocation::from_xdr_base64(ROOT_XDR_B64, Limits::none()).unwrap();
        assert_eq!(decoded, root());
    }

    /// The classic subject hashes the base64 text, not the decoded bytes.
    #[test]
    fn the_classic_subject_hashes_the_text() {
        assert_eq!(
            crate::hex::encode(&approval_subject_classic("AAAA")),
            "63c1dd951ffedf6f7fd968ad4efa39b8ed584f162f46e715114ee184f8de9201"
        );
    }

    /// The two x402 subjects follow their layouts and differ for one intent.
    #[test]
    fn the_x402_subjects_follow_their_layouts() {
        let intent = [0x22; 32];
        assert_eq!(
            crate::hex::encode(&approval_subject_x402(&intent)),
            "09aeccdb903274b21746582271e530d133fdfdd77f924e84c02c7193ba98bd98"
        );
        assert_eq!(
            crate::hex::encode(&approval_subject_x402_authenticated(&intent, "example.org")),
            "777f0ec44d4f1eb807c62baff2dabdfbeced7992ecfeb98af59dbacc22e02afa"
        );
        assert_ne!(
            approval_subject_x402(&intent),
            approval_subject_x402_authenticated(&intent, "")
        );
    }

    /// The intent and root digests follow their layouts over the root XDR,
    /// and the intent digest names the network.
    #[test]
    fn the_soroban_digests_follow_their_layouts() {
        let network_id = [0x33; 32];
        assert_eq!(
            crate::hex::encode(&soroban_intent_digest(&network_id, &root()).unwrap()),
            "401380f09b8041517e1ad73b4fe797c3695a4ff08089d1426d78fda08d05f03c"
        );
        assert_eq!(
            crate::hex::encode(&root_invocation_digest(&root()).unwrap()),
            "6ed9f531aac38bdb7ccbd8434b0f66ac8b1abb0dc0ca5e5744d24cd8a45db34d"
        );
        assert_ne!(
            soroban_intent_digest(&network_id, &root()).unwrap(),
            soroban_intent_digest(&[0x34; 32], &root()).unwrap()
        );
        let mut deeper = root();
        deeper.sub_invocations = vec![root()].try_into().unwrap();
        assert_ne!(
            root_invocation_digest(&deeper).unwrap(),
            root_invocation_digest(&root()).unwrap()
        );
    }

    #[test]
    fn root_arguments_and_child_order_have_frozen_digests() {
        let node = |n| {
            let mut r = root();
            let SorobanAuthorizedFunction::ContractFn(ref mut f) = r.function else {
                unreachable!()
            };
            f.args = vec![stellar_xdr::ScVal::U32(n)].try_into().unwrap();
            r
        };
        let mut tree = node(1);
        tree.sub_invocations = vec![node(2), node(3)].try_into().unwrap();
        assert_eq!(
            crate::hex::encode(&root_invocation_digest(&tree).unwrap()),
            "acf10491a750c9b3af94d1d8550b364b6e7d9f4f7a86fc63c58d0acdc58740c3"
        );
        tree.sub_invocations = vec![node(3), node(2)].try_into().unwrap();
        assert_eq!(
            crate::hex::encode(&root_invocation_digest(&tree).unwrap()),
            "3ad7510c4c7417e6d3dcf61f854798abdce225a81028693299ae878fa5cc01df"
        );
    }
}
