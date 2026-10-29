//! The verified signed policy of a mainnet profile.
//!
//! A [`VerifiedPolicy`](crate::mainnet::verified_policy::VerifiedPolicy) is produced by the policy
//! loader after it has checked
//! the owner's signature over the canonical policy bytes, and nowhere else:
//! its constructor is crate-private and its fields are private, so holding
//! one means the loader accepted the document it describes.
//!
//! ```compile_fail,E0451
//! use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
//! fn forge(p: VerifiedPolicy) -> VerifiedPolicy { VerifiedPolicy { ..p } }
//! ```
//!
//! The import alone resolves, so the snippet above fails on the field
//! privacy and not on the path:
//!
//! ```
//! use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
//! fn need(_: Option<VerifiedPolicy>) {}
//! need(None);
//! ```
//!
//! The proof implements none of `Serialize`, `Deserialize`, or `Default`:
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
//! fn need<T: serde::Serialize>() {}
//! need::<VerifiedPolicy>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
//! fn need<T: serde::de::DeserializeOwned>() {}
//! need::<VerifiedPolicy>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
//! fn need<T: Default>() {}
//! need::<VerifiedPolicy>();
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use super::fact::{FACT_LABEL_POLICY, FactDigest};
use crate::approval::presence::MainnetApprovalCredential;
use crate::policy::v1::PolicyEngineV1;

/// The mainnet section of a signed policy document.
///
/// Parsed by the policy loader from the owner-signed document; it reaches a
/// caller only through [`VerifiedPolicy::mainnet`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MainnetBody {
    /// The profile name the document enables mainnet writes for.
    pub profile: String,
    /// The RPC endpoint host the document allows.
    pub endpoint_host: String,
    /// SHA-256 of the installation's mainnet enablement nonce.
    pub installation_nonce_sha256: [u8; 32],
    /// The classic per-operation fee cap, in stroops.
    pub classic_max_fee_per_op_stroops: u32,
    /// The lifetime of a mainnet authorization, in seconds, when the document
    /// sets one.
    pub authorization_ttl_seconds: Option<u32>,
    /// Per-asset cross-check thresholds, in base units, when the document
    /// sets them.
    pub cross_check_thresholds: Option<BTreeMap<String, i128>>,
    /// The approval credentials the owner admits for mainnet consent, 1 to
    /// 16 entries with unique IDs, in ascending order of their raw IDs.
    pub approval_credentials: Vec<MainnetApprovalCredential>,
}

/// A signed policy the loader verified, with its engine.
///
/// See the module documentation for why holding one proves the verification.
/// The `sequence` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
/// fn inspect(p: &VerifiedPolicy) { let _ = &p.sequence; }
/// ```
///
/// ```
/// use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
/// fn need(_: Option<VerifiedPolicy>) {}
/// need(None);
/// ```
///
/// The `digest` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
/// fn inspect(p: &VerifiedPolicy) { let _ = &p.digest; }
/// ```
///
/// ```
/// use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
/// fn need(_: Option<VerifiedPolicy>) {}
/// need(None);
/// ```
///
/// The `owner` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
/// fn inspect(p: &VerifiedPolicy) { let _ = &p.owner; }
/// ```
///
/// ```
/// use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
/// fn need(_: Option<VerifiedPolicy>) {}
/// need(None);
/// ```
///
/// The `engine` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
/// fn inspect(p: &VerifiedPolicy) { let _ = &p.engine; }
/// ```
///
/// ```
/// use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
/// fn need(_: Option<VerifiedPolicy>) {}
/// need(None);
/// ```
///
/// The `mainnet` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
/// fn inspect(p: &VerifiedPolicy) { let _ = &p.mainnet; }
/// ```
///
/// ```
/// use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
/// fn need(_: Option<VerifiedPolicy>) {}
/// need(None);
/// ```
///
#[derive(Clone)]
pub struct VerifiedPolicy {
    sequence: i64,
    digest: [u8; 32],
    owner: [u8; 32],
    engine: Arc<PolicyEngineV1>,
    mainnet: Option<MainnetBody>,
}

impl std::fmt::Debug for VerifiedPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedPolicy")
            .field("sequence", &self.sequence)
            .field(
                "digest",
                &crate::hex::redact_hex_first8_last8(&crate::hex::encode(&self.digest)),
            )
            .field("mainnet", &self.mainnet.is_some())
            .finish_non_exhaustive()
    }
}

impl VerifiedPolicy {
    /// Records the policy the loader verified: the signed `sequence` (`0` for
    /// a version 1 document), the `canonical_bytes` the signature covers, the
    /// verifying `owner` key, the engine built from the document, and its
    /// mainnet section.
    ///
    /// The digest is the BLAKE3 digest of `canonical_bytes`.
    pub(crate) fn from_verified(
        sequence: i64,
        canonical_bytes: &[u8],
        owner: [u8; 32],
        engine: Arc<PolicyEngineV1>,
        mainnet: Option<MainnetBody>,
    ) -> Self {
        Self {
            sequence,
            digest: *blake3::hash(canonical_bytes).as_bytes(),
            owner,
            engine,
            mainnet,
        }
    }

    /// The signed policy sequence; `0` for a version 1 document.
    #[must_use]
    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    /// The BLAKE3 digest of the policy's canonical bytes.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The owner public key whose signature the loader verified.
    #[must_use]
    pub fn owner(&self) -> [u8; 32] {
        self.owner
    }

    /// The engine built from the verified document.
    #[must_use]
    pub fn engine(&self) -> Arc<PolicyEngineV1> {
        Arc::clone(&self.engine)
    }

    /// The document's mainnet section, when it has one.
    #[must_use]
    pub fn mainnet(&self) -> Option<&MainnetBody> {
        self.mainnet.as_ref()
    }

    /// The fact digest under `stellar-agent-authz-fact:policy:v1`.
    ///
    /// Fields, in order: `i64be(sequence)`, the 32-byte digest, the 32-byte
    /// owner key, then the optional mainnet section: `lp(profile)`,
    /// `lp(endpoint_host)`, the 32-byte installation nonce digest,
    /// `u32be(classic_max_fee_per_op_stroops)`, the optional
    /// `u32be(authorization_ttl_seconds)`, the optional threshold table, and
    /// the approval credentials: `u32be(count)`, then per credential in
    /// ascending ID order `lp(raw_id)` and the 65-byte SEC1 key. The policy
    /// parser bounds the list to 16 entries of at most 64-byte IDs, so every
    /// length fits its `u32` prefix. The engine is not a fact: the digest
    /// already names the document it was built from.
    #[must_use]
    pub fn fact_digest(&self) -> [u8; 32] {
        let mut digest = FactDigest::new(FACT_LABEL_POLICY);
        digest
            .i64(self.sequence)
            .fixed(&self.digest)
            .fixed(&self.owner)
            .present(self.mainnet.is_some());
        if let Some(body) = &self.mainnet {
            digest
                .bytes(body.profile.as_bytes())
                .bytes(body.endpoint_host.as_bytes())
                .fixed(&body.installation_nonce_sha256)
                .u32(body.classic_max_fee_per_op_stroops)
                .opt_u32(body.authorization_ttl_seconds)
                .thresholds(body.cross_check_thresholds.as_ref())
                .u32(u32::try_from(body.approval_credentials.len()).unwrap_or(u32::MAX));
            for credential in &body.approval_credentials {
                digest
                    .bytes(credential.credential_id())
                    .fixed(credential.public_key_sec1());
            }
        }
        digest.finish()
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

    use super::*;
    use crate::policy::v1::{PolicyDocument, ScopeId};

    fn engine() -> Arc<PolicyEngineV1> {
        Arc::new(PolicyEngineV1::new(
            PolicyDocument {
                version: 1,
                scope: ScopeId::AllProfiles,
                rules: Vec::new(),
                signature: None,
            },
            "main".to_owned(),
        ))
    }

    fn credential() -> MainnetApprovalCredential {
        let authenticator = stellar_agent_test_support::webauthn::TestAuthenticator::from_seed(
            [0x21; 32],
            vec![0x5a; 16],
        );
        MainnetApprovalCredential::from_raw(
            authenticator.credential_id(),
            &authenticator.public_key_sec1(),
        )
        .expect("fixture credential")
    }

    fn body() -> MainnetBody {
        let mut thresholds = BTreeMap::new();
        thresholds.insert("USDC:GA".to_owned(), 5_i128);
        MainnetBody {
            profile: "main".to_owned(),
            endpoint_host: "rpc.example.org".to_owned(),
            installation_nonce_sha256: [3; 32],
            classic_max_fee_per_op_stroops: 1_000,
            authorization_ttl_seconds: Some(60),
            cross_check_thresholds: Some(thresholds),
            approval_credentials: vec![credential()],
        }
    }

    /// The getters return what the loader recorded, the digest is BLAKE3 of
    /// the canonical bytes, and the fact digest follows the documented layout
    /// and a frozen vector.
    #[test]
    fn getters_and_fact_digest_follow_the_contract() {
        let policy = VerifiedPolicy::from_verified(4, b"", [9; 32], engine(), Some(body()));
        assert_eq!(policy.sequence(), 4);
        assert_eq!(
            crate::hex::encode(&policy.digest()),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            "the BLAKE3 digest of the empty input"
        );
        assert_eq!(policy.owner(), [9; 32]);
        assert_eq!(policy.mainnet(), Some(&body()));
        assert!(Arc::ptr_eq(&policy.engine(), &policy.engine));

        let mut expected = FACT_LABEL_POLICY.to_vec();
        expected.extend(4_i64.to_be_bytes());
        expected.extend(policy.digest());
        expected.extend([9; 32]);
        expected.push(1);
        expected.extend(4_u32.to_be_bytes());
        expected.extend(b"main");
        expected.extend(15_u32.to_be_bytes());
        expected.extend(b"rpc.example.org");
        expected.extend([3; 32]);
        expected.extend(1_000_u32.to_be_bytes());
        expected.push(1);
        expected.extend(60_u32.to_be_bytes());
        expected.push(1);
        expected.extend(1_u32.to_be_bytes());
        expected.extend(7_u32.to_be_bytes());
        expected.extend(b"USDC:GA");
        expected.extend(5_i128.to_be_bytes());
        expected.extend(1_u32.to_be_bytes());
        expected.extend(16_u32.to_be_bytes());
        expected.extend([0x5a; 16]);
        expected.extend(credential().public_key_sec1());
        let independent: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&expected).into();
        assert_eq!(policy.fact_digest(), independent);
        assert_eq!(
            crate::hex::encode(&policy.fact_digest()),
            "1de9d5c8d749b4077eecbd02f0bc63f5be21b41852809b2ccf184b322ad93900"
        );

        let bare = VerifiedPolicy::from_verified(0, b"canonical", [9; 32], engine(), None);
        assert_eq!(bare.sequence(), 0);
        assert_eq!(bare.digest(), *blake3::hash(b"canonical").as_bytes());
        assert_ne!(bare.digest(), policy.digest());
        assert!(bare.mainnet().is_none());
        assert_ne!(bare.fact_digest(), policy.fact_digest());

        // Each credential field is a fact: a changed ID, a changed key, or an
        // absent credential changes the digest.
        let other_key = stellar_agent_test_support::webauthn::TestAuthenticator::from_seed(
            [0x22; 32],
            vec![0x5a; 16],
        )
        .public_key_sec1();
        for credentials in [
            vec![
                MainnetApprovalCredential::from_raw(&[0x5b; 16], credential().public_key_sec1())
                    .expect("fixture"),
            ],
            vec![MainnetApprovalCredential::from_raw(&[0x5a; 16], &other_key).expect("fixture")],
            Vec::new(),
        ] {
            let mut changed = body();
            changed.approval_credentials = credentials;
            let changed = VerifiedPolicy::from_verified(4, b"", [9; 32], engine(), Some(changed));
            assert_ne!(changed.fact_digest(), policy.fact_digest());
        }
    }
}
