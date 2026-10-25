//! The verified mainnet enablement of a profile.
//!
//! An [`EnablementRecord`](crate::mainnet::enablement::EnablementRecord) states that the
//! installation's mainnet enablement
//! nonce, the profile, the endpoint host, and the fee and authorization
//! limits agree with the verified signed policy. The verifier produces it
//! through a crate-private constructor, and its fields are private, so
//! holding one means that verification succeeded.
//!
//! ```compile_fail,E0451
//! use stellar_agent_core::mainnet::enablement::EnablementRecord;
//! fn forge(p: EnablementRecord) -> EnablementRecord { EnablementRecord { ..p } }
//! ```
//!
//! The import alone resolves:
//!
//! ```
//! use stellar_agent_core::mainnet::enablement::EnablementRecord;
//! fn need(_: Option<EnablementRecord>) {}
//! need(None);
//! ```
//!
//! The proof implements none of `Serialize`, `Deserialize`, or `Default`:
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::mainnet::enablement::EnablementRecord;
//! fn need<T: serde::Serialize>() {}
//! need::<EnablementRecord>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::mainnet::enablement::EnablementRecord;
//! fn need<T: serde::de::DeserializeOwned>() {}
//! need::<EnablementRecord>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::mainnet::enablement::EnablementRecord;
//! fn need<T: Default>() {}
//! need::<EnablementRecord>();
//! ```

use std::collections::BTreeMap;

use super::fact::{FACT_LABEL_ENABLEMENT, FactDigest};

/// The verified mainnet enablement of one profile.
///
/// See the module documentation for why holding one proves the verification.
/// The `profile` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::mainnet::enablement::EnablementRecord;
/// fn inspect(p: &EnablementRecord) { let _ = &p.profile; }
/// ```
///
/// ```
/// use stellar_agent_core::mainnet::enablement::EnablementRecord;
/// fn need(_: Option<EnablementRecord>) {}
/// need(None);
/// ```
///
/// The `endpoint_host` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::mainnet::enablement::EnablementRecord;
/// fn inspect(p: &EnablementRecord) { let _ = &p.endpoint_host; }
/// ```
///
/// ```
/// use stellar_agent_core::mainnet::enablement::EnablementRecord;
/// fn need(_: Option<EnablementRecord>) {}
/// need(None);
/// ```
///
/// The `nonce_digest` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::mainnet::enablement::EnablementRecord;
/// fn inspect(p: &EnablementRecord) { let _ = &p.nonce_digest; }
/// ```
///
/// ```
/// use stellar_agent_core::mainnet::enablement::EnablementRecord;
/// fn need(_: Option<EnablementRecord>) {}
/// need(None);
/// ```
///
/// The `policy_sequence` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::mainnet::enablement::EnablementRecord;
/// fn inspect(p: &EnablementRecord) { let _ = &p.policy_sequence; }
/// ```
///
/// ```
/// use stellar_agent_core::mainnet::enablement::EnablementRecord;
/// fn need(_: Option<EnablementRecord>) {}
/// need(None);
/// ```
///
/// The `fee_cap` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::mainnet::enablement::EnablementRecord;
/// fn inspect(p: &EnablementRecord) { let _ = &p.fee_cap; }
/// ```
///
/// ```
/// use stellar_agent_core::mainnet::enablement::EnablementRecord;
/// fn need(_: Option<EnablementRecord>) {}
/// need(None);
/// ```
///
/// The `authorization_ttl` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::mainnet::enablement::EnablementRecord;
/// fn inspect(p: &EnablementRecord) { let _ = &p.authorization_ttl; }
/// ```
///
/// ```
/// use stellar_agent_core::mainnet::enablement::EnablementRecord;
/// fn need(_: Option<EnablementRecord>) {}
/// need(None);
/// ```
///
/// The `thresholds` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::mainnet::enablement::EnablementRecord;
/// fn inspect(p: &EnablementRecord) { let _ = &p.thresholds; }
/// ```
///
/// ```
/// use stellar_agent_core::mainnet::enablement::EnablementRecord;
/// fn need(_: Option<EnablementRecord>) {}
/// need(None);
/// ```
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnablementRecord {
    profile: String,
    endpoint_host: String,
    nonce_digest: [u8; 32],
    policy_sequence: i64,
    fee_cap: u32,
    authorization_ttl: Option<u32>,
    thresholds: Option<BTreeMap<String, i128>>,
}

impl EnablementRecord {
    /// Records a verified enablement: the profile and endpoint host it
    /// enables, the SHA-256 of the installation nonce, the sequence of the
    /// verified policy it agrees with, the classic per-operation fee cap in
    /// stroops, the authorization lifetime in seconds, and the cross-check
    /// thresholds.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "constructed by the policy loader")
    )]
    #[allow(
        clippy::too_many_arguments,
        reason = "one constructor records every verified enablement fact"
    )]
    pub(crate) fn from_verified(
        profile: String,
        endpoint_host: String,
        nonce_digest: [u8; 32],
        policy_sequence: i64,
        fee_cap: u32,
        authorization_ttl: Option<u32>,
        thresholds: Option<BTreeMap<String, i128>>,
    ) -> Self {
        Self {
            profile,
            endpoint_host,
            nonce_digest,
            policy_sequence,
            fee_cap,
            authorization_ttl,
            thresholds,
        }
    }

    /// The enabled profile's name.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The enabled RPC endpoint host.
    #[must_use]
    pub fn endpoint_host(&self) -> &str {
        &self.endpoint_host
    }

    /// SHA-256 of the installation's mainnet enablement nonce.
    #[must_use]
    pub fn nonce_digest(&self) -> &[u8; 32] {
        &self.nonce_digest
    }

    /// The sequence of the verified policy the enablement agrees with.
    #[must_use]
    pub fn policy_sequence(&self) -> i64 {
        self.policy_sequence
    }

    /// The classic per-operation fee cap, in stroops.
    #[must_use]
    pub fn fee_cap(&self) -> u32 {
        self.fee_cap
    }

    /// The authorization lifetime in seconds, when the policy sets one.
    #[must_use]
    pub fn authorization_ttl(&self) -> Option<u32> {
        self.authorization_ttl
    }

    /// The per-asset cross-check thresholds, when the policy sets them.
    #[must_use]
    pub fn thresholds(&self) -> Option<&BTreeMap<String, i128>> {
        self.thresholds.as_ref()
    }

    /// The fact digest under `stellar-agent-authz-fact:enablement:v1`.
    ///
    /// Fields, in order: `lp(profile)`, `lp(endpoint_host)`, the 32-byte
    /// nonce digest, `i64be(policy_sequence)`, `u32be(fee_cap)`, the optional
    /// `u32be(authorization_ttl)`, and the optional threshold table.
    #[must_use]
    pub fn fact_digest(&self) -> [u8; 32] {
        let mut digest = FactDigest::new(FACT_LABEL_ENABLEMENT);
        digest
            .bytes(self.profile.as_bytes())
            .bytes(self.endpoint_host.as_bytes())
            .fixed(&self.nonce_digest)
            .i64(self.policy_sequence)
            .u32(self.fee_cap)
            .opt_u32(self.authorization_ttl)
            .thresholds(self.thresholds.as_ref());
        digest.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The getters return what the verifier recorded and the fact digest
    /// follows the documented layout and a frozen vector.
    #[test]
    fn getters_and_fact_digest_follow_the_contract() {
        let record = EnablementRecord::from_verified(
            "main".to_owned(),
            "rpc.example.org".to_owned(),
            [4; 32],
            7,
            500,
            None,
            None,
        );
        assert_eq!(record.profile(), "main");
        assert_eq!(record.endpoint_host(), "rpc.example.org");
        assert_eq!(record.nonce_digest(), &[4; 32]);
        assert_eq!(record.policy_sequence(), 7);
        assert_eq!(record.fee_cap(), 500);
        assert_eq!(record.authorization_ttl(), None);
        assert_eq!(record.thresholds(), None);

        let mut expected = FACT_LABEL_ENABLEMENT.to_vec();
        expected.extend(4_u32.to_be_bytes());
        expected.extend(b"main");
        expected.extend(15_u32.to_be_bytes());
        expected.extend(b"rpc.example.org");
        expected.extend([4; 32]);
        expected.extend(7_i64.to_be_bytes());
        expected.extend(500_u32.to_be_bytes());
        expected.push(0);
        expected.push(0);
        let independent: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&expected).into();
        assert_eq!(record.fact_digest(), independent);
        assert_eq!(
            crate::hex::encode(&record.fact_digest()),
            "3226f264738bd07f190eb81e3ccaf67f64630304a831675fcd3858c340e01800"
        );
    }

    #[test]
    fn the_fact_digest_covers_present_ttl_and_thresholds() {
        let thresholds = BTreeMap::from([("b".to_owned(), 2), ("a".to_owned(), 1)]);
        let record = EnablementRecord::from_verified(
            "main".to_owned(),
            "rpc.example.org".to_owned(),
            [4; 32],
            7,
            500,
            Some(60),
            Some(thresholds),
        );
        assert_eq!(
            crate::hex::encode(&record.fact_digest()),
            "9b345afa62260aae121d165979de774d333b022df227e8e043bec5871484cf46"
        );
    }
}
