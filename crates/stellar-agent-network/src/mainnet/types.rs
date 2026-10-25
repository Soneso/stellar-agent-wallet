//! The vocabulary every mainnet authorization, its ledger record, and its
//! refusals share.

use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};

/// The durable identity of one mainnet authorization.
///
/// Drawn from the operating system's random source when the store mints the
/// record, and checked for collision under the store's lock. The same value
/// names the authorization's window reservation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AuthorizationId([u8; 32]);

impl AuthorizationId {
    /// The identity with these bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The identity's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The identity as 64 lowercase hex characters, its stored form.
    #[must_use]
    pub fn to_hex(&self) -> String {
        stellar_agent_core::hex::encode(&self.0)
    }

    /// Parses the stored form.
    pub(crate) fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 || hex.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        stellar_agent_core::hex::decode_hex32(hex).ok().map(Self)
    }

    /// A fresh identity from the operating system's random source.
    pub(crate) fn random() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl Serialize for AuthorizationId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for AuthorizationId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::from_hex(&text)
            .ok_or_else(|| serde::de::Error::custom("expected 64 lowercase hex characters"))
    }
}

impl std::fmt::Debug for AuthorizationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = self.to_hex();
        write!(f, "AuthorizationId({}…)", &hex[..8])
    }
}

/// What an authorization authorizes, and so which subject its content digest
/// names, which holds it owns, and how it is consumed.
///
/// The discriminants are the one-byte domain tags of the content digest and
/// remain stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum AuthorizationDomain {
    /// Signing a classic transaction.
    Transaction = 1,
    /// Signing the inner transaction of a fee bump.
    FeeBumpInner = 2,
    /// Signing the outer fee-bump transaction.
    FeeBumpOuter = 3,
    /// Submitting a signed fee bump.
    FeeBumpSubmit = 4,
    /// Releasing a signed x402 payment payload.
    X402Submit = 5,
    /// Signing a Soroban authorization for an x402 payment intent.
    Soroban = 6,
    /// Signing a message, such as a SEP-10 challenge.
    Message = 7,
}

/// Which holds an authorization of a domain owns between its mint and its
/// consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldOwner {
    /// The action's value entries.
    ValueHolds,
    /// The fee payer's fee entries.
    FeeHolds,
    /// No holds: the domain debits nothing.
    NoHolds,
}

/// How an authorization of a domain is consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumeBindingKind {
    /// Its holds become the pending records of one submission.
    Transaction,
    /// Its holds become retained authorized spend.
    RetainedIntent,
    /// The signed payload is released with no second spend.
    PayloadRelease,
    /// A zero-debit record settles.
    Message,
}

impl AuthorizationDomain {
    /// Every domain, in tag order.
    pub const ALL: [Self; 7] = [
        Self::Transaction,
        Self::FeeBumpInner,
        Self::FeeBumpOuter,
        Self::FeeBumpSubmit,
        Self::X402Submit,
        Self::Soroban,
        Self::Message,
    ];

    /// The domain's one-byte tag in the content digest.
    #[must_use]
    pub fn tag(self) -> u8 {
        self as u8
    }

    /// The subject the content digest of this domain names.
    #[must_use]
    pub fn subject(self) -> &'static str {
        match self {
            Self::Transaction => "unsigned transaction hash",
            Self::FeeBumpInner => "inner transaction hash",
            Self::FeeBumpOuter | Self::FeeBumpSubmit => "outer transaction hash",
            Self::X402Submit => "final envelope hash (submit::envelope_hash_hex bytes)",
            Self::Soroban => "Soroban intent digest",
            Self::Message => "message content digest",
        }
    }

    /// Which holds an authorization of this domain owns.
    #[must_use]
    pub fn hold_owner(self) -> HoldOwner {
        match self {
            Self::Transaction | Self::FeeBumpInner | Self::Soroban => HoldOwner::ValueHolds,
            Self::FeeBumpOuter => HoldOwner::FeeHolds,
            Self::FeeBumpSubmit | Self::X402Submit | Self::Message => HoldOwner::NoHolds,
        }
    }

    /// How an authorization of this domain is consumed.
    #[must_use]
    pub fn consume_binding(self) -> ConsumeBindingKind {
        match self {
            Self::Transaction | Self::FeeBumpInner | Self::FeeBumpOuter => {
                ConsumeBindingKind::Transaction
            }
            Self::Soroban => ConsumeBindingKind::RetainedIntent,
            Self::FeeBumpSubmit | Self::X402Submit => ConsumeBindingKind::PayloadRelease,
            Self::Message => ConsumeBindingKind::Message,
        }
    }

    /// Whether the domain requires an endpoint binding: every domain but
    /// [`AuthorizationDomain::Message`], which a message signing reaches
    /// without an RPC endpoint.
    #[must_use]
    pub fn requires_endpoint(self) -> bool {
        self != Self::Message
    }
}

/// The verb an authorization is minted for and may be consumed by.
///
/// One variant per verb that writes on mainnet; a check compares the
/// consuming verb with the authorization's, so authority minted for one verb
/// never serves another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MainnetConsumer {
    /// CLI `pay`.
    CliPay,
    /// CLI `claim`.
    CliClaim,
    /// CLI `accounts create`.
    CliCreateAccount,
    /// CLI `trustline`.
    CliTrustline,
    /// MCP `stellar_pay_commit`.
    McpPay,
    /// MCP `stellar_claim_commit`.
    McpClaim,
    /// MCP `stellar_create_account_commit`.
    McpCreateAccount,
    /// MCP `stellar_trustline_commit`.
    McpTrustline,
    /// MCP `x402_create_payment`.
    X402Create,
    /// MCP `x402_authenticated_payment`.
    X402Authenticated,
}

/// The role a signer acts in under an authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerRole {
    /// The profile's enrolled agent signer.
    AgentSigner,
    /// The fee payer of a fee bump: the enrolled agent key.
    FeePayer,
    /// A SEP-10 session's ephemeral key.
    Sep10Ephemeral,
}

impl SignerRole {
    /// The role's one-byte tag in the signer fact digest.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::AgentSigner => 1,
            Self::FeePayer => 2,
            Self::Sep10Ephemeral => 3,
        }
    }
}

/// The domains and server key a message authorization binds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageDomain {
    /// The home domain the session authenticates to.
    pub home_domain: String,
    /// The resolved web authentication domain.
    pub web_auth_domain: String,
    /// The server signing key, as its 32 bytes in lowercase hex on the wire.
    #[serde(with = "crate::mainnet::types::hex32")]
    pub server_key: [u8; 32],
}

/// The audit facts a consumer reads from a fresh
/// [`stellar_agent_core::audit_log::AuditWriter::verified_tip_facts`] at use
/// time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditFacts {
    /// The hash the active segment's first entry links to.
    pub segment: [u8; 32],
    /// The digest of the active log path.
    pub log_path_digest: [u8; 32],
    /// The anchored entry count, read only when the anchor covers the tip.
    pub anchored_count: u64,
}

/// What a consumer recomputed from the action it is about to perform, handed
/// to an authorization's `consume_expect`.
///
/// The authorization combines these with its own bound facts into the
/// expectation the store compares; the bound facts never leave the
/// authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecomputedFacts {
    /// The content digest of the action, under the authorization's domain.
    pub content_digest: [u8; 32],
    /// The digest of the window entries the action holds.
    pub entries_digest: [u8; 32],
    /// The fresh audit facts.
    pub audit: AuditFacts,
}

/// Serde adapter for a 32-byte value stored as 64 lowercase hex characters.
pub(crate) mod hex32 {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(value: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&stellar_agent_core::hex::encode(value))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        if text.len() != 64 || text.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(serde::de::Error::custom(
                "expected 64 lowercase hex characters",
            ));
        }
        stellar_agent_core::hex::decode_hex32(&text)
            .map_err(|_| serde::de::Error::custom("expected 64 lowercase hex characters"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use super::*;

    /// The table of domains, generated from the enum: tag, subject, hold
    /// owner, and consume binding. The ledger, the digests, and the consumers
    /// agree on exactly these seven rows.
    #[test]
    fn the_domain_table_is_frozen() {
        let rows: Vec<String> = AuthorizationDomain::ALL
            .iter()
            .map(|domain| {
                format!(
                    "{} | {:?} | {} | {:?} | {:?}",
                    domain.tag(),
                    domain,
                    domain.subject(),
                    domain.hold_owner(),
                    domain.consume_binding()
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                "1 | Transaction | unsigned transaction hash | ValueHolds | Transaction",
                "2 | FeeBumpInner | inner transaction hash | ValueHolds | Transaction",
                "3 | FeeBumpOuter | outer transaction hash | FeeHolds | Transaction",
                "4 | FeeBumpSubmit | outer transaction hash | NoHolds | PayloadRelease",
                "5 | X402Submit | final envelope hash (submit::envelope_hash_hex bytes) | NoHolds | PayloadRelease",
                "6 | Soroban | Soroban intent digest | ValueHolds | RetainedIntent",
                "7 | Message | message content digest | NoHolds | Message",
            ]
        );
        assert!(
            AuthorizationDomain::ALL
                .iter()
                .all(|d| d.requires_endpoint() != (*d == AuthorizationDomain::Message))
        );
    }

    #[test]
    fn identities_round_trip_their_stored_form() {
        let id = AuthorizationId::random();
        assert_eq!(AuthorizationId::from_hex(&id.to_hex()), Some(id));
        assert_eq!(
            AuthorizationId::from_hex(&id.to_hex().to_ascii_uppercase()),
            None
        );
        assert_eq!(AuthorizationId::from_hex("ab"), None);
        assert_ne!(AuthorizationId::random(), id);
        let shown = format!("{id:?}");
        assert!(
            shown.starts_with("AuthorizationId(") && shown.len() < 30,
            "{shown}"
        );
    }
}
