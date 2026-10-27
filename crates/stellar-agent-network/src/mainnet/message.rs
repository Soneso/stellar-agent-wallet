//! The SEP-10 message domain: the facts a challenge signing proposes, the
//! receipt of a consumed message authorization, and the checks that bind a
//! challenge to that receipt before the ephemeral key signs it.
//!
//! A SEP-10 challenge on mainnet is signed only after three steps. The
//! message resolver mints a zero-value [`super::AuthorizationDomain::Message`]
//! record over [`MessageFacts`]; the consume makes that record durably used
//! and returns a [`MessageUseReceipt`]; and
//! [`check_challenge_against_receipt`] compares the challenge the SEP-10
//! client prepared with the facts the receipt holds. Every binding comparison
//! lives here, so the SEP-10 signing point compares nothing itself.
//!
//! [`check_client_account`] also runs before the mint, so a challenge issued
//! for another account never spends an approval.
//!
//! Without the `mainnet-write` feature no receipt exists: its field is
//! uninhabited, and the challenge check is the empty match that proves it.

use super::refusal::require;
use super::{
    AuthorizationId, MainnetAuthorizationError, MainnetConsumer, MainnetPrecondition as P,
    MessageDomain,
};

/// The facts of one SEP-10 challenge signing, as the SEP-10 client proposes
/// them.
///
/// Plain data, not a proof: the signing point checks them against the
/// challenge it prepared and validated before it signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageFacts {
    /// The home domain, the web authentication domain, and the server key.
    pub domain: MessageDomain,
    /// SHA-256 of the challenge's `TransactionSignaturePayload` XDR: the hash
    /// the ephemeral key signs.
    pub content_digest: [u8; 32],
    /// The ephemeral key that signs the challenge.
    pub ephemeral_public_key: [u8; 32],
}

/// What the signing point knows about the challenge it is about to sign.
#[derive(Debug)]
pub struct ChallengeFacts<'a> {
    /// SHA-256 of the passphrase under which the challenge and its server
    /// signature were validated.
    pub validated_network_id: [u8; 32],
    /// SHA-256 of the passphrase the challenge is signed for.
    pub completion_network_id: [u8; 32],
    /// The message the signature covers.
    pub message: &'a MessageFacts,
    /// The challenge's client account, as the challenge names it.
    pub client_account: &'a str,
}

/// Proof that a message authorization was consumed: the record is durably
/// used, and the receipt holds every fact it bound.
///
/// Only the message consume constructs one. The receipt owns the
/// authorization's audit lease, which it releases when it drops. It derives
/// nothing, so it cannot be copied into a second signing.
///
/// ```compile_fail
/// use stellar_agent_network::mainnet::message::MessageUseReceipt;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<MessageUseReceipt>();
/// ```
pub struct MessageUseReceipt(
    #[cfg(feature = "mainnet-write")] ConsumedMessage,
    #[cfg(not(feature = "mainnet-write"))] std::convert::Infallible,
);

/// The consumed authorization and the message facts its binding held.
#[cfg(feature = "mainnet-write")]
struct ConsumedMessage {
    inner: super::authorization::MessageSignInner,
    facts: MessageFacts,
}

impl MessageUseReceipt {
    /// The receipt of the consumed authorization `inner`, whose message
    /// binding held `facts`.
    #[cfg(feature = "mainnet-write")]
    pub(crate) fn new(inner: super::authorization::MessageSignInner, facts: MessageFacts) -> Self {
        Self(ConsumedMessage { inner, facts })
    }

    /// The identity of the consumed authorization record.
    #[must_use]
    pub fn id(&self) -> AuthorizationId {
        #[cfg(feature = "mainnet-write")]
        {
            self.0.inner.header.id
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            match self.0 {}
        }
    }

    /// The home domain the consumed authorization bound.
    #[must_use]
    pub fn home_domain(&self) -> &str {
        #[cfg(feature = "mainnet-write")]
        {
            self.0.facts.domain.home_domain.as_str()
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            match self.0 {}
        }
    }

    /// The content digest the consumed authorization bound.
    #[must_use]
    pub fn content_digest(&self) -> [u8; 32] {
        #[cfg(feature = "mainnet-write")]
        {
            self.0.facts.content_digest
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            match self.0 {}
        }
    }

    /// The ephemeral key the consumed authorization bound.
    #[must_use]
    pub fn ephemeral_public_key(&self) -> [u8; 32] {
        #[cfg(feature = "mainnet-write")]
        {
            self.0.facts.ephemeral_public_key
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            match self.0 {}
        }
    }
}

impl std::fmt::Debug for MessageUseReceipt {
    /// The domain, an identity prefix, and the home domain; nothing else.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(feature = "mainnet-write")]
        {
            f.debug_struct("MessageUseReceipt")
                .field("domain", &self.0.inner.header.domain)
                .field("id", &self.0.inner.header.id)
                .field("home_domain", &self.home_domain())
                .finish_non_exhaustive()
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            let _ = f;
            match self.0 {}
        }
    }
}

/// Requires `client_account` to be the G-strkey of `ephemeral_public_key`.
///
/// A SEP-10 challenge names the account it authenticates; the ephemeral key
/// may sign only a challenge for its own account.
///
/// # Errors
///
/// [`MainnetAuthorizationError::Refused`] with
/// [`MainnetPrecondition::MessageClientAccount`](super::MainnetPrecondition::MessageClientAccount)
/// for a muxed account, any other strkey kind, a string that does not
/// decode, and the account of another key.
pub fn check_client_account(
    client_account: &str,
    ephemeral_public_key: &[u8; 32],
) -> Result<(), MainnetAuthorizationError> {
    let account = stellar_strkey::ed25519::PublicKey::from_string(client_account)
        .map_err(|_| MainnetAuthorizationError::Refused(P::MessageClientAccount))?;
    require(account.0 == *ephemeral_public_key, P::MessageClientAccount)
}

/// The signer fact digest of an ephemeral SEP-10 key: the key and the
/// [`super::SignerRole::Sep10Ephemeral`] role tag.
///
/// It differs from an enrolled signer's digest by its role tag and by the
/// absence of a keyring coordinate, because the key has none.
#[cfg(feature = "mainnet-write")]
pub(crate) fn ephemeral_signer_fact(public_key: [u8; 32]) -> [u8; 32] {
    use super::digest::{FACT_LABEL_SIGNER, FactDigest};
    let mut digest = FactDigest::new(FACT_LABEL_SIGNER);
    digest
        .fixed(&public_key)
        .tag(super::SignerRole::Sep10Ephemeral.tag());
    digest.finish()
}

/// Requires the challenge about to be signed to be the one the receipt's
/// consumed authorization bound.
///
/// The checks run in this order, each refusing on its own:
///
/// 1. The validated and the completion network ids are both the mainnet
///    network id ([`MainnetPrecondition::ChainNotMainnet`]): a challenge
///    validated under another network is never signed for mainnet.
/// 2. `consumer` is the bound consumer.
/// 3. `issued_at <= now_ms < expires_at`.
/// 4. The bound content digest and ephemeral key are the message's
///    ([`MainnetPrecondition::MessageUseMismatch`]).
/// 5. The bound home domain, web authentication domain, and server key are
///    the message's.
/// 6. The challenge's client account is the ephemeral account
///    ([`MainnetPrecondition::MessageClientAccount`]).
///
/// The header's chain is mainnet on every record, because the mint refuses
/// any other, and its signer is the ephemeral key in the SEP-10 role, which
/// check 4 compares through the binding.
///
/// [`MainnetPrecondition::ChainNotMainnet`]: super::MainnetPrecondition::ChainNotMainnet
/// [`MainnetPrecondition::MessageUseMismatch`]: super::MainnetPrecondition::MessageUseMismatch
/// [`MainnetPrecondition::MessageClientAccount`]: super::MainnetPrecondition::MessageClientAccount
///
/// # Errors
///
/// [`MainnetAuthorizationError::Refused`] naming the first failed check.
pub fn check_challenge_against_receipt(
    receipt: &MessageUseReceipt,
    consumer: MainnetConsumer,
    challenge: &ChallengeFacts<'_>,
    now_ms: u64,
) -> Result<(), MainnetAuthorizationError> {
    #[cfg(feature = "mainnet-write")]
    {
        use sha2::{Digest as _, Sha256};
        let mainnet: [u8; 32] =
            Sha256::digest(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE.as_bytes())
                .into();
        require(
            challenge.validated_network_id == mainnet && challenge.completion_network_id == mainnet,
            P::ChainNotMainnet,
        )?;
        let header = &receipt.0.inner.header;
        header.check_consumer(consumer)?;
        header.check_not_expired(now_ms)?;
        let bound = &receipt.0.facts;
        let message = challenge.message;
        require(
            bound.content_digest == message.content_digest
                && bound.ephemeral_public_key == message.ephemeral_public_key,
            P::MessageUseMismatch,
        )?;
        super::authorization::check_message_domain(
            &bound.domain,
            &bound.content_digest,
            &message.domain,
            &message.content_digest,
        )?;
        check_client_account(challenge.client_account, &message.ephemeral_public_key)
    }
    #[cfg(not(feature = "mainnet-write"))]
    {
        let _ = (consumer, challenge, now_ms);
        match receipt.0 {}
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use super::*;

    fn account(key: [u8; 32]) -> String {
        stellar_strkey::ed25519::PublicKey(key)
            .to_string()
            .as_str()
            .to_owned()
    }

    fn muxed(key: [u8; 32]) -> String {
        stellar_strkey::ed25519::MuxedAccount {
            ed25519: key,
            id: 7,
        }
        .to_string()
        .as_str()
        .to_owned()
    }

    /// The equal G-address passes; another key's address, a muxed address of
    /// the same key, and a string that is no strkey refuse.
    #[test]
    fn the_client_account_must_be_the_ephemeral_account() {
        let key = [0xe1; 32];
        assert_eq!(check_client_account(&account(key), &key), Ok(()));
        for other in [account([0xe2; 32]), muxed(key), "not a strkey".to_owned()] {
            assert_eq!(
                check_client_account(&other, &key),
                Err(MainnetAuthorizationError::Refused(P::MessageClientAccount)),
                "{other}"
            );
        }
    }

    /// The ephemeral signer fact is the key under the SEP-10 role tag, so it
    /// differs from the agent signer's fact over the same key.
    #[cfg(feature = "mainnet-write")]
    #[test]
    fn the_ephemeral_signer_fact_names_the_key_and_the_sep10_role() {
        use super::super::digest::{FACT_LABEL_SIGNER, FactDigest};
        let key = [0xe1; 32];
        let fact = |tag: u8| {
            let mut digest = FactDigest::new(FACT_LABEL_SIGNER);
            digest.fixed(&key).tag(tag);
            digest.finish()
        };
        assert_eq!(ephemeral_signer_fact(key), fact(3));
        assert_ne!(
            ephemeral_signer_fact(key),
            fact(super::super::SignerRole::AgentSigner.tag())
        );
        assert_ne!(
            ephemeral_signer_fact(key),
            ephemeral_signer_fact([0xe2; 32])
        );
    }

    #[cfg(feature = "mainnet-write")]
    fn network_id(passphrase: &str) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(passphrase.as_bytes()).into()
    }

    /// Checks a challenge that differs from the receipt's bound one in the
    /// way `case` names, against a real receipt the resolver and the consume
    /// produced.
    #[cfg(feature = "mainnet-write")]
    fn challenge_case(case: &str) -> Result<(), MainnetAuthorizationError> {
        use super::super::fixtures::{message_facts, x402_fixture, x402_root};
        use stellar_agent_core::profile::caip2::{MAINNET_PASSPHRASE, TESTNET_PASSPHRASE};
        let f = x402_fixture();
        let root = x402_root(&f);
        let key = [0xe1; 32];
        let bound = message_facts([1; 32], key);
        let receipt = f.message_receipt(&root, &bound);
        let mut message = bound.clone();
        let mut validated_network_id = network_id(MAINNET_PASSPHRASE);
        let mut completion_network_id = network_id(MAINNET_PASSPHRASE);
        let mut consumer = MainnetConsumer::X402Authenticated;
        let mut now_ms = f.now;
        let mut client_account = account(key);
        match case {
            "accept" => {}
            "testnet_validated" => validated_network_id = network_id(TESTNET_PASSPHRASE),
            "testnet_completion" => completion_network_id = network_id(TESTNET_PASSPHRASE),
            "consumer" => consumer = MainnetConsumer::X402Create,
            "before_issue" => now_ms = receipt.0.inner.header.issued_at_ms - 1,
            "at_expiry" => now_ms = receipt.0.inner.header.expires_at_ms,
            "content" => message.content_digest = [2; 32],
            "key" => {
                message.ephemeral_public_key = [0xe2; 32];
                client_account = account([0xe2; 32]);
            }
            "home_domain" => message.domain.home_domain = "other.example.com".to_owned(),
            "web_auth_domain" => {
                message.domain.web_auth_domain = "other.anchor.example.com".to_owned();
            }
            "server_key" => message.domain.server_key = [0x5f; 32],
            "client_other" => client_account = account([0xe2; 32]),
            "client_muxed" => client_account = muxed(key),
            other => unreachable!("{other}"),
        }
        check_challenge_against_receipt(
            &receipt,
            consumer,
            &ChallengeFacts {
                validated_network_id,
                completion_network_id,
                message: &message,
                client_account: &client_account,
            },
            now_ms,
        )
    }

    macro_rules! challenge_case {
        ($name:ident, $case:literal, $expected:ident) => {
            #[cfg(feature = "mainnet-write")]
            #[test]
            #[serial_test::serial]
            fn $name() {
                assert_eq!(
                    challenge_case($case),
                    Err(MainnetAuthorizationError::Refused(P::$expected))
                );
            }
        };
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial_test::serial]
    fn the_challenge_of_the_receipt_passes() {
        assert_eq!(challenge_case("accept"), Ok(()));
    }

    challenge_case!(
        a_challenge_validated_under_testnet_refuses,
        "testnet_validated",
        ChainNotMainnet
    );
    challenge_case!(
        a_challenge_completed_for_testnet_refuses,
        "testnet_completion",
        ChainNotMainnet
    );
    challenge_case!(
        a_challenge_for_another_consumer_refuses,
        "consumer",
        ConsumerMismatch
    );
    challenge_case!(
        a_challenge_before_the_issue_refuses,
        "before_issue",
        NotYetValid
    );
    challenge_case!(a_challenge_at_the_expiry_refuses, "at_expiry", Expired);
    challenge_case!(
        a_challenge_of_other_content_refuses,
        "content",
        MessageUseMismatch
    );
    challenge_case!(
        a_challenge_for_another_key_refuses,
        "key",
        MessageUseMismatch
    );
    challenge_case!(
        a_challenge_for_another_home_domain_refuses,
        "home_domain",
        MessageHomeDomain
    );
    challenge_case!(
        a_challenge_for_another_web_auth_domain_refuses,
        "web_auth_domain",
        MessageWebAuthDomain
    );
    challenge_case!(
        a_challenge_for_another_server_key_refuses,
        "server_key",
        MessageServerKey
    );
    challenge_case!(
        a_challenge_for_another_account_refuses,
        "client_other",
        MessageClientAccount
    );
    challenge_case!(
        a_challenge_for_a_muxed_account_refuses,
        "client_muxed",
        MessageClientAccount
    );

    /// The receipt prints its domain, an identity prefix and its home
    /// domain; no key, no digest and no other bound fact.
    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial_test::serial]
    fn the_receipt_prints_no_key_and_no_digest() {
        use super::super::fixtures::{MESSAGE_HOME_DOMAIN, message_facts, x402_fixture, x402_root};
        use stellar_agent_core::hex::encode;
        let f = x402_fixture();
        let root = x402_root(&f);
        let key = [0xe1; 32];
        let content = [0xc4; 32];
        let facts = message_facts(content, key);
        let receipt = f.message_receipt(&root, &facts);
        let printed = format!("{receipt:?}");
        assert_eq!(
            printed,
            format!(
                "MessageUseReceipt {{ domain: Message, id: {:?}, home_domain: {MESSAGE_HOME_DOMAIN:?}, .. }}",
                receipt.id()
            )
        );
        for hidden in [
            encode(&key),
            account(key),
            format!("{key:?}"),
            encode(&content),
            format!("{content:?}"),
            encode(&facts.domain.server_key),
            facts.domain.web_auth_domain.clone(),
        ] {
            assert!(!printed.contains(&hidden), "{printed} holds {hidden}");
        }
    }
}
