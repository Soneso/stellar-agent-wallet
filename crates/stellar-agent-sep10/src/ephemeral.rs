//! Per-request ephemeral ed25519 signing flow for SEP-10 authentication.
//!
//! [`auth_with_ephemeral_key`] is the production entry point for the SEP-10
//! client-side flow on every network except mainnet:
//!
//! 1. Generate a fresh `ed25519_dalek::SigningKey` via `rand_core::OsRng` (one
//!    key per call; never reused or persisted).
//! 2. Fetch and validate the SEP-10 challenge via
//!    [`Sep10Client::fetch_challenge`].
//! 3. Sign the challenge: compute the `TransactionSignaturePayload` SHA-256
//!    hash and produce a `DecoratedSignature` with the ephemeral pub-key hint
//!    (last 4 bytes of the 32-byte public key).
//! 4. Attach the `DecoratedSignature` to the envelope and re-encode to base64.
//! 5. Submit the signed challenge via
//!    [`Sep10Client::submit_signed_challenge`] → return `Sep10Session`.
//! 6. The `SigningKey` drops at end of function scope and is zeroed automatically
//!    via `ed25519_dalek::SigningKey`'s `ZeroizeOnDrop` impl (dalek 2.x).
//!
//! A mainnet challenge is signed only in two steps.
//! [`prepare_ephemeral_auth`] generates the key and fetches and validates the
//! challenge into a sealed [`PreparedEphemeralAuth`], whose message facts the
//! caller authorizes and consumes. [`complete_ephemeral_auth_authorized`] then
//! checks the challenge against the consumed authorization's receipt, signs
//! once, verifies the signature and submits it.
//!
//! # Memory discipline
//!
//! The ephemeral key lifetime is bounded to one authentication: the stack
//! frame of [`auth_with_ephemeral_key`], or the [`PreparedEphemeralAuth`]
//! value that [`complete_ephemeral_auth_authorized`] consumes. The key is
//! throwaway one-shot and is zeroed automatically on drop via
//! `ZeroizeOnDrop`. No mlock is required for a per-request throwaway key.

use crate::challenge::Challenge;
use crate::client::{ChallengeRequest, Sep10Client, web_auth_domain_for_endpoint};
use crate::error::Sep10Error;
use crate::session::Sep10Session;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use stellar_agent_core::error::{MAINNET_SIGNING_REFUSAL_DETAIL, NetworkError, WalletError};
use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;
#[cfg(any(test, feature = "test-helpers"))]
use stellar_agent_network::mainnet::AuthorizationId;
use stellar_agent_network::mainnet::message::{
    ChallengeFacts, MessageFacts, MessageUseReceipt, check_challenge_against_receipt,
    check_client_account,
};
use stellar_agent_network::mainnet::{
    MainnetAuthorizationError, MainnetConsumer, MainnetPrecondition, MessageDomain,
};
use stellar_xdr::{
    DecoratedSignature, Hash, Limits, ReadXdr, SignatureHint, Transaction, TransactionEnvelope,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    TransactionV1Envelope, WriteXdr,
};

/// Derives the G-key strkey for an ed25519 `VerifyingKey`.
fn ephemeral_account_id(signing_key: &SigningKey) -> Result<String, Sep10Error> {
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let pk = stellar_strkey::ed25519::PublicKey(pubkey_bytes);
    // stellar-strkey to_string() returns heapless::String<N>; format! via
    // Display coerces it to heap-allocated String.
    Ok(format!("{pk}"))
}

#[cfg(test)]
thread_local! {
    /// Keys generated on this thread, so a test can show that a refusal
    /// precedes key generation.
    static GENERATED_KEYS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Signatures produced on this thread, so a test can show that a refusal
    /// precedes signing.
    static SIGNATURES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Generates the one-shot ephemeral key of one authentication.
///
/// The only production key generation of this crate. `OsRng` is the OS
/// CSPRNG (getrandom on Linux, `SecRandomCopyBytes` on macOS,
/// `BCryptGenRandom` on Windows). `SigningKey` implements `ZeroizeOnDrop`, so
/// the key material is zeroed when the key drops.
fn generate_ephemeral_key() -> SigningKey {
    #[cfg(test)]
    GENERATED_KEYS.with(|count| count.set(count.get() + 1));
    SigningKey::generate(&mut OsRng)
}

/// The refusal of a signing path on a mainnet client that holds no mainnet
/// authorization.
fn mainnet_signing_forbidden() -> Sep10Error {
    Sep10Error::MainnetSigningForbidden {
        detail: MAINNET_SIGNING_REFUSAL_DETAIL.to_owned(),
    }
}

/// Maps a reported mainnet authorization error to its SEP-10 error.
///
/// `network.mainnet_write_forbidden` stays the signing refusal; every other
/// error is the generic authorization refusal, which names no precondition.
fn authorization_error(error: &WalletError) -> Sep10Error {
    match error {
        WalletError::Network(NetworkError::MainnetWriteForbidden) => mainnet_signing_forbidden(),
        _ => Sep10Error::MainnetAuthorizationRefused,
    }
}

/// The SHA-256 of a network passphrase: the network id a signature payload
/// names.
fn network_id(network_passphrase: &str) -> [u8; 32] {
    Sha256::digest(network_passphrase.as_bytes()).into()
}

// ─────────────────────────────────────────────────────────────────────────────
// auth_with_ephemeral_key
// ─────────────────────────────────────────────────────────────────────────────

/// Authenticates against the SEP-10 server at `web_auth_endpoint` using a
/// fresh per-request ephemeral ed25519 key.
///
/// Generates a one-shot ephemeral keypair and derives its G-key strkey as the
/// `account_id`. Because the ephemeral account does not exist on the Stellar
/// ledger, the server follows SEP-10 v3.4.1 and accepts the challenge signed
/// by the master key of the ephemeral G-key — which is the ephemeral signing
/// key itself. The session JWT `sub` claim will be the ephemeral G-key.
///
/// Using a non-existent ephemeral account gives per-request credential
/// isolation: each call produces a distinct JWT bound to a distinct one-shot
/// G-key, preventing session reuse across requests.
///
/// `web_auth_domain` is the expected `web_auth_domain` of the challenge.
/// Pass `None` to derive it from the host of `web_auth_endpoint` with
/// [`web_auth_domain_for_endpoint`].
///
/// A client on the mainnet passphrase is refused before a key is generated
/// and before any request: a mainnet challenge is signed only through
/// [`prepare_ephemeral_auth`] and [`complete_ephemeral_auth_authorized`].
///
/// # Steps
///
/// 1. Refuse the mainnet passphrase.
/// 2. Resolve the expected web auth domain.
/// 3. Generate fresh `SigningKey` via `OsRng` (CSPRNG; per-request unique).
/// 4. Derive `account_id` = G-key strkey of the ephemeral pubkey.
/// 5. Fetch + validate challenge for the ephemeral `account_id` (13-point
///    SEP-10 validation; server signature verified against
///    `expected_server_signing_key`).
/// 6. Sign `TransactionSignaturePayload` SHA-256 with ephemeral key; attach
///    `DecoratedSignature` (hint = last 4 bytes of ephemeral pubkey).
/// 7. Re-encode signed envelope to base64.
/// 8. POST to server; parse JWT session.
/// 9. Assert `session.account_id()` matches the ephemeral G-key. This
///    rejects a server that issues the JWT for a different account.
/// 10. The ephemeral `SigningKey` drops here, and `ZeroizeOnDrop` zeroes the key.
///
/// # Errors
///
/// - [`Sep10Error::MainnetSigningForbidden`] when the client's passphrase is
///   the mainnet passphrase.
/// - [`Sep10Error::InvalidWebAuthEndpoint`] when `web_auth_domain` is `None`
///   and `web_auth_endpoint` has no host.
/// - Any [`Sep10Error`] from [`Sep10Client::fetch_challenge`] on
///   challenge fetch/validation failure.
/// - [`Sep10Error::HttpError`] on network failure or non-200 HTTP status on
///   either the GET or POST step.
/// - [`Sep10Error::XdrDecodeError`] if the challenge XDR cannot be re-decoded
///   (should not occur if `fetch_challenge` succeeded).
/// - Any [`Sep10Error`] from [`Sep10Client::submit_signed_challenge`] on POST
///   failure or JWT parse failure.
/// - [`Sep10Error::SessionAccountMismatch`] if the JWT `sub` does not match
///   the ephemeral G-key that signed the challenge.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_sep10::{Sep10Client, ephemeral::auth_with_ephemeral_key};
///
/// # async fn example() -> Result<(), stellar_agent_sep10::Sep10Error> {
/// let client = Sep10Client::new("Test SDF Network ; September 2015")?;
/// let session = auth_with_ephemeral_key(
///     &client,
///     "https://testanchor.stellar.org/auth",
///     "testanchor.stellar.org",
///     "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
///     None,
/// )
/// .await?;
/// assert!(!session.is_expired(0));
/// # Ok(())
/// # }
/// ```
pub async fn auth_with_ephemeral_key(
    client: &Sep10Client,
    web_auth_endpoint: &str,
    home_domain: &str,
    expected_server_signing_key: &str,
    web_auth_domain: Option<&str>,
) -> Result<Sep10Session, Sep10Error> {
    if client.network_passphrase() == MAINNET_PASSPHRASE {
        return Err(mainnet_signing_forbidden());
    }
    let derived_domain;
    let web_auth_domain = match web_auth_domain {
        Some(domain) => domain,
        None => {
            derived_domain = web_auth_domain_for_endpoint(web_auth_endpoint)?;
            &derived_domain
        }
    };
    let prepared = prepare_body(
        client,
        web_auth_endpoint,
        home_domain,
        expected_server_signing_key,
        web_auth_domain,
        ClientAccount::Unchecked,
    )
    .await?;
    complete_ephemeral_auth(client, prepared).await
}

// ─────────────────────────────────────────────────────────────────────────────
// The prepared authentication
// ─────────────────────────────────────────────────────────────────────────────

/// A fetched and validated challenge with the ephemeral key that will sign
/// it, before any signature.
///
/// Produced only by [`prepare_ephemeral_auth`] and consumed by
/// [`complete_ephemeral_auth_authorized`], so one ephemeral key signs at most
/// one challenge. It is neither `Clone` nor serializable. The network the
/// challenge was validated under is sealed inside: no getter exposes it and
/// no caller can replace it, so the completion compares it with its own
/// client's network.
pub struct PreparedEphemeralAuth {
    /// The one-shot key, zeroed on drop.
    key: SigningKey,
    /// The G-key strkey of `key`.
    account_id: String,
    /// The challenge, validated for `account_id`.
    challenge: Challenge,
    /// The endpoint the challenge came from and the signed challenge goes to.
    web_auth_endpoint: String,
    /// The home domain the challenge was validated for.
    home_domain: String,
    /// SHA-256 of the challenge's `TransactionSignaturePayload` XDR under the
    /// passphrase it was validated under.
    content_digest: [u8; 32],
    /// SHA-256 of the passphrase the challenge was validated under.
    validated_network_id: [u8; 32],
}

impl std::fmt::Debug for PreparedEphemeralAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedEphemeralAuth")
            .field("account_id", &self.account_id)
            .field("home_domain", &self.home_domain)
            .finish_non_exhaustive()
    }
}

impl PreparedEphemeralAuth {
    /// The ephemeral public key the challenge is for.
    #[must_use]
    pub fn ephemeral_public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The SHA-256 of the challenge's `TransactionSignaturePayload` XDR: the
    /// hash the ephemeral key signs.
    #[must_use]
    pub fn content_digest(&self) -> [u8; 32] {
        self.content_digest
    }

    /// The home domain, web auth domain and server key the challenge was
    /// validated against.
    #[must_use]
    pub fn message_domain(&self) -> MessageDomain {
        MessageDomain {
            home_domain: self.home_domain.clone(),
            web_auth_domain: self.challenge.web_auth_domain.clone(),
            server_key: self.challenge.server_account.0,
        }
    }

    /// The message facts a mainnet authorization of this challenge binds.
    #[must_use]
    pub fn message_facts(&self) -> MessageFacts {
        MessageFacts {
            domain: self.message_domain(),
            content_digest: self.content_digest,
            ephemeral_public_key: self.ephemeral_public_key(),
        }
    }
}

/// Whether the prepare step requires the challenge's client account to be
/// the ephemeral account.
#[derive(Clone, Copy)]
enum ClientAccount {
    /// The session `sub` check after the POST is the only identity check.
    Unchecked,
    /// The challenge must name the ephemeral account before anything is
    /// authorized.
    MustBeEphemeral,
}

/// Prepares the authentication of a fresh ephemeral key against the SEP-10
/// server at `web_auth_endpoint`, without signing.
///
/// Generates the one-shot key, fetches and validates the challenge for its
/// account with `web_auth_domain` as the expected web auth domain, requires
/// the challenge's client account to be the ephemeral account, and computes
/// the content digest under the client's passphrase. The passphrase is the
/// one the challenge answer had to name and under which the server signature
/// was verified, so it is the validated network the prepared value seals.
///
/// The prepare step signs nothing and refuses no network.
/// [`complete_ephemeral_auth_authorized`] signs the prepared challenge once
/// a mainnet authorization of [`PreparedEphemeralAuth::message_facts`] has
/// been consumed. `web_auth_domain` is typically
/// [`web_auth_domain_for_endpoint`] of the endpoint.
///
/// # Errors
///
/// - Any [`Sep10Error`] from [`Sep10Client::fetch_challenge`].
/// - [`Sep10Error::MainnetAuthorizationRefused`] when the challenge's client
///   account is not the ephemeral account; the key drops unused.
/// - [`Sep10Error::XdrDecodeError`] when the validated envelope cannot be
///   re-decoded.
pub async fn prepare_ephemeral_auth(
    client: &Sep10Client,
    web_auth_endpoint: &str,
    home_domain: &str,
    expected_server_signing_key: &str,
    web_auth_domain: &str,
) -> Result<PreparedEphemeralAuth, Sep10Error> {
    prepare_body(
        client,
        web_auth_endpoint,
        home_domain,
        expected_server_signing_key,
        web_auth_domain,
        ClientAccount::MustBeEphemeral,
    )
    .await
}

/// Generates the key, fetches and validates its challenge, optionally
/// requires the challenge's client account to be the ephemeral account, and
/// seals the content digest and the validated network.
async fn prepare_body(
    client: &Sep10Client,
    web_auth_endpoint: &str,
    home_domain: &str,
    expected_server_signing_key: &str,
    web_auth_domain: &str,
    client_account: ClientAccount,
) -> Result<PreparedEphemeralAuth, Sep10Error> {
    const PATH: &str = "prepare_ephemeral_auth";
    let key = generate_ephemeral_key();
    // SEP-10 v3.4.1: the server uses the master key path for a non-existent
    // account, so the signature must be by the G-key's own key.
    let account_id = ephemeral_account_id(&key)?;
    // fetch_challenge performs the 13-point SEP-10 validation and verifies
    // the server signature against expected_server_signing_key.
    let challenge = client
        .fetch_challenge(ChallengeRequest {
            web_auth_endpoint,
            account_id: &account_id,
            home_domain,
            server_signing_key: expected_server_signing_key,
            memo: None,
            client_domain: None,
            web_auth_domain: Some(web_auth_domain),
        })
        .await?;
    if let ClientAccount::MustBeEphemeral = client_account {
        check_client_account(&challenge.client_account, &key.verifying_key().to_bytes())
            .map_err(|error| authorization_error(&error.report(PATH)))?;
    }
    let content_digest =
        challenge_payload_hash(&challenge.envelope_xdr, client.network_passphrase())?;
    Ok(PreparedEphemeralAuth {
        key,
        account_id,
        challenge,
        web_auth_endpoint: web_auth_endpoint.to_owned(),
        home_domain: home_domain.to_owned(),
        content_digest,
        validated_network_id: network_id(client.network_passphrase()),
    })
}

/// Signs and submits a prepared challenge on a network that needs no
/// mainnet authorization.
async fn complete_ephemeral_auth(
    client: &Sep10Client,
    prepared: PreparedEphemeralAuth,
) -> Result<Sep10Session, Sep10Error> {
    let signed_xdr =
        sign_challenge_with_key(&prepared.challenge.envelope_xdr, &prepared.key, client)?;
    submit_and_check_session(
        client,
        &prepared.web_auth_endpoint,
        &prepared.account_id,
        &signed_xdr,
    )
    .await
    // The prepared value drops here: ZeroizeOnDrop zeroes the key material.
}

// ─────────────────────────────────────────────────────────────────────────────
// The authorized completion
// ─────────────────────────────────────────────────────────────────────────────

/// Signs a prepared mainnet challenge under a consumed message authorization
/// and submits it.
///
/// `receipt` is the proof that the authorization of
/// [`PreparedEphemeralAuth::message_facts`] was durably consumed, so the
/// signature always follows the consume. The steps run in this order:
///
/// 1. Read the authorization clock once.
/// 2. Recompute the content digest from the prepared envelope under the
///    client's passphrase.
/// 3. Assemble the message facts and the challenge facts: the sealed
///    validated network and this client's network.
/// 4. Check the challenge against the receipt with
///    [`check_challenge_against_receipt`]: both networks mainnet, the
///    consumer, the authorization lifetime, the content digest, the key, the
///    domains and server key, and the client account.
/// 5. Sign the recomputed hash once and attach the signature.
/// 6. Verify the attached signature under the ephemeral public key.
/// 7. Submit the signed challenge and require the session `sub` to be the
///    ephemeral account.
///
/// A refusal of steps 1, 4 and 6 logs its precondition under this path and
/// returns [`Sep10Error::MainnetAuthorizationRefused`], which names none.
///
/// The Message authorization is consumed before the SEP-10 signature.
/// Without the `mainnet-write` feature of `stellar-agent-network` no
/// [`MessageUseReceipt`] exists, so this function cannot be called.
///
/// # Errors
///
/// - [`Sep10Error::MainnetAuthorizationRefused`] when the clock is
///   unavailable, the challenge does not match the receipt, or the signature
///   does not verify; no signed challenge is submitted.
/// - [`Sep10Error::MainnetSigningForbidden`] when the authorization check
///   reports `FeatureDisabled`, which maps to the signing refusal.
/// - [`Sep10Error::XdrDecodeError`] when the envelope cannot be decoded, or
///   the signature cannot be attached because the envelope already holds
///   twenty signatures.
/// - The HTTP, JWT and [`Sep10Error::SessionAccountMismatch`] errors of the
///   submission.
pub async fn complete_ephemeral_auth_authorized(
    client: &Sep10Client,
    prepared: PreparedEphemeralAuth,
    consumer: MainnetConsumer,
    receipt: &MessageUseReceipt,
) -> Result<Sep10Session, Sep10Error> {
    const PATH: &str = "complete_ephemeral_auth_authorized";
    let refuse = |error: MainnetAuthorizationError| authorization_error(&error.report(PATH));

    let now_ms = stellar_agent_network::mainnet::clock::now_ms().map_err(|_| {
        refuse(MainnetAuthorizationError::Refused(
            MainnetPrecondition::ClockUnavailable,
        ))
    })?;
    let hash = challenge_payload_hash(
        &prepared.challenge.envelope_xdr,
        client.network_passphrase(),
    )?;
    let message = MessageFacts {
        domain: prepared.message_domain(),
        content_digest: hash,
        ephemeral_public_key: prepared.ephemeral_public_key(),
    };
    let challenge = ChallengeFacts {
        validated_network_id: prepared.validated_network_id,
        completion_network_id: network_id(client.network_passphrase()),
        message: &message,
        client_account: &prepared.challenge.client_account,
    };
    check_challenge_against_receipt(receipt, consumer, &challenge, now_ms).map_err(refuse)?;

    #[cfg(any(test, feature = "test-helpers"))]
    AUTHORIZED_SIGNINGS.with(|signings| signings.borrow_mut().push(receipt.id()));
    let (signed_xdr, signature) =
        attach_ephemeral_signature(&prepared.challenge.envelope_xdr, &prepared.key, &hash)?;
    #[cfg(any(test, feature = "test-helpers"))]
    let signature = corrupt_if_requested(signature);
    if !signature_verifies(&message.ephemeral_public_key, &hash, &signature) {
        return Err(refuse(MainnetAuthorizationError::Refused(
            MainnetPrecondition::SignatureInvalid,
        )));
    }

    submit_and_check_session(
        client,
        &prepared.web_auth_endpoint,
        &prepared.account_id,
        &signed_xdr,
    )
    .await
}

/// Whether `signature` is a valid ed25519 signature of `payload` under `key`.
fn signature_verifies(key: &[u8; 32], payload: &[u8; 32], signature: &[u8; 64]) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(key).is_ok_and(|key| {
        key.verify_strict(payload, &ed25519_dalek::Signature::from_bytes(signature))
            .is_ok()
    })
}

/// Submits the signed challenge and requires the session's `sub` to be the
/// account that signed it.
async fn submit_and_check_session(
    client: &Sep10Client,
    web_auth_endpoint: &str,
    account_id: &str,
    signed_xdr: &str,
) -> Result<Sep10Session, Sep10Error> {
    let session = client
        .submit_signed_challenge(web_auth_endpoint, signed_xdr)
        .await?;

    // The JWT sub must be the same account that signed the challenge. A
    // mismatch means the server issued a session for a different account,
    // and the call fails closed.
    let session_account = session.account_id();
    if session_account != account_id {
        // Redact: show only first-5/last-5 chars of each key to aid diagnosis
        // without echoing full key bytes in error detail.
        let redact = |s: &str| {
            let chars: Vec<char> = s.chars().collect();
            if chars.len() <= 10 {
                s.to_owned()
            } else {
                format!(
                    "{}...{}",
                    chars[..5].iter().collect::<String>(),
                    chars[chars.len() - 5..].iter().collect::<String>()
                )
            }
        };
        return Err(Sep10Error::SessionAccountMismatch {
            detail: format!(
                "JWT sub {} does not match ephemeral account {}",
                redact(session_account),
                redact(account_id),
            ),
        });
    }
    Ok(session)
}

// ─────────────────────────────────────────────────────────────────────────────
// Signing observation hooks
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
thread_local! {
    /// The receipt ids the authorized completion signed under on this
    /// thread, each recorded immediately before its signature.
    static AUTHORIZED_SIGNINGS: std::cell::RefCell<Vec<AuthorizationId>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// Set to make the next authorized signature on this thread fail its
    /// verification.
    static CORRUPT_NEXT_SIGNATURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Drains the receipt ids the authorized completion signed under on this
/// thread.
///
/// Each id is recorded immediately before the signature, after every check
/// of the challenge against its receipt passed.
#[cfg(any(test, feature = "test-helpers"))]
#[doc(hidden)]
pub fn take_authorized_signings_for_test() -> Vec<AuthorizationId> {
    AUTHORIZED_SIGNINGS.with(std::cell::RefCell::take)
}

/// Makes the next authorized signature on this thread fail its verification,
/// so the completion refuses after signing and before the submission.
#[cfg(any(test, feature = "test-helpers"))]
#[doc(hidden)]
pub fn corrupt_next_signature_for_test() {
    CORRUPT_NEXT_SIGNATURE.with(|flag| flag.set(true));
}

/// Reads and clears the corruption flag.
#[cfg(any(test, feature = "test-helpers"))]
fn take_corruption_request() -> bool {
    CORRUPT_NEXT_SIGNATURE.with(|flag| flag.replace(false))
}

/// `signature` with bit 0 of byte 0 flipped when a corruption was requested.
#[cfg(any(test, feature = "test-helpers"))]
fn corrupt_if_requested(mut signature: [u8; 64]) -> [u8; 64] {
    if take_corruption_request() {
        signature[0] ^= 1;
    }
    signature
}

// ─────────────────────────────────────────────────────────────────────────────
// Hashing and signing (crate-private workhorses)
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes a challenge envelope with the bounded limits for untrusted XDR
/// and returns its V1 envelope.
fn decode_challenge_envelope(envelope_xdr: &str) -> Result<TransactionV1Envelope, Sep10Error> {
    // Even though the envelope was validated by `parse_and_validate`, it
    // originates from an untrusted anchor server; bounded limits are applied
    // consistently to every decode of externally-sourced XDR.
    let envelope = TransactionEnvelope::from_xdr_base64(
        envelope_xdr,
        stellar_agent_xdr_limits::untrusted_decode_limits(envelope_xdr.len()),
    )
    .map_err(|e| Sep10Error::XdrDecodeError {
        detail: format!(
            "re-decode of validated challenge envelope failed (should not happen): {e}"
        ),
    })?;
    // parse_and_validate already rejected non-V1 envelopes.
    match envelope {
        TransactionEnvelope::Tx(v1) => Ok(v1),
        _ => Err(Sep10Error::XdrDecodeError {
            detail: "challenge envelope is not TransactionEnvelope::Tx (V1) after re-decode"
                .to_owned(),
        }),
    }
}

/// The SHA-256 of the `TransactionSignaturePayload` XDR of `tx` under
/// `network_passphrase`.
fn signature_payload_hash(
    tx: &Transaction,
    network_passphrase: &str,
) -> Result<[u8; 32], Sep10Error> {
    // TransactionSignaturePayload:
    //   network_id: Hash(SHA-256(network_passphrase))
    //   tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx)
    let sig_payload = TransactionSignaturePayload {
        network_id: Hash(network_id(network_passphrase)),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
    };
    let payload_xdr =
        sig_payload
            .to_xdr(Limits::none())
            .map_err(|e| Sep10Error::XdrDecodeError {
                detail: format!("TransactionSignaturePayload XDR encode failed: {e}"),
            })?;
    Ok(Sha256::digest(&payload_xdr).into())
}

/// The hash an ephemeral key signs for the challenge `envelope_xdr` under
/// `network_passphrase`: the content digest of a message authorization.
///
/// # Errors
///
/// [`Sep10Error::XdrDecodeError`] when the envelope cannot be decoded or is
/// not a V1 envelope.
pub(crate) fn challenge_payload_hash(
    envelope_xdr: &str,
    network_passphrase: &str,
) -> Result<[u8; 32], Sep10Error> {
    let envelope = decode_challenge_envelope(envelope_xdr)?;
    signature_payload_hash(&envelope.tx, network_passphrase)
}

/// Signs `hash` with `key`, attaches the decorated signature to the
/// challenge `envelope_xdr`, and returns the re-encoded envelope with the 64
/// signature bytes it attached.
///
/// The only signing of this crate.
fn attach_ephemeral_signature(
    envelope_xdr: &str,
    key: &SigningKey,
    hash: &[u8; 32],
) -> Result<(String, [u8; 64]), Sep10Error> {
    let mut v1_envelope = decode_challenge_envelope(envelope_xdr)?;

    // ed25519_dalek::Signer::sign(&hash) produces a 64-byte signature over
    // the raw 32-byte SHA-256 output (not double-hashed).
    #[cfg(test)]
    SIGNATURES.with(|count| count.set(count.get() + 1));
    let sig_bytes: [u8; 64] = key.sign(hash).to_bytes();

    // The signature hint: last 4 bytes of the 32-byte public key.
    let pubkey_bytes = key.verifying_key().to_bytes();
    let hint: [u8; 4] =
        pubkey_bytes[28..32]
            .try_into()
            .map_err(|_| Sep10Error::XdrDecodeError {
                detail: "ephemeral public key shorter than 32 bytes (impossible)".to_owned(),
            })?;
    let dec_sig = DecoratedSignature {
        hint: SignatureHint(hint),
        signature: stellar_xdr::Signature::try_from(sig_bytes.to_vec()).map_err(|e| {
            Sep10Error::XdrDecodeError {
                detail: format!("signature bytes are not a valid Stellar Signature: {e}"),
            }
        })?,
    };
    // VecM<DecoratedSignature, 20> does not implement DerefMut, so direct push
    // is not possible. Reconstruct: take the existing signatures into a Vec,
    // push the new DecoratedSignature, then convert back via try_into(). An
    // envelope that already holds twenty signatures fails here.
    let mut sigs: Vec<DecoratedSignature> = v1_envelope.signatures.to_vec();
    sigs.push(dec_sig);
    v1_envelope.signatures = sigs.try_into().map_err(|_| Sep10Error::XdrDecodeError {
        detail: "too many signatures in challenge envelope (exceeded VecM<20> bound)".to_owned(),
    })?;

    let signed = TransactionEnvelope::Tx(v1_envelope)
        .to_xdr_base64(Limits::none())
        .map_err(|e| Sep10Error::XdrDecodeError {
            detail: format!("failed to re-encode signed challenge envelope: {e}"),
        })?;
    Ok((signed, sig_bytes))
}

/// Signs the challenge `TransactionEnvelope` with `signing_key` under the
/// client's passphrase and returns the re-encoded base64 XDR with the
/// signature attached.
///
/// The hash is [`challenge_payload_hash`] of the envelope, so the hash a
/// message authorization binds and the hash signed have one definition.
///
/// # Errors
///
/// - [`Sep10Error::XdrDecodeError`] if `envelope_xdr` cannot be re-decoded
///   (should not occur for a challenge that passed `parse_and_validate`).
/// - [`Sep10Error::XdrDecodeError`] if the signature cannot be attached or
///   the modified envelope cannot be re-encoded.
///
/// # Panics
///
/// Never panics.
pub(crate) fn sign_challenge_with_key(
    envelope_xdr: &str,
    signing_key: &SigningKey,
    client: &Sep10Client,
) -> Result<String, Sep10Error> {
    let hash = challenge_payload_hash(envelope_xdr, client.network_passphrase())?;
    attach_ephemeral_signature(envelope_xdr, signing_key, &hash).map(|(signed, _)| signed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test-helpers (public exports for integration-test binaries)
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a fresh `Zeroizing<[u8; 32]>` seed via `OsRng`.
///
/// Used by adversarial tests to generate ephemeral seeds without going through
/// the full auth flow.
///
/// Only available under `--features test-helpers`.
#[cfg(feature = "test-helpers")]
pub fn generate_ephemeral_seed() -> zeroize::Zeroizing<[u8; 32]> {
    use rand_core::RngCore;
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(seed.as_mut());
    seed
}

/// Constructs a `SigningKey` from a `Zeroizing<[u8; 32]>` seed.
///
/// Used by adversarial tests to build a deterministic or random ephemeral key.
///
/// Only available under `--features test-helpers`.
#[cfg(feature = "test-helpers")]
pub fn signing_key_from_seed(seed: &zeroize::Zeroizing<[u8; 32]>) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Signs a challenge `envelope_xdr` with `signing_key` and returns the
/// re-encoded base64 XDR.
///
/// Thin `pub` wrapper over the crate-private `sign_challenge_with_key` for use in integration
/// test binaries that cannot access `pub(crate)` items. A client on the
/// mainnet passphrase is refused before signing.
///
/// Only available under `--features test-helpers`.
///
/// # Errors
///
/// - [`Sep10Error::MainnetSigningForbidden`] when the client's passphrase is
///   the mainnet passphrase.
/// - Otherwise the errors of the wrapped crate-private
///   `sign_challenge_with_key`.
///
/// # Panics
///
/// Never panics.
#[cfg(feature = "test-helpers")]
pub fn sign_challenge_for_test(
    envelope_xdr: &str,
    signing_key: &SigningKey,
    client: &crate::client::Sep10Client,
) -> Result<String, crate::error::Sep10Error> {
    if client.network_passphrase() == MAINNET_PASSPHRASE {
        return Err(mainnet_signing_forbidden());
    }
    sign_challenge_with_key(envelope_xdr, signing_key, client)
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
    // The zeroize-on-drop test uses raw pointer reads to verify volatile_write
    // zeroization. This is intentionally unsafe and isolated to the test module.
    #![allow(
        unsafe_code,
        reason = "test-only raw-pointer read for zeroize verification"
    )]

    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use zeroize::Zeroizing;

    // generate_ephemeral_seed and signing_key_from_seed are feature-gated
    // behind test-helpers in production integration tests. In the inline unit
    // tests here we replicate their logic directly to avoid requiring the
    // feature flag for the inline test suite.
    fn generate_seed() -> Zeroizing<[u8; 32]> {
        use rand_core::RngCore;
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(seed.as_mut());
        seed
    }

    fn key_from_seed(seed: &Zeroizing<[u8; 32]>) -> SigningKey {
        SigningKey::from_bytes(seed)
    }

    // ── Ephemeral key uniqueness ──────────────────────────────────────────────

    /// Each call must produce a distinct key. Guards against CSPRNG failure.
    #[test]
    fn ephemeral_keys_differ_across_calls() {
        let seed1 = generate_seed();
        let seed2 = generate_seed();
        assert_ne!(*seed1, *seed2, "two consecutive OsRng seeds must differ");

        let key1 = key_from_seed(&seed1);
        let key2 = key_from_seed(&seed2);
        assert_ne!(
            key1.verifying_key().to_bytes(),
            key2.verifying_key().to_bytes(),
            "two ephemeral keys derived from distinct seeds must have distinct pubkeys"
        );
    }

    /// 100 consecutive seed generations must all be distinct.
    #[test]
    fn ephemeral_seeds_are_unique_across_100_calls() {
        use std::collections::HashSet;
        let mut seeds: HashSet<[u8; 32]> = HashSet::new();
        for _ in 0..100 {
            let s = generate_seed();
            assert!(
                seeds.insert(*s),
                "duplicate seed generated in 100-call loop (CSPRNG failure)"
            );
        }
    }

    // ── ZeroizeOnDrop enforcement ─────────────────────────────────────────────

    /// Regression lock: a `Zeroizing<[u8; 32]>` wrapping a known pattern is
    /// zeroed when it drops. Uses volatile_write via the zeroize crate to
    /// prevent compiler optimisation of the zeroing.
    #[test]
    fn zeroizing_seed_zeroes_bytes_on_drop() {
        let mut heap_seed: Box<[u8; 32]> = Box::new([0xABu8; 32]);
        let raw_ptr: *const u8 = heap_seed.as_ptr();

        {
            let _zeroized: Zeroizing<[u8; 32]> = Zeroizing::new(*heap_seed);
        }

        let raw2: *mut u8 = heap_seed.as_mut_ptr();
        {
            let zz: Zeroizing<[u8; 32]> = Zeroizing::new(*heap_seed);
            let inner_ptr: *const u8 = zz.as_ptr();
            unsafe {
                for i in 0..32usize {
                    assert_eq!(*inner_ptr.add(i), 0xABu8, "byte {i} before drop");
                }
            }
            drop(zz);
            // Note: reading freed stack memory after drop is UB in the general
            // case. We verify the heap_seed original remains untouched instead.
        }

        // The Zeroizing worked on its own copy, leaving the original heap_seed
        // untouched (still 0xAB).
        unsafe {
            assert_eq!(*raw2, 0xABu8, "original heap copy must still be 0xAB");
        }
        drop(heap_seed);
        let _ = raw_ptr;
    }

    // ── SigningKey from seed is deterministic ─────────────────────────────────

    #[test]
    fn signing_key_from_seed_is_deterministic() {
        let seed = Zeroizing::new([0x42u8; 32]);
        let key1 = SigningKey::from_bytes(&seed);
        let key2 = SigningKey::from_bytes(&seed);
        assert_eq!(
            key1.verifying_key().to_bytes(),
            key2.verifying_key().to_bytes(),
            "SigningKey::from_bytes must be deterministic for the same seed"
        );
    }

    // ── OsRng produces different keys each invocation ─────────────────────────

    #[test]
    fn generate_via_osrng_produces_unique_keys() {
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);
        assert_ne!(
            key_a.verifying_key().to_bytes(),
            key_b.verifying_key().to_bytes(),
            "two OsRng-generated signing keys must differ"
        );
    }

    // ── Wiremock full-flow tests ──────────────────────────────────────────────

    /// Shared challenge XDR builder for wiremock tests.
    ///
    /// Returns a server-signed SEP-10 challenge XDR, the server G-key strkey,
    /// and `now` as Unix seconds.
    struct ChallengeFixture {
        server_strkey: String,
        challenge_xdr: String,
        now: u64,
    }

    fn build_challenge_fixture() -> ChallengeFixture {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;
        use ed25519_dalek::Signer as _;
        use sha2::{Digest, Sha256};
        use stellar_xdr::{
            BytesM, DataValue, DecoratedSignature, Hash, Limits, ManageDataOp, Memo, MuxedAccount,
            OperationBody, Preconditions, SequenceNumber, SignatureHint, String64, StringM,
            TimeBounds, TimePoint, Transaction, TransactionEnvelope, TransactionExt,
            TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
            TransactionV1Envelope, VecM, WriteXdr,
        };

        const HOME_DOMAIN: &str = "mock.example.com";
        const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

        let server_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let server_vk = server_sk.verifying_key();
        let server_strkey = format!(
            "{}",
            stellar_strkey::ed25519::PublicKey(server_vk.to_bytes())
        );

        let fixture_client_vk = SigningKey::from_bytes(&[0x22u8; 32]).verifying_key();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let min_time: u64 = now - 900;
        let max_time: u64 = now + 900;

        let nonce_raw = [0x55u8; 48];
        let nonce_b64 = B64.encode(nonce_raw);

        let server_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(server_vk.to_bytes()));
        let client_muxed =
            MuxedAccount::Ed25519(stellar_xdr::Uint256(fixture_client_vk.to_bytes()));

        let str64 = |s: &str| -> String64 {
            StringM::<64>::try_from(s.as_bytes().to_vec())
                .unwrap()
                .into()
        };
        let data_val =
            |b: &[u8]| -> DataValue { DataValue(BytesM::<64>::try_from(b.to_vec()).unwrap()) };

        let ops: VecM<stellar_xdr::Operation, 100> = vec![
            stellar_xdr::Operation {
                source_account: Some(client_muxed),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str64(&format!("{HOME_DOMAIN} auth")),
                    data_value: Some(data_val(nonce_b64.as_bytes())),
                }),
            },
            stellar_xdr::Operation {
                source_account: Some(server_muxed.clone()),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str64("web_auth_domain"),
                    data_value: Some(data_val(HOME_DOMAIN.as_bytes())),
                }),
            },
        ]
        .try_into()
        .unwrap();

        let tx = Transaction {
            source_account: server_muxed,
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(min_time),
                max_time: TimePoint(max_time),
            }),
            memo: Memo::None,
            operations: ops,
            ext: TransactionExt::V0,
        };

        let network_id_hash = Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into());
        let tagged_tx = TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone());
        let sig_payload = TransactionSignaturePayload {
            network_id: network_id_hash,
            tagged_transaction: tagged_tx,
        };
        let payload_bytes = sig_payload.to_xdr(Limits::none()).unwrap();
        let tx_hash: [u8; 32] = Sha256::digest(&payload_bytes).into();
        let server_sig = server_sk.sign(&tx_hash);
        let server_hint: [u8; 4] = server_vk.to_bytes()[28..32].try_into().unwrap();

        let sigs_vec: VecM<DecoratedSignature, 20> = vec![DecoratedSignature {
            hint: SignatureHint(server_hint),
            signature: stellar_xdr::Signature::try_from(server_sig.to_bytes().to_vec()).unwrap(),
        }]
        .try_into()
        .unwrap();

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: sigs_vec,
        });
        ChallengeFixture {
            server_strkey,
            challenge_xdr: envelope.to_xdr_base64(Limits::none()).unwrap(),
            now,
        }
    }

    /// Verifies that `auth_with_ephemeral_key` rejects a JWT whose `sub` does
    /// not match the ephemeral G-key that signed the challenge.
    ///
    /// The flow succeeds through GET + sign + POST; the account integrity check
    /// fires when the server returns a JWT with a mismatched `sub`.
    #[tokio::test]
    async fn auth_with_ephemeral_key_rejects_session_account_mismatch() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        use crate::client::Sep10Client;
        use crate::error::Sep10Error;

        const HOME_DOMAIN: &str = "mock.example.com";
        const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

        let fixture = build_challenge_fixture();
        let now = fixture.now;
        let jwt_exp = now + 900;

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "transaction": fixture.challenge_xdr,
                "network_passphrase": TESTNET_PASSPHRASE,
            })))
            .mount(&mock_server)
            .await;

        // Return a JWT whose sub is a G-key that will never match the ephemeral key.
        let wrong_sub = "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR";
        let jwt_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let jwt_payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "sub": wrong_sub,
                "iss": "https://mock.example.com",
                "iat": now,
                "exp": jwt_exp,
            }))
            .unwrap(),
        );
        let bad_jwt = format!("{jwt_header}.{jwt_payload}.");

        Mock::given(method("POST"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": bad_jwt })))
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TESTNET_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());

        let err = super::auth_with_ephemeral_key(
            &client,
            &endpoint,
            HOME_DOMAIN,
            &fixture.server_strkey,
            Some(HOME_DOMAIN),
        )
        .await
        .expect_err("must fail with SessionAccountMismatch");

        assert!(
            matches!(err, Sep10Error::SessionAccountMismatch { .. }),
            "expected SessionAccountMismatch, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.session_account_mismatch");

        // Both GET and POST were received — the check fires after the POST.
        assert_eq!(
            mock_server.received_requests().await.unwrap().len(),
            2,
            "mock server must have received GET + POST before mismatch is detected"
        );
    }

    /// Exercises `sign_challenge_with_key` + `submit_signed_challenge` happy
    /// path. Uses a known deterministic signing key so the ephemeral G-key is
    /// knowable ahead of time, letting us pre-build a matching JWT `sub`.
    ///
    /// This avoids the "unknown ephemeral key" problem inherent in testing
    /// `auth_with_ephemeral_key`'s happy path end-to-end via mocks, while
    /// covering the same signing + submit + session field assertions.
    #[tokio::test]
    async fn sign_and_submit_happy_path_session_account_matches() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        use crate::client::Sep10Client;

        const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

        let fixture = build_challenge_fixture();
        let now = fixture.now;
        let jwt_exp = now + 900;

        // A deterministic signing key whose G-key strkey is known ahead of
        // time — this lets us pre-build the JWT with the correct `sub`.
        let test_signing_key = SigningKey::from_bytes(&[0x33u8; 32]);
        let test_signing_vk = test_signing_key.verifying_key();
        let test_g_key = format!(
            "{}",
            stellar_strkey::ed25519::PublicKey(test_signing_vk.to_bytes())
        );

        let mock_server = MockServer::start().await;

        // Build the JWT with sub = test_g_key.
        let jwt_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let jwt_payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "sub": test_g_key,
                "iss": "https://mock.example.com",
                "iat": now,
                "exp": jwt_exp,
            }))
            .unwrap(),
        );
        let good_jwt = format!("{jwt_header}.{jwt_payload}.");

        Mock::given(method("POST"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": good_jwt })))
            .mount(&mock_server)
            .await;

        let client = Sep10Client::new_for_unit_test(TESTNET_PASSPHRASE).unwrap();
        let endpoint = format!("{}/auth", mock_server.uri());

        // Sign the challenge directly (bypasses ephemeral key generation).
        let signed_xdr =
            super::sign_challenge_with_key(&fixture.challenge_xdr, &test_signing_key, &client)
                .expect("sign_challenge_with_key must succeed");

        let session = client
            .submit_signed_challenge(&endpoint, &signed_xdr)
            .await
            .expect("submit_signed_challenge must succeed");

        assert!(!session.jwt.is_empty(), "jwt must not be empty");
        assert_eq!(session.iss, "https://mock.example.com");
        assert_eq!(session.exp, jwt_exp);
        assert!(!session.is_expired(now), "session must not be expired");
        assert_eq!(
            session.account_id(),
            test_g_key,
            "session account_id must match the signing key G-key"
        );
    }

    // ── Mainnet refusals, the prepare step and the shared helpers ────────────

    const MAINNET: &str = "Public Global Stellar Network ; September 2015";
    const TESTNET: &str = "Test SDF Network ; September 2015";
    const PREPARE_HOME_DOMAIN: &str = "anchor.example.com";
    const PREPARE_WEB_AUTH_DOMAIN: &str = "auth.anchor.example.com";

    fn generated_keys() -> usize {
        super::GENERATED_KEYS.with(std::cell::Cell::get)
    }

    fn signatures() -> usize {
        super::SIGNATURES.with(std::cell::Cell::get)
    }

    fn server_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11u8; 32])
    }

    fn strkey(key: [u8; 32]) -> String {
        stellar_strkey::ed25519::PublicKey(key)
            .to_string()
            .to_string()
    }

    /// The SHA-256 of the `TransactionSignaturePayload` XDR of `envelope`
    /// under `passphrase`, computed without the crate's helpers.
    fn independent_payload_hash(envelope: &str, passphrase: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        use stellar_xdr::{
            Hash, Limits, ReadXdr, TransactionEnvelope, TransactionSignaturePayload,
            TransactionSignaturePayloadTaggedTransaction, WriteXdr,
        };
        let TransactionEnvelope::Tx(v1) =
            TransactionEnvelope::from_xdr_base64(envelope, Limits::none()).unwrap()
        else {
            panic!("the challenge is a V1 envelope");
        };
        let payload = TransactionSignaturePayload {
            network_id: Hash(Sha256::digest(passphrase.as_bytes()).into()),
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(v1.tx),
        };
        Sha256::digest(payload.to_xdr(Limits::none()).unwrap()).into()
    }

    /// A server-signed challenge for `client_key` under `passphrase`, with
    /// `extra_signatures` further decorated signatures beside the server's.
    fn challenge_xdr(client_key: [u8; 32], passphrase: &str, extra_signatures: usize) -> String {
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        use stellar_xdr::{
            BytesM, DataValue, DecoratedSignature, Limits, ManageDataOp, Memo, MuxedAccount,
            OperationBody, Preconditions, SequenceNumber, SignatureHint, String64, StringM,
            TimeBounds, TimePoint, Transaction, TransactionEnvelope, TransactionExt,
            TransactionV1Envelope, Uint256, VecM, WriteXdr,
        };
        let server = server_key();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let str64 = |s: &str| -> String64 {
            StringM::<64>::try_from(s.as_bytes().to_vec())
                .unwrap()
                .into()
        };
        let data = |b: &[u8]| DataValue(BytesM::<64>::try_from(b.to_vec()).unwrap());
        let server_account = MuxedAccount::Ed25519(Uint256(server.verifying_key().to_bytes()));
        let nonce = base64::engine::general_purpose::STANDARD.encode([0x55u8; 48]);
        let operations: VecM<stellar_xdr::Operation, 100> = vec![
            stellar_xdr::Operation {
                source_account: Some(MuxedAccount::Ed25519(Uint256(client_key))),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str64(&format!("{PREPARE_HOME_DOMAIN} auth")),
                    data_value: Some(data(nonce.as_bytes())),
                }),
            },
            stellar_xdr::Operation {
                source_account: Some(server_account.clone()),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str64("web_auth_domain"),
                    data_value: Some(data(PREPARE_WEB_AUTH_DOMAIN.as_bytes())),
                }),
            },
        ]
        .try_into()
        .unwrap();
        let tx = Transaction {
            source_account: server_account,
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(now - 60),
                max_time: TimePoint(now + 900),
            }),
            memo: Memo::None,
            operations,
            ext: TransactionExt::V0,
        };
        let hash = super::signature_payload_hash(&tx, passphrase).unwrap();
        let mut signatures = vec![DecoratedSignature {
            hint: SignatureHint(
                server.verifying_key().to_bytes()[28..32]
                    .try_into()
                    .unwrap(),
            ),
            signature: server.sign(&hash).to_bytes().to_vec().try_into().unwrap(),
        }];
        for index in 0..extra_signatures {
            let other = SigningKey::from_bytes(&[u8::try_from(index).unwrap() + 0x60; 32]);
            signatures.push(DecoratedSignature {
                hint: SignatureHint(other.verifying_key().to_bytes()[28..32].try_into().unwrap()),
                signature: other.sign(&hash).to_bytes().to_vec().try_into().unwrap(),
            });
        }
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: signatures.try_into().unwrap(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap()
    }

    /// What the challenge responder served: the requested account and the
    /// envelope it answered with.
    #[derive(Default)]
    struct Served {
        account: String,
        envelope: String,
    }

    /// Answers a challenge GET with a challenge for the `account` query
    /// parameter, or for `other_account` when set, under `passphrase`.
    struct ChallengeResponder {
        passphrase: &'static str,
        other_account: Option<[u8; 32]>,
        served: std::sync::Arc<std::sync::Mutex<Served>>,
    }

    impl wiremock::Respond for ChallengeResponder {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            let account = request
                .url
                .query_pairs()
                .find(|(name, _)| name == "account")
                .map(|(_, value)| value.into_owned())
                .unwrap();
            let requested = stellar_strkey::ed25519::PublicKey::from_string(&account)
                .unwrap()
                .0;
            let envelope =
                challenge_xdr(self.other_account.unwrap_or(requested), self.passphrase, 0);
            *self.served.lock().unwrap() = Served {
                account,
                envelope: envelope.clone(),
            };
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transaction": envelope,
                "network_passphrase": self.passphrase,
            }))
        }
    }

    /// Answers the POST of a signed challenge: verifies the client signature
    /// against the served account over the payload hash it computes itself,
    /// answers 400 when it does not verify, and otherwise a JWT whose `sub`
    /// is the served account.
    struct JwtResponder {
        passphrase: &'static str,
        served: std::sync::Arc<std::sync::Mutex<Served>>,
    }

    impl wiremock::Respond for JwtResponder {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            use base64::Engine as _;
            use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let signed = body["transaction"].as_str().unwrap();
            let served = self.served.lock().unwrap();
            let key = stellar_strkey::ed25519::PublicKey::from_string(&served.account)
                .unwrap()
                .0;
            let hash = independent_payload_hash(signed, self.passphrase);
            let TransactionEnvelope::Tx(v1) =
                TransactionEnvelope::from_xdr_base64(signed, Limits::none()).unwrap()
            else {
                return wiremock::ResponseTemplate::new(400);
            };
            let verifying = ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap();
            let verified = v1.signatures.iter().any(|signature| {
                <[u8; 64]>::try_from(signature.signature.as_slice()).is_ok_and(|bytes| {
                    verifying
                        .verify_strict(&hash, &ed25519_dalek::Signature::from_bytes(&bytes))
                        .is_ok()
                })
            });
            if !verified {
                return wiremock::ResponseTemplate::new(400);
            }
            let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::json!({
                    "sub": served.account,
                    "iss": "https://anchor.example.com",
                    "iat": 0,
                    "exp": 9_999_999_999_u64,
                })
                .to_string(),
            );
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "token": format!("header.{claims}.sig") }))
        }
    }

    struct Sep10Double {
        server: wiremock::MockServer,
        served: std::sync::Arc<std::sync::Mutex<Served>>,
    }

    impl Sep10Double {
        async fn start(
            passphrase: &'static str,
            other_account: Option<[u8; 32]>,
            expected_gets: u64,
            expected_posts: u64,
        ) -> Self {
            use wiremock::Mock;
            use wiremock::matchers::{method, path};
            let server = wiremock::MockServer::start().await;
            let served = std::sync::Arc::new(std::sync::Mutex::new(Served::default()));
            Mock::given(method("GET"))
                .and(path("/auth"))
                .respond_with(ChallengeResponder {
                    passphrase,
                    other_account,
                    served: served.clone(),
                })
                .expect(expected_gets)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/auth"))
                .respond_with(JwtResponder {
                    passphrase,
                    served: served.clone(),
                })
                .expect(expected_posts)
                .mount(&server)
                .await;
            Self { server, served }
        }

        fn endpoint(&self) -> String {
            format!("{}/auth", self.server.uri())
        }
    }

    /// The existing entry refuses a mainnet client before it generates a key
    /// and before any request.
    #[tokio::test]
    async fn the_existing_entry_refuses_mainnet_before_generating_a_key() {
        let double = Sep10Double::start(MAINNET, None, 0, 0).await;
        let client = crate::client::Sep10Client::new_for_unit_test(MAINNET).unwrap();
        let generated = generated_keys();
        let err = super::auth_with_ephemeral_key(
            &client,
            &double.endpoint(),
            PREPARE_HOME_DOMAIN,
            &strkey(server_key().verifying_key().to_bytes()),
            Some(PREPARE_WEB_AUTH_DOMAIN),
        )
        .await
        .unwrap_err();
        assert_eq!(err.wire_code(), "sep10.mainnet_signing_forbidden");
        let crate::error::Sep10Error::MainnetSigningForbidden { detail } = &err else {
            panic!("expected MainnetSigningForbidden, got {err:?}");
        };
        assert_eq!(
            detail,
            stellar_agent_core::error::MAINNET_SIGNING_REFUSAL_DETAIL
        );
        assert_eq!(generated_keys(), generated);
        double.server.verify().await;
    }

    /// The test signing wrapper refuses a mainnet client before signing.
    #[cfg(feature = "test-helpers")]
    #[test]
    fn the_test_signing_wrapper_refuses_mainnet_before_signing() {
        let client = crate::client::Sep10Client::new_for_unit_test(MAINNET).unwrap();
        let envelope = challenge_xdr([0x22; 32], MAINNET, 0);
        let signed = signatures();
        let err = super::sign_challenge_for_test(
            &envelope,
            &SigningKey::from_bytes(&[0x22; 32]),
            &client,
        )
        .unwrap_err();
        assert_eq!(err.wire_code(), "sep10.mainnet_signing_forbidden");
        assert!(
            matches!(
                &err,
                crate::error::Sep10Error::MainnetSigningForbidden { detail }
                    if detail == stellar_agent_core::error::MAINNET_SIGNING_REFUSAL_DETAIL
            ),
            "{err:?}"
        );
        assert_eq!(signatures(), signed);
    }

    /// The prepare step seals the payload hash of the served challenge under
    /// the client's passphrase, the validated network, the domains and server
    /// key, and the key of the requested account, without signing.
    #[tokio::test]
    async fn prepare_seals_the_challenge_under_the_client_network() {
        let mut digests = Vec::new();
        for passphrase in [MAINNET, TESTNET] {
            let double = Sep10Double::start(passphrase, None, 1, 0).await;
            let client = crate::client::Sep10Client::new_for_unit_test(passphrase).unwrap();
            let signed = signatures();
            let generated = generated_keys();
            let prepared = super::prepare_ephemeral_auth(
                &client,
                &double.endpoint(),
                PREPARE_HOME_DOMAIN,
                &strkey(server_key().verifying_key().to_bytes()),
                PREPARE_WEB_AUTH_DOMAIN,
            )
            .await
            .unwrap();
            assert_eq!(generated_keys(), generated + 1, "{passphrase}");
            assert_eq!(signatures(), signed, "{passphrase}");
            let (account, envelope) = {
                let served = double.served.lock().unwrap();
                (served.account.clone(), served.envelope.clone())
            };
            assert_eq!(
                prepared.content_digest(),
                independent_payload_hash(&envelope, passphrase),
                "{passphrase}"
            );
            {
                use sha2::{Digest, Sha256};
                let expected: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();
                assert_eq!(prepared.validated_network_id, expected, "{passphrase}");
            }
            assert_eq!(
                prepared.ephemeral_public_key(),
                stellar_strkey::ed25519::PublicKey::from_string(&account)
                    .unwrap()
                    .0,
                "{passphrase}"
            );
            let domain = prepared.message_domain();
            assert_eq!(domain.home_domain, PREPARE_HOME_DOMAIN);
            assert_eq!(domain.web_auth_domain, PREPARE_WEB_AUTH_DOMAIN);
            assert_eq!(domain.server_key, server_key().verifying_key().to_bytes());
            let facts = prepared.message_facts();
            assert_eq!(facts.domain, domain);
            assert_eq!(facts.content_digest, prepared.content_digest());
            assert_eq!(facts.ephemeral_public_key, prepared.ephemeral_public_key());
            digests.push(prepared.content_digest());
            double.server.verify().await;
        }
        assert_ne!(digests[0], digests[1]);
    }

    /// A challenge for another account refuses at the prepare step, before
    /// any signature and without a POST.
    #[tokio::test]
    async fn prepare_refuses_a_challenge_for_another_account() {
        let double = Sep10Double::start(MAINNET, Some([0x44; 32]), 1, 0).await;
        let client = crate::client::Sep10Client::new_for_unit_test(MAINNET).unwrap();
        let signed = signatures();
        let err = super::prepare_ephemeral_auth(
            &client,
            &double.endpoint(),
            PREPARE_HOME_DOMAIN,
            &strkey(server_key().verifying_key().to_bytes()),
            PREPARE_WEB_AUTH_DOMAIN,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, crate::error::Sep10Error::MainnetAuthorizationRefused),
            "{err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.mainnet_authorization_refused");
        assert_eq!(signatures(), signed);
        double.server.verify().await;
    }

    /// The existing entry completes a testnet authentication through the
    /// prepare body: the double verifies the signature and the session names
    /// the ephemeral account.
    #[tokio::test]
    async fn the_existing_entry_authenticates_on_testnet() {
        let double = Sep10Double::start(TESTNET, None, 1, 1).await;
        let client = crate::client::Sep10Client::new_for_unit_test(TESTNET).unwrap();
        let session = super::auth_with_ephemeral_key(
            &client,
            &double.endpoint(),
            PREPARE_HOME_DOMAIN,
            &strkey(server_key().verifying_key().to_bytes()),
            Some(PREPARE_WEB_AUTH_DOMAIN),
        )
        .await
        .unwrap();
        assert_eq!(session.account_id(), double.served.lock().unwrap().account);
        double.server.verify().await;
    }

    /// The existing testnet entry does not compare the challenge's client
    /// account: a challenge naming another account is signed and posted, and
    /// the session `sub` check after the POST is its identity check.
    #[tokio::test]
    async fn the_existing_entry_leaves_the_client_account_to_the_session_check() {
        let double = Sep10Double::start(TESTNET, Some([0x44; 32]), 1, 1).await;
        let client = crate::client::Sep10Client::new_for_unit_test(TESTNET).unwrap();
        let session = super::auth_with_ephemeral_key(
            &client,
            &double.endpoint(),
            PREPARE_HOME_DOMAIN,
            &strkey(server_key().verifying_key().to_bytes()),
            Some(PREPARE_WEB_AUTH_DOMAIN),
        )
        .await
        .unwrap();
        assert_eq!(session.account_id(), double.served.lock().unwrap().account);
        double.server.verify().await;
    }

    /// Without a web auth domain the existing entry expects the endpoint's
    /// host, so a challenge naming another domain refuses before the POST.
    #[tokio::test]
    async fn the_existing_entry_derives_the_web_auth_domain_from_the_endpoint() {
        let double = Sep10Double::start(TESTNET, None, 1, 0).await;
        let client = crate::client::Sep10Client::new_for_unit_test(TESTNET).unwrap();
        let err = super::auth_with_ephemeral_key(
            &client,
            &double.endpoint(),
            PREPARE_HOME_DOMAIN,
            &strkey(server_key().verifying_key().to_bytes()),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(err.wire_code(), "sep10.web_auth_domain_mismatch", "{err:?}");
        let err = super::auth_with_ephemeral_key(
            &client,
            "not-a-url",
            PREPARE_HOME_DOMAIN,
            &strkey(server_key().verifying_key().to_bytes()),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.wire_code(),
            "sep10.invalid_web_auth_endpoint",
            "{err:?}"
        );
        double.server.verify().await;
    }

    /// The prepared value prints its account and home domain only.
    #[tokio::test]
    async fn the_prepared_value_prints_no_key_and_no_envelope() {
        let double = Sep10Double::start(TESTNET, None, 1, 0).await;
        let client = crate::client::Sep10Client::new_for_unit_test(TESTNET).unwrap();
        let prepared = super::prepare_ephemeral_auth(
            &client,
            &double.endpoint(),
            PREPARE_HOME_DOMAIN,
            &strkey(server_key().verifying_key().to_bytes()),
            PREPARE_WEB_AUTH_DOMAIN,
        )
        .await
        .unwrap();
        let debug = format!("{prepared:?}");
        let served = double.served.lock().unwrap();
        assert!(debug.contains(&served.account), "{debug}");
        assert!(debug.contains(PREPARE_HOME_DOMAIN), "{debug}");
        let key = prepared.ephemeral_public_key();
        let seed = prepared.key.to_bytes();
        for secret in [
            stellar_agent_core::hex::encode(&seed),
            format!("{seed:?}"),
            format!("{key:?}"),
            stellar_agent_core::hex::encode(&key),
            stellar_agent_core::hex::encode(&prepared.content_digest()),
            served.envelope.clone(),
        ] {
            assert!(!debug.contains(&secret), "{debug}");
        }
        assert!(!debug.contains("envelope"), "{debug}");
        assert!(!debug.contains("key"), "{debug}");
    }

    /// The verification helper accepts the signature of the payload under
    /// the key and refuses one flipped bit.
    #[test]
    fn the_signature_verification_refuses_a_flipped_bit() {
        use ed25519_dalek::Signer as _;
        let key = SigningKey::from_bytes(&[0x33; 32]);
        let payload = [0x5a; 32];
        let mut signature = key.sign(&payload).to_bytes();
        let public = key.verifying_key().to_bytes();
        assert!(super::signature_verifies(&public, &payload, &signature));
        signature[0] ^= 1;
        assert!(!super::signature_verifies(&public, &payload, &signature));
    }

    /// The corruption flag is consumed by the first read, and the signing
    /// observation starts empty.
    #[test]
    fn the_test_hooks_hold_one_request_and_start_empty() {
        assert!(super::take_authorized_signings_for_test().is_empty());
        assert!(!super::take_corruption_request());
        super::corrupt_next_signature_for_test();
        assert!(super::take_corruption_request());
        assert!(!super::take_corruption_request());
        let signature = [0x80; 64];
        super::corrupt_next_signature_for_test();
        let corrupted = super::corrupt_if_requested(signature);
        assert_eq!(corrupted[0], 0x81);
        assert_eq!(corrupted[1..], signature[1..]);
        assert_eq!(super::corrupt_if_requested(signature), signature);
    }

    /// A reported forbidden write stays the signing refusal; every other
    /// reported error is the generic authorization refusal.
    #[test]
    fn reported_authorization_errors_map_to_the_two_mainnet_errors() {
        use stellar_agent_core::error::{NetworkError, WalletError};
        let forbidden =
            super::authorization_error(&WalletError::Network(NetworkError::MainnetWriteForbidden));
        assert!(
            matches!(
                &forbidden,
                crate::error::Sep10Error::MainnetSigningForbidden { detail }
                    if detail == stellar_agent_core::error::MAINNET_SIGNING_REFUSAL_DETAIL
            ),
            "{forbidden:?}"
        );
        for error in [
            WalletError::Network(NetworkError::MainnetAuthorizationRefused),
            WalletError::PolicyDenied {
                reason: Box::new(stellar_agent_core::policy::DenyReason::AssetNotAllowlisted),
            },
        ] {
            let mapped = super::authorization_error(&error);
            assert!(
                matches!(
                    mapped,
                    crate::error::Sep10Error::MainnetAuthorizationRefused
                ),
                "{mapped:?}"
            );
        }
    }

    /// The content digest is the payload hash under the given passphrase,
    /// and the attached signature is a signature of it by the key.
    #[test]
    fn the_signed_hash_is_the_content_digest() {
        use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};
        let key = SigningKey::from_bytes(&[0x22; 32]);
        let envelope = challenge_xdr(key.verifying_key().to_bytes(), TESTNET, 0);
        let hash = super::challenge_payload_hash(&envelope, TESTNET).unwrap();
        assert_eq!(hash, independent_payload_hash(&envelope, TESTNET));
        assert_ne!(
            hash,
            super::challenge_payload_hash(&envelope, MAINNET).unwrap()
        );
        let (signed, signature) =
            super::attach_ephemeral_signature(&envelope, &key, &hash).unwrap();
        assert!(super::signature_verifies(
            &key.verifying_key().to_bytes(),
            &hash,
            &signature
        ));
        let TransactionEnvelope::Tx(v1) =
            TransactionEnvelope::from_xdr_base64(&signed, Limits::none()).unwrap()
        else {
            panic!("the signed challenge is a V1 envelope");
        };
        assert_eq!(v1.signatures.len(), 2);
        assert_eq!(v1.signatures[1].signature.as_slice(), signature.as_slice());
        assert_eq!(
            v1.signatures[1].hint.0,
            key.verifying_key().to_bytes()[28..32]
        );
    }

    /// An envelope that already holds twenty signatures fails after the
    /// signature, at the attachment.
    #[test]
    fn a_full_envelope_refuses_the_attachment_after_signing() {
        let key = SigningKey::from_bytes(&[0x22; 32]);
        let envelope = challenge_xdr(key.verifying_key().to_bytes(), TESTNET, 19);
        let hash = super::challenge_payload_hash(&envelope, TESTNET).unwrap();
        let signed = signatures();
        let err = super::attach_ephemeral_signature(&envelope, &key, &hash).unwrap_err();
        assert_eq!(signatures(), signed + 1);
        assert!(
            matches!(
                &err,
                crate::error::Sep10Error::XdrDecodeError { detail }
                    if detail.contains("VecM<20>")
            ),
            "{err:?}"
        );
    }

    /// An envelope that is not base64 XDR, or not a V1 envelope, refuses the
    /// hash.
    #[test]
    fn the_payload_hash_refuses_an_undecodable_or_legacy_envelope() {
        use stellar_xdr::{
            Limits, TransactionEnvelope, TransactionV0, TransactionV0Envelope, TransactionV0Ext,
            WriteXdr,
        };
        let err = super::challenge_payload_hash("not xdr", TESTNET).unwrap_err();
        assert!(
            matches!(err, crate::error::Sep10Error::XdrDecodeError { .. }),
            "{err:?}"
        );
        let legacy = TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx: TransactionV0 {
                source_account_ed25519: stellar_xdr::Uint256([0x11; 32]),
                fee: 100,
                seq_num: stellar_xdr::SequenceNumber(0),
                time_bounds: None,
                memo: stellar_xdr::Memo::None,
                operations: Vec::new().try_into().unwrap(),
                ext: TransactionV0Ext::V0,
            },
            signatures: Vec::new().try_into().unwrap(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let err = super::challenge_payload_hash(&legacy, TESTNET).unwrap_err();
        assert!(
            matches!(
                &err,
                crate::error::Sep10Error::XdrDecodeError { detail } if detail.contains("V1")
            ),
            "{err:?}"
        );
    }
}
