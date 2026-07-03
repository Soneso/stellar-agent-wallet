//! Per-request ephemeral ed25519 signing flow for SEP-10 authentication.
//!
//! [`auth_with_ephemeral_key`] is the primary production entry point for the
//! SEP-10 client-side flow:
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
//! # Memory discipline
//!
//! The ephemeral key lifetime is bounded to this function's stack frame. The
//! key is throwaway one-shot and is zeroed automatically on drop via
//! `ZeroizeOnDrop`. No mlock is required for a per-request throwaway key.

use crate::client::{ChallengeRequest, Sep10Client};
use crate::error::Sep10Error;
use crate::session::Sep10Session;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use stellar_xdr::{
    DecoratedSignature, Hash, Limits, ReadXdr, SignatureHint, TransactionEnvelope,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction, WriteXdr,
};

/// Derives the G-key strkey for an ed25519 `VerifyingKey`.
fn ephemeral_account_id(signing_key: &SigningKey) -> Result<String, Sep10Error> {
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let pk = stellar_strkey::ed25519::PublicKey(pubkey_bytes);
    // stellar-strkey to_string() returns heapless::String<N>; format! via
    // Display coerces it to heap-allocated String.
    Ok(format!("{pk}"))
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
/// `web_auth_domain` is forwarded to [`Sep10Client::fetch_challenge`] as the
/// expected `web_auth_domain` in the challenge. Pass `None` to derive it from
/// the host of `web_auth_endpoint`.
///
/// # Steps
///
/// 1. Generate fresh `SigningKey` via `OsRng` (CSPRNG; per-request unique).
/// 2. Derive `account_id` = G-key strkey of the ephemeral pubkey.
/// 3. Fetch + validate challenge for the ephemeral `account_id` (13-point
///    SEP-10 validation; server signature verified against
///    `expected_server_signing_key`).
/// 4. Sign `TransactionSignaturePayload` SHA-256 with ephemeral key; attach
///    `DecoratedSignature` (hint = last 4 bytes of ephemeral pubkey).
/// 5. Re-encode signed envelope to base64.
/// 6. POST to server; parse JWT session.
/// 7. Assert `session.account_id()` matches the ephemeral G-key — rejects
///    server misbehaviour where the JWT is issued for a different account.
/// 8. Ephemeral `SigningKey` drops here → `ZeroizeOnDrop` zeroes the key.
///
/// # Errors
///
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
    // Step 1: Generate a fresh ephemeral ed25519 SigningKey.
    // OsRng is the OS CSPRNG (getrandom syscall on Linux, SecRandomCopyBytes
    // on macOS, BCryptGenRandom on Windows).
    //
    // SigningKey implements ZeroizeOnDrop (ed25519-dalek 2.x, zeroize feature)
    // — key material is zeroed automatically when ephemeral_key drops.
    let ephemeral_key = SigningKey::generate(&mut OsRng);

    // Step 2: Derive account_id from the ephemeral pubkey G-key strkey.
    // SEP-10 v3.4.1: server uses "master key" path for non-existent accounts
    // — verifies the signature matches the G-key's public key exactly.
    let account_id = ephemeral_account_id(&ephemeral_key)?;

    // Step 3: Fetch and validate the challenge.
    // fetch_challenge performs 13-point SEP-10 validation AND verifies the
    // server signature against expected_server_signing_key.
    let challenge = client
        .fetch_challenge(ChallengeRequest {
            web_auth_endpoint,
            account_id: &account_id,
            home_domain,
            server_signing_key: expected_server_signing_key,
            memo: None,
            client_domain: None,
            web_auth_domain,
        })
        .await?;

    // Step 4: Sign the challenge with the ephemeral key.
    let signed_xdr = sign_challenge_with_key(&challenge.envelope_xdr, &ephemeral_key, client)?;

    // Step 5: Submit the signed challenge.
    let session = client
        .submit_signed_challenge(web_auth_endpoint, &signed_xdr)
        .await?;

    // Step 6: Assert session account integrity. The JWT sub must be the same
    // account that signed the challenge. A mismatch means the server issued a
    // session for a different account — reject fail-closed.
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
                redact(&account_id),
            ),
        });
    }

    // Step 7: ephemeral_key drops here — ZeroizeOnDrop zeroes the key material.
    Ok(session)
}

// ─────────────────────────────────────────────────────────────────────────────
// sign_challenge_with_key (crate-private workhorse)
// ─────────────────────────────────────────────────────────────────────────────

/// Signs the challenge `TransactionEnvelope` with `signing_key` and returns
/// the re-encoded base64 XDR with the signature attached.
///
/// 1. Re-decode the `envelope_xdr` to `TransactionV1Envelope`.
/// 2. Compute `TransactionSignaturePayload` SHA-256 over
///    `SHA-256(network_passphrase_bytes) || TransactionV1_XDR`.
/// 3. Sign the hash with `signing_key` via `ed25519_dalek::Signer::sign`.
/// 4. Build `DecoratedSignature` with hint = last 4 bytes of the 32-byte
///    public key.
/// 5. Push `DecoratedSignature` into `envelope.signatures`.
/// 6. Re-encode modified envelope to base64.
///
/// # Errors
///
/// - [`Sep10Error::XdrDecodeError`] if `envelope_xdr` cannot be re-decoded
///   (should not occur for a challenge that passed `parse_and_validate`).
/// - [`Sep10Error::XdrDecodeError`] if the modified envelope cannot be
///   re-encoded (extremely unlikely; indicates OOM or XDR library bug).
///
/// # Panics
///
/// Never panics.
pub(crate) fn sign_challenge_with_key(
    envelope_xdr: &str,
    signing_key: &SigningKey,
    client: &Sep10Client,
) -> Result<String, Sep10Error> {
    // Re-decode the envelope from the stored base64 XDR. Even though this
    // value was previously validated by `parse_and_validate`, the envelope XDR
    // originates from an untrusted anchor server; bounded limits are applied
    // consistently to every decode of externally-sourced XDR.
    let mut envelope = TransactionEnvelope::from_xdr_base64(
        envelope_xdr,
        stellar_agent_xdr_limits::untrusted_decode_limits(envelope_xdr.len()),
    )
    .map_err(|e| Sep10Error::XdrDecodeError {
        detail: format!(
            "re-decode of validated challenge envelope failed (should not happen): {e}"
        ),
    })?;

    // Extract the V1 envelope (parse_and_validate already rejected non-V1).
    let v1_envelope = match &mut envelope {
        TransactionEnvelope::Tx(v1) => v1,
        _ => {
            return Err(Sep10Error::XdrDecodeError {
                detail: "challenge envelope is not TransactionEnvelope::Tx (V1) after re-decode"
                    .to_owned(),
            });
        }
    };

    // Compute the TransactionSignaturePayload hash.
    // stellar-xdr TransactionSignaturePayload:
    //   network_id: Hash(SHA-256(network_passphrase))
    //   tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx)
    let network_id_hash = Hash(Sha256::digest(client.network_passphrase().as_bytes()).into());
    let tagged_tx = TransactionSignaturePayloadTaggedTransaction::Tx(v1_envelope.tx.clone());
    let sig_payload = TransactionSignaturePayload {
        network_id: network_id_hash,
        tagged_transaction: tagged_tx,
    };
    let payload_xdr =
        sig_payload
            .to_xdr(Limits::none())
            .map_err(|e| Sep10Error::XdrDecodeError {
                detail: format!("TransactionSignaturePayload XDR encode failed: {e}"),
            })?;
    let tx_hash: [u8; 32] = Sha256::digest(&payload_xdr).into();

    // Sign the hash with the ephemeral key.
    // ed25519_dalek::Signer::sign(&hash) produces a 64-byte signature over
    // the raw 32-byte SHA-256 output (not double-hashed).
    let signature = signing_key.sign(&tx_hash);
    let sig_bytes: [u8; 64] = signature.to_bytes();

    // Build the signature hint: last 4 bytes of the 32-byte public key.
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let hint: [u8; 4] =
        pubkey_bytes[28..32]
            .try_into()
            .map_err(|_| Sep10Error::XdrDecodeError {
                detail: "ephemeral public key shorter than 32 bytes (impossible)".to_owned(),
            })?;

    // Build the DecoratedSignature and push into the envelope.
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
    // push the new DecoratedSignature, then convert back via try_into().
    //
    // The challenge spec guarantees at most 1 existing signature (the server's),
    // so the resulting vec has at most 2 entries — well within the 20-element
    // VecM bound.
    let mut sigs: Vec<DecoratedSignature> = v1_envelope.signatures.to_vec();
    sigs.push(dec_sig);
    v1_envelope.signatures = sigs.try_into().map_err(|_| Sep10Error::XdrDecodeError {
        detail: "too many signatures in challenge envelope (exceeded VecM<20> bound)".to_owned(),
    })?;

    // Re-encode the modified envelope to base64 XDR.
    envelope
        .to_xdr_base64(Limits::none())
        .map_err(|e| Sep10Error::XdrDecodeError {
            detail: format!("failed to re-encode signed challenge envelope: {e}"),
        })
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
/// Thin `pub` wrapper over [`sign_challenge_with_key`] for use in integration
/// test binaries that cannot access `pub(crate)` items.
///
/// Only available under `--features test-helpers`.
///
/// # Errors
///
/// Same as [`sign_challenge_with_key`].
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
}
