//! Ephemeral per-request ed25519 signing and real-signer signing for SEP-45
//! authentication.
//!
//! # Signing entry points
//!
//! There are two client-side signing paths:
//!
//! - [`auth_with_ephemeral_key`] — full auth flow using a per-request ephemeral
//!   keypair. Use only for contracts that register the ephemeral public key or
//!   do not require a fixed client signature (e.g. contracts whose `__check_auth`
//!   accepts any public key presented in the signature).
//!
//! - [`sign_authorization_entries`] — signs the client entry with one or more
//!   real, persistent ed25519 keypairs (e.g. a multisig wallet). Use this when
//!   the smart contract's `__check_auth` verifies a specific known public key.
//!
//! # `auth_with_ephemeral_key` flow
//!
//! 1. Generate a fresh `ed25519_dalek::SigningKey` via `rand_core::OsRng` (one
//!    key per call; never reused or persisted).
//! 2. Wrap the 32-byte seed in `Zeroizing<[u8; 32]>` so it is zeroed on drop.
//! 3. Fetch and validate the SEP-45 challenge via
//!    [`Sep45Client::fetch_challenge`].
//! 4. Sign the client entry's `HashIdPreimageSorobanAuthorization` with the
//!    ephemeral key; attach the `Vec<Map{public_key, signature}>` to the client
//!    entry's credentials (`SorobanAddressCredentials::signature`).
//! 5. Re-encode all entries as `SorobanAuthorizationEntries` XDR base64.
//! 6. Submit via [`Sep45Client::submit_signed_challenge`] → return `Sep45Session`.
//! 7. The `SigningKey` is dropped at end of function scope and zeroed automatically
//!    via `ed25519_dalek::SigningKey`'s `ZeroizeOnDrop` impl (dalek 2.x; `zeroize`
//!    feature enabled in workspace).
//!
//! # Memory discipline
//!
//! The ephemeral key lifetime is bounded to this function's stack frame. The
//! key is zeroed automatically on drop via `ZeroizeOnDrop`. The
//! `Zeroizing<[u8; 32]>` seed copy is also zeroed when the binding goes out
//! of scope.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    BytesM, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits, ScBytes, ScMap,
    ScMapEntry, ScSymbol, ScVal, ScVec, SorobanAuthorizationEntries, SorobanAuthorizationEntry,
    SorobanCredentials, VecM, WriteXdr,
};
use zeroize::Zeroizing;

use crate::client::{ChallengeRequest, Sep45Client};
use crate::entries::AuthorizationEntries;
use crate::error::Sep45Error;
use crate::session::Sep45Session;

// ─────────────────────────────────────────────────────────────────────────────
// auth_with_ephemeral_key
// ─────────────────────────────────────────────────────────────────────────────

/// Authenticates a contract account against the SEP-45 server at
/// `web_auth_endpoint` using a fresh per-request ephemeral ed25519 key.
///
/// This function is appropriate only for contracts whose `__check_auth`
/// accepts the ephemeral public key that is generated internally — typically
/// contracts that register the presented public key at auth time or that do
/// not require a fixed client signature. For contracts that require a
/// specific, known public key (e.g. a multisig wallet), use
/// [`sign_authorization_entries`] instead, which accepts real persistent
/// signer keypairs.
///
/// Generates a one-shot ephemeral keypair and uses it to sign the client
/// entry returned by the server's challenge. Because the server constructed
/// the client entry for the actual `contract_id` C-strkey, this function does
/// NOT need to derive a G-key from the ephemeral pubkey — the ephemeral key
/// is used purely as the signing authority for the client entry, and the
/// signature is attached in the SEP-45 `Vec<Map{public_key, signature}>` shape.
///
/// # SEP-45 signing flow
///
/// Per the SEP-45 signing section, the client must sign the
/// `HashIdPreimageSorobanAuthorization` of its auth entry — the same preimage
/// the server signs for the server entry. The signature is attached to
/// `SorobanAddressCredentials::signature` as
/// `ScVal::Vec([ScVal::Map({public_key: ScBytes(32), signature: ScBytes(64)})])`.
///
/// # Steps
///
/// 1. Generate fresh `SigningKey` via `OsRng` (CSPRNG; per-request unique).
/// 2. Fetch + validate the challenge (steps 1-12 SEP-45 validation; server
///    signature verified against `expected_server_signing_key`; step 13 deferred
///    to the caller's smart-contract layer).
/// 3. Sign the client entry's `HashIdPreimageSorobanAuthorization` SHA-256
///    with the ephemeral key using `request.signature_expiration_ledger`.
/// 4. Attach `Vec<Map{public_key, signature}>` to the client entry credentials.
/// 5. Re-encode all entries as `SorobanAuthorizationEntries` XDR base64.
/// 6. POST to server; parse JWT session.
/// 7. Ephemeral `SigningKey` drops here → `ZeroizeOnDrop` zeroes the key material.
///
/// # Errors
///
/// - Any [`Sep45Error`] from [`Sep45Client::fetch_challenge`] on challenge
///   fetch/validation failure.
/// - [`Sep45Error::InvalidSignatureExpirationLedger`] if
///   `request.signature_expiration_ledger` is 0.
/// - [`Sep45Error::XdrDecodeError`] if the auth preimage XDR cannot be encoded
///   (should not occur for well-formed challenge entries; treated as internal
///   error).
/// - [`Sep45Error::HttpError`] on network failure or non-200 HTTP status on
///   either the GET or POST step.
/// - Any [`Sep45Error`] from [`Sep45Client::submit_signed_challenge`] on POST
///   failure or JWT parse failure.
///
/// # Caveats
///
/// When `client_domain` is set in the request, this function validates that the
/// challenge carries a matching `client_domain` arg and a corresponding
/// credential entry (steps 3b and 11 of validation), but does NOT produce or
/// verify the client-domain entry's signature. Per SEP-45, the client-domain
/// signature must be obtained from the Client Domain Account's server as a
/// separate out-of-band step; this is a known deferred step, analogous to the
/// footprint validation deferral in step 13.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_sep45::client::{Sep45Client, ChallengeRequest};
/// use stellar_agent_sep45::ephemeral::auth_with_ephemeral_key;
///
/// # async fn example() -> Result<(), stellar_agent_sep45::Sep45Error> {
/// let client = Sep45Client::new("Test SDF Network ; September 2015")?;
/// let request = ChallengeRequest {
///     web_auth_endpoint: "https://testanchor.stellar.org/sep45/auth",
///     contract_id: "CCLIENTCONTRACTADDRESSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
///     home_domain: "testanchor.stellar.org",
///     expected_web_auth_contract: "CALI6JC3MSNDGFRP7Z2OKUEPREHOJRRXKMJEWQDEFZPFGXALA45RAUTH",
///     expected_server_signing_key: "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
///     client_domain: None,
///     web_auth_domain: None,
///     signature_expiration_ledger: 9_999_999,
/// };
/// let session = auth_with_ephemeral_key(&client, request).await?;
/// assert!(!session.is_expired(0));
/// # Ok(())
/// # }
/// ```
pub async fn auth_with_ephemeral_key(
    client: &Sep45Client,
    request: ChallengeRequest<'_>,
) -> Result<Sep45Session, Sep45Error> {
    let contract_id = request.contract_id;
    let web_auth_endpoint = request.web_auth_endpoint;

    // Step 1: Generate a fresh ephemeral ed25519 SigningKey.
    // The 32-byte raw seed is placed in a `Zeroizing<[u8; 32]>` wrapper so
    // it is guaranteed to be zeroed when the binding drops. `SigningKey` also
    // implements `ZeroizeOnDrop` — key material zeroed automatically when
    // `ephemeral_key` drops at end of function scope.
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(seed.as_mut());
    let ephemeral_key = SigningKey::from_bytes(&seed);

    // Step 2: Fetch and validate the challenge.
    // `fetch_challenge` performs SEP-45 validation steps 1-12 (step 13 footprint
    // deferred) AND verifies the server signature against `expected_server_signing_key`.
    let challenge = client.fetch_challenge(request).await?;

    // Step 3-5: Sign the client entry and re-encode all entries.
    let signed_xdr = sign_client_entry(
        &challenge,
        &ephemeral_key,
        client,
        request.signature_expiration_ledger,
    )?;

    // Step 6: Submit the signed entries.
    let session = client
        .submit_signed_challenge(web_auth_endpoint, &signed_xdr)
        .await?;

    // Step 7: Verify the JWT `sub` matches the contract_id we authenticated.
    // A mismatch indicates the server returned a JWT for a different account.
    if session.sub != contract_id {
        return Err(Sep45Error::SessionAccountMismatch {
            expected: contract_id.to_owned(),
            found: session.sub.clone(),
        });
    }

    // Step 8: `ephemeral_key` drops here — ZeroizeOnDrop zeroes the key material.
    Ok(session)
}

// ─────────────────────────────────────────────────────────────────────────────
// sign_client_entry
// ─────────────────────────────────────────────────────────────────────────────

/// Signs the client entry in `challenge` with `signing_key` and returns the
/// re-encoded base64 XDR for all entries as `SorobanAuthorizationEntries`.
///
/// Per the SEP-45 signing section:
///
/// 1. Reject `signature_expiration_ledger == 0` — caller must supply a non-zero
///    future ledger sequence (e.g. `current_ledger + 100`).
/// 2. Extract the client entry at `challenge.client_entry_index`.
/// 3. SET `addr_creds.signature_expiration_ledger = signature_expiration_ledger`
///    in the client entry BEFORE computing the preimage.
/// 4. Compute `HashIdPreimageSorobanAuthorization` SHA-256 using the entry's
///    nonce, the new `signature_expiration_ledger`, and root invocation.
/// 5. Sign the hash with `signing_key` via `ed25519_dalek::Signer::sign`.
/// 6. Build `ScVal::Vec([ScVal::Map({public_key: ScBytes(32), signature: ScBytes(64)})])`.
/// 7. Store in `SorobanAddressCredentials::signature` of the client entry.
/// 8. Re-encode all entries as `SorobanAuthorizationEntries` base64 XDR.
///
/// # XDR preimage
///
/// `HashIdPreimageSorobanAuthorization { network_id, nonce, signature_expiration_ledger, invocation }`.
/// `signature_expiration_ledger` is set by the caller; the server's challenge
/// entry carries a placeholder that is overwritten here.
///
/// # Errors
///
/// - [`Sep45Error::InvalidSignatureExpirationLedger`] if
///   `signature_expiration_ledger` is 0.
/// - [`Sep45Error::XdrDecodeError`] if the preimage XDR encode fails or the
///   re-encoded entries XDR fails.
///
/// # Panics
///
/// Never panics.
pub(crate) fn sign_client_entry(
    challenge: &AuthorizationEntries,
    signing_key: &SigningKey,
    client: &Sep45Client,
    signature_expiration_ledger: u32,
) -> Result<String, Sep45Error> {
    if signature_expiration_ledger == 0 {
        return Err(Sep45Error::InvalidSignatureExpirationLedger {
            detail: "signature_expiration_ledger must be non-zero; caller must supply current_ledger + margin".to_owned(),
        });
    }
    let mut entries = challenge.entries.clone();

    let entries_len = entries.len();
    let client_entry = entries
        .get_mut(challenge.client_entry_index)
        .ok_or_else(|| Sep45Error::XdrDecodeError {
            detail: format!(
                "client_entry_index {} out of range (entries len {})",
                challenge.client_entry_index, entries_len
            ),
        })?;

    // Extract address credentials from the client entry.
    let SorobanCredentials::Address(ref mut addr_creds) = client_entry.credentials else {
        return Err(Sep45Error::XdrDecodeError {
            detail: "client entry does not have SorobanCredentials::Address".to_owned(),
        });
    };

    // SET the expiration ledger supplied by the caller.
    // The server's challenge entry carries a placeholder value; the client is
    // responsible for choosing its own expiration window and writing it into
    // the credentials before computing the preimage.
    addr_creds.signature_expiration_ledger = signature_expiration_ledger;

    // Compute the auth preimage for this entry.
    // HashIdPreimageSorobanAuthorization: { network_id, nonce, signature_expiration_ledger, invocation }
    let network_id_hash: [u8; 32] = Sha256::digest(client.network_passphrase().as_bytes()).into();
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network_id_hash),
        nonce: addr_creds.nonce,
        signature_expiration_ledger: addr_creds.signature_expiration_ledger,
        invocation: client_entry.root_invocation.clone(),
    });
    let preimage_xdr = preimage
        .to_xdr(Limits::none())
        .map_err(|e| Sep45Error::XdrDecodeError {
            detail: format!("HashIdPreimageSorobanAuthorization XDR encode failed: {e}"),
        })?;
    let payload_hash: [u8; 32] = Sha256::digest(&preimage_xdr).into();

    // Sign the hash with the ephemeral key.
    // `ed25519_dalek::Signer::sign(&hash)` produces a 64-byte signature.
    let signature = signing_key.sign(&payload_hash);
    let sig_bytes: [u8; 64] = signature.to_bytes();

    // Build the SEP-45 signature shape:
    // `ScVal::Vec([ScVal::Map({public_key: ScBytes(32), signature: ScBytes(64)})])`
    // Per the SEP-45 signing convention (same shape used by the server;
    // client must match).
    let pubkey_bytes = signing_key.verifying_key().to_bytes();

    let pk_bytesm: BytesM =
        pubkey_bytes
            .to_vec()
            .try_into()
            .map_err(|_| Sep45Error::XdrDecodeError {
                detail: "public key bytes BytesM conversion failed (impossible for 32 bytes)"
                    .to_owned(),
            })?;
    let sig_bytesm: BytesM =
        sig_bytes
            .to_vec()
            .try_into()
            .map_err(|_| Sep45Error::XdrDecodeError {
                detail: "signature bytes BytesM conversion failed (impossible for 64 bytes)"
                    .to_owned(),
            })?;

    let sig_map: VecM<ScMapEntry> = vec![
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol::try_from("public_key").map_err(|e| {
                Sep45Error::XdrDecodeError {
                    detail: format!("ScSymbol 'public_key' encode failed: {e:?}"),
                }
            })?),
            val: ScVal::Bytes(ScBytes(pk_bytesm)),
        },
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol::try_from("signature").map_err(|e| {
                Sep45Error::XdrDecodeError {
                    detail: format!("ScSymbol 'signature' encode failed: {e:?}"),
                }
            })?),
            val: ScVal::Bytes(ScBytes(sig_bytesm)),
        },
    ]
    .try_into()
    .map_err(|_| Sep45Error::XdrDecodeError {
        detail: "signature map VecM conversion failed".to_owned(),
    })?;

    let sig_val = ScVal::Vec(Some(ScVec(
        vec![ScVal::Map(Some(ScMap(sig_map)))]
            .try_into()
            .map_err(|_| Sep45Error::XdrDecodeError {
                detail: "signature Vec outer ScVec conversion failed".to_owned(),
            })?,
    )));

    // Attach the signature to the client entry credentials.
    addr_creds.signature = sig_val;

    // Re-encode all entries (server entry unchanged; client entry now signed).
    re_encode_entries(&entries)
}

/// Re-encodes a list of `SorobanAuthorizationEntry` values as a base64 XDR
/// `SorobanAuthorizationEntries` string.
///
/// # Errors
///
/// - [`Sep45Error::XdrDecodeError`] if the entry list cannot be converted to
///   the XDR bounded `VecM` type or the XDR encode fails.
fn re_encode_entries(entries: &[SorobanAuthorizationEntry]) -> Result<String, Sep45Error> {
    let entries_vec: VecM<SorobanAuthorizationEntry> =
        entries
            .to_vec()
            .try_into()
            .map_err(|_| Sep45Error::XdrDecodeError {
                detail: "entries VecM conversion failed".to_owned(),
            })?;
    let entries_xdr = SorobanAuthorizationEntries(entries_vec);
    let mut buf = Vec::new();
    entries_xdr
        .write_xdr(&mut stellar_xdr::Limited::new(&mut buf, Limits::none()))
        .map_err(|e| Sep45Error::XdrDecodeError {
            detail: format!("SorobanAuthorizationEntries XDR encode failed: {e}"),
        })?;
    Ok(BASE64_STANDARD.encode(&buf))
}

// ─────────────────────────────────────────────────────────────────────────────
// Test-only helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a fresh `Zeroizing<[u8; 32]>` seed via `OsRng`.
///
/// Used by adversarial tests to generate ephemeral seeds without going through
/// the full auth flow.
#[cfg(any(test, feature = "test-helpers"))]
pub fn generate_ephemeral_seed() -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(seed.as_mut());
    seed
}

/// Constructs a `SigningKey` from a `Zeroizing<[u8; 32]>` seed.
///
/// Used by adversarial tests to build a deterministic or random ephemeral key.
#[cfg(any(test, feature = "test-helpers"))]
pub fn signing_key_from_seed(seed: &Zeroizing<[u8; 32]>) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Signs the client entry in a parsed SEP-45 challenge with one or more real
/// ed25519 signer keypairs and returns the re-encoded base64 XDR for all entries.
///
/// This is the signing entry point for contracts whose `__check_auth` verifies a
/// specific persistent public key (e.g. multisig wallets). For contracts that
/// accept any ephemeral key, use [`auth_with_ephemeral_key`] instead.
///
/// Only the entry whose `credentials.address` equals `client_account` is signed.
/// All other entries (server entry, client-domain entry) are passed through
/// unchanged.
///
/// When `signers` is empty no entry is modified — the client entry credentials
/// remain as the server issued them (suitable for contracts that do not require a
/// client signature).
///
/// Multiple signers produce multiple `{public_key, signature}` map entries in the
/// `ScVal::Vec(...)` credential, in the order the signers are supplied. The
/// contract's `__check_auth` is responsible for verifying all signatures it
/// requires.
///
/// # Parameters
///
/// - `challenge` — validated challenge returned by [`Sep45Client::fetch_challenge`].
/// - `signers` — slice of ed25519 signing keys. May be empty (no-op).
/// - `client` — `Sep45Client` whose `network_passphrase()` is used for the
///   auth preimage.
/// - `signature_expiration_ledger` — non-zero future ledger sequence written into
///   the client entry's `SorobanAddressCredentials` before hashing.
///
/// # Errors
///
/// - [`Sep45Error::InvalidSignatureExpirationLedger`] if
///   `signature_expiration_ledger` is 0.
/// - [`Sep45Error::XdrDecodeError`] if XDR encode of the auth preimage or the
///   final entries fails.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_sep45::ephemeral::sign_authorization_entries;
/// use stellar_agent_sep45::client::{Sep45Client, ChallengeRequest};
/// use ed25519_dalek::SigningKey;
///
/// # async fn example() -> Result<(), stellar_agent_sep45::Sep45Error> {
/// let client = Sep45Client::new("Test SDF Network ; September 2015")?;
/// let request = ChallengeRequest {
///     web_auth_endpoint: "https://auth.example.com/sep45/auth",
///     contract_id: "CCLIENTCONTRACTADDRESSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
///     home_domain: "example.com",
///     expected_web_auth_contract: "CALI6JC3MSNDGFRP7Z2OKUEPREHOJRRXKMJEWQDEFZPFGXALA45RAUTH",
///     expected_server_signing_key: "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
///     client_domain: None,
///     web_auth_domain: None,
///     signature_expiration_ledger: 9_999_999,
/// };
/// let challenge = client.fetch_challenge(request).await?;
///
/// // Provide the wallet's real ed25519 signing key.
/// let wallet_key = SigningKey::from_bytes(&[0x01u8; 32]);
/// let signed_xdr = sign_authorization_entries(&challenge, &[wallet_key], &client, 9_999_999)?;
///
/// let _session = client.submit_signed_challenge("https://auth.example.com/sep45/auth", &signed_xdr).await?;
/// # Ok(())
/// # }
/// ```
pub fn sign_authorization_entries(
    challenge: &AuthorizationEntries,
    signers: &[SigningKey],
    client: &Sep45Client,
    signature_expiration_ledger: u32,
) -> Result<String, Sep45Error> {
    if signature_expiration_ledger == 0 {
        return Err(Sep45Error::InvalidSignatureExpirationLedger {
            detail: "signature_expiration_ledger must be non-zero; caller must supply current_ledger + margin".to_owned(),
        });
    }

    let mut entries = challenge.entries.clone();

    // When signers is empty, pass through all entries unmodified.
    // An empty signers list means the client entry is submitted as-is
    // (applicable to contracts whose __check_auth does not require a client signature).
    if signers.is_empty() {
        return re_encode_entries(&entries);
    }

    // Identify the client entry (the one whose credential address == client_account).
    let entries_len = entries.len();
    let client_entry = entries
        .get_mut(challenge.client_entry_index)
        .ok_or_else(|| Sep45Error::XdrDecodeError {
            detail: format!(
                "client_entry_index {} out of range (entries len {})",
                challenge.client_entry_index, entries_len
            ),
        })?;

    // Extract address credentials.
    let SorobanCredentials::Address(ref mut addr_creds) = client_entry.credentials else {
        return Err(Sep45Error::XdrDecodeError {
            detail: "client entry does not have SorobanCredentials::Address".to_owned(),
        });
    };

    // Write the caller-supplied expiration into the credentials BEFORE computing
    // the preimage — the preimage includes signature_expiration_ledger.
    addr_creds.signature_expiration_ledger = signature_expiration_ledger;

    // Compute the auth preimage hash.
    let network_id_hash: [u8; 32] = Sha256::digest(client.network_passphrase().as_bytes()).into();
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network_id_hash),
        nonce: addr_creds.nonce,
        signature_expiration_ledger: addr_creds.signature_expiration_ledger,
        invocation: client_entry.root_invocation.clone(),
    });
    let preimage_xdr = preimage
        .to_xdr(Limits::none())
        .map_err(|e| Sep45Error::XdrDecodeError {
            detail: format!("HashIdPreimageSorobanAuthorization XDR encode failed: {e}"),
        })?;
    let payload_hash: [u8; 32] = Sha256::digest(&preimage_xdr).into();

    // Build one `ScVal::Map({public_key, signature})` per signer and collect
    // into the outer `ScVal::Vec` that `SorobanAddressCredentials::signature`
    // expects: `Vec<Map{public_key: Bytes(32), signature: Bytes(64)}>`.
    // Order is preserved — entry[i] corresponds to signers[i].
    let mut inner_vals: Vec<ScVal> = Vec::with_capacity(signers.len());
    for signer in signers {
        let pubkey_bytes = signer.verifying_key().to_bytes();
        let sig_bytes: [u8; 64] = signer.sign(&payload_hash).to_bytes();

        let pk_bytesm: BytesM =
            pubkey_bytes
                .to_vec()
                .try_into()
                .map_err(|_| Sep45Error::XdrDecodeError {
                    detail: "public key bytes BytesM conversion failed (impossible for 32 bytes)"
                        .to_owned(),
                })?;
        let sig_bytesm: BytesM =
            sig_bytes
                .to_vec()
                .try_into()
                .map_err(|_| Sep45Error::XdrDecodeError {
                    detail: "signature bytes BytesM conversion failed (impossible for 64 bytes)"
                        .to_owned(),
                })?;

        let entry_map: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("public_key").map_err(|e| {
                    Sep45Error::XdrDecodeError {
                        detail: format!("ScSymbol 'public_key' encode failed: {e:?}"),
                    }
                })?),
                val: ScVal::Bytes(ScBytes(pk_bytesm)),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signature").map_err(|e| {
                    Sep45Error::XdrDecodeError {
                        detail: format!("ScSymbol 'signature' encode failed: {e:?}"),
                    }
                })?),
                val: ScVal::Bytes(ScBytes(sig_bytesm)),
            },
        ]
        .try_into()
        .map_err(|_| Sep45Error::XdrDecodeError {
            detail: "signature map VecM conversion failed".to_owned(),
        })?;

        inner_vals.push(ScVal::Map(Some(ScMap(entry_map))));
    }

    let sig_val = ScVal::Vec(Some(ScVec(inner_vals.try_into().map_err(|_| {
        Sep45Error::XdrDecodeError {
            detail: "signature outer ScVec conversion failed".to_owned(),
        }
    })?)));

    addr_creds.signature = sig_val;

    re_encode_entries(&entries)
}

/// Signs a challenge and returns the re-encoded base64 XDR.
///
/// Thin `pub` wrapper over the internal `sign_client_entry` helper for use in
/// integration test binaries that cannot access `pub(crate)` items.
///
/// Only available under `--features test-helpers` or `--features testnet-integration`.
///
/// # Errors
///
/// Returns the same [`Sep45Error`] variants as `sign_client_entry`.
///
/// # Panics
///
/// Never panics.
#[cfg(any(test, feature = "test-helpers"))]
pub fn sign_challenge_for_test(
    challenge: &AuthorizationEntries,
    signing_key: &SigningKey,
    client: &Sep45Client,
    signature_expiration_ledger: u32,
) -> Result<String, Sep45Error> {
    sign_client_entry(challenge, signing_key, client, signature_expiration_ledger)
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

    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use zeroize::Zeroizing;

    use super::{generate_ephemeral_seed, sign_authorization_entries, signing_key_from_seed};

    // ── sign_authorization_entries ────────────────────────────────────────────

    /// `sign_authorization_entries` with a single real signer must produce a
    /// client entry whose credential signature contains exactly that signer's
    /// public key and a valid ed25519 signature over the correct preimage.
    #[test]
    fn sign_authorization_entries_single_signer_correct_pubkey_and_valid_sig() {
        use crate::entries::AuthorizationEntries;
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
        use sha2::{Digest, Sha256};
        use stellar_xdr::{
            AccountId, ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
            InvokeContractArgs, Limits, PublicKey as XdrPublicKey, ReadXdr, ScAddress, ScBytes,
            ScMap, ScMapEntry, ScString, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
            SorobanAuthorizationEntries, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation, SorobanCredentials, Uint256, VecM, WriteXdr,
        };

        let network = "Test SDF Network ; September 2015";
        let contract = "CALI6JC3MSNDGFRP7Z2OKUEPREHOJRRXKMJEWQDEFZPFGXALA45RAUTH";
        let client_account = "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ";
        let home = "example.com";
        let web_auth = "auth.example.com";
        let server_seed = [1u8; 32];
        const EXPIRY: u32 = 7_777_777;

        let server_key = SigningKey::from_bytes(&server_seed);
        let server_pubkey = server_key.verifying_key().to_bytes();
        let server_g_str = format!("{}", stellar_strkey::ed25519::PublicKey(server_pubkey));

        let contract_bytes = stellar_strkey::Contract::from_string(contract).unwrap().0;
        let contract_address = ScAddress::Contract(ContractId(Hash(contract_bytes)));

        let map_entries = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                val: ScVal::String(ScString(client_account.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                val: ScVal::String(ScString(home.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                val: ScVal::String(ScString("SIGNTEST_NONCE01".try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                val: ScVal::String(ScString(web_auth.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
            },
        ];
        let args_scmap: VecM<ScMapEntry> = map_entries.try_into().unwrap();
        let args_val = ScVal::Map(Some(ScMap(args_scmap)));
        let fn_args = InvokeContractArgs {
            contract_address: contract_address.clone(),
            function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
            args: vec![args_val].try_into().unwrap(),
        };
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(fn_args),
            sub_invocations: VecM::default(),
        };

        let server_nonce: i64 = 99887766;
        let server_expiry: u32 = 9_000_000;
        let network_id_hash = {
            let mut h = Sha256::new();
            h.update(network.as_bytes());
            Hash(h.finalize().into())
        };
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: network_id_hash,
            nonce: server_nonce,
            signature_expiration_ledger: server_expiry,
            invocation: invocation.clone(),
        });
        let mut pbuf = Vec::new();
        preimage
            .write_xdr(&mut stellar_xdr::Limited::new(&mut pbuf, Limits::none()))
            .unwrap();
        let payload = {
            let mut h = Sha256::new();
            h.update(&pbuf);
            h.finalize()
        };
        use ed25519_dalek::Signer;
        let sig_bytes_srv = server_key.sign(&payload).to_bytes();

        let server_sig_scval = ScVal::Vec(Some(ScVec(
            vec![ScVal::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("public_key".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(server_pubkey.to_vec().try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("signature".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(sig_bytes_srv.to_vec().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            )))]
            .try_into()
            .unwrap(),
        )));

        let client_nonce: i64 = 11223344;
        let server_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(server_pubkey),
                ))),
                nonce: server_nonce,
                signature_expiration_ledger: server_expiry,
                signature: server_sig_scval,
            }),
            root_invocation: invocation.clone(),
        };
        let client_bytes = stellar_strkey::Contract::from_string(client_account)
            .unwrap()
            .0;
        let client_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(client_bytes))),
                nonce: client_nonce,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: invocation.clone(),
        };

        let entries_xdr =
            SorobanAuthorizationEntries(vec![server_entry, client_entry].try_into().unwrap());
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        let xdr_b64 = BASE64_STANDARD.encode(&out);

        let challenge = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_g_str,
            None,
            client_account,
        )
        .unwrap();

        let test_client = crate::client::Sep45Client::new_for_unit_test(network).unwrap();

        // The real signer's key (deterministic).
        let signer_seed = [0xDEu8; 32];
        let real_signer = SigningKey::from_bytes(&signer_seed);
        let expected_pubkey = real_signer.verifying_key().to_bytes();

        let signed_b64 =
            sign_authorization_entries(&challenge, &[real_signer], &test_client, EXPIRY).unwrap();

        // Decode the signed XDR.
        let raw = BASE64_STANDARD.decode(&signed_b64).unwrap();
        let decoded = SorobanAuthorizationEntries::read_xdr(&mut stellar_xdr::Limited::new(
            raw.as_slice(),
            Limits::none(),
        ))
        .unwrap();
        let entries: Vec<_> = decoded.0.into_vec();

        // Client entry must have a non-Void Vec signature.
        let SorobanCredentials::Address(ref addr_creds) =
            entries[challenge.client_entry_index].credentials
        else {
            panic!("client entry must have Address credentials");
        };
        assert_eq!(
            addr_creds.signature_expiration_ledger, EXPIRY,
            "expiration ledger must be EXPIRY={EXPIRY}"
        );

        let sig_vec = match &addr_creds.signature {
            stellar_xdr::ScVal::Vec(Some(v)) => v,
            other => panic!("expected ScVal::Vec(Some(_)), got {other:?}"),
        };
        assert_eq!(sig_vec.len(), 1, "single signer → single sig map in Vec");

        let sig_map = match &sig_vec[0] {
            stellar_xdr::ScVal::Map(Some(m)) => m,
            other => panic!("expected ScVal::Map(Some(_)), got {other:?}"),
        };

        let mut pk_bytes: Option<&[u8]> = None;
        let mut sig_bytes: Option<&[u8]> = None;
        for entry in sig_map.iter() {
            let key = match &entry.key {
                stellar_xdr::ScVal::Symbol(sym) => {
                    std::str::from_utf8(sym.0.as_slice()).unwrap_or("")
                }
                _ => continue,
            };
            match key {
                "public_key" => {
                    if let stellar_xdr::ScVal::Bytes(b) = &entry.val {
                        pk_bytes = Some(b.0.as_slice());
                    }
                }
                "signature" => {
                    if let stellar_xdr::ScVal::Bytes(b) = &entry.val {
                        sig_bytes = Some(b.0.as_slice());
                    }
                }
                _ => {}
            }
        }

        let pk = pk_bytes.expect("public_key must be present");
        let sig = sig_bytes.expect("signature must be present");

        // Public key must match the real signer's verifying key.
        assert_eq!(
            pk, &expected_pubkey,
            "public_key in signed entry must be the real signer's verifying key"
        );

        // Verify the signature is cryptographically valid.
        // Recompute the payload independently.
        let client_invocation = entries[challenge.client_entry_index]
            .root_invocation
            .clone();
        let preimage2 = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: Hash(Sha256::digest(network.as_bytes()).into()),
            nonce: addr_creds.nonce,
            signature_expiration_ledger: EXPIRY,
            invocation: client_invocation,
        });
        let mut pbuf2 = Vec::new();
        preimage2
            .write_xdr(&mut stellar_xdr::Limited::new(&mut pbuf2, Limits::none()))
            .unwrap();
        let expected_payload: [u8; 32] = Sha256::digest(&pbuf2).into();

        let pk_arr: [u8; 32] = pk.try_into().expect("pk must be 32 bytes");
        let sig_arr: [u8; 64] = sig.try_into().expect("sig must be 64 bytes");
        let vk = VerifyingKey::from_bytes(&pk_arr).expect("valid ed25519 point");
        let dalek_sig = DalekSignature::from_bytes(&sig_arr);
        assert!(
            vk.verify_strict(&expected_payload, &dalek_sig).is_ok(),
            "signature must verify over HashIdPreimageSorobanAuthorization with EXPIRY={EXPIRY}"
        );

        // Server entry must remain unchanged (non-Void Vec).
        let SorobanCredentials::Address(ref srv_creds) =
            entries[challenge.server_entry_index].credentials
        else {
            panic!("server entry must have Address credentials");
        };
        assert!(
            matches!(srv_creds.signature, stellar_xdr::ScVal::Vec(Some(_))),
            "server entry must remain untouched"
        );
    }

    /// When `signers` is empty, `sign_authorization_entries` returns the entries
    /// re-encoded with the client entry unchanged (still Void signature).
    #[test]
    fn sign_authorization_entries_empty_signers_passthrough() {
        use crate::entries::AuthorizationEntries;
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use sha2::{Digest, Sha256};
        use stellar_xdr::{
            AccountId, ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
            InvokeContractArgs, Limits, PublicKey as XdrPublicKey, ReadXdr, ScAddress, ScBytes,
            ScMap, ScMapEntry, ScString, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
            SorobanAuthorizationEntries, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation, SorobanCredentials, Uint256, VecM, WriteXdr,
        };

        let network = "Test SDF Network ; September 2015";
        let contract = "CALI6JC3MSNDGFRP7Z2OKUEPREHOJRRXKMJEWQDEFZPFGXALA45RAUTH";
        let client_account = "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ";
        let home = "example.com";
        let web_auth = "auth.example.com";
        let server_seed = [1u8; 32];

        let server_key = SigningKey::from_bytes(&server_seed);
        let server_pubkey = server_key.verifying_key().to_bytes();
        let server_g_str = format!("{}", stellar_strkey::ed25519::PublicKey(server_pubkey));

        let contract_bytes = stellar_strkey::Contract::from_string(contract).unwrap().0;
        let contract_address = ScAddress::Contract(ContractId(Hash(contract_bytes)));

        let map_entries = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                val: ScVal::String(ScString(client_account.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                val: ScVal::String(ScString(home.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                val: ScVal::String(ScString("PASSTHROUGH_NONCE".try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                val: ScVal::String(ScString(web_auth.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
            },
        ];
        let args_scmap: VecM<ScMapEntry> = map_entries.try_into().unwrap();
        let args_val = ScVal::Map(Some(ScMap(args_scmap)));
        let fn_args = InvokeContractArgs {
            contract_address: contract_address.clone(),
            function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
            args: vec![args_val].try_into().unwrap(),
        };
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(fn_args),
            sub_invocations: VecM::default(),
        };

        let server_nonce: i64 = 55667788;
        let server_expiry: u32 = 8_000_000;
        let network_id_hash = {
            let mut h = Sha256::new();
            h.update(network.as_bytes());
            Hash(h.finalize().into())
        };
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: network_id_hash,
            nonce: server_nonce,
            signature_expiration_ledger: server_expiry,
            invocation: invocation.clone(),
        });
        let mut pbuf = Vec::new();
        preimage
            .write_xdr(&mut stellar_xdr::Limited::new(&mut pbuf, Limits::none()))
            .unwrap();
        let payload = {
            let mut h = Sha256::new();
            h.update(&pbuf);
            h.finalize()
        };
        use ed25519_dalek::Signer;
        let sig_bytes_srv = server_key.sign(&payload).to_bytes();

        let server_sig_scval = ScVal::Vec(Some(ScVec(
            vec![ScVal::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("public_key".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(server_pubkey.to_vec().try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("signature".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(sig_bytes_srv.to_vec().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            )))]
            .try_into()
            .unwrap(),
        )));

        let server_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(server_pubkey),
                ))),
                nonce: server_nonce,
                signature_expiration_ledger: server_expiry,
                signature: server_sig_scval,
            }),
            root_invocation: invocation.clone(),
        };
        let client_bytes = stellar_strkey::Contract::from_string(client_account)
            .unwrap()
            .0;
        let client_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(client_bytes))),
                nonce: 9988776i64,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: invocation,
        };

        let entries_xdr =
            SorobanAuthorizationEntries(vec![server_entry, client_entry].try_into().unwrap());
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        let xdr_b64 = BASE64_STANDARD.encode(&out);

        let challenge = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_g_str,
            None,
            client_account,
        )
        .unwrap();

        let test_client = crate::client::Sep45Client::new_for_unit_test(network).unwrap();

        // Empty signers → passthrough.
        let signed_b64 =
            sign_authorization_entries(&challenge, &[], &test_client, 5_000_000).unwrap();

        let raw = BASE64_STANDARD.decode(&signed_b64).unwrap();
        let decoded = SorobanAuthorizationEntries::read_xdr(&mut stellar_xdr::Limited::new(
            raw.as_slice(),
            Limits::none(),
        ))
        .unwrap();
        let entries: Vec<_> = decoded.0.into_vec();

        // Client entry must still carry Void (not signed).
        let SorobanCredentials::Address(ref addr_creds) =
            entries[challenge.client_entry_index].credentials
        else {
            panic!("client entry must have Address credentials");
        };
        assert!(
            matches!(addr_creds.signature, stellar_xdr::ScVal::Void),
            "empty signers must leave client entry Void; got {:?}",
            addr_creds.signature
        );
    }

    /// Two distinct deterministic signers produce a `ScVal::Vec` of length 2 in
    /// the client entry's signature, with entries in signer-supply order. Both
    /// signatures must verify independently via `ed25519_dalek::VerifyingKey::verify_strict`
    /// over the independently recomputed `HashIdPreimageSorobanAuthorization` hash.
    ///
    /// This test would fail if a signer entry were dropped, reordered, or its
    /// signature corrupted.
    #[test]
    fn sign_authorization_entries_two_signers_order_and_validity() {
        use crate::entries::AuthorizationEntries;
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
        use sha2::{Digest, Sha256};
        use stellar_xdr::{
            AccountId, ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
            InvokeContractArgs, Limits, PublicKey as XdrPublicKey, ReadXdr, ScAddress, ScBytes,
            ScMap, ScMapEntry, ScString, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
            SorobanAuthorizationEntries, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation, SorobanCredentials, Uint256, VecM, WriteXdr,
        };

        let network = "Test SDF Network ; September 2015";
        let contract = "CALI6JC3MSNDGFRP7Z2OKUEPREHOJRRXKMJEWQDEFZPFGXALA45RAUTH";
        let client_account = "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ";
        let home = "example.com";
        let web_auth = "auth.example.com";
        let server_seed = [1u8; 32];
        const EXPIRY: u32 = 6_543_210;

        let server_key = SigningKey::from_bytes(&server_seed);
        let server_pubkey = server_key.verifying_key().to_bytes();
        let server_g_str = format!("{}", stellar_strkey::ed25519::PublicKey(server_pubkey));

        let contract_bytes = stellar_strkey::Contract::from_string(contract).unwrap().0;
        let contract_address = ScAddress::Contract(ContractId(Hash(contract_bytes)));

        let map_entries = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                val: ScVal::String(ScString(client_account.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                val: ScVal::String(ScString(home.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                val: ScVal::String(ScString("TWO_SIGNER_NONCE".try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                val: ScVal::String(ScString(web_auth.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
            },
        ];
        let args_scmap: VecM<ScMapEntry> = map_entries.try_into().unwrap();
        let args_val = ScVal::Map(Some(ScMap(args_scmap)));
        let fn_args = InvokeContractArgs {
            contract_address: contract_address.clone(),
            function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
            args: vec![args_val].try_into().unwrap(),
        };
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(fn_args),
            sub_invocations: VecM::default(),
        };

        let server_nonce: i64 = 13579246;
        let server_expiry: u32 = 9_100_000;
        let network_id_hash = {
            let mut h = Sha256::new();
            h.update(network.as_bytes());
            Hash(h.finalize().into())
        };
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: network_id_hash,
            nonce: server_nonce,
            signature_expiration_ledger: server_expiry,
            invocation: invocation.clone(),
        });
        let mut pbuf = Vec::new();
        preimage
            .write_xdr(&mut stellar_xdr::Limited::new(&mut pbuf, Limits::none()))
            .unwrap();
        let payload = {
            let mut h = Sha256::new();
            h.update(&pbuf);
            h.finalize()
        };
        use ed25519_dalek::Signer;
        let sig_bytes_srv = server_key.sign(&payload).to_bytes();

        let server_sig_scval = ScVal::Vec(Some(ScVec(
            vec![ScVal::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("public_key".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(server_pubkey.to_vec().try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("signature".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(sig_bytes_srv.to_vec().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            )))]
            .try_into()
            .unwrap(),
        )));

        let client_nonce: i64 = 24681357;
        let server_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(server_pubkey),
                ))),
                nonce: server_nonce,
                signature_expiration_ledger: server_expiry,
                signature: server_sig_scval,
            }),
            root_invocation: invocation.clone(),
        };
        let client_bytes = stellar_strkey::Contract::from_string(client_account)
            .unwrap()
            .0;
        let client_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(client_bytes))),
                nonce: client_nonce,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: invocation.clone(),
        };

        let entries_xdr =
            SorobanAuthorizationEntries(vec![server_entry, client_entry].try_into().unwrap());
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        let xdr_b64 = BASE64_STANDARD.encode(&out);

        let challenge = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_g_str,
            None,
            client_account,
        )
        .unwrap();

        let test_client = crate::client::Sep45Client::new_for_unit_test(network).unwrap();

        // Two distinct deterministic signers: A (0xAA seed) and B (0xBB seed).
        let signer_a = SigningKey::from_bytes(&[0xAAu8; 32]);
        let signer_b = SigningKey::from_bytes(&[0xBBu8; 32]);
        let pubkey_a = signer_a.verifying_key().to_bytes();
        let pubkey_b = signer_b.verifying_key().to_bytes();
        assert_ne!(pubkey_a, pubkey_b, "signers A and B must be distinct");

        let signed_b64 =
            sign_authorization_entries(&challenge, &[signer_a, signer_b], &test_client, EXPIRY)
                .unwrap();

        // Decode re-encoded XDR.
        let raw = BASE64_STANDARD.decode(&signed_b64).unwrap();
        let decoded = SorobanAuthorizationEntries::read_xdr(&mut stellar_xdr::Limited::new(
            raw.as_slice(),
            Limits::none(),
        ))
        .unwrap();
        let entries: Vec<_> = decoded.0.into_vec();

        // Client entry must have Address credentials.
        let SorobanCredentials::Address(ref addr_creds) =
            entries[challenge.client_entry_index].credentials
        else {
            panic!("client entry must have Address credentials");
        };
        assert_eq!(addr_creds.signature_expiration_ledger, EXPIRY);

        // Signature must be Vec of exactly length 2.
        let sig_vec = match &addr_creds.signature {
            ScVal::Vec(Some(v)) => v,
            other => panic!("expected ScVal::Vec(Some(_)), got {other:?}"),
        };
        assert_eq!(
            sig_vec.len(),
            2,
            "two signers must produce Vec of length 2; got {}",
            sig_vec.len()
        );

        // Recompute the payload independently using the actual client nonce.
        let client_invocation = entries[challenge.client_entry_index]
            .root_invocation
            .clone();
        let preimage2 = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: Hash(Sha256::digest(network.as_bytes()).into()),
            nonce: addr_creds.nonce,
            signature_expiration_ledger: EXPIRY,
            invocation: client_invocation,
        });
        let mut pbuf2 = Vec::new();
        preimage2
            .write_xdr(&mut stellar_xdr::Limited::new(&mut pbuf2, Limits::none()))
            .unwrap();
        let expected_payload: [u8; 32] = Sha256::digest(&pbuf2).into();

        // Helper closure: extract (pk_bytes, sig_bytes) from a Vec entry.
        let extract_pk_sig = |entry: &ScVal| -> ([u8; 32], [u8; 64]) {
            let map = match entry {
                ScVal::Map(Some(m)) => m,
                other => panic!("expected ScVal::Map(Some(_)), got {other:?}"),
            };
            let mut pk: Option<[u8; 32]> = None;
            let mut sig: Option<[u8; 64]> = None;
            for e in map.iter() {
                let key = match &e.key {
                    ScVal::Symbol(sym) => std::str::from_utf8(sym.0.as_slice()).unwrap_or(""),
                    _ => continue,
                };
                match key {
                    "public_key" => {
                        if let ScVal::Bytes(b) = &e.val {
                            pk = Some(b.0.as_slice().try_into().expect("pk must be 32 bytes"));
                        }
                    }
                    "signature" => {
                        if let ScVal::Bytes(b) = &e.val {
                            sig = Some(b.0.as_slice().try_into().expect("sig must be 64 bytes"));
                        }
                    }
                    _ => {}
                }
            }
            (
                pk.expect("public_key must be present"),
                sig.expect("signature must be present"),
            )
        };

        // Entry 0 must carry signer A's pubkey, entry 1 must carry signer B's pubkey
        // (order preserved = order signers were supplied).
        let (pk0, sig0) = extract_pk_sig(&sig_vec[0]);
        let (pk1, sig1) = extract_pk_sig(&sig_vec[1]);

        assert_eq!(pk0, pubkey_a, "entry[0] public_key must be signer A's");
        assert_eq!(pk1, pubkey_b, "entry[1] public_key must be signer B's");

        // Both signatures must verify over the independently recomputed payload.
        let vk_a = VerifyingKey::from_bytes(&pk0).expect("valid ed25519 point for signer A");
        let vk_b = VerifyingKey::from_bytes(&pk1).expect("valid ed25519 point for signer B");
        let dalek_sig_a = DalekSignature::from_bytes(&sig0);
        let dalek_sig_b = DalekSignature::from_bytes(&sig1);
        assert!(
            vk_a.verify_strict(&expected_payload, &dalek_sig_a).is_ok(),
            "signer A signature must verify over HashIdPreimageSorobanAuthorization"
        );
        assert!(
            vk_b.verify_strict(&expected_payload, &dalek_sig_b).is_ok(),
            "signer B signature must verify over HashIdPreimageSorobanAuthorization"
        );
    }

    // ── Ephemeral key uniqueness ──────────────────────────────────────────────

    /// Each call to `generate_ephemeral_seed` + `signing_key_from_seed` must
    /// produce a distinct key. This enforces per-request key uniqueness.
    #[test]
    fn ephemeral_keys_differ_across_calls() {
        let seed1 = generate_ephemeral_seed();
        let seed2 = generate_ephemeral_seed();
        // Seeds MUST differ (birthday probability 2^{-256}; treat as impossible).
        assert_ne!(*seed1, *seed2, "two consecutive OsRng seeds must differ");

        let key1 = signing_key_from_seed(&seed1);
        let key2 = signing_key_from_seed(&seed2);
        assert_ne!(
            key1.verifying_key().to_bytes(),
            key2.verifying_key().to_bytes(),
            "two ephemeral keys derived from distinct seeds must have distinct pubkeys"
        );
    }

    /// Property: 50 consecutive `generate_ephemeral_seed` calls produce all
    /// distinct values.
    #[test]
    fn ephemeral_seeds_are_unique_across_50_calls() {
        use std::collections::HashSet;
        let mut seeds: HashSet<[u8; 32]> = HashSet::new();
        for _ in 0..50 {
            let s = generate_ephemeral_seed();
            assert!(
                seeds.insert(*s),
                "duplicate seed generated in 50-call loop (CSPRNG failure)"
            );
        }
    }

    // ── SigningKey from seed is deterministic ─────────────────────────────────

    /// A `SigningKey` constructed from the same seed bytes must produce the
    /// same public key every time.
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

    /// Generates two `SigningKey` instances via `SigningKey::generate(&mut OsRng)`
    /// and asserts they differ. This is the same path `auth_with_ephemeral_key`
    /// takes internally.
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
}
