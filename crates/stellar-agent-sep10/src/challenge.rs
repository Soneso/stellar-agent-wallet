//! SEP-10 v3.4.1 challenge transaction parsing and 13-point validation.
//!
//! The [`Challenge`] type holds the fully-validated result of a SEP-10
//! challenge transaction. [`Challenge::parse_and_validate`] performs all 13
//! validation steps from SEP-10 v3.4.1.
//!
//! # Validation steps
//!
//! 1. Base64-decode + XDR-decode to `TransactionEnvelope` (reject `TxV0` and `TxFeeBump`).
//! 2. Extract `Transaction` from the `Tx` (V1) envelope.
//! 3. Verify sequence number = 0. Critical replay defence: a non-zero sequence
//!    number would allow the challenge to be submitted to the network as a live
//!    transaction.
//! 4. Verify time bounds set + `min <= now < max`.
//! 5. Verify source account = expected server signing key.
//! 6. Verify at least 1 operation present.
//! 7. Verify first op = `ManageData` with source = client account (non-null).
//! 8. Verify first op key = `"<home_domain> auth"` (≤ 64 chars).
//! 9. Verify first op value = exactly 64 bytes (base64 of a 48-byte random nonce).
//! 10. Scan subsequent ops — locate `web_auth_domain` ManageData op (required v3.4.1).
//! 11. If `client_domain` op present, validate source ≠ Server Account.
//! 12. All other subsequent ops must have source = Server Account.
//! 13. Verify ≥ 1 signature present; cryptographically verify Server signature
//!     against `TransactionSignaturePayload` hash.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    Hash, Limits, MuxedAccount, Operation, OperationBody, ReadXdr, TransactionEnvelope,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction, WriteXdr,
};

use crate::error::Sep10Error;

/// A fully-validated SEP-10 v3.4.1 challenge transaction.
///
/// Constructed exclusively via [`Challenge::parse_and_validate`], which
/// performs all 13 validation steps before returning. Every field reflects
/// the validated, canonical state — callers do not need to re-validate.
#[derive(Debug, Clone)]
pub struct Challenge {
    /// The raw XDR base64 of the validated challenge envelope.
    ///
    /// Retained so the client can attach its own signature and resubmit.
    pub envelope_xdr: String,

    /// The server account (SIGNING_KEY) that issued the challenge.
    ///
    /// Validated to match `expected_server_signing_key` and confirmed to have
    /// signed the `TransactionSignaturePayload` in step 13.
    pub server_account: stellar_strkey::ed25519::PublicKey,

    /// The server's web auth domain (from the `web_auth_domain` ManageData op).
    ///
    /// Validated to match `expected_web_auth_domain` in step 10.
    pub web_auth_domain: String,

    /// The client account (source of the first ManageData operation).
    ///
    /// May be a plain G-key or muxed M-key stored as the raw strkey string.
    pub client_account: String,

    /// The client domain, if a `client_domain` ManageData operation is present.
    ///
    /// Validated to have a source account ≠ Server Account in step 11.
    pub client_domain: Option<String>,

    /// The 48-byte random nonce from the first ManageData operation value.
    ///
    /// The spec requires 64 encoded bytes (base64 of 48 random bytes). The
    /// decoded 48 bytes are stored here.
    pub nonce: [u8; 48],

    /// The challenge time bounds (`min_time`, `max_time`) in Unix seconds.
    ///
    /// Both bounds are validated at parse time against `now_unix`.
    pub time_bounds: (u64, u64),
}

impl Challenge {
    /// Parses and validates a SEP-10 v3.4.1 challenge transaction.
    ///
    /// Performs the full 13-point validation per SEP-10 v3.4.1. Any failure
    /// returns a typed [`Sep10Error`] variant; the function is fail-closed
    /// (no partial success).
    ///
    /// # Parameters
    ///
    /// - `xdr_b64` — the base64-encoded `TransactionEnvelope` XDR returned by
    ///   the server's challenge endpoint.
    /// - `network_passphrase` — the Stellar network passphrase used to compute
    ///   the `TransactionSignaturePayload` hash for server signature verification.
    /// - `expected_home_domain` — the Home Domain whose `"<home_domain> auth"`
    ///   ManageData key the first operation must carry.
    /// - `expected_web_auth_domain` — the server's web auth domain; must match
    ///   the `web_auth_domain` ManageData op value.
    /// - `expected_server_signing_key` — the `SIGNING_KEY` strkey from the
    ///   server's `stellar.toml`; must match both the transaction source account
    ///   and a valid signature over the payload.
    /// - `now_unix` — current time as Unix seconds (injected for deterministic
    ///   testing; callers pass `SystemTime::now()` in production).
    ///
    /// # Errors
    ///
    /// - [`Sep10Error::XdrDecodeError`] — base64 or XDR decode failure.
    /// - [`Sep10Error::InvalidSequenceNumber`] — sequence number is not 0.
    /// - [`Sep10Error::InvalidTimeBounds`] — time bounds absent or malformed.
    /// - [`Sep10Error::ChallengeExpired`] — `now_unix >= max_time`.
    /// - [`Sep10Error::ChallengeNotYetValid`] — `now_unix < min_time`.
    /// - [`Sep10Error::InvalidSourceAccount`] — tx source ≠ server signing key.
    /// - [`Sep10Error::MissingOperations`] — no operations in transaction.
    /// - [`Sep10Error::InvalidFirstOperation`] — first op not ManageData or missing source.
    /// - [`Sep10Error::InvalidManageDataKey`] — first op key ≠ `"<home_domain> auth"`.
    /// - [`Sep10Error::InvalidNonceLength`] — nonce value is not 64 bytes.
    /// - [`Sep10Error::InvalidNonceFormat`] — nonce value is not valid base64.
    /// - [`Sep10Error::MissingWebAuthDomainOp`] — no `web_auth_domain` op found.
    /// - [`Sep10Error::WebAuthDomainMismatch`] — `web_auth_domain` value mismatch.
    /// - [`Sep10Error::InvalidClientDomainOp`] — `client_domain` op invalid.
    /// - [`Sep10Error::UnexpectedOperationSource`] — extra op has wrong source.
    /// - [`Sep10Error::MissingServerSignature`] — transaction has no signatures.
    /// - [`Sep10Error::InvalidServerSignature`] — server signature fails to verify.
    ///
    /// # Time-bound semantics
    ///
    /// This implementation enforces a half-open interval `[min_time, max_time)`:
    /// the check `now_unix >= max_time` treats `max_time` as exclusive. This is
    /// intentionally stricter than some reference implementations — a challenge
    /// valid exactly at `max_time` on a slow network path could arrive at a
    /// downstream validator after the boundary has passed, causing a race.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Typically obtained from a GET to `WEB_AUTH_ENDPOINT?account=G...`:
    /// let xdr_b64 = "<base64 challenge from server>";
    /// let result = stellar_agent_sep10::Challenge::parse_and_validate(
    ///     xdr_b64,
    ///     "Test SDF Network ; September 2015",
    ///     "testanchor.stellar.org",
    ///     "testanchor.stellar.org",
    ///     "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
    ///     1_717_000_000,
    /// );
    /// ```
    pub fn parse_and_validate(
        xdr_b64: &str,
        network_passphrase: &str,
        expected_home_domain: &str,
        expected_web_auth_domain: &str,
        expected_server_signing_key: &str,
        now_unix: u64,
    ) -> Result<Self, Sep10Error> {
        // Step 1: base64-decode + XDR-decode to TransactionEnvelope.
        // The challenge XDR comes from an untrusted anchor server; bounded
        // limits prevent a crafted deeply-nested
        // `SorobanAuthorizedInvocation.sub_invocations` chain from exhausting
        // the stack.
        let envelope = TransactionEnvelope::from_xdr_base64(
            xdr_b64,
            stellar_agent_xdr_limits::untrusted_decode_limits(xdr_b64.len()),
        )
        .map_err(|e| Sep10Error::XdrDecodeError {
            detail: format!("TransactionEnvelope decode failed: {e}"),
        })?;

        // Step 2: Extract Transaction from V1 envelope; reject V0 and FeeBump.
        // SEP-10 challenges must be plain V1 (TransactionEnvelope::Tx).
        let v1_envelope = match &envelope {
            TransactionEnvelope::Tx(v1) => v1,
            TransactionEnvelope::TxV0(_) => {
                return Err(Sep10Error::XdrDecodeError {
                    detail: "SEP-10 challenge must be TransactionEnvelope::Tx (V1), got TxV0"
                        .to_owned(),
                });
            }
            TransactionEnvelope::TxFeeBump(_) => {
                return Err(Sep10Error::XdrDecodeError {
                    detail: "SEP-10 challenge must be TransactionEnvelope::Tx (V1), got TxFeeBump"
                        .to_owned(),
                });
            }
        };
        let tx = &v1_envelope.tx;

        // Step 3: Verify sequence number = 0.
        // Replay defence: the challenge must have sequence number 0 so it
        // cannot be submitted to the network as a live transaction.
        let seq_num: i64 = tx.seq_num.0;
        if seq_num != 0 {
            return Err(Sep10Error::InvalidSequenceNumber { found: seq_num });
        }

        // Step 4: Verify time bounds set and `min_time <= now_unix < max_time`.
        // SEP-10 recommends a 15-minute window.
        let (min_time, max_time) = extract_time_bounds(tx)?;
        if now_unix < min_time {
            return Err(Sep10Error::ChallengeNotYetValid {
                min_unix: min_time,
                now_unix,
            });
        }
        if now_unix >= max_time {
            return Err(Sep10Error::ChallengeExpired {
                exp_unix: max_time,
                now_unix,
            });
        }

        // Step 5: Verify source account = expected_server_signing_key.
        // The transaction source must be the Server Account.
        let server_pk = parse_server_signing_key(expected_server_signing_key)?;
        let tx_source_strkey = muxed_account_to_strkey(&tx.source_account)?;
        if tx_source_strkey != expected_server_signing_key {
            return Err(Sep10Error::InvalidSourceAccount {
                detail: format!(
                    "tx source account does not match expected server signing key \
                     (source has hint {:?})",
                    tx_source_strkey.get(..5).unwrap_or_default()
                ),
            });
        }

        // Step 6: Verify at least 1 operation present.
        let ops: &[Operation] = &tx.operations;
        if ops.is_empty() {
            return Err(Sep10Error::MissingOperations);
        }

        // Step 7: Verify first op = ManageData with source = client account.
        // Source must be non-null and set to the Client Account.
        let first_op = &ops[0];
        let manage_data_0 = require_manage_data_op(first_op, "first operation")?;
        let client_account_muxed =
            first_op
                .source_account
                .as_ref()
                .ok_or_else(|| Sep10Error::InvalidFirstOperation {
                    detail:
                        "first ManageData operation has no source account (client account required)"
                            .to_owned(),
                })?;
        let client_account_strkey = muxed_account_to_strkey(client_account_muxed)?;

        // Step 8: Verify first op key = "<expected_home_domain> auth" (≤ 64 chars).
        let expected_key = format!("{expected_home_domain} auth");
        if expected_key.len() > 64 {
            return Err(Sep10Error::InvalidManageDataKey {
                detail: format!(
                    "key \"{expected_key}\" is {} chars (max 64)",
                    expected_key.len()
                ),
            });
        }
        let actual_key = manage_data_0.data_name.to_string();
        if actual_key != expected_key {
            return Err(Sep10Error::InvalidManageDataKey {
                detail: format!("expected key \"{expected_key}\", got \"{actual_key}\""),
            });
        }

        // Step 9: Verify first op value = exactly 64 bytes, base64-decodable to 48 bytes.
        // The spec requires 64 bytes in the value field encoding 48 random bytes.
        let nonce_raw =
            manage_data_0
                .data_value
                .as_ref()
                .ok_or(Sep10Error::InvalidNonceLength {
                    found: 0,
                    expected: 64,
                })?;
        let nonce_bytes: &[u8] = nonce_raw.as_slice();
        if nonce_bytes.len() != 64 {
            return Err(Sep10Error::InvalidNonceLength {
                found: nonce_bytes.len(),
                expected: 64,
            });
        }
        // Decode the 64 encoded bytes to get the 48-byte random nonce.
        let nonce_decoded =
            BASE64_STANDARD
                .decode(nonce_bytes)
                .map_err(|e| Sep10Error::InvalidNonceFormat {
                    detail: format!("nonce base64 decode failed: {e}"),
                })?;
        if nonce_decoded.len() != 48 {
            return Err(Sep10Error::InvalidNonceFormat {
                detail: format!(
                    "nonce base64 decoded to {} bytes (expected 48)",
                    nonce_decoded.len()
                ),
            });
        }
        let mut nonce = [0u8; 48];
        nonce.copy_from_slice(&nonce_decoded);

        // Steps 10-12: Scan subsequent operations.
        // Required: one `web_auth_domain` op (source = Server Account).
        // Optional: one `client_domain` op (source ≠ Server Account).
        // All others: source must be Server Account.
        let ScanResult {
            web_auth_domain,
            client_domain,
        } = scan_subsequent_ops(ops, expected_server_signing_key, expected_web_auth_domain)?;

        // Step 13: Verify server signature.
        // Construct TransactionSignaturePayload, hash with SHA-256, verify.
        // The challenge must be signed by the Server Account.
        verify_server_signature(v1_envelope, tx, network_passphrase, &server_pk)?;

        Ok(Self {
            envelope_xdr: xdr_b64.to_owned(),
            server_account: server_pk,
            web_auth_domain,
            client_account: client_account_strkey,
            client_domain,
            nonce,
            time_bounds: (min_time, max_time),
        })
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Extracts and validates time bounds from the transaction preconditions.
///
/// Returns `(min_time, max_time)` as Unix seconds.
fn extract_time_bounds(tx: &stellar_xdr::Transaction) -> Result<(u64, u64), Sep10Error> {
    use stellar_xdr::Preconditions;
    match &tx.cond {
        Preconditions::Time(tb) => Ok((tb.min_time.0, tb.max_time.0)),
        Preconditions::V2(v2) => {
            let tb = v2
                .time_bounds
                .as_ref()
                .ok_or_else(|| Sep10Error::InvalidTimeBounds {
                    detail: "PreconditionsV2 has no time_bounds field".to_owned(),
                })?;
            Ok((tb.min_time.0, tb.max_time.0))
        }
        Preconditions::None => Err(Sep10Error::InvalidTimeBounds {
            detail: "challenge transaction has no time bounds (Preconditions::None)".to_owned(),
        }),
    }
}

/// Parses the expected server signing key from a G-strkey string.
fn parse_server_signing_key(
    strkey: &str,
) -> Result<stellar_strkey::ed25519::PublicKey, Sep10Error> {
    strkey
        .parse::<stellar_strkey::ed25519::PublicKey>()
        .map_err(|e| Sep10Error::InvalidSourceAccount {
            detail: format!("expected_server_signing_key is not a valid G-strkey: {e}"),
        })
}

/// Converts a `MuxedAccount` to its strkey string representation.
///
/// For `Ed25519` (plain G-key): returns the G-strkey.
/// For `MuxedEd25519` (M-key): returns the M-strkey via stellar_strkey.
fn muxed_account_to_strkey(muxed: &MuxedAccount) -> Result<String, Sep10Error> {
    match muxed {
        MuxedAccount::Ed25519(key_bytes) => {
            let pk = stellar_strkey::ed25519::PublicKey(key_bytes.0);
            // stellar-strkey to_string() returns heapless::String<N>;
            // convert to std::String via the Display trait.
            Ok(format!("{pk}"))
        }
        MuxedAccount::MuxedEd25519(mux) => {
            let muxed_pk = stellar_strkey::ed25519::MuxedAccount {
                id: mux.id,
                ed25519: mux.ed25519.0,
            };
            Ok(format!("{muxed_pk}"))
        }
    }
}

/// Requires that an operation is a ManageData operation and returns a reference
/// to the `ManageDataOp`. Returns `Sep10Error::InvalidFirstOperation` if not.
fn require_manage_data_op<'a>(
    op: &'a Operation,
    context: &str,
) -> Result<&'a stellar_xdr::ManageDataOp, Sep10Error> {
    match &op.body {
        OperationBody::ManageData(md) => Ok(md),
        other => Err(Sep10Error::InvalidFirstOperation {
            detail: format!("{context} must be ManageData, got {:?}", other.name()),
        }),
    }
}

/// Result from scanning subsequent operations (ops[1..]).
struct ScanResult {
    web_auth_domain: String,
    client_domain: Option<String>,
}

/// Scans operations at index 1 and beyond, validating sources and extracting
/// `web_auth_domain` and `client_domain` values.
fn scan_subsequent_ops(
    ops: &[Operation],
    server_signing_key: &str,
    expected_web_auth_domain: &str,
) -> Result<ScanResult, Sep10Error> {
    let mut found_web_auth_domain: Option<String> = None;
    let mut found_client_domain: Option<String> = None;

    for (raw_idx, op) in ops.iter().enumerate().skip(1) {
        let md = match &op.body {
            OperationBody::ManageData(md) => md,
            other => {
                // Extra ops that are not ManageData are unexpected per spec.
                return Err(Sep10Error::UnexpectedOperationSource {
                    op_index: raw_idx,
                    detail: format!(
                        "subsequent operations must be ManageData; got {:?}",
                        other.name()
                    ),
                });
            }
        };

        let key = md.data_name.to_string();
        let op_source_strkey = op
            .source_account
            .as_ref()
            .map(muxed_account_to_strkey)
            .transpose()?;

        if key == "web_auth_domain" {
            // Step 10: web_auth_domain op — source must be Server Account.
            match &op_source_strkey {
                Some(src) if src != server_signing_key => {
                    return Err(Sep10Error::UnexpectedOperationSource {
                        op_index: raw_idx,
                        detail: format!(
                            "web_auth_domain op source must be server account; \
                             got hint {:?}",
                            src.get(..5).unwrap_or_default()
                        ),
                    });
                }
                None => {
                    return Err(Sep10Error::UnexpectedOperationSource {
                        op_index: raw_idx,
                        detail: "web_auth_domain op has no source account".to_owned(),
                    });
                }
                Some(_) => {} // source == server_signing_key; OK
            }

            // Validate value matches expected_web_auth_domain.
            let value_bytes =
                md.data_value
                    .as_ref()
                    .ok_or_else(|| Sep10Error::WebAuthDomainMismatch {
                        found: String::new(),
                        expected: expected_web_auth_domain.to_owned(),
                    })?;
            let value = String::from_utf8(value_bytes.as_slice().to_vec()).map_err(|_| {
                Sep10Error::WebAuthDomainMismatch {
                    found: "<non-utf8>".to_owned(),
                    expected: expected_web_auth_domain.to_owned(),
                }
            })?;
            if value != expected_web_auth_domain {
                return Err(Sep10Error::WebAuthDomainMismatch {
                    found: value,
                    expected: expected_web_auth_domain.to_owned(),
                });
            }
            found_web_auth_domain = Some(value);
        } else if key == "client_domain" {
            // Step 11: client_domain op — source must NOT be the Server Account.
            match &op_source_strkey {
                Some(src) if src == server_signing_key => {
                    return Err(Sep10Error::InvalidClientDomainOp {
                        detail: "client_domain op source must not be the server account".to_owned(),
                    });
                }
                None => {
                    return Err(Sep10Error::InvalidClientDomainOp {
                        detail: "client_domain op has no source account".to_owned(),
                    });
                }
                Some(_) => {} // source ≠ server account; OK
            }

            let value_bytes =
                md.data_value
                    .as_ref()
                    .ok_or_else(|| Sep10Error::InvalidClientDomainOp {
                        detail: "client_domain op has no value".to_owned(),
                    })?;
            let value = String::from_utf8(value_bytes.as_slice().to_vec()).map_err(|_| {
                Sep10Error::InvalidClientDomainOp {
                    detail: "client_domain op value is not valid UTF-8".to_owned(),
                }
            })?;
            found_client_domain = Some(value);
        } else {
            // Step 12: all other subsequent ops — source must be Server Account.
            match &op_source_strkey {
                Some(src) if src != server_signing_key => {
                    return Err(Sep10Error::UnexpectedOperationSource {
                        op_index: raw_idx,
                        detail: format!(
                            "operation at index {raw_idx} source must be server account; \
                             got hint {:?}",
                            src.get(..5).unwrap_or_default()
                        ),
                    });
                }
                None => {
                    return Err(Sep10Error::UnexpectedOperationSource {
                        op_index: raw_idx,
                        detail: format!(
                            "operation at index {raw_idx} has no source account \
                             (server account required)"
                        ),
                    });
                }
                Some(_) => {} // source == server account; OK
            }
        }
    }

    // web_auth_domain is required in SEP-10 v3.4.1.
    let web_auth_domain = found_web_auth_domain.ok_or(Sep10Error::MissingWebAuthDomainOp)?;

    Ok(ScanResult {
        web_auth_domain,
        client_domain: found_client_domain,
    })
}

/// Verifies the server's ed25519 signature over the `TransactionSignaturePayload`.
///
/// Constructs the canonical signing payload
/// (`SHA-256(network_id_bytes || TaggedTransaction_XDR)`) and verifies that at
/// least one `DecoratedSignature` in the envelope matches the server public key.
fn verify_server_signature(
    envelope: &stellar_xdr::TransactionV1Envelope,
    tx: &stellar_xdr::Transaction,
    network_passphrase: &str,
    server_pk: &stellar_strkey::ed25519::PublicKey,
) -> Result<(), Sep10Error> {
    let sigs = &envelope.signatures;
    if sigs.is_empty() {
        return Err(Sep10Error::MissingServerSignature);
    }

    // Build TransactionSignaturePayload.
    // stellar-xdr TransactionSignaturePayload: { network_id: Hash(SHA256(passphrase)),
    //   tagged_transaction: Tx(tx) }. The hash of this XDR is what is signed.
    let network_id_hash = Hash(Sha256::digest(network_passphrase.as_bytes()).into());
    let tagged_tx = TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone());
    let sig_payload = TransactionSignaturePayload {
        network_id: network_id_hash,
        tagged_transaction: tagged_tx,
    };
    let payload_bytes =
        sig_payload
            .to_xdr(Limits::none())
            .map_err(|e| Sep10Error::InvalidServerSignature {
                detail: format!("TransactionSignaturePayload XDR encode failed: {e}"),
            })?;
    let tx_hash: [u8; 32] = Sha256::digest(&payload_bytes).into();

    // Construct the ed25519-dalek VerifyingKey from the server's 32-byte pubkey.
    let verifying_key =
        VerifyingKey::from_bytes(&server_pk.0).map_err(|e| Sep10Error::InvalidServerSignature {
            detail: format!("server public key is not a valid ed25519 key: {e}"),
        })?;

    // The server's signature hint is the last 4 bytes of its 32-byte public key.
    let server_hint: [u8; 4] =
        server_pk.0[28..32]
            .try_into()
            .map_err(|_| Sep10Error::InvalidServerSignature {
                detail: "server public key shorter than 32 bytes".to_owned(),
            })?;

    // Scan all DecoratedSignatures for one matching the server hint + passing
    // verify_strict. Ordering is not mandated by the spec.
    let mut found_server_sig = false;
    for dec_sig in sigs.iter() {
        if dec_sig.hint.0 != server_hint {
            continue;
        }
        // Hint matches — attempt cryptographic verification.
        let sig_bytes: &[u8] = dec_sig.signature.as_slice();
        if sig_bytes.len() != 64 {
            continue;
        }
        let sig_arr: [u8; 64] = match sig_bytes.try_into() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let dalek_sig = DalekSignature::from_bytes(&sig_arr);
        if verifying_key.verify_strict(&tx_hash, &dalek_sig).is_ok() {
            found_server_sig = true;
            break;
        }
    }

    if !found_server_sig {
        return Err(Sep10Error::InvalidServerSignature {
            detail: "no signature from the server account verified against the \
                     TransactionSignaturePayload hash"
                .to_owned(),
        });
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    //! Unit tests for [`Challenge::parse_and_validate`].
    //!
    //! All tests use fixture-only data (no HTTP I/O).
    //!
    //! Server keypair used in fixtures (test-only, never mainnet):
    //! - Seed: `[1u8; 32]`
    //! - Public key: `GBPWRXPKTKWBFKZW5ELRNZAGBXN2QG63B4DC7BXMMQARME2MH2BWRP3`
    //!
    //! Client keypair:
    //! - Seed: `[2u8; 32]`
    //! - Public key: `GDFZJNXAEFGBXFX4QKVLASFLSM3E6JBZ3JWTTODGRFLH7VMMYLFFNYS`

    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use stellar_xdr::{
        BytesM, DataValue, DecoratedSignature, Hash, Limits, ManageDataOp, Memo, MuxedAccount,
        Operation, OperationBody, Preconditions, SequenceNumber, Signature, SignatureHint, StringM,
        TimeBounds, TimePoint, Transaction, TransactionEnvelope, TransactionExt,
        TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
        TransactionV1Envelope, VecM, WriteXdr,
    };

    /// Converts a `&str` to a `String64` (XDR `StringM<64>` newtype).
    fn str_to_string64(s: &str) -> stellar_xdr::String64 {
        StringM::<64>::try_from(s.as_bytes().to_vec())
            .unwrap()
            .into()
    }

    /// Converts a byte slice to a `DataValue` (XDR `BytesM<64>` newtype).
    fn bytes_to_data_value(b: &[u8]) -> DataValue {
        DataValue(BytesM::<64>::try_from(b.to_vec()).unwrap())
    }

    use super::*;

    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
    const HOME_DOMAIN: &str = "testanchor.stellar.org";
    const WEB_AUTH_DOMAIN: &str = "testanchor.stellar.org";

    // ── Key material for fixtures (test-only, never mainnet) ─────────────────

    fn server_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    fn server_pub_key() -> stellar_strkey::ed25519::PublicKey {
        let sk = server_signing_key();
        let vk = ed25519_dalek::VerifyingKey::from(&sk);
        stellar_strkey::ed25519::PublicKey(vk.to_bytes())
    }

    fn client_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[2u8; 32])
    }

    fn client_pub_key() -> stellar_strkey::ed25519::PublicKey {
        let sk = client_signing_key();
        let vk = ed25519_dalek::VerifyingKey::from(&sk);
        stellar_strkey::ed25519::PublicKey(vk.to_bytes())
    }

    // ── Fixture builder ───────────────────────────────────────────────────────

    struct FixtureParams {
        seq_num: i64,
        min_time: u64,
        max_time: u64,
        server_key: stellar_strkey::ed25519::PublicKey,
        client_key: stellar_strkey::ed25519::PublicKey,
        first_op_key: String,
        nonce: Vec<u8>,
        include_web_auth_domain: bool,
        web_auth_domain_value: String,
        web_auth_domain_source: stellar_strkey::ed25519::PublicKey,
        include_client_domain: bool,
        client_domain_source: Option<stellar_strkey::ed25519::PublicKey>,
        sign_with: Option<SigningKey>,
        extra_ops: Vec<Operation>,
    }

    impl Default for FixtureParams {
        fn default() -> Self {
            let nonce_raw = [0xABu8; 48];
            let nonce_b64 = BASE64_STANDARD.encode(nonce_raw);
            Self {
                seq_num: 0,
                min_time: 1_000_000_000,
                max_time: 1_000_000_900, // 900-second window for test stability
                server_key: server_pub_key(),
                client_key: client_pub_key(),
                first_op_key: format!("{HOME_DOMAIN} auth"),
                nonce: nonce_b64.into_bytes(),
                include_web_auth_domain: true,
                web_auth_domain_value: WEB_AUTH_DOMAIN.to_owned(),
                web_auth_domain_source: server_pub_key(),
                include_client_domain: false,
                client_domain_source: None,
                sign_with: Some(server_signing_key()),
                extra_ops: Vec::new(),
            }
        }
    }

    fn build_fixture(p: FixtureParams) -> String {
        let server_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(p.server_key.0));
        let client_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(p.client_key.0));
        let web_auth_source =
            MuxedAccount::Ed25519(stellar_xdr::Uint256(p.web_auth_domain_source.0));

        let first_op = Operation {
            source_account: Some(client_muxed.clone()),
            body: OperationBody::ManageData(ManageDataOp {
                data_name: str_to_string64(&p.first_op_key),
                data_value: Some(bytes_to_data_value(&p.nonce)),
            }),
        };

        let mut ops: Vec<Operation> = vec![first_op];

        if p.include_web_auth_domain {
            ops.push(Operation {
                source_account: Some(web_auth_source),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64("web_auth_domain"),
                    data_value: Some(bytes_to_data_value(p.web_auth_domain_value.as_bytes())),
                }),
            });
        }

        if p.include_client_domain {
            let cd_source = p.client_domain_source.unwrap_or_else(client_pub_key);
            let cd_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(cd_source.0));
            ops.push(Operation {
                source_account: Some(cd_muxed),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64("client_domain"),
                    data_value: Some(bytes_to_data_value(b"client.example.com")),
                }),
            });
        }

        for op in p.extra_ops {
            ops.push(op);
        }

        let operations: VecM<Operation, 100> = ops.try_into().unwrap();

        let tx = Transaction {
            source_account: server_muxed,
            fee: 100,
            seq_num: SequenceNumber(p.seq_num),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(p.min_time),
                max_time: TimePoint(p.max_time),
            }),
            memo: Memo::None,
            operations,
            ext: TransactionExt::V0,
        };

        let mut signatures: Vec<DecoratedSignature> = Vec::new();
        if let Some(sk) = p.sign_with {
            let vk = ed25519_dalek::VerifyingKey::from(&sk);
            let pk = stellar_strkey::ed25519::PublicKey(vk.to_bytes());
            let hint: [u8; 4] = pk.0[28..32].try_into().unwrap();

            let network_id_hash = Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into());
            let tagged_tx = TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone());
            let sig_payload = TransactionSignaturePayload {
                network_id: network_id_hash,
                tagged_transaction: tagged_tx,
            };
            let payload_bytes = sig_payload.to_xdr(Limits::none()).unwrap();
            let tx_hash: [u8; 32] = Sha256::digest(&payload_bytes).into();

            use ed25519_dalek::Signer as _;
            let sig = sk.sign(&tx_hash);
            let sig_bytes: Vec<u8> = sig.to_bytes().to_vec();
            signatures.push(DecoratedSignature {
                hint: SignatureHint(hint),
                signature: Signature(sig_bytes.try_into().unwrap()),
            });
        }
        let sigs_vec: VecM<DecoratedSignature, 20> = signatures.try_into().unwrap();

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: sigs_vec,
        });
        envelope.to_xdr_base64(Limits::none()).unwrap()
    }

    fn now_in_window() -> u64 {
        1_000_000_500u64 // midpoint of the 1_000_000_000..1_000_000_900 window
    }

    fn server_strkey() -> String {
        format!("{}", server_pub_key())
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[test]
    fn happy_path_parse_and_validate_succeeds() {
        let xdr = build_fixture(FixtureParams::default());
        let challenge = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap();
        assert_eq!(challenge.web_auth_domain, WEB_AUTH_DOMAIN);
        assert_eq!(challenge.client_domain, None);
        assert_eq!(challenge.nonce.len(), 48);
        assert_eq!(challenge.time_bounds.0, 1_000_000_000);
        assert_eq!(challenge.time_bounds.1, 1_000_000_900);
    }

    // ── Step 3: sequence number ────────────────────────────────────────────────

    #[test]
    fn reject_non_zero_sequence_number() {
        let xdr = build_fixture(FixtureParams {
            seq_num: 1,
            ..Default::default()
        });
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::InvalidSequenceNumber { found: 1 }),
            "expected InvalidSequenceNumber got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.invalid_sequence_number");
    }

    /// Boundary coverage for `seq_num` validation.
    ///
    /// Guards against future `as u64` or `> 0` refactors.
    #[test]
    fn reject_non_zero_sequence_number_boundaries() {
        let boundary_values: &[i64] = &[-1, i64::MAX, i64::MIN];
        for &seq in boundary_values {
            let xdr = build_fixture(FixtureParams {
                seq_num: seq,
                ..Default::default()
            });
            let err = Challenge::parse_and_validate(
                &xdr,
                TESTNET_PASSPHRASE,
                HOME_DOMAIN,
                WEB_AUTH_DOMAIN,
                &server_strkey(),
                now_in_window(),
            )
            .unwrap_err();
            assert!(
                matches!(err, Sep10Error::InvalidSequenceNumber { found } if found == seq),
                "seq_num={seq}: expected InvalidSequenceNumber {{ found: {seq} }}, got {err:?}"
            );
            assert_eq!(
                err.wire_code(),
                "sep10.invalid_sequence_number",
                "wire_code mismatch for seq_num={seq}"
            );
        }
    }

    // ── Step 4: time bounds ───────────────────────────────────────────────────

    #[test]
    fn reject_expired_challenge() {
        let xdr = build_fixture(FixtureParams::default());
        // now_unix is past the max_time of 1_000_000_900
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            1_000_001_000,
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::ChallengeExpired { .. }),
            "expected ChallengeExpired got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.challenge_expired");
    }

    #[test]
    fn reject_not_yet_valid_challenge() {
        let xdr = build_fixture(FixtureParams::default());
        // now_unix is before the min_time of 1_000_000_000
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            999_999_999,
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::ChallengeNotYetValid { .. }),
            "expected ChallengeNotYetValid got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.challenge_not_yet_valid");
    }

    /// Regression lock for `Preconditions::None` path.
    #[test]
    fn reject_missing_time_bounds() {
        use stellar_xdr::{
            DecoratedSignature, Hash, Limits, Memo, MuxedAccount, Preconditions, Signature,
            SignatureHint, Transaction, TransactionEnvelope, TransactionExt,
            TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
            TransactionV1Envelope, VecM, WriteXdr,
        };
        let server = server_pub_key();
        let server_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(server.0));
        let tx = Transaction {
            source_account: server_muxed,
            fee: 100,
            seq_num: stellar_xdr::SequenceNumber(0),
            cond: Preconditions::None, // no time bounds at all
            memo: Memo::None,
            operations: VecM::default(),
            ext: TransactionExt::V0,
        };
        let sk = server_signing_key();
        let vk = ed25519_dalek::VerifyingKey::from(&sk);
        let pk = stellar_strkey::ed25519::PublicKey(vk.to_bytes());
        let hint: [u8; 4] = pk.0[28..32].try_into().unwrap();
        let network_id_hash = Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into());
        let tagged_tx = TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone());
        let sig_payload = TransactionSignaturePayload {
            network_id: network_id_hash,
            tagged_transaction: tagged_tx,
        };
        let payload_bytes = sig_payload.to_xdr(Limits::none()).unwrap();
        let tx_hash: [u8; 32] = Sha256::digest(&payload_bytes).into();
        use ed25519_dalek::Signer as _;
        let sig = sk.sign(&tx_hash);
        let sigs: VecM<DecoratedSignature, 20> = vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(sig.to_bytes().to_vec().try_into().unwrap()),
        }]
        .try_into()
        .unwrap();
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: sigs,
        });
        let xdr = env.to_xdr_base64(Limits::none()).unwrap();
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::InvalidTimeBounds { .. }),
            "expected InvalidTimeBounds for Preconditions::None, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.invalid_time_bounds");
    }

    /// Regression lock for `Preconditions::V2` with `time_bounds: None`.
    #[test]
    fn reject_v2_preconditions_with_no_time_bounds() {
        use stellar_xdr::{
            DecoratedSignature, Hash, LedgerBounds, Limits, Memo, MuxedAccount, PreconditionsV2,
            Signature, SignatureHint, Transaction, TransactionEnvelope, TransactionExt,
            TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
            TransactionV1Envelope, VecM, WriteXdr,
        };
        let server = server_pub_key();
        let server_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(server.0));
        let tx = Transaction {
            source_account: server_muxed,
            fee: 100,
            seq_num: stellar_xdr::SequenceNumber(0),
            cond: stellar_xdr::Preconditions::V2(PreconditionsV2 {
                time_bounds: None, // V2 present but no time_bounds
                ledger_bounds: Some(LedgerBounds {
                    min_ledger: 0,
                    max_ledger: 0,
                }),
                min_seq_num: None,
                min_seq_age: stellar_xdr::Duration(0),
                min_seq_ledger_gap: 0,
                extra_signers: VecM::default(),
            }),
            memo: Memo::None,
            operations: VecM::default(),
            ext: TransactionExt::V0,
        };
        let sk = server_signing_key();
        let vk = ed25519_dalek::VerifyingKey::from(&sk);
        let pk = stellar_strkey::ed25519::PublicKey(vk.to_bytes());
        let hint: [u8; 4] = pk.0[28..32].try_into().unwrap();
        let network_id_hash = Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into());
        let tagged_tx = TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone());
        let sig_payload = TransactionSignaturePayload {
            network_id: network_id_hash,
            tagged_transaction: tagged_tx,
        };
        let payload_bytes = sig_payload.to_xdr(Limits::none()).unwrap();
        let tx_hash: [u8; 32] = Sha256::digest(&payload_bytes).into();
        use ed25519_dalek::Signer as _;
        let sig = sk.sign(&tx_hash);
        let sigs: VecM<DecoratedSignature, 20> = vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(sig.to_bytes().to_vec().try_into().unwrap()),
        }]
        .try_into()
        .unwrap();
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: sigs,
        });
        let xdr = env.to_xdr_base64(Limits::none()).unwrap();
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::InvalidTimeBounds { .. }),
            "expected InvalidTimeBounds for PreconditionsV2 with no time_bounds, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.invalid_time_bounds");
    }

    // ── Step 5: source account ────────────────────────────────────────────────

    #[test]
    fn reject_wrong_source_account() {
        let xdr = build_fixture(FixtureParams::default());
        // Use a different key as the expected server key
        let wrong_key = client_pub_key().to_string();
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &wrong_key,
            now_in_window(),
        )
        .unwrap_err();
        // Step 5 (source account check) fires before signature verification.
        assert!(
            matches!(err, Sep10Error::InvalidSourceAccount { .. }),
            "expected InvalidSourceAccount got {err:?}"
        );
    }

    // ── Step 6: missing operations ────────────────────────────────────────────

    #[test]
    fn reject_missing_operations() {
        use stellar_xdr::{
            DecoratedSignature, Hash, Limits, Memo, MuxedAccount, Preconditions, SequenceNumber,
            Signature, SignatureHint, TimeBounds, TimePoint, Transaction, TransactionEnvelope,
            TransactionExt, TransactionSignaturePayload,
            TransactionSignaturePayloadTaggedTransaction, TransactionV1Envelope, VecM, WriteXdr,
        };
        let server = server_pub_key();
        let server_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(server.0));
        let tx = Transaction {
            source_account: server_muxed,
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(1_000_000_000),
                max_time: TimePoint(1_000_000_900),
            }),
            memo: Memo::None,
            operations: VecM::default(),
            ext: TransactionExt::V0,
        };
        let sk = server_signing_key();
        let vk = ed25519_dalek::VerifyingKey::from(&sk);
        let pk = stellar_strkey::ed25519::PublicKey(vk.to_bytes());
        let hint: [u8; 4] = pk.0[28..32].try_into().unwrap();
        let network_id_hash = Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into());
        let tagged_tx = TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone());
        let sig_payload = TransactionSignaturePayload {
            network_id: network_id_hash,
            tagged_transaction: tagged_tx,
        };
        let payload_bytes = sig_payload.to_xdr(Limits::none()).unwrap();
        let tx_hash: [u8; 32] = Sha256::digest(&payload_bytes).into();
        use ed25519_dalek::Signer as _;
        let sig = sk.sign(&tx_hash);
        let sigs: VecM<DecoratedSignature, 20> = vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(sig.to_bytes().to_vec().try_into().unwrap()),
        }]
        .try_into()
        .unwrap();
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: sigs,
        });
        let xdr = env.to_xdr_base64(Limits::none()).unwrap();
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::MissingOperations),
            "expected MissingOperations got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.missing_operations");
    }

    // ── Step 8: ManageData key format ─────────────────────────────────────────

    #[test]
    fn reject_wrong_manage_data_key() {
        let xdr = build_fixture(FixtureParams {
            first_op_key: "wrongdomain.com auth".to_owned(),
            ..Default::default()
        });
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::InvalidManageDataKey { .. }),
            "expected InvalidManageDataKey got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.invalid_manage_data_key");
    }

    // ── Step 9: nonce length ──────────────────────────────────────────────────

    #[test]
    fn reject_nonce_wrong_length() {
        let xdr = build_fixture(FixtureParams {
            nonce: b"tooshort".to_vec(),
            ..Default::default()
        });
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                Sep10Error::InvalidNonceLength { .. } | Sep10Error::InvalidNonceFormat { .. }
            ),
            "expected InvalidNonceLength or InvalidNonceFormat got {err:?}"
        );
    }

    #[test]
    fn reject_nonce_not_base64() {
        // Exactly 64 bytes that are not valid standard base64 (all '!' characters).
        // '!' is not in the standard base64 alphabet, so BASE64_STANDARD.decode will fail.
        let bad_nonce = vec![b'!'; 64];
        let xdr = build_fixture(FixtureParams {
            nonce: bad_nonce,
            ..Default::default()
        });
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                Sep10Error::InvalidNonceFormat { .. } | Sep10Error::InvalidNonceLength { .. }
            ),
            "expected InvalidNonceFormat or InvalidNonceLength got {err:?}"
        );
    }

    // ── Step 10: web_auth_domain ──────────────────────────────────────────────

    #[test]
    fn reject_missing_web_auth_domain_op() {
        let xdr = build_fixture(FixtureParams {
            include_web_auth_domain: false,
            ..Default::default()
        });
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::MissingWebAuthDomainOp),
            "expected MissingWebAuthDomainOp got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.missing_web_auth_domain_op");
    }

    #[test]
    fn reject_web_auth_domain_mismatch() {
        let xdr = build_fixture(FixtureParams {
            web_auth_domain_value: "evil.example.com".to_owned(),
            ..Default::default()
        });
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::WebAuthDomainMismatch { .. }),
            "expected WebAuthDomainMismatch got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.web_auth_domain_mismatch");
    }

    // ── Step 11: client_domain op ─────────────────────────────────────────────

    #[test]
    fn reject_client_domain_op_with_server_source() {
        let xdr = build_fixture(FixtureParams {
            include_client_domain: true,
            client_domain_source: Some(server_pub_key()),
            ..Default::default()
        });
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::InvalidClientDomainOp { .. }),
            "expected InvalidClientDomainOp got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.invalid_client_domain_op");
    }

    // ── Step 12: unexpected operation source ──────────────────────────────────

    #[test]
    fn reject_extra_op_with_non_server_source() {
        let client = client_pub_key();
        let extra_op = Operation {
            source_account: Some(MuxedAccount::Ed25519(stellar_xdr::Uint256(client.0))),
            body: OperationBody::ManageData(ManageDataOp {
                data_name: str_to_string64("custom_key"),
                data_value: None,
            }),
        };
        let xdr = build_fixture(FixtureParams {
            extra_ops: vec![extra_op],
            ..Default::default()
        });
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::UnexpectedOperationSource { .. }),
            "expected UnexpectedOperationSource got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.unexpected_operation_source");
    }

    // ── Step 13: server signature ─────────────────────────────────────────────

    #[test]
    fn reject_missing_server_signature() {
        let xdr = build_fixture(FixtureParams {
            sign_with: None,
            ..Default::default()
        });
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::MissingServerSignature),
            "expected MissingServerSignature got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.missing_server_signature");
    }

    #[test]
    fn reject_invalid_server_signature() {
        // Sign with the client key instead of the server key
        let xdr = build_fixture(FixtureParams {
            sign_with: Some(client_signing_key()),
            ..Default::default()
        });
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        // The client key hint doesn't match the server hint, so no matching
        // signature is found → found_server_sig stays false → InvalidServerSignature.
        assert!(
            matches!(err, Sep10Error::InvalidServerSignature { .. }),
            "expected InvalidServerSignature got {err:?}"
        );
    }

    /// Covers the cryptographic-verify-fail arm: injects a `DecoratedSignature`
    /// carrying the correct server hint but 64 garbage bytes, forcing
    /// `verify_strict` to run and return an error.
    #[test]
    fn reject_invalid_server_signature_with_matching_hint() {
        use stellar_xdr::{
            DecoratedSignature, Limits, Signature, SignatureHint, TransactionEnvelope,
            TransactionV1Envelope, VecM, WriteXdr,
        };

        let xdr_unsigned = build_fixture(FixtureParams {
            sign_with: None,
            ..Default::default()
        });
        let mut envelope =
            TransactionEnvelope::from_xdr_base64(&xdr_unsigned, Limits::none()).unwrap();

        let server_pk = server_pub_key();
        let server_hint: [u8; 4] = server_pk.0[28..32].try_into().unwrap();

        let garbage_sig_bytes = [0xDEu8; 64];
        let forged_dec_sig = DecoratedSignature {
            hint: SignatureHint(server_hint),
            signature: Signature(garbage_sig_bytes.to_vec().try_into().unwrap()),
        };

        let v1_env = match &mut envelope {
            TransactionEnvelope::Tx(v1) => v1,
            _ => panic!("expected Tx envelope"),
        };
        let sigs: VecM<DecoratedSignature, 20> = vec![forged_dec_sig].try_into().unwrap();
        *v1_env = TransactionV1Envelope {
            tx: v1_env.tx.clone(),
            signatures: sigs,
        };
        let xdr = envelope.to_xdr_base64(Limits::none()).unwrap();

        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::InvalidServerSignature { .. }),
            "expected InvalidServerSignature got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.invalid_server_signature");
    }

    // ── XDR decode error ──────────────────────────────────────────────────────

    #[test]
    fn reject_garbage_input() {
        let err = Challenge::parse_and_validate(
            "not-valid-base64!!!",
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::XdrDecodeError { .. }),
            "expected XdrDecodeError got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.xdr_decode_error");
    }

    // ── client_domain happy path ──────────────────────────────────────────────

    #[test]
    fn happy_path_with_client_domain() {
        let xdr = build_fixture(FixtureParams {
            include_client_domain: true,
            // client_domain_source defaults to client_pub_key (≠ server)
            ..Default::default()
        });
        let challenge = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap();
        assert_eq!(
            challenge.client_domain,
            Some("client.example.com".to_owned())
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Negative-path coverage: uncovered rejection branches
    // ─────────────────────────────────────────────────────────────────────────

    // ── 1. TxV0 envelope rejected ─────────────────────────────────────────────

    /// A `TransactionV0Envelope` XDR must be rejected with `XdrDecodeError`
    /// (only V1 envelopes are valid for SEP-10).
    #[test]
    fn reject_txv0_envelope() {
        use stellar_xdr::{TransactionV0, TransactionV0Envelope, TransactionV0Ext, Uint256, VecM};

        // Build a minimal TxV0 (sequence = 0, time bounds cover now_in_window).
        let server = server_pub_key();
        let client = client_pub_key();
        let nonce_raw = [0xABu8; 48];
        let nonce_b64 = BASE64_STANDARD.encode(nonce_raw);

        let client_muxed = MuxedAccount::Ed25519(Uint256(client.0));
        let server_muxed_src = MuxedAccount::Ed25519(Uint256(server.0));

        let ops: VecM<Operation, 100> = vec![
            Operation {
                source_account: Some(client_muxed),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64(&format!("{HOME_DOMAIN} auth")),
                    data_value: Some(bytes_to_data_value(nonce_b64.as_bytes())),
                }),
            },
            Operation {
                source_account: Some(server_muxed_src),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64("web_auth_domain"),
                    data_value: Some(bytes_to_data_value(WEB_AUTH_DOMAIN.as_bytes())),
                }),
            },
        ]
        .try_into()
        .unwrap();

        let tx_v0 = TransactionV0 {
            source_account_ed25519: Uint256(server.0),
            fee: 100,
            seq_num: SequenceNumber(0),
            time_bounds: Some(TimeBounds {
                min_time: TimePoint(1_000_000_000),
                max_time: TimePoint(1_000_000_900),
            }),
            memo: Memo::None,
            operations: ops,
            ext: TransactionV0Ext::V0,
        };
        let envelope = TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx: tx_v0,
            signatures: VecM::default(),
        });
        let xdr = envelope.to_xdr_base64(Limits::none()).unwrap();

        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::XdrDecodeError { ref detail } if detail.contains("TxV0")),
            "expected XdrDecodeError(TxV0), got {err:?}"
        );
    }

    // ── 2. FeeBump envelope rejected ──────────────────────────────────────────

    /// A `FeeBumpTransactionEnvelope` XDR must be rejected with `XdrDecodeError`.
    #[test]
    fn reject_fee_bump_envelope() {
        use stellar_xdr::{
            FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
            FeeBumpTransactionInnerTx, Uint256, VecM,
        };

        // Build a minimal inner V1 tx (the outer FeeBump wraps it).
        let inner_v1_xdr = build_fixture(FixtureParams::default());
        let inner_v1 = if let TransactionEnvelope::Tx(v1) =
            TransactionEnvelope::from_xdr_base64(&inner_v1_xdr, Limits::none()).unwrap()
        {
            v1
        } else {
            panic!("expected V1 envelope from build_fixture")
        };

        let fee_source = MuxedAccount::Ed25519(Uint256(server_pub_key().0));
        let fee_bump_tx = FeeBumpTransaction {
            fee_source,
            fee: 200,
            inner_tx: FeeBumpTransactionInnerTx::Tx(inner_v1),
            ext: FeeBumpTransactionExt::V0,
        };
        let envelope = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: fee_bump_tx,
            signatures: VecM::default(),
        });
        let xdr = envelope.to_xdr_base64(Limits::none()).unwrap();

        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::XdrDecodeError { ref detail } if detail.contains("TxFeeBump")),
            "expected XdrDecodeError(TxFeeBump), got {err:?}"
        );
    }

    // ── 3. First op is not ManageData → InvalidFirstOperation ────────────────

    /// When op[0] is a `BumpSequence` (not ManageData), the validator must
    /// return `InvalidFirstOperation`.
    #[test]
    fn reject_first_op_not_manage_data() {
        use stellar_xdr::{BumpSequenceOp, VecM};

        let server_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(server_pub_key().0));
        let server_muxed2 = MuxedAccount::Ed25519(stellar_xdr::Uint256(server_pub_key().0));

        // Build a fixture using extra_ops but put the bad op first manually.
        // Since build_fixture always builds the first op as ManageData, we
        // construct the full envelope directly.
        let ops: VecM<Operation, 100> = vec![
            // First op: BumpSequence — not ManageData
            Operation {
                source_account: Some(server_muxed.clone()),
                body: OperationBody::BumpSequence(BumpSequenceOp {
                    bump_to: SequenceNumber(0),
                }),
            },
            Operation {
                source_account: Some(server_muxed2),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64("web_auth_domain"),
                    data_value: Some(bytes_to_data_value(WEB_AUTH_DOMAIN.as_bytes())),
                }),
            },
        ]
        .try_into()
        .unwrap();

        let sk = server_signing_key();
        let vk = ed25519_dalek::VerifyingKey::from(&sk);
        let tx = Transaction {
            source_account: server_muxed,
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(1_000_000_000),
                max_time: TimePoint(1_000_000_900),
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
        use ed25519_dalek::Signer as _;
        let sig = sk.sign(&tx_hash);
        let hint: [u8; 4] = vk.to_bytes()[28..32].try_into().unwrap();
        let sigs_vec: VecM<DecoratedSignature, 20> = vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(sig.to_bytes().to_vec().try_into().unwrap()),
        }]
        .try_into()
        .unwrap();

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: sigs_vec,
        });
        let xdr = envelope.to_xdr_base64(Limits::none()).unwrap();

        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::InvalidFirstOperation { .. }),
            "expected InvalidFirstOperation for BumpSequence op[0], got {err:?}"
        );
    }

    // ── 4. First ManageData op with no source account → InvalidFirstOperation ─

    /// The first ManageData op must have a source account (the client account).
    /// Absent source must be rejected with `InvalidFirstOperation`.
    #[test]
    fn reject_first_op_missing_source_account() {
        let nonce_raw = [0xABu8; 48];
        let nonce_b64 = BASE64_STANDARD.encode(nonce_raw);
        let server = server_pub_key();
        let server_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(server.0));
        let server_muxed2 = MuxedAccount::Ed25519(stellar_xdr::Uint256(server.0));

        let ops: VecM<Operation, 100> = vec![
            // source_account = None
            Operation {
                source_account: None,
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64(&format!("{HOME_DOMAIN} auth")),
                    data_value: Some(bytes_to_data_value(nonce_b64.as_bytes())),
                }),
            },
            Operation {
                source_account: Some(server_muxed2),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64("web_auth_domain"),
                    data_value: Some(bytes_to_data_value(WEB_AUTH_DOMAIN.as_bytes())),
                }),
            },
        ]
        .try_into()
        .unwrap();

        let sk = server_signing_key();
        let vk = ed25519_dalek::VerifyingKey::from(&sk);
        let tx = Transaction {
            source_account: server_muxed,
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(1_000_000_000),
                max_time: TimePoint(1_000_000_900),
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
        use ed25519_dalek::Signer as _;
        let sig = sk.sign(&tx_hash);
        let hint: [u8; 4] = vk.to_bytes()[28..32].try_into().unwrap();
        let sigs_vec: VecM<DecoratedSignature, 20> = vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(sig.to_bytes().to_vec().try_into().unwrap()),
        }]
        .try_into()
        .unwrap();

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: sigs_vec,
        });
        let xdr = envelope.to_xdr_base64(Limits::none()).unwrap();

        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::InvalidFirstOperation { ref detail }
                if detail.contains("no source account")),
            "expected InvalidFirstOperation(no source account), got {err:?}"
        );
    }

    // ── 5. Nonce decodes to ≠ 48 bytes → InvalidNonceFormat ──────────────────

    /// A nonce that is 64 bytes and valid base64, but decodes to ≠ 48 bytes,
    /// must be rejected with `InvalidNonceFormat` (not `InvalidNonceLength`).
    ///
    /// Standard-base64 encodes 3 bytes → 4 chars, so 64 chars would normally
    /// decode to 48 bytes. We synthesise a 64-char string that is valid base64
    /// but uses `=` padding to encode fewer bytes: base64 of 46 bytes is 64
    /// chars when the final group carries 2-byte padding (`==` → 2 padding
    /// chars makes 64 total). We construct the nonce bytes as 46 bytes, b64-
    /// encode them (giving 64 chars with `==` at the end), then put that in the
    /// ManageData value.
    #[test]
    fn reject_nonce_decodes_to_wrong_byte_count() {
        // 46 raw bytes → 64-char base64 with "==" padding.
        let raw = [0xCCu8; 46];
        let nonce_b64 = BASE64_STANDARD.encode(raw);
        assert_eq!(nonce_b64.len(), 64, "prerequisite: 46 bytes → 64 b64 chars");
        assert!(
            BASE64_STANDARD.decode(&nonce_b64).unwrap().len() != 48,
            "prerequisite: must decode to ≠48 bytes"
        );

        let xdr = build_fixture(FixtureParams {
            nonce: nonce_b64.into_bytes(),
            ..Default::default()
        });
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::InvalidNonceFormat { ref detail }
                if detail.contains("decoded to")),
            "expected InvalidNonceFormat(decoded to N bytes), got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep10.invalid_nonce_format");
    }

    // ── 6. Subsequent op is not ManageData → UnexpectedOperationSource ────────

    /// A subsequent operation (index ≥ 1) that is NOT ManageData must be
    /// rejected with `UnexpectedOperationSource`.
    #[test]
    fn reject_subsequent_op_not_manage_data() {
        use stellar_xdr::BumpSequenceOp;

        let server_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(server_pub_key().0));

        let bump_op = Operation {
            source_account: Some(server_muxed),
            body: OperationBody::BumpSequence(BumpSequenceOp {
                bump_to: SequenceNumber(0),
            }),
        };
        let xdr = build_fixture(FixtureParams {
            extra_ops: vec![bump_op],
            ..Default::default()
        });
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::UnexpectedOperationSource { ref detail, .. }
                if detail.contains("must be ManageData")),
            "expected UnexpectedOperationSource(must be ManageData), got {err:?}"
        );
    }

    // ── 7. web_auth_domain op with source ≠ server → UnexpectedOperationSource

    /// A `web_auth_domain` ManageData op whose source account is NOT the server
    /// account must be rejected with `UnexpectedOperationSource`.
    #[test]
    fn reject_web_auth_domain_op_wrong_source() {
        let xdr = build_fixture(FixtureParams {
            // web_auth_domain_source set to the client key (≠ server)
            web_auth_domain_source: client_pub_key(),
            ..Default::default()
        });
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::UnexpectedOperationSource { ref detail, .. }
                if detail.contains("web_auth_domain op source must be server account")),
            "expected UnexpectedOperationSource(web_auth_domain source mismatch), got {err:?}"
        );
    }

    // ── 8. web_auth_domain op with no source account → UnexpectedOperationSource

    /// A `web_auth_domain` ManageData op with no source account at all must be
    /// rejected with `UnexpectedOperationSource`.
    #[test]
    fn reject_web_auth_domain_op_no_source() {
        let nonce_raw = [0xABu8; 48];
        let nonce_b64 = BASE64_STANDARD.encode(nonce_raw);
        let server = server_pub_key();
        let client = client_pub_key();
        let server_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(server.0));
        let client_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(client.0));

        let ops: VecM<Operation, 100> = vec![
            Operation {
                source_account: Some(client_muxed),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64(&format!("{HOME_DOMAIN} auth")),
                    data_value: Some(bytes_to_data_value(nonce_b64.as_bytes())),
                }),
            },
            // web_auth_domain op with source_account = None
            Operation {
                source_account: None,
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64("web_auth_domain"),
                    data_value: Some(bytes_to_data_value(WEB_AUTH_DOMAIN.as_bytes())),
                }),
            },
        ]
        .try_into()
        .unwrap();

        let sk = server_signing_key();
        let vk = ed25519_dalek::VerifyingKey::from(&sk);
        let tx = Transaction {
            source_account: server_muxed,
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(1_000_000_000),
                max_time: TimePoint(1_000_000_900),
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
        use ed25519_dalek::Signer as _;
        let sig = sk.sign(&tx_hash);
        let hint: [u8; 4] = vk.to_bytes()[28..32].try_into().unwrap();
        let sigs_vec: VecM<DecoratedSignature, 20> = vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(sig.to_bytes().to_vec().try_into().unwrap()),
        }]
        .try_into()
        .unwrap();
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: sigs_vec,
        });
        let xdr = envelope.to_xdr_base64(Limits::none()).unwrap();

        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::UnexpectedOperationSource { ref detail, .. }
                if detail.contains("web_auth_domain op has no source account")),
            "expected UnexpectedOperationSource(no source on web_auth_domain), got {err:?}"
        );
    }

    // ── 9. web_auth_domain op with absent/non-UTF8 value → WebAuthDomainMismatch

    /// A `web_auth_domain` op whose value field is absent must produce
    /// `WebAuthDomainMismatch`.
    #[test]
    fn reject_web_auth_domain_op_absent_value() {
        let nonce_raw = [0xABu8; 48];
        let nonce_b64 = BASE64_STANDARD.encode(nonce_raw);
        let server = server_pub_key();
        let client = client_pub_key();
        let server_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(server.0));
        let client_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(client.0));
        let server_muxed2 = MuxedAccount::Ed25519(stellar_xdr::Uint256(server.0));

        let ops: VecM<Operation, 100> = vec![
            Operation {
                source_account: Some(client_muxed),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64(&format!("{HOME_DOMAIN} auth")),
                    data_value: Some(bytes_to_data_value(nonce_b64.as_bytes())),
                }),
            },
            // web_auth_domain value = None
            Operation {
                source_account: Some(server_muxed2),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64("web_auth_domain"),
                    data_value: None,
                }),
            },
        ]
        .try_into()
        .unwrap();

        let sk = server_signing_key();
        let vk = ed25519_dalek::VerifyingKey::from(&sk);
        let tx = Transaction {
            source_account: server_muxed,
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(1_000_000_000),
                max_time: TimePoint(1_000_000_900),
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
        use ed25519_dalek::Signer as _;
        let sig = sk.sign(&tx_hash);
        let hint: [u8; 4] = vk.to_bytes()[28..32].try_into().unwrap();
        let sigs_vec: VecM<DecoratedSignature, 20> = vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(sig.to_bytes().to_vec().try_into().unwrap()),
        }]
        .try_into()
        .unwrap();
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: sigs_vec,
        });
        let xdr = envelope.to_xdr_base64(Limits::none()).unwrap();

        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::WebAuthDomainMismatch { .. }),
            "expected WebAuthDomainMismatch for absent web_auth_domain value, got {err:?}"
        );
    }

    // ── 10. client_domain op with no source account → InvalidClientDomainOp ───

    /// A `client_domain` op that has no source account at all must be rejected
    /// with `InvalidClientDomainOp`. (The same-source case is already tested in
    /// `reject_client_domain_op_with_server_source`.)
    #[test]
    fn reject_client_domain_op_no_source() {
        let nonce_raw = [0xABu8; 48];
        let nonce_b64 = BASE64_STANDARD.encode(nonce_raw);
        let server = server_pub_key();
        let client = client_pub_key();
        let server_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(server.0));
        let client_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(client.0));
        let server_muxed2 = MuxedAccount::Ed25519(stellar_xdr::Uint256(server.0));

        let ops: VecM<Operation, 100> = vec![
            Operation {
                source_account: Some(client_muxed),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64(&format!("{HOME_DOMAIN} auth")),
                    data_value: Some(bytes_to_data_value(nonce_b64.as_bytes())),
                }),
            },
            Operation {
                source_account: Some(server_muxed2),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64("web_auth_domain"),
                    data_value: Some(bytes_to_data_value(WEB_AUTH_DOMAIN.as_bytes())),
                }),
            },
            // client_domain with no source account
            Operation {
                source_account: None,
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64("client_domain"),
                    data_value: Some(bytes_to_data_value(b"client.example.com")),
                }),
            },
        ]
        .try_into()
        .unwrap();

        let sk = server_signing_key();
        let vk = ed25519_dalek::VerifyingKey::from(&sk);
        let tx = Transaction {
            source_account: server_muxed,
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(1_000_000_000),
                max_time: TimePoint(1_000_000_900),
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
        use ed25519_dalek::Signer as _;
        let sig = sk.sign(&tx_hash);
        let hint: [u8; 4] = vk.to_bytes()[28..32].try_into().unwrap();
        let sigs_vec: VecM<DecoratedSignature, 20> = vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(sig.to_bytes().to_vec().try_into().unwrap()),
        }]
        .try_into()
        .unwrap();
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: sigs_vec,
        });
        let xdr = envelope.to_xdr_base64(Limits::none()).unwrap();

        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::InvalidClientDomainOp { ref detail }
                if detail.contains("no source account")),
            "expected InvalidClientDomainOp(no source account), got {err:?}"
        );
    }

    // ── 11. client_domain op with absent value → InvalidClientDomainOp ────────

    /// A `client_domain` op whose ManageData value is absent must be rejected
    /// with `InvalidClientDomainOp`.
    #[test]
    fn reject_client_domain_op_absent_value() {
        let nonce_raw = [0xABu8; 48];
        let nonce_b64 = BASE64_STANDARD.encode(nonce_raw);
        let server = server_pub_key();
        let client = client_pub_key();
        let server_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(server.0));
        let client_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(client.0));
        let server_muxed2 = MuxedAccount::Ed25519(stellar_xdr::Uint256(server.0));
        let client_muxed2 = MuxedAccount::Ed25519(stellar_xdr::Uint256(client.0));

        let ops: VecM<Operation, 100> = vec![
            Operation {
                source_account: Some(client_muxed),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64(&format!("{HOME_DOMAIN} auth")),
                    data_value: Some(bytes_to_data_value(nonce_b64.as_bytes())),
                }),
            },
            Operation {
                source_account: Some(server_muxed2),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64("web_auth_domain"),
                    data_value: Some(bytes_to_data_value(WEB_AUTH_DOMAIN.as_bytes())),
                }),
            },
            // client_domain with source ≠ server but value absent
            Operation {
                source_account: Some(client_muxed2),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64("client_domain"),
                    data_value: None,
                }),
            },
        ]
        .try_into()
        .unwrap();

        let sk = server_signing_key();
        let vk = ed25519_dalek::VerifyingKey::from(&sk);
        let tx = Transaction {
            source_account: server_muxed,
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(1_000_000_000),
                max_time: TimePoint(1_000_000_900),
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
        use ed25519_dalek::Signer as _;
        let sig = sk.sign(&tx_hash);
        let hint: [u8; 4] = vk.to_bytes()[28..32].try_into().unwrap();
        let sigs_vec: VecM<DecoratedSignature, 20> = vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(sig.to_bytes().to_vec().try_into().unwrap()),
        }]
        .try_into()
        .unwrap();
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: sigs_vec,
        });
        let xdr = envelope.to_xdr_base64(Limits::none()).unwrap();

        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::InvalidClientDomainOp { ref detail }
                if detail.contains("no value")),
            "expected InvalidClientDomainOp(no value), got {err:?}"
        );
    }

    // ── 12. "other" subsequent op with no source account → UnexpectedOperationSource

    /// A subsequent ManageData op with an unrecognised key (not web_auth_domain
    /// or client_domain) and NO source account must be rejected with
    /// `UnexpectedOperationSource`.
    #[test]
    fn reject_other_subsequent_op_no_source() {
        // Extra op: valid ManageData key but no source_account.
        let extra = Operation {
            source_account: None,
            body: OperationBody::ManageData(ManageDataOp {
                data_name: str_to_string64("some_other_key"),
                data_value: Some(bytes_to_data_value(b"value")),
            }),
        };
        let xdr = build_fixture(FixtureParams {
            extra_ops: vec![extra],
            ..Default::default()
        });
        let err = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep10Error::UnexpectedOperationSource { ref detail, .. }
                if detail.contains("has no source account")),
            "expected UnexpectedOperationSource(has no source account), got {err:?}"
        );
    }

    // ── 13. Muxed M-key client account round-trips correctly ─────────────────

    /// A challenge whose first-op source is an M-key (muxed ed25519) must parse
    /// successfully and expose the M-key strkey as `client_account`. Exercises
    /// the `MuxedEd25519` arm of `muxed_account_to_strkey`.
    #[test]
    fn accept_muxed_m_key_client_account() {
        use stellar_xdr::{MuxedAccountMed25519, Uint256};

        let nonce_raw = [0xABu8; 48];
        let nonce_b64 = BASE64_STANDARD.encode(nonce_raw);
        let server = server_pub_key();
        let client = client_pub_key();
        let server_muxed = MuxedAccount::Ed25519(Uint256(server.0));
        let server_muxed2 = MuxedAccount::Ed25519(Uint256(server.0));

        // M-key: same ed25519 bytes as client_pub_key but with mux id = 42.
        let mux_id: u64 = 42;
        let muxed_client = MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
            id: mux_id,
            ed25519: Uint256(client.0),
        });

        let ops: VecM<Operation, 100> = vec![
            Operation {
                source_account: Some(muxed_client),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64(&format!("{HOME_DOMAIN} auth")),
                    data_value: Some(bytes_to_data_value(nonce_b64.as_bytes())),
                }),
            },
            Operation {
                source_account: Some(server_muxed2),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64("web_auth_domain"),
                    data_value: Some(bytes_to_data_value(WEB_AUTH_DOMAIN.as_bytes())),
                }),
            },
        ]
        .try_into()
        .unwrap();

        let sk = server_signing_key();
        let vk = ed25519_dalek::VerifyingKey::from(&sk);
        let tx = Transaction {
            source_account: server_muxed,
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(1_000_000_000),
                max_time: TimePoint(1_000_000_900),
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
        use ed25519_dalek::Signer as _;
        let sig = sk.sign(&tx_hash);
        let hint: [u8; 4] = vk.to_bytes()[28..32].try_into().unwrap();
        let sigs_vec: VecM<DecoratedSignature, 20> = vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(sig.to_bytes().to_vec().try_into().unwrap()),
        }]
        .try_into()
        .unwrap();
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: sigs_vec,
        });
        let xdr = envelope.to_xdr_base64(Limits::none()).unwrap();

        let challenge = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap();

        // The M-key strkey starts with 'M'.
        assert!(
            challenge.client_account.starts_with('M'),
            "muxed M-key client account must start with 'M', got {}",
            challenge.client_account
        );
        // The M-key round-trips: parsing it back gives the same mux id.
        let parsed_m: stellar_strkey::ed25519::MuxedAccount =
            challenge.client_account.parse().unwrap();
        assert_eq!(parsed_m.id, mux_id);
        assert_eq!(parsed_m.ed25519, client.0);
    }

    // ── 14. PreconditionsV2 with time_bounds present → valid happy path ───────

    /// A challenge using `Preconditions::V2` WITH `time_bounds` set must parse
    /// and validate successfully. Exercises the V2-with-timebounds success
    /// branch in `extract_time_bounds`.
    #[test]
    fn accept_preconditions_v2_with_time_bounds() {
        use stellar_xdr::{Duration, PreconditionsV2, VecM};

        let nonce_raw = [0xABu8; 48];
        let nonce_b64 = BASE64_STANDARD.encode(nonce_raw);
        let server = server_pub_key();
        let client = client_pub_key();
        let server_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(server.0));
        let server_muxed2 = MuxedAccount::Ed25519(stellar_xdr::Uint256(server.0));
        let client_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(client.0));

        let ops: VecM<Operation, 100> = vec![
            Operation {
                source_account: Some(client_muxed),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64(&format!("{HOME_DOMAIN} auth")),
                    data_value: Some(bytes_to_data_value(nonce_b64.as_bytes())),
                }),
            },
            Operation {
                source_account: Some(server_muxed2),
                body: OperationBody::ManageData(ManageDataOp {
                    data_name: str_to_string64("web_auth_domain"),
                    data_value: Some(bytes_to_data_value(WEB_AUTH_DOMAIN.as_bytes())),
                }),
            },
        ]
        .try_into()
        .unwrap();

        let sk = server_signing_key();
        let vk = ed25519_dalek::VerifyingKey::from(&sk);
        let tx = Transaction {
            source_account: server_muxed,
            fee: 100,
            seq_num: SequenceNumber(0),
            // Use PreconditionsV2 with time_bounds present.
            cond: Preconditions::V2(PreconditionsV2 {
                time_bounds: Some(TimeBounds {
                    min_time: TimePoint(1_000_000_000),
                    max_time: TimePoint(1_000_000_900),
                }),
                ledger_bounds: None,
                min_seq_num: None,
                min_seq_age: Duration(0),
                min_seq_ledger_gap: 0,
                extra_signers: VecM::default(),
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
        use ed25519_dalek::Signer as _;
        let sig = sk.sign(&tx_hash);
        let hint: [u8; 4] = vk.to_bytes()[28..32].try_into().unwrap();
        let sigs_vec: VecM<DecoratedSignature, 20> = vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(sig.to_bytes().to_vec().try_into().unwrap()),
        }]
        .try_into()
        .unwrap();
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: sigs_vec,
        });
        let xdr = envelope.to_xdr_base64(Limits::none()).unwrap();

        let challenge = Challenge::parse_and_validate(
            &xdr,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .unwrap();
        assert_eq!(challenge.web_auth_domain, WEB_AUTH_DOMAIN);
        assert_eq!(challenge.time_bounds, (1_000_000_000, 1_000_000_900));
    }

    // ── Depth-bomb regression ─────────────────────────────────────────────────

    /// A `TransactionEnvelope::Tx` with a 600-deep
    /// `SorobanAuthorizedInvocation.sub_invocations` chain is rejected by
    /// `parse_and_validate` with `Sep10Error::XdrDecodeError`.
    ///
    /// The depth (600) exceeds `XDR_DECODE_MAX_DEPTH` (500). The bounded
    /// decoder in `parse_and_validate` returns an error at step 1 (XDR
    /// decode) before the signer is reached or any other field is validated.
    ///
    /// The fixture is encoded with `Limits::none()` (write-side; writing 600
    /// levels fits the test stack). Only the bounded production path decodes
    /// it.
    #[test]
    fn deep_sub_invocations_chain_rejected_at_challenge_parse() {
        use stellar_xdr::{
            ContractId, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Limits, Memo,
            MuxedAccount, Operation, OperationBody, Preconditions, ScAddress, SequenceNumber,
            SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
            SorobanCredentials, Transaction, TransactionExt, TransactionV1Envelope, Uint256, VecM,
            WriteXdr,
        };

        let leaf_fn = SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([0xABu8; 32]))),
            function_name: "f".try_into().expect("short name"),
            args: VecM::default(),
        });

        // Build a 600-deep chain iteratively (innermost first, wrap outward).
        let mut inner = SorobanAuthorizedInvocation {
            function: leaf_fn.clone(),
            sub_invocations: VecM::default(),
        };
        for _ in 0..599 {
            inner = SorobanAuthorizedInvocation {
                function: leaf_fn.clone(),
                sub_invocations: vec![inner].try_into().expect("single-element VecM"),
            };
        }

        let auth_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: inner,
        };

        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([0xABu8; 32]))),
                    function_name: "f".try_into().expect("short name"),
                    args: VecM::default(),
                }),
                auth: vec![auth_entry].try_into().expect("single auth entry"),
            }),
        };

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![op].try_into().expect("single operation"),
            ext: TransactionExt::V0,
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });

        // ENCODE with Limits::none() — write-side; does not invoke the bounded
        // read path. Writing 600 levels of nesting fits the test stack.
        let deep_xdr_b64 = envelope
            .to_xdr_base64(Limits::none())
            .expect("encoding a deep structure must succeed");

        let err = Challenge::parse_and_validate(
            &deep_xdr_b64,
            TESTNET_PASSPHRASE,
            HOME_DOMAIN,
            WEB_AUTH_DOMAIN,
            &server_strkey(),
            now_in_window(),
        )
        .expect_err("600-deep chain must be rejected before stack exhaustion");

        assert!(
            matches!(err, Sep10Error::XdrDecodeError { .. }),
            "expected XdrDecodeError; got {err:?}"
        );
    }
}
