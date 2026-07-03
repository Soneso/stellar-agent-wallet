//! Soroban simulation-audit primitive: client-side pre-submission auth-entry
//! integrity gate.
//!
//! # Purpose
//!
//! This is a **client-side, pre-submission integrity gate** on the Soroban
//! submit path.  Between the moment the wallet simulates+signs a Soroban
//! `InvokeHostFunction` transaction and the moment it puts that envelope on the
//! wire, a malicious or buggy intermediary (WalletConnect host, MCP transport,
//! relayer hand-off) could mutate an auth entry.  This gate catches that
//! client-side, before spending fees, by:
//!
//! 1. At sign time, capturing the canonical hash of each
//!    [`SorobanAuthorizationEntry`] the wallet produced — the "expected set".
//! 2. Immediately before submission, re-extracting the auth entries from the
//!    exact envelope about to be submitted and re-hashing them — the "actual set".
//! 3. Requiring **exact ordered equality**; any divergence aborts with
//!    `WalletError::Submission(SubmissionError::AuthMismatch)` BEFORE
//!    `sendTransaction`.
//!
//! # Relationship to simulation re-check
//!
//! The simulation re-check (`resimulate_with_signed_auth`) catches drift in
//! simulation before signing (footprint/fee correctness); this gate catches
//! tampering between sign and submit.  Together they bracket the sign step.
//!
//! # Byte-identity invariant
//!
//! On the wallet's own happy path the auth-entry subtree is **byte-identical**
//! from end-of-signing through submission: no re-serialisation, re-ordering, or
//! mutation occurs.  The tripwire in `submit_signed_invoke` is an invariant
//! assertion — it fires only if a future refactor breaks this guarantee.
//! The primary security value of this gate is on an **external-submit**
//! boundary (a path where the wallet accepts a pre-signed blob from the outside
//! and submits it).
//!
//! # Byte-layout (stellar-xdr)
//!
//! `SorobanAuthorizationEntry` has two fields: `credentials: SorobanCredentials`
//! and `root_invocation: SorobanAuthorizedInvocation`.  This module hashes the
//! complete canonical XDR of each entry: `sha256(entry.to_xdr(Limits::none()))`.
//! `InvokeHostFunctionOp` carries `host_function: HostFunction` and
//! `auth: VecM<SorobanAuthorizationEntry>`.

use sha2::{Digest as _, Sha256};
use stellar_agent_core::error::{AuthMismatchReason, ProtocolError, SubmissionError, WalletError};
use stellar_xdr::{
    Limits, OperationBody, ReadXdr, SorobanAuthorizationEntry, TransactionEnvelope, WriteXdr,
};

/// The set of auth-entry hashes captured from a signed Soroban
/// [`InvokeHostFunction`][stellar_xdr::OperationBody::InvokeHostFunction]
/// at sign time — the "expected set" for the equality check before submission.
///
/// Opaque: the inner digests are private.  Equality is defined over the
/// **ordered** vector of per-entry `sha256(entry XDR)` digests.
///
/// # Ordering
///
/// Equality is ordered, not a sorted multiset.  For a single
/// `InvokeHostFunctionOp` the `auth` Vec is built in a fixed order by the
/// wallet and the network submits/verifies the envelope byte-exact — there is
/// no legitimate happy-path reordering.  An ordered compare is both simpler
/// and strictly stronger: a reorder is itself a tampering signal worth
/// catching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthEntryFingerprint {
    /// Ordered `sha256(entry.to_xdr(Limits::none()))` for each auth entry.
    ///
    /// Empty when the `InvokeHostFunction` carries no auth entries (host
    /// function that needs no auth, e.g. a pure read).
    ///
    /// Private: callers compare `AuthEntryFingerprint` values as a whole via
    /// `PartialEq`; the raw digests are not part of the public API.
    digests: Vec<[u8; 32]>,
}

impl AuthEntryFingerprint {
    /// Compute the fingerprint directly from a slice of already-built
    /// [`SorobanAuthorizationEntry`] values.
    ///
    /// This is the **capture path** used at end-of-signing before an envelope
    /// string exists.  The caller guarantees that `entries` is the auth slice
    /// of a single `InvokeHostFunctionOp`.
    ///
    /// # Errors
    ///
    /// Returns `WalletError::Protocol(ProtocolError::XdrCodecFailed)` if any
    /// entry fails XDR serialisation (should not occur for well-formed entries
    /// produced by the wallet's own signing path).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use stellar_agent_network::simulation_audit::AuthEntryFingerprint;
    /// let fp = AuthEntryFingerprint::from_entries(&auth_entries)?;
    /// ```
    pub fn from_entries(
        entries: &[SorobanAuthorizationEntry],
    ) -> Result<AuthEntryFingerprint, WalletError> {
        let digests = entries
            .iter()
            .map(digest_entry)
            .collect::<Result<Vec<[u8; 32]>, WalletError>>()?;
        Ok(AuthEntryFingerprint { digests })
    }

    /// Returns the number of auth entries in this fingerprint.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.digests.len()
    }
}

/// Compute the fingerprint of every [`SorobanAuthorizationEntry`] in a signed
/// single-op Soroban envelope.
///
/// Decodes `envelope_xdr` (base64 `TransactionEnvelope`), requires exactly
/// one operation whose body is `OperationBody::InvokeHostFunction`, and hashes
/// each auth entry via `sha256(entry.to_xdr(Limits::none()))` in order.
///
/// Signer-agnostic: works on entries with `SorobanCredentials::SourceAccount`
/// as well as `SorobanCredentials::Address` credentials.
///
/// # Errors
///
/// - `WalletError::Submission(SubmissionError::AuthMismatch { reason: NotSingleInvokeHostFunction })`
///   — the envelope is not a single-operation `InvokeHostFunction` (multi-op,
///   `TxFeeBump`, `TxV0`, or sole operation is not `InvokeHostFunction`).
/// - `WalletError::Protocol(ProtocolError::XdrCodecFailed)` — XDR decode
///   or encode failure.
///
/// # Examples
///
/// ```rust,ignore
/// use stellar_agent_network::simulation_audit::fingerprint_soroban_auth_entries;
/// let fp = fingerprint_soroban_auth_entries(&envelope_xdr)?;
/// ```
pub fn fingerprint_soroban_auth_entries(
    envelope_xdr: &str,
) -> Result<AuthEntryFingerprint, WalletError> {
    let entries = extract_auth_entries(envelope_xdr)?;
    let digests = entries
        .iter()
        .map(digest_entry)
        .collect::<Result<Vec<[u8; 32]>, WalletError>>()?;
    Ok(AuthEntryFingerprint { digests })
}

/// Verify that the envelope about to be submitted carries **exactly** the auth
/// entries captured in `expected` at sign time.
///
/// Fingerprints the `envelope_to_submit_xdr` and compares it ordered-equal to
/// `expected`.  On any divergence returns
/// [`WalletError::Submission(SubmissionError::AuthMismatch { reason })`] with
/// the most specific [`AuthMismatchReason`] available:
///
/// | Condition | `reason` |
/// |-----------|----------|
/// | Envelope is not a single `InvokeHostFunction` | `NotSingleInvokeHostFunction` |
/// | Entry-count mismatch (before ordered compare) | `EntryCountMismatch` |
/// | All digests equal — pass | `Ok(())` |
/// | At least one digest differs | `EntryMutated` |
///
/// `EntryCountMismatch` covers both "entry was added" and "entry was removed"
/// cases.  The ordered-compare model collapses both to a single count-mismatch
/// discriminant rather than requiring a diff algorithm.
///
/// # Errors
///
/// - `WalletError::Submission(SubmissionError::AuthMismatch { .. })` — any
///   fingerprint divergence.
/// - `WalletError::Protocol(ProtocolError::XdrCodecFailed)` — XDR decode or
///   encode failure.
///
/// # Redaction
///
/// The error carries ONLY the [`AuthMismatchReason`] label — no entry bytes,
/// no signature bytes, no strkeys.
///
/// # Examples
///
/// ```rust,ignore
/// use stellar_agent_network::simulation_audit::{
///     AuthEntryFingerprint, verify_auth_entries_unchanged,
/// };
/// // captured at sign time
/// let expected = AuthEntryFingerprint::from_entries(&signed_entries)?;
/// // verify before sendTransaction
/// verify_auth_entries_unchanged(&expected, &final_xdr)?;
/// ```
pub fn verify_auth_entries_unchanged(
    expected: &AuthEntryFingerprint,
    envelope_to_submit_xdr: &str,
) -> Result<(), WalletError> {
    // fingerprint_soroban_auth_entries returns NotSingleInvokeHostFunction for
    // non-single-op envelopes.
    let actual = fingerprint_soroban_auth_entries(envelope_to_submit_xdr)?;

    if actual.digests.len() != expected.digests.len() {
        return Err(auth_mismatch(AuthMismatchReason::EntryCountMismatch));
    }

    if actual.digests != expected.digests {
        return Err(auth_mismatch(AuthMismatchReason::EntryMutated));
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the `SorobanAuthorizationEntry` slice from a base64
/// `TransactionEnvelope` that must be a single-op `InvokeHostFunction`.
///
/// Returns `AuthMismatchReason::NotSingleInvokeHostFunction` on any structural
/// violation (multi-op, non-InvokeHostFunction, TxFeeBump, TxV0).
fn extract_auth_entries(envelope_xdr: &str) -> Result<Vec<SorobanAuthorizationEntry>, WalletError> {
    // The envelope is caller-supplied and untrusted; bounded limits prevent a
    // deeply nested auth-invocation tree from exhausting the stack.
    let envelope = TransactionEnvelope::from_xdr_base64(
        envelope_xdr,
        stellar_agent_xdr_limits::untrusted_decode_limits(envelope_xdr.len()),
    )
    .map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("simulation_audit: TransactionEnvelope decode failed: {e}"),
        })
    })?;

    let ops = match &envelope {
        TransactionEnvelope::Tx(v1) => &v1.tx.operations,
        // TxFeeBump and TxV0 are not single-op InvokeHostFunction shapes.
        _ => {
            return Err(auth_mismatch(
                AuthMismatchReason::NotSingleInvokeHostFunction,
            ));
        }
    };

    // CAP-46 restricts Soroban tx to exactly one InvokeHostFunction operation;
    // enforce it as a precondition so the audit surface is predictable.
    if ops.len() != 1 {
        return Err(auth_mismatch(
            AuthMismatchReason::NotSingleInvokeHostFunction,
        ));
    }

    match &ops[0].body {
        OperationBody::InvokeHostFunction(op) => Ok(op.auth.to_vec()),
        _ => Err(auth_mismatch(
            AuthMismatchReason::NotSingleInvokeHostFunction,
        )),
    }
}

/// Compute `sha256(entry.to_xdr(Limits::none()))` for a single
/// [`SorobanAuthorizationEntry`].
///
/// `SorobanAuthorizationEntry` (stellar-xdr) has two fields:
/// `credentials: SorobanCredentials` and `root_invocation:
/// SorobanAuthorizedInvocation`.  `WriteXdr::write_xdr` serialises both in
/// order; `to_xdr(Limits::none())` returns the complete canonical XDR bytes.
fn digest_entry(entry: &SorobanAuthorizationEntry) -> Result<[u8; 32], WalletError> {
    let xdr_bytes = entry.to_xdr(Limits::none()).map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("simulation_audit: SorobanAuthorizationEntry XDR encode failed: {e}"),
        })
    })?;
    Ok(Sha256::digest(&xdr_bytes).into())
}

/// Construct a `WalletError::Submission(SubmissionError::AuthMismatch)` with
/// the given `reason`.
fn auth_mismatch(reason: AuthMismatchReason) -> WalletError {
    WalletError::Submission(SubmissionError::AuthMismatch { reason })
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
        reason = "test-only"
    )]

    use stellar_xdr::{
        AccountId, ContractId, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp,
        Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions, PublicKey, ScAddress,
        ScSymbol, ScVal, SequenceNumber, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
        SorobanAuthorizedInvocation, SorobanCredentials, Transaction, TransactionEnvelope,
        TransactionEnvelope::Tx, TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
    };

    use super::*;

    // ── Test fixture helpers ──────────────────────────────────────────────────

    /// Build a deterministic `SorobanAuthorizationEntry` with
    /// `SorobanCredentials::SourceAccount` (signer-agnostic; no real key needed).
    ///
    /// `seed` is used to vary the contract address and function name so that
    /// distinct entries are distinguishable.
    fn make_source_account_entry(seed: u8) -> SorobanAuthorizationEntry {
        // Build a minimal SorobanAuthorizedInvocation.
        let fn_name: ScSymbol = format!("fn_{seed}").as_str().try_into().unwrap();
        let contract_addr: ScAddress = ScAddress::Contract(ContractId(Hash([seed; 32])));
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: contract_addr,
                function_name: fn_name,
                args: VecM::default(),
            }),
            sub_invocations: VecM::default(),
        };
        // SourceAccount credentials (signer-agnostic path).
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: invocation,
        }
    }

    /// Build a single-op InvokeHostFunction `TransactionEnvelope` from a Vec
    /// of auth entries.  Uses a fixed source account and sequence number — the
    /// outer envelope structure is irrelevant for auth-entry fingerprinting.
    fn envelope_with_entries(entries: Vec<SorobanAuthorizationEntry>) -> TransactionEnvelope {
        let auth_vecm: VecM<SorobanAuthorizationEntry> = entries.try_into().unwrap();
        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
                    function_name: "test_fn".try_into().unwrap(),
                    args: VecM::default(),
                }),
                auth: auth_vecm,
            }),
        };
        let ops: VecM<Operation, 100> = vec![op].try_into().unwrap();
        let source_acct = MuxedAccount::Ed25519(Uint256([1u8; 32]));
        let tx = Transaction {
            source_account: source_acct,
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: ops,
            ext: TransactionExt::V0,
        };
        Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        })
    }

    /// Encode an envelope to base64.
    fn encode_envelope(env: &TransactionEnvelope) -> String {
        env.to_xdr_base64(Limits::none()).unwrap()
    }

    // ── Tamper corpus ─────────────────────────────────────────────────────────

    /// Untampered envelope passes verification.
    #[test]
    fn untampered_passes() {
        let entries = vec![make_source_account_entry(0), make_source_account_entry(1)];
        let expected = AuthEntryFingerprint::from_entries(&entries).unwrap();
        let env = envelope_with_entries(entries);
        let xdr = encode_envelope(&env);
        assert!(verify_auth_entries_unchanged(&expected, &xdr).is_ok());
    }

    /// Mutating an entry's root_invocation function name is detected as EntryMutated.
    #[test]
    fn mutate_root_invocation_detected() {
        let entries = vec![make_source_account_entry(0), make_source_account_entry(1)];
        let expected = AuthEntryFingerprint::from_entries(&entries).unwrap();

        // Mutate entry[0]: change the function name.
        let mut mutated = entries.clone();
        let new_fn: ScSymbol = "mutated_fn".try_into().unwrap();
        mutated[0] = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
                    function_name: new_fn,
                    args: VecM::default(),
                }),
                sub_invocations: VecM::default(),
            },
        };

        let env = envelope_with_entries(mutated);
        let xdr = encode_envelope(&env);
        let result = verify_auth_entries_unchanged(&expected, &xdr);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                WalletError::Submission(SubmissionError::AuthMismatch {
                    reason: AuthMismatchReason::EntryMutated
                })
            ),
            "expected EntryMutated, got {err:?}"
        );
    }

    /// Changing credential type (SourceAccount to Address) is detected as EntryMutated.
    #[test]
    fn mutate_credential_type_detected() {
        let entries = vec![make_source_account_entry(0), make_source_account_entry(1)];
        let expected = AuthEntryFingerprint::from_entries(&entries).unwrap();

        // Mutate entry[0]: swap SourceAccount for Address credentials.
        let mut mutated = entries.clone();
        let addr_pubkey = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([42u8; 32])));
        let addr_credentials = stellar_xdr::SorobanAddressCredentials {
            address: ScAddress::Account(addr_pubkey),
            nonce: 12345,
            signature_expiration_ledger: 999_999,
            signature: ScVal::Void,
        };
        mutated[0] = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(addr_credentials),
            root_invocation: mutated[0].root_invocation.clone(),
        };

        let env = envelope_with_entries(mutated);
        let xdr = encode_envelope(&env);
        let result = verify_auth_entries_unchanged(&expected, &xdr);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                WalletError::Submission(SubmissionError::AuthMismatch {
                    reason: AuthMismatchReason::EntryMutated
                })
            ),
            "changing credential type must be detected as EntryMutated"
        );
    }

    /// Mutating signature bytes in Address credentials is detected as EntryMutated.
    #[test]
    fn mutate_signature_bytes_detected() {
        let addr_pubkey = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7u8; 32])));
        let addr_credentials = stellar_xdr::SorobanAddressCredentials {
            address: ScAddress::Account(addr_pubkey.clone()),
            nonce: 100,
            signature_expiration_ledger: 500_000,
            signature: ScVal::Bytes(vec![0xAA; 64].try_into().unwrap()),
        };
        let entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(addr_credentials),
            root_invocation: make_source_account_entry(2).root_invocation,
        };
        let entries = vec![entry];
        let expected = AuthEntryFingerprint::from_entries(&entries).unwrap();

        // Mutate: change the signature bytes.
        let mutated_creds = stellar_xdr::SorobanAddressCredentials {
            address: ScAddress::Account(addr_pubkey),
            nonce: 100,
            signature_expiration_ledger: 500_000,
            signature: ScVal::Bytes(vec![0xBB; 64].try_into().unwrap()),
        };
        let mutated_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(mutated_creds),
            root_invocation: entries[0].root_invocation.clone(),
        };

        let env = envelope_with_entries(vec![mutated_entry]);
        let xdr = encode_envelope(&env);
        let result = verify_auth_entries_unchanged(&expected, &xdr);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                WalletError::Submission(SubmissionError::AuthMismatch {
                    reason: AuthMismatchReason::EntryMutated
                })
            ),
            "mutated signature bytes must be caught as EntryMutated"
        );
    }

    /// Swapping the credential address is detected as EntryMutated.
    #[test]
    fn swap_credential_address_detected() {
        let addr_pubkey_a = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1u8; 32])));
        let addr_pubkey_b = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32])));
        let creds_a = stellar_xdr::SorobanAddressCredentials {
            address: ScAddress::Account(addr_pubkey_a),
            nonce: 0,
            signature_expiration_ledger: 1_000_000,
            signature: ScVal::Void,
        };
        let entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(creds_a),
            root_invocation: make_source_account_entry(0).root_invocation,
        };
        let expected = AuthEntryFingerprint::from_entries(&[entry]).unwrap();

        // Swap the address to addr_pubkey_b.
        let creds_b = stellar_xdr::SorobanAddressCredentials {
            address: ScAddress::Account(addr_pubkey_b),
            nonce: 0,
            signature_expiration_ledger: 1_000_000,
            signature: ScVal::Void,
        };
        let swapped_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(creds_b),
            root_invocation: make_source_account_entry(0).root_invocation,
        };

        let env = envelope_with_entries(vec![swapped_entry]);
        let xdr = encode_envelope(&env);
        let result = verify_auth_entries_unchanged(&expected, &xdr);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                WalletError::Submission(SubmissionError::AuthMismatch {
                    reason: AuthMismatchReason::EntryMutated
                })
            ),
            "swapped credential address must be caught as EntryMutated"
        );
    }

    /// Adding an auth entry is detected as EntryCountMismatch.
    #[test]
    fn add_entry_detected() {
        let entries = vec![make_source_account_entry(0), make_source_account_entry(1)];
        let expected = AuthEntryFingerprint::from_entries(&entries).unwrap();

        // Add a third entry.
        let mut more = entries.clone();
        more.push(make_source_account_entry(2));
        let env = envelope_with_entries(more);
        let xdr = encode_envelope(&env);
        let result = verify_auth_entries_unchanged(&expected, &xdr);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                WalletError::Submission(SubmissionError::AuthMismatch {
                    reason: AuthMismatchReason::EntryCountMismatch
                })
            ),
            "adding an entry must be caught as EntryCountMismatch"
        );
    }

    /// Removing an auth entry is detected as EntryCountMismatch.
    #[test]
    fn remove_entry_detected() {
        let entries = vec![make_source_account_entry(0), make_source_account_entry(1)];
        let expected = AuthEntryFingerprint::from_entries(&entries).unwrap();

        // Remove the second entry.
        let fewer = vec![entries[0].clone()];
        let env = envelope_with_entries(fewer);
        let xdr = encode_envelope(&env);
        let result = verify_auth_entries_unchanged(&expected, &xdr);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                WalletError::Submission(SubmissionError::AuthMismatch {
                    reason: AuthMismatchReason::EntryCountMismatch
                })
            ),
            "removing an entry must be caught as EntryCountMismatch"
        );
    }

    /// Reordering auth entries is detected as EntryMutated (ordered compare).
    #[test]
    fn reorder_entries_detected() {
        let entries = vec![make_source_account_entry(0), make_source_account_entry(1)];
        let expected = AuthEntryFingerprint::from_entries(&entries).unwrap();

        // Reverse the order.
        let reordered = vec![entries[1].clone(), entries[0].clone()];
        let env = envelope_with_entries(reordered);
        let xdr = encode_envelope(&env);
        let result = verify_auth_entries_unchanged(&expected, &xdr);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                WalletError::Submission(SubmissionError::AuthMismatch {
                    reason: AuthMismatchReason::EntryMutated
                })
            ),
            "reordering entries must be caught as EntryMutated (ordered compare)"
        );
    }

    /// Multi-op envelope is rejected as NotSingleInvokeHostFunction.
    #[test]
    fn multi_op_envelope_rejected() {
        let entry = make_source_account_entry(0);
        let auth_vecm: VecM<SorobanAuthorizationEntry> = vec![entry].try_into().unwrap();

        let ihf_op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
                    function_name: "fn".try_into().unwrap(),
                    args: VecM::default(),
                }),
                auth: auth_vecm,
            }),
        };
        // Second op: a no-op CreateAccount shape (not IHF).
        let create_op = Operation {
            source_account: None,
            body: OperationBody::CreateAccount(stellar_xdr::CreateAccountOp {
                destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32]))),
                starting_balance: 10_000_000,
            }),
        };

        let ops: VecM<Operation, 100> = vec![ihf_op, create_op].try_into().unwrap();
        let source_acct = MuxedAccount::Ed25519(Uint256([1u8; 32]));
        let tx = Transaction {
            source_account: source_acct,
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: ops,
            ext: TransactionExt::V0,
        };
        let env = Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });
        let xdr = encode_envelope(&env);

        let result = fingerprint_soroban_auth_entries(&xdr);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                WalletError::Submission(SubmissionError::AuthMismatch {
                    reason: AuthMismatchReason::NotSingleInvokeHostFunction
                })
            ),
            "multi-op envelope must be rejected as NotSingleInvokeHostFunction"
        );
    }

    /// Single-op envelope whose operation is not InvokeHostFunction is rejected
    /// as NotSingleInvokeHostFunction.
    #[test]
    fn non_invoke_host_function_rejected() {
        let create_op = Operation {
            source_account: None,
            body: OperationBody::CreateAccount(stellar_xdr::CreateAccountOp {
                destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32]))),
                starting_balance: 10_000_000,
            }),
        };
        let ops: VecM<Operation, 100> = vec![create_op].try_into().unwrap();
        let source_acct = MuxedAccount::Ed25519(Uint256([1u8; 32]));
        let tx = Transaction {
            source_account: source_acct,
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: ops,
            ext: TransactionExt::V0,
        };
        let env = Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });
        let xdr = encode_envelope(&env);

        let result = fingerprint_soroban_auth_entries(&xdr);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                WalletError::Submission(SubmissionError::AuthMismatch {
                    reason: AuthMismatchReason::NotSingleInvokeHostFunction
                })
            ),
            "non-IHF operation must be rejected as NotSingleInvokeHostFunction"
        );
    }

    /// Empty-auth InvokeHostFunction produces an empty fingerprint that passes;
    /// adding an entry to the submit envelope is caught as EntryCountMismatch.
    #[test]
    fn empty_auth_fingerprint_and_add_caught() {
        let empty_entries: Vec<SorobanAuthorizationEntry> = vec![];
        let expected = AuthEntryFingerprint::from_entries(&empty_entries).unwrap();
        assert_eq!(expected.entry_count(), 0);

        // Verify against an empty-auth envelope → passes.
        let empty_env = envelope_with_entries(empty_entries);
        let empty_xdr = encode_envelope(&empty_env);
        assert!(verify_auth_entries_unchanged(&expected, &empty_xdr).is_ok());

        // Adding an entry to the submit envelope is caught.
        let tampered_env = envelope_with_entries(vec![make_source_account_entry(0)]);
        let tampered_xdr = encode_envelope(&tampered_env);
        let result = verify_auth_entries_unchanged(&expected, &tampered_xdr);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                WalletError::Submission(SubmissionError::AuthMismatch {
                    reason: AuthMismatchReason::EntryCountMismatch
                })
            ),
            "adding an entry to empty-auth envelope must be caught as EntryCountMismatch"
        );
    }

    /// Verify the `AuthMismatch` error carries no secret bytes (the reason is
    /// a fixed public label string only).
    #[test]
    fn auth_mismatch_error_carries_no_secrets() {
        let entries = vec![make_source_account_entry(0)];
        let expected = AuthEntryFingerprint::from_entries(&entries).unwrap();

        // Mutate to produce a mismatch.
        let tampered = vec![make_source_account_entry(99)];
        let env = envelope_with_entries(tampered);
        let xdr = encode_envelope(&env);

        let err = verify_auth_entries_unchanged(&expected, &xdr).unwrap_err();
        let display = format!("{err}");

        // The display must not contain any raw XDR bytes or the word "bytes".
        assert!(
            !display.contains("AAAA"),
            "error display must not leak XDR bytes: {display}"
        );
        assert!(
            !display.contains("bytes"),
            "error display must not contain 'bytes': {display}"
        );
        // The display must contain the reason label.
        assert!(
            display.contains("entry_mutated"),
            "error display must include the reason label: {display}"
        );
    }

    /// Confirm that `AuthEntryFingerprint` is `Send + Sync` (no global state;
    /// no `#[serial]` needed).
    #[test]
    fn fingerprint_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AuthEntryFingerprint>();
    }
}
