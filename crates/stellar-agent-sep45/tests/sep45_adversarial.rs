//! SEP-45 adversarial fixtures.
//!
//! Tests (a) nonce-mismatch rejection, (b) entry-tampering detection, and (c)
//! ephemeral-key-per-request enforcement.
//!
//! # Feature gate
//!
//! Tests (a) and (b) are pure unit tests (no network I/O) and run under the
//! default feature set (no extra flag needed):
//! ```sh
//! cargo test -p stellar-agent-sep45 --test sep45_adversarial
//! ```
//!
//! Test (c) requires `--features test-helpers` because it uses the
//! `generate_ephemeral_seed` helper function:
//! ```sh
//! cargo test -p stellar-agent-sep45 --features test-helpers \
//!     --test sep45_adversarial
//! ```
//!
//! # Serial execution
//!
//! Tests run under `#[serial]` because they share process-global keyring and
//! HTTP state; concurrent execution would race.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in adversarial tests"
)]

// ─────────────────────────────────────────────────────────────────────────────
// Shared fixture helpers (always compiled for tests a + b)
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a minimal two-entry `SorobanAuthorizationEntries` XDR base64 string
/// in the standard challenge format expected by `parse_and_validate`.
///
/// The server entry receives a real ed25519 signature computed over the
/// `HashIdPreimageSorobanAuthorization` preimage. The client entry has a `Void`
/// signature (not yet signed by the client).
///
/// `nonce_override_for_client` — when `Some`, uses a DIFFERENT nonce string for
/// the client entry's args map, triggering `Sep45Error::NonceMismatch` in step 9
/// of `parse_and_validate`. When `None`, all entries share the same nonce.
///
/// `web_auth_domain_override` — when `Some`, replaces the `web_auth_domain` arg
/// in the client entry's args map with the given string, triggering
/// `Sep45Error::WebAuthDomainMismatch` if the entries are re-validated with the
/// standard expected domain.
#[allow(clippy::too_many_arguments)]
fn build_adversarial_entries_xdr(
    web_auth_contract: &str,
    home_domain: &str,
    web_auth_domain: &str,
    server_signing_key_seed: &[u8; 32],
    client_account: &str,
    nonce_str: &str,
    network_passphrase: &str,
    nonce_override_for_client: Option<&str>,
    web_auth_domain_override_for_client: Option<&str>,
) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use stellar_xdr::{
        AccountId, ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
        InvokeContractArgs, Limits, PublicKey as XdrPublicKey, ScAddress, ScBytes, ScMap,
        ScMapEntry, ScString, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
        SorobanAuthorizationEntries, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
        SorobanAuthorizedInvocation, SorobanCredentials, Uint256, VecM, WriteXdr,
    };

    let contract_bytes = stellar_strkey::Contract::from_string(web_auth_contract)
        .unwrap()
        .0;
    let contract_address = ScAddress::Contract(ContractId(Hash(contract_bytes)));

    let server_key = SigningKey::from_bytes(server_signing_key_seed);
    let server_pubkey_bytes = server_key.verifying_key().to_bytes();
    let server_g_str = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(server_pubkey_bytes)
    );

    // Build the args map for the SERVER entry (always uses the canonical nonce
    // and web_auth_domain — the server entry is the reference for step 9).
    let server_map_entries = vec![
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
            val: ScVal::String(ScString(client_account.try_into().unwrap())),
        },
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
            val: ScVal::String(ScString(home_domain.try_into().unwrap())),
        },
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
            val: ScVal::String(ScString(nonce_str.try_into().unwrap())),
        },
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
            val: ScVal::String(ScString(web_auth_domain.try_into().unwrap())),
        },
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
            val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
        },
    ];

    // Build the args map for the CLIENT entry — apply adversarial overrides.
    let client_nonce = nonce_override_for_client.unwrap_or(nonce_str);
    let client_web_auth_domain = web_auth_domain_override_for_client.unwrap_or(web_auth_domain);
    let client_map_entries = vec![
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
            val: ScVal::String(ScString(client_account.try_into().unwrap())),
        },
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
            val: ScVal::String(ScString(home_domain.try_into().unwrap())),
        },
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
            val: ScVal::String(ScString(client_nonce.try_into().unwrap())),
        },
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
            val: ScVal::String(ScString(client_web_auth_domain.try_into().unwrap())),
        },
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
            val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
        },
    ];

    // Build server invocation (canonical args — used for signature preimage).
    let server_args_val = ScVal::Map(Some(ScMap(server_map_entries.try_into().unwrap())));
    let server_fn_args = InvokeContractArgs {
        contract_address: contract_address.clone(),
        function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
        args: vec![server_args_val].try_into().unwrap(),
    };
    let server_invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(server_fn_args),
        sub_invocations: VecM::default(),
    };

    // Build client invocation (possibly-tampered args).
    let client_args_val = ScVal::Map(Some(ScMap(client_map_entries.try_into().unwrap())));
    let client_fn_args = InvokeContractArgs {
        contract_address: contract_address.clone(),
        function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
        args: vec![client_args_val].try_into().unwrap(),
    };
    let client_invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(client_fn_args),
        sub_invocations: VecM::default(),
    };

    // Compute the server's auth preimage over the SERVER invocation (canonical).
    let nonce_i64: i64 = 12_345_678;
    let expiry: u32 = 9_999_999;
    let network_id_hash = {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(network_passphrase.as_bytes());
        Hash(h.finalize().into())
    };

    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: network_id_hash,
        nonce: nonce_i64,
        signature_expiration_ledger: expiry,
        invocation: server_invocation.clone(),
    });
    let mut preimage_bytes = Vec::new();
    preimage
        .write_xdr(&mut stellar_xdr::Limited::new(
            &mut preimage_bytes,
            Limits::none(),
        ))
        .unwrap();
    let payload: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(&preimage_bytes);
        h.finalize().into()
    };
    let sig_bytes = server_key.sign(&payload).to_bytes();

    let sig_map_entry = ScVal::Map(Some(ScMap(
        vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("public_key".try_into().unwrap())),
                val: ScVal::Bytes(ScBytes(server_pubkey_bytes.to_vec().try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("signature".try_into().unwrap())),
                val: ScVal::Bytes(ScBytes(sig_bytes.to_vec().try_into().unwrap())),
            },
        ]
        .try_into()
        .unwrap(),
    )));
    let server_sig_val = ScVal::Vec(Some(ScVec(vec![sig_map_entry].try_into().unwrap())));

    let server_address = ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
        Uint256(server_pubkey_bytes),
    )));

    let server_entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: server_address,
            nonce: nonce_i64,
            signature_expiration_ledger: expiry,
            signature: server_sig_val,
        }),
        root_invocation: server_invocation,
    };

    // Build client entry — unsigned (Void signature), using the client invocation.
    let client_contract_bytes = stellar_strkey::Contract::from_string(client_account)
        .unwrap()
        .0;
    let client_address = ScAddress::Contract(ContractId(Hash(client_contract_bytes)));
    let client_entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: client_address,
            nonce: 87_654_321i64,
            signature_expiration_ledger: 0,
            signature: ScVal::Void,
        }),
        root_invocation: client_invocation,
    };

    // Encode as `SorobanAuthorizationEntries` XDR.
    let entries_xdr =
        SorobanAuthorizationEntries(vec![server_entry, client_entry].try_into().unwrap());
    let mut out = Vec::new();
    entries_xdr
        .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
        .unwrap();
    BASE64_STANDARD.encode(&out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants shared across all test modules
// ─────────────────────────────────────────────────────────────────────────────

const WEB_AUTH_CONTRACT: &str = "CALI6JC3MSNDGFRP7Z2OKUEPREHOJRRXKMJEWQDEFZPFGXALA45RAUTH";
const CLIENT_ACCOUNT: &str = "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ";
const HOME_DOMAIN: &str = "example.com";
const WEB_AUTH_DOMAIN: &str = "auth.example.com";
const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const SERVER_SEED: [u8; 32] = [1u8; 32];
const CANONICAL_NONCE: &str = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6";

/// Returns the G-strkey for a server seed.
fn server_signing_key_str(seed: &[u8; 32]) -> String {
    use ed25519_dalek::SigningKey;
    let sk = SigningKey::from_bytes(seed);
    format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(sk.verifying_key().to_bytes())
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial fixture (a): nonce-reuse rejection
// ─────────────────────────────────────────────────────────────────────────────

/// Adversarial fixture (a) — nonce-mismatch across entries.
///
/// SEP-45 `sep-0045.md` step 9 of challenge validation requires that all
/// entries share the SAME nonce value. This test constructs a challenge where
/// the client entry carries a DIFFERENT nonce string than the server entry.
///
/// `parse_and_validate` is expected to return `Sep45Error::NonceMismatch`
/// at step 9 (after extracting the canonical nonce from the server/first entry
/// and checking all subsequent entries for consistency).
///
/// # Adversarial model
///
/// A malicious server could generate entries with inconsistent nonces to
/// force the client to sign a different context than the one claimed. The
/// client MUST detect this and reject the challenge before signing.
#[test]
#[serial_test::serial]
fn nonce_mismatch_across_entries_is_rejected() {
    let server_key = server_signing_key_str(&SERVER_SEED);

    // Build a challenge where the client entry has a DIFFERENT nonce.
    // The server entry nonce is CANONICAL_NONCE; the client entry nonce is TAMPERED.
    let tampered_nonce = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";
    let xdr_b64 = build_adversarial_entries_xdr(
        WEB_AUTH_CONTRACT,
        HOME_DOMAIN,
        WEB_AUTH_DOMAIN,
        &SERVER_SEED,
        CLIENT_ACCOUNT,
        CANONICAL_NONCE,
        NETWORK_PASSPHRASE,
        Some(tampered_nonce), // client entry nonce override
        None,
    );

    let result = stellar_agent_sep45::AuthorizationEntries::parse_and_validate(
        &xdr_b64,
        NETWORK_PASSPHRASE,
        WEB_AUTH_CONTRACT,
        HOME_DOMAIN,
        WEB_AUTH_DOMAIN,
        &server_key,
        None,
        CLIENT_ACCOUNT,
    );

    assert!(
        result.is_err(),
        "nonce-mismatch challenge must be rejected; got Ok(_)"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, stellar_agent_sep45::Sep45Error::NonceMismatch { .. }),
        "expected Sep45Error::NonceMismatch for mismatched nonce in client entry; got {err:?}"
    );
    assert_eq!(
        err.wire_code(),
        "sep45.nonce_mismatch",
        "NonceMismatch wire_code must be 'sep45.nonce_mismatch'"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial fixture (b): entry-tampering detection
// ─────────────────────────────────────────────────────────────────────────────

/// Adversarial fixture (b) — web_auth_domain arg tampered in CLIENT entry.
///
/// A malicious server could construct a challenge where the client entry's
/// args map carries a different `web_auth_domain` than the server entry. Step
/// 9b of `parse_and_validate` enforces cross-entry consistency for all args
/// fields (`account`, `home_domain`, `web_auth_domain`, `web_auth_domain_account`,
/// `client_domain`) and returns `Sep45Error::WebAuthDomainMismatch` when the
/// client entry diverges from the server entry's reference values.
///
/// # Adversarial model
///
/// If the client entry's invocation carries a different `web_auth_domain` than
/// the server entry, the client would be signing a preimage over a different
/// context — potentially one controlled by an attacker. The client MUST detect
/// this cross-entry divergence and reject the challenge before signing.
#[test]
#[serial_test::serial]
fn tampered_web_auth_domain_in_client_entry_is_rejected() {
    let server_key = server_signing_key_str(&SERVER_SEED);

    // Build a challenge where the CLIENT entry carries a TAMPERED web_auth_domain.
    // The builder's `web_auth_domain_override_for_client` injects the tampered
    // value into the client entry's args map while leaving the server entry intact.
    let tampered_domain = "attacker-controlled.example.com";
    let xdr_b64 = build_adversarial_entries_xdr(
        WEB_AUTH_CONTRACT,
        HOME_DOMAIN,
        WEB_AUTH_DOMAIN, // server entry uses the canonical domain
        &SERVER_SEED,
        CLIENT_ACCOUNT,
        CANONICAL_NONCE,
        NETWORK_PASSPHRASE,
        None,
        Some(tampered_domain), // CLIENT entry's web_auth_domain is tampered
    );

    // Step 9b must detect the divergence between the server entry (canonical
    // web_auth_domain) and the client entry (tampered domain).
    let result = stellar_agent_sep45::AuthorizationEntries::parse_and_validate(
        &xdr_b64,
        NETWORK_PASSPHRASE,
        WEB_AUTH_CONTRACT,
        HOME_DOMAIN,
        WEB_AUTH_DOMAIN,
        &server_key,
        None,
        CLIENT_ACCOUNT,
    );

    assert!(
        result.is_err(),
        "tampered web_auth_domain in client entry must be rejected; got Ok(_)"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            stellar_agent_sep45::Sep45Error::WebAuthDomainMismatch { .. }
        ),
        "expected Sep45Error::WebAuthDomainMismatch for client entry with tampered web_auth_domain; got {err:?}"
    );
    assert_eq!(
        err.wire_code(),
        "sep45.web_auth_domain_mismatch",
        "WebAuthDomainMismatch wire_code must be 'sep45.web_auth_domain_mismatch'"
    );
}

/// Adversarial fixture (b) part 2 — wrong expected_web_auth_contract triggers
/// `InvalidContractAddress`.
///
/// A challenge whose entries reference `WEB_AUTH_CONTRACT` must be rejected
/// when the caller passes a DIFFERENT `expected_web_auth_contract` parameter.
/// This defends against a server that claims to run at one contract address
/// while the client has a different address from the anchor's `stellar.toml`.
#[test]
#[serial_test::serial]
fn wrong_expected_contract_is_rejected() {
    let server_key = server_signing_key_str(&SERVER_SEED);

    let xdr_b64 = build_adversarial_entries_xdr(
        WEB_AUTH_CONTRACT,
        HOME_DOMAIN,
        WEB_AUTH_DOMAIN,
        &SERVER_SEED,
        CLIENT_ACCOUNT,
        CANONICAL_NONCE,
        NETWORK_PASSPHRASE,
        None,
        None,
    );

    // A DIFFERENT contract address than what is in the entries.
    let wrong_contract = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
    let result = stellar_agent_sep45::AuthorizationEntries::parse_and_validate(
        &xdr_b64,
        NETWORK_PASSPHRASE,
        wrong_contract, // differs from WEB_AUTH_CONTRACT in the entries
        HOME_DOMAIN,
        WEB_AUTH_DOMAIN,
        &server_key,
        None,
        CLIENT_ACCOUNT,
    );

    assert!(
        result.is_err(),
        "wrong expected_web_auth_contract must be rejected; got Ok(_)"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            stellar_agent_sep45::Sep45Error::InvalidContractAddress { .. }
                | stellar_agent_sep45::Sep45Error::InvalidExpectedContractArg { .. }
        ),
        "expected InvalidContractAddress or InvalidExpectedContractArg; got {err:?}"
    );
}

/// Adversarial fixture (b) part 3 — invalid server signature is detected.
///
/// Constructs a well-formed challenge but signs the server entry with a
/// DIFFERENT key than the one passed as `expected_server_signing_key`.
/// `parse_and_validate` step 12 must detect the signature mismatch and return
/// `Sep45Error::InvalidServerSignature`.
#[test]
#[serial_test::serial]
fn wrong_server_signing_key_is_rejected() {
    // Build the challenge with SERVER_SEED (key A).
    let xdr_b64 = build_adversarial_entries_xdr(
        WEB_AUTH_CONTRACT,
        HOME_DOMAIN,
        WEB_AUTH_DOMAIN,
        &SERVER_SEED,
        CLIENT_ACCOUNT,
        CANONICAL_NONCE,
        NETWORK_PASSPHRASE,
        None,
        None,
    );

    // But pass a DIFFERENT key as expected_server_signing_key (key B).
    let different_seed = [2u8; 32];
    let different_server_key = server_signing_key_str(&different_seed);

    let result = stellar_agent_sep45::AuthorizationEntries::parse_and_validate(
        &xdr_b64,
        NETWORK_PASSPHRASE,
        WEB_AUTH_CONTRACT,
        HOME_DOMAIN,
        WEB_AUTH_DOMAIN,
        &different_server_key, // key B ≠ key A (used to sign the entries)
        None,
        CLIENT_ACCOUNT,
    );

    assert!(
        result.is_err(),
        "wrong expected_server_signing_key must be rejected; got Ok(_)"
    );
    let err = result.unwrap_err();
    // `parse_and_validate` checks the `web_auth_domain_account` arg (step 7)
    // BEFORE checking entry credentials at step 10.  The `web_auth_domain_account`
    // arg contains the actual server key (A); when the caller supplies a different
    // expected key (B), step 7 detects the mismatch as `WebAuthDomainAccountMismatch`.
    // All three error variants indicate the expected server key does not match
    // what the server returned — any is a valid fail-closed rejection.
    assert!(
        matches!(
            err,
            stellar_agent_sep45::Sep45Error::MissingServerEntry
                | stellar_agent_sep45::Sep45Error::InvalidServerSignature { .. }
                | stellar_agent_sep45::Sep45Error::WebAuthDomainAccountMismatch { .. }
        ),
        "expected MissingServerEntry, InvalidServerSignature, or WebAuthDomainAccountMismatch; got {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial fixture (c): ephemeral-key-per-request enforcement
// ─────────────────────────────────────────────────────────────────────────────

/// Adversarial fixture (c) — ephemeral-key-per-request uniqueness.
///
/// Each call to the SEP-45 ephemeral signing flow generates a FRESH ed25519
/// key via `OsRng`. This test asserts that 50 consecutive seed generations
/// produce entirely distinct values — an attacker cannot predict or replay a
/// prior session by reusing a previous ephemeral public key.
///
/// # Security note
///
/// If this test fails, it means the CSPRNG is returning repeated values —
/// a critical security failure that would allow session reuse.
///
/// # Feature gate
///
/// Requires `--features test-helpers` (or `--features testnet-integration`)
/// because `generate_ephemeral_seed` is a test-helper function.
#[cfg(feature = "test-helpers")]
#[test]
#[serial_test::serial]
fn ephemeral_key_per_request_uniqueness_across_50_calls() {
    use std::collections::HashSet;
    use stellar_agent_sep45::ephemeral::{generate_ephemeral_seed, signing_key_from_seed};

    let mut pubkeys: HashSet<[u8; 32]> = HashSet::new();

    for i in 0..50 {
        let seed = generate_ephemeral_seed();
        let key = signing_key_from_seed(&seed);
        let pubkey = key.verifying_key().to_bytes();

        assert!(
            pubkeys.insert(pubkey),
            "duplicate ephemeral public key at call {i} (CSPRNG failure or key reuse); \
             pubkey_prefix = {:?}",
            &pubkey[..8]
        );
    }

    assert_eq!(pubkeys.len(), 50, "all 50 ephemeral keys must be distinct");
}

// ─────────────────────────────────────────────────────────────────────────────
// Fail-closed: non-Address credential types rejected
// ─────────────────────────────────────────────────────────────────────────────

/// A challenge entry carrying `SorobanCredentials::SourceAccount` must be
/// rejected fail-closed by `parse_and_validate`.
///
/// `SourceAccount` entries are not defined in the SEP-45 challenge protocol.
/// The implementation returns `UnsupportedCredentialType` immediately on
/// encountering any non-Address entry at step-10 role classification.
#[test]
#[serial_test::serial]
fn source_account_entry_is_rejected() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use stellar_xdr::{
        Limits, SorobanAuthorizationEntries, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
        SorobanAuthorizedInvocation, SorobanCredentials, VecM, WriteXdr,
    };

    // Build a SourceAccount entry with a proper invocation that would pass
    // step-3 (no sub-invocations), step-4 (ContractFn), step-5 (correct
    // contract address), and step-6 (function name == "web_auth_verify") —
    // so that the code reaches step-10 credential classification where the
    // SourceAccount branch must be rejected fail-closed.
    let contract_bytes = stellar_strkey::Contract::from_string(WEB_AUTH_CONTRACT)
        .unwrap()
        .0;
    let contract_address = stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(
        stellar_xdr::Hash(contract_bytes),
    ));

    // Minimal args map (required to pass step-7 args extraction).
    use stellar_xdr::{ScMap, ScMapEntry, ScString, ScSymbol, ScVal};
    let server_key_bytes = {
        use ed25519_dalek::SigningKey;
        SigningKey::from_bytes(&SERVER_SEED)
            .verifying_key()
            .to_bytes()
    };
    let server_g_str = format!("{}", stellar_strkey::ed25519::PublicKey(server_key_bytes));
    let args_map = ScVal::Map(Some(ScMap(
        vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                val: ScVal::String(ScString(CLIENT_ACCOUNT.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                val: ScVal::String(ScString(HOME_DOMAIN.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                val: ScVal::String(ScString(CANONICAL_NONCE.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                val: ScVal::String(ScString(WEB_AUTH_DOMAIN.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
            },
        ]
        .try_into()
        .unwrap(),
    )));

    let source_account_entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(stellar_xdr::InvokeContractArgs {
                contract_address,
                function_name: stellar_xdr::ScSymbol("web_auth_verify".try_into().unwrap()),
                args: vec![args_map].try_into().unwrap(),
            }),
            sub_invocations: VecM::default(),
        },
    };

    let entries_xdr = SorobanAuthorizationEntries(vec![source_account_entry].try_into().unwrap());
    let mut out = Vec::new();
    entries_xdr
        .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
        .unwrap();
    let b64 = BASE64_STANDARD.encode(&out);

    let server_key = server_signing_key_str(&SERVER_SEED);
    let result = stellar_agent_sep45::AuthorizationEntries::parse_and_validate(
        &b64,
        NETWORK_PASSPHRASE,
        WEB_AUTH_CONTRACT,
        HOME_DOMAIN,
        WEB_AUTH_DOMAIN,
        &server_key,
        None,
        CLIENT_ACCOUNT,
    );

    assert!(
        result.is_err(),
        "SourceAccount entry must be rejected; got Ok(_)"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            stellar_agent_sep45::Sep45Error::UnsupportedCredentialType { .. }
        ),
        "expected UnsupportedCredentialType for SourceAccount entry; got {err:?}"
    );
    assert_eq!(err.wire_code(), "sep45.unsupported_credential_type");
}

/// Two sequential simulated `auth_with_ephemeral_key` calls produce distinct
/// ephemeral public keys — pure unit form of fixture (c).
///
/// Exercises the seed-generation path directly without any network I/O.
///
/// # Feature gate
///
/// Requires `--features test-helpers`.
#[cfg(feature = "test-helpers")]
#[test]
#[serial_test::serial]
fn two_sequential_auth_calls_use_distinct_ephemeral_keys() {
    use stellar_agent_sep45::ephemeral::{generate_ephemeral_seed, signing_key_from_seed};

    let seed_call_1 = generate_ephemeral_seed();
    let seed_call_2 = generate_ephemeral_seed();

    let key_call_1 = signing_key_from_seed(&seed_call_1);
    let key_call_2 = signing_key_from_seed(&seed_call_2);

    let pub1 = key_call_1.verifying_key().to_bytes();
    let pub2 = key_call_2.verifying_key().to_bytes();

    assert_ne!(
        pub1, pub2,
        "two consecutive auth-flow simulations must produce distinct ephemeral public keys"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// signature_expiration_ledger validation in sign_client_entry
// ─────────────────────────────────────────────────────────────────────────────

/// `signature_expiration_ledger == 0` is rejected by `sign_client_entry` with
/// `Sep45Error::InvalidSignatureExpirationLedger`.
///
/// Callers must supply a non-zero future ledger sequence from their RPC layer
/// (e.g. `current_ledger + 100`). A value of 0 indicates the caller did not
/// derive an expiration and must be rejected before any signature computation.
///
/// # Feature gate
///
/// Requires `--features test-helpers`.
#[cfg(feature = "test-helpers")]
#[test]
#[serial_test::serial]
fn sign_client_entry_zero_expiration_rejected() {
    use stellar_agent_sep45::client::Sep45Client;
    use stellar_agent_sep45::ephemeral::{sign_challenge_for_test, signing_key_from_seed};
    use zeroize::Zeroizing;

    // Build a valid challenge.
    let server_key = server_signing_key_str(&SERVER_SEED);
    let xdr_b64 = build_adversarial_entries_xdr(
        WEB_AUTH_CONTRACT,
        HOME_DOMAIN,
        WEB_AUTH_DOMAIN,
        &SERVER_SEED,
        CLIENT_ACCOUNT,
        CANONICAL_NONCE,
        NETWORK_PASSPHRASE,
        None,
        None,
    );
    let challenge = stellar_agent_sep45::AuthorizationEntries::parse_and_validate(
        &xdr_b64,
        NETWORK_PASSPHRASE,
        WEB_AUTH_CONTRACT,
        HOME_DOMAIN,
        WEB_AUTH_DOMAIN,
        &server_key,
        None,
        CLIENT_ACCOUNT,
    )
    .expect("valid challenge must parse");

    let client = Sep45Client::new_for_unit_test(NETWORK_PASSPHRASE).expect("client");
    let key = signing_key_from_seed(&Zeroizing::new([0x42u8; 32]));

    // signature_expiration_ledger == 0 must be rejected.
    let err = sign_challenge_for_test(&challenge, &key, &client, 0).unwrap_err();
    assert!(
        matches!(
            err,
            stellar_agent_sep45::Sep45Error::InvalidSignatureExpirationLedger { .. }
        ),
        "expected InvalidSignatureExpirationLedger for zero expiration; got {err:?}"
    );
    assert_eq!(err.wire_code(), "sep45.invalid_signature_expiration_ledger");
}

/// `sign_client_entry` writes `signature_expiration_ledger` into
/// the client entry's `SorobanAddressCredentials` before computing the preimage.
///
/// After signing, the re-encoded XDR must contain the caller-supplied ledger
/// sequence in the client entry's credentials. This verifies that the field is
/// set in the credentials, not just validated at the function entry point.
///
/// # Feature gate
///
/// Requires `--features test-helpers`.
#[cfg(feature = "test-helpers")]
#[test]
#[serial_test::serial]
fn sign_client_entry_sets_expiration_in_entry() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use stellar_agent_sep45::client::Sep45Client;
    use stellar_agent_sep45::ephemeral::{sign_challenge_for_test, signing_key_from_seed};
    use stellar_xdr::{Limits, ReadXdr, SorobanAuthorizationEntries, SorobanCredentials};
    use zeroize::Zeroizing;

    // Build a valid challenge.
    let server_key = server_signing_key_str(&SERVER_SEED);
    let xdr_b64 = build_adversarial_entries_xdr(
        WEB_AUTH_CONTRACT,
        HOME_DOMAIN,
        WEB_AUTH_DOMAIN,
        &SERVER_SEED,
        CLIENT_ACCOUNT,
        CANONICAL_NONCE,
        NETWORK_PASSPHRASE,
        None,
        None,
    );
    let challenge = stellar_agent_sep45::AuthorizationEntries::parse_and_validate(
        &xdr_b64,
        NETWORK_PASSPHRASE,
        WEB_AUTH_CONTRACT,
        HOME_DOMAIN,
        WEB_AUTH_DOMAIN,
        &server_key,
        None,
        CLIENT_ACCOUNT,
    )
    .expect("valid challenge must parse");

    let client = Sep45Client::new_for_unit_test(NETWORK_PASSPHRASE).expect("client");
    let key = signing_key_from_seed(&Zeroizing::new([0x42u8; 32]));
    let expected_expiry: u32 = 7_777_777;

    let signed_b64 = sign_challenge_for_test(&challenge, &key, &client, expected_expiry)
        .expect("sign must succeed for non-zero expiration");

    // Decode the re-encoded XDR and check the client entry's expiration ledger.
    let raw = BASE64_STANDARD.decode(&signed_b64).expect("base64 decode");
    let entries = SorobanAuthorizationEntries::read_xdr(&mut stellar_xdr::Limited::new(
        &mut raw.as_slice(),
        Limits::none(),
    ))
    .expect("XDR decode");

    let client_entry = entries
        .0
        .get(challenge.client_entry_index)
        .expect("client entry must exist");
    let SorobanCredentials::Address(ref creds) = client_entry.credentials else {
        panic!("client entry must have Address credentials");
    };
    assert_eq!(
        creds.signature_expiration_ledger, expected_expiry,
        "sign_client_entry must set signature_expiration_ledger to the caller-supplied value"
    );
}
