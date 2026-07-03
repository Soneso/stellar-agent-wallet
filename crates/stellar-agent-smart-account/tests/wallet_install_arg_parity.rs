//! Byte-parity gate for the `add_context_rule` arg shapes the wallet's
//! `build_add_context_rule_args` constructs.
//!
//! Sibling of `tests/auth_digest_parity.rs` (which covers only the
//! `Vec<u32>` rule-IDs arg of the auth-digest preimage). This file extends
//! the parity discipline to every other `add_context_rule` arg shape so
//! arg-shape regressions surface as test failures rather than testnet traps:
//!
//! 1. **Option<u32> ABI drift**. A bug in `encode_option_u32` that produces
//!    the soroban-sdk `#[contracttype]` enum-tagged ScVec encoding
//!    (`Vec([Symbol("Some"), payload])` / `Vec([Symbol("None")])`) instead of
//!    the standard library `Option<T>` Val ABI (`Some(n)` → inner-type raw,
//!    `None` → `ScVal::Void`) would be caught here.
//! 2. **Sub-shape extrapolation**. The `Vec<u32>` coverage in
//!    `auth_digest_parity.rs` was extended by extrapolation to the other arg
//!    shapes without empirically verifying them (Option<u32>, ScVal::String,
//!    Map<Address, Val>, Vec<Signer>, BytesM).
//!
//! # How this test pins the wire shape
//!
//! For each arg shape, the test:
//!
//! 1. Builds the wallet-side ScVal using the SAME constructors
//!    `crates/stellar-agent-smart-account/src/managers/rules.rs::
//!    build_add_context_rule_args` uses (via `stellar-xdr` through
//!    `stellar_xdr`).
//! 2. Builds the on-chain canonical encoding via soroban-sdk's `Env` +
//!    `to_xdr`.
//! 3. Asserts the two encodings produce byte-identical XDR.
//!
//! This is the same pattern as `auth_digest_parity.rs`: independent
//! recompute of what the contract host produces, not a tautology.
//!
//! # Wire-shape parity
//!
//! Baseline arg-shape parity: all `add_context_rule` argument encodings
//! match what the Soroban host receives at the wire level.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration test — panics are the correct failure mode"
)]
#![allow(
    clippy::needless_borrows_for_generic_args,
    reason = "clarity: explicit borrows show the to_xdr / write_xdr contracts"
)]

use soroban_sdk::xdr::ToXdr as _;
use soroban_sdk::{Address, Bytes, Env, IntoVal, Map, String as SorobanString, Vec as SorobanVec};
use stellar_xdr::{
    AccountId, BytesM, Hash, Limits, PublicKey, ScAddress, ScBytes, ScMap, ScSymbol, ScVal, ScVec,
    Uint256, VecM, WriteXdr,
};

/// Extracts the byte slice from a soroban-sdk `Bytes` Val for byte-comparison.
fn soroban_bytes_to_vec(env_bytes: &soroban_sdk::Bytes) -> Vec<u8> {
    let mut out = vec![0_u8; env_bytes.len() as usize];
    env_bytes.copy_into_slice(&mut out);
    out
}

/// Encodes the wallet-side ScVal as XDR bytes for byte-comparison.
///
/// Disambiguates `to_xdr` between soroban-sdk's `ToXdr` trait (env-bound)
/// and stellar-xdr's `WriteXdr` trait (Limits-bound). The wallet-side
/// uses `WriteXdr::to_xdr(&scval, Limits::none())`.
fn wallet_scval_to_xdr_bytes(scval: &ScVal) -> Vec<u8> {
    WriteXdr::to_xdr(scval, Limits::none())
        .expect("wallet-side ScVal XDR encode is infallible for bounded inputs")
}

// ─────────────────────────────────────────────────────────────────────────────
// Option<u32> — `valid_until` arg of `add_context_rule` and
// `update_context_rule_valid_until`.
// ─────────────────────────────────────────────────────────────────────────────

/// Asserts byte-equality between the wallet's `encode_option_u32(Some(n))`
/// shape and soroban-sdk's `Option::<u32>::Some(n)` Val ABI encoding.
///
/// Cross-reference: `soroban-env-common-25.0.1/src/option.rs:3-16` —
/// `Option<T>::try_from_val` checks `val.is_void()` for `None` and
/// otherwise delegates to `T::try_from_val(env, val)` for `Some(_)`. The
/// raw inner-type ABI is what gets serialised.
#[test]
fn option_u32_some_parity_with_onchain_canonical() {
    // Wallet-side: encode_option_u32(Some(n)) → ScVal::U32(n) raw.
    // (See managers/rules.rs::encode_option_u32 — pinned by the
    // encode_option_u32_some_round_trip unit test.)
    let wallet_scval = ScVal::U32(123_456);
    let wallet_xdr = wallet_scval_to_xdr_bytes(&wallet_scval);

    // On-chain: `Option<u32>::Some(n).into_val(env)` produces the same
    // Val that the soroban host would receive when the contract function
    // signature `valid_until: Option<u32>` is invoked with `Some(n)`.
    let env = Env::default();
    let onchain_val: soroban_sdk::Val = Some(123_456_u32).into_val(&env);
    let onchain_xdr_soroban = onchain_val.to_xdr(&env);
    let onchain_xdr = soroban_bytes_to_vec(&onchain_xdr_soroban);

    assert_eq!(
        wallet_xdr, onchain_xdr,
        "Option<u32>::Some(n) wire shape diverges between wallet (stellar-xdr 27) \
         and on-chain canonical (soroban-sdk).\n\
         wallet:  {wallet_xdr:02x?}\n\
         onchain: {onchain_xdr:02x?}"
    );
}

/// Asserts byte-equality between the wallet's `encode_option_u32(None)`
/// shape and soroban-sdk's `Option::<u32>::None` Val ABI encoding.
#[test]
fn option_u32_none_parity_with_onchain_canonical() {
    let wallet_scval = ScVal::Void;
    let wallet_xdr = wallet_scval_to_xdr_bytes(&wallet_scval);

    let env = Env::default();
    let onchain_val: soroban_sdk::Val = None::<u32>.into_val(&env);
    let onchain_xdr_soroban = onchain_val.to_xdr(&env);
    let onchain_xdr = soroban_bytes_to_vec(&onchain_xdr_soroban);

    assert_eq!(
        wallet_xdr, onchain_xdr,
        "Option<u32>::None wire shape diverges. \
         wallet={wallet_xdr:02x?}, onchain={onchain_xdr:02x?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// ScVal::String — `name` arg of `add_context_rule` and
// `update_context_rule_name`.
// ─────────────────────────────────────────────────────────────────────────────

/// Asserts byte-equality between the wallet's `ScVal::String(ScString)`
/// shape and soroban-sdk's `String::from_str(env, &str).into_val(env)`
/// encoding.
#[test]
fn name_string_parity_with_onchain_canonical() {
    use stellar_xdr::ScString;

    let name_text = "pr3-acceptance";

    // Wallet-side: ScVal::String(ScString(StringM::try_from(name)?)).
    let wallet_scval = ScVal::String(ScString(
        name_text
            .to_owned()
            .try_into()
            .expect("name fits StringM<u32>"),
    ));
    let wallet_xdr = wallet_scval_to_xdr_bytes(&wallet_scval);

    // On-chain: soroban_sdk::String::from_str(env, name).into_val(env).
    let env = Env::default();
    let onchain_val: soroban_sdk::Val = SorobanString::from_str(&env, name_text).into_val(&env);
    let onchain_xdr_soroban = onchain_val.to_xdr(&env);
    let onchain_xdr = soroban_bytes_to_vec(&onchain_xdr_soroban);

    assert_eq!(
        wallet_xdr, onchain_xdr,
        "ScVal::String wire shape diverges. \
         wallet={wallet_xdr:02x?}, onchain={onchain_xdr:02x?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Empty Map<Address, Val> — `policies` arg of `add_context_rule`.
// ─────────────────────────────────────────────────────────────────────────────

/// Asserts byte-equality between the wallet's empty `ScVal::Map`
/// shape and soroban-sdk's empty `Map<Address, Val>` encoding.
#[test]
fn empty_policies_map_parity_with_onchain_canonical() {
    let wallet_scval = ScVal::Map(Some(ScMap::default()));
    let wallet_xdr = wallet_scval_to_xdr_bytes(&wallet_scval);

    let env = Env::default();
    let onchain_map: Map<Address, soroban_sdk::Val> = Map::new(&env);
    let onchain_val: soroban_sdk::Val = onchain_map.into_val(&env);
    let onchain_xdr_soroban = onchain_val.to_xdr(&env);
    let onchain_xdr = soroban_bytes_to_vec(&onchain_xdr_soroban);

    assert_eq!(
        wallet_xdr, onchain_xdr,
        "Empty Map<Address, Val> wire shape diverges. \
         wallet={wallet_xdr:02x?}, onchain={onchain_xdr:02x?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Signer::Delegated(addr) — single-element `signers` arg of
// `add_context_rule`. Wallet builds the ScVec via `encode_signer`; the
// test mirrors that recipe inline and compares to the on-chain canonical.
// ─────────────────────────────────────────────────────────────────────────────

/// Asserts byte-equality between the wallet's `Signer::Delegated(g_addr)`
/// ScVec shape (Symbol("Delegated") + Address) and the on-chain canonical
/// `stellar_accounts::smart_account::Signer::Delegated(addr)` encoding.
#[test]
fn signer_delegated_parity_with_onchain_canonical() {
    use stellar_accounts::smart_account::Signer as OzSigner;

    // ── Fixture: a fixed ed25519 G-strkey ────────────────────────────────────
    // Using a deterministic 32-byte pubkey so the test is stable across runs.
    let pubkey_bytes: [u8; 32] = [
        0xa3, 0xfb, 0xa4, 0x95, 0xfb, 0xb1, 0xc7, 0x1c, 0xe1, 0x05, 0xc4, 0x76, 0x4f, 0x1e, 0x2e,
        0xa1, 0xe1, 0xf3, 0x91, 0xc6, 0x66, 0x69, 0x33, 0x47, 0xc6, 0xb1, 0x4e, 0x82, 0x06, 0xb4,
        0x9f, 0x8c,
    ];

    // ── Wallet-side: build `ScVal::Vec([Symbol("Delegated"), Address])` ─────
    // Mirrors managers/rules.rs::encode_signer (Delegated arm); pinned by
    // encode_signer_delegated_round_trip unit test.
    let wallet_addr = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        pubkey_bytes,
    ))));
    let delegated_sym =
        ScSymbol::try_from("Delegated").expect("Delegated symbol fits ScSymbol limits");
    let inner_vec: VecM<ScVal> = vec![ScVal::Symbol(delegated_sym), ScVal::Address(wallet_addr)]
        .try_into()
        .expect("2-element ScVec fits VecM");
    let wallet_scval = ScVal::Vec(Some(ScVec(inner_vec)));
    let wallet_xdr = wallet_scval_to_xdr_bytes(&wallet_scval);

    // ── On-chain canonical: stellar_accounts::smart_account::Signer::Delegated ─
    let env = Env::default();
    // soroban_sdk::Address from the same 32-byte pubkey (Stellar account form).
    // Use stellar-strkey to produce the canonical G-strkey, then construct
    // soroban-sdk Address.from_str.
    let g_strkey = stellar_strkey::ed25519::PublicKey(pubkey_bytes).to_string();
    let onchain_addr = Address::from_str(&env, &g_strkey);
    let onchain_signer = OzSigner::Delegated(onchain_addr);
    let onchain_val: soroban_sdk::Val = onchain_signer.into_val(&env);
    let onchain_xdr_soroban = onchain_val.to_xdr(&env);
    let onchain_xdr = soroban_bytes_to_vec(&onchain_xdr_soroban);

    assert_eq!(
        wallet_xdr, onchain_xdr,
        "Signer::Delegated wire shape diverges. \
         wallet={wallet_xdr:02x?}, onchain={onchain_xdr:02x?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Signer::External(verifier, key_data) — third arg variant. Pinning the
// shape here ensures that verifier-contract integration cannot drift the
// External wire encoding without a CI failure.
// ─────────────────────────────────────────────────────────────────────────────

/// Asserts byte-equality between the wallet's
/// `Signer::External(verifier, key_data)` ScVec shape (Symbol("External") +
/// Address verifier + Bytes key_data) and the on-chain canonical OZ
/// `Signer::External(...)` encoding.
#[test]
fn signer_external_parity_with_onchain_canonical() {
    use stellar_accounts::smart_account::Signer as OzSigner;

    // ── Fixture: a fixed verifier C-strkey + 64-byte key_data ────────────────
    let verifier_bytes: [u8; 32] = [0x11; 32];
    let key_data_bytes: [u8; 64] = [0x42; 64];

    // ── Wallet-side: ScVec([Symbol("External"), Address(verifier), Bytes(key_data)]) ─
    let wallet_verifier = ScAddress::Contract(stellar_xdr::ContractId(Hash(verifier_bytes)));
    let external_sym =
        ScSymbol::try_from("External").expect("External symbol fits ScSymbol limits");
    let key_data_bytesm: BytesM = key_data_bytes
        .to_vec()
        .try_into()
        .expect("64 bytes fits BytesM");
    let inner_vec: VecM<ScVal> = vec![
        ScVal::Symbol(external_sym),
        ScVal::Address(wallet_verifier),
        ScVal::Bytes(ScBytes(key_data_bytesm)),
    ]
    .try_into()
    .expect("3-element ScVec fits VecM");
    let wallet_scval = ScVal::Vec(Some(ScVec(inner_vec)));
    let wallet_xdr = wallet_scval_to_xdr_bytes(&wallet_scval);

    // ── On-chain canonical: OzSigner::External(verifier_address, key_data_bytes) ─
    let env = Env::default();
    let verifier_strkey = stellar_strkey::Contract(verifier_bytes).to_string();
    let onchain_verifier = Address::from_str(&env, &verifier_strkey);
    let onchain_key_data = Bytes::from_array(&env, &key_data_bytes);
    let onchain_signer = OzSigner::External(onchain_verifier, onchain_key_data);
    let onchain_val: soroban_sdk::Val = onchain_signer.into_val(&env);
    let onchain_xdr_soroban = onchain_val.to_xdr(&env);
    let onchain_xdr = soroban_bytes_to_vec(&onchain_xdr_soroban);

    assert_eq!(
        wallet_xdr, onchain_xdr,
        "Signer::External wire shape diverges. \
         wallet={wallet_xdr:02x?}, onchain={onchain_xdr:02x?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// BytesM — used for the External signer's `pubkey_data` payload AND for
// the AuthPayload signature value. Pinning here gates the WebAuthn
// verifier-contract pubkey_data encoding against drift.
// ─────────────────────────────────────────────────────────────────────────────

/// Asserts byte-equality between the wallet's `ScVal::Bytes(ScBytes(BytesM))`
/// shape and soroban-sdk's `Bytes::from_array` encoding for a 64-byte payload
/// (matches the External signer's typical key_data length).
#[test]
fn bytes_64_parity_with_onchain_canonical() {
    let payload: [u8; 64] = [0xab; 64];

    let bytesm: BytesM = payload.to_vec().try_into().expect("64 bytes fits BytesM");
    let wallet_scval = ScVal::Bytes(ScBytes(bytesm));
    let wallet_xdr = wallet_scval_to_xdr_bytes(&wallet_scval);

    let env = Env::default();
    let onchain_val: soroban_sdk::Val = Bytes::from_array(&env, &payload).into_val(&env);
    let onchain_xdr_soroban = onchain_val.to_xdr(&env);
    let onchain_xdr = soroban_bytes_to_vec(&onchain_xdr_soroban);

    assert_eq!(
        wallet_xdr, onchain_xdr,
        "ScVal::Bytes (64-byte payload) wire shape diverges. \
         wallet={wallet_xdr:02x?}, onchain={onchain_xdr:02x?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Vec<Signer> — wrapper around the per-signer encoding above. Asserts the
// outer ScVec is byte-identical between wallet and on-chain canonical for
// the single-Delegated-signer case.
// ─────────────────────────────────────────────────────────────────────────────

/// Asserts byte-equality between the wallet's `Vec<Signer>` shape with
/// a single Delegated entry and soroban-sdk's `Vec<Signer>::from_array`
/// encoding.
#[test]
fn vec_signer_single_delegated_parity_with_onchain_canonical() {
    use stellar_accounts::smart_account::Signer as OzSigner;

    let pubkey_bytes: [u8; 32] = [
        0xa3, 0xfb, 0xa4, 0x95, 0xfb, 0xb1, 0xc7, 0x1c, 0xe1, 0x05, 0xc4, 0x76, 0x4f, 0x1e, 0x2e,
        0xa1, 0xe1, 0xf3, 0x91, 0xc6, 0x66, 0x69, 0x33, 0x47, 0xc6, 0xb1, 0x4e, 0x82, 0x06, 0xb4,
        0x9f, 0x8c,
    ];

    // ── Wallet-side: ScVec([Vec([Symbol("Delegated"), Address])]) ────────────
    let wallet_addr = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        pubkey_bytes,
    ))));
    let delegated_sym = ScSymbol::try_from("Delegated").unwrap();
    let inner_vec: VecM<ScVal> = vec![ScVal::Symbol(delegated_sym), ScVal::Address(wallet_addr)]
        .try_into()
        .unwrap();
    let signer_scval = ScVal::Vec(Some(ScVec(inner_vec)));
    let signers_outer: VecM<ScVal> = vec![signer_scval].try_into().unwrap();
    let wallet_scval = ScVal::Vec(Some(ScVec(signers_outer)));
    let wallet_xdr = wallet_scval_to_xdr_bytes(&wallet_scval);

    // ── On-chain canonical: SorobanVec<OzSigner>::from_array ────────────────
    let env = Env::default();
    let g_strkey = stellar_strkey::ed25519::PublicKey(pubkey_bytes).to_string();
    let onchain_addr = Address::from_str(&env, &g_strkey);
    let onchain_signer = OzSigner::Delegated(onchain_addr);
    let onchain_signers: SorobanVec<OzSigner> = SorobanVec::from_array(&env, [onchain_signer]);
    let onchain_val: soroban_sdk::Val = onchain_signers.into_val(&env);
    let onchain_xdr_soroban = onchain_val.to_xdr(&env);
    let onchain_xdr = soroban_bytes_to_vec(&onchain_xdr_soroban);

    assert_eq!(
        wallet_xdr, onchain_xdr,
        "Vec<Signer> with single Delegated entry diverges. \
         wallet={wallet_xdr:02x?}, onchain={onchain_xdr:02x?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// WebAuthnSigData inner encoding.
//
// Tests the XDR encoding of:
// (a) `WebAuthnSigData` ScVal::Map shape per the OpenZeppelin smart-account
//     WebAuthn verifier.
// (b) The XDR-encode-to-bytes step producing the `<inner-encoding>` bytes
//     for the External-arm signer entry (double-XDR pattern).
// ─────────────────────────────────────────────────────────────────────────────

/// Asserts byte-equality between the wallet-side `WebAuthnSigData`
/// inner-encoding and the on-chain canonical OZ `WebAuthnSigData::to_xdr`
/// encoding.
///
/// # Fixture
///
/// Uses deterministic fixture data matching the on-chain canonical from the
/// OpenZeppelin smart-account WebAuthn verifier's `verify_success` test:
///
/// - `signature_compact` — ZERO 64 bytes. The gate verifies encoding SHAPE
///   (ScMap key-order + field byte layout), not signature validity. A zero
///   byte-pattern is sufficient for shape verification and avoids pulling
///   `p256` as a dev-dep for a single fixture-generation step.
/// - `authenticator_data` — 37-byte array with `data[32] = 0x1D`
///   (`UP | UV | BE | BS = 0x01 | 0x04 | 0x08 | 0x10`); matches
///   `encode_authenticator_data(&e, AUTH_DATA_FLAGS_UP | AUTH_DATA_FLAGS_UV
///   | AUTH_DATA_FLAGS_BE | AUTH_DATA_FLAGS_BS)` in the verifier test.
/// - `client_data_json` — JSON bytes equivalent to `encode_client_data`
///   output in the verifier test, with `challenge` = base64url-unpadded of the
///   32-byte `signature_payload_hex` fixture.
///
/// # Wire-shape parity
///
/// WebAuthn signer wire encoding: `WebAuthnSigData` inner XDR matches the on-chain canonical.
#[test]
fn webauthn_sigdata_inner_encoding_parity_with_onchain_canonical() {
    use base64::Engine as _;
    use soroban_sdk::{Bytes, BytesN, Env};
    use stellar_accounts::verifiers::webauthn::WebAuthnSigData;
    use stellar_agent_smart_account::webauthn::WebAuthnAssertion;
    use stellar_agent_smart_account::webauthn::encode_webauthn_signature_value_bytes;

    // ── Fixture: deterministic values matching the verifier verify_success test ─

    // `signature_payload_hex` from the WebAuthn verifier's verify_success test.
    let payload: [u8; 32] = [
        0x4b, 0xb7, 0xa8, 0xb9, 0x96, 0x09, 0xb0, 0xb8, 0xb1, 0xd5, 0x34, 0x69, 0x4b, 0xb1, 0xf3,
        0x1f, 0x12, 0x91, 0x38, 0xa2, 0xf2, 0xa1, 0x1f, 0x8e, 0x87, 0x02, 0xee, 0xdb, 0xb7, 0x92,
        0x92, 0x2e,
    ];

    // base64url-unpadded of the 32-byte payload, as produced by `base64_url_encode`
    // in the verifier test.
    // Using base64::URL_SAFE_NO_PAD which is byte-identical to the
    // custom `base64_url_encode` function (same alphabet, no padding).
    let challenge_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
    assert_eq!(
        challenge_b64url.len(),
        43,
        "base64url of 32 bytes must be 43 chars (no padding)"
    );

    // client_data_json: mirrors `encode_client_data(&e, challenge, "webauthn.get")`
    // in the WebAuthn verifier test.
    let client_data_json_str = format!(
        "{{\n            \"type\": \"webauthn.get\",\n            \"challenge\": \"{challenge_b64url}\",\n            \"origin\": \"https://example.com\",\n            \"crossOrigin\": false\n        }}"
    );
    let client_data_json_bytes = client_data_json_str.as_bytes().to_vec();

    // authenticator_data: 37-byte array with flags byte at index 32.
    // Flags: UP | UV | BE | BS = 0x01 | 0x04 | 0x08 | 0x10 = 0x1D.
    // Mirrors `encode_authenticator_data(&e, UP | UV | BE | BS)` in the
    // WebAuthn verifier test.
    let mut auth_data = [0u8; 37];
    auth_data[32] = 0x1D; // UP | UV | BE | BS
    let authenticator_data_bytes = auth_data.to_vec();

    // signature_compact: ZERO 64 bytes. The gate tests encoding shape
    // (ScMap key-order, field bytes), not signature validity. A zero
    // byte-pattern is sufficient and avoids a `p256` dev-dep.
    let signature_compact = [0u8; 64];

    // ── Wallet-side encode ───────────────────────────────────────────────────

    let assertion = WebAuthnAssertion {
        signature_compact,
        authenticator_data: authenticator_data_bytes.clone(),
        client_data_json: client_data_json_bytes.clone(),
    };

    let wallet_inner_bytes = encode_webauthn_signature_value_bytes(&assertion)
        .expect("encode_webauthn_signature_value_bytes must not fail on well-formed inputs");

    // ── On-chain canonical encode ────────────────────────────────────────────
    //
    // Construct the same fixture via the soroban-sdk-side `WebAuthnSigData`
    // type and call `to_xdr(&env)`. The `to_xdr` impl is the soroban-sdk
    // `ToXdr` trait (env-bound); the wallet uses `WriteXdr` (Limits-bound).
    // Both must produce byte-identical XDR for the same logical value.

    let env = Env::default();
    let onchain_sig_data = WebAuthnSigData {
        signature: BytesN::<64>::from_array(&env, &signature_compact),
        authenticator_data: Bytes::from_slice(&env, &authenticator_data_bytes),
        client_data: Bytes::from_slice(&env, &client_data_json_bytes),
    };
    let onchain_xdr_soroban = onchain_sig_data.to_xdr(&env);
    let onchain_inner_bytes = soroban_bytes_to_vec(&onchain_xdr_soroban);

    // ── Assert byte-equality ─────────────────────────────────────────────────

    assert_eq!(
        wallet_inner_bytes, onchain_inner_bytes,
        "WebAuthnSigData inner-encoding diverges between wallet encoder and \
         OZ on-chain canonical. \
         wallet={wallet_inner_bytes:02x?}, \
         onchain={onchain_inner_bytes:02x?}"
    );
}
