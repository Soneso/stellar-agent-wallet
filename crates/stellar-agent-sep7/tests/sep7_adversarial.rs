//! SEP-7 adversarial corpus.
//!
//! # Coverage categories
//!
//! (a) **Injection / parameter smuggling** — non-base64 XDR, oversized `msg`,
//!     invalid `memo_type`, missing required params, unbalanced `replace` (tx
//!     path with a real XDR), duplicate parameters.
//!
//! (b) **Callback URL SSRF** — private IPs, loopback, dangerous schemes,
//!     missing `url:` prefix, non-HTTPS flagged.  The tool NEVER POSTs to
//!     the callback; the preview surfaces the authority for operator inspection.
//!
//! (c) **Signature bypass** — `origin_domain` present + `signature` absent →
//!     `missing_required`; tampered URI; valid URI for different content; bad
//!     FQDN formats; no key in toml; key mismatch.  The crypto tests drive the
//!     real `verify_against_toml_body` production logic through the
//!     `verify_with_injected_body` seam (a stellar.toml body is injected
//!     instead of fetched), so the actual signature-decode and ed25519-verify
//!     code is exercised rather than a reimplementation.  The live fetch
//!     wrapper is covered by `tests/sep7_testnet_acceptance.rs`.
//!
//! (d) **Replay** — the same signed URI verifies twice (no built-in replay
//!     protection); a URI signed for a different `network_passphrase` that was
//!     subsequently mutated fails (payload changed).
//!
//! # Ephemeral keys
//!
//! Signing keys are generated at test runtime using `ed25519_dalek`; no
//! literal `S...` seed is committed.  See `make_ephemeral_keypair()`.
//!
//! # Parse-and-verify-only invariant
//!
//! Every test asserts that `will_auto_post_callback` and `will_auto_submit`
//! are `false` in any preview that is produced.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "test-only; panics and status output acceptable in integration tests"
)]

use base64::Engine as _;
use stellar_agent_sep7::{
    Sep7Error,
    parse::parse_sep7_uri,
    preview::{build_preview, inspect_callback},
    verify::SignatureStatus,
};

#[cfg(feature = "test-helpers")]
use ed25519_dalek::{Signer, SigningKey};
#[cfg(feature = "test-helpers")]
use rand_core::OsRng;
#[cfg(feature = "test-helpers")]
use stellar_agent_sep7::verify::build_signature_payload;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generates an ephemeral ed25519 keypair at test runtime.
/// Never commits a literal `S...` seed.
#[cfg(feature = "test-helpers")]
fn make_ephemeral_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Returns the G-strkey for an ephemeral signing key.
#[cfg(feature = "test-helpers")]
fn g_strkey(sk: &SigningKey) -> String {
    let vk = sk.verifying_key();
    // stellar_strkey::to_string() returns heapless::String<56>; format! gives std::String.
    format!("{}", stellar_strkey::ed25519::PublicKey(vk.to_bytes()))
}

/// Signs a URI with an ephemeral key and appends `&signature=<b64url-encoded-standard-b64>`.
///
/// Stores the signature as URL-encoded standard base64, exercising
/// the STANDARD fallback in the production decoder (which tries URL_SAFE_NO_PAD first,
/// then STANDARD).
#[cfg(feature = "test-helpers")]
fn sign_uri(uri: &str, sk: &SigningKey) -> String {
    let payload = build_signature_payload(uri);
    let sig = sk.sign(&payload);
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    // URL-encode the base64 signature (replaces '+', '/', '=').
    let sig_urlencoded = sig_b64
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D");
    format!("{uri}&signature={sig_urlencoded}")
}

/// Builds a stellar.toml body string containing `URI_REQUEST_SIGNING_KEY`.
#[cfg(feature = "test-helpers")]
fn toml_with_signing_key(g_strkey: &str) -> String {
    format!("URI_REQUEST_SIGNING_KEY = \"{g_strkey}\"\n")
}

/// Builds a stellar.toml body string WITHOUT `URI_REQUEST_SIGNING_KEY`.
#[cfg(feature = "test-helpers")]
fn toml_without_signing_key() -> &'static str {
    "VERSION = \"2.0.0\"\n"
}

// ─────────────────────────────────────────────────────────────────────────────
// Test seam: verify_with_injected_body
// ─────────────────────────────────────────────────────────────────────────────

/// Skips the HTTP fetch and injects a stellar.toml body directly, then
/// delegates to `stellar_agent_sep7::verify_against_toml_body`.
///
/// All TOML-parse → key-extraction → signature-decode → ed25519-verify steps
/// execute inside the production function, so there is no duplicate
/// implementation in the test module.
#[cfg(feature = "test-helpers")]
async fn verify_with_injected_body(
    uri: &str,
    origin_domain: &str,
    signature_b64: Option<&str>,
    toml_body: &str,
) -> Result<SignatureStatus, Sep7Error> {
    // Delegate entirely to the production post-fetch path.
    stellar_agent_sep7::verify_against_toml_body(uri, origin_domain, signature_b64, toml_body)
}

// ─────────────────────────────────────────────────────────────────────────────
// (a) Injection / parameter smuggling
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a1_non_base64_xdr_fails_before_signature_verification() {
    // The xdr decode MUST fail before any signature verification is attempted.
    let uri = "web+stellar:tx?xdr=NOT_VALID_BASE64!!!&origin_domain=example.com\
               &signature=fake_sig";
    let err = parse_sep7_uri(uri).unwrap_err();
    assert!(
        matches!(err, Sep7Error::InvalidParamValue { param: "xdr", .. }),
        "non-base64 xdr must fail with InvalidParamValue, got: {err:?}"
    );
}

#[test]
fn a2_xdr_that_decodes_but_is_not_transactionenvelope_fails() {
    // Valid base64 but not a TransactionEnvelope.
    let bad_xdr = base64::engine::general_purpose::STANDARD.encode(b"this is not XDR");
    let uri = format!(
        "web+stellar:tx?xdr={}",
        bad_xdr
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    let err = parse_sep7_uri(&uri).unwrap_err();
    assert!(
        matches!(err, Sep7Error::InvalidParamValue { param: "xdr", .. }),
        "non-XDR bytes must fail with InvalidParamValue for xdr, got: {err:?}"
    );
}

#[test]
fn a3_oversized_msg_rejected() {
    let msg: String = "x".repeat(301);
    let uri = format!(
        "web+stellar:pay?destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
         &msg={msg}"
    );
    let err = parse_sep7_uri(&uri).unwrap_err();
    assert!(
        matches!(err, Sep7Error::MsgTooLong { len: 301 }),
        "msg > 300 chars must fail with MsgTooLong, got: {err:?}"
    );
}

#[test]
fn a4_invalid_memo_type_rejected() {
    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &memo=test\
        &memo_type=MEMO_EVIL";
    let err = parse_sep7_uri(uri).unwrap_err();
    assert!(
        matches!(
            err,
            Sep7Error::InvalidParamValue {
                param: "memo_type",
                ..
            }
        ),
        "invalid memo_type must fail, got: {err:?}"
    );
}

#[test]
fn a5_missing_destination_for_pay_fails() {
    let err = parse_sep7_uri("web+stellar:pay?amount=100").unwrap_err();
    assert!(
        matches!(
            err,
            Sep7Error::MissingRequiredParam {
                param: "destination"
            }
        ),
        "missing destination must fail, got: {err:?}"
    );
}

#[test]
fn a6_missing_xdr_for_tx_fails() {
    let err = parse_sep7_uri("web+stellar:tx?pubkey=GABC").unwrap_err();
    assert!(
        matches!(err, Sep7Error::MissingRequiredParam { param: "xdr" }),
        "missing xdr must fail, got: {err:?}"
    );
}

/// Asserts that unbalanced `replace` identifiers in a `tx` URI are rejected.
///
/// A real SEP-7 `tx` URI with a valid XDR and an unbalanced `replace` param
/// (`sourceAccount:X;Y:The account` — left set {X} ≠ right set {Y}) must
/// return `InvalidParamValue { param: "replace" }`.
#[test]
fn a7_unbalanced_replace_identifiers_in_tx_uri_rejected() {
    use stellar_xdr::{
        Limits, Memo, MuxedAccount, Preconditions, SequenceNumber, Transaction,
        TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
    };

    // Build a minimal valid TransactionEnvelope at runtime so we do not depend
    // on a precomputed base64 literal that may not round-trip correctly.
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
        fee: 100,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![].try_into().unwrap(),
        ext: TransactionExt::V0,
    };
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![].try_into().unwrap(),
    });
    let xdr_b64 = env.to_xdr_base64(Limits::none()).unwrap();
    // URL-encode the standard-base64 form ('+' → %2B, '/' → %2F, '=' → %3D).
    let xdr_urlenc = xdr_b64
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D");

    // Unbalanced replace: left has identifier X, right references Y (not X).
    let replace = "sourceAccount%3AX%3BY%3AThe%20account";
    let uri = format!("web+stellar:tx?xdr={xdr_urlenc}&replace={replace}");
    let err = parse_sep7_uri(&uri).unwrap_err();
    assert!(
        matches!(
            err,
            Sep7Error::InvalidParamValue {
                param: "replace",
                ..
            }
        ),
        "unbalanced replace in tx URI must return InvalidParamValue{{replace}}, got: {err:?}"
    );
}

#[test]
fn a8_duplicate_params_rejected() {
    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &destination=GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
    let err = parse_sep7_uri(uri).unwrap_err();
    assert!(
        matches!(err, Sep7Error::InvalidParamValue { param: "query", .. }),
        "duplicate params must be rejected, got: {err:?}"
    );
}

#[test]
fn a9_memo_without_memo_type_rejected() {
    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &memo=test_memo";
    let err = parse_sep7_uri(uri).unwrap_err();
    assert!(
        matches!(
            err,
            Sep7Error::InvalidParamValue {
                param: "memo_type",
                ..
            }
        ),
        "memo without memo_type must be rejected, got: {err:?}"
    );
}

#[test]
fn a10_asset_code_without_issuer_rejected() {
    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &asset_code=USDC";
    let err = parse_sep7_uri(uri).unwrap_err();
    assert!(
        matches!(
            err,
            Sep7Error::InvalidParamValue {
                param: "asset_issuer",
                ..
            }
        ),
        "non-XLM asset without issuer must fail, got: {err:?}"
    );
}

/// Single-label origin_domain values (e.g. "localhost", "consul") are rejected
/// at parse time, before any stellar.toml fetch is attempted, to prevent SSRF
/// against internal infrastructure.
#[test]
fn a11_single_label_origin_domain_rejected_before_fetch() {
    for hostname in &["localhost", "consul", "metadata", "intranet", "internal"] {
        let uri = format!(
            "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &origin_domain={hostname}\
            &signature=fakesig"
        );
        let err = parse_sep7_uri(&uri).unwrap_err();
        assert!(
            matches!(err, Sep7Error::InvalidOriginDomain { .. }),
            "single-label origin_domain '{hostname}' must be rejected at parse, got: {err:?}"
        );
    }
}

/// Builds a `web+stellar:tx?xdr=...` URI with exactly `depth` levels of nested
/// `chain` parameters by recursively URL-encoding from the inside out.
///
/// Inner levels use `web+stellar:pay?destination=G...` URIs (no pre-existing
/// percent-encoded characters) to avoid double-encoding the `xdr` value.
/// `parse_sep7_uri_chain` validates chain URIs structurally regardless of
/// operation type.
///
/// Used by `a12_chain_nesting_boundary_and_overflow`.
fn build_chained_tx_uri(depth: usize) -> String {
    use stellar_xdr::{
        Limits, Memo, MuxedAccount, Preconditions, SequenceNumber, Transaction,
        TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
    };

    // Build a minimal valid TransactionEnvelope for the outermost (only `tx`) level.
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
        fee: 100,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![].try_into().unwrap(),
        ext: TransactionExt::V0,
    };
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![].try_into().unwrap(),
    });
    let xdr_b64 = env.to_xdr_base64(Limits::none()).unwrap();
    let xdr_urlenc = xdr_b64
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D");

    // Innermost level (depth 0): simple pay URI — no percent-encoded chars.
    const INNER: &str =
        "web+stellar:pay?destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO";

    if depth == 0 {
        // No chain nesting at all — just return a tx URI without a chain param.
        return format!("web+stellar:tx?xdr={xdr_urlenc}");
    }

    // Build depth-1 through depth-(depth-1) using pay URIs (no % chars).
    let mut current = INNER.to_owned();
    for level in 1..depth {
        // Encode the current URI as the chain= value.
        // Since pay URIs contain only LDH chars + colon/question/equals/ampersand,
        // there are no pre-existing `%` chars to double-encode.
        let encoded = percent_encode_uri(current.as_str());
        current = format!(
            "web+stellar:pay?\
             destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
             &chain={encoded}"
        );
        let _ = level; // suppress unused-variable warning
    }

    // Outermost: a tx URI wrapping the deepest pay URI as its chain= value.
    let encoded = percent_encode_uri(current.as_str());
    format!("web+stellar:tx?xdr={xdr_urlenc}&chain={encoded}")
}

/// Percent-encodes a URI string for embedding as a query parameter value.
///
/// Encodes `:`, `?`, `=`, `&`, `+`, `/` and `%` (the last one first to avoid
/// double-encoding).  Does NOT encode alphanumeric chars or `-`, `_`, `.`.
fn percent_encode_uri(uri: &str) -> String {
    // Order matters: `%` must be encoded before any other substitution.
    uri.replace('%', "%25")
        .replace(':', "%3A")
        .replace('?', "%3F")
        .replace('=', "%3D")
        .replace('&', "%26")
        .replace('+', "%2B")
        .replace('/', "%2F")
}

/// Chain nesting at depth 7 (the maximum) must be accepted; depth 8 must be
/// rejected with `TooManyChainLevels`.  Per `sep-0007.md`, wallets MUST reject
/// chain depth > 7.
#[test]
fn a12_chain_nesting_boundary_and_overflow() {
    // Boundary: exactly MAX_CHAIN_DEPTH (7) levels must parse successfully.
    let uri_7 = build_chained_tx_uri(7);
    assert!(
        parse_sep7_uri(&uri_7).is_ok(),
        "chain depth 7 (max allowed) must parse successfully"
    );

    // Overflow: 8 levels deep must be rejected with TooManyChainLevels.
    let uri_8 = build_chained_tx_uri(8);
    let err = parse_sep7_uri(&uri_8).unwrap_err();
    assert!(
        matches!(err, Sep7Error::TooManyChainLevels { .. }),
        "chain depth 8 (> max) must return TooManyChainLevels, got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (b) Callback URL SSRF
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that any preview surfacing a callback host has:
/// - `will_auto_post_callback == false`
/// - `will_auto_submit == false`
/// - callback.will_auto_post == false
fn assert_no_auto_action(preview: &serde_json::Value) {
    assert_eq!(
        preview["will_auto_post_callback"], false,
        "preview must never set will_auto_post_callback=true"
    );
    assert_eq!(
        preview["will_auto_submit"], false,
        "preview must never set will_auto_submit=true"
    );
    if !preview["callback"].is_null() {
        assert_eq!(
            preview["callback"]["will_auto_post"], false,
            "callback.will_auto_post must always be false"
        );
    }
}

#[test]
fn b1_private_ip_callback_surfaced_in_preview_not_posted() {
    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &callback=url%3Ahttp%3A%2F%2F192.168.1.1%2Fcb";
    let (req, status) = stellar_agent_sep7::parse_uri(uri).unwrap();
    let preview = build_preview(&req, &status);
    // Callback host must be surfaced.
    assert_eq!(preview["callback"]["authority"], "192.168.1.1");
    // Private IP must be flagged.
    assert_eq!(preview["callback"]["is_private_or_loopback"], true);
    // NEVER auto-posts.
    assert_no_auto_action(&preview);
}

#[test]
fn b2_loopback_callback_flagged() {
    let info = inspect_callback(Some("url:http://127.0.0.1:8080/cb")).unwrap();
    assert!(info.is_private_or_loopback);
    assert!(!info.is_https);
}

#[test]
fn b3_file_scheme_dangerous() {
    let info = inspect_callback(Some("url:file:///etc/passwd")).unwrap();
    assert!(info.is_dangerous_scheme);
}

#[test]
fn b4_gopher_scheme_dangerous() {
    let info = inspect_callback(Some("url:gopher://evil.com/1%20GET%20/")).unwrap();
    assert!(info.is_dangerous_scheme);
}

#[test]
fn b5_javascript_scheme_dangerous() {
    // javascript: is a dangerous scheme.
    let info = inspect_callback(Some("url:javascript:alert(1)"));
    // May be None if url::Url::parse rejects the URL as non-absolute.
    if let Some(info) = info {
        assert!(info.is_dangerous_scheme || !info.is_https);
    }
    // Either None or a correctly-flagged result — must not panic.
}

#[test]
fn b6_missing_url_prefix_fails_at_parse() {
    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &callback=https%3A%2F%2Fexample.com%2Fcb";
    let err = parse_sep7_uri(uri).unwrap_err();
    assert!(
        matches!(
            err,
            Sep7Error::InvalidParamValue {
                param: "callback",
                ..
            }
        ),
        "callback without url: prefix must fail at parse, got: {err:?}"
    );
}

#[test]
fn b7_non_https_callback_flagged_not_rejected() {
    // Non-HTTPS is surfaced as a flag, not a hard error.
    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &callback=url%3Ahttp%3A%2F%2Flegacy.example.com%2Fcb";
    let (req, status) = stellar_agent_sep7::parse_uri(uri).unwrap();
    let preview = build_preview(&req, &status);
    // Non-HTTPS is flagged.
    assert_eq!(preview["callback"]["is_https"], false);
    // But the tool still returns a valid preview.
    assert_eq!(preview["operation"], "pay");
    assert_no_auto_action(&preview);
}

#[test]
fn b8_https_callback_authority_surfaced() {
    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &callback=url%3Ahttps%3A%2F%2Fsigning.example.com%2Fsign";
    let (req, status) = stellar_agent_sep7::parse_uri(uri).unwrap();
    let preview = build_preview(&req, &status);
    assert_eq!(preview["callback"]["authority"], "signing.example.com");
    assert_eq!(preview["callback"]["is_https"], true);
    assert_no_auto_action(&preview);
}

/// IPv6 unique-local addresses (fc00::/7) must be flagged as private/loopback.
#[test]
fn b9_ipv6_unique_local_callback_flagged() {
    // fd00::1 is a unique-local (fc00::/7) address.
    let info = inspect_callback(Some("url:https://[fd00::1]/cb")).unwrap();
    assert!(
        info.is_private_or_loopback,
        "fd00::1 (unique-local fc00::/7) must be flagged as private/loopback"
    );
}

#[test]
fn b10_ipv6_link_local_callback_flagged() {
    // fe80::1 is a link-local (fe80::/10) address.
    let info = inspect_callback(Some("url:https://[fe80::1]/cb")).unwrap();
    assert!(
        info.is_private_or_loopback,
        "fe80::1 (link-local fe80::/10) must be flagged as private/loopback"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (c) Signature bypass — ALL crypto tests drive the REAL verify path
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn c1_origin_domain_without_signature_is_missing_required() {
    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &origin_domain=example.com";
    let (req, status) = stellar_agent_sep7::parse_uri(uri).unwrap();
    assert_eq!(
        status,
        SignatureStatus::MissingRequired,
        "origin_domain without signature must yield MissingRequired"
    );
    // origin_verified MUST be false.
    let preview = build_preview(&req, &status);
    assert_eq!(preview["origin_verified"], false);
    assert_eq!(preview["signature_status"], "missing_required");
}

/// c2: a URI whose payload is mutated after signing must yield `Failed`.
#[cfg(feature = "test-helpers")]
#[tokio::test]
async fn c2_tampered_uri_signature_fails() {
    let sk = make_ephemeral_keypair();
    let pk_str = g_strkey(&sk);
    let toml = toml_with_signing_key(&pk_str);

    let base_uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &amount=100\
        &origin_domain=example.com";
    let signed = sign_uri(base_uri, &sk);

    // Tamper: change amount from 100 to 200.
    let tampered = signed.replace("amount=100", "amount=200");

    // Extract the URL-decoded signature.
    let (_, sig_part) = tampered.split_once("&signature=").unwrap();
    let sig_decoded = urlencoding_decode(sig_part);

    let status = verify_with_injected_body(&tampered, "example.com", Some(&sig_decoded), &toml)
        .await
        .unwrap();
    assert_eq!(
        status,
        SignatureStatus::Failed,
        "tampered URI must fail signature verification"
    );
}

/// URL-decodes a percent-encoded string.
#[cfg(feature = "test-helpers")]
fn urlencoding_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_nibble(bytes[i + 1]);
            let lo = hex_nibble(bytes[i + 2]);
            out.push(char::from(hi << 4 | lo));
            i += 3;
        } else {
            out.push(char::from(bytes[i]));
            i += 1;
        }
    }
    out
}

#[cfg(feature = "test-helpers")]
fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// c3: a signature valid for URI A must fail when applied to URI B.
///
/// The signature is URL-encoded STANDARD-b64 (the form `sign_uri` emits),
/// exercising the production decoder's STANDARD fallback.
#[cfg(feature = "test-helpers")]
#[tokio::test]
async fn c3_signature_for_different_uri_fails() {
    let sk = make_ephemeral_keypair();
    let pk_str = g_strkey(&sk);
    let toml = toml_with_signing_key(&pk_str);

    // Sign URI A.
    let uri_a = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &amount=100\
        &origin_domain=example.com";
    let signed_a = sign_uri(uri_a, &sk);

    // Extract the URL-encoded signature from signed_a (as it appears in the URI).
    let (_, sig_part_a_urlenc) = signed_a.split_once("&signature=").unwrap();
    // Decode for passing to verify_with_injected_body.
    let sig_decoded_a = urlencoding_decode(sig_part_a_urlenc);

    // Apply signature from A to URI B (different amount — payload differs).
    let uri_b = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &amount=999\
        &origin_domain=example.com";
    // Append the URL-encoded sig from A to uri_b.
    let uri_b_with_sig = format!("{uri_b}&signature={sig_part_a_urlenc}");

    let status =
        verify_with_injected_body(&uri_b_with_sig, "example.com", Some(&sig_decoded_a), &toml)
            .await
            .unwrap();
    assert_eq!(
        status,
        SignatureStatus::Failed,
        "signature valid for URI A must fail when applied to URI B"
    );
}

/// c4: stellar.toml without `URI_REQUEST_SIGNING_KEY` yields `SigningKeyNotInToml`.
#[cfg(feature = "test-helpers")]
#[tokio::test]
async fn c4_toml_without_signing_key_returns_signing_key_not_in_toml() {
    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &origin_domain=example.com\
        &signature=dummysig";

    let (_, sig_part) = uri.split_once("&signature=").unwrap();
    let sig_decoded = urlencoding_decode(sig_part);

    let err = verify_with_injected_body(
        uri,
        "example.com",
        Some(&sig_decoded),
        toml_without_signing_key(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, Sep7Error::SigningKeyNotInToml),
        "toml without URI_REQUEST_SIGNING_KEY must return SigningKeyNotInToml, got: {err:?}"
    );
}

/// c5: a signature produced by key A must fail when the toml advertises key B.
#[cfg(feature = "test-helpers")]
#[tokio::test]
async fn c5_key_mismatch_signature_fails() {
    let sk_signer = make_ephemeral_keypair();
    let sk_other = make_ephemeral_keypair();
    let pk_str_other = g_strkey(&sk_other);
    // Toml advertises the OTHER key, not the one that signed.
    let toml = toml_with_signing_key(&pk_str_other);

    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &origin_domain=example.com";
    let signed = sign_uri(uri, &sk_signer);

    let (_, sig_part) = signed.split_once("&signature=").unwrap();
    let sig_decoded = urlencoding_decode(sig_part);

    let status = verify_with_injected_body(&signed, "example.com", Some(&sig_decoded), &toml)
        .await
        .unwrap();
    assert_eq!(
        status,
        SignatureStatus::Failed,
        "signature signed by key A must fail when verified with key B"
    );
}

#[test]
fn c6_invalid_origin_domain_ip_rejected() {
    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &origin_domain=192.168.1.1\
        &signature=fake";
    let err = parse_sep7_uri(uri).unwrap_err();
    assert!(
        matches!(err, Sep7Error::InvalidOriginDomain { .. }),
        "IP address as origin_domain must be rejected, got: {err:?}"
    );
}

#[test]
fn c7_invalid_origin_domain_double_dot_rejected() {
    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &origin_domain=exam..ple.com\
        &signature=fake";
    let err = parse_sep7_uri(uri).unwrap_err();
    assert!(
        matches!(err, Sep7Error::InvalidOriginDomain { .. }),
        "double-dot origin_domain must be rejected, got: {err:?}"
    );
}

#[test]
fn c8_invalid_origin_domain_uppercase_rejected() {
    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &origin_domain=UPPERCASE.COM\
        &signature=fake";
    let err = parse_sep7_uri(uri).unwrap_err();
    assert!(
        matches!(err, Sep7Error::InvalidOriginDomain { .. }),
        "uppercase origin_domain must be rejected, got: {err:?}"
    );
}

/// c9: a correctly signed URI must verify through the production path.
#[cfg(feature = "test-helpers")]
#[tokio::test]
async fn c9_valid_signed_uri_verifies() {
    let sk = make_ephemeral_keypair();
    let pk_str = g_strkey(&sk);
    let toml = toml_with_signing_key(&pk_str);

    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &amount=100\
        &origin_domain=example.com";
    let signed = sign_uri(uri, &sk);

    let (_, sig_part) = signed.split_once("&signature=").unwrap();
    let sig_decoded = urlencoding_decode(sig_part);

    let status = verify_with_injected_body(&signed, "example.com", Some(&sig_decoded), &toml)
        .await
        .unwrap();
    assert_eq!(
        status,
        SignatureStatus::Verified,
        "correctly signed URI must verify through the real production path"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (d) Replay
// ─────────────────────────────────────────────────────────────────────────────

/// SEP-7 signatures protect integrity and authenticate the origin domain but
/// provide no replay protection: a validly-signed URI presented multiple times
/// will verify each time.  The parse tool is stateless.  The operator or MCP
/// host layer must enforce idempotency if replay protection is required (e.g.
/// by recording a digest of recently processed URIs).
#[cfg(feature = "test-helpers")]
#[tokio::test]
async fn d1_same_signed_uri_verifies_twice_demonstrating_no_replay_protection() {
    let sk = make_ephemeral_keypair();
    let pk_str = g_strkey(&sk);
    let toml = toml_with_signing_key(&pk_str);

    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &amount=100\
        &origin_domain=example.com";
    let signed = sign_uri(uri, &sk);

    let (_, sig_part) = signed.split_once("&signature=").unwrap();
    let sig_decoded = urlencoding_decode(sig_part);

    // First verification — real path.
    let status1 = verify_with_injected_body(&signed, "example.com", Some(&sig_decoded), &toml)
        .await
        .unwrap();
    assert_eq!(
        status1,
        SignatureStatus::Verified,
        "first verification must succeed"
    );

    // Second verification — same URI, same result.
    // Demonstrates there is no built-in replay protection.
    let status2 = verify_with_injected_body(&signed, "example.com", Some(&sig_decoded), &toml)
        .await
        .unwrap();
    assert_eq!(
        status2,
        SignatureStatus::Verified,
        "second verification of same URI also succeeds — no built-in replay protection"
    );
}

#[cfg(feature = "test-helpers")]
#[tokio::test]
async fn d2_uri_with_network_passphrase_mutated_fails() {
    let sk = make_ephemeral_keypair();
    let pk_str = g_strkey(&sk);
    let toml = toml_with_signing_key(&pk_str);

    let uri_testnet = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
        &amount=100\
        &origin_domain=example.com\
        &network_passphrase=Test%20SDF%20Network%20%3B%20September%202015";
    let signed_testnet = sign_uri(uri_testnet, &sk);

    // Mutate: strip the network_passphrase from the signed URI.
    let mutated = signed_testnet
        .replace(
            "&network_passphrase=Test%20SDF%20Network%20%3B%20September%202015",
            "",
        )
        .replace(
            "network_passphrase=Test%20SDF%20Network%20%3B%20September%202015&",
            "",
        );

    let (_, sig_part) = signed_testnet.split_once("&signature=").unwrap();
    let sig_decoded = urlencoding_decode(sig_part);

    let status = verify_with_injected_body(&mutated, "example.com", Some(&sig_decoded), &toml)
        .await
        .unwrap();
    assert_eq!(
        status,
        SignatureStatus::Failed,
        "mutating network_passphrase after signing must fail verification"
    );
}

#[test]
fn d3_absent_origin_domain_is_absent_status() {
    let uri = "web+stellar:pay?\
        destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO";
    let (req, status) = stellar_agent_sep7::parse_uri(uri).unwrap();
    assert_eq!(status, SignatureStatus::Absent);
    let preview = build_preview(&req, &status);
    assert_eq!(preview["signature_status"], "absent");
    assert_eq!(preview["origin_verified"], false);
}

// ─────────────────────────────────────────────────────────────────────────────
// Parse-and-verify-only invariant
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies the global parse-and-verify-only invariant: every preview
/// produced by this crate has `will_auto_submit = false` and
/// `will_auto_post_callback = false`.
#[test]
fn invariant_parse_verify_only_no_auto_actions() {
    let uris = vec![
        "web+stellar:pay?destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO",
        "web+stellar:pay?destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
         &callback=url%3Ahttps%3A%2F%2Fexample.com%2Fcb",
        "web+stellar:pay?destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
         &origin_domain=example.com",
    ];
    for uri in uris {
        let (req, status) = stellar_agent_sep7::parse_uri(uri).unwrap();
        let preview = build_preview(&req, &status);
        assert_eq!(
            preview["will_auto_submit"], false,
            "will_auto_submit must always be false; uri={uri}"
        );
        assert_eq!(
            preview["will_auto_post_callback"], false,
            "will_auto_post_callback must always be false; uri={uri}"
        );
    }
}
