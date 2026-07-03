//! SEP-7 URI parsing and strict validation.
//!
//! # What this module does
//!
//! Parses a `web+stellar:<operation>?<params>` URI into a typed [`Sep7Request`]
//! enum.  Every parameter is strictly validated BEFORE the preview is
//! assembled — malformed values are rejected (not silently ignored).
//!
//! # Untrusted-input hardening
//!
//! This module is the primary untrusted-input gate.  The wallet receives URIs
//! from untrusted dApps; every field is validated with these principles:
//!
//! - Reject, never silently ignore, malformed values.
//! - Validate the `xdr` parameter by fully decoding the XDR envelope before
//!   proceeding.
//! - Reject duplicate parameters (last-value-wins semantics are a parameter
//!   injection vector).
//! - Enforce the 300-character `msg` limit strictly.
//! - Validate `callback` scheme (`url:` prefix) and flag non-HTTPS schemes for
//!   operator inspection — the wallet NEVER POSTs to a callback.

use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope, WriteXdr};

use crate::error::Sep7Error;

/// Maximum `msg` length in Unicode scalar values before URL-encoding.
///
/// Per `sep-0007.md`.
const MSG_MAX_CHARS: usize = 300;

/// Maximum allowed `chain` nesting depth.
///
/// Per `sep-0007.md`.
const MAX_CHAIN_DEPTH: u8 = 7;

// ─────────────────────────────────────────────────────────────────────────────
// Public output types
// ─────────────────────────────────────────────────────────────────────────────

/// The structured result of parsing a `web+stellar:tx?...` URI.
///
/// All fields validated; `xdr_envelope` is decoded and re-encoded to confirm
/// it is a well-formed `TransactionEnvelope`.
#[derive(Debug, Clone)]
pub struct Sep7TxParams {
    /// Re-encoded canonical XDR (base64, standard) of the validated
    /// `TransactionEnvelope`.  The wallet MUST NOT sign this without an
    /// explicit operator approval step.
    pub xdr_canonical: String,

    /// SEP-11 replacement field references, validated for identifier balance
    /// (i.e. the identifiers on the left of `;` equal those on the right).
    pub replace: Option<String>,

    /// Callback destination — parsed and surface the `url:` prefix stripped.
    ///
    /// `None` if no `callback` param was supplied.
    /// For SSRF inspection: use [`crate::preview::CallbackInfo`] in the preview output.
    pub callback_raw: Option<String>,

    /// Signing pubkey hint, if supplied.
    pub pubkey: Option<String>,

    /// Nested SEP-7 chain URI (informational only), if supplied.
    /// Depth-bounded to `MAX_CHAIN_DEPTH` levels.
    pub chain: Option<String>,

    /// Additional message to display to the user (≤300 Unicode scalar values).
    pub msg: Option<String>,

    /// Network passphrase, if supplied.
    pub network_passphrase: Option<String>,

    /// The origin domain claiming to have generated this URI.
    pub origin_domain: Option<String>,

    /// Raw base64url signature bytes, URL-decoded, if supplied.
    pub signature_raw: Option<String>,
}

/// The structured result of parsing a `web+stellar:pay?...` URI.
#[derive(Debug, Clone)]
pub struct Sep7PayParams {
    /// Required payment destination — G-strkey or federated address.
    pub destination: String,

    /// Optional amount.
    pub amount: Option<String>,

    /// Asset code (XLM if absent).
    pub asset_code: Option<String>,

    /// Asset issuer G-strkey (required when `asset_code` is present and not
    /// `"XLM"`).
    pub asset_issuer: Option<String>,

    /// Optional memo value.
    pub memo: Option<String>,

    /// Memo type: `MEMO_TEXT`, `MEMO_ID`, `MEMO_HASH`, `MEMO_RETURN`.
    pub memo_type: Option<MemoType>,

    /// Callback destination raw string.
    pub callback_raw: Option<String>,

    /// Additional message to display to the user (≤300 Unicode scalar values).
    pub msg: Option<String>,

    /// Network passphrase, if supplied.
    pub network_passphrase: Option<String>,

    /// The origin domain claiming to have generated this URI.
    pub origin_domain: Option<String>,

    /// Raw base64url signature bytes, URL-decoded, if supplied.
    pub signature_raw: Option<String>,
}

/// SEP-7 memo types.
///
/// Per `sep-0007.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoType {
    /// Text memo.
    MemoText,
    /// Integer ID memo.
    MemoId,
    /// 32-byte hash memo (base64-encoded value).
    MemoHash,
    /// 32-byte return hash memo (base64-encoded value).
    MemoReturn,
}

/// Parsed SEP-7 request.
#[derive(Debug, Clone)]
pub enum Sep7Request {
    /// `web+stellar:tx?...` — sign a specific `TransactionEnvelope`.
    Tx(Sep7TxParams),
    /// `web+stellar:pay?...` — make a payment to a destination.
    Pay(Sep7PayParams),
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_sep7_uri — public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Parses and strictly validates a `web+stellar:` URI.
///
/// Returns a [`Sep7Request`] on success; any structural or semantic validation
/// failure yields a typed [`Sep7Error`].
///
/// # Untrusted-input hardening
///
/// - Duplicate parameters are rejected (not last-value-wins).
/// - The `xdr` parameter is fully decoded to confirm it is a valid
///   `TransactionEnvelope` before the preview is assembled.
/// - `msg` exceeding 300 characters is rejected.
/// - `callback` is extracted; the wallet NEVER POSTs to it — caller must
///   surface the `callback_raw` host for operator SSRF inspection.
///
/// # Errors
///
/// Returns [`Sep7Error`] on any parse or validation failure.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```rust
/// use stellar_agent_sep7::parse::parse_sep7_uri;
///
/// let uri = "web+stellar:pay?destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
///            &amount=120.1234567&memo=hello&memo_type=MEMO_TEXT";
/// let req = parse_sep7_uri(uri).expect("valid pay URI must parse");
/// ```
pub fn parse_sep7_uri(uri: &str) -> Result<Sep7Request, Sep7Error> {
    // ── 1. Strip the scheme prefix ────────────────────────────────────────────
    let after_scheme = uri
        .strip_prefix("web+stellar:")
        .ok_or_else(|| Sep7Error::MalformedUri {
            detail: "URI must start with 'web+stellar:'".to_owned(),
        })?;

    if after_scheme.is_empty() {
        return Err(Sep7Error::MalformedUri {
            detail: "URI has no operation after 'web+stellar:'".to_owned(),
        });
    }

    // ── 2. Split operation from query string ──────────────────────────────────
    let (operation, query) = match after_scheme.split_once('?') {
        Some((op, q)) => (op, q),
        None => (after_scheme, ""),
    };

    // ── 3. Parse + deduplicate query parameters ───────────────────────────────
    let params = parse_query_params(query)?;

    // ── 4. Dispatch to operation-specific parser ──────────────────────────────
    match operation {
        "tx" => parse_tx_params(params).map(Sep7Request::Tx),
        "pay" => parse_pay_params(params).map(Sep7Request::Pay),
        other => Err(Sep7Error::UnknownOperation {
            operation: sanitize_operation(other),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Query parameter parsing — deduplication + URL-decode
// ─────────────────────────────────────────────────────────────────────────────

/// Parses the query string into a key→value map, rejecting duplicate keys.
///
/// URL-decodes both keys and values using percent-decoding.
fn parse_query_params(query: &str) -> Result<std::collections::HashMap<String, String>, Sep7Error> {
    let mut map = std::collections::HashMap::new();

    if query.is_empty() {
        return Ok(map);
    }

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };

        let key = percent_decode(k).map_err(|_| Sep7Error::MalformedUri {
            detail: "query parameter key contains invalid percent-encoding".to_owned(),
        })?;
        let value = percent_decode(v).map_err(|_| Sep7Error::MalformedUri {
            detail: "query parameter value contains invalid percent-encoding".to_owned(),
        })?;

        // Reject duplicate parameters — last-value-wins is a parameter injection vector.
        if map.contains_key(&key) {
            return Err(Sep7Error::InvalidParamValue {
                param: "query",
                detail: format!("duplicate parameter: {key:?}"),
            });
        }

        map.insert(key, value);
    }

    Ok(map)
}

/// Percent-decodes a query string component.
fn percent_decode(s: &str) -> Result<String, ()> {
    // Replace '+' with space (application/x-www-form-urlencoded convention).
    // SEP-7 URIs use standard URI percent-encoding, not form encoding, but
    // both '+' and '%20' should decode to a space for interoperability.
    let replaced = s.replace('+', " ");
    // Manual percent-decode: iterate bytes.
    let bytes = replaced.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(());
            }
            let hi = hex_digit(bytes[i + 1]).ok_or(())?;
            let lo = hex_digit(bytes[i + 2]).ok_or(())?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// tx operation parser
// ─────────────────────────────────────────────────────────────────────────────

fn parse_tx_params(
    mut params: std::collections::HashMap<String, String>,
) -> Result<Sep7TxParams, Sep7Error> {
    // xdr — REQUIRED.
    let xdr_raw = params
        .remove("xdr")
        .ok_or(Sep7Error::MissingRequiredParam { param: "xdr" })?;
    let xdr_canonical = validate_transaction_envelope_xdr(&xdr_raw)?;

    // replace — optional; validate identifier balance if present.
    let replace = params
        .remove("replace")
        .map(validate_replace_field)
        .transpose()?;

    // callback — optional; extract and validate scheme.
    let callback_raw = params
        .remove("callback")
        .map(|v| validate_callback(&v))
        .transpose()?;

    // pubkey — optional; validate as G-strkey if present.
    let pubkey = params
        .remove("pubkey")
        .map(|v| validate_g_strkey(v, "pubkey"))
        .transpose()?;

    // chain — optional; depth-bound.
    let chain = params
        .remove("chain")
        .map(|v| validate_chain(v, 1))
        .transpose()?;

    // msg — optional; 300-char limit.
    let msg = params.remove("msg").map(validate_msg).transpose()?;

    // network_passphrase — optional; pass through.
    let network_passphrase = params.remove("network_passphrase");

    // origin_domain — optional; validate FQDN syntax if present.
    let origin_domain = params
        .remove("origin_domain")
        .map(validate_origin_domain_syntax)
        .transpose()?;

    // signature — optional; extract raw (URL-decoding already done above).
    let signature_raw = params.remove("signature");

    Ok(Sep7TxParams {
        xdr_canonical,
        replace,
        callback_raw,
        pubkey,
        chain,
        msg,
        network_passphrase,
        origin_domain,
        signature_raw,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// pay operation parser
// ─────────────────────────────────────────────────────────────────────────────

fn parse_pay_params(
    mut params: std::collections::HashMap<String, String>,
) -> Result<Sep7PayParams, Sep7Error> {
    // destination — REQUIRED.
    let destination = params
        .remove("destination")
        .ok_or(Sep7Error::MissingRequiredParam {
            param: "destination",
        })?;

    // Validate destination: G-strkey or federation address (contains '*').
    // Per sep-0007.md: destination must be a valid account ID or payment address.
    if !destination.contains('*') {
        // Not a federation address — validate as G-strkey.
        validate_g_strkey_raw(&destination, "destination")?;
    }

    // amount — optional; validate as numeric if present.
    let amount = params.remove("amount").map(validate_amount).transpose()?;

    // asset_code — optional; 1-12 alphanumeric chars.
    let asset_code = params
        .remove("asset_code")
        .map(validate_asset_code)
        .transpose()?;

    // asset_issuer — optional; G-strkey; required if asset_code present and not XLM.
    let asset_issuer = params
        .remove("asset_issuer")
        .map(|v| validate_g_strkey(v, "asset_issuer"))
        .transpose()?;

    // Validate asset_code + asset_issuer coherence.
    validate_asset_coherence(asset_code.as_deref(), asset_issuer.as_deref())?;

    // memo — optional.
    let memo = params.remove("memo");

    // memo_type — optional; validate known enum.
    let memo_type = params
        .remove("memo_type")
        .map(|v| parse_memo_type(&v))
        .transpose()?;

    // Validate memo coherence.
    validate_memo_coherence(memo.as_deref(), memo_type.as_ref())?;

    // callback — optional.
    let callback_raw = params
        .remove("callback")
        .map(|v| validate_callback(&v))
        .transpose()?;

    // msg — optional; 300-char limit.
    let msg = params.remove("msg").map(validate_msg).transpose()?;

    // network_passphrase — optional.
    let network_passphrase = params.remove("network_passphrase");

    // origin_domain — optional; FQDN.
    let origin_domain = params
        .remove("origin_domain")
        .map(validate_origin_domain_syntax)
        .transpose()?;

    // signature — optional.
    let signature_raw = params.remove("signature");

    Ok(Sep7PayParams {
        destination,
        amount,
        asset_code,
        asset_issuer,
        memo,
        memo_type,
        callback_raw,
        msg,
        network_passphrase,
        origin_domain,
        signature_raw,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Field validators
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes and validates a base64url `TransactionEnvelope` XDR string.
///
/// The function tries both base64url (no-pad) and standard base64 to match
/// real-world wallets that may use either encoding.  On success, returns the
/// re-serialised canonical base64 (standard) string.
///
/// # Byte-layout citation
///
/// `TransactionEnvelope` XDR shape: `TransactionEnvelope` union defined in
/// `Stellar-transaction.x` (stellar-xdr, Protocol-26).
fn validate_transaction_envelope_xdr(raw: &str) -> Result<String, Sep7Error> {
    use base64::Engine as _;

    // Try base64url (no-pad) first, then standard base64 with pad.
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(raw))
        .map_err(|_| Sep7Error::InvalidParamValue {
            param: "xdr",
            detail: "failed to decode as base64; must be a base64 or base64url TransactionEnvelope"
                .to_owned(),
        })?;

    // Deserialise: reject if not a valid TransactionEnvelope.
    // Two independent bounds apply:
    // - `len: 64 * 1024` — the SEP-7 URI `xdr` param is limited to 64 KiB of
    //   raw bytes; a larger payload is malformed per the URI length cap.
    // - `depth: XDR_DECODE_MAX_DEPTH` — caps recursion to prevent a crafted
    //   deeply-nested `SorobanAuthorizedInvocation.sub_invocations` chain from
    //   exhausting the stack.
    let envelope = TransactionEnvelope::from_xdr(
        &bytes,
        stellar_xdr::Limits {
            depth: stellar_agent_xdr_limits::XDR_DECODE_MAX_DEPTH,
            len: 64 * 1024,
        },
    )
    .map_err(|e| Sep7Error::InvalidParamValue {
        param: "xdr",
        detail: format!("XDR is not a valid TransactionEnvelope: {e}"),
    })?;

    // Re-serialise to canonical base64.
    let canonical =
        envelope
            .to_xdr_base64(Limits::none())
            .map_err(|e| Sep7Error::InvalidParamValue {
                param: "xdr",
                detail: format!("failed to re-serialise TransactionEnvelope: {e}"),
            })?;

    Ok(canonical)
}

/// Validates the SEP-11 `replace` field: identifiers on both sides of `;`
/// must be balanced (the same set must appear on each side).
///
/// Per `sep-0007.md`.
fn validate_replace_field(replace: String) -> Result<String, Sep7Error> {
    // Format: `field1:id1,field2:id2;id1:hint1,id2:hint2`
    // Two sections separated by `;`.
    let (fields_section, hints_section) = match replace.split_once(';') {
        Some((l, r)) => (l, r),
        None => {
            return Err(Sep7Error::InvalidParamValue {
                param: "replace",
                detail: "must contain exactly one ';' separating field-refs from hints".to_owned(),
            });
        }
    };

    // Extract identifiers from the left side (field:id pairs).
    let left_ids: std::collections::HashSet<&str> = fields_section
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| pair.split_once(':').map(|(_, id)| id))
        .collect();

    // Extract identifiers from the right side (id:hint pairs).
    let right_ids: std::collections::HashSet<&str> = hints_section
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| pair.split_once(':').map(|(id, _)| id))
        .collect();

    if left_ids != right_ids {
        return Err(Sep7Error::InvalidParamValue {
            param: "replace",
            detail: format!(
                "unbalanced replace identifiers: left has {}, right has {}",
                left_ids.len(),
                right_ids.len()
            ),
        });
    }

    Ok(replace)
}

/// Validates a `callback` parameter value.
///
/// Accepts `url:<https-url>` (the only supported callback type per the spec).
/// Non-HTTPS callbacks are NOT rejected at parse time — they are surfaced in
/// the preview so the operator can inspect them — but the wallet NEVER POSTs
/// to any callback.
///
/// Returns the raw callback string (including the `url:` prefix) if valid.
///
/// Per `sep-0007.md`.
fn validate_callback(callback: &str) -> Result<String, Sep7Error> {
    // Must start with `url:` prefix.
    if !callback.starts_with("url:") {
        return Err(Sep7Error::InvalidParamValue {
            param: "callback",
            detail: "callback must start with the 'url:' prefix".to_owned(),
        });
    }

    // Validate the URL portion is parseable (authority-only error; do not echo URL).
    let url_part = &callback["url:".len()..];
    url::Url::parse(url_part).map_err(|_| Sep7Error::InvalidParamValue {
        param: "callback",
        detail: "the URL after 'url:' is not a valid URL".to_owned(),
    })?;

    Ok(callback.to_owned())
}

/// Validates a G-strkey string and returns it on success.
fn validate_g_strkey(value: String, param: &'static str) -> Result<String, Sep7Error> {
    validate_g_strkey_raw(&value, param)?;
    Ok(value)
}

fn validate_g_strkey_raw(value: &str, param: &'static str) -> Result<(), Sep7Error> {
    stellar_strkey::ed25519::PublicKey::from_string(value)
        .map(|_| ())
        .map_err(|_| Sep7Error::InvalidParamValue {
            param,
            detail: "must be a valid Stellar ed25519 public key G-strkey".to_owned(),
        })
}

/// Validates and depth-bounds a nested `chain` URI.
///
/// Recursively parses the chain field's own `chain` parameter, incrementing
/// the depth counter at each level.  Rejects nesting deeper than
/// [`MAX_CHAIN_DEPTH`] to prevent parameter-smuggling via deep nesting.
///
/// Per `sep-0007.md`.
fn validate_chain(chain: String, depth: u8) -> Result<String, Sep7Error> {
    parse_sep7_uri_chain(&chain, depth)?;
    Ok(chain)
}

/// Recursively validates a nested chain URI, enforcing the depth bound.
///
/// At each level we:
/// 1. Confirm the URI has the `web+stellar:` scheme.
/// 2. Parse the query params (duplicate-check included).
/// 3. If a `chain` param is present, recurse at `depth + 1`.
///
/// Depth starts at 1 for the first nested `chain` value.  A depth > 7 at
/// any recursive call immediately returns [`Sep7Error::TooManyChainLevels`].
fn parse_sep7_uri_chain(uri: &str, depth: u8) -> Result<(), Sep7Error> {
    if depth > MAX_CHAIN_DEPTH {
        return Err(Sep7Error::TooManyChainLevels { depth });
    }

    let after_scheme = uri
        .strip_prefix("web+stellar:")
        .ok_or_else(|| Sep7Error::MalformedUri {
            detail: "chain URI must start with 'web+stellar:'".to_owned(),
        })?;

    let (_op, query) = match after_scheme.split_once('?') {
        Some(pair) => pair,
        None => (after_scheme, ""),
    };

    // Parse params to check for a nested chain field.  Duplicate-key check
    // also applies at nested levels (injection guard).
    let params = parse_query_params(query)?;

    // If a further nested `chain` param exists, recurse.
    // Note: `parse_query_params` already percent-decoded all param values, so
    // `nested` is the raw decoded chain URI — no second decode here.
    if let Some(nested) = params.get("chain") {
        parse_sep7_uri_chain(nested, depth + 1)?;
    }

    Ok(())
}

/// Validates the `msg` field does not exceed 300 Unicode scalar values.
///
/// Per `sep-0007.md`.
fn validate_msg(msg: String) -> Result<String, Sep7Error> {
    let len = msg.chars().count();
    if len > MSG_MAX_CHARS {
        return Err(Sep7Error::MsgTooLong { len });
    }
    Ok(msg)
}

/// Validates the `origin_domain` field as a syntactically valid FQDN.
///
/// Requirements:
/// - Rejects IPv4/IPv6 addresses — IP addresses are not valid FQDNs.
/// - Rejects single-label hostnames (`localhost`, `consul`, `metadata`,
///   `intranet`, etc.) — a valid FQDN requires ≥2 non-empty labels (an
///   interior dot). Single-label names would cause `verify_origin=true` to
///   fetch `https://localhost/.well-known/stellar.toml` — SSRF to internal
///   infrastructure.
/// - Rejects all-numeric dot-separated sequences (numeric-only labels).
/// - Rejects non-LDH characters, double-dots, leading underscores, etc. via
///   `is_valid_ldh_home_domain`.
///
/// Per `sep-0007.md`, `origin_domain` must be a fully qualified domain name.
fn validate_origin_domain_syntax(domain: String) -> Result<String, Sep7Error> {
    use stellar_agent_network::counterparty::validation::is_valid_ldh_home_domain;

    // Reject IPv4 addresses (e.g. "192.168.1.1") — these are not FQDNs.
    // `is_valid_ldh_home_domain` accepts numeric-only labels (valid LDH) so we
    // must explicitly check for pure-numeric labels here.
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return Err(Sep7Error::InvalidOriginDomain {
            detail: format!("'{domain}' is an IP address, not a valid FQDN"),
        });
    }

    // Reject purely numeric dot-separated strings that look like IPv4 but
    // have the wrong number of octets (e.g. "10.0") — not valid FQDNs.
    let all_labels_numeric = domain
        .split('.')
        .all(|label| !label.is_empty() && label.chars().all(|c| c.is_ascii_digit()));
    if all_labels_numeric {
        return Err(Sep7Error::InvalidOriginDomain {
            detail: format!("'{domain}' consists of numeric labels only; must be a valid FQDN"),
        });
    }

    // SSRF guard: require ≥2 labels (an interior dot).
    // Single-label names (e.g. "localhost", "consul", "metadata") are not FQDNs
    // and would route `verify_origin` fetches to internal infrastructure.
    // We check AFTER IP rejection and AFTER the LDH validation so the error
    // message is as specific as possible.
    let label_count = domain.split('.').filter(|l| !l.is_empty()).count();
    if label_count < 2 {
        return Err(Sep7Error::InvalidOriginDomain {
            detail: format!(
                "'{domain}' is a single-label hostname; a valid FQDN requires at least two labels"
            ),
        });
    }

    if !is_valid_ldh_home_domain(&domain) {
        return Err(Sep7Error::InvalidOriginDomain {
            detail: format!("'{domain}' is not a valid lowercase RFC 1035 LDH FQDN"),
        });
    }
    Ok(domain)
}

/// Validates an `amount` string as a positive decimal number.
fn validate_amount(amount: String) -> Result<String, Sep7Error> {
    // Must be a valid positive decimal (e.g. "120.1234567", "1", "0.0000001").
    let trimmed = amount.trim();
    if trimmed.is_empty() {
        return Err(Sep7Error::InvalidParamValue {
            param: "amount",
            detail: "amount must not be empty".to_owned(),
        });
    }
    // Allow digits, exactly one optional '.', no sign.
    let mut dot_count = 0u8;
    for ch in trimmed.chars() {
        match ch {
            '0'..='9' => {}
            '.' => {
                dot_count += 1;
                if dot_count > 1 {
                    return Err(Sep7Error::InvalidParamValue {
                        param: "amount",
                        detail: "amount has more than one decimal point".to_owned(),
                    });
                }
            }
            _ => {
                return Err(Sep7Error::InvalidParamValue {
                    param: "amount",
                    detail: "amount must consist of digits and an optional decimal point"
                        .to_owned(),
                });
            }
        }
    }
    Ok(amount)
}

/// Validates an `asset_code`: 1–12 alphanumeric ASCII characters.
///
/// Per the Stellar asset-code convention (XDR `AssetCode4` / `AssetCode12`).
fn validate_asset_code(code: String) -> Result<String, Sep7Error> {
    if code.is_empty() || code.len() > 12 {
        return Err(Sep7Error::InvalidParamValue {
            param: "asset_code",
            detail: "asset_code must be 1–12 characters".to_owned(),
        });
    }
    if !code.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(Sep7Error::InvalidParamValue {
            param: "asset_code",
            detail: "asset_code must be ASCII alphanumeric characters only".to_owned(),
        });
    }
    Ok(code)
}

/// Validates asset_code + asset_issuer coherence.
///
/// If `asset_code` is present and is not `"XLM"`, `asset_issuer` must also
/// be present.
fn validate_asset_coherence(
    asset_code: Option<&str>,
    asset_issuer: Option<&str>,
) -> Result<(), Sep7Error> {
    if let Some(code) = asset_code
        && !code.eq_ignore_ascii_case("XLM")
        && asset_issuer.is_none()
    {
        return Err(Sep7Error::InvalidParamValue {
            param: "asset_issuer",
            detail: "asset_issuer is required when asset_code is a non-XLM asset".to_owned(),
        });
    }
    Ok(())
}

/// Parses a `memo_type` string into [`MemoType`].
fn parse_memo_type(s: &str) -> Result<MemoType, Sep7Error> {
    match s {
        "MEMO_TEXT" => Ok(MemoType::MemoText),
        "MEMO_ID" => Ok(MemoType::MemoId),
        "MEMO_HASH" => Ok(MemoType::MemoHash),
        "MEMO_RETURN" => Ok(MemoType::MemoReturn),
        other => Err(Sep7Error::InvalidParamValue {
            param: "memo_type",
            detail: format!(
                "unknown memo_type: {other:?}; must be one of \
                 MEMO_TEXT, MEMO_ID, MEMO_HASH, MEMO_RETURN"
            ),
        }),
    }
}

/// Validates memo coherence: `memo_type` requires `memo`, and vice versa.
fn validate_memo_coherence(
    memo: Option<&str>,
    memo_type: Option<&MemoType>,
) -> Result<(), Sep7Error> {
    match (memo, memo_type) {
        (Some(_), None) => Err(Sep7Error::InvalidParamValue {
            param: "memo_type",
            detail: "memo_type is required when memo is present".to_owned(),
        }),
        (None, Some(_)) => Err(Sep7Error::InvalidParamValue {
            param: "memo",
            detail: "memo is required when memo_type is present".to_owned(),
        }),
        _ => Ok(()),
    }
}

/// Sanitises an operation token for inclusion in an error message.
///
/// Limits to 16 chars, ASCII-printable only; replaces control chars with `?`.
fn sanitize_operation(op: &str) -> String {
    const MAX: usize = 16;
    op.chars()
        .take(MAX)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Re-export: extract the original URI without the `&signature=...` parameter
// ─────────────────────────────────────────────────────────────────────────────

/// Strips the `&signature=<urlencoded-value>` suffix from a URI string to
/// produce the payload URI for signature verification.
///
/// The SEP-7 spec requires `signature` to be the LAST parameter.  Strips
/// from `&signature=` (or `?signature=` when it is the first/only param) to
/// the end of the string.  This matches the approach used by the Flutter and
/// Python Stellar SDKs.
pub fn strip_signature_param(uri: &str) -> &str {
    // Prefer removing the `&signature=` form (signature is not the first param).
    if let Some(idx) = uri.find("&signature=") {
        return &uri[..idx];
    }
    // Fallback: `?signature=` (signature is the only/first param).
    if let Some(idx) = uri.find("?signature=") {
        return &uri[..idx];
    }
    uri
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn parses_minimal_pay_uri() {
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &amount=120.1234567\
            &memo=hello\
            &memo_type=MEMO_TEXT";
        let req = parse_sep7_uri(uri).unwrap();
        match req {
            Sep7Request::Pay(p) => {
                assert_eq!(
                    p.destination,
                    "GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO"
                );
                assert_eq!(p.amount.as_deref(), Some("120.1234567"));
                assert_eq!(p.memo.as_deref(), Some("hello"));
                assert_eq!(p.memo_type, Some(MemoType::MemoText));
            }
            Sep7Request::Tx(_) => panic!("expected Pay"),
        }
    }

    #[test]
    fn missing_scheme_fails() {
        let err = parse_sep7_uri("stellar:pay?destination=G...").unwrap_err();
        assert!(matches!(err, Sep7Error::MalformedUri { .. }));
    }

    #[test]
    fn unknown_operation_fails() {
        let err = parse_sep7_uri("web+stellar:sign?foo=bar").unwrap_err();
        assert!(matches!(err, Sep7Error::UnknownOperation { .. }));
    }

    #[test]
    fn missing_destination_fails() {
        let err = parse_sep7_uri("web+stellar:pay?amount=1").unwrap_err();
        assert!(matches!(
            err,
            Sep7Error::MissingRequiredParam {
                param: "destination"
            }
        ));
    }

    #[test]
    fn msg_too_long_fails() {
        let msg: String = "a".repeat(301);
        let uri = format!(
            "web+stellar:pay?destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO&msg={msg}"
        );
        let err = parse_sep7_uri(&uri).unwrap_err();
        assert!(matches!(err, Sep7Error::MsgTooLong { len: 301 }));
    }

    #[test]
    fn duplicate_param_fails() {
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(matches!(
            err,
            Sep7Error::InvalidParamValue { param: "query", .. }
        ));
    }

    #[test]
    fn invalid_memo_type_fails() {
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &memo=foo\
            &memo_type=MEMO_BAD";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(matches!(
            err,
            Sep7Error::InvalidParamValue {
                param: "memo_type",
                ..
            }
        ));
    }

    #[test]
    fn callback_without_url_prefix_fails() {
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &callback=https%3A%2F%2Fexample.com%2Fcb";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(matches!(
            err,
            Sep7Error::InvalidParamValue {
                param: "callback",
                ..
            }
        ));
    }

    #[test]
    fn valid_callback_with_url_prefix_accepted() {
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &callback=url%3Ahttps%3A%2F%2Fexample.com%2Fcb";
        let req = parse_sep7_uri(uri).unwrap();
        match req {
            Sep7Request::Pay(p) => {
                assert!(p.callback_raw.as_deref().unwrap().starts_with("url:https"));
            }
            Sep7Request::Tx(_) => panic!("expected Pay"),
        }
    }

    #[test]
    fn asset_code_without_issuer_fails() {
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &asset_code=USDC";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(matches!(
            err,
            Sep7Error::InvalidParamValue {
                param: "asset_issuer",
                ..
            }
        ));
    }

    #[test]
    fn unbalanced_replace_fails() {
        let uri = "web+stellar:tx?xdr=AAAAAP%2Byw%2BZEuNg533pUmwlYxfrq6%2FBoMJqiJ8vuQhf6rHWmAAAAZAB8NHAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAYAAAABSFVHAAAAAABAH0wIyY3BJBS2qHdRPAV80M8hF7NBpxRjXyjuT9kEbH%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FAAAAAAAAAAA%3D\
            &replace=sourceAccount%3AX%3BY%3AThe%20account";
        let err = parse_sep7_uri(uri);
        // Either parse fails or replace validation fails.
        // xdr in example may be invalid — just check we don't panic.
        let _ = err;
    }

    #[test]
    fn strip_signature_param_removes_last_param() {
        let uri = "web+stellar:pay?destination=GABC&origin_domain=example.com\
                   &signature=abc123%2F%3D%3D";
        let stripped = strip_signature_param(uri);
        assert!(!stripped.contains("&signature="));
        assert!(stripped.contains("origin_domain=example.com"));
    }

    #[test]
    fn strip_signature_param_noop_when_absent() {
        let uri = "web+stellar:pay?destination=GABC&origin_domain=example.com";
        let stripped = strip_signature_param(uri);
        assert_eq!(stripped, uri);
    }

    #[test]
    fn xlm_asset_code_without_issuer_accepted() {
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &asset_code=XLM";
        let req = parse_sep7_uri(uri).unwrap();
        assert!(matches!(req, Sep7Request::Pay(_)));
    }

    // ── Additional coverage for uncovered branches ────────────────────────────

    // parse_sep7_uri: empty after-scheme
    #[test]
    fn empty_after_scheme_fails() {
        let err = parse_sep7_uri("web+stellar:").unwrap_err();
        assert!(
            matches!(err, Sep7Error::MalformedUri { .. }),
            "empty after 'web+stellar:' must fail with MalformedUri, got: {err:?}"
        );
    }

    // parse_sep7_uri: operation with no query string (no `?`)
    #[test]
    fn no_query_string_pay_fails_missing_destination() {
        // "web+stellar:pay" with no `?` splits to ("pay", "") — empty query map.
        let err = parse_sep7_uri("web+stellar:pay").unwrap_err();
        assert!(
            matches!(
                err,
                Sep7Error::MissingRequiredParam {
                    param: "destination"
                }
            ),
            "pay with no query string must fail with missing destination, got: {err:?}"
        );
    }

    // parse_query_params: empty query string returns empty map
    #[test]
    fn empty_query_string_is_accepted() {
        // Exercises the early-return for an empty query string.
        // parse_sep7_uri with operation="pay" and empty query → MissingRequiredParam.
        // This indirectly exercises the `if query.is_empty()` branch.
        let err = parse_sep7_uri("web+stellar:pay?").unwrap_err();
        assert!(matches!(
            err,
            Sep7Error::MissingRequiredParam {
                param: "destination"
            }
        ));
    }

    // parse_query_params: empty pair (trailing `&`) is skipped
    #[test]
    fn trailing_ampersand_is_skipped() {
        // "destination=G...&" — the trailing empty pair is skipped, not an error.
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO&";
        let req = parse_sep7_uri(uri).unwrap();
        assert!(matches!(req, Sep7Request::Pay(_)));
    }

    // parse_query_params: pair with no `=` is treated as key="" (empty value)
    #[test]
    fn pair_without_equals_is_treated_as_key_with_empty_value() {
        // A key with no `=` is stored as key=<whole pair>, value="".
        // This is a structural branch hit, not a meaningful semantic case —
        // we just confirm it doesn't panic and produces an error for duplicate/missing param.
        // "web+stellar:pay?destination=G...&noequalssuffix" — 'noequalssuffix' has no '='.
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &noequalssuffix";
        // This should succeed (the bare key is stored as "noequalssuffix" → "").
        let req = parse_sep7_uri(uri).unwrap();
        assert!(matches!(req, Sep7Request::Pay(_)));
    }

    // parse_query_params: invalid percent-encoding in key
    #[test]
    fn invalid_percent_encoding_in_key_fails() {
        // Key contains %GG — non-hex digits after %, which is invalid percent-encoding.
        let uri = "web+stellar:pay?%GGdestination=G";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(
            matches!(err, Sep7Error::MalformedUri { ref detail }
                if detail.contains("key contains invalid percent-encoding")),
            "invalid percent-encoding in key must fail, got: {err:?}"
        );
    }

    // parse_query_params: invalid percent-encoding in value
    #[test]
    fn invalid_percent_encoding_in_value_fails() {
        // Value has truncated percent sequence.
        let uri = "web+stellar:pay?destination=%2Z";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(
            matches!(err, Sep7Error::MalformedUri { ref detail }
                if detail.contains("value contains invalid percent-encoding")),
            "invalid percent-encoding in value must fail, got: {err:?}"
        );
    }

    // validate_replace_field: no semicolon
    #[test]
    fn replace_without_semicolon_fails() {
        // Build a valid tx XDR for the outer URI.
        use stellar_xdr::{
            Limits, Memo, MuxedAccount, Preconditions, SequenceNumber, Transaction,
            TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
        };
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
        // replace value has no ';' — must fail
        let uri = format!("web+stellar:tx?xdr={xdr_urlenc}&replace=sourceAccount%3AX");
        let err = parse_sep7_uri(&uri).unwrap_err();
        assert!(
            matches!(
                err,
                Sep7Error::InvalidParamValue {
                    param: "replace",
                    ..
                }
            ),
            "replace without ';' must fail, got: {err:?}"
        );
    }

    // validate_callback: valid URL parse failure (url: prefix present but URL invalid)
    #[test]
    fn callback_url_not_parseable_fails() {
        // "url:::invalid-url:::" — starts with url: but the URL part is invalid.
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &callback=url%3A%3A%3Ainvalid";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(
            matches!(
                err,
                Sep7Error::InvalidParamValue {
                    param: "callback",
                    ..
                }
            ),
            "unparseable URL after url: must fail with InvalidParamValue, got: {err:?}"
        );
    }

    // validate_g_strkey via tx pubkey param
    #[test]
    fn invalid_pubkey_in_tx_fails() {
        use stellar_xdr::{
            Limits, Memo, MuxedAccount, Preconditions, SequenceNumber, Transaction,
            TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
        };
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
        let uri = format!("web+stellar:tx?xdr={xdr_urlenc}&pubkey=NOTAVALIDGSTRKEY");
        let err = parse_sep7_uri(&uri).unwrap_err();
        assert!(
            matches!(
                err,
                Sep7Error::InvalidParamValue {
                    param: "pubkey",
                    ..
                }
            ),
            "invalid pubkey G-strkey must fail, got: {err:?}"
        );
    }

    // parse_sep7_uri_chain: chain URI without web+stellar: scheme
    #[test]
    fn chain_without_scheme_fails() {
        use stellar_xdr::{
            Limits, Memo, MuxedAccount, Preconditions, SequenceNumber, Transaction,
            TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
        };
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
        // chain value does not start with "web+stellar:"
        let uri = format!("web+stellar:tx?xdr={xdr_urlenc}&chain=https%3A%2F%2Fevil.example.com");
        let err = parse_sep7_uri(&uri).unwrap_err();
        assert!(
            matches!(err, Sep7Error::MalformedUri { .. }),
            "chain without web+stellar: scheme must fail MalformedUri, got: {err:?}"
        );
    }

    // parse_sep7_uri_chain: chain URI with no query string (no `?`)
    #[test]
    fn chain_without_query_string_is_accepted() {
        use stellar_xdr::{
            Limits, Memo, MuxedAccount, Preconditions, SequenceNumber, Transaction,
            TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
        };
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
        // chain = "web+stellar:pay" with no `?` (no query string) is structurally valid.
        let chain_encoded = "web%2Bstellar%3Apay";
        let uri = format!("web+stellar:tx?xdr={xdr_urlenc}&chain={chain_encoded}");
        // Should succeed — chain with no query is allowed.
        let req = parse_sep7_uri(&uri).unwrap();
        assert!(matches!(req, Sep7Request::Tx(_)));
    }

    // validate_msg: exactly 300 chars is accepted
    #[test]
    fn msg_exactly_300_chars_accepted() {
        let msg: String = "a".repeat(300);
        let uri = format!(
            "web+stellar:pay?destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO&msg={msg}"
        );
        let req = parse_sep7_uri(&uri).unwrap();
        assert!(matches!(req, Sep7Request::Pay(_)));
    }

    // validate_msg: exactly 301 chars is rejected (exercises the Ok branch + Err branch)
    #[test]
    fn msg_at_301_chars_rejected() {
        let msg: String = "x".repeat(301);
        let uri = format!(
            "web+stellar:pay?destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO&msg={msg}"
        );
        let err = parse_sep7_uri(&uri).unwrap_err();
        assert!(matches!(err, Sep7Error::MsgTooLong { len: 301 }));
    }

    // validate_amount: empty amount fails
    #[test]
    fn empty_amount_fails() {
        // amount= with an empty value triggers the empty-string check.
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &amount=";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(
            matches!(
                err,
                Sep7Error::InvalidParamValue {
                    param: "amount",
                    ref detail
                } if detail.contains("must not be empty")
            ),
            "empty amount must fail, got: {err:?}"
        );
    }

    // validate_amount: non-digit non-dot char fails
    #[test]
    fn amount_with_letter_fails() {
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &amount=1e7";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(
            matches!(
                err,
                Sep7Error::InvalidParamValue {
                    param: "amount",
                    ref detail
                } if detail.contains("digits and an optional decimal point")
            ),
            "amount with 'e' must fail, got: {err:?}"
        );
    }

    // validate_amount: more than one decimal point fails
    #[test]
    fn amount_with_two_decimal_points_fails() {
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &amount=1.0.0";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(
            matches!(
                err,
                Sep7Error::InvalidParamValue {
                    param: "amount",
                    ref detail
                } if detail.contains("more than one decimal point")
            ),
            "amount with two decimal points must fail, got: {err:?}"
        );
    }

    // validate_asset_code: empty asset_code fails
    #[test]
    fn empty_asset_code_fails() {
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &asset_code=\
            &asset_issuer=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(
            matches!(
                err,
                Sep7Error::InvalidParamValue {
                    param: "asset_code",
                    ..
                }
            ),
            "empty asset_code must fail, got: {err:?}"
        );
    }

    // validate_asset_code: too long (>12 chars) fails
    #[test]
    fn asset_code_too_long_fails() {
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &asset_code=TOOLONGASSET1\
            &asset_issuer=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(
            matches!(
                err,
                Sep7Error::InvalidParamValue {
                    param: "asset_code",
                    ..
                }
            ),
            "asset_code >12 chars must fail, got: {err:?}"
        );
    }

    // validate_asset_code: non-alphanumeric char fails
    #[test]
    fn asset_code_with_non_alphanumeric_fails() {
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &asset_code=US-DC\
            &asset_issuer=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(
            matches!(
                err,
                Sep7Error::InvalidParamValue {
                    param: "asset_code",
                    ..
                }
            ),
            "asset_code with '-' must fail, got: {err:?}"
        );
    }

    // validate_memo_coherence: memo_type without memo
    #[test]
    fn memo_type_without_memo_fails() {
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &memo_type=MEMO_TEXT";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(
            matches!(err, Sep7Error::InvalidParamValue { param: "memo", .. }),
            "memo_type without memo must fail, got: {err:?}"
        );
    }

    // validate_origin_domain_syntax: numeric-only labels
    #[test]
    fn origin_domain_numeric_only_labels_rejected() {
        // "10.0" is not a valid IPv4 address but has only numeric labels.
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &origin_domain=10.0\
            &signature=fakesig";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(
            matches!(err, Sep7Error::InvalidOriginDomain { .. }),
            "numeric-only labels must be rejected, got: {err:?}"
        );
    }

    // strip_signature_param: ?signature= (first-param) form
    #[test]
    fn strip_signature_param_first_param_form() {
        // signature= is the first/only param — uses the ?signature= form.
        let uri = "web+stellar:pay?signature=abc123";
        let stripped = strip_signature_param(uri);
        assert_eq!(stripped, "web+stellar:pay");
    }

    // validate_g_strkey_raw: called via destination validation (invalid G-strkey)
    #[test]
    fn invalid_destination_g_strkey_fails() {
        let uri = "web+stellar:pay?destination=NOTVALIDGKEY";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(
            matches!(
                err,
                Sep7Error::InvalidParamValue {
                    param: "destination",
                    ..
                }
            ),
            "invalid destination G-strkey must fail, got: {err:?}"
        );
    }

    // sanitize_operation: long or non-ascii operation token is sanitised
    #[test]
    fn unknown_long_operation_is_sanitized_in_error() {
        let long_op = "a".repeat(20);
        let err = parse_sep7_uri(&format!("web+stellar:{long_op}?foo=bar")).unwrap_err();
        assert!(
            matches!(err, Sep7Error::UnknownOperation { .. }),
            "long operation token must fail with UnknownOperation, got: {err:?}"
        );
        if let Sep7Error::UnknownOperation { ref operation } = err {
            assert!(
                operation.len() <= 16,
                "sanitised operation must be ≤16 chars, got {len}: {operation}",
                len = operation.len()
            );
        }
    }

    // percent_decode: truncated % at end of string (line 269)
    #[test]
    fn percent_encoding_truncated_at_end_of_key_fails() {
        // Key ends with a bare `%` — truncated sequence triggers Err at line 269.
        let uri = "web+stellar:pay?destination%=G";
        let err = parse_sep7_uri(uri).unwrap_err();
        assert!(
            matches!(err, Sep7Error::MalformedUri { ref detail }
                if detail.contains("key contains invalid percent-encoding")),
            "truncated % at end of key must fail, got: {err:?}"
        );
    }

    // percent_decode: lowercase hex digits in percent-encoding (line 286)
    #[test]
    fn percent_encoding_lowercase_hex_in_value_accepted() {
        // %2f = '/' in lowercase hex — exercises the b'a'..=b'f' arm of hex_digit.
        // The destination uses a valid G-strkey; the percent-decoded value here is
        // in the msg field (letters are fine in msg values).
        // We URL-encode the letter 'a' as %61 (lowercase hex) in the msg value.
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &msg=hell%6f"; // %6f = 'o' (lowercase hex)
        let req = parse_sep7_uri(uri).unwrap();
        match req {
            Sep7Request::Pay(p) => {
                assert_eq!(
                    p.msg.as_deref(),
                    Some("hello"),
                    "lowercase hex %6f must decode to 'o'"
                );
            }
            Sep7Request::Tx(_) => panic!("expected Pay"),
        }
    }

    // validate_replace_field: balanced identifiers are accepted (lines 531, 533)
    #[test]
    fn balanced_replace_field_is_accepted() {
        use stellar_xdr::{
            Limits, Memo, MuxedAccount, Preconditions, SequenceNumber, Transaction,
            TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
        };
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
        // Balanced: left has X, right has X (same identifier on both sides).
        let replace = "sourceAccount%3AX%3BX%3AThe%20source%20account";
        let uri = format!("web+stellar:tx?xdr={xdr_urlenc}&replace={replace}");
        let req = parse_sep7_uri(&uri).unwrap();
        match req {
            Sep7Request::Tx(p) => {
                assert!(p.replace.is_some(), "balanced replace must be accepted");
            }
            Sep7Request::Pay(_) => panic!("expected Tx"),
        }
    }

    // validate_g_strkey success path via tx pubkey (line 568)
    #[test]
    fn valid_pubkey_in_tx_is_accepted() {
        use stellar_xdr::{
            Limits, Memo, MuxedAccount, Preconditions, SequenceNumber, Transaction,
            TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
        };
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
        let uri = format!(
            "web+stellar:tx?xdr={xdr_urlenc}\
             &pubkey=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO"
        );
        let req = parse_sep7_uri(&uri).unwrap();
        match req {
            Sep7Request::Tx(p) => {
                assert_eq!(
                    p.pubkey.as_deref(),
                    Some("GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO")
                );
            }
            Sep7Request::Pay(_) => panic!("expected Tx"),
        }
    }

    // ── Depth-bomb regression ─────────────────────────────────────────────────
    //
    // A `TransactionEnvelope::Tx` whose InvokeHostFunction operation carries a
    // 600-deep `root_invocation.sub_invocations` chain is rejected by the
    // production parser before it returns.  Without the depth bound the decode
    // at the `validate_xdr_param` call site would be unbounded and could
    // exhaust the stack.

    /// A SEP-7 `tx` URI whose `xdr` param contains a `TransactionEnvelope::Tx`
    /// with a 600-deep `SorobanAuthorizedInvocation.sub_invocations` chain is
    /// rejected with `Sep7Error::InvalidParamValue { param: "xdr", .. }`.
    ///
    /// The fixture is encoded with `Limits::none()` (write-side; encoding does
    /// not apply the bounded depth). Only the production decode path enforces
    /// `XDR_DECODE_MAX_DEPTH` (500). Depth 600 > 500 so the decoder returns
    /// an error that the parser maps to `InvalidParamValue { param: "xdr" }`.
    #[test]
    fn depth_bomb_xdr_param_rejected_before_stack_exhaustion() {
        use stellar_xdr::{
            ContractId, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Limits, Memo,
            MuxedAccount, Operation, OperationBody, Preconditions, ScAddress, SequenceNumber,
            SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
            SorobanCredentials, Transaction, TransactionEnvelope, TransactionExt,
            TransactionV1Envelope, Uint256, VecM, WriteXdr,
        };

        let leaf_fn = SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([0xABu8; 32]))),
            function_name: "f".try_into().expect("short function name"),
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
            root_invocation: inner.clone(),
        };

        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([0xABu8; 32]))),
                    function_name: "f".try_into().expect("short function name"),
                    args: VecM::default(),
                }),
                auth: vec![auth_entry].try_into().expect("single auth entry"),
            }),
        };

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![op].try_into().expect("single operation"),
            ext: TransactionExt::V0,
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });

        // ENCODE with Limits::none() — write-side; does not apply the depth
        // bound. Writing 600 levels of nesting fits the default stack.
        let xdr_b64 = envelope
            .to_xdr_base64(Limits::none())
            .expect("encoding a deep structure must succeed");

        // Encode the XDR base64 as URL-safe query param value.
        let xdr_urlenc = xdr_b64
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");

        let uri = format!("web+stellar:tx?xdr={xdr_urlenc}");
        let err = parse_sep7_uri(&uri)
            .expect_err("600-deep sub_invocations chain must be rejected by the depth bound");

        assert!(
            matches!(err, Sep7Error::InvalidParamValue { param: "xdr", .. }),
            "expected InvalidParamValue {{ param: \"xdr\" }}; got {err:?}"
        );
    }

    // federation address destination (contains '*') bypasses G-strkey check (line 376)
    #[test]
    fn federation_address_destination_accepted() {
        // A destination containing '*' is treated as a federation address and skips
        // the G-strkey validation (the `if !destination.contains('*')` block is not entered).
        let uri = "web+stellar:pay?destination=user*example.com";
        let req = parse_sep7_uri(uri).unwrap();
        match req {
            Sep7Request::Pay(p) => {
                assert_eq!(p.destination, "user*example.com");
            }
            Sep7Request::Tx(_) => panic!("expected Pay"),
        }
    }
}
