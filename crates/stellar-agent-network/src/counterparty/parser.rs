//! Minimal SEP-1 `stellar.toml` parser.
//!
//! # What this module does
//!
//! Provides [`parse_minimal_sep1`] which extracts the subset of `stellar.toml`
//! fields consumed by the counterparty resolution and policy subsystems:
//!
//! - `FEDERATION_SERVER` — URL of the federation server.
//! - `WEB_AUTH_ENDPOINT` — URL of the SEP-10 web authentication endpoint.
//! - `ACCOUNTS` — list of G-strkeys that belong to this operator.
//! - `CURRENCIES` — array of currency tables (optional); preserved for
//!   `KNOWN_ISSUER` binding checks.
//!
//! All fields are optional at the parser level.  The criterion checks
//! whichever fields it needs and treats missing fields as "not declared".
//! SEP-1 top-level URL fields are validated when present so callers fail
//! closed on downgradeable `http://` endpoints.
//!
//! # Body size cap (defence-in-depth)
//!
//! Even though the fetch layer already enforces a 64 KiB cap, the parser
//! re-checks the body length before parsing.  This ensures the invariant is
//! maintained regardless of how the body reached the parser (e.g. a cache read
//! path that does not go through `fetch_stellar_toml`).
//!
//! # TOML parser choice
//!
//! Uses `toml_edit` (workspace-pinned), which is the same crate used by the
//! policy-file canonical-form emitter.  `toml_edit` provides a typed
//! `DocumentMut` that allows walking the document without re-serialising.
//!
//! `FEDERATION_SERVER` and `WEB_AUTH_ENDPOINT` are the substrate for the
//! SEP-10 server-key binding step.

use toml_edit::{DocumentMut, Item, Table, Value};
use url::Url;

use crate::counterparty::{
    CounterpartyError, CounterpartyKindParseError, fetch::MAX_BODY_BYTES,
    validation::is_valid_ldh_home_domain,
};

const KIND_FIELD: &str = "kind";
const KNOWN_ISSUER_KIND: &str = "KNOWN_ISSUER";
const CODE_FIELD: &str = "code";
const ISSUER_FIELD: &str = "issuer";
const ACCEPTED_COUNTERPARTY_KINDS: [&str; 6] = [
    "G_ACCOUNT",
    "C_ACCOUNT",
    KNOWN_ISSUER_KIND,
    "SEP10_IDENTITY",
    "HOME_DOMAIN",
    "ONE_TIME_ADDRESS",
];
const EXTRA_TOP_LEVEL_HTTPS_URL_FIELDS: [&str; 8] = [
    "AUTH_SERVER",
    "TRANSFER_SERVER",
    "TRANSFER_SERVER_SEP0024",
    "KYC_SERVER",
    "WEB_AUTH_FOR_CONTRACTS_ENDPOINT",
    "HORIZON_URL",
    "DIRECT_PAYMENT_SERVER",
    "ANCHOR_QUOTE_SERVER",
];
const EXTRA_TOP_LEVEL_STELLAR_PUBLIC_KEY_FIELDS: [&str; 2] =
    ["SIGNING_KEY", "URI_REQUEST_SIGNING_KEY"];
const KNOWN_TOP_LEVEL_FIELDS: [&str; 16] = [
    "VERSION",
    "NETWORK_PASSPHRASE",
    "FEDERATION_SERVER",
    "WEB_AUTH_ENDPOINT",
    "ACCOUNTS",
    "CURRENCIES",
    "AUTH_SERVER",
    "TRANSFER_SERVER",
    "TRANSFER_SERVER_SEP0024",
    "KYC_SERVER",
    "WEB_AUTH_FOR_CONTRACTS_ENDPOINT",
    "HORIZON_URL",
    "DIRECT_PAYMENT_SERVER",
    "ANCHOR_QUOTE_SERVER",
    "SIGNING_KEY",
    "URI_REQUEST_SIGNING_KEY",
];

// ─────────────────────────────────────────────────────────────────────────────
// MinimalCurrency
// ─────────────────────────────────────────────────────────────────────────────

/// Structured projection of one SEP-1 `CURRENCIES` entry.
///
/// The parser keeps the known discriminator fields structured for downstream
/// binding checks while retaining the raw string rendering for forensic
/// correlation and forward-compatible fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalCurrency {
    /// Optional SEP-1 `kind` discriminator.
    pub kind: Option<String>,
    /// Optional asset code declared by the entry.
    pub code: Option<String>,
    /// Optional issuer account declared by `KNOWN_ISSUER` entries.
    pub issuer: Option<String>,
    /// String rendering of the original TOML table entry.
    pub raw: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// MinimalSep1
// ─────────────────────────────────────────────────────────────────────────────

/// The minimal projection of a parsed `stellar.toml` document.
///
/// All fields are `Option` — the parser does not mandate any specific field.
/// Callers check individual fields according to the relevant criterion logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalSep1 {
    /// The anchor-declared Stellar network passphrase, if declared.
    pub network_passphrase: Option<String>,

    /// URL of the federation server, if declared.
    pub federation_server: Option<String>,

    /// URL of the SEP-10 web authentication endpoint, if declared.
    pub web_auth_endpoint: Option<String>,

    /// List of operator-declared account G-strkeys, if declared.
    pub accounts: Vec<String>,

    /// Currency tables projected into structured SEP-1 fields.
    pub currencies: Vec<MinimalCurrency>,

    /// The validated `URI_REQUEST_SIGNING_KEY` G-strkey, if declared.
    ///
    /// Used for SEP-7 `origin_domain` signature verification.  The key is
    /// validated as a G-strkey in the parser (via `validate_stellar_public_key`)
    /// before being stored.
    pub uri_request_signing_key: Option<String>,

    /// The validated `SIGNING_KEY` G-strkey, if declared.
    ///
    /// Used for SEP-10 server-key verification (e.g. passing
    /// `expected_server_signing_key` to the ephemeral auth path).  The key is
    /// validated as a G-strkey in the parser (via `validate_stellar_public_key`)
    /// before being stored.
    pub signing_key: Option<String>,

    /// The validated `TRANSFER_SERVER` HTTPS URL (SEP-6), if declared.
    ///
    /// Validated as HTTPS by the `EXTRA_TOP_LEVEL_HTTPS_URL_FIELDS` loop
    /// before being stored here.
    pub transfer_server: Option<String>,

    /// The validated `TRANSFER_SERVER_SEP0024` HTTPS URL (SEP-24), if declared.
    ///
    /// Validated as HTTPS by the `EXTRA_TOP_LEVEL_HTTPS_URL_FIELDS` loop
    /// before being stored here.
    pub transfer_server_sep0024: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_minimal_sep1
// ─────────────────────────────────────────────────────────────────────────────

/// Parses a `stellar.toml` body and returns the minimal SEP-1 projection.
///
/// Applies a 64 KiB body length guard before parsing (defence-in-depth;
/// the fetch layer enforces the same limit at the network boundary).
///
/// # Errors
///
/// - [`CounterpartyError::TomlInvalid`] — body exceeds 64 KiB, or is not
///   valid TOML.  The oversized-body path returns `TomlInvalid` (not
///   `FetchFailed`) because the parser has no knowledge of fetch failures —
///   the oversized body is a structural input problem, not a network error.
/// - [`CounterpartyError::KindParseError`] — kind-field parser failures on
///   `[[CURRENCIES]]` array-of-tables and inline-table forms.  Sub-variants
///   (see [`CounterpartyKindParseError`]):
///     - [`UnknownKind`](CounterpartyKindParseError::UnknownKind) when the
///       `kind` discriminator is not a recognised value.
///     - [`MissingField`](CounterpartyKindParseError::MissingField) when a
///       recognised kind omits a required field (e.g. `KNOWN_ISSUER` without
///       `code` or `issuer`).
///     - [`InvalidValue`](CounterpartyKindParseError::InvalidValue) when a
///       kind-related field is present but malformed (non-string scalar where
///       a string is required, or an empty / whitespace-only required string).
///       The `value` field on this variant is sanitised — control characters
///       are replaced and the rendered length is capped — so the typed error
///       is safe to render through `tracing` text-formatters and other
///       operator-facing sinks.
/// - [`CounterpartyError::TomlInvalid`] if `SIGNING_KEY` or
///   `URI_REQUEST_SIGNING_KEY` is present but not a valid Stellar ed25519
///   G-strkey (rejects M-strkey muxed, C-strkey contract, S-strkey secret, and
///   malformed forms).
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```rust
/// use stellar_agent_network::counterparty::parser::parse_minimal_sep1;
///
/// let body = r#"
/// FEDERATION_SERVER = "https://fed.example.com/federation"
/// WEB_AUTH_ENDPOINT = "https://auth.example.com"
/// ACCOUNTS = ["GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"]
/// "#;
///
/// let parsed = parse_minimal_sep1(body).expect("valid TOML must parse");
/// assert_eq!(
///     parsed.federation_server.as_deref(),
///     Some("https://fed.example.com/federation")
/// );
/// assert_eq!(parsed.accounts.len(), 1);
/// ```
pub fn parse_minimal_sep1(body: &str) -> Result<MinimalSep1, CounterpartyError> {
    // Defence-in-depth: enforce the 64 KiB cap before parsing.
    // The fetch layer enforces the same limit at the network boundary; this
    // check catches callers that bypass `fetch_stellar_toml` (e.g. cache-read
    // path, direct test invocation).  Error variant is `TomlInvalid` because
    // the parser has no knowledge of fetch failures — the oversized body is a
    // structural input problem, not a network error.
    if body.len() > MAX_BODY_BYTES {
        return Err(CounterpartyError::TomlInvalid {
            detail: format!(
                "stellar.toml: body exceeds 64 KiB cap (size = {} bytes)",
                body.len()
            ),
        });
    }

    let doc: DocumentMut =
        body.parse()
            .map_err(|e: toml_edit::TomlError| CounterpartyError::TomlInvalid {
                detail: format!("stellar.toml: TOML parse error: {e}"),
            })?;

    log_unknown_top_level_fields(&doc);

    let network_passphrase = optional_string_field(&doc, "NETWORK_PASSPHRASE")?;

    // FEDERATION_SERVER and WEB_AUTH_ENDPOINT must use https://.
    // Accepting http:// would allow downgrade attacks on the auth endpoint.
    let federation_server = match optional_string_field(&doc, "FEDERATION_SERVER")? {
        None => None,
        Some(raw) => {
            validate_https_url(&raw, "FEDERATION_SERVER")?;
            Some(raw)
        }
    };

    let web_auth_endpoint = match optional_string_field(&doc, "WEB_AUTH_ENDPOINT")? {
        None => None,
        Some(raw) => {
            validate_https_url(&raw, "WEB_AUTH_ENDPOINT")?;
            Some(raw)
        }
    };

    // Validate all extra HTTPS URL fields; capture the two transfer-server
    // fields for SEP-6 and SEP-24 resolution.
    let mut transfer_server: Option<String> = None;
    let mut transfer_server_sep0024: Option<String> = None;
    for field in EXTRA_TOP_LEVEL_HTTPS_URL_FIELDS {
        if let Some(raw) = optional_string_field(&doc, field)? {
            validate_https_url(&raw, field)?;
            match field {
                "TRANSFER_SERVER" => transfer_server = Some(raw),
                "TRANSFER_SERVER_SEP0024" => transfer_server_sep0024 = Some(raw),
                _ => {}
            }
        }
    }

    // Validate all public-key fields and capture SIGNING_KEY +
    // URI_REQUEST_SIGNING_KEY.  After the loop, signing_key and
    // uri_request_signing_key hold the validated values (if any).
    let mut signing_key: Option<String> = None;
    let mut uri_request_signing_key: Option<String> = None;
    for field in EXTRA_TOP_LEVEL_STELLAR_PUBLIC_KEY_FIELDS {
        if let Some(raw) = optional_string_field(&doc, field)? {
            validate_stellar_public_key(&raw, field)?;
            match field {
                "SIGNING_KEY" => signing_key = Some(raw),
                "URI_REQUEST_SIGNING_KEY" => uri_request_signing_key = Some(raw),
                _ => {}
            }
        }
    }

    // ACCOUNTS must be an array of strings; fail-closed on any non-string
    // entry rather than silently skipping it.
    let accounts = if let Some(v) = doc.get("ACCOUNTS").and_then(|v| v.as_array()) {
        let mut result = Vec::with_capacity(v.len());
        for (i, item) in v.iter().enumerate() {
            match item.as_str() {
                Some(s) => result.push(s.to_owned()),
                None => {
                    return Err(CounterpartyError::TomlInvalid {
                        detail: format!(
                            "ACCOUNTS[{i}]: is not a string; stellar.toml ACCOUNTS must \
                             be an array of G-strkeys"
                        ),
                    });
                }
            }
        }
        result
    } else {
        Vec::new()
    };

    // CURRENCIES appears as either:
    //   - An array of tables (`[[CURRENCIES]]` TOML syntax) — `as_array_of_tables()`.
    //   - An inline array of inline tables (`CURRENCIES = [{...}, {...}]`) — `as_array()`.
    // We handle both forms by serialising each table entry to a string for
    // downstream structured access.
    let currencies = match doc.get("CURRENCIES") {
        Some(v) if v.is_array_of_tables() => {
            // `[[CURRENCIES]]` array-of-tables form.
            let mut result = Vec::new();
            if let Some(arr) = v.as_array_of_tables() {
                for tbl in arr.iter() {
                    result.push(parse_currency_table(tbl)?);
                }
            }
            result
        }
        Some(v) if v.is_array() => {
            // Inline array form: `CURRENCIES = [{code = "USDC", ...}]`.
            let mut result = Vec::new();
            if let Some(arr) = v.as_array() {
                for item in arr.iter() {
                    if let Some(currency) = parse_currency_inline(item)? {
                        result.push(currency);
                    }
                }
            }
            result
        }
        _ => Vec::new(),
    };

    Ok(MinimalSep1 {
        network_passphrase,
        federation_server,
        web_auth_endpoint,
        accounts,
        currencies,
        signing_key,
        uri_request_signing_key,
        transfer_server,
        transfer_server_sep0024,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal validation helpers
// ─────────────────────────────────────────────────────────────────────────────

fn optional_string_field(
    doc: &DocumentMut,
    field: &'static str,
) -> Result<Option<String>, CounterpartyError> {
    match doc.get(field) {
        None => Ok(None),
        Some(v) => v.as_str().map(ToOwned::to_owned).map(Some).ok_or_else(|| {
            CounterpartyError::TomlInvalid {
                detail: format!("{field}: must be a string"),
            }
        }),
    }
}

/// Validates that a URL string from the stellar.toml uses the `https://` scheme.
///
/// Rejects `http://` to prevent downgrade attacks on SEP-10 auth endpoints.
fn validate_https_url(raw: &str, field: &str) -> Result<(), CounterpartyError> {
    if raw
        .strip_prefix("https://")
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    {
        return Err(CounterpartyError::TomlInvalid {
            detail: format!("{field}: must include a valid host"),
        });
    }
    let parsed = Url::parse(raw).map_err(|_| CounterpartyError::TomlInvalid {
        detail: format!("{field}: is not a valid URL"),
    })?;
    if parsed.scheme() != "https" {
        return Err(CounterpartyError::TomlInvalid {
            detail: format!(
                "{field}: must be an https:// URL (got '{}')",
                parsed.scheme()
            ),
        });
    }
    let Some(host) = parsed.host_str() else {
        return Err(CounterpartyError::TomlInvalid {
            detail: format!("{field}: must include a valid host"),
        });
    };
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        // Allow explicit loopback endpoints for local integration seams while
        // still rejecting public IP literals in operator-facing stellar.toml.
        if ip.is_loopback() {
            return Ok(());
        }
        return Err(CounterpartyError::TomlInvalid {
            detail: format!("{field}: host must be a lowercase DNS home domain"),
        });
    }
    if host.is_empty() || !is_valid_ldh_home_domain(host) {
        return Err(CounterpartyError::TomlInvalid {
            detail: format!("{field}: host must be a lowercase DNS home domain"),
        });
    }
    Ok(())
}

fn validate_stellar_public_key(raw: &str, field: &str) -> Result<(), CounterpartyError> {
    stellar_strkey::ed25519::PublicKey::from_string(raw)
        .map(|_| ())
        .map_err(|_| CounterpartyError::TomlInvalid {
            detail: format!("{field}: must be a valid Stellar ed25519 public key (G-strkey)"),
        })
}

fn log_unknown_top_level_fields(doc: &DocumentMut) {
    for (key, _) in doc.iter() {
        if !KNOWN_TOP_LEVEL_FIELDS.contains(&key) {
            tracing::debug!(
                field = %key,
                "unknown SEP-1 top-level stellar.toml field ignored"
            );
        }
    }
}

fn parse_currency_table(table: &Table) -> Result<MinimalCurrency, CounterpartyError> {
    let kind = optional_item_str(table.get(KIND_FIELD), KIND_FIELD)?;
    let code = optional_item_str(table.get(CODE_FIELD), CODE_FIELD)?;
    let issuer = optional_item_str(table.get(ISSUER_FIELD), ISSUER_FIELD)?;
    validate_counterparty_kind_fields(kind, code, issuer)?;
    Ok(MinimalCurrency {
        kind: kind.map(ToOwned::to_owned),
        code: code.map(ToOwned::to_owned),
        issuer: issuer.map(ToOwned::to_owned),
        raw: table.to_string(),
    })
}

fn parse_currency_inline(value: &Value) -> Result<Option<MinimalCurrency>, CounterpartyError> {
    let Some(table) = value.as_inline_table() else {
        return Ok(None);
    };

    let kind = optional_value_str(table.get(KIND_FIELD), KIND_FIELD)?;
    let code = optional_value_str(table.get(CODE_FIELD), CODE_FIELD)?;
    let issuer = optional_value_str(table.get(ISSUER_FIELD), ISSUER_FIELD)?;
    validate_counterparty_kind_fields(kind, code, issuer)?;
    Ok(Some(MinimalCurrency {
        kind: kind.map(ToOwned::to_owned),
        code: code.map(ToOwned::to_owned),
        issuer: issuer.map(ToOwned::to_owned),
        raw: table.to_string(),
    }))
}

fn validate_counterparty_kind_fields(
    kind: Option<&str>,
    code: Option<&str>,
    issuer: Option<&str>,
) -> Result<(), CounterpartyError> {
    let Some(kind) = kind else {
        return Ok(());
    };

    if !ACCEPTED_COUNTERPARTY_KINDS.contains(&kind) {
        return Err(CounterpartyKindParseError::UnknownKind {
            kind: kind.to_owned(),
        }
        .into());
    }

    if kind == KNOWN_ISSUER_KIND {
        require_kind_field(kind, CODE_FIELD, code)?;
        require_kind_field(kind, ISSUER_FIELD, issuer)?;
    }

    Ok(())
}

fn require_kind_field(
    kind: &str,
    field: &str,
    value: Option<&str>,
) -> Result<(), CounterpartyError> {
    let Some(value) = value else {
        return Err(CounterpartyKindParseError::MissingField {
            kind: kind.to_owned(),
            field: field.to_owned(),
        }
        .into());
    };

    if value.trim().is_empty() {
        return Err(CounterpartyKindParseError::InvalidValue {
            field: field.to_owned(),
            value: sanitize_invalid_value(value),
        }
        .into());
    }

    Ok(())
}

/// Sanitize an attacker-controlled TOML scalar before embedding it in a typed
/// `CounterpartyKindParseError::InvalidValue.value` field.
///
/// Replaces ASCII / Unicode control characters with `?` and caps the rendered
/// length to 64 chars (with a trailing `...` truncation marker if capped).
/// The typed error flows through `tracing::warn!(error = %e, ...)` in the CLI
/// counterparty refresh path, where a text-formatter subscriber would otherwise
/// render attacker-controlled ANSI escapes / newlines / null bytes to the
/// operator's terminal verbatim (terminal-injection / log-spoofing).
fn sanitize_invalid_value(value: &str) -> String {
    const MAX_LEN: usize = 64;
    let mut out = String::with_capacity(value.len().min(MAX_LEN));
    for (i, ch) in value.chars().enumerate() {
        if i >= MAX_LEN {
            out.push_str("...");
            break;
        }
        if ch.is_control() {
            out.push('?');
        } else {
            out.push(ch);
        }
    }
    out
}

fn optional_item_str<'a>(
    item: Option<&'a Item>,
    field: &str,
) -> Result<Option<&'a str>, CounterpartyError> {
    item.map_or(Ok(None), |item| {
        item.as_str().map(Some).ok_or_else(|| {
            CounterpartyKindParseError::InvalidValue {
                field: field.to_owned(),
                value: sanitize_invalid_value(&item.to_string()),
            }
            .into()
        })
    })
}

fn optional_value_str<'a>(
    value: Option<&'a Value>,
    field: &str,
) -> Result<Option<&'a str>, CounterpartyError> {
    value.map_or(Ok(None), |value| {
        value.as_str().map(Some).ok_or_else(|| {
            CounterpartyKindParseError::InvalidValue {
                field: field.to_owned(),
                value: sanitize_invalid_value(&value.to_string()),
            }
            .into()
        })
    })
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

    use super::*;

    const SAMPLE_TOML: &str = r#"
FEDERATION_SERVER = "https://fed.example.com/federation"
WEB_AUTH_ENDPOINT = "https://auth.example.com"
ACCOUNTS = [
  "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
  "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI"
]

[[CURRENCIES]]
code = "USDC"
issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
display_decimals = 2

[[CURRENCIES]]
code = "EURC"
issuer = "GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP"
display_decimals = 2
"#;

    #[test]
    fn parses_federation_server() {
        let parsed = parse_minimal_sep1(SAMPLE_TOML).unwrap();
        assert_eq!(
            parsed.federation_server.as_deref(),
            Some("https://fed.example.com/federation")
        );
    }

    #[test]
    fn parses_web_auth_endpoint() {
        let parsed = parse_minimal_sep1(SAMPLE_TOML).unwrap();
        assert_eq!(
            parsed.web_auth_endpoint.as_deref(),
            Some("https://auth.example.com")
        );
    }

    #[test]
    fn parses_accounts_array() {
        let parsed = parse_minimal_sep1(SAMPLE_TOML).unwrap();
        assert_eq!(parsed.accounts.len(), 2);
        assert!(
            parsed
                .accounts
                .contains(&"GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned())
        );
    }

    #[test]
    fn parses_valid_sep1_signing_keys() {
        let body = r#"
SIGNING_KEY = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"
URI_REQUEST_SIGNING_KEY = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI"
"#;
        parse_minimal_sep1(body).unwrap();
    }

    /// Verifies that `MinimalSep1::signing_key` is populated when `SIGNING_KEY`
    /// is present and valid, and is `None` when absent.
    /// Required for SEP-10 server-key verification in the x402
    /// counterparty-identity gate.
    #[test]
    fn signing_key_extracted_when_present() {
        let body = r#"
SIGNING_KEY = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"
URI_REQUEST_SIGNING_KEY = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI"
"#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert_eq!(
            parsed.signing_key.as_deref(),
            Some("GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"),
            "signing_key must be populated from SIGNING_KEY"
        );
    }

    /// Verifies that `MinimalSep1::signing_key` is `None` when `SIGNING_KEY` is absent.
    #[test]
    fn signing_key_is_none_when_absent() {
        let body = r#"
URI_REQUEST_SIGNING_KEY = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI"
"#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert!(
            parsed.signing_key.is_none(),
            "signing_key must be None when SIGNING_KEY is absent"
        );
    }

    /// Verifies that both `SIGNING_KEY` and `URI_REQUEST_SIGNING_KEY`
    /// are extracted simultaneously when both are present.
    #[test]
    fn both_signing_keys_extracted_simultaneously() {
        let body = r#"
SIGNING_KEY = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"
URI_REQUEST_SIGNING_KEY = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI"
"#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert_eq!(
            parsed.signing_key.as_deref(),
            Some("GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"),
            "signing_key must be set"
        );
        assert_eq!(
            parsed.uri_request_signing_key.as_deref(),
            Some("GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI"),
            "uri_request_signing_key must be set"
        );
    }

    /// Verifies that `signing_key` is `None` from SAMPLE_TOML (which has no `SIGNING_KEY`).
    #[test]
    fn signing_key_is_none_from_sample_toml() {
        let parsed = parse_minimal_sep1(SAMPLE_TOML).unwrap();
        assert!(
            parsed.signing_key.is_none(),
            "signing_key must be None when absent in SAMPLE_TOML"
        );
    }

    /// Verifies that `MinimalSep1::uri_request_signing_key` is populated when
    /// `URI_REQUEST_SIGNING_KEY` is present and valid, and is `None` when absent.
    /// Required for the SEP-7 anti-phishing flow.
    #[test]
    fn uri_request_signing_key_extracted_when_present() {
        let body = r#"
SIGNING_KEY = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"
URI_REQUEST_SIGNING_KEY = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI"
"#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert_eq!(
            parsed.uri_request_signing_key.as_deref(),
            Some("GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI"),
            "uri_request_signing_key must be populated from URI_REQUEST_SIGNING_KEY"
        );
    }

    #[test]
    fn uri_request_signing_key_is_none_when_absent() {
        let body = r#"
SIGNING_KEY = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"
"#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert!(
            parsed.uri_request_signing_key.is_none(),
            "uri_request_signing_key must be None when URI_REQUEST_SIGNING_KEY is absent"
        );
    }

    #[test]
    fn uri_request_signing_key_is_none_from_sample_toml() {
        // The SAMPLE_TOML fixture has no URI_REQUEST_SIGNING_KEY.
        let parsed = parse_minimal_sep1(SAMPLE_TOML).unwrap();
        assert!(
            parsed.uri_request_signing_key.is_none(),
            "uri_request_signing_key must be None when absent in SAMPLE_TOML"
        );
    }

    #[test]
    fn rejects_lowercase_sep1_signing_key() {
        let body = r#"
SIGNING_KEY = "gaqaa5l65lsyh7cq3vtj7f3hhlgcl3dslar2y47263d56mnnghsqstvy"
"#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("SIGNING_KEY"))
        );
    }

    #[test]
    fn rejects_empty_sep1_signing_key() {
        let body = r#"
URI_REQUEST_SIGNING_KEY = ""
"#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("URI_REQUEST_SIGNING_KEY"))
        );
    }

    #[test]
    fn rejects_wrong_length_sep1_signing_key() {
        let body = r#"
SIGNING_KEY = "GABC"
"#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("SIGNING_KEY"))
        );
    }

    #[test]
    fn rejects_malformed_checksum_sep1_signing_key() {
        let body = r#"
SIGNING_KEY = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVZ"
"#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("SIGNING_KEY"))
        );
    }

    fn sample_secret_seed_strkey() -> String {
        // Split so static secret scanners do not treat the rejection fixture as
        // a committed seed.
        [
            "SBGWSG6BTNCK",
            "COB3DIFBGCVM",
            "UPQFYPA2G4O3",
            "4RMTB343OYPX",
            "U5DJDVMN",
        ]
        .concat()
    }

    fn sample_muxed_account_strkey() -> String {
        [
            "MA3D5KRYM6CB",
            "7OWQ6TWYRR3Z",
            "4T7GNZLKERYN",
            "ZGGA5SOAOPIF",
            "Y6YQGAAAAAAA",
            "AAPCICBKU",
        ]
        .concat()
    }

    fn sample_contract_strkey() -> String {
        // Canonical contract-id vector from rs-stellar-strkey tests
        // (CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE).  Chunked
        // for stylistic consistency with the S/M-strkey fixtures above.
        [
            "CA3D5KRYM6CB",
            "7OWQ6TWYRR3Z",
            "4T7GNZLKERYN",
            "ZGGA5SOAOPIF",
            "Y6YQGAXE",
        ]
        .concat()
    }

    #[test]
    fn rejects_s_strkey_as_sep1_signing_key() {
        let s_strkey = sample_secret_seed_strkey();
        stellar_strkey::ed25519::PrivateKey::from_string(&s_strkey)
            .expect("canonical S-strkey fixture must have a valid CRC");

        let body = format!(r#"SIGNING_KEY = "{s_strkey}""#);
        let err = parse_minimal_sep1(&body).expect_err("S-strkey must be rejected as SIGNING_KEY");
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("SIGNING_KEY")),
            "expected TomlInvalid for SIGNING_KEY, got: {err:?}"
        );
    }

    #[test]
    fn rejects_m_strkey_as_sep1_signing_key() {
        let m_strkey = sample_muxed_account_strkey();
        stellar_strkey::ed25519::MuxedAccount::from_string(&m_strkey)
            .expect("canonical SDK M-strkey fixture must have a valid CRC");

        let body = format!(r#"SIGNING_KEY = "{m_strkey}""#);
        let err = parse_minimal_sep1(&body).expect_err("M-strkey must be rejected as SIGNING_KEY");
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("SIGNING_KEY")),
            "expected TomlInvalid for SIGNING_KEY, got: {err:?}"
        );
    }

    #[test]
    fn rejects_s_strkey_as_uri_request_signing_key() {
        let s_strkey = sample_secret_seed_strkey();
        stellar_strkey::ed25519::PrivateKey::from_string(&s_strkey)
            .expect("canonical S-strkey fixture must have a valid CRC");

        let body = format!(
            r#"
SIGNING_KEY = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"
URI_REQUEST_SIGNING_KEY = "{s_strkey}"
"#
        );
        let err = parse_minimal_sep1(&body)
            .expect_err("S-strkey must be rejected as URI_REQUEST_SIGNING_KEY");
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("URI_REQUEST_SIGNING_KEY")),
            "expected TomlInvalid for URI_REQUEST_SIGNING_KEY, got: {err:?}"
        );
    }

    #[test]
    fn rejects_m_strkey_as_uri_request_signing_key() {
        let m_strkey = sample_muxed_account_strkey();
        stellar_strkey::ed25519::MuxedAccount::from_string(&m_strkey)
            .expect("canonical SDK M-strkey fixture must have a valid CRC");

        let body = format!(
            r#"
SIGNING_KEY = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"
URI_REQUEST_SIGNING_KEY = "{m_strkey}"
"#
        );
        let err = parse_minimal_sep1(&body)
            .expect_err("M-strkey must be rejected as URI_REQUEST_SIGNING_KEY");
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("URI_REQUEST_SIGNING_KEY")),
            "expected TomlInvalid for URI_REQUEST_SIGNING_KEY, got: {err:?}"
        );
    }

    #[test]
    fn rejects_c_strkey_as_sep1_signing_key() {
        let c_strkey = sample_contract_strkey();
        stellar_strkey::Contract::from_string(&c_strkey)
            .expect("canonical SDK C-strkey fixture must have a valid CRC");

        let body = format!(r#"SIGNING_KEY = "{c_strkey}""#);
        let err = parse_minimal_sep1(&body).expect_err("C-strkey must be rejected as SIGNING_KEY");
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("SIGNING_KEY")),
            "expected TomlInvalid for SIGNING_KEY, got: {err:?}"
        );
    }

    #[test]
    fn rejects_c_strkey_as_uri_request_signing_key() {
        let c_strkey = sample_contract_strkey();
        stellar_strkey::Contract::from_string(&c_strkey)
            .expect("canonical SDK C-strkey fixture must have a valid CRC");

        let body = format!(
            r#"
SIGNING_KEY = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"
URI_REQUEST_SIGNING_KEY = "{c_strkey}"
"#
        );
        let err = parse_minimal_sep1(&body)
            .expect_err("C-strkey must be rejected as URI_REQUEST_SIGNING_KEY");
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("URI_REQUEST_SIGNING_KEY")),
            "expected TomlInvalid for URI_REQUEST_SIGNING_KEY, got: {err:?}"
        );
    }

    #[test]
    fn parses_currencies_array() {
        let parsed = parse_minimal_sep1(SAMPLE_TOML).unwrap();
        assert_eq!(parsed.currencies.len(), 2);
        assert!(
            parsed.currencies.iter().any(|currency| {
                currency.code.as_deref() == Some("USDC")
                    && currency.issuer.as_deref().is_some()
                    && currency.raw.contains("USDC")
            }),
            "USDC currency must be present in structured currencies"
        );
    }

    #[test]
    fn unknown_top_level_field_is_logged_but_accepted() {
        let body = r#"
FEDERATION_SERVER = "https://fed.example.com/federation"
FUTURE_SEP1_FIELD = "forward-compatible"
"#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert_eq!(
            parsed.federation_server.as_deref(),
            Some("https://fed.example.com/federation")
        );
    }

    #[test]
    fn counterparty_kind_parse_error_for_unknown_currency_kind() {
        let body = r#"
[[CURRENCIES]]
kind = "NOT_A_KIND"
code = "USDC"
issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
"#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(
                err,
                CounterpartyError::KindParseError(CounterpartyKindParseError::UnknownKind {
                    ref kind
                }) if kind == "NOT_A_KIND"
            ),
            "unknown CURRENCIES.kind must return UnknownKind, got: {err:?}"
        );
    }

    #[test]
    fn counterparty_kind_parse_error_for_missing_known_issuer_field() {
        let body = r#"
[[CURRENCIES]]
kind = "KNOWN_ISSUER"
code = "USDC"
"#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(
                err,
                CounterpartyError::KindParseError(CounterpartyKindParseError::MissingField {
                    ref kind,
                    ref field
                }) if kind == "KNOWN_ISSUER" && field == "issuer"
            ),
            "missing KNOWN_ISSUER issuer must return MissingField, got: {err:?}"
        );
    }

    #[test]
    fn counterparty_kind_parse_error_for_non_string_kind_field() {
        let body = r#"
[[CURRENCIES]]
kind = 42
code = "USDC"
issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
"#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(
                err,
                CounterpartyError::KindParseError(CounterpartyKindParseError::InvalidValue {
                    ref field,
                    ..
                }) if field == "kind"
            ),
            "non-string CURRENCIES.kind must return InvalidValue, got: {err:?}"
        );
    }

    #[test]
    fn counterparty_kind_known_issuer_inline_table_parses() {
        let body = r#"
CURRENCIES = [
  { kind = "KNOWN_ISSUER", code = "USDC", issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN" }
]
"#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert_eq!(parsed.currencies.len(), 1);
        assert_eq!(parsed.currencies[0].kind.as_deref(), Some("KNOWN_ISSUER"));
        assert_eq!(parsed.currencies[0].code.as_deref(), Some("USDC"));
        assert_eq!(
            parsed.currencies[0].issuer.as_deref(),
            Some("GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN")
        );
    }

    #[test]
    fn inline_table_currencies_unknown_kind_returns_typed_error() {
        let body = r#"CURRENCIES = [{ code = "USDC", kind = "UNRECOGNISED" }]"#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(
                err,
                CounterpartyError::KindParseError(CounterpartyKindParseError::UnknownKind {
                    ref kind
                }) if kind == "UNRECOGNISED"
            ),
            "inline-table unknown kind must return UnknownKind, got: {err:?}"
        );
    }

    #[test]
    fn inline_table_currencies_non_string_kind_returns_typed_error() {
        let body = r#"CURRENCIES = [{ code = "USDC", kind = 42 }]"#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(
                err,
                CounterpartyError::KindParseError(CounterpartyKindParseError::InvalidValue {
                    ref field,
                    ..
                }) if field == "kind"
            ),
            "inline-table non-string kind must return InvalidValue, got: {err:?}"
        );
    }

    /// Symmetric counterpart to `missing_known_issuer_field_in_array_of_tables`
    /// for the inline-table currency form.  Closes the third sub-variant of
    /// `KindParseError` for the inline-table path so the inline-table tests
    /// cover all three sub-variants the array-of-tables side does.
    #[test]
    fn inline_table_currencies_known_issuer_missing_issuer_returns_typed_error() {
        let body = r#"CURRENCIES = [{ kind = "KNOWN_ISSUER", code = "USDC" }]"#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(
                err,
                CounterpartyError::KindParseError(CounterpartyKindParseError::MissingField {
                    ref kind,
                    ref field,
                }) if kind == "KNOWN_ISSUER" && field == "issuer"
            ),
            "inline-table missing KNOWN_ISSUER issuer must return MissingField, got: {err:?}"
        );
    }

    #[test]
    fn minimal_toml_parses_with_empty_fields() {
        let body = r#"VERSION = "2.0.0""#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert!(parsed.federation_server.is_none());
        assert!(parsed.web_auth_endpoint.is_none());
        assert!(parsed.accounts.is_empty());
        assert!(parsed.currencies.is_empty());
    }

    #[test]
    fn invalid_toml_returns_toml_invalid() {
        let err = parse_minimal_sep1("this is [not valid toml {{{{").unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { .. }),
            "expected TomlInvalid, got: {err:?}"
        );
    }

    /// The parser returns `TomlInvalid` (not `FetchFailed`) for
    /// oversized bodies because the parser is not a network component.
    #[test]
    fn body_over_64kib_returns_toml_invalid() {
        let big_body = "x".repeat(MAX_BODY_BYTES + 1);
        let err = parse_minimal_sep1(&big_body).unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { .. }),
            "expected TomlInvalid for oversized body, got: {err:?}"
        );
    }

    #[test]
    fn empty_toml_parses_ok() {
        let parsed = parse_minimal_sep1("").unwrap();
        assert!(parsed.federation_server.is_none());
        assert!(parsed.accounts.is_empty());
    }

    /// Non-string ACCOUNTS entries must fail-closed, not be silently skipped.
    #[test]
    fn accounts_non_string_entry_returns_toml_invalid() {
        // A mixed-type ACCOUNTS array; non-string items must cause TomlInvalid.
        let body = r#"ACCOUNTS = ["GABC", 42, "GDEF"]"#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { .. }),
            "non-string ACCOUNTS entry must return TomlInvalid, got: {err:?}"
        );
    }

    #[test]
    fn toml_invalid_for_accounts_array_includes_index() {
        let body = r#"ACCOUNTS = ["GABC", 42, "GDEF"]"#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("ACCOUNTS[")),
            "non-string ACCOUNTS error must include array index, got: {err:?}"
        );
    }

    #[test]
    fn toml_invalid_for_top_level_field_includes_field_name() {
        let body = r#"FEDERATION_SERVER = 42"#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("FEDERATION_SERVER")),
            "top-level field error must include field name, got: {err:?}"
        );
    }

    /// FEDERATION_SERVER with http:// scheme must be rejected.
    #[test]
    fn federation_server_http_scheme_rejected() {
        let body = r#"FEDERATION_SERVER = "http://fed.example.com/federation""#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { .. }),
            "http:// FEDERATION_SERVER must return TomlInvalid, got: {err:?}"
        );
    }

    /// FEDERATION_SERVER with https:// scheme must be accepted.
    #[test]
    fn federation_server_https_scheme_accepted() {
        let body = r#"FEDERATION_SERVER = "https://fed.example.com/federation""#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert_eq!(
            parsed.federation_server.as_deref(),
            Some("https://fed.example.com/federation")
        );
    }

    /// WEB_AUTH_ENDPOINT with http:// scheme must be rejected.
    #[test]
    fn web_auth_endpoint_http_scheme_rejected() {
        let body = r#"WEB_AUTH_ENDPOINT = "http://auth.example.com""#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { .. }),
            "http:// WEB_AUTH_ENDPOINT must return TomlInvalid, got: {err:?}"
        );
    }

    /// WEB_AUTH_ENDPOINT with https:// scheme must be accepted.
    #[test]
    fn web_auth_endpoint_https_scheme_accepted() {
        let body = r#"WEB_AUTH_ENDPOINT = "https://auth.example.com""#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert_eq!(
            parsed.web_auth_endpoint.as_deref(),
            Some("https://auth.example.com")
        );
    }

    #[test]
    fn horizon_url_http_scheme_rejected() {
        let body = r#"HORIZON_URL = "http://horizon.example.com""#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("HORIZON_URL")),
            "http:// HORIZON_URL must return TomlInvalid with field name, got: {err:?}"
        );
    }

    #[test]
    fn kyc_server_http_scheme_rejected() {
        let body = r#"KYC_SERVER = "http://kyc.example.com""#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("KYC_SERVER")),
            "http:// KYC_SERVER must return TomlInvalid with field name, got: {err:?}"
        );
    }

    #[test]
    fn extra_top_level_https_url_fields_are_accepted() {
        let body = r#"
AUTH_SERVER = "https://compliance.example.com"
TRANSFER_SERVER = "https://transfer.example.com/sep6"
TRANSFER_SERVER_SEP0024 = "https://transfer.example.com/sep24"
KYC_SERVER = "https://kyc.example.com"
WEB_AUTH_FOR_CONTRACTS_ENDPOINT = "https://auth.example.com/contracts"
HORIZON_URL = "https://horizon.example.com"
DIRECT_PAYMENT_SERVER = "https://payments.example.com"
ANCHOR_QUOTE_SERVER = "https://quotes.example.com"
"#;
        parse_minimal_sep1(body).unwrap();
    }

    #[test]
    fn federation_server_missing_host_rejected() {
        let body = r#"FEDERATION_SERVER = "https:///federation""#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("valid URL") || detail.contains("host")),
            "missing-host URL must return TomlInvalid, got: {err:?}"
        );
    }

    #[test]
    fn web_auth_endpoint_ip_literal_host_rejected() {
        let body = r#"WEB_AUTH_ENDPOINT = "https://203.0.113.7/auth""#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("lowercase DNS home domain")),
            "IP literal host must return TomlInvalid, got: {err:?}"
        );
    }

    #[test]
    fn web_auth_endpoint_bracketed_ipv6_host_rejected() {
        let body = r#"WEB_AUTH_ENDPOINT = "https://[2001:db8::1]/auth""#;
        let err = parse_minimal_sep1(body).unwrap_err();
        assert!(
            matches!(err, CounterpartyError::TomlInvalid { ref detail } if detail.contains("lowercase DNS home domain")),
            "IPv6 literal host must return TomlInvalid, got: {err:?}"
        );
    }

    /// `validate_https_url` loopback-accept carve-out: `127.0.0.1` is an
    /// explicit exception so local integration seams (e.g. test anchors) can be
    /// declared in `WEB_AUTH_ENDPOINT`.  A future regression that removes the
    /// loopback carve-out would cause this test to fail.
    #[test]
    fn web_auth_endpoint_loopback_ipv4_accepted() {
        let body = r#"WEB_AUTH_ENDPOINT = "https://127.0.0.1/auth""#;
        let result = parse_minimal_sep1(body);
        assert!(
            result.is_ok(),
            "loopback WEB_AUTH_ENDPOINT must be accepted, got: {result:?}"
        );
        let sep1 = result.unwrap();
        assert_eq!(
            sep1.web_auth_endpoint.as_deref(),
            Some("https://127.0.0.1/auth")
        );
    }

    /// Verifies that `MinimalSep1::transfer_server` is populated when
    /// `TRANSFER_SERVER` is present and valid (HTTPS), and is `None` when absent.
    /// Required for the SEP-6 discovery-only client.
    #[test]
    fn transfer_server_extracted_when_present() {
        let body = r#"
TRANSFER_SERVER = "https://transfer.example.com/sep6"
"#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert_eq!(
            parsed.transfer_server.as_deref(),
            Some("https://transfer.example.com/sep6"),
            "transfer_server must be populated from TRANSFER_SERVER"
        );
    }

    #[test]
    fn transfer_server_is_none_when_absent() {
        let body = r#"
FEDERATION_SERVER = "https://fed.example.com"
"#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert!(
            parsed.transfer_server.is_none(),
            "transfer_server must be None when TRANSFER_SERVER is absent"
        );
    }

    /// Verifies that `MinimalSep1::transfer_server_sep0024` is populated when
    /// `TRANSFER_SERVER_SEP0024` is present and valid (HTTPS), and is `None`
    /// when absent.  Required for the SEP-24 interactive hand-off.
    #[test]
    fn transfer_server_sep0024_extracted_when_present() {
        let body = r#"
TRANSFER_SERVER_SEP0024 = "https://transfer.example.com/sep24"
"#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert_eq!(
            parsed.transfer_server_sep0024.as_deref(),
            Some("https://transfer.example.com/sep24"),
            "transfer_server_sep0024 must be populated from TRANSFER_SERVER_SEP0024"
        );
    }

    #[test]
    fn transfer_server_sep0024_is_none_when_absent() {
        let body = r#"
TRANSFER_SERVER = "https://transfer.example.com/sep6"
"#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert!(
            parsed.transfer_server_sep0024.is_none(),
            "transfer_server_sep0024 must be None when TRANSFER_SERVER_SEP0024 is absent"
        );
    }

    /// Both transfer server fields extracted simultaneously.
    #[test]
    fn both_transfer_server_fields_extracted() {
        let body = r#"
TRANSFER_SERVER = "https://transfer.example.com/sep6"
TRANSFER_SERVER_SEP0024 = "https://transfer.example.com/sep24"
"#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert_eq!(
            parsed.transfer_server.as_deref(),
            Some("https://transfer.example.com/sep6"),
            "transfer_server must be set"
        );
        assert_eq!(
            parsed.transfer_server_sep0024.as_deref(),
            Some("https://transfer.example.com/sep24"),
            "transfer_server_sep0024 must be set"
        );
    }

    /// Verifies that the sample TOML has neither transfer server field
    /// (both are always absent in the minimal fixture).
    #[test]
    fn transfer_server_fields_are_none_from_sample_toml() {
        let parsed = parse_minimal_sep1(SAMPLE_TOML).unwrap();
        assert!(
            parsed.transfer_server.is_none(),
            "transfer_server must be None from SAMPLE_TOML"
        );
        assert!(
            parsed.transfer_server_sep0024.is_none(),
            "transfer_server_sep0024 must be None from SAMPLE_TOML"
        );
    }

    #[test]
    fn signing_key_is_not_url_validated() {
        let body = r#"
SIGNING_KEY = "GBBHQ7H4V6RRORKYLHTCAWP6MOHNORRFJSDPXDFYDGJB2LPZUFPXUEW3"
URI_REQUEST_SIGNING_KEY = "GBBHQ7H4V6RRORKYLHTCAWP6MOHNORRFJSDPXDFYDGJB2LPZUFPXUEW3"
"#;
        parse_minimal_sep1(body).unwrap();
    }

    /// ANSI escape + control characters in an invalid kind-field value are
    /// replaced with `?` before reaching the typed `InvalidValue.value` field,
    /// defending the CLI tracing render path.
    #[test]
    fn sanitize_invalid_value_replaces_control_characters() {
        let raw = "USDC\u{1b}[2J\u{1b}[H<spoofed>\nfaked-log";
        let sanitised = sanitize_invalid_value(raw);
        assert!(
            !sanitised.contains('\u{1b}'),
            "ANSI ESC must be stripped, got: {sanitised:?}"
        );
        assert!(
            !sanitised.contains('\n'),
            "newline must be stripped, got: {sanitised:?}"
        );
        assert!(
            sanitised.contains("USDC"),
            "non-control prefix must survive, got: {sanitised:?}"
        );
    }

    /// Oversized values are capped at 64 chars with a trailing `...` truncation
    /// marker, defending against display-spam / log-overflow via crafted TOML
    /// scalar values.
    #[test]
    fn sanitize_invalid_value_caps_length_at_64_chars() {
        let raw: String = "a".repeat(200);
        let sanitised = sanitize_invalid_value(&raw);
        assert!(
            sanitised.len() <= 64 + 3,
            "length cap (64 + '...' marker) must hold, got len={}: {sanitised:?}",
            sanitised.len()
        );
        assert!(
            sanitised.ends_with("..."),
            "truncation marker must be present, got: {sanitised:?}"
        );
    }

    /// End-to-end via `require_kind_field` whitespace-only path — confirms the
    /// construction-site sanitisation wrap is in place.
    /// `\t` and `\n` are both whitespace (so trim-to-empty fires) AND control
    /// characters (so the sanitiser must replace them with `?`).
    #[test]
    fn require_kind_field_invalid_value_is_sanitised() {
        let raw = "  \t\n  ";
        let result = require_kind_field("KNOWN_ISSUER", "code", Some(raw));
        let err = result.expect_err("whitespace-only value must be rejected");
        let CounterpartyError::KindParseError(CounterpartyKindParseError::InvalidValue {
            value,
            ..
        }) = err
        else {
            panic!("expected KindParseError::InvalidValue, got: {err:?}");
        };
        assert!(
            !value.contains('\t') && !value.contains('\n'),
            "construction-site sanitisation must replace control chars, got: {value:?}"
        );
    }

    // ── ACCOUNTS anchoring substrate ──────────────────────────────────────────

    /// `ACCOUNTS` is parsed into `MinimalSep1::accounts` so the x402 identity
    /// gate can carry it in `VerifiedCounterpartySession::accounts` for the
    /// payTo-anchoring signal.
    ///
    /// Verifies that a multi-entry `ACCOUNTS` array is extracted in-order with
    /// the exact string values declared in the TOML.
    #[test]
    fn accounts_parsed_for_t5_anchoring_substrate() {
        let body = r#"
WEB_AUTH_ENDPOINT = "https://auth.example.com"
SIGNING_KEY = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"
ACCOUNTS = [
  "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
  "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI"
]
"#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert_eq!(
            parsed.accounts.len(),
            2,
            "two ACCOUNTS entries must be parsed"
        );
        assert_eq!(
            parsed.accounts[0], "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
            "first account must match"
        );
        assert_eq!(
            parsed.accounts[1], "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI",
            "second account must match"
        );
    }

    /// When `ACCOUNTS` is absent, `accounts` is empty — the anchoring signal
    /// falls through to "unknown", not "not_anchored".
    #[test]
    fn accounts_empty_when_absent_for_t5_anchoring() {
        let body = r#"
WEB_AUTH_ENDPOINT = "https://auth.example.com"
SIGNING_KEY = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"
"#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert!(
            parsed.accounts.is_empty(),
            "absent ACCOUNTS must yield empty vec (anchoring 'unknown' path)"
        );
    }

    /// Single-entry `ACCOUNTS` array is extracted correctly — boundary case for
    /// the anchoring equality check.
    #[test]
    fn accounts_single_entry_parsed_for_t5_anchoring() {
        let body = r#"
ACCOUNTS = ["GBBHQ7H4V6RRORKYLHTCAWP6MOHNORRFJSDPXDFYDGJB2LPZUFPXUEW3"]
"#;
        let parsed = parse_minimal_sep1(body).unwrap();
        assert_eq!(parsed.accounts.len(), 1);
        assert_eq!(
            parsed.accounts[0],
            "GBBHQ7H4V6RRORKYLHTCAWP6MOHNORRFJSDPXDFYDGJB2LPZUFPXUEW3"
        );
    }
}
