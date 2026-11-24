//! The `mainnet.approval_origin` and `mainnet.approval_cert_spki_sha256`
//! fields of a signed mainnet policy.
//!
//! ```toml
//! approval_origin = "https://approve.example.invalid:8443"
//! approval_cert_spki_sha256 = "<64 lowercase hex characters>"
//! ```
//!
//! The origin is exactly `https://<host>[:<port>]`. The host is a lowercase
//! ASCII DNS name whose last label is neither all decimal digits nor `0x`
//! followed by hex digits, so no URL parser reads it as an IPv4 address. The
//! port is 1 through 65535 in decimal without a sign or leading zero; the
//! default port 443 is omitted, so each origin has one spelling. The RP ID is
//! the entire host. The pin is the SHA-256 of the served leaf certificate's
//! SPKI DER.
//!
//! The loader, the verified projection, and the bootstrap validator parse the
//! fields through this module, so they agree on what is accepted. The minimum
//! evaluator and the bootstrap validator share its pairing rule. The core
//! crate does not depend on the remote approval crate, so the host check
//! lives here.

use crate::policy::PolicyError;
use toml_edit::{Item, TableLike};

/// The only accepted scheme, with its separator.
const SCHEME: &str = "https://";

/// The default HTTPS port, which a canonical origin omits.
const DEFAULT_PORT: u16 = 443;

/// The longest accepted host, in bytes.
const HOST_MAX: usize = 253;

/// The longest accepted DNS label, in bytes.
const LABEL_MAX: usize = 63;

/// The minimum requirement refusing a certificate pin without an origin.
pub const REQUIREMENT_PIN_WITHOUT_ORIGIN: &str = "approval.cert_pin_without_origin";

/// The minimum requirement refusing an origin without a certificate pin.
pub const REQUIREMENT_ORIGIN_WITHOUT_PIN: &str = "approval.origin_without_cert_pin";

/// The parse details, fixed so an error never reflects policy content.
const DETAIL_ORIGIN: &str = "mainnet.approval_origin must be a canonical HTTPS DNS origin";
const DETAIL_PIN: &str = "mainnet.approval_cert_spki_sha256 must be 64 lowercase hex characters";

/// A canonical HTTPS approval origin whose RP ID is its entire DNS host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalOrigin(String);

impl ApprovalOrigin {
    /// Returns the validated origin, including its port when present.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the RP ID: the entire origin host, without scheme or port.
    #[must_use]
    pub fn rp_id(&self) -> &str {
        let authority = &self.0[SCHEME.len()..];
        authority
            .split_once(':')
            .map_or(authority, |(host, _)| host)
    }

    /// Validates `text` against the origin grammar.
    fn parse(text: &str) -> Result<Self, PolicyError> {
        let authority = text.strip_prefix(SCHEME).ok_or_else(origin_error)?;
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        if !valid_host(host) || port.is_some_and(|port| !valid_port(port)) {
            return Err(origin_error());
        }
        Ok(Self(text.to_owned()))
    }
}

fn origin_error() -> PolicyError {
    PolicyError::PolicyFileParseFailed {
        detail: DETAIL_ORIGIN.to_owned(),
    }
}

fn pin_error() -> PolicyError {
    PolicyError::PolicyFileParseFailed {
        detail: DETAIL_PIN.to_owned(),
    }
}

/// Whether `host` is a lowercase ASCII DNS name that no URL parser reads as
/// an IPv4 address.
fn valid_host(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or_default();
    let numeric = last.bytes().all(|b| b.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()));
    !numeric
        && host.len() <= HOST_MAX
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= LABEL_MAX
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Whether `port` is a decimal port from 1 through 65535 other than the
/// default, without a sign or leading zero.
fn valid_port(port: &str) -> bool {
    !port.starts_with('0')
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|n| n != DEFAULT_PORT)
}

/// Decodes a pin of lowercase hex characters; the decoder refuses any length
/// other than 64.
fn parse_pin(item: &Item) -> Result<[u8; 32], PolicyError> {
    let text = item.as_str().ok_or_else(pin_error)?;
    if !text
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(pin_error());
    }
    crate::hex::decode_hex32(text).map_err(|_| pin_error())
}

/// Parses the origin and the pin of a `[mainnet]` table; `None` for an
/// absent field.
///
/// # Errors
/// Returns [`PolicyError::PolicyFileParseFailed`] with a fixed detail for a
/// present field of the wrong type or grammar.
pub(crate) fn parse_fields(
    table: &dyn TableLike,
) -> Result<(Option<ApprovalOrigin>, Option<[u8; 32]>), PolicyError> {
    let origin = table
        .get("approval_origin")
        .map(|item| ApprovalOrigin::parse(item.as_str().ok_or_else(origin_error)?))
        .transpose()?;
    let pin = table
        .get("approval_cert_spki_sha256")
        .map(parse_pin)
        .transpose()?;
    Ok((origin, pin))
}

/// Refuses a certificate pin without an origin, and an origin without a
/// certificate pin. Both present or both absent pass.
///
/// The mainnet minimum and [`validate_bootstrap`] apply this one rule.
///
/// # Errors
/// Returns [`PolicyError::MainnetMinimumUnmet`] without a rule index, naming
/// [`REQUIREMENT_PIN_WITHOUT_ORIGIN`] or [`REQUIREMENT_ORIGIN_WITHOUT_PIN`].
pub fn validate_pair(origin_present: bool, pin_present: bool) -> Result<(), PolicyError> {
    let requirement = match (origin_present, pin_present) {
        (false, true) => REQUIREMENT_PIN_WITHOUT_ORIGIN,
        (true, false) => REQUIREMENT_ORIGIN_WITHOUT_PIN,
        _ => return Ok(()),
    };
    Err(PolicyError::MainnetMinimumUnmet {
        requirement,
        rule: None,
    })
}

/// Reads the origin and the pin from an unsigned `[mainnet]` table.
///
/// Applies the closed mainnet key set, the field grammar, and
/// [`validate_pair`]. It reads no credential and verifies no signature, so it
/// accepts a table before the policy is complete or signed.
///
/// # Errors
/// Returns [`PolicyError::PolicyFileParseFailed`] for an unknown key or a
/// malformed field, and [`PolicyError::MainnetMinimumUnmet`] for a lone
/// origin or pin.
pub fn validate_bootstrap(
    table: &dyn TableLike,
) -> Result<(Option<ApprovalOrigin>, Option<[u8; 32]>), PolicyError> {
    super::schema::reject_unknown_keys(
        table,
        super::schema::MAINNET_KEYS,
        Some("mainnet"),
        "the mainnet table",
    )?;
    let (origin, pin) = parse_fields(table)?;
    validate_pair(origin.is_some(), pin.is_some())?;
    Ok((origin, pin))
}
