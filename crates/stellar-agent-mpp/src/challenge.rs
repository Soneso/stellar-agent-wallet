//! Bounded challenge parsing, selection, and Stellar charge validation.

use std::{collections::BTreeMap, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use stellar_strkey::Strkey;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    CHARGE_INTENT, STELLAR_METHOD, TESTNET_NETWORK,
    context::{HttpRequestContext, McpRequestContext, RequestContext},
    error::{MppError, MppErrorCode},
    json::{canonical_json, parse_strict_json},
    limits::{
        MAX_CHALLENGE_BYTES, MAX_CHALLENGE_LIFETIME_SECS, MAX_CHALLENGES, MAX_FIELD_BYTES,
        MAX_HEADER_BYTES, MAX_LONG_FIELD_BYTES, MAX_REQUEST_BYTES, MIN_CHALLENGE_LIFETIME_SECS,
    },
};

/// Transport-tagged MPP challenge input.
#[derive(Clone, Debug, Deserialize, schemars::JsonSchema, Serialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum ChallengeInput {
    /// One or more raw `WWW-Authenticate` field values and their HTTP context.
    Http {
        /// Raw header field values. Each must be bounded and independently valid.
        www_authenticate: Vec<String>,
        /// Optional challenge identifier used to resolve multiple supported options.
        selected_challenge_id: Option<String>,
        /// Request context the challenge authorizes.
        context: HttpRequestContext,
    },
    /// Native JSON challenge objects and their MCP context.
    Mcp {
        /// Native challenge objects from the payment-required error.
        challenges: Vec<Value>,
        /// Optional challenge identifier used to resolve multiple supported options.
        selected_challenge_id: Option<String>,
        /// Original MCP operation context.
        context: McpRequestContext,
    },
}

/// Exact selected challenge representation used in credentials.
#[derive(Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ChallengeEcho(Value);

impl ChallengeEcho {
    /// Returns the selected challenge object exactly as retained for its
    /// transport credential.
    #[must_use]
    pub const fn as_value(&self) -> &Value {
        &self.0
    }

    /// Returns the selected challenge identifier.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.0.get("id").and_then(Value::as_str)
    }
}

impl fmt::Debug for ChallengeEcho {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChallengeEcho([redacted])")
    }
}

/// Validated Stellar charge terms.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StellarChargeRequest {
    amount: i128,
    amount_decimal: String,
    currency: String,
    recipient: String,
    description: Option<String>,
    external_id: Option<String>,
}

impl StellarChargeRequest {
    /// Returns the positive amount in token base units.
    #[must_use]
    pub const fn amount(&self) -> i128 {
        self.amount
    }

    /// Returns the canonical decimal amount exactly as challenged.
    #[must_use]
    pub fn amount_decimal(&self) -> &str {
        &self.amount_decimal
    }

    /// Returns the SEP-41 token contract C-strkey.
    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }

    /// Returns the recipient G- or C-strkey.
    #[must_use]
    pub fn recipient(&self) -> &str {
        &self.recipient
    }

    /// Returns the optional payment description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the optional merchant reconciliation identifier.
    #[must_use]
    pub fn external_id(&self) -> Option<&str> {
        self.external_id.as_deref()
    }
}

/// Fully selected, validated, and context-bound sponsored charge challenge.
#[derive(Clone, Deserialize, Serialize)]
pub struct SelectedChallenge {
    echo: ChallengeEcho,
    request: StellarChargeRequest,
    context: RequestContext,
    effective_expires_at: i64,
    challenge_digest: [u8; 32],
}

impl SelectedChallenge {
    /// Returns the exact challenge echo.
    #[must_use]
    pub const fn echo(&self) -> &ChallengeEcho {
        &self.echo
    }

    /// Returns the validated payment terms.
    #[must_use]
    pub const fn request(&self) -> &StellarChargeRequest {
        &self.request
    }

    /// Returns the normalized transport request context.
    #[must_use]
    pub const fn context(&self) -> &RequestContext {
        &self.context
    }

    /// Returns the effective expiry as a Unix timestamp.
    #[must_use]
    pub const fn effective_expires_at(&self) -> i64 {
        self.effective_expires_at
    }

    /// Returns the SHA-256 digest of the exact selected challenge object.
    #[must_use]
    pub const fn challenge_digest(&self) -> &[u8; 32] {
        &self.challenge_digest
    }
}

impl fmt::Debug for SelectedChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedChallenge")
            .field("challenge", &"[redacted]")
            .field("request", &self.request)
            .field("effective_expires_at", &self.effective_expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestWire {
    amount: String,
    currency: String,
    recipient: String,
    description: Option<String>,
    external_id: Option<String>,
    method_details: Option<MethodDetailsWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MethodDetailsWire {
    network: String,
    fee_payer: Option<bool>,
    credential_types: Option<Vec<String>>,
}

struct Candidate {
    echo: ChallengeEcho,
    request_value: Value,
    context: RequestContext,
}

/// Parses all Payment challenges, selects exactly one supported Stellar charge,
/// and validates its request and request-context binding.
///
/// `now_unix` is injected so expiry tests and calling processes use one clock
/// observation.
///
/// # Errors
///
/// Returns a stable `mpp.*` error for malformed, unsupported, ambiguous,
/// expired, or context-mismatched input.
pub fn select_and_validate(
    input: &ChallengeInput,
    now_unix: i64,
) -> Result<SelectedChallenge, MppError> {
    let (candidates, selected_id) = match input {
        ChallengeInput::Http {
            www_authenticate,
            selected_challenge_id,
            context,
        } => {
            context.validate()?;
            (
                parse_http_candidates(www_authenticate, context)?,
                selected_challenge_id.as_deref(),
            )
        }
        ChallengeInput::Mcp {
            challenges,
            selected_challenge_id,
            context,
        } => {
            context.validate()?;
            (
                parse_mcp_candidates(challenges, context)?,
                selected_challenge_id.as_deref(),
            )
        }
    };
    validate_selected_id(selected_id)?;

    // Retained pre-filter so an empty selection can be classified with the
    // same precision on both transports.
    let echoes: Vec<Value> = candidates
        .iter()
        .map(|candidate| candidate.echo.0.clone())
        .collect();
    let mut matching = candidates
        .into_iter()
        .filter(|candidate| {
            let object = candidate.echo.0.as_object();
            let method = object
                .and_then(|value| value.get("method"))
                .and_then(Value::as_str);
            let intent = object
                .and_then(|value| value.get("intent"))
                .and_then(Value::as_str);
            let id = object
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str);
            method == Some(STELLAR_METHOD)
                && intent == Some(CHARGE_INTENT)
                && selected_id.is_none_or(|selected| id == Some(selected))
        })
        .collect::<Vec<_>>();

    if matching.len() > 1 {
        return Err(MppError::new(
            MppErrorCode::ChallengeAmbiguous,
            "multiple supported payment challenges require explicit selection",
        ));
    }
    let candidate = if let Some(candidate) = matching.pop() {
        candidate
    } else {
        return classify_unsupported(&echoes, selected_id);
    };
    validate_candidate(candidate, now_unix)
}

fn validate_candidate(candidate: Candidate, now_unix: i64) -> Result<SelectedChallenge, MppError> {
    let object = candidate.echo.0.as_object().ok_or_else(invalid_challenge)?;
    validate_required_challenge_fields(object)?;
    let request: RequestWire =
        serde_json::from_value(candidate.request_value).map_err(|_error| {
            MppError::new(
                MppErrorCode::ChallengeInvalid,
                "invalid Stellar charge request",
            )
        })?;
    let terms = validate_request(request)?;
    validate_digest_binding(object, &candidate.context)?;
    let effective_expires_at = effective_expiry(object, now_unix)?;
    let challenge_digest = Sha256::digest(canonical_json(&candidate.echo.0)?).into();
    Ok(SelectedChallenge {
        echo: candidate.echo,
        request: terms,
        context: candidate.context,
        effective_expires_at,
        challenge_digest,
    })
}

fn parse_http_candidates(
    fields: &[String],
    context: &HttpRequestContext,
) -> Result<Vec<Candidate>, MppError> {
    validate_challenge_count(fields.len())?;
    let mut total = 0_usize;
    let mut candidates = Vec::new();
    for field in fields {
        if field.len() > MAX_HEADER_BYTES {
            return Err(input_too_large());
        }
        total = total.checked_add(field.len()).ok_or_else(input_too_large)?;
        if total > MAX_CHALLENGE_BYTES {
            return Err(input_too_large());
        }
        for params in parse_payment_header(field)? {
            let request_encoded = params.get("request").ok_or_else(invalid_challenge)?;
            if request_encoded.contains('=') {
                return Err(invalid_challenge());
            }
            let request_bytes = URL_SAFE_NO_PAD
                .decode(request_encoded)
                .map_err(|_error| invalid_challenge())?;
            if request_bytes.len() > MAX_REQUEST_BYTES {
                return Err(input_too_large());
            }
            let request_value = parse_strict_json(&request_bytes)?;
            if canonical_json(&request_value)? != request_bytes {
                return Err(invalid_challenge());
            }
            let mut echo = Map::new();
            for (key, value) in params {
                echo.insert(key, Value::String(value));
            }
            candidates.push(Candidate {
                echo: ChallengeEcho(Value::Object(echo)),
                request_value,
                context: RequestContext::Http(context.clone()),
            });
        }
    }
    if candidates.len() > MAX_CHALLENGES {
        return Err(input_too_large());
    }
    Ok(candidates)
}

fn parse_mcp_candidates(
    challenges: &[Value],
    context: &McpRequestContext,
) -> Result<Vec<Candidate>, MppError> {
    validate_challenge_count(challenges.len())?;
    let mut total = 0_usize;
    challenges
        .iter()
        .map(|challenge| {
            let canonical = canonical_json(challenge)?;
            total = total
                .checked_add(canonical.len())
                .ok_or_else(input_too_large)?;
            if total > MAX_CHALLENGE_BYTES {
                return Err(input_too_large());
            }
            let object = challenge.as_object().ok_or_else(invalid_challenge)?;
            let request_value = object
                .get("request")
                .filter(|value| value.is_object())
                .cloned()
                .ok_or_else(invalid_challenge)?;
            // The native transport has no header-size ceiling, so the decoded
            // request bound is enforced here directly.
            if canonical_json(&request_value)?.len() > MAX_REQUEST_BYTES {
                return Err(input_too_large());
            }
            Ok(Candidate {
                echo: ChallengeEcho(challenge.clone()),
                request_value,
                context: RequestContext::Mcp(context.clone()),
            })
        })
        .collect()
}

fn validate_challenge_count(count: usize) -> Result<(), MppError> {
    if count == 0 {
        return Err(invalid_challenge());
    }
    if count > MAX_CHALLENGES {
        return Err(input_too_large());
    }
    Ok(())
}

fn parse_payment_header(field: &str) -> Result<Vec<BTreeMap<String, String>>, MppError> {
    let bytes = field.as_bytes();
    let mut index = skip_ows(bytes, 0);
    let mut challenges = Vec::new();
    while index < bytes.len() {
        let (scheme, next) = parse_token(bytes, index)?;
        index = next;
        if !scheme.eq_ignore_ascii_case("Payment") {
            return Err(invalid_challenge());
        }
        if index >= bytes.len() || !matches!(bytes[index], b' ' | b'\t') {
            return Err(invalid_challenge());
        }
        index = skip_ows(bytes, index);
        let mut params = BTreeMap::new();
        loop {
            let (name, next) = parse_token(bytes, index)?;
            index = skip_ows(bytes, next);
            if bytes.get(index) != Some(&b'=') {
                return Err(invalid_challenge());
            }
            index = skip_ows(bytes, index + 1);
            let (value, next) = parse_auth_value(bytes, index)?;
            index = skip_ows(bytes, next);
            let normalized = name.to_ascii_lowercase();
            if params.insert(normalized, value).is_some() {
                return Err(invalid_challenge());
            }
            if index == bytes.len() {
                challenges.push(params);
                break;
            }
            if bytes[index] != b',' {
                return Err(invalid_challenge());
            }
            index = skip_ows(bytes, index + 1);
            if index == bytes.len() {
                return Err(invalid_challenge());
            }
            if starts_payment_scheme(bytes, index) {
                challenges.push(params);
                break;
            }
        }
    }
    Ok(challenges)
}

fn parse_token(bytes: &[u8], start: usize) -> Result<(String, usize), MppError> {
    token_run(bytes, start, MAX_FIELD_BYTES)
}

// Auth-param VALUES are structurally bounded by the header-field limit during
// parsing; per-field semantic caps (short fields, long fields, the encoded
// request) are enforced after selection so the `request` parameter can carry
// its full encoded payload.
fn parse_value_token(bytes: &[u8], start: usize) -> Result<(String, usize), MppError> {
    token_run(bytes, start, MAX_HEADER_BYTES)
}

fn token_run(bytes: &[u8], start: usize, max: usize) -> Result<(String, usize), MppError> {
    let mut end = start;
    while end < bytes.len() && is_token_byte(bytes[end]) {
        end += 1;
    }
    if end == start || end - start > max {
        return Err(invalid_challenge());
    }
    let value = std::str::from_utf8(&bytes[start..end]).map_err(|_error| invalid_challenge())?;
    Ok((value.to_owned(), end))
}

fn parse_auth_value(bytes: &[u8], start: usize) -> Result<(String, usize), MppError> {
    if bytes.get(start) != Some(&b'"') {
        return parse_value_token(bytes, start);
    }
    let mut index = start + 1;
    let mut value = Vec::new();
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'"' => {
                if value.len() > MAX_HEADER_BYTES {
                    return Err(input_too_large());
                }
                let text = String::from_utf8(value).map_err(|_error| invalid_challenge())?;
                return Ok((text, index + 1));
            }
            b'\\' => {
                let escaped = *bytes.get(index + 1).ok_or_else(invalid_challenge)?;
                if escaped.is_ascii_control() {
                    return Err(invalid_challenge());
                }
                value.push(escaped);
                index += 2;
            }
            control if control.is_ascii_control() => return Err(invalid_challenge()),
            other => {
                value.push(other);
                index += 1;
            }
        }
    }
    Err(invalid_challenge())
}

fn starts_payment_scheme(bytes: &[u8], index: usize) -> bool {
    let remaining = &bytes[index..];
    remaining.len() > 7
        && remaining[..7].eq_ignore_ascii_case(b"Payment")
        && matches!(remaining[7], b' ' | b'\t')
}

const fn skip_ows(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
        index += 1;
    }
    index
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn validate_required_challenge_fields(object: &Map<String, Value>) -> Result<(), MppError> {
    for field in ["id", "realm", "method", "intent"] {
        let value = object
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(invalid_challenge)?;
        validate_short_field(value)?;
    }
    if let Some(value) = object.get("description") {
        validate_long_field(value.as_str().ok_or_else(invalid_challenge)?)?;
    }
    if let Some(value) = object.get("opaque") {
        validate_long_field(value.as_str().ok_or_else(invalid_challenge)?)?;
    }
    // Unknown members are retained only for exact challenge echo; bound each
    // one so the echo cannot smuggle oversized data past the named limits.
    // `request` and `expires`/`digest` carry their own dedicated bounds.
    for (key, value) in object {
        if matches!(
            key.as_str(),
            "id" | "realm"
                | "method"
                | "intent"
                | "description"
                | "opaque"
                | "request"
                | "expires"
                | "digest"
        ) {
            continue;
        }
        if canonical_json(value)?.len() > MAX_LONG_FIELD_BYTES {
            return Err(input_too_large());
        }
    }
    Ok(())
}

fn validate_request(request: RequestWire) -> Result<StellarChargeRequest, MppError> {
    let amount = parse_amount(&request.amount)?;
    if !matches!(
        Strkey::from_string(&request.currency),
        Ok(Strkey::Contract(_))
    ) {
        return Err(invalid_challenge());
    }
    if !matches!(
        Strkey::from_string(&request.recipient),
        Ok(Strkey::PublicKeyEd25519(_) | Strkey::Contract(_))
    ) {
        return Err(invalid_challenge());
    }
    let details = request.method_details.ok_or_else(invalid_challenge)?;
    if details.network != TESTNET_NETWORK {
        return Err(MppError::new(
            MppErrorCode::NetworkForbidden,
            "MPP charge is enabled only on Stellar testnet",
        ));
    }
    if details.fee_payer != Some(true) {
        return Err(MppError::new(
            MppErrorCode::UnsupportedMode,
            "only sponsored pull credentials are supported",
        ));
    }
    if details
        .credential_types
        .as_ref()
        .is_some_and(|types| !types.iter().any(|value| value == "transaction"))
    {
        return Err(MppError::new(
            MppErrorCode::UnsupportedMode,
            "server does not accept transaction credentials",
        ));
    }
    if let Some(description) = request.description.as_deref() {
        validate_long_field(description)?;
    }
    if let Some(external_id) = request.external_id.as_deref() {
        validate_long_field(external_id)?;
    }
    Ok(StellarChargeRequest {
        amount,
        amount_decimal: request.amount,
        currency: request.currency,
        recipient: request.recipient,
        description: request.description,
        external_id: request.external_id,
    })
}

fn parse_amount(value: &str) -> Result<i128, MppError> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid_challenge());
    }
    let amount = value
        .parse::<i128>()
        .map_err(|_error| invalid_challenge())?;
    if amount <= 0 {
        return Err(invalid_challenge());
    }
    Ok(amount)
}

fn validate_digest_binding(
    object: &Map<String, Value>,
    context: &RequestContext,
) -> Result<(), MppError> {
    let challenge_digest = object.get("digest").map(|value| {
        value
            .as_str()
            .filter(|digest| digest.starts_with("sha-256=") && digest.len() <= MAX_FIELD_BYTES)
            .ok_or_else(invalid_challenge)
    });
    let Some(challenge_digest) = challenge_digest.transpose()? else {
        return Ok(());
    };
    match context {
        RequestContext::Http(http) if http.content_digest() == Some(challenge_digest) => Ok(()),
        RequestContext::Http(_) => Err(MppError::new(
            MppErrorCode::ChallengeMismatch,
            "challenge body digest does not match request context",
        )),
        RequestContext::Mcp(_) => Err(MppError::new(
            MppErrorCode::ChallengeMismatch,
            "HTTP body digest is not valid for MCP context",
        )),
    }
}

fn effective_expiry(object: &Map<String, Value>, now_unix: i64) -> Result<i64, MppError> {
    let maximum = now_unix
        .checked_add(MAX_CHALLENGE_LIFETIME_SECS)
        .ok_or_else(invalid_challenge)?;
    let expiry = object.get("expires").map_or(Ok(maximum), |value| {
        let text = value.as_str().ok_or_else(invalid_challenge)?;
        validate_short_field(text)?;
        OffsetDateTime::parse(text, &Rfc3339)
            .map(|timestamp| timestamp.unix_timestamp().min(maximum))
            .map_err(|_error| invalid_challenge())
    })?;
    if expiry.saturating_sub(now_unix) < MIN_CHALLENGE_LIFETIME_SECS {
        return Err(MppError::new(
            MppErrorCode::ChallengeExpired,
            "challenge is expired or too close to expiry",
        ));
    }
    Ok(expiry)
}

fn classify_unsupported<T>(values: &[Value], selected_id: Option<&str>) -> Result<T, MppError> {
    if selected_id.is_some()
        && values
            .iter()
            .all(|value| value.get("id").and_then(Value::as_str) != selected_id)
    {
        return Err(invalid_challenge());
    }
    if values
        .iter()
        .any(|value| value.get("method").and_then(Value::as_str) != Some(STELLAR_METHOD))
    {
        return Err(MppError::new(
            MppErrorCode::UnsupportedMethod,
            "no selected Stellar payment challenge",
        ));
    }
    if values
        .iter()
        .any(|value| value.get("intent").and_then(Value::as_str) != Some(CHARGE_INTENT))
    {
        return Err(MppError::new(
            MppErrorCode::UnsupportedIntent,
            "no selected charge challenge",
        ));
    }
    Err(invalid_challenge())
}

fn validate_selected_id(value: Option<&str>) -> Result<(), MppError> {
    if let Some(id) = value {
        validate_short_field(id)?;
    }
    Ok(())
}

fn validate_short_field(value: &str) -> Result<(), MppError> {
    if value.is_empty()
        || value.len() > MAX_FIELD_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(invalid_challenge());
    }
    Ok(())
}

fn validate_long_field(value: &str) -> Result<(), MppError> {
    if value.len() > MAX_LONG_FIELD_BYTES || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(input_too_large());
    }
    Ok(())
}

const fn invalid_challenge() -> MppError {
    MppError::new(MppErrorCode::ChallengeInvalid, "invalid payment challenge")
}

const fn input_too_large() -> MppError {
    MppError::new(
        MppErrorCode::InputTooLarge,
        "MPP input exceeds a named limit",
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::needless_pass_by_value,
        reason = "test fixtures use expect for concise setup"
    )]

    use super::*;
    use proptest::prelude::*;

    const CONTRACT: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
    const ACCOUNT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

    fn http_context() -> HttpRequestContext {
        HttpRequestContext::new(
            "https://api.example.com",
            "GET",
            "https://api.example.com/resource",
            None,
            None,
        )
        .expect("valid context")
    }

    fn request() -> Value {
        serde_json::json!({
            "amount": "10000000",
            "currency": CONTRACT,
            "methodDetails": {
                "feePayer": true,
                "network": "stellar:testnet"
            },
            "recipient": ACCOUNT
        })
    }

    fn http_input() -> ChallengeInput {
        let encoded =
            URL_SAFE_NO_PAD.encode(canonical_json(&request()).expect("canonical request"));
        ChallengeInput::Http {
            www_authenticate: vec![format!(
                "Payment id=\"challenge-1\", realm=\"api.example.com\", method=\"stellar\", intent=\"charge\", request={encoded}"
            )],
            selected_challenge_id: None,
            context: http_context(),
        }
    }

    fn mcp_context() -> McpRequestContext {
        McpRequestContext::from_params(
            "server",
            crate::context::McpOperationKind::Tool,
            "charge",
            None,
        )
        .expect("valid context")
    }

    fn mcp_challenge(request: Value) -> Value {
        serde_json::json!({
            "id": "challenge-1",
            "realm": "server",
            "method": "stellar",
            "intent": "charge",
            "request": request
        })
    }

    fn mcp_input(challenges: Vec<Value>, selected_challenge_id: Option<&str>) -> ChallengeInput {
        ChallengeInput::Mcp {
            challenges,
            selected_challenge_id: selected_challenge_id.map(str::to_owned),
            context: mcp_context(),
        }
    }

    #[test]
    fn selects_valid_sponsored_http_charge() {
        let selected = select_and_validate(&http_input(), 1_700_000_000).expect("valid challenge");
        assert_eq!(selected.request().amount(), 10_000_000);
        assert_eq!(selected.echo().id(), Some("challenge-1"));
        assert_eq!(selected.effective_expires_at(), 1_700_000_300);
    }

    #[test]
    fn exposes_validated_mcp_terms_without_leaking_debug_echo() {
        let mut request = request();
        request["description"] = Value::String("invoice settlement".to_owned());
        request["externalId"] = Value::String("invoice-7".to_owned());
        request["methodDetails"]["credentialTypes"] = serde_json::json!(["transaction", "other"]);
        let mut challenge = mcp_challenge(request);
        challenge["description"] = Value::String("merchant challenge".to_owned());
        challenge["opaque"] = Value::String("round-trip".to_owned());
        challenge["expires"] = Value::String("2023-11-14T22:15:00Z".to_owned());

        let selected = select_and_validate(&mcp_input(vec![challenge], None), 1_700_000_000)
            .expect("valid MCP challenge");
        assert_eq!(selected.request().amount_decimal(), "10000000");
        assert_eq!(selected.request().currency(), CONTRACT);
        assert_eq!(selected.request().recipient(), ACCOUNT);
        assert_eq!(selected.request().description(), Some("invoice settlement"));
        assert_eq!(selected.request().external_id(), Some("invoice-7"));
        assert_eq!(selected.effective_expires_at(), 1_700_000_100);
        assert_eq!(selected.echo().as_value()["opaque"], "round-trip");
        assert_ne!(selected.challenge_digest(), &[0; 32]);
        assert_eq!(
            format!("{:?}", selected.echo()),
            "ChallengeEcho([redacted])"
        );
        let debug = format!("{selected:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("round-trip"));
    }

    #[test]
    fn rejects_duplicate_auth_params_case_insensitively() {
        let input = ChallengeInput::Http {
            www_authenticate: vec![
                "Payment id=a, ID=b, realm=r, method=stellar, intent=charge, request=e30"
                    .to_owned(),
            ],
            selected_challenge_id: None,
            context: http_context(),
        };
        assert!(select_and_validate(&input, 1_700_000_000).is_err());
    }

    #[test]
    fn rejects_noncanonical_amount() {
        let mut invalid = request();
        invalid["amount"] = Value::String("01".to_owned());
        let context = McpRequestContext::from_params(
            "server",
            crate::context::McpOperationKind::Tool,
            "charge",
            None,
        )
        .expect("valid context");
        let input = ChallengeInput::Mcp {
            challenges: vec![serde_json::json!({
                "id": "challenge-1",
                "realm": "server",
                "method": "stellar",
                "intent": "charge",
                "request": invalid
            })],
            selected_challenge_id: None,
            context,
        };
        assert!(select_and_validate(&input, 1_700_000_000).is_err());
    }

    #[test]
    fn requires_selection_for_multiple_supported_challenges() {
        let context = McpRequestContext::from_params(
            "server",
            crate::context::McpOperationKind::Tool,
            "charge",
            None,
        )
        .expect("valid context");
        let challenge = |id: &str| {
            serde_json::json!({
                "id": id,
                "realm": "server",
                "method": "stellar",
                "intent": "charge",
                "request": request()
            })
        };
        let input = ChallengeInput::Mcp {
            challenges: vec![challenge("one"), challenge("two")],
            selected_challenge_id: None,
            context,
        };
        let error = select_and_validate(&input, 1_700_000_000).expect_err("ambiguous");
        assert_eq!(error.code(), "mpp.challenge_ambiguous");
    }

    #[test]
    fn explicit_selection_resolves_multiple_supported_challenges() {
        let mut second = mcp_challenge(request());
        second["id"] = Value::String("challenge-2".to_owned());
        let selected = select_and_validate(
            &mcp_input(vec![mcp_challenge(request()), second], Some("challenge-2")),
            1_700_000_000,
        )
        .expect("explicit selection");
        assert_eq!(selected.echo().id(), Some("challenge-2"));
    }

    #[test]
    fn rejects_invalid_charge_request_variants_with_stable_codes() {
        let mut cases = Vec::new();

        for amount in [
            "",
            "0",
            "01",
            "-1",
            "1.0",
            "170141183460469231731687303715884105728",
        ] {
            let mut value = request();
            value["amount"] = Value::String(amount.to_owned());
            cases.push((value, "mpp.challenge_invalid"));
        }
        let mut value = request();
        value["currency"] = Value::String(ACCOUNT.to_owned());
        cases.push((value, "mpp.challenge_invalid"));
        let mut value = request();
        value["recipient"] = Value::String("not-an-account".to_owned());
        cases.push((value, "mpp.challenge_invalid"));
        let mut value = request();
        value
            .as_object_mut()
            .expect("object")
            .remove("methodDetails");
        cases.push((value, "mpp.challenge_invalid"));
        let mut value = request();
        value["unexpected"] = Value::Bool(true);
        cases.push((value, "mpp.challenge_invalid"));
        let mut value = request();
        value["methodDetails"]["network"] = Value::String("stellar:pubnet".to_owned());
        cases.push((value, "mpp.network_forbidden"));
        for fee_payer in [Value::Bool(false), Value::Null] {
            let mut value = request();
            value["methodDetails"]["feePayer"] = fee_payer;
            cases.push((value, "mpp.unsupported_mode"));
        }
        let mut value = request();
        value["methodDetails"]["credentialTypes"] = serde_json::json!(["signature"]);
        cases.push((value, "mpp.unsupported_mode"));
        let mut value = request();
        value["description"] = Value::String("x".repeat(MAX_LONG_FIELD_BYTES + 1));
        cases.push((value, "mpp.input_too_large"));
        let mut value = request();
        value["externalId"] = Value::String("bad\nreference".to_owned());
        cases.push((value, "mpp.input_too_large"));

        for (request, expected) in cases {
            let error = select_and_validate(
                &mcp_input(vec![mcp_challenge(request)], None),
                1_700_000_000,
            )
            .expect_err("invalid request");
            assert_eq!(error.code(), expected);
        }
    }

    #[test]
    fn rejects_invalid_challenge_fields_and_native_shapes() {
        let mut cases = vec![Value::Null, serde_json::json!({"request": request()})];
        for field in ["id", "realm", "method", "intent"] {
            let mut challenge = mcp_challenge(request());
            challenge[field] = Value::String(String::new());
            cases.push(challenge);
        }
        let mut challenge = mcp_challenge(request());
        challenge["description"] = Value::Bool(true);
        cases.push(challenge);
        let mut challenge = mcp_challenge(request());
        challenge["opaque"] = Value::String("x".repeat(MAX_LONG_FIELD_BYTES + 1));
        cases.push(challenge);
        let mut challenge = mcp_challenge(request());
        challenge["request"] = Value::String("not-an-object".to_owned());
        cases.push(challenge);

        for challenge in cases {
            assert!(select_and_validate(&mcp_input(vec![challenge], None), 1_700_000_000).is_err());
        }
    }

    #[test]
    fn enforces_digest_binding_for_http_and_mcp() {
        let digest = "sha-256=YWJj";
        let context = HttpRequestContext::new(
            "https://api.example.com",
            "POST",
            "https://api.example.com/resource",
            Some(digest),
            None,
        )
        .expect("valid digest context");
        let encoded = URL_SAFE_NO_PAD.encode(canonical_json(&request()).expect("request"));
        let http = |challenge_digest: &str| ChallengeInput::Http {
            www_authenticate: vec![format!(
                "Payment id=one, realm=server, method=stellar, intent=charge, digest=\"{challenge_digest}\", request={encoded}"
            )],
            selected_challenge_id: None,
            context: context.clone(),
        };
        assert!(select_and_validate(&http(digest), 1_700_000_000).is_ok());
        assert_eq!(
            select_and_validate(&http("sha-256=eHl6"), 1_700_000_000)
                .expect_err("mismatched digest")
                .code(),
            "mpp.challenge_mismatch"
        );

        let mut challenge = mcp_challenge(request());
        challenge["digest"] = Value::String(digest.to_owned());
        assert_eq!(
            select_and_validate(&mcp_input(vec![challenge], None), 1_700_000_000)
                .expect_err("HTTP digest on MCP")
                .code(),
            "mpp.challenge_mismatch"
        );
        let mut invalid = mcp_challenge(request());
        invalid["digest"] = Value::Number(1.into());
        assert!(select_and_validate(&mcp_input(vec![invalid], None), 1_700_000_000).is_err());
    }

    #[test]
    fn validates_expiry_and_caps_long_lived_challenges() {
        let challenge_with_expiry = |expires: Value| {
            let mut challenge = mcp_challenge(request());
            challenge["expires"] = expires;
            mcp_input(vec![challenge], None)
        };
        for expires in [
            Value::Bool(true),
            Value::String("not-a-date".to_owned()),
            Value::String("2023-11-14T22:13:30Z".to_owned()),
        ] {
            assert!(select_and_validate(&challenge_with_expiry(expires), 1_700_000_000).is_err());
        }
        let selected = select_and_validate(
            &challenge_with_expiry(Value::String("2099-01-01T00:00:00Z".to_owned())),
            1_700_000_000,
        )
        .expect("long expiry is capped");
        assert_eq!(selected.effective_expires_at(), 1_700_000_300);
        assert!(
            select_and_validate(&mcp_input(vec![mcp_challenge(request())], None), i64::MAX)
                .is_err()
        );
    }

    #[test]
    fn classifies_unsupported_and_unknown_selections() {
        let mut unsupported_method = mcp_challenge(request());
        unsupported_method["method"] = Value::String("evm".to_owned());
        assert_eq!(
            select_and_validate(&mcp_input(vec![unsupported_method], None), 1_700_000_000)
                .expect_err("method")
                .code(),
            "mpp.unsupported_method"
        );
        let mut unsupported_intent = mcp_challenge(request());
        unsupported_intent["intent"] = Value::String("pay".to_owned());
        assert_eq!(
            select_and_validate(&mcp_input(vec![unsupported_intent], None), 1_700_000_000)
                .expect_err("intent")
                .code(),
            "mpp.unsupported_intent"
        );
        assert_eq!(
            select_and_validate(
                &mcp_input(vec![mcp_challenge(request())], Some("missing")),
                1_700_000_000,
            )
            .expect_err("unknown selection")
            .code(),
            "mpp.challenge_invalid"
        );
        assert!(
            select_and_validate(
                &mcp_input(vec![mcp_challenge(request())], Some("bad\nselection")),
                1_700_000_000,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_empty_oversized_and_malformed_transport_inputs() {
        assert!(select_and_validate(&mcp_input(Vec::new(), None), 1_700_000_000).is_err());
        assert!(
            select_and_validate(
                &mcp_input(vec![mcp_challenge(request()); MAX_CHALLENGES + 1], None),
                1_700_000_000,
            )
            .is_err()
        );
        let huge = Value::String("x".repeat(MAX_CHALLENGE_BYTES + 1));
        assert!(select_and_validate(&mcp_input(vec![huge], None), 1_700_000_000).is_err());

        for header in [
            "Basic token",
            "Payment",
            "Payment id",
            "Payment id=",
            "Payment id=one; realm=server",
            "Payment id=one,",
            "Payment id=\"unterminated",
            "Payment id=\"bad\\",
            "Payment id=\"bad\nvalue\"",
            "Payment id=\"bad\\\nvalue\"",
        ] {
            assert!(parse_payment_header(header).is_err(), "accepted {header:?}");
        }
        // A quoted value beyond the header ceiling fails structurally; an
        // over-long but header-fitting `id` parses and is then rejected by the
        // semantic short-field bound during selection.
        assert!(
            parse_payment_header(&format!(
                "Payment id=\"{}\"",
                "x".repeat(MAX_HEADER_BYTES + 1)
            ))
            .is_err()
        );
        let long_id = format!(
            "Payment id=\"{}\", realm=server, method=stellar, intent=charge, request=e30",
            "x".repeat(MAX_LONG_FIELD_BYTES + 1)
        );
        assert_eq!(
            parse_payment_header(&long_id)
                .expect("parses structurally")
                .len(),
            1
        );
        let input = ChallengeInput::Http {
            www_authenticate: vec![long_id],
            selected_challenge_id: None,
            context: http_context(),
        };
        assert_eq!(
            select_and_validate(&input, 1_700_000_000)
                .expect_err("semantic id bound")
                .code(),
            "mpp.challenge_invalid"
        );

        let mut input = http_input();
        let ChallengeInput::Http {
            www_authenticate, ..
        } = &mut input
        else {
            unreachable!()
        };
        *www_authenticate = vec!["x".repeat(MAX_HEADER_BYTES + 1)];
        assert!(select_and_validate(&input, 1_700_000_000).is_err());
    }

    #[test]
    fn rejects_noncanonical_and_oversized_http_request_payloads() {
        let input_for = |encoded: String| ChallengeInput::Http {
            www_authenticate: vec![format!(
                "Payment id=one, realm=server, method=stellar, intent=charge, request={encoded}"
            )],
            selected_challenge_id: None,
            context: http_context(),
        };
        assert!(select_and_validate(&input_for("e30=".to_owned()), 1_700_000_000).is_err());
        assert!(select_and_validate(&input_for("!!!!".to_owned()), 1_700_000_000).is_err());
        let noncanonical = URL_SAFE_NO_PAD.encode(br#"{ "amount": 1 }"#);
        assert!(select_and_validate(&input_for(noncanonical), 1_700_000_000).is_err());
        let oversized = URL_SAFE_NO_PAD.encode(vec![b'x'; MAX_REQUEST_BYTES + 1]);
        assert_eq!(
            select_and_validate(&input_for(oversized), 1_700_000_000)
                .expect_err("request bound")
                .code(),
            "mpp.input_too_large"
        );
    }

    #[test]
    fn http_unsupported_method_and_intent_classify_precisely() {
        let header_with = |method: &str, intent: &str| {
            let encoded =
                URL_SAFE_NO_PAD.encode(canonical_json(&request()).expect("canonical request"));
            ChallengeInput::Http {
                www_authenticate: vec![format!(
                    "Payment id=one, realm=server, method={method}, intent={intent}, request={encoded}"
                )],
                selected_challenge_id: None,
                context: http_context(),
            }
        };
        assert_eq!(
            select_and_validate(&header_with("evm", "charge"), 1_700_000_000)
                .expect_err("HTTP unsupported method")
                .code(),
            "mpp.unsupported_method"
        );
        assert_eq!(
            select_and_validate(&header_with("stellar", "subscription"), 1_700_000_000)
                .expect_err("HTTP unsupported intent")
                .code(),
            "mpp.unsupported_intent"
        );
    }

    #[test]
    fn http_request_param_carries_a_long_description_within_named_limits() {
        // A validator-legal request (2 KiB description) encodes far beyond the
        // former 512-byte token cap; it must parse and validate over HTTP.
        let mut long_request = request();
        long_request["description"] = Value::String("d".repeat(MAX_LONG_FIELD_BYTES));
        let encoded =
            URL_SAFE_NO_PAD.encode(canonical_json(&long_request).expect("canonical request"));
        assert!(encoded.len() > 2 * MAX_FIELD_BYTES);
        let input = ChallengeInput::Http {
            www_authenticate: vec![format!(
                "Payment id=one, realm=server, method=stellar, intent=charge, request={encoded}"
            )],
            selected_challenge_id: None,
            context: http_context(),
        };
        let selected = select_and_validate(&input, 1_700_000_000).expect("long request parses");
        assert_eq!(
            selected.request().description(),
            Some("d".repeat(MAX_LONG_FIELD_BYTES).as_str())
        );
    }

    #[test]
    fn mcp_request_bound_bites_at_exactly_max_request_bytes() {
        // Build a request whose canonical form is exactly MAX_REQUEST_BYTES,
        // using an unknown member so the size gate and the wire decode yield
        // distinguishable codes.
        let request_of = |filler: usize| {
            let mut value = request();
            value["zzfiller"] = Value::String("x".repeat(filler));
            value
        };
        let base = canonical_json(&request_of(0))
            .expect("canonical base")
            .len();
        let at_limit = request_of(MAX_REQUEST_BYTES - base);
        assert_eq!(
            canonical_json(&at_limit).expect("canonical at-limit").len(),
            MAX_REQUEST_BYTES
        );
        // At the bound: the size gate passes; the unknown member then fails
        // wire decoding with the ordinary invalid code.
        assert_eq!(
            select_and_validate(
                &mcp_input(vec![mcp_challenge(at_limit)], None),
                1_700_000_000
            )
            .expect_err("unknown member")
            .code(),
            "mpp.challenge_invalid"
        );
        // One byte above: the size gate fires first.
        let over_limit = request_of(MAX_REQUEST_BYTES - base + 1);
        assert_eq!(
            select_and_validate(
                &mcp_input(vec![mcp_challenge(over_limit)], None),
                1_700_000_000,
            )
            .expect_err("request bound")
            .code(),
            "mpp.input_too_large"
        );
    }

    #[test]
    fn oversized_unknown_challenge_members_are_bounded() {
        let mut challenge = mcp_challenge(request());
        challenge["extension"] = Value::String("x".repeat(MAX_LONG_FIELD_BYTES + 1));
        assert_eq!(
            select_and_validate(&mcp_input(vec![challenge], None), 1_700_000_000)
                .expect_err("unknown member bound")
                .code(),
            "mpp.input_too_large"
        );
        let mut nested = mcp_challenge(request());
        nested["extension"] = serde_json::json!({ "data": "x".repeat(MAX_LONG_FIELD_BYTES) });
        assert_eq!(
            select_and_validate(&mcp_input(vec![nested], None), 1_700_000_000)
                .expect_err("nested unknown member bound")
                .code(),
            "mpp.input_too_large"
        );
    }

    proptest! {
        #[test]
        fn payment_auth_params_are_order_independent_and_preserve_quoted_values(
            identifier in "[A-Za-z0-9_-]{1,32}",
            realm in "[A-Za-z0-9._ -]{1,32}",
        ) {
            let left = format!(
                "Payment id=\"{identifier}\", realm=\"{realm}\", method=stellar, intent=charge, request=e30"
            );
            let right = format!(
                "Payment request=e30, intent=charge, method=stellar, realm=\"{realm}\", id=\"{identifier}\""
            );
            let left = parse_payment_header(&left).expect("valid left header");
            let right = parse_payment_header(&right).expect("valid right header");
            prop_assert_eq!(&left, &right);
            prop_assert_eq!(left[0].get("id").map(String::as_str), Some(identifier.as_str()));
            prop_assert_eq!(left[0].get("realm").map(String::as_str), Some(realm.as_str()));
        }
    }
}
