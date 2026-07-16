//! Request-context normalization and cryptographic binding.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    error::{MppError, MppErrorCode},
    json::canonical_json,
    limits::MAX_FIELD_BYTES,
};

/// Normalized HTTP request context bound into an MPP authorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, schemars::JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestContext {
    origin: String,
    http_method: String,
    canonical_resource: String,
    content_digest: Option<String>,
    idempotency_key_hash: Option<String>,
}

impl HttpRequestContext {
    /// Validates and normalizes an HTTPS request context.
    ///
    /// `resource` must be an absolute URL on `origin`. Fragments and embedded
    /// credentials are forbidden.
    ///
    /// # Errors
    ///
    /// Returns `mpp.challenge_mismatch` for an invalid or cross-origin context.
    pub fn new(
        origin: &str,
        http_method: &str,
        resource: &str,
        content_digest: Option<&str>,
        idempotency_key_hash: Option<&str>,
    ) -> Result<Self, MppError> {
        let origin_url = parse_https_url(origin)?;
        if origin_url.path() != "/"
            || origin_url.query().is_some()
            || origin_url.fragment().is_some()
        {
            return Err(context_error("origin must not contain a resource path"));
        }
        let resource_url = parse_https_url(resource)?;
        if origin_url.origin() != resource_url.origin() || resource_url.fragment().is_some() {
            return Err(context_error("resource must match the HTTPS origin"));
        }

        let method = normalize_http_method(http_method)?;
        let digest = content_digest.map(validate_content_digest).transpose()?;
        let key_hash = idempotency_key_hash.map(validate_hex_digest).transpose()?;

        Ok(Self {
            origin: origin_url.origin().ascii_serialization(),
            http_method: method,
            canonical_resource: resource_url.to_string(),
            content_digest: digest,
            idempotency_key_hash: key_hash,
        })
    }

    /// Returns the normalized HTTPS origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Returns the uppercase HTTP method.
    #[must_use]
    pub fn http_method(&self) -> &str {
        &self.http_method
    }

    /// Returns the canonical absolute resource URL.
    #[must_use]
    pub fn canonical_resource(&self) -> &str {
        &self.canonical_resource
    }

    /// Returns the optional canonical body digest.
    #[must_use]
    pub fn content_digest(&self) -> Option<&str> {
        self.content_digest.as_deref()
    }

    /// Returns the resource for operator display: origin plus path, with the
    /// query and fragment stripped. Query values may carry sensitive request
    /// data and never reach approval summaries, previews, or status output;
    /// the full canonical resource stays bound in the context digest and the
    /// authorization fingerprint.
    #[must_use]
    pub fn display_resource(&self) -> String {
        match Url::parse(&self.canonical_resource) {
            Ok(mut url) => {
                url.set_query(None);
                url.set_fragment(None);
                url.to_string()
            }
            // The stored resource is always a validated HTTPS URL; if it ever
            // fails to re-parse, fall back to the origin rather than leaking
            // the raw string.
            Err(_) => self.origin.clone(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), MppError> {
        let normalized = Self::new(
            &self.origin,
            &self.http_method,
            &self.canonical_resource,
            self.content_digest.as_deref(),
            self.idempotency_key_hash.as_deref(),
        )?;
        if normalized != *self {
            return Err(context_error("HTTP request context is not canonical"));
        }
        Ok(())
    }
}

/// MCP operation family bound into an MPP authorization.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, schemars::JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpOperationKind {
    /// An MCP tool invocation.
    Tool,
    /// An MCP resource read.
    Resource,
    /// An MCP prompt request.
    Prompt,
}

/// Normalized MCP request context bound into an MPP authorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, schemars::JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpRequestContext {
    server_identity: String,
    operation: McpOperationKind,
    target: String,
    params_digest: String,
}

impl McpRequestContext {
    /// Builds a context and computes the params digest. `None` is intentionally
    /// distinct from `Some(JSON null)`.
    ///
    /// # Errors
    ///
    /// Returns a redacted challenge error for oversized fields or values that
    /// cannot be canonicalized.
    pub fn from_params(
        server_identity: &str,
        operation: McpOperationKind,
        target: &str,
        params: Option<&Value>,
    ) -> Result<Self, MppError> {
        validate_field(server_identity)?;
        validate_field(target)?;
        let mut envelope = Map::new();
        envelope.insert("present".to_owned(), Value::Bool(params.is_some()));
        if let Some(value) = params {
            envelope.insert("value".to_owned(), value.clone());
        }
        let digest = Sha256::digest(canonical_json(&Value::Object(envelope))?);
        Ok(Self {
            server_identity: server_identity.to_owned(),
            operation,
            target: target.to_owned(),
            params_digest: hex::encode(digest),
        })
    }

    /// Returns the stable upstream server identity.
    #[must_use]
    pub fn server_identity(&self) -> &str {
        &self.server_identity
    }

    /// Returns the operation family.
    #[must_use]
    pub const fn operation(&self) -> McpOperationKind {
        self.operation
    }

    /// Returns the operation target.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the lowercase params SHA-256 digest.
    #[must_use]
    pub fn params_digest(&self) -> &str {
        &self.params_digest
    }

    pub(crate) fn validate(&self) -> Result<(), MppError> {
        validate_field(&self.server_identity)?;
        validate_field(&self.target)?;
        validate_hex_digest(&self.params_digest)?;
        Ok(())
    }
}

/// Transport-specific request context.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, schemars::JsonSchema, Serialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum RequestContext {
    /// HTTP request binding.
    Http(HttpRequestContext),
    /// MCP request binding.
    Mcp(McpRequestContext),
}

impl RequestContext {
    /// Computes the versioned context SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns a redacted challenge error if canonical serialization fails.
    pub fn digest(&self) -> Result<[u8; 32], MppError> {
        self.validate()?;
        let value = serde_json::to_value(self).map_err(|_error| {
            MppError::new(
                MppErrorCode::ChallengeInvalid,
                "request context serialization failed",
            )
        })?;
        let bytes = canonical_json(&value)?;
        let mut hash = Sha256::new();
        hash.update(b"stellar-agent-mpp-context:v1\0");
        hash.update(bytes);
        Ok(hash.finalize().into())
    }

    pub(crate) fn validate(&self) -> Result<(), MppError> {
        match self {
            Self::Http(context) => context.validate(),
            Self::Mcp(context) => context.validate(),
        }
    }
}

fn parse_https_url(value: &str) -> Result<Url, MppError> {
    let url = Url::parse(value).map_err(|_error| context_error("invalid HTTPS URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(context_error("invalid HTTPS URL"));
    }
    Ok(url)
}

fn normalize_http_method(value: &str) -> Result<String, MppError> {
    if value.is_empty()
        || value.len() > MAX_FIELD_BYTES
        || !value.bytes().all(is_token_byte)
        || value.eq_ignore_ascii_case("TRACE")
        || value.eq_ignore_ascii_case("CONNECT")
    {
        return Err(context_error("unsupported HTTP method"));
    }
    Ok(value.to_ascii_uppercase())
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

fn validate_content_digest(value: &str) -> Result<String, MppError> {
    let Some(encoded) = value.strip_prefix("sha-256=") else {
        return Err(context_error("invalid content digest"));
    };
    if encoded.is_empty()
        || encoded.len() > MAX_FIELD_BYTES
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(context_error("invalid content digest"));
    }
    Ok(value.to_owned())
}

fn validate_hex_digest(value: &str) -> Result<String, MppError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(context_error("invalid idempotency-key digest"));
    }
    Ok(value.to_owned())
}

fn validate_field(value: &str) -> Result<(), MppError> {
    if value.is_empty()
        || value.len() > MAX_FIELD_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(context_error("invalid MCP request context"));
    }
    Ok(())
}

const fn context_error(message: &'static str) -> MppError {
    MppError::new(MppErrorCode::ChallengeMismatch, message)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test fixtures use expect for concise setup"
    )]

    use super::*;

    #[test]
    fn normalizes_http_context() {
        let context = HttpRequestContext::new(
            "https://EXAMPLE.com",
            "post",
            "https://example.com:443/pay?order=1",
            None,
            None,
        )
        .expect("valid context");
        assert_eq!(context.origin(), "https://example.com");
        assert_eq!(context.http_method(), "POST");
        assert_eq!(
            context.canonical_resource(),
            "https://example.com/pay?order=1"
        );
    }

    #[test]
    fn display_resource_strips_query_and_fragment() {
        let context = HttpRequestContext::new(
            "https://merchant.example",
            "POST",
            "https://merchant.example/checkout?order=42&customer=alice",
            None,
            None,
        )
        .expect("valid context");
        assert_eq!(
            context.display_resource(),
            "https://merchant.example/checkout"
        );
        assert!(!context.display_resource().contains("alice"));
        // The full canonical resource (with query) stays bound for replay.
        assert!(context.canonical_resource().contains("customer=alice"));

        let plain = HttpRequestContext::new(
            "https://merchant.example",
            "GET",
            "https://merchant.example/paid",
            None,
            None,
        )
        .expect("valid context");
        assert_eq!(plain.display_resource(), "https://merchant.example/paid");
    }

    #[test]
    fn rejects_cross_origin_context() {
        assert!(
            HttpRequestContext::new(
                "https://example.com",
                "GET",
                "https://other.example/pay",
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn absent_and_null_mcp_params_have_different_digests() {
        let absent = McpRequestContext::from_params("server", McpOperationKind::Tool, "pay", None)
            .expect("valid context");
        let null = McpRequestContext::from_params(
            "server",
            McpOperationKind::Tool,
            "pay",
            Some(&Value::Null),
        )
        .expect("valid context");
        assert_ne!(absent.params_digest(), null.params_digest());
    }

    #[test]
    fn rejects_noncanonical_deserialized_http_context() {
        let context: HttpRequestContext = serde_json::from_value(serde_json::json!({
            "origin": "https://EXAMPLE.com",
            "http_method": "post",
            "canonical_resource": "https://example.com:443/pay",
            "content_digest": null,
            "idempotency_key_hash": null
        }))
        .expect("wire shape");
        assert!(context.validate().is_err());
    }

    #[test]
    fn rejects_malformed_deserialized_mcp_digest() {
        let context: McpRequestContext = serde_json::from_value(serde_json::json!({
            "server_identity": "server",
            "operation": "tool",
            "target": "pay",
            "params_digest": "not-a-sha256-digest"
        }))
        .expect("wire shape");
        assert!(context.validate().is_err());
    }

    #[test]
    fn exposes_mcp_context_fields_and_digest() {
        let context = McpRequestContext::from_params(
            "server.example",
            McpOperationKind::Resource,
            "ledger://entry",
            Some(&serde_json::json!({"z": 1, "a": 2})),
        )
        .expect("valid context");
        assert_eq!(context.server_identity(), "server.example");
        assert_eq!(context.operation(), McpOperationKind::Resource);
        assert_eq!(context.target(), "ledger://entry");
        assert_eq!(context.params_digest().len(), 64);
        assert_ne!(
            RequestContext::Mcp(context).digest().expect("MCP digest"),
            RequestContext::Http(
                HttpRequestContext::new(
                    "https://server.example",
                    "GET",
                    "https://server.example/ledger",
                    None,
                    None,
                )
                .expect("HTTP context")
            )
            .digest()
            .expect("HTTP digest")
        );
    }

    #[test]
    fn rejects_invalid_http_context_components() {
        let invalid = [
            (
                "http://example.com",
                "GET",
                "http://example.com/pay",
                None,
                None,
            ),
            (
                "https://example.com/path",
                "GET",
                "https://example.com/pay",
                None,
                None,
            ),
            (
                "https://example.com?query=1",
                "GET",
                "https://example.com/pay",
                None,
                None,
            ),
            (
                "https://user@example.com",
                "GET",
                "https://example.com/pay",
                None,
                None,
            ),
            (
                "https://example.com",
                "TRACE",
                "https://example.com/pay",
                None,
                None,
            ),
            (
                "https://example.com",
                "CONNECT",
                "https://example.com/pay",
                None,
                None,
            ),
            (
                "https://example.com",
                "BAD METHOD",
                "https://example.com/pay",
                None,
                None,
            ),
            (
                "https://example.com",
                "POST",
                "https://example.com/pay#fragment",
                None,
                None,
            ),
            (
                "https://example.com",
                "POST",
                "https://example.com/pay",
                Some("sha-512=abc"),
                None,
            ),
            (
                "https://example.com",
                "POST",
                "https://example.com/pay",
                Some("sha-256="),
                None,
            ),
            (
                "https://example.com",
                "POST",
                "https://example.com/pay",
                None,
                Some("ABC"),
            ),
        ];
        for (origin, method, resource, digest, key_hash) in invalid {
            assert!(
                HttpRequestContext::new(origin, method, resource, digest, key_hash).is_err(),
                "accepted invalid context: {origin} {method} {resource}"
            );
        }
    }

    #[test]
    fn accepts_canonical_optional_http_digests() {
        let context = HttpRequestContext::new(
            "https://example.com",
            "PATCH",
            "https://example.com/pay",
            Some("sha-256=YWJjZA=="),
            Some(&"a".repeat(64)),
        )
        .expect("canonical optional digests");
        assert_eq!(context.content_digest(), Some("sha-256=YWJjZA=="));
        assert!(format!("{context:?}").contains("PATCH"));
    }

    #[test]
    fn rejects_invalid_mcp_identity_and_target_fields() {
        for (server, target) in [("", "tool"), ("server", ""), ("server\n", "tool")] {
            assert!(
                McpRequestContext::from_params(server, McpOperationKind::Prompt, target, None)
                    .is_err()
            );
        }
    }
}
