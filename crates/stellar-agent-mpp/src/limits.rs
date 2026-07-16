//! Named limits for untrusted MPP inputs and outputs.

/// Maximum Payment challenges accepted in one call.
pub const MAX_CHALLENGES: usize = 8;
/// Maximum bytes in one HTTP authentication header field.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Maximum bytes across all challenge input.
pub const MAX_CHALLENGE_BYTES: usize = 64 * 1024;
/// Maximum decoded request JSON bytes.
///
/// Reachable in full only on the native MCP transport. An HTTP challenge is
/// additionally bounded by [`MAX_HEADER_BYTES`], whose base64url capacity
/// (~12 KiB decoded) is tighter; the HTTP-side check remains as
/// defense-in-depth behind that structural ceiling.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// Maximum JSON nesting depth.
pub const MAX_JSON_DEPTH: usize = 32;
/// Maximum bytes in ordinary protocol identifier fields.
pub const MAX_FIELD_BYTES: usize = 512;
/// Maximum bytes in descriptions and external references.
pub const MAX_LONG_FIELD_BYTES: usize = 2 * 1024;
/// Maximum decoded receipt bytes.
pub const MAX_RECEIPT_BYTES: usize = 16 * 1024;
/// Maximum serialized credential bytes.
pub const MAX_CREDENTIAL_BYTES: usize = 128 * 1024;
/// Maximum transaction XDR bytes embedded in a credential.
pub const MAX_XDR_BYTES: usize = 128 * 1024;
/// Default and maximum effective challenge lifetime in seconds.
pub const MAX_CHALLENGE_LIFETIME_SECS: i64 = 5 * 60;
/// Minimum remaining challenge lifetime required for authorization.
pub const MIN_CHALLENGE_LIFETIME_SECS: i64 = 30;
