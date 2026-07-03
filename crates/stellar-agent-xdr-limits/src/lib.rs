//! Recursion-depth and length bounds for decoding XDR from untrusted sources.
//!
//! All sites in the Stellar agent wallet that decode XDR originating from an
//! untrusted caller or network peer use [`untrusted_decode_limits`] rather than
//! `Limits::none()`. This crate is a separate leaf so lean SEP crates can apply
//! the policy without depending on the heavy `stellar-agent-core` substrate.
//!
//! # Why both bounds matter
//!
//! - **Depth** (`depth` field): XDR decode is recursive per nesting level
//!   (e.g. `SorobanAuthorizedInvocation.sub_invocations`,
//!   `TransactionEnvelope`). An unbounded decode of a crafted depth-bomb exhausts
//!   the stack and aborts the process. [`XDR_DECODE_MAX_DEPTH`] matches the limit
//!   `soroban-env-host` applies to its own XDR (de)serialization
//!   (`DEFAULT_XDR_RW_LIMITS.depth`).
//!
//! - **Length** (`len` field): A forged XDR length field can drive an oversized
//!   allocation. Capping `len` to the input buffer size prevents that class of
//!   attack because a legitimate payload can never require more bytes than its
//!   own encoding already contains.
use stellar_xdr::Limits;

/// Maximum recursion depth permitted when decoding XDR from an untrusted source.
///
/// Bounding recursion depth is the guard against a maliciously deeply nested
/// structure (for example a `SorobanAuthorizedInvocation.sub_invocations` chain
/// or nested `TransactionEnvelope`) exhausting the stack and aborting the
/// process. The value matches the recursion limit `soroban-env-host` applies to
/// XDR (de)serialization (`DEFAULT_XDR_RW_LIMITS.depth`).
pub const XDR_DECODE_MAX_DEPTH: u32 = 500;

/// `Limits` for decoding XDR received from an untrusted source.
///
/// Caps recursion depth at [`XDR_DECODE_MAX_DEPTH`] and the number of bytes read
/// to `input_len` (the size of the encoded input buffer). Deserialization length
/// must be bounded to the input size rather than left unbounded, so a forged
/// length field cannot drive an oversized allocation. For base64 input pass the
/// base64 string length: the decoded byte length is strictly smaller, so this
/// never rejects valid input.
#[must_use]
pub fn untrusted_decode_limits(input_len: usize) -> Limits {
    Limits {
        depth: XDR_DECODE_MAX_DEPTH,
        len: input_len,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use stellar_xdr::Limits;

    use super::*;

    #[test]
    fn xdr_decode_max_depth_is_500() {
        assert_eq!(XDR_DECODE_MAX_DEPTH, 500);
    }

    #[test]
    fn untrusted_decode_limits_sets_both_fields() {
        assert_eq!(
            untrusted_decode_limits(123),
            Limits {
                depth: 500,
                len: 123,
            }
        );
    }

    #[test]
    fn untrusted_decode_limits_zero_len() {
        assert_eq!(untrusted_decode_limits(0), Limits { depth: 500, len: 0 });
    }
}
