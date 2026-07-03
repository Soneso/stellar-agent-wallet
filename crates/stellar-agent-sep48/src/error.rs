//! Typed error enum for `stellar-agent-sep48`.
//!
//! [`Sep48Error`] covers the full set of failure modes across the SEP-48
//! contract-spec fetch + parse + render pipeline and the SEP-47
//! claim-discovery path.
//!
//! # Redaction
//!
//! No variant carries secret material. Contract IDs and RPC URLs are
//! first-5-last-5 redacted before inclusion in variant fields.

use thiserror::Error;

/// Errors from the SEP-48 typed-preview and SEP-47 claim-discovery pipeline.
///
/// # Redaction
///
/// All string fields that accept caller-supplied identifiers are expected to
/// be pre-redacted by the call site before constructing an error variant.
/// `Sep48Error` never stores raw secret bytes or private key material.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Sep48Error {
    /// The supplied contract address is not a valid C-strkey.
    ///
    /// # Arguments
    ///
    /// `addr` — the invalid address string, first-5-last-5 redacted.
    #[error("invalid contract address: {addr}")]
    InvalidContractAddress {
        /// First-5-last-5 redacted representation of the invalid address.
        addr: String,
    },

    /// An RPC request to fetch the contract WASM or ledger entries failed.
    ///
    /// # Arguments
    ///
    /// `reason` — a short description of the failure; never contains secret
    /// material.
    #[error("RPC fetch failed: {reason}")]
    RpcFetchFailure {
        /// Short description of the failure, stripped of any URL that would
        /// expose private RPC endpoint configuration.
        reason: String,
    },

    /// The fetched WASM bytes could not be parsed by `soroban-spec-tools`.
    ///
    /// # Arguments
    ///
    /// `reason` — upstream error description from `soroban_spec_tools::Error`.
    #[error("WASM parse failed: {reason}")]
    WasmParseFailure {
        /// Upstream error description from `soroban_spec_tools::Spec::from_wasm`.
        reason: String,
    },

    /// The WASM does not contain a `contractspecv0` custom section.
    ///
    /// Per the SEP-48 specification ("Wasm Custom Section"): the spec section
    /// MUST be present for a contract to conform to SEP-48.
    #[error("contract spec section missing from WASM (not a SEP-48 contract)")]
    SpecSectionMissing,

    /// The requested function was not found in the contract spec.
    ///
    /// # Arguments
    ///
    /// `function_name` — the name of the missing function.
    #[error("function '{function_name}' not found in contract spec")]
    FunctionNotFound {
        /// Name of the function requested but absent in the spec.
        function_name: String,
    },

    /// Decoding the `InvokeHostFunction` operation from the supplied XDR failed.
    ///
    /// # Arguments
    ///
    /// `reason` — XDR decode error description.
    #[error("InvokeHostFunction decode failed: {reason}")]
    InvokeDecodeFailed {
        /// XDR decode error description.
        reason: String,
    },

    /// An argument `ScVal` could not be rendered to JSON because its type is
    /// not supported in the current render path.
    ///
    /// # Arguments
    ///
    /// `arg_index` — zero-based position of the unsupported argument.
    /// `type_hint` — human-readable name of the `ScType` that was encountered.
    #[error("unsupported arg type at position {arg_index}: {type_hint}")]
    UnsupportedArgType {
        /// Zero-based index of the argument that could not be rendered.
        arg_index: usize,
        /// Human-readable description of the `ScType` discriminant.
        type_hint: String,
    },

    /// The number of positional arguments does not match the number of
    /// parameters declared in the function spec.
    ///
    /// A Soroban contract function has a fixed arity defined by its SEP-48
    /// spec. A mismatch indicates a spec/invocation mismatch (e.g. the wrong
    /// transaction was provided, or the spec is out of sync with the deployed
    /// bytecode) and MUST fail closed rather than render a misleading partial
    /// preview.
    ///
    /// # Arguments
    ///
    /// `expected` — the number of parameters declared in the spec.
    /// `actual` — the number of positional args supplied by the caller.
    #[error(
        "argument count mismatch: expected {expected} (from spec), got {actual} (from invocation)"
    )]
    ArgCountMismatch {
        /// Number of parameters declared in the function spec.
        expected: usize,
        /// Number of positional `ScVal` args supplied by the caller.
        actual: usize,
    },
}

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    //! Test constructors for [`Sep48Error`] variants.
    //!
    //! Gated by `#[cfg(any(test, feature = "test-helpers"))]` so these
    //! constructors are never compiled into production binaries.

    use super::Sep48Error;

    /// Constructs a [`Sep48Error::InvalidContractAddress`] for tests.
    #[must_use]
    pub fn invalid_contract_address(addr: impl Into<String>) -> Sep48Error {
        Sep48Error::InvalidContractAddress { addr: addr.into() }
    }

    /// Constructs a [`Sep48Error::RpcFetchFailure`] for tests.
    #[must_use]
    pub fn rpc_fetch_failure(reason: impl Into<String>) -> Sep48Error {
        Sep48Error::RpcFetchFailure {
            reason: reason.into(),
        }
    }

    /// Constructs a [`Sep48Error::WasmParseFailure`] for tests.
    #[must_use]
    pub fn wasm_parse_failure(reason: impl Into<String>) -> Sep48Error {
        Sep48Error::WasmParseFailure {
            reason: reason.into(),
        }
    }

    /// Constructs a [`Sep48Error::InvokeDecodeFailed`] for tests.
    #[must_use]
    pub fn invoke_decode_failed(reason: impl Into<String>) -> Sep48Error {
        Sep48Error::InvokeDecodeFailed {
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]
mod tests {
    use super::Sep48Error;
    use super::test_helpers;

    #[test]
    fn test_helpers_construct_correct_variants() {
        assert!(matches!(
            test_helpers::invalid_contract_address("bad"),
            Sep48Error::InvalidContractAddress { addr } if addr == "bad"
        ));
        assert!(matches!(
            test_helpers::rpc_fetch_failure("rpc down"),
            Sep48Error::RpcFetchFailure { reason } if reason == "rpc down"
        ));
        assert!(matches!(
            test_helpers::wasm_parse_failure("bad wasm"),
            Sep48Error::WasmParseFailure { reason } if reason == "bad wasm"
        ));
        assert!(matches!(
            test_helpers::invoke_decode_failed("bad tx"),
            Sep48Error::InvokeDecodeFailed { reason } if reason == "bad tx"
        ));
    }

    #[test]
    fn error_display_messages_are_correct() {
        let e = Sep48Error::InvalidContractAddress {
            addr: "CBAD".to_owned(),
        };
        assert!(e.to_string().contains("CBAD"), "display must include addr");

        let e = Sep48Error::ArgCountMismatch {
            expected: 2,
            actual: 3,
        };
        assert!(
            e.to_string().contains("expected 2"),
            "display must include expected count"
        );
        assert!(
            e.to_string().contains("got 3"),
            "display must include actual count"
        );

        let e = Sep48Error::UnsupportedArgType {
            arg_index: 1,
            type_hint: "Bool".to_owned(),
        };
        assert!(
            e.to_string().contains("position 1"),
            "display must include arg_index"
        );
        assert!(
            e.to_string().contains("Bool"),
            "display must include type_hint"
        );
    }
}
