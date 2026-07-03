//! SEP-48 contract-interface typed-preview and SEP-47 Contract Interface
//! Discovery for the Stellar agent wallet.
//!
//! # What this crate does
//!
//! Implements the agent-side SEP-48 ("Contract Interface Specification") typed
//! argument preview and SEP-47 ("Contract Interface Discovery") claim-discovery
//! per the SEP-48 / SEP-47 specifications.
//!
//! # Primary consumers
//!
//! - `stellar-agent-mcp`: `stellar_sep48_preview_invocation` and
//!   `stellar_sep47_discover` MCP tools.
//!
//! # What this crate does NOT do
//!
//! - Does NOT submit transactions or modify chain state.
//! - Does NOT extend `stellar_agent_core::envelope_decode::decode_authoritative_args`
//!   (SEP-48 owns its own `InvokeHostFunction` decode path;
//!   `decode_authoritative_args` covers classic-op-only paths).
//! - Does NOT validate spec semantics beyond the bounded XDR parse: upstream
//!   contract specs are treated as trusted. The typed preview is
//!   non-authoritative display only and does not gate signing.
//!
//! # Module overview
//!
//! | Module | Contents |
//! |---|---|
//! | [`error`] | [`Sep48Error`] typed error enum |
//! | [`spec`] | Contract WASM fetch + SEP-48 spec-section parse (in-memory cache) |
//! | [`decode`] | [`DecodedInvocation`]: `InvokeHostFunction` XDR decode |
//! | [`render`] | [`TypedPreview`]: typed-arg rendering via the SEP-48 spec |
//! | [`discovery`] | SEP-47 claim-discovery from the `contractmetav0` `sep` entry |
//!
//! # KMP reference
//!
//! - KMP Stellar SDK `SorobanContractParser.kt` — SEP-47 meta parse reference.
//! - KMP Stellar SDK `ContractSpec.kt` — typed-arg mapping reference.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::missing_errors_doc)]
#![deny(clippy::missing_panics_doc)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod decode;
pub mod discovery;
pub mod error;
pub mod render;
pub mod spec;

pub use decode::{DecodedInvocation, decode_invoke_host_function};
pub use discovery::{discover_claimed_seps, extract_seps_from_wasm};
pub use error::Sep48Error;
pub use render::{TypedPreview, render_typed_args};
pub use spec::fetch_contract_spec;
