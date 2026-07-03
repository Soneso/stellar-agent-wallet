//! WebAuthn passkey signer for smart-account authentication.
//!
//! The module is structured as a directory with the following submodules:
//!
//! | Submodule        | Contents                                                           |
//! |------------------|--------------------------------------------------------------------|
//! | `sig_data`       | XDR encoders (`WebAuthnAssertion` re-export from `stellar-agent-network::signing`) |
//! | `pre_verifier`   | `webauthn-rs` off-chain pre-verification                          |
//! | `sig_normalize`  | DER → compact + low-S normalisation                               |
//! | `passkey_signer` | `PasskeySignHandle` + `AssertionInput` type                       |
//! | `verifiers`      | Verifier-contract address registry (pending)                      |
//!
//! The `authenticator` sub-module (macOS + Linux in-process platform-authenticator
//! shells) was removed per the browser-handoff architecture: WebAuthn ceremony
//! bytes are now produced by the browser and stored in the approval spine
//! before this signer pipeline runs. The replacement substrate is
//! `stellar-agent-webauthn-bridge`.
//!
//! # Wraps
//!
//! `webauthn-rs = "=0.5.5"` (the relying-party verifier; consumption site is
//! `pre_verifier.rs`).
//!
pub mod passkey_signer;
pub mod pre_verifier;
pub mod sig_data;
pub mod sig_normalize;

pub use passkey_signer::{AssertionInput, PasskeyCredentialRecord, PasskeySignHandle};
pub use pre_verifier::pre_verify_assertion;
pub use sig_data::{
    WebAuthnAssertion, encode_webauthn_sig_data_scval, encode_webauthn_signature_value_bytes,
};
pub use sig_normalize::{NormalisedSignature, normalize_der_to_compact_low_s};
