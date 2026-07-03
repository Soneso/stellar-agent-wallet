//! Smart-account signing pipeline support.
//!
//! This module hosts the pre-signing refusal gates and the ed25519
//! auth-digest signing adapter. The network crate owns the signer
//! primitive; this module owns smart-account auth-entry assembly concerns.

pub mod divergence;
