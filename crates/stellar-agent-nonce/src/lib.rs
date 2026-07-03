//! HMAC-SHA256 wallet-issued nonce, replay-window, and nonce-key rotation.
//!
//! # What this crate does
//!
//! Provides:
//!
//! - [`Nonce`] — a 48-byte (16-byte random salt + 32-byte HMAC-SHA256 tag)
//!   opaque value transmitted as base64.
//! - [`NonceMint`] — a per-profile minter.  Holds no key bytes; the HMAC key
//!   is lazy-loaded from the platform keyring on every [`NonceMint::mint`] or
//!   [`NonceMint::verify`] call and zeroised immediately after.
//! - [`ReplayWindow`] — an in-memory `HashMap`-backed single-use nonce tracker
//!   with TTL eviction.  Fail-closed on process restart (see `boot_nonce` design
//!   below).
//! - [`ToolCatalogue`] — a runtime-free trait abstraction for the registered
//!   MCP tool catalogue.
//! - [`rotate_nonce_key`] — generates 32 fresh bytes via `OsRng`, base64-
//!   encodes them, and atomically swaps the keyring entry for the profile's
//!   `mcp_nonce_key_alias`.
//!
//! # Primary consumers
//!
//! - `stellar-agent-mcp`: creates a `NonceMint` from the loaded profile, uses
//!   `mint` at simulation time, and `verify` at commit time via `ReplayWindow`.
//! - `stellar-agent-cli`: the `profile rotate-nonce-key` subcommand.
//!
//! # What this crate does NOT do
//!
//! - Does NOT implement MCP tool dispatch (that is `stellar-agent-mcp`).
//! - Does NOT persist the replay window across process restarts (by design).
//! - Does NOT generate XDR envelopes (that is `stellar-agent-network`).
//!
//! # HMAC input domain (canonical form)
//!
//! ```text
//! HMAC-SHA256(profile_nonce_key,
//!     boot_nonce             ||   // 16 bytes — process-scoped (see below)
//!     SHA-256(envelope_xdr)  ||   // 32 bytes
//!     expiry_unix_ms         ||   // 8 bytes big-endian u64
//!     len(tool_name) as BE4  ||   // 4 bytes — length-prefix separator
//!     tool_name              ||   // variable-length UTF-8
//!     len(chain_id) as BE4   ||   // 4 bytes — length-prefix separator
//!     chain_id                    // variable-length UTF-8
//! )
//! ```
//!
//! Length-prefix separators prevent boundary-collision attacks where different
//! `(tool_name, chain_id)` pairs produce the same concatenated byte stream.
//!
//! The `boot_nonce` field is a 16-byte process-scoped random value initialised
//! once via `OsRng` and never persisted.  It enforces the fail-closed property:
//! after a process restart every outstanding nonce returns `nonce.expired`.
//!
//! ## boot_nonce design
//!
//! Three mechanisms for fail-closed-on-restart were evaluated:
//!
//! 1. **In-memory HashMap only** — after restart the HashMap is empty so
//!    any pre-restart nonce is *accepted* on first presentation, violating
//!    the fail-closed invariant.  Rejected.
//!
//! 2. **`boot_nonce` as HMAC input** (adopted) — a pre-restart nonce has a
//!    different `boot_nonce` baked into its HMAC tag; when verified after
//!    restart the recomputed tag differs → `HmacMismatch`.
//!
//! 3. **Persistent monotonic counter** — rejected: would let an operator opt
//!    out of fail-closed-on-restart by persisting the counter across restarts.
//!
//! ## Key encoding
//!
//! The keyring entry stores the key as URL-safe base64 with no padding
//! ([`base64::engine::general_purpose::URL_SAFE_NO_PAD`]).  Platform keyrings
//! (macOS Keychain, Linux Secret Service, Windows Credential Manager) accept
//! UTF-8 strings as passwords; raw bytes may fail on some backends.  URL-safe
//! base64 avoids quoting issues in TOML contexts.  This encoding is the
//! canonical source; any future consumer MUST use the same alphabet.
//!
//! ## Nonce wire format
//!
//! Transmitted as base64 (same URL-safe alphabet).  48 bytes on the wire:
//!
//! ```text
//! bytes[0..16]  = random salt (OsRng; uniqueness + replay-window key)
//! bytes[16..48] = HMAC-SHA256 tag (32 bytes)
//! ```
//!
//! The salt does NOT feed into either side of the HMAC computation.  Its role
//! is nonce-uniqueness (two calls with the same envelope at the same millisecond
//! produce different nonces) and the HashMap key for the replay window.
//!
//! # Self-custodial key residency
//!
//! The HMAC nonce key never leaves the user's host.  Every `load_key` call goes
//! directly to the platform keyring and the resulting bytes exist only within a
//! single stack frame before being zeroised by `Zeroizing<T>` drop semantics.
//! No key bytes are returned via any public API, transmitted over a network, or
//! written to a file.
//!
//! # Zeroisation discipline
//!
//! All secret-bearing locals use `Zeroizing<T>` so `Drop` fires on every exit
//! path including panic unwinding.  The key load sequence in [`NonceMint`] is
//! analogous to `stellar-agent-network::keyring::signer_from_keyring`:
//!
//! 1. `get_password()` result wrapped in `Zeroizing<String>`.
//! 2. Base64-decode into `Zeroizing<Vec<u8>>`.
//! 3. Copy first 32 bytes into `Zeroizing<[u8; 32]>`.
//! 4. Drop the `Zeroizing<String>` and `Zeroizing<Vec<u8>>` immediately.
//! 5. Use the `Zeroizing<[u8; 32]>` only within the HMAC call; it is dropped
//!    before the function returns.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::missing_errors_doc)]
#![deny(clippy::missing_panics_doc)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod error;
pub mod mint;
pub mod replay;
pub mod rotate;

pub use error::NonceError;
pub use mint::{Nonce, NonceMint, NonceVerifyHmacOnlyRequest, NonceVerifyRequest, ToolCatalogue};
pub use replay::ReplayWindow;
pub use rotate::rotate_nonce_key;
