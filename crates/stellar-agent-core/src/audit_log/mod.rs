//! Hash-chained audit log substrate.
//!
//! Implements the per-profile structured audit log for this Stellar agent wallet.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────┐
//! │   AuditWriter        │  per-profile singleton (Arc<Mutex<AuditWriter>>)
//! │   (writer.rs)        │  O_APPEND + File::lock() + per-line fsync
//! └────────┬─────────────┘
//!          │ appends
//!          ▼
//! ┌──────────────────────────────────────────────────────┐
//! │   ~/.local/state/stellar-agent/audit/<profile>.jsonl │
//! │   (one JSON line per entry; 10 MiB rotation;         │
//! │    10 retained rotated files)                        │
//! └──────────────────────────────────────────────────────┘
//!          │ hash chain
//!          ▼
//! ┌──────────────────────┐
//! │   chain.rs           │  SHA-256 + HMAC-SHA256 chain-root signing
//! └──────────────────────┘
//!          │ verify
//!          ▼
//! ┌──────────────────────┐
//! │   verify.rs          │  chain-walk; consumed by `audit verify` CLI
//! └──────────────────────┘
//! ```
//!
//! # Hash chain mechanism
//!
//! ```text
//! current_entry_hash = SHA-256(canonical_json(entry \ previous_entry_hash)
//!                              || previous_entry_hash)
//! ```
//!
//! # Canonical-form contract
//!
//! The `previous_entry_hash` field is set to `""` (empty string — NOT JSON
//! `null`) when computing the hash-input body.  Fields appear in
//! struct-declaration order.  Strings are passed through as-is (no Unicode
//! normalisation enforced; operators MUST NOT use mixed-form Unicode in
//! tool/chain_id/decision_reason).  Numbers are JSON integers only.
//!
//! # First-entry-per-file rule
//!
//! - The **very first file's** first entry uses
//!   `previous_entry_hash = SHA-256([0u8; 32])` (the
//!   [`crate::audit_log::chain::ZERO_BLOCK_HASH`]).
//! - **Subsequent files'** first entries chain via the rotation handoff
//!   entry's hash — NOT the zero-block hash.  The zero-block hash is only
//!   used for the very first file in the chain.
//!
//! # Per-rotation hash-chain bridge
//!
//! When rotation occurs, the outgoing file's last entry is an
//! `AuditRotationHandoff` entry whose `next_file_name` field contains the
//! **archive basename** that the outgoing file was renamed to (e.g.
//! `audit.jsonl.20260429T123456789`).  The new file's first entry chains off
//! the handoff entry's hash.  [`verify_log`] follows rotation
//! boundaries by scanning the log directory for sibling files matching the
//! strict `<stem>.<YYYYMMDDTHHMMSS[ms]>` pattern, then validates each handoff
//! entry's `next_file_name` against the actual basename of the file being
//! verified to detect substitution attacks.
//!
//! # Per-file HMAC sidecar
//!
//! Each log file gets its own `<file>.root_hmac` sidecar, written on the first
//! entry of that file.  On rotation the sidecar is renamed alongside the log
//! file: `audit.jsonl.root_hmac` → `audit.jsonl.<ts>.root_hmac`.
//!
//! # Single-writer invariant
//!
//! [`AuditWriter::open`] acquires an exclusive advisory lock via
//! `std::fs::File::try_lock()` (stable Rust 1.89; exclusive by default).  A
//! second process attempting to open the same file receives
//! [`crate::audit_log::WriterError::FileLocked`].
//!
//! # Redaction discipline
//!
//! Argument VALUES are never logged; only key names in `arg_keys`.
//! Public/account-like strkeys in `decision_reason` are first-5-last-5
//! redacted.
//! Tx-hashes in `decision_reason` are first-8-last-8 redacted.
//! `envelope_hash` is unredacted (SHA-256 digest; no user data).
//!
//! # File path
//!
//! `~/.local/state/stellar-agent/audit/<profile>.jsonl` (Linux).
//! `~/Library/Application Support/stellar-agent/audit/<profile>.jsonl` (macOS).
//! `%LOCALAPPDATA%\stellar-agent\audit\<profile>.jsonl` (Windows).
//!
//! # Reserved event kinds
//!
//! `PluginInvoked`, `WalletMlockFailed`, and `AuditRotationHandoff` are
//! declared in [`EventKind`]; `PluginInvoked` and `WalletMlockFailed`
//! are not currently emitted by this crate but are recognised by `audit verify`
//! so future additions require no retroactive schema change.

pub mod chain;
pub mod entry;
pub mod health;
pub mod reader;
pub(crate) mod redact;
pub mod rotation;
pub mod schema;
pub mod signer_set;
pub mod verify;
pub mod writer;

pub use entry::{AuditEntry, NewToolInvocation};
pub use health::{AuditWriterHealth, AuditWriterHealthHandle};
pub use reader::{AuditLogIntegrityError, AuditReader, PinnedHashesRecord};
pub use schema::{EventKind, PolicyDecision};
pub use signer_set::{
    BaselineReason, DOMAIN_SA_SIGNER_SET_V1, ObservedSignerSet, SignerPubkey,
    SignerSetStatePayload, compute_signer_set_digest, format_digest_first8_last8,
    signer_pubkey_canonical_body,
};
pub use verify::{
    FileVerifyResult, PartialRotationState, VerifyError, VerifyOk, VerifyWarning, verify_log,
};
pub use writer::{AuditWriter, AuditWriterRegistry, WriterError};
