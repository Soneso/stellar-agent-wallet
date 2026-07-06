//! Short-in-memory-unlock window: `mlock`-protected signing seed with RAII dispose.
//!
//! This module provides:
//!
//! - [`MlockRequired`] — the three-posture config enum (`true` / `"warn"` / `false`)
//!   controlling how `mlock` failures are handled.
//! - [`LockedSeed`] — an opaque 32-byte seed holder that pins the seed page in
//!   RAM via `region::lock` and zeroizes the seed on drop.
//! - [`Wallet`] — the full lifecycle manager: bounded TTL, background timer,
//!   and RAII dispose.
//! - [`WalletLifecycleError`] — typed error taxonomy for all lifecycle failure
//!   modes.
//!
//! # Mechanism overview
//!
//! When an agent tool requires signing, the MCP server calls
//! `Wallet::unlock(profile, seed, ttl_seconds, mlock_required)`.  The seed
//! is immediately moved into a `Zeroizing<[u8; 32]>` and the backing page is
//! locked in physical RAM via `mlock(2)` / `VirtualLock`.  A background
//! `tokio` task fires after `ttl_seconds` (default 30) and marks the wallet
//! as disposed.  On any drop path — normal return, `?` propagation, or
//! panic-unwind — the seed is zeroed and the lock is released.
//!
//! # `mlock(2)` vs `mlock2(MLOCK_ONFAULT)`
//!
//! The `region` crate calls plain `mlock(2)` only; it does not expose
//! `MLOCK_ONFAULT` or `mlock2(2)`.  Plain `mlock(2)` is at least as strong
//! as `mlock2(MLOCK_ONFAULT)` for the wallet's small, definitely-accessed
//! signing-key region: it requires the kernel to populate and pin pages
//! eagerly at lock time, closing any pre-first-fault swap-disclosure window
//! that `MLOCK_ONFAULT` would leave open for never-faulted pages.  For a
//! 32-byte seed that is immediately read at signing time, the
//! eager-vs-deferred distinction is operationally inert; the security
//! argument runs in `mlock(2)`'s favour.
//!
//! # `MlockRequired` postures
//!
//! | Value | Behaviour on `mlock` failure |
//! |-------|------------------------------|
//! | `true` (default Linux/macOS) | Typed `WalletLifecycleError::MlockUnavailable`; unlock aborted. |
//! | `"warn"` (default Windows) | Proceeds with unprotected memory; emits `tracing::warn!`. |
//! | `false` | No lock attempted; no warning. |
//!
//! Operators set this field in their profile TOML:
//! ```toml
//! [wallet]
//! mlock_required = true      # default on Linux/macOS
//! mlock_required = "warn"    # default on Windows; opt-in elsewhere
//! mlock_required = false     # operator opt-out (accepts T6 swap-disclosure risk)
//! ```
//!
//! # Audit-log integration
//!
//! This layer emits `tracing::warn!` with structured fields (`profile`,
//! `reason`, `errno`) when `mlock` fails under `MlockRequired::Warn`.
//! `EventKind::WalletMlockFailed` is a reserved audit-log event kind
//! (recognised by `audit verify`) not currently emitted by any call site.
//! This module is deliberately ignorant of the audit-log writer; the tracing
//! span is the handover point for any future caller that wires the entry.

pub mod config;
pub mod error;
pub mod lifecycle;
pub mod mlock;

pub use config::MlockRequired;
pub use error::WalletLifecycleError;
pub use lifecycle::{DEFAULT_TTL_SECONDS, MAX_TTL_SECONDS, Wallet};
pub use mlock::LockedSeed;
