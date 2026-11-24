//! Short-in-memory-unlock window: `mlock`-protected signing seed with RAII dispose.
//!
//! This module provides:
//!
//! - [`MlockRequired`] — the three-posture config enum (`true` / `"warn"` / `false`)
//!   controlling how `mlock` failures are handled.
//! - [`LockedSeed`]: a seed and its signing key in one page, pinned in RAM via
//!   `region::lock` when the lock succeeds, with both zeroized on drop.
//! - [`Wallet`]: clock-checked seed access, ownership transfer, and RAII disposal.
//! - [`WalletLifecycleError`] — typed error taxonomy for all lifecycle failure
//!   modes.
//!
//! # Mechanism overview
//!
//! CLI environment signers call `Wallet::unlock(profile, &seed, ttl, posture)`.
//! The wallet allocates a stable zeroed home, attempts the configured memory
//! lock, then copies the borrowed seed and builds its signing key in that page.
//! Clock checks refuse seed and key access and transfer after the TTL. The page
//! lives until its wallet or signer drops. Mainnet refuses environment signers
//! for transactions; an owner ceremony keeps its page for its operation.
//! Testnet environment signers keep it for the command, past the TTL
//! if needed. Drop zeroizes before unlocking and freeing, including on unwind.
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
//! `reason`, `errno`) when `mlock` fails under `MlockRequired::Warn`, and
//! exposes the same details via [`Wallet::mlock_degradation`]. This module
//! is deliberately ignorant of the audit-log writer; the caller that has one
//! (the CLI secret-env signer ceremony) records the `WalletMlockFailed`
//! entry.

pub mod config;
pub mod error;
pub mod lifecycle;
pub mod mlock;

pub use config::MlockRequired;
pub use error::WalletLifecycleError;
pub use lifecycle::{DEFAULT_TTL_SECONDS, MAX_TTL_SECONDS, Wallet};
pub use mlock::{LockedSeed, MlockDegradation};
