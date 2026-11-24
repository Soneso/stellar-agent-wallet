//! The single-writer lock of the persisted policy window-state store.
//!
//! The lock is defined in core, where the policy pin operations take the
//! same guard; this module re-exports it beside the store. The lock file is
//! named by the window-state keyring entry, in the directory of the store
//! file, and [`WindowStoreLock::acquire_for`] answers
//! [`StateLockError::WriterLocked`] while another holder owns it.

pub use stellar_agent_core::policy::state_lock::{
    StateLockError, WindowStoreLock, window_lock_path,
};
