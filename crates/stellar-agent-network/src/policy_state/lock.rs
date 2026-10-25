//! The single-writer lock of the persisted policy window-state store.
//!
//! The lock is defined in core, where the policy pin operations take the
//! same guard; this module keeps the path the store has always exported it
//! under. The lock file lives at `<window-state-file>.lock`, a sibling of the
//! store file, and [`WindowStoreLock::acquire`] answers
//! [`StateLockError::WriterLocked`] while another holder owns it.

pub use stellar_agent_core::policy::state_lock::{
    StateLockError, WindowStoreLock, window_lock_path,
};
