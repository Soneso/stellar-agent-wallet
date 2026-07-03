//! CLI output renderers for human-readable (non-JSON) formats.
//!
//! Each command that supports `--output table` has a corresponding renderer
//! function in a submodule here. The `table` module provides the `balances`
//! table renderer; future commands add their own submodules.

pub mod table;
