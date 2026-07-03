//! Matrix invariant tests — pure-name checks that do not require linking the
//! MCP server's tool inventory registrations.
//!
//! These tests verify the structural disjointness invariants (matrix ∩ denylist = ∅,
//! signing tools do not resolve via the ungated path) using only literal name
//! comparisons. No `inventory` crate or MCP binary link is needed.
//!
//! Inventory-based checks (every matrix tool exists in the static registry,
//! every denylist tool exists in the registry, `destructive_hint == false` for
//! all ungated matrix tools, and end-to-end gated-tool-only-via-both-gates
//! verification) require the full MCP tool inventory at link time and live in
//! the MCP server's integration suite once that crate is added.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::collections::HashSet;

use stellar_agent_toolsets_runtime::matrix::{ALL_MATRIX_ENTRIES, SIGNING_DENYLIST};

// ── Invariant 1 (pure names): matrix ∩ denylist = ∅ ─────────────────────────

#[test]
fn matrix_and_denylist_are_disjoint() {
    let denylist: HashSet<&str> = SIGNING_DENYLIST.iter().copied().collect();
    for (tool, cap) in ALL_MATRIX_ENTRIES {
        assert!(
            !denylist.contains(tool),
            "matrix tool '{tool}' (granting {cap:?}) appears in SIGNING_DENYLIST — \
             this violates the disjoint invariant"
        );
    }
}

// ── Signing tools are not in the matrix ──────────────────────────────────────

#[test]
fn signing_tools_not_in_matrix() {
    use stellar_agent_toolsets_runtime::matrix::resolve_action;
    for tool in SIGNING_DENYLIST {
        let result = resolve_action(tool);
        assert!(
            result.is_err(),
            "signing/denylist tool '{tool}' must NOT resolve via the matrix"
        );
    }
}
