//! Toolsets capability→tool matrix invariant tests.
//!
//! These tests validate the capability→tool matrix against the static inventory
//! registry.  They live in `stellar-agent-mcp/tests/` so they link against the
//! full tool registration surface (all `inventory::submit!` items emitted by
//! `#[mcp_tool_router]`/`#[mcp_tool_item]` expansions).
//!
//! ## Invariants
//!
//! - Every matrix tool name EXISTS in `inventory::iter::<McpToolRegistration>()`.
//! - Every SIGNING_DENYLIST name EXISTS in the static registry.
//! - Every matrix tool has `destructive_hint == false`.
//! - Matrix ∩ denylist = ∅ by literal name (confirmed vs registry).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::collections::HashSet;

use stellar_agent_core::policy::McpToolRegistration;
use stellar_agent_mcp::server::WalletServer;
use stellar_agent_toolsets_runtime::matrix::{ALL_MATRIX_ENTRIES, SIGNING_DENYLIST};

fn registry_names() -> HashSet<&'static str> {
    // Force-link WalletServer so inventory::submit! items in stellar-agent-mcp
    // are included in the test binary's linker output.
    let _ = std::hint::black_box(WalletServer::router_tool_names);

    inventory::iter::<McpToolRegistration>()
        .map(|r| r.name)
        .collect()
}

fn find_registration(name: &str) -> Option<&'static McpToolRegistration> {
    let _ = std::hint::black_box(WalletServer::router_tool_names);
    inventory::iter::<McpToolRegistration>().find(|r| r.name == name)
}

// ── Matrix tools exist in the registry ──────────────────────────────────────

#[test]
fn every_matrix_tool_exists_in_registry() {
    let names = registry_names();
    for (tool, cap) in ALL_MATRIX_ENTRIES {
        assert!(
            names.contains(tool),
            "matrix tool '{tool}' (granting {cap:?}) NOT found in static inventory registry — \
             the matrix has drifted from the registered tools"
        );
    }
}

// ── Denylist tools exist in the registry ────────────────────────────────────

#[test]
fn every_denylist_tool_exists_in_registry() {
    let names = registry_names();
    for tool in SIGNING_DENYLIST {
        assert!(
            names.contains(tool),
            "denylist tool '{tool}' NOT found in static inventory registry — \
             the denylist may reference a renamed or removed tool"
        );
    }
}

// ── Matrix tools have destructive_hint == false ─────────────────────────────

#[test]
fn every_matrix_tool_has_destructive_hint_false() {
    for (tool, cap) in ALL_MATRIX_ENTRIES {
        let reg = find_registration(tool)
            .unwrap_or_else(|| panic!("matrix tool '{tool}' not in registry"));
        assert!(
            !reg.destructive_hint,
            "matrix tool '{tool}' (granting {cap:?}) has destructive_hint=true"
        );
    }
}

// ── Combined: matrix ∩ denylist = ∅ (registry-confirmed) ─────────────────────

#[test]
fn matrix_and_denylist_disjoint_registry_confirmed() {
    let denylist: HashSet<&str> = SIGNING_DENYLIST.iter().copied().collect();
    for (tool, cap) in ALL_MATRIX_ENTRIES {
        assert!(
            !denylist.contains(tool),
            "matrix tool '{tool}' (granting {cap:?}) is in SIGNING_DENYLIST — disjoint invariant violated"
        );
    }
}
