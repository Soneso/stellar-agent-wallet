//! Capability→tool matrix, gated capability→tool matrix, and explicit signing
//! denylist.
//!
//! The UNGATED matrix ([`grants_for_capability`] / [`ALL_MATRIX_ENTRIES`]) is
//! the admission path for non-signing toolset actions. Tools NOT listed here are
//! default-denied regardless of what capabilities a toolset declares.
//!
//! The GATED matrix ([`GATED_MATRIX_ENTRIES`]) is a SEPARATE tier for
//! signing-adjacent capabilities. It routes `SignPayment → stellar_pay_commit`
//! ONLY through the first-invoke gate. `stellar_pay_commit` STAYS in
//! `SIGNING_DENYLIST`; `resolve_action` does NOT resolve `sign-payment`; the
//! ungated `ALL_MATRIX_ENTRIES` invariant tests iterate the ungated tier only.
//!
//! ## Security invariants
//!
//! ### Ungated tier
//!
//! 1. `{ungated matrix grant tools} ∩ {SIGNING_DENYLIST} = ∅` by literal name.
//! 2. Every ungated matrix tool name EXISTS in the static `inventory` registry.
//! 3. Every SIGNING_DENYLIST name EXISTS in the static `inventory` registry
//!    (so the denylist cannot silently rot into referencing renamed/removed tools).
//! 4. Every ungated matrix tool has `destructive_hint == false` (transitive-signing lock).
//!
//! ### Gated tier
//!
//! 5. The gated tool (`stellar_pay_commit`) IS in `SIGNING_DENYLIST` — this is
//!    INTENTIONAL and is the load-bearing invariant proving the ungated path is
//!    blocked. The gated tier is NOT in `ALL_MATRIX_ENTRIES`.
//! 6. The gated tool is reachable ONLY via (four-part check AND a current
//!    first-invoke grant) — the end-to-end gate is verified by the MCP
//!    server's integration suite once that crate is added (full tool inventory
//!    required at link time).
//! 7. `SignPayment` grant ∩ {sep43/sep53 bare-sign tools} = ∅.
//! 8. The gated tool exists in the static `inventory` registry.
//! 9. `{flattened GATED_MATRIX_ENTRIES tools} ⊆ SIGNING_DENYLIST` (structural
//!    proof that no gated tool is reachable via the ungated path). Asserted by
//!    `gated_matrix_entries_subset_of_signing_denylist`.
//!
//! Inventory-based checks (invariants 2, 3, 4, 8 above) require the full MCP
//! tool inventory at link time and therefore live in the MCP server's
//! integration suite once that crate is added.
//!
//! **Adding a new tool to the ungated matrix requires:**
//! - Confirming it is NOT a signing/key/policy-mutation tool.
//! - Adding it to the appropriate capability grant array below.
//! - Adding a test that verifies it is NOT in `SIGNING_DENYLIST`.
//! - Verifying it has `destructive_hint == false` in the registry.
//!
//! **Adding a new tool to the GATED matrix requires:**
//! - Confirming it IS a signing-adjacent tool that should remain in `SIGNING_DENYLIST`.
//! - Adding the capability → `[tool_name]` entry to `GATED_MATRIX_ENTRIES`.
//! - The tool MUST NOT appear in `ALL_MATRIX_ENTRIES` (ungated tier).
//! - A new `ApprovalKind` arm may be required if the grant shape differs.
//!
//! ## Adding a signer to an ungated-matrix-listed tool
//!
//! If a future implementation of an ungated matrix tool adds signing or
//! submission behaviour (e.g. `stellar_pay` gets an optional sign flag), REMOVE
//! that tool from its matrix grant row before merging. The precedent: signing
//! lives only in `*_commit` / `sep4x_sign_*` / `sep53_sign_*` tools, NEVER in
//! `stellar_pay`.

use stellar_agent_toolsets::Capability;

// ── ReadBalance grant ─────────────────────────────────────────────────────────

/// Tools granted by [`Capability::ReadBalance`].
///
/// - `stellar_balances` — read native XLM + trustline balances.
pub const READ_BALANCE_GRANTS: &[&str] = &["stellar_balances"];

// ── ProposeTransaction grant ──────────────────────────────────────────────────

/// Tools granted by [`Capability::ProposeTransaction`].
///
/// - `stellar_pay` — simulate/build an UNSIGNED payment envelope ONLY.
///   `stellar_pay_commit` is EXPLICITLY excluded (that is the sign+submit tool).
/// - `stellar_claim` — simulate/build an UNSIGNED `ClaimClaimableBalance`
///   envelope ONLY. `stellar_claim_commit` is EXPLICITLY excluded (that is the
///   sign+submit tool; it is denylist-only, unreachable via toolset routing).
///
/// **Invariant**: `stellar_pay_commit` / `stellar_claim_commit` MUST NOT appear
/// here. If either simulate tool ever gains an integrated sign step, remove it
/// from this list immediately.
pub const PROPOSE_TRANSACTION_GRANTS: &[&str] = &["stellar_pay", "stellar_claim"];

// ── SuggestDestination grant ──────────────────────────────────────────────────

/// Tools granted by [`Capability::SuggestDestination`].
///
/// - `stellar_sep47_discover` — SEP-47 claim-discovery (read-only).
/// - `stellar_sep48_preview_invocation` — SEP-48 typed-preview (read-only).
/// - `stellar_sep7_parse_uri` — SEP-7 inbound URI parse + verify (read-only).
pub const SUGGEST_DESTINATION_GRANTS: &[&str] = &[
    "stellar_sep47_discover",
    "stellar_sep48_preview_invocation",
    "stellar_sep7_parse_uri",
];

// ── ObserveEvent grant ────────────────────────────────────────────────────────

/// Tools granted by [`Capability::ObserveEvent`].
///
/// EMPTY: no read-only event/stream tool exists yet. An empty grant is valid —
/// it simply refuses every action for this capability. A tool will be added
/// here when the event-stream surface lands.
pub const OBSERVE_EVENT_GRANTS: &[&str] = &[];

// ── ReadRules grant ───────────────────────────────────────────────────────────

/// Tools granted by [`Capability::ReadRules`].
///
/// - `stellar_rules_list` — enumerate active context rules (read-only).
/// - `stellar_rules_get` — read a single context rule's metadata and, when
///   exactly one spending-limit policy identifies, its budget snapshot
///   (read-only).
///
/// Separately grantable from `read-balance`: rule visibility and balance
/// visibility are distinct concerns.
pub const READ_RULES_GRANTS: &[&str] = &["stellar_rules_list", "stellar_rules_get"];

// ── Flat matrix entries for iteration ────────────────────────────────────────

/// All (action_name, granting_capability) pairs in the matrix.
///
/// Used for exhaustive invariant tests and for [`ALL_MATRIX_TOOL_NAMES`].
pub const ALL_MATRIX_ENTRIES: &[(&str, Capability)] = &[
    // ReadBalance
    ("stellar_balances", Capability::ReadBalance),
    // ProposeTransaction
    ("stellar_pay", Capability::ProposeTransaction),
    ("stellar_claim", Capability::ProposeTransaction),
    // SuggestDestination
    ("stellar_sep47_discover", Capability::SuggestDestination),
    (
        "stellar_sep48_preview_invocation",
        Capability::SuggestDestination,
    ),
    ("stellar_sep7_parse_uri", Capability::SuggestDestination),
    // ObserveEvent — empty; no entries.
    // ReadRules
    ("stellar_rules_list", Capability::ReadRules),
    ("stellar_rules_get", Capability::ReadRules),
];

/// All tool names that appear in the UNGATED matrix (deduped, in stable order).
///
/// This list covers ONLY ungated tools. The gated tool `stellar_pay_commit` is
/// deliberately absent — it is in `SIGNING_DENYLIST` and in
/// `GATED_MATRIX_ENTRIES` only.
pub const ALL_MATRIX_TOOL_NAMES: &[&str] = &[
    "stellar_balances",
    "stellar_pay",
    "stellar_claim",
    "stellar_sep47_discover",
    "stellar_sep48_preview_invocation",
    "stellar_sep7_parse_uri",
    "stellar_rules_list",
    "stellar_rules_get",
];

// ── GATED capability→tool matrix ─────────────────────────────────────────────
//
// THIS IS A SEPARATE TIER from the ungated matrix above. It maps
// signing-adjacent capabilities that are:
//   (a) NOT in `ALL_MATRIX_ENTRIES` (the ungated matrix),
//   (b) NOT reachable via `resolve_action`,
//   (c) reachable ONLY through the first-invoke gate + per-action approval.
//
// `stellar_pay_commit` STAYS in `SIGNING_DENYLIST` — this is load-bearing.
// The test `gated_matrix_entries_subset_of_signing_denylist` asserts
// `{flattened GATED_MATRIX_ENTRIES tools} ⊆ SIGNING_DENYLIST`, which is the
// structural proof that no gated tool is reachable via the ungated path.
// All gated-tier invariant tests iterate the flattened GATED_MATRIX_ENTRIES
// directly so they stay in sync with the routing source of truth.

/// The single gated-tier entry for `SignPayment`.
///
/// `stellar_pay_commit` routes through the first-invoke gate ONLY. It MUST
/// remain in `SIGNING_DENYLIST` so the ungated `resolve_action` path is
/// permanently blocked.
pub const SIGN_PAYMENT_GATED_TOOLS: &[&str] = &["stellar_pay_commit"];

/// All (capability, tool_name) pairs in the GATED matrix.
///
/// This structure is iterated by the gated-tier invariant tests and by the
/// gated resolver to verify the tool name is a known gated constant.
///
/// NEVER add a gated entry to `ALL_MATRIX_ENTRIES` — that would bypass the
/// gate entirely.
pub const GATED_MATRIX_ENTRIES: &[(Capability, &[&str])] =
    &[(Capability::SignPayment, SIGN_PAYMENT_GATED_TOOLS)];

/// Returns the gated grant set for a signing-adjacent capability.
///
/// Returns the tool slice if `cap` is a gated capability, or `None` if it is
/// not gated. Used by the gated resolver's closed-routing invariant check.
///
/// # Examples
///
/// ```rust
/// use stellar_agent_toolsets_runtime::matrix::gated_grants_for_capability;
/// use stellar_agent_toolsets::Capability;
///
/// assert!(gated_grants_for_capability(Capability::SignPayment).is_some());
/// assert!(gated_grants_for_capability(Capability::ReadBalance).is_none());
/// ```
#[must_use]
pub fn gated_grants_for_capability(cap: Capability) -> Option<&'static [&'static str]> {
    match cap {
        Capability::SignPayment => Some(SIGN_PAYMENT_GATED_TOOLS),
        _ => None,
    }
}

// ── Signing / key / policy denylist ──────────────────────────────────────────

/// Explicit by-name denylist of signing, key-derivation, policy-mutation, and
/// reflexive-escalation tools.
///
/// These tools MUST NOT appear in any grant set. Their presence is a
/// compile-time invariant verified by the `matrix_and_denylist_are_disjoint`
/// test.
///
/// The denylist also includes the generic dispatcher's own tools
/// (`stellar_toolset_list`, `stellar_toolset_invoke`) to prevent reflexive
/// escalation — a toolset must not be able to invoke the toolset dispatcher itself.
///
/// ## Maintenance rule
///
/// When adding a new signing/key/policy MCP tool:
/// 1. Add it to this list.
/// 2. Verify it is NOT in any grant array above.
/// 3. Run `cargo test -p stellar-agent-toolsets-runtime` to confirm the invariant
///    tests pass.
pub const SIGNING_DENYLIST: &[&str] = &[
    // SEP-43 signing tools
    "stellar_sep43_sign_transaction",
    "stellar_sep43_sign_and_submit_transaction",
    "stellar_sep43_sign_auth_entry",
    "stellar_sep43_sign_message",
    // SEP-53 sign tool
    "stellar_sep53_sign_message",
    // Classic commit (sign+submit) tools
    "stellar_pay_commit",
    "stellar_create_account_commit",
    "stellar_claim_commit",
    // x402 tools (default-exclude: confirm at impl whether each reaches a signer)
    "stellar_x402_create_payment",
    "stellar_x402_parse_receipt",
    "stellar_x402_authenticated_payment",
    // Generic toolset dispatcher tools (no reflexive escalation)
    "stellar_toolset_list",
    "stellar_toolset_invoke",
];

/// Returns the UNGATED grant set for a capability.
///
/// This is the lookup used by [`resolve_action`] and the listing path.
/// Signing-adjacent gated capabilities (e.g. [`Capability::SignPayment`])
/// return an EMPTY slice here — they are NOT ungated and their tool set is
/// only accessible through the first-invoke gate.
///
/// # Examples
///
/// ```rust
/// use stellar_agent_toolsets_runtime::matrix::grants_for_capability;
/// use stellar_agent_toolsets::Capability;
///
/// assert!(grants_for_capability(Capability::ReadBalance).contains(&"stellar_balances"));
/// // SignPayment is gated — returns empty slice from the ungated path.
/// assert!(grants_for_capability(Capability::SignPayment).is_empty());
/// ```
#[must_use]
pub fn grants_for_capability(cap: Capability) -> &'static [&'static str] {
    match cap {
        Capability::ReadBalance => READ_BALANCE_GRANTS,
        Capability::ProposeTransaction => PROPOSE_TRANSACTION_GRANTS,
        Capability::SuggestDestination => SUGGEST_DESTINATION_GRANTS,
        Capability::ObserveEvent => OBSERVE_EVENT_GRANTS,
        // SignPayment is gated — ungated path always returns empty.
        // The gated resolver is the sole admission path.
        Capability::SignPayment => &[],
        Capability::ReadRules => READ_RULES_GRANTS,
        // New variants fail closed (empty grant).
        _ => &[],
    }
}

/// Resolves an `action` string to a `(&'static str, Capability)` pair via the
/// CLOSED matrix lookup.
///
/// Returns `Ok((tool_name, granting_capability))` if the action is in the
/// matrix, or `Err(ToolsetRuntimeError::UnknownToolsetAction)` otherwise.
///
/// This is part (a) + (b) of the four-part enforcement. The returned
/// `tool_name` is a compile-time constant — it cannot be a toolset-supplied
/// string.
///
/// # Errors
///
/// - [`crate::ToolsetRuntimeError::UnknownToolsetAction`] — the action is not in
///   the matrix.
pub fn resolve_action(
    action: &str,
) -> Result<(&'static str, Capability), crate::ToolsetRuntimeError> {
    for (tool, cap) in ALL_MATRIX_ENTRIES {
        if *tool == action {
            return Ok((tool, *cap));
        }
    }
    Err(crate::ToolsetRuntimeError::UnknownToolsetAction {
        action: stellar_agent_toolsets::sanitise_display(action, 128),
    })
}

// ── Unit tests (no inventory dependency needed here) ─────────────────────────
//
// Inventory-based invariant tests (matrix tool exists in registry, denylist
// tools exist in registry, destructive_hint checks) require the full MCP tool
// inventory at link time and live in the MCP server's integration suite.

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in unit tests"
)]
mod tests {
    use super::*;

    // ── Invariant 1 (pure names, no registry): matrix ∩ denylist = ∅ ─────────

    #[test]
    fn matrix_and_denylist_are_disjoint() {
        use std::collections::HashSet;
        let denylist: HashSet<&str> = SIGNING_DENYLIST.iter().copied().collect();
        for (tool, cap) in ALL_MATRIX_ENTRIES {
            assert!(
                !denylist.contains(tool),
                "matrix tool '{tool}' (granting {cap:?}) appears in SIGNING_DENYLIST — \
                 this violates the disjoint invariant"
            );
        }
    }

    // ── ALL_MATRIX_ENTRIES covers all per-capability grant arrays ─────────────
    //
    // Prevents a grant added to a per-capability array from escaping the
    // ALL_MATRIX_ENTRIES iteration used for invariant tests.

    #[test]
    fn all_matrix_entries_covers_every_per_capability_grant() {
        use std::collections::HashSet;

        // Collect all tools from per-capability grant arrays.
        let mut from_grants: HashSet<&str> = HashSet::new();
        for t in READ_BALANCE_GRANTS {
            from_grants.insert(t);
        }
        for t in PROPOSE_TRANSACTION_GRANTS {
            from_grants.insert(t);
        }
        for t in SUGGEST_DESTINATION_GRANTS {
            from_grants.insert(t);
        }
        for t in OBSERVE_EVENT_GRANTS {
            from_grants.insert(t);
        }
        for t in READ_RULES_GRANTS {
            from_grants.insert(t);
        }

        // Collect all tools from ALL_MATRIX_ENTRIES.
        let from_entries: HashSet<&str> = ALL_MATRIX_ENTRIES.iter().map(|(t, _)| *t).collect();

        // Every tool in per-capability grants must be in ALL_MATRIX_ENTRIES.
        for t in &from_grants {
            assert!(
                from_entries.contains(t),
                "tool '{t}' is in a per-capability grant array but NOT in \
                 ALL_MATRIX_ENTRIES — add it to keep single source of truth"
            );
        }

        // Every tool in ALL_MATRIX_ENTRIES must be in some per-capability grant array.
        for t in &from_entries {
            assert!(
                from_grants.contains(t),
                "tool '{t}' is in ALL_MATRIX_ENTRIES but NOT in any per-capability \
                 grant array — ALL_MATRIX_ENTRIES must be derived from the grant arrays"
            );
        }
    }

    // ── ALL_MATRIX_TOOL_NAMES covers every ALL_MATRIX_ENTRIES tool ────────────

    #[test]
    fn all_matrix_tool_names_covers_every_matrix_entry() {
        use std::collections::HashSet;
        let from_entries: HashSet<&str> = ALL_MATRIX_ENTRIES.iter().map(|(t, _)| *t).collect();
        let from_names: HashSet<&str> = ALL_MATRIX_TOOL_NAMES.iter().copied().collect();
        for t in &from_entries {
            assert!(
                from_names.contains(t),
                "tool '{t}' is in ALL_MATRIX_ENTRIES but NOT in ALL_MATRIX_TOOL_NAMES"
            );
        }
        for t in &from_names {
            assert!(
                from_entries.contains(t),
                "tool '{t}' is in ALL_MATRIX_TOOL_NAMES but NOT in ALL_MATRIX_ENTRIES"
            );
        }
    }

    // ── resolve_action: happy paths ───────────────────────────────────────────

    #[test]
    fn resolve_read_balance() {
        let (tool, cap) = resolve_action("stellar_balances").unwrap();
        assert_eq!(tool, "stellar_balances");
        assert_eq!(cap, Capability::ReadBalance);
    }

    #[test]
    fn resolve_stellar_pay() {
        let (tool, cap) = resolve_action("stellar_pay").unwrap();
        assert_eq!(tool, "stellar_pay");
        assert_eq!(cap, Capability::ProposeTransaction);
    }

    #[test]
    fn resolve_suggest_destination_tools() {
        for tool in [
            "stellar_sep47_discover",
            "stellar_sep48_preview_invocation",
            "stellar_sep7_parse_uri",
        ] {
            let (resolved, cap) = resolve_action(tool).unwrap();
            assert_eq!(resolved, tool);
            assert_eq!(cap, Capability::SuggestDestination);
        }
    }

    #[test]
    fn resolve_read_rules_tools() {
        for tool in ["stellar_rules_list", "stellar_rules_get"] {
            let (resolved, cap) = resolve_action(tool).unwrap();
            assert_eq!(resolved, tool);
            assert_eq!(cap, Capability::ReadRules);
        }
    }

    // ── resolve_action: signing tools not in matrix ───────────────────────────

    #[test]
    fn signing_tools_not_in_matrix() {
        for tool in SIGNING_DENYLIST {
            let result = resolve_action(tool);
            assert!(
                result.is_err(),
                "signing/denylist tool '{tool}' must NOT resolve via the matrix"
            );
        }
    }

    // ── ObserveEvent grant is empty ───────────────────────────────────────────

    #[test]
    fn observe_event_grant_is_empty() {
        assert!(
            OBSERVE_EVENT_GRANTS.is_empty(),
            "ObserveEvent grant must be empty (no event-stream tool exists yet)"
        );
    }

    // ── grants_for_capability returns correct slices ──────────────────────────

    #[test]
    fn grants_for_read_balance() {
        let grants = grants_for_capability(Capability::ReadBalance);
        assert_eq!(grants, READ_BALANCE_GRANTS);
    }

    #[test]
    fn grants_for_propose_transaction() {
        let grants = grants_for_capability(Capability::ProposeTransaction);
        assert_eq!(grants, PROPOSE_TRANSACTION_GRANTS);
    }

    #[test]
    fn grants_for_suggest_destination() {
        let grants = grants_for_capability(Capability::SuggestDestination);
        assert_eq!(grants, SUGGEST_DESTINATION_GRANTS);
    }

    #[test]
    fn grants_for_observe_event() {
        let grants = grants_for_capability(Capability::ObserveEvent);
        assert!(grants.is_empty());
    }

    #[test]
    fn grants_for_read_rules() {
        let grants = grants_for_capability(Capability::ReadRules);
        assert_eq!(grants, READ_RULES_GRANTS);
        assert_eq!(grants, &["stellar_rules_list", "stellar_rules_get"]);
    }

    // ── grants_for_capability: SignPayment returns empty from ungated path ────

    #[test]
    fn grants_for_sign_payment_ungated_is_empty() {
        // SignPayment is gated — the ungated path MUST return empty.
        // Any non-empty result here would mean the gated tool is reachable ungated.
        let grants = grants_for_capability(Capability::SignPayment);
        assert!(
            grants.is_empty(),
            "SignPayment ungated grant must be empty (gated tier only)"
        );
    }

    // ── Gated tier invariants ─────────────────────────────────────────────────
    //
    // All tests iterate the flattened GATED_MATRIX_ENTRIES (the routing source
    // of truth) rather than a separate hand-maintained name list. Adding a new
    // entry to GATED_MATRIX_ENTRIES automatically covers it in every invariant
    // check below.

    /// Collect all tool names from GATED_MATRIX_ENTRIES by flattening each
    /// entry's tool slice. This is the single source of truth for the gated
    /// tier; it matches exactly what resolve_gated_action iterates.
    fn flattened_gated_tools() -> Vec<&'static str> {
        GATED_MATRIX_ENTRIES
            .iter()
            .flat_map(|(_, tools)| tools.iter().copied())
            .collect()
    }

    // (i) Every gated tool is NOT in the ungated matrix (ALL_MATRIX_ENTRIES).
    #[test]
    fn gated_tool_not_in_ungated_matrix() {
        use std::collections::HashSet;
        let ungated: HashSet<&str> = ALL_MATRIX_ENTRIES.iter().map(|(t, _)| *t).collect();
        for tool in flattened_gated_tools() {
            assert!(
                !ungated.contains(tool),
                "gated tool '{tool}' must NOT appear in the ungated ALL_MATRIX_ENTRIES \
                 (would bypass the first-invoke gate)"
            );
        }
    }

    // (ii) Every gated tool IS in SIGNING_DENYLIST.
    //      This is the load-bearing structural proof: a tool in SIGNING_DENYLIST
    //      cannot be reached via the ungated resolve_action path (invariant 1
    //      ensures the ungated matrix and denylist are disjoint).
    #[test]
    fn gated_tool_is_in_signing_denylist() {
        use std::collections::HashSet;
        let denylist: HashSet<&str> = SIGNING_DENYLIST.iter().copied().collect();
        for tool in flattened_gated_tools() {
            assert!(
                denylist.contains(tool),
                "gated tool '{tool}' MUST be in SIGNING_DENYLIST — this is the structural \
                 proof that the ungated resolve_action path is permanently blocked"
            );
        }
    }

    // (ii-full) {flattened GATED_MATRIX_ENTRIES} ⊆ SIGNING_DENYLIST.
    //           Checks every gated entry against the denylist in one assertion
    //           so a new gated tool missing from SIGNING_DENYLIST fails here.
    #[test]
    fn gated_matrix_entries_subset_of_signing_denylist() {
        use std::collections::HashSet;
        let denylist: HashSet<&str> = SIGNING_DENYLIST.iter().copied().collect();
        for (cap, tools) in GATED_MATRIX_ENTRIES {
            for tool in *tools {
                assert!(
                    denylist.contains(tool),
                    "gated tool '{tool}' (capability {cap:?}) is in GATED_MATRIX_ENTRIES \
                     but NOT in SIGNING_DENYLIST — add it to SIGNING_DENYLIST so the \
                     ungated resolve_action path is permanently blocked"
                );
            }
        }
    }

    // (iii) SignPayment ∩ {bare-sign tools (sep43/sep53)} = ∅
    //       (The gated tool for SignPayment must route to stellar_pay_commit ONLY,
    //        never to any sep43/sep53 signing tool.)
    #[test]
    fn sign_payment_gated_tools_do_not_include_bare_sign_tools() {
        let bare_sign_tools = [
            "stellar_sep43_sign_transaction",
            "stellar_sep43_sign_and_submit_transaction",
            "stellar_sep43_sign_auth_entry",
            "stellar_sep43_sign_message",
            "stellar_sep53_sign_message",
        ];
        for bare in &bare_sign_tools {
            assert!(
                !SIGN_PAYMENT_GATED_TOOLS.contains(bare),
                "SignPayment gated tools must NOT include bare-sign tool '{bare}'"
            );
        }
        // Also verify the positive invariant: stellar_pay_commit IS in the gated set.
        assert!(
            SIGN_PAYMENT_GATED_TOOLS.contains(&"stellar_pay_commit"),
            "stellar_pay_commit must be in SIGN_PAYMENT_GATED_TOOLS"
        );
    }

    // (iv) resolve_action does NOT resolve any gated tool (ungated path is blocked).
    #[test]
    fn resolve_action_does_not_resolve_gated_tools() {
        for tool in flattened_gated_tools() {
            let result = resolve_action(tool);
            assert!(
                result.is_err(),
                "gated tool '{tool}' must NOT resolve via the ungated resolve_action path \
                 (gated resolver is the sole admission)"
            );
        }
    }

    // (v) gated_grants_for_capability returns Some for SignPayment, None for others.
    #[test]
    fn gated_grants_for_sign_payment() {
        let grants = gated_grants_for_capability(Capability::SignPayment);
        assert!(grants.is_some(), "SignPayment must have gated grants");
        let grants = grants.unwrap();
        assert!(grants.contains(&"stellar_pay_commit"));
    }

    #[test]
    fn gated_grants_for_ungated_capabilities_is_none() {
        for cap in [
            Capability::ReadBalance,
            Capability::ProposeTransaction,
            Capability::SuggestDestination,
            Capability::ObserveEvent,
        ] {
            assert!(
                gated_grants_for_capability(cap).is_none(),
                "capability {cap:?} must NOT have gated grants"
            );
        }
    }
}
