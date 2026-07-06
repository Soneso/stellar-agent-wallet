//! Registry walk test — inventory registry ↔ rmcp ToolRouter parity.
//!
//! Acceptance criteria:
//!
//! (a) Every rmcp router entry has a matching `McpToolRegistration` record in the
//!     inventory registry.
//! (b) Every `McpToolRegistration` record's `name` appears in the rmcp router.
//! (c) For `stellar_balances` specifically: `destructive_hint == false`,
//!     `read_only_hint == true`, and the values match the rmcp `tools/list`
//!     response.
//! (d) For `stellar_friendbot`: `destructive_hint == true`,
//!     `read_only_hint == false`, `chain_id_required == true`.
//!
//! # Design
//!
//! `WalletServer::new` builds its tool registry from
//! `inventory::iter::<McpToolRegistration>()`.  This test independently iterates
//! the same inventory registry and cross-checks it against the rmcp router
//! exposed by `WalletServer::router_tool_names()`, verifying:
//!
//! - No orphaned registry records (registration without router entry).
//! - No orphaned router entries (router entry without registration record).
//! - Annotation values are correct for both registered tools.
//!
//! The test fails the build if the pairing breaks — preventing silent drift
//! between `#[mcp_tool_item]` annotations and `#[tool]` annotations on the same fn.
//!
//! With at least two registered tools (`stellar_balances` + `stellar_friendbot`),
//! `every_router_tool_has_registry_record` and `every_registry_record_appears_in_router`
//! are not vacuously true.  Trybuild compile-fail negative tests provide additional
//! coverage of malformed registrations.
//!
//! # Fail-closed duplicate-registration test
//!
//! `duplicate_registration_fails_closed` synthesises two `McpToolRegistration`
//! values with the same `name` and asserts that `build_tool_registry` returns
//! `Err(BuildRegistryError::DuplicateRegistration)`.  The `inventory` iterator
//! cannot be seeded with synthetic records (it is populated at link time), so
//! this test calls the same duplicate-check helper that production uses.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::collections::HashSet;

use stellar_agent_core::{
    policy::{BuildRegistryError, McpToolRegistration},
    profile::schema::Profile,
};
use stellar_agent_mcp::server::{WalletServer, check_duplicate_registrations};

// ─────────────────────────────────────────────────────────────────────────────
// Helper: iterate all registered McpToolRegistration records
// ─────────────────────────────────────────────────────────────────────────────

fn collect_registry_names() -> HashSet<&'static str> {
    inventory::iter::<McpToolRegistration>()
        .map(|reg| reg.name)
        .collect()
}

fn find_registration(name: &str) -> Option<&'static McpToolRegistration> {
    inventory::iter::<McpToolRegistration>().find(|reg| reg.name == name)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: get rmcp router tool names
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the set of tool names in the rmcp `ToolRouter` for `WalletServer`.
///
/// Uses `WalletServer::router_tool_names()` which builds the same merged route
/// inventory that is cached in `WalletServer::tool_router` for runtime dispatch.
fn collect_router_names() -> HashSet<String> {
    WalletServer::router_tool_names().into_iter().collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// (a) Every router entry has a matching registry record
// ─────────────────────────────────────────────────────────────────────────────

/// Acceptance (a): every rmcp router entry must have a matching
/// `McpToolRegistration` in the inventory registry.
///
/// Failure means a fn has `#[tool]` but is missing `#[mcp_tool_item]`.
#[test]
fn every_router_tool_has_registry_record() {
    let registry = collect_registry_names();
    let router_names = collect_router_names();

    for tool_name in &router_names {
        assert!(
            registry.contains(tool_name.as_str()),
            "Router tool '{}' has no matching McpToolRegistration in inventory registry. \
             Add #[mcp_tool_item(name = \"{}\", ...)] alongside #[tool(name = \"{}\", ...)].",
            tool_name,
            tool_name,
            tool_name,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// (b) Every registry record appears in the router
// ─────────────────────────────────────────────────────────────────────────────

/// Acceptance (b): every `McpToolRegistration` record's `name`
/// must appear in the rmcp ToolRouter.
///
/// Failure means a fn has `#[mcp_tool_item]` but is missing `#[tool]` (or the
/// names are mismatched between the two attributes).
#[test]
fn every_registry_record_appears_in_router() {
    let registry = collect_registry_names();
    let router_names = collect_router_names();
    let router_name_strs: HashSet<&str> = router_names.iter().map(|s| s.as_str()).collect();

    for reg_name in &registry {
        assert!(
            router_name_strs.contains(reg_name),
            "McpToolRegistration for '{}' has no matching router entry. \
             Check that #[mcp_tool_item(name = \"{}\")] and #[tool(name = \"{}\")] \
             are both present on the same fn and that the names match.",
            reg_name,
            reg_name,
            reg_name,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// (c) stellar_balances — annotation values correct
// ─────────────────────────────────────────────────────────────────────────────

/// Acceptance (c): `stellar_balances` must have
/// `destructive_hint == false`, `read_only_hint == true`, `chain_id_required == true`.
///
/// Also verifies that `WalletServer::new`'s tool registry returns the same
/// values as the inventory record — confirming the registry builder preserves
/// the #[mcp_tool_item] annotations through to the policy-engine dispatch site.
#[test]
fn stellar_balances_annotations_correct() {
    let reg = find_registration("stellar_balances").expect(
        "stellar_balances McpToolRegistration not found in inventory registry; \
         ensure #[mcp_tool_item(name = \"stellar_balances\", ...)] is present on the fn",
    );

    assert!(
        !reg.destructive_hint,
        "stellar_balances: destructive_hint must be false (read-only tool)"
    );
    assert!(
        reg.read_only_hint,
        "stellar_balances: read_only_hint must be true (read-only tool)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_balances: chain_id_required must be true (CAIP-2 chain_id arg required)"
    );
}

/// Acceptance (d): `stellar_friendbot` must have
/// `destructive_hint == true`, `read_only_hint == false`, `chain_id_required == true`.
///
/// With two tools registered, the parity assertions above are not vacuous.
#[test]
fn stellar_friendbot_annotations_correct() {
    let reg = find_registration("stellar_friendbot").expect(
        "stellar_friendbot McpToolRegistration not found in inventory registry; \
         ensure #[mcp_tool_item(name = \"stellar_friendbot\", ...)] is present on the fn",
    );

    assert!(
        reg.destructive_hint,
        "stellar_friendbot: destructive_hint must be true (mainnet-gated tool)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_friendbot: read_only_hint must be false (writes on-chain state)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_friendbot: chain_id_required must be true (CAIP-2 chain_id arg required)"
    );
}

/// Confirms that `WalletServer::new`'s built registry propagates annotation values
/// correctly for every registered tool — i.e. `build_tool_registry()` preserves
/// the `#[mcp_tool_item]` annotations through to the policy-engine dispatch site.
///
/// Both `stellar_balances` and `stellar_friendbot` must round-trip; the test
/// fails the build if either tool drops any field.
///
/// Also asserts that `WalletServer::new` is `Ok` for a valid (non-duplicate)
/// registry — the fail-closed path is tested by `duplicate_registration_fails_closed`.
#[test]
fn wallet_server_registry_matches_inventory() {
    // Explicitly set Noop so WalletServer::new succeeds without a policy file
    // on disk (PolicyEngineKind::default() is V1).
    let profile_testnet = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    let server = WalletServer::new(profile_testnet)
        .expect("WalletServer::new must succeed with a valid (no duplicate) registry");

    // Iterate every registration and verify the WalletServer descriptor matches.
    for reg in inventory::iter::<stellar_agent_core::policy::McpToolRegistration>() {
        let descriptor = server
            .tool_registry_descriptor(reg.name)
            .unwrap_or_else(|| {
                panic!(
                    "tool '{}' is in the inventory registry but not in WalletServer's \
                     tool_registry — build_tool_registry() dropped it",
                    reg.name
                )
            });

        assert_eq!(
            descriptor.destructive_hint, reg.destructive_hint,
            "tool '{}': ToolDescriptor.destructive_hint must match \
             McpToolRegistration.destructive_hint",
            reg.name
        );
        assert_eq!(
            descriptor.read_only_hint, reg.read_only_hint,
            "tool '{}': ToolDescriptor.read_only_hint must match \
             McpToolRegistration.read_only_hint",
            reg.name
        );
        assert_eq!(
            descriptor.chain_id_required, reg.chain_id_required,
            "tool '{}': ToolDescriptor.chain_id_required must match \
             McpToolRegistration.chain_id_required",
            reg.name
        );
    }
}

/// Guards against `get_info` instruction-string drift: every tool registered in
/// the inventory registry must be named in the `instructions` string the server
/// advertises in its `initialize` response.  Adding a tool without adding its
/// line to `INSTRUCTIONS_STATIC` in `server.rs` fails this test.
#[test]
fn instructions_string_names_every_registered_tool() {
    use rmcp::ServerHandler as _;

    let profile_testnet = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    let server = WalletServer::new(profile_testnet)
        .expect("WalletServer::new must succeed with a valid registry");
    let instructions = server
        .get_info()
        .instructions
        .expect("get_info must return an instructions string");

    for reg in inventory::iter::<stellar_agent_core::policy::McpToolRegistration>() {
        assert!(
            instructions.contains(reg.name),
            "tool '{}' is registered but not named in the get_info instructions string; \
             add it to INSTRUCTIONS_STATIC in server.rs",
            reg.name
        );
    }
}

/// Verifies that the registry contains exactly the registered tools.
///
/// If this test fails, either `inventory::collect!(McpToolRegistration)` was not
/// called, or the `#[mcp_tool_item]` expansion failed silently.
///
/// The count assertion guards against a tool being accidentally added or dropped.
/// When the tool set changes, update the expected count and the name list below.
#[test]
fn registry_contains_thirty_eight_tools() {
    let registry = collect_registry_names();
    assert_eq!(
        registry.len(),
        38,
        "registry must contain exactly 38 tools \
         (stellar_balances + stellar_friendbot + stellar_create_account \
         + stellar_create_account_commit + stellar_pay + stellar_pay_commit \
         + stellar_fee_stats + stellar_sep43_get_address + stellar_sep43_get_network \
         + stellar_sep43_sign_transaction + stellar_sep43_sign_auth_entry \
         + stellar_sep43_sign_message + stellar_sep43_sign_and_submit_transaction \
         + stellar_x402_create_payment + stellar_x402_parse_receipt \
         + stellar_sep48_preview_invocation + stellar_sep47_discover \
         + stellar_sep53_sign_message + stellar_sep53_verify_message \
         + stellar_sep7_parse_uri + stellar_sep6_deposit_info \
         + stellar_sep24_interactive_url + stellar_x402_authenticated_payment \
         + stellar_toolset_list + stellar_toolset_invoke + stellar_blend_lend \
         + stellar_defindex_vault_deposit + stellar_defindex_vault_withdraw \
         + stellar_dex_trade + stellar_dex_quote \
         + stellar_trustline + stellar_trustline_commit \
         + stellar_claim + stellar_claim_commit \
         + stellar_rules_list + stellar_rules_get \
         + stellar_rule_create + stellar_rule_create_commit); \
         got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_balances"),
        "registry must contain stellar_balances; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_friendbot"),
        "registry must contain stellar_friendbot; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_create_account"),
        "registry must contain stellar_create_account; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_create_account_commit"),
        "registry must contain stellar_create_account_commit; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_pay"),
        "registry must contain stellar_pay; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_pay_commit"),
        "registry must contain stellar_pay_commit; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_fee_stats"),
        "registry must contain stellar_fee_stats; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_sep43_get_address"),
        "registry must contain stellar_sep43_get_address; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_sep43_get_network"),
        "registry must contain stellar_sep43_get_network; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_sep43_sign_transaction"),
        "registry must contain stellar_sep43_sign_transaction; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_sep43_sign_auth_entry"),
        "registry must contain stellar_sep43_sign_auth_entry; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_sep43_sign_message"),
        "registry must contain stellar_sep43_sign_message; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_sep43_sign_and_submit_transaction"),
        "registry must contain stellar_sep43_sign_and_submit_transaction; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_x402_create_payment"),
        "registry must contain stellar_x402_create_payment; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_x402_parse_receipt"),
        "registry must contain stellar_x402_parse_receipt; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_sep48_preview_invocation"),
        "registry must contain stellar_sep48_preview_invocation; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_sep47_discover"),
        "registry must contain stellar_sep47_discover; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_sep53_sign_message"),
        "registry must contain stellar_sep53_sign_message; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_sep53_verify_message"),
        "registry must contain stellar_sep53_verify_message; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_sep7_parse_uri"),
        "registry must contain stellar_sep7_parse_uri; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_sep6_deposit_info"),
        "registry must contain stellar_sep6_deposit_info; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_sep24_interactive_url"),
        "registry must contain stellar_sep24_interactive_url; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_x402_authenticated_payment"),
        "registry must contain stellar_x402_authenticated_payment; got: {registry:?}"
    );
    // Generic toolset-invocation surface.
    assert!(
        registry.contains("stellar_toolset_list"),
        "registry must contain stellar_toolset_list; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_toolset_invoke"),
        "registry must contain stellar_toolset_invoke; got: {registry:?}"
    );
    // Blend lending adapter.
    assert!(
        registry.contains("stellar_blend_lend"),
        "registry must contain stellar_blend_lend; got: {registry:?}"
    );
    // DeFindex vault adapter — deposit and withdraw.
    assert!(
        registry.contains("stellar_defindex_vault_deposit"),
        "registry must contain stellar_defindex_vault_deposit; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_defindex_vault_withdraw"),
        "registry must contain stellar_defindex_vault_withdraw; got: {registry:?}"
    );
    // Soroswap DEX swap adapter — trade and quote.
    assert!(
        registry.contains("stellar_dex_trade"),
        "registry must contain stellar_dex_trade; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_dex_quote"),
        "registry must contain stellar_dex_quote; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_trustline"),
        "registry must contain stellar_trustline; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_trustline_commit"),
        "registry must contain stellar_trustline_commit; got: {registry:?}"
    );
    // Claimable-balance claim adapter — simulate and commit.
    assert!(
        registry.contains("stellar_claim"),
        "registry must contain stellar_claim; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_claim_commit"),
        "registry must contain stellar_claim_commit; got: {registry:?}"
    );
    // Smart-account rules observability — read-only.
    assert!(
        registry.contains("stellar_rules_list"),
        "registry must contain stellar_rules_list; got: {registry:?}"
    );
    assert!(
        registry.contains("stellar_rules_get"),
        "registry must contain stellar_rules_get; got: {registry:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Duplicate-registration fail-closed test
// ─────────────────────────────────────────────────────────────────────────────

/// Exercises the fail-closed duplicate-registration logic.
///
/// The `inventory` iterator is populated at link time and cannot be seeded
/// with synthetic records in a test.  This test directly exercises the same
/// HashMap-insertion logic used by `build_tool_registry()` to verify the
/// `Err(DuplicateRegistration)` path.
///
/// Fail-closed contract: a duplicate `name` in the registry MUST cause startup
/// failure, not silent first-registration-wins.  This prevents a malicious
/// second `McpToolRegistration` with `destructive_hint = false` from shadowing
/// a legitimate `destructive_hint = true` entry, which would bypass the
/// mainnet write-tools gate.
///
/// # Relationship to runtime gate
///
/// The runtime check in `build_tool_registry()` delegates to
/// `check_duplicate_registrations()`. This test calls that same helper with
/// synthetic inputs that mirror what the inventory iterator would yield with a
/// duplicate.
/// The `check-mcp-tool-registry-generated.sh` script provides a complementary
/// fast-fail static check by grepping for duplicate `name = "..."` literals.
#[test]
fn duplicate_registration_fails_closed() {
    // Two distinct registrations — must succeed.
    let distinct = [
        McpToolRegistration {
            name: "stellar_balances",
            destructive_hint: false,
            read_only_hint: true,
            chain_id_required: true,
        },
        McpToolRegistration {
            name: "stellar_pay",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
        },
    ];
    assert!(
        check_duplicate_registrations(&distinct).is_ok(),
        "two distinct registrations must succeed"
    );

    // Duplicate name — MUST fail closed.
    // The second entry shadows the first with destructive_hint = false,
    // which is the exact attack vector this gate closes.
    let duplicate = [
        McpToolRegistration {
            name: "stellar_pay",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
        },
        McpToolRegistration {
            name: "stellar_pay",     // same name — attacker variant
            destructive_hint: false, // would shadow the legitimate destructive=true entry
            read_only_hint: false,
            chain_id_required: false,
        },
    ];
    let result = check_duplicate_registrations(&duplicate);
    assert!(
        matches!(
            result,
            Err(BuildRegistryError::DuplicateRegistration {
                name: "stellar_pay"
            })
        ),
        "duplicate registration must return Err(DuplicateRegistration), got {result:?}"
    );

    // Verify the error message contains the tool name (useful for operator diagnostics).
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("stellar_pay"),
        "DuplicateRegistration error message must name the tool: {err_msg}"
    );
}

/// Acceptance (e): `stellar_create_account` must have
/// `destructive_hint == false`, `read_only_hint == false`, `chain_id_required == true`.
///
/// Simulate step; does NOT submit a transaction.
#[test]
fn stellar_create_account_annotations_correct() {
    let reg = find_registration("stellar_create_account")
        .expect("stellar_create_account McpToolRegistration not found in inventory registry");
    assert!(
        !reg.destructive_hint,
        "stellar_create_account: destructive_hint must be false (simulate step only)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_create_account: read_only_hint must be false (mints nonce = wallet state change)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_create_account: chain_id_required must be true"
    );
}

/// Acceptance (f): `stellar_create_account_commit` must have
/// `destructive_hint == true`, `read_only_hint == false`, `chain_id_required == true`.
///
/// Commit step; signs and submits a transaction.
#[test]
fn stellar_create_account_commit_annotations_correct() {
    let reg = find_registration("stellar_create_account_commit").expect(
        "stellar_create_account_commit McpToolRegistration not found in inventory registry",
    );
    assert!(
        reg.destructive_hint,
        "stellar_create_account_commit: destructive_hint must be true (submits transaction)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_create_account_commit: read_only_hint must be false"
    );
    assert!(
        reg.chain_id_required,
        "stellar_create_account_commit: chain_id_required must be true"
    );
}

/// Acceptance (g): `stellar_pay` must have
/// `destructive_hint == false`, `read_only_hint == false`, `chain_id_required == true`.
///
/// Simulate step; does NOT submit a transaction.
#[test]
fn stellar_pay_annotations_correct() {
    let reg = find_registration("stellar_pay")
        .expect("stellar_pay McpToolRegistration not found in inventory registry");
    assert!(
        !reg.destructive_hint,
        "stellar_pay: destructive_hint must be false (simulate step only)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_pay: read_only_hint must be false (mints nonce = wallet state change)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_pay: chain_id_required must be true"
    );
}

/// Acceptance (h): `stellar_pay_commit` must have
/// `destructive_hint == true`, `read_only_hint == false`, `chain_id_required == true`.
///
/// Commit step; signs and submits a transaction.
#[test]
fn stellar_pay_commit_annotations_correct() {
    let reg = find_registration("stellar_pay_commit")
        .expect("stellar_pay_commit McpToolRegistration not found in inventory registry");
    assert!(
        reg.destructive_hint,
        "stellar_pay_commit: destructive_hint must be true (submits transaction)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_pay_commit: read_only_hint must be false"
    );
    assert!(
        reg.chain_id_required,
        "stellar_pay_commit: chain_id_required must be true"
    );
}

/// `stellar_sep43_get_address` must have
/// `destructive_hint == false`, `read_only_hint == true`, `chain_id_required == true`.
///
/// SEP-43 `getAddress` returns the active wallet address; it is read-only and
/// does NOT modify chain state or access the keyring signer.
#[test]
fn stellar_sep43_get_address_annotations_correct() {
    let reg = find_registration("stellar_sep43_get_address")
        .expect("stellar_sep43_get_address McpToolRegistration not found in inventory registry");
    assert!(
        !reg.destructive_hint,
        "stellar_sep43_get_address: destructive_hint must be false (read-only address lookup)"
    );
    assert!(
        reg.read_only_hint,
        "stellar_sep43_get_address: read_only_hint must be true (does not modify state)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_sep43_get_address: chain_id_required must be true"
    );
}

/// `stellar_sep43_get_network` must have
/// `destructive_hint == false`, `read_only_hint == true`, `chain_id_required == true`.
///
/// SEP-43 `getNetwork` returns the active network name and passphrase; it is
/// read-only and does NOT modify chain state.
#[test]
fn stellar_sep43_get_network_annotations_correct() {
    let reg = find_registration("stellar_sep43_get_network")
        .expect("stellar_sep43_get_network McpToolRegistration not found in inventory registry");
    assert!(
        !reg.destructive_hint,
        "stellar_sep43_get_network: destructive_hint must be false (read-only network info)"
    );
    assert!(
        reg.read_only_hint,
        "stellar_sep43_get_network: read_only_hint must be true (does not modify state)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_sep43_get_network: chain_id_required must be true"
    );
}

/// `stellar_sep43_sign_transaction` must have
/// `destructive_hint == false`, `read_only_hint == false`, `chain_id_required == true`.
///
/// SEP-43 `signTransaction` creates a signature but does NOT submit a
/// transaction to the network. The `submit?` option defaults to `false` per
/// the SEP-43 spec; submission is a separate step.
#[test]
fn stellar_sep43_sign_transaction_annotations_correct() {
    let reg = find_registration("stellar_sep43_sign_transaction").expect(
        "stellar_sep43_sign_transaction McpToolRegistration not found in inventory registry",
    );
    assert!(
        !reg.destructive_hint,
        "stellar_sep43_sign_transaction: destructive_hint must be false \
         (signs only, does not submit to network)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_sep43_sign_transaction: read_only_hint must be false (creates a signature)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_sep43_sign_transaction: chain_id_required must be true"
    );
}

/// `stellar_sep43_sign_auth_entry` must have
/// `destructive_hint == false`, `read_only_hint == false`, `chain_id_required == true`.
///
/// SEP-43 `signAuthEntry` creates a signature over a `SorobanAuthorizationEntry`
/// but does NOT submit anything to the network.
#[test]
fn stellar_sep43_sign_auth_entry_annotations_correct() {
    let reg = find_registration("stellar_sep43_sign_auth_entry").expect(
        "stellar_sep43_sign_auth_entry McpToolRegistration not found in inventory registry",
    );
    assert!(
        !reg.destructive_hint,
        "stellar_sep43_sign_auth_entry: destructive_hint must be false \
         (signs only, does not submit to network)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_sep43_sign_auth_entry: read_only_hint must be false (creates a signature)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_sep43_sign_auth_entry: chain_id_required must be true"
    );
}

/// `stellar_sep43_sign_message` must have
/// `destructive_hint == false`, `read_only_hint == false`, `chain_id_required == true`.
///
/// SEP-43 `signMessage` creates a signature over an arbitrary UTF-8 message
/// but does NOT modify chain state or submit a transaction.
#[test]
fn stellar_sep43_sign_message_annotations_correct() {
    let reg = find_registration("stellar_sep43_sign_message")
        .expect("stellar_sep43_sign_message McpToolRegistration not found in inventory registry");
    assert!(
        !reg.destructive_hint,
        "stellar_sep43_sign_message: destructive_hint must be false \
         (signs only, does not submit to network)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_sep43_sign_message: read_only_hint must be false (creates a signature)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_sep43_sign_message: chain_id_required must be true"
    );
}

/// `stellar_x402_create_payment` must have
/// `destructive_hint == false`, `read_only_hint == false`, `chain_id_required == true`.
///
/// The tool constructs and signs a payment payload (accesses keyring) but does
/// NOT submit anything to the network.  The MCP host performs the HTTP-402 submit.
#[test]
fn stellar_x402_create_payment_annotations_correct() {
    let reg = find_registration("stellar_x402_create_payment")
        .expect("stellar_x402_create_payment McpToolRegistration not found in inventory registry");
    assert!(
        !reg.destructive_hint,
        "stellar_x402_create_payment: destructive_hint must be false \
         (produces signed payload only; wallet does not submit)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_x402_create_payment: read_only_hint must be false \
         (accesses keyring + creates a signed artifact)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_x402_create_payment: chain_id_required must be true"
    );
}

/// `stellar_x402_parse_receipt` must have
/// `destructive_hint == false`, `read_only_hint == true`, `chain_id_required == false`.
///
/// The tool is a pure decode of the `PAYMENT-RESPONSE` header; it does not
/// access the keyring, sign anything, or interact with the network.
#[test]
fn stellar_x402_parse_receipt_annotations_correct() {
    let reg = find_registration("stellar_x402_parse_receipt")
        .expect("stellar_x402_parse_receipt McpToolRegistration not found in inventory registry");
    assert!(
        !reg.destructive_hint,
        "stellar_x402_parse_receipt: destructive_hint must be false (read-only decode)"
    );
    assert!(
        reg.read_only_hint,
        "stellar_x402_parse_receipt: read_only_hint must be true (pure decode, no side effects)"
    );
    assert!(
        !reg.chain_id_required,
        "stellar_x402_parse_receipt: chain_id_required must be false \
         (receipt parsing is chain-agnostic)"
    );
}

/// `stellar_sep48_preview_invocation` must have
/// `destructive_hint == false`, `read_only_hint == true`, `chain_id_required == true`.
///
/// The tool fetches the on-chain SEP-48 spec and renders typed args; it does not
/// sign, submit, or modify any chain state.
#[test]
fn stellar_sep48_preview_invocation_annotations_correct() {
    let reg = find_registration("stellar_sep48_preview_invocation").expect(
        "stellar_sep48_preview_invocation McpToolRegistration not found in inventory registry",
    );
    assert!(
        !reg.destructive_hint,
        "stellar_sep48_preview_invocation: destructive_hint must be false (read-only spec fetch)"
    );
    assert!(
        reg.read_only_hint,
        "stellar_sep48_preview_invocation: read_only_hint must be true (does not modify state)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_sep48_preview_invocation: chain_id_required must be true"
    );
}

/// `stellar_sep47_discover` must have
/// `destructive_hint == false`, `read_only_hint == true`, `chain_id_required == true`.
///
/// The tool fetches the contract WASM and reads the `contractmetav0` `sep` entry;
/// it does not sign, submit, or modify any chain state.
#[test]
fn stellar_sep47_discover_annotations_correct() {
    let reg = find_registration("stellar_sep47_discover")
        .expect("stellar_sep47_discover McpToolRegistration not found in inventory registry");
    assert!(
        !reg.destructive_hint,
        "stellar_sep47_discover: destructive_hint must be false (read-only meta fetch)"
    );
    assert!(
        reg.read_only_hint,
        "stellar_sep47_discover: read_only_hint must be true (does not modify state)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_sep47_discover: chain_id_required must be true"
    );
}

/// `stellar_sep53_sign_message` must have
/// `destructive_hint == false`, `read_only_hint == false`, `chain_id_required == true`.
///
/// The tool accesses the keyring to produce a SEP-53 prefixed signature but
/// does NOT submit any transaction to the network.
#[test]
fn stellar_sep53_sign_message_annotations_correct() {
    let reg = find_registration("stellar_sep53_sign_message")
        .expect("stellar_sep53_sign_message McpToolRegistration not found in inventory registry");
    assert!(
        !reg.destructive_hint,
        "stellar_sep53_sign_message: destructive_hint must be false (signs only, does not submit)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_sep53_sign_message: read_only_hint must be false (accesses keyring)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_sep53_sign_message: chain_id_required must be true"
    );
}

/// `stellar_sep53_verify_message` must have
/// `destructive_hint == false`, `read_only_hint == true`, `chain_id_required == true`.
///
/// The tool is pure verification — no keyring access, no network calls, no
/// state mutation.
#[test]
fn stellar_sep53_verify_message_annotations_correct() {
    let reg = find_registration("stellar_sep53_verify_message")
        .expect("stellar_sep53_verify_message McpToolRegistration not found in inventory registry");
    assert!(
        !reg.destructive_hint,
        "stellar_sep53_verify_message: destructive_hint must be false (read-only verification)"
    );
    assert!(
        reg.read_only_hint,
        "stellar_sep53_verify_message: read_only_hint must be true (pure verification, no side effects)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_sep53_verify_message: chain_id_required must be true"
    );
}

/// `stellar_sep7_parse_uri` must have
/// `destructive_hint == false`, `read_only_hint == true`, `chain_id_required == true`.
///
/// The tool is parse-and-verify-only: no keyring access, no signing,
/// no callback POST.  Verification is a read-only HTTPS GET of stellar.toml.
#[test]
fn stellar_sep7_parse_uri_annotations_correct() {
    let reg = find_registration("stellar_sep7_parse_uri")
        .expect("stellar_sep7_parse_uri McpToolRegistration not found in inventory registry");
    assert!(
        !reg.destructive_hint,
        "stellar_sep7_parse_uri: destructive_hint must be false (parse-and-verify-only)"
    );
    assert!(
        reg.read_only_hint,
        "stellar_sep7_parse_uri: read_only_hint must be true (no keyring, no signing)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_sep7_parse_uri: chain_id_required must be true"
    );
}

/// `stellar_sep6_deposit_info` must have
/// `destructive_hint == false`, `read_only_hint == true`, `chain_id_required == true`.
///
/// The tool calls GET /info ONLY.  Never initiates a deposit, transmits KYC,
/// or modifies any state.
#[test]
fn stellar_sep6_deposit_info_annotations_correct() {
    let reg = find_registration("stellar_sep6_deposit_info")
        .expect("stellar_sep6_deposit_info McpToolRegistration not found in inventory registry");
    assert!(
        !reg.destructive_hint,
        "stellar_sep6_deposit_info: destructive_hint must be false (GET /info only)"
    );
    assert!(
        reg.read_only_hint,
        "stellar_sep6_deposit_info: read_only_hint must be true (no keyring, no state mutation)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_sep6_deposit_info: chain_id_required must be true"
    );
}

/// `stellar_sep24_interactive_url` must have
/// `destructive_hint == false`, `read_only_hint == false`, `chain_id_required == true`.
///
/// The tool accesses a JWT Bearer token (keyring-derived path) but does not
/// modify on-chain state.  `read_only_hint=false` (JWT access path).
#[test]
fn stellar_sep24_interactive_url_annotations_correct() {
    let reg = find_registration("stellar_sep24_interactive_url").expect(
        "stellar_sep24_interactive_url McpToolRegistration not found in inventory registry",
    );
    assert!(
        !reg.destructive_hint,
        "stellar_sep24_interactive_url: destructive_hint must be false \
         (no on-chain state modification)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_sep24_interactive_url: read_only_hint must be false \
         (initiates anchor session via JWT)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_sep24_interactive_url: chain_id_required must be true"
    );
}

/// `stellar_x402_authenticated_payment` must have
/// `destructive_hint == false`, `read_only_hint == false`, `chain_id_required == true`.
///
/// The tool runs a SEP-10 ephemeral auth session (anchor interaction) + accesses
/// the keyring + constructs a signed payment artifact but does NOT submit anything
/// to the network.  `read_only_hint=false` (keyring + anchor session).
#[test]
fn stellar_x402_authenticated_payment_annotations_correct() {
    let reg = find_registration("stellar_x402_authenticated_payment").expect(
        "stellar_x402_authenticated_payment McpToolRegistration not found in inventory registry",
    );
    assert!(
        !reg.destructive_hint,
        "stellar_x402_authenticated_payment: destructive_hint must be false \
         (produces signed payload + JWT only; wallet does not submit)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_x402_authenticated_payment: read_only_hint must be false \
         (accesses keyring + initiates anchor auth session)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_x402_authenticated_payment: chain_id_required must be true"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Toolset dispatcher tool annotation tests
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies `stellar_toolset_list` annotations: read-only, not destructive,
/// chain_id not required.
#[test]
fn stellar_toolset_list_annotations_correct() {
    let reg = find_registration("stellar_toolset_list")
        .expect("stellar_toolset_list McpToolRegistration not found");
    assert!(
        !reg.destructive_hint,
        "stellar_toolset_list: destructive_hint must be false (read-only enumeration)"
    );
    assert!(
        reg.read_only_hint,
        "stellar_toolset_list: read_only_hint must be true (reads install metadata only)"
    );
    assert!(
        !reg.chain_id_required,
        "stellar_toolset_list: chain_id_required must be false (no network call)"
    );
}

/// Verifies `stellar_toolset_invoke` annotations: read-only, not destructive,
/// chain_id not required at the outer gate level.
#[test]
fn stellar_toolset_invoke_annotations_correct() {
    let reg = find_registration("stellar_toolset_invoke")
        .expect("stellar_toolset_invoke McpToolRegistration not found");
    assert!(
        !reg.destructive_hint,
        "stellar_toolset_invoke: destructive_hint must be false (all routable matrix tools are non-destructive)"
    );
    assert!(
        reg.read_only_hint,
        "stellar_toolset_invoke: read_only_hint must be true (outer gate; routed tool determines actual mutability)"
    );
    assert!(
        !reg.chain_id_required,
        "stellar_toolset_invoke: chain_id_required must be false (outer gate; routed tool handles chain_id)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Stablecoin trustline tool annotation tests
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies `stellar_trustline` annotations: simulate step — not destructive,
/// not read-only, chain_id required.
///
/// `destructive_hint=false`: does NOT submit a transaction (mints a nonce only).
/// `read_only_hint=false`: mints a nonce (wallet state mutation).
/// `chain_id_required=true`: denomination resolver requires network passphrase.
#[test]
fn stellar_trustline_annotations_correct() {
    let reg = find_registration("stellar_trustline")
        .expect("stellar_trustline McpToolRegistration not found");
    assert!(
        !reg.destructive_hint,
        "stellar_trustline: destructive_hint must be false (simulate step; does not submit)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_trustline: read_only_hint must be false (mints a nonce)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_trustline: chain_id_required must be true"
    );
}

/// Verifies `stellar_trustline_commit` annotations: commit step — destructive,
/// not read-only, chain_id required.
///
/// `destructive_hint=true`: submits a `ChangeTrust` transaction on-chain.
/// `read_only_hint=false`: signs and submits.
/// `chain_id_required=true`: network passphrase required for signing.
#[test]
fn stellar_trustline_commit_annotations_correct() {
    let reg = find_registration("stellar_trustline_commit")
        .expect("stellar_trustline_commit McpToolRegistration not found");
    assert!(
        reg.destructive_hint,
        "stellar_trustline_commit: destructive_hint must be true (submits on-chain ChangeTrust)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_trustline_commit: read_only_hint must be false (signs and submits)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_trustline_commit: chain_id_required must be true"
    );
}

/// Verifies `stellar_claim` annotations: simulate step — not destructive, not
/// read-only, chain_id required.
///
/// `destructive_hint=false`: does NOT submit a transaction (mints a nonce only).
/// `read_only_hint=false`: mints a nonce (wallet state mutation).
/// `chain_id_required=true`: CAIP-2 chain_id arg required.
#[test]
fn stellar_claim_annotations_correct() {
    let reg =
        find_registration("stellar_claim").expect("stellar_claim McpToolRegistration not found");
    assert!(
        !reg.destructive_hint,
        "stellar_claim: destructive_hint must be false (simulate step; does not submit)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_claim: read_only_hint must be false (mints a nonce)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_claim: chain_id_required must be true"
    );
}

/// Verifies `stellar_claim_commit` annotations: commit step — destructive, not
/// read-only, chain_id required.
///
/// `destructive_hint=true`: submits a `ClaimClaimableBalance` transaction.
/// `read_only_hint=false`: signs and submits.
/// `chain_id_required=true`: network passphrase required for signing.
#[test]
fn stellar_claim_commit_annotations_correct() {
    let reg = find_registration("stellar_claim_commit")
        .expect("stellar_claim_commit McpToolRegistration not found");
    assert!(
        reg.destructive_hint,
        "stellar_claim_commit: destructive_hint must be true (submits on-chain ClaimClaimableBalance)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_claim_commit: read_only_hint must be false (signs and submits)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_claim_commit: chain_id_required must be true"
    );
}

/// Verifies that `WalletServer::new` is `Ok` when the real production registry
/// contains no duplicates — belt-and-braces against a regression where the
/// production fns accidentally share a name.
#[test]
fn wallet_server_new_succeeds_with_production_registry() {
    // Explicitly set Noop so WalletServer::new succeeds without a policy file
    // on disk (PolicyEngineKind::default() is V1).
    let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    assert!(
        WalletServer::new(profile).is_ok(),
        "WalletServer::new must succeed with the production registry (no duplicates expected)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Rules-observability tool annotation tests
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies `stellar_rules_list` annotations: read-only, not destructive,
/// chain_id required.
#[test]
fn stellar_rules_list_annotations_correct() {
    let reg = find_registration("stellar_rules_list")
        .expect("stellar_rules_list McpToolRegistration not found in inventory registry");
    assert!(
        !reg.destructive_hint,
        "stellar_rules_list: destructive_hint must be false (read-only enumeration)"
    );
    assert!(
        reg.read_only_hint,
        "stellar_rules_list: read_only_hint must be true (does not modify state)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_rules_list: chain_id_required must be true"
    );
}

/// Verifies `stellar_rules_get` annotations: read-only, not destructive,
/// chain_id required.
#[test]
fn stellar_rules_get_annotations_correct() {
    let reg = find_registration("stellar_rules_get")
        .expect("stellar_rules_get McpToolRegistration not found in inventory registry");
    assert!(
        !reg.destructive_hint,
        "stellar_rules_get: destructive_hint must be false (read-only read)"
    );
    assert!(
        reg.read_only_hint,
        "stellar_rules_get: read_only_hint must be true (does not modify state)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_rules_get: chain_id_required must be true"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent-proposed context rules tool annotation tests (Package D, GH issue #8)
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies `stellar_rule_create` annotations: not read-only (persists a
/// pending approval), not destructive (does not install anything),
/// chain_id required.
#[test]
fn stellar_rule_create_annotations_correct() {
    let reg = find_registration("stellar_rule_create")
        .expect("stellar_rule_create McpToolRegistration not found in inventory registry");
    assert!(
        !reg.destructive_hint,
        "stellar_rule_create: destructive_hint must be false (simulate only, no install)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_rule_create: read_only_hint must be false (persists a pending-approval entry)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_rule_create: chain_id_required must be true"
    );
}

/// Verifies `stellar_rule_create_commit` annotations: not read-only, IS
/// destructive (installs a rule on-chain), chain_id required.
#[test]
fn stellar_rule_create_commit_annotations_correct() {
    let reg = find_registration("stellar_rule_create_commit")
        .expect("stellar_rule_create_commit McpToolRegistration not found in inventory registry");
    assert!(
        reg.destructive_hint,
        "stellar_rule_create_commit: destructive_hint must be true (installs on-chain)"
    );
    assert!(
        !reg.read_only_hint,
        "stellar_rule_create_commit: read_only_hint must be false (signs and submits)"
    );
    assert!(
        reg.chain_id_required,
        "stellar_rule_create_commit: chain_id_required must be true"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire-format drift guard: every tool INPUT schema must not carry a raw
// integer/number-typed value-denominated property.
// ─────────────────────────────────────────────────────────────────────────────

/// A JSON-Schema property discovered under a value-denominated-looking name
/// that is typed as a raw integer/number rather than a string.
#[derive(Debug)]
struct NumericValueField {
    tool_name: String,
    field_name: String,
    json_type: String,
}

/// Exact field names allowed to be integer/number-typed despite matching the
/// value-denominated name pattern below. Each entry is a COUNT-like or
/// budget-like field that is genuinely not a stroop/base-unit amount, or a
/// third-party passthrough field explicitly out of scope for this wire
/// convention (see the crate-level amount-wire rustdoc for the class rule).
///
/// Built empirically: run `wire_drift_guard_input_schemas_have_no_raw_numeric_amount_fields`
/// with this set emptied to regenerate, then re-populate with a one-line
/// justification per entry.
const ALLOWED_NUMERIC_FIELD_NAMES: &[(&str, &str)] = &[];

/// Returns `true` if a JSON-Schema `"type"` value denotes `"integer"` or
/// `"number"`.
///
/// `schemars` (draft 2020-12) renders a required field's type as a bare
/// string (`"type": "integer"`) but an `Option<T>` field's type as an array
/// including `"null"` (`"type": ["integer", "null"]`) — both forms must be
/// checked, or every optional numeric field silently evades this guard.
fn schema_type_is_numeric(type_value: &serde_json::Value) -> bool {
    match type_value {
        serde_json::Value::String(s) => s == "integer" || s == "number",
        serde_json::Value::Array(arr) => arr
            .iter()
            .any(|v| v.as_str().is_some_and(|s| s == "integer" || s == "number")),
        _ => false,
    }
}

/// Resolves a `{"$ref": "#/$defs/Name"}` node against `root`'s `$defs` map.
///
/// Returns `None` when `node` is not a `$ref` object or the target is absent
/// from `$defs` (schemars always emits a resolvable local `$defs` ref for
/// this crate's schemas, so an absent target indicates a walker bug, not a
/// production schema issue — returning `None` here simply skips the branch
/// rather than panicking).
fn resolve_ref<'a>(
    root: &'a serde_json::Value,
    node: &serde_json::Value,
) -> Option<&'a serde_json::Value> {
    let ref_path = node.get("$ref")?.as_str()?;
    let name = ref_path.strip_prefix("#/$defs/")?;
    root.get("$defs")?.get(name)
}

/// Returns `true` if `node` (or, when `node` is a `$ref`, its resolved
/// target) is directly typed as `"integer"`/`"number"` — checked via
/// [`schema_type_is_numeric`] on `node`'s own `"type"` key only (does not
/// recurse into nested `anyOf`; the caller handles the `anyOf` fan-out).
fn node_is_numeric(root: &serde_json::Value, node: &serde_json::Value) -> bool {
    if let Some(type_value) = node.get("type")
        && schema_type_is_numeric(type_value)
    {
        return true;
    }
    if let Some(resolved) = resolve_ref(root, node) {
        return node_is_numeric(root, resolved);
    }
    false
}

/// Recursively walks a JSON-Schema node, looking for `properties` entries
/// whose name matches `(?i)(_stroops|amount|balance|limit|fee|budget|qty|spend|price)`
/// and whose type resolves to `"integer"`/`"number"` (rather than
/// `"string"`), across every representation `schemars` (draft 2020-12) emits:
///
/// - Required field: bare `"type": "integer"`.
/// - `Option<primitive>`: `"type": ["integer", "null"]`.
/// - `Option<RefType>` / enum-shaped field: `"anyOf": [{"$ref": "..."}, {"type": "null"}]`
///   — each `anyOf` branch is checked, resolving `$ref` against the tool's
///   own `$defs` map.
///
/// Also walks into `items` (array schemas) and `properties` (nested object
/// schemas) so a `Vec<Struct>` or nested-object input field is covered, AND
/// descends into each `anyOf` branch's `$ref`-resolved target so a field
/// shaped `Option<Struct { amount: u64 }>` — an object hidden behind an
/// `anyOf`/`$ref` indirection rather than exposed as a direct `properties`
/// entry — cannot evade the guard.
fn walk_schema_for_numeric_value_fields(
    tool_name: &str,
    root: &serde_json::Value,
    schema: &serde_json::Value,
    findings: &mut Vec<NumericValueField>,
) {
    let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) else {
        return;
    };

    for (field_name, field_schema) in properties {
        if matches_value_denominated_name(field_name) {
            let mut hit_type: Option<String> = None;
            if let Some(type_value) = field_schema.get("type")
                && schema_type_is_numeric(type_value)
            {
                hit_type = Some(type_value.to_string());
            }
            if hit_type.is_none()
                && let Some(branches) = field_schema.get("anyOf").and_then(|v| v.as_array())
            {
                for branch in branches {
                    if node_is_numeric(root, branch) {
                        hit_type = Some(format!("anyOf branch: {branch}"));
                        break;
                    }
                }
            }
            if let Some(json_type) = hit_type {
                findings.push(NumericValueField {
                    tool_name: tool_name.to_owned(),
                    field_name: field_name.clone(),
                    json_type,
                });
            }
        }
        // Recurse into nested object schemas.
        walk_schema_for_numeric_value_fields(tool_name, root, field_schema, findings);
        // Recurse into each `anyOf` branch's `$ref`-resolved target (e.g.
        // `Option<Struct>`, where the struct's own `amount`-shaped fields
        // live behind the ref, not as direct properties on this node).
        if let Some(branches) = field_schema.get("anyOf").and_then(|v| v.as_array()) {
            for branch in branches {
                if let Some(resolved) = resolve_ref(root, branch) {
                    walk_schema_for_numeric_value_fields(tool_name, root, resolved, findings);
                } else {
                    walk_schema_for_numeric_value_fields(tool_name, root, branch, findings);
                }
            }
        }
        // Recurse into array item schemas (e.g. Vec<Struct> fields).
        if let Some(items) = field_schema.get("items") {
            walk_schema_for_numeric_value_fields(tool_name, root, items, findings);
        }
    }
}

/// Case-insensitive match against the value-denominated name pattern:
/// `(?i)(_stroops|amount|balance|limit|fee|budget|qty|spend|price)`.
fn matches_value_denominated_name(field_name: &str) -> bool {
    let lower = field_name.to_ascii_lowercase();
    [
        "_stroops", "amount", "balance", "limit", "fee", "budget", "qty", "spend", "price",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Wire-format drift guard (input schemas only).
///
/// Walks every registered tool's rmcp `input_schema` and fails if any
/// property whose name matches the value-denominated pattern above is typed
/// as a raw JSON integer/number rather than a string. A JSON number backed by
/// `f64` cannot represent a stroop/base-unit amount exactly once it exceeds
/// `2^53`; every value-denominated MCP tool input MUST be a decimal string
/// (see `amount_wire.rs` / `stellar_agent_core::wire_stroops` for the
/// convention this enforces).
///
/// # Scope
///
/// This guard covers INPUT schemas only. It does NOT protect the reader/output
/// side of the convention (a tool could still emit a numeric-typed field in
/// its `CallToolResult` JSON body — rmcp tools do not declare
/// `#[tool(output_schema)]` here, so there is no machine-checkable output
/// schema to walk). Response-side conformance is pinned by the per-tool wire
/// shape tests added alongside the string-encoding migration (see
/// `pay_integration.rs`, `create_account_integration.rs`,
/// `trustline_integration.rs`, `claim_integration.rs`, and the `wire_stroops`
/// unit tests) — this guard and those tests are complementary, not
/// substitutes for each other.
#[test]
fn wire_drift_guard_input_schemas_have_no_raw_numeric_amount_fields() {
    let allowed: std::collections::HashSet<&str> = ALLOWED_NUMERIC_FIELD_NAMES
        .iter()
        .map(|(name, _reason)| *name)
        .collect();

    let mut findings = Vec::new();
    for tool in WalletServer::all_registered_tools() {
        let schema = serde_json::Value::Object((*tool.input_schema).clone());
        walk_schema_for_numeric_value_fields(&tool.name, &schema, &schema, &mut findings);
    }

    let unallowed: Vec<&NumericValueField> = findings
        .iter()
        .filter(|f| !allowed.contains(f.field_name.as_str()))
        .collect();

    let summary: Vec<String> = unallowed
        .iter()
        .map(|f| format!("{}.{} (type: {})", f.tool_name, f.field_name, f.json_type))
        .collect();

    assert!(
        unallowed.is_empty(),
        "the following INPUT schema properties look value-denominated \
         (name matches _stroops/amount/balance/limit/fee/budget/qty/spend/price) \
         but are typed as a raw JSON {{integer,number}} rather than a decimal \
         string: {summary:#?}\n\
         Either retype the field as a decimal string on the wire, or — if it is \
         genuinely a count/id/budget rather than a stroop amount — add its exact \
         field name to ALLOWED_NUMERIC_FIELD_NAMES with a one-line justification."
    );
}
