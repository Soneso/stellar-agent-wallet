//! MCP tool implementations for the Stellar agent wallet.
//!
//! Each sub-module owns one or more related tool fns in their own
//! `#[mcp_tool_router] #[tool_router(...)]` impl block.  The sub-routers are
//! merged into the master `ToolRouter` field of `WalletServer` inside
//! `WalletServer::new` (server.rs).
//!
//! # Module layout
//!
//! - `common` — shared constants, `ToolCatalogueAdapter`, dispatch helpers, and
//!   `build_tool_registry`.
//! - `balances` — `stellar_balances` tool (read-only).
//! - `friendbot` — `stellar_friendbot` tool (testnet-only, destructive).
//! - `create_account` — `stellar_create_account` and
//!   `stellar_create_account_commit` tools.
//! - `pay` — `stellar_pay` and `stellar_pay_commit` tools.
//! - `sep43_get_address` — `stellar_sep43_get_address` tool (SEP-43 getAddress).
//! - `sep43_get_network` — `stellar_sep43_get_network` tool (SEP-43 getNetwork).
//! - `sep43_sign_transaction` — `stellar_sep43_sign_transaction` tool.
//! - `sep43_sign_auth_entry` — `stellar_sep43_sign_auth_entry` tool.
//! - `sep43_sign_message` — `stellar_sep43_sign_message` tool.
//! - `sep43_sign_and_submit_transaction` — `stellar_sep43_sign_and_submit_transaction` tool.
//! - `x402_create_payment` — `stellar_x402_create_payment` tool (x402 payer).
//! - `x402_parse_receipt` — `stellar_x402_parse_receipt` tool (x402 receipt).
//! - `sep48_preview_invocation` — `stellar_sep48_preview_invocation` tool (SEP-48 typed-preview).
//! - `sep47_discover` — `stellar_sep47_discover` tool (SEP-47 claim-discovery).
//! - `sep53_sign_message` — `stellar_sep53_sign_message` tool (SEP-53 prefixed sign).
//! - `sep53_verify_message` — `stellar_sep53_verify_message` tool (SEP-53 verify).
//! - `sep7_parse_uri` — `stellar_sep7_parse_uri` tool (SEP-7 inbound URI parse + verify).
//! - `sep6_deposit_info` — `stellar_sep6_deposit_info` tool (SEP-6 /info discovery).
//! - `sep24_interactive_url` — `stellar_sep24_interactive_url` tool (SEP-24 hand-off).
//! - `x402_authenticated_payment` — `stellar_x402_authenticated_payment` tool (x402 + SEP-10 gate).
//! - `toolsets` — `stellar_toolset_list` and `stellar_toolset_invoke` tools (generic dispatcher).
//! - `blend_lend` — `stellar_blend_lend` tool (Blend lending adapter).
//! - `dex_trade` — `stellar_dex_trade` + `stellar_dex_quote` tools (Soroswap swap adapter).
//! - `trustline` — `stellar_trustline` + `stellar_trustline_commit` tools (stablecoin trustline verb).

// Shared decimal-string <-> i128 parse helpers for the DeFi tool args (dex,
// blend, vault) and other i128-carrying wire fields.
pub(crate) mod amount_wire;
pub(crate) mod balances;
pub(crate) mod common;
pub(crate) mod create_account;
pub(crate) mod fee_stats;
pub(crate) mod friendbot;
pub(crate) mod pay;
pub(crate) mod sep43_get_address;
pub(crate) mod sep43_get_network;
pub(crate) mod sep43_sign_and_submit_transaction;
pub(crate) mod sep43_sign_auth_entry;
pub(crate) mod sep43_sign_message;
pub(crate) mod sep43_sign_transaction;
pub(crate) mod value_audit;
// x402 Exact Stellar payment scheme MCP tools.
pub(crate) mod x402_create_payment;
pub(crate) mod x402_parse_receipt;
// x402 authenticated payment (SEP-10 identity gate + payment).
pub(crate) mod x402_authenticated_payment;
// SEP-48 typed-preview + SEP-47 claim-discovery tools.
pub(crate) mod sep47_discover;
pub(crate) mod sep48_preview_invocation;
// SEP-53 prefixed message sign/verify tools.
pub(crate) mod sep53_sign_message;
pub(crate) mod sep53_verify_message;
// SEP-7 inbound URI parse + verify tool.
pub(crate) mod sep7_parse_uri;
// SEP-6 discovery + SEP-24 interactive hand-off tools.
pub(crate) mod sep24_interactive_url;
pub(crate) mod sep6_deposit_info;
// Generic toolset-invocation surface (list + invoke).
pub(crate) mod toolsets;
// Blend lending adapter — live DeFi verb.
pub(crate) mod blend_lend;
// DeFindex vault adapter — vault deposit/withdraw verbs.
pub(crate) mod vault;
// Soroswap DEX swap adapter — trade + quote verbs.
pub(crate) mod dex_trade;
// Stablecoin substrate — trustline verb.
pub(crate) mod trustline;

pub(crate) mod claim;
// Smart-account rules observability — stellar_rules_list / stellar_rules_get.
pub(crate) mod rules;
// Agent-proposed context rules — stellar_rule_create / stellar_rule_create_commit
// (Package D, GH issue #8).
pub(crate) mod rule_create;
