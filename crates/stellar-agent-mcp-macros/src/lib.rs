//! Wallet-owned proc-macro crate for the Stellar agent MCP tool registry.
//!
//! Exports the `#[mcp_tool_router]` attribute macro, which is applied to the
//! same `impl` block as rmcp's `#[tool_router]`.  The macro scans the impl
//! block for fns carrying `#[mcp_tool_item(...)]` annotations, strips those
//! annotations (so the Rust compiler does not see unknown attributes), and
//! emits `inventory::submit!{ McpToolRegistration { ... } }` items at module
//! scope (outside the impl block), where `inventory`'s linker-section trick
//! can collect them.
//!
//! # Attribute syntax
//!
//! ```rust,ignore
//! #[mcp_tool_router]    // scans the impl block, emits inventory::submit!
//! #[tool_router]        // rmcp's attribute — processes #[tool] fns
//! impl WalletServer {
//!     #[mcp_tool_item(
//!         name = "stellar_balances",
//!         destructive_hint = false,
//!         read_only_hint = true,
//!         chain_id_required = true
//!     )]
//!     #[tool(name = "stellar_balances", ...)]
//!     async fn stellar_balances(&self, ...) { ... }
//! }
//! ```
//!
//! # Design rationale
//!
//! rmcp's `#[tool]` rewrites async fn signatures (`async fn` →
//! `Pin<Box<Future>>`).  Our `#[mcp_tool_item]` annotations co-exist with
//! rmcp's machinery without conflict: Rust expands stacked attribute macros
//! OUTERMOST-FIRST, so `#[mcp_tool_router]` (placed outermost, above rmcp's
//! `#[tool_router]`) runs FIRST and observes each fn's `#[tool(...)]` and
//! `#[mcp_tool_item(...)]` markers BEFORE rmcp's fn-level `#[tool]` macro (an
//! independent attribute macro) consumes them.  It walks the `fn` items, parses
//! each `#[mcp_tool_item(...)]` annotation, strips the marker so the compiler
//! does not see an unknown attribute, and emits an `inventory::submit!` registry
//! entry per stripped marker.  It then re-emits the impl block, after which
//! `#[tool_router]` and the per-fn `#[tool]` macros expand.  This ordering is
//! load-bearing: the missing-`#[mcp_tool_item]` guard is reachable only because
//! the `#[tool]` markers are still present when `#[mcp_tool_router]` walks the
//! impl, so `#[mcp_tool_router]` MUST stay outermost.
//!
//! `inventory::submit!` expands to a `const _: () = { ... }` item containing a
//! link-section constructor that registers the value at load time.  This is
//! valid at module scope, which is why the macro emits the submit items OUTSIDE
//! the impl block in the returned TokenStream.
//!
//! The "by construction" property: deleting the fn deletes both `#[tool]` and
//! `#[mcp_tool_item]` simultaneously, which removes the rmcp-router entry and
//! the registry submission together.
//!
//! # Registry type location
//!
//! `McpToolRegistration` lives in `stellar_agent_core::policy`.  Proc-macro
//! crates cannot export non-macro items; the emitted code references
//! `stellar_agent_core::policy::McpToolRegistration` by its full path.
//!
//! # Trust boundary
//!
//! This crate is compile-time host-privileged code (same class as `build.rs`).
//! Invariants strictly enforced:
//!
//! - No `unsafe` (blocked at the crate level via `#![forbid(unsafe_code)]`).
//! - No env-var reads.
//! - No filesystem reads.
//! - No network access.
//! - No `#[link]` attributes.
//! - No `extern "C"` declarations.
//!
//! # Primary consumer
//!
//! The wallet MCP server's tool-router impl block: every tool fn carries both
//! rmcp's `#[tool(...)]` and a sibling `#[mcp_tool_item(...)]` registration.

#![forbid(unsafe_code)]

extern crate proc_macro;

use darling::{FromMeta, ast::NestedMeta};
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{ImplItem, ItemImpl, parse_macro_input};

mod args;

use args::McpToolItemArgs;

// ─────────────────────────────────────────────────────────────────────────────
// #[mcp_tool_router] — impl-block level attribute
// ─────────────────────────────────────────────────────────────────────────────

/// Scans an `impl` block for `#[mcp_tool_item(...)]`-annotated fns and emits
/// `inventory::submit!{ McpToolRegistration { ... } }` items at module scope.
///
/// Apply this attribute on the **same `impl` block** as rmcp's `#[tool_router]`.
/// Each tool fn inside the block carries `#[mcp_tool_item(...)]` to declare its
/// registration metadata.  This attribute strips the `#[mcp_tool_item]`
/// annotations (preventing "unknown attribute" compiler errors) and emits the
/// registry submissions outside the impl block where `inventory` can collect them.
///
/// # Usage
///
/// ```rust,ignore
/// #[mcp_tool_router]
/// #[tool_router]
/// impl WalletServer {
///     #[mcp_tool_item(
///         name = "stellar_balances",
///         destructive_hint = false,
///         read_only_hint = true,
///         chain_id_required = true
///     )]
///     #[tool(name = "stellar_balances", description = "...",
///            annotations(read_only_hint = true, destructive_hint = false))]
///     async fn stellar_balances(&self, ...) -> Result<...> { ... }
/// }
/// ```
///
/// # Emitted code (per annotated fn)
///
/// ```text
/// ::inventory::submit! {
///     ::stellar_agent_core::policy::McpToolRegistration {
///         name: "stellar_balances",
///         destructive_hint: false,
///         read_only_hint: true,
///         chain_id_required: true,
///     }
/// }
/// ```
///
/// These items are emitted at module scope (outside the impl block), where
/// `inventory`'s linker-section trick can register them.
///
/// # Trust boundary
///
/// Compile-time host-privileged code.  Reads only attribute arguments; no env
/// vars, no filesystem, no network.
///
/// # Errors
///
/// Emits a `compile_error!` (via `syn::Error::to_compile_error`) when:
/// - The annotated item is not a `syn::ItemImpl` (e.g., applied to a `fn`
///   or `struct`) — the parse fails before `expand_mcp_tool_router` is called.
/// - A `#[mcp_tool_item(...)]` attribute on a fn inside the impl is malformed:
///   wrong argument type, missing required field (`name`, `destructive_hint`,
///   `read_only_hint`, or `chain_id_required`), or non-literal value where a
///   string or bool literal is required.
/// - A fn carries more than one `#[mcp_tool_item(...)]` attribute (the binding-integrity
///   guarantee: each tool fn must have a single registration annotation).
/// - A fn carries rmcp's `#[tool(...)]` attribute but lacks the sibling
///   `#[mcp_tool_item(...)]` registration annotation.
/// - A fn carries `#[mcp_tool_item(...)]` but lacks rmcp's `#[tool(...)]` (a
///   registry entry must correspond to an actual MCP tool).
///
/// # Panics
///
/// This macro never panics; all error paths route through `syn::Error` and
/// `compile_error!`.
#[proc_macro_attribute]
pub fn mcp_tool_router(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut impl_block = parse_macro_input!(item as ItemImpl);

    match expand_mcp_tool_router(&mut impl_block) {
        Ok(ts) => ts.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Scans the impl block for `#[mcp_tool_item(...)]` attributes, strips them,
/// and emits `inventory::submit!` items at module scope.
///
/// # Errors
///
/// Returns a `syn::Error` (which becomes a `compile_error!`) when:
/// - The annotated item is not a `syn::ItemImpl` (handled by the caller).
/// - A fn carries more than one `#[mcp_tool_item(...)]` attribute (the
///   binding-integrity guarantee: silently using the last annotation would allow
///   one annotation to shadow another with different values).
/// - A fn carries rmcp's `#[tool(...)]` attribute but lacks the sibling
///   `#[mcp_tool_item(...)]` registration annotation.
/// - A fn carries `#[mcp_tool_item(...)]` but lacks rmcp's `#[tool(...)]` (a
///   registry entry must correspond to an actual MCP tool).
/// - A `#[mcp_tool_item(...)]` attribute is malformed (wrong arg type, missing
///   required field, non-bool literal for bool fields, etc.).
fn expand_mcp_tool_router(impl_block: &mut ItemImpl) -> syn::Result<TokenStream2> {
    let mut submit_items: Vec<TokenStream2> = Vec::new();

    for item in &mut impl_block.items {
        if let ImplItem::Fn(fn_item) = item {
            // Collect indices of #[mcp_tool_item] attrs on this fn.
            let mut tool_item_indices = Vec::new();
            let mut parsed_args: Vec<McpToolItemArgs> = Vec::new();
            let mut has_rmcp_tool_attr = false;

            for (idx, attr) in fn_item.attrs.iter().enumerate() {
                let path = attr.path();
                if path.segments.last().is_some_and(|seg| seg.ident == "tool") {
                    has_rmcp_tool_attr = true;
                }
                let is_mcp_tool_item = path
                    .segments
                    .last()
                    .is_some_and(|seg| seg.ident == "mcp_tool_item");
                if is_mcp_tool_item {
                    tool_item_indices.push(idx);
                    // Parse the attribute arguments.
                    let attr_args =
                        NestedMeta::parse_meta_list(attr.meta.require_list()?.tokens.clone())?;
                    parsed_args.push(McpToolItemArgs::from_list(&attr_args)?);
                }
            }

            // More than one #[mcp_tool_item] on the same fn is a compile error.
            // Silently using the last annotation would allow one annotation to
            // shadow another with different values.
            if tool_item_indices.len() > 1 {
                return Err(syn::Error::new_spanned(
                    &fn_item.sig.ident,
                    "fn carries more than one #[mcp_tool_item(...)] attribute; \
                     expected at most one (each tool fn must have a single registration annotation)",
                ));
            }

            if has_rmcp_tool_attr && tool_item_indices.is_empty() {
                return Err(syn::Error::new_spanned(
                    &fn_item.sig.ident,
                    "fn carries #[tool(...)] but is missing #[mcp_tool_item(...)]; \
                     each rmcp tool fn must declare wallet registry metadata",
                ));
            }

            // The reverse direction: a #[mcp_tool_item] with no sibling #[tool]
            // would emit a registry record for a tool rmcp never dispatches.
            // Reject it so the registry can never advertise a phantom tool.
            if !has_rmcp_tool_attr && !tool_item_indices.is_empty() {
                return Err(syn::Error::new_spanned(
                    &fn_item.sig.ident,
                    "fn carries #[mcp_tool_item(...)] but is missing rmcp's #[tool(...)]; \
                     a registry entry must correspond to an actual MCP tool",
                ));
            }

            // Strip the #[mcp_tool_item] attrs so the Rust compiler doesn't
            // see unknown attributes.
            // Remove in reverse order so indices stay valid.
            for idx in tool_item_indices.into_iter().rev() {
                fn_item.attrs.remove(idx);
            }

            // Emit a submit! item for the single found annotation (if any).
            if let Some(args) = parsed_args.into_iter().next() {
                let McpToolItemArgs {
                    name,
                    destructive_hint,
                    read_only_hint,
                    chain_id_required,
                } = args;

                submit_items.push(quote! {
                    ::inventory::submit! {
                        ::stellar_agent_core::policy::McpToolRegistration {
                            name: #name,
                            destructive_hint: #destructive_hint,
                            read_only_hint: #read_only_hint,
                            chain_id_required: #chain_id_required,
                        }
                    }
                });
            }
        }
    }

    // Emit: impl block (with #[mcp_tool_item] attrs stripped) + submit! items.
    Ok(quote! {
        #impl_block
        #(#submit_items)*
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests for expand_mcp_tool_router
// ─────────────────────────────────────────────────────────────────────────────
//
// Design choice: the tests live in a `#[cfg(test)] mod tests` block at the
// bottom of this file rather than in a separate `tests/` directory.
// `expand_mcp_tool_router` is a private function; placing the tests in the
// same file gives access via `super::expand_mcp_tool_router` without requiring
// a `pub(crate)` re-export.  This avoids exposing the function in the
// production API surface.
//
// These tests cover:
//   (a) zero `#[mcp_tool_item]` attrs → Ok; submit_items count == 0.
//   (b) one  `#[mcp_tool_item]` attr  → Ok; submit_items count == 1;
//       the annotation is stripped from the impl block output.
//   (c) two  `#[mcp_tool_item]` attrs on the same fn → Err with the
//       expected message substring (the binding-integrity guarantee).
//   (d) malformed `#[mcp_tool_item]` (missing required field) → Err.
//   (e) multiple fns: two annotated fns → two submit! items.
//   (f) `#[tool]` without `#[mcp_tool_item]` → Err (binding-integrity check).
//   (g) emitted submit! contains the correct field values.
#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use syn::parse_quote;

    // Helper: count the number of `::inventory::submit!` calls in the expanded
    // token stream.  Counts the literal token sequence `inventory :: submit !`
    // (with the spacing produced by `proc-macro2::TokenStream::to_string`),
    // which is unique to the macro invocation and cannot occur in any field or
    // method identifier (the `::` and `!` punctuation rules out collisions with
    // identifiers like `submit_handler`, `submit_items`, etc.).
    fn count_submit_items(ts: &TokenStream2) -> usize {
        ts.to_string().matches("inventory :: submit !").count()
    }

    /// (a) An impl block with no `#[mcp_tool_item]` annotations produces an `Ok`
    /// result with zero `inventory::submit!` items emitted.
    #[test]
    fn zero_mcp_tool_items_produces_empty_submit_list() {
        let mut impl_block: ItemImpl = parse_quote! {
            impl Dummy {
                fn not_a_tool(&self) {}
            }
        };
        let result = expand_mcp_tool_router(&mut impl_block);
        assert!(
            result.is_ok(),
            "expected Ok for impl block with no #[mcp_tool_item]"
        );
        assert_eq!(
            count_submit_items(&result.unwrap()),
            0,
            "expected zero inventory::submit! items when no fns carry #[mcp_tool_item]"
        );
    }

    /// (b) A single `#[mcp_tool_item]` annotation on one fn produces exactly one
    /// `inventory::submit!` item in the expanded output, and the annotation is
    /// stripped from the impl block.
    #[test]
    fn one_mcp_tool_item_produces_one_submit_item() {
        let mut impl_block: ItemImpl = parse_quote! {
            impl Dummy {
                #[mcp_tool_item(
                    name = "stellar_balances",
                    destructive_hint = false,
                    read_only_hint = true,
                    chain_id_required = true
                )]
                #[tool(name = "stellar_balances")]
                fn stellar_balances(&self) {}
            }
        };
        let result = expand_mcp_tool_router(&mut impl_block);
        assert!(
            result.is_ok(),
            "expected Ok for a single valid #[mcp_tool_item]"
        );
        let expanded = result.unwrap();
        assert_eq!(
            count_submit_items(&expanded),
            1,
            "expected exactly one inventory::submit! item for one #[mcp_tool_item] fn"
        );
        // The stripped impl block must no longer contain `mcp_tool_item`.
        assert!(
            !expanded.to_string().contains("mcp_tool_item"),
            "expand_mcp_tool_router must strip #[mcp_tool_item] from the impl block"
        );
    }

    /// (c) Two `#[mcp_tool_item]` annotations on the same fn must produce an `Err`
    /// containing the expected message substring (binding-integrity guarantee).
    ///
    /// Fail-closed contract: silently using the last annotation would allow one
    /// annotation to shadow another with different `destructive_hint` values.
    #[test]
    fn two_mcp_tool_items_on_same_fn_returns_err() {
        let mut impl_block: ItemImpl = parse_quote! {
            impl Dummy {
                #[mcp_tool_item(
                    name = "stellar_pay",
                    destructive_hint = true,
                    read_only_hint = false,
                    chain_id_required = true
                )]
                #[mcp_tool_item(
                    name = "stellar_pay",
                    destructive_hint = false,
                    read_only_hint = false,
                    chain_id_required = false
                )]
                fn stellar_pay(&self) {}
            }
        };
        let result = expand_mcp_tool_router(&mut impl_block);
        assert!(
            result.is_err(),
            "expected Err when a fn carries more than one #[mcp_tool_item] attribute"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("more than one #[mcp_tool_item(...)]"),
            "error message must mention 'more than one #[mcp_tool_item(...)]'; got: {err_msg}"
        );
    }

    /// (d) A malformed `#[mcp_tool_item]` missing a required field produces an
    /// `Err` from darling's `FromMeta` parsing.
    #[test]
    fn malformed_mcp_tool_item_missing_field_returns_err() {
        let mut impl_block: ItemImpl = parse_quote! {
            impl Dummy {
                // Missing `chain_id_required` — darling must reject this.
                #[mcp_tool_item(
                    name = "stellar_pay",
                    destructive_hint = true,
                    read_only_hint = false
                )]
                fn stellar_pay(&self) {}
            }
        };
        let result = expand_mcp_tool_router(&mut impl_block);
        assert!(
            result.is_err(),
            "expected Err when #[mcp_tool_item] is missing required field chain_id_required"
        );
    }

    /// (e) Two separately-annotated fns each produce one submit! item (total: 2).
    #[test]
    fn two_annotated_fns_produce_two_submit_items() {
        let mut impl_block: ItemImpl = parse_quote! {
            impl Dummy {
                #[mcp_tool_item(
                    name = "stellar_balances",
                    destructive_hint = false,
                    read_only_hint = true,
                    chain_id_required = true
                )]
                #[tool(name = "stellar_balances")]
                fn stellar_balances(&self) {}

                #[mcp_tool_item(
                    name = "stellar_pay",
                    destructive_hint = true,
                    read_only_hint = false,
                    chain_id_required = true
                )]
                #[tool(name = "stellar_pay")]
                fn stellar_pay(&self) {}
            }
        };
        let result = expand_mcp_tool_router(&mut impl_block);
        assert!(
            result.is_ok(),
            "expected Ok for two valid #[mcp_tool_item] fns"
        );
        assert_eq!(
            count_submit_items(&result.unwrap()),
            2,
            "expected exactly two inventory::submit! items for two annotated fns"
        );
    }

    /// (f) A fn carrying `#[tool(...)]` but missing `#[mcp_tool_item(...)]`
    /// produces an `Err` (binding-integrity check).
    #[test]
    fn tool_attr_without_mcp_tool_item_returns_err() {
        let mut impl_block: ItemImpl = parse_quote! {
            impl Dummy {
                #[tool(name = "stellar_pay")]
                fn stellar_pay(&self) {}
            }
        };
        let result = expand_mcp_tool_router(&mut impl_block);
        assert!(
            result.is_err(),
            "expected Err when #[tool] is present without #[mcp_tool_item]"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("missing #[mcp_tool_item"),
            "error message must mention missing #[mcp_tool_item]; got: {err_msg}"
        );
    }

    /// (g) The emitted submit! item contains the correct field values from the
    /// `#[mcp_tool_item(...)]` annotation.
    #[test]
    fn emitted_submit_item_contains_correct_field_values() {
        let mut impl_block: ItemImpl = parse_quote! {
            impl Dummy {
                #[mcp_tool_item(
                    name = "stellar_pay",
                    destructive_hint = true,
                    read_only_hint = false,
                    chain_id_required = true
                )]
                #[tool(name = "stellar_pay")]
                fn stellar_pay(&self) {}
            }
        };
        let expanded = expand_mcp_tool_router(&mut impl_block)
            .expect("expected Ok for a single valid #[mcp_tool_item]");
        let ts_str = expanded.to_string();
        // The emitted submit! must reference the correct name and bool values.
        // Match the registration field form `name : "stellar_pay"`, NOT the bare
        // identifier (the preserved impl block still contains `fn stellar_pay`),
        // so a wrong or omitted name in the submit! item is caught.
        assert!(
            ts_str.contains("name : \"stellar_pay\""),
            "emitted submit! item must contain name : \"stellar_pay\""
        );
        assert!(
            ts_str.contains("destructive_hint : true"),
            "emitted TokenStream must contain destructive_hint : true"
        );
        assert!(
            ts_str.contains("read_only_hint : false"),
            "emitted TokenStream must contain read_only_hint : false"
        );
        assert!(
            ts_str.contains("chain_id_required : true"),
            "emitted TokenStream must contain chain_id_required : true"
        );
        assert!(
            ts_str.contains("McpToolRegistration"),
            "emitted TokenStream must reference McpToolRegistration"
        );
    }

    /// (h) The strip removes ONLY `#[mcp_tool_item]` and preserves every other
    /// attribute on the fn — notably rmcp's `#[tool]` (which wires the router)
    /// and any `#[doc]`.  A regression that removed the wrong index would
    /// silently break the rmcp wiring, so this asserts the exact surviving set.
    #[test]
    fn strip_preserves_sibling_attributes() {
        let mut impl_block: ItemImpl = parse_quote! {
            impl Dummy {
                // #[mcp_tool_item] is deliberately NOT the first attribute, so
                // the reverse-order strip is exercised at a non-zero index.
                #[tool(name = "stellar_pay")]
                #[mcp_tool_item(
                    name = "stellar_pay",
                    destructive_hint = true,
                    read_only_hint = false,
                    chain_id_required = true
                )]
                #[doc = "keep me"]
                fn stellar_pay(&self) {}
            }
        };
        expand_mcp_tool_router(&mut impl_block)
            .expect("expected Ok for a fn carrying #[tool] + #[mcp_tool_item]");
        // expand_mcp_tool_router strips in place; inspect the mutated fn.
        let ImplItem::Fn(fn_item) = &impl_block.items[0] else {
            panic!("expected a fn item");
        };
        assert_eq!(
            fn_item.attrs.len(),
            2,
            "strip must remove only #[mcp_tool_item], leaving #[tool] and #[doc]"
        );
        assert!(
            fn_item.attrs.iter().any(|a| a.path().is_ident("tool")),
            "the sibling #[tool] attribute must survive the strip"
        );
        assert!(
            fn_item.attrs.iter().any(|a| a.path().is_ident("doc")),
            "the sibling #[doc] attribute must survive the strip"
        );
        assert!(
            !fn_item
                .attrs
                .iter()
                .any(|a| a.path().is_ident("mcp_tool_item")),
            "the #[mcp_tool_item] attribute must be stripped"
        );
    }

    /// (i) A fn carrying `#[mcp_tool_item(...)]` with no sibling `#[tool(...)]`
    /// produces an `Err`: a registry entry must correspond to a real MCP tool,
    /// so an orphan annotation can never emit a phantom registration.
    #[test]
    fn mcp_tool_item_without_tool_returns_err() {
        let mut impl_block: ItemImpl = parse_quote! {
            impl Dummy {
                #[mcp_tool_item(
                    name = "stellar_pay",
                    destructive_hint = true,
                    read_only_hint = false,
                    chain_id_required = true
                )]
                fn stellar_pay(&self) {}
            }
        };
        let result = expand_mcp_tool_router(&mut impl_block);
        assert!(
            result.is_err(),
            "expected Err when #[mcp_tool_item] is present without #[tool]"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("missing rmcp's #[tool"),
            "error message must mention the missing #[tool]; got: {err_msg}"
        );
    }
}
