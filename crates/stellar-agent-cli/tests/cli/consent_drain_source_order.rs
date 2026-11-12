//! CLI consumers of an approval acquire the keyed audit writer after they read
//! the approval and before they load the signing key.
//!
//! The acquisition drains consent rows `stellar-agent approve` queued while
//! this process held the writer, so the row is in the log before the key is
//! touched. The mainnet write path orders its steps the same way: the
//! confirmation, then the drain, then the readiness proof, the recorder and
//! the mint, and the signer only after the mint.

#![allow(clippy::panic, clippy::unwrap_used, reason = "source scan assertions")]

use stellar_agent_test_support::source_order::{assert_called_between, production_half};

/// The shared mainnet steps, from the signer choice to the submit.
const MAINNET_WRITE: &str = include_str!("../../src/common/mainnet_write.rs");

#[test]
fn confirm_mainnet_write_has_one_production_caller() {
    use syn::visit::Visit as _;
    #[derive(Default)]
    struct Calls {
        caller: String,
        found: Vec<String>,
    }
    fn test_only(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|attr| {
            let syn::Meta::List(list) = &attr.meta else {
                return false;
            };
            let tokens = list.tokens.to_string();
            list.path.is_ident("cfg") && (tokens == "test" || tokens.starts_with("all (test ,"))
        })
    }
    impl<'ast> syn::visit::Visit<'ast> for Calls {
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            if !test_only(&node.attrs) {
                syn::visit::visit_item_mod(self, node);
            }
        }
        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            if test_only(&node.attrs) {
                return;
            }
            let outer = std::mem::replace(&mut self.caller, node.sig.ident.to_string());
            syn::visit::visit_item_fn(self, node);
            self.caller = outer;
        }
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*node.func
                && path
                    .path
                    .segments
                    .last()
                    .is_some_and(|s| s.ident == "confirm_mainnet_write")
            {
                self.found.push(self.caller.clone());
            }
            syn::visit::visit_expr_call(self, node);
        }
    }
    let mut calls = Calls::default();
    let mut dirs = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let source = std::fs::read_to_string(path).unwrap();
                calls.visit_file(&syn::parse_file(&source).unwrap());
            }
        }
    }
    assert_eq!(calls.found, ["cli_mainnet_authority"]);
}

#[test]
fn the_wrapper_calls_the_ceremony_only_under_require_approval() {
    use syn::visit::Visit as _;
    #[derive(Default)]
    struct Calls {
        ceremonies: usize,
        insertions: usize,
        borrowed_slots: usize,
    }
    fn path_is(expr: &syn::Expr, name: &str) -> bool {
        matches!(expr, syn::Expr::Path(path) if path.path.is_ident(name))
    }
    impl<'ast> syn::visit::Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*node.func {
                if path
                    .path
                    .segments
                    .last()
                    .is_some_and(|s| s.ident == "confirm_mainnet_write")
                {
                    self.ceremonies += 1;
                }
                if path.path.is_ident("Some")
                    && let Some(syn::Expr::Reference(reference)) = node.args.first()
                    && reference.mutability.is_none()
                    && let syn::Expr::Unary(unary) = &*reference.expr
                    && matches!(unary.op, syn::UnOp::Deref(_))
                    && path_is(&unary.expr, "slot")
                {
                    self.borrowed_slots += 1;
                }
            }
            syn::visit::visit_expr_call(self, node);
        }
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if node.method == "insert" && path_is(&node.receiver, "witness") {
                self.insertions += 1;
            }
            syn::visit::visit_expr_method_call(self, node);
        }
    }
    let parsed = syn::parse_file(include_str!("../../src/common/mainnet_confirm.rs")).unwrap();
    let wrapper = parsed
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "cli_mainnet_authority" => {
                Some(function)
            }
            _ => None,
        })
        .unwrap();
    let [syn::Stmt::Expr(syn::Expr::Match(branches), _)] = wrapper.block.stmts.as_slice() else {
        panic!("the wrapper selects authority with one decision match");
    };
    let syn::Expr::MethodCall(selector) = &*branches.expr else {
        panic!("the match reads the governing decision");
    };
    assert!(path_is(&selector.receiver, "decision"));
    assert_eq!(selector.method, "decision");
    assert!(selector.args.is_empty());
    let mut total = 0;
    for arm in &branches.arms {
        let mut calls = Calls::default();
        calls.visit_arm(arm);
        if calls.ceremonies > 0 {
            let syn::Pat::TupleStruct(pattern) = &arm.pat else {
                panic!("only the approval pattern calls the ceremony");
            };
            let segments: Vec<_> = pattern
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            assert_eq!(segments, ["Decision", "RequireApproval"]);
            assert!(matches!(pattern.elems.first(), Some(syn::Pat::Wild(_))));
            assert_eq!(pattern.elems.len(), 1);
            assert!(arm.guard.is_none());
            assert_eq!(calls.insertions, 1);
            assert_eq!(calls.borrowed_slots, 1);
        }
        total += calls.ceremonies;
    }
    assert_eq!(total, 1);
}

/// The verb sources that carry a mainnet pipeline.
const MAINNET_VERBS: &[(&str, &str)] = &[
    ("commands/pay.rs", include_str!("../../src/commands/pay.rs")),
    (
        "commands/claim.rs",
        include_str!("../../src/commands/claim.rs"),
    ),
    (
        "commands/trustline.rs",
        include_str!("../../src/commands/trustline.rs"),
    ),
    (
        "commands/accounts/create.rs",
        include_str!("../../src/commands/accounts/create.rs"),
    ),
];

/// The start of a verb's mainnet pipeline.
const MAINNET_PIPELINE: &str = "async fn run_mainnet_pipeline<";

/// The text of the item starting at `start`, up to the next item at column 0.
fn item<'a>(file: &str, source: &'a str, start: &str) -> &'a str {
    let source = production_half(source);
    let begin = source
        .find(start)
        .unwrap_or_else(|| panic!("{file}: `{start}` not found"));
    let rest = &source[begin..];
    let end = rest
        .find("\n}\n")
        .unwrap_or_else(|| panic!("{file}: `{start}` has no end"));
    &rest[..end + 3]
}

#[test]
fn mpp_charge_authorize_acquires_the_writer_between_the_approval_read_and_the_signer() {
    assert_called_between(
        "commands/mpp.rs",
        include_str!("../../src/commands/mpp.rs"),
        "async fn commit_cli(",
        "verify_pending_approval(",
        "drain_consent_rows_before_signing(",
        "lazy_signer_from_keyring(",
    );
}

/// The trustline reads the clawback opt-in in its gate, which runs after the
/// audit pre-flight and before the signing step, and the signing step drains
/// the outbox after its witness and before the keyring signer loads.
#[test]
fn trustline_acquires_the_writer_between_the_opt_in_read_and_the_signer() {
    const TRUSTLINE: &str = include_str!("../../src/commands/trustline.rs");
    assert!(
        item("commands/trustline.rs", TRUSTLINE, "fn clawback_gate(")
            .contains("verify_attested_trustline_clawback_opt_in("),
        "commands/trustline.rs: the clawback gate reads the opt-in"
    );
    assert_called_between(
        "commands/trustline.rs",
        TRUSTLINE,
        "async fn run_with_dependencies<",
        "require_value_audit_writer(",
        "clawback_gate(",
        "sign_and_submit(",
    );
    assert_called_between(
        "commands/trustline.rs",
        TRUSTLINE,
        "async fn sign_and_submit<",
        "obtain_classic_witness(",
        "drain_consent_rows_before_signing(",
        "enrolled_keyring_signer(",
    );
}

#[test]
fn the_mainnet_confirmation_follows_the_enrolled_proof() {
    assert_called_between(
        "common/mainnet_write.rs",
        MAINNET_WRITE,
        "async fn authorize_and_submit(",
        "enrolled_signer(",
        "cli_mainnet_authority(",
        "drain_consent_rows_before_signing(",
    );
}

#[test]
fn the_mainnet_drain_sits_between_the_confirmation_and_the_readiness_proof() {
    assert_called_between(
        "common/mainnet_write.rs",
        MAINNET_WRITE,
        "async fn authorize_and_submit(",
        "cli_mainnet_authority(",
        "drain_consent_rows_before_signing(",
        "audit_readiness(",
    );
}

#[test]
fn the_mainnet_recorder_is_prepared_between_the_readiness_proof_and_the_mint() {
    assert_called_between(
        "common/mainnet_write.rs",
        MAINNET_WRITE,
        "async fn authorize_and_submit(",
        "audit_readiness(",
        "prepare_mainnet_recorder(",
        "resolve_tx_sign(",
    );
}

#[test]
fn the_mainnet_signer_is_built_between_the_mint_and_the_attach() {
    assert_called_between(
        "common/mainnet_write.rs",
        MAINNET_WRITE,
        "async fn authorize_and_submit(",
        "resolve_tx_sign(",
        "mainnet_signer(",
        "attach_signature_authorized(",
    );
}

#[test]
fn each_mainnet_pipeline_reconciles_after_its_probe_and_before_its_policy() {
    for (file, source) in MAINNET_VERBS {
        // The claim probe is its endpoint check, which precedes the record
        // lookup and the envelope build.
        let after = if *file == "commands/claim.rs" {
            "check_claim_endpoint("
        } else {
            "check_endpoint_identity("
        };
        assert_called_between(
            file,
            source,
            MAINNET_PIPELINE,
            after,
            "reconcile_open_reservations(",
            "load_mainnet_policy_engine(",
        );
    }
}

#[test]
fn each_mainnet_pipeline_checks_the_audit_writer_between_the_fee_cap_and_the_witness() {
    for (file, source) in MAINNET_VERBS {
        assert_called_between(
            file,
            source,
            MAINNET_PIPELINE,
            "check_classic_fee_cap_signed(",
            "require_value_audit_writer",
            "obtain_classic_witness_bound(",
        );
    }
}

#[test]
fn no_mainnet_step_builds_a_context_from_the_profile() {
    for (file, source) in MAINNET_VERBS {
        let pipeline = item(file, source, MAINNET_PIPELINE);
        assert!(
            !pipeline.contains("NetworkContext::from_profile("),
            "{file}: the mainnet pipeline takes its context from the write context"
        );
    }
    assert!(
        !production_half(MAINNET_WRITE).contains("NetworkContext::from_profile("),
        "common/mainnet_write.rs: the shared steps take their context from the write context"
    );
}

#[test]
fn no_mainnet_step_records_a_confirmed_window_entry_itself() {
    assert!(
        !production_half(MAINNET_WRITE).contains("record_confirmed("),
        "common/mainnet_write.rs: the window entries settle through the recorder"
    );
    let recorder = item(
        "commands/submission_record.rs",
        include_str!("../../src/commands/submission_record.rs"),
        "pub(crate) fn prepare_mainnet_recorder<",
    );
    assert!(
        !recorder.contains("record_confirmed("),
        "commands/submission_record.rs: the recorder's entries come from the authorization"
    );
}
