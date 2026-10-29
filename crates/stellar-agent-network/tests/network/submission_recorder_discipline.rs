//! Literal recorder omissions at the submission seam and its forwarding sites.
//!
//! The scan checks Rust expressions before each file's first test-module
//! boundary. It checks literal omissions and forwarding syntax, not the runtime
//! value of an Option or the reachability of a call.
//!
//! A file that builds a submit-capable DeFi context owes one recorder
//! attachment per construction, so a new submitting tool that names no
//! recorder at all fails the scan rather than passing unnoticed.
//!
//! The four MCP classic commit tools submit through one shared helper. Each
//! tool's file owes exactly one call to that helper, and the helper's file is
//! a covered source whose seam calls carry the recorders.

#![allow(clippy::expect_used, clippy::panic, reason = "source-scan assertions")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, Member};

/// Each allowance states its scope and pins its number of literal omissions.
const ALLOWED_NONE: &[(&str, usize, &str)] = &[
    (
        "crates/stellar-agent-smart-account/src/deployment/deploy.rs",
        2,
        "Account deployment is fee-only with no value legs.",
    ),
    (
        "crates/stellar-agent-smart-account/src/deployment/deploy_ed25519_verifier.rs",
        2,
        "Verifier deployment is fee-only with no value legs.",
    ),
    (
        "crates/stellar-agent-smart-account/src/deployment/deploy_policy.rs",
        2,
        "Policy deployment is fee-only with no value legs.",
    ),
    (
        "crates/stellar-agent-smart-account/src/deployment/deploy_spending_limit_policy.rs",
        2,
        "Spending-limit policy deployment is fee-only with no value legs.",
    ),
    (
        "crates/stellar-agent-smart-account/src/deployment/deploy_timelock_controller.rs",
        2,
        "Controller deployment is fee-only with no value legs.",
    ),
    (
        "crates/stellar-agent-smart-account/src/deployment/deploy_webauthn_verifier.rs",
        2,
        "Verifier deployment is fee-only with no value legs.",
    ),
    (
        "crates/stellar-agent-defi/src/adapter.rs",
        2,
        "Context constructors leave recorder attachment to the submitting caller.",
    ),
    (
        "crates/stellar-agent-smart-account/src/timelock.rs",
        2,
        "Schedule and cancel change scheduling state; execute forwards its recorder.",
    ),
];

/// The callee names of the submission seam: the submit layer's own entry
/// point, and the injected submission step of the trustline verb, which
/// production fills with that entry point and which takes the same six
/// arguments. The recorder is the last argument.
const SEAM_CALLEES: &[&str] = &["submit_transaction_and_wait", "submit_and_wait"];

/// The authorized submission seam: nine arguments, the recorder at index 6.
/// Its recorder parameter is a reference, so a call always names one.
const AUTHORIZED_SEAM: (&str, usize, usize) = ("submit_authorized_transaction_and_wait", 9, 6);

/// Files that submit through a shared helper instead of calling the seam,
/// with the helper's callee name and the number of production calls each
/// file owes it. The helper's own file is listed in [`REQUIRED_FILES`].
const DELEGATED_FILES: &[(&str, &str, usize)] = &[
    (
        "crates/stellar-agent-mcp/src/tools/pay.rs",
        "sign_and_submit_classic",
        1,
    ),
    (
        "crates/stellar-agent-mcp/src/tools/claim.rs",
        "sign_and_submit_classic",
        1,
    ),
    (
        "crates/stellar-agent-mcp/src/tools/trustline.rs",
        "sign_and_submit_classic",
        1,
    ),
    (
        "crates/stellar-agent-mcp/src/tools/create_account.rs",
        "sign_and_submit_classic",
        1,
    ),
];

const REQUIRED_FILES: &[&str] = &[
    "crates/stellar-agent-pool/src/init.rs",
    "crates/stellar-agent-pool/src/submit.rs",
    "crates/stellar-agent-cli/src/commands/pay.rs",
    "crates/stellar-agent-cli/src/commands/claim.rs",
    "crates/stellar-agent-cli/src/commands/trustline.rs",
    "crates/stellar-agent-cli/src/commands/accounts/create.rs",
    "crates/stellar-agent-cli/src/commands/trade.rs",
    "crates/stellar-agent-cli/src/commands/vault.rs",
    "crates/stellar-agent-cli/src/commands/smart_account/execute.rs",
    "crates/stellar-agent-cli/src/commands/smart_account/timelock/execute.rs",
    "crates/stellar-agent-mcp/src/tools/submission_record.rs",
    "crates/stellar-agent-mcp/src/tools/dex_trade.rs",
    "crates/stellar-agent-mcp/src/tools/vault.rs",
    "crates/stellar-agent-mcp/src/tools/sep43_sign_and_submit_transaction.rs",
    "crates/stellar-agent-smart-account/src/submit.rs",
    "crates/stellar-agent-smart-account/src/timelock.rs",
    "crates/stellar-agent-smart-account/src/timelock_submit.rs",
    "crates/stellar-agent-smart-account/src/multicall.rs",
    "crates/stellar-agent-defi/src/adapter.rs",
    "crates/stellar-agent-dex/src/adapter.rs",
    "crates/stellar-agent-defindex/src/adapter.rs",
];

fn workspace_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if std::fs::read_to_string(path.join("Cargo.toml"))
            .is_ok_and(|text| text.lines().any(|line| line.trim() == "[workspace]"))
        {
            return path;
        }
        assert!(path.pop(), "workspace Cargo.toml must exist");
    }
}

fn rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(path).expect("source directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn literal_none(expr: &Expr) -> bool {
    match expr {
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "None"),
        Expr::Paren(paren) => literal_none(&paren.expr),
        Expr::Group(group) => literal_none(&group.expr),
        _ => false,
    }
}

fn recorder_member(member: &Member) -> bool {
    matches!(member, Member::Named(name) if name == "submission_recorder")
}

struct Site {
    line: usize,
    none: bool,
}

struct RecorderSites {
    test_boundary: usize,
    sites: Vec<Site>,
    /// Calls building a DeFi context that carries submit capability. Each one
    /// owes a recorder attachment in the same file.
    submit_contexts: usize,
    /// Production calls per callee name of [`DELEGATED_FILES`].
    delegations: BTreeMap<String, usize>,
}

impl RecorderSites {
    fn record(&mut self, span: proc_macro2::Span, value: &Expr) {
        let line = span.start().line;
        if line < self.test_boundary {
            self.sites.push(Site {
                line,
                none: literal_none(value),
            });
        }
    }
}

impl<'ast> Visit<'ast> for RecorderSites {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(function) = call.func.as_ref()
            && let Some(name) = function.path.segments.last()
            && call.span().start().line < self.test_boundary
        {
            if SEAM_CALLEES.iter().any(|seam| name.ident == seam) {
                assert_eq!(
                    call.args.len(),
                    6,
                    "submission seam argument shape at line {}",
                    call.span().start().line
                );
                self.record(call.span(), call.args.last().expect("recorder argument"));
            } else if name.ident == AUTHORIZED_SEAM.0 {
                assert_eq!(
                    call.args.len(),
                    AUTHORIZED_SEAM.1,
                    "authorized submission seam argument shape at line {}",
                    call.span().start().line
                );
                self.record(
                    call.span(),
                    call.args
                        .iter()
                        .nth(AUTHORIZED_SEAM.2)
                        .expect("recorder argument"),
                );
            } else if name.ident == "new_with_submit_ctx" {
                self.submit_contexts += 1;
            } else if DELEGATED_FILES
                .iter()
                .any(|(_, helper, _)| name.ident == helper)
            {
                *self.delegations.entry(name.ident.to_string()).or_default() += 1;
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
        if let Expr::Field(field) = assign.left.as_ref()
            && recorder_member(&field.member)
        {
            self.record(assign.span(), &assign.right);
        }
        visit::visit_expr_assign(self, assign);
    }

    fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
        if recorder_member(&field.member) {
            self.record(field.span(), &field.expr);
        }
        visit::visit_field_value(self, field);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        // The optional setter is generated by the args builder; both forms
        // attach a recorder.
        if call.method == "submission_recorder" || call.method == "maybe_submission_recorder" {
            assert_eq!(call.args.len(), 1, "recorder setter argument shape");
            self.record(
                call.span(),
                call.args.first().expect("recorder setter value"),
            );
        }
        visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn every_value_submission_carries_a_recorder() {
    let root = workspace_root();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root.join("crates")).expect("workspace crates") {
        let src = entry.expect("crate entry").path().join("src");
        if src.is_dir() {
            rust_files(&src, &mut files);
        }
    }
    files.sort();
    let mut found = BTreeMap::new();
    let mut delegated = std::collections::BTreeSet::new();
    let mut violations = Vec::new();
    for path in files {
        let source = std::fs::read_to_string(&path).expect("Rust source");
        let syntax =
            syn::parse_file(&source).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        // Test-only imports can precede production functions; the test module
        // marks the boundary of the production half.
        let test_boundary = syntax
            .items
            .iter()
            .find_map(|item| {
                let syn::Item::Mod(module) = item else {
                    return None;
                };
                module
                    .attrs
                    .iter()
                    .any(|attribute| {
                        attribute.path().is_ident("cfg")
                            && attribute
                                .parse_args::<syn::Path>()
                                .is_ok_and(|path| path.is_ident("test"))
                    })
                    .then(|| module.span().start().line)
            })
            .unwrap_or(usize::MAX);
        let mut scan = RecorderSites {
            test_boundary,
            sites: Vec::new(),
            submit_contexts: 0,
            delegations: BTreeMap::new(),
        };
        scan.visit_file(&syntax);
        let relative = path
            .strip_prefix(&root)
            .expect("workspace source")
            .to_string_lossy()
            .replace('\\', "/");
        if let Some((_, helper, expected)) = DELEGATED_FILES
            .iter()
            .find(|(file, _, _)| *file == relative)
        {
            let calls = scan.delegations.get(*helper).copied().unwrap_or(0);
            if calls != *expected {
                violations.push(format!(
                    "{relative}: expects {expected} production call(s) to `{helper}`, found {calls}"
                ));
            }
            delegated.insert(relative.clone());
        }
        if scan.sites.is_empty() && scan.submit_contexts == 0 {
            continue;
        }
        if !ALLOWED_NONE
            .iter()
            .any(|(allowed, _, _)| *allowed == relative)
        {
            for site in &scan.sites {
                if site.none {
                    violations.push(format!(
                        "{relative}:{}: submission recorder is literal None",
                        site.line
                    ));
                }
            }
        }
        let attached = scan.sites.iter().filter(|site| !site.none).count();
        if attached < scan.submit_contexts {
            violations.push(format!(
                "{relative}: {} submit-capable DeFi context(s) built, {attached} recorder \
                 attachment(s) present",
                scan.submit_contexts
            ));
        }
        found.insert(relative, scan.sites);
    }
    for (file, expected, reason) in ALLOWED_NONE {
        assert!(!reason.is_empty(), "allowance must explain {file}");
        let count = found
            .get(*file)
            .map_or(0, |sites| sites.iter().filter(|site| site.none).count());
        if count != *expected {
            violations.push(format!("{file}: allowance expects {expected} literal None recorder(s), found {count}; {reason}"));
        }
    }
    for file in REQUIRED_FILES {
        if !found.contains_key(*file) {
            violations.push(format!("missing covered source: {file}"));
        }
    }
    for (file, _, _) in DELEGATED_FILES {
        if !delegated.contains(*file) {
            violations.push(format!("missing delegating source: {file}"));
        }
    }
    assert!(
        violations.is_empty(),
        "submission recorder omissions:\n{}",
        violations.join("\n")
    );
    let count: usize = found.values().map(Vec::len).sum();
    assert!(
        count >= 40,
        "expected at least 40 submission/recorder sites, found {count}"
    );
}
