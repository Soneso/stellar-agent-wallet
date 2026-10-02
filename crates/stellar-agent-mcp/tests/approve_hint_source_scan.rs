//! Agent-facing approve commands always name their profile.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "source scan assertions"
)]
use std::path::Path;

fn scan(dir: &Path, root: &Path) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            scan(&path, root);
            continue;
        }
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\r\n", "\n");
        for (index, line) in source.lines().enumerate() {
            let line = line.trim_start();
            if line.starts_with("//") || !line.contains("approve --id") {
                continue;
            }
            // Static tool descriptions cannot interpolate a server profile.
            let static_placeholder = relative == "stellar-agent-mcp/src/tools/rule_create.rs"
                && line.contains("--profile <profile>");
            // Production never constructs this error variant.
            let unused_runtime_variant = relative == "stellar-agent-toolsets-runtime/src/error.rs"
                && line.contains("(approval_nonce={approval_nonce}; run `stellar-agent approve --id {approval_nonce}`");
            assert!(
                line.contains("approve_hint") || static_placeholder || unused_runtime_variant,
                "unscoped approve hint at {relative}:{}: {line}",
                index + 1
            );
        }
    }
}

#[test]
fn agent_approve_hints_name_the_profile() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    scan(&root.join("stellar-agent-mcp/src"), root);
    scan(&root.join("stellar-agent-toolsets-runtime/src"), root);
}
