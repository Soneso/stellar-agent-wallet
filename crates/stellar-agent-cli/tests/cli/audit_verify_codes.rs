//! Audit verification exposes the verifier code in the binary envelope.

use std::process::Command;
use stellar_agent_core::audit_log::{
    entry::{AuditEntry, NewToolInvocation},
    schema::PolicyDecision,
    writer::AuditWriter,
};

#[test]
fn tampered_log_exits_1_with_chain_broken_code() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("audit.jsonl");
    {
        let mut writer = AuditWriter::open(path.clone(), None)?;
        for i in 0..3 {
            writer.write_entry(AuditEntry::new_tool_invocation(NewToolInvocation::new(
                "stellar_pay_commit",
                "stellar:testnet",
                vec!["destination".to_owned()],
                PolicyDecision::Allow,
                format!("verify-{i}"),
            )))?;
        }
    }
    let content = std::fs::read_to_string(&path)?;
    let mut rows: Vec<serde_json::Value> = content
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    rows[1]["tool"] = serde_json::Value::String("tampered".to_owned());
    let tampered = rows
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?;
    std::fs::write(&path, tampered.join("\n") + "\n")?;
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(["audit", "verify"])
        .arg(&path)
        .env("STELLAR_AGENT_HOME", dir.path())
        .env_remove("STELLAR_AGENT_PROFILE")
        .output()?;
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        envelope["error"]["code"], "audit.chain_broken",
        "{envelope}"
    );
    Ok(())
}
