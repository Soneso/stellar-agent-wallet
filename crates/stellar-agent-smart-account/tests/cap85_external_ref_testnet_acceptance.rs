//! Testnet acceptance: the wallet's handling of CAP-85 external-reference
//! executables, end to end on Protocol 28 testnet.
//!
//! Every live test builds its own fixture, because the repoint mutates the
//! beacon and the runner's single test thread does not order tests:
//!
//! 1. A fresh Friendbot-funded admin uploads and instantiates the vendored
//!    beacon ([`CAP85_BEACON_WASM`]) with itself as admin.
//! 2. The OZ ed25519 and WebAuthn verifiers are deployed through the wallet's
//!    `deploy_ed25519_verifier` / `deploy_webauthn_verifier`, which upload
//!    their code; the two code hashes are the vendored Wasm digests.
//! 3. The admin calls `publish("verifier", <ed25519 hash>)` and
//!    `deploy_ref("verifier", salt)` on the beacon. The return value of
//!    `deploy_ref` is the proxy: a contract whose executable is
//!    `ContractExecutable::ExternalRef { executable_owner: <beacon>, tag:
//!    "verifier" }`, running the ed25519 verifier until the beacon repoints
//!    the tag.
//!
//! # Tests
//!
//! - `proxy_runs_the_referenced_wasm_and_reads_the_tag_entry` (proofs 1, 6):
//!   `canonicalize_key` on the proxy returns its 32-byte input, and the
//!   simulation's read-only footprint holds exactly the beacon's
//!   executable-tag key. This is a protocol precondition for the wallet-side
//!   proofs; the wallet-side invocation proofs are the confirmed rule install
//!   (`add_context_rule` calls `batch_canonicalize_key` on the proxy) and the
//!   confirmed transfer (`__check_auth` calls `verify` on the proxy) below.
//! - `install_pins_the_reference_and_signing_detects_the_repoint` (proofs
//!   2, 3): the wallet observes the reference; rule install refuses the
//!   mutable proxy without the override and pins owner, tag and resolved hash
//!   with it; a transfer signed through the rule confirms; after the repoint
//!   the passkey signing path and `verify_rule_wasm_pins` both report drift.
//! - `spec_follows_the_repoint_and_defi_gates_refuse_the_reference` (proofs
//!   4, 5): the SEP-48 spec fetch returns the spec of the Wasm the tag names,
//!   before and after the repoint, and the beacon's `get_ref` returns the
//!   repointed hash; the DeFi sign-time pin gate and the
//!   DeFindex vault pin gate refuse the reference by type.
//! - `vendored_verifier_specs_differ_in_key_data_and_error_enum`: offline
//!   parse of both vendored verifiers, the reference values proof 4 compares
//!   the live fetch against.
//!
//! The `smart-account execute` path (`submit_signed_invoke` with an
//! `Ed25519RuleSigner`) runs no drift check; this suite proves drift on the
//! passkey signing path and on `verify_rule_wasm_pins`, the two paths that
//! run one.
//!
//! Each test prints `CAP85-RECORD <test> <item> <value>` lines with every
//! testnet address and transaction hash it produced.
//!
//! # Gating
//!
//! ```text
//! cargo test -p stellar-agent-smart-account --features testnet-integration \
//!   --test cap85_external_ref_testnet_acceptance
//! ```

#![cfg(feature = "testnet-integration")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics and diagnostic output are acceptable in testnet acceptance tests"
)]

mod common;

use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    TESTNET_FRIENDBOT_URL, TESTNET_PASSPHRASE, TESTNET_RPC_URL, XLM_SAC_TESTNET,
    build_sac_transfer_invoke, fetch_testnet_sequence, fund_via_friendbot,
    invoke_as_source_account, sign_testnet_envelope, submit_testnet_signed_xdr,
    transfer_host_function, upload_and_create_contract, xlm_stroops_balance,
};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore as _};
use sha2::{Digest as _, Sha256};
use soroban_spec_tools::Spec;
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::{ContractKind, EventKind, ExecutableRefPin};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::sc_address::executable_tag_ledger_key;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_defi::pins::{DefiContractPin, PinVerifyError, verify_pin_for_sign};
use stellar_agent_defindex::pins::{DefindexPinError, verify_defindex_vault_wasm};
use stellar_agent_network::{
    Signer, SoftwareSigningKey, StellarRpcClient, WasmHashFetch, fetch_contract_wasm_hash,
};
use stellar_agent_sep48::fetch_contract_spec;
use stellar_agent_smart_account::AdminOrOwnerKey;
use stellar_agent_smart_account::cap85_beacon::CAP85_BEACON_WASM;
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, Ed25519VerifierDeployArgs, PolicyDeployArgs, PolicyDeployKind,
    ResolvedFeePerOp, WebAuthnVerifierDeployArgs, deploy_ed25519_verifier, deploy_policy,
    deploy_smart_account, deploy_webauthn_verifier,
};
use stellar_agent_smart_account::ed25519_verifier::ED25519_VERIFIER_WASM;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::credentials::{CredentialsError, CredentialsManager};
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRulePolicy,
    ContextRuleSignerInput, PinStatus, RuleContext, parse_c_strkey_to_smart_account,
    parse_g_strkey_to_signer_address,
};
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};
use stellar_agent_smart_account::simple_threshold_policy::build_simple_threshold_install_param;
use stellar_agent_smart_account::submit::{
    Ed25519RuleSigner, SubmitInvokeArgs, submit_signed_invoke,
};
use stellar_agent_smart_account::webauthn_verifier::WEBAUTHN_VERIFIER_WASM;
use stellar_agent_test_support::testnet_helpers::{
    contract_scaddress, derive_contract_address, fund_sac_balance,
};
use stellar_xdr::{
    BytesM, ContractDataDurability, LedgerKey, LedgerKeyContractData, Limits, ScAddress, ScBytes,
    ScSpecEntry, ScSpecTypeBytesN, ScSpecTypeDef, ScString, ScVal, StringM, WriteXdr as _,
};
use tempfile::TempDir;
use uuid::Uuid;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const CHAIN_ID: &str = "stellar:testnet";
const TIMEOUT: Duration = Duration::from_secs(120);
const FEE_STROOPS: u32 = 1_000_000;

/// The executable-reference tag the beacon publishes.
const TAG: &str = "verifier";

/// XLM funded into the smart account's SAC balance (3 XLM).
const SMART_ACCOUNT_FUND_STROOPS: i128 = 30_000_000;

/// The transfer signed through the proxy-verified rule (1 XLM).
const TRANSFER_STROOPS: i128 = 10_000_000;

// ─────────────────────────────────────────────────────────────────────────────
// Fixture
// ─────────────────────────────────────────────────────────────────────────────

/// One test's beacon, verifiers and proxy.
struct Cap85Fixture {
    /// Beacon admin and fee payer of every beacon call.
    admin_g: String,
    admin_seed: Zeroizing<[u8; 32]>,
    beacon: String,
    beacon_sc: ScAddress,
    proxy: String,
    proxy_sc: ScAddress,
    tag: ScString,
    ed25519_hash: [u8; 32],
    webauthn_hash: [u8; 32],
}

/// Prints one report record: every testnet address and transaction hash a
/// test produces is public testnet data.
fn record(test: &str, item: &str, value: &str) {
    eprintln!("CAP85-RECORD {test} {item} {value}");
}

fn record_opt(test: &str, item: &str, value: Option<&str>) {
    record(test, item, value.unwrap_or("none (not submitted)"));
}

fn rid() -> String {
    Uuid::new_v4().to_string()
}

/// Generates a fresh ed25519 keypair: `(g_strkey, seed)`.
fn fresh_keypair() -> (String, Zeroizing<[u8; 32]>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
    );
    (g_strkey, Zeroizing::new(signing_key.to_bytes()))
}

fn boxed_signer(seed: &Zeroizing<[u8; 32]>) -> Box<dyn Signer + Send + Sync> {
    Box::new(SoftwareSigningKey::new_from_zeroizing(Zeroizing::new(
        **seed,
    )))
}

/// A fresh Friendbot-funded deployer for one wallet deploy call.
async fn funded_deployer(label: &str) -> DeployerKeypair {
    let (g, seed) = fresh_keypair();
    fund_via_friendbot(&g).await;
    DeployerKeypair::SecretEnv {
        var_name: format!("cap85-acceptance-{label}"),
        signer: boxed_signer(&seed),
    }
}

fn explicit_fee() -> ResolvedFeePerOp {
    ResolvedFeePerOp {
        stroops: FEE_STROOPS,
        percentile_label: "explicit".to_owned(),
    }
}

fn random_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn first8_hex(hash: &[u8; 32]) -> String {
    hex::encode(&hash[..8])
}

fn bytes_scval(bytes: &[u8]) -> ScVal {
    ScVal::Bytes(ScBytes(
        BytesM::try_from(bytes.to_vec()).expect("bytes fit ScBytes"),
    ))
}

fn tag_scstring() -> ScString {
    ScString(StringM::try_from(TAG).expect("tag fits ScString"))
}

/// Deploys the beacon, both verifiers and the proxy for `test`.
async fn deploy_fixture(test: &str, registry_path: &Path) -> Cap85Fixture {
    let (admin_g, admin_seed) = fresh_keypair();
    fund_via_friendbot(&admin_g).await;
    record(test, "beacon-admin", &admin_g);

    let admin_sc = parse_g_strkey_to_signer_address(&admin_g).expect("admin G-strkey parses");
    let beacon = upload_and_create_contract(
        CAP85_BEACON_WASM,
        &admin_g,
        &admin_seed,
        random_salt(),
        vec![ScVal::Address(admin_sc)],
    )
    .await
    .unwrap_or_else(|e| panic!("beacon upload and create must succeed: {e}"));
    record(test, "beacon", &beacon.contract);
    record(test, "beacon-wasm-hash", &hex::encode(beacon.wasm_hash));
    record_opt(
        test,
        "beacon-upload-tx",
        beacon.upload.as_ref().map(|s| s.tx_hash.as_str()),
    );
    record(test, "beacon-create-tx", &beacon.create.tx_hash);

    let ed25519 = deploy_ed25519_verifier(
        Ed25519VerifierDeployArgs {
            deployer: funded_deployer("ed25519-verifier").await,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: TIMEOUT,
            fee: explicit_fee(),
            dry_run: false,
            registry_path_override: Some(registry_path.to_path_buf()),
        },
        None,
    )
    .await
    .expect("ed25519 verifier deployment must succeed on testnet");
    record(test, "ed25519-verifier", &ed25519.verifier_address);
    record_opt(test, "ed25519-verifier-tx", ed25519.tx_hash.as_deref());

    let webauthn = deploy_webauthn_verifier(
        WebAuthnVerifierDeployArgs {
            deployer: funded_deployer("webauthn-verifier").await,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: TIMEOUT,
            fee: explicit_fee(),
            dry_run: false,
            registry_path_override: Some(registry_path.to_path_buf()),
        },
        None,
    )
    .await
    .expect("WebAuthn verifier deployment must succeed on testnet");
    record(test, "webauthn-verifier", &webauthn.verifier_address);
    record_opt(test, "webauthn-verifier-tx", webauthn.tx_hash.as_deref());

    let ed25519_hash: [u8; 32] = Sha256::digest(ED25519_VERIFIER_WASM).into();
    let webauthn_hash: [u8; 32] = Sha256::digest(WEBAUTHN_VERIFIER_WASM).into();
    record(test, "ed25519-wasm-hash", &hex::encode(ed25519_hash));
    record(test, "webauthn-wasm-hash", &hex::encode(webauthn_hash));

    let tag = tag_scstring();
    let published = invoke_as_source_account(
        &beacon.contract,
        "publish",
        vec![ScVal::String(tag.clone()), bytes_scval(&ed25519_hash)],
        &admin_g,
        &admin_seed,
    )
    .await
    .unwrap_or_else(|e| panic!("beacon publish(ed25519) must succeed: {e}"));
    record(test, "publish-ed25519-tx", &published.submission.tx_hash);

    let proxy_salt = random_salt();
    let deployed = invoke_as_source_account(
        &beacon.contract,
        "deploy_ref",
        vec![ScVal::String(tag.clone()), bytes_scval(&proxy_salt)],
        &admin_g,
        &admin_seed,
    )
    .await
    .unwrap_or_else(|e| panic!("beacon deploy_ref must succeed: {e}"));
    record(test, "deploy-ref-tx", &deployed.submission.tx_hash);

    let beacon_sc = contract_scaddress(&beacon.contract).expect("beacon C-strkey parses");
    let proxy = derive_contract_address(&beacon_sc, &proxy_salt, TESTNET_PASSPHRASE)
        .expect("proxy address derives");
    let proxy_sc = contract_scaddress(&proxy).expect("proxy C-strkey parses");
    assert_eq!(
        deployed.return_value,
        ScVal::Address(proxy_sc.clone()),
        "deploy_ref must return the address derived from the beacon and the salt"
    );
    record(test, "proxy", &proxy);

    Cap85Fixture {
        admin_g,
        admin_seed,
        beacon: beacon.contract,
        beacon_sc,
        proxy,
        proxy_sc,
        tag,
        ed25519_hash,
        webauthn_hash,
    }
}

/// Repoints the beacon's tag at `wasm_hash` and returns the transaction hash.
async fn repoint(fixture: &Cap85Fixture, wasm_hash: &[u8; 32]) -> String {
    invoke_as_source_account(
        &fixture.beacon,
        "publish",
        vec![ScVal::String(fixture.tag.clone()), bytes_scval(wasm_hash)],
        &fixture.admin_g,
        &fixture.admin_seed,
    )
    .await
    .unwrap_or_else(|e| panic!("beacon repoint must succeed: {e}"))
    .submission
    .tx_hash
}

/// Asserts the wallet observes the proxy as an external reference to the
/// beacon's tag, resolving to `expected_resolved`.
async fn assert_proxy_resolves_to(fixture: &Cap85Fixture, expected_resolved: &[u8; 32]) {
    let rpc = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");
    match fetch_contract_wasm_hash(&rpc, None, &fixture.proxy)
        .await
        .expect("fetch_contract_wasm_hash on the proxy must succeed")
    {
        WasmHashFetch::ExternalRef(external) => {
            assert_eq!(
                external.owner, fixture.beacon_sc,
                "owner must be the beacon"
            );
            assert_eq!(external.tag, fixture.tag, "tag must be the published tag");
            assert_eq!(
                external.resolved,
                Some(*expected_resolved),
                "the tag must resolve to the hash the beacon published"
            );
        }
        other => panic!("expected WasmHashFetch::ExternalRef for the proxy; got {other:?}"),
    }
}

/// Reads every JSONL row of the audit log; a row that does not parse fails
/// the test, so an absence assertion cannot pass on an unreadable log.
fn read_audit_entries(log_path: &Path) -> Vec<AuditEntry> {
    let file = std::fs::File::open(log_path).expect("audit log must be readable");
    BufReader::new(file)
        .lines()
        .map(|line| line.expect("audit log line must read"))
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<AuditEntry>(&line)
                .unwrap_or_else(|e| panic!("audit row must parse ({e}): {line}"))
        })
        .collect()
}

fn tmp_audit_writer() -> (Arc<Mutex<AuditWriter>>, std::path::PathBuf, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path.clone(), None).expect("AuditWriter::open");
    (Arc::new(Mutex::new(writer)), path, dir)
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec helpers
// ─────────────────────────────────────────────────────────────────────────────

fn offline_spec(wasm: &[u8]) -> Vec<ScSpecEntry> {
    Spec::from_wasm(wasm)
        .expect("vendored verifier spec parses")
        .0
        .expect("vendored verifier carries a contractspecv0 section")
}

fn function_names(entries: &[ScSpecEntry]) -> Vec<String> {
    let mut names: Vec<String> = entries
        .iter()
        .filter_map(|entry| match entry {
            ScSpecEntry::FunctionV0(function) => Some(function.name.0.to_utf8_string_lossy()),
            _ => None,
        })
        .collect();
    names.sort();
    names
}

/// The declared type of the `key_data` input of `verify`.
fn verify_key_data_type(entries: &[ScSpecEntry]) -> ScSpecTypeDef {
    let verify = entries
        .iter()
        .find_map(|entry| match entry {
            ScSpecEntry::FunctionV0(function)
                if function.name.0.to_utf8_string_lossy() == "verify" =>
            {
                Some(function)
            }
            _ => None,
        })
        .expect("spec must declare verify");
    verify
        .inputs
        .iter()
        .find(|input| input.name.to_utf8_string_lossy() == "key_data")
        .expect("verify must declare key_data")
        .type_
        .clone()
}

fn declares_error_enum(entries: &[ScSpecEntry], name: &str) -> bool {
    entries.iter().any(|entry| {
        matches!(entry, ScSpecEntry::UdtErrorEnumV0(error) if error.name.to_utf8_string_lossy() == name)
    })
}

/// Asserts the ed25519 verifier spec shape: `key_data: BytesN<32>` and no
/// `WebAuthnError`.
fn assert_ed25519_spec_shape(entries: &[ScSpecEntry]) {
    assert_eq!(
        verify_key_data_type(entries),
        ScSpecTypeDef::BytesN(ScSpecTypeBytesN { n: 32 }),
        "ed25519 verify must take key_data: BytesN<32>"
    );
    assert!(
        !declares_error_enum(entries, "WebAuthnError"),
        "the ed25519 verifier spec must not declare WebAuthnError"
    );
}

/// Asserts the WebAuthn verifier spec shape: `key_data: Bytes` and a
/// `WebAuthnError` enum.
fn assert_webauthn_spec_shape(entries: &[ScSpecEntry]) {
    assert_eq!(
        verify_key_data_type(entries),
        ScSpecTypeDef::Bytes,
        "WebAuthn verify must take key_data: Bytes"
    );
    assert!(
        declares_error_enum(entries, "WebAuthnError"),
        "the WebAuthn verifier spec must declare WebAuthnError"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Offline reference values
// ─────────────────────────────────────────────────────────────────────────────

/// Both vendored verifiers export exactly `verify`, `canonicalize_key` and
/// `batch_canonicalize_key`, and differ in the `key_data` type of `verify`
/// and in the `WebAuthnError` enum.
#[test]
fn vendored_verifier_specs_differ_in_key_data_and_error_enum() {
    let expected_functions = vec![
        "batch_canonicalize_key".to_owned(),
        "canonicalize_key".to_owned(),
        "verify".to_owned(),
    ];
    let ed25519 = offline_spec(ED25519_VERIFIER_WASM);
    let webauthn = offline_spec(WEBAUTHN_VERIFIER_WASM);
    assert_eq!(function_names(&ed25519), expected_functions);
    assert_eq!(function_names(&webauthn), expected_functions);
    assert_ed25519_spec_shape(&ed25519);
    assert_webauthn_spec_shape(&webauthn);
    assert_ne!(ed25519, webauthn, "the two verifier specs must differ");
}

// ─────────────────────────────────────────────────────────────────────────────
// Proofs 1 and 6: invocation through the reference and its footprint
// ─────────────────────────────────────────────────────────────────────────────

/// `canonicalize_key` on the proxy runs the ed25519 verifier Wasm and
/// returns its 32-byte input; the simulation reads the beacon's
/// executable-tag entry, which appears in the read-only footprint exactly
/// once and not in the read-write footprint.
#[tokio::test]
async fn proxy_runs_the_referenced_wasm_and_reads_the_tag_entry() {
    const TEST: &str = "invocation";
    let registry = tempfile::tempdir().expect("tempdir");
    let fixture = deploy_fixture(TEST, &registry.path().join("networks.toml")).await;

    let (_key_g, key_seed) = fresh_keypair();
    let pubkey = SigningKey::from_bytes(&key_seed).verifying_key().to_bytes();
    let invocation = invoke_as_source_account(
        &fixture.proxy,
        "canonicalize_key",
        vec![bytes_scval(&pubkey)],
        &fixture.admin_g,
        &fixture.admin_seed,
    )
    .await
    .unwrap_or_else(|e| panic!("canonicalize_key on the proxy must succeed: {e}"));
    record(TEST, "canonicalize-key-tx", &invocation.submission.tx_hash);

    // Proof 1: the ed25519 verifier's canonicalize_key returns the key bytes.
    assert_eq!(
        invocation.return_value,
        bytes_scval(&pubkey),
        "canonicalize_key through the reference must return the 32-byte input"
    );

    // Proof 6: the executable-tag entry is read, never written.
    let tag_key = executable_tag_ledger_key(&fixture.beacon_sc, &fixture.tag);
    let independent_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: fixture.beacon_sc.clone(),
        key: ScVal::ExecutableTag(fixture.tag.clone()),
        durability: ContractDataDurability::Persistent,
    });
    assert_eq!(
        tag_key, independent_key,
        "executable_tag_ledger_key must build the persistent ExecutableTag key"
    );
    let footprint = &invocation.transaction_data.resources.footprint;
    let read_only_hits = footprint
        .read_only
        .iter()
        .filter(|key| **key == tag_key)
        .count();
    assert_eq!(
        read_only_hits, 1,
        "the read-only footprint must hold the beacon's tag key exactly once; footprint: {:?}",
        footprint.read_only
    );
    assert!(
        !footprint.read_write.contains(&tag_key),
        "the tag key must not be in the read-write footprint"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Proofs 2 and 3: install-time pin and signing-time drift
// ─────────────────────────────────────────────────────────────────────────────

fn proxy_rule_definition(
    proxy_sc: &ScAddress,
    agent_pubkey: &[u8; 32],
    policy_sc: &ScAddress,
) -> ContextRuleDefinition {
    ContextRuleDefinition::new(
        RuleContext::CallContract {
            contract: parse_c_strkey_to_smart_account(XLM_SAC_TESTNET).expect("XLM SAC parses"),
        },
        "cap85-proxy".to_owned(),
        None,
        vec![ContextRuleSignerInput::External {
            verifier: proxy_sc.clone(),
            pubkey_data: agent_pubkey.to_vec(),
        }],
        vec![ContextRulePolicy::new(
            policy_sc.clone(),
            build_simple_threshold_install_param(1).expect("threshold param builds"),
        )],
    )
}

/// The wallet observes the proxy as a reference; install refuses it without
/// the mutable-contract override and pins owner, tag and resolved hash with
/// it; a transfer signed through the rule confirms; after the repoint both
/// signing-time drift paths report the change.
#[tokio::test(flavor = "multi_thread")]
async fn install_pins_the_reference_and_signing_detects_the_repoint() {
    const TEST: &str = "install-drift";
    let registry = tempfile::tempdir().expect("tempdir");
    let registry_path = registry.path().join("networks.toml");
    let fixture = deploy_fixture(TEST, &registry_path).await;
    let beacon_redacted = redact_strkey_first5_last5(&fixture.beacon);
    let proxy_redacted = redact_strkey_first5_last5(&fixture.proxy);

    // ── Proof 2: the wallet's executable fetch sees the reference ───────────
    assert_proxy_resolves_to(&fixture, &fixture.ed25519_hash).await;

    // ── Smart account, threshold policy, managers ───────────────────────────
    let (bootstrap_g, bootstrap_seed) = fresh_keypair();
    fund_via_friendbot(&bootstrap_g).await;
    let bootstrap_signer = boxed_signer(&bootstrap_seed);
    let deployed = deploy_smart_account(
        DeploymentArgs {
            deployer: funded_deployer("smart-account").await,
            initial_signer: bootstrap_g.clone(),
            salt: random_salt(),
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: TIMEOUT,
            fee: explicit_fee(),
            dry_run: false,
            genesis_signer_scval_override: None,
        },
        None,
    )
    .await
    .expect("smart-account deployment must succeed on testnet");
    let smart_account = deployed.smart_account;
    record(TEST, "smart-account", &smart_account);
    record_opt(TEST, "smart-account-tx", deployed.tx_hash.as_deref());
    let smart_account_sc =
        parse_c_strkey_to_smart_account(&smart_account).expect("smart-account C-strkey parses");

    let policy = deploy_policy(
        PolicyDeployArgs {
            kind: PolicyDeployKind::SimpleThreshold,
            deployer: funded_deployer("threshold-policy").await,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: TIMEOUT,
            fee: explicit_fee(),
            dry_run: false,
            registry_path_override: Some(registry_path.clone()),
        },
        None,
    )
    .await
    .expect("threshold-policy deployment must succeed on testnet");
    record(TEST, "threshold-policy", &policy.policy_address);
    record_opt(TEST, "threshold-policy-tx", policy.tx_hash.as_deref());
    let policy_sc =
        parse_c_strkey_to_smart_account(&policy.policy_address).expect("policy C-strkey parses");

    let (audit_writer, audit_log_path, _audit_dir) = tmp_audit_writer();
    let signers_manager = Arc::new(
        SignersManager::new(SignersManagerConfig::new(
            TESTNET_RPC_URL.to_owned(),
            TESTNET_RPC_URL.to_owned(),
            Arc::clone(&audit_writer),
            audit_log_path.clone(),
            TESTNET_PASSPHRASE.to_owned(),
            "cap85-acceptance".to_owned(),
            TIMEOUT,
            CHAIN_ID.to_owned(),
        ))
        .expect("SignersManager::new"),
    );
    let manager = ContextRuleManager::new(
        ContextRuleManagerConfig::new(
            TESTNET_RPC_URL.to_owned(),
            TESTNET_PASSPHRASE.to_owned(),
            TIMEOUT,
            CHAIN_ID.to_owned(),
        )
        .with_audit_writer(Arc::clone(&audit_writer))
        .with_signers_manager(Arc::clone(&signers_manager)),
    )
    .expect("ContextRuleManager::new");

    let (_agent_g, agent_seed) = fresh_keypair();
    let agent_pubkey = SigningKey::from_bytes(&agent_seed)
        .verifying_key()
        .to_bytes();
    let agent_signer = boxed_signer(&agent_seed);

    // ── Proof 2: install without the override is refused by variant ─────────
    let refusal = manager
        .install_rule(
            smart_account_sc.clone(),
            proxy_rule_definition(&fixture.proxy_sc, &agent_pubkey, &policy_sc),
            vec![ContextRuleId::new(0)],
            bootstrap_signer.as_ref(),
            None,
            rid(),
            false,
            false,
        )
        .await
        .expect_err("install through a mutable external reference must be refused");
    let refused_rule_id = match refusal {
        SaError::VerifierMutable {
            rule_id,
            ref contract_address_redacted,
            admin_or_owner_key: AdminOrOwnerKey::ExternalRefExecutable,
            detail: Some(ref detail),
            ..
        } => {
            assert_eq!(contract_address_redacted.as_str(), proxy_redacted);
            assert_eq!(
                detail,
                &format!("owner {beacon_redacted}, tag \"{TAG}\""),
                "the refusal must name the redacted beacon and the tag"
            );
            rule_id
        }
        other => panic!(
            "expected VerifierMutable {{ ExternalRefExecutable, detail: Some(..) }}; got {other:?}"
        ),
    };
    record(TEST, "refused-rule-id", &refused_rule_id.to_string());
    let overrides_after_refusal = read_audit_entries(&audit_log_path)
        .into_iter()
        .filter(|entry| {
            matches!(
                entry.event_kind,
                EventKind::SaMutableContractOverride { .. }
            )
        })
        .count();
    assert_eq!(
        overrides_after_refusal, 0,
        "a refused install must write no SaMutableContractOverride row (refused rule id \
         {refused_rule_id})"
    );

    // ── Proof 2: install with the override pins the reference ───────────────
    let install_request_id = rid();
    let installed = manager
        .install_rule(
            smart_account_sc.clone(),
            proxy_rule_definition(&fixture.proxy_sc, &agent_pubkey, &policy_sc),
            vec![ContextRuleId::new(0)],
            bootstrap_signer.as_ref(),
            None,
            install_request_id.clone(),
            true,
            false,
        )
        .await
        .expect("install with accept_mutable_verifier must succeed on testnet");
    let rule_id = installed.rule_id;
    record(TEST, "rule-id", &rule_id.to_string());
    record(TEST, "install-tx", &installed.tx_hash);
    assert!(
        rule_id != 0,
        "the installed rule must not be the bootstrap rule"
    );
    assert!(installed.pin_result.mutable_override);

    let ref_key_xdr = LedgerKey::ContractData(LedgerKeyContractData {
        contract: fixture.beacon_sc.clone(),
        key: ScVal::ExecutableTag(fixture.tag.clone()),
        durability: ContractDataDurability::Persistent,
    })
    .to_xdr(Limits::none())
    .expect("tag key encodes");
    let expected_pin = ExecutableRefPin {
        owner_redacted: stellar_agent_core::observability::RedactedStrkey::from_already_redacted(
            beacon_redacted.clone(),
        ),
        tag: TAG.to_owned(),
        ref_key_hex: hex::encode(Sha256::digest(&ref_key_xdr)),
        resolved_hash_first8: first8_hex(&fixture.ed25519_hash),
    };
    assert_eq!(
        installed.pin_result.pinned_verifier_executable_refs,
        vec![Some(expected_pin.clone())]
    );

    let entries = read_audit_entries(&audit_log_path);
    // The override row is written before the rule has an on-chain id; the
    // install request id is what joins it to the SaContextRuleCreated row.
    let overrides: Vec<&AuditEntry> = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.event_kind,
                EventKind::SaMutableContractOverride { .. }
            )
        })
        .collect();
    assert_eq!(
        overrides.len(),
        1,
        "exactly one override row: {overrides:?}"
    );
    assert_eq!(overrides[0].request_id, install_request_id);
    match &overrides[0].event_kind {
        EventKind::SaMutableContractOverride {
            rule_id: override_rule_id,
            contract_address_redacted,
            contract_kind,
            executable_owner_redacted,
            executable_tag,
            ..
        } => {
            record(TEST, "override-row-rule-id", &override_rule_id.to_string());
            assert_eq!(contract_address_redacted.as_str(), proxy_redacted);
            assert_eq!(*contract_kind, ContractKind::Verifier);
            assert_eq!(
                executable_owner_redacted.as_ref().map(|o| o.as_str()),
                Some(beacon_redacted.as_str())
            );
            assert_eq!(executable_tag.as_deref(), Some(TAG));
        }
        other => panic!("filtered to SaMutableContractOverride; got {other:?}"),
    }
    let created = entries
        .iter()
        .find_map(|entry| match &entry.event_kind {
            EventKind::SaContextRuleCreated {
                rule_id: created_rule_id,
                pinned_verifier_wasm_hashes_first8,
                pinned_verifier_executable_refs,
                mutable_override,
                ..
            } if *created_rule_id == rule_id && entry.request_id == install_request_id => Some((
                pinned_verifier_wasm_hashes_first8.clone(),
                pinned_verifier_executable_refs.clone(),
                *mutable_override,
            )),
            _ => None,
        })
        .expect("SaContextRuleCreated row for the installed rule and the install request");
    assert_eq!(created.0, vec![first8_hex(&fixture.ed25519_hash)]);
    assert_eq!(created.1, vec![Some(expected_pin)]);
    assert!(created.2, "the created row must carry mutable_override");

    signers_manager
        .refresh_signer_baseline(smart_account_sc.clone(), rule_id, Some(&bootstrap_g), rid())
        .await
        .expect("refresh_signer_baseline must succeed");

    // ── Proof 3: a transfer signed through the proxy-verified rule ──────────
    let funded = fund_sac_balance(
        "cap85-acceptance",
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        TESTNET_FRIENDBOT_URL,
        XLM_SAC_TESTNET,
        &smart_account,
        SMART_ACCOUNT_FUND_STROOPS,
        build_sac_transfer_invoke,
        |account_id| fetch_testnet_sequence(account_id.to_owned()),
        |unsigned_xdr, seed, network_passphrase| {
            sign_testnet_envelope(unsigned_xdr, seed, network_passphrase.to_owned())
        },
        submit_testnet_signed_xdr,
    )
    .await
    .unwrap_or_else(|e| panic!("SAC funding of the smart account must succeed: {e}"));
    record(TEST, "fund-sac-tx", &funded.tx_hash);

    let (recipient_g, _recipient_seed) = fresh_keypair();
    fund_via_friendbot(&recipient_g).await;
    let recipient_sc =
        parse_g_strkey_to_signer_address(&recipient_g).expect("recipient G-strkey parses");
    let balance_before = xlm_stroops_balance(&recipient_g).await;
    let rule_ids = vec![ContextRuleId::new(rule_id)];
    let transfer = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(XLM_SAC_TESTNET)
            .auth_address(smart_account.as_str())
            .auth_rule_ids(&rule_ids)
            .host_function(transfer_host_function(
                parse_c_strkey_to_smart_account(XLM_SAC_TESTNET).expect("XLM SAC parses"),
                smart_account_sc.clone(),
                recipient_sc,
                TRANSFER_STROOPS,
            ))
            .signer(bootstrap_signer.as_ref())
            .ed25519_rule_signer(Ed25519RuleSigner {
                signer: agent_signer.as_ref(),
                verifier: fixture.proxy_sc.clone(),
            })
            .primary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .chain_id(CHAIN_ID)
            .timeout(TIMEOUT)
            .op_label("cap85_proxy_verified_transfer")
            .emit_observability_logs(true)
            .build(),
    )
    .await
    .expect("a transfer signed through the proxy-verified rule must confirm");
    record(TEST, "transfer-tx", &transfer.tx_hash);
    let balance_after = xlm_stroops_balance(&recipient_g).await;
    assert_eq!(
        balance_after - balance_before,
        i64::try_from(TRANSFER_STROOPS).expect("fits i64"),
        "the recipient must receive exactly the transferred amount"
    );

    // ── Repoint the tag at the WebAuthn verifier ────────────────────────────
    let repoint_tx = repoint(&fixture, &fixture.webauthn_hash).await;
    record(TEST, "repoint-webauthn-tx", &repoint_tx);
    assert_proxy_resolves_to(&fixture, &fixture.webauthn_hash).await;
    let expected_observed = format!(
        "external reference owner {beacon_redacted} tag \"{TAG}\" resolved {}",
        first8_hex(&fixture.webauthn_hash)
    );

    // ── Proof 3a: the passkey signing path refuses on drift ─────────────────
    let passkeys_dir = tempfile::tempdir().expect("tempdir");
    let credentials = CredentialsManager::new(
        passkeys_dir.path().join("passkeys"),
        "default",
        "localhost",
        None,
    );
    let outcome = credentials
        .sign_with_passkey_rule(
            "cap85-no-such-credential",
            &smart_account,
            &[0u8; 32],
            vec![rule_id],
            Some(Arc::clone(&signers_manager)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19907),
            Duration::from_millis(500),
            |_| {},
            true,
        )
        .await;
    match outcome {
        Err(CredentialsError::WasmHashDrift { ref source }) => match source.as_ref() {
            SaError::VerifierHashDrift {
                rule_id: drift_rule_id,
                deploy_address_redacted,
                pinned_hash_first8,
                observed_hash_first8,
                observed_executable: Some(observed_executable),
                ..
            } => {
                assert_eq!(*drift_rule_id, rule_id);
                assert_eq!(deploy_address_redacted.as_str(), proxy_redacted);
                assert_eq!(pinned_hash_first8, &first8_hex(&fixture.ed25519_hash));
                assert_eq!(observed_hash_first8, &first8_hex(&fixture.webauthn_hash));
                assert_eq!(observed_executable, &expected_observed);
            }
            other => panic!(
                "expected VerifierHashDrift {{ observed_executable: Some(..) }}; got {other:?}"
            ),
        },
        other => panic!("expected CredentialsError::WasmHashDrift; got {other:?}"),
    }

    let entries = read_audit_entries(&audit_log_path);
    let drift_rows: Vec<&AuditEntry> = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.event_kind,
                EventKind::SaVerifierHashDrift { rule_id: r, .. } if r == rule_id
            )
        })
        .collect();
    assert_eq!(drift_rows.len(), 1, "exactly one SaVerifierHashDrift row");
    let drift_row = drift_rows[0];
    match &drift_row.event_kind {
        EventKind::SaVerifierHashDrift {
            deploy_address_redacted,
            pinned_hash_first8,
            observed_hash_first8,
            observed_executable,
            ..
        } => {
            assert_eq!(deploy_address_redacted.as_str(), proxy_redacted);
            assert_eq!(pinned_hash_first8, &first8_hex(&fixture.ed25519_hash));
            assert_eq!(observed_hash_first8, &first8_hex(&fixture.webauthn_hash));
            assert_eq!(
                observed_executable.as_deref(),
                Some(expected_observed.as_str())
            );
        }
        other => panic!("filtered to SaVerifierHashDrift; got {other:?}"),
    }
    let assertion_row = entries
        .iter()
        .find(|entry| {
            matches!(
                &entry.event_kind,
                EventKind::PasskeyAssertion { result, .. } if result == "failure:verifier_hash_drift"
            )
        })
        .expect("PasskeyAssertion(failure:verifier_hash_drift) row");
    assert_eq!(
        drift_row.request_id, assertion_row.request_id,
        "the drift row and the assertion row must share the request id"
    );

    // ── Proof 3b: verify_rule_wasm_pins reports drift ───────────────────────
    let pins = manager
        .verify_rule_wasm_pins(smart_account_sc, rule_id, &bootstrap_g, &rid())
        .await
        .expect("verify_rule_wasm_pins must return a report");
    assert_eq!(pins.verifier_pin_status, PinStatus::Drift);
    assert_eq!(
        pins.pinned_verifier_first8,
        vec![first8_hex(&fixture.ed25519_hash)]
    );
    assert_eq!(
        pins.observed_verifier_first8,
        vec![first8_hex(&fixture.webauthn_hash)]
    );
    assert_eq!(pins.policy_pin_status, PinStatus::Match);
}

// ─────────────────────────────────────────────────────────────────────────────
// Proofs 4 and 5: SEP-48 spec and the DeFi / DeFindex gates
// ─────────────────────────────────────────────────────────────────────────────

/// Asserts the DeFi sign-time gate and the DeFindex vault gate refuse the
/// proxy as an external reference naming the beacon and the tag, even with a
/// DeFi pin whose hash equals the one the tag resolves to.
async fn assert_defi_gates_refuse(fixture: &Cap85Fixture, resolved: &[u8; 32]) {
    let rpc = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");
    let beacon_redacted = redact_strkey_first5_last5(&fixture.beacon);
    let proxy_redacted = redact_strkey_first5_last5(&fixture.proxy);

    let fetch = fetch_contract_wasm_hash(&rpc, None, &fixture.proxy)
        .await
        .expect("fetch_contract_wasm_hash on the proxy must succeed");
    let pin = DefiContractPin::new(
        "defindex",
        "v1",
        "default",
        CHAIN_ID,
        fixture.proxy.as_str(),
        *resolved,
        "cap85-acceptance",
    );
    match verify_pin_for_sign(&pin, &fetch) {
        Err(PinVerifyError::ExternalRef {
            contract_redacted,
            owner_redacted,
            tag,
            wire_code,
        }) => {
            assert_eq!(wire_code, "defi.pin.external_ref");
            assert_eq!(contract_redacted, proxy_redacted);
            assert_eq!(owner_redacted, beacon_redacted);
            assert_eq!(tag, TAG);
        }
        other => panic!("expected PinVerifyError::ExternalRef; got {other:?}"),
    }

    match verify_defindex_vault_wasm(&fixture.proxy, &rpc, None).await {
        Err(DefindexPinError::ExternalRef {
            vault_redacted,
            owner_redacted,
            tag,
        }) => {
            assert_eq!(vault_redacted, proxy_redacted);
            assert_eq!(owner_redacted, beacon_redacted);
            assert_eq!(tag, TAG);
        }
        other => panic!("expected DefindexPinError::ExternalRef; got {other:?}"),
    }
}

/// The SEP-48 spec fetch returns the spec of the Wasm the tag names now, and
/// the DeFi and DeFindex pin gates refuse the reference before and after
/// the repoint.
#[tokio::test]
async fn spec_follows_the_repoint_and_defi_gates_refuse_the_reference() {
    const TEST: &str = "spec-defi";
    let registry = tempfile::tempdir().expect("tempdir");
    let fixture = deploy_fixture(TEST, &registry.path().join("networks.toml")).await;

    let ed25519_offline = offline_spec(ED25519_VERIFIER_WASM);
    let webauthn_offline = offline_spec(WEBAUTHN_VERIFIER_WASM);

    // ── Before the repoint ──────────────────────────────────────────────────
    let before = fetch_contract_spec(TESTNET_RPC_URL, &fixture.proxy)
        .await
        .expect("SEP-48 spec fetch through the reference must succeed");
    assert_eq!(
        before, ed25519_offline,
        "the proxy's spec must equal the ed25519 verifier's"
    );
    assert_ed25519_spec_shape(&before);
    assert_defi_gates_refuse(&fixture, &fixture.ed25519_hash).await;

    // ── After the repoint ───────────────────────────────────────────────────
    let repoint_tx = repoint(&fixture, &fixture.webauthn_hash).await;
    record(TEST, "repoint-webauthn-tx", &repoint_tx);
    assert_proxy_resolves_to(&fixture, &fixture.webauthn_hash).await;
    let get_ref = invoke_as_source_account(
        &fixture.beacon,
        "get_ref",
        vec![ScVal::String(fixture.tag.clone())],
        &fixture.admin_g,
        &fixture.admin_seed,
    )
    .await
    .unwrap_or_else(|e| panic!("beacon get_ref must succeed: {e}"));
    record(TEST, "get-ref-tx", &get_ref.submission.tx_hash);
    assert_eq!(
        get_ref.return_value,
        bytes_scval(&fixture.webauthn_hash),
        "get_ref must return the hash the repoint published"
    );

    let after = fetch_contract_spec(TESTNET_RPC_URL, &fixture.proxy)
        .await
        .expect("SEP-48 spec fetch after the repoint must succeed");
    assert_eq!(
        after, webauthn_offline,
        "after the repoint the proxy's spec must equal the WebAuthn verifier's"
    );
    assert_webauthn_spec_shape(&after);
    assert_defi_gates_refuse(&fixture, &fixture.webauthn_hash).await;
}
