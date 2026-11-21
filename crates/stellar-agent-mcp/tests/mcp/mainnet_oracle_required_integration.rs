//! A server start on an enabled mainnet profile whose stored profile names
//! no oracle refuses the enablement with `on_disk_oracle_host`: the stored
//! profile names no oracle host the signed policy binds.
//!
//! The fixture enables a mainnet profile with a complete oracle the way the
//! ceremony leaves it: the owner key, the agent signer and its identity
//! record, the minted profile keys, a signed version 2 policy bound to the
//! installation nonce, the primary endpoint, and the oracle host, the pin
//! from a first startup, and the nonce. A server started on that profile
//! admits each of the six mainnet write tools. The operator then removes the
//! oracle URL and its record from the profile file and restarts the server:
//! startup refuses the enablement. The server reads the profile at startup,
//! so the restart is what applies the edit.
//!
//! The primary endpoint is a loopback connection counter, so the refusal is
//! shown to precede any endpoint contact.
//!
//! The mock keyring and the data root are process-global, so the test is
//! `#[serial]`.

#![cfg(feature = "mainnet-write")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; a failed setup step fails the test loudly"
)]

use serial_test::serial;
use sha2::Digest as _;
use stellar_agent_core::audit_log::BindingCheck;
use stellar_agent_core::mainnet::enablement::normalize_endpoint_host;
use stellar_agent_core::policy::v1::{
    canonical::canonical_bytes,
    signature::{digest, sign},
};
use stellar_agent_core::profile::loader::save_to_dir;
use stellar_agent_core::profile::name::ProfileNameSource;
use stellar_agent_core::profile::schema::{
    KeyringEntryRef, PrimaryProviderRecord, Profile, ProviderRecord, default_policy_dir,
    default_profile_dir, mainnet_enablement_entry_ref, signer_identity_entry_ref,
};
use stellar_agent_core::profile::signer_identity::SignerIdentityRecord;
use stellar_agent_mcp::server::{
    StellarClaimCommitArgs, StellarCreateAccountCommitArgs, StellarPayCommitArgs,
    StellarTrustlineCommitArgs, WalletServer, X402AuthenticatedPaymentArgs, X402CreatePaymentArgs,
};
use stellar_agent_mcp::transport::{build_selected_server, build_server};
use stellar_agent_test_support::{ConnectionCounter, StellarAgentHomeGuard, keyring_mock};

/// The installation nonce the enablement stores.
const NONCE: &str = "installation-nonce";
/// The seed of the enrolled agent signer.
const AGENT_SEED: [u8; 32] = [42; 32];
/// The seed of the policy owner.
const OWNER_SEED: [u8; 32] = [11; 32];

fn put(entry: &KeyringEntryRef, value: &str) {
    keyring_core::Entry::new(&entry.service, &entry.account)
        .unwrap()
        .set_password(value)
        .unwrap();
}

fn agent_g() -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&AGENT_SEED);
    stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes())
        .to_string()
        .to_string()
}

/// The mainnet profile `operator` on the primary endpoint `rpc_url`, with
/// its primary record and a complete oracle.
fn complete_profile(home: &std::path::Path, rpc_url: &str) -> Profile {
    let host = url::Url::parse(rpc_url)
        .unwrap()
        .host_str()
        .unwrap()
        .to_owned();
    let mut profile = Profile::builder_mainnet_named(
        "operator",
        rpc_url,
        "stellar-agent-signer-operator",
        &agent_g(),
        "stellar-agent-nonce-operator",
        "default",
    )
    .primary_provider(PrimaryProviderRecord::new("Primary operator", host))
    .oracle_provider_url(url::Url::parse("https://oracle.example.invalid").unwrap())
    .oracle_provider(ProviderRecord::new(
        "Oracle operator",
        "oracle.example.invalid",
        true,
    ))
    .build();
    profile.audit_log_path = home.join("audit.jsonl");
    profile
}

/// Enrolls the keys of `profile`, saves it, installs its signed policy bound
/// to [`NONCE`] and to the profile's endpoint, pins the policy with a first
/// startup, and stores the nonce.
fn enable(profile: &Profile) {
    let owner = ed25519_dalek::SigningKey::from_bytes(&OWNER_SEED);
    let owner_g = stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()).to_string();
    put(&profile.policy_owner_key_id, &owner_g);
    put(&KeyringEntryRef::default_owner_key("operator"), &owner_g);
    put(
        &profile.mcp_signer_default,
        &stellar_strkey::Unredacted(&stellar_strkey::ed25519::PrivateKey(AGENT_SEED)).to_string(),
    );
    put(
        &signer_identity_entry_ref(&profile.mcp_signer_default),
        &SignerIdentityRecord::signed_for_test(
            ed25519_dalek::SigningKey::from_bytes(&AGENT_SEED)
                .verifying_key()
                .to_bytes(),
            "operator",
            profile,
            &owner,
        )
        .render()
        .unwrap(),
    );
    for key in [
        &profile.policy_window_state_key_id,
        &profile.audit_log_hash_chain_key_id,
        &profile.attestation_key_id,
        &profile.mcp_nonce_key_alias,
    ] {
        stellar_agent_network::keyring::rotate_keyring_secret_32(&key.service, &key.account)
            .unwrap();
    }
    save_to_dir("operator", profile, &default_profile_dir().unwrap()).unwrap();
    let raw = include_str!("../../../stellar-agent-core/tests/fixtures/policy-v2.toml")
        .replace(
            &"0".repeat(64),
            &stellar_agent_core::hex::encode(&sha2::Sha256::digest(NONCE.as_bytes())),
        )
        .replace(
            "endpoint_host = \"rpc.example.invalid\"",
            &format!(
                "endpoint_host = \"{}\"",
                normalize_endpoint_host(profile.rpc_url.as_str()).unwrap()
            ),
        );
    let signature = sign(&digest(&canonical_bytes(&raw).unwrap()), &owner);
    let directory = default_policy_dir().unwrap();
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("operator.toml"),
        format!(
            "{raw}\n[signature]\nowner_id = \"{owner_g}\"\nsig = \"{}\"\n",
            stellar_agent_core::hex::encode(&signature)
        ),
    )
    .unwrap();
    drop(build_server(profile.clone(), BindingCheck::Enforce).unwrap());
    put(
        &mainnet_enablement_entry_ref(&profile.policy_window_state_key_id),
        NONCE,
    );
}

/// The server a startup on the stored profile builds.
fn start(profile: &Profile) -> WalletServer {
    build_selected_server(
        profile.clone(),
        ProfileNameSource::Flag,
        BindingCheck::Enforce,
    )
    .expect("an enabled mainnet profile starts")
}

/// The error code and message of a tool's business-error result.
fn refusal(result: &rmcp::model::CallToolResult) -> (String, String) {
    let (code, message, _) = crate::common::assert_business_envelope(result);
    (code, message)
}

/// The arguments of one tool call, from their JSON form.
fn args<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> T {
    serde_json::from_value(value).unwrap()
}

/// The six mainnet write tools, each with the code an admitted call refuses
/// with: its inputs pass argument decoding, and the handler refuses the
/// malformed envelope or payment requirement after admission.
const TOOLS: [(&str, &str); 6] = [
    ("stellar_pay_commit", "simulation.divergence"),
    ("stellar_claim_commit", "simulation.divergence"),
    ("stellar_create_account_commit", "simulation.divergence"),
    ("stellar_trustline_commit", "simulation.divergence"),
    (
        "stellar_x402_create_payment",
        "x402.invalid_payment_required",
    ),
    (
        "stellar_x402_create_authenticated_payment",
        "x402.invalid_payment_required",
    ),
];

/// Calls `tool` on `server` and returns its business-error code and message.
async fn call(server: &WalletServer, tool: &str) -> (String, String) {
    let commit = serde_json::json!({
        "chain_id": "stellar:mainnet",
        "nonce": "dGVzdA",
        "expires_at_unix_ms": u64::MAX,
        "envelope_xdr": "AAAA",
    });
    let with = |extra: serde_json::Value| {
        let mut value = commit.clone();
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        value
    };
    let result = match tool {
        "stellar_pay_commit" => {
            server
                .call_stellar_pay_commit(args::<StellarPayCommitArgs>(with(serde_json::json!({
                    "source": agent_g(),
                    "destination": agent_g(),
                    "amount": "1 XLM",
                    "asset": "native",
                }))))
                .await
        }
        "stellar_claim_commit" => {
            server
                .call_stellar_claim_commit(args::<StellarClaimCommitArgs>(with(
                    serde_json::json!({
                        "balance_id": "0".repeat(72),
                        "source_account": agent_g(),
                    }),
                )))
                .await
        }
        "stellar_create_account_commit" => {
            server
                .call_stellar_create_account_commit(args::<StellarCreateAccountCommitArgs>(with(
                    serde_json::json!({
                        "source": agent_g(),
                        "destination": agent_g(),
                        "starting_balance": "2 XLM",
                    }),
                )))
                .await
        }
        "stellar_trustline_commit" => {
            server
                .call_stellar_trustline_commit(args::<StellarTrustlineCommitArgs>(with(
                    serde_json::json!({ "from": agent_g() }),
                )))
                .await
        }
        "stellar_x402_create_payment" => {
            server
                .call_stellar_x402_create_payment(args::<X402CreatePaymentArgs>(
                    serde_json::json!({
                        "payment_required": "not a payment requirement",
                        "chain_id": "stellar:mainnet",
                    }),
                ))
                .await
        }
        "stellar_x402_create_authenticated_payment" => {
            server
                .call_stellar_x402_authenticated_payment(args::<X402AuthenticatedPaymentArgs>(
                    serde_json::json!({
                        "payment_required": "not a payment requirement",
                        "chain_id": "stellar:mainnet",
                        "home_domain": "anchor.example.invalid",
                    }),
                ))
                .await
        }
        _ => unreachable!("{tool}"),
    };
    refusal(&result.unwrap_or_else(|error| panic!("{tool}: {error:?}")))
}

/// With its oracle the enabled server admits each write tool, which then
/// refuses its malformed input with its own code. After the oracle URL and
/// its record leave the profile file, a restart refuses the enablement with
/// `on_disk_oracle_host` before any endpoint contact.
#[tokio::test]
#[serial]
async fn mainnet_oracle_required_refuses_write_tools_after_the_oracle_is_removed() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    assert!(
        home.path()
            .join(stellar_agent_test_support::sandbox::MARKER)
            .is_file(),
        "owned wallet root is marked before the home guard"
    );
    let _home = StellarAgentHomeGuard::new(home.path());
    let endpoint = ConnectionCounter::start().expect("loopback connection counter");
    let complete = complete_profile(home.path(), &endpoint.https_uri());
    keyring_mock::install().expect("mock keyring store init");
    enable(&complete);

    let server = start(&complete);
    for (tool, admitted) in TOOLS {
        let (code, message) = call(&server, tool).await;
        assert_eq!(code, admitted, "{tool} with its oracle: {message}");
    }
    drop(server);

    let mut removed = complete.clone();
    removed.oracle_provider_url = None;
    removed.providers.as_mut().unwrap().oracle = None;
    save_to_dir("operator", &removed, &default_profile_dir().unwrap()).unwrap();
    let connections = endpoint.accepted().expect("connection count");
    match build_selected_server(removed, ProfileNameSource::Flag, BindingCheck::Enforce) {
        Ok(_) => panic!("a profile without its signed oracle started with mainnet writes"),
        Err(error) => assert_eq!(
            error.to_string(),
            stellar_agent_core::policy::BuildRegistryError::PolicyEngineError {
                detail: stellar_agent_core::error::ValidationError::MainnetEnablementInvalid {
                    binding: "on_disk_oracle_host",
                }
                .to_string(),
            }
            .to_string()
        ),
    }
    assert_eq!(
        endpoint.accepted().expect("connection count"),
        connections,
        "no connection reaches the primary endpoint"
    );
}
