//! Live SEP-43 `signAuthEntry` interop with the released JavaScript SDK.
//!
//! The pinned `@stellar/stellar-sdk@17.2.0` driver in
//! `interop/stellar-sdk-v17/sign-roundtrip.mjs` simulates a native-asset
//! `transfer` from a fresh payer with `useUpgradedAuth`, so the testnet RPC
//! returns the payer's entry with CAP-71 `AddressV2` credentials, and hands the
//! wallet the envelope type 10 preimage the SDK's `authorizeEntry` signs over.
//! The wallet signs it through the SEP-43 `signAuthEntry` dispatch; the SDK
//! verifies the signature against the payer, assembles and submits the
//! transaction, and reports the credential type of the ledger's entry. A
//! second leg rewrites the preimage's address to another account and proves
//! the wallet refuses it without producing a signature. Network or runtime
//! unavailability is a failure, not a self-skip.

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "acceptance failures must stop with their violated invariant, and \
              the run prints the transaction hash as evidence"
)]

use std::{
    io::{BufRead as _, BufReader, Write as _},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{Receiver, RecvTimeoutError, channel},
    },
    thread,
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serial_test::serial;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::{
    WalletError, profile::caip2::TESTNET_PASSPHRASE, profile::schema::Profile,
};
use stellar_agent_network::{
    SoftwareSigningKey, fund_with_friendbot,
    signing::{Signer, WebAuthnAssertion},
};
use stellar_agent_sep43::{Sep43Error, module::sign_auth_entry::dispatch};
use stellar_xdr::{
    AccountId, HashIdPreimage, Limits, PublicKey, ReadXdr as _, ScAddress, Uint256, WriteXdr as _,
};

const RPC_URL: &str = "https://soroban-testnet.stellar.org";
const FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const NATIVE_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
/// Upper bound on one driver reply: a submit polls the ledger for up to a
/// minute, and simulation and submission are single RPC round trips.
const DRIVER_REPLY_TIMEOUT: Duration = Duration::from_secs(300);

fn harness_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../interop/stellar-sdk-v17")
        .canonicalize()
        .expect("interop harness directory")
}

fn prepare_harness(directory: &Path) {
    let node = Command::new("node")
        .args(["-p", "process.versions.node"])
        .output()
        .expect("Node 24.5.0 is installed");
    assert!(node.status.success(), "Node version probe failed");
    assert_eq!(
        String::from_utf8(node.stdout)
            .expect("Node version output")
            .trim(),
        "24.5.0",
        "acceptance must run on the frozen Node version"
    );
    let install = Command::new("corepack")
        .args(["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"])
        .current_dir(directory)
        .status()
        .expect("frozen pnpm install starts");
    assert!(install.success(), "frozen stellar-sdk install failed");
}

fn account_strkey(key: &SigningKey) -> String {
    stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes())
        .to_string()
        .as_str()
        .to_owned()
}

fn secret_strkey(key: &SigningKey) -> String {
    stellar_strkey::ed25519::PrivateKey::from_payload(&key.to_bytes())
        .expect("32-byte seed")
        .as_unredacted()
        .to_string()
        .as_str()
        .to_owned()
}

fn account_address(key: [u8; 32]) -> ScAddress {
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key))))
}

/// The SDK driver process and its line-delimited JSON channel.
struct Driver {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
}

impl Driver {
    fn start(directory: &Path, env: &[(&str, &str)]) -> Self {
        let mut command = Command::new("node");
        command
            .arg("sign-roundtrip.mjs")
            .current_dir(directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for (name, value) in env {
            command.env(name, value);
        }
        let mut child = command.spawn().expect("SDK driver starts");
        let stdin = child.stdin.take().expect("driver stdin");
        let stdout = child.stdout.take().expect("driver stdout");
        let (sender, lines) = channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let mut driver = Self {
            child,
            stdin,
            lines,
        };
        let ready = driver.read_reply();
        assert_eq!(ready["ready"], serde_json::Value::Bool(true), "{ready}");
        driver
    }

    fn read_reply(&mut self) -> serde_json::Value {
        let line = match self.lines.recv_timeout(DRIVER_REPLY_TIMEOUT) {
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => panic!("SDK driver did not reply in time"),
            Err(RecvTimeoutError::Disconnected) => panic!("SDK driver exited without a reply"),
        };
        println!("sdk-driver: {line}");
        let reply: serde_json::Value = serde_json::from_str(&line).expect("driver reply is JSON");
        if let Some(error) = reply.get("error") {
            panic!("SDK driver error: {error}");
        }
        reply
    }

    fn request(&mut self, request: &serde_json::Value) -> serde_json::Value {
        writeln!(self.stdin, "{request}").expect("driver stdin write");
        self.stdin.flush().expect("driver stdin flush");
        self.read_reply()
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Delegating signer that counts every signature request, so the refusal leg
/// can prove it produced no signature.
struct CountingSigner {
    inner: SoftwareSigningKey,
    signatures: AtomicUsize,
}

impl CountingSigner {
    fn new(inner: SoftwareSigningKey) -> Self {
        Self {
            inner,
            signatures: AtomicUsize::new(0),
        }
    }

    fn signature_count(&self) -> usize {
        self.signatures.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Signer for CountingSigner {
    async fn sign_tx_payload(&self, payload: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        self.signatures.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_tx_payload(payload).await
    }

    async fn sign_auth_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        self.signatures.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_auth_digest(digest).await
    }

    async fn sign_soroban_address_auth_payload(
        &self,
        payload: &[u8; 32],
    ) -> Result<[u8; 64], WalletError> {
        self.signatures.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_soroban_address_auth_payload(payload).await
    }

    async fn sign_webauthn_assertion(
        &self,
        auth_digest: &[u8; 32],
        credential_id: &[u8],
    ) -> Result<WebAuthnAssertion, WalletError> {
        self.signatures.fetch_add(1, Ordering::SeqCst);
        self.inner
            .sign_webauthn_assertion(auth_digest, credential_id)
            .await
    }

    async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
        self.inner.public_key().await
    }
}

/// Decodes a `prepare` reply's preimage, checks the SDK's payload is its hash,
/// and returns the type 10 preimage.
fn prepared_preimage(prepared: &serde_json::Value) -> HashIdPreimage {
    assert_eq!(
        prepared["credentialType"], "address_v2",
        "the testnet RPC must record AddressV2 credentials for useUpgradedAuth"
    );
    let preimage_b64 = prepared["preimageXdr"].as_str().expect("preimageXdr");
    let preimage_bytes = STANDARD.decode(preimage_b64).expect("preimage base64");
    assert_eq!(
        prepared["payloadHex"].as_str().expect("payloadHex"),
        Sha256::digest(&preimage_bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "the SDK payload is the SHA-256 of the preimage bytes"
    );
    HashIdPreimage::from_xdr(&preimage_bytes, Limits::none()).expect("preimage decodes")
}

#[tokio::test]
#[serial]
async fn sdk_v17_address_v2_entry_signed_through_sep43_settles_on_testnet() {
    let harness = harness_dir();
    prepare_harness(&harness);

    let payer_key = SigningKey::generate(&mut OsRng);
    let source_key = SigningKey::generate(&mut OsRng);
    let payer = account_strkey(&payer_key);
    let source = account_strkey(&source_key);
    for account in [&payer, &source] {
        fund_with_friendbot(FRIENDBOT_URL, account, TESTNET_PASSPHRASE, RPC_URL)
            .await
            .expect("Friendbot funding reaches RPC");
    }

    let signer = CountingSigner::new(SoftwareSigningKey::new_from_bytes(payer_key.to_bytes()));
    let profile =
        Profile::builder_testnet("svc", payer.as_str(), "nonce-svc", "nonce-acct").build();
    let source_secret = secret_strkey(&source_key);
    // The source account receives the transfer: it exists, and it differs from
    // the payer, so the payer's authorization surfaces as an address entry.
    let mut driver = Driver::start(
        &harness,
        &[
            ("SDK_RPC_URL", RPC_URL),
            ("SDK_NETWORK_PASSPHRASE", TESTNET_PASSPHRASE),
            ("SDK_SOURCE_SECRET", source_secret.as_str()),
            ("SDK_PAYER_ADDRESS", payer.as_str()),
            ("SDK_CONTRACT", NATIVE_SAC_TESTNET),
            ("SDK_RECIPIENT", source.as_str()),
        ],
    );

    // Accepted leg: the SDK's type 10 preimage, bound to the payer.
    let prepared = driver.request(&serde_json::json!({ "cmd": "prepare" }));
    let HashIdPreimage::SorobanAuthorizationWithAddress(with_address) =
        prepared_preimage(&prepared)
    else {
        panic!("the SDK must hand the wallet an envelope type 10 preimage");
    };
    assert_eq!(
        with_address.address,
        account_address(payer_key.verifying_key().to_bytes()),
        "the preimage is bound to the payer"
    );

    let signed = dispatch(
        &profile,
        &signer,
        prepared["preimageXdr"].as_str().expect("preimageXdr"),
        Some(TESTNET_PASSPHRASE),
        Some(payer.as_str()),
    )
    .await
    .expect("SEP-43 signs the SDK's type 10 preimage for the payer");
    assert_eq!(signed["signerAddress"], payer.as_str());
    assert_eq!(signer.signature_count(), 1);

    let settled = driver.request(&serde_json::json!({
        "cmd": "assemble",
        "signatureBase64": signed["signedAuthEntry"],
    }));
    assert_eq!(settled["status"], "SUCCESS", "{settled}");
    assert_eq!(
        settled["credentialType"], "address_v2",
        "the ledger entry keeps AddressV2 credentials"
    );
    let hash = settled["hash"].as_str().expect("hash");
    assert!(
        hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "transaction hash is 64 hex characters: {hash}"
    );
    println!("sep43 v17 interop transaction hash: {hash}");

    // Refused leg: the same SDK preimage rebound to another account.
    let prepared = driver.request(&serde_json::json!({ "cmd": "prepare" }));
    let HashIdPreimage::SorobanAuthorizationWithAddress(mut rebound) = prepared_preimage(&prepared)
    else {
        panic!("the SDK must hand the wallet an envelope type 10 preimage");
    };
    rebound.address = account_address(SigningKey::generate(&mut OsRng).verifying_key().to_bytes());
    let rebound_b64 = HashIdPreimage::SorobanAuthorizationWithAddress(rebound)
        .to_xdr_base64(Limits::none())
        .expect("rebound preimage encodes");
    let signatures_before = signer.signature_count();
    let error = dispatch(
        &profile,
        &signer,
        &rebound_b64,
        Some(TESTNET_PASSPHRASE),
        None,
    )
    .await
    .expect_err("a preimage bound to another account must be refused");
    assert!(
        matches!(error, Sep43Error::InvalidAddress { .. }),
        "got: {error:?}"
    );
    assert_eq!(error.wire_code(), "sep43.invalid_address");
    assert_eq!(
        signer.signature_count(),
        signatures_before,
        "the refused preimage produced no signature"
    );
}
