//! A toolset payment commit through the shared payment handler, off mainnet.
//!
//! The commit carries a toolset context built from a real gated resolution:
//! the outer gate's outcome composes with the routed rule, a composed
//! approval requirement queues before any nonce or send, and the grant lease
//! holds off every grant and installation writer until submission returns.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test assertions"
)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::json;
use serial_test::serial;
use stellar_agent_core::approval::{
    ApprovalError, ApprovalKind, AttestationBinding, PendingApproval, PendingApprovalStore,
    ToolsetGrantStore, process_uid_for_attestation,
};
use stellar_agent_core::policy::v1::{
    AccountIdentityView, AccountReservesView, CounterpartyCacheView, Sep10SessionView,
    Sep45SessionView,
};
use stellar_agent_core::policy::{
    ApprovalRequest, Decision, DenyReason, PolicyEngine, PolicyError, ToolDescriptor,
};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_core::timefmt::now_unix_ms;
use stellar_agent_mcp::server::{StellarPayCommitArgs, StellarToolsetInvokeArgs, WalletServer};
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_seq, account_ledger_key_xdr,
};
use stellar_agent_toolsets_install::{ToolsetInstallError, lock_toolsets};
use stellar_agent_toolsets_runtime::{
    GatedInvokeParams, GatedResolveOutcome, ToolsetRuntimeError, record_first_invoke_grant,
    resolve_toolset_sign_payment_gated,
};
use tempfile::TempDir;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

const TOOLSET: &str = "context-pay-toolset";
const ACTION: &str = "stellar_pay_commit";
const INSTALL_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHASUM: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
const AMOUNT: i64 = 10_000_000;
const KEY: [u8; 32] = [0x42; 32];

/// Answers each tool with its configured decision, `Allow` otherwise, and
/// records every evaluated tool name and its arguments.
#[derive(Clone, Default)]
struct PerToolEngine {
    decisions: Arc<Mutex<HashMap<&'static str, Decision>>>,
    evaluated: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
}

impl PerToolEngine {
    fn decide(&self, tool: &'static str, decision: Decision) {
        self.decisions.lock().unwrap().insert(tool, decision);
    }

    fn arguments_for(&self, tool: &str) -> Vec<serde_json::Value> {
        self.evaluated
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| name == tool)
            .map(|(_, args)| args.clone())
            .collect()
    }

    fn evaluations(&self) -> Vec<String> {
        self.evaluated
            .lock()
            .unwrap()
            .iter()
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn clear(&self) {
        self.evaluated.lock().unwrap().clear();
    }
}

impl PolicyEngine for PerToolEngine {
    fn record_confirmed_checked(
        &self,
        tool: &ToolDescriptor,
        profile: &Profile,
        value: &stellar_agent_core::policy::v1::ValueClass,
    ) -> Result<stellar_agent_core::policy::v1::SizingOutcome, PolicyError> {
        stellar_agent_core::policy::NoopPolicyEngine.record_confirmed_checked(tool, profile, value)
    }
    fn size_unvalued_call(
        &self,
        tool: &ToolDescriptor,
        profile: &Profile,
        reason: stellar_agent_core::policy::v1::OpaqueReason,
        now_ms: u64,
    ) -> Result<stellar_agent_core::policy::v1::SizingOutcome, PolicyError> {
        stellar_agent_core::policy::NoopPolicyEngine
            .size_unvalued_call(tool, profile, reason, now_ms)
    }
    fn size_no_value(
        &self,
        tool: &ToolDescriptor,
        profile: &Profile,
        now_ms: u64,
    ) -> Result<stellar_agent_core::policy::v1::CheckedSizing, PolicyError> {
        stellar_agent_core::policy::NoopPolicyEngine.size_no_value(tool, profile, now_ms)
    }
    fn evaluate(
        &self,
        tool: &ToolDescriptor,
        args: &serde_json::Value,
        _profile: &Profile,
        _account_view: Option<&dyn AccountReservesView>,
        _identity_view: Option<&dyn AccountIdentityView>,
        _counterparty_cache: Option<&dyn CounterpartyCacheView>,
        _sep10_sessions: Option<&dyn Sep10SessionView>,
        _sep45_sessions: Option<&dyn Sep45SessionView>,
        _now_ms: u64,
    ) -> Result<Decision, PolicyError> {
        self.evaluated
            .lock()
            .unwrap()
            .push((tool.name.clone(), args.clone()));
        Ok(self
            .decisions
            .lock()
            .unwrap()
            .get(tool.name.as_str())
            .cloned()
            .unwrap_or(Decision::Allow))
    }
}

fn approval(reason: &str, ttl_seconds: u32) -> Decision {
    let mut request = ApprovalRequest::new(String::new(), ttl_seconds);
    request.reason = Some(reason.to_owned());
    Decision::RequireApproval(request)
}

/// Toolset writers run in a peer process while submission holds the lease.
struct Writers {
    name: String,
    root: PathBuf,
    grants: PathBuf,
    home: PathBuf,
    peer: Mutex<Option<LockPeer>>,
    before: Mutex<Vec<Vec<u8>>>,
    /// Per send: whether the peer's writers refused, and whether the grant
    /// bytes stayed unchanged.
    seen: Mutex<Vec<[bool; 2]>>,
}

impl Writers {
    fn bytes(&self) -> Vec<Vec<u8>> {
        let mut files: Vec<PathBuf> = match std::fs::read_dir(self.root.join(TOOLSET)) {
            Ok(entries) => entries.map(|entry| entry.unwrap().path()).collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("cannot inspect the retained installation: {error}"),
        };
        files.sort();
        files.push(self.grants.clone());
        files
            .iter()
            .map(|file| std::fs::read(file).unwrap_or_default())
            .collect()
    }

    fn record_grant(&self, destination: &str) -> Result<(), ToolsetRuntimeError> {
        grant(
            &self.name,
            &self.grants,
            destination,
            now_unix_ms().unwrap(),
        )
    }

    fn revoke(&self) -> Result<usize, ApprovalError> {
        ToolsetGrantStore::open(self.grants.clone(), now_unix_ms().unwrap())
            .and_then(|mut store| store.revoke_toolset(TOOLSET))
    }

    /// Waits for the peer's writer refusals before the RPC answers the send.
    fn attempt(&self) {
        let mut peer = LockPeer::spawn("writers", self);
        let refused = peer.wait_for("refused");
        let unchanged = self.bytes() == *self.before.lock().unwrap();
        self.seen.lock().unwrap().push([refused, unchanged]);
        *self.peer.lock().unwrap() = Some(peer);
    }
}

struct LockPeer {
    child: std::process::Child,
    stdout: std::io::BufReader<std::process::ChildStdout>,
}

impl LockPeer {
    fn spawn(role: &str, writers: &Writers) -> Self {
        use std::process::{Command, Stdio};
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "toolset_payment_context::lease_holds_toolset_writers_off_until_submission_returns",
                "--nocapture",
            ])
            .env("PAYMENT_LOCK_ROLE", role)
            .env("PAYMENT_LOCK_ROOT", &writers.root)
            .env("PAYMENT_LOCK_GRANTS", &writers.grants)
            .env("PAYMENT_LOCK_PROFILE", &writers.name)
            .env("STELLAR_AGENT_HOME", &writers.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        Self { child, stdout }
    }

    fn wait_for(&mut self, marker: &str) -> bool {
        use std::io::BufRead as _;
        loop {
            let mut line = String::new();
            if self.stdout.read_line(&mut line).unwrap() == 0 {
                return false;
            }
            if line.trim() == marker {
                return true;
            }
        }
    }

    fn release(&mut self) {
        use std::io::Write as _;
        self.child.stdin.as_mut().unwrap().write_all(b"1").unwrap();
        self.child.stdin.as_mut().unwrap().flush().unwrap();
    }

    fn finish(&mut self) {
        use std::io::Read as _;
        drop(self.child.stdin.take());
        let mut errors = String::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut errors)
            .unwrap();
        assert!(
            self.child.wait().unwrap().success(),
            "peer failed: {errors}"
        );
    }
}

#[allow(clippy::print_stdout, reason = "child-process handshake protocol")]
fn signal_and_wait(marker: &str) {
    use std::io::{Read as _, Write as _};
    println!("{marker}");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_exact(&mut [0]).unwrap();
}

fn reinstall(root: &Path) -> Result<(), ToolsetInstallError> {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let lock = lock_toolsets(root)?;
    // A deterministic tar.gz containing the fixture's payment manifest.
    let package = base64::engine::general_purpose::STANDARD.decode("H4sIAAAAAAACA+3SsU4DMQwG4Mx5iryAy5UrHW5E6obUgb6AyVlVpLskio1E3560EgywMCAW/m9xZMuxB8eSTd6MKl/ISllU7O50PD49H06bdXa/Yuj2u90tdl/jcL8dP9+3/HYcH/YuDO4PvKpx6+Pd/0REPvMqU4jfL8HPorGlaqnkKfTCKtmCiZpfxXhm48mHoCbLwo343MsUufJLWpIl0SloOmf66Kyt1KJC1jgrx+u3/rrAY5kvG+8AAAAAAAAAAAAAAAAAAAAAAADg594B5+fN7gAoAAA=").unwrap();
    let hash = stellar_agent_toolsets_install::sha256_hex_of(&package);
    let signer = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
    let publisher = signer.verifying_key().to_bytes();
    let signature = signer
        .sign(&stellar_agent_toolsets_install::signature::build_preimage(
            TOOLSET, "1.0.0", &hash,
        ))
        .to_bytes();
    std::fs::write(
        root.join("trust.txt"),
        stellar_strkey::ed25519::PublicKey(publisher).to_string(),
    )
    .unwrap();
    std::fs::write(root.join("auditor-trust.txt"), "").unwrap();
    stellar_agent_toolsets_install::install_toolset(
        TOOLSET,
        "1.0.0",
        &package,
        &hash,
        &signature,
        &publisher,
        root,
        &root.join("trust.txt"),
        None,
        &root.join("auditor-trust.txt"),
        &stellar_agent_toolsets_install::InstallOptions {
            force: true,
            override_attestation: true,
            ..Default::default()
        },
        &lock,
        &crate::common::toolset_pin_key(),
    )
    .map(drop)
}

fn uninstall(root: &Path) -> Result<(), ToolsetInstallError> {
    let lock = lock_toolsets(root)?;
    stellar_agent_toolsets_install::uninstall_toolset(TOOLSET, root, &lock)
}

fn lock_child(role: &str) {
    let root = PathBuf::from(std::env::var_os("PAYMENT_LOCK_ROOT").unwrap());
    let grants = PathBuf::from(std::env::var_os("PAYMENT_LOCK_GRANTS").unwrap());
    let name = std::env::var("PAYMENT_LOCK_PROFILE").unwrap();
    if role == "writers" {
        assert!(
            matches!(
                grant(&name, &grants, SECOND_DEST, now_unix_ms().unwrap()),
                Err(ToolsetRuntimeError::CoordinationBusy)
            ),
            "grant insertion must refuse while the lease is held"
        );
        assert!(
            matches!(
                ToolsetGrantStore::open(grants.clone(), now_unix_ms().unwrap()),
                Err(ApprovalError::WriterLocked)
            ),
            "grant revocation must refuse while the lease is held"
        );
        assert!(
            matches!(reinstall(&root), Err(ToolsetInstallError::Busy)),
            "force reinstall must refuse while the lease is held"
        );
        assert!(
            matches!(uninstall(&root), Err(ToolsetInstallError::Busy)),
            "uninstall must refuse while the lease is held"
        );
        signal_and_wait("refused");
        grant(&name, &grants, SECOND_DEST, now_unix_ms().unwrap()).unwrap();
        assert_eq!(
            ToolsetGrantStore::open(grants, now_unix_ms().unwrap())
                .unwrap()
                .revoke_toolset(TOOLSET)
                .unwrap(),
            2
        );
        reinstall(&root).unwrap();
        uninstall(&root).unwrap();
    } else if role == "root" {
        let _lock = lock_toolsets(&root).unwrap();
        signal_and_wait("locked");
        std::process::exit(0);
    } else {
        assert_eq!(role, "lease");
        let pin = crate::common::toolset_pin_key();
        let binding = AttestationBinding::new(&name, "stellar:testnet");
        let GatedResolveOutcome::Resolved { grant, .. } =
            resolve_toolset_sign_payment_gated(&GatedInvokeParams {
                toolset_name: TOOLSET,
                action: ACTION,
                toolsets_root: &root,
                profile_name: &name,
                attestation_key: &KEY,
                attestation_binding: &binding,
                authoritative_destination: DEST_G,
                authoritative_asset: "XLM",
                authoritative_amount_stroops: AMOUNT,
                now_unix_ms: now_unix_ms().unwrap(),
                process_uid: &process_uid_for_attestation().unwrap(),
                pin_key: Some(&pin),
                approval_dir_override: Some(root.join("approvals")),
                grant_store_path_override: Some(grants.clone()),
            })
            .unwrap()
        else {
            panic!("child needs a verified grant")
        };
        let _lease = stellar_agent_toolsets_runtime::acquire_toolset_grant_lease(
            &grant,
            &stellar_agent_toolsets_runtime::GrantRecheckParams {
                toolset_name: TOOLSET,
                action: ACTION,
                toolsets_root: &root,
                profile_name: &name,
                attestation_key: &KEY,
                attestation_binding: &binding,
                authoritative_destination: DEST_G,
                authoritative_asset: "XLM",
                authoritative_amount_stroops: AMOUNT,
                pin_key: Some(&pin),
                grant_store_path_override: Some(grants),
            },
        )
        .unwrap();
        signal_and_wait("leased");
        std::process::exit(0);
    }
}

const SECOND_DEST: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

/// The suite's RPC answers, trying the writers inside each send when armed.
struct WriterRpc {
    inner: crate::common::TimeoutRpc,
    writers: Arc<Mutex<Option<Arc<Writers>>>>,
}

impl Respond for WriterRpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
        if body["method"] == "sendTransaction"
            && let Some(writers) = self.writers.lock().unwrap().clone()
        {
            writers.attempt();
        }
        self.inner.respond(request)
    }
}

fn grant(
    name: &str,
    grants: &Path,
    destination: &str,
    now_ms: u64,
) -> Result<(), ToolsetRuntimeError> {
    record_first_invoke_grant(
        name,
        TOOLSET,
        INSTALL_ID,
        "1.0.0",
        SHASUM,
        "sign-payment",
        destination,
        "XLM",
        0,
        i64::MAX,
        &process_uid_for_attestation().unwrap(),
        now_ms,
        &KEY,
        &AttestationBinding::new(name, "stellar:testnet"),
        Some(grants.to_path_buf()),
    )
    .map(drop)
}

/// The M address of `base` with mux ID `id`.
fn muxed(base: &str, id: u64) -> String {
    stellar_strkey::Strkey::MuxedAccountEd25519(stellar_strkey::ed25519::MuxedAccount {
        ed25519: stellar_strkey::ed25519::PublicKey::from_string(base)
            .unwrap()
            .0,
        id,
    })
    .to_string()
    .as_str()
    .to_owned()
}

/// One profile's server with an installed toolset, a recorded grant for
/// [`DEST_G`], and an RPC endpoint that confirms every send.
struct Harness {
    name: String,
    server: WalletServer,
    engine: PerToolEngine,
    profile: Profile,
    source: String,
    rpc: MockServer,
    approval: TempDir,
    grants: PathBuf,
    toolsets: TempDir,
    writers: Arc<Mutex<Option<Arc<Writers>>>>,
    nonce_lease_seen: Arc<Mutex<Vec<bool>>>,
    _grant_dir: TempDir,
    _home: stellar_agent_test_support::StellarAgentHomeGuard,
    _sandbox: stellar_agent_test_support::sandbox::StateSandbox,
}

impl Harness {
    async fn new(name: &str) -> Self {
        Self::build(name, false).await
    }

    async fn build(name: &str, recovery_policy: bool) -> Self {
        use base64::Engine as _;
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let writers: Arc<Mutex<Option<Arc<Writers>>>> = Arc::new(Mutex::new(None));
        let nonce_lease_seen = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&nonce_lease_seen);
        let during_nonce = Arc::clone(&writers);
        stellar_agent_test_support::keyring_mock::install_with_read_hooks(vec![
            stellar_agent_test_support::keyring_mock::ReadHook::new(
                "n-svc",
                "n-acct",
                Arc::new(move || {
                    if let Some(writers) = during_nonce.lock().unwrap().as_ref() {
                        let locked = matches!(writers.revoke(), Err(ApprovalError::WriterLocked));
                        let unchanged = writers.bytes() == *writers.before.lock().unwrap();
                        observed.lock().unwrap().push(locked && unchanged);
                    }
                }),
            ),
        ])
        .unwrap();
        keyring_core::Entry::new("n-svc", "n-acct")
            .unwrap()
            .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(KEY))
            .unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[0x61; 32]);
        let source = stellar_strkey::ed25519::PublicKey(signer.verifying_key().to_bytes())
            .to_string()
            .to_string();
        keyring_core::Entry::new("svc", name)
            .unwrap()
            .set_password(
                stellar_strkey::ed25519::PrivateKey(signer.to_bytes())
                    .as_unredacted()
                    .to_string()
                    .as_ref(),
            )
            .unwrap();
        crate::common::store_signer_identity("svc", name, [0x61; 32]);
        let rpc = MockServer::start().await;
        let base = SECOND_DEST;
        Mock::given(method("POST"))
            .respond_with(WriterRpc {
                inner: crate::common::TimeoutRpc::new(vec![
                    (
                        account_ledger_key_xdr(&source),
                        account_entry_xdr_with_seq(&source, 1_000_000_000, 0, 42),
                    ),
                    (
                        account_ledger_key_xdr(DEST_G),
                        account_entry_xdr_with_seq(DEST_G, 1_000_000_000, 0, 42),
                    ),
                    (
                        account_ledger_key_xdr(base),
                        account_entry_xdr_with_seq(base, 1_000_000_000, 0, 42),
                    ),
                ])
                .confirming_in(1001),
                writers: Arc::clone(&writers),
            })
            .mount(&rpc)
            .await;
        let mut profile = crate::common::timeout_profile(&rpc.uri(), name);
        profile.submit_timeout_seconds = Some(30);
        keyring_core::Entry::new(
            &profile.attestation_key_id.service,
            &profile.attestation_key_id.account,
        )
        .unwrap()
        .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(KEY))
        .unwrap();
        let approval = TempDir::new().unwrap();
        let grant_dir = TempDir::new().unwrap();
        let grants = grant_dir.path().join("grants.toml");
        let toolsets = TempDir::new().unwrap();
        stellar_agent_toolsets_install::write_toolset_for_test(
            toolsets.path(),
            TOOLSET,
            &["sign-payment", "propose-transaction"],
            &[],
            "2026-06-02T00:00:00Z",
            INSTALL_ID,
            &crate::common::toolset_pin_key(),
        )
        .unwrap();
        grant(name, &grants, DEST_G, now_unix_ms().unwrap()).unwrap();
        let engine = PerToolEngine::default();
        let mut server = WalletServer::new(profile.clone()).unwrap();
        server.set_policy_engine_for_test(Arc::new(engine.clone()));
        if recovery_policy {
            server.set_payment_recovery_policy_for_test(crate::common::payment_recovery_policy(
                &server,
            ));
        }
        server.set_approval_dir_for_test(approval.path().to_path_buf());
        server.set_grant_store_path_for_test(grants.clone());
        server.set_toolsets_root_for_test(toolsets.path().to_path_buf());
        server.set_toolset_pin_key_for_test(crate::common::toolset_pin_key());
        Self {
            name: name.to_owned(),
            server,
            engine,
            profile,
            source,
            rpc,
            approval,
            grants,
            toolsets,
            writers,
            nonce_lease_seen,
            _grant_dir: grant_dir,
            _home: home,
            _sandbox: sandbox,
        }
    }

    /// Prepares a native payment of `amount` to `destination` through the
    /// direct preparation and returns its data.
    async fn prepare(&self, destination: &str, amount: i64) -> serde_json::Value {
        let result = self
            .server
            .call_stellar_pay(
                serde_json::from_value(json!({
                    "chain_id": "stellar:testnet", "source": self.source,
                    "destination": destination, "asset": "native",
                    "amount_in_stroops": amount.to_string(),
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
        assert_eq!(body["ok"], true, "{body}");
        body["data"].clone()
    }

    fn commit_args(
        &self,
        data: &serde_json::Value,
        destination: &str,
        amount: i64,
    ) -> serde_json::Value {
        json!({
            "chain_id": "stellar:testnet", "source": self.source, "destination": destination,
            "asset": "native", "amount_in_stroops": amount.to_string(),
            "nonce": data["nonce"], "expires_at_unix_ms": data["expires_at_unix_ms"],
            "envelope_xdr": data["envelope_xdr"],
        })
    }

    fn invoke(&self, args: &serde_json::Value) -> StellarToolsetInvokeArgs {
        StellarToolsetInvokeArgs {
            toolset: TOOLSET.into(),
            action: ACTION.into(),
            chain_id: Some("stellar:testnet".into()),
            args: args.clone(),
        }
    }

    /// The gated resolver's outcome for a payment of `amount` to
    /// `destination`, read at `now_ms`.
    fn resolve_at(&self, destination: &str, amount: i64, now_ms: u64) -> GatedResolveOutcome {
        let pin = crate::common::toolset_pin_key();
        let uid = process_uid_for_attestation().unwrap();
        resolve_toolset_sign_payment_gated(&GatedInvokeParams {
            toolset_name: TOOLSET,
            action: ACTION,
            toolsets_root: self.toolsets.path(),
            profile_name: &self.name,
            attestation_key: &KEY,
            attestation_binding: &AttestationBinding::new(&self.name, "stellar:testnet"),
            authoritative_destination: destination,
            authoritative_asset: "XLM",
            authoritative_amount_stroops: amount,
            now_unix_ms: now_ms,
            process_uid: &uid,
            pin_key: Some(&pin),
            approval_dir_override: Some(self.approval.path().to_path_buf()),
            grant_store_path_override: Some(self.grants.clone()),
        })
        .unwrap()
    }

    fn resolve(&self, destination: &str, amount: i64) -> GatedResolveOutcome {
        self.resolve_at(destination, amount, now_unix_ms().unwrap())
    }

    /// Commits `args` through the toolset context of `resolved`.
    async fn commit_with(
        &self,
        args: &serde_json::Value,
        resolved: GatedResolveOutcome,
    ) -> serde_json::Value {
        let result = self
            .server
            .call_stellar_pay_commit_in_toolset(
                &self.invoke(args),
                resolved,
                serde_json::from_value::<StellarPayCommitArgs>(args.clone()).unwrap(),
            )
            .await
            .unwrap();
        serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap()
    }

    /// Commits `args` for `destination` and `amount` through a fresh
    /// resolution of that invocation.
    async fn commit(
        &self,
        args: &serde_json::Value,
        destination: &str,
        amount: i64,
    ) -> serde_json::Value {
        self.commit_with(args, self.resolve(destination, amount))
            .await
    }

    async fn direct_commit(&self, args: &serde_json::Value) -> serde_json::Value {
        let result = self
            .server
            .call_stellar_pay_commit(serde_json::from_value(args.clone()).unwrap())
            .await
            .unwrap();
        serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap()
    }

    async fn protocol_commit(&self, args: &serde_json::Value) -> serde_json::Value {
        let mut client = super::proof_rows::ProofClient::connect(self.server.clone()).await;
        let response = client
            .request(
                "tools/call",
                json!({
                    "name": "stellar_toolset_invoke",
                    "arguments": {
                        "toolset": TOOLSET, "action": ACTION,
                        "chain_id": "stellar:testnet", "args": args,
                    },
                }),
            )
            .await;
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("payment response: {response}"));
        serde_json::from_str(text).unwrap()
    }

    fn pending(&self) -> Vec<PendingApproval> {
        let path = self.approval.path().join(format!("{}.toml", self.name));
        if !path.exists() {
            return Vec::new();
        }
        let store = PendingApprovalStore::open(path).unwrap();
        store
            .snapshot(now_unix_ms().unwrap())
            .iter()
            .filter_map(|view| store.get(&view.approval_nonce).cloned())
            .collect()
    }

    /// Attests the queued approval `nonce` for `envelope` and returns the
    /// encoded attestation.
    fn attest(&self, nonce: &str, envelope: &str) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use stellar_agent_core::approval::attestation::{compute_attestation_v4, envelope_sha256};
        let mut store =
            PendingApprovalStore::open(self.approval.path().join(format!("{}.toml", self.name)))
                .unwrap();
        let stored = store.get(nonce).unwrap().clone();
        let blob = compute_attestation_v4(
            &KEY,
            &AttestationBinding::new(&self.name, "stellar:testnet"),
            nonce,
            &envelope_sha256(envelope.as_bytes()),
            &process_uid_for_attestation().unwrap(),
            &stored.attested_lifetime(),
            &stellar_agent_core::approval::AttestedApprover::Local,
        );
        store
            .record_attestation(
                nonce,
                blob,
                stellar_agent_core::approval::AttestedApprover::Local,
            )
            .unwrap();
        URL_SAFE_NO_PAD.encode(blob)
    }

    async fn sends(&self) -> usize {
        self.rpc
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| {
                serde_json::from_slice::<serde_json::Value>(&request.body)
                    .is_ok_and(|body| body["method"] == "sendTransaction")
            })
            .count()
    }

    fn arm_writers(&self) -> Arc<Writers> {
        let writers = Arc::new(Writers {
            name: self.name.clone(),
            root: self.toolsets.path().to_path_buf(),
            grants: self.grants.clone(),
            home: self._sandbox.path().to_path_buf(),
            peer: Mutex::new(None),
            before: Mutex::new(Vec::new()),
            seen: Mutex::new(Vec::new()),
        });
        *writers.before.lock().unwrap() = writers.bytes();
        *self.writers.lock().unwrap() = Some(Arc::clone(&writers));
        writers
    }

    fn audit_decisions(&self) -> Vec<serde_json::Value> {
        crate::common::rows_of_kind(
            &crate::common::audit_rows(&self.profile),
            "value_action_pending",
        )
        .iter()
        .map(|row| row["policy_decision"].clone())
        .collect()
    }
}

fn code(body: &serde_json::Value) -> &str {
    body["error"]["code"].as_str().unwrap_or("")
}

/// A context binds the exact invocation it was resolved for: a G grant
/// covers the G, M0, and M`u64::MAX` spellings as distinct leases, and a
/// context resolved for one spelling refuses another's envelope with
/// `toolset.grant_invocation_mismatch` before its nonce is consumed.
#[tokio::test]
#[serial]
async fn context_binds_the_exact_resolved_invocation() {
    let h = Harness::new("context-exact").await;
    let m0 = muxed(DEST_G, 0);
    let mmax = muxed(DEST_G, u64::MAX);
    let prepared = h.prepare(&m0, AMOUNT).await;
    let args = h.commit_args(&prepared, &m0, AMOUNT);
    let refused = h.commit_with(&args, h.resolve(DEST_G, AMOUNT)).await;
    assert_eq!(
        code(&refused),
        "toolset.grant_invocation_mismatch",
        "{refused}"
    );
    let refused = h.commit_with(&args, h.resolve(&mmax, AMOUNT)).await;
    assert_eq!(
        code(&refused),
        "toolset.grant_invocation_mismatch",
        "{refused}"
    );
    assert_eq!(h.sends().await, 0);
    for destination in [m0.as_str(), mmax.as_str(), DEST_G] {
        let prepared = h.prepare(destination, AMOUNT).await;
        let args = h.commit_args(&prepared, destination, AMOUNT);
        let committed = h.commit(&args, destination, AMOUNT).await;
        assert_eq!(committed["ok"], true, "{destination}: {committed}");
    }
    assert_eq!(h.sends().await, 3);
}

/// A context commit leaves no state that changes a later direct commit: its
/// decision, evaluations, audit decision, and absence of a queued approval
/// equal a fresh server's.
#[tokio::test]
#[serial]
async fn direct_commit_after_a_context_commit_equals_a_fresh_server() {
    async fn direct_run(h: &Harness) -> (serde_json::Value, Vec<String>, usize) {
        let prepared = h.prepare(DEST_G, AMOUNT + 1).await;
        let args = h.commit_args(&prepared, DEST_G, AMOUNT + 1);
        h.engine.clear();
        let body = h.direct_commit(&args).await;
        (
            json!({ "ok": body["ok"], "code": code(&body) }),
            h.engine.evaluations(),
            h.pending().len(),
        )
    }
    let used = Harness::new("context-then-direct").await;
    let prepared = used.prepare(DEST_G, AMOUNT).await;
    let args = used.commit_args(&prepared, DEST_G, AMOUNT);
    assert_eq!(used.commit(&args, DEST_G, AMOUNT).await["ok"], true);
    let after_context = direct_run(&used).await;
    let fresh = Harness::new("direct-fresh").await;
    assert_eq!(after_context, direct_run(&fresh).await);
    assert_eq!(
        after_context,
        (
            json!({ "ok": true, "code": "" }),
            vec!["stellar_pay_commit".to_owned()],
            0
        )
    );
    assert_eq!(used.audit_decisions(), vec![json!("allow"), json!("allow")]);
    assert_eq!(fresh.audit_decisions(), vec![json!("allow")]);

    // A direct commit that requires approval queues nothing, with or without
    // an earlier context commit.
    for h in [&used, &fresh] {
        let prepared = h.prepare(DEST_G, AMOUNT + 2).await;
        let args = h.commit_args(&prepared, DEST_G, AMOUNT + 2);
        h.engine
            .decide("stellar_pay_commit", approval("routed", 600));
        let body = h.direct_commit(&args).await;
        assert_eq!(code(&body), "policy.approval_required", "{body}");
        assert!(h.pending().is_empty(), "{}", h.name);
        h.engine.decide("stellar_pay_commit", Decision::Allow);
    }
}

/// Off mainnet the outer gate's own outcome takes part: an outer approval
/// requirement over a routed `Allow` queues the outer rule's request, and an
/// outer `Allow` submits once without approval. The outer rule evaluates
/// once, at the outer gate, over the raw names.
#[tokio::test]
#[serial]
async fn carried_outer_outcome_governs_off_mainnet() {
    for required in [true, false] {
        let h = Harness::new(if required {
            "carried-proposal-approval"
        } else {
            "carried-proposal-allow"
        })
        .await;
        if required {
            h.engine
                .decide("stellar_toolset_invoke", approval("outer-proposal", 300));
        }
        let grant_bytes = std::fs::read(&h.grants).unwrap();
        let result = h
            .server
            .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                toolset: TOOLSET.to_owned(),
                action: "stellar_pay".to_owned(),
                chain_id: Some("stellar:testnet".to_owned()),
                args: json!({
                    "source": h.source, "destination": DEST_G, "asset": "native",
                    "amount_in_stroops": AMOUNT.to_string(),
                }),
            })
            .await
            .expect("the proposal answers with a business envelope, not a protocol error");
        let body: serde_json::Value =
            serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
        assert_eq!(body["ok"], true, "{body}");
        assert_eq!(
            body["data"]["approval"].is_null(),
            !required,
            "the carried outer preparation requirement governs consent: {body}"
        );
        assert_eq!(
            h.engine.arguments_for("stellar_toolset_invoke"),
            vec![json!({ "toolset": TOOLSET, "action": "stellar_pay" })],
            "the provisional outer outcome is evaluated exactly once"
        );
        let pending = h.pending();
        assert_eq!(pending.len(), usize::from(required));
        if required {
            assert_eq!(pending[0].reason.as_deref(), Some("outer-proposal"));
            assert_eq!(
                body["data"]["approval"]["approval_nonce"],
                pending[0].approval_nonce
            );
        }
        assert_eq!(h.sends().await, 0);
        assert_eq!(std::fs::read(&h.grants).unwrap(), grant_bytes);
    }

    let h = Harness::new("carried-outer").await;
    let prepared = h.prepare(DEST_G, AMOUNT).await;
    let args = h.commit_args(&prepared, DEST_G, AMOUNT);
    h.engine.clear();
    h.engine
        .decide("stellar_toolset_invoke", approval("outer-rule", 300));
    let body = h.protocol_commit(&args).await;
    assert_eq!(code(&body), "policy.approval_required", "{body}");
    let pending = h.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].reason.as_deref(), Some("outer-rule"));
    assert_eq!(
        h.engine.arguments_for("stellar_toolset_invoke"),
        vec![json!({ "toolset": TOOLSET, "action": ACTION })]
    );
    assert_eq!(h.sends().await, 0);

    let control = Harness::new("carried-outer-allow").await;
    let prepared = control.prepare(DEST_G, AMOUNT).await;
    let args = control.commit_args(&prepared, DEST_G, AMOUNT);
    assert_eq!(control.protocol_commit(&args).await["ok"], true);
    assert_eq!(control.sends().await, 1);
    assert!(control.pending().is_empty());
}

/// Composition at fixed policy instants: the earlier absolute end bounds the
/// queued approval, a tie selects the routed request, an outer denial
/// refuses with its own code and no queue or send, and an outer end at the
/// routed instant refuses typed.
#[tokio::test]
#[serial]
async fn composition_bounds_ties_and_denials() {
    let h = Harness::new("composition").await;
    let now = now_unix_ms().unwrap();
    let clock = stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(now);
    for (amount, routed_ttl, outer_ttl, reason, end) in [
        (AMOUNT + 1, 600, 120, "routed", now + 120_000),
        (AMOUNT + 2, 120, 600, "routed", now + 120_000),
        (AMOUNT + 3, 600, 600, "routed", now + 600_000),
    ] {
        h.engine.decide("stellar_pay_commit", Decision::Allow);
        h.engine.decide("stellar_toolset_invoke", Decision::Allow);
        let prepared = h.prepare(DEST_G, amount).await;
        let args = h.commit_args(&prepared, DEST_G, amount);
        h.engine
            .decide("stellar_pay_commit", approval("routed", routed_ttl));
        h.engine
            .decide("stellar_toolset_invoke", approval("outer", outer_ttl));
        let body = h.commit(&args, DEST_G, amount).await;
        assert_eq!(code(&body), "policy.approval_required", "{body}");
        let queued: Vec<_> = h
            .pending()
            .into_iter()
            .filter(|entry| {
                matches!(&entry.kind, stellar_agent_core::approval::ApprovalKind::PaymentSimulated { envelope_xdr_b64, .. } if *envelope_xdr_b64 == args["envelope_xdr"])
            })
            .collect();
        assert_eq!(queued.len(), 1);
        assert_eq!(
            (
                queued[0].reason.as_deref(),
                queued[0].created_at_unix_ms,
                queued[0].expires_at_unix_ms
            ),
            (Some(reason), now, end),
            "routed {routed_ttl}, outer {outer_ttl}"
        );
    }
    // Only the outer rule requires approval: its request governs.
    h.engine.decide("stellar_pay_commit", Decision::Allow);
    h.engine.decide("stellar_toolset_invoke", Decision::Allow);
    let prepared = h.prepare(DEST_G, AMOUNT + 4).await;
    let args = h.commit_args(&prepared, DEST_G, AMOUNT + 4);
    h.engine
        .decide("stellar_toolset_invoke", approval("outer", 600));
    assert_eq!(
        code(&h.commit(&args, DEST_G, AMOUNT + 4).await),
        "policy.approval_required"
    );
    assert!(
        h.pending()
            .iter()
            .any(|entry| entry.reason.as_deref() == Some("outer")
                && entry.expires_at_unix_ms == now + 600_000)
    );

    let before = h.pending().len();
    h.engine.decide(
        "stellar_toolset_invoke",
        Decision::Deny(DenyReason::ExplicitRuleDeny),
    );
    h.engine.decide("stellar_pay_commit", Decision::Allow);
    let prepared = h.prepare(DEST_G, AMOUNT).await;
    let args = h.commit_args(&prepared, DEST_G, AMOUNT);
    for _ in 0..2 {
        let body = h.commit(&args, DEST_G, AMOUNT).await;
        assert_eq!(code(&body), "policy.deny.explicit_rule_deny", "{body}");
    }
    assert_eq!(h.pending().len(), before);
    assert_eq!(h.sends().await, 0);
    drop(clock);
}

/// A composed approval requirement without a proof queues once, under the
/// composed interval, before any nonce use or send. A repeat and a direct
/// preparation of the same envelope reuse that approval, and the attested
/// proof then submits once under the original nonce.
#[tokio::test]
#[serial]
async fn composed_approval_queues_before_the_nonce_and_submits_with_its_proof() {
    let h = Harness::build("composed-queue", true).await;
    let now = now_unix_ms().unwrap();
    let _clock =
        stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(now);
    let prepared = h.prepare(DEST_G, AMOUNT).await;
    let mut args = h.commit_args(&prepared, DEST_G, AMOUNT);
    h.engine
        .decide("stellar_pay_commit", approval("routed", 300));
    h.engine
        .decide("stellar_toolset_invoke", approval("outer", 120));
    let mut queued = Vec::new();
    for _ in 0..2 {
        let body = h.commit(&args, DEST_G, AMOUNT).await;
        assert_eq!(code(&body), "policy.approval_required", "{body}");
        let pending = h.pending();
        assert_eq!(pending.len(), 1);
        queued.push((
            pending[0].approval_nonce.clone(),
            pending[0].created_at_unix_ms,
            pending[0].expires_at_unix_ms,
            pending[0].reason.clone(),
        ));
    }
    assert_eq!(queued[0], queued[1]);
    assert_eq!(
        (queued[0].1, queued[0].2, queued[0].3.as_deref()),
        (now, now + 120_000, Some("routed"))
    );
    assert_eq!(h.sends().await, 0);

    // The direct preparation of the same envelope reuses the approval.
    h.engine.decide("stellar_pay", approval("routed", 300));
    let again = h.prepare(DEST_G, AMOUNT).await;
    assert_eq!(again["envelope_xdr"], prepared["envelope_xdr"]);
    assert_eq!(again["approval"]["approval_nonce"], json!(queued[0].0));
    assert_eq!(h.pending().len(), 1);

    let envelope = prepared["envelope_xdr"].as_str().unwrap();
    args["approval_nonce"] = json!(queued[0].0);
    args["approval_attestation"] = json!(h.attest(&queued[0].0, envelope));
    let body = h.commit(&args, DEST_G, AMOUNT).await;
    assert_eq!(body["ok"], true, "{body}");
    assert_eq!(h.sends().await, 1);
    assert_eq!(h.audit_decisions(), vec![json!("require_approval")]);
}

/// A direct testnet preparation that a synthetic engine sends to approval
/// refuses without a signed, verified policy and queues nothing. With the
/// fixture policy, the same preparation queues one approval.
#[tokio::test]
#[serial]
async fn direct_approval_queues_only_under_a_verified_policy() {
    let args = |source: &str| {
        serde_json::from_value(json!({
            "chain_id": "stellar:testnet", "source": source,
            "destination": DEST_G, "asset": "native",
            "amount_in_stroops": AMOUNT.to_string(),
        }))
        .unwrap()
    };
    let h = Harness::build("direct-unverified", false).await;
    h.engine.decide("stellar_pay", approval("direct", 300));
    let error = h
        .server
        .call_stellar_pay(args(&h.source))
        .await
        .unwrap_err();
    assert_eq!(
        error.message,
        "approval.store_error: invalid approval store entry: payment recovery requires a verified policy"
    );
    assert!(h.pending().is_empty());
    drop(h);

    let h = Harness::build("direct-verified", true).await;
    h.engine.decide("stellar_pay", approval("direct", 300));
    let prepared = h.prepare(DEST_G, AMOUNT).await;
    let pending = h.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        prepared["approval"]["approval_nonce"],
        json!(pending[0].approval_nonce)
    );
    assert_eq!(pending[0].reason.as_deref(), Some("direct"));
}

/// An approved context commit leaves its approval unconsumed on disk while
/// the restriction holds the grant lease, and consumes it after the lease
/// drops, before the commit returns.
#[tokio::test]
#[serial]
async fn approved_context_commit_consumes_its_approval_after_the_lease_drops() {
    let mut h = Harness::build("lease-then-consume", true).await;
    let _clock = stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(
        now_unix_ms().unwrap(),
    );
    let prepared = h.prepare(DEST_G, AMOUNT).await;
    let mut args = h.commit_args(&prepared, DEST_G, AMOUNT);
    h.engine
        .decide("stellar_pay_commit", approval("routed", 300));
    h.engine
        .decide("stellar_toolset_invoke", approval("outer", 120));
    let body = h.commit(&args, DEST_G, AMOUNT).await;
    assert_eq!(code(&body), "policy.approval_required", "{body}");
    let nonce = h.pending()[0].approval_nonce.clone();
    args["approval_nonce"] = json!(nonce);
    args["approval_attestation"] =
        json!(h.attest(&nonce, prepared["envelope_xdr"].as_str().unwrap()));
    let store = h.approval.path().join(format!("{}.toml", h.name));
    let consumed = move |nonce: &str| {
        PendingApprovalStore::open(store.clone())
            .unwrap()
            .get(nonce)
            .is_some_and(|entry| matches!(entry.kind, ApprovalKind::Consumed { .. }))
    };
    let at_release = Arc::new(Mutex::new(Vec::new()));
    let probe = {
        let at_release = Arc::clone(&at_release);
        let consumed = consumed.clone();
        let nonce = nonce.clone();
        move || at_release.lock().unwrap().push(consumed(&nonce))
    };
    h.server
        .set_toolset_lease_release_probe_for_test(Arc::new(probe));

    let body = h.commit(&args, DEST_G, AMOUNT).await;

    assert_eq!(body["ok"], true, "{body}");
    assert_eq!(h.sends().await, 1);
    assert_eq!(
        *at_release.lock().unwrap(),
        [false],
        "the approval is unconsumed while the restriction holds its lease"
    );
    assert!(
        consumed(&nonce),
        "the approval is consumed after the lease drops"
    );
}

/// An attested legacy approval with no recovery binding remains usable
/// when the current policy requires consent.
#[tokio::test]
#[serial]
async fn legacy_unbound_approval_is_accepted_when_policy_requires_it() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use stellar_agent_core::approval::attestation::{compute_attestation_v4, envelope_sha256};
    let h = Harness::new("forced-then-context").await;
    let prepared = h.prepare(DEST_G, AMOUNT).await;
    let mut args = h.commit_args(&prepared, DEST_G, AMOUNT);
    let now = now_unix_ms().unwrap();
    let mut entry = PendingApproval::new_payment_pending_until(
        prepared["envelope_xdr"].as_str().unwrap().to_owned(),
        process_uid_for_attestation().unwrap(),
        now,
        now + 600_000,
        now,
        None,
    )
    .unwrap();
    let blob = compute_attestation_v4(
        &KEY,
        &AttestationBinding::new(&h.name, "stellar:testnet"),
        &entry.approval_nonce,
        &envelope_sha256(prepared["envelope_xdr"].as_str().unwrap().as_bytes()),
        &process_uid_for_attestation().unwrap(),
        &entry.attested_lifetime(),
        &stellar_agent_core::approval::AttestedApprover::Local,
    );
    let attestation = URL_SAFE_NO_PAD.encode(blob);
    entry.attestation_blob_b64 = Some(attestation.clone());
    entry.attestation_version = 4;
    entry.attested_approver = Some(stellar_agent_core::approval::AttestedApprover::Local);
    PendingApprovalStore::open(h.approval.path().join(format!("{}.toml", h.name)))
        .unwrap()
        .insert(entry, now)
        .unwrap();
    let pending = h.pending();
    assert_eq!(pending.len(), 1);
    let nonce = pending[0].approval_nonce.clone();
    h.engine
        .decide("stellar_pay_commit", approval("routed", 600));
    args["approval_nonce"] = json!(nonce);
    args["approval_attestation"] = json!(attestation);
    let body = h.commit(&args, DEST_G, AMOUNT).await;
    assert_eq!(body["ok"], true, "{body}");
    assert_eq!(h.sends().await, 1);
}

/// The grant lease holds off grant insertion, revocation, and the install
/// lock, with unchanged bytes, while the payment is sent; each succeeds once
/// the commit returns.
#[tokio::test]
#[serial]
async fn lease_holds_toolset_writers_off_until_submission_returns() {
    if let Ok(role) = std::env::var("PAYMENT_LOCK_ROLE") {
        lock_child(&role);
        return;
    }
    let h = Harness::new("lease-interval").await;
    let prepared = h.prepare(DEST_G, AMOUNT).await;
    let args = h.commit_args(&prepared, DEST_G, AMOUNT);
    let writers = h.arm_writers();
    let body = h.commit(&args, DEST_G, AMOUNT).await;
    assert_eq!(body["ok"], true, "{body}");
    assert_eq!(
        *h.nonce_lease_seen.lock().unwrap(),
        vec![true],
        "the successful recorder receives the lease held during nonce HMAC access"
    );
    assert_eq!(
        *writers.seen.lock().unwrap(),
        vec![[true, true]],
        "the lease holds off every writer, with unchanged bytes, during the send"
    );
    *h.writers.lock().unwrap() = None;
    let mut peer = writers.peer.lock().unwrap().take().unwrap();
    peer.release();
    peer.finish();

    let h = Harness::new("lease-process-exit").await;
    let writers = h.arm_writers();
    let mut peer = LockPeer::spawn("lease", &writers);
    assert!(peer.wait_for("leased"));
    let held = writers.record_grant(SECOND_DEST);
    peer.release();
    peer.finish();
    assert!(matches!(held, Err(ToolsetRuntimeError::CoordinationBusy)));
    writers.record_grant(SECOND_DEST).unwrap();
    assert_eq!(writers.revoke().unwrap(), 2);
    drop(lock_toolsets(&writers.root).unwrap());
}

#[tokio::test]
#[serial]
async fn public_payment_reports_coordination_busy_without_writing() {
    let h = Harness::new("handler-coordination").await;
    let prepared = h.prepare(DEST_G, AMOUNT).await;
    let args = h.commit_args(&prepared, DEST_G, AMOUNT);
    let writers = h.arm_writers();
    *h.writers.lock().unwrap() = None;
    let mut peer = LockPeer::spawn("root", &writers);
    assert!(peer.wait_for("locked"));
    let body = h.protocol_commit(&args).await;
    peer.release();
    peer.finish();
    assert_eq!(code(&body), "toolset.coordination_busy", "{body}");
    assert_eq!(writers.bytes(), *writers.before.lock().unwrap());
    assert!(h.pending().is_empty());
    assert_eq!(h.sends().await, 0);
    let body = h.protocol_commit(&args).await;
    assert_eq!(body["ok"], true, "{body}");
    assert_eq!(h.sends().await, 1);
}

/// A grant revoked or expired before acquisition refuses with its own code
/// before the nonce is used; after a new grant the same commit submits.
#[tokio::test]
#[serial]
async fn changed_or_expired_grant_refuses_before_the_nonce() {
    use stellar_agent_core::approval::TOOLSET_GRANT_DEFAULT_TTL_MS;
    let h = Harness::new("lease-refusals").await;
    let prepared = h.prepare(DEST_G, AMOUNT).await;
    let args = h.commit_args(&prepared, DEST_G, AMOUNT);
    let resolved = h.resolve(DEST_G, AMOUNT);
    ToolsetGrantStore::open(h.grants.clone(), now_unix_ms().unwrap())
        .unwrap()
        .revoke_toolset(TOOLSET)
        .unwrap();
    let body = h.commit_with(&args, resolved).await;
    assert_eq!(code(&body), "toolset.grant_changed", "{body}");

    let then = now_unix_ms().unwrap() - TOOLSET_GRANT_DEFAULT_TTL_MS - 1_000;
    grant(&h.name, &h.grants, DEST_G, then).unwrap();
    let body = h
        .commit_with(&args, h.resolve_at(DEST_G, AMOUNT, then + 1))
        .await;
    assert_eq!(code(&body), "toolset.grant_expired", "{body}");
    assert_eq!(h.sends().await, 0);

    grant(&h.name, &h.grants, DEST_G, now_unix_ms().unwrap()).unwrap();
    let body = h.commit(&args, DEST_G, AMOUNT).await;
    assert_eq!(body["ok"], true, "{body}");
    assert_eq!(h.sends().await, 1);
}

/// A grant whose end passes between lease acquisition and nonce recording
/// refuses `toolset.grant_expired` under the replay mutex and records no
/// nonce; the same commit then submits on a current clock.
#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn grant_end_is_checked_again_at_the_nonce() {
    use stellar_agent_core::approval::TOOLSET_GRANT_DEFAULT_TTL_MS;
    let h = Harness::new("lease-nonce-end").await;
    let prepared = h.prepare(DEST_G, AMOUNT).await;
    let args = h.commit_args(&prepared, DEST_G, AMOUNT);
    let later = now_unix_ms().unwrap() + TOOLSET_GRANT_DEFAULT_TTL_MS + 60_000;
    let clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(later);
    let body = h.protocol_commit(&args).await;
    assert_eq!(code(&body), "toolset.grant_expired", "{body}");
    assert_eq!(h.sends().await, 0);
    drop(clock);
    let body = h.protocol_commit(&args).await;
    assert_eq!(body["ok"], true, "{body}");
    assert_eq!(h.sends().await, 1);
}

/// A composed consent's proof is used only inside its interval: at a policy
/// instant before the consent was created and at its composed end, the
/// attested proof refuses with no send. Once the interval has ended, the
/// context queues a fresh consent over a new interval, its proof submits
/// once, and retries after that send add no send.
#[tokio::test]
#[serial]
async fn context_proof_is_bounded_by_the_composed_interval_and_renews_after_retention() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test;
    let mut h = Harness::build("context-interval", true).await;
    let now = now_unix_ms().unwrap();
    // The policy instant and the server clock that bounds proof use move
    // together.
    let policy_clock = set_query_time_for_test(now);
    let server_now = Arc::new(AtomicU64::new(now));
    let read = Arc::clone(&server_now);
    h.server
        .set_clock_for_test(Arc::new(stellar_agent_core::timefmt::MockClock::new(
            move || Ok(read.load(Ordering::SeqCst)),
        )));
    let clock = |instant: u64| {
        policy_clock.set(instant);
        server_now.store(instant, Ordering::SeqCst);
    };
    let prepared = h.prepare(DEST_G, AMOUNT).await;
    let proofless = h.commit_args(&prepared, DEST_G, AMOUNT);
    let envelope = prepared["envelope_xdr"].as_str().unwrap();
    h.engine
        .decide("stellar_pay_commit", approval("routed", 300));
    h.engine
        .decide("stellar_toolset_invoke", approval("outer", 120));
    let body = h.commit(&proofless, DEST_G, AMOUNT).await;
    assert_eq!(code(&body), "policy.approval_required", "{body}");
    let first = h.pending();
    assert_eq!(first.len(), 1);
    assert_eq!(
        (first[0].created_at_unix_ms, first[0].expires_at_unix_ms),
        (now, now + 120_000)
    );
    let mut proven = proofless.clone();
    proven["approval_nonce"] = json!(first[0].approval_nonce);
    proven["approval_attestation"] = json!(h.attest(&first[0].approval_nonce, envelope));

    for (instant, case) in [
        (now - 1, "before the consent was created"),
        (now + 120_000, "at the composed end"),
    ] {
        clock(instant);
        let body = h.commit(&proven, DEST_G, AMOUNT).await;
        assert_eq!(
            code(&body),
            "policy.approval_required",
            "{case}: the proof is refused: {body}"
        );
        assert_eq!(h.sends().await, 0, "{case}");
    }

    // After the interval the context renews consent instead of reusing it.
    let renewed_at = now + 120_000;
    clock(renewed_at);
    let body = h.commit(&proofless, DEST_G, AMOUNT).await;
    assert_eq!(code(&body), "policy.approval_required", "{body}");
    let renewed: Vec<_> = h
        .pending()
        .into_iter()
        .filter(|entry| entry.approval_nonce != first[0].approval_nonce)
        .collect();
    assert_eq!(renewed.len(), 1, "one fresh consent");
    assert_eq!(
        (renewed[0].created_at_unix_ms, renewed[0].expires_at_unix_ms),
        (renewed_at, renewed_at + 120_000)
    );
    let mut renewed_proof = proofless.clone();
    renewed_proof["approval_nonce"] = json!(renewed[0].approval_nonce);
    renewed_proof["approval_attestation"] = json!(h.attest(&renewed[0].approval_nonce, envelope));
    let body = h.commit(&renewed_proof, DEST_G, AMOUNT).await;
    assert_eq!(body["ok"], true, "{body}");
    assert_eq!(h.sends().await, 1);

    // Retries after the first send: the proof, the proofless call, and the
    // protocol route each meet the spent consent and add no send or queue.
    let pending: Vec<_> = h
        .pending()
        .into_iter()
        .map(|entry| entry.approval_nonce)
        .collect();
    for (retry, case, expected) in [
        (&renewed_proof, "proof retry", "policy.approval_consumed"),
        (&proofless, "proofless retry", "policy.approval_consumed"),
    ] {
        let body = h.commit(retry, DEST_G, AMOUNT).await;
        assert_eq!(code(&body), expected, "{case}: {body}");
    }
    let body = h.protocol_commit(&renewed_proof).await;
    assert_eq!(
        code(&body),
        "policy.approval_consumed",
        "protocol retry: {body}"
    );
    assert_eq!(h.sends().await, 1);
    assert_eq!(
        h.pending()
            .into_iter()
            .map(|entry| entry.approval_nonce)
            .collect::<Vec<_>>(),
        pending,
        "a retry after the send queues nothing"
    );
}
