//! The TLS listener of a mainnet approval credential enrollment at a signed
//! origin.
//!
//! [`start_signed_enrollment`] serves the enrollment ceremony of
//! `stellar_agent_approval_ui::operator_enroll` at the `approval_origin` of
//! an unsigned policy body, for the RP that origin's host names. The caller
//! validates the body and passes its origin and its certificate pin; this
//! module reads neither a signed policy nor any request header for them.
//!
//! Startup refuses before it binds, in this order:
//!
//! 1. The profile has no enabled `[remote_approval]` table:
//!    `internal.unexpected_state` naming `approve.remote_not_configured`.
//! 2. The profile `rp_id` is not the signed host:
//!    `approval.origin_profile_mismatch`.
//! 3. The configured `bind` or `rp_id` is invalid:
//!    `internal.unexpected_state` naming `approve.remote_config_invalid`.
//! 4. The configured TLS pair fails [`crate::tls::select_tls`] with the pin.
//!    A missing or unusable file names its field under
//!    `approve.remote_tls_unavailable`. A key looser than `0600` keeps its
//!    permission refusal, and another leaf key returns
//!    `approval.cert_pin_mismatch`. No certificate is generated.
//!
//! Then it binds the configured socket. A held socket returns
//! `approval.listener_busy` and nothing else is tried. The router admits
//! only the signed `Host` authority and, on every state-changing request,
//! the exact signed `Origin`.
//!
//! After the bind, a startup callback receives the enrollment code once, for
//! the terminal. The handle's `Debug` output and the release API carry no
//! code. The listener writes no profile, policy, credential store or keyring
//! item; the confirmed credential is only exported by its caller.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum_server::tls_rustls::RustlsConfig;
use stellar_agent_approval_ui::operator_enroll::{
    OperatorEnrollAwaitError, PendingOperatorEnrollment, SignedEnrollmentCeremony,
    signed_mainnet_approval_enroll,
};
use stellar_agent_core::policy::v1::approval_origin::ApprovalOrigin;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_core::{ApprovalFailure, WalletError};
use tokio::task::JoinHandle;

use crate::{PageIdentity, RemoteServeStartError, ServerHandle, validate_remote_config};

/// Deadline for [`SignedEnrollmentHandle::shutdown`].
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

/// What [`start_signed_enrollment`] serves.
#[non_exhaustive]
pub struct SignedEnrollmentConfig {
    /// The profile name, which also names the default TLS paths that a
    /// signed origin never uses.
    pub profile_name: String,
    /// The persisted mainnet profile with its `[remote_approval]` table.
    pub profile: Profile,
    /// The validated `approval_origin` of the unsigned policy body.
    pub origin: ApprovalOrigin,
    /// The body's `approval_cert_spki_sha256` pin.
    pub cert_spki_sha256: [u8; 32],
    /// The ceremony timeout; the enrollment code lives at most ten minutes
    /// of it.
    pub timeout: Duration,
    /// Optional pre-fill of the page's label field.
    pub label_prefill: Option<String>,
    /// The identity the pages announce.
    pub page_identity: PageIdentity,
}

impl SignedEnrollmentConfig {
    /// A configuration with no label pre-fill and the neutral page identity.
    #[must_use]
    pub fn new(
        profile_name: impl Into<String>,
        profile: Profile,
        origin: ApprovalOrigin,
        cert_spki_sha256: [u8; 32],
        timeout: Duration,
    ) -> Self {
        Self {
            profile_name: profile_name.into(),
            profile,
            origin,
            cert_spki_sha256,
            timeout,
            label_prefill: None,
            page_identity: PageIdentity::neutral(),
        }
    }

    /// Sets the label pre-fill.
    #[must_use = "builder setters return the updated configuration by value"]
    pub fn with_label(mut self, label_prefill: Option<String>) -> Self {
        self.label_prefill = label_prefill;
        self
    }

    /// Sets the identity the pages announce.
    #[must_use = "builder setters return the updated configuration by value"]
    pub fn with_page_identity(mut self, page_identity: PageIdentity) -> Self {
        self.page_identity = page_identity;
        self
    }
}

/// Handle to a running signed-origin enrollment listener.
///
/// `Debug` shows the public origin and the bound address only. Dropping the
/// handle, also through the cancellation of the task that owns it, stops
/// the listener at once and releases its socket.
pub struct SignedEnrollmentHandle {
    local_addr: SocketAddr,
    public_origin: String,
    ceremony: SignedEnrollmentCeremony,
    guard: ShutdownGuard,
    server_join: JoinHandle<()>,
}

/// Signals the server to stop when it goes out of scope.
struct ShutdownGuard(ServerHandle);

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

impl std::fmt::Debug for SignedEnrollmentHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedEnrollmentHandle")
            .field("local_addr", &self.local_addr)
            .field("public_origin", &self.public_origin)
            .finish_non_exhaustive()
    }
}

impl SignedEnrollmentHandle {
    /// The bound backend socket.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The signed origin, with its canonical port.
    #[must_use]
    pub fn public_origin(&self) -> &str {
        &self.public_origin
    }

    /// The page URL: the signed origin and `/enroll`, without any secret.
    #[must_use]
    pub fn enroll_url(&self) -> String {
        self.ceremony.enroll_url().to_owned()
    }

    /// The enrollment code the startup callback receives.
    #[cfg(feature = "test-helpers")]
    #[must_use]
    pub fn enrollment_code(&self) -> &str {
        self.ceremony.enrollment_code()
    }

    /// A trigger that stops the server at once while the ceremony waits, so a
    /// test can end it as a failed server does.
    #[cfg(feature = "test-helpers")]
    pub fn stop_trigger(&self) -> impl Fn() + Send + Sync + 'static {
        let server = self.guard.0.clone();
        move || server.shutdown()
    }

    /// How long the enrollment code lives.
    #[cfg(feature = "test-helpers")]
    #[must_use]
    pub fn code_lifetime(&self) -> Duration {
        self.ceremony.code_lifetime()
    }

    /// Await the verified registration until `deadline`.
    ///
    /// # Errors
    ///
    /// The errors of [`SignedEnrollmentCeremony::await_completion_until`]:
    /// a timeout or code expiry, code exhaustion, a second call, or a
    /// stopped server.
    pub async fn await_completion_until(
        &mut self,
        deadline: Instant,
    ) -> Result<PendingOperatorEnrollment, OperatorEnrollAwaitError> {
        self.ceremony.await_completion_until(deadline).await
    }

    /// Stops the listener and waits for its task, releasing the socket.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic string when the task does not stop within the
    /// deadline or ends in a panic.
    pub async fn shutdown(self) -> Result<(), String> {
        self.guard.0.graceful_shutdown(Some(SHUTDOWN_DEADLINE));
        tokio::time::timeout(SHUTDOWN_DEADLINE + Duration::from_secs(1), self.server_join)
            .await
            .map_err(|_| {
                "enrollment listener did not stop within the shutdown deadline".to_owned()
            })?
            .map_err(|error| format!("enrollment listener task panicked: {error}"))
    }
}

/// Starts the signed-origin enrollment listener and hands the enrollment
/// code to `on_code` once, after the bind succeeds.
///
/// # Errors
///
/// Every refusal happens before the bind, in the order of the module
/// documentation; a held socket returns `approval.listener_busy`.
/// [`RemoteServeStartError::into_wallet_error`] renders each one.
pub async fn start_signed_enrollment(
    config: SignedEnrollmentConfig,
    on_code: impl FnOnce(&str),
) -> Result<SignedEnrollmentHandle, RemoteServeStartError> {
    let remote = config
        .profile
        .remote_approval
        .as_ref()
        .filter(|remote| remote.enabled)
        .ok_or_else(|| {
            WalletError::Internal(stellar_agent_core::error::InternalError::UnexpectedState {
                detail: "approve.remote_not_configured: profile has no enabled \
                         [remote_approval] block; enable it before signed-origin enrollment"
                    .to_owned(),
            })
        })?;
    if remote.rp_id != config.origin.rp_id() {
        return Err(WalletError::Approval(ApprovalFailure::OriginProfileMismatch).into());
    }
    let bind_addr = validate_remote_config(&remote.bind, &remote.rp_id).map_err(|error| {
        WalletError::Internal(stellar_agent_core::error::InternalError::UnexpectedState {
            detail: format!("approve.remote_config_invalid: {error}"),
        })
    })?;
    let (_tls, rustls_config): (_, RustlsConfig) =
        crate::tls::select_tls(&config.profile_name, remote, Some(&config.cert_spki_sha256))
            .await?;

    let std_listener = std::net::TcpListener::bind(bind_addr).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AddrInUse {
            RemoteServeStartError::Policy(WalletError::Approval(ApprovalFailure::ListenerBusy))
        } else {
            RemoteServeStartError::Bind { kind: error.kind() }
        }
    })?;
    std_listener
        .set_nonblocking(true)
        .map_err(|error| RemoteServeStartError::Bind { kind: error.kind() })?;
    let local_addr = std_listener
        .local_addr()
        .map_err(|error| RemoteServeStartError::Bind { kind: error.kind() })?;

    let origin = config.origin.as_str().to_owned();
    let (router, ceremony) = signed_mainnet_approval_enroll(
        &config.origin,
        config.profile_name.clone(),
        config.label_prefill,
        config.page_identity,
        config.timeout,
    );
    // The security headers sit outermost, so the Host and Origin refusals
    // carry them too, as on the signed consent listener.
    let router = router
        .layer(stellar_agent_loopback_http::signed_origin::SignedOriginLayer::new(&origin))
        .layer(stellar_agent_loopback_http::signed_origin::SignedHostLayer::new(&origin))
        .layer(stellar_agent_loopback_http::security_headers::SecurityHeadersLayer::new());

    let axum_handle = ServerHandle::new();
    let server_handle = axum_handle.clone();
    let server_join = tokio::spawn(async move {
        let result = match axum_server::tls_rustls::from_tcp_rustls(std_listener, rustls_config) {
            Ok(server) => {
                server
                    .handle(server_handle)
                    .serve(router.into_make_service())
                    .await
            }
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            tracing::error!(error = %error, "enrollment listener task exited with error");
        }
    });
    tracing::info!(local_addr = %local_addr, origin = %origin, "signed-origin enrollment listener started");
    on_code(ceremony.enrollment_code());
    Ok(SignedEnrollmentHandle {
        local_addr,
        public_origin: origin,
        ceremony,
        guard: ShutdownGuard(axum_handle),
        server_join,
    })
}

#[cfg(all(test, feature = "test-helpers"))]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "listener assertions"
    )]
    use super::*;
    use crate::test_helpers::{PinnedLeaf, pinned_leaf};
    use stellar_agent_approval_ui::operator_enroll::EnrollmentPurpose;
    use stellar_agent_approval_ui::operator_enroll::test_support::{
        EnrollmentClient, SoftwareRegistrar, signed_origin_request,
    };
    use stellar_agent_core::approval::mainnet_fixtures::{
        MainnetConsentFixture, SIGNED_ORIGIN, SIGNED_RP_ID,
    };

    /// A mainnet profile whose `[remote_approval]` table names a free
    /// loopback socket and a pinned leaf for the signed host. The signed
    /// origin comes from a policy body with that leaf's pin.
    struct Setup {
        fixture: MainnetConsentFixture,
        leaf: PinnedLeaf,
        bind: SocketAddr,
        _files: tempfile::TempDir,
    }

    impl Setup {
        fn new() -> Self {
            let files = tempfile::tempdir().unwrap();
            let leaf = pinned_leaf(SIGNED_RP_ID, &rcgen::PKCS_ECDSA_P256_SHA256);
            let cert = files.path().join("cert.pem");
            let key = files.path().join("key.pem");
            std::fs::write(&cert, leaf.chain_pem()).unwrap();
            std::fs::write(&key, &leaf.key_pem).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            let bind = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            let mut fixture = MainnetConsentFixture::with_profile("enroll-listener", |profile| {
                profile.remote_approval = Some(
                    serde_json::from_value(serde_json::json!({
                        "enabled": true, "bind": bind.to_string(), "rp_id": SIGNED_RP_ID,
                        "cert_path": cert, "key_path": key,
                    }))
                    .unwrap(),
                );
            });
            fixture.sign_signed_origin_policy(
                &[&stellar_agent_test_support::webauthn::fixture_authenticator()],
                &leaf.pin,
            );
            Self {
                fixture,
                leaf,
                bind,
                _files: files,
            }
        }

        fn origin(&self) -> ApprovalOrigin {
            self.fixture
                .current_policy()
                .mainnet()
                .unwrap()
                .approval_origin
                .clone()
                .unwrap()
        }

        fn config(&self, pin: [u8; 32]) -> SignedEnrollmentConfig {
            SignedEnrollmentConfig::new(
                self.fixture.name(),
                self.fixture.profile().clone(),
                self.origin(),
                pin,
                Duration::from_secs(300),
            )
        }

        async fn start(&self) -> SignedEnrollmentHandle {
            start_signed_enrollment(self.config(self.leaf.pin), |_| {})
                .await
                .unwrap()
        }

        async fn request(
            &self,
            method: &str,
            path: &str,
            headers: &[(&str, &str)],
            body: Option<&str>,
        ) -> stellar_agent_approval_ui::operator_enroll::test_support::HttpReply {
            signed_origin_request(
                self.bind,
                SIGNED_ORIGIN,
                &self.leaf.cert_pem,
                method,
                path,
                headers,
                body,
            )
            .await
            .unwrap()
        }
    }

    fn socket_is_free(addr: SocketAddr) -> bool {
        std::net::TcpListener::bind(addr).is_ok()
    }

    /// A leaf whose key differs from the pin refuses with the pin code
    /// before the bind, also while the configured socket is held.
    #[tokio::test]
    #[serial_test::serial]
    async fn signed_enrollment_refuses_pin_mismatch_before_bind() {
        let setup = Setup::new();
        let other = pinned_leaf(SIGNED_RP_ID, &rcgen::PKCS_ECDSA_P256_SHA256);
        let mut delivered = false;
        let error = start_signed_enrollment(setup.config(other.pin), |_| delivered = true)
            .await
            .unwrap_err()
            .into_wallet_error();
        assert_eq!(error.code(), "approval.cert_pin_mismatch");
        assert!(socket_is_free(setup.bind));
        let held = std::net::TcpListener::bind(setup.bind).unwrap();
        let error = start_signed_enrollment(setup.config(other.pin), |_| delivered = true)
            .await
            .unwrap_err()
            .into_wallet_error();
        assert_eq!(
            error.code(),
            "approval.cert_pin_mismatch",
            "the pin refusal precedes the busy socket"
        );
        drop(held);
        assert!(!delivered, "no code leaves a refused startup");
    }

    /// The security headers of `reply`: every header except those that
    /// describe the body or the connection.
    fn security_headers(
        reply: &stellar_agent_approval_ui::operator_enroll::test_support::HttpReply,
    ) -> Vec<(String, String)> {
        let mut headers: Vec<(String, String)> = reply
            .headers
            .iter()
            .filter(|(name, _)| {
                ![
                    "content-type",
                    "content-length",
                    "date",
                    "transfer-encoding",
                    "connection",
                    "set-cookie",
                ]
                .contains(&name.as_str())
            })
            .cloned()
            .collect();
        headers.sort();
        headers
    }

    /// Only `Host: <signed authority>` reaches the router, and a POST needs
    /// the exact signed `Origin`. The backend authority and forwarded
    /// headers grant nothing. Both refusals carry every security header a
    /// served page carries.
    #[tokio::test]
    #[serial_test::serial]
    async fn signed_enrollment_admits_only_the_signed_host_and_origin() {
        let setup = Setup::new();
        let handle = setup.start().await;
        assert_ne!(setup.bind.port(), 8443);
        let served = setup.request("GET", "/enroll", &[], None).await;
        assert_eq!(served.status, 200);
        let page_headers = security_headers(&served);
        for name in [
            "content-security-policy",
            "cache-control",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
        ] {
            assert!(
                page_headers.iter().any(|(header, _)| header == name),
                "the page carries {name}: {page_headers:?}"
            );
        }
        let backend = format!("127.0.0.1:{}", setup.bind.port());
        let backend_host = format!("{SIGNED_RP_ID}:{}", setup.bind.port());
        for host in [
            "foreign.example",
            SIGNED_RP_ID,
            backend.as_str(),
            backend_host.as_str(),
        ] {
            let reply = setup
                .request(
                    "GET",
                    "/enroll",
                    &[
                        ("host", host),
                        ("x-forwarded-host", "approve.example.invalid:8443"),
                        ("forwarded", "host=approve.example.invalid:8443;proto=https"),
                    ],
                    None,
                )
                .await;
            assert_eq!(reply.status, 421, "{host}");
            assert_eq!(security_headers(&reply), page_headers, "421 for {host}");
        }
        let code_body = serde_json::json!({ "code": handle.enrollment_code() }).to_string();
        for origin in [
            Some("https://foreign.example"),
            Some("http://approve.example.invalid:8443"),
            Some("https://approve.example.invalid"),
            None,
        ] {
            let mut headers = vec![
                ("content-type", "application/json"),
                ("x-forwarded-proto", "https"),
                ("x-forwarded-host", "approve.example.invalid:8443"),
            ];
            if let Some(origin) = origin {
                headers.push(("origin", origin));
            }
            let reply = setup
                .request("POST", "/enroll/code", &headers, Some(&code_body))
                .await;
            assert_eq!(reply.status, 403, "{origin:?}");
            assert!(reply.set_cookie.is_none());
            assert_eq!(security_headers(&reply), page_headers, "403 for {origin:?}");
        }
        let page = setup
            .request(
                "GET",
                "/enroll",
                &[("x-forwarded-host", "foreign.example")],
                None,
            )
            .await;
        assert_eq!(page.status, 200);
        assert!(page.body.contains(&format!("<code>{SIGNED_ORIGIN}</code>")));
        assert!(!page.body.contains("foreign.example"));
        let client = EnrollmentClient::connect_signed(
            setup.bind,
            SIGNED_ORIGIN,
            &setup.leaf.cert_pem,
            handle.enrollment_code(),
        )
        .await
        .expect("the untouched code still opens the session");
        assert!(!client.cookie().is_empty());
        handle.shutdown().await.unwrap();
    }

    /// The listener verifies registrations for the signed RP and origin
    /// only: the localhost RP, the backend-port origin, the HTTP origin and
    /// a cross-origin response refuse; the signed registration passes.
    #[tokio::test]
    #[serial_test::serial]
    async fn signed_enrollment_registers_for_the_signed_rp_only() {
        use base64::Engine as _;
        let setup = Setup::new();
        let mut handle = setup.start().await;
        let client = EnrollmentClient::connect_signed(
            setup.bind,
            SIGNED_ORIGIN,
            &setup.leaf.cert_pem,
            handle.enrollment_code(),
        )
        .await
        .unwrap();
        let options = client.challenge().await.unwrap().json();
        assert_eq!(options["rp_id"], SIGNED_RP_ID);
        let challenge: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(options["challenge"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let signed = SoftwareRegistrar::new([0x41; 32], vec![0x6b; 18]).with_rp_id(SIGNED_RP_ID);
        let localhost = SoftwareRegistrar::new([0x41; 32], vec![0x6b; 18]);
        let backend_origin = format!("https://{SIGNED_RP_ID}:{}", setup.bind.port());
        for (name, builder) in [
            ("localhost RP", localhost.builder(&challenge, SIGNED_ORIGIN)),
            ("backend port", signed.builder(&challenge, &backend_origin)),
            (
                "HTTP origin",
                signed.builder(&challenge, "http://approve.example.invalid:8443"),
            ),
            (
                "cross origin",
                signed
                    .builder(&challenge, SIGNED_ORIGIN)
                    .cross_origin(Some(true)),
            ),
        ] {
            let reply = client.post_credential(&builder.json()).await.unwrap();
            assert_eq!(reply.status, 400, "{name}: {reply:?}");
            assert_eq!(reply.json()["error"], "registration_invalid", "{name}");
        }
        let valid = signed.builder(&challenge, SIGNED_ORIGIN);
        let reply = client.post_credential(&valid.json()).await.unwrap();
        assert_eq!(reply.status, 200, "{reply:?}");
        let pending = handle
            .await_completion_until(std::time::Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let credential = pending
            .confirm(
                &valid.confirmation_code_for(EnrollmentPurpose::MainnetApproval),
                std::time::Instant::now(),
            )
            .unwrap()
            .into_mainnet_policy_credential()
            .unwrap();
        assert_eq!(credential.credential_id(), signed.credential_id());
        handle.shutdown().await.unwrap();
    }

    /// The public startup hands the code to the callback once, after the
    /// bind; the test accessor agrees; a registration completes the wait;
    /// shutdown releases the socket. `Debug` carries no code.
    #[tokio::test]
    #[serial_test::serial]
    async fn signed_enrollment_handle_completes_and_shuts_down() {
        let setup = Setup::new();
        let mut delivered = Vec::new();
        let mut handle = start_signed_enrollment(setup.config(setup.leaf.pin), |code| {
            assert!(
                !socket_is_free(setup.bind),
                "the callback runs after the bind"
            );
            delivered.push(code.to_owned());
        })
        .await
        .unwrap();
        assert_eq!(delivered, [handle.enrollment_code().to_owned()]);
        assert_eq!(handle.public_origin(), SIGNED_ORIGIN);
        assert_eq!(handle.enroll_url(), format!("{SIGNED_ORIGIN}/enroll"));
        assert_eq!(handle.local_addr(), setup.bind);
        assert!(!format!("{handle:?}").contains(handle.enrollment_code()));
        let client = EnrollmentClient::connect_signed(
            setup.bind,
            SIGNED_ORIGIN,
            &setup.leaf.cert_pem,
            &delivered[0],
        )
        .await
        .unwrap();
        let registrar = SoftwareRegistrar::new([0x42; 32], vec![0x6c; 18]).with_rp_id(SIGNED_RP_ID);
        let (reply, _) = client.register_response(&registrar, "phone").await.unwrap();
        assert_eq!(reply.status, 200, "{reply:?}");
        let pending = handle
            .await_completion_until(std::time::Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(pending.label(), "phone");
        handle.shutdown().await.unwrap();
        assert!(socket_is_free(setup.bind), "shutdown releases the socket");
    }

    /// Waits until a new bind on `addr` succeeds, for at most five seconds.
    async fn released_within_bound(addr: SocketAddr) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            if socket_is_free(addr) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    /// The listener stops and frees its socket when the handle is dropped
    /// right after startup and when the task that owns the handle is
    /// aborted, without an explicit shutdown.
    #[tokio::test]
    #[serial_test::serial]
    async fn signed_enrollment_handle_drop_and_abort_release_the_socket() {
        let setup = Setup::new();
        let handle = setup.start().await;
        assert!(!socket_is_free(setup.bind));
        drop(handle);
        assert!(
            released_within_bound(setup.bind).await,
            "a dropped handle releases the socket within five seconds"
        );

        let config = setup.config(setup.leaf.pin);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let owner = tokio::spawn(async move {
            let handle = start_signed_enrollment(config, |_| {}).await.unwrap();
            let _ = started_tx.send(());
            let _held = handle;
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        assert!(!socket_is_free(setup.bind));
        owner.abort();
        assert!(owner.await.unwrap_err().is_cancelled());
        assert!(
            released_within_bound(setup.bind).await,
            "an aborted owner task releases the socket within five seconds"
        );
    }
}
