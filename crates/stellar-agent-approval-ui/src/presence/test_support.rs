//! HTTP driver for the shipped presence routes with synthetic assertions.
//!
//! The client navigates as the bootstrap page script does: it reads the
//! storage key and landing path from the bootstrap island, admits only the
//! pair `session-bootstrap.js` admits for the listener it expects, and loads
//! that landing path. It never chooses the first page itself.
//!
//! [`HttpsSessionGate`] is the session gate of tests that drive the
//! signed-origin consent routes.
use super::ConsentSessionGate;
use crate::auth::{AuthState, OpaqueToken, SessionPurpose, SessionState, compute_csrf};
use crate::operator_enroll::test_support::{HttpReply, island, request};
use axum::{http::HeaderMap, response::Response};
use serde_json::{Value, json};
use std::{io, net::SocketAddr, sync::Mutex};

/// A session gate over one session of a page served over HTTPS.
/// It applies the loopback listeners' cookie, CSRF and session proof checks.
/// The session cookie carries `Secure`.
pub struct HttpsSessionGate(Mutex<AuthState>);

/// The browser side of the session an [`HttpsSessionGate`] admits.
pub struct HttpsSession {
    set_cookie: String,
    proof: String,
    csrf_key: [u8; 32],
}

impl HttpsSessionGate {
    /// A gate whose one session the browser has already opened, and that
    /// browser's side of it.
    ///
    /// # Panics
    ///
    /// Never: the bootstrap token is exchanged once, right after it is made.
    #[must_use]
    pub fn open() -> (Self, HttpsSession) {
        let token = OpaqueToken::generate();
        let hex = token.to_hex();
        let mut auth = AuthState::new(token, SessionPurpose::Inbox).with_secure_cookie();
        let now = auth.now();
        #[allow(
            clippy::expect_used,
            reason = "test support; a fresh token exchanges exactly once"
        )]
        let session = auth
            .exchange_bootstrap(&hex, now)
            .expect("a fresh bootstrap token exchanges");
        let browser = HttpsSession {
            set_cookie: auth.set_cookie_value(&session),
            proof: session.session_proof.to_hex(),
            csrf_key: session.csrf_key,
        };
        (Self(Mutex::new(auth)), browser)
    }
}

/// A live session an [`HttpsSessionGate`] admitted.
pub struct HttpsGateSession(SessionState);

impl ConsentSessionGate for HttpsSessionGate {
    type Session = HttpsGateSession;

    fn session(&self, headers: &HeaderMap) -> Result<HttpsGateSession, Response> {
        self.0.session(headers).map(HttpsGateSession)
    }

    fn authorize_mutation(&self, headers: &HeaderMap, csrf_nonce: &str) -> Result<(), Response> {
        self.0.authorize_mutation(headers, csrf_nonce)
    }

    fn session_key(&self, session: &HttpsGateSession) -> String {
        self.0.session_key(&session.0)
    }

    fn csrf(&self, session: &HttpsGateSession, nonce: &str) -> String {
        self.0.csrf(&session.0, nonce)
    }
}

impl HttpsSession {
    /// The `Set-Cookie` value the session was opened with.
    #[must_use]
    pub fn set_cookie(&self) -> &str {
        &self.set_cookie
    }

    /// The headers a page of this session sends with a request about the
    /// entry `nonce`: the cookie, the session proof and the CSRF value.
    #[must_use]
    pub fn headers(&self, nonce: &str) -> Vec<(&'static str, String)> {
        let cookie = self
            .set_cookie
            .split(';')
            .next()
            .unwrap_or_default()
            .to_owned();
        vec![
            ("cookie", cookie),
            ("x-session-proof", self.proof.clone()),
            (
                "x-stellar-approval-csrf",
                compute_csrf(&self.csrf_key, nonce),
            ),
        ]
    }
}

/// A bootstrapped browser session on a real loopback presence listener.
pub struct PresenceClient {
    addr: SocketAddr,
    nonce: String,
    cookie: String,
    proof: String,
    data: Value,
}

/// The session a bootstrap exchange opened: its address, cookie, proof and
/// the landing path its island names.
struct Bootstrapped {
    addr: SocketAddr,
    cookie: String,
    proof: String,
    storage_key: String,
    next: String,
}

/// Whether `next` is the consent page path the bootstrap script admits for
/// the mainnet consent storage key: `/approval/` and a 22-character
/// base64url approval nonce.
fn is_consent_path(next: &str) -> bool {
    next.strip_prefix("/approval/").is_some_and(|nonce| {
        nonce.len() == 22
            && nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    })
}

impl PresenceClient {
    /// Exchanges the private bootstrap of a single consent ceremony for the
    /// entry `nonce` and loads the page its island lands on.
    ///
    /// # Errors
    /// Returns transport errors, missing page fields, and an island whose
    /// storage key is not the consent key, whose landing path is not a
    /// consent page path, or whose consent page is not that of `nonce`.
    pub async fn connect(url: &str, nonce: &str) -> io::Result<Self> {
        let session = bootstrap(url).await?;
        if session.storage_key != SessionPurpose::MainnetPresence.proof_storage_key()
            || !is_consent_path(&session.next)
            || session.next != super::one_shot_destination(nonce)
        {
            return Err(invalid());
        }
        let next = session.next.clone();
        Self::open(session, nonce, &next).await
    }

    /// Exchanges the private bootstrap of a mainnet inbox, loads the inbox its
    /// island lands on, and opens the consent page of the entry `nonce`.
    ///
    /// # Errors
    /// Returns transport errors, missing page fields, an island other than
    /// the inbox key with `/inbox`, and an inbox that does not load.
    pub async fn connect_inbox(url: &str, nonce: &str) -> io::Result<Self> {
        let session = bootstrap(url).await?;
        if session.storage_key != SessionPurpose::Inbox.proof_storage_key()
            || session.next != "/inbox"
        {
            return Err(invalid());
        }
        let inbox = request(
            session.addr,
            "GET",
            &session.next,
            &[("cookie", &session.cookie)],
            None,
        )
        .await?;
        if inbox.status != 200 {
            return Err(invalid());
        }
        Self::open(session, nonce, &super::one_shot_destination(nonce)).await
    }

    async fn open(session: Bootstrapped, nonce: &str, page: &str) -> io::Result<Self> {
        let reply = request(
            session.addr,
            "GET",
            page,
            &[("cookie", &session.cookie)],
            None,
        )
        .await?;
        let data = island(&reply.body, "presence-data").ok_or_else(invalid)?;
        if data["storageKey"] != session.storage_key.as_str() || data["nonce"] != nonce {
            return Err(invalid());
        }
        Ok(Self {
            addr: session.addr,
            nonce: nonce.to_owned(),
            cookie: session.cookie,
            proof: session.proof,
            data,
        })
    }

    /// This session, sending its later requests to `addr`: another socket of
    /// the same listener, such as `[::1]` on the port of a `localhost`
    /// ceremony.
    #[must_use]
    pub fn at(mut self, addr: SocketAddr) -> Self {
        self.addr = addr;
        self
    }

    /// The assertion origin of this listener.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("http://localhost:{}", self.addr.port())
    }

    /// The page data the consent page carries for its script.
    #[must_use]
    pub fn data(&self) -> &Value {
        &self.data
    }

    /// Sends one authorized request to a presence action.
    ///
    /// # Errors
    /// Returns a transport error or malformed page data.
    pub async fn post(&self, action: &str, body: &Value) -> io::Result<HttpReply> {
        request(
            self.addr,
            "POST",
            &format!("/approval/{}/{action}", self.nonce),
            &[
                ("cookie", &self.cookie),
                ("origin", &self.origin()),
                ("x-session-proof", &self.proof),
                (
                    "x-stellar-approval-csrf",
                    self.data["csrf"].as_str().ok_or_else(invalid)?,
                ),
                ("content-type", "application/json"),
            ],
            Some(&body.to_string()),
        )
        .await
    }

    /// Requests a challenge against the page this client reads.
    ///
    /// # Errors
    /// Returns a transport error or malformed page data.
    pub async fn challenge(&self) -> io::Result<HttpReply> {
        self.post(
            "challenge",
            &json!({"consent_view_digest": self.data["consent_view_digest"]}),
        )
        .await
    }
}

/// Exchanges the bootstrap token of `url`, a `http://localhost:{port}`
/// bootstrap URL, and reads the island of the page the exchange returns.
async fn bootstrap(url: &str) -> io::Result<Bootstrapped> {
    let suffix = url.strip_prefix("http://localhost:").ok_or_else(invalid)?;
    let (port, token) = suffix.split_once("/bootstrap/").ok_or_else(invalid)?;
    let addr = SocketAddr::from(([127, 0, 0, 1], port.parse().map_err(|_| invalid())?));
    let reply = request(addr, "GET", &format!("/bootstrap/{token}"), &[], None).await?;
    let cookie = reply
        .set_cookie
        .and_then(|v| v.split(';').next().map(str::to_owned))
        .ok_or_else(invalid)?;
    let data = island(&reply.body, "session-bootstrap-data").ok_or_else(invalid)?;
    let field = |name: &str| {
        data[name]
            .as_str()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(invalid)
    };
    Ok(Bootstrapped {
        addr,
        cookie,
        proof: field("proof")?,
        storage_key: field("storageKey")?,
        next: field("next")?,
    })
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "presence page unavailable")
}
