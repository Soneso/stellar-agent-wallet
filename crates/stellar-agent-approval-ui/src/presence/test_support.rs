//! HTTP driver for the shipped presence routes with synthetic assertions.
//!
//! The client navigates as the bootstrap page script does: it reads the
//! storage key and landing path from the bootstrap island, admits only the
//! pair `session-bootstrap.js` admits for the listener it expects, and loads
//! that landing path. It never chooses the first page itself.
use crate::auth::SessionPurpose;
use crate::operator_enroll::test_support::{HttpReply, island, request};
use serde_json::{Value, json};
use std::{io, net::SocketAddr};

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
