//! Test support for the enrollment ceremony: a software registrar that
//! produces real WebAuthn registration responses, and a loopback HTTP client
//! that drives a running enrollment server the way the page does.
//!
//! Enabled for tests and by the explicit `test-helpers` feature; the
//! release binaries are built without it.

use std::net::SocketAddr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::EnrollmentPurpose;
use super::confirmation::enrollment_confirmation_code;
use super::registration::{
    COSE_ALG_ES256, EnrollCredentialRequest, FLAG_AT, FLAG_UP, FLAG_UV, REGISTRATION_RP_ID,
};

/// A minimal CBOR encoder for building registration fixtures, including
/// malformed ones. Every head it writes uses the shortest encoding.
#[derive(Default)]
pub struct CborWriter {
    out: Vec<u8>,
}

impl CborWriter {
    fn head(&mut self, major: u8, value: u64) -> &mut Self {
        let major = major << 5;
        match value {
            0..=23 => self.out.push(major | u8::try_from(value).unwrap_or(0)),
            24..=0xff => {
                self.out.push(major | 24);
                self.out.push(u8::try_from(value).unwrap_or(0));
            }
            0x100..=0xffff => {
                self.out.push(major | 25);
                self.out
                    .extend_from_slice(&u16::try_from(value).unwrap_or(0).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.out.push(major | 26);
                self.out
                    .extend_from_slice(&u32::try_from(value).unwrap_or(0).to_be_bytes());
            }
            _ => {
                self.out.push(major | 27);
                self.out.extend_from_slice(&value.to_be_bytes());
            }
        }
        self
    }

    /// Writes an integer.
    pub fn int(&mut self, value: i64) -> &mut Self {
        if value >= 0 {
            self.head(0, value.unsigned_abs())
        } else {
            self.head(1, (value + 1).unsigned_abs())
        }
    }

    /// Writes a byte string.
    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.head(2, value.len() as u64);
        self.out.extend_from_slice(value);
        self
    }

    /// Writes a text string.
    pub fn text(&mut self, value: &str) -> &mut Self {
        self.head(3, value.len() as u64);
        self.out.extend_from_slice(value.as_bytes());
        self
    }

    /// Writes a map head for `entries` key-value pairs.
    pub fn map(&mut self, entries: usize) -> &mut Self {
        self.head(5, entries as u64)
    }

    /// Appends already-encoded bytes.
    pub fn raw(&mut self, encoded: &[u8]) -> &mut Self {
        self.out.extend_from_slice(encoded);
        self
    }

    /// The bytes written so far.
    #[must_use]
    pub fn finish(&self) -> Vec<u8> {
        self.out.clone()
    }
}

/// The COSE_Key of `public_key_sec1` with the given algorithm and curve
/// labels, in the label order authenticators emit.
#[must_use]
pub fn cose_es256_key(public_key_sec1: &[u8; 65], alg: i64, crv: i64) -> Vec<u8> {
    let mut w = CborWriter::default();
    w.map(5);
    w.int(1).int(2);
    w.int(3).int(alg);
    w.int(-1).int(crv);
    w.int(-2).bytes(&public_key_sec1[1..33]);
    w.int(-3).bytes(&public_key_sec1[33..]);
    w.finish()
}

/// A software authenticator with a fixed P-256 key pair and credential ID
/// that answers registration ceremonies with the `none` attestation format.
pub struct SoftwareRegistrar {
    public_key_sec1: [u8; 65],
    credential_id: Vec<u8>,
}

impl SoftwareRegistrar {
    /// A registrar whose key derives from `seed` and whose credential ID is
    /// `credential_id`.
    ///
    /// # Panics
    ///
    /// Panics when `seed` is not a valid P-256 scalar, which no fixed
    /// non-zero test seed below the curve order is.
    #[must_use]
    pub fn new(seed: [u8; 32], credential_id: Vec<u8>) -> Self {
        #[allow(
            clippy::expect_used,
            reason = "test support; a fixed seed below the curve order is a valid scalar"
        )]
        let secret = SecretKey::from_slice(&seed).expect("valid P-256 seed");
        let point = secret.public_key().to_encoded_point(false);
        let mut public_key_sec1 = [0u8; 65];
        public_key_sec1.copy_from_slice(point.as_bytes());
        Self {
            public_key_sec1,
            credential_id,
        }
    }

    /// The uncompressed SEC1 public key.
    #[must_use]
    pub fn public_key_sec1(&self) -> [u8; 65] {
        self.public_key_sec1
    }

    /// The raw credential ID.
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// The credential ID in unpadded base64url.
    #[must_use]
    pub fn credential_id_b64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.credential_id)
    }

    /// A builder for this registrar's response to `challenge` at `origin`,
    /// valid until a setter changes it.
    #[must_use]
    pub fn builder(&self, challenge: &[u8; 32], origin: &str) -> RegistrationBuilder {
        RegistrationBuilder {
            challenge: *challenge,
            origin: origin.to_owned(),
            client_type: "webauthn.create".to_owned(),
            cross_origin: None,
            client_data_raw: None,
            rp_id_hash: Sha256::digest(REGISTRATION_RP_ID.as_bytes()).into(),
            flags: FLAG_UP | FLAG_UV | FLAG_AT,
            sign_count: 0,
            attested_credential_id: self.credential_id.clone(),
            cose_key: cose_es256_key(&self.public_key_sec1, COSE_ALG_ES256, 1),
            auth_data_suffix: Vec::new(),
            format: "none".to_owned(),
            att_stmt: {
                let mut w = CborWriter::default();
                w.map(0);
                w.finish()
            },
            duplicate_fmt: false,
            attestation_object_raw: None,
            posted_credential_id: self.credential_id.clone(),
            posted_public_key: self.public_key_sec1,
            label: "laptop".to_owned(),
        }
    }
}

/// A registration response under construction. Each setter replaces one
/// part, so a test changes exactly the field it is about.
#[derive(Clone)]
pub struct RegistrationBuilder {
    challenge: [u8; 32],
    origin: String,
    client_type: String,
    cross_origin: Option<bool>,
    client_data_raw: Option<String>,
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    attested_credential_id: Vec<u8>,
    cose_key: Vec<u8>,
    auth_data_suffix: Vec<u8>,
    format: String,
    att_stmt: Vec<u8>,
    duplicate_fmt: bool,
    attestation_object_raw: Option<Vec<u8>>,
    posted_credential_id: Vec<u8>,
    posted_public_key: [u8; 65],
    label: String,
}

impl RegistrationBuilder {
    /// Sets `clientDataJSON.type`.
    #[must_use]
    pub fn client_type(mut self, value: &str) -> Self {
        value.clone_into(&mut self.client_type);
        self
    }

    /// Sets the challenge `clientDataJSON` carries.
    #[must_use]
    pub fn challenge(mut self, value: &[u8; 32]) -> Self {
        self.challenge = *value;
        self
    }

    /// Sets `clientDataJSON.origin`.
    #[must_use]
    pub fn origin(mut self, value: &str) -> Self {
        value.clone_into(&mut self.origin);
        self
    }

    /// Sets `clientDataJSON.crossOrigin`, or omits it for `None`.
    #[must_use]
    pub fn cross_origin(mut self, value: Option<bool>) -> Self {
        self.cross_origin = value;
        self
    }

    /// Replaces `clientDataJSON` with `value` verbatim.
    #[must_use]
    pub fn client_data_raw(mut self, value: String) -> Self {
        self.client_data_raw = Some(value);
        self
    }

    /// Sets the authenticator data's RP ID hash.
    #[must_use]
    pub fn rp_id_hash(mut self, value: [u8; 32]) -> Self {
        self.rp_id_hash = value;
        self
    }

    /// Sets the authenticator data's flags byte.
    #[must_use]
    pub fn flags(mut self, value: u8) -> Self {
        self.flags = value;
        self
    }

    /// Sets the authenticator data's signature counter.
    #[must_use]
    pub fn sign_count(mut self, value: u32) -> Self {
        self.sign_count = value;
        self
    }

    /// Sets the credential ID inside the authenticator data only.
    #[must_use]
    pub fn attested_credential_id(mut self, value: Vec<u8>) -> Self {
        self.attested_credential_id = value;
        self
    }

    /// Replaces the encoded COSE key inside the authenticator data.
    #[must_use]
    pub fn cose_key(mut self, value: Vec<u8>) -> Self {
        self.cose_key = value;
        self
    }

    /// Sets the posted SEC1 public key only.
    #[must_use]
    pub fn public_key(mut self, value: [u8; 65]) -> Self {
        self.posted_public_key = value;
        self
    }

    /// Appends `value` to the authenticator data after the COSE key.
    #[must_use]
    pub fn auth_data_suffix(mut self, value: Vec<u8>) -> Self {
        self.auth_data_suffix = value;
        self
    }

    /// Sets the attestation format.
    #[must_use]
    pub fn format(mut self, value: &str) -> Self {
        value.clone_into(&mut self.format);
        self
    }

    /// Replaces the encoded attestation statement.
    #[must_use]
    pub fn att_stmt(mut self, value: Vec<u8>) -> Self {
        self.att_stmt = value;
        self
    }

    /// Encodes `fmt` twice in the attestation object.
    #[must_use]
    pub fn duplicate_fmt(mut self) -> Self {
        self.duplicate_fmt = true;
        self
    }

    /// Replaces the attestation object with `value` verbatim.
    #[must_use]
    pub fn attestation_object_raw(mut self, value: Vec<u8>) -> Self {
        self.attestation_object_raw = Some(value);
        self
    }

    /// Sets the posted label.
    #[must_use]
    pub fn label(mut self, value: &str) -> Self {
        value.clone_into(&mut self.label);
        self
    }

    /// The `clientDataJSON` bytes.
    #[must_use]
    pub fn client_data_json(&self) -> Vec<u8> {
        if let Some(raw) = &self.client_data_raw {
            return raw.clone().into_bytes();
        }
        let cross_origin = self
            .cross_origin
            .map(|value| format!(r#","crossOrigin":{value}"#))
            .unwrap_or_default();
        format!(
            r#"{{"type":"{}","challenge":"{}","origin":"{}"{cross_origin}}}"#,
            self.client_type,
            URL_SAFE_NO_PAD.encode(self.challenge),
            self.origin
        )
        .into_bytes()
    }

    /// The authenticator data bytes.
    #[must_use]
    pub fn auth_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.rp_id_hash);
        data.push(self.flags);
        data.extend_from_slice(&self.sign_count.to_be_bytes());
        data.extend_from_slice(&[0u8; 16]);
        let id_len = u16::try_from(self.attested_credential_id.len()).unwrap_or(u16::MAX);
        data.extend_from_slice(&id_len.to_be_bytes());
        data.extend_from_slice(&self.attested_credential_id);
        data.extend_from_slice(&self.cose_key);
        data.extend_from_slice(&self.auth_data_suffix);
        data
    }

    /// The attestation object bytes.
    #[must_use]
    pub fn attestation_object(&self) -> Vec<u8> {
        if let Some(raw) = &self.attestation_object_raw {
            return raw.clone();
        }
        let mut w = CborWriter::default();
        w.map(if self.duplicate_fmt { 4 } else { 3 });
        w.text("fmt").text(&self.format);
        if self.duplicate_fmt {
            w.text("fmt").text(&self.format);
        }
        w.text("attStmt").raw(&self.att_stmt);
        w.text("authData").bytes(&self.auth_data());
        w.finish()
    }

    /// The request the page posts.
    pub(crate) fn request(&self) -> EnrollCredentialRequest {
        EnrollCredentialRequest {
            credential_id_b64url: URL_SAFE_NO_PAD.encode(&self.posted_credential_id),
            public_key_sec1_b64: URL_SAFE_NO_PAD.encode(self.posted_public_key),
            label: self.label.clone(),
            client_data_json: URL_SAFE_NO_PAD.encode(self.client_data_json()),
            attestation_object: URL_SAFE_NO_PAD.encode(self.attestation_object()),
        }
    }

    /// The JSON body the page posts to `POST /enroll/credential`.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        let request = self.request();
        serde_json::json!({
            "credential_id_b64url": request.credential_id_b64url,
            "public_key_sec1_b64": request.public_key_sec1_b64,
            "label": request.label,
            "client_data_json": request.client_data_json,
            "attestation_object": request.attestation_object,
        })
    }

    /// The operator credential confirmation code the page shows for this
    /// response.
    #[must_use]
    pub fn confirmation_code(&self) -> String {
        self.confirmation_code_for(EnrollmentPurpose::RemoteOperator)
    }

    /// The confirmation code a `purpose` page shows for this response.
    #[must_use]
    pub fn confirmation_code_for(&self, purpose: EnrollmentPurpose) -> String {
        enrollment_confirmation_code(
            purpose,
            &self.challenge,
            &self.posted_credential_id,
            &self.posted_public_key,
        )
    }
}

/// An HTTP response from the enrollment server.
#[derive(Debug)]
pub struct HttpReply {
    /// The status code.
    pub status: u16,
    /// The `Set-Cookie` header value, when present.
    pub set_cookie: Option<String>,
    /// The body as text.
    pub body: String,
}

impl HttpReply {
    /// The body parsed as JSON, or `Null` when it is not JSON.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// Drives a running enrollment server over loopback HTTP the way the
/// enrollment page does: bootstrap, page, challenge, credential.
pub struct EnrollmentClient {
    addr: SocketAddr,
    cookie: String,
    csrf: String,
    proof: String,
}

impl EnrollmentClient {
    /// Exchanges `bootstrap_token_hex` at the server on `addr` and reads the
    /// session cookie, the session proof and the page's CSRF value.
    ///
    /// # Errors
    ///
    /// Any transport error, or [`std::io::ErrorKind::InvalidData`] when a
    /// response lacks what the page reads from it.
    pub async fn connect(addr: SocketAddr, bootstrap_token_hex: &str) -> std::io::Result<Self> {
        let invalid =
            |what: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_owned());
        let bootstrap = request(
            addr,
            "GET",
            &format!("/bootstrap/{bootstrap_token_hex}"),
            &[],
            None,
        )
        .await?;
        if bootstrap.status != 200 {
            return Err(invalid("bootstrap refused"));
        }
        let cookie = bootstrap
            .set_cookie
            .as_deref()
            .and_then(|value| value.split(';').next())
            .ok_or_else(|| invalid("no session cookie"))?
            .to_owned();
        let proof = island(&bootstrap.body, "session-bootstrap-data")
            .and_then(|island| island["proof"].as_str().map(str::to_owned))
            .ok_or_else(|| invalid("no session proof"))?;
        let page = request(addr, "GET", "/enroll", &[("cookie", &cookie)], None).await?;
        let csrf = island(&page.body, "enroll-data")
            .and_then(|island| island["csrfToken"].as_str().map(str::to_owned))
            .ok_or_else(|| invalid("no CSRF value"))?;
        Ok(Self {
            addr,
            cookie,
            csrf,
            proof,
        })
    }

    /// The origin the page runs at.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("http://localhost:{}", self.addr.port())
    }

    async fn post(&self, path: &str, body: &serde_json::Value) -> std::io::Result<HttpReply> {
        let origin = self.origin();
        request(
            self.addr,
            "POST",
            path,
            &[
                ("cookie", &self.cookie),
                ("origin", &origin),
                ("x-stellar-approval-csrf", &self.csrf),
                ("x-session-proof", &self.proof),
                ("content-type", "application/json"),
            ],
            Some(&body.to_string()),
        )
        .await
    }

    /// `POST /enroll/challenge`.
    ///
    /// # Errors
    ///
    /// Any transport error.
    pub async fn challenge(&self) -> std::io::Result<HttpReply> {
        self.post("/enroll/challenge", &serde_json::json!({})).await
    }

    /// `POST /enroll/credential` with `body`.
    ///
    /// # Errors
    ///
    /// Any transport error.
    pub async fn post_credential(&self, body: &serde_json::Value) -> std::io::Result<HttpReply> {
        self.post("/enroll/credential", body).await
    }

    /// Runs the page's ceremony with `registrar`: requests a challenge,
    /// registers over it, posts the response, and returns the server's reply
    /// with the code an operator credential page shows.
    ///
    /// # Errors
    ///
    /// Any transport error, or [`std::io::ErrorKind::InvalidData`] when the
    /// challenge response carries no challenge.
    pub async fn register(
        &self,
        registrar: &SoftwareRegistrar,
        label: &str,
    ) -> std::io::Result<(HttpReply, String)> {
        let (reply, builder) = self.register_response(registrar, label).await?;
        Ok((reply, builder.confirmation_code()))
    }

    /// [`Self::register`], returning the posted response, from which the
    /// code of either page purpose follows through
    /// [`RegistrationBuilder::confirmation_code_for`].
    ///
    /// # Errors
    ///
    /// As [`Self::register`].
    pub async fn register_response(
        &self,
        registrar: &SoftwareRegistrar,
        label: &str,
    ) -> std::io::Result<(HttpReply, RegistrationBuilder)> {
        let reply = self.challenge().await?;
        let challenge: [u8; 32] = reply.json()["challenge"]
            .as_str()
            .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no challenge"))?;
        let builder = registrar.builder(&challenge, &self.origin()).label(label);
        let reply = self.post_credential(&builder.json()).await?;
        Ok((reply, builder))
    }
}

/// The JSON data island with `id` in `html`.
fn island(html: &str, id: &str) -> Option<serde_json::Value> {
    let open = format!(r#"<script type="application/json" id="{id}""#);
    let tag = html.find(&open)?;
    let start = tag + html[tag..].find('>')? + 1;
    let rest = &html[start..];
    let end = rest.find("</script>")?;
    serde_json::from_str(&rest[..end]).ok()
}

/// Sends one HTTP/1.1 request on a fresh connection and reads the response
/// to the end.
async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> std::io::Result<HttpReply> {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nhost: localhost:{}\r\nconnection: close\r\n",
        addr.port()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    let body = body.unwrap_or_default();
    head.push_str(&format!("content-length: {}\r\n\r\n", body.len()));
    head.push_str(body);
    stream.write_all(head.as_bytes()).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    parse_reply(&raw)
}

fn parse_reply(raw: &[u8]) -> std::io::Result<HttpReply> {
    let invalid =
        || std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed HTTP response");
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(invalid)?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| invalid())?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(invalid)?;
    let mut set_cookie = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("set-cookie") {
            set_cookie = Some(value.to_owned());
        }
        if name.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked") {
            chunked = true;
        }
    }
    let mut body = raw[split + 4..].to_vec();
    if chunked {
        body = dechunk(&body).ok_or_else(invalid)?;
    }
    Ok(HttpReply {
        status,
        set_cookie,
        body: String::from_utf8(body).map_err(|_| invalid())?,
    })
}

fn dechunk(mut input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = input.windows(2).position(|window| window == b"\r\n")?;
        let size_text = std::str::from_utf8(&input[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(input.get(..size)?);
        input = input.get(size + 2..)?;
    }
}
