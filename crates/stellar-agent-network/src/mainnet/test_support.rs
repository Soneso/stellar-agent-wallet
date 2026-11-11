//! A mainnet profile with its authorization ledger, receipt store and keyed
//! audit writer, for integration tests of the authorized submission path.
//!
//! For tests only: the module exists only with the `mainnet-write` and
//! `test-helpers` features. A binary built with `test-helpers` embeds the
//! test-only `STELLAR_AGENT_HOME` override, which the release binary check
//! refuses. A grant is
//! minted through the window store's own mint, so the authorized submission
//! consumes it as it consumes a resolved grant.
//!
//! The fixture fixes the process-wide mainnet clock and installs the
//! in-memory keyring while it lives, so tests that use it run serially.
//! A fixture that cannot be set up or inspected panics with the cause, so
//! the calling test fails.

#![allow(
    clippy::panic,
    clippy::expect_used,
    reason = "test fixture; a failed inspection is a failed test"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use stellar_agent_test_support::signed_envelope::SignedTestEnvelope;

use super::AuthorizationId;
use super::fixtures::{self, LedgerFixture};
use crate::StellarRpcClient;
use crate::submission_record::{AuditWriterHandle, WalletSubmissionRecorder};
use crate::submit::MainnetSubmitGrant;

/// A mainnet profile in a temporary directory, for tests of the authorized
/// submission path.
pub struct AuthorizedSubmissionFixture {
    fx: LedgerFixture,
}

impl std::fmt::Debug for AuthorizedSubmissionFixture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizedSubmissionFixture")
            .field("profile", &self.fx.name)
            .finish_non_exhaustive()
    }
}

/// The signed envelope a test submits and the unsigned envelope a grant
/// binds, built from the fixture's source and sequence.
#[derive(Debug)]
pub struct FixtureEnvelope {
    /// The envelope the submission sends.
    pub signed: SignedTestEnvelope,
    /// The same transaction unsigned, which the grant binds.
    pub unsigned: SignedTestEnvelope,
}

impl AuthorizedSubmissionFixture {
    /// A fixture whose stores are fresh, with the mainnet clock fixed at
    /// `now_ms`.
    ///
    /// # Panics
    ///
    /// When a store cannot be set up.
    #[must_use]
    pub fn new(label: &str, now_ms: u64) -> Self {
        Self {
            fx: LedgerFixture::new(label, now_ms),
        }
    }

    /// Moves the fixed mainnet clock to `now_ms`.
    pub fn set_now(&mut self, now_ms: u64) {
        self.fx.clock.set(now_ms);
        self.fx.now = now_ms;
    }

    /// The profile's keyed, anchored audit writer.
    #[must_use]
    pub fn writer(&self) -> AuditWriterHandle {
        Arc::clone(&self.fx.writer)
    }

    /// The profile's active audit log.
    #[must_use]
    pub fn audit_log_path(&self) -> &Path {
        &self.fx.profile.audit_log_path
    }

    /// The fixture's temporary directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        self.fx.dir.path()
    }

    /// The receipt store's file, or `None` when the store names none.
    #[must_use]
    pub fn receipts_file(&self) -> Option<PathBuf> {
        self.fx.receipts.file_path().ok()
    }

    /// A payment from the fixture's source at its sequence, of
    /// `amount_stroops`, valid until `max_time_s`.
    #[must_use]
    pub fn envelope(&self, amount_stroops: i64, max_time_s: u64) -> FixtureEnvelope {
        let build = |signed: bool| {
            let builder = SignedTestEnvelope::builder(fixtures::SIGNER_SEED)
                .network_passphrase(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE)
                .time_bounds(0, max_time_s)
                .sequence(fixtures::SEQUENCE)
                .amount_stroops(amount_stroops);
            if signed {
                builder.build()
            } else {
                builder.unsigned().build()
            }
        };
        FixtureEnvelope {
            signed: build(true),
            unsigned: build(false),
        }
    }

    /// Mints a grant over `envelope` for `client`'s endpoint under the
    /// approval `nonce`, holding `hold_stroops` in the window when given and
    /// nothing otherwise.
    #[must_use]
    pub fn grant(
        &self,
        envelope: &FixtureEnvelope,
        client: &StellarRpcClient,
        hold_stroops: Option<i128>,
        nonce: &str,
    ) -> (AuthorizationId, MainnetSubmitGrant) {
        let binding = fixtures::tx_binding(
            envelope.unsigned.envelope_xdr(),
            envelope.unsigned.tx_hash_hex(),
        );
        let authorization = self.fx.mint(
            binding,
            &self.holds(hold_stroops),
            Some((client.url.authority(), client.id())),
            nonce,
        );
        (authorization.id(), MainnetSubmitGrant::Tx(authorization))
    }

    /// The wallet recorder of a `stellar_pay_commit` submission sizing the
    /// holds of [`Self::grant`], writing through `writer`.
    #[must_use]
    pub fn recorder(
        &self,
        hold_stroops: Option<i128>,
        writer: AuditWriterHandle,
    ) -> WalletSubmissionRecorder<'_> {
        self.fx.recorder(self.holds(hold_stroops), Some(writer))
    }

    /// Whether the ledger lists `id` as open.
    #[must_use]
    pub fn is_open(&self, id: AuthorizationId) -> bool {
        self.fx.is_open(id)
    }

    /// Whether the ledger still records `id` in any state.
    ///
    /// # Panics
    ///
    /// When the window store cannot be read or decoded, or a record's `id` or
    /// `state` does not decode to its typed form: an inspection failure
    /// never reads as absence.
    #[must_use]
    pub fn is_recorded(&self, id: AuthorizationId) -> bool {
        let wire = self.wire();
        let mut recorded = false;
        for (index, record) in records(&wire, "authorizations").into_iter().enumerate() {
            let record_id = typed_id(record, "authorizations", index, "id");
            typed_state(record, index);
            recorded |= record_id == id;
        }
        recorded
    }

    /// The number of reservation holds the window store keeps.
    ///
    /// # Panics
    ///
    /// When the window store cannot be read or decoded, or a hold's
    /// `authorization_id` or `amount` does not decode to its typed form.
    #[must_use]
    pub fn holds_recorded(&self) -> usize {
        let wire = self.wire();
        let holds = records(&wire, "holds");
        for (index, hold) in holds.iter().enumerate() {
            let _ = typed_id(hold, "holds", index, "authorization_id");
            typed_amount(hold, index);
        }
        holds.len()
    }

    /// The window store's file.
    #[must_use]
    pub fn window_store_path(&self) -> &Path {
        self.fx.window.path()
    }

    fn holds(
        &self,
        hold_stroops: Option<i128>,
    ) -> Vec<stellar_agent_core::policy::v1::criteria::state_store::WindowEntry> {
        hold_stroops
            .map(|amount| fixtures::hold(&self.fx.name, self.fx.now, amount))
            .into_iter()
            .collect()
    }

    /// The window store's body, a JSON object after the store's 32-byte tag.
    fn wire(&self) -> serde_json::Map<String, serde_json::Value> {
        let path = self.fx.window.path();
        let bytes = std::fs::read(path)
            .unwrap_or_else(|error| panic!("the window store {} reads: {error}", path.display()));
        let body = bytes
            .get(32..)
            .filter(|body| !body.is_empty())
            .unwrap_or_else(|| {
                panic!(
                    "the window store holds {} bytes, short of its 32-byte tag and a body",
                    bytes.len()
                )
            });
        match serde_json::from_slice(body) {
            Ok(serde_json::Value::Object(wire)) => wire,
            Ok(other) => panic!("the window store body is not an object: {other}"),
            Err(error) => panic!("the window store body does not decode: {error}"),
        }
    }
}

type WireObject = serde_json::Map<String, serde_json::Value>;

/// The states of the ledger's `AuthorizationState`, as the store writes them.
const LEDGER_STATES: [&str; 5] = ["open", "claimed", "used", "expired", "invalidated"];

/// The objects of the list `field` of `wire`. The store omits an empty list,
/// so an absent field is empty; any other shape fails.
fn records<'w>(wire: &'w WireObject, field: &str) -> Vec<&'w WireObject> {
    let items = match wire.get(field) {
        None => return Vec::new(),
        Some(serde_json::Value::Array(items)) => items,
        Some(other) => panic!("the window store's {field} is not a list: {other}"),
    };
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            item.as_object()
                .unwrap_or_else(|| panic!("{field}[{index}] is not an object: {item}"))
        })
        .collect()
}

/// The field `key` of `record`, the entry `index` of `field`.
fn required<'r>(
    record: &'r WireObject,
    field: &str,
    index: usize,
    key: &str,
) -> &'r serde_json::Value {
    record
        .get(key)
        .unwrap_or_else(|| panic!("{field}[{index}].{key} is missing"))
}

/// An authorization identifier, decoded as the ledger decodes one: 64
/// lowercase hex characters.
fn typed_id(record: &WireObject, field: &str, index: usize, key: &str) -> AuthorizationId {
    let value = required(record, field, index, key);
    serde_json::from_value(value.clone())
        .unwrap_or_else(|error| panic!("{field}[{index}].{key} is no identifier: {value}: {error}"))
}

/// An authorization's state, one of the ledger's states.
fn typed_state(record: &WireObject, index: usize) {
    let value = required(record, "authorizations", index, "state");
    if !value
        .as_str()
        .is_some_and(|state| LEDGER_STATES.contains(&state))
    {
        panic!("authorizations[{index}].state is no ledger state: {value}");
    }
}

/// A hold's amount, decoded as the store decodes one: a decimal string of an
/// `i128`.
fn typed_amount(record: &WireObject, index: usize) -> i128 {
    let value = required(record, "holds", index, "amount");
    value
        .as_str()
        .and_then(|text| text.parse::<i128>().ok())
        .unwrap_or_else(|| panic!("holds[{index}].amount is no decimal amount: {value}"))
}
