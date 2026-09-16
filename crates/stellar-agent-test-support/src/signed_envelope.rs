//! Signed-envelope fixtures whose signatures are real and whose accounts are
//! answerable by a mocked `getLedgerEntries`.
//!
//! Available only when the `test-helpers` cargo feature is enabled.
//!
//! A submit path verifies that each signature on an envelope was produced for
//! the network the endpoint serves, against the ed25519 signers of the
//! transaction's source accounts. A fixture built by hand from an arbitrary
//! key and an unrelated source account cannot satisfy that, so envelopes for
//! submit-path tests are built here: the source account is derived from the
//! signing seed, so the account's own master key is the signer, and the same
//! builder emits the `getLedgerEntries` body that reports it.
//!
//! # Inventory
//!
//! - [`SignedTestEnvelope`] — a built envelope plus its transaction hash and
//!   the JSON-RPC result bodies a mock server needs to answer for it.
//! - [`SignedTestEnvelopeBuilder`] — operation-level sources, fee-bump
//!   wrapping, signatures under any passphrase and by any key, forged
//!   signature hints, extra or hash-x signers, and accounts deliberately
//!   absent from the ledger.
//! - [`get_network_result`] — the `getNetwork` result body for a passphrase.
//!
//! All helpers are test-only and panic on malformed input per each item's
//! documented `# Panics` section.

#![allow(
    clippy::panic,
    reason = "test-helper fixture constructors expose documented panic paths"
)]

use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountEntry, AccountEntryExt, AccountId, Asset, ClaimClaimableBalanceOp, ClaimableBalanceId,
    DecoratedSignature, FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
    FeeBumpTransactionInnerTx, Hash, LedgerEntryData, LedgerKey, LedgerKeyAccount, Limits, Memo,
    MuxedAccount, Operation, OperationBody, PaymentOp, Preconditions, PublicKey, SequenceNumber,
    Signature, SignatureHint, Signer as XdrSigner, SignerKey, String32, Thresholds, Transaction,
    TransactionEnvelope, TransactionExt, TransactionSignaturePayload,
    TransactionSignaturePayloadTaggedTransaction, TransactionV1Envelope, Uint256, WriteXdr,
};

/// The canonical Stellar testnet passphrase.
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// The canonical Stellar mainnet passphrase.
pub const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// Default payment destination. A valid G-strkey that is never a source
/// account, so it needs no ledger entry.
const DEFAULT_DESTINATION: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

/// Default payment amount in stroops.
const DEFAULT_AMOUNT_STROOPS: i64 = 1_000_000;

/// Default native balance reported for every account in the ledger body.
const DEFAULT_BALANCE_STROOPS: i64 = 100_000_000_000;

/// Ledger sequence reported alongside every entry.
const FIXTURE_LEDGER_SEQ: u32 = 100;

/// Returns the ed25519 public key bytes for `seed`.
///
/// The seed is a test fixture, never a production key.
#[must_use]
pub fn public_key_for_seed(seed: [u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

/// Returns the G-strkey for `seed`.
#[must_use]
pub fn account_id_for_seed(seed: [u8; 32]) -> String {
    format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(public_key_for_seed(seed))
    )
}

/// Returns a `getNetwork` JSON-RPC result body reporting `passphrase`.
#[must_use]
pub fn get_network_result(passphrase: &str) -> Value {
    json!({
        "friendbotUrl": "https://friendbot.stellar.org",
        "passphrase": passphrase,
        "protocolVersion": 23
    })
}

/// Returns a `getLedgerEntries` result body reporting each account in
/// `account_ids` with no signers beyond its own master key.
///
/// For envelopes assembled outside [`SignedTestEnvelopeBuilder`]: as long as
/// each source account signed with its own key, this body answers the
/// signer-set fetch the submit path performs.
///
/// # Panics
///
/// Panics if an account ID is not a valid G-strkey or XDR encoding fails.
#[must_use]
pub fn ledger_entries_result_for(account_ids: &[&str]) -> Value {
    let accounts: Vec<LedgerAccount> = account_ids
        .iter()
        .map(|id| LedgerAccount::new(strkey_bytes(id)))
        .collect();
    ledger_entries_result(&accounts)
}

/// How one signature is produced.
#[derive(Clone)]
struct SignatureSpec {
    seed: [u8; 32],
    passphrase: String,
    /// Overrides the hint that would be derived from the signing key, so a
    /// signature can claim a hint belonging to a different signer.
    hint_override: Option<[u8; 4]>,
}

/// One account as the mocked `getLedgerEntries` will report it.
#[derive(Clone)]
struct LedgerAccount {
    key: [u8; 32],
    extra_signers: Vec<XdrSigner>,
    present: bool,
}

impl LedgerAccount {
    fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            extra_signers: Vec::new(),
            present: true,
        }
    }
}

/// A built envelope with real signatures, plus the JSON-RPC bodies a mock
/// server needs to answer for it.
#[derive(Clone, Debug)]
pub struct SignedTestEnvelope {
    source: String,
    source_seed: [u8; 32],
    sequence: i64,
    destination: String,
    envelope_xdr: String,
    tx_hash_hex: String,
    ledger_entries_result: Value,
    account_ids: Vec<String>,
}

impl SignedTestEnvelope {
    /// Builds a payment from `seed`'s account, sequence 1, signed by that
    /// account's own key under the testnet passphrase.
    ///
    /// # Panics
    ///
    /// Panics if XDR encoding fails.
    #[must_use]
    pub fn for_source(seed: [u8; 32]) -> Self {
        Self::builder(seed).build()
    }

    /// Builds a payment from `seed`'s account at `sequence`, signed by that
    /// account's own key under the testnet passphrase.
    ///
    /// # Panics
    ///
    /// Panics if XDR encoding fails.
    #[must_use]
    pub fn for_source_with_sequence(seed: [u8; 32], sequence: i64) -> Self {
        Self::builder(seed).sequence(sequence).build()
    }

    /// Starts a builder for a payment from `seed`'s account.
    #[must_use]
    pub fn builder(seed: [u8; 32]) -> SignedTestEnvelopeBuilder {
        SignedTestEnvelopeBuilder::new(seed)
    }

    /// The transaction source account's G-strkey.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The seed the source account was derived from.
    #[must_use]
    pub fn source_seed(&self) -> [u8; 32] {
        self.source_seed
    }

    /// The sequence number the transaction consumes.
    #[must_use]
    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    /// The payment destination's G-strkey.
    ///
    /// The destination is not a source account, so it has no signer set here;
    /// a caller that drives a policy gate reading destination state needs the
    /// address to answer for it.
    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// The signed envelope as base64 XDR.
    #[must_use]
    pub fn envelope_xdr(&self) -> &str {
        &self.envelope_xdr
    }

    /// The transaction hash, 64 lowercase hex characters, computed locally
    /// from the envelope under its own network passphrase.
    #[must_use]
    pub fn tx_hash_hex(&self) -> &str {
        &self.tx_hash_hex
    }

    /// A `getLedgerEntries` JSON-RPC result body reporting every source
    /// account of this envelope, with the signers the builder configured.
    ///
    /// Accounts marked absent are omitted, which is how a caller reproduces an
    /// operation source that does not exist on the ledger.
    #[must_use]
    pub fn ledger_entries_result(&self) -> Value {
        self.ledger_entries_result.clone()
    }

    /// Every source account named by this envelope, in the order the builder
    /// registered them.
    #[must_use]
    pub fn account_ids(&self) -> &[String] {
        &self.account_ids
    }
}

/// Builds a [`SignedTestEnvelope`].
///
/// Defaults: sequence 1, a single native payment to a fixed destination, one
/// signature by the source account's own key under the testnet passphrase, and
/// a ledger body reporting every source account with no extra signers.
pub struct SignedTestEnvelopeBuilder {
    source_seed: [u8; 32],
    sequence: i64,
    destination: [u8; 32],
    amount_stroops: i64,
    network_passphrase: String,
    operation_source: Option<[u8; 32]>,
    muxed_source_id: Option<u64>,
    claim_balance_id: Option<[u8; 32]>,
    fee_bump_source: Option<[u8; 32]>,
    inner_signatures: Option<Vec<SignatureSpec>>,
    outer_signatures: Vec<SignatureSpec>,
    ledger_overrides: Vec<(String, LedgerAccountOverride)>,
}

/// A change to how one account is reported by `getLedgerEntries`.
#[derive(Clone)]
enum LedgerAccountOverride {
    AddSigner(XdrSigner),
    Absent,
}

impl SignedTestEnvelopeBuilder {
    fn new(source_seed: [u8; 32]) -> Self {
        Self {
            source_seed,
            sequence: 1,
            destination: strkey_bytes(DEFAULT_DESTINATION),
            amount_stroops: DEFAULT_AMOUNT_STROOPS,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            operation_source: None,
            muxed_source_id: None,
            claim_balance_id: None,
            fee_bump_source: None,
            inner_signatures: None,
            outer_signatures: Vec::new(),
            ledger_overrides: Vec::new(),
        }
    }

    /// Sets the transaction sequence number.
    #[must_use]
    pub fn sequence(mut self, sequence: i64) -> Self {
        self.sequence = sequence;
        self
    }

    /// Makes the transaction source a muxed account (`M...`) carrying `id`
    /// over the same underlying `G...` account.
    ///
    /// The mux id selects a sub-account for memo purposes. The sequence
    /// number, the signer set and the ledger entry all belong to the account
    /// beneath it, so the signature and the reported signers are unchanged.
    #[must_use]
    pub fn muxed_source_id(mut self, id: u64) -> Self {
        self.muxed_source_id = Some(id);
        self
    }

    /// Sets the payment amount in stroops.
    #[must_use]
    pub fn amount_stroops(mut self, amount_stroops: i64) -> Self {
        self.amount_stroops = amount_stroops;
        self
    }

    /// Sets the passphrase the default signature is made under and the one the
    /// transaction hash is computed for.
    #[must_use]
    pub fn network_passphrase(mut self, passphrase: &str) -> Self {
        self.network_passphrase = passphrase.to_owned();
        self
    }

    /// Gives the payment operation its own source account, derived from
    /// `seed`. That account becomes a second source whose signers are gathered
    /// and reported.
    #[must_use]
    pub fn operation_source(mut self, seed: [u8; 32]) -> Self {
        self.operation_source = Some(seed);
        self
    }

    /// Replaces the payment with a `ClaimClaimableBalance` operation for
    /// `balance_id`.
    ///
    /// A policy gate that decodes under a claim tool name only recognises a
    /// claim-shaped envelope; a payment decodes to nothing there.
    #[must_use]
    pub fn claim_claimable_balance(mut self, balance_id: [u8; 32]) -> Self {
        self.claim_balance_id = Some(balance_id);
        self
    }

    /// Wraps the transaction in a fee-bump paid by `seed`'s account.
    ///
    /// Unless [`Self::sign_outer`] is called, the fee source signs the outer
    /// transaction with its own key under the builder's passphrase.
    #[must_use]
    pub fn fee_bump(mut self, seed: [u8; 32]) -> Self {
        self.fee_bump_source = Some(seed);
        self
    }

    /// Replaces the default signature set on the inner transaction with an
    /// explicit signature by `seed`'s key under `passphrase`.
    ///
    /// Repeated calls append.
    #[must_use]
    pub fn sign(mut self, seed: [u8; 32], passphrase: &str) -> Self {
        self.inner_signatures
            .get_or_insert_with(Vec::new)
            .push(SignatureSpec {
                seed,
                passphrase: passphrase.to_owned(),
                hint_override: None,
            });
        self
    }

    /// Appends a signature by `seed`'s key under `passphrase` that claims
    /// `hint` instead of the hint derived from the signing key.
    ///
    /// Reproduces a hint that matches a signer other than the one that
    /// actually signed.
    #[must_use]
    pub fn sign_with_hint(mut self, seed: [u8; 32], passphrase: &str, hint: [u8; 4]) -> Self {
        self.inner_signatures
            .get_or_insert_with(Vec::new)
            .push(SignatureSpec {
                seed,
                passphrase: passphrase.to_owned(),
                hint_override: Some(hint),
            });
        self
    }

    /// Leaves the inner transaction with no signatures at all.
    #[must_use]
    pub fn unsigned(mut self) -> Self {
        self.inner_signatures = Some(Vec::new());
        self
    }

    /// Appends an outer (fee-bump) signature by `seed`'s key under
    /// `passphrase`, replacing the default outer signature.
    ///
    /// # Panics
    ///
    /// Panics if the builder has no fee-bump source.
    #[must_use]
    pub fn sign_outer(mut self, seed: [u8; 32], passphrase: &str) -> Self {
        assert!(
            self.fee_bump_source.is_some(),
            "sign_outer requires fee_bump to have been called first"
        );
        self.outer_signatures.push(SignatureSpec {
            seed,
            passphrase: passphrase.to_owned(),
            hint_override: None,
        });
        self
    }

    /// Adds an ed25519 signer with weight 1 to `account_id`'s reported entry.
    #[must_use]
    pub fn ed25519_signer(mut self, account_id: &str, signer_seed: [u8; 32]) -> Self {
        let signer = XdrSigner {
            key: SignerKey::Ed25519(Uint256(public_key_for_seed(signer_seed))),
            weight: 1,
        };
        self.ledger_overrides.push((
            account_id.to_owned(),
            LedgerAccountOverride::AddSigner(signer),
        ));
        self
    }

    /// Adds a hash-x signer with weight 1 to `account_id`'s reported entry.
    ///
    /// A hash-x signer contributes no ed25519 key, so a signature whose hint
    /// matches it alone has no candidate to verify against.
    #[must_use]
    pub fn hash_x_signer(mut self, account_id: &str, key: [u8; 32]) -> Self {
        let signer = XdrSigner {
            key: SignerKey::HashX(Uint256(key)),
            weight: 1,
        };
        self.ledger_overrides.push((
            account_id.to_owned(),
            LedgerAccountOverride::AddSigner(signer),
        ));
        self
    }

    /// Omits `account_id` from the reported `getLedgerEntries` body, as the
    /// ledger would for an account that does not exist.
    #[must_use]
    pub fn absent_from_ledger(mut self, account_id: &str) -> Self {
        self.ledger_overrides
            .push((account_id.to_owned(), LedgerAccountOverride::Absent));
        self
    }

    /// Builds the envelope.
    ///
    /// # Panics
    ///
    /// Panics if XDR encoding fails or an operation list exceeds its bound.
    #[must_use]
    pub fn build(self) -> SignedTestEnvelope {
        let source_key = public_key_for_seed(self.source_seed);
        let source_strkey = account_id_for_seed(self.source_seed);

        let body = match self.claim_balance_id {
            Some(balance_id) => OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp {
                balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(balance_id)),
            }),
            None => OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256(self.destination)),
                asset: Asset::Native,
                amount: self.amount_stroops,
            }),
        };
        let operation = Operation {
            source_account: self
                .operation_source
                .map(|seed| MuxedAccount::Ed25519(Uint256(public_key_for_seed(seed)))),
            body,
        };

        let tx = Transaction {
            source_account: match self.muxed_source_id {
                Some(id) => MuxedAccount::MuxedEd25519(stellar_xdr::MuxedAccountMed25519 {
                    id,
                    ed25519: Uint256(source_key),
                }),
                None => MuxedAccount::Ed25519(Uint256(source_key)),
            },
            fee: 100,
            seq_num: SequenceNumber(self.sequence),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![operation]
                .try_into()
                .unwrap_or_else(|_err| panic!("one operation must fit the operation list")),
            ext: TransactionExt::V0,
        };

        // Default: the source account signs with its own key, so the envelope
        // is bound to the builder's network by a key the account reports.
        let inner_specs = self.inner_signatures.unwrap_or_else(|| {
            vec![SignatureSpec {
                seed: self.source_seed,
                passphrase: self.network_passphrase.clone(),
                hint_override: None,
            }]
        });

        let inner_tagged = TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone());
        let inner_signatures: Vec<DecoratedSignature> = inner_specs
            .iter()
            .map(|spec| decorated_signature(spec, &inner_tagged))
            .collect();

        let inner_envelope = TransactionV1Envelope {
            tx,
            signatures: inner_signatures
                .try_into()
                .unwrap_or_else(|_err| panic!("signature list must fit the 20-signature bound")),
        };

        // Accounts whose signers the submit path gathers, in a stable order.
        let mut account_ids: Vec<String> = vec![source_strkey.clone()];
        if let Some(seed) = self.operation_source {
            let strkey = account_id_for_seed(seed);
            if !account_ids.contains(&strkey) {
                account_ids.push(strkey);
            }
        }

        let (envelope, hash_tagged) = match self.fee_bump_source {
            None => {
                let tagged =
                    TransactionSignaturePayloadTaggedTransaction::Tx(inner_envelope.tx.clone());
                (TransactionEnvelope::Tx(inner_envelope), tagged)
            }
            Some(fee_seed) => {
                let fee_key = public_key_for_seed(fee_seed);
                let fee_strkey = account_id_for_seed(fee_seed);
                if !account_ids.contains(&fee_strkey) {
                    account_ids.push(fee_strkey);
                }

                let fee_bump_tx = FeeBumpTransaction {
                    fee_source: MuxedAccount::Ed25519(Uint256(fee_key)),
                    fee: 400,
                    inner_tx: FeeBumpTransactionInnerTx::Tx(inner_envelope),
                    ext: FeeBumpTransactionExt::V0,
                };

                let outer_specs = if self.outer_signatures.is_empty() {
                    vec![SignatureSpec {
                        seed: fee_seed,
                        passphrase: self.network_passphrase.clone(),
                        hint_override: None,
                    }]
                } else {
                    self.outer_signatures.clone()
                };

                let tagged =
                    TransactionSignaturePayloadTaggedTransaction::TxFeeBump(fee_bump_tx.clone());
                let outer_signatures: Vec<DecoratedSignature> = outer_specs
                    .iter()
                    .map(|spec| decorated_signature(spec, &tagged))
                    .collect();

                let envelope = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
                    tx: fee_bump_tx,
                    signatures: outer_signatures.try_into().unwrap_or_else(|_err| {
                        panic!("signature list must fit the 20-signature bound")
                    }),
                });
                (envelope, tagged)
            }
        };

        let envelope_xdr = envelope
            .to_xdr_base64(Limits::none())
            .unwrap_or_else(|err| panic!("TransactionEnvelope XDR encoding failed: {err}"));
        let tx_hash_hex = hex(&payload_hash(&self.network_passphrase, &hash_tagged));

        // Ledger bodies for every gathered account, with the caller's
        // overrides applied.
        let mut ledger_accounts: Vec<LedgerAccount> = account_ids
            .iter()
            .map(|strkey| LedgerAccount::new(strkey_bytes(strkey)))
            .collect();
        for (account_id, change) in &self.ledger_overrides {
            let target = strkey_bytes(account_id);
            let Some(entry) = ledger_accounts.iter_mut().find(|a| a.key == target) else {
                panic!("ledger override names {account_id}, which is not a source account");
            };
            match change {
                LedgerAccountOverride::AddSigner(signer) => {
                    entry.extra_signers.push(signer.clone());
                }
                LedgerAccountOverride::Absent => entry.present = false,
            }
        }

        SignedTestEnvelope {
            source: source_strkey,
            source_seed: self.source_seed,
            sequence: self.sequence,
            destination: format!("{}", stellar_strkey::ed25519::PublicKey(self.destination)),
            envelope_xdr,
            tx_hash_hex,
            ledger_entries_result: ledger_entries_result(&ledger_accounts),
            account_ids,
        }
    }
}

/// Builds a `getLedgerEntries` result body for the present accounts.
fn ledger_entries_result(accounts: &[LedgerAccount]) -> Value {
    let entries: Vec<Value> = accounts
        .iter()
        .filter(|a| a.present)
        .map(|a| {
            json!({
                "key": account_ledger_key(a.key),
                "xdr": account_entry(a),
                "lastModifiedLedgerSeq": FIXTURE_LEDGER_SEQ
            })
        })
        .collect();

    json!({
        "entries": entries,
        "latestLedger": FIXTURE_LEDGER_SEQ
    })
}

/// Encodes a `LedgerKey::Account` as base64 XDR.
fn account_ledger_key(key: [u8; 32]) -> String {
    LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key))),
    })
    .to_xdr_base64(Limits::none())
    .unwrap_or_else(|err| panic!("LedgerKey XDR encoding failed: {err}"))
}

/// Encodes a `LedgerEntryData::Account` as base64 XDR.
fn account_entry(account: &LedgerAccount) -> String {
    let entry = AccountEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account.key))),
        balance: DEFAULT_BALANCE_STROOPS,
        seq_num: SequenceNumber(1),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: String32::default(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: account
            .extra_signers
            .clone()
            .try_into()
            .unwrap_or_else(|_err| panic!("signer list must fit the 20-signer bound")),
        ext: AccountEntryExt::V0,
    };
    LedgerEntryData::Account(entry)
        .to_xdr_base64(Limits::none())
        .unwrap_or_else(|err| panic!("AccountEntry XDR encoding failed: {err}"))
}

/// Produces one decorated signature over `tagged` under the spec's passphrase.
fn decorated_signature(
    spec: &SignatureSpec,
    tagged: &TransactionSignaturePayloadTaggedTransaction,
) -> DecoratedSignature {
    let signing_key = SigningKey::from_bytes(&spec.seed);
    let hash = payload_hash(&spec.passphrase, tagged);
    let signature = signing_key.sign(&hash);

    let public_key = signing_key.verifying_key().to_bytes();
    let hint = spec.hint_override.unwrap_or_else(|| {
        let mut derived = [0u8; 4];
        derived.copy_from_slice(&public_key[28..32]);
        derived
    });

    DecoratedSignature {
        hint: SignatureHint(hint),
        signature: Signature(
            signature
                .to_bytes()
                .to_vec()
                .try_into()
                .unwrap_or_else(|_err| panic!("an ed25519 signature is 64 bytes")),
        ),
    }
}

/// Returns the SEP-23 payload hash for `tagged` under `passphrase`.
fn payload_hash(
    passphrase: &str,
    tagged: &TransactionSignaturePayloadTaggedTransaction,
) -> [u8; 32] {
    let payload = TransactionSignaturePayload {
        network_id: Hash(Sha256::digest(passphrase.as_bytes()).into()),
        tagged_transaction: tagged.clone(),
    };
    let bytes = payload
        .to_xdr(Limits::none())
        .unwrap_or_else(|err| panic!("TransactionSignaturePayload XDR encoding failed: {err}"));
    Sha256::digest(&bytes).into()
}

/// Computes the transaction hash a Stellar endpoint reports for
/// `envelope_xdr` under `passphrase`.
///
/// `SHA-256(network_id ‖ tagged transaction)`, built here from the decoded
/// envelope rather than borrowed from the wallet, so a mocked endpoint answers
/// what a real one would and the wallet's own computation is checked against
/// an independent one.
///
/// # Panics
///
/// Panics if `envelope_xdr` is not a decodable `TransactionEnvelope`, or is a
/// legacy `TxV0` envelope, which has no tagged-transaction form.
#[must_use]
pub fn transaction_hash_hex(envelope_xdr: &str, passphrase: &str) -> String {
    use stellar_xdr::{FeeBumpTransactionInnerTx, ReadXdr as _};

    let envelope = TransactionEnvelope::from_xdr_base64(envelope_xdr, Limits::none())
        .unwrap_or_else(|err| panic!("TransactionEnvelope decode failed: {err}"));
    let tagged = match &envelope {
        TransactionEnvelope::Tx(v1) => {
            TransactionSignaturePayloadTaggedTransaction::Tx(v1.tx.clone())
        }
        TransactionEnvelope::TxFeeBump(fb) => {
            let FeeBumpTransactionInnerTx::Tx(_) = &fb.tx.inner_tx;
            TransactionSignaturePayloadTaggedTransaction::TxFeeBump(fb.tx.clone())
        }
        TransactionEnvelope::TxV0(_) => {
            panic!("a legacy TxV0 envelope has no tagged-transaction form")
        }
    };
    hex(&payload_hash(passphrase, &tagged))
}

/// Computes the transaction hash for the envelope carried by a
/// `sendTransaction` JSON-RPC request body.
///
/// A mocked endpoint calls this to answer with the hash of the transaction it
/// was actually handed, the way a real endpoint does.
///
/// # Panics
///
/// Panics if the request carries no decodable `transaction` parameter.
#[must_use]
pub fn send_transaction_hash_hex(request_body: &Value, passphrase: &str) -> String {
    let envelope_xdr = request_body
        .get("params")
        .and_then(|p| p.get("transaction"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!("sendTransaction request carries no `params.transaction` string")
        });
    transaction_hash_hex(envelope_xdr, passphrase)
}

/// Decodes a G-strkey into its 32 key bytes.
fn strkey_bytes(strkey: &str) -> [u8; 32] {
    match stellar_strkey::ed25519::PublicKey::from_string(strkey) {
        Ok(pk) => pk.0,
        Err(err) => panic!("invalid G-strkey {strkey}: {err}"),
    }
}

/// Lowercase hex encoding.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        })
}
