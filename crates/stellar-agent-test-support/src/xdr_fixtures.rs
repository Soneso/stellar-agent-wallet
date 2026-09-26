//! XDR and JSON-RPC fixtures shared by integration tests.
//!
//! Available only when the `test-helpers` cargo feature is enabled (see the
//! crate front-door doc).
//!
//! # Inventory
//!
//! - [`EchoIdResponder`] — wiremock JSON-RPC responder that echoes the
//!   request `id` field and returns a fixed `result` payload.
//! - [`account_entry_xdr`] — synthetic `LedgerEntry` for an account with a
//!   given native-balance and `numSubEntries`.
//! - [`account_entry_xdr_with_balance`] — backward-compat 2-arg form passing
//!   `numSubEntries = 0`.
//! - [`account_entry_xdr_with_seq`] — synthetic account entry with explicit
//!   sequence number for cross-RPC divergence fixtures.
//! - [`account_ledger_key_xdr`] — `LedgerKey::Account` for the supplied
//!   account ID.
//! - [`trustline_entry_xdr`] — synthetic `LedgerEntry` for a credit-asset
//!   trustline (Alphanum4 only; Alphanum12 not supported).
//! - [`trustline_ledger_key_xdr`] — `LedgerKey::Trustline` for an
//!   Alphanum4 asset.
//! - [`contract_instance_ledger_entries_json`] — synthetic `getLedgerEntries`
//!   response for a WASM contract instance (`ContractExecutable::Wasm`).
//! - [`sac_instance_ledger_entries_json`] — same shape but with
//!   `ContractExecutable::StellarAsset` (SAC), for cross-parser parity tests.
//! - [`external_ref_instance_ledger_entries_json`] — same shape but with
//!   `ContractExecutable::ExternalRef` naming an owner and a tag.
//! - [`executable_tag_ledger_entries_json`] — the owner's persistent
//!   `ScVal::ExecutableTag` entry holding a 32-byte Wasm hash;
//!   [`executable_tag_ledger_entries_json_with_value`] takes any value.
//! - [`ledger_entry_from_response_json`] — extracts the single entry object
//!   from one of the response bodies above, for a keyed responder.
//!
//! All helpers are test-only; they panic on malformed inputs (account-ID
//! decode failure, asset-code length > 4) per the documented `# Panics`
//! section on each function. Production code MUST NOT depend on them — the
//! `test-helpers` feature is a dev-only opt-in per dep-discipline.

#![allow(
    clippy::panic,
    reason = "test-helper fixture constructors expose documented panic paths"
)]

pub use crate::echo_id_responder::EchoIdResponder;

fn public_key_bytes(label: &str, value: &str) -> [u8; 32] {
    match stellar_strkey::ed25519::PublicKey::from_string(value) {
        Ok(pk) => pk.0,
        Err(err) => panic!("invalid {label} G-strkey: {err}"),
    }
}

/// Builds a `LedgerEntryData::Account` XDR base64 string.
///
/// # Panics
///
/// Panics if `account_id` is not a valid G-strkey or if XDR encoding fails.
#[must_use]
pub fn account_entry_xdr(account_id: &str, balance_stroops: i64, num_sub_entries: u32) -> String {
    account_entry_xdr_with_seq(account_id, balance_stroops, num_sub_entries, 100)
}

/// Builds a `LedgerEntryData::Account` XDR base64 string with an explicit
/// sequence number.
///
/// # Panics
///
/// Panics if `account_id` is not a valid G-strkey or if XDR encoding fails.
#[must_use]
pub fn account_entry_xdr_with_seq(
    account_id: &str,
    balance_stroops: i64,
    num_sub_entries: u32,
    seq_num: i64,
) -> String {
    use stellar_xdr::{
        AccountEntry, AccountEntryExt, AccountId, LedgerEntryData, Limits, PublicKey,
        SequenceNumber, String32, Thresholds, Uint256, WriteXdr,
    };

    let pk_bytes = public_key_bytes("account_id", account_id);
    let entry = AccountEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
        balance: balance_stroops,
        seq_num: SequenceNumber(seq_num),
        num_sub_entries,
        inflation_dest: None,
        flags: 0,
        home_domain: String32::default(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: vec![]
            .try_into()
            .unwrap_or_else(|_err| panic!("empty signer vector must fit AccountEntry signer list")),
        ext: AccountEntryExt::V0,
    };
    LedgerEntryData::Account(entry)
        .to_xdr_base64(Limits::none())
        .unwrap_or_else(|err| panic!("AccountEntry XDR encoding failed: {err}"))
}

/// Builds a `LedgerEntryData::Account` XDR base64 string with zero subentries.
///
/// # Panics
///
/// Panics if `account_id` is not a valid G-strkey or if XDR encoding fails.
#[must_use]
pub fn account_entry_xdr_with_balance(account_id: &str, balance_stroops: i64) -> String {
    account_entry_xdr(account_id, balance_stroops, 0)
}

/// Builds a `LedgerKey::Account` XDR base64 string.
///
/// # Panics
///
/// Panics if `account_id` is not a valid G-strkey or if XDR encoding fails.
#[must_use]
pub fn account_ledger_key_xdr(account_id: &str) -> String {
    use stellar_xdr::{
        AccountId, LedgerKey, LedgerKeyAccount, Limits, PublicKey, Uint256, WriteXdr,
    };

    let pk_bytes = public_key_bytes("account_id", account_id);
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
    });
    key.to_xdr_base64(Limits::none())
        .unwrap_or_else(|err| panic!("account key XDR encoding failed: {err}"))
}

/// Builds a `LedgerEntryData::Trustline` XDR base64 string.
///
/// # Panics
///
/// Panics if `account_id` or `issuer` is not a valid G-strkey, or if XDR
/// encoding fails.
#[must_use]
pub fn trustline_entry_xdr(
    account_id: &str,
    asset_code: &str,
    issuer: &str,
    balance: i64,
) -> String {
    use stellar_xdr::{
        AccountId, AlphaNum4, AssetCode4, LedgerEntryData, Limits, PublicKey, TrustLineAsset,
        TrustLineEntry, TrustLineEntryExt, Uint256, WriteXdr,
    };

    let pk_bytes = public_key_bytes("account_id", account_id);
    let issuer_bytes = public_key_bytes("issuer", issuer);

    let mut code = [0u8; 4];
    let b = asset_code.as_bytes();
    let copy_len = b.len().min(4);
    code[..copy_len].copy_from_slice(&b[..copy_len]);

    let entry = TrustLineEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
        asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(code),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(issuer_bytes))),
        }),
        balance,
        limit: i64::MAX,
        flags: 0,
        ext: TrustLineEntryExt::V0,
    };
    LedgerEntryData::Trustline(entry)
        .to_xdr_base64(Limits::none())
        .unwrap_or_else(|err| panic!("TrustLine XDR encoding failed: {err}"))
}

/// Builds a JSON-RPC `getLedgerEntries` response body containing a single
/// `ContractData` entry for a WASM contract instance.
///
/// The returned string is a JSON object suitable as a wiremock response body
/// for testing `fetch_contract_wasm_hash`.
///
/// # Panics
///
/// Panics if `contract_address` is not a valid C-strkey or if XDR encoding
/// fails.
#[must_use]
pub fn contract_instance_ledger_entries_json(
    contract_address: &str,
    wasm_hash: [u8; 32],
) -> String {
    use stellar_xdr::{
        ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint,
        Hash, LedgerEntryData, LedgerKey, LedgerKeyContractData, Limits, ScAddress,
        ScContractInstance, ScMap, ScVal, WriteXdr,
    };

    let contract = stellar_strkey::Contract::from_string(contract_address)
        .unwrap_or_else(|e| panic!("invalid contract address: {e}"));

    let sc_addr = ScAddress::Contract(ContractId(Hash(contract.0)));
    let key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: sc_addr.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });

    let instance = ScContractInstance {
        executable: ContractExecutable::Wasm(Hash(wasm_hash)),
        storage: Some(ScMap(
            vec![]
                .try_into()
                .unwrap_or_else(|_| panic!("empty ScMap must fit")),
        )),
    };

    let entry_data = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: sc_addr,
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(instance),
    });

    let key_b64 = key
        .to_xdr_base64(Limits::none())
        .unwrap_or_else(|e| panic!("key XDR encode failed: {e}"));
    let val_b64 = entry_data
        .to_xdr_base64(Limits::none())
        .unwrap_or_else(|e| panic!("entry XDR encode failed: {e}"));

    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"entries":[{{"key":"{key_b64}","xdr":"{val_b64}","lastModifiedLedgerSeq":100,"liveUntilLedgerSeq":999999}}],"latestLedger":100}}}}"#
    )
}

/// Builds a JSON-RPC `getLedgerEntries` response body containing a single
/// `ContractData` entry for a Stellar Asset Contract (SAC) instance.
///
/// The entry's `executable` field is `ContractExecutable::StellarAsset`, which
/// is the on-chain XDR variant that indicates a SAC rather than an ordinary
/// WASM contract.  Parsers that look only for `ContractExecutable::Wasm` must
/// produce `None` / no hash for this entry, while parsers with an explicit SAC
/// arm must return their SAC variant.
///
/// The returned string is a JSON object suitable as a wiremock response body
/// for parity-testing both `stellar_agent_network::fetch_contract_wasm_hash`
/// (which maps `ContractExecutable::StellarAsset` → `WasmHashFetch::Sac`) and
/// `fetch_contract_wasm_hashes` (which maps SAC → `None` via the Wasm-only
/// match arm in `signers.rs`).
///
/// # Panics
///
/// Panics if `contract_address` is not a valid C-strkey or if XDR encoding
/// fails.
#[must_use]
pub fn sac_instance_ledger_entries_json(contract_address: &str) -> String {
    use stellar_xdr::{
        ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint,
        Hash, LedgerEntryData, LedgerKey, LedgerKeyContractData, Limits, ScAddress,
        ScContractInstance, ScVal, WriteXdr,
    };

    let contract = stellar_strkey::Contract::from_string(contract_address)
        .unwrap_or_else(|e| panic!("invalid contract address: {e}"));

    let sc_addr = ScAddress::Contract(ContractId(Hash(contract.0)));
    let key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: sc_addr.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });

    // ContractExecutable::StellarAsset — the SAC variant
    // (`pub enum ContractExecutable { Wasm(Hash), StellarAsset }`).
    let instance = ScContractInstance {
        executable: ContractExecutable::StellarAsset,
        storage: None,
    };

    let entry_data = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: sc_addr,
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(instance),
    });

    let key_b64 = key
        .to_xdr_base64(Limits::none())
        .unwrap_or_else(|e| panic!("key XDR encode failed: {e}"));
    let val_b64 = entry_data
        .to_xdr_base64(Limits::none())
        .unwrap_or_else(|e| panic!("entry XDR encode failed: {e}"));

    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"entries":[{{"key":"{key_b64}","xdr":"{val_b64}","lastModifiedLedgerSeq":100,"liveUntilLedgerSeq":999999}}],"latestLedger":100}}}}"#
    )
}

/// Builds a JSON-RPC `getLedgerEntries` response body containing a single
/// `ContractData` entry for a contract instance whose executable is a CAP-85
/// external reference (`ContractExecutable::ExternalRef`).
///
/// `owner_address` is the executable owner as a G- or C-strkey; `tag` is the
/// owner-chosen tag bytes. The instance carries no Wasm hash: the executable
/// is whatever the owner stores under its `ScVal::ExecutableTag(tag)` entry
/// (see [`executable_tag_ledger_entries_json`]).
///
/// # Panics
///
/// Panics if `contract_address` is not a valid C-strkey, if `owner_address`
/// is neither a valid G- nor C-strkey, or if XDR encoding fails.
#[must_use]
pub fn external_ref_instance_ledger_entries_json(
    contract_address: &str,
    owner_address: &str,
    tag: &[u8],
) -> String {
    use stellar_xdr::{
        ContractDataDurability, ContractDataEntry, ContractExecutable,
        ContractExecutableExternalRef, ContractId, ExtensionPoint, Hash, LedgerEntryData,
        LedgerKey, LedgerKeyContractData, ScAddress, ScContractInstance, ScVal,
    };

    let contract = stellar_strkey::Contract::from_string(contract_address)
        .unwrap_or_else(|e| panic!("invalid contract address: {e}"));
    let sc_addr = ScAddress::Contract(ContractId(Hash(contract.0)));

    let key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: sc_addr.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    let instance = ScContractInstance {
        executable: ContractExecutable::ExternalRef(ContractExecutableExternalRef {
            executable_owner: sc_address_from_strkey("owner_address", owner_address),
            tag: sc_string(tag),
        }),
        storage: None,
    };
    let entry_data = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: sc_addr,
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(instance),
    });

    single_entry_response_json(&key, &entry_data)
}

/// Builds a JSON-RPC `getLedgerEntries` response body containing the owner's
/// persistent `ContractData` entry keyed by `ScVal::ExecutableTag(tag)`,
/// holding `wasm_hash` as `ScVal::Bytes`.
///
/// This is the entry an external-reference instance built by
/// [`external_ref_instance_ledger_entries_json`] resolves through.
///
/// # Panics
///
/// Panics if `owner_address` is neither a valid G- nor C-strkey, or if XDR
/// encoding fails.
#[must_use]
pub fn executable_tag_ledger_entries_json(
    owner_address: &str,
    tag: &[u8],
    wasm_hash: [u8; 32],
) -> String {
    let bytes = stellar_xdr::ScBytes(
        wasm_hash
            .to_vec()
            .try_into()
            .unwrap_or_else(|_| panic!("32-byte hash must fit ScBytes")),
    );
    executable_tag_ledger_entries_json_with_value(
        owner_address,
        tag,
        stellar_xdr::ScVal::Bytes(bytes),
    )
}

/// Same as [`executable_tag_ledger_entries_json`] with an arbitrary `value`
/// stored under the tag key, for malformed-entry fixtures.
///
/// # Panics
///
/// Panics if `owner_address` is neither a valid G- nor C-strkey, or if XDR
/// encoding fails.
#[must_use]
pub fn executable_tag_ledger_entries_json_with_value(
    owner_address: &str,
    tag: &[u8],
    value: stellar_xdr::ScVal,
) -> String {
    use stellar_xdr::{
        ContractDataDurability, ContractDataEntry, ExtensionPoint, LedgerEntryData, LedgerKey,
        LedgerKeyContractData, ScVal,
    };

    let owner = sc_address_from_strkey("owner_address", owner_address);
    let key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: owner.clone(),
        key: ScVal::ExecutableTag(sc_string(tag)),
        durability: ContractDataDurability::Persistent,
    });
    let entry_data = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: owner,
        key: ScVal::ExecutableTag(sc_string(tag)),
        durability: ContractDataDurability::Persistent,
        val: value,
    });

    single_entry_response_json(&key, &entry_data)
}

/// Extracts the single `entries[0]` object from a response body built by one
/// of the `*_ledger_entries_json` fixtures, for registration with
/// [`crate::echo_id_responder::KeyedLedgerEntriesResponder::with_entry`].
///
/// # Panics
///
/// Panics if `response_json` is not valid JSON or carries no `entries[0]`.
#[must_use]
pub fn ledger_entry_from_response_json(response_json: &str) -> serde_json::Value {
    let parsed: serde_json::Value = serde_json::from_str(response_json)
        .unwrap_or_else(|e| panic!("fixture response is not JSON: {e}"));
    let entry = parsed["result"]["entries"][0].clone();
    if entry.is_null() {
        panic!("fixture response carries no entries[0]");
    }
    entry
}

fn sc_address_from_strkey(label: &str, value: &str) -> stellar_xdr::ScAddress {
    use stellar_xdr::{AccountId, ContractId, Hash, PublicKey, ScAddress, Uint256};

    if let Ok(contract) = stellar_strkey::Contract::from_string(value) {
        return ScAddress::Contract(ContractId(Hash(contract.0)));
    }
    let pk = public_key_bytes(label, value);
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk))))
}

fn sc_string(tag: &[u8]) -> stellar_xdr::ScString {
    stellar_xdr::ScString(
        tag.to_vec()
            .try_into()
            .unwrap_or_else(|_| panic!("tag exceeds the ScString length bound")),
    )
}

fn single_entry_response_json(
    key: &stellar_xdr::LedgerKey,
    entry_data: &stellar_xdr::LedgerEntryData,
) -> String {
    use stellar_xdr::{Limits, WriteXdr};

    let key_b64 = key
        .to_xdr_base64(Limits::none())
        .unwrap_or_else(|e| panic!("key XDR encode failed: {e}"));
    let val_b64 = entry_data
        .to_xdr_base64(Limits::none())
        .unwrap_or_else(|e| panic!("entry XDR encode failed: {e}"));

    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"entries":[{{"key":"{key_b64}","xdr":"{val_b64}","lastModifiedLedgerSeq":100,"liveUntilLedgerSeq":999999}}],"latestLedger":100}}}}"#
    )
}

/// Builds a `LedgerKey::Trustline` XDR base64 string.
///
/// # Panics
///
/// Panics if `account_id` or `issuer` is not a valid G-strkey, or if XDR
/// encoding fails.
#[must_use]
pub fn trustline_ledger_key_xdr(account_id: &str, asset_code: &str, issuer: &str) -> String {
    use stellar_xdr::{
        AccountId, AlphaNum4, AssetCode4, LedgerKey, LedgerKeyTrustLine, Limits, PublicKey,
        TrustLineAsset, Uint256, WriteXdr,
    };

    let pk_bytes = public_key_bytes("account_id", account_id);
    let issuer_bytes = public_key_bytes("issuer", issuer);

    let mut code = [0u8; 4];
    let b = asset_code.as_bytes();
    let copy_len = b.len().min(4);
    code[..copy_len].copy_from_slice(&b[..copy_len]);

    let key = LedgerKey::Trustline(LedgerKeyTrustLine {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
        asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(code),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(issuer_bytes))),
        }),
    });
    key.to_xdr_base64(Limits::none())
        .unwrap_or_else(|err| panic!("trustline key XDR encoding failed: {err}"))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;
    use stellar_xdr::{Limits, ReadXdr};

    fn g(seed: u8) -> String {
        format!("{}", stellar_strkey::ed25519::PublicKey([seed; 32]))
    }
    fn c(seed: u8) -> String {
        format!("{}", stellar_strkey::Contract([seed; 32]))
    }

    #[test]
    fn account_entry_decodes_with_fields() {
        let xdr = account_entry_xdr(&g(1), 5_000_000, 3);
        let stellar_xdr::LedgerEntryData::Account(a) =
            stellar_xdr::LedgerEntryData::from_xdr_base64(&xdr, Limits::none()).unwrap()
        else {
            panic!("expected Account");
        };
        assert_eq!(a.balance, 5_000_000);
        assert_eq!(a.num_sub_entries, 3);
        assert_eq!(a.seq_num.0, 100);
    }

    #[test]
    fn account_entry_with_seq_sets_sequence() {
        let xdr = account_entry_xdr_with_seq(&g(2), 1, 0, 4242);
        let stellar_xdr::LedgerEntryData::Account(a) =
            stellar_xdr::LedgerEntryData::from_xdr_base64(&xdr, Limits::none()).unwrap()
        else {
            panic!("expected Account");
        };
        assert_eq!(a.seq_num.0, 4242);
    }

    #[test]
    fn account_entry_with_balance_zero_subentries() {
        let xdr = account_entry_xdr_with_balance(&g(3), 99);
        let stellar_xdr::LedgerEntryData::Account(a) =
            stellar_xdr::LedgerEntryData::from_xdr_base64(&xdr, Limits::none()).unwrap()
        else {
            panic!("expected Account");
        };
        assert_eq!(a.balance, 99);
        assert_eq!(a.num_sub_entries, 0);
    }

    #[test]
    fn account_ledger_key_decodes() {
        let xdr = account_ledger_key_xdr(&g(4));
        let key = stellar_xdr::LedgerKey::from_xdr_base64(&xdr, Limits::none()).unwrap();
        assert!(matches!(key, stellar_xdr::LedgerKey::Account(_)));
    }

    #[test]
    fn trustline_entry_decodes_alphanum4() {
        let xdr = trustline_entry_xdr(&g(5), "USDC", &g(6), 777);
        let stellar_xdr::LedgerEntryData::Trustline(t) =
            stellar_xdr::LedgerEntryData::from_xdr_base64(&xdr, Limits::none()).unwrap()
        else {
            panic!("expected Trustline");
        };
        assert_eq!(t.balance, 777);
        assert!(matches!(
            t.asset,
            stellar_xdr::TrustLineAsset::CreditAlphanum4(_)
        ));
    }

    #[test]
    fn trustline_ledger_key_decodes() {
        let xdr = trustline_ledger_key_xdr(&g(7), "EURC", &g(8));
        let key = stellar_xdr::LedgerKey::from_xdr_base64(&xdr, Limits::none()).unwrap();
        assert!(matches!(key, stellar_xdr::LedgerKey::Trustline(_)));
    }

    #[test]
    fn contract_instance_json_carries_wasm_hash() {
        let body = contract_instance_ledger_entries_json(&c(9), [0xAB; 32]);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let xdr = v["result"]["entries"][0]["xdr"].as_str().unwrap();
        let stellar_xdr::LedgerEntryData::ContractData(cd) =
            stellar_xdr::LedgerEntryData::from_xdr_base64(xdr, Limits::none()).unwrap()
        else {
            panic!("expected ContractData");
        };
        let stellar_xdr::ScVal::ContractInstance(inst) = cd.val else {
            panic!("expected ContractInstance");
        };
        assert!(matches!(
            inst.executable,
            stellar_xdr::ContractExecutable::Wasm(stellar_xdr::Hash(h)) if h == [0xAB; 32]
        ));
    }

    #[test]
    fn sac_instance_json_is_stellar_asset() {
        let body = sac_instance_ledger_entries_json(&c(10));
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let xdr = v["result"]["entries"][0]["xdr"].as_str().unwrap();
        let stellar_xdr::LedgerEntryData::ContractData(cd) =
            stellar_xdr::LedgerEntryData::from_xdr_base64(xdr, Limits::none()).unwrap()
        else {
            panic!("expected ContractData");
        };
        let stellar_xdr::ScVal::ContractInstance(inst) = cd.val else {
            panic!("expected ContractInstance");
        };
        assert!(matches!(
            inst.executable,
            stellar_xdr::ContractExecutable::StellarAsset
        ));
    }

    #[test]
    fn external_ref_instance_json_names_owner_and_tag() {
        let body = external_ref_instance_ledger_entries_json(&c(11), &c(12), b"pool-v2");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let xdr = v["result"]["entries"][0]["xdr"].as_str().unwrap();
        let stellar_xdr::LedgerEntryData::ContractData(cd) =
            stellar_xdr::LedgerEntryData::from_xdr_base64(xdr, Limits::none()).unwrap()
        else {
            panic!("expected ContractData");
        };
        assert_eq!(cd.key, stellar_xdr::ScVal::LedgerKeyContractInstance);
        let stellar_xdr::ScVal::ContractInstance(inst) = cd.val else {
            panic!("expected ContractInstance");
        };
        let stellar_xdr::ContractExecutable::ExternalRef(ext) = inst.executable else {
            panic!("expected ExternalRef");
        };
        assert_eq!(
            ext.executable_owner,
            stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash([12; 32])))
        );
        assert_eq!(ext.tag.0.as_vec().as_slice(), b"pool-v2");
    }

    #[test]
    fn executable_tag_json_keys_by_tag_and_carries_hash() {
        let body = executable_tag_ledger_entries_json(&g(13), b"pool-v2", [0xCD; 32]);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let entry = &v["result"]["entries"][0];
        let key =
            stellar_xdr::LedgerKey::from_xdr_base64(entry["key"].as_str().unwrap(), Limits::none())
                .unwrap();
        let stellar_xdr::LedgerKey::ContractData(k) = key else {
            panic!("expected ContractData key");
        };
        assert_eq!(
            k.durability,
            stellar_xdr::ContractDataDurability::Persistent
        );
        assert!(matches!(
            &k.key,
            stellar_xdr::ScVal::ExecutableTag(t) if t.0.as_vec().as_slice() == b"pool-v2"
        ));
        assert!(matches!(k.contract, stellar_xdr::ScAddress::Account(_)));
        let stellar_xdr::LedgerEntryData::ContractData(cd) =
            stellar_xdr::LedgerEntryData::from_xdr_base64(
                entry["xdr"].as_str().unwrap(),
                Limits::none(),
            )
            .unwrap()
        else {
            panic!("expected ContractData");
        };
        assert!(matches!(
            cd.val,
            stellar_xdr::ScVal::Bytes(b) if b.0.as_vec().as_slice() == [0xCD; 32]
        ));
    }

    #[test]
    fn ledger_entry_from_response_json_returns_entry_object() {
        let body = sac_instance_ledger_entries_json(&c(14));
        let entry = ledger_entry_from_response_json(&body);
        assert!(entry["key"].is_string());
        assert!(entry["xdr"].is_string());
    }
}
