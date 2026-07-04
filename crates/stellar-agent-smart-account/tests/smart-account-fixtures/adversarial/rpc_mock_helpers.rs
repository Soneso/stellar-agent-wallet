//! Shared RPC mock helpers for adversarial fixtures that require wiremock.
//!
//! Provides:
//! - `build_context_rule_scval_xdr` — encodes a minimal `ContextRule` ScVal::Map to XDR-base64.
//! - `build_simulate_response` — constructs a full `simulateTransaction` JSON-RPC result body.
//! - `build_ledger_entries_response` — constructs a `getLedgerEntries` JSON-RPC result body
//!   serving both account entries and contract-instance entries.
//! - `SorobanRpcDispatcher` — a `wiremock::Respond` implementation that dispatches
//!   by JSON-RPC `method` and sequence (call counter).
//! - `account_key_xdr` / `account_entry_xdr` / `contract_instance_entry_xdr` — XDR builders.
//! - `KNOWN_WASM_HASH` — the allowlisted wasm hash byte array from `THRESHOLD_POLICY_WASM_HASHES[0]`.
//! - `manager_two_url` — constructs a `SignersManager` with separate primary and secondary URLs.
//! - `write_baseline_for_observed` — writes a `SaSignerSetBaselined` audit entry.
//! - `zero_sc_address` / `zero_policy_sc_address` — helper addresses.
//! - `signer_set_n_of_n` — builds an `ObservedSignerSet` with N identical Ed25519 signers.
//!
//! All helpers are `pub` so they can be referenced from `#[path]`-included sub-modules.
//!
//! # Implements
//!
//! Shared adversarial fixture layer for signer-set integrity verification.

#![allow(
    dead_code,
    reason = "not all helpers are used by every fixture sub-module"
)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::signer_set::{BaselineReason, ObservedSignerSet, SignerPubkey};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::RedactedStrkey;
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};
use stellar_xdr::{
    AccountEntry, AccountEntryExt, AccountId, BytesM, ContractDataDurability, ContractDataEntry,
    ContractExecutable, ContractId, ExtensionPoint, Hash, LedgerEntryData, LedgerKey,
    LedgerKeyAccount, LedgerKeyContractData, Limits, PublicKey, ScAddress, ScBytes,
    ScContractInstance, ScMap, ScMapEntry, ScString, ScSymbol, ScVal, ScVec, SequenceNumber,
    String32, Thresholds, Uint256, VecM, WriteXdr,
};
use uuid::Uuid;
use wiremock::{Request, Respond, ResponseTemplate};

// ── Known wasm hash from THRESHOLD_POLICY_WASM_HASHES[0] ─────────────────────

/// The OZ threshold-policy WASM hash from the compile-time allowlist.
///
/// Value: `4c14f402df29675d4155283698c436ee588aacb39adc313845010a565c07567d`
/// (OZ multisig-threshold-policy-example v0.7.2, SHA `a9c4216`) —
/// `THRESHOLD_POLICY_WASM_HASHES[0]`, the canonical deploy hash. The legacy
/// v0.7.1 hash is `THRESHOLD_POLICY_WASM_HASHES[1]`; both are allowlisted.
pub const KNOWN_WASM_HASH: [u8; 32] = [
    0x4c, 0x14, 0xf4, 0x02, 0xdf, 0x29, 0x67, 0x5d, 0x41, 0x55, 0x28, 0x36, 0x98, 0xc4, 0x36, 0xee,
    0x58, 0x8a, 0xac, 0xb3, 0x9a, 0xdc, 0x31, 0x38, 0x45, 0x01, 0x0a, 0x56, 0x5c, 0x07, 0x56, 0x7d,
];

/// Unknown wasm hash — not in the allowlist.
pub const UNKNOWN_WASM_HASH: [u8; 32] = [0xddu8; 32];

// ── Source account G-strkey used in all simulate_read_only calls ──────────────

/// The source G-strkey used as `source_account_strkey` in all verify calls.
///
/// This is a well-known testnet key (`G...WHF`) whose pubkey bytes the mock
/// `getLedgerEntries` account response must encode correctly.
pub const SOURCE_G: &str = stellar_agent_core::constants::SIMULATE_SENTINEL_G;

// ── Address helpers ───────────────────────────────────────────────────────────

/// A zero-hash smart-account contract address (`CAAAA...AD2KM`).
pub fn zero_sc_address() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0u8; 32])))
}

/// A policy contract address (`[0x01; 32]` hash bytes).
pub fn policy_sc_address() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x01u8; 32])))
}

/// A second policy contract address (`[0x02; 32]` hash bytes) — used in multi-match tests.
pub fn policy2_sc_address() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x02u8; 32])))
}

// ── Signer-set builders ───────────────────────────────────────────────────────

/// Builds an `ObservedSignerSet` with `n` Ed25519 signers.
///
/// Signer IDs are `[0, 1, ..., n-1]`. Pubkeys are `[0x11; 32]` for signer 0,
/// `[0x12; 32]` for signer 1, etc. (each byte is `0x10 + id`, capped at 0xff).
/// Threshold is set to `n`.
pub fn signer_set_n_of_n(n: u32) -> ObservedSignerSet {
    let signer_count = n;
    let signer_ids: Vec<u32> = (0..n).collect();
    let signer_pubkeys = (0..n)
        .map(|i| {
            let byte = (0x10u8).wrapping_add(i as u8);
            SignerPubkey::Ed25519 { pubkey: [byte; 32] }
        })
        .collect();
    ObservedSignerSet {
        signer_count,
        threshold: n,
        signer_ids,
        signer_pubkeys,
    }
}

// ── XDR helpers ───────────────────────────────────────────────────────────────

/// Encodes a `LedgerKey::Account` for a G-strkey to XDR base64.
///
/// Used as the `key` field in `getLedgerEntries` account responses so that
/// `fetch_account` can decode the key and extract the sequence number.
pub fn account_key_xdr(g: &str) -> String {
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(g)
        .expect("valid G-strkey")
        .0;
    LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
    })
    .to_xdr_base64(Limits::none())
    .expect("LedgerKey::Account XDR must encode")
}

/// Encodes an `AccountEntry` for a G-strkey with the given sequence number to XDR base64.
///
/// The `xdr` field in `getLedgerEntries` entries must encode `LedgerEntryData::Account`
/// so that `fetch_account` classifies the entry as an account and extracts `seq_num`.
pub fn account_entry_xdr(g: &str, seq: i64) -> String {
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(g)
        .expect("valid G-strkey")
        .0;
    let entry = AccountEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
        balance: 10_000_000_000,
        seq_num: SequenceNumber(seq),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: String32::default(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: vec![].try_into().expect("empty signers"),
        ext: AccountEntryExt::V0,
    };
    LedgerEntryData::Account(entry)
        .to_xdr_base64(Limits::none())
        .expect("AccountEntry XDR must encode")
}

/// Encodes a `LedgerKey::ContractData(ContractInstance)` for a contract address.
pub fn contract_instance_key_xdr(addr: &ScAddress) -> String {
    LedgerKey::ContractData(LedgerKeyContractData {
        contract: addr.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    })
    .to_xdr_base64(Limits::none())
    .expect("LedgerKey::ContractData XDR must encode")
}

/// Encodes a `LedgerEntryData::ContractData(ContractInstance{Wasm(hash)})` to XDR base64.
///
/// Used as the `xdr` field in `getLedgerEntries` contract-instance responses so that
/// `fetch_contract_wasm_hashes` can extract the wasm hash.
pub fn contract_instance_entry_xdr(contract: &ScAddress, wasm_hash: [u8; 32]) -> String {
    let instance = ScContractInstance {
        executable: ContractExecutable::Wasm(Hash(wasm_hash)),
        storage: None,
    };
    LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: contract.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(instance),
    })
    .to_xdr_base64(Limits::none())
    .expect("ContractInstance XDR must encode")
}

// ── ContextRule ScVal builder ─────────────────────────────────────────────────

/// Builds a `ContextRule` `ScVal::Map` and encodes it to XDR base64.
///
/// The `ContextRule` 8-field `#[contracttype]` struct sorted lexicographically
/// by key (per soroban-sdk derive): `context_type`, `id`, `name`, `policies`,
/// `policy_ids`, `signer_ids`, `signers`, `valid_until`.
///
/// Produces a well-formed ScVal that `parse_context_rule_summary` can decode:
/// `context_type` = `ScVal::Vec([Symbol("Default")])`, `name` = `ScVal::String("rule-{id}")`,
/// `valid_until` = `ScVal::Void` (None variant, canonical soroban-env-common/src/option.rs:3-16).
///
/// The `signer_ids`, `signers`, and `policies` fields are fully populated from
/// the supplied arguments.
///
/// # Byte-layout citation
///
/// `stellar-accounts-0.7.2/src/smart_account/storage.rs:153-174` (SHA `a9c4216`):
/// `ContextRule` 8-field `#[contracttype]` struct; soroban-sdk-macros
/// `derive_type_struct` produces `ScVal::Map` sorted by `ScVal::Symbol` key.
pub fn build_context_rule_scval_xdr(
    rule_id: u32,
    signers: &ObservedSignerSet,
    policies: &[ScAddress],
) -> String {
    // Build signer ScVals: Delegated(Address) for each Ed25519 signer.
    // OZ Signer contracttype: `Delegated(Address)` →
    //   `ScVal::Vec([Symbol("Delegated"), Address(account_addr)])`
    // storage.rs:96-102 (SHA `a9c4216`).
    let signer_scvals: Vec<ScVal> = signers
        .signer_pubkeys
        .iter()
        .map(|pk| {
            let pubkey = match pk {
                SignerPubkey::Ed25519 { pubkey } => *pubkey,
                SignerPubkey::External { .. } => [0u8; 32],
                _ => [0u8; 32],
            };
            let addr =
                ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pubkey))));
            let tag = ScVal::Symbol(ScSymbol(
                b"Delegated".to_vec().try_into().expect("Delegated fits"),
            ));
            let items: VecM<ScVal> = vec![tag, ScVal::Address(addr)]
                .try_into()
                .expect("signer Vec fits");
            ScVal::Vec(Some(ScVec(items)))
        })
        .collect();

    let signer_ids_scvals: Vec<ScVal> = signers
        .signer_ids
        .iter()
        .map(|id| ScVal::U32(*id))
        .collect();

    let policies_scvals: Vec<ScVal> = policies
        .iter()
        .map(|addr| ScVal::Address(addr.clone()))
        .collect();

    // Build the ScMap. Keys must be sorted lexicographically (alphabetical by name).
    // Sorted order: context_type, id, name, policies, policy_ids, signer_ids, signers, valid_until.
    let sym = |s: &[u8]| {
        ScVal::Symbol(ScSymbol(
            s.to_vec().try_into().expect("symbol fits in StringM<32>"),
        ))
    };

    let vec_or_void = |v: Vec<ScVal>| -> ScVal {
        let vm: VecM<ScVal> = v.try_into().expect("vec fits");
        ScVal::Vec(Some(ScVec(vm)))
    };

    // context_type: `Default` variant = ScVal::Vec([Symbol("Default")]).
    // OZ contracttype enum encoding: leading Symbol("VariantName") + payload.
    // storage.rs:96 (SHA a9c4216).
    let context_type_vec: VecM<ScVal> = vec![sym(b"Default")]
        .try_into()
        .expect("context_type Vec fits");
    let context_type_entry = ScMapEntry {
        key: sym(b"context_type"),
        val: ScVal::Vec(Some(ScVec(context_type_vec))),
    };
    // id: u32
    let id_entry = ScMapEntry {
        key: sym(b"id"),
        val: ScVal::U32(rule_id),
    };
    // name: ScVal::String("rule-{rule_id}").
    // soroban-sdk encodes String fields as ScVal::String(ScString).
    let name_str = format!("rule-{rule_id}");
    let name_entry = ScMapEntry {
        key: sym(b"name"),
        val: ScVal::String(ScString(
            name_str
                .into_bytes()
                .try_into()
                .expect("name fits in StringM"),
        )),
    };
    // policies: Vec<Address>
    let policies_entry = ScMapEntry {
        key: sym(b"policies"),
        val: vec_or_void(policies_scvals),
    };
    // policy_ids: placeholder empty Vec
    let policy_ids_entry = ScMapEntry {
        key: sym(b"policy_ids"),
        val: vec_or_void(vec![]),
    };
    // signer_ids: Vec<u32>
    let signer_ids_entry = ScMapEntry {
        key: sym(b"signer_ids"),
        val: vec_or_void(signer_ids_scvals),
    };
    // signers: Vec<Signer>
    let signers_entry = ScMapEntry {
        key: sym(b"signers"),
        val: vec_or_void(signer_scvals),
    };
    // valid_until: soroban `Option<u32>` None variant.
    // Canonical ABI per soroban-env-common/src/option.rs:3-16:
    //   None  → ScVal::Void
    //   Some(n) → ScVal::U32(n)
    // The canonical `Option<u32>` ABI uses ScVal::Void for None and ScVal::U32(n) for Some(n),
    // not the enum-variant Map shape which is the ABI for #[contracttype] enums.
    let valid_until_entry = ScMapEntry {
        key: sym(b"valid_until"),
        val: ScVal::Void, // None variant
    };

    let map: VecM<ScMapEntry> = vec![
        context_type_entry,
        id_entry,
        name_entry,
        policies_entry,
        policy_ids_entry,
        signer_ids_entry,
        signers_entry,
        valid_until_entry,
    ]
    .try_into()
    .expect("ScMap entries fit");

    let scval = ScVal::Map(Some(ScMap(map)));
    scval
        .to_xdr_base64(Limits::none())
        .expect("ContextRule ScVal::Map must encode to XDR")
}

/// Builds a `ContextRule` `ScVal::Map` with an explicit `valid_until` value and
/// encodes it to XDR base64.
///
/// The `valid_until` field uses the canonical soroban `Option<u32>` ABI:
/// - `None` → `ScVal::Void`
/// - `Some(n)` → `ScVal::U32(n)`
///
/// Canonical citation: `soroban-env-common/src/option.rs:3-16`.
///
/// # Byte-layout citation
///
/// `stellar-accounts-0.7.2/src/smart_account/storage.rs:153-174` (SHA `a9c4216`);
/// `soroban-env-common/src/option.rs:3-16`.
pub fn build_context_rule_scval_xdr_with_valid_until(
    rule_id: u32,
    signers: &ObservedSignerSet,
    policies: &[ScAddress],
    valid_until: Option<u32>,
) -> String {
    let signer_scvals: Vec<ScVal> = signers
        .signer_pubkeys
        .iter()
        .map(|pk| {
            let pubkey = match pk {
                SignerPubkey::Ed25519 { pubkey } => *pubkey,
                SignerPubkey::External { .. } => [0u8; 32],
                _ => [0u8; 32],
            };
            let addr =
                ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pubkey))));
            let tag = ScVal::Symbol(ScSymbol(
                b"Delegated".to_vec().try_into().expect("Delegated fits"),
            ));
            let items: VecM<ScVal> = vec![tag, ScVal::Address(addr)]
                .try_into()
                .expect("signer Vec fits");
            ScVal::Vec(Some(ScVec(items)))
        })
        .collect();

    let signer_ids_scvals: Vec<ScVal> = signers
        .signer_ids
        .iter()
        .map(|id| ScVal::U32(*id))
        .collect();

    let policies_scvals: Vec<ScVal> = policies
        .iter()
        .map(|addr| ScVal::Address(addr.clone()))
        .collect();

    let sym = |s: &[u8]| {
        ScVal::Symbol(ScSymbol(
            s.to_vec().try_into().expect("symbol fits in StringM<32>"),
        ))
    };
    let vec_or_void = |v: Vec<ScVal>| -> ScVal {
        let vm: VecM<ScVal> = v.try_into().expect("vec fits");
        ScVal::Vec(Some(ScVec(vm)))
    };

    let context_type_vec: VecM<ScVal> = vec![sym(b"Default")]
        .try_into()
        .expect("context_type Vec fits");
    let context_type_entry = ScMapEntry {
        key: sym(b"context_type"),
        val: ScVal::Vec(Some(ScVec(context_type_vec))),
    };
    let id_entry = ScMapEntry {
        key: sym(b"id"),
        val: ScVal::U32(rule_id),
    };
    let name_str = format!("rule-{rule_id}");
    let name_entry = ScMapEntry {
        key: sym(b"name"),
        val: ScVal::String(ScString(
            name_str
                .into_bytes()
                .try_into()
                .expect("name fits in StringM"),
        )),
    };
    let policies_entry = ScMapEntry {
        key: sym(b"policies"),
        val: vec_or_void(policies_scvals),
    };
    let policy_ids_entry = ScMapEntry {
        key: sym(b"policy_ids"),
        val: vec_or_void(vec![]),
    };
    let signer_ids_entry = ScMapEntry {
        key: sym(b"signer_ids"),
        val: vec_or_void(signer_ids_scvals),
    };
    let signers_entry = ScMapEntry {
        key: sym(b"signers"),
        val: vec_or_void(signer_scvals),
    };
    // Canonical Option<u32> ABI: None → Void, Some(n) → U32(n).
    let valid_until_val = match valid_until {
        None => ScVal::Void,
        Some(n) => ScVal::U32(n),
    };
    let valid_until_entry = ScMapEntry {
        key: sym(b"valid_until"),
        val: valid_until_val,
    };

    let map: VecM<ScMapEntry> = vec![
        context_type_entry,
        id_entry,
        name_entry,
        policies_entry,
        policy_ids_entry,
        signer_ids_entry,
        signers_entry,
        valid_until_entry,
    ]
    .try_into()
    .expect("ScMap entries fit");

    let scval = ScVal::Map(Some(ScMap(map)));
    scval
        .to_xdr_base64(Limits::none())
        .expect("ContextRule ScVal::Map (with_valid_until) must encode to XDR")
}

/// Builds a `ContextRule` `ScVal::Map` with `External(Address, Bytes)` signers
/// and encodes it to XDR base64.
///
/// Used by verifier-migration fixtures to build rules containing External signers
/// whose verifier addresses reference `verifier_addr` with `key_data` bytes.
///
/// The 8-field layout is identical to [`build_context_rule_scval_xdr`] but with
/// `Signer::External(Address, Bytes)` ScVal encoding:
/// `ScVal::Vec([Symbol("External"), Address(verifier_addr), Bytes(key_data)])`.
///
/// # Byte-layout citation
///
/// `Signer::External(Address, Bytes)` at
/// `stellar-accounts-0.7.2/src/smart_account/storage.rs:96-102` (SHA `a9c4216`):
/// `External(Address, Bytes)` → `ScVal::Vec([Symbol("External"), Address(...), Bytes(...)])`.
pub fn build_context_rule_external_signers_xdr(
    rule_id: u32,
    signer_ids: &[u32],
    verifier_addr: &ScAddress,
    key_data: &[u8],
) -> String {
    let sym = |s: &[u8]| {
        ScVal::Symbol(ScSymbol(
            s.to_vec().try_into().expect("symbol fits in StringM<32>"),
        ))
    };

    let vec_or_void = |v: Vec<ScVal>| -> ScVal {
        let vm: VecM<ScVal> = v.try_into().expect("vec fits");
        ScVal::Vec(Some(ScVec(vm)))
    };

    // Build External signer ScVals:
    // `ScVal::Vec([Symbol("External"), Address(verifier_addr), Bytes(key_data)])`.
    let signer_scvals: Vec<ScVal> = signer_ids
        .iter()
        .map(|_id| {
            let key_bytes: BytesM = key_data.to_vec().try_into().expect("key_data fits BytesM");
            let items: VecM<ScVal> = vec![
                sym(b"External"),
                ScVal::Address(verifier_addr.clone()),
                ScVal::Bytes(ScBytes(key_bytes)),
            ]
            .try_into()
            .expect("External signer Vec fits");
            ScVal::Vec(Some(ScVec(items)))
        })
        .collect();

    let signer_ids_scvals: Vec<ScVal> = signer_ids.iter().map(|id| ScVal::U32(*id)).collect();

    // context_type: Default variant.
    let context_type_vec: VecM<ScVal> = vec![sym(b"Default")]
        .try_into()
        .expect("context_type Vec fits");
    let context_type_entry = ScMapEntry {
        key: sym(b"context_type"),
        val: ScVal::Vec(Some(ScVec(context_type_vec))),
    };
    let id_entry = ScMapEntry {
        key: sym(b"id"),
        val: ScVal::U32(rule_id),
    };
    let name_str = format!("rule-{rule_id}");
    let name_entry = ScMapEntry {
        key: sym(b"name"),
        val: ScVal::String(ScString(
            name_str
                .into_bytes()
                .try_into()
                .expect("name fits in StringM"),
        )),
    };
    let policies_entry = ScMapEntry {
        key: sym(b"policies"),
        val: vec_or_void(vec![]),
    };
    let policy_ids_entry = ScMapEntry {
        key: sym(b"policy_ids"),
        val: vec_or_void(vec![]),
    };
    let signer_ids_entry = ScMapEntry {
        key: sym(b"signer_ids"),
        val: vec_or_void(signer_ids_scvals),
    };
    let signers_entry = ScMapEntry {
        key: sym(b"signers"),
        val: vec_or_void(signer_scvals),
    };
    // valid_until: canonical None ABI = ScVal::Void.
    // soroban-env-common/src/option.rs:3-16.
    let valid_until_entry = ScMapEntry {
        key: sym(b"valid_until"),
        val: ScVal::Void, // None variant
    };

    let map: VecM<ScMapEntry> = vec![
        context_type_entry,
        id_entry,
        name_entry,
        policies_entry,
        policy_ids_entry,
        signer_ids_entry,
        signers_entry,
        valid_until_entry,
    ]
    .try_into()
    .expect("ScMap entries fit");

    let scval = ScVal::Map(Some(ScMap(map)));
    scval
        .to_xdr_base64(Limits::none())
        .expect("ContextRule ScVal::Map (External) must encode to XDR")
}

/// Builds a `ScVal::U32(threshold)` XDR base64 — the return value of `get_threshold`.
pub fn build_threshold_scval_xdr(threshold: u32) -> String {
    ScVal::U32(threshold)
        .to_xdr_base64(Limits::none())
        .expect("ScVal::U32 must encode to XDR")
}

// ── simulateTransaction response builder ──────────────────────────────────────

/// Builds a valid `simulateTransaction` JSON-RPC result JSON value.
///
/// The `return_xdr` must be the XDR-base64 of the `ScVal` to return.
/// Uses a canonical `transactionData` XDR value as a stable placeholder.
pub fn build_simulate_response(return_xdr: &str) -> serde_json::Value {
    serde_json::json!({
        "transactionData": MINIMAL_SOROBAN_TRANSACTION_DATA_XDR,
        "minResourceFee": "1000",
        "results": [
            {
                "auth": [],
                "xdr": return_xdr
            }
        ],
        "latestLedger": 1000
    })
}

/// A minimal, fixed `SorobanTransactionData` XDR value used as a stable test placeholder.
const MINIMAL_SOROBAN_TRANSACTION_DATA_XDR: &str = "AAAAAAAAAAIAAAAGAAAAAcwD/nT9D7Dc2LxRdab+2vEUF8B+XoN7mQW21oxPT8ALAAAAFAAAAAEAAAAHy8vNUZ8vyZ2ybPHW0XbSrRtP7gEWsJ6zDzcfY9P8z88AAAABAAAABgAAAAHMA/50/Q+w3Ni8UXWm/trxFBfAfl6De5kFttaMT0/ACwAAABAAAAABAAAAAgAAAA8AAAAHQ291bnRlcgAAAAASAAAAAAAAAAAg4dbAxsGAGICfBG3iT2cKGYQ6hK4sJWzZ6or1C5v6GAAAAAEAHfKyAAAFiAAAAIgAAAAAAAAAAw==";

/// Builds a `getLedgerEntries` JSON-RPC result JSON value with a single account entry.
pub fn build_ledger_entries_account(g: &str) -> serde_json::Value {
    serde_json::json!({
        "entries": [
            {
                "key": account_key_xdr(g),
                "xdr": account_entry_xdr(g, 100),
                "lastModifiedLedgerSeq": 100
            }
        ],
        "latestLedger": 1000
    })
}

/// Builds a `getLedgerEntries` JSON-RPC result with a single contract-instance entry.
///
/// `contract` is the contract address; `wasm_hash` is the 32-byte wasm hash.
pub fn build_ledger_entries_contract_instance(
    contract: &ScAddress,
    wasm_hash: [u8; 32],
) -> serde_json::Value {
    let key_xdr = contract_instance_key_xdr(contract);
    let entry_xdr = contract_instance_entry_xdr(contract, wasm_hash);
    serde_json::json!({
        "entries": [
            {
                "key": key_xdr,
                "xdr": entry_xdr,
                "lastModifiedLedgerSeq": 100
            }
        ],
        "latestLedger": 1000
    })
}

/// Builds a `getLedgerEntries` JSON-RPC result with two contract-instance entries.
pub fn build_ledger_entries_two_contract_instances(
    contract_a: &ScAddress,
    wasm_hash_a: [u8; 32],
    contract_b: &ScAddress,
    wasm_hash_b: [u8; 32],
) -> serde_json::Value {
    serde_json::json!({
        "entries": [
            {
                "key": contract_instance_key_xdr(contract_a),
                "xdr": contract_instance_entry_xdr(contract_a, wasm_hash_a),
                "lastModifiedLedgerSeq": 100
            },
            {
                "key": contract_instance_key_xdr(contract_b),
                "xdr": contract_instance_entry_xdr(contract_b, wasm_hash_b),
                "lastModifiedLedgerSeq": 100
            }
        ],
        "latestLedger": 1000
    })
}

/// Builds a `getLedgerEntries` JSON-RPC result with an account entry AND a
/// contract-instance entry.
///
/// Used when the mock server must serve both `fetch_account` (which decodes
/// the account entry via the `LedgerKey::Account` variant) AND
/// `fetch_contract_wasm_hashes` (which decodes the contract instance entry via
/// the `LedgerKey::ContractData` variant) from a single static response.
///
/// `ContextRuleManager::simulate_read_only` calls `fetch_account` internally
/// before every `simulateTransaction`, so migration-planner wiremock tests that
/// exercise the new `list_active_context_rules` path require both entry types.
pub fn build_ledger_entries_account_and_contract(
    g: &str,
    contract: &ScAddress,
    wasm_hash: [u8; 32],
) -> serde_json::Value {
    let key_xdr = contract_instance_key_xdr(contract);
    let entry_xdr = contract_instance_entry_xdr(contract, wasm_hash);
    serde_json::json!({
        "entries": [
            {
                "key": account_key_xdr(g),
                "xdr": account_entry_xdr(g, 100),
                "lastModifiedLedgerSeq": 100
            },
            {
                "key": key_xdr,
                "xdr": entry_xdr,
                "lastModifiedLedgerSeq": 100
            }
        ],
        "latestLedger": 1000
    })
}

/// Builds an empty `getLedgerEntries` JSON-RPC result (no entries found).
pub fn build_ledger_entries_empty() -> serde_json::Value {
    serde_json::json!({
        "entries": [],
        "latestLedger": 1000
    })
}

// ── SorobanRpcDispatcher ──────────────────────────────────────────────────────

/// A `wiremock::Respond` implementation that dispatches by JSON-RPC `method`.
///
/// Routes `getLedgerEntries` and `simulateTransaction` to separately-configurable
/// canned responses. The `simulateTransaction` response can be set to a sequence
/// of responses (first call, second call, ...) to handle the two separate
/// `simulate_read_only` calls (one for `get_context_rule`, one for `get_threshold`).
pub struct SorobanRpcDispatcher {
    /// Response for `getLedgerEntries` calls.
    pub ledger_entries: serde_json::Value,
    /// Responses for `simulateTransaction` calls, in call order.
    /// If only one is provided it is reused for all calls.
    pub simulate_responses: Vec<serde_json::Value>,
    /// Call counter for simulateTransaction (shared across dispatches).
    pub simulate_call: std::sync::atomic::AtomicUsize,
}

impl SorobanRpcDispatcher {
    /// Creates a dispatcher with a single canned `simulateTransaction` response.
    pub fn new(ledger_entries: serde_json::Value, simulate: serde_json::Value) -> Self {
        Self {
            ledger_entries,
            simulate_responses: vec![simulate],
            simulate_call: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Creates a dispatcher with multiple ordered `simulateTransaction` responses.
    pub fn new_multi_simulate(
        ledger_entries: serde_json::Value,
        simulate_responses: Vec<serde_json::Value>,
    ) -> Self {
        Self {
            ledger_entries,
            simulate_responses,
            simulate_call: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl Respond for SorobanRpcDispatcher {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        use std::sync::atomic::Ordering;

        let body: serde_json::Value =
            serde_json::from_slice(&request.body).unwrap_or(serde_json::json!({}));
        let req_id = body.get("id").cloned().unwrap_or(serde_json::json!(1));
        let method = body
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let result = match method {
            "getLedgerEntries" => self.ledger_entries.clone(),
            "simulateTransaction" => {
                let idx = self
                    .simulate_call
                    .fetch_add(1, Ordering::Relaxed)
                    .min(self.simulate_responses.len().saturating_sub(1));
                self.simulate_responses[idx].clone()
            }
            _ => serde_json::json!({}),
        };

        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result
            }))
            .insert_header("content-type", "application/json")
    }
}

// ── Manager factory helpers ───────────────────────────────────────────────────

/// Builds a `SignersManager` pointing at `primary_url` and `secondary_url`.
pub fn manager_two_url(
    primary_url: &str,
    secondary_url: &str,
    audit_writer: Arc<Mutex<AuditWriter>>,
    audit_log_path: PathBuf,
) -> SignersManager {
    let config = SignersManagerConfig::new(
        primary_url.to_owned(),
        secondary_url.to_owned(),
        audit_writer,
        audit_log_path,
        "Test SDF Network ; September 2015".to_owned(),
        "test-profile".to_owned(),
        Duration::from_secs(5),
        "stellar:testnet".to_owned(),
    );
    SignersManager::new(config).expect("SignersManager::new must succeed")
}

/// Builds a `SignersManager` where primary and secondary point to the same URL.
pub fn manager_one_url(
    rpc_url: &str,
    audit_writer: Arc<Mutex<AuditWriter>>,
    audit_log_path: PathBuf,
) -> SignersManager {
    manager_two_url(rpc_url, rpc_url, audit_writer, audit_log_path)
}

// ── Audit-log helpers ─────────────────────────────────────────────────────────

/// Creates a temp dir and an `AuditWriter` pointing at `audit.jsonl` within it.
///
/// Returns `(writer, path, dir)`. Caller must hold `dir` for the duration of the test
/// (drop = delete).
pub fn tmp_audit_writer() -> (Arc<Mutex<AuditWriter>>, PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir must succeed");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path.clone(), None).expect("AuditWriter::open must succeed");
    (Arc::new(Mutex::new(writer)), path, dir)
}

/// Writes a `SaSignerSetBaselined` audit entry for `(rule_id, smart_account_redacted, observed)`.
pub fn write_baseline(
    writer: &Arc<Mutex<AuditWriter>>,
    rule_id: u32,
    smart_account_redacted: &str,
    observed: &ObservedSignerSet,
) {
    let prev_tip = writer.lock().unwrap().current_chain_tip();
    let first8: Vec<String> = observed
        .signer_pubkeys
        .iter()
        .map(|_| "0101010101010101".to_owned())
        .collect();
    let entry = AuditEntry::new_sa_signer_set_baselined(
        rule_id,
        observed,
        first8,
        0,
        BaselineReason::first_observation(),
        prev_tip,
        RedactedStrkey::from_already_redacted(smart_account_redacted),
        "stellar:testnet",
        Uuid::new_v4().to_string(),
    );
    writer
        .lock()
        .unwrap()
        .write_entry(entry)
        .expect("write_baseline must succeed");
}

/// The `smart_account_redacted` value for the zero contract address.
///
/// `stellar_strkey::Contract([0u8; 32]).to_string()` → `CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4`
/// redacted to first-5 / last-5: `CAAAA...ABSC4`.
pub const ZERO_CONTRACT_REDACTED: &str = "CAAAA...ABSC4";
