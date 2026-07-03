//! Contract WASM fetch and SEP-48 spec-section parse.
//!
//! # Overview
//!
//! This module fetches a contract's WASM bytes from the Stellar RPC layer and
//! parses the embedded `contractspecv0` custom section into a
//! [`soroban_spec_tools::Spec`] value. The parsed entries are cached in memory
//! (per-contract-id) so repeated calls for the same contract do not re-fetch
//! from the network.
//!
//! # Fetch path
//!
//! 1. Look up `LedgerKey::ContractData { key: ScVal::LedgerKeyContractInstance }` for
//!    the contract address via `getLedgerEntries` to obtain the WASM hash.
//! 2. Look up `LedgerKey::ContractCode { hash }` to obtain the raw WASM bytes.
//! 3. Parse via `soroban_spec_tools::Spec::from_wasm` (wraps `soroban_spec::read::from_wasm`
//!    which reads the `contractspecv0` custom section).
//!
//! # SEP-48 specification
//!
//! The SEP-48 specification ("Wasm Custom Section"): "The contract interface is
//! stored in one `contractspecv0` Wasm custom section." Each entry is a binary
//! XDR-encoded `SCSpecEntry` appended with no frame or delimiter.
//!
//! # Cache semantics
//!
//! `SPEC_CACHE` stores the parsed `Vec<ScSpecEntry>` keyed on the contract
//! C-strkey — it is SEP-48 spec-path only. The SEP-47 discovery path
//! ([`crate::discovery`]) fetches WASM bytes independently via
//! `fetch_wasm_bytes`; it does NOT share this cache (which stores parsed
//! spec entries, not raw WASM bytes). Upstream contract specs are treated as
//! trusted: the typed preview is a non-authoritative display and does not
//! validate spec semantics beyond the bounded XDR parse.
//!
//! # KMP reference
//!
//! KMP Stellar SDK `SorobanContractParser.kt`: `parseContractSpec` reads
//! `contractspecv0` and iterates `SCSpecEntryXdr` — same section name and parse
//! loop this module delegates to `soroban_spec_tools`.

use std::{collections::HashMap, sync::Mutex};

use stellar_agent_network::redact_rpc_error;
use stellar_agent_xdr_limits::untrusted_decode_limits;
use stellar_xdr::{
    ContractDataDurability, ContractExecutable, ContractId, Hash, LedgerEntryData, LedgerKey,
    LedgerKeyContractCode, LedgerKeyContractData, ReadXdr, ScAddress, ScContractInstance, ScVal,
};

use soroban_spec_tools::Spec;

use crate::error::Sep48Error;

// ─────────────────────────────────────────────────────────────────────────────
// In-process spec cache (fetch-once-per-contract per process lifetime)
// ─────────────────────────────────────────────────────────────────────────────

/// In-process cache of parsed [`Spec`] entries, keyed on the contract C-strkey.
///
/// The cache is process-global but lock-protected. Each entry maps a contract
/// address string to the parsed `Vec<ScSpecEntry>` so we pay the RPC cost once
/// per contract-id per process lifetime.
///
/// Upstream contract specs are treated as trusted: the typed preview is
/// non-authoritative and does not validate spec semantics beyond the bounded
/// XDR parse. The cache persists for the lifetime of the process with no TTL.
static SPEC_CACHE: Mutex<Option<HashMap<String, Vec<stellar_xdr::ScSpecEntry>>>> = Mutex::new(None);

fn with_cache<F, T>(f: F) -> T
where
    F: FnOnce(&mut HashMap<String, Vec<stellar_xdr::ScSpecEntry>>) -> T,
{
    // `Mutex::lock` panics only if the mutex is poisoned (a previous lock-holder
    // panicked while holding the guard). Re-initialise the cache on poison:
    // the cache is a plain HashMap with no cross-guard invariants, so this is safe.
    let mut guard = SPEC_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let cache = guard.get_or_insert_with(HashMap::new);
    f(cache)
}

// ─────────────────────────────────────────────────────────────────────────────
// LedgerKey construction helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Constructs the `LedgerKey::ContractData` key for a contract instance.
///
/// Per Soroban host semantics, the contract-instance entry lives at:
/// `ContractData { contract: ScAddress::Contract(id), key: ScVal::LedgerKeyContractInstance,
///  durability: Persistent }`.
///
/// # Errors
///
/// Returns [`Sep48Error::InvalidContractAddress`] when `contract_strkey` is not
/// a valid C-strkey.
fn contract_instance_ledger_key(contract_strkey: &str) -> Result<LedgerKey, Sep48Error> {
    let contract_id = parse_contract_id(contract_strkey)?;
    Ok(LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(contract_id),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    }))
}

/// Constructs the `LedgerKey::ContractCode` key for a WASM hash.
fn contract_code_ledger_key(wasm_hash: &[u8; 32]) -> LedgerKey {
    LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: Hash(*wasm_hash),
    })
}

/// Parses a C-strkey string into a [`ContractId`].
///
/// # Errors
///
/// Returns [`Sep48Error::InvalidContractAddress`] if the string is not a valid
/// C-strkey.
fn parse_contract_id(contract_strkey: &str) -> Result<ContractId, Sep48Error> {
    stellar_strkey::Contract::from_string(contract_strkey)
        .map(|c| ContractId(Hash(c.0)))
        .map_err(|_| {
            let redacted = redact_strkey(contract_strkey);
            Sep48Error::InvalidContractAddress { addr: redacted }
        })
}

/// Applies first-5-last-5 redaction to a strkey for use in error messages.
///
/// Account and contract IDs are redacted before inclusion in log-visible fields
/// or error messages to prevent leaking user identifiers at info level.
fn redact_strkey(s: &str) -> String {
    if s.len() <= 10 {
        return "REDACTED".to_owned();
    }
    format!("{}...{}", &s[..5], &s[s.len() - 5..])
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API: fetch_contract_spec
// ─────────────────────────────────────────────────────────────────────────────

/// Fetches the SEP-48 contract spec for the given contract address.
///
/// The spec is fetched from the Stellar RPC layer and cached in memory for the
/// lifetime of the process (fetch-once-per-contract per process).
///
/// # Fetch path
///
/// 1. Resolve the contract instance entry via `getLedgerEntries` to obtain the
///    WASM hash (`ContractExecutable::Wasm`).
/// 2. Fetch the WASM bytes via a second `getLedgerEntries` call on
///    `LedgerKey::ContractCode`.
/// 3. Parse via `soroban_spec_tools::Spec::from_wasm`, which reads the
///    `contractspecv0` WASM custom section.
///
/// # Errors
///
/// - [`Sep48Error::InvalidContractAddress`] — invalid C-strkey.
/// - [`Sep48Error::RpcFetchFailure`] — `getLedgerEntries` call failed.
/// - [`Sep48Error::WasmParseFailure`] — WASM bytes present but spec parse failed.
/// - [`Sep48Error::SpecSectionMissing`] — no `contractspecv0` section in WASM.
pub async fn fetch_contract_spec(
    rpc_url: &str,
    contract_strkey: &str,
) -> Result<Vec<stellar_xdr::ScSpecEntry>, Sep48Error> {
    // Fast path: cache hit.
    if let Some(entries) = with_cache(|c| c.get(contract_strkey).cloned()) {
        tracing::debug!(
            contract = %redact_strkey(contract_strkey),
            "sep48: spec cache hit"
        );
        return Ok(entries);
    }

    tracing::debug!(
        contract = %redact_strkey(contract_strkey),
        "sep48: fetching contract spec from RPC"
    );

    let wasm_bytes = fetch_wasm_bytes(rpc_url, contract_strkey).await?;

    let entries = Spec::from_wasm(&wasm_bytes)
        .map(|spec| spec.0.unwrap_or_default())
        .map_err(|e| {
            let reason = e.to_string();
            if reason.contains("not found") || reason.contains("NotFound") {
                Sep48Error::SpecSectionMissing
            } else {
                Sep48Error::WasmParseFailure { reason }
            }
        })?;

    if entries.is_empty() {
        return Err(Sep48Error::SpecSectionMissing);
    }

    // Populate cache.
    with_cache(|c| c.insert(contract_strkey.to_owned(), entries.clone()));

    Ok(entries)
}

/// Fetches the raw WASM bytes for a contract address via two `getLedgerEntries`
/// calls: one for the instance (to get the WASM hash) and one for the code entry.
///
/// Exposed as `pub(crate)` so [`crate::discovery`] can reuse it for SEP-47
/// claim-discovery without re-fetching the WASM via a second RPC path.
///
/// # Errors
///
/// - [`Sep48Error::InvalidContractAddress`] — invalid C-strkey.
/// - [`Sep48Error::RpcFetchFailure`] — either `getLedgerEntries` call failed or
///   the entries were not found / had unexpected shapes.
pub(crate) async fn fetch_wasm_bytes(
    rpc_url: &str,
    contract_strkey: &str,
) -> Result<Vec<u8>, Sep48Error> {
    use stellar_agent_network::StellarRpcClient;

    let client = StellarRpcClient::new(rpc_url).map_err(|e| Sep48Error::RpcFetchFailure {
        // redact_rpc_error strips the full RPC URL from display strings.
        reason: redact_rpc_error(&format!("RPC client construction failed: {e}")),
    })?;

    // ── Step 1: fetch contract instance to get WASM hash ─────────────────────
    let instance_key = contract_instance_ledger_key(contract_strkey)?;
    let instance_resp = client
        .get_ledger_entries(&[instance_key])
        .await
        .map_err(|e| Sep48Error::RpcFetchFailure {
            reason: redact_rpc_error(&format!("getLedgerEntries(instance) failed: {e}")),
        })?;

    let wasm_hash = extract_wasm_hash_from_instance_response(&instance_resp, contract_strkey)?;

    // ── Step 2: fetch contract code (WASM bytes) ──────────────────────────────
    let code_key = contract_code_ledger_key(&wasm_hash);
    let code_resp =
        client
            .get_ledger_entries(&[code_key])
            .await
            .map_err(|e| Sep48Error::RpcFetchFailure {
                reason: redact_rpc_error(&format!("getLedgerEntries(code) failed: {e}")),
            })?;

    extract_wasm_bytes_from_code_response(&code_resp, contract_strkey)
}

/// Extracts the WASM hash from a `getLedgerEntries` response for a contract
/// instance entry.
///
/// Uses `stellar_rpc_client::GetLedgerEntriesResponse` (re-exported from
/// `stellar-agent-network`) whose `LedgerEntryResult.xdr` is a public field,
/// unlike `soroban_client::LedgerEntryResult` whose field is private.
///
/// # Errors
///
/// Returns [`Sep48Error::RpcFetchFailure`] when the response has no entries,
/// the entry is not a contract instance, or the executable is a native
/// (`StellarAsset`) rather than a WASM contract.
fn extract_wasm_hash_from_instance_response(
    resp: &stellar_agent_network::GetLedgerEntriesResponse,
    contract_strkey: &str,
) -> Result<[u8; 32], Sep48Error> {
    let entries = resp
        .entries
        .as_deref()
        .ok_or_else(|| Sep48Error::RpcFetchFailure {
            reason: format!(
                "no instance ledger entry for contract {}",
                redact_strkey(contract_strkey)
            ),
        })?;

    let entry = entries.first().ok_or_else(|| Sep48Error::RpcFetchFailure {
        reason: format!(
            "empty instance ledger entries for contract {}",
            redact_strkey(contract_strkey)
        ),
    })?;

    // `LedgerEntryResult.xdr` is a base64-encoded `LedgerEntryData`. The XDR
    // originates from the network (untrusted source); bounded depth+len limits
    // guard against stack exhaustion and oversized allocations.
    let entry_data = parse_ledger_entry_xdr(&entry.xdr, contract_strkey)?;

    match entry_data {
        LedgerEntryData::ContractData(cd) => match &cd.val {
            ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::Wasm(Hash(bytes)),
                ..
            }) => Ok(*bytes),
            ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::StellarAsset,
                ..
            }) => Err(Sep48Error::RpcFetchFailure {
                reason: format!(
                    "contract {} is a Stellar Asset Contract (SAC), not a Wasm contract",
                    redact_strkey(contract_strkey)
                ),
            }),
            _ => Err(Sep48Error::RpcFetchFailure {
                reason: format!(
                    "unexpected ContractData val shape for contract {}",
                    redact_strkey(contract_strkey)
                ),
            }),
        },
        _ => Err(Sep48Error::RpcFetchFailure {
            reason: format!(
                "unexpected ledger entry type (not ContractData) for contract {}",
                redact_strkey(contract_strkey)
            ),
        }),
    }
}

/// Extracts the raw WASM bytes from a `getLedgerEntries` response for a
/// `ContractCode` entry.
///
/// # Errors
///
/// Returns [`Sep48Error::RpcFetchFailure`] when the response has no entries or
/// the entry has an unexpected shape.
fn extract_wasm_bytes_from_code_response(
    resp: &stellar_agent_network::GetLedgerEntriesResponse,
    contract_strkey: &str,
) -> Result<Vec<u8>, Sep48Error> {
    let entries = resp
        .entries
        .as_deref()
        .ok_or_else(|| Sep48Error::RpcFetchFailure {
            reason: format!(
                "no code ledger entry for contract {}",
                redact_strkey(contract_strkey)
            ),
        })?;

    let entry = entries.first().ok_or_else(|| Sep48Error::RpcFetchFailure {
        reason: format!(
            "empty code ledger entries for contract {}",
            redact_strkey(contract_strkey)
        ),
    })?;

    let entry_data = parse_ledger_entry_xdr(&entry.xdr, contract_strkey)?;

    match entry_data {
        LedgerEntryData::ContractCode(cc) => Ok(cc.code.into_vec()),
        _ => Err(Sep48Error::RpcFetchFailure {
            reason: format!(
                "unexpected ledger entry type (not ContractCode) for contract {}",
                redact_strkey(contract_strkey)
            ),
        }),
    }
}

/// Parses a base64-encoded XDR `LedgerEntryData` string.
///
/// The XDR originates from the RPC network layer (untrusted on-chain source);
/// bounded depth and length limits prevent stack exhaustion and oversized
/// allocations. Passing the base64 string length is safe: the decoded byte
/// count is strictly smaller, so valid input is never rejected.
///
/// # Errors
///
/// Returns [`Sep48Error::RpcFetchFailure`] when the XDR parse fails.
fn parse_ledger_entry_xdr(
    xdr_base64: &str,
    contract_strkey: &str,
) -> Result<LedgerEntryData, Sep48Error> {
    let limits = untrusted_decode_limits(xdr_base64.len());
    LedgerEntryData::from_xdr_base64(xdr_base64, limits).map_err(|e| Sep48Error::RpcFetchFailure {
        reason: format!(
            "malformed LedgerEntryData XDR for contract {}: {e}",
            redact_strkey(contract_strkey)
        ),
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in unit tests"
)]
mod tests {
    use super::*;
    use stellar_agent_network::{GetLedgerEntriesResponse, LedgerEntryResult};
    use stellar_xdr::{
        ContractCodeCostInputs, ContractCodeEntry, ContractCodeEntryExt, ContractCodeEntryV1,
        ContractDataDurability, ContractDataEntry, ContractId, ExtensionPoint, Hash,
        LedgerEntryData, Limits, ScAddress, ScVal, WriteXdr,
    };

    // ── Helpers ───────────────────────────────────────────────────────────────

    const CONTRACT: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";

    fn make_resp_with_entry(xdr: &str) -> GetLedgerEntriesResponse {
        GetLedgerEntriesResponse {
            entries: Some(vec![LedgerEntryResult {
                key: "dummy".to_owned(),
                xdr: xdr.to_owned(),
                last_modified_ledger: 1,
                live_until_ledger_seq_ledger_seq: None,
            }]),
            latest_ledger: 100,
        }
    }

    fn make_resp_null_entries() -> GetLedgerEntriesResponse {
        GetLedgerEntriesResponse {
            entries: None,
            latest_ledger: 100,
        }
    }

    fn make_resp_empty_entries() -> GetLedgerEntriesResponse {
        GetLedgerEntriesResponse {
            entries: Some(vec![]),
            latest_ledger: 100,
        }
    }

    fn contract_data_xdr_with_val(val: ScVal) -> String {
        let entry = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(ContractId(Hash(
                stellar_strkey::Contract::from_string(CONTRACT)
                    .expect("valid strkey")
                    .0,
            ))),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val,
        });
        entry.to_xdr_base64(Limits::none()).unwrap()
    }

    /// Returns a base64-XDR `LedgerEntryData::ContractCode` for use as a
    /// "wrong type" response in the instance-step (expects ContractData).
    fn contract_code_as_wrong_instance_type_xdr() -> String {
        contract_code_xdr(b"\x00asm\x01\x00\x00\x00")
    }

    /// Returns a base64-XDR `LedgerEntryData::ContractData` with a Boolean val
    /// for use as a "wrong type" response in the code-step (expects ContractCode).
    fn contract_data_as_wrong_code_type_xdr() -> String {
        contract_data_xdr_with_val(ScVal::Bool(false))
    }

    fn contract_code_xdr(code: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let hash = Hash(Sha256::digest(code).into());
        let code_bytes: stellar_xdr::BytesM = code.try_into().unwrap();
        let entry = LedgerEntryData::ContractCode(ContractCodeEntry {
            ext: ContractCodeEntryExt::V1(ContractCodeEntryV1 {
                ext: ExtensionPoint::V0,
                cost_inputs: ContractCodeCostInputs {
                    ext: ExtensionPoint::V0,
                    n_instructions: 0,
                    n_functions: 0,
                    n_globals: 0,
                    n_table_entries: 0,
                    n_types: 0,
                    n_data_segments: 0,
                    n_elem_segments: 0,
                    n_imports: 0,
                    n_exports: 0,
                    n_data_segment_bytes: 0,
                },
            }),
            hash,
            code: code_bytes,
        });
        entry.to_xdr_base64(Limits::none()).unwrap()
    }

    // ── extract_wasm_hash_from_instance_response ──────────────────────────────

    /// `entries: None` in the GetLedgerEntriesResponse hits the
    /// `no instance ledger entry` error path (as_deref() → None → ok_or_else).
    #[test]
    fn extract_wasm_hash_null_entries_returns_no_instance_error() {
        let resp = make_resp_null_entries();
        let result = extract_wasm_hash_from_instance_response(&resp, CONTRACT);
        match &result {
            Err(Sep48Error::RpcFetchFailure { reason }) => {
                assert!(
                    reason.contains("no instance ledger entry"),
                    "null entries must produce 'no instance ledger entry' reason, got: {reason}"
                );
            }
            other => {
                panic!("null entries must return RpcFetchFailure(no instance ...), got: {other:?}")
            }
        }
    }

    /// `entries: Some([])` hits the `empty instance ledger entries` path
    /// (entries.first() → None → ok_or_else).
    #[test]
    fn extract_wasm_hash_empty_entries_returns_empty_instance_error() {
        let resp = make_resp_empty_entries();
        let result = extract_wasm_hash_from_instance_response(&resp, CONTRACT);
        match &result {
            Err(Sep48Error::RpcFetchFailure { reason }) => {
                assert!(
                    reason.contains("empty instance ledger entries"),
                    "empty entries must produce 'empty instance ledger entries' reason, got: {reason}"
                );
            }
            other => panic!(
                "empty entries must return RpcFetchFailure(empty instance ...), got: {other:?}"
            ),
        }
    }

    /// `ContractData` entry whose `val` is neither `ContractInstance(Wasm)` nor
    /// `ContractInstance(StellarAsset)` hits the `unexpected ContractData val shape`
    /// catch-all arm.
    #[test]
    fn extract_wasm_hash_unexpected_contract_data_val_returns_error() {
        // Use ScVal::Bool — a value that doesn't match either ContractInstance arm.
        let xdr = contract_data_xdr_with_val(ScVal::Bool(true));
        let resp = make_resp_with_entry(&xdr);
        let result = extract_wasm_hash_from_instance_response(&resp, CONTRACT);
        match &result {
            Err(Sep48Error::RpcFetchFailure { reason }) => {
                assert!(
                    reason.contains("unexpected ContractData val shape"),
                    "non-ContractInstance val must produce 'unexpected ContractData val shape' reason, got: {reason}"
                );
            }
            other => panic!("unexpected val shape must return RpcFetchFailure, got: {other:?}"),
        }
    }

    /// A `LedgerEntryData` variant that is not `ContractData` hits the
    /// `unexpected ledger entry type (not ContractData)` catch-all arm.
    ///
    /// Uses a `ContractCode` entry for the instance step since it is easy to
    /// construct and is unambiguously not `ContractData`.
    #[test]
    fn extract_wasm_hash_non_contract_data_entry_returns_error() {
        let xdr = contract_code_as_wrong_instance_type_xdr();
        let resp = make_resp_with_entry(&xdr);
        let result = extract_wasm_hash_from_instance_response(&resp, CONTRACT);
        match &result {
            Err(Sep48Error::RpcFetchFailure { reason }) => {
                assert!(
                    reason.contains("unexpected ledger entry type (not ContractData)"),
                    "non-ContractData entry must produce 'unexpected ledger entry type' reason, got: {reason}"
                );
            }
            other => panic!("non-ContractData must return RpcFetchFailure, got: {other:?}"),
        }
    }

    // ── extract_wasm_bytes_from_code_response ─────────────────────────────────

    /// `entries: None` in the code-step response hits the
    /// `no code ledger entry` path.
    #[test]
    fn extract_wasm_bytes_null_code_entries_returns_error() {
        let resp = make_resp_null_entries();
        let result = extract_wasm_bytes_from_code_response(&resp, CONTRACT);
        match &result {
            Err(Sep48Error::RpcFetchFailure { reason }) => {
                assert!(
                    reason.contains("no code ledger entry"),
                    "null code entries must produce 'no code ledger entry' reason, got: {reason}"
                );
            }
            other => panic!("null code entries must return RpcFetchFailure, got: {other:?}"),
        }
    }

    /// `entries: Some([])` in the code-step response hits the
    /// `empty code ledger entries` path.
    #[test]
    fn extract_wasm_bytes_empty_code_entries_returns_error() {
        let resp = make_resp_empty_entries();
        let result = extract_wasm_bytes_from_code_response(&resp, CONTRACT);
        match &result {
            Err(Sep48Error::RpcFetchFailure { reason }) => {
                assert!(
                    reason.contains("empty code ledger entries"),
                    "empty code entries must produce 'empty code ledger entries' reason, got: {reason}"
                );
            }
            other => panic!("empty code entries must return RpcFetchFailure, got: {other:?}"),
        }
    }

    /// A `LedgerEntryData` variant that is not `ContractCode` in the code-step
    /// response hits the `unexpected ledger entry type (not ContractCode)` arm.
    ///
    /// Uses a `ContractData` entry for the code step since it is easy to construct
    /// and is unambiguously not `ContractCode`.
    #[test]
    fn extract_wasm_bytes_non_contract_code_entry_returns_error() {
        let xdr = contract_data_as_wrong_code_type_xdr();
        let resp = make_resp_with_entry(&xdr);
        let result = extract_wasm_bytes_from_code_response(&resp, CONTRACT);
        match &result {
            Err(Sep48Error::RpcFetchFailure { reason }) => {
                assert!(
                    reason.contains("unexpected ledger entry type (not ContractCode)"),
                    "non-ContractCode entry must produce expected reason, got: {reason}"
                );
            }
            other => panic!("non-ContractCode entry must return RpcFetchFailure, got: {other:?}"),
        }
    }

    /// A valid `ContractCode` entry in the code-step response is decoded
    /// correctly and the raw WASM bytes are returned.
    #[test]
    fn extract_wasm_bytes_valid_code_entry_returns_bytes() {
        let wasm = b"\x00asm\x01\x00\x00\x00";
        let xdr = contract_code_xdr(wasm);
        let resp = make_resp_with_entry(&xdr);
        let result = extract_wasm_bytes_from_code_response(&resp, CONTRACT);
        assert!(
            result.is_ok(),
            "valid ContractCode entry must succeed, got: {result:?}"
        );
        assert_eq!(
            result.unwrap(),
            wasm.to_vec(),
            "returned bytes must match the original WASM"
        );
    }

    #[test]
    fn parse_valid_contract_id() {
        // Testnet USDC SAC C-strkey.
        let result = parse_contract_id("CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA");
        assert!(
            result.is_ok(),
            "valid C-strkey must parse successfully: {result:?}"
        );
    }

    #[test]
    fn parse_invalid_contract_id_returns_error() {
        let result = parse_contract_id("not-a-valid-strkey");
        assert!(
            matches!(result, Err(Sep48Error::InvalidContractAddress { .. })),
            "invalid strkey must return InvalidContractAddress"
        );
    }

    #[test]
    fn redact_strkey_short() {
        assert_eq!(redact_strkey("CSHORT"), "REDACTED");
    }

    #[test]
    fn redact_strkey_long() {
        let s = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
        let redacted = redact_strkey(s);
        assert_eq!(redacted, "CBIEL...QDAMA", "must emit first-5 ... last-5");
    }

    /// Verifies that `fetch_contract_spec` wires `redact_rpc_error` into its
    /// error path: when an RPC failure occurs and the RPC URL contains userinfo
    /// credentials, neither the scheme nor the credentials appear in the
    /// `Sep48Error::RpcFetchFailure` reason string.
    ///
    /// This proves sep48's own error path applies redaction, not just that the
    /// underlying `redact_rpc_error` function works correctly.
    #[tokio::test]
    async fn fetch_contract_spec_rpc_error_reason_is_redacted() {
        // Bind then drop to get a closed port — the connection attempt fails,
        // producing a RpcFetchFailure whose reason flows through redact_rpc_error.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            l.local_addr().expect("addr").port()
        };
        // URL with userinfo (basic-auth credentials) and a secret-bearing path.
        let secret_url = format!("http://admin:s3cr3t@127.0.0.1:{port}/soroban/rpc?token=SEC");

        let result = fetch_contract_spec(&secret_url, CONTRACT).await;

        let reason = match result {
            Err(Sep48Error::RpcFetchFailure { reason }) => reason,
            Err(Sep48Error::InvalidContractAddress { .. }) => {
                // CONTRACT is a valid strkey; this branch should not be reached.
                panic!("unexpected InvalidContractAddress for a valid strkey");
            }
            other => panic!("expected RpcFetchFailure, got: {other:?}"),
        };
        assert!(
            !reason.contains("s3cr3t"),
            "userinfo credentials must not appear in redacted error reason: {reason}"
        );
        assert!(
            !reason.contains("token=SEC"),
            "secret-bearing query must not appear in redacted error reason: {reason}"
        );
        assert!(
            !reason.to_ascii_lowercase().contains("http://admin"),
            "scheme+userinfo must not appear in redacted error reason: {reason}"
        );
    }
}
