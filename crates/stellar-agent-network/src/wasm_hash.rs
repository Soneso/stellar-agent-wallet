//! On-chain WASM-hash fetch primitive for contract-pin verification.
//!
//! # What this module does
//!
//! Provides [`fetch_contract_wasm_hash`], a two-RPC parallel fetch that returns
//! one of four explicit [`WasmHashFetch`] outcomes (`Wasm`, `Sac`,
//! `ExternalRef`, `Absent`) for a single Soroban contract address, or a typed
//! [`FetchContractWasmHashError`]. Primary and secondary endpoints are
//! cross-checked; divergence is a hard error.
//!
//! This primitive is the shared single-contract fetch core: the DeFi,
//! DeFindex, DEX and smart-account paths delegate here and apply their own
//! per-caller policy to the returned outcome.  Only the smart-account
//! multi-key batch fetch (`fetch_contract_wasm_hashes`) keeps a separate
//! implementation — it has no single-contract analogue.
//!
//! # Per-caller policy
//!
//! This primitive NEVER collapses a non-Wasm outcome to a zero hash or any
//! other sentinel — callers must handle every variant.  The DeFi sign-time
//! gate (`stellar_agent_defi::pins::verify_pin_for_sign`) maps `Absent`,
//! `Sac` and `ExternalRef` to typed `Err` variants (fail-closed by type).  The
//! smart-account caller maps `Sac`/`Absent` to "no code" and keeps
//! `ExternalRef` as an observation: its install path pins an external
//! reference's owner, tag and resolved hash only under the operator's
//! mutable-contract acknowledgement, and its signing-time drift check
//! compares all three and the executable kind. Its accept-unknown-verifier
//! install flow, which has no DeFi analogue, pins the zero hash for an absent
//! contract, so the zero value exists only on that caller's side and never
//! stands for an owner-managed executable.
//!
//! # External references (CAP-85)
//!
//! A contract instance whose executable is
//! `ContractExecutable::ExternalRef { executable_owner, tag }` runs the Wasm
//! whose hash the owner stores in its persistent `ContractData` entry keyed by
//! `ScVal::ExecutableTag(tag)`. The owner can repoint that entry at any time,
//! so the executable is owner-controlled and mutable. The fetch resolves the
//! tag entry at the same endpoint that returned the instance and reports the
//! owner, the tag and the resolved hash as [`ExternalRefExecutable`]. The
//! resolved hash is a snapshot that can change on the next ledger; a caller
//! that acts on it fetches at act time.
//!
//! # Divergence detection
//!
//! The single-contract case compares the two endpoints' whole outcomes and
//! reports a bounded summary of each side on divergence: first-8 hex of a
//! Wasm hash, the `<SAC>` / `<Absent>` sentinel, or the redacted owner,
//! bounded tag and resolved first-8 of an external reference.  A malformed
//! ledger entry on either endpoint is reported as
//! [`FetchContractWasmHashError::Malformed`] before any comparison.  The
//! multi-key smart-account batch path uses a SHA-256
//! digest-of-concatenation to compare aligned result vectors instead.
//!
//! # SAC variant
//!
//! `ContractExecutable::StellarAsset` is the on-chain XDR variant that
//! indicates a Stellar Asset Contract (SAC) rather than an ordinary WASM
//! contract.

use std::fmt;

use stellar_xdr::{
    ContractDataDurability, ContractExecutable, ContractExecutableExternalRef, ContractId, Hash,
    LedgerEntryData, LedgerKey, LedgerKeyContractData, ReadXdr, ScAddress, ScString, ScVal,
};

use crate::StellarRpcClient;
use stellar_agent_core::error::NetworkError;
use stellar_agent_core::observability::untrusted_display_bounded;
use stellar_agent_core::sc_address::scaddress_redacted;

// ─────────────────────────────────────────────────────────────────────────────
// WasmHashFetch — four explicit outcomes, no zero value
// ─────────────────────────────────────────────────────────────────────────────

/// The result of fetching a contract's on-chain executable.
///
/// Callers MUST handle every variant and MUST NOT collapse `Absent`, `Sac` or
/// `ExternalRef` to a zero hash or any other sentinel.
///
/// The distinction matters for the DeFi sign-time gate:
/// `stellar_agent_defi::pins::verify_pin_for_sign` maps `Wasm` to a
/// match-or-drift check, and maps `Sac`, `ExternalRef` and `Absent` to typed
/// `Err` variants fail-closed by type.
///
/// # Design note
///
/// The smart-account caller pins `Absent` as `[0u8;32]` to support an
/// accept-unknown-verifier install flow that has no DeFi analogue.  This type
/// is the stronger form: a zero value is impossible to express here.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WasmHashFetch {
    /// The contract has an ordinary WASM executable; carries the 32-byte hash.
    Wasm([u8; 32]),
    /// The contract is a Stellar Asset Contract (SAC).
    ///
    /// Corresponds to `ContractExecutable::StellarAsset` in the XDR schema.
    Sac,
    /// The contract's executable is a CAP-85 external reference: the owner
    /// named in the instance decides, and can change, which Wasm runs.
    ///
    /// Corresponds to `ContractExecutable::ExternalRef` in the XDR schema.
    ExternalRef(ExternalRefExecutable),
    /// The RPC returned no entry for the contract-instance key.
    Absent,
}

/// A contract executable that is a CAP-85 external reference.
///
/// The fields keep their XDR types so a caller can rebuild the owner's tag
/// key losslessly ([`Self::tag_ledger_key`]). `owner` and `tag` are
/// ledger-supplied and owner-chosen: render them only through
/// [`Self::owner_redacted`] and [`Self::tag_display`]. The `Debug` form uses
/// the same bounded renderings.
///
/// `resolved` is the Wasm hash the owner's tag entry held when it was read.
/// It is a snapshot of an owner-mutable entry that can change on the next
/// ledger, so every consumer fetches at act time. A consumer that pins it
/// (the smart-account install path) pins the owner and tag with it and
/// compares all three against a fresh fetch before acting.
#[derive(Clone, PartialEq, Eq)]
pub struct ExternalRefExecutable {
    /// Address that owns the executable-tag entry.
    pub owner: ScAddress,
    /// Owner-chosen tag naming the entry.
    pub tag: ScString,
    /// The 32-byte Wasm hash stored under the tag entry, or `None` when the
    /// endpoint returned no live tag entry (archived, or omitted).
    pub resolved: Option<[u8; 32]>,
}

impl ExternalRefExecutable {
    /// Wraps a raw XDR external reference for rendering, without reading the
    /// owner's tag entry.
    ///
    /// `resolved` is `None` because no tag entry was read, so only
    /// [`Self::owner_redacted`], [`Self::tag_display`] and
    /// [`Self::tag_ledger_key`] carry information. Consumers that refuse an
    /// external reference from a ledger entry they decoded themselves use
    /// this for the refusal message.
    #[must_use]
    pub fn from_xdr(external: &ContractExecutableExternalRef) -> Self {
        Self {
            owner: external.executable_owner.clone(),
            tag: external.tag.clone(),
            resolved: None,
        }
    }

    /// Returns the owner as a first-5-last-5 redacted strkey, or
    /// `<unsupported address>` for an address variant with no account or
    /// contract strkey form.
    #[must_use]
    pub fn owner_redacted(&self) -> String {
        scaddress_redacted(&self.owner)
    }

    /// Returns the tag rendered lossily, with control and invisible
    /// formatting characters escaped, and bounded to
    /// [`stellar_agent_core::observability::UNTRUSTED_DISPLAY_MAX_BYTES`].
    #[must_use]
    pub fn tag_display(&self) -> String {
        untrusted_display_bounded(self.tag.0.as_vec())
    }

    /// Returns first-8 hex of the resolved hash, or `<unset>` when no live
    /// tag entry was returned.
    #[must_use]
    pub fn resolved_first8(&self) -> String {
        self.resolved
            .as_ref()
            .map_or_else(|| "<unset>".to_owned(), first8_hex)
    }

    /// Returns the ledger key of the owner's executable-tag entry.
    #[must_use]
    pub fn tag_ledger_key(&self) -> LedgerKey {
        executable_tag_ledger_key(&self.owner, &self.tag)
    }

    /// Returns the SHA-256 digest of the XDR of [`Self::tag_ledger_key`],
    /// which identifies this owner and tag pair exactly.
    ///
    /// # Errors
    ///
    /// Returns the XDR encoder's error from
    /// [`stellar_agent_core::sc_address::executable_tag_key_digest`].
    pub fn tag_key_digest(&self) -> Result<[u8; 32], stellar_xdr::Error> {
        stellar_agent_core::sc_address::executable_tag_key_digest(&self.owner, &self.tag)
    }
}

impl fmt::Debug for ExternalRefExecutable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalRefExecutable")
            .field("owner", &self.owner_redacted())
            .field("tag", &self.tag_display())
            .field("resolved", &self.resolved_first8())
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WasmHashDivergenceError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when primary and secondary RPC endpoints disagree on the
/// on-chain executable.
///
/// Carries a bounded summary of each side; full 32-byte hashes and full
/// addresses are NOT included. This guards against contract-substitution by
/// requiring both endpoints to agree before the caller proceeds.
#[derive(Debug, thiserror::Error)]
#[error(
    "two-RPC WASM-hash divergence for {contract_redacted}: \
     primary={primary_summary} secondary={secondary_summary}"
)]
pub struct WasmHashDivergenceError {
    /// First-5-last-5 redacted contract address.
    pub contract_redacted: String,
    /// Summary of the primary RPC's outcome: first-8 hex of a Wasm hash,
    /// `<SAC>`, `<Absent>`, or
    /// `external-ref(owner=<redacted> tag="<bounded>" resolved=<first-8 or <unset>>)`.
    pub primary_summary: String,
    /// Summary of the secondary RPC's outcome, in the same form as
    /// `primary_summary`.
    pub secondary_summary: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// fetch_contract_wasm_hash
// ─────────────────────────────────────────────────────────────────────────────

/// Fetches the on-chain executable for a single contract address using a
/// two-RPC parallel cross-check.
///
/// Calls `getLedgerEntries` on both `primary_rpc` and `secondary_rpc` in
/// parallel (via `tokio::join!`), then compares the results.  If the two RPCs
/// disagree, returns [`WasmHashDivergenceError`].  If `secondary_rpc` is `None`,
/// only the primary is queried (single-RPC trust, permitted ONLY when the
/// profile configures no secondary endpoint).
///
/// The returned [`WasmHashFetch`] is one of:
/// - `Wasm(hash)` — ordinary WASM contract.
/// - `Sac` — Stellar Asset Contract (`ContractExecutable::StellarAsset`).
/// - `ExternalRef(..)` — CAP-85 external reference. Each endpoint resolves the
///   owner's tag entry with a second `getLedgerEntries` at that same endpoint,
///   and the resolved hash takes part in the two-RPC comparison.
/// - `Absent` — the RPC returned no entry for the contract-instance key.
///
/// Returned entries are matched to the requested key; entries for any other
/// key are ignored.
///
/// # Errors
///
/// - [`FetchContractWasmHashError::InvalidAddress`] — `contract_address` is
///   not a valid Stellar C-strkey.
/// - [`FetchContractWasmHashError::Unavailable`] — the primary or secondary
///   RPC request failed (connection refused, DNS failure, TLS error, etc.).
///   The `url` in the underlying [`NetworkError::RpcUnreachable`] is
///   authority-only (scheme://host\[:port\]); credentials are stripped.
/// - [`FetchContractWasmHashError::Malformed`] — an endpoint returned an
///   entry for a requested key that does not have the expected shape (see
///   [`MalformedEntryReason`]). A malformed entry on either endpoint is
///   reported as `Malformed`, never as `Divergent`.
/// - [`FetchContractWasmHashError::Divergent`] — the primary and secondary
///   RPC endpoints returned different outcomes for the same contract,
///   including different resolved hashes for the same external reference.
///   This indicates either a ledger race, a fork, or a misconfigured
///   endpoint.
pub async fn fetch_contract_wasm_hash(
    primary_rpc: &StellarRpcClient,
    secondary_rpc: Option<&StellarRpcClient>,
    contract_address: &str,
) -> Result<WasmHashFetch, FetchContractWasmHashError> {
    let contract_redacted = redact_strkey_first5_last5(contract_address);
    let key = contract_instance_ledger_key(contract_address)?;

    match secondary_rpc {
        Some(secondary) => {
            // Two-RPC parallel fetch via `tokio::join!`.
            let (primary_result, secondary_result) = tokio::join!(
                fetch_single_wasm_hash(primary_rpc, &key),
                fetch_single_wasm_hash(secondary, &key),
            );

            let primary_fetch = primary_result.map_err(|e| e.into_error(&contract_redacted))?;
            let secondary_fetch = secondary_result.map_err(|e| e.into_error(&contract_redacted))?;

            // Compare the two whole outcomes, including an external
            // reference's owner, tag and resolved hash.
            if primary_fetch != secondary_fetch {
                let primary_summary = wasm_hash_fetch_summary(&primary_fetch);
                let secondary_summary = wasm_hash_fetch_summary(&secondary_fetch);
                return Err(FetchContractWasmHashError::Divergent(
                    WasmHashDivergenceError {
                        contract_redacted,
                        primary_summary,
                        secondary_summary,
                    },
                ));
            }

            Ok(primary_fetch)
        }
        // No secondary configured — single-RPC trust (explicit operator config only).
        None => fetch_single_wasm_hash(primary_rpc, &key)
            .await
            .map_err(|e| e.into_error(&contract_redacted)),
    }
}

/// Ledger key of an owner's executable-tag entry; defined in
/// [`stellar_agent_core::sc_address`] so the smart-account pin and the audit
/// log derive the same key.
pub use stellar_agent_core::sc_address::executable_tag_ledger_key;

// ─────────────────────────────────────────────────────────────────────────────
// FetchContractWasmHashError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by [`fetch_contract_wasm_hash`].
///
/// All variants carry first-8 hex redactions, first-5-last-5 addresses or
/// fixed shape descriptions; full hashes, full addresses and decoded ledger
/// content NEVER appear in `Display` or `Debug`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FetchContractWasmHashError {
    /// The contract address is not a valid Stellar strkey.
    #[error("invalid contract address {contract_redacted}: {reason}")]
    InvalidAddress {
        /// First-5-last-5 redacted contract address.
        contract_redacted: String,
        /// Non-sensitive reason string.
        reason: String,
    },
    /// The RPC fetch failed (primary or secondary).
    #[error("WASM-hash fetch unavailable for {contract_redacted}: {source}")]
    Unavailable {
        /// First-5-last-5 redacted contract address.
        contract_redacted: String,
        /// Underlying network error.
        #[source]
        source: NetworkError,
    },
    /// An endpoint returned an entry for a requested key whose shape is not
    /// the expected one.
    #[error("malformed ledger entry for {contract_redacted}: {reason}")]
    Malformed {
        /// First-5-last-5 redacted contract address.
        contract_redacted: String,
        /// Which shape check failed.
        reason: MalformedEntryReason,
    },
    /// Primary and secondary RPC disagree on the on-chain state.
    #[error(transparent)]
    Divergent(#[from] WasmHashDivergenceError),
}

/// The shape check a returned ledger entry failed.
///
/// A closed set of fixed descriptions; no decoded content or XDR bytes are
/// carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MalformedEntryReason {
    /// A returned entry's `key` does not decode as a `LedgerKey`.
    EntryKeyUndecodable,
    /// The entry under the contract-instance key does not decode.
    InstanceEntryUndecodable,
    /// The value under the contract-instance key is not a contract instance.
    NotContractInstance,
    /// The entry under the owner's executable-tag key does not decode.
    TagEntryUndecodable,
    /// The value under the owner's executable-tag key is not 32 bytes.
    TagValueNotHash,
}

impl MalformedEntryReason {
    /// Returns the fixed description.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EntryKeyUndecodable => "ledger entry key does not decode",
            Self::InstanceEntryUndecodable => "contract instance entry does not decode",
            Self::NotContractInstance => "value under the instance key is not a contract instance",
            Self::TagEntryUndecodable => "executable tag entry does not decode",
            Self::TagValueNotHash => "executable tag entry value is not a 32-byte hash",
        }
    }
}

impl fmt::Display for MalformedEntryReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Failure of one endpoint's fetch, before the contract context is attached.
enum SingleFetchError {
    Network(NetworkError),
    Malformed(MalformedEntryReason),
}

impl SingleFetchError {
    fn into_error(self, contract_redacted: &str) -> FetchContractWasmHashError {
        match self {
            Self::Network(source) => FetchContractWasmHashError::Unavailable {
                contract_redacted: contract_redacted.to_owned(),
                source,
            },
            Self::Malformed(reason) => FetchContractWasmHashError::Malformed {
                contract_redacted: contract_redacted.to_owned(),
                reason,
            },
        }
    }
}

impl From<NetworkError> for SingleFetchError {
    fn from(e: NetworkError) -> Self {
        Self::Network(e)
    }
}

/// Fetches the [`WasmHashFetch`] outcome for a single contract-instance key
/// from one RPC endpoint, resolving an external reference at the same
/// endpoint.
async fn fetch_single_wasm_hash(
    client: &StellarRpcClient,
    key: &LedgerKey,
) -> Result<WasmHashFetch, SingleFetchError> {
    let Some(entry_data) =
        fetch_entry_for_key(client, key, MalformedEntryReason::InstanceEntryUndecodable).await?
    else {
        return Ok(WasmHashFetch::Absent);
    };

    let LedgerEntryData::ContractData(cd) = &entry_data else {
        return Err(SingleFetchError::Malformed(
            MalformedEntryReason::NotContractInstance,
        ));
    };
    let ScVal::ContractInstance(instance) = &cd.val else {
        return Err(SingleFetchError::Malformed(
            MalformedEntryReason::NotContractInstance,
        ));
    };

    match &instance.executable {
        ContractExecutable::Wasm(Hash(bytes)) => Ok(WasmHashFetch::Wasm(*bytes)),
        ContractExecutable::StellarAsset => Ok(WasmHashFetch::Sac),
        ContractExecutable::ExternalRef(external) => {
            let tag_key = executable_tag_ledger_key(&external.executable_owner, &external.tag);
            let resolved = match fetch_entry_for_key(
                client,
                &tag_key,
                MalformedEntryReason::TagEntryUndecodable,
            )
            .await?
            {
                None => None,
                Some(LedgerEntryData::ContractData(tag_entry)) => match &tag_entry.val {
                    ScVal::Bytes(bytes) => Some(
                        <[u8; 32]>::try_from(bytes.0.as_vec().as_slice()).map_err(|_| {
                            SingleFetchError::Malformed(MalformedEntryReason::TagValueNotHash)
                        })?,
                    ),
                    _ => {
                        return Err(SingleFetchError::Malformed(
                            MalformedEntryReason::TagValueNotHash,
                        ));
                    }
                },
                Some(_) => {
                    return Err(SingleFetchError::Malformed(
                        MalformedEntryReason::TagValueNotHash,
                    ));
                }
            };
            Ok(WasmHashFetch::ExternalRef(ExternalRefExecutable {
                owner: external.executable_owner.clone(),
                tag: external.tag.clone(),
                resolved,
            }))
        }
    }
}

/// Requests `key` from one endpoint and returns the decoded data of the entry
/// whose own key equals `key`, or `None` when the endpoint returned no such
/// entry.
///
/// Both the entry key and the entry data come from an untrusted RPC response
/// and are decoded under the depth- and length-bounded untrusted-decode
/// limits, so a crafted depth-bomb is rejected without exhausting the stack.
/// A returned key that does not decode is `EntryKeyUndecodable`; the matched
/// entry's data that does not decode is `undecodable`.
async fn fetch_entry_for_key(
    client: &StellarRpcClient,
    key: &LedgerKey,
    undecodable: MalformedEntryReason,
) -> Result<Option<LedgerEntryData>, SingleFetchError> {
    let response = client.get_ledger_entries(std::slice::from_ref(key)).await?;

    for entry_result in response.entries.unwrap_or_default() {
        let entry_key = LedgerKey::from_xdr_base64(
            &entry_result.key,
            stellar_agent_xdr_limits::untrusted_decode_limits(entry_result.key.len()),
        )
        .map_err(|_| SingleFetchError::Malformed(MalformedEntryReason::EntryKeyUndecodable))?;
        if &entry_key != key {
            continue;
        }
        let data = LedgerEntryData::from_xdr_base64(
            &entry_result.xdr,
            stellar_agent_xdr_limits::untrusted_decode_limits(entry_result.xdr.len()),
        )
        .map_err(|_| SingleFetchError::Malformed(undecodable))?;
        return Ok(Some(data));
    }

    Ok(None)
}

/// Constructs a `LedgerKey::ContractData` for the contract-instance slot.
fn contract_instance_ledger_key(
    contract_address: &str,
) -> Result<LedgerKey, FetchContractWasmHashError> {
    let contract_redacted = redact_strkey_first5_last5(contract_address);

    let contract = stellar_strkey::Contract::from_string(contract_address).map_err(|e| {
        FetchContractWasmHashError::InvalidAddress {
            contract_redacted: contract_redacted.clone(),
            reason: e.to_string(),
        }
    })?;

    let hash = Hash(contract.0);
    let sc_addr = ScAddress::Contract(ContractId(hash));

    Ok(LedgerKey::ContractData(LedgerKeyContractData {
        contract: sc_addr,
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    }))
}

/// Returns a bounded summary of a `WasmHashFetch` outcome for divergence
/// reporting.
///
/// `Wasm` renders first-8 hex; `Sac` and `Absent` render distinguishable
/// constant strings; `ExternalRef` renders the redacted owner, the bounded
/// tag and the resolved first-8 (or `<unset>`), so divergence messages
/// identify the exact mismatch without leaking full hashes or addresses.
fn wasm_hash_fetch_summary(fetch: &WasmHashFetch) -> String {
    match fetch {
        WasmHashFetch::Wasm(hash) => first8_hex(hash),
        WasmHashFetch::Sac => "<SAC>".to_owned(),
        WasmHashFetch::ExternalRef(external) => format!(
            "external-ref(owner={} tag=\"{}\" resolved={})",
            external.owner_redacted(),
            external.tag_display(),
            external.resolved_first8()
        ),
        WasmHashFetch::Absent => "<Absent>".to_owned(),
    }
}

/// Returns lower-case hex of the first 8 bytes of `hash`.
fn first8_hex(hash: &[u8; 32]) -> String {
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Redacts a strkey to first-5-last-5 characters for safe error reporting.
fn redact_strkey_first5_last5(strkey: &str) -> String {
    if strkey.len() <= 10 {
        return strkey.to_owned();
    }
    let (head, tail) = strkey.split_at(5);
    let last5 = &tail[tail.len() - 5..];
    format!("{head}\u{2026}{last5}")
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only fixture construction"
    )]

    use super::*;
    use stellar_agent_test_support::{
        KeyedLedgerEntriesResponder, echo_id_responder::EchoIdResponder, xdr_fixtures,
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer};

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// A testnet-format contract address (56 chars, starts with C).
    const TEST_CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

    fn wasm_result_json(wasm_hash: [u8; 32]) -> serde_json::Value {
        // Build the result JSON via xdr_fixtures then extract the result payload.
        // The full JSON-RPC envelope is built by EchoIdResponder.
        let full_json =
            xdr_fixtures::contract_instance_ledger_entries_json(TEST_CONTRACT, wasm_hash);
        let parsed: serde_json::Value = serde_json::from_str(&full_json).expect("valid json");
        parsed["result"].clone()
    }

    fn absent_result_json() -> serde_json::Value {
        serde_json::json!({"entries": null, "latestLedger": 100})
    }

    async fn mock_rpc_with_result(result: serde_json::Value) -> (MockServer, StellarRpcClient) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(result))
            .mount(&server)
            .await;
        let client = StellarRpcClient::new(&server.uri()).expect("valid URL");
        (server, client)
    }

    // ── Two-RPC divergence path ────────────────────────────────────────────

    /// Asserts that when primary and secondary return different hashes, the
    /// function returns `FetchContractWasmHashError::Divergent`.
    #[tokio::test]
    async fn two_rpc_divergence_returns_error() {
        let hash_a = [0xaau8; 32];
        let hash_b = [0xbbu8; 32];

        let (_s1, primary) = mock_rpc_with_result(wasm_result_json(hash_a)).await;
        let (_s2, secondary) = mock_rpc_with_result(wasm_result_json(hash_b)).await;

        let result = fetch_contract_wasm_hash(&primary, Some(&secondary), TEST_CONTRACT).await;

        assert!(
            matches!(result, Err(FetchContractWasmHashError::Divergent(_))),
            "expected Divergent; got {result:?}"
        );
        // Inspect divergence detail — must contain first-8 of each hash.
        if let Err(FetchContractWasmHashError::Divergent(e)) = result {
            assert_eq!(e.primary_summary, "aaaaaaaaaaaaaaaa");
            assert_eq!(e.secondary_summary, "bbbbbbbbbbbbbbbb");
        }
    }

    // ── Two-RPC agreement — Wasm ──────────────────────────────────────────

    #[tokio::test]
    async fn two_rpc_agreement_wasm_returns_hash() {
        let hash = [0x01u8; 32];
        let (_s1, primary) = mock_rpc_with_result(wasm_result_json(hash)).await;
        let (_s2, secondary) = mock_rpc_with_result(wasm_result_json(hash)).await;

        let result = fetch_contract_wasm_hash(&primary, Some(&secondary), TEST_CONTRACT).await;

        assert!(
            matches!(result, Ok(WasmHashFetch::Wasm(h)) if h == hash),
            "expected Wasm(hash); got {result:?}"
        );
    }

    // ── Single-RPC (no secondary) ──────────────────────────────────────────

    #[tokio::test]
    async fn single_rpc_absent_returns_absent() {
        let (_s, primary) = mock_rpc_with_result(absent_result_json()).await;
        let result = fetch_contract_wasm_hash(&primary, None, TEST_CONTRACT).await;
        assert!(
            matches!(result, Ok(WasmHashFetch::Absent)),
            "expected Absent; got {result:?}"
        );
    }

    // ── Primary absent, secondary wasm → divergence ────────────────────────

    #[tokio::test]
    async fn divergence_absent_vs_wasm() {
        let hash = [0x01u8; 32];
        let (_s1, primary) = mock_rpc_with_result(absent_result_json()).await;
        let (_s2, secondary) = mock_rpc_with_result(wasm_result_json(hash)).await;

        let result = fetch_contract_wasm_hash(&primary, Some(&secondary), TEST_CONTRACT).await;

        assert!(
            matches!(result, Err(FetchContractWasmHashError::Divergent(_))),
            "expected Divergent (Absent vs Wasm); got {result:?}"
        );
    }

    // ── Unavailable Display: no host/credential leakage ──────────────────

    /// Asserts that `FetchContractWasmHashError::Unavailable.to_string()` does
    /// NOT contain any credential substring embedded in the originating URL.
    ///
    /// `StellarRpcClient::get_ledger_entries` strips credentials from the URL
    /// before storing it in `NetworkError::RpcUnreachable.url`, so only
    /// `scheme://host[:port]` is retained. This test drives the error path
    /// end-to-end and asserts the credential string never reaches the formatter.
    #[tokio::test]
    async fn unavailable_display_does_not_leak_credentials() {
        // Build a client pointed at a URL that embeds userinfo credentials.
        // The RPC call will fail immediately (no server listening), which is
        // sufficient to trigger the Unavailable error path.
        let client = StellarRpcClient::new("https://user:secret-token@rpc.example.invalid")
            .expect("URL parses successfully");

        let result = fetch_contract_wasm_hash(&client, None, TEST_CONTRACT).await;

        let err = result.expect_err("expected RPC failure against an unreachable host");
        let display = err.to_string();
        let debug = format!("{err:?}");

        // The raw credential must not appear in Display or Debug output.
        assert!(
            !display.contains("secret-token"),
            "credential appeared in Display: {display}"
        );
        assert!(
            !debug.contains("secret-token"),
            "credential appeared in Debug: {debug}"
        );
        // The host should be present (authority-only form), but the userinfo must not.
        assert!(
            !display.contains("user:secret-token"),
            "full userinfo appeared in Display: {display}"
        );
    }

    /// Same credential-leak assertion as
    /// [`unavailable_display_does_not_leak_credentials`], but against a
    /// reachable server that returns HTTP 500 — exercising the post-connect
    /// transport-error path.
    #[tokio::test]
    async fn unavailable_display_does_not_leak_credentials_on_http_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        // Inject userinfo credentials into the mock server's URI.
        let credentialed = server.uri().replace("http://", "http://user:secret-token@");
        let client = StellarRpcClient::new(&credentialed).expect("credentialed mock URL parses");

        let result = fetch_contract_wasm_hash(&client, None, TEST_CONTRACT).await;

        let err = result.expect_err("expected RPC failure against an HTTP-500 server");
        let display = err.to_string();
        let debug = format!("{err:?}");

        assert!(
            !display.contains("secret-token"),
            "credential appeared in Display: {display}"
        );
        assert!(
            !debug.contains("secret-token"),
            "credential appeared in Debug: {debug}"
        );
    }

    // ── Depth-bomb regression ─────────────────────────────────────────────
    //
    // A `LedgerEntryData::ContractData` whose `val` field is a 600-deep
    // `ScVal::Vec` chain is returned by the mocked RPC under the instance
    // key. The bounded decoder rejects it without exhausting the stack, and
    // the fetch reports the entry as `Malformed`: an instance entry that
    // exists but does not decode is never read as "not deployed".

    /// A `getLedgerEntries` response whose single entry carries a 600-deep
    /// `ScVal::Vec` chain in the `ContractDataEntry.val` field is rejected by
    /// the bounded decoder and the call returns
    /// `FetchContractWasmHashError::Malformed` with reason
    /// `InstanceEntryUndecodable`.
    ///
    /// The fixture is encoded on a thread with an extended stack
    /// (32 MiB) because XDR encoding of a 600-deep `ScVal::Vec` chain is also
    /// recursive and overflows the default 8 MiB thread stack. Only the
    /// production decode path applies the depth bound; the encode-side stack
    /// extension is test-only scaffolding.
    #[tokio::test]
    async fn depth_bomb_ledger_entry_is_malformed_without_panic() {
        use stellar_strkey::Contract as StrkeyContract;
        use stellar_xdr::{
            ContractDataDurability, ContractDataEntry, ContractId, ExtensionPoint, Hash,
            LedgerEntryData, LedgerKey, LedgerKeyContractData, Limits, ScAddress, ScVal, ScVec,
            WriteXdr,
        };

        let contract = StrkeyContract::from_string(TEST_CONTRACT).expect("valid contract strkey");
        let sc_addr = ScAddress::Contract(ContractId(Hash(contract.0)));

        // Build a 600-deep `ScVal::Vec` chain iteratively (innermost first,
        // wrap outward). 600 > XDR_DECODE_MAX_DEPTH (500), so the bounded
        // decoder rejects it at the read side.
        let mut nested: ScVal = ScVal::Bool(false);
        for _ in 0..600 {
            nested = ScVal::Vec(Some(ScVec(
                vec![nested].try_into().expect("single-element ScVec"),
            )));
        }

        let entry_data = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: sc_addr.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: nested,
        });

        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: sc_addr,
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });

        // ENCODE on a thread with 32 MiB stack — write-side recursion for a
        // 600-deep ScVal::Vec overflows the default 8 MiB thread stack. The
        // extended stack is test-only; it is not available to the production
        // decode path, which remains bounded at XDR_DECODE_MAX_DEPTH.
        let (key_b64, val_b64) = std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(move || {
                let k = key.to_xdr_base64(Limits::none()).expect("key XDR encode");
                let v = entry_data
                    .to_xdr_base64(Limits::none())
                    .expect("entry XDR encode");
                (k, v)
            })
            .expect("thread spawn")
            .join()
            .expect("thread join");

        let result_json = serde_json::json!({
            "entries": [{
                "key": key_b64,
                "xdr": val_b64,
                "lastModifiedLedgerSeq": 100,
                "liveUntilLedgerSeq": 999_999
            }],
            "latestLedger": 100
        });

        let (_s, primary) = mock_rpc_with_result(result_json).await;
        let result = fetch_contract_wasm_hash(&primary, None, TEST_CONTRACT).await;

        assert!(
            matches!(
                result,
                Err(FetchContractWasmHashError::Malformed {
                    reason: MalformedEntryReason::InstanceEntryUndecodable,
                    ..
                })
            ),
            "expected Malformed(InstanceEntryUndecodable); got {result:?}"
        );
    }

    // ── CAP-85 external references ───────────────────────────────────────

    /// Owner of the external-reference fixtures (a contract address).
    const OWNER: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
    const TAG: &[u8] = b"pool-v2";

    fn entry(response_json: &str) -> serde_json::Value {
        xdr_fixtures::ledger_entry_from_response_json(response_json)
    }

    fn external_ref_instance_entry() -> serde_json::Value {
        entry(&xdr_fixtures::external_ref_instance_ledger_entries_json(
            TEST_CONTRACT,
            OWNER,
            TAG,
        ))
    }

    fn tag_entry(hash: [u8; 32]) -> serde_json::Value {
        entry(&xdr_fixtures::executable_tag_ledger_entries_json(
            OWNER, TAG, hash,
        ))
    }

    fn expected_owner() -> ScAddress {
        ScAddress::Contract(ContractId(Hash(
            stellar_strkey::Contract::from_string(OWNER)
                .expect("owner")
                .0,
        )))
    }

    #[tokio::test]
    async fn external_ref_with_live_tag_entry_resolves_on_both_endpoints() {
        let hash = [0x5au8; 32];
        let responder = KeyedLedgerEntriesResponder::new()
            .with_entry(external_ref_instance_entry())
            .with_entry(tag_entry(hash));
        let server1 = responder.clone().serve().await;
        let primary = StellarRpcClient::new(&server1.uri()).expect("valid URL");
        let server2 = responder.serve().await;
        let secondary = StellarRpcClient::new(&server2.uri()).expect("valid URL");

        let result = fetch_contract_wasm_hash(&primary, Some(&secondary), TEST_CONTRACT).await;

        let Ok(WasmHashFetch::ExternalRef(external)) = result else {
            panic!("expected ExternalRef; got {result:?}");
        };
        assert_eq!(external.owner, expected_owner());
        assert_eq!(external.tag.0.as_vec().as_slice(), TAG);
        assert_eq!(external.resolved, Some(hash));
        assert_eq!(external.resolved_first8(), "5a5a5a5a5a5a5a5a");
        assert_eq!(external.owner_redacted(), "CAAAA...ABSC4");
        assert_eq!(external.tag_display(), "pool-v2");
    }

    #[tokio::test]
    async fn external_ref_without_live_tag_entry_resolves_to_none() {
        let responder =
            KeyedLedgerEntriesResponder::new().with_entry(external_ref_instance_entry());
        let server = responder.serve().await;
        let primary = StellarRpcClient::new(&server.uri()).expect("valid URL");

        let result = fetch_contract_wasm_hash(&primary, None, TEST_CONTRACT).await;

        let Ok(WasmHashFetch::ExternalRef(external)) = result else {
            panic!("expected ExternalRef; got {result:?}");
        };
        assert_eq!(external.resolved, None);
        assert_eq!(external.resolved_first8(), "<unset>");
    }

    #[tokio::test]
    async fn external_ref_tag_entry_with_non_hash_value_is_malformed() {
        use stellar_xdr::{ScBytes, ScVal};

        let short = ScVal::Bytes(ScBytes(vec![0x11u8; 31].try_into().expect("31 bytes")));
        for value in [short, ScVal::U32(7)] {
            let responder = KeyedLedgerEntriesResponder::new()
                .with_entry(external_ref_instance_entry())
                .with_entry(entry(
                    &xdr_fixtures::executable_tag_ledger_entries_json_with_value(OWNER, TAG, value),
                ));
            let server = responder.serve().await;
            let primary = StellarRpcClient::new(&server.uri()).expect("valid URL");

            let result = fetch_contract_wasm_hash(&primary, None, TEST_CONTRACT).await;

            assert!(
                matches!(
                    result,
                    Err(FetchContractWasmHashError::Malformed {
                        reason: MalformedEntryReason::TagValueNotHash,
                        ..
                    })
                ),
                "expected Malformed(TagValueNotHash); got {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn external_ref_undecodable_tag_entry_is_malformed() {
        let mut tag = tag_entry([0x01; 32]);
        tag["xdr"] = serde_json::Value::String("AAAA////".to_owned());
        let responder = KeyedLedgerEntriesResponder::new()
            .with_entry(external_ref_instance_entry())
            .with_entry(tag);
        let server = responder.serve().await;
        let primary = StellarRpcClient::new(&server.uri()).expect("valid URL");

        let result = fetch_contract_wasm_hash(&primary, None, TEST_CONTRACT).await;

        assert!(
            matches!(
                result,
                Err(FetchContractWasmHashError::Malformed {
                    reason: MalformedEntryReason::TagEntryUndecodable,
                    ..
                })
            ),
            "expected Malformed(TagEntryUndecodable); got {result:?}"
        );
    }

    #[tokio::test]
    async fn undecodable_entry_key_is_malformed() {
        let instance_key = entry(&xdr_fixtures::contract_instance_ledger_entries_json(
            TEST_CONTRACT,
            [0u8; 32],
        ))["key"]
            .as_str()
            .expect("key")
            .to_owned();
        let mut returned = entry(&xdr_fixtures::contract_instance_ledger_entries_json(
            TEST_CONTRACT,
            [0u8; 32],
        ));
        returned["key"] = serde_json::Value::String("AAAA////".to_owned());
        let responder =
            KeyedLedgerEntriesResponder::new().with_entry_for_key(instance_key, returned);
        let server = responder.serve().await;
        let primary = StellarRpcClient::new(&server.uri()).expect("valid URL");

        let result = fetch_contract_wasm_hash(&primary, None, TEST_CONTRACT).await;

        assert!(
            matches!(
                result,
                Err(FetchContractWasmHashError::Malformed {
                    reason: MalformedEntryReason::EntryKeyUndecodable,
                    ..
                })
            ),
            "expected Malformed(EntryKeyUndecodable); got {result:?}"
        );
    }

    #[tokio::test]
    async fn non_instance_value_with_matching_key_is_malformed() {
        use stellar_xdr::{
            ContractDataDurability, ContractDataEntry, ExtensionPoint, LedgerEntryData, Limits,
            ScVal, WriteXdr,
        };

        let contract = stellar_strkey::Contract::from_string(TEST_CONTRACT).expect("contract");
        let data = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(ContractId(Hash(contract.0))),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::U64(1),
        });
        let mut instance = entry(&xdr_fixtures::contract_instance_ledger_entries_json(
            TEST_CONTRACT,
            [0u8; 32],
        ));
        instance["xdr"] =
            serde_json::Value::String(data.to_xdr_base64(Limits::none()).expect("encode"));
        let server = KeyedLedgerEntriesResponder::new()
            .with_entry(instance)
            .serve()
            .await;
        let primary = StellarRpcClient::new(&server.uri()).expect("valid URL");

        let result = fetch_contract_wasm_hash(&primary, None, TEST_CONTRACT).await;

        assert!(
            matches!(
                result,
                Err(FetchContractWasmHashError::Malformed {
                    reason: MalformedEntryReason::NotContractInstance,
                    ..
                })
            ),
            "expected Malformed(NotContractInstance); got {result:?}"
        );
    }

    #[tokio::test]
    async fn entry_for_an_unrequested_key_is_ignored() {
        // The endpoint answers the instance request with the owner's tag
        // entry only; no entry matches the instance key.
        let instance_key = entry(&xdr_fixtures::contract_instance_ledger_entries_json(
            TEST_CONTRACT,
            [0u8; 32],
        ))["key"]
            .as_str()
            .expect("key")
            .to_owned();
        let responder =
            KeyedLedgerEntriesResponder::new().with_entry_for_key(instance_key, tag_entry([1; 32]));
        let server = responder.serve().await;
        let primary = StellarRpcClient::new(&server.uri()).expect("valid URL");

        let result = fetch_contract_wasm_hash(&primary, None, TEST_CONTRACT).await;

        assert!(
            matches!(result, Ok(WasmHashFetch::Absent)),
            "expected Absent; got {result:?}"
        );
    }

    /// Both endpoints return byte-identical instance entries and differ only
    /// in the value stored under the owner's tag entry, so the resolved hash
    /// alone decides the comparison.
    #[tokio::test]
    async fn external_ref_resolved_hash_divergence_is_divergent() {
        let instance = external_ref_instance_entry();
        let server1 = KeyedLedgerEntriesResponder::new()
            .with_entry(instance.clone())
            .with_entry(tag_entry([0xaa; 32]))
            .serve()
            .await;
        let primary = StellarRpcClient::new(&server1.uri()).expect("valid URL");
        let server2 = KeyedLedgerEntriesResponder::new()
            .with_entry(instance)
            .with_entry(tag_entry([0xbb; 32]))
            .serve()
            .await;
        let secondary = StellarRpcClient::new(&server2.uri()).expect("valid URL");

        let result = fetch_contract_wasm_hash(&primary, Some(&secondary), TEST_CONTRACT).await;

        let Err(FetchContractWasmHashError::Divergent(e)) = result else {
            panic!("expected Divergent; got {result:?}");
        };
        assert_eq!(
            e.primary_summary,
            "external-ref(owner=CAAAA...ABSC4 tag=\"pool-v2\" resolved=aaaaaaaaaaaaaaaa)"
        );
        assert_eq!(
            e.secondary_summary,
            "external-ref(owner=CAAAA...ABSC4 tag=\"pool-v2\" resolved=bbbbbbbbbbbbbbbb)"
        );
        let display = e.to_string();
        assert!(!display.contains(OWNER), "full owner leaked: {display}");
    }

    #[tokio::test]
    async fn malformed_on_one_endpoint_is_malformed_not_divergent() {
        let responder = KeyedLedgerEntriesResponder::new()
            .with_entry(external_ref_instance_entry())
            .with_entry(entry(
                &xdr_fixtures::executable_tag_ledger_entries_json_with_value(
                    OWNER,
                    TAG,
                    stellar_xdr::ScVal::Void,
                ),
            ));
        let (_s1, primary) = mock_rpc_with_result(wasm_result_json([0x01; 32])).await;
        let server2 = responder.serve().await;
        let secondary = StellarRpcClient::new(&server2.uri()).expect("valid URL");

        let result = fetch_contract_wasm_hash(&primary, Some(&secondary), TEST_CONTRACT).await;

        assert!(
            matches!(
                result,
                Err(FetchContractWasmHashError::Malformed {
                    reason: MalformedEntryReason::TagValueNotHash,
                    ..
                })
            ),
            "expected Malformed; got {result:?}"
        );
    }

    #[test]
    fn external_ref_tag_display_bounds_and_escapes_owner_chosen_bytes() {
        let mut raw = b"evil\x1b[2J\n\r\t".to_vec();
        raw.extend(std::iter::repeat_n(b'A', 500));
        let external = ExternalRefExecutable {
            owner: expected_owner(),
            tag: stellar_xdr::ScString(raw.try_into().expect("tag fits")),
            resolved: None,
        };

        let shown = external.tag_display();
        assert!(shown.len() <= stellar_agent_core::observability::UNTRUSTED_DISPLAY_MAX_BYTES);
        assert!(shown.starts_with("evil\\u{1b}[2J\\n\\r\\t"), "{shown}");
        assert!(shown.ends_with("..."), "{shown}");
        assert!(!shown.chars().any(char::is_control), "{shown}");

        // The Debug form uses the same bounded renderings.
        let debug = format!("{external:?}");
        assert!(!debug.contains(OWNER), "{debug}");
        assert!(!debug.chars().any(char::is_control), "{debug}");
        assert!(debug.len() < 200, "{debug}");
    }

    #[test]
    fn external_ref_owner_without_strkey_form_renders_placeholder() {
        let external = ExternalRefExecutable {
            owner: ScAddress::LiquidityPool(stellar_xdr::PoolId(Hash([9; 32]))),
            tag: stellar_xdr::ScString(b"t".to_vec().try_into().expect("tag")),
            resolved: Some([0; 32]),
        };
        assert_eq!(external.owner_redacted(), "<unsupported address>");
    }

    #[test]
    fn tag_ledger_key_is_the_owner_persistent_executable_tag_key() {
        let external = ExternalRefExecutable {
            owner: expected_owner(),
            tag: stellar_xdr::ScString(TAG.to_vec().try_into().expect("tag")),
            resolved: None,
        };
        let fixture_key = entry(&xdr_fixtures::executable_tag_ledger_entries_json(
            OWNER, TAG, [0; 32],
        ))["key"]
            .as_str()
            .expect("key")
            .to_owned();
        let key = external.tag_ledger_key();
        assert_eq!(
            stellar_xdr::WriteXdr::to_xdr_base64(&key, stellar_xdr::Limits::none())
                .expect("encode"),
            fixture_key
        );
        assert_eq!(
            key,
            executable_tag_ledger_key(&external.owner, &external.tag)
        );
    }

    // ── Display/Debug redaction audit ─────────────────────────────────────

    #[test]
    fn divergence_error_display_redacts_full_hash() {
        let err = WasmHashDivergenceError {
            contract_redacted: "CAAAA\u{2026}AAB".to_owned(),
            primary_summary: "aaaaaaaaaaaaaaa1".to_owned(),
            secondary_summary: "bbbbbbbbbbbbbbb2".to_owned(),
        };
        let display = err.to_string();
        // Full hex of a known hash must not appear
        let full_hash_hex: String = [0xaau8; 32].iter().map(|b| format!("{b:02x}")).collect();
        assert!(!display.contains(&full_hash_hex));
        assert!(display.contains("aaaaaaaaaaaaaaa1"));
    }
}
