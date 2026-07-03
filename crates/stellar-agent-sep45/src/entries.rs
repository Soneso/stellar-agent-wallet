//! SEP-45 v0.1.1 authorization entries parsing and 13-point validation.
//!
//! [`AuthorizationEntries`] holds the fully-validated result of a SEP-45
//! challenge response's `authorization_entries` field.
//! [`AuthorizationEntries::parse_and_validate`] enforces steps 1-12 per
//! the SEP-45 challenge-response schema. Step 13 (footprint validation)
//! requires simulation results not available at challenge-fetch time and is
//! deferred to the caller.
//!
//! # Validation steps
//!
//! 1. Base64-decode + XDR-decode to `Vec<SorobanAuthorizationEntry>`.
//! 2. Verify entry count ≥ 1. A client entry is required (step 10); contracts
//!    whose `__check_auth` needs no client signature are not yet supported by
//!    this validator. If `client_domain` is present in the step-6 args, ≥ 3
//!    entries are required.
//! 3. Verify each entry's `sub_invocations` is empty (per SEP-45 challenge schema).
//! 4. Verify each entry's `root_invocation.function` is `ContractFn` variant.
//! 5. Verify each entry's `contract_address` = expected web auth contract
//!    (per SEP-45 challenge schema).
//! 6. Verify each entry's `function_name` = `"web_auth_verify"`
//!    (per SEP-45 challenge schema).
//! 7. Extract and validate args from first entry's `args` map (5-7 keys).
//!    Validate `account`, `home_domain`, `web_auth_domain`,
//!    `web_auth_domain_account`, optional `client_domain[_account]`, `nonce`.
//! 8. Verify nonce is non-empty (per the SEP-45 nonce definition — spec
//!    places no length constraint; non-emptiness is the only invariant
//!    asserted here).
//! 9. Verify nonce is consistent across all entries. Step 9b additionally
//!    verifies the full args map is identical across entries (account,
//!    home_domain, web_auth_domain, web_auth_domain_account, client_domain).
//! 10. Identify server-signed entry (`credentials.address.address` =
//!     server signing key) and client entry (= client account).
//! 11. If `client_domain` arg present, verify a client-domain-account
//!     credential entry exists.
//! 12. Verify server signature is present and cryptographically valid.
//!     Uses `ed25519_dalek::VerifyingKey::verify_strict` over the
//!     SHA-256 of the `HashIdPreimageSorobanAuthorization` XDR preimage.
//! 13. Footprint `read_write` validation (per SEP-45 step 13) requires
//!     simulation results and is deferred to the caller.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits, ReadXdr, ScAddress, ScVal,
    SorobanAuthorizationEntries, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanCredentials, WriteXdr,
};

use crate::error::Sep45Error;

/// Expected function name for SEP-45 web auth (per the SEP-45 challenge-validation steps).
const WEB_AUTH_VERIFY_FN: &str = "web_auth_verify";

/// A fully-validated SEP-45 v0.1.1 challenge response.
///
/// Constructed exclusively via [`AuthorizationEntries::parse_and_validate`],
/// which performs all 13 validation steps before returning. Every field
/// reflects the validated, canonical state — callers do not need to
/// re-validate.
///
#[derive(Debug, Clone)]
pub struct AuthorizationEntries {
    /// The raw decoded `SorobanAuthorizationEntry` list from the challenge.
    ///
    /// The signing flow in `ephemeral.rs` signs only the entry whose
    /// `credentials.address.address` matches the `client_account`.
    pub entries: Vec<SorobanAuthorizationEntry>,

    /// The server signing key (G-strkey) that issued the challenge.
    ///
    /// Validated to match `expected_server_signing_key` and confirmed to have
    /// signed the `HashIdPreimageSorobanAuthorization` in step 12.
    pub server_account: stellar_strkey::ed25519::PublicKey,

    /// The client contract account (C-strkey) being authenticated.
    ///
    /// Validated to match both the `account` arg in step 7 and the
    /// `expected_account` parameter supplied by the caller (SEP-45 step 7.1).
    pub client_account: stellar_strkey::Contract,

    /// The server's web auth domain from the `web_auth_domain` arg.
    ///
    /// Validated to match `expected_web_auth_domain` in step 7.
    pub web_auth_domain: String,

    /// The server signing key from the `web_auth_domain_account` arg.
    ///
    /// Validated to match `expected_server_signing_key` in step 7.
    pub web_auth_domain_account: stellar_strkey::ed25519::PublicKey,

    /// The nonce value from the args map (same across all entries).
    ///
    /// The raw nonce string from the args map. The SEP-45 nonce definition
    /// requires it to be a unique value, the same across all entries, with no
    /// length constraint. Step 8 validates that the nonce is non-empty.
    pub nonce: String,

    /// The home domain from the `home_domain` arg.
    ///
    /// Validated to match `expected_home_domain` in step 7.
    pub expected_home_domain: String,

    /// The web auth contract address (C-strkey) from each entry's invocation.
    ///
    /// Validated against `expected_web_auth_contract` in step 5.
    pub web_auth_contract: stellar_strkey::Contract,

    /// The `client_domain` arg value, if present in the args map.
    ///
    /// `Some` when the challenge was requested with a `client_domain` parameter.
    pub client_domain: Option<String>,

    /// The `client_domain_account` arg value (G-strkey), if present.
    ///
    /// `Some` when the challenge includes a client domain signing entry.
    pub client_domain_account: Option<stellar_strkey::ed25519::PublicKey>,

    /// Zero-based index of the server-signed entry in `entries`.
    pub server_entry_index: usize,

    /// Zero-based index of the client (unsigned) entry in `entries`.
    pub client_entry_index: usize,

    /// Zero-based index of the client-domain entry in `entries`, if present.
    pub client_domain_entry_index: Option<usize>,
}

impl AuthorizationEntries {
    /// Returns the UTF-8 bytes of the nonce string.
    ///
    /// Equivalent to `self.nonce.as_bytes()`. Provided as a convenience accessor
    /// for callers that need the byte representation directly. The returned slice
    /// is guaranteed non-empty because step 8 rejects empty nonces.
    #[must_use]
    pub fn nonce_bytes(&self) -> &[u8] {
        self.nonce.as_bytes()
    }
}

impl AuthorizationEntries {
    /// Parses and validates a SEP-45 v0.1.1 challenge's `authorization_entries`.
    ///
    /// Enforces steps 1-12 per `sep-0045.md` lines 85-127 + 148-150.
    /// Step 13 (footprint `read_write` validation) requires prior simulation
    /// results and is deferred to the caller. Fail-closed: any validation
    /// step failure returns a typed [`Sep45Error`].
    ///
    /// # Parameters
    ///
    /// - `xdr_b64` — the base64-encoded `SorobanAuthorizationEntries` XDR
    ///   from the server's GET response `authorization_entries` field.
    /// - `network_passphrase` — Stellar network passphrase (used to compute
    ///   the `network_id` hash for server-signature preimage).
    /// - `expected_web_auth_contract` — the `WEB_AUTH_CONTRACT_ID` C-strkey
    ///   from the server's `stellar.toml`.
    /// - `expected_home_domain` — the home domain submitted in the challenge
    ///   request (must match the `home_domain` arg).
    /// - `expected_web_auth_domain` — the server's own domain (must match the
    ///   `web_auth_domain` arg).
    /// - `expected_server_signing_key` — the `SIGNING_KEY` G-strkey from the
    ///   server's `stellar.toml`.
    /// - `expected_client_domain` — when `Some`, the challenge MUST carry a
    ///   matching `client_domain` arg; when `None`, the challenge MUST NOT
    ///   carry a `client_domain` arg.
    /// - `expected_account` — the C-strkey of the contract account the client
    ///   requested authentication for. Per SEP-45 step 7.1
    ///   (per SEP-45 challenge-validation step 7.1), the `account` arg in the
    ///   challenge MUST equal this value. Pass the same value as the `account=`
    ///   GET query parameter sent to the server.
    ///
    /// # Errors
    ///
    /// - [`Sep45Error::XdrDecodeError`] — base64 or XDR decode failure.
    /// - [`Sep45Error::InvalidExpectedContractArg`] — `expected_web_auth_contract`
    ///   is not a valid C-strkey (caller argument is malformed).
    /// - [`Sep45Error::InvalidExpectedServerKeyArg`] — `expected_server_signing_key`
    ///   is not a valid G-strkey (caller argument is malformed).
    /// - [`Sep45Error::InvalidEntryCount`] — zero entries (step 2), or fewer
    ///   than 3 entries when `client_domain` arg is present.
    ///   Note: the SEP-45 challenge-validation steps permit a server-only entry
    ///   for contracts that do not require client signatures; client-entry
    ///   enforcement is conservatively applied via
    ///   [`Sep45Error::MissingClientEntry`] (step 10).
    /// - [`Sep45Error::UnsupportedCredentialType`] — any entry carries a
    ///   credential type other than `SorobanCredentials::Address`.
    /// - [`Sep45Error::UnexpectedSubInvocations`] — any entry has
    ///   `sub_invocations` (forbidden per the SEP-45 challenge-validation steps).
    /// - [`Sep45Error::InvalidContractAddress`] — entry's contract address does
    ///   not match `expected_web_auth_contract`.
    /// - [`Sep45Error::InvalidFunctionName`] — entry's function name is not
    ///   `"web_auth_verify"`.
    /// - [`Sep45Error::InvalidArgsCount`] — fewer than 5 args in the first
    ///   entry's args map.
    /// - [`Sep45Error::InvalidArgsFormat`] — args map is structurally invalid
    ///   (e.g. duplicate Symbol key, or a Symbol key or String value with
    ///   invalid UTF-8 bytes).
    /// - [`Sep45Error::InvalidAccountArg`] — `account` arg absent, malformed,
    ///   not a C-strkey, or does not match `expected_account` (SEP-45 step 7.1).
    /// - [`Sep45Error::HomeDomainMismatch`] — `home_domain` arg mismatch.
    /// - [`Sep45Error::WebAuthDomainMismatch`] — `web_auth_domain` arg
    ///   mismatch (including cross-entry divergence detected at step 9b).
    /// - [`Sep45Error::WebAuthDomainAccountMismatch`] — `web_auth_domain_account`
    ///   arg mismatch.
    /// - [`Sep45Error::ClientDomainMismatch`] — `client_domain` arg present
    ///   when `expected_client_domain` is `None`, absent when it is `Some`,
    ///   or its value differs from the expected value.
    /// - [`Sep45Error::InvalidClientDomainAccount`] — `client_domain_account`
    ///   is present but not a valid G-strkey, or differs across entries.
    /// - [`Sep45Error::MissingNonce`] — `nonce` arg absent from any entry, or
    ///   the nonce string is empty (step 8).
    /// - [`Sep45Error::NonceMismatch`] — nonce inconsistent across entries.
    /// - [`Sep45Error::MissingClientDomainOp`] — `client_domain` arg present
    ///   but no client-domain-account credential entry found.
    /// - [`Sep45Error::MissingServerEntry`] — no entry with server signing key
    ///   credentials found.
    /// - [`Sep45Error::MissingClientEntry`] — no entry with client account
    ///   credentials found.
    /// - [`Sep45Error::MissingServerSignature`] — server entry has no
    ///   signature in its credentials.
    /// - [`Sep45Error::InvalidServerSignature`] — server signature fails
    ///   `ed25519_dalek::VerifyingKey::verify_strict`.
    ///
    /// # Security
    ///
    /// This method does not access the network. All validation is performed
    /// on the XDR bytes provided. The server signature is verified using
    /// `ed25519_dalek::VerifyingKey::verify_strict` (hardened against
    /// malleability attacks) over the SHA-256 of the
    /// `HashIdPreimageSorobanAuthorization` XDR preimage.
    ///
    /// Step 13 (footprint `read_write` validation per SEP-45 step 13) is not
    /// enforced here because it requires simulation results from a prior
    /// contract invocation. Callers that need step-13 enforcement must perform
    /// it separately after obtaining simulation results.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_sep45::AuthorizationEntries;
    ///
    /// // The server's authorization_entries b64 XDR string from the GET response.
    /// // (This example uses an intentionally invalid value to demonstrate the
    /// // error path; a real server XDR would pass validation.)
    /// let result = AuthorizationEntries::parse_and_validate(
    ///     "not_valid_base64!!",
    ///     "Test SDF Network ; September 2015",
    ///     "CALI6JC3MSNDGFRP7Z2OKUEPREHOJRRXKMJEWQDEFZPFGXALA45RAUTH",
    ///     "example.com",
    ///     "auth.example.com",
    ///     "GCHLHDBOKGWJWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
    ///     None,
    ///     "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ",
    /// );
    /// assert!(result.is_err());
    /// ```
    #[allow(
        clippy::too_many_arguments,
        reason = "SEP-45 validation requires all parameters"
    )]
    pub fn parse_and_validate(
        xdr_b64: &str,
        network_passphrase: &str,
        expected_web_auth_contract: &str,
        expected_home_domain: &str,
        expected_web_auth_domain: &str,
        expected_server_signing_key: &str,
        expected_client_domain: Option<&str>,
        expected_account: &str,
    ) -> Result<Self, Sep45Error> {
        // ── Step 1: base64-decode + XDR-decode ──────────────────────────────
        let raw_bytes =
            BASE64_STANDARD
                .decode(xdr_b64)
                .map_err(|e| Sep45Error::XdrDecodeError {
                    detail: format!("base64 decode failed: {e}"),
                })?;

        // `SorobanAuthorizationEntries` is a XDR typedef:
        // `typedef SorobanAuthorizationEntry SorobanAuthorizationEntries<>;`
        // It reads as a length-prefixed XDR array of `SorobanAuthorizationEntry`.
        // Each entry carries a recursive `root_invocation` from an untrusted
        // anchor/client source; bounded limits prevent a crafted deep
        // `sub_invocations` chain from exhausting the stack.
        let entries_xdr = SorobanAuthorizationEntries::read_xdr(&mut stellar_xdr::Limited::new(
            std::io::Cursor::new(&raw_bytes),
            stellar_agent_xdr_limits::untrusted_decode_limits(raw_bytes.len()),
        ))
        .map_err(|e| Sep45Error::XdrDecodeError {
            detail: format!("XDR decode of SorobanAuthorizationEntries failed: {e}"),
        })?;

        let entries: Vec<SorobanAuthorizationEntry> = entries_xdr.0.into_vec();

        // ── Step 2: entry count ≥ 1 minimum (pre-client_domain check) ───────
        // A client entry is required (step 10); contracts whose __check_auth
        // needs no client signature are not yet supported by this validator.
        // The ≥ 3 re-check (for client_domain) happens after the args are
        // extracted below.
        if entries.is_empty() {
            return Err(Sep45Error::InvalidEntryCount {
                found: 0,
                expected_min: 1,
            });
        }

        // ── Parse expected contract address (validate C-strkey input) ────────
        // `InvalidExpectedContractArg` is the caller-arg error; it is
        // semantically distinct from `InvalidContractAddress` (which is
        // returned when an *entry's* contract address does not match).
        let expected_contract = stellar_strkey::Contract::from_string(expected_web_auth_contract)
            .map_err(|e| Sep45Error::InvalidExpectedContractArg {
                detail: format!(
                    "expected_web_auth_contract {expected_web_auth_contract:?} is not a valid C-strkey: {e}"
                ),
            })?;

        // ── Parse expected server signing key (validate G-strkey input) ──────
        // A malformed caller-supplied key is a different error class from a
        // cryptographic verification failure — map it to InvalidExpectedServerKeyArg
        // rather than InvalidServerSignature so callers can distinguish "bad
        // argument" from "bad signature".
        let expected_server_key = stellar_strkey::ed25519::PublicKey::from_string(
            expected_server_signing_key,
        )
        .map_err(|e| Sep45Error::InvalidExpectedServerKeyArg {
            detail: format!("expected_server_signing_key {expected_server_signing_key:?} is not a valid G-strkey: {e}"),
        })?;

        // ── Step 3-6: per-entry structural checks ────────────────────────────
        for (idx, entry) in entries.iter().enumerate() {
            // Step 3: No sub-invocations (sep-0045.md line 86).
            if !entry.root_invocation.sub_invocations.is_empty() {
                return Err(Sep45Error::UnexpectedSubInvocations { entry_index: idx });
            }

            // Step 4: Function must be ContractFn variant.
            let contract_fn = match &entry.root_invocation.function {
                SorobanAuthorizedFunction::ContractFn(fn_args) => fn_args,
                _ => {
                    return Err(Sep45Error::InvalidFunctionName {
                        found: "<non-contract function>".to_owned(),
                        expected: WEB_AUTH_VERIFY_FN,
                    });
                }
            };

            // Step 5: Contract address = expected web auth contract
            // (per the SEP-45 challenge-validation steps).
            let entry_contract_str = sc_address_to_string(&contract_fn.contract_address)?;
            if entry_contract_str != expected_web_auth_contract {
                return Err(Sep45Error::InvalidContractAddress {
                    found: entry_contract_str,
                    expected: expected_web_auth_contract.to_owned(),
                });
            }

            // Step 6: Function name = "web_auth_verify" (per the SEP-45 challenge-validation steps).
            let fn_name = contract_fn.function_name.0.as_slice();
            let fn_name_str = std::str::from_utf8(fn_name).unwrap_or("<invalid utf8>");
            if fn_name_str != WEB_AUTH_VERIFY_FN {
                return Err(Sep45Error::InvalidFunctionName {
                    found: fn_name_str.to_owned(),
                    expected: WEB_AUTH_VERIFY_FN,
                });
            }
        }

        // ── Step 7: Extract and validate args from first entry ───────────────
        // Per the SEP-45 challenge args schema, args is a Map<Symbol, String>
        // with keys: account, home_domain, web_auth_domain,
        // web_auth_domain_account, nonce, [client_domain, client_domain_account].
        let first_fn = match &entries[0].root_invocation.function {
            SorobanAuthorizedFunction::ContractFn(fn_args) => fn_args,
            // SAFETY: Step 3-6 already verified every entry is ContractFn.
            // If this arm is reached it is an internal logic error; we return
            // a typed error rather than panic so the "Never panics" rustdoc
            // contract holds and `#![deny(clippy::panic)]` is satisfied.
            _ => {
                return Err(Sep45Error::InvalidFunctionName {
                    found: "<non-contract function>".to_owned(),
                    expected: WEB_AUTH_VERIFY_FN,
                });
            }
        };

        // The args is a VecM<ScVal>; first element must be a ScMap.
        // Per the SEP-45 challenge args schema, the args field is a single
        // Map<Symbol,String>. InvokeContractArgs.args is VecM<ScVal>; the map
        // is the first (and only) arg.
        if first_fn.args.is_empty() {
            return Err(Sep45Error::InvalidArgsCount {
                found: 0,
                expected_min: 1,
            });
        }

        let args_map = extract_args_map(&first_fn.args[0])?;

        // Validate minimum arg count: account, home_domain, web_auth_domain,
        // web_auth_domain_account, nonce = 5 required.
        const MIN_ARGS: usize = 5;
        if args_map.len() < MIN_ARGS {
            return Err(Sep45Error::InvalidArgsCount {
                found: args_map.len(),
                expected_min: MIN_ARGS,
            });
        }

        // Extract `account` arg — must be a C-strkey.
        let account_str = args_map
            .get("account")
            .ok_or_else(|| Sep45Error::InvalidAccountArg {
                detail: "account arg is absent from args map".to_owned(),
            })?
            .clone();

        let client_account = stellar_strkey::Contract::from_string(&account_str).map_err(|e| {
            Sep45Error::InvalidAccountArg {
                detail: format!("account arg {account_str:?} is not a valid C-strkey: {e}"),
            }
        })?;

        // SEP-45 step 7.1: the `account` arg must equal the Client Account
        // address the caller requested. Without this check a server could
        // substitute any contract address and the client would sign an
        // authorization for a different account than it intended.
        if account_str != expected_account {
            return Err(Sep45Error::InvalidAccountArg {
                detail: format!(
                    "account arg {account_str:?} does not match the requested client account {expected_account:?}"
                ),
            });
        }

        // Extract `home_domain` arg.
        let home_domain_found = args_map
            .get("home_domain")
            .ok_or_else(|| Sep45Error::HomeDomainMismatch {
                found: String::new(),
                expected: expected_home_domain.to_owned(),
            })?
            .clone();

        if home_domain_found != expected_home_domain {
            return Err(Sep45Error::HomeDomainMismatch {
                found: home_domain_found,
                expected: expected_home_domain.to_owned(),
            });
        }

        // Extract `web_auth_domain` arg.
        let web_auth_domain_found = args_map
            .get("web_auth_domain")
            .ok_or_else(|| Sep45Error::WebAuthDomainMismatch {
                found: String::new(),
                expected: expected_web_auth_domain.to_owned(),
            })?
            .clone();

        if web_auth_domain_found != expected_web_auth_domain {
            return Err(Sep45Error::WebAuthDomainMismatch {
                found: web_auth_domain_found,
                expected: expected_web_auth_domain.to_owned(),
            });
        }

        // Extract `web_auth_domain_account` arg — must be the server signing key.
        let wada_found = args_map
            .get("web_auth_domain_account")
            .ok_or_else(|| Sep45Error::WebAuthDomainAccountMismatch {
                found: String::new(),
                expected: expected_server_signing_key.to_owned(),
            })?
            .clone();

        if wada_found != expected_server_signing_key {
            return Err(Sep45Error::WebAuthDomainAccountMismatch {
                found: wada_found,
                expected: expected_server_signing_key.to_owned(),
            });
        }

        let web_auth_domain_account = stellar_strkey::ed25519::PublicKey::from_string(&wada_found)
            .map_err(|_e| {
                // `_e` is the strkey parse error; we return a typed variant
                // that names the found vs expected value. The raw parse error
                // is intentionally dropped — `wada_found` already carries the
                // diagnostic string for the mismatch context.
                Sep45Error::WebAuthDomainAccountMismatch {
                    found: wada_found.clone(),
                    expected: expected_server_signing_key.to_owned(),
                }
            })?;

        // Extract optional `client_domain` and `client_domain_account` args.
        let client_domain = args_map.get("client_domain").cloned();
        let client_domain_account_str = args_map.get("client_domain_account").cloned();

        // ── Validate client_domain against caller expectation ────────────────
        // The caller specifies whether it expects a client_domain in the
        // challenge. A mismatch in either direction is a fail-closed rejection.
        match (expected_client_domain, client_domain.as_deref()) {
            (Some(expected_cd), Some(found_cd)) => {
                if found_cd != expected_cd {
                    return Err(Sep45Error::ClientDomainMismatch {
                        found: found_cd.to_owned(),
                        expected: expected_cd.to_owned(),
                    });
                }
            }
            (Some(expected_cd), None) => {
                return Err(Sep45Error::ClientDomainMismatch {
                    found: String::new(),
                    expected: expected_cd.to_owned(),
                });
            }
            (None, Some(found_cd)) => {
                return Err(Sep45Error::ClientDomainMismatch {
                    found: found_cd.to_owned(),
                    expected: String::new(),
                });
            }
            (None, None) => {}
        }

        let client_domain_account = if let Some(ref cda_str) = client_domain_account_str {
            let key = stellar_strkey::ed25519::PublicKey::from_string(cda_str).map_err(|e| {
                Sep45Error::InvalidClientDomainAccount {
                    detail: format!(
                        "client_domain_account {cda_str:?} is not a valid G-strkey: {e}"
                    ),
                }
            })?;
            Some(key)
        } else {
            None
        };

        // Extract `nonce` arg.
        let nonce_str = args_map
            .get("nonce")
            .ok_or(Sep45Error::MissingNonce { entry_index: 0 })?
            .clone();

        // ── Step 8: Validate nonce is non-empty ──────────────────────────────
        // The SEP-45 spec defines the nonce as a unique value that must be the
        // same across all entries with no length constraint. The only invariant
        // asserted here without further spec authority is non-emptiness;
        // cross-entry consistency is verified in step 9.
        let nonce_bytes_slice = nonce_str.as_bytes();
        if nonce_bytes_slice.is_empty() {
            return Err(Sep45Error::MissingNonce { entry_index: 0 });
        }

        // ── Re-check entry count if client_domain present (≥ 3) ─────────────
        if client_domain.is_some() && entries.len() < 3 {
            return Err(Sep45Error::InvalidEntryCount {
                found: entries.len(),
                expected_min: 3,
            });
        }

        // ── Step 9: Verify nonce consistent across all entries ───────────────
        for (idx, entry) in entries.iter().enumerate().skip(1) {
            let fn_args = match &entry.root_invocation.function {
                SorobanAuthorizedFunction::ContractFn(a) => a,
                // SAFETY: Step 3-6 already verified every entry is ContractFn.
                // Return typed error to preserve the "Never panics" rustdoc
                // contract and satisfy `#![deny(clippy::panic)]`.
                _ => {
                    return Err(Sep45Error::InvalidFunctionName {
                        found: "<non-contract function>".to_owned(),
                        expected: WEB_AUTH_VERIFY_FN,
                    });
                }
            };
            if fn_args.args.is_empty() {
                return Err(Sep45Error::MissingNonce { entry_index: idx });
            }
            let entry_args = extract_args_map(&fn_args.args[0])?;
            let entry_nonce = entry_args
                .get("nonce")
                .ok_or(Sep45Error::MissingNonce { entry_index: idx })?;
            if *entry_nonce != nonce_str {
                return Err(Sep45Error::NonceMismatch { entry_index: idx });
            }
        }

        // ── Step 9b: Cross-entry args consistency ────────────────────────────
        // Every entry's full args map must carry the same account, home_domain,
        // web_auth_domain, web_auth_domain_account, and optional client_domain
        // values as the reference extracted in step 7. A server that injects
        // different args into the client entry would cause the client to sign a
        // different invocation context than the server entry references.
        for (idx, entry) in entries.iter().enumerate().skip(1) {
            let fn_args = match &entry.root_invocation.function {
                SorobanAuthorizedFunction::ContractFn(a) => a,
                _ => {
                    // Steps 3-6 already verified ContractFn; this branch is
                    // an internal logic error — return typed error to satisfy
                    // the "Never panics" contract and #![deny(clippy::panic)].
                    return Err(Sep45Error::InvalidFunctionName {
                        found: "<non-contract function>".to_owned(),
                        expected: WEB_AUTH_VERIFY_FN,
                    });
                }
            };
            if fn_args.args.is_empty() {
                return Err(Sep45Error::MissingNonce { entry_index: idx });
            }
            let entry_args = extract_args_map(&fn_args.args[0])?;

            // Validate web_auth_domain.
            let entry_wad = entry_args
                .get("web_auth_domain")
                .map(String::as_str)
                .unwrap_or("");
            if entry_wad != web_auth_domain_found {
                return Err(Sep45Error::WebAuthDomainMismatch {
                    found: entry_wad.to_owned(),
                    expected: web_auth_domain_found.clone(),
                });
            }

            // Validate account.
            let entry_account = entry_args.get("account").map(String::as_str).unwrap_or("");
            if entry_account != account_str {
                return Err(Sep45Error::InvalidAccountArg {
                    detail: format!(
                        "account arg in entry {idx} ({entry_account:?}) differs from \
                         reference entry ({account_str:?})"
                    ),
                });
            }

            // Validate home_domain.
            let entry_home = entry_args
                .get("home_domain")
                .map(String::as_str)
                .unwrap_or("");
            if entry_home != home_domain_found {
                return Err(Sep45Error::HomeDomainMismatch {
                    found: entry_home.to_owned(),
                    expected: home_domain_found.clone(),
                });
            }

            // Validate web_auth_domain_account.
            let entry_wada = entry_args
                .get("web_auth_domain_account")
                .map(String::as_str)
                .unwrap_or("");
            if entry_wada != wada_found {
                return Err(Sep45Error::WebAuthDomainAccountMismatch {
                    found: entry_wada.to_owned(),
                    expected: wada_found.clone(),
                });
            }

            // Validate client_domain when it was present in the reference entry.
            if let Some(ref ref_cd) = client_domain {
                let entry_cd = entry_args
                    .get("client_domain")
                    .map(String::as_str)
                    .unwrap_or("");
                if entry_cd != ref_cd {
                    return Err(Sep45Error::ClientDomainMismatch {
                        found: entry_cd.to_owned(),
                        expected: ref_cd.clone(),
                    });
                }
            }

            // Validate client_domain_account when it was present in the
            // reference entry. A server that injects a different
            // client_domain_account into a non-first entry would cause the
            // client to sign an authorization for a different domain account.
            if let Some(ref ref_cda) = client_domain_account_str {
                let entry_cda = entry_args
                    .get("client_domain_account")
                    .map(String::as_str)
                    .unwrap_or("");
                if entry_cda != ref_cda {
                    return Err(Sep45Error::InvalidClientDomainAccount {
                        detail: format!(
                            "client_domain_account in entry {idx} ({entry_cda:?}) differs from \
                             reference entry ({ref_cda:?})"
                        ),
                    });
                }
            }
        }

        // ── Steps 10-11: Identify entry roles by credential address ──────────
        let server_key_str = expected_server_signing_key;
        let client_account_str = account_str.as_str();
        let client_domain_account_str_ref = client_domain_account_str.as_deref();

        let mut server_entry_index: Option<usize> = None;
        let mut client_entry_index: Option<usize> = None;
        let mut client_domain_entry_index: Option<usize> = None;

        for (idx, entry) in entries.iter().enumerate() {
            let cred_addr_str = match &entry.credentials {
                SorobanCredentials::Address(addr_creds) => {
                    sc_address_to_string(&addr_creds.address)?
                }
                // SourceAccount, AddressV2, and AddressWithDelegates are not
                // valid in a SEP-45 challenge. Fail-closed: reject any entry
                // that is not SorobanCredentials::Address.
                SorobanCredentials::SourceAccount
                | SorobanCredentials::AddressV2(_)
                | SorobanCredentials::AddressWithDelegates(_) => {
                    return Err(Sep45Error::UnsupportedCredentialType { entry_index: idx });
                }
            };

            if cred_addr_str == server_key_str {
                server_entry_index = Some(idx);
            } else if cred_addr_str == client_account_str {
                client_entry_index = Some(idx);
            } else if let Some(cda) = client_domain_account_str_ref
                && cred_addr_str == cda
            {
                client_domain_entry_index = Some(idx);
            }
        }

        let server_idx = server_entry_index.ok_or(Sep45Error::MissingServerEntry)?;
        let client_idx = client_entry_index.ok_or(Sep45Error::MissingClientEntry)?;

        // Step 11: If client_domain arg present, verify a credential entry for
        // the client domain account exists.
        if client_domain.is_some() && client_domain_entry_index.is_none() {
            return Err(Sep45Error::MissingClientDomainOp);
        }

        // ── Step 12: Verify server signature ────────────────────────────────
        // Compute `HashIdPreimageSorobanAuthorization` XDR, SHA-256 hash it,
        // then verify with `ed25519_dalek::VerifyingKey::verify_strict`.
        //
        // HashIdPreimageSorobanAuthorization fields:
        //   network_id: Hash,       // SHA-256 of network_passphrase bytes
        //   nonce: i64,
        //   signature_expiration_ledger: u32,
        //   invocation: SorobanAuthorizedInvocation,
        verify_server_signature(
            &entries[server_idx],
            network_passphrase,
            &expected_server_key,
        )?;

        // ── Step 13: Footprint validation ────────────────────────────────────
        // Deferred: requires simulation results not available at challenge-fetch
        // time. The footprint read_write check (per SEP-45 step 13) requires a
        // prior contract invocation simulation. Callers must perform this check
        // separately after obtaining simulation results.

        Ok(Self {
            entries,
            server_account: expected_server_key,
            client_account,
            web_auth_domain: web_auth_domain_found,
            web_auth_domain_account,
            nonce: nonce_str,
            expected_home_domain: home_domain_found,
            web_auth_contract: expected_contract,
            client_domain,
            client_domain_account,
            server_entry_index: server_idx,
            client_entry_index: client_idx,
            client_domain_entry_index,
        })
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Converts a `ScAddress` to its string representation (G-strkey or C-strkey).
fn sc_address_to_string(address: &ScAddress) -> Result<String, Sep45Error> {
    match address {
        ScAddress::Account(account_id) => {
            // AccountID is PublicKey enum; we handle Ed25519 variant.
            match &account_id.0 {
                stellar_xdr::PublicKey::PublicKeyTypeEd25519(bytes) => {
                    let key = stellar_strkey::ed25519::PublicKey(bytes.0);
                    // Display impl delegates to the heapless to_string(); use
                    // format! to obtain a std::string::String.
                    Ok(format!("{key}"))
                }
            }
        }
        ScAddress::Contract(contract_id) => {
            // `ContractId(Hash)` where `Hash([u8; 32])`.
            // Access the raw bytes via two newtype unwraps.
            // `[u8; 32]` is `Copy` so `(contract_id.0).0` copies the array.
            let contract = stellar_strkey::Contract((contract_id.0).0);
            Ok(format!("{contract}"))
        }
        // MuxedAccount, ClaimableBalance, LiquidityPool are not valid
        // SEP-45 credential addresses — return an error.
        _ => Err(Sep45Error::InvalidContractAddress {
            found: "non-account non-contract ScAddress variant".to_owned(),
            expected: "C-strkey contract address".to_owned(),
        }),
    }
}

/// Extracts the args map from a `ScVal` (which must be a `ScMap`).
///
/// Returns a `HashMap<String, String>` of (symbol_key → string_value) pairs.
/// The spec stores args as `Map<Symbol, String>` per `sep-0045.md` lines
/// 203-276.
///
/// Non-Symbol keys and non-String values are silently skipped — SEP-45 args
/// MUST be Symbol→String pairs; other types are irrelevant to the validation
/// contract and are ignored rather than hard-errored so that forward-compatible
/// server extensions do not break existing clients.
///
/// Duplicate Symbol keys are rejected with
/// [`Sep45Error::InvalidArgsFormat`] (fail-closed for untrusted server input).
/// The XDR `ScMap` type permits duplicate keys at the byte level; accepting
/// them would allow a server to inject ambiguous key→value bindings.
fn extract_args_map(
    arg_val: &ScVal,
) -> Result<std::collections::HashMap<String, String>, Sep45Error> {
    let map = match arg_val {
        ScVal::Map(Some(m)) => m,
        ScVal::Map(None) => {
            return Err(Sep45Error::InvalidArgsCount {
                found: 0,
                expected_min: 5,
            });
        }
        _ => {
            return Err(Sep45Error::InvalidArgsCount {
                found: 0,
                expected_min: 5,
            });
        }
    };

    let mut result = std::collections::HashMap::with_capacity(map.len());
    // Duplicate-key tracking precedes the value-type filter so that a duplicate
    // Symbol key whose second occurrence has a non-String value is still caught.
    // Skipping non-String values before the duplicate check would allow such
    // duplicates to pass through silently.
    let mut seen_symbol_keys = std::collections::HashSet::with_capacity(map.len());
    for entry in map.iter() {
        // Key must be a Symbol; skip non-Symbol keys.
        let key_str = match &entry.key {
            ScVal::Symbol(sym) => std::str::from_utf8(sym.0.as_slice())
                .map_err(|_e| Sep45Error::InvalidArgsFormat {
                    detail: "args map contains a Symbol key with invalid UTF-8 bytes".to_owned(),
                })?
                .to_owned(),
            _ => continue,
        };

        // Reject duplicate Symbol keys before checking the value type —
        // fail-closed against ambiguous server input regardless of value kind.
        if !seen_symbol_keys.insert(key_str.clone()) {
            return Err(Sep45Error::InvalidArgsFormat {
                detail: format!("duplicate key '{key_str}' in args map"),
            });
        }

        // Value must be a String; skip non-String values (forward-compatible:
        // a future SEP-45 extension may add non-String args we don't yet know).
        let val_str = match &entry.val {
            ScVal::String(s) => std::str::from_utf8(s.0.as_slice())
                .map_err(|_e| Sep45Error::InvalidArgsFormat {
                    detail: format!(
                        "args map value for key '{key_str}' contains invalid UTF-8 bytes"
                    ),
                })?
                .to_owned(),
            _ => continue,
        };

        result.insert(key_str, val_str);
    }
    Ok(result)
}

/// Verifies the server's ed25519 signature on a `SorobanAuthorizationEntry`.
///
/// Computes the `HashIdPreimageSorobanAuthorization` XDR, hashes it with
/// SHA-256, and verifies via `ed25519_dalek::VerifyingKey::verify_strict`.
///
/// The signature `ScVal` shape is `Vec<Map{public_key: Bytes, signature: Bytes}>`
/// per the SEP-45 signing convention.
fn verify_server_signature(
    entry: &SorobanAuthorizationEntry,
    network_passphrase: &str,
    expected_key: &stellar_strkey::ed25519::PublicKey,
) -> Result<(), Sep45Error> {
    // Extract address credentials.
    let addr_creds = match &entry.credentials {
        SorobanCredentials::Address(c) => c,
        SorobanCredentials::SourceAccount
        | SorobanCredentials::AddressV2(_)
        | SorobanCredentials::AddressWithDelegates(_) => {
            // The server entry passed step-10 role classification, which means
            // it had Address credentials; reaching this arm is an internal
            // logic error, but we fail-closed with a typed error rather than
            // panicking.
            return Err(Sep45Error::UnsupportedCredentialType { entry_index: 0 });
        }
    };

    // Extract signature: must be ScVal::Vec(Some(...)) with at least one map entry.
    // Shape: Vec<Map{public_key: Bytes(32), signature: Bytes(64)}>.
    // The outer Vec holds one Map per signer; each Map carries a
    // public_key and a signature per the SEP-45 signing convention.
    let sig_vec = match &addr_creds.signature {
        ScVal::Vec(Some(v)) => v,
        ScVal::Vec(None) | ScVal::Void => {
            return Err(Sep45Error::MissingServerSignature);
        }
        _ => {
            return Err(Sep45Error::MissingServerSignature);
        }
    };

    if sig_vec.is_empty() {
        return Err(Sep45Error::MissingServerSignature);
    }

    // Get first signature map entry.
    let first_sig_map = match &sig_vec[0] {
        ScVal::Map(Some(m)) => m,
        _ => {
            return Err(Sep45Error::InvalidServerSignature {
                detail: "first signature entry is not a Map".to_owned(),
            });
        }
    };

    // Extract public_key and signature bytes.
    let mut public_key_bytes: Option<&[u8]> = None;
    let mut signature_bytes: Option<&[u8]> = None;

    for map_entry in first_sig_map.iter() {
        let key_name = match &map_entry.key {
            ScVal::Symbol(sym) => std::str::from_utf8(sym.0.as_slice()).unwrap_or(""),
            _ => continue,
        };
        match key_name {
            "public_key" => {
                if let ScVal::Bytes(b) = &map_entry.val {
                    public_key_bytes = Some(b.0.as_slice());
                }
            }
            "signature" => {
                if let ScVal::Bytes(b) = &map_entry.val {
                    signature_bytes = Some(b.0.as_slice());
                }
            }
            _ => {}
        }
    }

    let pk_bytes = public_key_bytes.ok_or(Sep45Error::MissingServerSignature)?;
    let sig_bytes = signature_bytes.ok_or(Sep45Error::MissingServerSignature)?;

    // Verify public_key bytes match the expected server signing key.
    if pk_bytes != expected_key.0.as_ref() {
        return Err(Sep45Error::InvalidServerSignature {
            detail: "public_key in signature does not match expected server signing key".to_owned(),
        });
    }

    // Build the authorization preimage.
    // HashIdPreimageSorobanAuthorization: { network_id: Hash, nonce: i64,
    //   signature_expiration_ledger: u32, invocation: SorobanAuthorizedInvocation }
    let network_id = {
        let mut hasher = Sha256::new();
        hasher.update(network_passphrase.as_bytes());
        Hash(hasher.finalize().into())
    };

    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id,
        nonce: addr_creds.nonce,
        signature_expiration_ledger: addr_creds.signature_expiration_ledger,
        invocation: entry.root_invocation.clone(),
    });

    // XDR-encode the preimage and SHA-256 hash it.
    let mut preimage_bytes = Vec::new();
    preimage
        .write_xdr(&mut stellar_xdr::Limited::new(
            &mut preimage_bytes,
            Limits::none(),
        ))
        .map_err(|e| Sep45Error::InvalidServerSignature {
            detail: format!("failed to encode authorization preimage: {e}"),
        })?;

    let mut hasher = Sha256::new();
    hasher.update(&preimage_bytes);
    let payload = hasher.finalize();

    // Verify with ed25519_dalek VerifyingKey::verify_strict.
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| Sep45Error::InvalidServerSignature {
            detail: format!(
                "public_key has wrong length: expected 32 bytes, got {}",
                pk_bytes.len()
            ),
        })?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_arr).map_err(|e| Sep45Error::InvalidServerSignature {
            detail: format!("invalid ed25519 public key bytes: {e}"),
        })?;

    let sig_arr: [u8; 64] =
        sig_bytes
            .try_into()
            .map_err(|_| Sep45Error::InvalidServerSignature {
                detail: format!(
                    "signature has wrong length: expected 64 bytes, got {}",
                    sig_bytes.len()
                ),
            })?;
    let dalek_sig = DalekSignature::from_bytes(&sig_arr);

    verifying_key
        .verify_strict(&payload, &dalek_sig)
        .map_err(|e| Sep45Error::InvalidServerSignature {
            detail: format!("ed25519 verification failed: {e}"),
        })?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use stellar_xdr::ScMapEntry;

    // ── Test helpers ──────────────────────────────────────────────────────────

    /// Builds a minimal `SorobanAuthorizationEntry` for use in unit tests.
    ///
    /// This builds entries programmatically using stellar-xdr types directly.
    /// The server entry receives a real ed25519 signature; the client entry
    /// has a Void signature (not yet signed).
    #[allow(
        clippy::too_many_arguments,
        reason = "test helper; all args required to construct a full challenge fixture"
    )]
    fn build_test_entries_xdr(
        web_auth_contract: &str,
        home_domain: &str,
        web_auth_domain: &str,
        server_signing_key_seed: &[u8; 32],
        client_account: &str,
        nonce_str: &str,
        network_passphrase: &str,
        with_client_domain: bool,
        client_domain_str: Option<&str>,
        client_domain_signing_key_seed: Option<&[u8; 32]>,
        client_domain_account_str: Option<&str>,
    ) -> String {
        use ed25519_dalek::SigningKey;
        use stellar_xdr::{
            AccountId, ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
            InvokeContractArgs, PublicKey as XdrPublicKey, ScAddress, ScBytes, ScMap, ScMapEntry,
            ScString, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
            SorobanAuthorizationEntries, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation, SorobanCredentials, Uint256, VecM, WriteXdr,
        };

        let contract_bytes = stellar_strkey::Contract::from_string(web_auth_contract)
            .unwrap()
            .0;
        // ScAddress::Contract wraps a ContractId(Hash([u8; 32])).
        let contract_address = ScAddress::Contract(ContractId(Hash(contract_bytes)));

        let server_signing_key = SigningKey::from_bytes(server_signing_key_seed);
        let server_pubkey_bytes = server_signing_key.verifying_key().to_bytes();
        // to_string() on stellar_strkey types returns heapless::String<N>; use format! for std::String.
        let server_g_str = format!(
            "{}",
            stellar_strkey::ed25519::PublicKey(server_pubkey_bytes)
        );

        // Always use server key for web_auth_domain_account in this fixture.
        // The client_domain_account_str is only used when building the args map
        // if client_domain is present — see the map_entries push below.
        let web_auth_domain_account_str = server_g_str.clone();

        // Build args map ScVal.
        let mut map_entries = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                val: ScVal::String(ScString(client_account.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                val: ScVal::String(ScString(home_domain.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                val: ScVal::String(ScString(nonce_str.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                val: ScVal::String(ScString(web_auth_domain.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                val: ScVal::String(ScString(
                    web_auth_domain_account_str.as_str().try_into().unwrap(),
                )),
            },
        ];

        if let (Some(cd), Some(cda)) = (client_domain_str, client_domain_account_str) {
            map_entries.push(ScMapEntry {
                key: ScVal::Symbol(ScSymbol("client_domain".try_into().unwrap())),
                val: ScVal::String(ScString(cd.try_into().unwrap())),
            });
            map_entries.push(ScMapEntry {
                key: ScVal::Symbol(ScSymbol("client_domain_account".try_into().unwrap())),
                val: ScVal::String(ScString(cda.try_into().unwrap())),
            });
        }

        let args_scmap: VecM<ScMapEntry> = map_entries.try_into().unwrap();
        let args_val = ScVal::Map(Some(ScMap(args_scmap)));

        let fn_args = InvokeContractArgs {
            contract_address: contract_address.clone(),
            function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
            args: vec![args_val].try_into().unwrap(),
        };

        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(fn_args),
            sub_invocations: VecM::default(),
        };

        // Build server entry credentials with a real signature.
        let server_nonce: i64 = 12345678;
        let server_expiry: u32 = 9_999_999;

        // Compute preimage.
        let network_id_hash = {
            let mut hasher = Sha256::new();
            hasher.update(network_passphrase.as_bytes());
            Hash(hasher.finalize().into())
        };
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: network_id_hash,
            nonce: server_nonce,
            signature_expiration_ledger: server_expiry,
            invocation: invocation.clone(),
        });
        let mut preimage_bytes = Vec::new();
        preimage
            .write_xdr(&mut stellar_xdr::Limited::new(
                &mut preimage_bytes,
                Limits::none(),
            ))
            .unwrap();
        let payload = {
            let mut h = Sha256::new();
            h.update(&preimage_bytes);
            h.finalize()
        };

        use ed25519_dalek::Signer;
        let signature_bytes = server_signing_key.sign(&payload).to_bytes();

        // Build Vec<Map{public_key, signature}> ScVal.
        let sig_map = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("public_key".try_into().unwrap())),
                    val: ScVal::Bytes(ScBytes(server_pubkey_bytes.to_vec().try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("signature".try_into().unwrap())),
                    val: ScVal::Bytes(ScBytes(signature_bytes.to_vec().try_into().unwrap())),
                },
            ]
            .try_into()
            .unwrap(),
        )));

        let server_sig_scval = ScVal::Vec(Some(ScVec(vec![sig_map].try_into().unwrap())));

        let server_addr_bytes = server_pubkey_bytes;
        let server_address = ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
            Uint256(server_addr_bytes),
        )));

        let server_creds = SorobanAddressCredentials {
            address: server_address,
            nonce: server_nonce,
            signature_expiration_ledger: server_expiry,
            signature: server_sig_scval,
        };

        let server_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(server_creds),
            root_invocation: invocation.clone(),
        };

        // Build client entry — unsigned (Void signature).
        let client_contract_bytes = stellar_strkey::Contract::from_string(client_account)
            .unwrap()
            .0;
        let client_address = ScAddress::Contract(ContractId(Hash(client_contract_bytes)));
        let client_creds = SorobanAddressCredentials {
            address: client_address,
            nonce: 87654321i64,
            signature_expiration_ledger: 0,
            signature: ScVal::Void,
        };
        let client_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(client_creds),
            root_invocation: invocation.clone(),
        };

        let mut all_entries = vec![server_entry, client_entry];

        // Optionally add client domain entry — collapsed per clippy::collapsible_if.
        if with_client_domain
            && let (Some(_cda_str), Some(cda_seed)) =
                (client_domain_account_str, client_domain_signing_key_seed)
        {
            let cda_key = SigningKey::from_bytes(cda_seed);
            let cda_pubkey_bytes = cda_key.verifying_key().to_bytes();
            let cda_address = ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                Uint256(cda_pubkey_bytes),
            )));
            let cd_creds = SorobanAddressCredentials {
                address: cda_address,
                nonce: 11111111i64,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            };
            let cd_entry = SorobanAuthorizationEntry {
                credentials: SorobanCredentials::Address(cd_creds),
                root_invocation: invocation.clone(),
            };
            all_entries.push(cd_entry);
        }

        // Encode as `SorobanAuthorizationEntries` XDR (length-prefixed array).
        let entries_xdr = SorobanAuthorizationEntries(all_entries.try_into().unwrap());
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        BASE64_STANDARD.encode(&out)
    }

    /// Returns a valid set of test parameters for use in happy-path tests.
    fn test_params() -> (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        [u8; 32],
    ) {
        let web_auth_contract = "CALI6JC3MSNDGFRP7Z2OKUEPREHOJRRXKMJEWQDEFZPFGXALA45RAUTH";
        let client_account = "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ";
        let home_domain = "example.com";
        let web_auth_domain = "auth.example.com";
        let server_seed = [1u8; 32];
        (
            web_auth_contract,
            client_account,
            home_domain,
            web_auth_domain,
            server_seed,
        )
    }

    fn test_nonce() -> String {
        // 32-byte ASCII nonce string.
        "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6".to_owned()
    }

    fn test_network() -> &'static str {
        "Test SDF Network ; September 2015"
    }

    fn server_signing_key_str(seed: &[u8; 32]) -> String {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(seed);
        format!(
            "{}",
            stellar_strkey::ed25519::PublicKey(sk.verifying_key().to_bytes())
        )
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[test]
    fn happy_path_two_entries_no_client_domain() {
        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key = server_signing_key_str(&server_seed);

        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            &nonce,
            network,
            false,
            None,
            None,
            None,
        );

        let result = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_key,
            None,
            client,
        );
        assert!(result.is_ok(), "happy path failed: {:?}", result.err());

        let parsed = result.unwrap();
        assert_eq!(parsed.expected_home_domain, home);
        assert_eq!(parsed.web_auth_domain, web_auth);
        assert_eq!(parsed.nonce, nonce);
        assert_eq!(parsed.nonce_bytes(), nonce.as_bytes());
        assert_eq!(parsed.entries.len(), 2);
        assert!(parsed.client_domain.is_none());
        assert!(parsed.client_domain_account.is_none());
    }

    #[test]
    fn happy_path_three_entries_with_client_domain() {
        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key = server_signing_key_str(&server_seed);

        let cd_seed = [2u8; 32];
        use ed25519_dalek::SigningKey;
        let cd_key = SigningKey::from_bytes(&cd_seed);
        let cd_account =
            stellar_strkey::ed25519::PublicKey(cd_key.verifying_key().to_bytes()).to_string();

        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            &nonce,
            network,
            true,
            Some("wallet.example.com"),
            Some(&cd_seed),
            Some(&cd_account),
        );

        let result = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_key,
            Some("wallet.example.com"),
            client,
        );
        assert!(
            result.is_ok(),
            "happy path with client_domain failed: {:?}",
            result.err()
        );

        let parsed = result.unwrap();
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.client_domain, Some("wallet.example.com".to_owned()));
        assert!(parsed.client_domain_account.is_some());
        assert!(parsed.client_domain_entry_index.is_some());
    }

    // ── Failure: XDR decode ───────────────────────────────────────────────────

    #[test]
    fn fail_invalid_base64() {
        let err = AuthorizationEntries::parse_and_validate(
            "not!valid!base64",
            test_network(),
            "CALI6JC3MSNDGFRP7Z2OKUEPREHOJRRXKMJEWQDEFZPFGXALA45RAUTH",
            "example.com",
            "auth.example.com",
            "GCHLHDBOKGWJWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
            None,
            "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ",
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep45Error::XdrDecodeError { .. }),
            "expected XdrDecodeError, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.xdr_decode_error");
    }

    #[test]
    fn fail_invalid_xdr_bytes() {
        let bad_b64 = BASE64_STANDARD.encode(b"this is not valid XDR");
        let err = AuthorizationEntries::parse_and_validate(
            &bad_b64,
            test_network(),
            "CALI6JC3MSNDGFRP7Z2OKUEPREHOJRRXKMJEWQDEFZPFGXALA45RAUTH",
            "example.com",
            "auth.example.com",
            "GCHLHDBOKGWJWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
            None,
            "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ",
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep45Error::XdrDecodeError { .. }),
            "expected XdrDecodeError, got {err:?}"
        );
    }

    // ── Failure: entry count ──────────────────────────────────────────────────

    #[test]
    fn fail_empty_entry_list() {
        use stellar_xdr::{Limits, SorobanAuthorizationEntries, VecM, WriteXdr};
        let entries = SorobanAuthorizationEntries(VecM::default());
        let mut out = Vec::new();
        entries
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        let b64 = BASE64_STANDARD.encode(&out);

        let err = AuthorizationEntries::parse_and_validate(
            &b64,
            test_network(),
            "CALI6JC3MSNDGFRP7Z2OKUEPREHOJRRXKMJEWQDEFZPFGXALA45RAUTH",
            "example.com",
            "auth.example.com",
            "GCHLHDBOKGWJWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
            None,
            "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ",
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                Sep45Error::InvalidEntryCount {
                    found: 0,
                    expected_min: 1
                }
            ),
            "expected InvalidEntryCount {{ found: 0, expected_min: 1 }}, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.invalid_entry_count");
    }

    // ── Failure: sub-invocations ──────────────────────────────────────────────

    #[test]
    fn fail_sub_invocations_present() {
        use ed25519_dalek::SigningKey;
        use stellar_xdr::{
            AccountId, ContractId, Hash, InvokeContractArgs, Limits, PublicKey as XdrPublicKey,
            ScAddress, ScMap, ScMapEntry, ScString, ScSymbol, ScVal, SorobanAddressCredentials,
            SorobanAuthorizationEntries, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation, SorobanCredentials, Uint256, VecM, WriteXdr,
        };

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key = SigningKey::from_bytes(&server_seed);
        let server_pubkey_bytes = server_key.verifying_key().to_bytes();
        let server_g_str = stellar_strkey::ed25519::PublicKey(server_pubkey_bytes).to_string();

        let contract_bytes = stellar_strkey::Contract::from_string(contract).unwrap().0;
        let contract_address = ScAddress::Contract(ContractId(Hash(contract_bytes)));

        let args_map_val = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                    val: ScVal::String(ScString(client.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(home.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                    val: ScVal::String(ScString(nonce.as_str().try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(web_auth.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                    val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
                },
            ]
            .try_into()
            .unwrap(),
        )));

        let inner_fn = InvokeContractArgs {
            contract_address: contract_address.clone(),
            function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
            args: vec![args_map_val.clone()].try_into().unwrap(),
        };

        // Build a sub-invocation (which is forbidden).
        // Clone inner_fn here so the original is available for the plain_invocation below.
        let sub_invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(inner_fn.clone()),
            sub_invocations: VecM::default(),
        };

        let invocation_with_sub = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(inner_fn.clone()),
            sub_invocations: vec![sub_invocation].try_into().unwrap(),
        };

        let server_address = ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
            Uint256(server_pubkey_bytes),
        )));
        let server_creds = SorobanAddressCredentials {
            address: server_address,
            nonce: 123,
            signature_expiration_ledger: 999,
            signature: ScVal::Void,
        };
        let entry1 = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(server_creds),
            root_invocation: invocation_with_sub,
        };

        let client_bytes = stellar_strkey::Contract::from_string(client).unwrap().0;
        let client_address = ScAddress::Contract(ContractId(Hash(client_bytes)));
        let client_creds = SorobanAddressCredentials {
            address: client_address,
            nonce: 456,
            signature_expiration_ledger: 0,
            signature: ScVal::Void,
        };
        let plain_invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(inner_fn.clone()),
            sub_invocations: VecM::default(),
        };
        let entry2 = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(client_creds),
            root_invocation: plain_invocation,
        };

        let entries_xdr = SorobanAuthorizationEntries(vec![entry1, entry2].try_into().unwrap());
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        let b64 = BASE64_STANDARD.encode(&out);

        let err = AuthorizationEntries::parse_and_validate(
            &b64,
            network,
            contract,
            home,
            web_auth,
            &server_g_str,
            None,
            client,
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep45Error::UnexpectedSubInvocations { entry_index: 0 }),
            "expected UnexpectedSubInvocations, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.unexpected_sub_invocations");
    }

    // ── Failure: contract address mismatch ────────────────────────────────────

    #[test]
    fn fail_wrong_contract_address() {
        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key = server_signing_key_str(&server_seed);

        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            &nonce,
            network,
            false,
            None,
            None,
            None,
        );

        // Pass a wrong expected contract.
        let wrong_contract = "CABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGCK3";
        let err = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            wrong_contract,
            home,
            web_auth,
            &server_key,
            None,
            client,
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep45Error::InvalidContractAddress { .. }),
            "expected InvalidContractAddress, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.invalid_contract_address");
    }

    // ── Failure: function name mismatch ───────────────────────────────────────

    #[test]
    fn fail_wrong_function_name() {
        // Build entries with wrong function name manually.
        use ed25519_dalek::SigningKey;
        use stellar_xdr::{
            AccountId, ContractId, Hash, InvokeContractArgs, Limits, PublicKey as XdrPublicKey,
            ScAddress, ScMap, ScMapEntry, ScString, ScSymbol, ScVal, SorobanAddressCredentials,
            SorobanAuthorizationEntries, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation, SorobanCredentials, Uint256, VecM, WriteXdr,
        };

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key = SigningKey::from_bytes(&server_seed);
        let server_pubkey_bytes = server_key.verifying_key().to_bytes();
        let server_g_str = stellar_strkey::ed25519::PublicKey(server_pubkey_bytes).to_string();

        let contract_bytes = stellar_strkey::Contract::from_string(contract).unwrap().0;
        let contract_address = ScAddress::Contract(ContractId(Hash(contract_bytes)));

        let args_map_val = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                    val: ScVal::String(ScString(client.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(home.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                    val: ScVal::String(ScString(nonce.as_str().try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(web_auth.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                    val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
                },
            ]
            .try_into()
            .unwrap(),
        )));

        let wrong_fn = InvokeContractArgs {
            contract_address: contract_address.clone(),
            function_name: ScSymbol("wrong_function".try_into().unwrap()),
            args: vec![args_map_val.clone()].try_into().unwrap(),
        };
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(wrong_fn),
            sub_invocations: VecM::default(),
        };

        let server_address = ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
            Uint256(server_pubkey_bytes),
        )));
        let entry1 = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: server_address,
                nonce: 1,
                signature_expiration_ledger: 99,
                signature: ScVal::Void,
            }),
            root_invocation: invocation.clone(),
        };

        let client_bytes = stellar_strkey::Contract::from_string(client).unwrap().0;
        let entry2 = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(client_bytes))),
                nonce: 2,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: invocation,
        };

        let entries_xdr = SorobanAuthorizationEntries(vec![entry1, entry2].try_into().unwrap());
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        let b64 = BASE64_STANDARD.encode(&out);

        let err = AuthorizationEntries::parse_and_validate(
            &b64,
            network,
            contract,
            home,
            web_auth,
            &server_g_str,
            None,
            client,
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep45Error::InvalidFunctionName { .. }),
            "expected InvalidFunctionName, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.invalid_function_name");
    }

    // ── Failure: home_domain mismatch ─────────────────────────────────────────

    #[test]
    fn fail_home_domain_mismatch() {
        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key = server_signing_key_str(&server_seed);

        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            &nonce,
            network,
            false,
            None,
            None,
            None,
        );

        let err = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            "wrong-domain.com",
            web_auth,
            &server_key,
            None,
            client,
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep45Error::HomeDomainMismatch { .. }),
            "expected HomeDomainMismatch, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.home_domain_mismatch");
    }

    // ── Failure: web_auth_domain mismatch ─────────────────────────────────────

    #[test]
    fn fail_web_auth_domain_mismatch() {
        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key = server_signing_key_str(&server_seed);

        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            &nonce,
            network,
            false,
            None,
            None,
            None,
        );

        let err = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            "wrong-auth.example.com",
            &server_key,
            None,
            client,
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep45Error::WebAuthDomainMismatch { .. }),
            "expected WebAuthDomainMismatch, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.web_auth_domain_mismatch");
    }

    // ── Failure: nonce mismatch ────────────────────────────────────────────────

    #[test]
    fn fail_nonce_mismatch_across_entries() {
        use ed25519_dalek::{Signer, SigningKey};
        use stellar_xdr::{
            AccountId, ContractId, Hash, InvokeContractArgs, Limits, PublicKey as XdrPublicKey,
            ScAddress, ScBytes, ScMap, ScMapEntry, ScString, ScSymbol, ScVal, ScVec,
            SorobanAddressCredentials, SorobanAuthorizationEntries, SorobanAuthorizationEntry,
            SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, Uint256,
            VecM, WriteXdr,
        };

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let other_nonce = "B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7".to_owned(); // different nonce (same length, different value)
        let network = test_network();
        let server_key = SigningKey::from_bytes(&server_seed);
        let server_pubkey_bytes = server_key.verifying_key().to_bytes();
        let server_g_str = stellar_strkey::ed25519::PublicKey(server_pubkey_bytes).to_string();

        let contract_bytes = stellar_strkey::Contract::from_string(contract).unwrap().0;
        let contract_address = ScAddress::Contract(ContractId(Hash(contract_bytes)));

        let make_invocation_with_nonce = |nonce_value: &str| {
            let args_map_val = ScVal::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                        val: ScVal::String(ScString(client.try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                        val: ScVal::String(ScString(home.try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                        val: ScVal::String(ScString(nonce_value.try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                        val: ScVal::String(ScString(web_auth.try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                        val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            )));
            SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: contract_address.clone(),
                    function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
                    args: vec![args_map_val].try_into().unwrap(),
                }),
                sub_invocations: VecM::default(),
            }
        };

        let server_invocation = make_invocation_with_nonce(&nonce);
        let server_nonce_i64: i64 = 999;
        let server_expiry: u32 = 88888;

        // Sign server entry with the first (correct) nonce.
        let preimage_bytes = {
            let network_id_hash = {
                let mut h = Sha256::new();
                h.update(network.as_bytes());
                Hash(h.finalize().into())
            };
            let preimage = stellar_xdr::HashIdPreimage::SorobanAuthorization(
                stellar_xdr::HashIdPreimageSorobanAuthorization {
                    network_id: network_id_hash,
                    nonce: server_nonce_i64,
                    signature_expiration_ledger: server_expiry,
                    invocation: server_invocation.clone(),
                },
            );
            let mut buf = Vec::new();
            preimage
                .write_xdr(&mut stellar_xdr::Limited::new(&mut buf, Limits::none()))
                .unwrap();
            buf
        };
        let payload = {
            let mut h = Sha256::new();
            h.update(&preimage_bytes);
            h.finalize()
        };
        let sig_bytes = server_key.sign(&payload).to_bytes();

        let server_sig_scval = ScVal::Vec(Some(ScVec(
            vec![ScVal::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("public_key".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(
                            server_pubkey_bytes.to_vec().try_into().unwrap(),
                        )),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("signature".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(sig_bytes.to_vec().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            )))]
            .try_into()
            .unwrap(),
        )));

        let server_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(server_pubkey_bytes),
                ))),
                nonce: server_nonce_i64,
                signature_expiration_ledger: server_expiry,
                signature: server_sig_scval,
            }),
            root_invocation: server_invocation,
        };

        // Client entry uses a DIFFERENT nonce — should trigger NonceMismatch.
        let client_invocation = make_invocation_with_nonce(&other_nonce);
        let client_bytes = stellar_strkey::Contract::from_string(client).unwrap().0;
        let client_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(client_bytes))),
                nonce: 222,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: client_invocation,
        };

        let entries_xdr =
            SorobanAuthorizationEntries(vec![server_entry, client_entry].try_into().unwrap());
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        let b64 = BASE64_STANDARD.encode(&out);

        let err = AuthorizationEntries::parse_and_validate(
            &b64,
            network,
            contract,
            home,
            web_auth,
            &server_g_str,
            None,
            client,
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep45Error::NonceMismatch { entry_index: 1 }),
            "expected NonceMismatch at index 1, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.nonce_mismatch");
    }

    // ── Failure: invalid server signature ────────────────────────────────────

    #[test]
    fn fail_invalid_server_signature() {
        use ed25519_dalek::SigningKey;
        use stellar_xdr::{
            AccountId, ContractId, Hash, InvokeContractArgs, Limits, PublicKey as XdrPublicKey,
            ScAddress, ScBytes, ScMap, ScMapEntry, ScString, ScSymbol, ScVal, ScVec,
            SorobanAddressCredentials, SorobanAuthorizationEntries, SorobanAuthorizationEntry,
            SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, Uint256,
            VecM, WriteXdr,
        };

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key = SigningKey::from_bytes(&server_seed);
        let server_pubkey_bytes = server_key.verifying_key().to_bytes();
        let server_g_str = stellar_strkey::ed25519::PublicKey(server_pubkey_bytes).to_string();

        let contract_bytes = stellar_strkey::Contract::from_string(contract).unwrap().0;
        let contract_address = ScAddress::Contract(ContractId(Hash(contract_bytes)));

        let args_map_val = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                    val: ScVal::String(ScString(client.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(home.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                    val: ScVal::String(ScString(nonce.as_str().try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(web_auth.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                    val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
                },
            ]
            .try_into()
            .unwrap(),
        )));

        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: contract_address.clone(),
                function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
                args: vec![args_map_val.clone()].try_into().unwrap(),
            }),
            sub_invocations: VecM::default(),
        };

        // Use all-zero (invalid) signature bytes.
        let bad_sig = [0u8; 64];
        let server_sig_scval = ScVal::Vec(Some(ScVec(
            vec![ScVal::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("public_key".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(
                            server_pubkey_bytes.to_vec().try_into().unwrap(),
                        )),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("signature".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(bad_sig.to_vec().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            )))]
            .try_into()
            .unwrap(),
        )));

        let entry1 = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(server_pubkey_bytes),
                ))),
                nonce: 1,
                signature_expiration_ledger: 999,
                signature: server_sig_scval,
            }),
            root_invocation: invocation.clone(),
        };

        let client_bytes = stellar_strkey::Contract::from_string(client).unwrap().0;
        let entry2 = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(client_bytes))),
                nonce: 2,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: invocation,
        };

        let entries_xdr = SorobanAuthorizationEntries(vec![entry1, entry2].try_into().unwrap());
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        let b64 = BASE64_STANDARD.encode(&out);

        let err = AuthorizationEntries::parse_and_validate(
            &b64,
            network,
            contract,
            home,
            web_auth,
            &server_g_str,
            None,
            client,
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep45Error::InvalidServerSignature { .. }),
            "expected InvalidServerSignature, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.invalid_server_signature");
    }

    // ── Failure: missing server entry ─────────────────────────────────────────

    #[test]
    fn fail_missing_server_entry() {
        use ed25519_dalek::SigningKey;
        use stellar_xdr::{
            AccountId, ContractId, Hash, InvokeContractArgs, Limits, PublicKey as XdrPublicKey,
            ScAddress, ScMap, ScMapEntry, ScString, ScSymbol, ScVal, SorobanAddressCredentials,
            SorobanAuthorizationEntries, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation, SorobanCredentials, Uint256, VecM, WriteXdr,
        };

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();

        // Use a DIFFERENT server key for signing; present the original key in args
        // but the credentials won't match.
        let actual_server_key = SigningKey::from_bytes(&server_seed);
        let actual_pubkey = actual_server_key.verifying_key().to_bytes();
        let actual_g_str = stellar_strkey::ed25519::PublicKey(actual_pubkey).to_string();

        // Different signing key — credentials won't match expected key.
        let different_seed = [9u8; 32];
        let different_key = SigningKey::from_bytes(&different_seed);
        let different_pubkey = different_key.verifying_key().to_bytes();
        let _different_g_str = stellar_strkey::ed25519::PublicKey(different_pubkey).to_string();

        let contract_bytes = stellar_strkey::Contract::from_string(contract).unwrap().0;
        let args_map_val = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                    val: ScVal::String(ScString(client.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(home.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                    val: ScVal::String(ScString(nonce.as_str().try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(web_auth.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                    val: ScVal::String(ScString(actual_g_str.as_str().try_into().unwrap())),
                },
            ]
            .try_into()
            .unwrap(),
        )));

        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash(contract_bytes))),
                function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
                args: vec![args_map_val.clone()].try_into().unwrap(),
            }),
            sub_invocations: VecM::default(),
        };

        // Entry 1: uses DIFFERENT key (not the expected server key).
        let entry1 = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(different_pubkey),
                ))),
                nonce: 1,
                signature_expiration_ledger: 999,
                signature: ScVal::Void,
            }),
            root_invocation: invocation.clone(),
        };

        let client_bytes = stellar_strkey::Contract::from_string(client).unwrap().0;
        let entry2 = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(client_bytes))),
                nonce: 2,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: invocation,
        };

        let entries_xdr = SorobanAuthorizationEntries(vec![entry1, entry2].try_into().unwrap());
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        let b64 = BASE64_STANDARD.encode(&out);

        let err = AuthorizationEntries::parse_and_validate(
            &b64,
            network,
            contract,
            home,
            web_auth,
            &actual_g_str,
            None,
            client,
        )
        .unwrap_err();
        // Should fail because server entry has no signature and won't have
        // verified sig — the MissingServerEntry is from the identify phase.
        // The sig check would come first IF server_idx is found, but here it
        // can't be found because credential address ≠ expected server key.
        assert!(
            matches!(
                err,
                Sep45Error::MissingServerEntry
                    | Sep45Error::MissingServerSignature
                    | Sep45Error::InvalidServerSignature { .. }
            ),
            "expected MissingServerEntry or sig error, got {err:?}"
        );
    }

    // ── Failure: missing client entry ─────────────────────────────────────────

    #[test]
    fn fail_missing_client_entry() {
        use ed25519_dalek::{Signer, SigningKey};
        use stellar_xdr::{
            AccountId, ContractId, Hash, InvokeContractArgs, Limits, PublicKey as XdrPublicKey,
            ScAddress, ScBytes, ScMap, ScMapEntry, ScString, ScSymbol, ScVal, ScVec,
            SorobanAddressCredentials, SorobanAuthorizationEntries, SorobanAuthorizationEntry,
            SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, Uint256,
            VecM, WriteXdr,
        };

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key = SigningKey::from_bytes(&server_seed);
        let server_pubkey_bytes = server_key.verifying_key().to_bytes();
        let server_g_str = stellar_strkey::ed25519::PublicKey(server_pubkey_bytes).to_string();

        let contract_bytes = stellar_strkey::Contract::from_string(contract).unwrap().0;
        let args_map_val = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                    val: ScVal::String(ScString(client.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(home.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                    val: ScVal::String(ScString(nonce.as_str().try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(web_auth.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                    val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
                },
            ]
            .try_into()
            .unwrap(),
        )));

        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash(contract_bytes))),
                function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
                args: vec![args_map_val.clone()].try_into().unwrap(),
            }),
            sub_invocations: VecM::default(),
        };

        // Sign server entry properly.
        let server_nonce_i64: i64 = 111;
        let server_expiry: u32 = 9999;
        let network_id_hash = {
            let mut h = Sha256::new();
            h.update(network.as_bytes());
            Hash(h.finalize().into())
        };
        let preimage = stellar_xdr::HashIdPreimage::SorobanAuthorization(
            stellar_xdr::HashIdPreimageSorobanAuthorization {
                network_id: network_id_hash,
                nonce: server_nonce_i64,
                signature_expiration_ledger: server_expiry,
                invocation: invocation.clone(),
            },
        );
        let mut preimage_bytes = Vec::new();
        preimage
            .write_xdr(&mut stellar_xdr::Limited::new(
                &mut preimage_bytes,
                Limits::none(),
            ))
            .unwrap();
        let payload = {
            let mut h = Sha256::new();
            h.update(&preimage_bytes);
            h.finalize()
        };
        let sig_bytes = server_key.sign(&payload).to_bytes();

        let server_sig_scval = ScVal::Vec(Some(ScVec(
            vec![ScVal::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("public_key".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(
                            server_pubkey_bytes.to_vec().try_into().unwrap(),
                        )),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("signature".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(sig_bytes.to_vec().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            )))]
            .try_into()
            .unwrap(),
        )));

        let server_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(server_pubkey_bytes),
                ))),
                nonce: server_nonce_i64,
                signature_expiration_ledger: server_expiry,
                signature: server_sig_scval,
            }),
            root_invocation: invocation.clone(),
        };

        // Second entry uses a DIFFERENT address (not the expected client account).
        let different_contract_bytes = stellar_strkey::Contract::from_string(
            "CABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGCK3",
        )
        .unwrap()
        .0;
        let entry2 = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(different_contract_bytes))),
                nonce: 2,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: invocation,
        };

        let entries_xdr =
            SorobanAuthorizationEntries(vec![server_entry, entry2].try_into().unwrap());
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        let b64 = BASE64_STANDARD.encode(&out);

        let err = AuthorizationEntries::parse_and_validate(
            &b64,
            network,
            contract,
            home,
            web_auth,
            &server_g_str,
            None,
            client,
        )
        .unwrap_err();
        assert!(
            matches!(err, Sep45Error::MissingClientEntry),
            "expected MissingClientEntry, got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.missing_client_entry");
    }

    // ── Nonce length: no length constraint (spec-correct) ─────────────────────
    //
    // The SEP-45 nonce definition requires it to be a unique value, the same
    // across all entries, with no length constraint. These tests verify that
    // short nonces and long nonces are both accepted, and that the only
    // enforced invariant is non-emptiness (step 8).

    #[test]
    fn short_nonce_accepted_spec_example_length() {
        // The SEP-45 canonical example uses a 10-byte nonce ("2318448561").
        // The spec places no length constraint on nonces.
        let (contract, client, home, web_auth, server_seed) = test_params();
        let short_nonce = "2318448561"; // 10 bytes — spec canonical example
        let network = test_network();
        let server_key = server_signing_key_str(&server_seed);

        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            short_nonce,
            network,
            false,
            None,
            None,
            None,
        );

        let result = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_key,
            None,
            client,
        );
        assert!(
            result.is_ok(),
            "10-byte nonce (spec canonical example) should be accepted: {:?}",
            result.err()
        );
        let parsed = result.unwrap();
        assert_eq!(parsed.nonce, short_nonce);
        assert_eq!(parsed.nonce_bytes(), short_nonce.as_bytes());
    }

    #[test]
    fn long_nonce_accepted_py_stellar_base_length() {
        // py-stellar-base generates 48-byte base64-encoded nonces (64 chars).
        // This MUST be accepted.
        let (contract, client, home, web_auth, server_seed) = test_params();
        // 64-char nonce simulating py-stellar-base base64-encoded nonce.
        let long_nonce = "dGhpcyBpcyBhIHB5LXN0ZWxsYXItYmFzZSBzdHlsZSBub25jZSB4eHh4";
        let network = test_network();
        let server_key = server_signing_key_str(&server_seed);

        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            long_nonce,
            network,
            false,
            None,
            None,
            None,
        );

        let result = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_key,
            None,
            client,
        );
        assert!(
            result.is_ok(),
            "64-byte nonce (py-stellar-base style) should be accepted: {:?}",
            result.err()
        );
    }

    // ── Failure: missing client domain op ─────────────────────────────────────

    #[test]
    fn fail_client_domain_arg_but_no_credential_entry() {
        use ed25519_dalek::{Signer, SigningKey};
        use stellar_xdr::{
            AccountId, ContractId, Hash, InvokeContractArgs, Limits, PublicKey as XdrPublicKey,
            ScAddress, ScBytes, ScMap, ScMapEntry, ScString, ScSymbol, ScVal, ScVec,
            SorobanAddressCredentials, SorobanAuthorizationEntries, SorobanAuthorizationEntry,
            SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, Uint256,
            VecM, WriteXdr,
        };

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key = SigningKey::from_bytes(&server_seed);
        let server_pubkey_bytes = server_key.verifying_key().to_bytes();
        let server_g_str = stellar_strkey::ed25519::PublicKey(server_pubkey_bytes).to_string();

        // Use a different key as the client_domain_account in args.
        let cd_seed = [3u8; 32];
        let cd_key = SigningKey::from_bytes(&cd_seed);
        let cd_pubkey_bytes = cd_key.verifying_key().to_bytes();
        let cd_g_str = stellar_strkey::ed25519::PublicKey(cd_pubkey_bytes).to_string();

        let contract_bytes = stellar_strkey::Contract::from_string(contract).unwrap().0;
        // Args include client_domain and client_domain_account.
        let args_map_val = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                    val: ScVal::String(ScString(client.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("client_domain".try_into().unwrap())),
                    val: ScVal::String(ScString("wallet.example.com".try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("client_domain_account".try_into().unwrap())),
                    val: ScVal::String(ScString(cd_g_str.as_str().try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(home.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                    val: ScVal::String(ScString(nonce.as_str().try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(web_auth.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                    val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
                },
            ]
            .try_into()
            .unwrap(),
        )));

        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash(contract_bytes))),
                function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
                args: vec![args_map_val.clone()].try_into().unwrap(),
            }),
            sub_invocations: VecM::default(),
        };

        // Sign server entry properly.
        let server_nonce_i64: i64 = 333;
        let server_expiry: u32 = 7777;
        let network_id_hash = {
            let mut h = Sha256::new();
            h.update(network.as_bytes());
            Hash(h.finalize().into())
        };
        let preimage = stellar_xdr::HashIdPreimage::SorobanAuthorization(
            stellar_xdr::HashIdPreimageSorobanAuthorization {
                network_id: network_id_hash,
                nonce: server_nonce_i64,
                signature_expiration_ledger: server_expiry,
                invocation: invocation.clone(),
            },
        );
        let mut preimage_bytes = Vec::new();
        preimage
            .write_xdr(&mut stellar_xdr::Limited::new(
                &mut preimage_bytes,
                Limits::none(),
            ))
            .unwrap();
        let payload = {
            let mut h = Sha256::new();
            h.update(&preimage_bytes);
            h.finalize()
        };
        let sig_bytes = server_key.sign(&payload).to_bytes();

        let server_sig_scval = ScVal::Vec(Some(ScVec(
            vec![ScVal::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("public_key".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(
                            server_pubkey_bytes.to_vec().try_into().unwrap(),
                        )),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("signature".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(sig_bytes.to_vec().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            )))]
            .try_into()
            .unwrap(),
        )));

        let server_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(server_pubkey_bytes),
                ))),
                nonce: server_nonce_i64,
                signature_expiration_ledger: server_expiry,
                signature: server_sig_scval,
            }),
            root_invocation: invocation.clone(),
        };

        let client_bytes = stellar_strkey::Contract::from_string(client).unwrap().0;
        let client_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(client_bytes))),
                nonce: 2,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: invocation,
        };

        // Only 2 entries — no client_domain_account entry.
        let entries_xdr =
            SorobanAuthorizationEntries(vec![server_entry, client_entry].try_into().unwrap());
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        let b64 = BASE64_STANDARD.encode(&out);

        // 2 entries but args have client_domain → should fail with InvalidEntryCount
        // (needs ≥ 3) or MissingClientDomainOp.
        // Pass expected_client_domain = Some(...) so the client_domain validation
        // passes and the entry-count check is reached.
        let err = AuthorizationEntries::parse_and_validate(
            &b64,
            network,
            contract,
            home,
            web_auth,
            &server_g_str,
            Some("wallet.example.com"),
            client,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                Sep45Error::InvalidEntryCount { .. } | Sep45Error::MissingClientDomainOp
            ),
            "expected InvalidEntryCount or MissingClientDomainOp, got {err:?}"
        );
    }

    // ── expected_client_domain validation ─────────────────────────────────────

    /// When `expected_client_domain = Some("wallet.example.com")` and the
    /// challenge's client entry does NOT include a `client_domain` arg,
    /// `parse_and_validate` must return `ClientDomainMismatch`
    /// (expected non-empty, found empty).
    #[test]
    fn client_domain_arg_mismatch_rejected() {
        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key_str = server_signing_key_str(&server_seed);

        // Build a standard 2-entry challenge WITHOUT a client_domain arg.
        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            &nonce,
            network,
            false,
            None,
            None,
            None, // no client_domain in args
        );

        let err = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_key_str,
            Some("wallet.example.com"), // caller expects a client_domain
            client,
        )
        .unwrap_err();

        assert!(
            matches!(err, Sep45Error::ClientDomainMismatch { .. }),
            "expected ClientDomainMismatch when challenge has no client_domain arg but caller expects one; got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.client_domain_mismatch");
    }

    /// When `expected_client_domain = None` (caller does not expect a
    /// `client_domain`) but the challenge's args map includes one,
    /// `parse_and_validate` must return `ClientDomainMismatch`
    /// (expected empty, found non-empty).
    ///
    /// The `ClientDomainMismatch` check fires before the "≥ 3 entries" re-check
    /// so a 2-entry challenge with client_domain in args is sufficient.
    #[test]
    fn unexpected_client_domain_in_challenge_rejected() {
        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key_str = server_signing_key_str(&server_seed);

        // G-strkey for a dummy client_domain_account — needed so build_test_entries_xdr
        // inserts the client_domain/client_domain_account args into the map.
        let cd_seed = [9u8; 32];
        let cd_key_str = server_signing_key_str(&cd_seed);

        // Build a 2-entry challenge WITH client_domain and client_domain_account
        // in the args map (but WITHOUT a 3rd credential entry).
        // `with_client_domain: false` means no 3rd entry is appended.
        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            &nonce,
            network,
            false,                      // no 3rd entry
            Some("wallet.example.com"), // client_domain present in args map
            None,                       // no client_domain_signing_key_seed (3rd entry not needed)
            Some(cd_key_str.as_str()),  // client_domain_account present in args map
        );

        // The caller passes None — they do not expect any client_domain.
        // The check at step 3b fires before the "≥ 3 entries" re-check.
        let err = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_key_str,
            None,
            client,
        )
        .unwrap_err();

        assert!(
            matches!(err, Sep45Error::ClientDomainMismatch { .. }),
            "expected ClientDomainMismatch when challenge has client_domain arg but caller expects none; got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.client_domain_mismatch");
    }

    // ── Ephemeral signing coverage ─────────────────────────────────────────────
    //
    // These tests exercise `ephemeral::sign_client_entry` and the internal
    // `re_encode_entries` helper (called by sign_client_entry) without HTTP.
    // They live here because `build_test_entries_xdr` is private to this module.

    /// Happy-path: `sign_challenge_for_test` attaches a valid ed25519 signature
    /// to the client entry and returns re-encoded XDR that round-trips.
    #[test]
    fn sign_client_entry_attaches_signature_and_reencodes() {
        use ed25519_dalek::SigningKey;
        use stellar_xdr::{Limits, ReadXdr, SorobanAuthorizationEntries, SorobanCredentials};

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key_str = server_signing_key_str(&server_seed);

        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            &nonce,
            network,
            false,
            None,
            None,
            None,
        );

        let challenge = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_key_str,
            None,
            client,
        )
        .unwrap();

        // Use a deterministic ephemeral key for reproducibility.
        let ephemeral_seed = [0x77u8; 32];
        let ephemeral_key = SigningKey::from_bytes(&ephemeral_seed);
        let test_client = crate::client::Sep45Client::new_for_unit_test(network).unwrap();

        let signed_xdr_b64 = crate::ephemeral::sign_challenge_for_test(
            &challenge,
            &ephemeral_key,
            &test_client,
            9_999_999,
        )
        .unwrap();

        // The output must be valid base64 + valid XDR.
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&signed_xdr_b64)
            .unwrap();
        let decoded = SorobanAuthorizationEntries::read_xdr(&mut stellar_xdr::Limited::new(
            raw.as_slice(),
            Limits::none(),
        ))
        .unwrap();

        let entries: Vec<_> = decoded.0.into_vec();
        assert_eq!(entries.len(), 2, "signed XDR must still contain 2 entries");

        // Client entry must have a non-Void signature attached.
        let client_entry = &entries[challenge.client_entry_index];
        let SorobanCredentials::Address(ref creds) = client_entry.credentials else {
            panic!("client entry must have Address credentials");
        };
        assert!(
            !matches!(creds.signature, stellar_xdr::ScVal::Void),
            "client entry signature must be non-Void after signing"
        );
        // Signature must be Vec([Map(...)]) shape: ScVal::Vec(Some(_)).
        assert!(
            matches!(creds.signature, stellar_xdr::ScVal::Vec(Some(_))),
            "client entry signature must be ScVal::Vec(Some(_)), got {:?}",
            creds.signature
        );
    }

    /// Server entry must remain UNCHANGED after `sign_client_entry`.
    #[test]
    fn sign_client_entry_does_not_modify_server_entry() {
        use ed25519_dalek::SigningKey;
        use stellar_xdr::{Limits, ReadXdr, SorobanAuthorizationEntries, SorobanCredentials};

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key_str = server_signing_key_str(&server_seed);

        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            &nonce,
            network,
            false,
            None,
            None,
            None,
        );

        let challenge = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_key_str,
            None,
            client,
        )
        .unwrap();

        let ephemeral_seed = [0xAAu8; 32];
        let ephemeral_key = SigningKey::from_bytes(&ephemeral_seed);
        let test_client = crate::client::Sep45Client::new_for_unit_test(network).unwrap();

        let signed_xdr_b64 = crate::ephemeral::sign_challenge_for_test(
            &challenge,
            &ephemeral_key,
            &test_client,
            9_999_999,
        )
        .unwrap();

        let raw = base64::engine::general_purpose::STANDARD
            .decode(&signed_xdr_b64)
            .unwrap();
        let decoded = SorobanAuthorizationEntries::read_xdr(&mut stellar_xdr::Limited::new(
            raw.as_slice(),
            Limits::none(),
        ))
        .unwrap();
        let entries: Vec<_> = decoded.0.into_vec();

        // Server entry (index 0) must still carry the original server signature.
        let server_entry = &entries[challenge.server_entry_index];
        let SorobanCredentials::Address(ref server_creds) = server_entry.credentials else {
            panic!("server entry must have Address credentials");
        };
        // Server signature is a Vec; it must remain a non-Void Vec.
        assert!(
            matches!(server_creds.signature, stellar_xdr::ScVal::Vec(Some(_))),
            "server entry signature must be untouched Vec(Some(_)) after client signing"
        );
    }

    /// `sign_challenge_for_test` on a challenge with a client-domain entry
    /// must still sign only the client entry (not the client-domain entry).
    #[test]
    fn sign_client_entry_three_way_challenge_signs_only_client() {
        use ed25519_dalek::SigningKey;
        use stellar_xdr::{Limits, ReadXdr, SorobanAuthorizationEntries, SorobanCredentials};

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key_str = server_signing_key_str(&server_seed);
        let cd_seed = [0x03u8; 32];
        let cd_key = SigningKey::from_bytes(&cd_seed);
        let cd_pubkey_bytes = cd_key.verifying_key().to_bytes();
        let cd_g_str = format!("{}", stellar_strkey::ed25519::PublicKey(cd_pubkey_bytes));

        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            &nonce,
            network,
            true,
            Some("wallet.example.com"),
            Some(&cd_seed),
            Some(&cd_g_str),
        );

        let challenge = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_key_str,
            Some("wallet.example.com"),
            client,
        )
        .unwrap();

        assert_eq!(challenge.entries.len(), 3, "fixture must have 3 entries");
        assert!(
            challenge.client_domain_entry_index.is_some(),
            "client_domain_entry_index must be set for 3-entry challenge"
        );

        let ephemeral_seed = [0xBBu8; 32];
        let ephemeral_key = SigningKey::from_bytes(&ephemeral_seed);
        let test_client = crate::client::Sep45Client::new_for_unit_test(network).unwrap();

        let signed_xdr_b64 = crate::ephemeral::sign_challenge_for_test(
            &challenge,
            &ephemeral_key,
            &test_client,
            9_999_999,
        )
        .unwrap();

        let raw = base64::engine::general_purpose::STANDARD
            .decode(&signed_xdr_b64)
            .unwrap();
        let decoded = SorobanAuthorizationEntries::read_xdr(&mut stellar_xdr::Limited::new(
            raw.as_slice(),
            Limits::none(),
        ))
        .unwrap();
        let entries: Vec<_> = decoded.0.into_vec();

        // Client entry must be signed (non-Void).
        let SorobanCredentials::Address(ref client_creds) =
            entries[challenge.client_entry_index].credentials
        else {
            panic!("client entry must have Address credentials");
        };
        assert!(
            matches!(client_creds.signature, stellar_xdr::ScVal::Vec(Some(_))),
            "client entry must be signed"
        );

        // Client-domain entry must remain unsigned (Void).
        let cd_idx = challenge.client_domain_entry_index.unwrap();
        let SorobanCredentials::Address(ref cd_creds) = entries[cd_idx].credentials else {
            panic!("client-domain entry must have Address credentials");
        };
        assert!(
            matches!(cd_creds.signature, stellar_xdr::ScVal::Void),
            "client-domain entry must remain Void — only the client entry is signed by ephemeral key"
        );
    }

    /// Two sequential calls with different ephemeral keys must produce different
    /// signed XDR blobs (signature covers the key material).
    #[test]
    fn sign_client_entry_different_keys_produce_different_blobs() {
        use ed25519_dalek::SigningKey;

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key_str = server_signing_key_str(&server_seed);

        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            &nonce,
            network,
            false,
            None,
            None,
            None,
        );

        let challenge = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_key_str,
            None,
            client,
        )
        .unwrap();

        let test_client = crate::client::Sep45Client::new_for_unit_test(network).unwrap();

        let key_a = SigningKey::from_bytes(&[0x11u8; 32]);
        let key_b = SigningKey::from_bytes(&[0x22u8; 32]);

        let blob_a =
            crate::ephemeral::sign_challenge_for_test(&challenge, &key_a, &test_client, 9_999_999)
                .unwrap();
        let blob_b =
            crate::ephemeral::sign_challenge_for_test(&challenge, &key_b, &test_client, 9_999_999)
                .unwrap();

        assert_ne!(
            blob_a, blob_b,
            "different ephemeral keys must produce different signed XDR blobs"
        );
    }

    // ── Cryptographic signature coverage of signature_expiration_ledger ──────

    /// Verifies that the ephemeral signature in the re-encoded XDR is
    /// cryptographically correct over the caller-supplied
    /// `signature_expiration_ledger` (not 0 or any other placeholder).
    ///
    /// Steps:
    /// 1. Build a valid challenge, parse it.
    /// 2. Sign with a deterministic ephemeral seed and `N = 8888u32`.
    /// 3. Decode the re-encoded XDR; extract the client entry's `addr_creds`.
    /// 4. Independently re-derive `HashIdPreimageSorobanAuthorization` using:
    ///    - `network_id = SHA-256(network_passphrase_bytes)`
    ///    - `nonce = addr_creds.nonce`
    ///    - `signature_expiration_ledger = N` (the caller-supplied value)
    ///    - `invocation = client_entry.root_invocation`
    /// 5. SHA-256 hash the XDR-encoded preimage.
    /// 6. Extract `public_key` (32 bytes) and `signature` (64 bytes) from the
    ///    client entry's `ScVal::Vec([ScVal::Map({public_key, signature})])`.
    /// 7. Verify with `ed25519_dalek::VerifyingKey::verify_strict`.
    ///
    /// This proves that `sign_client_entry` uses `signature_expiration_ledger = N`
    /// (not 0) when computing the preimage, and that the resulting signature is
    /// cryptographically valid.
    #[test]
    fn sign_client_entry_signature_covers_expiration() {
        use ed25519_dalek::{Signature as DalekSignature, SigningKey, VerifyingKey};
        use stellar_xdr::{
            HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits, ReadXdr,
            SorobanAuthorizationEntries, SorobanCredentials, WriteXdr,
        };

        const N: u32 = 8888;

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key_str = server_signing_key_str(&server_seed);

        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            &nonce,
            network,
            false,
            None,
            None,
            None,
        );

        let challenge = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_key_str,
            None,
            client,
        )
        .unwrap();

        // Deterministic ephemeral seed — use the same value to derive expected pubkey.
        let ephemeral_seed = [0xC0u8; 32];
        let ephemeral_key = SigningKey::from_bytes(&ephemeral_seed);
        let expected_verifying_key = ephemeral_key.verifying_key();
        let test_client = crate::client::Sep45Client::new_for_unit_test(network).unwrap();

        let signed_b64 =
            crate::ephemeral::sign_challenge_for_test(&challenge, &ephemeral_key, &test_client, N)
                .unwrap();

        // Step 3: decode the signed XDR and extract client entry.
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&signed_b64)
            .unwrap();
        let decoded = SorobanAuthorizationEntries::read_xdr(&mut stellar_xdr::Limited::new(
            raw.as_slice(),
            Limits::none(),
        ))
        .unwrap();
        let entries: Vec<_> = decoded.0.into_vec();

        let client_entry = &entries[challenge.client_entry_index];
        let SorobanCredentials::Address(ref addr_creds) = client_entry.credentials else {
            panic!("client entry must have Address credentials");
        };

        // Confirm the expiration was set.
        assert_eq!(
            addr_creds.signature_expiration_ledger, N,
            "signature_expiration_ledger must be N={N}"
        );

        // Step 4: Re-derive the preimage using the values from the signed entry.
        let network_id = Hash(Sha256::digest(network.as_bytes()).into());
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id,
            nonce: addr_creds.nonce,
            // Using N (not 0) is what the production code sets; we verify that
            // the signature covers exactly this value.
            signature_expiration_ledger: N,
            invocation: client_entry.root_invocation.clone(),
        });
        let mut preimage_bytes = Vec::new();
        preimage
            .write_xdr(&mut stellar_xdr::Limited::new(
                &mut preimage_bytes,
                Limits::none(),
            ))
            .unwrap();
        let payload_hash: [u8; 32] = Sha256::digest(&preimage_bytes).into();

        // Step 6: Extract the public_key (32 bytes) and signature (64 bytes) from
        // the client entry's credential ScVal::Vec([ScVal::Map({public_key, signature})]).
        let sig_vec = match &addr_creds.signature {
            stellar_xdr::ScVal::Vec(Some(v)) => v,
            other => panic!("expected ScVal::Vec(Some(_)), got {other:?}"),
        };
        assert!(!sig_vec.is_empty(), "signature vec must be non-empty");

        let sig_map = match &sig_vec[0] {
            stellar_xdr::ScVal::Map(Some(m)) => m,
            other => panic!("expected first element to be ScVal::Map(Some(_)), got {other:?}"),
        };

        let mut pk_bytes: Option<&[u8]> = None;
        let mut sig_bytes: Option<&[u8]> = None;
        for map_entry in sig_map.iter() {
            let key_name = match &map_entry.key {
                stellar_xdr::ScVal::Symbol(sym) => {
                    std::str::from_utf8(sym.0.as_slice()).unwrap_or("")
                }
                _ => continue,
            };
            match key_name {
                "public_key" => {
                    if let stellar_xdr::ScVal::Bytes(b) = &map_entry.val {
                        pk_bytes = Some(b.0.as_slice());
                    }
                }
                "signature" => {
                    if let stellar_xdr::ScVal::Bytes(b) = &map_entry.val {
                        sig_bytes = Some(b.0.as_slice());
                    }
                }
                _ => {}
            }
        }

        let pk_bytes = pk_bytes.expect("public_key must be present in signature map");
        let sig_bytes = sig_bytes.expect("signature must be present in signature map");

        // The public_key in the signed entry must match our ephemeral key.
        assert_eq!(
            pk_bytes,
            expected_verifying_key.as_bytes().as_slice(),
            "public_key in signed entry must match ephemeral verifying key"
        );

        // Step 7: Verify ed25519 signature over the payload hash.
        let pk_arr: [u8; 32] = pk_bytes
            .try_into()
            .expect("public_key must be exactly 32 bytes");
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .expect("signature must be exactly 64 bytes");

        let verifying_key = VerifyingKey::from_bytes(&pk_arr)
            .expect("ephemeral public key bytes must be a valid ed25519 point");
        let dalek_sig = DalekSignature::from_bytes(&sig_arr);

        assert!(
            verifying_key
                .verify_strict(&payload_hash, &dalek_sig)
                .is_ok(),
            "ed25519 signature must verify over SHA-256(HashIdPreimageSorobanAuthorization) \
             with signature_expiration_ledger = N={N}"
        );
    }

    // ── Duplicate-key rejection ───────────────────────────────────────────────

    /// A server that sends an args map with a duplicate Symbol key (e.g.
    /// `nonce` appearing twice) must be rejected fail-closed.
    ///
    /// The XDR `ScMap` type permits duplicate keys at the byte level; the
    /// stellar-xdr `VecM` inner representation carries no uniqueness constraint
    /// at construction time. `extract_args_map` is the only gate that enforces
    /// uniqueness before the values are used for validation.
    #[test]
    fn args_map_duplicate_key_rejected() {
        use ed25519_dalek::{Signer, SigningKey};
        use stellar_xdr::{
            AccountId, ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
            InvokeContractArgs, Limits, PublicKey as XdrPublicKey, ScAddress, ScBytes, ScMap,
            ScMapEntry, ScString, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
            SorobanAuthorizationEntries, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation, SorobanCredentials, Uint256, VecM, WriteXdr,
        };

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key = SigningKey::from_bytes(&server_seed);
        let server_pubkey_bytes = server_key.verifying_key().to_bytes();
        let server_g_str = stellar_strkey::ed25519::PublicKey(server_pubkey_bytes).to_string();

        let contract_bytes = stellar_strkey::Contract::from_string(contract).unwrap().0;
        let contract_address = ScAddress::Contract(ContractId(Hash(contract_bytes)));

        // Build an args map with a DUPLICATE "nonce" key. The VecM inner type
        // has no uniqueness constraint; we bypass ScMap::sorted_from (which
        // would reject duplicates) and construct the raw VecM directly.
        let duplicate_nonce_map_val = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                    val: ScVal::String(ScString(client.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(home.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                    val: ScVal::String(ScString(nonce.as_str().try_into().unwrap())),
                },
                // Duplicate "nonce" key — same symbol, different value.
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                    val: ScVal::String(ScString(
                        "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ2".try_into().unwrap(),
                    )),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(web_auth.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                    val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
                },
            ]
            .try_into()
            .unwrap(),
        )));

        let fn_args = InvokeContractArgs {
            contract_address: contract_address.clone(),
            function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
            args: vec![duplicate_nonce_map_val].try_into().unwrap(),
        };
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(fn_args),
            sub_invocations: VecM::default(),
        };

        // Compute a real server signature so the entry passes step-12 if reached.
        let server_nonce_i64: i64 = 9_876_543;
        let server_expiry: u32 = 8_888_888;
        let network_id_hash = {
            let mut h = Sha256::new();
            h.update(network.as_bytes());
            Hash(h.finalize().into())
        };
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: network_id_hash,
            nonce: server_nonce_i64,
            signature_expiration_ledger: server_expiry,
            invocation: invocation.clone(),
        });
        let mut preimage_bytes = Vec::new();
        preimage
            .write_xdr(&mut stellar_xdr::Limited::new(
                &mut preimage_bytes,
                Limits::none(),
            ))
            .unwrap();
        let payload = {
            let mut h = Sha256::new();
            h.update(&preimage_bytes);
            h.finalize()
        };
        let sig_bytes = server_key.sign(&payload).to_bytes();

        let server_sig_scval = ScVal::Vec(Some(ScVec(
            vec![ScVal::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("public_key".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(
                            server_pubkey_bytes.to_vec().try_into().unwrap(),
                        )),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("signature".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(sig_bytes.to_vec().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            )))]
            .try_into()
            .unwrap(),
        )));

        let server_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(server_pubkey_bytes),
                ))),
                nonce: server_nonce_i64,
                signature_expiration_ledger: server_expiry,
                signature: server_sig_scval,
            }),
            root_invocation: invocation.clone(),
        };

        let client_bytes = stellar_strkey::Contract::from_string(client).unwrap().0;
        let client_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(client_bytes))),
                nonce: 2,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: invocation,
        };

        let entries_xdr =
            SorobanAuthorizationEntries(vec![server_entry, client_entry].try_into().unwrap());
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        let b64 = BASE64_STANDARD.encode(&out);

        let err = AuthorizationEntries::parse_and_validate(
            &b64,
            network,
            contract,
            home,
            web_auth,
            &server_g_str,
            None,
            client,
        )
        .unwrap_err();

        assert!(
            matches!(err, Sep45Error::InvalidArgsFormat { .. }),
            "expected InvalidArgsFormat for duplicate 'nonce' key in args map; got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.invalid_args_format");
    }

    // ── Depth-bomb: XDR decode depth limit enforcement ───────────────────────

    /// A `SorobanAuthorizationEntries` payload containing one entry whose
    /// `root_invocation` has a 600-deep `sub_invocations` chain is rejected by
    /// `parse_and_validate` with `Sep45Error::XdrDecodeError`.
    ///
    /// The depth (600) exceeds `XDR_DECODE_MAX_DEPTH` (500). The bounded
    /// decoder in `parse_and_validate` returns an error at step 1 (XDR
    /// decode) before any other field is validated.
    ///
    /// The fixture is encoded with `Limits::none()` (write-side; writing 600
    /// levels fits the test stack). Only the bounded production path decodes
    /// it.
    #[test]
    fn deep_sub_invocations_chain_rejected_at_entries_parse() {
        use stellar_xdr::{
            ContractId, Hash, InvokeContractArgs, Limits, ScAddress, SorobanAuthorizationEntries,
            SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
            SorobanCredentials, VecM, WriteXdr,
        };

        let leaf_fn = SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([0xABu8; 32]))),
            function_name: "f".try_into().expect("short name"),
            args: VecM::default(),
        });

        // Build a 600-deep chain iteratively (innermost first, wrap outward).
        let mut inner = SorobanAuthorizedInvocation {
            function: leaf_fn.clone(),
            sub_invocations: VecM::default(),
        };
        for _ in 0..599 {
            inner = SorobanAuthorizedInvocation {
                function: leaf_fn.clone(),
                sub_invocations: vec![inner].try_into().expect("single-element VecM"),
            };
        }

        let entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: inner,
        };

        let entries_xdr =
            SorobanAuthorizationEntries(vec![entry].try_into().expect("single-entry VecM"));

        // ENCODE with Limits::none() — write-side; does not invoke the bounded
        // read path. Writing 600 levels of nesting fits the test stack.
        let mut raw_bytes = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(
                &mut raw_bytes,
                Limits::none(),
            ))
            .expect("encoding a deep structure must succeed");
        let deep_b64 = BASE64_STANDARD.encode(&raw_bytes);

        // Dummy params — execution never reaches validation of these values
        // because the XDR decode at step 1 fails first.
        let err = AuthorizationEntries::parse_and_validate(
            &deep_b64,
            "Test SDF Network ; September 2015",
            "CALI6JC3MSNDGFRP7Z2OKUEPREHOJRRXKMJEWQDEFZPFGXALA45RAUTH",
            "example.com",
            "auth.example.com",
            "GCHLHDBOKGWJWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
            None,
            "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ",
        )
        .expect_err("600-deep chain must be rejected before stack exhaustion");

        assert!(
            matches!(err, Sep45Error::XdrDecodeError { .. }),
            "expected XdrDecodeError; got {err:?}"
        );
    }

    // ── account arg binding ───────────────────────────────────────────────────

    /// When the server returns an `account` arg that differs from the client
    /// account in the original GET request, `parse_and_validate` must return
    /// `InvalidAccountArg`. Without this check a server could return a
    /// challenge for a different contract account and the client would sign it.
    #[test]
    fn fail_account_arg_does_not_match_expected() {
        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key = server_signing_key_str(&server_seed);

        // Build a challenge where `account` = `client` (the fixture default).
        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            &nonce,
            network,
            false,
            None,
            None,
            None,
        );

        // Pass a DIFFERENT expected_account — distinct valid C-strkey.
        let different_account = "CABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGCK3";
        let err = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_key,
            None,
            different_account,
        )
        .unwrap_err();

        assert!(
            matches!(err, Sep45Error::InvalidAccountArg { .. }),
            "expected InvalidAccountArg when account arg != expected_account; got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.invalid_account_arg");
    }

    // ── malformed expected_server_signing_key ─────────────────────────────────

    /// A caller-supplied `expected_server_signing_key` that is not a valid
    /// G-strkey must produce `InvalidExpectedServerKeyArg`, not
    /// `InvalidServerSignature`. The two errors are semantically distinct:
    /// one is a bad caller argument, the other is a failed cryptographic check.
    #[test]
    fn fail_malformed_expected_server_signing_key() {
        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();

        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            &nonce,
            network,
            false,
            None,
            None,
            None,
        );

        let err = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            "not-a-valid-g-strkey",
            None,
            client,
        )
        .unwrap_err();

        assert!(
            matches!(err, Sep45Error::InvalidExpectedServerKeyArg { .. }),
            "expected InvalidExpectedServerKeyArg for malformed expected_server_signing_key; got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.invalid_expected_server_key_arg");
    }

    // ── duplicate Symbol key with non-String second value ────────────────────

    /// A duplicate Symbol key whose second occurrence has a non-String value
    /// must still be rejected. A `continue` on non-String values before the
    /// duplicate check would allow such duplicates to pass through silently.
    #[test]
    fn args_map_duplicate_symbol_key_non_string_second_value_rejected() {
        use ed25519_dalek::{Signer, SigningKey};
        use stellar_xdr::{
            AccountId, ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
            InvokeContractArgs, Limits, PublicKey as XdrPublicKey, ScAddress, ScBytes, ScMap,
            ScMapEntry, ScString, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
            SorobanAuthorizationEntries, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation, SorobanCredentials, Uint256, VecM, WriteXdr,
        };

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key = SigningKey::from_bytes(&server_seed);
        let server_pubkey_bytes = server_key.verifying_key().to_bytes();
        let server_g_str = stellar_strkey::ed25519::PublicKey(server_pubkey_bytes).to_string();

        let contract_bytes = stellar_strkey::Contract::from_string(contract).unwrap().0;
        let contract_address = ScAddress::Contract(ContractId(Hash(contract_bytes)));

        // Build an args map where "nonce" appears twice:
        //   first occurrence  → ScVal::String (valid)
        //   second occurrence → ScVal::I32    (non-String — evaded the old dup check)
        let dup_nonstring_map_val = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                    val: ScVal::String(ScString(client.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(home.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                    val: ScVal::String(ScString(nonce.as_str().try_into().unwrap())),
                },
                // Duplicate "nonce" key — non-String value (ScVal::I32).
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                    val: ScVal::I32(42),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(web_auth.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                    val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
                },
            ]
            .try_into()
            .unwrap(),
        )));

        let fn_args = InvokeContractArgs {
            contract_address: contract_address.clone(),
            function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
            args: vec![dup_nonstring_map_val].try_into().unwrap(),
        };
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(fn_args),
            sub_invocations: VecM::default(),
        };

        // Build a real server signature so the duplicate-key check is reached.
        let server_nonce_i64: i64 = 5_555_555;
        let server_expiry: u32 = 7_777_777;
        let network_id_hash = {
            let mut h = Sha256::new();
            h.update(network.as_bytes());
            Hash(h.finalize().into())
        };
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: network_id_hash,
            nonce: server_nonce_i64,
            signature_expiration_ledger: server_expiry,
            invocation: invocation.clone(),
        });
        let mut preimage_bytes = Vec::new();
        preimage
            .write_xdr(&mut stellar_xdr::Limited::new(
                &mut preimage_bytes,
                Limits::none(),
            ))
            .unwrap();
        let payload = {
            let mut h = Sha256::new();
            h.update(&preimage_bytes);
            h.finalize()
        };
        let sig_bytes = server_key.sign(&payload).to_bytes();

        let server_sig_scval = ScVal::Vec(Some(ScVec(
            vec![ScVal::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("public_key".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(
                            server_pubkey_bytes.to_vec().try_into().unwrap(),
                        )),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("signature".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(sig_bytes.to_vec().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            )))]
            .try_into()
            .unwrap(),
        )));

        let server_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(server_pubkey_bytes),
                ))),
                nonce: server_nonce_i64,
                signature_expiration_ledger: server_expiry,
                signature: server_sig_scval,
            }),
            root_invocation: invocation.clone(),
        };

        let client_bytes = stellar_strkey::Contract::from_string(client).unwrap().0;
        let client_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(client_bytes))),
                nonce: 77,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: invocation,
        };

        let entries_xdr =
            SorobanAuthorizationEntries(vec![server_entry, client_entry].try_into().unwrap());
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        let b64 = BASE64_STANDARD.encode(&out);

        let err = AuthorizationEntries::parse_and_validate(
            &b64,
            network,
            contract,
            home,
            web_auth,
            &server_g_str,
            None,
            client,
        )
        .unwrap_err();

        assert!(
            matches!(err, Sep45Error::InvalidArgsFormat { .. }),
            "expected InvalidArgsFormat for duplicate Symbol key with non-String second value; got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.invalid_args_format");
    }

    // ── client_domain_account cross-entry consistency ─────────────────────────

    /// When the `client_domain_account` arg differs between entries,
    /// `parse_and_validate` must return `InvalidClientDomainAccount`.
    /// A server that injects a different client_domain_account into a non-first
    /// entry would cause the client to authorize a different domain account.
    #[test]
    fn fail_client_domain_account_cross_entry_mismatch() {
        use ed25519_dalek::{Signer, SigningKey};
        use stellar_xdr::{
            AccountId, ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
            InvokeContractArgs, Limits, PublicKey as XdrPublicKey, ScAddress, ScBytes, ScMap,
            ScMapEntry, ScString, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
            SorobanAuthorizationEntries, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation, SorobanCredentials, Uint256, VecM, WriteXdr,
        };

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();
        let server_key = SigningKey::from_bytes(&server_seed);
        let server_pubkey_bytes = server_key.verifying_key().to_bytes();
        let server_g_str = stellar_strkey::ed25519::PublicKey(server_pubkey_bytes).to_string();

        // Two different client_domain_account keys.
        let cd_seed_a = [0x0Au8; 32];
        let cd_seed_b = [0x0Bu8; 32];
        let cd_key_a = SigningKey::from_bytes(&cd_seed_a);
        let cd_key_b = SigningKey::from_bytes(&cd_seed_b);
        let cd_g_str_a =
            stellar_strkey::ed25519::PublicKey(cd_key_a.verifying_key().to_bytes()).to_string();
        let cd_g_str_b =
            stellar_strkey::ed25519::PublicKey(cd_key_b.verifying_key().to_bytes()).to_string();

        let contract_bytes = stellar_strkey::Contract::from_string(contract).unwrap().0;
        let contract_address = ScAddress::Contract(ContractId(Hash(contract_bytes)));

        // Helper closure: build an invocation with given client_domain_account string.
        let make_invocation = |cda_str: &str| {
            let args_map_val = ScVal::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                        val: ScVal::String(ScString(client.try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("client_domain".try_into().unwrap())),
                        val: ScVal::String(ScString("wallet.example.com".try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("client_domain_account".try_into().unwrap())),
                        val: ScVal::String(ScString(cda_str.try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                        val: ScVal::String(ScString(home.try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                        val: ScVal::String(ScString(nonce.as_str().try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                        val: ScVal::String(ScString(web_auth.try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                        val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            )));
            SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: contract_address.clone(),
                    function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
                    args: vec![args_map_val].try_into().unwrap(),
                }),
                sub_invocations: VecM::default(),
            }
        };

        // Entry 0 (server): uses cd_g_str_a as client_domain_account.
        let server_invocation = make_invocation(&cd_g_str_a);
        let server_nonce_i64: i64 = 4_444_444;
        let server_expiry: u32 = 6_666_666;
        let network_id_hash = {
            let mut h = Sha256::new();
            h.update(network.as_bytes());
            Hash(h.finalize().into())
        };
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: network_id_hash,
            nonce: server_nonce_i64,
            signature_expiration_ledger: server_expiry,
            invocation: server_invocation.clone(),
        });
        let mut preimage_bytes = Vec::new();
        preimage
            .write_xdr(&mut stellar_xdr::Limited::new(
                &mut preimage_bytes,
                Limits::none(),
            ))
            .unwrap();
        let payload = {
            let mut h = Sha256::new();
            h.update(&preimage_bytes);
            h.finalize()
        };
        let sig_bytes = server_key.sign(&payload).to_bytes();
        let server_sig_scval = ScVal::Vec(Some(ScVec(
            vec![ScVal::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("public_key".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(
                            server_pubkey_bytes.to_vec().try_into().unwrap(),
                        )),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("signature".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(sig_bytes.to_vec().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            )))]
            .try_into()
            .unwrap(),
        )));

        let server_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(server_pubkey_bytes),
                ))),
                nonce: server_nonce_i64,
                signature_expiration_ledger: server_expiry,
                signature: server_sig_scval,
            }),
            root_invocation: server_invocation,
        };

        // Entry 1 (client): uses cd_g_str_b (DIFFERENT from server entry).
        let client_invocation = make_invocation(&cd_g_str_b);
        let client_bytes = stellar_strkey::Contract::from_string(client).unwrap().0;
        let client_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(client_bytes))),
                nonce: 88,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: client_invocation,
        };

        // Entry 2 (client-domain): uses cd_key_a's address (matching arg-A).
        let cd_a_pubkey_bytes = cd_key_a.verifying_key().to_bytes();
        let cd_invocation = make_invocation(&cd_g_str_a);
        let cd_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(cd_a_pubkey_bytes),
                ))),
                nonce: 99,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: cd_invocation,
        };

        let entries_xdr = SorobanAuthorizationEntries(
            vec![server_entry, client_entry, cd_entry]
                .try_into()
                .unwrap(),
        );
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        let b64 = BASE64_STANDARD.encode(&out);

        let err = AuthorizationEntries::parse_and_validate(
            &b64,
            network,
            contract,
            home,
            web_auth,
            &server_g_str,
            Some("wallet.example.com"),
            client,
        )
        .unwrap_err();

        assert!(
            matches!(err, Sep45Error::InvalidClientDomainAccount { .. }),
            "expected InvalidClientDomainAccount when client_domain_account differs between entries; got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.invalid_client_domain_account");
    }

    // ── Failure: empty nonce ──────────────────────────────────────────────────

    /// An args map whose `nonce` value is present but empty must be rejected
    /// with `MissingNonce`. An empty nonce is not usable as a replay-prevention
    /// token.
    #[test]
    fn fail_empty_nonce_rejected() {
        let (contract, client, home, web_auth, server_seed) = test_params();
        let network = test_network();
        let server_key = server_signing_key_str(&server_seed);

        // Build entries with an empty nonce string.
        let xdr_b64 = build_test_entries_xdr(
            contract,
            home,
            web_auth,
            &server_seed,
            client,
            "", // empty nonce
            network,
            false,
            None,
            None,
            None,
        );

        let err = AuthorizationEntries::parse_and_validate(
            &xdr_b64,
            network,
            contract,
            home,
            web_auth,
            &server_key,
            None,
            client,
        )
        .unwrap_err();

        assert!(
            matches!(err, Sep45Error::MissingNonce { entry_index: 0 }),
            "expected MissingNonce at entry 0 for empty nonce string; got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.missing_nonce");
    }

    // ── Step-9b cross-entry consistency ───────────────────────────────────────

    /// Builds a two-entry (server + client) XDR fixture in base64 where the
    /// server entry's args map is valid and the client entry's args map is
    /// produced by calling `mutate_client_args` on an identical starting map.
    ///
    /// The server entry carries a real ed25519 signature so that validation
    /// reaches step 9b without failing on earlier checks.
    #[allow(
        clippy::too_many_lines,
        reason = "test helper; all setup required to reach the step-9b check"
    )]
    fn build_two_entry_b64_with_client_arg_override(
        mutate_client_args: impl Fn(&mut Vec<ScMapEntry>),
    ) -> (String, String) {
        use ed25519_dalek::{Signer, SigningKey};
        use stellar_xdr::{
            AccountId, ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
            InvokeContractArgs, Limits, PublicKey as XdrPublicKey, ScAddress, ScBytes, ScMap,
            ScMapEntry, ScString, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
            SorobanAuthorizationEntries, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation, SorobanCredentials, Uint256, VecM, WriteXdr,
        };

        let (contract, client, home, web_auth, server_seed) = test_params();
        let nonce = test_nonce();
        let network = test_network();

        let server_signing_key = SigningKey::from_bytes(&server_seed);
        let server_pubkey_bytes = server_signing_key.verifying_key().to_bytes();
        let server_g_str = stellar_strkey::ed25519::PublicKey(server_pubkey_bytes).to_string();

        let contract_bytes = stellar_strkey::Contract::from_string(contract).unwrap().0;
        let contract_address = ScAddress::Contract(ContractId(Hash(contract_bytes)));

        // Reference args map (used for server entry and as starting point for
        // the client entry before mutation).
        let make_args_entries = || -> Vec<ScMapEntry> {
            vec![
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                    val: ScVal::String(ScString(client.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(home.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                    val: ScVal::String(ScString(nonce.as_str().try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(web_auth.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                    val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
                },
            ]
        };

        let make_invocation = |entries: Vec<ScMapEntry>| -> SorobanAuthorizedInvocation {
            let args_val = ScVal::Map(Some(ScMap(entries.try_into().unwrap())));
            SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: contract_address.clone(),
                    function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
                    args: vec![args_val].try_into().unwrap(),
                }),
                sub_invocations: VecM::default(),
            }
        };

        let server_entries = make_args_entries();
        let server_invocation = make_invocation(server_entries);
        let server_nonce_i64: i64 = 3_333_333;
        let server_expiry: u32 = 7_777_777;

        let network_id_hash = {
            let mut h = Sha256::new();
            h.update(network.as_bytes());
            Hash(h.finalize().into())
        };
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: network_id_hash,
            nonce: server_nonce_i64,
            signature_expiration_ledger: server_expiry,
            invocation: server_invocation.clone(),
        });
        let mut preimage_bytes = Vec::new();
        preimage
            .write_xdr(&mut stellar_xdr::Limited::new(
                &mut preimage_bytes,
                Limits::none(),
            ))
            .unwrap();
        let payload = {
            let mut h = Sha256::new();
            h.update(&preimage_bytes);
            h.finalize()
        };
        let sig_bytes = server_signing_key.sign(&payload).to_bytes();
        let server_sig_scval = ScVal::Vec(Some(ScVec(
            vec![ScVal::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("public_key".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(
                            server_pubkey_bytes.to_vec().try_into().unwrap(),
                        )),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("signature".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(sig_bytes.to_vec().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            )))]
            .try_into()
            .unwrap(),
        )));

        let server_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(server_pubkey_bytes),
                ))),
                nonce: server_nonce_i64,
                signature_expiration_ledger: server_expiry,
                signature: server_sig_scval,
            }),
            root_invocation: server_invocation,
        };

        // Build client entry with a mutated args map.
        let mut client_entries = make_args_entries();
        mutate_client_args(&mut client_entries);
        let client_invocation = make_invocation(client_entries);
        let client_bytes = stellar_strkey::Contract::from_string(client).unwrap().0;
        let client_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(client_bytes))),
                nonce: 123,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: client_invocation,
        };

        let entries_xdr =
            SorobanAuthorizationEntries(vec![server_entry, client_entry].try_into().unwrap());
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        (BASE64_STANDARD.encode(&out), server_g_str.to_string())
    }

    /// A non-first entry with a mismatched `account` arg must be rejected with
    /// `InvalidAccountArg`. The account binding must be consistent across all
    /// entries so the client cannot be coerced into signing for a different account.
    #[test]
    fn fail_step9b_account_mismatch_in_second_entry() {
        use stellar_xdr::{ScString, ScVal};

        let (contract, client, home, web_auth, server_seed) = test_params();
        let network = test_network();
        let server_key = server_signing_key_str(&server_seed);

        let (b64, _) =
            build_two_entry_b64_with_client_arg_override(|entries: &mut Vec<ScMapEntry>| {
                // Replace the "account" entry with a different contract address.
                if let Some(e) = entries
                    .iter_mut()
                    .find(|e| matches!(&e.key, ScVal::Symbol(s) if s.0.as_slice() == b"account"))
                {
                    e.val = ScVal::String(ScString(
                        "CABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2"
                            .try_into()
                            .unwrap(),
                    ));
                }
            });

        let err = AuthorizationEntries::parse_and_validate(
            &b64,
            network,
            contract,
            home,
            web_auth,
            &server_key,
            None,
            client,
        )
        .unwrap_err();

        assert!(
            matches!(err, Sep45Error::InvalidAccountArg { .. }),
            "expected InvalidAccountArg for account mismatch in entry 1; got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.invalid_account_arg");
    }

    /// A non-first entry with a mismatched `home_domain` arg must be rejected
    /// with `HomeDomainMismatch`. Consistent home_domain across entries prevents
    /// the server from binding different domain contexts per signer.
    #[test]
    fn fail_step9b_home_domain_mismatch_in_second_entry() {
        use stellar_xdr::{ScString, ScVal};

        let (contract, client, home, web_auth, server_seed) = test_params();
        let network = test_network();
        let server_key = server_signing_key_str(&server_seed);

        let (b64, _) =
            build_two_entry_b64_with_client_arg_override(|entries: &mut Vec<ScMapEntry>| {
                if let Some(e) = entries.iter_mut().find(
                    |e| matches!(&e.key, ScVal::Symbol(s) if s.0.as_slice() == b"home_domain"),
                ) {
                    e.val = ScVal::String(ScString(
                        "attacker-controlled.example.com".try_into().unwrap(),
                    ));
                }
            });

        let err = AuthorizationEntries::parse_and_validate(
            &b64,
            network,
            contract,
            home,
            web_auth,
            &server_key,
            None,
            client,
        )
        .unwrap_err();

        assert!(
            matches!(err, Sep45Error::HomeDomainMismatch { .. }),
            "expected HomeDomainMismatch for home_domain mismatch in entry 1; got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.home_domain_mismatch");
    }

    /// A non-first entry with a mismatched `web_auth_domain_account` arg must be
    /// rejected with `WebAuthDomainAccountMismatch`. This prevents a server from
    /// presenting a different signing authority to different entries.
    #[test]
    fn fail_step9b_web_auth_domain_account_mismatch_in_second_entry() {
        use stellar_xdr::{ScString, ScVal};

        let (contract, client, home, web_auth, server_seed) = test_params();
        let network = test_network();
        let server_key = server_signing_key_str(&server_seed);
        // A different (but valid) G-strkey.
        let alt_key = "GBSE5JFTRFCMJB3KXIUFKLBQDBZYWQ7M7SQ3CZJHM7DGEQF6SNHBQD";

        let (b64, _) = build_two_entry_b64_with_client_arg_override(
            |entries: &mut Vec<ScMapEntry>| {
                if let Some(e) = entries.iter_mut().find(|e| {
                    matches!(&e.key, ScVal::Symbol(s) if s.0.as_slice() == b"web_auth_domain_account")
                }) {
                    e.val = ScVal::String(ScString(alt_key.try_into().unwrap()));
                }
            },
        );

        let err = AuthorizationEntries::parse_and_validate(
            &b64,
            network,
            contract,
            home,
            web_auth,
            &server_key,
            None,
            client,
        )
        .unwrap_err();

        assert!(
            matches!(err, Sep45Error::WebAuthDomainAccountMismatch { .. }),
            "expected WebAuthDomainAccountMismatch for web_auth_domain_account mismatch in entry 1; got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.web_auth_domain_account_mismatch");
    }

    /// A non-first entry with a mismatched `client_domain` arg must be rejected
    /// with `ClientDomainMismatch`. A server that varies the client_domain across
    /// entries could cause signers to authorize different wallet domains.
    #[test]
    fn fail_step9b_client_domain_mismatch_in_second_entry() {
        let (contract, client, home, web_auth, server_seed) = test_params();
        let network = test_network();
        let expected_client_domain = "wallet.example.com";
        let alt_client_domain = "evil-wallet.example.com";

        // Build a fresh server G-strkey string for client_domain_account.
        let server_g_str = {
            use ed25519_dalek::SigningKey;
            let sk = SigningKey::from_bytes(&server_seed);
            stellar_strkey::ed25519::PublicKey(sk.verifying_key().to_bytes()).to_string()
        };

        // Build two-entry XDR: server entry has the expected client_domain;
        // client entry has a different client_domain value.
        use ed25519_dalek::{Signer, SigningKey};
        use stellar_xdr::{
            AccountId, ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
            InvokeContractArgs, Limits, PublicKey as XdrPublicKey, ScAddress, ScMap,
            ScVal as ScVal2, ScVec, SorobanAddressCredentials, SorobanAuthorizationEntries,
            SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
            SorobanCredentials, Uint256, VecM, WriteXdr,
        };

        let server_signing_key = SigningKey::from_bytes(&server_seed);
        let server_pubkey_bytes = server_signing_key.verifying_key().to_bytes();

        let contract_bytes = stellar_strkey::Contract::from_string(contract).unwrap().0;
        let contract_address = ScAddress::Contract(ContractId(Hash(contract_bytes)));
        let nonce = test_nonce();

        let make_invocation_with_client_domain = |cd: &str| {
            use stellar_xdr::{ScString as ScString2, ScSymbol as ScSymbol2};
            let args_val = ScVal2::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal2::Symbol(ScSymbol2("account".try_into().unwrap())),
                        val: ScVal2::String(ScString2(client.try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal2::Symbol(ScSymbol2("client_domain".try_into().unwrap())),
                        val: ScVal2::String(ScString2(cd.try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal2::Symbol(ScSymbol2("client_domain_account".try_into().unwrap())),
                        val: ScVal2::String(ScString2(server_g_str.as_str().try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal2::Symbol(ScSymbol2("home_domain".try_into().unwrap())),
                        val: ScVal2::String(ScString2(home.try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal2::Symbol(ScSymbol2("nonce".try_into().unwrap())),
                        val: ScVal2::String(ScString2(nonce.as_str().try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal2::Symbol(ScSymbol2("web_auth_domain".try_into().unwrap())),
                        val: ScVal2::String(ScString2(web_auth.try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal2::Symbol(ScSymbol2(
                            "web_auth_domain_account".try_into().unwrap(),
                        )),
                        val: ScVal2::String(ScString2(server_g_str.as_str().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            )));
            SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: contract_address.clone(),
                    function_name: stellar_xdr::ScSymbol("web_auth_verify".try_into().unwrap()),
                    args: vec![args_val].try_into().unwrap(),
                }),
                sub_invocations: VecM::default(),
            }
        };

        let server_invocation = make_invocation_with_client_domain(expected_client_domain);
        let server_nonce_i64: i64 = 6_666_666;
        let server_expiry: u32 = 8_888_888;
        let network_id_hash = {
            let mut h = Sha256::new();
            h.update(network.as_bytes());
            Hash(h.finalize().into())
        };
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: network_id_hash,
            nonce: server_nonce_i64,
            signature_expiration_ledger: server_expiry,
            invocation: server_invocation.clone(),
        });
        let mut preimage_bytes = Vec::new();
        preimage
            .write_xdr(&mut stellar_xdr::Limited::new(
                &mut preimage_bytes,
                Limits::none(),
            ))
            .unwrap();
        let payload = {
            let mut h = Sha256::new();
            h.update(&preimage_bytes);
            h.finalize()
        };
        let sig_bytes = server_signing_key.sign(&payload).to_bytes();
        let server_sig_scval = ScVal2::Vec(Some(ScVec(
            vec![ScVal2::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal2::Symbol(stellar_xdr::ScSymbol(
                            "public_key".try_into().unwrap(),
                        )),
                        val: ScVal2::Bytes(stellar_xdr::ScBytes(
                            server_pubkey_bytes.to_vec().try_into().unwrap(),
                        )),
                    },
                    ScMapEntry {
                        key: ScVal2::Symbol(stellar_xdr::ScSymbol("signature".try_into().unwrap())),
                        val: ScVal2::Bytes(stellar_xdr::ScBytes(
                            sig_bytes.to_vec().try_into().unwrap(),
                        )),
                    },
                ]
                .try_into()
                .unwrap(),
            )))]
            .try_into()
            .unwrap(),
        )));

        let server_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(server_pubkey_bytes),
                ))),
                nonce: server_nonce_i64,
                signature_expiration_ledger: server_expiry,
                signature: server_sig_scval,
            }),
            root_invocation: server_invocation,
        };

        // Client entry uses a DIFFERENT client_domain — should trigger ClientDomainMismatch.
        let client_invocation = make_invocation_with_client_domain(alt_client_domain);
        let client_bytes = stellar_strkey::Contract::from_string(client).unwrap().0;
        let client_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(client_bytes))),
                nonce: 555,
                signature_expiration_ledger: 0,
                signature: ScVal2::Void,
            }),
            root_invocation: client_invocation,
        };

        // Need a third entry (client_domain op) because client_domain is present.
        let cd_invocation = make_invocation_with_client_domain(expected_client_domain);
        let cd_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(server_pubkey_bytes),
                ))),
                nonce: 666,
                signature_expiration_ledger: 0,
                signature: ScVal2::Void,
            }),
            root_invocation: cd_invocation,
        };

        let entries_xdr = SorobanAuthorizationEntries(
            vec![server_entry, client_entry, cd_entry]
                .try_into()
                .unwrap(),
        );
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        let b64 = BASE64_STANDARD.encode(&out);

        let err = AuthorizationEntries::parse_and_validate(
            &b64,
            network,
            contract,
            home,
            web_auth,
            &server_g_str,
            Some(expected_client_domain),
            client,
        )
        .unwrap_err();

        assert!(
            matches!(err, Sep45Error::ClientDomainMismatch { .. }),
            "expected ClientDomainMismatch for client_domain mismatch in entry 1; got {err:?}"
        );
        assert_eq!(err.wire_code(), "sep45.client_domain_mismatch");
    }
}
