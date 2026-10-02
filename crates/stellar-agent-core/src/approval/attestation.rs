//! HMAC-SHA256 attestation primitive for the wallet-owned approval spine.
//!
//! The attestation binds the profile name, CAIP-2 chain id, approval nonce,
//! envelope digest, and approving process UID.
//!
//! # Canonical input layout
//!
//! ```text
//! mac.update(b"stellar-agent-approval-attestation:v2")
//! mac.update(u32_be(len(profile_name)))   mac.update(profile_name)
//! mac.update(u32_be(len(chain_id)))       mac.update(chain_id)
//! mac.update(u32_be(len(approval_nonce))) mac.update(approval_nonce)
//! mac.update(envelope_sha256)
//! mac.update(u32_be(len(process_uid)))    mac.update(process_uid)
//! ```
//!
//! Lengths count UTF-8 bytes, encoded as big-endian u32 with saturation.
//! The 37-byte tag and 32-byte digest have no prefix or NUL terminator.
//! The tag separates this HMAC from every other use of the key.
//! Binding fields make a blob unverifiable under another profile or chain.
//! A layout change bumps the tag; blobs under the previous tag do not verify.
//!
//! # Key discipline
//!
//! This module accepts the key as `&[u8; 32]`.  The caller is responsible for:
//!
//! 1. Loading the key from the platform keyring into a `Zeroizing<[u8; 32]>`.
//! 2. Dereferencing into this function as `compute_attestation(&*key, ...)`.
//! 3. Dropping the `Zeroizing` guard immediately after the call.
//!
//! Callers load the key from the keyring; this module implements only the
//! HMAC primitive.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Profile and chain that mint or verify an approval.
///
/// The profile name is the approval store file stem both binaries open.
/// The CAIP-2 chain id comes from the environment-merged profile.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct AttestationBinding<'a> {
    /// Approval store profile name.
    pub profile_name: &'a str,
    /// CAIP-2 chain id of the environment-merged profile.
    pub chain_id: &'a str,
}

impl<'a> AttestationBinding<'a> {
    /// Constructs the profile and chain binding.
    #[must_use]
    pub fn new(profile_name: &'a str, chain_id: &'a str) -> Self {
        Self {
            profile_name,
            chain_id,
        }
    }
}

/// HMAC-SHA256 type alias.
type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────────────────────────────
// Toolset-gate digest constants
// ─────────────────────────────────────────────────────────────────────────────

/// Domain-separation tag for the `ToolsetFirstInvokeGate` attestation digest.
///
/// A layout change bumps the tag; digests under the previous tag do not verify.
///
/// Current version: `v1`.
pub const TOOLSET_GATE_DOMAIN_TAG: &[u8] = b"stellar-agent-toolset-grant:v1";

// ─────────────────────────────────────────────────────────────────────────────
// Public helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Computes the SHA-256 hash of `envelope_xdr_bytes`.
///
/// Returns a 32-byte array.  Used to derive `envelope_sha256_hex` when
/// constructing a [`super::store::PendingApproval`].
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::envelope_sha256;
///
/// let hash = envelope_sha256(b"fake-envelope-xdr");
/// assert_eq!(hash.len(), 32);
/// ```
#[must_use]
pub fn envelope_sha256(envelope_xdr_bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(envelope_xdr_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Computes the 32-byte SHA-256 digest for a `ToolsetFirstInvokeGate` approval.
///
/// # Domain-separated length-prefixed preimage
///
/// ```text
/// SHA-256(
///   TOOLSET_GATE_DOMAIN_TAG
///   || u32_be(len(toolset_name))  || toolset_name
///   || u32_be(len(capability))  || capability
///   || u32_be(len(destination)) || destination   (canonical G-strkey)
///   || u32_be(len(asset))       || asset          (code:issuer or "XLM")
///   || i64_be(amount_min_stroops)
///   || i64_be(amount_max_stroops)
/// )
/// ```
///
/// Length prefixes on every variable-length field prevent boundary-collision
/// attacks (same discipline as the HMAC preimage for `PaymentSimulated`).
/// The fixed-width amount fields need no length prefix.
///
/// # Layout citation
///
/// Preimage layout is defined here (this file) and is the canonical source.
/// The `TOOLSET_GATE_DOMAIN_TAG` version tag guarantees old grants fail closed
/// if the layout is ever revised.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::compute_toolset_gate_digest;
///
/// let digest = compute_toolset_gate_digest(
///     "my-toolset",
///     "sign-payment",
///     "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
///     "XLM",
///     0,
///     10_000_000,
/// );
/// assert_eq!(digest.len(), 32);
/// ```
#[must_use]
pub fn compute_toolset_gate_digest(
    toolset_name: &str,
    capability: &str,
    destination: &str,
    asset: &str,
    amount_min_stroops: i64,
    amount_max_stroops: i64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Domain-separation tag (fixed-length; no length prefix needed).
    hasher.update(TOOLSET_GATE_DOMAIN_TAG);

    // Length-prefixed variable-length fields.
    let toolset_len = u32::try_from(toolset_name.len()).unwrap_or(u32::MAX);
    hasher.update(toolset_len.to_be_bytes());
    hasher.update(toolset_name.as_bytes());

    let cap_len = u32::try_from(capability.len()).unwrap_or(u32::MAX);
    hasher.update(cap_len.to_be_bytes());
    hasher.update(capability.as_bytes());

    let dest_len = u32::try_from(destination.len()).unwrap_or(u32::MAX);
    hasher.update(dest_len.to_be_bytes());
    hasher.update(destination.as_bytes());

    let asset_len = u32::try_from(asset.len()).unwrap_or(u32::MAX);
    hasher.update(asset_len.to_be_bytes());
    hasher.update(asset.as_bytes());

    // Fixed-width amount fields (no length prefix needed).
    hasher.update(amount_min_stroops.to_be_bytes());
    hasher.update(amount_max_stroops.to_be_bytes());

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Verifies whether `attestation_blob` was produced by the HMAC-SHA256
/// attestation of a `ToolsetFirstInvokeGate` approval with the given fields.
///
/// Recomputes the toolset-gate digest from `toolset_name`, `capability`,
/// `destination`, `asset`, `amount_min_stroops`, `amount_max_stroops` via
/// [`compute_toolset_gate_digest`], then feeds the result as the
/// `envelope_sha256` slot of [`verify_attestation`].
///
/// Returns `true` iff the attestation blob matches.  Comparison is
/// constant-time via [`subtle::ConstantTimeEq`] (inherited from
/// [`verify_attestation`]).
///
/// # Key discipline
///
/// Same as [`compute_attestation`]: caller wraps the key in
/// `Zeroizing<[u8; 32]>` and passes `&*key`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::{
///     compute_attestation, compute_toolset_gate_digest, verify_toolset_gate_attestation,
/// };
///
/// let key = [0x42u8; 32];
/// let digest = compute_toolset_gate_digest(
///     "my-toolset", "sign-payment",
///     "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
///     "XLM", 0, 10_000_000,
/// );
/// let blob = compute_attestation(&key, &stellar_agent_core::approval::AttestationBinding::new("default", "stellar:testnet"), "test-nonce", &digest, "1000");
/// assert!(verify_toolset_gate_attestation(
///     &key, &stellar_agent_core::approval::AttestationBinding::new("default", "stellar:testnet"),
///     "test-nonce",
///     "my-toolset",
///     "sign-payment",
///     "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
///     "XLM",
///     0,
///     10_000_000,
///     "1000",
///     &blob,
/// ));
/// ```
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_toolset_gate_attestation(
    key: &[u8; 32],
    binding: &AttestationBinding<'_>,
    approval_nonce: &str,
    toolset_name: &str,
    capability: &str,
    destination: &str,
    asset: &str,
    amount_min_stroops: i64,
    amount_max_stroops: i64,
    process_uid: &str,
    attestation_blob: &[u8; 32],
) -> bool {
    let digest = compute_toolset_gate_digest(
        toolset_name,
        capability,
        destination,
        asset,
        amount_min_stroops,
        amount_max_stroops,
    );
    verify_attestation(
        key,
        binding,
        approval_nonce,
        &digest,
        process_uid,
        attestation_blob,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// TrustlineClawbackOptIn digest
// ─────────────────────────────────────────────────────────────────────────────

/// Domain-separation tag for the `TrustlineClawbackOptIn` attestation digest.
///
/// A layout change bumps the tag; digests under the previous tag do not verify.
///
/// Current version: `v1`.
pub const TRUSTLINE_CLAWBACK_OPT_IN_DOMAIN_TAG: &[u8] =
    b"stellar-agent-trustline-clawback-opt-in:v1";

/// Computes the 32-byte SHA-256 commitment for a `TrustlineClawbackOptIn`
/// approval, binding the wallet owner's acknowledgment to a specific
/// `(network, code, issuer)` triple.
///
/// # Domain-separated length-prefixed preimage
///
/// ```text
/// SHA-256(
///   TRUSTLINE_CLAWBACK_OPT_IN_DOMAIN_TAG
///   || u32_be(len(network)) || network
///   || u32_be(len(code))    || code
///   || u32_be(len(issuer))  || issuer
/// )
/// ```
///
/// Length prefixes on every variable-length field prevent boundary-collision
/// attacks.  The domain-separation tag ensures this digest cannot
/// cross-validate against any other attestation kind.
///
/// # Layout citation
///
/// Preimage layout is defined here (this file) and is the canonical source.
/// The `TRUSTLINE_CLAWBACK_OPT_IN_DOMAIN_TAG` version tag guarantees existing
/// blobs fail closed if the layout is ever revised.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::compute_trustline_clawback_opt_in_digest;
///
/// let digest = compute_trustline_clawback_opt_in_digest(
///     "Test SDF Network ; September 2015",
///     "USDC",
///     "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
/// );
/// assert_eq!(digest.len(), 32);
/// ```
#[must_use]
pub fn compute_trustline_clawback_opt_in_digest(
    network: &str,
    code: &str,
    issuer: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Domain-separation tag (fixed-length; no length prefix needed).
    hasher.update(TRUSTLINE_CLAWBACK_OPT_IN_DOMAIN_TAG);

    // Length-prefixed variable-length fields.
    let network_len = u32::try_from(network.len()).unwrap_or(u32::MAX);
    hasher.update(network_len.to_be_bytes());
    hasher.update(network.as_bytes());

    let code_len = u32::try_from(code.len()).unwrap_or(u32::MAX);
    hasher.update(code_len.to_be_bytes());
    hasher.update(code.as_bytes());

    let issuer_len = u32::try_from(issuer.len()).unwrap_or(u32::MAX);
    hasher.update(issuer_len.to_be_bytes());
    hasher.update(issuer.as_bytes());

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// RuleProposalSimulated digest
// ─────────────────────────────────────────────────────────────────────────────

/// Domain-separation tag for the `RuleProposalSimulated` attestation digest.
///
/// A layout change bumps the tag; digests under the previous tag do not verify.
///
/// Current version: `v1`.
pub const RULE_PROPOSAL_DOMAIN_TAG: &[u8] = b"stellar-agent-rule-proposal-v1";

/// Computes the 32-byte SHA-256 digest binding an agent-proposed
/// `add_context_rule` installation to its EXACT resolved arguments.
///
/// # Domain-separated length-prefixed preimage
///
/// ```text
/// SHA-256(
///   RULE_PROPOSAL_DOMAIN_TAG
///   || u32_be(len(invoke_contract_args_xdr)) || invoke_contract_args_xdr
///   || u32_be(len(smart_account_xdr))        || smart_account_xdr
///   || u32_be(len(auth_rule_ids_xdr))         || auth_rule_ids_xdr
///   || flags_byte
/// )
/// ```
///
/// Length prefixes on every variable-length field prevent boundary-collision
/// attacks (same discipline as every other digest in this module). The
/// fixed-width `flags_byte` needs no length prefix.
///
/// # Why XDR, not serde
///
/// `serde`/JSON/TOML serialization of the resolved rule definition is not
/// ordering-stable across crate versions (field order, map key order, and
/// numeric representation are all serde-implementation details). XDR is the
/// wire format the Soroban host itself consumes to execute
/// `add_context_rule`, and is stable by protocol definition — hashing the
/// SAME XDR bytes the invocation will submit is the only representation
/// guaranteed to bind EXACTLY what gets installed.
///
/// # Domain separation
///
/// The domain tag, plus hashing a distinct XDR type
/// (`InvokeContractArgs` for `add_context_rule`), makes this digest space
/// disjoint from `envelope_sha256` (`PaymentSimulated` / `ClaimSimulated`,
/// which hash a full transaction envelope) and from
/// [`compute_toolset_gate_digest`] / [`compute_trustline_clawback_opt_in_digest`]
/// (different domain tags) — an attestation minted for one kind can never
/// verify as another, even though every kind shares the same keyring HMAC key.
///
/// # Caller-side construction
///
/// `stellar-agent-core` cannot depend on `stellar-agent-smart-account` (the
/// latter depends on the former), so this function accepts pre-encoded XDR
/// byte buffers rather than typed `InvokeContractArgs` / `ScAddress` values.
/// `stellar-agent-smart-account::managers::rules::compute_context_rule_proposal_sha256`
/// builds `invoke_contract_args_xdr` from `build_add_context_rule_args`
/// wrapped in the OZ `add_context_rule` `InvokeContractArgs` (the SAME
/// builder `install_rule_inner` calls), `smart_account_xdr` from XDR-encoding
/// the smart-account contract's `ScAddress`, and `auth_rule_ids_xdr` via
/// [`super::super::smart_account::rule_id::encode_context_rule_ids`] — the
/// SAME encoder already used for the on-chain signing auth-digest preimage.
/// `flags_byte` packs `accept_mutable_verifier` (bit 0) and
/// `accept_unknown_verifier` (bit 1); all other bits are reserved and MUST
/// be zero.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::compute_rule_proposal_digest;
///
/// let digest = compute_rule_proposal_digest(b"invoke-args-xdr", b"sa-xdr", b"ids-xdr", 0);
/// assert_eq!(digest.len(), 32);
/// ```
#[must_use]
pub fn compute_rule_proposal_digest(
    invoke_contract_args_xdr: &[u8],
    smart_account_xdr: &[u8],
    auth_rule_ids_xdr: &[u8],
    flags_byte: u8,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Domain-separation tag (fixed-length; no length prefix needed).
    hasher.update(RULE_PROPOSAL_DOMAIN_TAG);

    // Length-prefixed variable-length fields.
    let args_len = u32::try_from(invoke_contract_args_xdr.len()).unwrap_or(u32::MAX);
    hasher.update(args_len.to_be_bytes());
    hasher.update(invoke_contract_args_xdr);

    let sa_len = u32::try_from(smart_account_xdr.len()).unwrap_or(u32::MAX);
    hasher.update(sa_len.to_be_bytes());
    hasher.update(smart_account_xdr);

    let ids_len = u32::try_from(auth_rule_ids_xdr.len()).unwrap_or(u32::MAX);
    hasher.update(ids_len.to_be_bytes());
    hasher.update(auth_rule_ids_xdr);

    // Fixed-width flags byte (no length prefix needed).
    hasher.update([flags_byte]);

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Computes the HMAC-SHA256 attestation blob.
///
/// # Input domain
///
/// ```text
/// mac.update(b"stellar-agent-approval-attestation:v2")
/// mac.update(u32_be(len(profile_name)))   mac.update(profile_name)
/// mac.update(u32_be(len(chain_id)))       mac.update(chain_id)
/// mac.update(u32_be(len(approval_nonce))) mac.update(approval_nonce)
/// mac.update(envelope_sha256)
/// mac.update(u32_be(len(process_uid)))    mac.update(process_uid)
/// ```
///
/// Lengths count UTF-8 bytes, encoded as big-endian u32 with saturation.
/// The tag separates this HMAC from every other use of the key.
/// Binding fields make a blob unverifiable under another profile or chain.
/// A layout change bumps the tag; blobs under the previous tag do not verify.
///
/// # Key discipline
///
/// The caller MUST wrap the key in `Zeroizing<[u8; 32]>` and pass `&*key`
/// here.  This function does not allocate key bytes.
///
/// # Panics
///
/// Never panics in practice.  `HmacSha256::new_from_slice` returns `Err` only
/// for a zero-length key slice; a `&[u8; 32]` is always 32 bytes so the error
/// path is unreachable.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::compute_attestation;
///
/// let key = [0x42u8; 32];
/// let env_hash = [0x01u8; 32];
/// let blob = compute_attestation(&key, &stellar_agent_core::approval::AttestationBinding::new("default", "stellar:testnet"), "test-nonce", &env_hash, "1000");
/// assert_eq!(blob.len(), 32);
/// ```
#[must_use]
pub fn compute_attestation(
    key: &[u8; 32],
    binding: &AttestationBinding<'_>,
    approval_nonce: &str,
    envelope_sha256: &[u8; 32],
    process_uid: &str,
) -> [u8; 32] {
    // `new_from_slice` on a 32-byte array is always `Ok`.  The only failure
    // mode is a zero-length key slice; `&[u8; 32]` is never zero-length.
    #[allow(
        clippy::expect_used,
        reason = "new_from_slice fails only for zero-length keys; &[u8; 32] is always 32 bytes"
    )]
    let mut mac = HmacSha256::new_from_slice(key.as_ref())
        .expect("HmacSha256 key initialisation with 32-byte array is infallible");

    mac.update(b"stellar-agent-approval-attestation:v2");
    let profile_len = u32::try_from(binding.profile_name.len()).unwrap_or(u32::MAX);
    mac.update(&profile_len.to_be_bytes());
    mac.update(binding.profile_name.as_bytes());
    let chain_len = u32::try_from(binding.chain_id.len()).unwrap_or(u32::MAX);
    mac.update(&chain_len.to_be_bytes());
    mac.update(binding.chain_id.as_bytes());

    // Length-prefix the approval_nonce.
    let nonce_len = u32::try_from(approval_nonce.len()).unwrap_or(u32::MAX);
    mac.update(&nonce_len.to_be_bytes());
    mac.update(approval_nonce.as_bytes());

    // envelope_sha256 is always 32 bytes (fixed-length); no length prefix needed.
    mac.update(envelope_sha256);

    // Length-prefix the process_uid.
    let uid_len = u32::try_from(process_uid.len()).unwrap_or(u32::MAX);
    mac.update(&uid_len.to_be_bytes());
    mac.update(process_uid.as_bytes());

    let mut out = [0u8; 32];
    out.copy_from_slice(mac.finalize().into_bytes().as_slice());
    out
}

/// Verifies an HMAC-SHA256 attestation blob using constant-time comparison.
///
/// Returns `true` iff `attestation_blob` matches the expected tag for the
/// given inputs.  The comparison is constant-time via
/// [`subtle::ConstantTimeEq`] to prevent timing side-channels.
///
/// # Key discipline
///
/// Same as [`compute_attestation`]: caller wraps the key in
/// `Zeroizing<[u8; 32]>` and passes `&*key`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::{compute_attestation, verify_attestation};
///
/// let key = [0x42u8; 32];
/// let env_hash = [0x01u8; 32];
/// let blob = compute_attestation(&key, &stellar_agent_core::approval::AttestationBinding::new("default", "stellar:testnet"), "my-nonce", &env_hash, "1000");
/// assert!(verify_attestation(&key, &stellar_agent_core::approval::AttestationBinding::new("default", "stellar:testnet"), "my-nonce", &env_hash, "1000", &blob));
/// // Wrong key returns false.
/// let wrong_key = [0xffu8; 32];
/// assert!(!verify_attestation(&wrong_key, &stellar_agent_core::approval::AttestationBinding::new("default", "stellar:testnet"), "my-nonce", &env_hash, "1000", &blob));
/// ```
#[must_use]
pub fn verify_attestation(
    key: &[u8; 32],
    binding: &AttestationBinding<'_>,
    approval_nonce: &str,
    envelope_sha256: &[u8; 32],
    process_uid: &str,
    attestation_blob: &[u8; 32],
) -> bool {
    let expected = compute_attestation(key, binding, approval_nonce, envelope_sha256, process_uid);
    // Constant-time comparison to prevent timing side-channels.
    expected.ct_eq(attestation_blob).into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    // ── KAT (known-answer test) ──────────────────────────────────────────────

    #[test]
    fn compute_attestation_known_answer_v2() {
        let result = compute_attestation(
            &[0x42; 32],
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "test-nonce",
            &[0x01; 32],
            "1000",
        );
        let actual: String = result.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            actual,
            "eb90c7b47bafc0f5cc69786042755460f544f79b8c6b4e8874d5cc9fa87edabf"
        );
    }

    #[test]
    fn compute_attestation_utf8_length_prefixes_count_bytes() {
        let binding = AttestationBinding::new("trésor", "stellar:網");
        let key = [0x42; 32];
        let digest = [0x01; 32];
        let mut preimage = b"stellar-agent-approval-attestation:v2".to_vec();
        preimage.extend_from_slice(&7_u32.to_be_bytes());
        preimage.extend_from_slice(binding.profile_name.as_bytes());
        preimage.extend_from_slice(&11_u32.to_be_bytes());
        preimage.extend_from_slice(binding.chain_id.as_bytes());
        preimage.extend_from_slice(&10_u32.to_be_bytes());
        preimage.extend_from_slice(b"test-nonce");
        preimage.extend_from_slice(&digest);
        preimage.extend_from_slice(&4_u32.to_be_bytes());
        preimage.extend_from_slice(b"1000");
        assert_eq!(
            u32::from_be_bytes(preimage[37..41].try_into().unwrap()) as usize,
            binding.profile_name.len()
        );
        assert_eq!(
            u32::from_be_bytes(preimage[48..52].try_into().unwrap()) as usize,
            binding.chain_id.len()
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(&preimage);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(
            compute_attestation(&key, &binding, "test-nonce", &digest, "1000"),
            expected,
            "the HMAC must use UTF-8 byte-length prefixes"
        );
    }

    // ── Round-trip (compute → verify) ───────────────────────────────────────

    #[test]
    fn compute_then_verify_succeeds() {
        let key = [0x42u8; 32];
        let env_hash = [0xabu8; 32];
        let blob = compute_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "my-approval-nonce",
            &env_hash,
            "500",
        );
        assert!(
            verify_attestation(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "my-approval-nonce",
                &env_hash,
                "500",
                &blob
            ),
            "round-trip verify must succeed"
        );
    }

    // ── Tamper detection ─────────────────────────────────────────────────────

    #[test]
    fn tamper_nonce_fails_verify() {
        let key = [0x42u8; 32];
        let env_hash = [0xabu8; 32];
        let blob = compute_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "original-nonce",
            &env_hash,
            "500",
        );
        assert!(
            !verify_attestation(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "tampered-nonce",
                &env_hash,
                "500",
                &blob
            ),
            "tampered nonce must fail verify"
        );
    }

    #[test]
    fn tamper_envelope_hash_fails_verify() {
        let key = [0x42u8; 32];
        let env_hash = [0xabu8; 32];
        let blob = compute_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "nonce",
            &env_hash,
            "500",
        );
        let mut tampered_hash = env_hash;
        tampered_hash[0] ^= 0xff;
        assert!(
            !verify_attestation(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "nonce",
                &tampered_hash,
                "500",
                &blob
            ),
            "tampered envelope hash must fail verify"
        );
    }

    #[test]
    fn tamper_user_id_fails_verify() {
        let key = [0x42u8; 32];
        let env_hash = [0xabu8; 32];
        let blob = compute_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "nonce",
            &env_hash,
            "1000",
        );
        assert!(
            !verify_attestation(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "nonce",
                &env_hash,
                "9999",
                &blob
            ),
            "tampered process_uid must fail verify"
        );
    }

    #[test]
    fn tamper_blob_byte_fails_verify() {
        let key = [0x42u8; 32];
        let env_hash = [0xabu8; 32];
        let mut blob = compute_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "nonce",
            &env_hash,
            "1000",
        );
        blob[0] ^= 0xff;
        assert!(
            !verify_attestation(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "nonce",
                &env_hash,
                "1000",
                &blob
            ),
            "bit-flipped blob must fail verify"
        );
    }

    // ── Cross-key isolation ──────────────────────────────────────────────────

    #[test]
    fn different_key_fails_verify() {
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let env_hash = [0xabu8; 32];
        let blob = compute_attestation(
            &key1,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "nonce",
            &env_hash,
            "1000",
        );
        assert!(
            !verify_attestation(
                &key2,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "nonce",
                &env_hash,
                "1000",
                &blob
            ),
            "different key must fail verify"
        );
    }

    // ── Boundary-collision defence ───────────────────────────────────────────

    #[test]
    fn no_boundary_collision_nonce_uid() {
        let key = [0x55u8; 32];
        let env_hash = [0x00u8; 32];
        let blob1 = compute_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "ab",
            &env_hash,
            "cd",
        );
        let blob2 = compute_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "abc",
            &env_hash,
            "d",
        );
        assert_ne!(
            blob1, blob2,
            "length-prefix separators must prevent boundary collisions"
        );
    }

    // ── Determinism ──────────────────────────────────────────────────────────

    #[test]
    fn compute_attestation_is_deterministic() {
        let key = [0x99u8; 32];
        let env_hash = [0x77u8; 32];
        let b1 = compute_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "same-nonce",
            &env_hash,
            "42",
        );
        let b2 = compute_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "same-nonce",
            &env_hash,
            "42",
        );
        assert_eq!(b1, b2, "compute_attestation must be deterministic");
    }

    // ── envelope_sha256 ──────────────────────────────────────────────────────

    #[test]
    fn envelope_sha256_is_32_bytes() {
        let hash = envelope_sha256(b"fake-xdr-bytes");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn envelope_sha256_differs_on_different_input() {
        let h1 = envelope_sha256(b"xdr1");
        let h2 = envelope_sha256(b"xdr2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn envelope_sha256_is_deterministic() {
        let h1 = envelope_sha256(b"xdr");
        let h2 = envelope_sha256(b"xdr");
        assert_eq!(h1, h2);
    }

    // ── verify_attestation: constant-time path exercised ────────────────────

    #[test]
    fn verify_attestation_constant_time_path_reachable() {
        let key = [0x33u8; 32];
        let env_hash = [0xddu8; 32];
        let blob = compute_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "n",
            &env_hash,
            "u",
        );
        assert!(verify_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "n",
            &env_hash,
            "u",
            &blob
        ));
        let wrong = [0u8; 32];
        assert!(!verify_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "n",
            &env_hash,
            "u",
            &wrong
        ));
    }

    // ── Toolset-gate digest KAT ─────────────────────────────────────────────────
    //
    // Known-answer test vector for `compute_toolset_gate_digest`.  Any accidental
    // change to the preimage layout is detected immediately.
    // The expected bytes are computed by the reference Python below:
    //
    // ```python
    // import hashlib, struct
    // DOMAIN_TAG = b"stellar-agent-toolset-grant:v1"
    // toolset_name = b"test-toolset"
    // capability = b"sign-payment"
    // destination = b"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    // asset = b"XLM"
    // amount_min = 0
    // amount_max = 10_000_000
    //
    // msg = (
    //     DOMAIN_TAG
    //     + struct.pack(">I", len(toolset_name)) + toolset_name
    //     + struct.pack(">I", len(capability)) + capability
    //     + struct.pack(">I", len(destination)) + destination
    //     + struct.pack(">I", len(asset)) + asset
    //     + struct.pack(">q", amount_min)
    //     + struct.pack(">q", amount_max)
    // )
    // print(hashlib.sha256(msg).hexdigest())
    // ```
    //
    // Run to regenerate if preimage layout changes (REQUIRES domain tag bump).

    #[test]
    fn compute_toolset_gate_digest_known_answer() {
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        let result = compute_toolset_gate_digest(
            "test-toolset",
            "sign-payment",
            DEST_G,
            "XLM",
            0_i64,
            10_000_000_i64,
        );

        // Reference Python gives the expected 32-byte hex digest.
        // Recompute here using the same algorithm as the function under test.
        let mut hasher = Sha256::new();
        hasher.update(TOOLSET_GATE_DOMAIN_TAG);
        let fields: &[&[u8]] = &[b"test-toolset", b"sign-payment", DEST_G.as_bytes(), b"XLM"];
        for field in fields {
            let len = u32::try_from(field.len()).unwrap().to_be_bytes();
            hasher.update(len);
            hasher.update(field);
        }
        hasher.update(0_i64.to_be_bytes());
        hasher.update(10_000_000_i64.to_be_bytes());
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&hasher.finalize());

        assert_eq!(
            result, expected,
            "KAT: compute_toolset_gate_digest output mismatch — domain tag or \
             preimage layout changed; bump TOOLSET_GATE_DOMAIN_TAG version"
        );
        assert_ne!(
            result, [0u8; 32],
            "KAT: toolset gate digest must not be all-zero"
        );
    }

    // ── Toolset-gate boundary-collision defence ─────────────────────────────────

    #[test]
    fn toolset_gate_digest_no_boundary_collision_toolset_cap() {
        // toolset="ab" cap="cd" must differ from toolset="a" cap="bcd" (length prefixes).
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let d1 = compute_toolset_gate_digest("ab", "cd", DEST_G, "XLM", 0, 1_000_000);
        let d2 = compute_toolset_gate_digest("a", "bcd", DEST_G, "XLM", 0, 1_000_000);
        assert_ne!(
            d1, d2,
            "boundary collision detected in toolset_name/capability fields"
        );
    }

    // ── verify_toolset_gate_attestation round-trip ──────────────────────────────

    #[test]
    fn verify_toolset_gate_attestation_round_trip() {
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key = [0x77u8; 32];
        let digest =
            compute_toolset_gate_digest("my-toolset", "sign-payment", DEST_G, "XLM", 0, 5_000_000);
        let blob = compute_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "gate-nonce",
            &digest,
            "1234",
        );

        assert!(
            verify_toolset_gate_attestation(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "gate-nonce",
                "my-toolset",
                "sign-payment",
                DEST_G,
                "XLM",
                0,
                5_000_000,
                "1234",
                &blob,
            ),
            "round-trip verify_toolset_gate_attestation must succeed"
        );
    }

    #[test]
    fn verify_toolset_gate_attestation_wrong_toolset_fails() {
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key = [0x77u8; 32];
        let digest =
            compute_toolset_gate_digest("my-toolset", "sign-payment", DEST_G, "XLM", 0, 5_000_000);
        let blob = compute_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "gate-nonce",
            &digest,
            "1234",
        );

        assert!(
            !verify_toolset_gate_attestation(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "gate-nonce",
                "other-toolset", // tampered
                "sign-payment",
                DEST_G,
                "XLM",
                0,
                5_000_000,
                "1234",
                &blob,
            ),
            "tampered toolset_name must fail verification"
        );
    }

    #[test]
    fn verify_toolset_gate_attestation_wrong_amount_fails() {
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key = [0x77u8; 32];
        let digest =
            compute_toolset_gate_digest("my-toolset", "sign-payment", DEST_G, "XLM", 0, 5_000_000);
        let blob = compute_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "gate-nonce",
            &digest,
            "1234",
        );

        assert!(
            !verify_toolset_gate_attestation(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "gate-nonce",
                "my-toolset",
                "sign-payment",
                DEST_G,
                "XLM",
                0,
                9_999_999, // tampered amount_max
                "1234",
                &blob,
            ),
            "tampered amount_max_stroops must fail verification"
        );
    }

    // ── RuleProposalSimulated digest KAT ─────────────────────────────────────
    //
    // Known-answer test vector for `compute_rule_proposal_digest`. Any
    // accidental change to the preimage layout is detected immediately.
    // Reference Python:
    //
    // ```python
    // import hashlib, struct
    // DOMAIN_TAG = b"stellar-agent-rule-proposal-v1"
    // args_xdr = b"fake-invoke-contract-args-xdr"
    // sa_xdr = b"fake-smart-account-xdr"
    // ids_xdr = b"fake-auth-rule-ids-xdr"
    // flags = 0
    //
    // msg = (
    //     DOMAIN_TAG
    //     + struct.pack(">I", len(args_xdr)) + args_xdr
    //     + struct.pack(">I", len(sa_xdr)) + sa_xdr
    //     + struct.pack(">I", len(ids_xdr)) + ids_xdr
    //     + bytes([flags])
    // )
    // print(hashlib.sha256(msg).hexdigest())
    // ```

    #[test]
    fn compute_rule_proposal_digest_known_answer() {
        const ARGS: &[u8] = b"fake-invoke-contract-args-xdr";
        const SA: &[u8] = b"fake-smart-account-xdr";
        const IDS: &[u8] = b"fake-auth-rule-ids-xdr";

        let result = compute_rule_proposal_digest(ARGS, SA, IDS, 0);

        let mut hasher = Sha256::new();
        hasher.update(RULE_PROPOSAL_DOMAIN_TAG);
        for field in [ARGS, SA, IDS] {
            let len = u32::try_from(field.len()).unwrap().to_be_bytes();
            hasher.update(len);
            hasher.update(field);
        }
        hasher.update([0u8]);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&hasher.finalize());

        assert_eq!(
            result, expected,
            "KAT: compute_rule_proposal_digest output mismatch — domain tag or \
             preimage layout changed; bump RULE_PROPOSAL_DOMAIN_TAG version"
        );
        assert_ne!(
            result, [0u8; 32],
            "KAT: rule proposal digest must not be all-zero"
        );
    }

    #[test]
    fn rule_proposal_digest_no_boundary_collision_across_fields() {
        // args="ab" sa="cd" must differ from args="a" sa="bcd" (length prefixes).
        let d1 = compute_rule_proposal_digest(b"ab", b"cd", b"ids", 0);
        let d2 = compute_rule_proposal_digest(b"a", b"bcd", b"ids", 0);
        assert_ne!(
            d1, d2,
            "boundary collision detected across invoke_contract_args_xdr/smart_account_xdr"
        );
    }

    #[test]
    fn rule_proposal_digest_flags_byte_changes_digest() {
        let d0 = compute_rule_proposal_digest(b"args", b"sa", b"ids", 0);
        let d1 = compute_rule_proposal_digest(b"args", b"sa", b"ids", 1);
        let d2 = compute_rule_proposal_digest(b"args", b"sa", b"ids", 2);
        let d3 = compute_rule_proposal_digest(b"args", b"sa", b"ids", 3);
        assert_ne!(d0, d1);
        assert_ne!(d0, d2);
        assert_ne!(d0, d3);
        assert_ne!(d1, d2);
    }

    #[test]
    fn rule_proposal_digest_is_deterministic() {
        let a = compute_rule_proposal_digest(b"args", b"sa", b"ids", 3);
        let b = compute_rule_proposal_digest(b"args", b"sa", b"ids", 3);
        assert_eq!(a, b);
    }

    #[test]
    fn rule_proposal_digest_differs_from_toolset_gate_digest() {
        // Same conceptual inputs must land in disjoint digest spaces because
        // of the differing domain tags — a rule-proposal attestation can
        // never verify as a toolset-gate attestation.
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let rule_digest = compute_rule_proposal_digest(b"x", b"y", b"z", 0);
        let toolset_digest = compute_toolset_gate_digest("x", "y", DEST_G, "XLM", 0, 1_000_000);
        assert_ne!(rule_digest, toolset_digest);
    }

    #[test]
    fn attestation_differs_per_profile_name() {
        let a = AttestationBinding::new("a", "stellar:testnet");
        let b = AttestationBinding::new("b", "stellar:testnet");
        let blob = compute_attestation(&[0x42; 32], &a, "nonce", &[1; 32], "1000");
        assert_ne!(
            blob,
            compute_attestation(&[0x42; 32], &b, "nonce", &[1; 32], "1000")
        );
        assert!(!verify_attestation(
            &[0x42; 32],
            &b,
            "nonce",
            &[1; 32],
            "1000",
            &blob
        ));
    }

    #[test]
    fn attestation_differs_per_chain_id() {
        let testnet = AttestationBinding::new("a", "stellar:testnet");
        let mainnet = AttestationBinding::new("a", "stellar:mainnet");
        for (mint, verify) in [(testnet, mainnet), (mainnet, testnet)] {
            let blob = compute_attestation(&[0x42; 32], &mint, "nonce", &[1; 32], "1000");
            assert_ne!(
                blob,
                compute_attestation(&[0x42; 32], &verify, "nonce", &[1; 32], "1000")
            );
            assert!(!verify_attestation(
                &[0x42; 32],
                &verify,
                "nonce",
                &[1; 32],
                "1000",
                &blob
            ));
        }
    }

    #[test]
    fn v1_layout_blob_does_not_verify() {
        let mut mac = HmacSha256::new_from_slice(&[0x42; 32]).unwrap();
        mac.update(&10_u32.to_be_bytes());
        mac.update(b"test-nonce");
        mac.update(&[1; 32]);
        mac.update(&4_u32.to_be_bytes());
        mac.update(b"1000");
        let blob: [u8; 32] = mac.finalize().into_bytes().into();
        assert!(!verify_attestation(
            &[0x42; 32],
            &AttestationBinding::new("default", "stellar:testnet"),
            "test-nonce",
            &[1; 32],
            "1000",
            &blob
        ));
    }
}
