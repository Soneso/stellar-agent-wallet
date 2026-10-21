//! Shared writer for v2 counterparty cache files.
//!
//! A v2 file holds the HMAC-SHA-256 tag over the context label and the
//! payload, followed by the payload. The payload holds the home domain length
//! (u16), the home domain, the fetch time in UNIX seconds (i64), the body
//! length (u32), and the body. Every integer is big-endian.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stellar_agent_core::profile::schema::KeyringEntryRef;
use stellar_agent_network::counterparty::cache::cache_file_path;

/// HMAC context label of the v2 cache format.
const CONTEXT_LABEL: &[u8] = b"stellar-agent-counterparty/v2/stellar-toml-body\x00";

/// Cache key [`plant_cache_entry`] stores for the profile.
const PLANTED_KEY: [u8; 32] = [0xAB; 32];

/// Returns the bytes of a v2 cache file sealed under `key`.
pub(crate) fn v2_cache_file_bytes(
    key: &[u8; 32],
    home_domain: &str,
    fetched_at_unix_s: i64,
    body: &[u8],
) -> Vec<u8> {
    use hmac::{KeyInit as _, Mac as _};

    let domain = home_domain.as_bytes();
    let mut payload = Vec::new();
    payload.extend_from_slice(&u16::try_from(domain.len()).unwrap().to_be_bytes());
    payload.extend_from_slice(domain);
    payload.extend_from_slice(&fetched_at_unix_s.to_be_bytes());
    payload.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    payload.extend_from_slice(body);
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    mac.update(CONTEXT_LABEL);
    mac.update(&payload);
    let mut bytes = mac.finalize().into_bytes().to_vec();
    bytes.extend_from_slice(&payload);
    bytes
}

/// Stores a fixed cache key for `profile` and writes a signed entry for
/// `home_domain` at the resolver's cache path, fetched `age` before now.
///
/// The fetch time is recorded in whole seconds, as the cache format stores
/// it; the return value is that recorded time.
pub(crate) fn plant_cache_entry(
    profile: &str,
    cache_dir: &Path,
    home_domain: &str,
    body: &str,
    age: Duration,
) -> SystemTime {
    use base64::Engine as _;

    let reference = KeyringEntryRef::default_counterparty_key(profile);
    keyring_core::Entry::new(&reference.service, &reference.account)
        .unwrap()
        .set_password(&base64::engine::general_purpose::STANDARD.encode(PLANTED_KEY))
        .unwrap();
    let fetched_at_unix_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .saturating_sub(age)
        .as_secs();
    let bytes = v2_cache_file_bytes(
        &PLANTED_KEY,
        home_domain,
        i64::try_from(fetched_at_unix_s).unwrap(),
        body.as_bytes(),
    );
    std::fs::write(cache_file_path(cache_dir, home_domain), bytes).unwrap();
    UNIX_EPOCH + Duration::from_secs(fetched_at_unix_s)
}
