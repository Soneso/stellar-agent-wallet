//! Witness digest byte layout, version 1.
//!
//! SHA-256 starts with `b"stellar-agent/cross-check/v1\0"`.
//! Observations follow in ascending explicit `WitnessEntry` tag order.
//! Equal kinds retain input field order, including the pool's channel order.
//! Each observation contributes its one-byte tag and length-prefixed `LedgerKey` XDR.
//! Lengths are u32 big-endian; signed i64 and unsigned u32 fields are big-endian.
//! Options use a zero byte for absence or a one byte followed by their value.
//! Strings use a u32 byte length followed by UTF-8 bytes; booleans use one byte.
//! Accounts encode presence, sequence, native balance, subentry count, and optional flags.
//! Flags encode required, revocable, immutable, and clawback booleans in that order.
//! Trustlines encode presence followed by balance, limit, and raw u32 flags.
//! Destinations encode presence, optional home domain, and optional flags.
//! Issuers encode presence and optional flags; memo observations encode one boolean.
//! Claimable balances encode presence and length-prefixed complete entry XDR.
//! Absent pool channels encode a zero presence byte.

use super::{
    classic::{Observation, Observed},
    inputs::invalid_observation,
};
use crate::account::AccountFlagsView;
use sha2::{Digest, Sha256};
use stellar_agent_core::error::WalletError;
use stellar_xdr::{Limits, WriteXdr};

fn bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), WalletError> {
    let len = u32::try_from(value.len()).map_err(|_| invalid_observation())?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn flags(out: &mut Vec<u8>, value: &Option<AccountFlagsView>) {
    out.push(u8::from(value.is_some()));
    if let Some(value) = value {
        out.extend([
            u8::from(value.auth_required),
            u8::from(value.auth_revocable),
            u8::from(value.auth_immutable),
            u8::from(value.auth_clawback_enabled),
        ]);
    }
}

pub(super) fn inputs_digest(observations: &[Observation]) -> Result<[u8; 32], WalletError> {
    let mut out = b"stellar-agent/cross-check/v1\0".to_vec();
    for observation in observations {
        out.push(observation.kind as u8);
        bytes(
            &mut out,
            &observation
                .key
                .to_xdr(Limits::none())
                .map_err(|_| invalid_observation())?,
        )?;
        match &observation.value {
            Observed::Account(v) => {
                out.push(1);
                out.extend_from_slice(&v.sequence.to_be_bytes());
                out.extend_from_slice(&v.native_balance.to_be_bytes());
                out.extend_from_slice(&v.subentry_count.to_be_bytes());
                flags(&mut out, &v.flags);
            }
            Observed::Trustline(v) => {
                out.push(u8::from(v.state.is_some()));
                if let Some((balance, limit, flags)) = v.state {
                    out.extend_from_slice(&balance.to_be_bytes());
                    out.extend_from_slice(&limit.to_be_bytes());
                    out.extend_from_slice(&flags.to_be_bytes());
                }
            }
            Observed::Destination(v) => {
                out.push(u8::from(v.present.is_some()));
                if let Some((home_domain, account_flags)) = &v.present {
                    out.push(u8::from(home_domain.is_some()));
                    if let Some(domain) = home_domain {
                        bytes(&mut out, domain.as_bytes())?;
                    }
                    flags(&mut out, account_flags);
                }
            }
            Observed::Issuer(v) => {
                out.push(u8::from(v.flags.is_some()));
                if let Some(value) = &v.flags {
                    flags(&mut out, value);
                }
            }
            Observed::Claimable(v) => {
                out.push(u8::from(v.entry.is_some()));
                if let Some(entry) = &v.entry {
                    bytes(
                        &mut out,
                        &entry
                            .to_xdr(Limits::none())
                            .map_err(|_| invalid_observation())?,
                    )?;
                }
            }
            Observed::Memo(value) => out.push(u8::from(*value)),
            Observed::Absent => out.push(0),
        }
    }
    Ok(Sha256::digest(out).into())
}
