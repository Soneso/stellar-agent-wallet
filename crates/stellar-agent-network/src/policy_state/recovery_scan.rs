//! Contiguous paired ledger evidence, bounded by the committed release.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use stellar_rpc_client::GetLedgersResponse;

use super::recovery_run::RecoveryStopReason as Reason;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryScan {
    pub configuration: String,
    pub next_unread: u32,
    pub preceding_close: Option<u64>,
    pub digest: String,
    pub end: Option<(u32, u64)>,
}

impl RecoveryScan {
    pub fn new(configuration: String, exposure: &str, start: u32) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"stellar-agent/recovery-scan/v1\0");
        hash.update(exposure.as_bytes());
        hash.update(start.to_be_bytes());
        Self {
            configuration,
            next_unread: start,
            preceding_close: None,
            digest: stellar_agent_core::hex::encode(&hash.finalize()),
            end: None,
        }
    }

    pub fn valid(&self, start: Option<u32>, release: Option<u32>, max_time: u64) -> bool {
        let (Some(start), Some(release)) = (start, release) else {
            return false;
        };
        let digest = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        };
        digest(&self.configuration)
            && digest(&self.digest)
            && start > 0
            && start <= release
            && self.next_unread >= start
            && self.preceding_close.is_none_or(|c| c > 0)
            && (self.preceding_close.is_none() == (self.next_unread == start))
            && match self.end {
                Some((end, close)) => {
                    end >= start
                        && end <= release
                        && close > max_time
                        && self.preceding_close == Some(close)
                        && end.checked_add(1) == Some(self.next_unread)
                }
                None => {
                    self.next_unread <= release
                        && self.preceding_close.is_none_or(|c| c <= max_time)
                }
            }
    }

    pub fn accept(&mut self, closes: [u64; 2], max_time: u64) -> Result<(), Reason> {
        if closes[0] != closes[1] {
            return Err(Reason::Disagreement);
        }
        let close = closes[0];
        if close == 0
            || self
                .preceding_close
                .is_some_and(|previous| close < previous)
        {
            return Err(Reason::MissingField);
        }
        let next = self
            .next_unread
            .checked_add(1)
            .ok_or(Reason::MissingField)?;
        let mut hash = Sha256::new();
        hash.update(self.digest.as_bytes());
        hash.update(self.next_unread.to_be_bytes());
        hash.update(close.to_be_bytes());
        self.digest = stellar_agent_core::hex::encode(&hash.finalize());
        if close > max_time {
            self.end = Some((self.next_unread, close));
        }
        self.next_unread = next;
        self.preceding_close = Some(close);
        Ok(())
    }
}

pub(super) fn ledger(page: &GetLedgersResponse, next: u32, tip: u32) -> Result<u64, Reason> {
    if page.oldest_ledger > next {
        return Err(Reason::HistoryLost);
    }
    if page.latest_ledger < tip || page.latest_ledger < next {
        return Err(Reason::Lagging);
    }
    if page.oldest_ledger == 0 || page.ledgers.len() != 1 || page.ledgers[0].sequence != next {
        return Err(Reason::MissingField);
    }
    page.ledgers[0]
        .ledger_close_time
        .parse::<u64>()
        .ok()
        .filter(|close| *close > 0 && close.checked_mul(1_000).is_some())
        .ok_or(Reason::MissingField)
}

#[cfg(test)]
mod tests;
