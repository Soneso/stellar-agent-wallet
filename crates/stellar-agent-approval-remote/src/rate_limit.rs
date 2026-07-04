//! A minimal in-process token bucket bounding concurrent unauthenticated
//! login attempts.
//!
//! The remote-approval listener's pre-authentication endpoints (the login
//! page and login-challenge mint) are reachable by anyone who can route to
//! the bound address, before any WebAuthn assertion is checked. This bucket
//! is a cheap, dependency-free backstop against a naive flood of mint
//! requests; it is deliberately not a substitute for per-IP connection
//! limiting or a firewall, which stay an operator responsibility
//! (documented in the remote-approval onboarding guide).

use std::time::Instant;

/// Maximum tokens the bucket holds (burst size).
const BUCKET_CAPACITY: f64 = 20.0;

/// Tokens replenished per second.
const REFILL_PER_SECOND: f64 = 2.0;

/// A single-bucket, non-keyed token-bucket limiter.
///
/// Not keyed per source IP: this is process-wide, cheap, dependency-free
/// hardening against a single flooding client — not a fairness mechanism
/// across many distinct legitimate operators (remote approval targets a
/// single-operator deployment; see the profile's `RemoteApprovalConfig`
/// design). Operators expecting multiple distinct source IPs should also
/// apply firewall-level per-IP limiting.
pub struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    refill_per_second: f64,
}

impl Default for TokenBucket {
    fn default() -> Self {
        Self::new(BUCKET_CAPACITY, REFILL_PER_SECOND)
    }
}

impl TokenBucket {
    /// Constructs a bucket with the given capacity and refill rate, starting
    /// full.
    #[must_use]
    pub fn new(capacity: f64, refill_per_second: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            capacity,
            refill_per_second,
        }
    }

    /// Attempts to consume one token.
    ///
    /// Returns `true` (and consumes a token) if at least one was available
    /// after refilling for elapsed time; `false` if the bucket is empty —
    /// the caller should reject the request (e.g. `429 Too Many Requests`).
    pub fn try_acquire(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        self.last_refill = now;
        let added = elapsed.as_secs_f64() * self.refill_per_second;
        self.tokens = (self.tokens + added).min(self.capacity);
    }
}

/// Test-only refill-rate override, kept separate from [`TokenBucket::new`]'s
/// public constructor purely so production call sites always use
/// [`TokenBucket::default`] and never accidentally configure a weaker cap.
#[cfg(test)]
fn fast_test_bucket() -> TokenBucket {
    TokenBucket::new(3.0, 1000.0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test-only")]
    use super::*;

    #[test]
    fn allows_up_to_capacity_then_refuses() {
        let mut bucket = TokenBucket::new(3.0, 0.0); // no refill during the test
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(
            !bucket.try_acquire(),
            "a fourth immediate acquire must be refused once capacity is exhausted"
        );
    }

    #[test]
    fn refills_over_time() {
        let mut bucket = fast_test_bucket();
        for _ in 0..3 {
            assert!(bucket.try_acquire());
        }
        assert!(
            !bucket.try_acquire(),
            "bucket must be empty immediately after burst"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(
            bucket.try_acquire(),
            "bucket must have refilled at least one token after a short wait"
        );
    }

    #[test]
    fn default_bucket_allows_a_reasonable_burst() {
        let mut bucket = TokenBucket::default();
        let mut allowed = 0;
        for _ in 0..(BUCKET_CAPACITY as usize + 5) {
            if bucket.try_acquire() {
                allowed += 1;
            }
        }
        assert_eq!(allowed, BUCKET_CAPACITY as usize);
    }
}
