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
        Self::new_at(capacity, refill_per_second, Instant::now())
    }

    fn new_at(capacity: f64, refill_per_second: f64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            last_refill: now,
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
        self.try_acquire_at(Instant::now())
    }

    fn try_acquire_at(&mut self, now: Instant) -> bool {
        self.refill_at(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill_at(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last_refill);
        self.last_refill = now;
        let added = elapsed.as_secs_f64() * self.refill_per_second;
        self.tokens = (self.tokens + added).min(self.capacity);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test-only")]
    use std::time::Duration;

    use super::*;

    #[test]
    fn allows_up_to_capacity_then_refuses() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new_at(3.0, 1000.0, now);
        assert!(bucket.try_acquire_at(now));
        assert!(bucket.try_acquire_at(now));
        assert!(bucket.try_acquire_at(now));
        assert!(
            !bucket.try_acquire_at(now),
            "a fourth immediate acquire must be refused once capacity is exhausted"
        );
    }

    #[test]
    fn refills_over_time() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new_at(3.0, 1000.0, start);
        for _ in 0..3 {
            assert!(bucket.try_acquire_at(start));
        }
        assert!(
            !bucket.try_acquire_at(start),
            "bucket must be empty immediately after burst"
        );
        let refilled_at = start + Duration::from_millis(20);
        assert!(
            bucket.try_acquire_at(refilled_at),
            "bucket must have refilled after 20 milliseconds"
        );
        assert!(bucket.try_acquire_at(refilled_at));
        assert!(bucket.try_acquire_at(refilled_at));
        assert!(
            !bucket.try_acquire_at(refilled_at),
            "refill must stop at capacity"
        );
    }

    #[test]
    fn default_bucket_allows_a_reasonable_burst() {
        let mut bucket = TokenBucket::default();
        let now = bucket.last_refill;
        let mut allowed = 0;
        for _ in 0..(BUCKET_CAPACITY as usize + 5) {
            if bucket.try_acquire_at(now) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, BUCKET_CAPACITY as usize);
    }
}
