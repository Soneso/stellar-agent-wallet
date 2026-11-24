//! The single-use enrollment code of a signed-origin enrollment.
//!
//! A signed-origin enrollment page is reachable by anyone who can reach the
//! listener, so the browser first proves that its operator reads the
//! terminal. The terminal shows eight decimal digits drawn from the OS random
//! source. The page posts them once to `POST /enroll/code`, and a match opens
//! the enrollment session.
//!
//! The code lives `min(600 seconds, ceremony timeout)` on the session clock
//! and admits five attempts. Four wrong codes followed by the right one
//! succeed. After five wrong codes the sixth attempt exhausts the code,
//! right or wrong, and ends the ceremony. Expiry ends it as well. A code
//! that opens a session never matches again.

use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore as _};
use subtle::ConstantTimeEq as _;

/// The number of decimal digits of an enrollment code.
pub(crate) const CODE_DIGITS: usize = 8;

/// The longest lifetime of an enrollment code.
pub(crate) const CODE_LIFETIME_MAX: Duration = Duration::from_secs(600);

/// The number of wrong codes an enrollment code tolerates. The attempt
/// after the last tolerated wrong code exhausts it.
pub(crate) const CODE_ATTEMPTS: u32 = 5;

/// The lifetime of the code of a ceremony with `timeout`.
#[must_use]
pub(crate) fn code_lifetime(timeout: Duration) -> Duration {
    timeout.min(CODE_LIFETIME_MAX)
}

/// The answer to one submitted code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CodeAttempt {
    /// The code matches; it is now spent.
    Accepted,
    /// The code does not match, or the code is already spent.
    Refused,
    /// The attempt limit is reached; the ceremony ends.
    Exhausted,
    /// The code's lifetime is over; the ceremony ends.
    Expired,
}

/// One enrollment code and its attempt count.
///
/// `Debug` redacts the digits, so no log line or debug output carries them.
pub(crate) struct EnrollmentCode {
    digits: [u8; CODE_DIGITS],
    expires_at: Instant,
    wrong: u32,
    spent: bool,
}

impl EnrollmentCode {
    /// A fresh code from the OS random source, valid from `now` for
    /// `lifetime`.
    pub(crate) fn generate(now: Instant, lifetime: Duration) -> Self {
        let mut digits = [0u8; CODE_DIGITS];
        for digit in &mut digits {
            *digit = b'0' + uniform_digit();
        }
        Self::from_digits(digits, now + lifetime)
    }

    /// A code with the given ASCII digits and expiry.
    pub(crate) fn from_digits(digits: [u8; CODE_DIGITS], expires_at: Instant) -> Self {
        Self {
            digits,
            expires_at,
            wrong: 0,
            spent: false,
        }
    }

    /// The digits, for the terminal.
    pub(crate) fn digits(&self) -> &str {
        std::str::from_utf8(&self.digits).unwrap_or_default()
    }

    /// When the code expires.
    pub(crate) fn expires_at(&self) -> Instant {
        self.expires_at
    }

    /// Whether the code has opened a session and matches no more.
    #[cfg(test)]
    pub(crate) fn is_spent(&self) -> bool {
        self.spent
    }

    /// Answers `submitted` at `now`.
    ///
    /// Expiry comes first, then the attempt limit, then the comparison,
    /// which runs in constant time over the eight digits.
    pub(crate) fn attempt(&mut self, submitted: &str, now: Instant) -> CodeAttempt {
        if now >= self.expires_at {
            return CodeAttempt::Expired;
        }
        if self.wrong >= CODE_ATTEMPTS {
            return CodeAttempt::Exhausted;
        }
        let matches = submitted.len() == CODE_DIGITS
            && bool::from(submitted.as_bytes().ct_eq(&self.digits))
            && !self.spent;
        if matches {
            self.spent = true;
            return CodeAttempt::Accepted;
        }
        if !self.spent {
            self.wrong += 1;
        }
        CodeAttempt::Refused
    }
}

impl std::fmt::Debug for EnrollmentCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentCode").finish_non_exhaustive()
    }
}

/// One decimal digit, uniform by rejection sampling over OS random bytes.
fn uniform_digit() -> u8 {
    loop {
        let mut byte = [0u8; 1];
        OsRng.fill_bytes(&mut byte);
        // 250 is the largest multiple of 10 that fits a byte.
        if byte[0] < 250 {
            return byte[0] % 10;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    const CODE: [u8; CODE_DIGITS] = *b"12345678";

    /// Eight digits, five tolerated wrong codes, single use, and a lifetime
    /// of the timeout capped at ten minutes on a manual clock. Production
    /// generation differs across independent ceremonies and never repeats
    /// one digit throughout.
    #[test]
    fn enrollment_code_admits_five_attempts_and_expires_after_ten_minutes() {
        let start = Instant::now();

        let mut code = EnrollmentCode::from_digits(CODE, start + CODE_LIFETIME_MAX);
        for _ in 0..4 {
            assert_eq!(code.attempt("87654321", start), CodeAttempt::Refused);
        }
        assert_eq!(code.attempt("12345678", start), CodeAttempt::Accepted);
        assert!(code.is_spent());
        assert_eq!(code.attempt("12345678", start), CodeAttempt::Refused);

        for sixth in ["12345678", "87654321"] {
            let mut code = EnrollmentCode::from_digits(CODE, start + CODE_LIFETIME_MAX);
            for _ in 0..5 {
                assert_eq!(code.attempt("00000000", start), CodeAttempt::Refused);
            }
            assert_eq!(code.attempt(sixth, start), CodeAttempt::Exhausted);
            assert_eq!(code.attempt("12345678", start), CodeAttempt::Exhausted);
            assert!(!code.is_spent());
        }

        for (timeout, lifetime) in [(600, 600), (300, 300), (601, 600), (3_600, 600)] {
            assert_eq!(
                code_lifetime(Duration::from_secs(timeout)),
                Duration::from_secs(lifetime)
            );
        }
        for timeout in [600, 300] {
            let lifetime = code_lifetime(Duration::from_secs(timeout));
            let mut code = EnrollmentCode::generate(start, lifetime);
            assert_eq!(code.expires_at(), start + Duration::from_secs(timeout));
            let digits = code.digits().to_owned();
            let mut late = EnrollmentCode::from_digits(
                digits.as_bytes().try_into().unwrap(),
                code.expires_at(),
            );
            assert_eq!(
                late.attempt(&digits, start + lifetime - Duration::from_millis(1)),
                CodeAttempt::Accepted
            );
            assert_eq!(
                code.attempt(&digits, start + lifetime),
                CodeAttempt::Expired
            );
            assert!(!code.is_spent());
        }
        assert_eq!(
            EnrollmentCode::from_digits(CODE, start + Duration::from_secs(1))
                .attempt("1234567", start),
            CodeAttempt::Refused
        );
        assert_eq!(
            format!("{:?}", EnrollmentCode::from_digits(CODE, start)),
            "EnrollmentCode { .. }"
        );

        let drawn: Vec<String> = (0..64)
            .map(|_| {
                EnrollmentCode::generate(start, CODE_LIFETIME_MAX)
                    .digits()
                    .to_owned()
            })
            .collect();
        for digits in &drawn {
            assert_eq!(digits.len(), CODE_DIGITS);
            assert!(digits.bytes().all(|b| b.is_ascii_digit()), "{digits}");
        }
        let distinct: std::collections::BTreeSet<&String> = drawn.iter().collect();
        assert!(
            distinct.len() > 60,
            "independent ceremonies draw independent codes"
        );
        let concatenated: String = drawn.concat();
        assert!(
            !concatenated
                .bytes()
                .all(|b| b == concatenated.as_bytes()[0]),
            "the draw is not one repeated digit"
        );
    }
}
