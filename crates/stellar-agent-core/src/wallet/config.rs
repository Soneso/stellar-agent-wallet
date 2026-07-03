//! `MlockRequired` configuration enum for the short-in-memory-unlock window.
//!
//! Provides [`MlockRequired`] — the typed form of the TOML profile field
//! `wallet.mlock_required = true | false | "warn"`.  Platform defaults differ:
//! Linux and macOS default to `True` (fail-closed); Windows defaults to `Warn`
//! (degraded-but-operable) because `VirtualLock` semantics on Windows impose
//! tighter per-process quotas that operators are less likely to have tuned.
//!
//! # TOML serialisation shape
//!
//! The TOML field accepts three shapes:
//!
//! ```toml
//! wallet.mlock_required = true      # → MlockRequired::True
//! wallet.mlock_required = false     # → MlockRequired::False
//! wallet.mlock_required = "warn"    # → MlockRequired::Warn
//! ```
//!
//! The boolean forms (`true` / `false`) follow TOML native boolean syntax.
//! The `"warn"` form is a TOML string.  The custom deserialiser
//! `MlockRequiredVisitor` handles both shapes via `serde::de::Visitor`.

use serde::{Deserialize, Deserializer, Serialize, de};

/// The `wallet.mlock_required` profile-config posture.
///
/// Controls how the wallet responds when the operating system refuses the
/// `mlock(2)` (POSIX) or `VirtualLock` (Windows) memory-pinning call at
/// unlock time.
///
/// # Platform defaults
///
/// | Platform | Default |
/// |----------|---------|
/// | Linux | `True` |
/// | macOS | `True` |
/// | Windows | `Warn` |
/// | Other | `True` |
///
/// # TOML field
///
/// ```toml
/// [wallet]
/// mlock_required = true       # fail-closed (default on Linux/macOS)
/// mlock_required = "warn"     # degraded-but-operable (default on Windows)
/// mlock_required = false      # no lock attempted (operator opt-out)
/// ```
///
/// # Examples
///
/// ```
/// use stellar_agent_core::wallet::MlockRequired;
///
/// // The default on the current platform:
/// let default_posture = MlockRequired::default();
///
/// // Round-trip through TOML strings:
/// let as_json = serde_json::to_string(&MlockRequired::True).unwrap();
/// assert_eq!(as_json, "true");
///
/// let warn: MlockRequired = serde_json::from_str(r#""warn""#).unwrap();
/// assert_eq!(warn, MlockRequired::Warn);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MlockRequired {
    /// `mlock` failure → typed `WalletLifecycleError::MlockUnavailable` (default
    /// on Linux and macOS).
    ///
    /// The wallet refuses to start the unlock window if the OS refuses to pin
    /// the seed bytes in RAM.  Operators must either raise `RLIMIT_MEMLOCK` or
    /// opt into `Warn` mode.
    True,

    /// `mlock` failure → unprotected memory + structured audit-log entry
    /// (default on Windows; opt-in elsewhere).
    ///
    /// The wallet proceeds with the unlock window even if memory pinning fails,
    /// but emits a `tracing::warn!` with the structured fields `profile`,
    /// `reason`, and `errno`.  The MCP server layer wires the
    /// `EventKind::WalletMlockFailed` audit-log entry; this layer's
    /// responsibility is the `tracing::warn!` emission.
    ///
    /// Every degradation event is visible in the hash-chained audit log so the
    /// forensic record is complete.
    Warn,

    /// `mlock` is not attempted at all (operator opt-out).
    ///
    /// Use only on platforms where memory locking is unavailable AND the
    /// operator explicitly accepts the residual T6 swap-disclosure risk.
    /// The opt-out is recorded in the hash-chained audit log at wallet startup.
    False,
}

impl Default for MlockRequired {
    // Manual impl required because the default differs by platform (True on
    // Linux/macOS, Warn on Windows).  `#[derive(Default)]` does not support
    // platform-conditional defaults; suppressing the clippy lint is the correct
    // approach here.
    #[allow(clippy::derivable_impls, reason = "platform-conditional default")]
    fn default() -> Self {
        // Windows defaults to Warn because VirtualLock quotas are tighter and
        // less likely to be tuned by operators out-of-box.  All other platforms
        // (Linux, macOS, BSD, etc.) default to True (fail-closed).
        #[cfg(target_os = "windows")]
        {
            Self::Warn
        }
        #[cfg(not(target_os = "windows"))]
        {
            Self::True
        }
    }
}

// ── Custom deserialiser ───────────────────────────────────────────────────────
//
// TOML / JSON can represent this field as a native boolean (true / false) OR
// as the string "warn".  serde's standard enum deserialiser does not handle
// that mixed shape, so we implement a custom visitor.
//
// The Serialize impl above handles the reverse direction: True → true (JSON
// boolean), Warn → "warn" (JSON string), False → false (JSON boolean).
// However, `#[serde(rename = "true")]` on an enum variant only affects string
// tag serialisation, not native boolean serialisation.  To emit proper JSON
// booleans we implement Serialize manually below.

impl Serialize for MlockRequired {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::True => serializer.serialize_bool(true),
            Self::Warn => serializer.serialize_str("warn"),
            Self::False => serializer.serialize_bool(false),
        }
    }
}

impl<'de> Deserialize<'de> for MlockRequired {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(MlockRequiredVisitor)
    }
}

/// Visitor that accepts native booleans (`true`/`false`) or the string
/// `"warn"` when deserialising [`MlockRequired`].
struct MlockRequiredVisitor;

impl de::Visitor<'_> for MlockRequiredVisitor {
    type Value = MlockRequired;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("boolean `true`/`false` or the string \"warn\"")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value {
            Ok(MlockRequired::True)
        } else {
            Ok(MlockRequired::False)
        }
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match value {
            "warn" => Ok(MlockRequired::Warn),
            "true" => Ok(MlockRequired::True),
            "false" => Ok(MlockRequired::False),
            other => Err(de::Error::unknown_variant(
                other,
                &["true", "false", "warn"],
            )),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    use super::*;

    // ── Default per platform ──────────────────────────────────────────────────

    #[test]
    fn default_is_warn_on_windows() {
        // On Windows the fail-closed posture is impractical out-of-box; Warn
        // allows operators to proceed without tuning VirtualLock quotas.
        #[cfg(target_os = "windows")]
        assert_eq!(MlockRequired::default(), MlockRequired::Warn);

        // On Linux/macOS/other the fail-closed posture protects by default.
        #[cfg(not(target_os = "windows"))]
        assert_eq!(MlockRequired::default(), MlockRequired::True);
    }

    // ── Serde round-trips ─────────────────────────────────────────────────────

    #[test]
    fn serde_true_json() {
        // Serialises to JSON boolean `true`.
        let s = serde_json::to_string(&MlockRequired::True).unwrap();
        assert_eq!(s, "true", "True must serialise to JSON boolean true");
        let r: MlockRequired = serde_json::from_str("true").unwrap();
        assert_eq!(r, MlockRequired::True);
    }

    #[test]
    fn serde_false_json() {
        // Serialises to JSON boolean `false`.
        let s = serde_json::to_string(&MlockRequired::False).unwrap();
        assert_eq!(s, "false", "False must serialise to JSON boolean false");
        let r: MlockRequired = serde_json::from_str("false").unwrap();
        assert_eq!(r, MlockRequired::False);
    }

    #[test]
    fn serde_warn_json() {
        // Serialises to the JSON string "warn".
        let s = serde_json::to_string(&MlockRequired::Warn).unwrap();
        assert_eq!(
            s, r#""warn""#,
            "Warn must serialise to JSON string \"warn\""
        );
        let r: MlockRequired = serde_json::from_str(r#""warn""#).unwrap();
        assert_eq!(r, MlockRequired::Warn);
    }

    #[test]
    fn serde_invalid_string_rejected() {
        // An unrecognised string value must fail deserialisation with a typed error.
        let err = serde_json::from_str::<MlockRequired>(r#""strict""#);
        assert!(
            err.is_err(),
            "unrecognised string \"strict\" must be rejected"
        );
    }

    #[test]
    fn serde_invalid_number_rejected() {
        // Integers are not a valid representation.
        let err = serde_json::from_str::<MlockRequired>("1");
        assert!(err.is_err(), "integer 1 must be rejected");
    }

    #[test]
    fn toml_true_roundtrip() {
        // TOML native boolean `true` must round-trip.
        #[derive(serde::Serialize, serde::Deserialize, Debug)]
        struct Wrapper {
            mlock_required: MlockRequired,
        }
        let toml_str = "mlock_required = true\n";
        let w: Wrapper = toml::from_str(toml_str).unwrap();
        assert_eq!(w.mlock_required, MlockRequired::True);
        let back = toml::to_string(&w).unwrap();
        assert!(
            back.contains("true"),
            "round-tripped TOML must contain 'true': {back}"
        );
    }

    #[test]
    fn toml_false_roundtrip() {
        #[derive(serde::Serialize, serde::Deserialize, Debug)]
        struct Wrapper {
            mlock_required: MlockRequired,
        }
        let toml_str = "mlock_required = false\n";
        let w: Wrapper = toml::from_str(toml_str).unwrap();
        assert_eq!(w.mlock_required, MlockRequired::False);
        let back = toml::to_string(&w).unwrap();
        assert!(
            back.contains("false"),
            "round-tripped TOML must contain 'false': {back}"
        );
    }

    #[test]
    fn toml_warn_roundtrip() {
        #[derive(serde::Serialize, serde::Deserialize, Debug)]
        struct Wrapper {
            mlock_required: MlockRequired,
        }
        let toml_str = r#"mlock_required = "warn""#;
        let w: Wrapper = toml::from_str(toml_str).unwrap();
        assert_eq!(w.mlock_required, MlockRequired::Warn);
        let back = toml::to_string(&w).unwrap();
        assert!(
            back.contains("warn"),
            "round-tripped TOML must contain 'warn': {back}"
        );
    }

    #[test]
    fn toml_invalid_string_rejected() {
        #[derive(serde::Serialize, serde::Deserialize, Debug)]
        struct Wrapper {
            mlock_required: MlockRequired,
        }
        let toml_str = r#"mlock_required = "enabled""#;
        let err = toml::from_str::<Wrapper>(toml_str);
        assert!(
            err.is_err(),
            "unrecognised string 'enabled' must be rejected"
        );
    }

    #[test]
    fn clone_and_copy() {
        let a = MlockRequired::True;
        let b = a; // Copy
        let c = a; // Copy again
        assert_eq!(b, c);
        assert_eq!(a, MlockRequired::True);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", MlockRequired::True), "True");
        assert_eq!(format!("{:?}", MlockRequired::Warn), "Warn");
        assert_eq!(format!("{:?}", MlockRequired::False), "False");
    }
}
