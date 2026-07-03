//! Typed error surface for toolset format parse and validation failures.
//!
//! [`ToolsetFormatError`] is the closed-set of all distinct refusal reasons returned
//! by [`crate::parse_toolset`].  Every variant carries enough context to surface a
//! useful error message without echoing secret material (toolsets contain no key
//! material, but can contain attacker-controlled strings whose Display output is
//! sanitised to prevent terminal-spoof and log-injection).

use crate::sanitise::sanitise_display;

/// Maximum byte length echoed in rendered error variants that carry
/// attacker-controlled content.  Strings longer than this are truncated.
const ECHO_CAP: usize = 256;

/// All distinct reasons a toolset directory can be refused by [`crate::parse_toolset`].
///
/// The set is closed: a match on `ToolsetFormatError` that is exhaustive today will
/// require an update if new variants are added.  The `#[non_exhaustive]` attribute
/// is intentionally absent — the parity test in this module locks the surface by
/// failing to compile when a variant is added without updating the test.
#[derive(Debug, thiserror::Error)]
pub enum ToolsetFormatError {
    /// The `TOOLSET.md` file could not be read from the toolset directory.
    ///
    /// The `detail` string is the sanitised I/O error message; it never contains
    /// attacker-controlled path contents longer than `ECHO_CAP` bytes.
    #[error("I/O error reading TOOLSET.md: {}", sanitise_display(.detail, ECHO_CAP))]
    Io {
        /// Sanitised I/O error description.
        detail: String,
    },

    /// The `TOOLSET.md` file exceeds the 256 KiB size cap (enforced before parsing).
    #[error("TOOLSET.md is too large: {size} bytes (cap is {cap} bytes)")]
    ToolsetFileTooLarge {
        /// Actual file size in bytes.
        size: u64,
        /// Maximum permitted size in bytes.
        cap: u64,
    },

    /// The `TOOLSET.md` bytes are not valid UTF-8.
    #[error("TOOLSET.md is not valid UTF-8")]
    NotUtf8,

    /// The file does not begin with a `---` YAML frontmatter fence.
    #[error("TOOLSET.md has no frontmatter (file must begin with '---')")]
    MissingFrontmatter,

    /// The YAML inside the frontmatter fence could not be parsed.
    ///
    /// `detail` is the parser's error message (not a file-content snippet).
    #[error("TOOLSET.md frontmatter is malformed YAML: {}", sanitise_display(.detail, ECHO_CAP))]
    MalformedFrontmatter {
        /// Parser error description.
        detail: String,
    },

    /// The frontmatter YAML contains an anchor (`&a`) or alias (`*a`).
    ///
    /// Anchors and aliases are forbidden to prevent alias-expansion DoS
    /// (billion-laughs attack class).  The parser rejects them before any tree
    /// is materialised.
    #[error("TOOLSET.md frontmatter contains YAML anchors or aliases (forbidden)")]
    YamlAnchorsForbidden,

    /// The frontmatter nesting depth exceeds the limit of 8.
    ///
    /// Deeply-nested input is refused before full materialisation to prevent
    /// stack-overflow or runaway recursion during mapping.
    #[error("TOOLSET.md frontmatter nesting exceeds the maximum depth of 8")]
    FrontmatterTooDeep,

    /// A mapping key appears more than once in the frontmatter (at the top level
    /// or inside the `metadata` block).
    ///
    /// Duplicate keys are a common confusion vector: a human reviewer sees one
    /// value while a parser resolves another.  We refuse rather than silently
    /// resolving to first-wins or last-wins.
    #[error("TOOLSET.md frontmatter has a duplicate mapping key: {}", sanitise_display(.key, ECHO_CAP))]
    DuplicateKey {
        /// The key that appeared more than once.
        key: String,
    },

    /// A `metadata` key begins with the reserved prefix `stellar-agent-` but is
    /// not a recognised wallet key.
    ///
    /// Currently the only recognised wallet-reserved key is
    /// `stellar-agent-capabilities`.  Any other `stellar-agent-`-prefixed key is
    /// refused to prevent future collision with wallet-defined extensions.
    #[error(
        "TOOLSET.md metadata key '{}' uses the reserved 'stellar-agent-' prefix",
        sanitise_display(.key, ECHO_CAP)
    )]
    ReservedMetadataKey {
        /// The offending metadata key.
        key: String,
    },

    /// The `name` field is absent from the frontmatter.
    #[error("TOOLSET.md frontmatter is missing the required 'name' field")]
    MissingName,

    /// The `name` field is present but empty.
    #[error("TOOLSET.md 'name' is empty")]
    NameEmpty,

    /// The `name` field exceeds 64 characters.
    #[error("TOOLSET.md 'name' exceeds 64 characters")]
    NameTooLong,

    /// The `name` field contains a character outside `[a-z0-9-]`.
    ///
    /// The agentskills spec's "unicode lowercase alphanumeric" wording is resolved
    /// in favour of the ASCII range it explicitly enumerates (`a-z`, `0-9`).
    /// Non-ASCII characters — including unicode homoglyphs of ASCII letters — are
    /// refused here rather than silently normalised.
    #[error("TOOLSET.md 'name' contains a character outside [a-z0-9-]")]
    NameInvalidChar,

    /// The `name` field starts or ends with a hyphen.
    #[error("TOOLSET.md 'name' must not start or end with a hyphen")]
    NameLeadingTrailingHyphen,

    /// The `name` field contains consecutive hyphens (`--`).
    #[error("TOOLSET.md 'name' must not contain consecutive hyphens ('--')")]
    NameConsecutiveHyphens,

    /// The `name` field does not match the parent directory name (byte-exact).
    ///
    /// Because `name` is constrained to ASCII `[a-z0-9-]` and the comparison is
    /// byte-exact, a unicode-homoglyph directory name (e.g. containing Cyrillic
    /// look-alikes) always fails here rather than matching by visual equivalence.
    #[error(
        "TOOLSET.md 'name' ('{}') does not match the toolset directory name ('{}')",
        sanitise_display(.name, ECHO_CAP),
        sanitise_display(.dir, ECHO_CAP),
    )]
    NameDirMismatch {
        /// The `name` value from the frontmatter.
        name: String,
        /// The actual directory name the toolset was loaded from.
        dir: String,
    },

    /// The `description` field is absent from the frontmatter.
    #[error("TOOLSET.md frontmatter is missing the required 'description' field")]
    MissingDescription,

    /// The `description` field is present but empty (or whitespace-only).
    #[error("TOOLSET.md 'description' must not be empty")]
    DescriptionEmpty,

    /// The `description` field exceeds 1024 characters.
    #[error("TOOLSET.md 'description' exceeds 1024 characters")]
    DescriptionTooLong,

    /// The `compatibility` field (if present) exceeds 500 characters.
    #[error("TOOLSET.md 'compatibility' exceeds 500 characters")]
    CompatibilityTooLong,

    /// A capability token contains a character outside `[a-z0-9-]`.
    ///
    /// The charset gate is applied BEFORE name-matching so that no casing variant
    /// of a recognised or forbidden token can reach the matching step.
    /// `Sign-Transaction`, `SIGN-TRANSACTION`, `sign_transaction`, a tab-padded
    /// token, or a unicode-homoglyph are each refused here.
    #[error(
        "capability token '{}' contains a character outside [a-z0-9-]",
        sanitise_display(.token, ECHO_CAP)
    )]
    CapabilityTokenInvalidChar {
        /// The offending token (sanitised, length-capped).
        token: String,
    },

    /// A capability token passed the charset gate but is not in the recognised
    /// taxonomy.
    ///
    /// Unknown tokens are refused rather than silently ignored so that a toolset
    /// author's typo (`reed-balance`) does not silently produce an empty
    /// capability set.
    #[error(
        "capability token '{}' is not in the recognised taxonomy",
        sanitise_display(.token, ECHO_CAP)
    )]
    UnknownCapability {
        /// The unrecognised token (sanitised, length-capped).
        token: String,
    },

    /// The token `sign-transaction` was found in the capability manifest.
    ///
    /// Signing is not grantable as a flat capability declaration.  Toolsets may not
    /// declare `sign-transaction`; the signing path is governed by the first-invoke
    /// gate and the attestation gate.
    ///
    /// This is a distinct error from [`ToolsetFormatError::UnknownCapability`] to
    /// make the "no bare sign" rule legible: an author who writes
    /// `sign-transaction` gets a clear explanation rather than a generic
    /// "unknown token" message.
    #[error(
        "capability token 'sign-transaction' is not grantable; signing is \
        gated and cannot be declared as a flat capability"
    )]
    BareSignTransactionForbidden,

    /// The `stellar-agent-capabilities` metadata value is not a YAML string.
    ///
    /// The agentskills spec defines `metadata` values as strings; a YAML list or
    /// mapping value is a spec violation and is refused.
    #[error(
        "stellar-agent-capabilities metadata value is malformed: {}",
        sanitise_display(.detail, ECHO_CAP)
    )]
    CapabilityManifestMalformed {
        /// Description of the malformation.
        detail: String,
    },
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    /// Parity test: locks the closed-set variant count so adding a new variant
    /// without updating this test causes a compile error.
    ///
    /// Update this count when a new variant is added, and add a corresponding
    /// unit test in `parse` or `capability` that exercises the new variant.
    #[test]
    fn variant_count_parity() {
        // 24 variants. Count the arms in the match below.
        fn count_variants(e: &ToolsetFormatError) -> u32 {
            match e {
                ToolsetFormatError::Io { .. } => 1,
                ToolsetFormatError::ToolsetFileTooLarge { .. } => 2,
                ToolsetFormatError::NotUtf8 => 3,
                ToolsetFormatError::MissingFrontmatter => 4,
                ToolsetFormatError::MalformedFrontmatter { .. } => 5,
                ToolsetFormatError::YamlAnchorsForbidden => 6,
                ToolsetFormatError::FrontmatterTooDeep => 7,
                ToolsetFormatError::DuplicateKey { .. } => 8,
                ToolsetFormatError::ReservedMetadataKey { .. } => 9,
                ToolsetFormatError::MissingName => 10,
                ToolsetFormatError::NameEmpty => 11,
                ToolsetFormatError::NameTooLong => 12,
                ToolsetFormatError::NameInvalidChar => 13,
                ToolsetFormatError::NameLeadingTrailingHyphen => 14,
                ToolsetFormatError::NameConsecutiveHyphens => 15,
                ToolsetFormatError::NameDirMismatch { .. } => 16,
                ToolsetFormatError::MissingDescription => 17,
                ToolsetFormatError::DescriptionEmpty => 18,
                ToolsetFormatError::DescriptionTooLong => 19,
                ToolsetFormatError::CompatibilityTooLong => 20,
                ToolsetFormatError::CapabilityTokenInvalidChar { .. } => 21,
                ToolsetFormatError::UnknownCapability { .. } => 22,
                ToolsetFormatError::BareSignTransactionForbidden => 23,
                ToolsetFormatError::CapabilityManifestMalformed { .. } => 24,
            }
        }

        // Construct one instance of each variant and call count_variants.
        let variants: &[ToolsetFormatError] = &[
            ToolsetFormatError::Io {
                detail: String::new(),
            },
            ToolsetFormatError::ToolsetFileTooLarge { size: 0, cap: 0 },
            ToolsetFormatError::NotUtf8,
            ToolsetFormatError::MissingFrontmatter,
            ToolsetFormatError::MalformedFrontmatter {
                detail: String::new(),
            },
            ToolsetFormatError::YamlAnchorsForbidden,
            ToolsetFormatError::FrontmatterTooDeep,
            ToolsetFormatError::DuplicateKey { key: String::new() },
            ToolsetFormatError::ReservedMetadataKey { key: String::new() },
            ToolsetFormatError::MissingName,
            ToolsetFormatError::NameEmpty,
            ToolsetFormatError::NameTooLong,
            ToolsetFormatError::NameInvalidChar,
            ToolsetFormatError::NameLeadingTrailingHyphen,
            ToolsetFormatError::NameConsecutiveHyphens,
            ToolsetFormatError::NameDirMismatch {
                name: String::new(),
                dir: String::new(),
            },
            ToolsetFormatError::MissingDescription,
            ToolsetFormatError::DescriptionEmpty,
            ToolsetFormatError::DescriptionTooLong,
            ToolsetFormatError::CompatibilityTooLong,
            ToolsetFormatError::CapabilityTokenInvalidChar {
                token: String::new(),
            },
            ToolsetFormatError::UnknownCapability {
                token: String::new(),
            },
            ToolsetFormatError::BareSignTransactionForbidden,
            ToolsetFormatError::CapabilityManifestMalformed {
                detail: String::new(),
            },
        ];

        let max = variants.iter().map(count_variants).max().unwrap_or(0);
        // Assert both the highest assigned number AND the array length so that an
        // out-of-sync constructor array (e.g. a variant added to the enum but not
        // to `variants`) is caught even if the match numbering looks correct.
        assert_eq!(
            variants.len(),
            24,
            "constructor array length changed; add the new variant to `variants`"
        );
        assert_eq!(max, 24, "variant count changed; update parity test + doc");
    }

    /// The BareSignTransactionForbidden Display message must describe the refusal
    /// in user-facing terms without referencing internal development artefacts.
    #[test]
    fn bare_sign_transaction_message_is_user_facing() {
        let msg = ToolsetFormatError::BareSignTransactionForbidden.to_string();
        assert!(
            msg.contains("sign-transaction"),
            "message must name the token: {msg}"
        );
        assert!(
            msg.contains("gated") || msg.contains("not grantable"),
            "message must explain that signing is gated: {msg}"
        );
        // Must not contain internal development references.
        assert!(
            !msg.contains("PR-"),
            "message must not contain PR refs: {msg}"
        );
        assert!(
            !msg.contains("Phase-"),
            "message must not contain Phase refs: {msg}"
        );
    }
}
