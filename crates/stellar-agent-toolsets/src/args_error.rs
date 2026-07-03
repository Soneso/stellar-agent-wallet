//! Typed error surface for pre-canonicalisation argument validation failures.
//!
//! [`ToolsetArgsError`] is the closed-set of all distinct refusal reasons returned
//! by [`crate::validate_toolset_tool_args`].  This is a SEPARATE error type from
//! [`crate::ToolsetFormatError`], which is the TOOLSET.md-parse error enum.
//!
//! The distinction matters: `ToolsetFormatError` covers static manifest format
//! violations detected at parse/install time; `ToolsetArgsError` covers runtime
//! argument-payload violations detected at dispatch time.  They live on different
//! code paths, are returned to different callers, and carry different semantics.
//!
//! ## Redaction discipline
//!
//! No variant echoes any attacker-controlled input KEY (the input key string is
//! not included — only the matched `&'static str` denylist constant is referenced),
//! and no variant echoes any VALUE byte from the argument payload.  This ensures
//! that a carefully-crafted argument payload containing secret-shaped content (e.g.
//! a key that looks like a mnemonic) can never leak through the error Display or
//! Debug output.

/// All distinct reasons [`crate::validate_toolset_tool_args`] can reject a payload.
///
/// The set is `#[non_exhaustive]` — the validator may grow new check classes in
/// future versions and callers should match with a `_ =>` fallback.
/// (Unlike [`crate::ToolsetFormatError`], which is exhaustive by design, this type
/// intentionally carries the `#[non_exhaustive]` attribute.)
///
/// # Redaction guarantee
///
/// No variant Display output ever contains:
/// - The inbound argument key string (even the rejected one).
/// - Any byte from any argument value.
///
/// Error messages reference only compile-time `&'static str` constants from the
/// denylist, ensuring that a crafted payload carrying secret-shaped values cannot
/// leak through Display.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ToolsetArgsError {
    /// The argument payload contains a key that is in the JS-runtime-dangerous
    /// denylist at some depth (including within arrays).
    ///
    /// The `matched_key` field holds the matched `&'static str` constant from
    /// [`crate::ARGS_KEY_DENYLIST`], NOT the input key string.  This ensures the
    /// error message never echoes attacker-controlled bytes.
    ///
    /// ## Why this class of key is dangerous
    ///
    /// When the wallet's JSON output is consumed by a downstream JavaScript agent
    /// runtime, certain property names have special semantics that can be exploited:
    ///
    /// - `toJSON` — custom serialisation hook; overrides `JSON.stringify`.
    /// - `then` — presence makes an object "thenable", hijacking `await`/`Promise.resolve`.
    /// - `__proto__` — prototype pollution via `Object.assign` or spread.
    /// - `constructor` / `prototype` — class-hierarchy tampering.
    /// - `toString` / `valueOf` — coercion hooks invoked in string + number contexts.
    /// - `__defineGetter__` / `__defineSetter__` / `__lookupGetter__` /
    ///   `__lookupSetter__` — `Object.prototype` accessor-injection vectors.
    ///
    /// These keys have NO legitimate use in any matrix-tool argument struct
    /// (`StellarPayArgs`, `StellarPayCommitArgs`, `StellarBalancesArgs`, SEP
    /// tool args).  Their presence at any depth is unambiguously attacker-authored.
    #[error(
        "toolset args payload contains a JS-runtime-dangerous key \
         (matched denylist constant: {matched_key}); payload rejected"
    )]
    DangerousKey {
        /// The matched `&'static str` constant from [`crate::ARGS_KEY_DENYLIST`].
        ///
        /// This is NOT the input key string — it is the constant from the denylist
        /// that the input key matched.  The Display output is therefore
        /// attacker-controlled-bytes-free.
        matched_key: &'static str,
    },

    /// The argument payload nesting depth exceeds [`crate::TOOLSET_ARGS_MAX_DEPTH`].
    ///
    /// Excessively-nested payloads are refused to prevent work-stack exhaustion
    /// and to bound the cost of the iterative walk.  The depth bound is set
    /// substantially above the deepest legitimate matrix-tool arg shape
    /// (see [`crate::TOOLSET_ARGS_MAX_DEPTH`] documentation for the sizing rationale).
    ///
    /// `depth` is the exact depth of the first node that exceeded the bound
    /// (the walk short-circuits at that node and never descends further).
    #[error(
        "toolset args payload nesting depth {depth} exceeds the maximum of {max_depth}; \
         payload rejected"
    )]
    NestingTooDeep {
        /// The exact depth of the first node that exceeded the bound.
        ///
        /// The walk short-circuits at this node; no further nodes are visited.
        depth: usize,
        /// The depth bound that was exceeded (`TOOLSET_ARGS_MAX_DEPTH`).
        max_depth: usize,
    },

    /// The argument payload total node count exceeds [`crate::TOOLSET_ARGS_MAX_NODES`].
    ///
    /// Payloads with an excessive number of nodes (deep OR wide) are refused to
    /// bound the total work performed by the iterative walk.
    ///
    /// ## Why this bound is necessary
    ///
    /// The depth bound (`TOOLSET_ARGS_MAX_DEPTH`) prevents stack-like traversal cost
    /// but does not bound WIDTH: a flat object or array with N million elements
    /// pushes N million references onto the work-stack in a single iteration.  The
    /// node-count cap closes this O(payload-width) unbounded case.
    ///
    /// The MCP transport bounds message size via the frame-size limit, but the
    /// CLI `--args` consumer does NOT have that guard.  This cap ensures the walk
    /// is bounded on both transports.
    ///
    /// `count_limit` is the only field — no attacker-controlled value is echoed.
    #[error(
        "toolset args payload node count exceeds the maximum of {count_limit}; \
         payload rejected"
    )]
    TooManyNodes {
        /// The node-count limit that was exceeded (`TOOLSET_ARGS_MAX_NODES`).
        count_limit: usize,
    },
}
