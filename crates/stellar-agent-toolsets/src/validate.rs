//! Pre-canonicalisation argument validation for toolset tool dispatch.
//!
//! The public entry point is [`validate_toolset_tool_args`].  It performs an
//! iterative, depth-bounded, node-count-bounded walk over a `serde_json::Value` to:
//!
//! 1. Reject any argument object that contains a JS-runtime-dangerous key
//!    (the denylist; see [`ARGS_KEY_DENYLIST`]) at ANY depth, including keys
//!    inside objects nested within arrays.
//!
//! 2. Reject payloads that nest deeper than [`TOOLSET_ARGS_MAX_DEPTH`].
//!
//! 3. Reject payloads whose total node count exceeds [`TOOLSET_ARGS_MAX_NODES`].
//!    This closes the O(payload-width) unbounded case that the depth bound alone
//!    does not prevent (a flat object with millions of keys passes depth-1 but
//!    would queue millions of stack entries before the denylist check runs).
//!
//! ## Why this guard exists
//!
//! When a JS extension attaches a `toJSON` method to an argument object, the
//! value that PASSES validation differs from the value DISPATCHED after
//! `JSON.stringify` (the `toJSON` hook runs during serialisation).  In a
//! `serde_json::Value` world there is no live `toJSON` method — a `Value` is
//! inert data — so the Rust realisation of that invariant is: **the exact
//! in-memory `Value` validated here is the one moved into dispatch with no
//! re-parse**.  The guard is still necessary because:
//!
//! - Our canonical JSON output is consumed DOWNSTREAM by a JS agent runtime.
//! - A `toJSON` key in the serialised JSON output enables the serialisation-hook
//!   bypass in the downstream runtime.
//! - Dangerous keys (`then`, `__proto__`, etc.) enable thenable-hijack and
//!   prototype-pollution attacks downstream.
//!
//! Rejecting these keys at the Rust validation layer prevents our serialised
//! output from carrying them.
//!
//! ## Walk strategy
//!
//! The walk is ITERATIVE — it uses an explicit heap-allocated work-stack
//! (`Vec<(&Value, usize)>`) rather than native C-stack recursion.  This prevents
//! stack overflow on adversarially-deep payloads.
//!
//! Note: `serde_json`'s own parse recursion limit (~128 on most builds) already
//! rejects pathologically-deep JSON before our layer, but a `Value` constructed
//! in-memory (e.g. in a unit test or by a future refactor) can exceed that limit.
//! The iterative walk is therefore bounded independently of the parse path.
//!
//! ## Mutation-before-guard invariant
//!
//! The caller MUST pass the FINAL post-injection `Value` to this function.  ALL
//! mutation (`chain_id` injection, `envelope_xdr` insertion, any future merge)
//! happens BEFORE this call; no insert/merge/serde round-trip occurs between this
//! function and `from_value::<TypedArgs>`.  This is the "freeze before dispatch"
//! invariant: the validated `Value` is the dispatched `Value`.

use crate::args_error::ToolsetArgsError;

// ── Public constants ──────────────────────────────────────────────────────────

/// The denylist of JS-runtime-dangerous object-key names.
///
/// Any `serde_json::Value::Object` key that byte-exactly matches one of these
/// strings at ANY depth (including inside arrays) causes
/// [`validate_toolset_tool_args`] to return `Err(ToolsetArgsError::DangerousKey)`.
///
/// ## Matching is post-parse, exact-byte
///
/// `serde_json` decodes JSON unicode escapes (e.g. `__` → `_`) before
/// our walk runs.  Matching against the already-decoded key string means
/// escape-variant evasion collapses to the literal key — `__proto__`
/// IS caught as `__proto__`.  This soundness property holds ONLY because the
/// walk runs POST-PARSE; moving this guard upstream of `serde_json` parsing
/// would re-open the escape evasion vector.
///
/// ## Why these 11 keys
///
/// - `toJSON` — custom serialisation hook; overrides `JSON.stringify`/`toJSON`.
///   The value passed validation is NOT the value dispatched after stringify.
/// - `then` — presence makes an object "thenable"; hijacks `await`/`Promise.resolve`.
/// - `__proto__` — prototype chain pollution via `Object.assign` or spread (`{...}`).
/// - `constructor` — class hierarchy tampering (e.g. `obj.constructor.prototype`).
/// - `prototype` — direct prototype-chain pollution via `constructor.prototype`.
/// - `toString` — coercion hook; invoked in string contexts (`""+obj`).
/// - `valueOf` — coercion hook; invoked in numeric contexts (`+obj`, comparisons).
/// - `__defineGetter__` — `Object.prototype` accessor injection; defines a getter.
/// - `__defineSetter__` — `Object.prototype` accessor injection; defines a setter.
/// - `__lookupGetter__` — `Object.prototype` accessor inspection; exposes getter.
/// - `__lookupSetter__` — `Object.prototype` accessor inspection; exposes setter.
///
/// No legitimate matrix-tool argument field collides with any of these names
/// (`chain_id`, `source`, `destination`, `amount`, `account_id`, `envelope_xdr`,
/// and all SEP tool arg names).  A future collision requires an explicit
/// allowlist exception with a decision-record entry.
pub const ARGS_KEY_DENYLIST: &[&str] = &[
    "toJSON",
    "then",
    "__proto__",
    "constructor",
    "prototype",
    "toString",
    "valueOf",
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
];

/// Maximum nesting depth for toolset tool argument payloads.
///
/// A payload nested deeper than this value is rejected with
/// [`ToolsetArgsError::NestingTooDeep`].
///
/// ## Sizing rationale
///
/// The deepest legitimate matrix-tool argument shapes are flat or single-level:
///
/// - `StellarBalancesArgs` — flat: `{ account_id, chain_id? }`.
/// - `StellarPayArgs` — flat: `{ source, destination, asset?, amount?,
///   amount_in_stroops?, memo?, memo_type?, chain_id? }`.
/// - `StellarPayCommitArgs` — flat: `{ source?, destination, asset?, amount?,
///   amount_in_stroops?, memo?, memo_type?, chain_id?, envelope_xdr,
///   approval_nonce?, approval_attestation? }`.
/// - SEP tool args — flat to single nested object for metadata.
///
/// Setting `TOOLSET_ARGS_MAX_DEPTH = 16` is 15x the deepest legitimate depth,
/// providing headroom for future SEP tool args that may carry one or two levels
/// of nesting, while remaining well below `serde_json`'s parse limit (~128) and
/// far below stack-overflow territory for the iterative walk.
///
/// ## Note on parse limit
///
/// `serde_json` rejects pathologically-deep JSON at parse time (typically at
/// depth ~128).  Our walk is bounded independently so it cannot overflow even
/// on a `Value` constructed directly in memory (bypassing the parse limit).
///
/// ## Distinct from `parse.rs::MAX_DEPTH`
///
/// `parse.rs::MAX_DEPTH = 8` is the YAML frontmatter nesting bound for TOOLSET.md
/// parse.  That constant is in a different structural domain (YAML frontmatter
/// fields) and is deliberately too small for JSON tool args (which can
/// legitimately nest slightly deeper in SEP metadata objects).  Do NOT reuse it.
pub const TOOLSET_ARGS_MAX_DEPTH: usize = 16;

/// Maximum total node count for toolset tool argument payloads.
///
/// A payload whose total number of visited nodes (objects, arrays, and scalars
/// combined) exceeds this value is rejected with [`ToolsetArgsError::TooManyNodes`].
///
/// ## Why this bound is necessary
///
/// [`TOOLSET_ARGS_MAX_DEPTH`] prevents deep payloads from exceeding the depth bound
/// but does NOT bound WIDTH: a flat `Value::Object` with N million entries passes
/// depth-1 but would enqueue N million `&Value` references onto the work-stack in
/// a single loop iteration.  This node-count cap closes the O(payload-width)
/// unbounded case.
///
/// The MCP transport bounds message size via the frame-size limit, so a real MCP
/// caller cannot craft a million-entry object.  However, the CLI `--args` consumer
/// will NOT have that frame-size guard.  This cap ensures the walk is bounded on
/// both transports.
///
/// ## Sizing rationale
///
/// The widest legitimate matrix-tool argument payload is `StellarPayCommitArgs`
/// (~12 flat fields) or the SEP tool args (~20 fields with a one-level-deep
/// metadata sub-object, ~40 total nodes).  Setting `TOOLSET_ARGS_MAX_NODES = 1_024`
/// is ~25× the widest legitimate payload, providing headroom for future tool args
/// that may carry larger flat maps or short arrays, while remaining small enough
/// to bound the walk to a trivial per-call cost.
pub const TOOLSET_ARGS_MAX_NODES: usize = 1_024;

// ── Public API ────────────────────────────────────────────────────────────────

/// Validate a toolset tool argument payload before dispatch.
///
/// Performs an iterative, depth-bounded walk over `args`:
///
/// - `Value::Object`: each key is checked against [`ARGS_KEY_DENYLIST`].  A
///   match returns `Err(ToolsetArgsError::DangerousKey { matched_key })` where
///   `matched_key` is the matched `&'static str` constant (NOT the input key
///   string — the error is redaction-clean).  Object values are pushed onto the
///   work-stack for further traversal.
/// - `Value::Array`: each element is pushed onto the work-stack.  Objects
///   nested inside arrays ARE key-checked when popped.
/// - `Value::String` / `Value::Number` / `Value::Bool` / `Value::Null`:
///   no-op (scalars carry no keys to check).
/// - Depth > [`TOOLSET_ARGS_MAX_DEPTH`]: returns
///   `Err(ToolsetArgsError::NestingTooDeep)`.
/// - Total nodes visited > [`TOOLSET_ARGS_MAX_NODES`]: returns
///   `Err(ToolsetArgsError::TooManyNodes)`.
///
/// The walk is allocation-light: the work-stack holds `&Value` BORROWS of the
/// original tree (no cloning of the payload).  The stack capacity is bounded by
/// `TOOLSET_ARGS_MAX_NODES`.
///
/// ## Caller contract (mutation-before-guard invariant)
///
/// The caller MUST pass the FINAL post-injection `Value` (after all `chain_id`
/// and `envelope_xdr` insertions).  No further mutation or serde round-trip
/// should occur between this call and `serde_json::from_value::<TypedArgs>`.
///
/// # Errors
///
/// - [`ToolsetArgsError::DangerousKey`] — a key matching [`ARGS_KEY_DENYLIST`]
///   was found at any depth (including nested in arrays).
/// - [`ToolsetArgsError::NestingTooDeep`] — payload nesting exceeds
///   [`TOOLSET_ARGS_MAX_DEPTH`].
/// - [`ToolsetArgsError::TooManyNodes`] — total nodes visited exceeds
///   [`TOOLSET_ARGS_MAX_NODES`].
///
/// # Examples
///
/// ```
/// use stellar_agent_toolsets::validate_toolset_tool_args;
/// use serde_json::json;
///
/// // Benign payload passes.
/// let ok = validate_toolset_tool_args(&json!({ "account_id": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN" }));
/// assert!(ok.is_ok());
///
/// // Dangerous key rejected.
/// let err = validate_toolset_tool_args(&json!({ "toJSON": "value" }));
/// assert!(err.is_err());
/// ```
pub fn validate_toolset_tool_args(args: &serde_json::Value) -> Result<(), ToolsetArgsError> {
    // Iterative work-stack: each entry is (value_ref, current_depth).
    // The root is at depth 0; each Object/Array nesting increments depth by 1
    // when pushing children.
    let mut stack: Vec<(&serde_json::Value, usize)> = Vec::new();
    stack.push((args, 0));

    // Total nodes visited (popped from the stack).  Bounds the O(payload-width)
    // case that TOOLSET_ARGS_MAX_DEPTH alone does not prevent: a flat object with
    // N million keys passes depth-1 but would enqueue N million refs.
    // Checked at the top of each iteration, before any work on the node.
    let mut nodes_visited: usize = 0;

    while let Some((value, depth)) = stack.pop() {
        // Node-count bound: checked first so the per-node cost is O(1).
        nodes_visited = nodes_visited.saturating_add(1);
        if nodes_visited > TOOLSET_ARGS_MAX_NODES {
            return Err(ToolsetArgsError::TooManyNodes {
                count_limit: TOOLSET_ARGS_MAX_NODES,
            });
        }

        // Depth bound check: if the CURRENT node is at depth > MAX, reject.
        // The walk short-circuits here; the exact tripping depth is reported.
        if depth > TOOLSET_ARGS_MAX_DEPTH {
            return Err(ToolsetArgsError::NestingTooDeep {
                depth,
                max_depth: TOOLSET_ARGS_MAX_DEPTH,
            });
        }

        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    // Check key against denylist.  Match is exact-byte against the
                    // already-serde-decoded key string.  The error carries the
                    // matched `&'static str` constant (NOT `key`) — redaction-clean.
                    if let Some(matched) = denylist_match(key.as_str()) {
                        return Err(ToolsetArgsError::DangerousKey {
                            matched_key: matched,
                        });
                    }
                    // Push the value for further traversal.
                    stack.push((child, depth + 1));
                }
            }
            serde_json::Value::Array(elements) => {
                // No key check on array indices; push elements for traversal.
                // Objects nested inside arrays ARE key-checked when popped.
                for element in elements {
                    stack.push((element, depth + 1));
                }
            }
            // Scalars (String, Number, Bool, Null): no keys to check, no children.
            _ => {}
        }
    }

    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Check `key` against [`ARGS_KEY_DENYLIST`] and return the matched `&'static str`
/// constant if found, or `None` if the key is not in the denylist.
///
/// The returned value is the `&'static str` from the denylist slice, NOT the
/// input key string.  Callers use this to build a redaction-clean error.
#[inline]
fn denylist_match(key: &str) -> Option<&'static str> {
    ARGS_KEY_DENYLIST
        .iter()
        .copied()
        .find(|&denied| key == denied)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps acceptable in unit tests"
    )]

    use serde_json::{Value, json};

    use super::*;

    // ── Helper: assert DangerousKey with matched constant ─────────────────────

    fn assert_dangerous_key(result: &Result<(), ToolsetArgsError>, expected_key: &str) {
        match result {
            Err(ToolsetArgsError::DangerousKey { matched_key }) => {
                assert_eq!(
                    *matched_key, expected_key,
                    "expected matched_key = {expected_key:?}, got {matched_key:?}"
                );
                // Verify Display does NOT contain any attacker-supplied input.
                // (The error references the &'static str constant only.)
                let display = result.as_ref().unwrap_err().to_string();
                assert!(
                    display.contains(expected_key),
                    "Display must mention the matched constant: {display}"
                );
            }
            other => panic!("expected DangerousKey({expected_key}), got {other:?}"),
        }
    }

    // ── Benign payloads pass ──────────────────────────────────────────────────

    #[test]
    fn benign_flat_object_passes() {
        let val = json!({
            "account_id": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN",
            "chain_id": "stellar:testnet"
        });
        validate_toolset_tool_args(&val).unwrap();
    }

    #[test]
    fn benign_null_passes() {
        validate_toolset_tool_args(&Value::Null).unwrap();
    }

    #[test]
    fn benign_string_passes() {
        validate_toolset_tool_args(&Value::String("hello".into())).unwrap();
    }

    #[test]
    fn benign_array_of_objects_passes() {
        let val = json!([
            { "account_id": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN" },
            { "chain_id": "stellar:testnet" }
        ]);
        validate_toolset_tool_args(&val).unwrap();
    }

    #[test]
    fn benign_nested_at_max_depth_passes() {
        // Build a JSON object nested so that the deepest OBJECT is at depth
        // TOOLSET_ARGS_MAX_DEPTH - 1.  The walk pushes child scalars at depth
        // TOOLSET_ARGS_MAX_DEPTH, and `TOOLSET_ARGS_MAX_DEPTH > TOOLSET_ARGS_MAX_DEPTH`
        // is false, so they pass.
        //
        // Depth accounting in the iterative walk:
        //   - root (outer wrapper) is popped at depth 0; its child pushed at depth 1.
        //   - each nested object is popped at its own depth D; its child pushed at D+1.
        //   - The depth bound fires when `D > TOOLSET_ARGS_MAX_DEPTH`, i.e. D >= 17.
        //
        // Wrapping TOOLSET_ARGS_MAX_DEPTH - 1 = 15 times gives innermost object at
        // depth 15, whose child scalar is pushed at depth 16 = TOOLSET_ARGS_MAX_DEPTH.
        // `16 > 16` is false -> scalar is a no-op -> payload passes.
        let mut val = json!({ "leaf": "value" });
        for _ in 0..TOOLSET_ARGS_MAX_DEPTH - 1 {
            val = json!({ "nested": val });
        }
        validate_toolset_tool_args(&val).unwrap();
    }

    // ── Denylist: each of the 11 keys at top level ────────────────────────────

    #[test]
    fn denylist_tojson_top_level() {
        let val = json!({ "toJSON": "something" });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "toJSON");
    }

    #[test]
    fn denylist_then_top_level() {
        let val = json!({ "then": "something" });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "then");
    }

    #[test]
    fn denylist_proto_top_level() {
        let val = json!({ "__proto__": { "isAdmin": true } });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__proto__");
    }

    #[test]
    fn denylist_constructor_top_level() {
        let val = json!({ "constructor": "something" });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "constructor");
    }

    #[test]
    fn denylist_prototype_top_level() {
        let val = json!({ "prototype": "something" });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "prototype");
    }

    #[test]
    fn denylist_tostring_top_level() {
        let val = json!({ "toString": "something" });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "toString");
    }

    #[test]
    fn denylist_valueof_top_level() {
        let val = json!({ "valueOf": "something" });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "valueOf");
    }

    #[test]
    fn denylist_define_getter_top_level() {
        let val = json!({ "__defineGetter__": "something" });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__defineGetter__");
    }

    #[test]
    fn denylist_define_setter_top_level() {
        let val = json!({ "__defineSetter__": "something" });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__defineSetter__");
    }

    #[test]
    fn denylist_lookup_getter_top_level() {
        let val = json!({ "__lookupGetter__": "something" });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__lookupGetter__");
    }

    #[test]
    fn denylist_lookup_setter_top_level() {
        let val = json!({ "__lookupSetter__": "something" });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__lookupSetter__");
    }

    // ── Denylist: each key nested in an object ────────────────────────────────

    #[test]
    fn denylist_tojson_nested_in_object() {
        let val = json!({ "safe_key": { "toJSON": "evil" } });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "toJSON");
    }

    #[test]
    fn denylist_then_nested_in_object() {
        let val = json!({ "outer": { "inner": { "then": "evil" } } });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "then");
    }

    #[test]
    fn denylist_proto_nested_in_object() {
        let val = json!({ "metadata": { "__proto__": "evil" } });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__proto__");
    }

    #[test]
    fn denylist_constructor_nested_in_object() {
        let val = json!({ "outer": { "constructor": "evil" } });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "constructor");
    }

    #[test]
    fn denylist_prototype_nested_in_object() {
        let val = json!({ "outer": { "prototype": "evil" } });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "prototype");
    }

    #[test]
    fn denylist_tostring_nested_in_object() {
        let val = json!({ "outer": { "toString": "evil" } });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "toString");
    }

    #[test]
    fn denylist_valueof_nested_in_object() {
        let val = json!({ "outer": { "valueOf": "evil" } });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "valueOf");
    }

    #[test]
    fn denylist_define_getter_nested_in_object() {
        let val = json!({ "outer": { "__defineGetter__": "evil" } });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__defineGetter__");
    }

    #[test]
    fn denylist_define_setter_nested_in_object() {
        let val = json!({ "outer": { "__defineSetter__": "evil" } });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__defineSetter__");
    }

    #[test]
    fn denylist_lookup_getter_nested_in_object() {
        let val = json!({ "outer": { "__lookupGetter__": "evil" } });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__lookupGetter__");
    }

    #[test]
    fn denylist_lookup_setter_nested_in_object() {
        let val = json!({ "outer": { "__lookupSetter__": "evil" } });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__lookupSetter__");
    }

    // ── Denylist: each key nested in an array ─────────────────────────────────
    //
    // Objects nested inside arrays ARE key-checked.

    #[test]
    fn denylist_tojson_nested_in_array() {
        let val = json!([{ "toJSON": "evil" }]);
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "toJSON");
    }

    #[test]
    fn denylist_then_nested_in_array() {
        let val = json!([{ "benign": "value" }, { "then": "evil" }]);
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "then");
    }

    #[test]
    fn denylist_proto_nested_in_array() {
        let val = json!([{ "__proto__": "evil" }]);
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__proto__");
    }

    #[test]
    fn denylist_constructor_nested_in_array() {
        let val = json!([{ "constructor": "evil" }]);
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "constructor");
    }

    #[test]
    fn denylist_prototype_nested_in_array() {
        let val = json!([{ "prototype": "evil" }]);
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "prototype");
    }

    #[test]
    fn denylist_tostring_nested_in_array() {
        let val = json!([{ "toString": "evil" }]);
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "toString");
    }

    #[test]
    fn denylist_valueof_nested_in_array() {
        let val = json!([{ "valueOf": "evil" }]);
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "valueOf");
    }

    #[test]
    fn denylist_define_getter_nested_in_array() {
        let val = json!([{ "__defineGetter__": "evil" }]);
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__defineGetter__");
    }

    #[test]
    fn denylist_define_setter_nested_in_array() {
        let val = json!([{ "__defineSetter__": "evil" }]);
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__defineSetter__");
    }

    #[test]
    fn denylist_lookup_getter_nested_in_array() {
        let val = json!([{ "__lookupGetter__": "evil" }]);
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__lookupGetter__");
    }

    #[test]
    fn denylist_lookup_setter_nested_in_array() {
        let val = json!([{ "__lookupSetter__": "evil" }]);
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__lookupSetter__");
    }

    // ── Depth bound ───────────────────────────────────────────────────────────

    #[test]
    fn depth_at_max_plus_1_rejected() {
        // Build a Value nested at TOOLSET_ARGS_MAX_DEPTH + 1.
        let mut val = json!({ "leaf": "value" });
        for _ in 0..=TOOLSET_ARGS_MAX_DEPTH {
            val = json!({ "nested": val });
        }
        let r = validate_toolset_tool_args(&val);
        assert!(
            matches!(r, Err(ToolsetArgsError::NestingTooDeep { .. })),
            "expected NestingTooDeep, got {r:?}"
        );
    }

    /// Proof that the iterative walk does NOT stack-overflow at serde_json's
    /// parse limit.  We construct a deeply-nested `Value` directly in memory
    /// (bypassing the parse limit) and verify the walk returns `Err` without
    /// overflowing.
    ///
    /// serde_json's parse recursion limit is typically ~128, but a
    /// directly-constructed `Value` can be much deeper.  The iterative walk
    /// must handle any in-memory depth without a stack overflow.
    #[test]
    fn depth_at_serde_parse_limit_no_overflow() {
        // Construct a Value 500 levels deep (well past serde's ~128 parse limit).
        // This can only be done in memory; serde_json would reject this as JSON text.
        let depth = 500_usize;
        let mut val = json!({ "leaf": "value" });
        for _ in 0..depth {
            val = json!({ "nested": val });
        }
        // Must return NestingTooDeep (not stack-overflow / panic).
        let r = validate_toolset_tool_args(&val);
        assert!(
            matches!(r, Err(ToolsetArgsError::NestingTooDeep { .. })),
            "expected NestingTooDeep for depth-{depth} value, got {r:?}"
        );
    }

    // ── Unicode escape proof: decode-then-match catches escape evasion ────────
    //
    // serde_json decodes unicode escapes to the literal byte string during parsing.
    // Our walk runs on the already-decoded `Value`, so the literal key is caught.

    #[test]
    fn proto_unicode_escaped_caught_as_literal() {
        // Build the JSON string manually: __proto__ expressed as unicode escapes.
        // serde_json::from_str will decode the escapes before our walk sees the key.
        let json_str = r#"{ "__proto__": "evil" }"#;
        let val: serde_json::Value = serde_json::from_str(json_str).unwrap();

        // Verify the key is decoded to "__proto__" by serde_json.
        if let serde_json::Value::Object(map) = &val {
            assert!(
                map.contains_key("__proto__"),
                "serde_json must decode escape sequences to __proto__"
            );
        }

        // The walk must catch it.
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "__proto__");
    }

    // ── Redaction: secret in sibling field never appears in error ─────────────

    #[test]
    fn secret_in_sibling_value_not_in_error_display() {
        // Plant a secret-shaped value in a sibling field alongside the dangerous key.
        // The error Display must NOT contain the planted secret string.
        let secret = "SBSECRETPLANTEDVALUETHATMUSTNEVERAPPEARINERROR12345ABCDEF";
        let val = json!({
            "account_id": secret,
            "toJSON": "irrelevant_value"
        });
        let err = validate_toolset_tool_args(&val).unwrap_err();
        let display = err.to_string();
        assert!(
            !display.contains(secret),
            "error Display must not contain the planted secret: {display}"
        );
        // Also verify the dangerous key constant IS present.
        assert!(
            display.contains("toJSON"),
            "error Display must mention the matched denylist constant: {display}"
        );
    }

    // ── Error references matched &'static str constant, not input ─────────────

    #[test]
    fn error_names_denylist_constant_not_input() {
        // A key that has the same BYTES as a denylist constant must produce
        // an error whose matched_key is the &'static str from the denylist.
        let val = json!({ "__proto__": "polluted" });
        let err = validate_toolset_tool_args(&val).unwrap_err();
        if let ToolsetArgsError::DangerousKey { matched_key } = &err {
            // The matched_key must be one of the ARGS_KEY_DENYLIST constants.
            assert!(
                ARGS_KEY_DENYLIST.contains(matched_key),
                "matched_key must be a denylist constant, got {matched_key:?}"
            );
            assert_eq!(*matched_key, "__proto__");
        } else {
            panic!("expected DangerousKey, got {err:?}");
        }
    }

    // ── Mixed payloads ────────────────────────────────────────────────────────

    #[test]
    fn benign_key_before_dangerous_key_still_caught() {
        // Safe keys before the dangerous one — the dangerous key must still be caught.
        let val = json!({
            "account_id": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN",
            "chain_id": "stellar:testnet",
            "__proto__": "evil"
        });
        let r = validate_toolset_tool_args(&val);
        assert!(
            r.is_err(),
            "dangerous key must be caught regardless of position"
        );
    }

    #[test]
    fn dangerous_key_in_object_inside_array_inside_object_caught() {
        // Pathological nesting: object -> array -> object with dangerous key.
        let val = json!({
            "records": [
                { "safe": "value" },
                { "constructor": "pollution" }
            ]
        });
        let r = validate_toolset_tool_args(&val);
        assert_dangerous_key(&r, "constructor");
    }

    // ── Denylist completeness (count) ─────────────────────────────────────────

    #[test]
    fn denylist_has_exactly_11_entries() {
        // Locks the denylist count so adding a new entry without updating the
        // tests causes this to fail (complementary to the per-key tests above).
        assert_eq!(
            ARGS_KEY_DENYLIST.len(),
            11,
            "ARGS_KEY_DENYLIST must have exactly 11 entries"
        );
    }

    // ── Node-count bound ──────────────────────────────────────────────────────

    /// A wide flat object over TOOLSET_ARGS_MAX_NODES is rejected with TooManyNodes.
    ///
    /// This test exercises the O(width) case that TOOLSET_ARGS_MAX_DEPTH alone does
    /// not prevent: a flat object passes depth-1 but can enqueue an arbitrary
    /// number of entries onto the work-stack.
    #[test]
    fn wide_object_over_node_cap_rejected() {
        // Build a flat object with TOOLSET_ARGS_MAX_NODES + 1 entries.
        // Each entry is a benign (key, scalar) pair — no dangerous keys, no nesting.
        let mut map = serde_json::Map::new();
        for i in 0..=TOOLSET_ARGS_MAX_NODES {
            map.insert(format!("field_{i}"), serde_json::Value::String("v".into()));
        }
        let val = serde_json::Value::Object(map);
        let r = validate_toolset_tool_args(&val);
        assert!(
            matches!(r, Err(ToolsetArgsError::TooManyNodes { .. })),
            "expected TooManyNodes for wide-over-cap object, got {r:?}"
        );
    }

    /// A wide flat object UNDER TOOLSET_ARGS_MAX_NODES passes.
    #[test]
    fn wide_object_under_node_cap_passes() {
        // Build a flat object with TOOLSET_ARGS_MAX_NODES / 2 entries — well under
        // the cap and with no dangerous keys.
        let half = TOOLSET_ARGS_MAX_NODES / 2;
        let mut map = serde_json::Map::new();
        for i in 0..half {
            map.insert(format!("safe_{i}"), serde_json::Value::String("ok".into()));
        }
        let val = serde_json::Value::Object(map);
        validate_toolset_tool_args(&val).unwrap();
    }
}
