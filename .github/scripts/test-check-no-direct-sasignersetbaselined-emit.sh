#!/usr/bin/env bash
# Offline regression checks for check-no-direct-sasignersetbaselined-emit.sh.
#
# Runs the gate on the repository tree, then on a copy of `crates/` with one
# injection at a time: each forbidden shape must fail with its assertion's
# line, and a production pattern match or a construction inside a test module
# must still pass.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
GATE="$ROOT/.github/scripts/check-no-direct-sasignersetbaselined-emit.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

SIGNERS="crates/stellar-agent-smart-account/src/managers/signers.rs"
VERIFIERS="crates/stellar-agent-smart-account/src/managers/verifiers.rs"
WS="$TMP/ws"

fail() {
  echo "$1" >&2
  exit 1
}

# Runs the gate from the directory `$1`, writing its output to `$2`; returns
# the gate's exit status.
run_gate() {
  local status=0
  (cd "$1" && bash "$GATE") >"$2" 2>&1 || status=$?
  return "$status"
}

# Inserts the lines of `$3` into file `$1` inside the body of the first
# function whose definition line matches `$2`: after the first line ending in
# `{` at or below the definition.
inject() {
  local file="$WS/$1"
  ANCHOR="$2" TEXT="$3" awk '
    state == 0 && $0 ~ ENVIRON["ANCHOR"] { state = 1 }
    { print }
    state == 1 && /[{][[:space:]]*$/ { print ENVIRON["TEXT"]; state = 2 }
    END { if (state != 2) exit 3 }
  ' "$file" >"$TMP/injected" || fail "injection anchor not found in $1: $2"
  cp "$TMP/injected" "$file"
}

# Inserts the lines of `$3` into file `$1` directly after the first line
# matching `$2`.
inject_after_line() {
  local file="$WS/$1"
  ANCHOR="$2" TEXT="$3" awk '
    { print }
    state == 0 && $0 ~ ENVIRON["ANCHOR"] { print ENVIRON["TEXT"]; state = 1 }
    END { if (state != 1) exit 3 }
  ' "$file" >"$TMP/injected" || fail "injection anchor not found in $1: $2"
  cp "$TMP/injected" "$file"
}

# Inserts the lines of `$3` into file `$1` directly before the first line
# equal to `$2`.
inject_before_line() {
  local file="$WS/$1"
  LINE="$2" TEXT="$3" awk '
    state == 0 && $0 == ENVIRON["LINE"] { print ENVIRON["TEXT"]; state = 1 }
    { print }
    END { if (state != 1) exit 3 }
  ' "$file" >"$TMP/injected" || fail "injection line not found in $1: $2"
  cp "$TMP/injected" "$file"
}

reset_ws() {
  rm -rf "$WS"
  mkdir -p "$WS"
  cp -R "$ROOT/crates" "$WS/crates"
}

# Asserts the gate fails in the workspace and prints a line starting with `$2`
# and containing `$3`.
expect_fail() {
  local label=$1 prefix=$2 location=$3
  if run_gate "$WS" "$TMP/$label.out"; then
    fail "$label: the gate passed; expected a failure: $(cat "$TMP/$label.out")"
  fi
  awk -v prefix="$prefix" -v location="$location" '
    index($0, prefix) == 1 && index($0, location) > 0 { found = 1 }
    END { exit found ? 0 : 1 }
  ' "$TMP/$label.out" || fail "$label: unexpected gate output: $(cat "$TMP/$label.out")"
  echo "$label: $(cat "$TMP/$label.out")"
}

expect_pass() {
  local label=$1
  run_gate "$WS" "$TMP/$label.out" ||
    fail "$label: the gate failed; expected a pass: $(cat "$TMP/$label.out")"
  echo "$label: passes"
}

# The repository tree passes.
run_gate "$ROOT" "$TMP/tree.out" || fail "the repository tree fails the gate: $(cat "$TMP/tree.out")"
echo "repository tree: $(cat "$TMP/tree.out")"

# An unmodified copy passes, so the copy has the shape the gate expects.
reset_ws
expect_pass "unmodified copy"

# (a) A second constructor call in another production function.
inject "$SIGNERS" '^    async fn fetch_context_rule_primary[(]' \
  '        let _row = AuditEntry::new_sa_signer_set_baselined(rule_id);'
expect_fail "extra constructor call" "FAIL (a):" "(in fn fetch_context_rule_primary)"

# (a) A version-2 constructor call outside fn emit_baseline.
reset_ws
inject "$SIGNERS" '^    async fn fetch_context_rule_primary[(]' \
  '        let _row = AuditEntry::new_sa_signer_set_baselined_v2(rule_id);'
expect_fail "version-2 constructor call" "FAIL (a):" "(in fn fetch_context_rule_primary)"

# (b) An emit_baseline call in another function.
reset_ws
inject "$SIGNERS" '^    async fn fetch_signer_set[(]' \
  '        self.emit_baseline(&observed, rule_id, &redacted, reason, &request_id);'
expect_fail "extra emit_baseline call" "FAIL (b):" "(in fn fetch_signer_set)"

# (c) A struct-literal construction in another module.
reset_ws
inject "$VERIFIERS" '^pub async fn pin_referenced_contracts[(]' \
  "$(printf '%s\n' \
    '    let _kind = EventKind::SaSignerSetBaselined {' \
    '        rule_id,' \
    '        signer_count: 1,' \
    '    };')"
expect_fail "construction in verifiers.rs" "FAIL (c):" "at $VERIFIERS:"

# (c) A version-2 struct-literal construction in another module.
reset_ws
inject "$VERIFIERS" '^pub async fn pin_referenced_contracts[(]' \
  "$(printf '%s\n' \
    '    let _kind = EventKind::SaSignerSetBaselinedV2 {' \
    '        rule_id,' \
    '        signer_count: 1,' \
    '    };')"
expect_fail "version-2 construction in verifiers.rs" "FAIL (c): SaSignerSetBaselinedV2" \
  "at $VERIFIERS:"

# (c) Trailing comments inside the braces are not code: neither `...` nor a
# comment ending in `, ..` makes a construction a rest pattern.
reset_ws
inject "$VERIFIERS" '^pub async fn pin_referenced_contracts[(]' \
  "$(printf '%s\n' \
    '    let _kind = EventKind::SaSignerSetBaselined {' \
    '        rule_id: Some(1), // see the baseline row ...' \
    '        signer_count: 1, // the other fields, ..' \
    '    };')"
expect_fail "construction with a trailing comment" "FAIL (c):" "at $VERIFIERS:"

# (c) A range expression inside the braces is not a rest pattern.
reset_ws
inject "$VERIFIERS" '^pub async fn pin_referenced_contracts[(]' \
  '    let _kind = EventKind::SaSignerSetBaselined { rule_id: Some(ids[..].len() as u32), signer_count: 1 };'
expect_fail "construction holding a range expression" "FAIL (c):" "at $VERIFIERS:"

# (c) A construction through an imported variant has no `EventKind::` prefix.
reset_ws
printf '%s\n' \
  'use stellar_agent_core::audit_log::schema::EventKind::*;' \
  '' \
  'pub fn forged_baseline() -> EventKind {' \
  '    SaSignerSetBaselined { rule_id: Some(1), signer_count: 1 }' \
  '}' >"$WS/crates/stellar-agent-mcp/src/imported_variant.rs"
expect_fail "construction through an imported variant" "FAIL (c):" \
  "at crates/stellar-agent-mcp/src/imported_variant.rs:4"

# (c) A `Self::` construction in a production `impl EventKind` in the schema
# module: only the variant definition line there is exempt.
reset_ws
inject_after_line "crates/stellar-agent-core/src/audit_log/schema.rs" '^use ' \
  "$(printf '%s\n' \
    'impl EventKind {' \
    '    pub fn forged_baseline() -> Self {' \
    '        Self::SaSignerSetBaselined { rule_id: Some(1), signer_count: 1 }' \
    '    }' \
    '}')"
expect_fail "Self construction in the schema module" "FAIL (c):" \
  "at crates/stellar-agent-core/src/audit_log/schema.rs:"

# (c) The schema module exempts only its first bare `SaSignerSetBaselined {`
# line, the variant definition; a second bare construction after it fails.
reset_ws
inject_before_line "crates/stellar-agent-core/src/audit_log/schema.rs" '#[cfg(test)]' \
  "$(printf '%s\n' \
    'impl EventKind {' \
    '    pub fn forged_bare() -> Self {' \
    '        use EventKind::SaSignerSetBaselined;' \
    '        SaSignerSetBaselined {' \
    '            rule_id: Some(1),' \
    '            signer_count: 1,' \
    '        }' \
    '    }' \
    '}')"
expect_fail "second bare construction in the schema module" "FAIL (c):" \
  "at crates/stellar-agent-core/src/audit_log/schema.rs:"

# (c) The schema module exempts each variant's definition once: a second bare
# `SaSignerSetBaselinedV2 {` construction after the version-2 definition fails
# although the version-1 definition was also exempted.
reset_ws
inject_before_line "crates/stellar-agent-core/src/audit_log/schema.rs" '#[cfg(test)]' \
  "$(printf '%s\n' \
    'impl EventKind {' \
    '    pub fn forged_bare_v2() -> Self {' \
    '        use EventKind::SaSignerSetBaselinedV2;' \
    '        SaSignerSetBaselinedV2 {' \
    '            rule_id: 1,' \
    '            account_digest: [0; 32],' \
    '        }' \
    '    }' \
    '}')"
expect_fail "second bare version-2 construction in the schema module" \
  "FAIL (c): SaSignerSetBaselinedV2" "at crates/stellar-agent-core/src/audit_log/schema.rs:"

# (c) An `==` after the closing brace is a comparison, not a pattern `=`.
reset_ws
inject "$VERIFIERS" '^pub async fn pin_referenced_contracts[(]' \
  '    let _same = EventKind::SaSignerSetBaselined { rule_id: Some(1), signer_count: 1 } == other;'
expect_fail "construction compared with ==" "FAIL (c):" "at $VERIFIERS:"

# (e) An import through `EventKind::`, here in a grouped multi-line `use`.
reset_ws
printf '%s\n' \
  'use stellar_agent_core::audit_log::schema::{' \
  '    EventKind::SaSignerSetBaselined as Baselined,' \
  '    PinsUpdateReason,' \
  '};' >"$WS/crates/stellar-agent-mcp/src/imported_alias.rs"
expect_fail "import through EventKind" "FAIL (e):" \
  "at crates/stellar-agent-mcp/src/imported_alias.rs:1"

# (d) A BaselineReason constructor call in another function.
reset_ws
inject "$SIGNERS" '^    async fn fetch_signer_set[(]' \
  '        let _reason = BaselineReason::first_observation();'
expect_fail "BaselineReason call" "FAIL (d):" "(in fn fetch_signer_set)"

# (d) The confirmed-install constructor in another function.
reset_ws
inject "$SIGNERS" '^    async fn fetch_signer_set[(]' \
  '        let _reason = BaselineReason::confirmed_install();'
expect_fail "confirmed_install call" "FAIL (d):" "(in fn fetch_signer_set)"

# (d) A `const fn` and an `extern "C" fn` are functions of their own: a call
# inside one placed within `list_signers` is not attributed to it.
reset_ws
inject_after_line "$SIGNERS" '^                BaselineReason::first_observation[(][)],$' \
  '        pub const fn forged() -> u8 { let _r = BaselineReason::first_observation(); 0 }'
expect_fail "BaselineReason call in a const fn" "FAIL (d):" "(in fn forged)"

reset_ws
inject_after_line "$SIGNERS" '^                BaselineReason::first_observation[(][)],$' \
  '        pub extern "C" fn forged_extern() { let _r = BaselineReason::explicit_refresh(); }'
expect_fail "BaselineReason call in an extern fn" "FAIL (d):" "(in fn forged_extern)"

# (d) A BaselineReason variant constructed directly.
reset_ws
printf '%s\n' \
  'use stellar_agent_core::audit_log::signer_set::BaselineReason;' \
  '' \
  'pub fn forged_reason() -> BaselineReason {' \
  '    BaselineReason::FirstObservation' \
  '}' >"$WS/crates/stellar-agent-mcp/src/forged_reason.rs"
expect_fail "direct BaselineReason variant" "FAIL (d):" \
  "at crates/stellar-agent-mcp/src/forged_reason.rs:4"

# (d) The confirmed-install variant constructed directly.
reset_ws
printf '%s\n' \
  'use stellar_agent_core::audit_log::signer_set::BaselineReason;' \
  '' \
  'pub fn forged_install_reason() -> BaselineReason {' \
  '    BaselineReason::ConfirmedInstall' \
  '}' >"$WS/crates/stellar-agent-mcp/src/forged_install_reason.rs"
expect_fail "direct ConfirmedInstall variant" "FAIL (d):" \
  "at crates/stellar-agent-mcp/src/forged_install_reason.rs:4"

# The walk covers every crate: a construction in a new MCP source file.
reset_ws
printf '%s\n' \
  'use stellar_agent_core::audit_log::schema::EventKind;' \
  '' \
  'pub fn forged_baseline() -> EventKind {' \
  '    EventKind::SaSignerSetBaselined { rule_id: 1 }' \
  '}' >"$WS/crates/stellar-agent-mcp/src/forged_baseline.rs"
expect_fail "construction in a new MCP file" "FAIL (c):" \
  "at crates/stellar-agent-mcp/src/forged_baseline.rs:4"

# The cut rule: a `#[cfg(test)]` on a static does not start the test module,
# so the production code after it is scanned.
reset_ws
printf '%s\n' \
  'use std::sync::Mutex;' \
  '' \
  '#[cfg(test)]' \
  'static FORCE_NEXT_FAILURE: Mutex<Option<u32>> = Mutex::new(None);' \
  '' \
  'pub fn forged_baseline() -> EventKind {' \
  '    EventKind::SaSignerSetBaselined {' \
  '        rule_id: 1,' \
  '    }' \
  '}' \
  '' \
  '#[cfg(test)]' \
  'mod tests {' \
  '    #[test]' \
  '    fn baseline() {}' \
  '}' >"$WS/crates/stellar-agent-core/src/audit_log/early_cfg_test_static.rs"
expect_fail "construction after a cfg(test) static" "FAIL (c):" \
  "at crates/stellar-agent-core/src/audit_log/early_cfg_test_static.rs:7"

# The test module starts at the last `#[cfg(test)]` + `mod`, so production
# code after an earlier test module is scanned.
reset_ws
printf '%s\n' \
  '#[cfg(test)]' \
  'mod early {}' \
  '' \
  'pub fn forged_baseline() -> EventKind {' \
  '    EventKind::SaSignerSetBaselined { rule_id: 1 }' \
  '}' \
  '' \
  '#[cfg(test)]' \
  'mod tests {' \
  '    #[test]' \
  '    fn baseline() {}' \
  '}' >"$WS/crates/stellar-agent-core/src/audit_log/two_test_modules.rs"
expect_fail "construction between two test modules" "FAIL (c):" \
  "at crates/stellar-agent-core/src/audit_log/two_test_modules.rs:5"

# The last `#[cfg(test)]` starts the test module only when a `mod` follows it:
# a file ending in a `#[cfg(test)]` const is production text throughout.
reset_ws
printf '%s\n' \
  '#[cfg(test)]' \
  'const FIXTURE_RULE_ID: u32 = 1;' \
  '' \
  'pub fn forged_baseline() -> EventKind {' \
  '    EventKind::SaSignerSetBaselined { rule_id: 1 }' \
  '}' >"$WS/crates/stellar-agent-core/src/audit_log/trailing_cfg_test_const.rs"
expect_fail "construction after a trailing cfg(test) const" "FAIL (c):" \
  "at crates/stellar-agent-core/src/audit_log/trailing_cfg_test_const.rs:5"

# A test module behind `#[cfg(test)]` and a multi-line `#[allow(...)]` block is
# not production text, so a construction inside it passes.
reset_ws
printf '%s\n' \
  'pub fn rule_id() -> u32 {' \
  '    1' \
  '}' \
  '' \
  '#[cfg(test)]' \
  '#[allow(' \
  '    clippy::unwrap_used,' \
  '    reason = "test-only"' \
  ')]' \
  'mod tests {' \
  '    #[test]' \
  '    fn baseline() {' \
  '        let _kind = EventKind::SaSignerSetBaselined { rule_id: 1 };' \
  '    }' \
  '}' >"$WS/crates/stellar-agent-core/src/audit_log/allow_attributed_tests.rs"
expect_pass "construction inside an allow-attributed test module"

# A production pattern match is not a construction. Each occurrence below is
# a pattern by one rule only: `..` inside the braces, or the token after the
# closing brace (`=>`, `|`, `if`, `=` on a later line).
reset_ws
inject "$VERIFIERS" '^pub async fn pin_referenced_contracts[(]' \
  "$(printf '%s\n' \
    '    let _baselined = matches!(kind, EventKind::SaSignerSetBaselined { .. });' \
    '    let _baselined_v2 = matches!(kind, EventKind::SaSignerSetBaselinedV2 { .. });' \
    '    match kind {' \
    '        EventKind::SaSignerSetBaselined { rule_id } => {}' \
    '        EventKind::SaSignerSetBaselined { rule_id } | EventKind::Other => {}' \
    '        EventKind::SaSignerSetBaselined { rule_id } if rule_id > 0 => {}' \
    '        _ => {}' \
    '    }' \
    '    if let EventKind::SaSignerSetBaselined {' \
    '        rule_id' \
    '    }' \
    '        = kind {}' \
    '    match reason {' \
    '        BaselineReason::FirstObservation => {}' \
    '        BaselineReason::ExplicitRefresh | _ => {}' \
    '    }' \
    '    match reason {' \
    '        BaselineReason::ConfirmedInstall => {}' \
    '        _ => {}' \
    '    }')"
expect_pass "production pattern match"

echo "baseline emit gate tests passed"
