#!/usr/bin/env bash
# Single-caller gate for the `SaSignerSetBaselined` and `SaSignerSetBaselinedV2`
# audit rows.
#
# A signer-set baseline is the anchor of divergence detection, so only
# `SignersManager::list_signers` (first observation) and
# `SignersManager::refresh_signer_baseline` (explicit re-anchor) may write one,
# both through `SignersManager::emit_baseline`, the only builder of a
# `SaSignerSetBaselinedV2` row. No production code builds a version-1
# `SaSignerSetBaselined` row. The constructors involved are `pub` across
# crates, and `AuditEntry::event_kind` is a `pub` field, so Rust visibility
# cannot enforce this; this gate does.
#
# Scope: every `*.rs` file under a `src/` directory of `crates/`, run from the
# repository root. The production text of a file is the text before its test
# module: the last line equal to `#[cfg(test)]` that is followed, after any
# `#[allow(...)]` attribute blocks, by a `mod <name> {` line. A file without
# such a line is production text throughout; a file that declares `mod tests;`
# keeps its tests in a separate `tests.rs` under `src/`, and that file is
# scanned whole. A file with two test modules is cut at the last one, so the
# earlier module is scanned as production text. Comment lines are ignored,
# and `//` comments are stripped before braces are matched. The enclosing
# function of a line is the nearest preceding `fn` definition (with any
# `pub`, `const`, `async`, `unsafe` and `extern` qualifiers).
#
# Assertions (each failure prints one line naming the offending file:line and
# exits 1):
#   (a) no call `new_sa_signer_set_baselined(` (the version-1 constructor),
#       and exactly one call `new_sa_signer_set_baselined_v2(`, inside
#       `fn emit_baseline` of the signers manager;
#   (b) exactly two calls `emit_baseline(`, one inside `fn list_signers` and
#       one inside `fn refresh_signer_baseline` of the signers manager;
#   (c) no construction `SaSignerSetBaselined { .. }` or
#       `SaSignerSetBaselinedV2 { .. }`, with any path prefix, outside the
#       audit-entry module; each variant's definition in the schema module is
#       exempt once. An occurrence is a pattern when its braces end in a
#       rest pattern (`..` after `{` or `,`) or the first token after the
#       closing brace is `=>`, `|`, `if` or `=`, and a construction otherwise.
#       The match requires the opening brace on the same line as the variant
#       name, which `cargo fmt` guarantees for code that passes the CI fmt job;
#   (d) no use of `BaselineReason::first_observation()`,
#       `BaselineReason::explicit_refresh()`,
#       `BaselineReason::confirmed_install()`, `BaselineReason::FirstObservation`,
#       `BaselineReason::ExplicitRefresh` or `BaselineReason::ConfirmedInstall`
#       (or the `Self::` forms) outside `fn list_signers` and
#       `fn refresh_signer_baseline` of the signers manager and outside the
#       module that defines `BaselineReason`; a variant followed by `=>` or
#       `|` is a pattern and allowed;
#   (e) no `use` statement importing through `EventKind::` or renaming
#       `EventKind as`, outside the audit-entry and schema modules, so every
#       construction in (c) is spelled with a visible path.
set -euo pipefail

SIGNERS="crates/stellar-agent-smart-account/src/managers/signers.rs"
ENTRY="crates/stellar-agent-core/src/audit_log/entry.rs"
SCHEMA="crates/stellar-agent-core/src/audit_log/schema.rs"
SIGNER_SET="crates/stellar-agent-core/src/audit_log/signer_set.rs"
NAME="check-no-direct-sasignersetbaselined-emit"

if [ ! -d crates ] || [ ! -f "$SIGNERS" ]; then
  echo "$NAME: run from the repository root ($SIGNERS not found)" >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

find crates -path '*/src/*' -name '*.rs' | LC_ALL=C sort >"$TMP/files"

awk -v list="$TMP/files" -v signers="$SIGNERS" -v entry="$ENTRY" -v schema="$SCHEMA" \
  -v signer_set="$SIGNER_SET" -v name="$NAME" '
# Returns the function name when `line` is a function definition, else "".
function fn_name(line,    s) {
  if (match(line, /^[[:space:]]*(pub([(][^)]*[)])?[[:space:]]+)?(const[[:space:]]+)?(async[[:space:]]+)?(unsafe[[:space:]]+)?(extern([[:space:]]+"[^"]*")?[[:space:]]+)?fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)) {
    s = substr(line, RSTART, RLENGTH)
    sub(/^.*fn[[:space:]]+/, "", s)
    return s
  }
  return ""
}

function is_comment(line) {
  return line ~ /^[[:space:]]*\/\//
}

# `line` without a trailing `//` comment.
function code(line) {
  sub(/\/\/.*$/, "", line)
  return line
}

# Line number where the test module starts, or n + 1 when there is none.
function test_cut(n,    i, j, cut) {
  cut = n + 1
  for (i = 1; i <= n; i++) {
    if (L[i] != "#[cfg(test)]") continue
    j = i + 1
    while (j <= n && L[j] ~ /^#[[]allow[(]/) {
      while (j <= n && L[j] !~ /[)][]][[:space:]]*$/) j++
      j++
    }
    if (j <= n && L[j] ~ /^(pub([(]crate[)])? )?mod [a-z_]+ [{]/) cut = i
  }
  return cut
}

function loc(f, i, fnn) {
  return f ":" i " (in " (fnn == "" ? "no fn" : "fn " fnn) ")"
}

# The first non-space text at or after column `col` of line `k`, continuing
# on later non-comment production lines, with `//` comments stripped.
function next_text(k, col, prod_end,    rest) {
  rest = substr(code(L[k]), col)
  sub(/^[[:space:]]+/, "", rest)
  while (rest == "" && ++k < prod_end) {
    if (is_comment(L[k])) continue
    rest = code(L[k])
    sub(/^[[:space:]]+/, "", rest)
  }
  return rest
}

# Classifies the `SaSignerSetBaselined {` or `SaSignerSetBaselinedV2 {`
# occurrence whose opening brace is at column `col` of line `i`: returns
# "pattern" or "construction".
function classify(i, col, prod_end,    depth, text, k, line, c, ch, start) {
  depth = 0
  text = ""
  k = i
  start = col
  while (k < prod_end) {
    if (k != i && is_comment(L[k])) { k++; start = 1; continue }
    line = code(L[k])
    for (c = start; c <= length(line); c++) {
      ch = substr(line, c, 1)
      if (ch == "{") depth++
      else if (ch == "}") {
        depth--
        if (depth == 0) return verdict(text, next_text(k, c + 1, prod_end))
      }
      text = text ch
    }
    text = text "\n"
    k++
    start = 1
  }
  return "construction"
}

function verdict(text, rest) {
  if (text ~ /(^|[{,])[[:space:]]*\.\.[[:space:]]*$/) return "pattern"
  if (rest ~ /^=>/) return "pattern"
  if (rest ~ /^=([^=>]|$)/) return "pattern"
  if (rest ~ /^[|]([^|]|$)/) return "pattern"
  if (rest ~ /^if([^A-Za-z0-9_]|$)/) return "pattern"
  return "construction"
}

BEGIN {
  files = 0
  na = 0; na2 = 0; nb = 0
  a_bad = ""; a2_bad = ""; b_bad = ""; c_bad = ""; c_variant = ""; d_bad = ""; e_bad = ""
  a_locs = ""; a2_locs = ""; b_locs = ""
  b_list = 0; b_refresh = 0
  while ((getline f < list) > 0) {
    files++
    n = 0
    split("", L)
    while ((getline line < f) > 0) {
      sub(/\r$/, "", line)
      L[++n] = line
    }
    close(f)
    prod_end = test_cut(n)
    cur = ""
    split("", seen)
    in_use = 0
    use_text = ""
    for (i = 1; i < prod_end; i++) {
      if (is_comment(L[i])) continue
      line = code(L[i])
      def = fn_name(line)
      if (def != "") cur = def

      if (def == "" && line ~ /new_sa_signer_set_baselined[(]/) {
        na++
        if (a_bad == "") a_bad = loc(f, i, cur)
      }

      if (def == "" && line ~ /new_sa_signer_set_baselined_v2[(]/) {
        na2++
        a2_locs = a2_locs (a2_locs == "" ? "" : ", ") f ":" i
        if (a2_bad == "" && !(f == signers && cur == "emit_baseline")) a2_bad = loc(f, i, cur)
      }

      if (def == "" && line ~ /emit_baseline[(]/) {
        nb++
        b_locs = b_locs (b_locs == "" ? "" : ", ") f ":" i
        if (f == signers && cur == "list_signers") b_list++
        else if (f == signers && cur == "refresh_signer_baseline") b_refresh++
        else if (b_bad == "") b_bad = loc(f, i, cur)
      }

      if (f != entry && c_bad == "") {
        offset = 0
        rest = line
        while (match(rest, /(^|[^A-Za-z0-9_])SaSignerSetBaselined(V2)?[[:space:]]*[{]/)) {
          col = offset + RSTART + RLENGTH - 1
          variant = substr(rest, RSTART, RLENGTH)
          sub(/^[^A-Za-z0-9_]/, "", variant)
          sub(/[[:space:]]*[{]$/, "", variant)
          definition = (f == schema && !seen[variant] && line ~ ("^[[:space:]]*" variant "[[:space:]]*[{][[:space:]]*$"))
          if (definition) seen[variant] = 1
          else if (classify(i, col, prod_end) == "construction") { c_bad = f ":" i; c_variant = variant; break }
          offset = col
          rest = substr(line, col + 1)
        }
      }

      if (f != signer_set && d_bad == "") {
        offset = 0
        rest = line
        while (match(rest, /(BaselineReason|Self)::(first_observation[(][)]|explicit_refresh[(][)]|confirmed_install[(][)]|FirstObservation|ExplicitRefresh|ConfirmedInstall)/)) {
          hit = substr(rest, RSTART, RLENGTH)
          before = RSTART > 1 ? substr(rest, RSTART - 1, 1) : ""
          after_char = substr(rest, RSTART + RLENGTH, 1)
          stop = offset + RSTART + RLENGTH - 1
          offset = stop
          rest = substr(line, stop + 1)
          if (before ~ /[A-Za-z0-9_]/) continue
          call = hit ~ /[(][)]$/
          if (!call && after_char ~ /[A-Za-z0-9_]/) continue
          allowed = (f == signers && (cur == "list_signers" || cur == "refresh_signer_baseline"))
          if (!allowed && !call) {
            after = next_text(i, stop + 1, prod_end)
            if (after ~ /^=>/ || after ~ /^[|]([^|]|$)/) allowed = 1
          }
          if (!allowed) { d_bad = loc(f, i, cur); break }
        }
      }

      if (f != entry && f != schema) {
        if (!in_use && line ~ /^[[:space:]]*(pub([(][^)]*[)])?[[:space:]]+)?use[[:space:]]/) {
          in_use = 1
          use_text = ""
          use_line = i
        }
        if (in_use) {
          use_text = use_text " " line
          if (index(line, ";") > 0) {
            in_use = 0
            if (e_bad == "" && use_text ~ /EventKind(::|[[:space:]]+as[[:space:]])/) e_bad = f ":" use_line
          }
        }
      }
    }
  }
  close(list)

  if (a_bad != "") {
    print "FAIL (a): the version-1 constructor new_sa_signer_set_baselined( is called at " a_bad
    exit 1
  }
  if (a2_bad != "") {
    print "FAIL (a): new_sa_signer_set_baselined_v2( is called outside fn emit_baseline of " signers " at " a2_bad
    exit 1
  }
  if (na2 != 1) {
    print "FAIL (a): expected exactly one new_sa_signer_set_baselined_v2( call, found " na2 (na2 ? " at " a2_locs : "")
    exit 1
  }
  if (b_bad != "") {
    print "FAIL (b): emit_baseline( is called outside fn list_signers and fn refresh_signer_baseline of " signers " at " b_bad
    exit 1
  }
  if (nb != 2 || b_list != 1 || b_refresh != 1) {
    print "FAIL (b): expected one emit_baseline( call in each of fn list_signers and fn refresh_signer_baseline, found " nb (nb ? " at " b_locs : "")
    exit 1
  }
  if (c_bad != "") {
    print "FAIL (c): " c_variant " is constructed outside " entry " at " c_bad
    exit 1
  }
  if (d_bad != "") {
    print "FAIL (d): a BaselineReason constructor or variant is used outside fn list_signers and fn refresh_signer_baseline of " signers " at " d_bad
    exit 1
  }
  if (e_bad != "") {
    print "FAIL (e): a use statement imports through EventKind:: or renames EventKind outside " entry " and " schema " at " e_bad
    exit 1
  }
  print name ": ok (" files " files; SaSignerSetBaselinedV2 is built only in emit_baseline, reached from list_signers and refresh_signer_baseline; no version-1 baseline constructor call exists in production code)"
}
'
