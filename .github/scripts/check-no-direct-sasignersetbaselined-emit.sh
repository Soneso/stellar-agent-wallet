#!/usr/bin/env bash
# Single-caller gate for the `SaSignerSetBaselined` and `SaSignerSetBaselinedV2`
# audit rows.
#
# A signer-set baseline is the anchor of divergence detection, so only
# `SignersManager::list_signers` (first observation),
# `SignersManager::refresh_signer_baseline` (explicit re-anchor) and
# `SignersManager::baseline_confirmed_install` (a rule the wallet installed)
# may write one, each through `SignersManager::emit_baseline`, the only
# builder of a `SaSignerSetBaselinedV2` row. No production code builds a
# version-1 `SaSignerSetBaselined` row. The constructors involved are `pub` across
# crates, and `AuditEntry::event_kind` is a `pub` field, so Rust visibility
# cannot enforce this; this gate does.
#
# Scope: every `*.rs` file under a `src/` directory of `crates/`, run from the
# repository root. Production text excludes the last inline test module.
# Its marker is a line equal to `#[cfg(test)]`, followed after any
# `#[allow(...)]` attribute blocks by a `mod <name> {` line.
# A file without such a module is production text throughout.
# An external `mod tests;` keeps tests in a separate `tests.rs` under `src/`;
# that file is scanned whole. The inline module is skipped by brace depth,
# and scanning resumes after its closing brace. Earlier test modules are
# scanned as production text. Comment lines are ignored,
# and `//` comments are stripped before braces are matched. The enclosing
# function of a line is the nearest preceding `fn` definition (with any
# `pub`, `const`, `async`, `unsafe` and `extern` qualifiers).
#
# Assertions (each failure prints one line naming the offending file:line and
# exits 1):
#   (a) no call `new_sa_signer_set_baselined(` (the version-1 constructor),
#       and exactly one call `new_sa_signer_set_baselined_v2(`, inside
#       `fn emit_baseline` of the signers manager;
#   (b) exactly three calls `emit_baseline(`, one inside each of
#       `fn list_signers`, `fn refresh_signer_baseline` and
#       `fn baseline_confirmed_install` of the signers manager;
#   (c) no construction `SaSignerSetBaselined { .. }` or
#       `SaSignerSetBaselinedV2 { .. }`, with any path prefix, outside the
#       audit-entry module; each variant's definition in the schema module is
#       exempt once. An occurrence is a pattern when its braces end in a
#       rest pattern (`..` after `{` or `,`) or the first token after the
#       closing brace is `=>`, `|`, `if` or `=`, and a construction otherwise.
#       Only whitespace and newlines may precede the opening brace;
#   (d) each `BaselineReason` constructor and variant is used only in its own
#       function of the signers manager, outside the module that defines
#       `BaselineReason`: `first_observation()` and `FirstObservation` in
#       `fn list_signers`, `explicit_refresh()` and `ExplicitRefresh` in
#       `fn refresh_signer_baseline`, `confirmed_install()` and
#       `ConfirmedInstall` in `fn baseline_confirmed_install` (with the
#       `Self::` forms); a variant followed by `=>` or `|` is a pattern and
#       allowed anywhere;
#   (e) no `use` statement importing through `EventKind::` or renaming
#       `EventKind as`, outside the audit-entry and schema modules, so every
#       construction in (c) is spelled with a visible path;
#   (f) no baseline variant token inside macro arguments or a macro definition
#       body, including patterns. Macros are inspected as text without
#       expansion.
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

# Strip strings and comments for module depth and macro token checks.
# Lexical state spans lines; raw strings and block comments may span lines.
function syntax(line,    out, c, ch, pair, tail, hashes) {
  if (!block_depth && raw_end == "" && !quoted && is_comment(line)) return ""
  if (!block_depth && raw_end == "" && !quoted && line !~ /["\047]|\/\/|\/[*]/) return line
  out = ""
  for (c = 1; c <= length(line); c++) {
    ch = substr(line, c, 1)
    pair = substr(line, c, 2)
    if (block_depth) {
      if (pair == "/*") { block_depth++; c++ }
      else if (pair == "*/") { block_depth--; c++ }
      out = out " "
    } else if (raw_end != "") {
      if (substr(line, c, length(raw_end)) == raw_end) {
        c += length(raw_end) - 1
        raw_end = ""
      }
      out = out " "
    } else if (quoted) {
      if (ch == "\\") c++
      else if (ch == "\"") quoted = 0
      out = out " "
    } else if (pair == "//") break
    else if (pair == "/*") { block_depth = 1; c++; out = out " " }
    else if (ch == "r" && match(substr(line, c), /^r#*"/)) {
      tail = substr(line, c, RLENGTH)
      hashes = substr(tail, 2, length(tail) - 2)
      raw_end = "\"" hashes
      c += length(tail) - 1
      out = out " "
    } else if (ch == "\"") { quoted = 1; out = out " " }
    else if (ch == sprintf("%c", 39) && match(substr(line, c), /^\047([^\047\\]|\\[^[:space:]])\047/)) {
      c += RLENGTH - 1
      out = out " "
    } else out = out ch
  }
  return out
}

# Mask the last inline test module, retaining source line numbers.
function skip_tests(n,    i, j, cut, start, depth, text) {
  cut = n + 1
  for (i = 1; i <= n; i++) {
    if (L[i] != "#[cfg(test)]" || C[i] != "#[cfg(test)]") continue
    j = i + 1
    while (j <= n && L[j] ~ /^#[[]allow[(]/) {
      while (j <= n && L[j] !~ /[)][]][[:space:]]*$/) j++
      j++
    }
    if (j <= n && L[j] ~ /^(pub([(]crate[)])? )?mod [a-z_]+ [{]/) { cut = i; start = j }
  }
  test_end = 0
  if (cut > n) return
  depth = 0
  for (i = start; i <= n; i++) {
    text = C[i]
    depth += gsub(/[{]/, "{", text)
    depth -= gsub(/[}]/, "}", text)
    if (depth == 0) { test_end = i; break }
  }
  if (!test_end) test_end = n
  for (i = cut; i <= test_end; i++) { L[i] = ""; C[i] = "" }
}

# Locate a forbidden macro token in sanitized production text.
function macro_token(text,    rest, offset, start, c, depth, ch, body, body_start, hit, definition, prefix, lines) {
  rest = text
  offset = 0
  while (match(rest, /[A-Za-z_][A-Za-z0-9_]*![[:space:]]*/)) {
    start = offset + RSTART
    definition = substr(rest, RSTART, RLENGTH) ~ /^macro_rules!/
    c = start + RLENGTH
    offset = c - 1
    rest = substr(text, offset + 1)
    if (definition) {
      prefix = substr(text, c)
      if (!match(prefix, /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*/)) continue
      c += RLENGTH
    }
    while (substr(text, c, 1) ~ /[[:space:]]/) c++
    if (substr(text, c, 1) ~ /[({[]/) {
      depth = 1
      body = ""
      body_start = c + 1
      for (c++; c <= length(text); c++) {
        ch = substr(text, c, 1)
        if (ch ~ /[({[]/) depth++
        else if (ch ~ /[)}\]]/) depth--
        if (!depth) break
        body = body ch
      }
      hit = match(body, baseline_variant)
      if (hit) {
        prefix = substr(text, 1, body_start - 1) substr(body, 1, RSTART)
        lines = gsub(/\n/, "\n", prefix)
        return lines + 1
      }
      offset = c
      rest = substr(text, offset + 1)
    }
  }
  return 0
}

# Find a brace after whitespace and newlines.
function opening_brace(i, col, prod_end,    rest, k) {
  for (k = i; k < prod_end; k++) {
    rest = substr(code(L[k]), k == i ? col : 1)
    sub(/^[[:space:]]+/, "", rest)
    if (rest == "") continue
    if (rest ~ /^[{]/) { brace_line = k; return length(code(L[k])) - length(rest) + 1 }
    return 0
  }
  return 0
}

function loc(f, i, fnn) {
  return f ":" i " (in " (fnn == "" ? "no fn" : "fn " fnn) ")"
}

# The one signers-manager function that may use the BaselineReason
# constructor or variant `hit`.
function reason_owner(hit) {
  if (hit ~ /first_observation|FirstObservation/) return "list_signers"
  if (hit ~ /explicit_refresh|ExplicitRefresh/) return "refresh_signer_baseline"
  return "baseline_confirmed_install"
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
  baseline_variant = "(^|[^A-Za-z0-9_])SaSignerSetBaselined(V2)?([^A-Za-z0-9_]|$)"
  files = 0
  na = 0; na2 = 0; nb = 0
  a_bad = ""; a2_bad = ""; b_bad = ""; c_bad = ""; c_variant = ""; d_bad = ""; e_bad = ""; f_bad = ""
  a_locs = ""; a2_locs = ""; b_locs = ""
  b_list = 0; b_refresh = 0; b_install = 0
  while ((getline f < list) > 0) {
    files++
    n = 0
    split("", L)
    split("", C)
    block_depth = 0; raw_end = ""; quoted = 0
    while ((getline line < f) > 0) {
      sub(/\r$/, "", line)
      L[++n] = line
      C[n] = syntax(line)
    }
    close(f)
    skip_tests(n)
    prod_end = n + 1
    has_macro = 0; has_variant = 0
    for (i = 1; i <= n; i++) {
      if (C[i] ~ /[A-Za-z_][A-Za-z0-9_]*!/) has_macro = 1
      if (C[i] ~ /SaSignerSetBaselined/) has_variant = 1
    }
    if (f_bad == "" && has_macro && has_variant) {
      production = ""
      for (i = 1; i <= n; i++) production = production C[i] "\n"
      macro_line = macro_token(production)
      if (macro_line) f_bad = f ":" macro_line
    }
    cur = ""
    split("", seen)
    in_use = 0
    use_text = ""
    for (i = 1; i < prod_end; i++) {
      if (i == test_end + 1) cur = ""
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
        else if (f == signers && cur == "baseline_confirmed_install") b_install++
        else if (b_bad == "") b_bad = loc(f, i, cur)
      }

      if (f != entry && c_bad == "") {
        offset = 0
        rest = line
        while (match(rest, baseline_variant)) {
          variant = substr(rest, RSTART, RLENGTH)
          sub(/^[^A-Za-z0-9_]/, "", variant)
          sub(/[^A-Za-z0-9_]$/, "", variant)
          stop = offset + RSTART + (substr(rest, RSTART, 1) ~ /[^A-Za-z0-9_]/ ? 1 : 0) + length(variant)
          col = opening_brace(i, stop, prod_end)
          definition = (f == schema && !seen[variant] && line ~ ("^[[:space:]]*" variant "[[:space:]]*[{][[:space:]]*$"))
          if (definition) seen[variant] = 1
          else if (col && classify(brace_line, col, prod_end) == "construction") { c_bad = f ":" i; c_variant = variant; break }
          offset = stop - 1
          rest = substr(line, stop)
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
          allowed = (f == signers && cur == reason_owner(hit))
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
    print "FAIL (b): emit_baseline( is called outside fn list_signers, fn refresh_signer_baseline and fn baseline_confirmed_install of " signers " at " b_bad
    exit 1
  }
  if (nb != 3 || b_list != 1 || b_refresh != 1 || b_install != 1) {
    print "FAIL (b): expected one emit_baseline( call in each of fn list_signers, fn refresh_signer_baseline and fn baseline_confirmed_install, found " nb (nb ? " at " b_locs : "")
    exit 1
  }
  if (f_bad != "") {
    print "FAIL (f): a macro names a baseline variant token at " f_bad
    exit 1
  }
  if (c_bad != "") {
    print "FAIL (c): " c_variant " is constructed outside " entry " at " c_bad
    exit 1
  }
  if (d_bad != "") {
    print "FAIL (d): a BaselineReason constructor or variant is used outside its own function of " signers " (first_observation in fn list_signers, explicit_refresh in fn refresh_signer_baseline, confirmed_install in fn baseline_confirmed_install) at " d_bad
    exit 1
  }
  if (e_bad != "") {
    print "FAIL (e): a use statement imports through EventKind:: or renames EventKind outside " entry " and " schema " at " e_bad
    exit 1
  }
  print name ": ok (" files " files; SaSignerSetBaselinedV2 is built only in emit_baseline, reached from list_signers, refresh_signer_baseline and baseline_confirmed_install, each with its own baseline reason; no version-1 baseline constructor call exists in production code)"
}
'
