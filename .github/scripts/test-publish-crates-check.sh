#!/usr/bin/env bash
# Offline regression checks for publish-crates.sh --check.
#
# Each case prints "ok   <label>" or "FAIL <label>: <reason>", and the run
# exits 1 when a case fails. The first cases run the script against the real
# workspace. The unpublished-member cases serve the workspace metadata through
# a stub cargo, with one synthetic member that has `publish = false` added, so
# they hold whatever the real workspace contains.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCRIPT="$ROOT/.github/scripts/publish-crates.sh"
tmp_root=${TMPDIR:-/tmp}
TMP=$(mktemp -d "${tmp_root%/}/test-publish-crates-check.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

UNPUBLISHED=stellar-agent-unpublished-probe
MATCH="match every publishable workspace member exactly once"
MISMATCH="Tier lists do not match"

failures=0
fail() {
  echo "FAIL $1: $2" >&2
  failures=$((failures + 1))
}

# Copies the script to $TMP/<name>.sh with sed expression <expr> applied, and
# fails case <label> when the expression changed nothing.
mutate() {
  local label=$1 name=$2 expr=$3
  sed "$expr" "$SCRIPT" >"$TMP/$name.sh"
  if cmp -s "$SCRIPT" "$TMP/$name.sh"; then
    fail "$label" "the edit '$expr' changed nothing"
    return 1
  fi
}

# check_case <label> <pass|refuse> <script> <expected line> [stub]
# Runs <script> --check, against the stub metadata when the fifth argument is
# "stub", and requires the outcome and a line holding <expected line>.
check_case() {
  local label=$1 want=$2 script=$3 expected=$4 rc=0
  if [ "${5:-}" = stub ]; then
    PATH="$TMP/bin:$PATH" STUB_METADATA="$TMP/metadata.json" env -u CARGO_REGISTRY_TOKEN \
      bash "$script" --check >"$TMP/out" 2>&1 || rc=$?
  else
    env -u CARGO_REGISTRY_TOKEN bash "$script" --check >"$TMP/out" 2>&1 || rc=$?
  fi
  if [ "$want" = pass ] && [ "$rc" -ne 0 ]; then
    fail "$label" "exit $rc: $(tail -3 "$TMP/out")"
  elif [ "$want" = refuse ] && [ "$rc" -eq 0 ]; then
    fail "$label" "the check passed"
  elif ! grep -qF -- "$expected" "$TMP/out"; then
    fail "$label" "output lacks '$expected': $(tail -3 "$TMP/out")"
  else
    echo "ok   $label"
  fi
}

cd "$ROOT"

check_case "the tiers match the workspace" pass "$SCRIPT" "$MATCH"

label="a member missing from the tiers"
if mutate "$label" missing 's/ stellar-agent-mpp//'; then
  check_case "$label" refuse "$TMP/missing.sh" "$MISMATCH"
fi

label="a member listed twice"
if mutate "$label" duplicate 's/stellar-agent-mpp stellar-agent-x402/stellar-agent-mpp stellar-agent-mpp stellar-agent-x402/'; then
  check_case "$label" refuse "$TMP/duplicate.sh" "$MISMATCH"
fi

cargo metadata --no-deps --format-version 1 >"$TMP/workspace.json"
python3 - "$TMP/workspace.json" "$TMP/metadata.json" "$UNPUBLISHED" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
version = data["packages"][0]["version"]
data["packages"].append({"name": sys.argv[3], "version": version, "publish": []})
json.dump(data, open(sys.argv[2], "w"))
PY
mkdir -p "$TMP/bin"
cat >"$TMP/bin/cargo" <<'STUB'
#!/usr/bin/env bash
if [ "${1:-}" = metadata ]; then
  cat "$STUB_METADATA"
  exit 0
fi
echo "stub cargo: unexpected call: $*" >&2
exit 99
STUB
chmod +x "$TMP/bin/cargo"

check_case "an unpublished member outside the tiers" pass "$SCRIPT" "$MATCH" stub

# Every unpublished name of the stub metadata, the real ones included, goes
# into a tier. The tiers then hold every member, so only a guard that reads the
# publish field refuses them.
label="every unpublished member in a tier"
UNPUBLISHED_ALL=$(python3 -c "import json,sys; print(' '.join(p['name'] for p in json.load(open(sys.argv[1]))['packages'] if p['publish'] == []))" "$TMP/metadata.json")
if ! grep -qw -- "$UNPUBLISHED" <<<"$UNPUBLISHED_ALL"; then
  fail "$label" "the stub metadata lacks $UNPUBLISHED"
elif mutate "$label" tiered-unpublished "s/^TIER6=\"/TIER6=\"$UNPUBLISHED_ALL /"; then
  check_case "$label" refuse "$TMP/tiered-unpublished.sh" "$MISMATCH" stub
fi

# Metadata travels through a file descriptor above Linux's per-argument limit
# and macOS's total argument limit. Unpublished packages preserve tier membership.
python3 - "$TMP/workspace.json" "$TMP/metadata.json" <<'PYLARGE'
import json, pathlib, sys
metadata = json.load(open(sys.argv[1]))
metadata["packages"].append({
    "name": "unpublished-padding",
    "version": "0.0.0",
    "publish": [],
    "description": "x" * (1024 * 1024),
})
path = pathlib.Path(sys.argv[2])
path.write_text(json.dumps(metadata))
assert path.stat().st_size > 1024 * 1024
PYLARGE
check_case "metadata above 1 MiB" pass "$SCRIPT" "$MATCH" stub

# The member manifests, rather than metadata's resolved dependency list,
# determine normal and build edges, including aliases and target tables.
for spec in same later build target renamed inherited dev earlier; do
  python3 - "$TMP/workspace.json" "$TMP/metadata.json" "$TMP/member.toml" "$spec" <<'PYCASE'
import json, pathlib, sys
metadata = json.load(open(sys.argv[1]))
case = sys.argv[4]
entries = {
    "same": '[dependencies]\nstellar-agent-network = "0.1"',
    "later": '[dependencies]\nstellar-agent-sep43 = "0.1"',
    "build": '[build-dependencies]\nstellar-agent-network = "0.1"',
    "target": '[target.\'cfg(unix)\'.build-dependencies]\nstellar-agent-network = "0.1"',
    "renamed": '[dependencies]\nnet = { package = "stellar-agent-network", version = "0.1", optional = true }',
    "inherited": '[dependencies]\nstellar-agent-network = { workspace = true }',
    "dev": '[dev-dependencies]\nstellar-agent-mcp = "0.1"',
    "earlier": '[dependencies]\nstellar-agent-core = { workspace = true }',
}
pathlib.Path(sys.argv[3]).write_text(entries[case])
for package in metadata["packages"]:
    if package["name"] == "stellar-agent-sep45":
        package["manifest_path"] = sys.argv[3]
json.dump(metadata, open(sys.argv[2], "w"))
PYCASE
  case "$spec" in
    dev|earlier) check_case "$spec dependency allowed" pass "$SCRIPT" "$MATCH" stub ;;
    later) check_case "$spec dependency refused" refuse "$SCRIPT" "stellar-agent-sep45 depends on stellar-agent-sep43" stub ;;
    *) check_case "$spec dependency refused" refuse "$SCRIPT" "stellar-agent-sep45 depends on stellar-agent-network" stub ;;
  esac
done

if [ "$failures" -ne 0 ]; then
  echo "$failures publish check-mode case(s) failed" >&2
  exit 1
fi
echo "publish check-mode tests passed"
