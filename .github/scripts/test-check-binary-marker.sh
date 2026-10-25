#!/usr/bin/env bash
# Stub binaries isolate each marker assertion without compiling Rust.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$root/target/tmp"
tmp=$(mktemp -d "$root/target/tmp/marker.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
checker="$root/.github/scripts/check-binary-marker.sh"
prefix=STELLAR_AGENT_BUILD_MAINNET_WRITE=
run_case() {
  local label=$1 expected=$2 rc=$3 actual=0
  bash "$checker" "$tmp/binary" "$expected" > "$tmp/output" 2>&1 || actual=$?
  if [ "$actual" -ne "$rc" ]; then
    echo "FAIL $label: exit $actual, expected $rc" >&2
    cat "$tmp/output" >&2
    exit 1
  fi
  echo "ok $label"
}
for state in off on; do
  printf '#!/usr/bin/env bash\nprintf "stub 1\\n%s%s\\n"\n' "$prefix" "$state" > "$tmp/binary"
  chmod +x "$tmp/binary"
  run_case "valid-$state" "$state" 0
  run_case "version-line-$state" "$([ "$state" = off ] && echo on || echo off)" 1
done
printf '#!/usr/bin/env bash\nprintf "stub 1\\n%s%s\\n"\n# %soff\n' "$prefix" on "$prefix" > "$tmp/binary"
run_case opposite-bytes on 1
printf '#!/usr/bin/env bash\nprintf "stub 1\\n%%s%%s\\n" "%s" on\n' "$prefix" > "$tmp/binary"
run_case expected-bytes on 1
printf '#!/usr/bin/env bash\nprintf "stub 1\\nincorrect\\n"\n# %soff\n' "$prefix" > "$tmp/binary"
run_case version-line-only off 1
printf '#!/usr/bin/env bash\nprintf "stub 1\\n%soff\\n"\nexit 1\n' "$prefix" > "$tmp/binary"
run_case version-exit off 1
run_case invalid-expectation invalid 2
echo 'binary marker tests passed'
