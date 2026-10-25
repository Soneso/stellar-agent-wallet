#!/usr/bin/env bash
# Checks the binaries that cargo's package verification builds. Cargo
# unpacks each packaged crate under <target-dir>/package and verify-builds
# it into the shared target directory, so the debug binaries of the CLI and
# MCP crates land in <target-dir>/debug. Nothing builds before the packaging
# step in the verify job, so the one binary of each name under the target
# directory, newer than the start timestamp, comes from that step.
#
# Usage: check-packaged-markers.sh <target-dir> <start-timestamp> <on|off>
set -euo pipefail
if [ "$#" -ne 3 ]; then
  echo 'usage: check-packaged-markers.sh <target-dir> <start-timestamp> <on|off>' >&2
  exit 2
fi
target_dir=${1%/}
started=$2
expected=$3
[ -f "$started" ] || { echo 'packaged marker: missing start timestamp' >&2; exit 1; }
script_dir=$(cd "$(dirname "$0")" && pwd)
for binary in stellar-agent stellar-agent-mcp; do
  found=0
  candidate=
  while IFS= read -r path; do
    candidate=$path
    found=$((found + 1))
  done < <(find "$target_dir" -type f \( -name "$binary" -o -name "$binary.exe" \))
  [ "$found" -eq 1 ] || { echo "packaged marker: expected one verification binary for $binary, found $found" >&2; exit 1; }
  case "$candidate" in
    "$target_dir/debug/$binary" | "$target_dir/debug/$binary.exe") ;;
    *) echo "packaged marker: $candidate is outside $target_dir/debug" >&2; exit 1 ;;
  esac
  [ "$candidate" -nt "$started" ] || { echo "packaged marker: stale $binary" >&2; exit 1; }
  bash "$script_dir/check-binary-marker.sh" "$candidate" "$expected"
done
