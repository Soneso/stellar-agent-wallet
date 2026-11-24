#!/usr/bin/env bash
# Installs stellar-agent-cli of a published tag from crates.io, copies its
# stellar-agent executable to stellar-agent-mcp with copy_alias of
# copy-alias.sh, requires equal bytes, and checks the mainnet-write marker
# under both names. The install log is a new mktemp file in a new mode-700
# mktemp directory under RUNNER_TEMP, so no existing path or link is written. The index can lag a
# completed publish, so an install that cargo reports as missing from the
# registry is retried, up to five attempts 30 seconds apart. Any other
# install failure stops the run.
#
# Usage: verify-install.sh <tag> <on|off>
set -euo pipefail
if [ "$#" -ne 2 ]; then
  echo 'usage: verify-install.sh <tag> <on|off>' >&2
  exit 2
fi
TAG=$1
expected=$2
tag_re='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
if ! [[ "$TAG" =~ $tag_re ]]; then
  echo "verify-install.sh: tag '$TAG' does not match $tag_re" >&2
  exit 2
fi
V=${TAG#v}
script_dir=$(cd "$(dirname "$0")/.." && pwd)
log_dir=$(mktemp -d "$RUNNER_TEMP/verify-install-log.XXXXXX")
trap 'rm -rf -- "$log_dir"' EXIT
log=$(mktemp "$log_dir/install.XXXXXX")
package=stellar-agent-cli
installed=0
for attempt in 1 2 3 4 5; do
  status=0
  cargo install --locked --version "$V" "$package" --root "$RUNNER_TEMP/verify-install" 2>"$log" || status=$?
  cat "$log" >&2
  if [ "$status" -eq 0 ]; then
    installed=1
    break
  fi
  grep -qF "could not find \`$package\` in " "$log" || exit 1
  [ "$attempt" -eq 5 ] || sleep 30
done
[ "$installed" -eq 1 ] || exit 1
bin="$RUNNER_TEMP/verify-install/bin"
# shellcheck source=SCRIPTDIR/copy-alias.sh
. "$script_dir/release/copy-alias.sh"
copy_alias "$bin/stellar-agent" "$bin/stellar-agent-mcp"
cmp "$bin/stellar-agent" "$bin/stellar-agent-mcp"
for binary in stellar-agent stellar-agent-mcp; do
  bash "$script_dir/check-binary-marker.sh" "$bin/$binary" "$expected"
done
