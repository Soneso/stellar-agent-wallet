#!/usr/bin/env bash
# Builds the release executable for the host target with the shared release
# recipe, which also places its stellar-agent-mcp copy, requires equal bytes,
# and checks each name and workspace version with mainnet-write on. It builds the CLI
# package alone, as cargo install does, copies its debug executable to
# target/tmp/host-alias/stellar-agent-mcp with copy_alias of copy-alias.sh,
# requires equal bytes, and checks
# each debug name and workspace version with mainnet-write on. The script installs
# nothing: on Linux without libudev, the one system prerequisite, it prints
# the install command and exits 2. build.sh refuses compiler overrides and
# cargo configuration files, and builds through cross on an aarch64 Linux
# host.
#
# Usage: check-host.sh, from the repository root
set -euo pipefail
if [ "$(uname -s)" = Linux ] && ! pkg-config --exists libudev 2>/dev/null; then
  echo 'check-host.sh: libudev is missing; install it with: sudo apt-get install -y libudev-dev pkg-config' >&2
  exit 2
fi
version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')
version_re='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
if ! [[ "$version" =~ $version_re ]]; then
  echo 'check-host.sh: invalid workspace version' >&2
  exit 2
fi
target=$(rustc -vV | sed -n 's/^host: //p')
bash .github/scripts/release/build.sh "$target"
cmp "target/$target/release/stellar-agent" "target/$target/release/stellar-agent-mcp"
bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent" on "stellar-agent $version"
bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent-mcp" on "stellar-agent-mcp $version"
cargo build --locked -p stellar-agent-cli
mkdir -p target/tmp/host-alias
# shellcheck source=SCRIPTDIR/copy-alias.sh
. .github/scripts/release/copy-alias.sh
copy_alias target/debug/stellar-agent target/tmp/host-alias/stellar-agent-mcp
cmp target/debug/stellar-agent target/tmp/host-alias/stellar-agent-mcp
bash .github/scripts/check-binary-marker.sh target/debug/stellar-agent on "stellar-agent $version"
bash .github/scripts/check-binary-marker.sh target/tmp/host-alias/stellar-agent-mcp on "stellar-agent-mcp $version"
