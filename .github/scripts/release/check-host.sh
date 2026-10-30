#!/usr/bin/env bash
# Builds the release binaries for the host target with the shared release
# recipe and checks that both report mainnet-write on. It then builds each
# binary package alone, as cargo install does, and checks that each of those
# binaries reports mainnet-write on as well. The script installs nothing: on
# Linux without libudev, the one system prerequisite, it prints the install
# command and exits 2. build.sh refuses compiler overrides and cargo
# configuration files, and builds through cross on an aarch64 Linux host.
#
# Usage: check-host.sh, from the repository root
set -euo pipefail
if [ "$(uname -s)" = Linux ] && ! pkg-config --exists libudev 2>/dev/null; then
  echo 'check-host.sh: libudev is missing; install it with: sudo apt-get install -y libudev-dev pkg-config' >&2
  exit 2
fi
target=$(rustc -vV | sed -n 's/^host: //p')
bash .github/scripts/release/build.sh "$target"
bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent" on
bash .github/scripts/check-binary-marker.sh "target/$target/release/stellar-agent-mcp" on
cargo build --locked -p stellar-agent-cli
bash .github/scripts/check-binary-marker.sh target/debug/stellar-agent on
cargo build --locked -p stellar-agent-mcp
bash .github/scripts/check-binary-marker.sh target/debug/stellar-agent-mcp on
