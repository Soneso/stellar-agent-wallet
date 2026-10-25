#!/usr/bin/env bash
# Exercises the package, archive, install and host checks with stub tools.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
mkdir -p target/tmp
tmp=$(mktemp -d "$root/target/tmp/release-checks.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
prefix=STELLAR_AGENT_BUILD_MAINNET_WRITE=
make_binary() {
  mkdir -p "$(dirname "$1")"
  printf '#!/usr/bin/env bash\nprintf "stub 1\\n%s%s\\n"\n' "$prefix" "${2:-off}" > "$1"
  chmod +x "$1"
}
expect() {
  local name=$1 wanted=$2 rc=0
  shift 2
  "$@" > "$tmp/output" 2>&1 || rc=$?
  if [ "$rc" -ne "$wanted" ]; then
    echo "FAIL $name: exit $rc, expected $wanted" >&2
    cat "$tmp/output" >&2
    exit 1
  fi
  echo "ok $name"
}
# Requires the output of the last case to hold $2.
expect_output() {
  if ! grep -qF -- "$2" "$tmp/output"; then
    echo "FAIL $1: the output lacks $2" >&2
    cat "$tmp/output" >&2
    exit 1
  fi
}
attempts() {
  if [ "$(cat "$tmp/count")" != "$2" ]; then
    echo "FAIL $1: $(cat "$tmp/count") install attempts, expected $2" >&2
    exit 1
  fi
  rm "$tmp/count"
}

# Package verification builds the binaries into the shared target directory.
target_dir="$tmp/target"
cli="$target_dir/debug/stellar-agent"
mcp="$target_dir/debug/stellar-agent-mcp"
make_binary "$cli"
make_binary "$mcp"
touch -t 200001010000 "$tmp/start"
check=(bash .github/scripts/check-packaged-markers.sh "$target_dir" "$tmp/start" off)
expect package-fresh 0 "${check[@]}"
expect package-start-missing 1 bash .github/scripts/check-packaged-markers.sh "$target_dir" "$tmp/missing" off
expect_output package-start "missing start timestamp"
expect package-usage 2 bash .github/scripts/check-packaged-markers.sh "$target_dir"
expect_output package-usage "usage: check-packaged-markers.sh"
mv "$mcp" "$tmp/mcp"
expect package-binary-missing 1 "${check[@]}"
expect_output package-binary-missing "expected one verification binary for stellar-agent-mcp, found 0"
mv "$tmp/mcp" "$mcp"
touch -t 199901010000 "$cli"
expect package-stale 1 "${check[@]}"
make_binary "$cli"
# Both candidates sit where package verification puts binaries, so only the
# count can fail the check.
make_binary "$target_dir/debug/stellar-agent.exe"
expect package-duplicate 1 "${check[@]}"
expect_output package-duplicate "expected one verification binary for stellar-agent, found 2"
rm "$target_dir/debug/stellar-agent.exe"
mkdir -p "$target_dir/x86_64-unknown-linux-gnu/debug"
mv "$cli" "$target_dir/x86_64-unknown-linux-gnu/debug/stellar-agent"
expect package-location 1 "${check[@]}"
expect_output package-location "outside $target_dir/debug"
mv "$target_dir/x86_64-unknown-linux-gnu/debug/stellar-agent" "$cli"
make_binary "$mcp" on
expect package-state 1 "${check[@]}"
make_binary "$mcp"

stem=stellar-agent-1.0.0-x86_64-unknown-linux-gnu
mkdir "$tmp/$stem"
cp "$cli" "$tmp/$stem/stellar-agent"
cp "$mcp" "$tmp/$stem/stellar-agent-mcp"
tar -cJf "$tmp/$stem.tar.xz" -C "$tmp" "$stem"
archive=(bash .github/scripts/release/verify-archive.sh "$tmp" 1.0.0)
expect archive-markers 0 "${archive[@]}" x86_64-unknown-linux-gnu off
expect archive-state 1 "${archive[@]}" x86_64-unknown-linux-gnu on
expect archive-usage 2 "${archive[@]}"
expect_output archive-usage "usage: verify-archive.sh"
# The CLI binary passes, so only the MCP binary can fail the check.
make_binary "$tmp/$stem/stellar-agent-mcp" on
tar -cJf "$tmp/$stem.tar.xz" -C "$tmp" "$stem"
expect archive-mcp 1 "${archive[@]}" x86_64-unknown-linux-gnu off
expect_output archive-mcp "/stellar-agent is off"

# The Windows archive is a ZIP that the stub 7z extracts.
mkdir "$tmp/bin" "$tmp/runner"
cat > "$tmp/bin/7z" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = x ] && [ "${3#-o}" != "$3" ] || exit 2
python3 - "$2" "${3#-o}" <<'PY'
import os, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    archive.extractall(sys.argv[2])
    for name in archive.namelist():
        os.chmod(os.path.join(sys.argv[2], name), 0o755)
PY
STUB
chmod +x "$tmp/bin/7z"
windows=stellar-agent-1.0.0-x86_64-pc-windows-msvc
make_binary "$tmp/$windows/stellar-agent.exe"
make_binary "$tmp/$windows/stellar-agent-mcp.exe"
python3 - "$tmp/$windows.zip" "$tmp" "$windows" <<'PY'
import pathlib, sys, zipfile
root = pathlib.Path(sys.argv[2])
with zipfile.ZipFile(sys.argv[1], 'w') as archive:
    for path in sorted((root / sys.argv[3]).iterdir()):
        archive.write(path, path.relative_to(root).as_posix())
PY
expect archive-windows 0 env PATH="$tmp/bin:$PATH" "${archive[@]}" x86_64-pc-windows-msvc off
expect_output archive-windows "/stellar-agent-mcp.exe is off"

cat > "$tmp/bin/cargo" <<'STUB'
#!/usr/bin/env bash
# The first four calls report the version missing from the registry, as
# cargo does while the index lags; later calls install the binary of their
# package from INSTALL_STATE.
set -euo pipefail
count=0
[ ! -f "$INSTALL_STATE/count" ] || read -r count < "$INSTALL_STATE/count"
count=$((count + 1))
echo "$count" > "$INSTALL_STATE/count"
[ "$1" = install ] && [ "$2" = --locked ] && [ "$3" = --version ] && [ "$4" = 1.0.0 ] || exit 2
if [ "${INSTALL_ERROR:-0}" = 1 ]; then
  echo "error: failed to compile \`$5\`" >&2
  exit 101
fi
if [ "${INSTALL_FAIL:-0}" = 1 ] || [ "$count" -lt 5 ]; then
  echo "error: could not find \`$5\` in registry \`crates-io\` with version \`=$4\`" >&2
  exit 101
fi
mkdir -p "$7/bin"
cp "$INSTALL_STATE/$5" "$7/bin/$( [ "$5" = stellar-agent-cli ] && echo stellar-agent || echo stellar-agent-mcp )"
STUB
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/sleep"
chmod +x "$tmp/bin/cargo" "$tmp/bin/sleep"
cp "$cli" "$tmp/stellar-agent-cli"
cp "$mcp" "$tmp/stellar-agent-mcp"
export INSTALL_STATE="$tmp" RUNNER_TEMP="$tmp/runner"
install=(env PATH="$tmp/bin:$PATH" bash .github/scripts/release/verify-install.sh)
expect install-retry 0 "${install[@]}" v1.0.0 off
attempts install-retry 6
expect install-bounded 1 env INSTALL_FAIL=1 "${install[@]}" v1.0.0 off
attempts install-bounded 5
expect install-other-error 1 env INSTALL_ERROR=1 "${install[@]}" v1.0.0 off
attempts install-other-error 1
expect install-state 1 "${install[@]}" v1.0.0 on
attempts install-state 6
# The CLI binary passes, so only the MCP binary can fail the check.
make_binary "$tmp/stellar-agent-mcp" on
expect install-mcp 1 "${install[@]}" v1.0.0 off
expect_output install-mcp "/stellar-agent is off"
expect install-tag 2 "${install[@]}" invalid off
expect_output install-tag "does not match"
expect install-usage 2 "${install[@]}" v1.0.0
expect_output install-usage "usage: verify-install.sh"

# A Linux host without libudev gets the install command; nothing runs sudo.
printf '#!/usr/bin/env bash\necho Linux\n' > "$tmp/bin/uname"
printf '#!/usr/bin/env bash\nexit 1\n' > "$tmp/bin/pkg-config"
printf '#!/usr/bin/env bash\necho "$*" >> "%s/sudo.log"\n' "$tmp" > "$tmp/bin/sudo"
chmod +x "$tmp/bin/uname" "$tmp/bin/pkg-config" "$tmp/bin/sudo"
expect host-libudev 2 env PATH="$tmp/bin:$PATH" bash .github/scripts/release/check-host.sh
expect_output host-libudev "sudo apt-get install -y libudev-dev pkg-config"
if [ -e "$tmp/sudo.log" ]; then
  echo 'FAIL host-libudev: check-host.sh ran sudo' >&2
  exit 1
fi
echo 'release assertion tests passed'
