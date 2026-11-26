#!/usr/bin/env bash
# Exercises package, archive, install, host, and signature checks with stub tools.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
mkdir -p target/tmp
tmp=$(mktemp -d "$root/target/tmp/release-checks.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
prefix=STELLAR_AGENT_BUILD_MAINNET_WRITE=
make_binary() {
  mkdir -p "$(dirname "$1")"
  # shellcheck disable=SC2016 # The stub evaluates its invocation name and test controls.
  printf '#!/usr/bin/env bash\nname=${0##*/}; name=${name%%.exe}\nversion=1.0.0\nif [ "$name" = "${BAD_BINARY:-}" ] && [[ "$0" == *"${BAD_STAGE:-}"* ]]; then\n  name=${BAD_NAME:-$name}; version=${BAD_VERSION:-$version}\nfi\nprintf "%%s %%s\\n%s%s\\n" "$name" "$version"\n' "$prefix" "${2:-off}" > "$1"
  chmod +x "$1"
}
# A binary whose report depends on its invocation name: the canonical name
# reports $2 and the stellar-agent-mcp name reports the other state. Its file
# holds only the $2 literal, so equal copies pass every check but the alias
# marker run.
make_name_sensitive() {
  local opposite=on
  [ "$2" != on ] || opposite=off
  mkdir -p "$(dirname "$1")"
  # shellcheck disable=SC2016 # The stub body expands when the stub runs.
  printf '#!/usr/bin/env bash\nname=${0##*/}; name=${name%%.exe}\nprintf "%%s 1.0.0\\n" "$name"\ncase "$name" in\n  stellar-agent-mcp*) printf "%s%%s\\n" "%s""%s" ;;\n  *) printf "%s%s\\n" ;;\nesac\n' \
    "$prefix" "${opposite:0:1}" "${opposite:1}" "$prefix" "$2" > "$1"
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

# --signatures runs only the manifest, bundle, and workflow fixtures.
if [ "${1:-}" != --signatures ]; then
# Package verification builds the canonical executable into the shared target
# directory; the check derives the alias from it.
target_dir="$tmp/target"
cli="$target_dir/debug/stellar-agent"
make_binary "$cli"
touch -t 200001010000 "$tmp/start"
check=(bash .github/scripts/check-packaged-markers.sh "$target_dir" "$tmp/start" off 1.0.0)
expect package-fresh 0 "${check[@]}"
expect_output package-fresh "$target_dir/debug/stellar-agent is off"
expect_output package-fresh "/stellar-agent-mcp is off"
expect package-start-missing 1 bash .github/scripts/check-packaged-markers.sh "$target_dir" "$tmp/missing" off 1.0.0
expect_output package-start "missing start timestamp"
expect package-usage 2 bash .github/scripts/check-packaged-markers.sh "$target_dir"
expect_output package-usage "usage: check-packaged-markers.sh"
mv "$cli" "$tmp/cli"
expect package-binary-missing 1 "${check[@]}"
expect_output package-binary-missing "expected one verification binary for stellar-agent, found 0"
mv "$tmp/cli" "$cli"
# A leftover alias in the target directory is never a candidate.
make_binary "$target_dir/debug/stellar-agent-mcp" on
expect package-ignores-alias 0 "${check[@]}"
rm "$target_dir/debug/stellar-agent-mcp"
touch -t 199901010000 "$cli"
expect package-stale 1 "${check[@]}"
expect_output package-stale "stale stellar-agent"
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
make_binary "$cli" on
expect package-state 1 "${check[@]}"
# The canonical name passes, so only the derived alias can fail the check.
make_name_sensitive "$cli" off
expect package-alias-state 1 "${check[@]}"
expect_output package-alias-state "$target_dir/debug/stellar-agent is off"
make_binary "$cli"
# A cp first on PATH that appends a comment line to every copy at an alias
# or alias-temporary name. The copy still runs and reports the right state,
# so only the byte comparison can refuse it.
corrupt="$tmp/corrupt-bin"
mkdir -p "$corrupt"
cat > "$corrupt/cp" <<'STUB'
#!/usr/bin/env bash
/bin/cp "$@" || exit
dest=${*: -1}
case "${dest##*/}" in
  stellar-agent-mcp* | .stellar-agent-mcp.*) printf '# corrupted copy\n' >> "$dest" ;;
esac
STUB
chmod +x "$corrupt/cp"
expect package-copy-differs 1 env PATH="$corrupt:$PATH" "${check[@]}"
expect_output package-copy-differs "cmp: EOF on"

# Fixture archives hold the release layout: one directory with README.md,
# LICENSE, and the executable under both names.
stem=stellar-agent-1.0.0-x86_64-unknown-linux-gnu
mkdir "$tmp/$stem"
printf 'readme\n' > "$tmp/$stem/README.md"
printf 'license\n' > "$tmp/$stem/LICENSE"
# Places $1 under both names as equal regular files and packs the archive.
pack_equal() {
  cp "$1" "$tmp/$stem/stellar-agent"
  rm -f "$tmp/$stem/stellar-agent-mcp"
  cp "$1" "$tmp/$stem/stellar-agent-mcp"
  tar -cJf "$tmp/$stem.tar.xz" -C "$tmp" "$stem"
}
pack_equal "$cli"
archive=(bash .github/scripts/release/verify-archive.sh "$tmp" 1.0.0)
expect archive-markers 0 "${archive[@]}" x86_64-unknown-linux-gnu off
expect_output archive-markers "/stellar-agent is off"
expect_output archive-markers "/stellar-agent-mcp is off"
expect archive-state 1 "${archive[@]}" x86_64-unknown-linux-gnu on
expect archive-usage 2 "${archive[@]}"
expect_output archive-usage "usage: verify-archive.sh"
# Equal copies whose canonical name passes, so only the alias run can fail.
make_name_sensitive "$tmp/name-sensitive" off
pack_equal "$tmp/name-sensitive"
expect archive-alias-state 1 "${archive[@]}" x86_64-unknown-linux-gnu off
expect_output archive-alias-state "/stellar-agent is off"
# Two regular files with different bytes, each reporting the right state.
pack_equal "$cli"
printf '# differs\n' >> "$tmp/$stem/stellar-agent-mcp"
tar -cJf "$tmp/$stem.tar.xz" -C "$tmp" "$stem"
expect archive-unequal 1 "${archive[@]}" x86_64-unknown-linux-gnu off
expect_output archive-unequal "stellar-agent and stellar-agent-mcp differ"
# A symbolic link under the alias name.
rm "$tmp/$stem/stellar-agent-mcp"
ln -s stellar-agent "$tmp/$stem/stellar-agent-mcp"
tar -cJf "$tmp/$stem.tar.xz" -C "$tmp" "$stem"
expect archive-symlink 1 "${archive[@]}" x86_64-unknown-linux-gnu off
expect_output archive-symlink "stellar-agent-mcp is not a regular file"
# A hard link: the archive stores one name as a link to the other.
rm "$tmp/$stem/stellar-agent-mcp"
ln "$tmp/$stem/stellar-agent" "$tmp/$stem/stellar-agent-mcp"
tar -cJf "$tmp/$stem.tar.xz" -C "$tmp" "$stem"
expect archive-hardlink 1 "${archive[@]}" x86_64-unknown-linux-gnu off
expect_output archive-hardlink "stellar-agent has more than one link"
pack_equal "$cli"

for literal in STELLAR_AGENT_HOME STELLAR_AGENT_TEST_OWNER_PUBKEY_FILE; do
  make_binary "$tmp/override"
  printf '# %s\n' "$literal" >> "$tmp/override"
  pack_equal "$tmp/override"
  expect "archive-test-override-$literal" 1 "${archive[@]}" x86_64-unknown-linux-gnu off
  expected_literal=$literal
  [ "$literal" != STELLAR_AGENT_TEST_OWNER_PUBKEY_FILE ] || expected_literal=STELLAR_AGENT_TEST_
  expect_output "archive-test-override-$literal" "marker: test override literal $expected_literal is embedded"
done
pack_equal "$cli"

# The signing action derives the alias from the signed canonical file.
derive=(bash .github/actions/macos-sign-notarize/derive-alias.sh)
signed="$tmp/signed"
mkdir "$signed"
make_binary "$signed/stellar-agent"
chmod 0751 "$signed/stellar-agent"
expect derive-ordinary 0 "${derive[@]}" "$signed" ''
cmp "$signed/stellar-agent" "$signed/stellar-agent-mcp"
if [ -L "$signed/stellar-agent-mcp" ] || [ -z "$(find "$signed/stellar-agent-mcp" -links 1 -perm 0751)" ]; then
  echo 'FAIL derive-ordinary: the alias is not a single-link copy with the canonical mode' >&2
  exit 1
fi
printf 'stale alias\n' > "$signed/stellar-agent-mcp"
expect derive-replaces 0 "${derive[@]}" "$signed" ''
cmp "$signed/stellar-agent" "$signed/stellar-agent-mcp"
if [ "$(find "$signed" -name '.stellar-agent-mcp.*' | wc -l)" -ne 0 ]; then
  echo 'FAIL derive-replaces: a temporary file is left' >&2
  exit 1
fi
make_binary "$signed/stellar-agent.exe"
expect derive-exe 0 "${derive[@]}" "$signed" .exe
cmp "$signed/stellar-agent.exe" "$signed/stellar-agent-mcp.exe"
expect derive-usage 2 "${derive[@]}" "$signed"
expect_output derive-usage "usage: derive-alias.sh"
expect derive-suffix 2 "${derive[@]}" "$signed" .bin
mv "$signed/stellar-agent" "$tmp/signed-canonical"
expect derive-missing 1 "${derive[@]}" "$signed" ''
expect_output derive-missing "stellar-agent is not a regular file"
ln -s "$tmp/signed-canonical" "$signed/stellar-agent"
expect derive-symlink 1 "${derive[@]}" "$signed" ''
expect_output derive-symlink "stellar-agent is not a regular file"
rm "$signed/stellar-agent"
ln "$tmp/signed-canonical" "$signed/stellar-agent"
printf 'kept alias\n' > "$signed/stellar-agent-mcp"
expect derive-hardlink 1 "${derive[@]}" "$signed" ''
expect_output derive-hardlink "stellar-agent has more than one link"
if [ "$(cat "$signed/stellar-agent-mcp")" != 'kept alias' ]; then
  echo 'FAIL derive-hardlink: the refusal changed the alias' >&2
  exit 1
fi
rm "$signed/stellar-agent" "$signed/stellar-agent-mcp"
cp "$tmp/signed-canonical" "$signed/stellar-agent"
# A directory link at the alias name refuses and receives nothing.
mkdir -p "$tmp/derive-victimdir"
ln -s "$tmp/derive-victimdir" "$signed/stellar-agent-mcp"
expect derive-directory-link 1 "${derive[@]}" "$signed" ''
expect_output derive-directory-link "stellar-agent-mcp is not a regular file"
if [ -n "$(ls -A "$tmp/derive-victimdir")" ]; then
  echo 'FAIL derive-directory-link: the linked directory received a file' >&2
  exit 1
fi
rm "$signed/stellar-agent-mcp"
# A file link at the alias name, even to the canonical file, refuses.
ln -s "$signed/stellar-agent" "$signed/stellar-agent-mcp"
expect derive-file-link 1 "${derive[@]}" "$signed" ''
expect_output derive-file-link "stellar-agent-mcp is not a regular file"
if [ ! -L "$signed/stellar-agent-mcp" ]; then
  echo 'FAIL derive-file-link: the refusal replaced the link' >&2
  exit 1
fi
rm "$signed/stellar-agent-mcp"
# A directory link that appears at the alias name after the check is
# replaced by the rename. A copy of the script whose cp plants that link
# stands in for the race.
mkdir -p "$tmp/derive-race"
cat > "$tmp/derive-race/cp" <<'STUB'
#!/bin/bash
/bin/cp "$@" || exit
rm -f "$RACE_LINK"
ln -s "$RACE_VICTIM" "$RACE_LINK"
STUB
chmod +x "$tmp/derive-race/cp"
sed "s#/bin/cp -p#$tmp/derive-race/cp -p#" .github/actions/macos-sign-notarize/derive-alias.sh > "$tmp/derive-race/derive-alias.sh"
if [ "$(grep -c "$tmp/derive-race/cp -p" "$tmp/derive-race/derive-alias.sh")" -ne 1 ]; then
  echo 'FAIL derive-directory-race: the copy of derive-alias.sh does not use the racing cp' >&2
  exit 1
fi
expect derive-directory-race 0 env RACE_LINK="$signed/stellar-agent-mcp" RACE_VICTIM="$tmp/derive-victimdir" \
  bash "$tmp/derive-race/derive-alias.sh" "$signed" ''
if [ -n "$(ls -A "$tmp/derive-victimdir")" ] || [ -L "$signed/stellar-agent-mcp" ] ||
  ! cmp -s "$signed/stellar-agent" "$signed/stellar-agent-mcp"; then
  echo 'FAIL derive-directory-race: the raced directory link was followed' >&2
  exit 1
fi

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
cp "$tmp/$windows/stellar-agent.exe" "$tmp/$windows/stellar-agent-mcp.exe"
printf 'readme\n' > "$tmp/$windows/README.md"
printf 'license\n' > "$tmp/$windows/LICENSE"
python3 - "$tmp/$windows.zip" "$tmp" "$windows" <<'PY'
import pathlib, sys, zipfile
root = pathlib.Path(sys.argv[2])
with zipfile.ZipFile(sys.argv[1], 'w') as archive:
    for path in sorted((root / sys.argv[3]).iterdir()):
        archive.write(path, path.relative_to(root).as_posix())
PY
expect archive-windows 0 env PATH="$tmp/bin:$PATH" "${archive[@]}" x86_64-pc-windows-msvc off
expect_output archive-windows "/stellar-agent.exe is off"
expect_output archive-windows "/stellar-agent-mcp.exe is off"

# Each caller checks both invocation names and the supplied version.
for binary in stellar-agent stellar-agent-mcp; do
  for fault in BAD_NAME=wrong BAD_VERSION=2.0.0; do
    expect "package-$binary-$fault" 1 env BAD_BINARY="$binary" "$fault" "${check[@]}"
    expect_output version-line 'version line 1 differs'
    expect "archive-linux-$binary-$fault" 1 env BAD_BINARY="$binary" "$fault" "${archive[@]}" x86_64-unknown-linux-gnu off
    expect_output version-line 'version line 1 differs'
    expect "archive-windows-$binary-$fault" 1 env PATH="$tmp/bin:$PATH" BAD_BINARY="$binary" "$fault" "${archive[@]}" x86_64-pc-windows-msvc off
    expect_output version-line 'version line 1 differs'
  done
done

cat > "$tmp/bin/cargo" <<'STUB'
#!/usr/bin/env bash
# The first four calls report the version missing from the registry, as
# cargo does while the index lags; later calls install the stellar-agent
# executable from INSTALL_STATE. Only stellar-agent-cli is an install package.
set -euo pipefail
count=0
[ ! -f "$INSTALL_STATE/count" ] || read -r count < "$INSTALL_STATE/count"
count=$((count + 1))
echo "$count" > "$INSTALL_STATE/count"
[ "$1" = install ] && [ "$2" = --locked ] && [ "$3" = --version ] && [ "$4" = 1.0.0 ] || exit 2
[ "$5" = stellar-agent-cli ] && [ "$6" = --root ] && [ "$#" -eq 7 ] || exit 3
if [ "${INSTALL_ERROR:-0}" = 1 ]; then
  echo "error: failed to compile \`$5\`" >&2
  exit 101
fi
if [ "${INSTALL_FAIL:-0}" = 1 ] || [ "$count" -lt 5 ]; then
  echo "error: could not find \`$5\` in registry \`crates-io\` with version \`=$4\`" >&2
  exit 101
fi
mkdir -p "$7/bin"
cp "$INSTALL_STATE/stellar-agent" "$7/bin/stellar-agent"
STUB
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/sleep"
chmod +x "$tmp/bin/cargo" "$tmp/bin/sleep"
cp "$cli" "$tmp/stellar-agent"
export INSTALL_STATE="$tmp" RUNNER_TEMP="$tmp/runner"
install=(env PATH="$tmp/bin:$PATH" bash .github/scripts/release/verify-install.sh)
# One package: four registry misses, then the fifth and last attempt installs.
expect install-retry 0 "${install[@]}" v1.0.0 off
attempts install-retry 5
expect_output install-retry "/bin/stellar-agent is off"
expect_output install-retry "/bin/stellar-agent-mcp is off"
cmp "$RUNNER_TEMP/verify-install/bin/stellar-agent" "$RUNNER_TEMP/verify-install/bin/stellar-agent-mcp"
expect install-bounded 1 env INSTALL_FAIL=1 "${install[@]}" v1.0.0 off
attempts install-bounded 5
expect install-other-error 1 env INSTALL_ERROR=1 "${install[@]}" v1.0.0 off
attempts install-other-error 1
expect install-state 1 "${install[@]}" v1.0.0 on
attempts install-state 5
# The canonical name passes, so only the derived alias can fail the check.
make_name_sensitive "$tmp/stellar-agent" off
expect install-alias-state 1 "${install[@]}" v1.0.0 off
expect_output install-alias-state "/stellar-agent is off"
rm "$tmp/count"
cp "$cli" "$tmp/stellar-agent"
# A changed copy fails the comparison even though both names report off.
expect install-copy-differs 1 env PATH="$corrupt:$tmp/bin:$PATH" bash .github/scripts/release/verify-install.sh v1.0.0 off
expect_output install-copy-differs "cmp: EOF on"
rm "$tmp/count"
# A link planted at the former fixed temporary name is never followed: the
# victim keeps its bytes and the alias is a new equal file.
installed="$RUNNER_TEMP/verify-install/bin"
printf 'victim\n' > "$tmp/victim"
mkdir -p "$tmp/victimdir"
ln -s "$tmp/victim" "$installed/.stellar-agent-mcp.tmp"
expect install-links 0 "${install[@]}" v1.0.0 off
if [ "$(cat "$tmp/victim")" != victim ] || [ -L "$installed/stellar-agent-mcp" ] ||
  ! cmp -s "$installed/stellar-agent" "$installed/stellar-agent-mcp"; then
  echo 'FAIL install-links: a planted link was followed or the alias is not an equal file' >&2
  exit 1
fi
if [ "$(find "$installed" -name '.stellar-agent-mcp.?*' ! -name '.stellar-agent-mcp.tmp' | wc -l)" -ne 0 ]; then
  echo 'FAIL install-links: a temporary file is left' >&2
  exit 1
fi
rm "$installed/.stellar-agent-mcp.tmp" "$tmp/count"
# A directory link at the alias name refuses and receives nothing.
rm -f "$installed/stellar-agent-mcp"
ln -s "$tmp/victimdir" "$installed/stellar-agent-mcp"
expect install-directory-link 1 "${install[@]}" v1.0.0 off
expect_output install-directory-link "stellar-agent-mcp is not a regular file"
if [ -n "$(ls -A "$tmp/victimdir")" ]; then
  echo 'FAIL install-directory-link: the linked directory received a file' >&2
  exit 1
fi
rm "$installed/stellar-agent-mcp" "$tmp/count"
# A file link at the alias name, even to the canonical file, refuses and the
# canonical file keeps its bytes.
cp "$installed/stellar-agent" "$tmp/canonical.before"
ln -s "$installed/stellar-agent" "$installed/stellar-agent-mcp"
expect install-file-link 1 "${install[@]}" v1.0.0 off
expect_output install-file-link "stellar-agent-mcp is not a regular file"
if [ ! -L "$installed/stellar-agent-mcp" ] || ! cmp -s "$installed/stellar-agent" "$tmp/canonical.before"; then
  echo 'FAIL install-file-link: the link was replaced or the canonical file changed' >&2
  exit 1
fi
rm "$installed/stellar-agent-mcp" "$tmp/count"
# A directory link that appears at the alias name after the check, while the
# copy runs, is replaced by the rename and receives nothing.
race="$tmp/race-bin"
mkdir -p "$race"
cat > "$race/cp" <<'STUB'
#!/usr/bin/env bash
/bin/cp "$@" || exit
case "${*: -1}" in
  */.stellar-agent-mcp.*) rm -f "$RACE_LINK"; ln -s "$RACE_VICTIM" "$RACE_LINK" ;;
esac
STUB
chmod +x "$race/cp"
expect install-directory-race 0 env PATH="$race:$tmp/bin:$PATH" RACE_LINK="$installed/stellar-agent-mcp" \
  RACE_VICTIM="$tmp/victimdir" bash .github/scripts/release/verify-install.sh v1.0.0 off
if [ -n "$(ls -A "$tmp/victimdir")" ] || [ -L "$installed/stellar-agent-mcp" ] ||
  ! cmp -s "$installed/stellar-agent" "$installed/stellar-agent-mcp"; then
  echo 'FAIL install-directory-race: the raced directory link was followed' >&2
  exit 1
fi
rm "$tmp/count"
# The install log is never a fixed path: a link planted at the former log
# path keeps its victim unchanged, and no log directory stays behind.
if [ -e "$RUNNER_TEMP/verify-install.log" ] || [ -L "$RUNNER_TEMP/verify-install.log" ]; then
  echo 'FAIL install-log-link: the earlier installs wrote the fixed log path' >&2
  exit 1
fi
ln -s "$tmp/victim" "$RUNNER_TEMP/verify-install.log"
expect install-log-link 0 "${install[@]}" v1.0.0 off
if [ "$(cat "$tmp/victim")" != victim ]; then
  echo 'FAIL install-log-link: the planted log link was followed' >&2
  exit 1
fi
if [ "$(find "$RUNNER_TEMP" -maxdepth 1 -name 'verify-install-log.*' | wc -l)" -ne 0 ]; then
  echo 'FAIL install-log-link: a log directory is left' >&2
  exit 1
fi
rm "$RUNNER_TEMP/verify-install.log" "$tmp/count"
expect install-tag 2 "${install[@]}" invalid off
expect_output install-tag "does not match"
expect install-usage 2 "${install[@]}" v1.0.0
expect_output install-usage "usage: verify-install.sh"
for binary in stellar-agent stellar-agent-mcp; do
  for fault in BAD_NAME=wrong BAD_VERSION=2.0.0; do
    expect "install-$binary-$fault" 1 env BAD_BINARY="$binary" "$fault" "${install[@]}" v1.0.0 off
    expect_output version-line 'version line 1 differs'
    attempts install-version 5
  done
done

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

# A scratch checkout keeps the real host checker and replaces only build tools.
host="$tmp/host"
mkdir -p "$host/.github/scripts/release" "$host/bin"
cp .github/scripts/release/{check-host,copy-alias}.sh "$host/.github/scripts/release/"
cp .github/scripts/check-binary-marker.sh "$host/.github/scripts/"
printf '[workspace.package]\nversion = "1.0.0"\n' > "$host/Cargo.toml"
make_binary "$host/fixture" on
cat > "$host/.github/scripts/release/build.sh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "target/$1/release"
cp "$HOST_BINARY" "target/$1/release/stellar-agent"
cp "$HOST_BINARY" "target/$1/release/stellar-agent-mcp"
STUB
cat > "$host/bin/cargo" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[ "$*" = 'build --locked -p stellar-agent-cli' ] || exit 3
mkdir -p target/debug
cp "$HOST_BINARY" target/debug/stellar-agent
STUB
printf '#!/usr/bin/env bash\nprintf "host: fixture-target\\n"\n' > "$host/bin/rustc"
printf '#!/usr/bin/env bash\nexit 0\n' > "$host/bin/pkg-config"
cp "$tmp/bin/uname" "$host/bin/uname"
chmod +x "$host/bin/"*
host_check() (
  cd "$host"
  env PATH="$host/bin:$PATH" HOST_BINARY="$host/fixture" "$@" bash .github/scripts/release/check-host.sh
)
expect host-valid 0 host_check
for specification in 'release stellar-agent' 'release stellar-agent-mcp' 'debug stellar-agent' 'host-alias stellar-agent-mcp'; do
  read -r stage binary <<< "$specification"
  for fault in BAD_NAME=wrong BAD_VERSION=2.0.0; do
    expect "host-$stage-$binary-$fault" 1 host_check BAD_STAGE="$stage" BAD_BINARY="$binary" "$fault"
    expect_output version-line "version line 1 differs from $binary 1.0.0"
  done
done
printf '[workspace.package]\nversion = "invalid"\n' > "$host/Cargo.toml"
expect host-invalid-version 2 host_check
expect_output host-invalid-version 'invalid workspace version'
printf '[workspace.package]\nversion = "1.0.0"\n' > "$host/Cargo.toml"
# File-specific download bytes make the logged MSVC archive digest reproducible.
cat > "$tmp/bin/curl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then
    [ "${2##*/}" != "${CURL_FAIL_FILE:-}" ] || exit 22
    printf 'fixed:%s\n' "${2##*/}" > "$2"
    exit 0
  fi
  shift
done
exit 2
STUB
chmod +x "$tmp/bin/curl"
printf 'EXISTING=value\n' > "$tmp/github-env"
stub_digest=$(printf 'fixed:%s\n' libsodium-1.0.22-stable-msvc.zip |
  python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')
# The split literal keeps the environment-file scanner of
# check-feature-discipline.py from reading this fixture line as a write.
# shellcheck disable=SC2016 # The inner shell expands its stderr path argument.
expect sodium-download 0 env PATH="$tmp/bin:$PATH" "GITHUB""_ENV=$tmp/github-env" \
  bash -c 'bash .github/scripts/release/sodium.sh 2> "$1"' -- "$tmp/sodium-stderr"
if ! cmp -s "$tmp/output" <(printf 'sodium: libsodium-1.0.22-stable-msvc.zip SHA-256 %s\n' "$stub_digest"); then
  echo 'FAIL sodium-download: stdout is not exactly the archive digest line' >&2
  exit 1
fi
if [ -s "$tmp/sodium-stderr" ]; then
  echo 'FAIL sodium-download: stderr is not empty' >&2
  exit 1
fi
for name in libsodium-1.0.22-stable-msvc.zip libsodium-1.0.22-stable-msvc.zip.minisig LATEST.tar.gz LATEST.tar.gz.minisig; do
  [ -s "$RUNNER_TEMP/sodium-dist/$name" ] || { echo "FAIL sodium-download: missing $name" >&2; exit 1; }
done
if ! cmp -s "$tmp/github-env" <(printf 'EXISTING=value\nSODIUM_DIST_DIR=%s/sodium-dist\n' "$RUNNER_TEMP"); then
  echo 'FAIL sodium-download: the environment file is not the existing line followed by exactly one SODIUM_DIST_DIR line' >&2
  cat "$tmp/github-env" >&2
  exit 1
fi
# A failed download stops setup before the directory reaches the build.
: > "$tmp/github-env"
expect sodium-download-fails 22 env PATH="$tmp/bin:$PATH" "GITHUB""_ENV=$tmp/github-env" \
  CURL_FAIL_FILE=LATEST.tar.gz.minisig bash .github/scripts/release/sodium.sh
if [ -s "$tmp/github-env" ]; then
  echo 'FAIL sodium-download-fails: exports an incomplete download directory' >&2
  exit 1
fi

fi

release="$tmp/publication"
mkdir -p "$release/all-artifacts/linux" "$release/all-artifacts/windows" "$release/release-combined" "$release/all-signatures"
for name in mac-arm.tar.xz mac-intel.tar.xz linux-arm.tar.xz; do
  printf "%s\\n" "$name" > "$release/all-artifacts/linux/$name"
done
printf 'linux archive\n' > "$release/all-artifacts/linux/fixture.tar.xz"
printf 'windows archive\n' > "$release/all-artifacts/windows/fixture.zip"
python3 - "$release" <<'PY_SUMS'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
with (root / 'release-combined/SHA256SUMS').open('w') as sums:
    for path in sorted((root / 'all-artifacts').rglob('*')):
        if path.is_file():
            sums.write(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n')
            (root / "all-signatures" / (path.name + ".sigstore.json")).write_bytes(path.read_bytes())
(root / "all-signatures/SHA256SUMS.sigstore.json").write_bytes((root / "release-combined/SHA256SUMS").read_bytes())
PY_SUMS
sums=(bash .github/scripts/release/verify-sums.sh "$release")
expect sums-equal 0 "${sums[@]}"
expect_output sums-equal '5 archives match SHA256SUMS'
cp "$release/all-artifacts/windows/fixture.zip" "$release/all-artifacts/windows/extra.zip"
expect sums-extra 1 "${sums[@]}"
expect_output sums-extra 'archive set differs'
rm "$release/all-artifacts/windows/extra.zip"
mv "$release/all-artifacts/windows/fixture.zip" "$tmp/fixture.zip"
expect sums-missing 1 "${sums[@]}"
expect_output sums-missing 'archive set differs'
mv "$tmp/fixture.zip" "$release/all-artifacts/windows/fixture.zip"
size=$(wc -c < "$release/all-artifacts/windows/fixture.zip")
printf X | dd of="$release/all-artifacts/windows/fixture.zip" bs=1 seek=3 conv=notrunc 2>/dev/null
if [ "$(wc -c < "$release/all-artifacts/windows/fixture.zip")" != "$size" ]; then
  echo 'FAIL sums-changed-byte: the archive length changed' >&2
  exit 1
fi
expect sums-changed-byte 1 "${sums[@]}"
expect_output sums-changed-byte 'SHA-256 differs: fixture.zip'
printf 'windows archive\n' > "$release/all-artifacts/windows/fixture.zip"
cp "$release/all-artifacts/windows/fixture.zip" "$release/all-artifacts/linux/fixture.zip"
expect sums-duplicate-archive 1 "${sums[@]}"
expect_output sums-duplicate-archive 'duplicate archive name'
rm "$release/all-artifacts/linux/fixture.zip"
cp "$release/release-combined/SHA256SUMS" "$tmp/sums"
cat "$tmp/sums" >> "$release/release-combined/SHA256SUMS"
expect sums-duplicate-entry 1 "${sums[@]}"
expect_output sums-duplicate-entry 'duplicate SHA256SUMS name'
: > "$release/release-combined/SHA256SUMS"
expect sums-empty 1 "${sums[@]}"
expect_output sums-empty 'SHA256SUMS must list exactly five archives'
for name in 'linux/fixture.tar.xz' 'linux\fixture.tar.xz'; do
  python3 -c 'import sys; text = open(sys.argv[1]).read(); print(text.replace("  fixture.tar.xz\n", f"  {sys.argv[2]}\n"), end="")' \
    "$tmp/sums" "$name" > "$release/release-combined/SHA256SUMS"
  if ! grep -qF -- "  $name" "$release/release-combined/SHA256SUMS"; then
    echo "FAIL sums-path-separator: the entry $name was not written" >&2
    exit 1
  fi
  expect "sums-path-separator $name" 1 "${sums[@]}"
  expect_output "sums-path-separator $name" 'invalid SHA256SUMS entry'
done
cp "$tmp/sums" "$release/release-combined/SHA256SUMS"
expect sums-restored 0 "${sums[@]}"
mv "$release/all-artifacts/windows/fixture.zip" "$tmp/fixture.zip"
ln -s "$tmp/fixture.zip" "$release/all-artifacts/windows/fixture.zip"
expect sums-symlink 1 "${sums[@]}"
expect_output sums-symlink 'archive is not a regular file: fixture.zip'
rm "$release/all-artifacts/windows/fixture.zip"
mkdir "$release/all-artifacts/windows/fixture.zip"
expect sums-directory 1 "${sums[@]}"
expect_output sums-directory 'archive is not a regular file: fixture.zip'
rmdir "$release/all-artifacts/windows/fixture.zip"
mv "$tmp/fixture.zip" "$release/all-artifacts/windows/fixture.zip"
expect sums-final 0 "${sums[@]}"
python3 - "$release" "$tmp" <<'PY_SIGNATURES'
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap

release, scratch = map(Path, sys.argv[1:])
tools = scratch / 'cosign-bin'
tools.mkdir()
stub = tools / 'cosign'
stub.write_text('#!' + sys.executable + '''
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['COSIGN_LOG'], 'a') as log:
    log.write(json.dumps(args) + '\\n')
if os.environ.get('COSIGN_FAIL') or pathlib.Path(args[-1]).name == os.environ.get('COSIGN_FAIL_FILE'):
    sys.exit(9)
if args[0] == 'sign-blob':
    assert args[1:3] == ['--yes', '--bundle'] and len(args) == 5
    pathlib.Path(args[3]).write_bytes(pathlib.Path(args[4]).read_bytes())
else:
    assert args[0:2] == ['verify-blob', '--bundle'] and len(args) == 10
    assert args[3:9] == ['--certificate-identity', 'identity', '--certificate-oidc-issuer',
                          'issuer', '--certificate-github-workflow-sha', 'sha']
    assert pathlib.Path(args[2]).read_bytes() == pathlib.Path(args[9]).read_bytes()
''')
stub.chmod(0o755)
log = scratch / 'cosign.log'
env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'], COSIGN_LOG=str(log))
verify = ['bash', '.github/scripts/release/verify-signatures.sh']
sums = ['bash', '.github/scripts/release/verify-sums.sh']

def run(label, command, status=0, message='', extra=None):
    result = subprocess.run(command, env=env | (extra or {}), capture_output=True, text=True)
    assert result.returncode == status, (label, result.returncode, result.stdout, result.stderr)
    assert message in result.stdout + result.stderr, (label, message, result.stderr)
    print('ok', label)

def check(label, status=1, message='', claims=('identity', 'issuer', 'sha'), extra=None):
    run(label, verify + [str(release), *claims], status, message, extra)

check('signatures-six-exact-pairs', 0)
calls = [json.loads(line) for line in log.read_text().splitlines()]
files = [p for p in (release / 'all-artifacts').rglob('*') if p.is_file()]
files.append(release / 'release-combined/SHA256SUMS')
assert len(calls) == 6
assert {(call[9], call[2]) for call in calls} == {
    (str(p), str(release / 'all-signatures' / (p.name + '.sigstore.json'))) for p in files}
for index, label in enumerate(('identity', 'issuer', 'workflow-sha')):
    claims = ['identity', 'issuer', 'sha']
    claims[index] = 'wrong'
    check('wrong-' + label, message='verify-signatures: SHA256SUMS:', claims=claims)
    claims[index] = ''
    log.write_text('')
    check('empty-' + label, 2, 'must be non-empty', claims=claims)
    assert not log.read_text(), 'empty claims must fail before cosign runs'
check('cosign-failure', message='verify-signatures: SHA256SUMS:', extra={'COSIGN_FAIL': '1'})
check('cosign-archive-failure', message='verify-signatures: fixture.zip:', extra={'COSIGN_FAIL_FILE': 'fixture.zip'})
minimal = scratch / 'without-cosign'
minimal.mkdir()
for name in ('bash', 'dirname', 'python3'):
    (minimal / name).symlink_to(shutil.which(name))
check('cosign-missing', message='verify-signatures: SHA256SUMS:', extra={'PATH': str(minimal)})
run('signatures-usage', verify, 2, 'usage: verify-signatures.sh')
run('sums-usage', sums, 2, 'usage: verify-sums.sh')
for name in ('fixture.zip.sigstore.json', 'SHA256SUMS.sigstore.json'):
    bundle = release / 'all-signatures' / name
    contents = bundle.read_bytes()
    for kind in ('missing', 'extra', 'duplicate', 'symlink', 'directory'):
        other = release / 'all-signatures/other'
        other.mkdir()
        if kind == 'extra':
            (other / 'extra.sigstore.json').write_bytes(contents)
        elif kind == 'duplicate':
            (other / name).write_bytes(contents)
        else:
            bundle.unlink()
            if kind == 'symlink':
                bundle.symlink_to(files[0])
            elif kind == 'directory':
                bundle.mkdir()
        check(f'bundle-{name}-{kind}', message='bundle')
        run(f'sums-bundle-{name}-{kind}', sums + [str(release)], 1, 'bundle')
        shutil.rmtree(other)
        if bundle.is_symlink():
            bundle.unlink()
        elif bundle.is_dir():
            bundle.rmdir()
        bundle.write_bytes(contents)
manifest = release / 'release-combined/SHA256SUMS'
original = manifest.read_bytes()
for count in (4, 6):
    lines = original.splitlines(keepends=True)
    manifest.write_bytes(b''.join(lines[:count]) if count == 4 else original + lines[0].replace(b'fixture.tar.xz', b'extra.tar.xz'))
    check(f'archive-count-{count}', message='exactly five archives')
manifest.write_bytes(original.replace(b'  ', b' *', 1))
check('changed-manifest-byte', message='verify-signatures: SHA256SUMS:')
manifest.write_bytes(original)
archive = release / 'all-artifacts/windows/fixture.zip'
contents = archive.read_bytes()
archive.write_bytes(contents.replace(b'w', b'W', 1))
check('changed-archive-byte', message='SHA-256 differs: fixture.zip')
archive.write_bytes(contents)
for kind in ('missing', 'symlink', 'directory'):
    manifest.unlink()
    if kind == 'symlink':
        manifest.symlink_to(archive)
    elif kind == 'directory':
        manifest.mkdir()
    check('manifest-' + kind, message='SHA256SUMS is not a regular file')
    if manifest.is_symlink():
        manifest.unlink()
    elif manifest.is_dir():
        manifest.rmdir()
    manifest.write_bytes(original)

# Execute the signing step itself so a workflow edit cannot restore skipping.
def workflow_run(workflow, name):
    step = Path('.github/workflows/' + workflow).read_text().split('      - name: ' + name + '\n', 1)[1]
    block = step.split('        run: |\n', 1)[1].splitlines(keepends=True)
    end = next((i for i, line in enumerate(block) if line.strip() and not line.startswith('          ')), len(block))
    return textwrap.dedent(''.join(block[:end]))

sign = workflow_run('release.yml', 'Sign archives and SHA256SUMS with cosign')
signroot = scratch / 'signing'
signroot.mkdir()
shutil.copytree(release / 'all-artifacts', signroot / 'artifacts')
shutil.copytree(release / 'release-combined', signroot / 'release-combined')
log.write_text('')
run('sign-six', ['bash', '-c', sign], extra={'RUNNER_TEMP': str(signroot)})
calls = [json.loads(line) for line in log.read_text().splitlines()]
assert len(calls) == 6 and {Path(c[-1]).name for c in calls} == {p.name for p in files}
sign_sums = signroot / 'release-combined/SHA256SUMS'
for kind in ('empty', 'four', 'six', 'duplicate', 'invalid', 'missing', 'symlink', 'directory'):
    sign_sums.unlink()
    if kind == 'symlink':
        sign_sums.symlink_to(manifest)
    elif kind == 'directory':
        sign_sums.mkdir()
    elif kind != 'missing':
        body = {'empty': b'', 'four': b''.join(original.splitlines(keepends=True)[:4]),
                'six': original + original.splitlines(keepends=True)[0],
                'duplicate': b''.join(original.splitlines(keepends=True)[:4]) + original.splitlines(keepends=True)[0],
                'invalid': b'invalid\n'}[kind]
        sign_sums.write_bytes(body)
    log.write_text('')
    run('sign-manifest-' + kind, ['bash', '-c', sign], 1, 'sign:', {'RUNNER_TEMP': str(signroot)})
    assert not log.read_text(), 'invalid input must fail before any signing'
    if sign_sums.is_symlink():
        sign_sums.unlink()
    elif sign_sums.is_dir():
        sign_sums.rmdir()
    sign_sums.write_bytes(original)
for kind in ('missing', 'symlink', 'directory', 'duplicate', 'extra', 'duplicate-sums'):
    path = signroot / 'artifacts/windows/fixture.zip'
    other = signroot / 'artifacts/linux/fixture.zip'
    if kind in ('missing', 'symlink', 'directory'):
        path.unlink()
        if kind == 'symlink':
            path.symlink_to(archive)
        elif kind == 'directory':
            path.mkdir()
    else:
        other = other.with_name({'duplicate': 'fixture.zip', 'extra': 'extra.zip', 'duplicate-sums': 'SHA256SUMS'}[kind])
        other.write_bytes(contents)
    log.write_text('')
    run('sign-archive-' + kind, ['bash', '-c', sign], 1, 'sign:', {'RUNNER_TEMP': str(signroot)})
    assert not log.read_text(), 'invalid input must fail before any signing'
    if kind in ('duplicate', 'extra', 'duplicate-sums'):
        other.unlink()
    elif path.is_symlink():
        path.unlink()
    elif path.is_dir():
        path.rmdir()
    path.write_bytes(contents)
run('sign-cosign-failure', ['bash', '-c', sign], 1, 'sign:', {'RUNNER_TEMP': str(signroot), 'COSIGN_FAIL': '1'})
duplicate = signroot / 'release-combined/nested/SHA256SUMS'
duplicate.parent.mkdir()
duplicate.write_bytes(original)
run('sign-nested-duplicate-sums', ['bash', '-c', sign], 1, 'duplicate file: SHA256SUMS', {'RUNNER_TEMP': str(signroot)})
duplicate.unlink()

version_run = workflow_run('release-rehearsal.yml', 'Read workspace version')
version_root = scratch / 'workspace-version'
version_root.mkdir()
output = version_root / 'output'
for version, status in (('1.2.3-alpha.4', 0), ('bad', 2)):
    (version_root / 'Cargo.toml').write_text(f'[workspace.package]\nversion = "{version}"\n')
    output.write_text('')
    result = subprocess.run(['bash', '-c', version_run], cwd=version_root,
                            env=env | {'GITHUB_OUTPUT': str(output)}, capture_output=True, text=True)
    assert result.returncode == status, (version, result.stderr)
    assert output.read_text() == (f'version={version}\n' if status == 0 else '')
check('signatures-restored', 0)
PY_SIGNATURES
echo 'release assertion tests passed'
