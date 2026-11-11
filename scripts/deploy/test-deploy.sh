#!/usr/bin/env bash
# Offline test of the deployment scripts in scripts/deploy/.
#
# Renders the wrapper and sudoers templates through a copy of bootstrap.sh
# whose fixed values point into a temporary root, once for macOS and once
# for Linux. Logging stubs stand in for every native and system command: the
# two wallet binaries, env, security, dbus-daemon, gnome-keyring-daemon,
# setsid, sudo, and the user database tools. The rendering of the host
# platform meets the real stat, ls, and pgrep; the other rendering gets stat
# and ls stubs and the real pgrep. Nothing runs as root, calls sudo, or
# reaches the network, and the real security, dbus-daemon, and
# gnome-keyring-daemon never run.
#
# Each case asserts exit codes, the refusal line, the stub calls, and the
# files. A prompt runs on a terminal fixture: a pseudo-terminal with echo
# off whose input queue holds the typed lines, so the prompted value never
# rests in a file, and whose output the case reads back. A perl or mv stub
# can put a directory at a rename destination after the installs check it.
#
# Usage: test-deploy.sh [--case <name>]
# Prints "deploy test: N of N passed" and exits 0, or lists each failed case
# with its output and exits 1. Needs bash 3.2 or later, python3, and perl.
# The env and wallet binary stubs start in perl, which hands on the
# environment exactly as it arrived; python adds variables of its own.
set -euo pipefail

DEPLOY=$(cd "$(dirname "$0")" && pwd -P)
tmp_root=${TMPDIR:-/tmp}
WORK=$(mktemp -d "${tmp_root%/}/test-deploy.XXXXXX")
WORK=$(cd "$WORK" && pwd -P)

# Stops the stub daemons a case left running, then removes the test root.
cleanup() {
  local pid_file pid
  for pid_file in "$WORK"/*/home/run/*.pid; do
    if [ -f "$pid_file" ]; then
      pid=$(cat "$pid_file" 2>/dev/null || true)
      case "$pid" in
        '' | *[!0-9]*) ;;
        *) kill "$pid" 2>/dev/null || true ;;
      esac
    fi
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

case "$(uname -s)" in
  Darwin) HOST_PLATFORM=macos OTHER_PLATFORM=linux ;;
  Linux) HOST_PLATFORM=linux OTHER_PLATFORM=macos ;;
  *)
    echo "test-deploy.sh runs on macOS or Linux" >&2
    exit 1
    ;;
esac
PLATFORMS="macos linux"
if ! PYTHON=$(python3 -c 'import sys; print(sys.executable)' 2>/dev/null); then
  echo "test-deploy.sh needs python3" >&2
  exit 1
fi
PERL=$(command -v perl || true)
case "$PERL" in
  /*) ;;
  *)
    echo "test-deploy.sh needs perl" >&2
    exit 1
    ;;
esac
case "$WORK$PYTHON$PERL" in
  *"'"* | *\\*)
    echo "test-deploy.sh needs a test root, python, and perl path without quotes or backslashes" >&2
    exit 1
    ;;
esac
ACCOUNT=$(id -un)
ACCOUNT_UID=$(id -u)
OPERATOR=deploy-operator
PROJECT=deploy-test-project
FOREIGN_UID=4242
# The marker the secret cases prompt with; no file may hold it except the
# remote key PEM.
MARKER="S-MARKER-$$-${RANDOM}${RANDOM}"
PREFIX_LINE="stellar-agent-wrapper: refused: "
STATE_LINE="the mainnet state is unreadable; run cli-launch profile enable-mainnet --state"
ENABLED_LINE="mainnet is enabled, and this form runs only before enablement"
FORM_LINE="the form is not one of the listed forms"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Sets the paths of platform $1.
use() {
  P=$1
  BASE="$WORK/$P"
  HOME_DIR="$BASE/home"
  case "$P" in
    macos) DATA_ROOT="$HOME_DIR/Library/Application Support/Soneso.stellar-agent" ;;
    linux) DATA_ROOT="$HOME_DIR/.local/share/stellar-agent" ;;
  esac
  PREFIX="$BASE/prefix"
  STATE="$BASE/state"
  STUBS="$BASE/stubs"
  BSTUBS="$BASE/bstubs"
  TTY="$BASE/tty"
  RUN_DIR="$HOME_DIR/run"
  PROFILE_FILE="$DATA_ROOT/profiles/mainnet.toml"
  POLICY_FILE="$DATA_ROOT/policies/mainnet.toml"
  KEYCHAIN="$HOME_DIR/Library/Keychains/login.keychain-db"
}

# Replaces the one line of file $1 that equals $2 with $3.
replace_line() {
  local file=$1 old=$2 new=$3
  if [ "$(grep -cxF -- "$old" "$file")" -ne 1 ]; then
    fail "$file holds no single line '$old'"
  fi
  awk -v old="$old" -v new="$new" '$0 == old { print new; next } { print }' "$file" >"$file.new"
  mv "$file.new" "$file"
}

# Writes the header of a bash stub $1 named $2: the values it needs and the
# log function, which writes one tab-separated line per call.
stub_header() {
  {
    printf '#!/bin/bash -p\n'
    printf 'STATE=%q\nNAME=%q\nPYTHON=%q\nACCOUNT=%q\nACCOUNT_UID=%q\nHOST_PLATFORM=%q\n' \
      "$STATE" "$2" "$PYTHON" "$ACCOUNT" "$ACCOUNT_UID" "$HOST_PLATFORM"
    cat <<'STUB'
log() {
  local word
  {
    printf '%s' "$NAME"
    for word in "$@"; do
      printf '\t%s' "$word"
    done
    printf '\n'
  } >>"$STATE/system.log"
}
# Prints the configured value of key $1, or $2.
conf() {
  local line
  if [ -f "$STATE/native.conf" ]; then
    while IFS= read -r line; do
      if [ "${line%%=*}" = "$1" ]; then
        printf '%s\n' "${line#*=}"
        return 0
      fi
    done <"$STATE/native.conf"
  fi
  printf '%s\n' "$2"
}
# Logs the SHA-256 of one line read from standard input.
log_stdin_line() {
  local line=""
  IFS= read -r line || true
  printf '%s\tstdin\t%s\n' "$NAME" "$(printf '%s' "$line" | "$PYTHON" -I -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')" >>"$STATE/system.log"
}
STUB
  } >"$1"
}

# Writes the body that the wallet binary stubs run, once per test root.
write_native_body() {
  cat >"$WORK/native-stub.py" <<'STUB'
"""Logging stand-in for a wallet binary in the deployment test.

The perl front of each stub passes the binary path and the environment it
received, hex encoded, because python adds variables to its own.
"""
import hashlib
import json
import os
import pathlib
import sys

BINARY = pathlib.Path(sys.argv[1])
NAME = BINARY.name
STATE = BINARY.resolve().parents[2] / "state"
SECRET = "STELLAR_AGENT_PROVISION_" + "SECRET"


def digest(value):
    return {"sha256": hashlib.sha256(value.encode()).hexdigest(), "length": len(value)}


received = {}
for pair in filter(None, os.environ.get("DEPLOY_STUB_ENVIRONMENT", "").split(",")):
    key, _, value = pair.partition(":")
    received[bytes.fromhex(key).decode()] = bytes.fromhex(value).decode()
conf = {}
for line in (STATE / "native.conf").read_text().splitlines():
    key, _, value = line.partition("=")
    conf[key] = value
argv = sys.argv[2:]
record = {
    "bin": NAME,
    "argv": argv,
    "pid": os.getpid(),
    "env": {key: digest(value) if key == SECRET else value for key, value in received.items()},
}
rc = int(conf.get("default", "0"))
stderr = ""
# A diagnostic that names a caller token, written on both streams.
noise = conf.get("noise", "")
if noise and NAME != "stellar-agent-mcp":
    sys.stdout.write(noise + "\n")
    sys.stderr.write(noise + "\n")
    sys.stdout.flush()
    sys.stderr.flush()
if NAME == "stellar-agent-mcp":
    data = sys.stdin.read()
    record["stdin"] = data
    sys.stdout.write(data)
elif argv[:2] == ["profile", "enable-mainnet"] and "--state" in argv:
    rc = int(conf.get("state", "3"))
elif argv[:2] == ["profile", "policy-check"]:
    record["stdin"] = sys.stdin.read()
    rc = int(conf.get("origin" if "--origin" in argv else "check", "0"))
elif argv[:2] == ["profile", "apply-fragment"]:
    record["stdin"] = sys.stdin.read()
    rc = int(conf.get("fragment", "0"))
    stderr = conf.get("fragment_stderr", "credential-roles:").replace("\\n", "\n")
elif argv[:2] == ["profile", "enroll-rpc-credential"]:
    record["stdin"] = digest(sys.stdin.read().rstrip("\n"))
with open(STATE / "calls.jsonl", "a") as log:
    log.write(json.dumps(record) + "\n")
if stderr:
    sys.stderr.write(stderr + "\n")
sys.exit(rc)
STUB
}

# Writes the stub of a wallet binary to $1: a perl front that runs the
# shared python body under the same process ID. $2 is an extra literal line
# for the binary checks of bootstrap.sh.
write_native_stub() {
  {
    printf '#!%s\n' "$PERL"
    printf '# %s\n' "${2:-STELLAR_AGENT_BUILD_MAINNET_WRITE=on}"
    printf "my @run = ('%s', '-I', '%s');\n" "$PYTHON" "$WORK/native-stub.py"
    cat <<'STUB'
$ENV{DEPLOY_STUB_ENVIRONMENT} = join(",", map { unpack("H*", $_) . ":" . unpack("H*", $ENV{$_}) } sort keys %ENV);
exec { $run[0] } @run, $0, @ARGV or die "exec failed: $!";
STUB
  } >"$1"
  chmod 755 "$1"
}

# Writes the stubs of platform $P.
write_stubs() {
  local tool
  mkdir -p "$STUBS" "$BSTUBS" "$STATE" "$BASE/src"
  # env logs its arguments and runs the real env with the environment it
  # received.
  {
    printf '#!%s\n' "$PERL"
    printf "my \$log_file = '%s';\n" "$STATE/system.log"
    cat <<'STUB'
open(my $log, ">>", $log_file) or die "cannot open the log: $!";
print $log join("\t", "env", @ARGV), "\n";
close($log);
exec { "/usr/bin/env" } "/usr/bin/env", @ARGV or die "exec failed: $!";
STUB
  } >"$STUBS/env"
  stub_header "$STUBS/setsid" setsid
  echo 'log "$@"; exec "$@"' >>"$STUBS/setsid"
  stub_header "$STUBS/security" security
  cat >>"$STUBS/security" <<'STUB'
log "$@"
case "${1-}" in
  create-keychain) log_stdin_line; : >"${2-}" ;;
  unlock-keychain) log_stdin_line ;;
esac
noise=$(conf noise "")
if [ -n "$noise" ]; then
  printf '%s\n' "$noise"
  printf '%s\n' "$noise" >&2
fi
exit "$(conf "security_${1-}" 0)"
STUB
  stub_header "$STUBS/dbus-daemon" dbus-daemon
  cat >>"$STUBS/dbus-daemon" <<'STUB'
log "$@"
socket=""
for word in "$@"; do
  case "$word" in
    --address=unix:path=*) socket=${word#--address=unix:path=} ;;
  esac
done
[ "$(conf dbus_start 0)" = 0 ] || exit 1
: >"$socket"
trap 'exit 0' TERM
while :; do sleep 1; done
STUB
  stub_header "$STUBS/gnome-keyring-daemon" gnome-keyring-daemon
  cat >>"$STUBS/gnome-keyring-daemon" <<'STUB'
log "$@"
log_stdin_line
control=""
foreground=0
for word in "$@"; do
  case "$word" in
    --control-directory=*) control=${word#--control-directory=} ;;
    --foreground) foreground=1 ;;
  esac
done
[ "$foreground" = 1 ] || exit "$(conf keyring_unlock 0)"
: >"$control/control"
trap 'exit 0' TERM
while :; do sleep 1; done
STUB
  if [ "$P" = "$OTHER_PLATFORM" ]; then
    # The other rendering's stat and ls read the host's real tools and
    # apply the owner overrides and ACL marks of the case.
    stub_header "$STUBS/stat" stat
    cat >>"$STUBS/stat" <<'STUB'
log "$@"
for path in "$@"; do :; done
if [ "$HOST_PLATFORM" = macos ]; then
  facts=$(/usr/bin/stat -f '%u %Lp' "$path") || exit 1
else
  facts=$(/usr/bin/stat -c '%u %a' "$path") || exit 1
fi
owner=$(awk -F '\t' -v path="$path" '$2 == path { print $1 }' "$STATE/owners")
if [ -n "$owner" ]; then
  facts="$owner ${facts#* }"
fi
printf '%s\n' "$facts"
STUB
    stub_header "$STUBS/ls" ls
    cat >>"$STUBS/ls" <<'STUB'
log "$@"
for path in "$@"; do :; done
listing=$(/bin/ls -ld "$path") || exit 1
if grep -qxF -- "$path" "$STATE/acl"; then
  mode=${listing%% *}
  printf '%s+ %s\n 0: group:everyone deny delete\n' "$mode" "${listing#* }"
else
  printf '%s\n' "$listing"
fi
STUB
  fi
  # perl and mv of the installs run the real tool. With the rename hook of
  # the case present, they first move a file at the rename destination
  # aside and put a directory there. That is the race between the
  # directory check and the rename, whichever tool renames.
  for tool in perl mv; do
    {
      printf '#!/bin/bash\nHOOK=%q\nTOOL=%q\nMV=%q\n' "$STATE/rename_hook" "$(command -v "$tool")" "$(command -v mv)"
      cat <<'STUB'
if [ -f "$HOOK" ]; then
  "$MV" "$HOOK" "$HOOK.used"
  for destination in "$@"; do :; done
  if [ -e "$destination" ]; then
    "$MV" "$destination" "$destination.raced"
  fi
  /bin/mkdir "$destination"
fi
exec "$TOOL" "$@"
STUB
    } >"$STUBS/$tool"
    cp "$STUBS/$tool" "$BSTUBS/$tool"
  done
  # The user database and root tools of bootstrap.sh.
  stub_header "$BSTUBS/id" id
  cat >>"$BSTUBS/id" <<'STUB'
log "$@"
exists() { [ "$(cat "$STATE/account_exists")" = yes ]; }
case "$*" in
  -u) cat "$STATE/root_uid" ;;
  "-u $ACCOUNT") exists && echo "$ACCOUNT_UID" ;;
  "-u deploy-operator") echo 4243 ;;
  "-Gn $ACCOUNT") exists && cat "$STATE/account_groups" ;;
  *) exit 1 ;;
esac
STUB
  stub_header "$BSTUBS/sysadminctl" sysadminctl
  # shellcheck disable=SC2016 # The stub body expands when the stub runs.
  echo 'log "$@"; echo yes >"$STATE/account_exists"' >>"$BSTUBS/sysadminctl"
  stub_header "$BSTUBS/useradd" useradd
  # shellcheck disable=SC2016 # The stub body expands when the stub runs.
  echo 'log "$@"; echo yes >"$STATE/account_exists"' >>"$BSTUBS/useradd"
  stub_header "$BSTUBS/usermod" usermod
  echo 'log "$@"' >>"$BSTUBS/usermod"
  stub_header "$BSTUBS/chown" chown
  echo 'log "$@"' >>"$BSTUBS/chown"
  stub_header "$BSTUBS/visudo" visudo
  # shellcheck disable=SC2016 # The stub body expands when the stub runs.
  echo 'log "$@"; exit "$(conf visudo 0)"' >>"$BSTUBS/visudo"
  stub_header "$BSTUBS/dscl" dscl
  cat >>"$BSTUBS/dscl" <<'STUB'
log "$@"
case "${2-} ${4-}" in
  "-read NFSHomeDirectory") printf 'NFSHomeDirectory: %s\n' "$(cat "$STATE/account_home")" ;;
  "-read AuthenticationAuthority") [ -f "$STATE/authentication_authority" ] ;;
  "-delete AuthenticationAuthority") rm -f "$STATE/authentication_authority" ;;
esac
STUB
  stub_header "$BSTUBS/getent" getent
  cat >>"$BSTUBS/getent" <<'STUB'
log "$@"
[ "$(cat "$STATE/account_exists")" = yes ] || exit 2
printf '%s:x:%s:%s::%s:/usr/sbin/nologin\n' "$ACCOUNT" "$ACCOUNT_UID" "$ACCOUNT_UID" "$(cat "$STATE/account_home")"
STUB
  chmod 755 "$STUBS"/* "$BSTUBS"/*
  write_native_stub "$BASE/src/stellar-agent"
  write_native_stub "$BASE/src/stellar-agent-mcp"
}

# Copies the templates and writes the bootstrap copy of platform $P, whose
# fixed values point into its root.
write_bootstrap() {
  local file system
  mkdir -p "$BASE/deploy"
  for file in mcp-launch cli-launch provision sudoers bootstrap.sh; do
    cp "$DEPLOY/$file" "$BASE/deploy/$file"
  done
  file="$BASE/deploy/bootstrap.sh"
  system=Darwin
  [ "$P" = macos ] || system=Linux
  replace_line "$file" "ACCOUNT=stellar-agent" "ACCOUNT='$ACCOUNT'"
  replace_line "$file" "PREFIX=/usr/local/libexec/stellar-agent" "PREFIX='$PREFIX'"
  replace_line "$file" "PROJECT_FILE=/usr/local/etc/stellar-agent/project" "PROJECT_FILE='$BASE/etc/project'"
  replace_line "$file" "SUDOERS_FILE=/etc/sudoers.d/stellar-agent" "SUDOERS_FILE='$BASE/sudoers.d/stellar-agent'"
  replace_line "$file" "MACOS_HOME=/Users/stellar-agent" "MACOS_HOME='$HOME_DIR'"
  replace_line "$file" "LINUX_HOME=/var/lib/stellar-agent" "LINUX_HOME='$HOME_DIR'"
  replace_line "$file" "WRAPPER_PATH=/usr/bin:/bin" "WRAPPER_PATH='$STUBS:/usr/bin:/bin'"
  replace_line "$file" "TTY_PATH=/dev/tty" "TTY_PATH='$TTY'"
  replace_line "$file" "SECURITY_TOOL=/usr/bin/security" "SECURITY_TOOL='$STUBS/security'"
  replace_line "$file" "DBUS_DAEMON_TOOL=/usr/bin/dbus-daemon" "DBUS_DAEMON_TOOL='$STUBS/dbus-daemon'"
  replace_line "$file" "GNOME_KEYRING_DAEMON_TOOL=/usr/bin/gnome-keyring-daemon" \
    "GNOME_KEYRING_DAEMON_TOOL='$STUBS/gnome-keyring-daemon'"
  replace_line "$file" "ENV_TOOL=/usr/bin/env" "ENV_TOOL='$STUBS/env'"
  replace_line "$file" "PATH=/usr/sbin:/usr/bin:/sbin:/bin" "PATH='$BSTUBS:/usr/sbin:/usr/bin:/sbin:/bin'"
  # shellcheck disable=SC2016 # The old line is the literal text of bootstrap.sh.
  replace_line "$file" 'HOST_SYSTEM=$(uname -s)' "HOST_SYSTEM=$system"
  chmod 755 "$file"
}

# Resets the user database state of platform $P to an absent account.
reset_account() {
  echo 0 >"$STATE/root_uid"
  echo no >"$STATE/account_exists"
  echo "$HOME_DIR" >"$STATE/account_home"
  if [ "$P" = macos ]; then
    echo "staff everyone" >"$STATE/account_groups"
    echo ShadowHash >"$STATE/authentication_authority"
  else
    echo "$ACCOUNT" >"$STATE/account_groups"
  fi
}

# Runs the bootstrap copy of platform $P with arguments $@, logging into
# BOOT_OUT and BOOT_ERR. Sets BOOT_RC.
run_bootstrap() {
  BOOT_RC=0
  "$BASE/deploy/bootstrap.sh" "$@" </dev/null >"$WORK/boot.out" 2>"$WORK/boot.err" || BOOT_RC=$?
  BOOT_OUT=$(cat "$WORK/boot.out")
  BOOT_ERR=$(cat "$WORK/boot.err")
}

# The arguments of a regular bootstrap run of platform $P.
bootstrap_args() {
  BOOT_ARGS=(--operator "$OPERATOR" --project "$PROJECT" --cli "$BASE/src/stellar-agent" --mcp "$BASE/src/stellar-agent-mcp")
}

# Sets up platform $1 through a first bootstrap run.
install_platform() {
  use "$1"
  mkdir -p "$BASE/etc" "$BASE/sudoers.d"
  write_stubs
  write_bootstrap
  : >"$STATE/system.log"
  : >"$STATE/native.conf"
  reset_account
  bootstrap_args
  run_bootstrap "${BOOT_ARGS[@]}"
  if [ "$BOOT_RC" -ne 0 ]; then
    echo "$BOOT_OUT" >&2
    echo "$BOOT_ERR" >&2
    fail "the $P bootstrap exited $BOOT_RC"
  fi
}

# Kills the stub daemon in PID file $1 and waits for it to end.
kill_daemon() {
  local pid tries=0
  [ -f "$1" ] || return 0
  pid=$(cat "$1")
  rm -f "$1"
  case "$pid" in
    '' | *[!0-9]*) return 0 ;;
  esac
  kill "$pid" 2>/dev/null || return 0
  while kill -0 "$pid" 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -le 50 ] || fail "the stub daemon $pid did not stop"
    sleep 0.1
  done
}

# Returns platform $1 to the installed state with a 0600 profile, default
# native answers, empty logs, and an empty terminal.
reset_platform() {
  use "$1"
  kill_daemon "$RUN_DIR/keyring.pid"
  kill_daemon "$RUN_DIR/dbus.pid"
  if [ "$P" = macos ] && [ "$HOST_PLATFORM" = macos ]; then
    chmod -N "$HOME_DIR" "$DATA_ROOT" 2>/dev/null || true
    if [ -e "$PROFILE_FILE" ]; then
      chmod -N "$PROFILE_FILE" 2>/dev/null || true
    fi
  fi
  rm -rf "$RUN_DIR" "$DATA_ROOT/policies" "$DATA_ROOT/remote" "$DATA_ROOT/profiles" \
    "$HOME_DIR/Library/Keychains"
  mkdir -m 700 "$RUN_DIR" "$DATA_ROOT/profiles"
  chmod 700 "$HOME_DIR" "$DATA_ROOT"
  printf 'network = "mainnet"\n' >"$PROFILE_FILE"
  chmod 600 "$PROFILE_FILE"
  printf 'state=3\norigin=0\ncheck=0\nfragment=0\nfragment_stderr=credential-roles:\ndefault=0\n' >"$STATE/native.conf"
  : >"$STATE/calls.jsonl"
  : >"$STATE/system.log"
  : >"$STATE/owners"
  : >"$STATE/acl"
  rm -f "$TTY"
  ln -s /dev/null "$TTY"
  unset STDIN_TEXT
}

# Sets native answer $1 to $2 for platform $P.
answer() {
  grep -v "^$1=" "$STATE/native.conf" >"$STATE/native.conf.new" || true
  printf '%s=%s\n' "$1" "$2" >>"$STATE/native.conf.new"
  mv "$STATE/native.conf.new" "$STATE/native.conf"
}

# Writes the terminal fixture, once per test root. It opens a
# pseudo-terminal with echo and output processing off, links argv[1] to
# its slave, queues standard input as typed lines, and copies what the
# wrappers write to the terminal into argv[2] until argv[4] appears.
write_tty_fixture() {
  cat >"$WORK/tty-fixture.py" <<'STUB'
"""Terminal fixture of the deployment test."""
import os
import select
import sys
import termios

link, output, ready, stop = sys.argv[1:5]
typed = sys.stdin.buffer.read()
master, slave = os.openpty()
attributes = termios.tcgetattr(slave)
attributes[1] &= ~termios.OPOST
attributes[3] &= ~(termios.ECHO | termios.ECHONL)
termios.tcsetattr(slave, termios.TCSANOW, attributes)
os.symlink(os.ttyname(slave), link)
os.write(master, typed)
with open(ready, "w"):
    pass
with open(output, "wb") as sink:
    while True:
        stopping = os.path.exists(stop)
        readable, _, _ = select.select([master], [], [], 0.05)
        if readable:
            chunk = os.read(master, 4096)
            if chunk:
                sink.write(chunk)
                sink.flush()
                continue
        if stopping:
            break
os.close(slave)
os.close(master)
STUB
}

# Points the terminal of platform $P at a new terminal fixture whose input
# queue holds the lines $@, then three empty lines that make a further
# prompt refuse instead of block. The lines reach the fixture through a
# pipe. Sets TTY_PID.
feed_tty() {
  local tries=0
  rm -f "$TTY" "$BASE/tty-output" "$BASE/tty-ready" "$BASE/tty-stop"
  printf '%s\n' "$@" '' '' '' |
    "$PYTHON" -I "$WORK/tty-fixture.py" "$TTY" "$BASE/tty-output" "$BASE/tty-ready" "$BASE/tty-stop" &
  TTY_PID=$!
  while [ ! -e "$BASE/tty-ready" ]; do
    tries=$((tries + 1))
    [ "$tries" -le 100 ] || fail "the terminal fixture did not start"
    sleep 0.05
  done
}

# Stops the terminal fixture, sets TTY_OUTPUT to what the wrappers wrote to
# the terminal, and points the terminal at /dev/null.
close_tty() {
  : >"$BASE/tty-stop"
  wait "$TTY_PID" || fail "the terminal fixture failed"
  unset TTY_PID
  TTY_OUTPUT=$(cat "$BASE/tty-output")
  rm -f "$TTY" "$BASE/tty-output" "$BASE/tty-ready" "$BASE/tty-stop"
  ln -s /dev/null "$TTY"
}

# Runs wrapper $1 of platform $P with arguments $2... Standard input is the
# text of STDIN_TEXT through a pipe when set, else /dev/null. Sets RC, OUT,
# ERR, and PID, the wrapper's process ID.
run() {
  local wrapper=$1
  shift
  RC=0
  if [ -n "${STDIN_TEXT+set}" ]; then
    printf '%s' "$STDIN_TEXT" | "$PREFIX/$wrapper" "$@" >"$WORK/run.out" 2>"$WORK/run.err" &
  else
    "$PREFIX/$wrapper" "$@" </dev/null >"$WORK/run.out" 2>"$WORK/run.err" &
  fi
  PID=$!
  wait "$PID" || RC=$?
  OUT=$(cat "$WORK/run.out")
  ERR=$(cat "$WORK/run.err")
}

# Prints the logged native calls of platform $P, one per line as
# "<binary> <arguments>" joined by single spaces.
native_calls() {
  "$PYTHON" -I - "$STATE/calls.jsonl" <<'PY'
import json
import sys

for line in open(sys.argv[1]):
    call = json.loads(line)
    print(" ".join([call["bin"], *call["argv"]]))
PY
}

# Prints field $2 of logged native call $1 (1-based) of platform $P as JSON.
native_field() {
  "$PYTHON" -I - "$STATE/calls.jsonl" "$1" "$2" <<'PY'
import json
import sys

calls = [json.loads(line) for line in open(sys.argv[1])]
print(json.dumps(calls[int(sys.argv[2]) - 1].get(sys.argv[3]), sort_keys=True))
PY
}

# Prints the SHA-256 of $1 as the stubs log it.
sha() {
  printf '%s' "$1" | "$PYTHON" -I -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
}

# Prints the logged calls of the keychain and daemon stubs of platform $P:
# the system calls a form makes after its checks.
system_calls() {
  grep -E "^(security|setsid|dbus-daemon|gnome-keyring-daemon)	" "$STATE/system.log" || true
}

# Fails unless the run exited $1 with the refusal line of reason $2 as its
# only standard error output.
expect_refusal() {
  if [ "$RC" -ne "$1" ] || [ "$ERR" != "$PREFIX_LINE$2" ]; then
    fail "$P $3: exit $RC, stderr '$ERR', expected $1 with '$PREFIX_LINE$2'"
  fi
}

# Fails unless the native calls of platform $P are exactly the lines $@.
expect_native() {
  local expected actual
  expected=$(printf '%s\n' "$@")
  [ "$#" -gt 0 ] || expected=""
  actual=$(native_calls)
  if [ "$actual" != "$expected" ]; then
    fail "$P native calls:
$actual
expected:
$expected"
  fi
}

# The predicate call and the native calls of a form.
PREDICATE="stellar-agent profile enable-mainnet --profile mainnet --state"

# The listed forms: wrapper, eligibility (E, Y, N), the input a run needs,
# and the arguments. Inputs: none; keychain, the unlock password; secret,
# one prompted value; providers, a fragment on standard input; cert, key,
# and policy, a file on standard input; signed, a signed-origin policy.
FORMS="cli-launch E keychain keychain-unlock
cli-launch Y none keychain-lock
cli-launch Y none profile show
cli-launch Y none profile enable-mainnet --check
cli-launch E none profile enable-mainnet --state
cli-launch Y none audit verify
cli-launch Y none approve credential enroll --open-by-operator
cli-launch Y none approve credential enroll --origin-from-installed
cli-launch Y none approve serve --open-by-operator
cli-launch Y none approve serve --remote --confirm-remote-exposure
cli-launch Y none approve --id probe-1 --open-by-operator
cli-launch Y signed approve --id probe-1
provision E none profile init --network mainnet --rpc-url https://rpc.example/soroban
provision Y none profile rotate-audit-key
provision Y secret profile enroll-owner-key
provision N secret profile enroll-signer
provision N secret profile bind-signer
provision Y none profile rotate-nonce-key
provision Y none profile rotate-attestation-key
provision N providers providers
provision Y secret provider-credential --role primary
provision Y none remote-config --bind 127.0.0.1:8443 --rp-id wallet.example
provision Y cert remote-cert
provision Y key remote-key
provision Y policy policy-install
provision Y secret profile sign-policy
provision N none profile enable-mainnet
mcp-launch Y none"

CERT_PEM=$'-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n'
KEY_PEM=$'-----BEGIN PRIVATE KEY-----\nMIIEtest\n-----END PRIVATE KEY-----\n'
POLICY_TEXT=$'version = 2\n[mainnet]\napproval_origin = "https://wallet.example"\n'
FRAGMENT=$'oracle_provider_url = "https://oracle.example/v1"\n\n[providers.primary]\nurl = "https://rpc.example/soroban"\n'

# Prepares input $1 of a form on platform $P with value $2 for prompts.
prepare_input() {
  unset STDIN_TEXT
  case "$1" in
    keychain)
      if [ "$P" = macos ]; then
        STDIN_TEXT="$2"$'\n'"$2"$'\n'
      else
        feed_tty "$2"
      fi
      ;;
    secret) feed_tty "$2" ;;
    providers) STDIN_TEXT=$FRAGMENT ;;
    cert) STDIN_TEXT=$CERT_PEM ;;
    key) STDIN_TEXT=$KEY_PEM ;;
    policy) STDIN_TEXT=$POLICY_TEXT ;;
    signed)
      mkdir -m 700 "$DATA_ROOT/policies"
      printf '%s' "$POLICY_TEXT" >"$POLICY_FILE"
      chmod 600 "$POLICY_FILE"
      answer origin 3
      ;;
  esac
}

# Ends the input of a form: closes a fed terminal.
finish_input() {
  if [ -n "${TTY_PID-}" ]; then
    close_tty
  fi
}

# Runs form line $2 on platform $1 with eligibility predicate exit $3.
# Sets FORM_WRAPPER, FORM_ELIGIBILITY, FORM_ARGS, and the run results.
run_form() {
  local wrapper eligibility input
  reset_platform "$1"
  answer state "$3"
  read -r wrapper eligibility input FORM_REST <<<"$2"
  FORM_WRAPPER=$wrapper
  FORM_ELIGIBILITY=$eligibility
  FORM_ARGS=${FORM_REST:-}
  prepare_input "$input" "$MARKER"
  set -f
  # shellcheck disable=SC2086 # The form words split on spaces by design.
  run "$wrapper" $FORM_ARGS
  set +f
  finish_input
}

# Fails unless the form run reached its action: the predicate ran for a Y
# or N form and never for an exempt one, and no eligibility refusal came.
expect_admitted() {
  local calls predicates
  calls=$(native_calls)
  predicates=$(printf '%s\n' "$calls" | grep -cxF "$PREDICATE" || true)
  if [ "$FORM_ELIGIBILITY" = E ] && [ "$predicates" -ne 0 ]; then
    fail "$P '$FORM_ARGS': an exempt form ran the predicate"
  fi
  if [ "$FORM_ELIGIBILITY" != E ] && [ "$predicates" -ne 1 ]; then
    fail "$P '$FORM_ARGS': the predicate ran $predicates times"
  fi
  case "$ERR" in
    *"$STATE_LINE"* | *"$ENABLED_LINE"*) fail "$P '$FORM_ARGS': admitted form refused: $ERR" ;;
  esac
  if [ "$FORM_ARGS" = "profile enable-mainnet --state" ]; then
    [ "$RC" -eq "$(grep '^state=' "$STATE/native.conf" | cut -d= -f2)" ] ||
      fail "$P the --state form exited $RC, not the native exit code"
  elif [ "$RC" -ne 0 ]; then
    fail "$P '$FORM_ARGS' ($FORM_WRAPPER): exit $RC, stderr '$ERR'"
  fi
}

# Fails unless the form run refused with reason $1 after the predicate and
# before any other native or system call.
expect_refused_after_predicate() {
  expect_refusal 65 "$1" "'$FORM_ARGS'"
  expect_native "$PREDICATE"
  if [ -n "$(system_calls)" ]; then
    fail "$P '$FORM_ARGS': system calls after the refusal: $(system_calls)"
  fi
}

case_wrapper_eligibility_follows_nonce() {
  local platform line
  for platform in $PLATFORMS; do
    while IFS= read -r line; do
      run_form "$platform" "$line" 3
      expect_admitted
      run_form "$platform" "$line" 0
      if [ "$FORM_ELIGIBILITY" = N ]; then
        expect_refused_after_predicate "$ENABLED_LINE"
      else
        expect_admitted
      fi
    done <<<"$FORMS"
  done
}

case_unreadable_nonce_refuses_every_other_form() {
  local platform line code
  for platform in $PLATFORMS; do
    while IFS= read -r line; do
      case "$line" in
        *" E "*) continue ;;
      esac
      for code in 1 2 101; do
        run_form "$platform" "$line" "$code"
        expect_refused_after_predicate "$STATE_LINE"
      done
    done <<<"$FORMS"
  done
}

case_predicate_exempt_forms_run_with_unreadable_nonce() {
  local platform line code
  for platform in $PLATFORMS; do
    while IFS= read -r line; do
      case "$line" in
        *" E "*) ;;
        *) continue ;;
      esac
      for code in 1 2 101 0 3; do
        run_form "$platform" "$line" "$code"
        expect_admitted
      done
    done <<<"$FORMS"
  done
}

TAB=$'\t'

# Fails unless a run of wrapper $1 with arguments $2... exits RC_WANT with
# reason REASON_WANT and makes no native call.
refused_without_native() {
  run "$@"
  expect_refusal "$RC_WANT" "$REASON_WANT" "'$*'"
  expect_native
}

# Prints $1 copies of the letter a.
letters() {
  local count=0 text=""
  while [ "$count" -lt "$1" ]; do
    text="${text}a"
    count=$((count + 1))
  done
  printf '%s' "$text"
}

case_wrapper_refuses_unlisted_verb() {
  local platform form wrapper suffix id
  for platform in $PLATFORMS; do
    reset_platform "$platform"
    RC_WANT=64 REASON_WANT=$FORM_LINE
    refused_without_native cli-launch
    refused_without_native cli-launch unlock
    refused_without_native cli-launch profile
    refused_without_native cli-launch profile list
    refused_without_native cli-launch pay --to someone
    refused_without_native provision
    refused_without_native provision profile init
    refused_without_native provision profile init --network testnet --rpc-url https://rpc.example
    refused_without_native provision profile init --rpc-url https://rpc.example --network mainnet
    refused_without_native mcp-launch serve
    # Each listed form with a trailing token, a caller profile, a caller
    # audit log, or an unknown option.
    while IFS= read -r form; do
      set -f
      # shellcheck disable=SC2086 # The form words split on spaces by design.
      set -- $form
      set +f
      wrapper=$1
      shift 3
      for suffix in extra --profile "--profile mainnet" "--audit-log x" --unknown; do
        set -f
        # shellcheck disable=SC2086 # The suffix words split on spaces by design.
        refused_without_native "$wrapper" "$@" $suffix
        set +f
      done
    done <<<"$FORMS"
    REASON_WANT="the approval id does not match the id grammar"
    refused_without_native cli-launch approve --id ""
    id=$(letters 65)
    refused_without_native cli-launch approve --id "$id"
    refused_without_native cli-launch approve --id "$id" --open-by-operator
    refused_without_native cli-launch approve --id probe.1
    refused_without_native cli-launch approve --id probe/1
    refused_without_native cli-launch approve --id "probe 1"
    REASON_WANT=$FORM_LINE
    refused_without_native cli-launch approve --id probe-1 --remote
    REASON_WANT="the role is not primary, secondary, or oracle"
    refused_without_native provision provider-credential --role tertiary
    refused_without_native provision provider-credential --role Primary
    REASON_WANT="the RPC URL is not an https URL without whitespace, quotes, or backslashes"
    refused_without_native provision profile init --network mainnet --rpc-url http://rpc.example
    refused_without_native provision profile init --network mainnet --rpc-url "https://rpc example"
    refused_without_native provision profile init --network mainnet --rpc-url 'https://rpc"example'
    refused_without_native provision profile init --network mainnet --rpc-url 'https://rpc\example'
    REASON_WANT="the bind address does not match the address grammar"
    refused_without_native provision remote-config --bind localhost:8443 --rp-id wallet.example
    refused_without_native provision remote-config --bind 127.0.0.1 --rp-id wallet.example
    refused_without_native provision remote-config --bind 127.0.0.1:123456 --rp-id wallet.example
    REASON_WANT="the relying party id is not a lowercase DNS name"
    refused_without_native provision remote-config --bind 127.0.0.1:8443 --rp-id Wallet.example
    refused_without_native provision remote-config --bind 127.0.0.1:8443 --rp-id wallet..example
    refused_without_native provision remote-config --bind 127.0.0.1:8443 --rp-id -wallet.example
    # The longest approval id passes the grammar.
    install_policy
    answer origin 3
    id=$(letters 64)
    run cli-launch approve --id "$id"
    [ "$RC" -eq 0 ] || fail "$P a 64-character id exited $RC: $ERR"
    expect_native "$PREDICATE" "$ORIGIN_CHECK" "stellar-agent approve --id $id --profile mainnet"
  done
}

# Fails unless form $2... of wrapper $1 refuses with exit 65 and reason
# REASON_WANT before any native call.
refused_by_checks() {
  RC_WANT=65
  refused_without_native "$@"
}

# Moves path $1 aside and puts a symlink to it in its place.
swap_for_symlink() {
  mv "$1" "$1.real"
  ln -s "$1.real" "$1"
}

# Puts the path that swap_for_symlink moved aside back in place.
restore_from_symlink() {
  rm "$1"
  mv "$1.real" "$1"
}

case_wrapper_refuses_foreign_home_owner() {
  local platform mode target original variant
  for platform in $PLATFORMS; do
    reset_platform "$platform"
    for mode in 750 755; do
      chmod "$mode" "$HOME_DIR"
      REASON_WANT="the home directory does not have mode 0700"
      refused_by_checks cli-launch profile show
      refused_by_checks provision profile init --network mainnet --rpc-url https://rpc.example
      chmod 700 "$HOME_DIR"
      chmod "$mode" "$DATA_ROOT"
      REASON_WANT="the data root does not have mode 0700"
      refused_by_checks cli-launch profile show
      refused_by_checks cli-launch keychain-unlock
      chmod 700 "$DATA_ROOT"
    done
    chmod 644 "$PROFILE_FILE"
    REASON_WANT="the profile does not have mode 0600"
    refused_by_checks cli-launch profile show
    refused_by_checks provision profile rotate-audit-key
    refused_by_checks mcp-launch
    # The bootstrap tier accepts an account-owned profile in any mode.
    run provision profile init --network mainnet --rpc-url https://rpc.example
    [ "$RC" -eq 0 ] || fail "$P profile init refused a 0644 profile: $ERR"
    reset_platform "$platform"
    swap_for_symlink "$HOME_DIR"
    REASON_WANT="the home directory is a symlink"
    refused_by_checks cli-launch profile show
    refused_by_checks cli-launch keychain-unlock
    restore_from_symlink "$HOME_DIR"
    swap_for_symlink "$DATA_ROOT"
    REASON_WANT="the data root is a symlink"
    refused_by_checks cli-launch profile show
    refused_by_checks provision profile init --network mainnet --rpc-url https://rpc.example
    restore_from_symlink "$DATA_ROOT"
    swap_for_symlink "$PROFILE_FILE"
    REASON_WANT="the profile is a symlink"
    refused_by_checks cli-launch profile show
    refused_by_checks provision profile enroll-owner-key
    refused_by_checks provision profile init --network mainnet --rpc-url https://rpc.example
    restore_from_symlink "$PROFILE_FILE"
    # Foreign owners: the stubbed stat of the other rendering reports them,
    # and the host rendering meets the root-owned / as its home through the
    # real stat.
    if [ "$P" = "$OTHER_PLATFORM" ]; then
      printf '%s\t%s\n' "$FOREIGN_UID" "$HOME_DIR" >"$STATE/owners"
      REASON_WANT="the home directory is not owned by the wallet account"
      refused_by_checks cli-launch profile show
      printf '%s\t%s\n' "$FOREIGN_UID" "$DATA_ROOT" >"$STATE/owners"
      REASON_WANT="the data root is not owned by the wallet account"
      refused_by_checks cli-launch profile show
      printf '%s\t%s\n' "$FOREIGN_UID" "$PROFILE_FILE" >"$STATE/owners"
      REASON_WANT="the profile is not owned by the wallet account"
      refused_by_checks cli-launch profile show
      refused_by_checks provision profile init --network mainnet --rpc-url https://rpc.example
      : >"$STATE/owners"
    else
      original="$PREFIX/cli-launch"
      variant="$WORK/cli-launch.variant"
      sed "s|^ACCOUNT_HOME='.*'\$|ACCOUNT_HOME='/'|" "$original" >"$variant"
      [ "$(grep -cx "ACCOUNT_HOME='/'" "$variant")" -eq 1 ] || fail "the variant has no root-owned home"
      chmod 755 "$variant"
      mv "$original" "$original.installed"
      mv "$variant" "$original"
      REASON_WANT="the home directory is not owned by the wallet account"
      refused_by_checks cli-launch profile show
      mv "$original.installed" "$original"
    fi
    # Extended ACL entries on macOS: the real ls of a macOS host, the
    # stubbed ls with an ACL mark on a Linux host.
    if [ "$P" = macos ]; then
      for target in "$HOME_DIR" "$DATA_ROOT" "$PROFILE_FILE"; do
        if [ "$HOST_PLATFORM" = macos ]; then
          chmod +a "everyone deny delete" "$target"
        else
          printf '%s\n' "$target" >"$STATE/acl"
        fi
        case "$target" in
          "$HOME_DIR") REASON_WANT="the home directory carries an access control list" ;;
          "$DATA_ROOT") REASON_WANT="the data root carries an access control list" ;;
          *) REASON_WANT="the profile carries an access control list" ;;
        esac
        refused_by_checks cli-launch profile show
        if [ "$HOST_PLATFORM" = macos ]; then
          chmod -N "$target"
        else
          : >"$STATE/acl"
        fi
      done
    fi
    run cli-launch profile show
    [ "$RC" -eq 0 ] || fail "$P the restored tree refused: $ERR"
  done
}

# Prints the exact environment a native verb of platform $P receives, one
# KEY=VALUE per line, sorted. $1, when given, is the prompted secret the
# secret variable carries.
expected_environment() {
  {
    printf 'HOME=%s\n' "$HOME_DIR"
    printf 'PATH=%s\n' "$STUBS:/usr/bin:/bin"
    printf 'TMPDIR=%s\n' "$HOME_DIR/tmp"
    printf 'STELLAR_AGENT_PROJECT=%s\n' "$PROJECT"
    if [ "$P" = linux ]; then
      printf 'DBUS_SESSION_BUS_ADDRESS=unix:path=%s\n' "$RUN_DIR/bus"
      printf 'GNOME_KEYRING_CONTROL=%s\n' "$RUN_DIR/keyring"
    fi
    if [ -n "${1-}" ]; then
      printf 'STELLAR_AGENT_PROVISION_SECRET={"length": %s, "sha256": "%s"}\n' "${#1}" "$(sha "$1")"
    fi
  } | LC_ALL=C sort
}

# Prints the environment of logged native call $1 (1-based) of platform $P
# as sorted KEY=VALUE lines.
call_environment() {
  "$PYTHON" -I - "$STATE/calls.jsonl" "$1" <<'PY' | LC_ALL=C sort
import json
import sys

calls = [json.loads(line) for line in open(sys.argv[1])]
for key, value in calls[int(sys.argv[2]) - 1]["env"].items():
    shown = json.dumps(value, sort_keys=True) if isinstance(value, dict) else value
    print(f"{key}={shown}")
PY
}

# Runs wrapper $1 with arguments $2... under a caller environment that sets
# every variable the wrappers must never pass on. Sets RC and ERR.
run_polluted() {
  RC=0
  env STELLAR_AGENT_HOME="$WORK/caller-home" STELLAR_AGENT_KEYRING_BACKEND=headless-env \
    STELLAR_AGENT_HEADLESS_KEYRING_KEY=caller-key STELLAR_AGENT_NETWORKS_TOML="$WORK/networks.toml" \
    STELLAR_AGENT_PROFILE=caller-profile STELLAR_AGENT_RPC_URL=https://caller.example \
    STELLAR_AGENT_PROVISION_SECRET=caller-secret XDG_DATA_HOME="$WORK/xdg" LOCALAPPDATA="$WORK/local" \
    DISPLAY=:9 WAYLAND_DISPLAY=wayland-9 BASH_ENV="$WORK/bash-env" PATH="$WORK/caller-bin:$PATH" \
    "$PREFIX/$1" "${@:2}" </dev/null >"$WORK/run.out" 2>"$WORK/run.err" || RC=$?
  ERR=$(cat "$WORK/run.err")
}

case_wrapper_environment() {
  local platform form count want got secret
  printf 'echo sourced >%q\n' "$WORK/bash-env-ran" >"$WORK/bash-env"
  for platform in $PLATFORMS; do
    for form in "cli-launch profile show" "mcp-launch" "provision profile rotate-nonce-key" \
      "provision profile enroll-owner-key" "provision profile enroll-signer" \
      "provision profile bind-signer" "provision profile sign-policy" \
      "provision provider-credential --role oracle"; do
      reset_platform "$platform"
      secret=""
      case "$form" in
        *enroll-owner-key | *enroll-signer | *bind-signer | *sign-policy) secret="$MARKER-$platform" ;;
      esac
      feed_tty "$MARKER-$platform"
      set -f
      # shellcheck disable=SC2086 # The form words split on spaces by design.
      run_polluted $form
      set +f
      close_tty
      [ "$RC" -eq 0 ] || fail "$P '$form' exited $RC: $ERR"
      count=$(wc -l <"$STATE/calls.jsonl" | tr -d ' ')
      [ "$count" -eq 2 ] || fail "$P '$form' made $count native calls"
      want=$(expected_environment)
      got=$(call_environment 1)
      [ "$got" = "$want" ] || fail "$P '$form' predicate environment:
$got
expected:
$want"
      want=$(expected_environment "$secret")
      got=$(call_environment 2)
      [ "$got" = "$want" ] || fail "$P '$form' environment:
$got
expected:
$want"
      [ ! -e "$WORK/bash-env-ran" ] || fail "$P '$form' sourced BASH_ENV"
    done
  done
}

# Fails when a regular file under the test root other than a remote key
# PEM holds the marker.
expect_marker_nowhere() {
  local hits
  hits=$(find "$WORK" -type f -exec grep -lF -- "$MARKER" {} + 2>/dev/null |
    grep -vE '/remote/key\.pem$' || true)
  [ -z "$hits" ] || fail "the marker is in: $hits"
}

# Prints the stub log line of an input of digest $2 read by stub $1.
stdin_line() {
  printf '%s%sstdin%s%s' "$1" "$TAB" "$TAB" "$2"
}

case_secret_appears_in_no_argv_env_dump_log_or_file() {
  local platform form digest
  digest=$(sha "$MARKER")
  for platform in $PLATFORMS; do
    reset_platform "$platform"
    for form in "profile enroll-owner-key" "profile enroll-signer" "profile bind-signer" "profile sign-policy"; do
      : >"$STATE/calls.jsonl"
      feed_tty "$MARKER"
      set -f
      # shellcheck disable=SC2086 # The form words split on spaces by design.
      run provision $form
      set +f
      close_tty
      [ "$RC" -eq 0 ] || fail "$P '$form' exited $RC: $ERR"
      grep -qF "\"sha256\": \"$digest\"" "$STATE/calls.jsonl" ||
        fail "$P '$form': the native verb did not receive the prompted value"
      expect_marker_nowhere
    done
    : >"$STATE/calls.jsonl"
    feed_tty "$MARKER"
    run provision provider-credential --role secondary
    close_tty
    [ "$RC" -eq 0 ] || fail "$P provider-credential exited $RC: $ERR"
    grep -qF "\"sha256\": \"$digest\"" "$STATE/calls.jsonl" || fail "$P provider-credential lost the value"
    answer fragment_stderr "credential-roles: primary oracle"
    : >"$STATE/calls.jsonl"
    feed_tty "$MARKER" "$MARKER"
    STDIN_TEXT=$FRAGMENT run provision providers
    close_tty
    [ "$RC" -eq 0 ] || fail "$P providers exited $RC: $ERR"
    [ "$(grep -cF "\"sha256\": \"$digest\"" "$STATE/calls.jsonl")" -eq 2 ] || fail "$P providers lost a value"
    : >"$STATE/system.log"
    if [ "$P" = macos ]; then
      STDIN_TEXT="$MARKER"$'\n'"$MARKER"$'\n' run cli-launch keychain-unlock
      [ "$RC" -eq 0 ] || fail "$P keychain-unlock exited $RC: $ERR"
      grep -qxF "$(stdin_line security "$digest")" "$STATE/system.log" || fail "$P keychain-unlock lost the password"
    else
      feed_tty "$MARKER"
      run cli-launch keychain-unlock
      close_tty
      [ "$RC" -eq 0 ] || fail "$P keychain-unlock exited $RC: $ERR"
      grep -qxF "$(stdin_line gnome-keyring-daemon "$digest")" "$STATE/system.log" ||
        fail "$P keychain-unlock lost the password"
    fi
    STDIN_TEXT=$'-----BEGIN PRIVATE KEY-----\n'"$MARKER"$'\n-----END PRIVATE KEY-----\n' run provision remote-key
    [ "$RC" -eq 0 ] || fail "$P remote-key exited $RC: $ERR"
    grep -qF -- "$MARKER" "$DATA_ROOT/remote/key.pem" || fail "$P remote-key did not land"
    expect_marker_nowhere
  done
}

# Prints the logged security calls of platform $P without their input
# lines, one per line with single spaces.
security_calls() {
  grep "^security$TAB" "$STATE/system.log" | grep -v "^security${TAB}stdin$TAB" | tr '\t' ' ' || true
}

# Prints the logged daemon calls of platform $P without their input lines.
daemon_calls() {
  grep -E "^(setsid|dbus-daemon|gnome-keyring-daemon)$TAB" "$STATE/system.log" | grep -v "${TAB}stdin$TAB" |
    tr '\t' ' ' || true
}

case_keychain_unlock_password_reaches_only_stdin() {
  local platform digest dbus_pid keyring_pid tries
  digest=$(sha "$MARKER")
  for platform in $PLATFORMS; do
    reset_platform "$platform"
    if [ "$P" = macos ]; then
      STDIN_TEXT="$MARKER"$'\n'"$MARKER"$'\n' run cli-launch keychain-unlock
      [ "$RC" -eq 0 ] || fail "macos keychain-unlock exited $RC: $ERR"
      [ "$(security_calls)" = "security create-keychain $KEYCHAIN
security default-keychain -s $KEYCHAIN
security unlock-keychain $KEYCHAIN
security set-keychain-settings $KEYCHAIN" ] || fail "macos security calls:
$(security_calls)"
      [ "$(grep -cxF "$(stdin_line security "$digest")" "$STATE/system.log")" -eq 2 ] ||
        fail "macos create-keychain and unlock-keychain did not read the password on standard input"
      [ "$(host_facts "$HOME_DIR/Library/Keychains")" = "$ACCOUNT_UID 700" ] || fail "macos Keychains is not 0700"
      : >"$STATE/system.log"
      STDIN_TEXT="$MARKER"$'\n' run cli-launch keychain-unlock
      [ "$RC" -eq 0 ] || fail "macos repeated keychain-unlock exited $RC: $ERR"
      [ "$(security_calls)" = "security default-keychain -s $KEYCHAIN
security unlock-keychain $KEYCHAIN
security set-keychain-settings $KEYCHAIN" ] || fail "macos repeated security calls:
$(security_calls)"
      : >"$STATE/system.log"
      run cli-launch keychain-lock
      [ "$RC" -eq 0 ] || fail "macos keychain-lock exited $RC: $ERR"
      [ "$(security_calls)" = "security lock-keychain $KEYCHAIN" ] || fail "macos lock calls: $(security_calls)"
    else
      feed_tty "$MARKER"
      run cli-launch keychain-unlock
      close_tty
      [ "$RC" -eq 0 ] || fail "linux keychain-unlock exited $RC: $ERR"
      [ "$(daemon_calls)" = "setsid $STUBS/dbus-daemon --session --address=unix:path=$RUN_DIR/bus --nofork --nopidfile
dbus-daemon --session --address=unix:path=$RUN_DIR/bus --nofork --nopidfile
setsid $STUBS/gnome-keyring-daemon --foreground --unlock --components=secrets --control-directory=$RUN_DIR/keyring
gnome-keyring-daemon --foreground --unlock --components=secrets --control-directory=$RUN_DIR/keyring" ] ||
        fail "linux daemon calls:
$(daemon_calls)"
      [ "$(grep -cxF "$(stdin_line gnome-keyring-daemon "$digest")" "$STATE/system.log")" -eq 1 ] ||
        fail "linux gnome-keyring-daemon did not read the password on standard input"
      [ "$(host_facts "$RUN_DIR/keyring")" = "$ACCOUNT_UID 700" ] || fail "linux the control directory is not 0700"
      dbus_pid=$(cat "$RUN_DIR/dbus.pid")
      keyring_pid=$(cat "$RUN_DIR/keyring.pid")
      kill -0 "$dbus_pid" || fail "linux the session bus is not running"
      kill -0 "$keyring_pid" || fail "linux the keyring daemon is not running"
      : >"$STATE/system.log"
      feed_tty "$MARKER"
      run cli-launch keychain-unlock
      close_tty
      [ "$RC" -eq 0 ] || fail "linux repeated keychain-unlock exited $RC: $ERR"
      [ "$(daemon_calls)" = "gnome-keyring-daemon --unlock --components=secrets --control-directory=$RUN_DIR/keyring" ] ||
        fail "linux repeated unlock calls:
$(daemon_calls)"
      [ "$(grep -cxF "$(stdin_line gnome-keyring-daemon "$digest")" "$STATE/system.log")" -eq 1 ] ||
        fail "linux the repeated unlock did not read the password on standard input"
      [ "$(cat "$RUN_DIR/dbus.pid")" = "$dbus_pid" ] || fail "linux the repeated unlock replaced the session bus"
      [ "$(cat "$RUN_DIR/keyring.pid")" = "$keyring_pid" ] || fail "linux the repeated unlock replaced the keyring daemon"
      run cli-launch keychain-lock
      [ "$RC" -eq 0 ] || fail "linux keychain-lock exited $RC: $ERR"
      [ ! -e "$RUN_DIR/dbus.pid" ] || fail "linux lock kept the bus PID file"
      [ ! -e "$RUN_DIR/keyring.pid" ] || fail "linux lock kept the keyring PID file"
      tries=0
      while kill -0 "$dbus_pid" 2>/dev/null || kill -0 "$keyring_pid" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -le 50 ] || fail "linux lock left a daemon running"
        sleep 0.1
      done
    fi
    if grep -E "^(security|gnome-keyring-daemon|dbus-daemon|setsid)$TAB" "$STATE/system.log" |
      grep -qE "$TAB-p($TAB|\$)"; then
      fail "$P a keychain call passed -p"
    fi
  done
}

case_keychain_access_lists_form() {
  local platform suffix
  for platform in $PLATFORMS; do
    reset_platform "$platform"
    RC_WANT=64 REASON_WANT=$FORM_LINE
    if [ "$P" = macos ]; then
      run cli-launch keychain-access-lists
      [ "$RC" -eq 0 ] || fail "macos keychain-access-lists exited $RC: $ERR"
      [ "$(security_calls)" = "security dump-keychain -a $KEYCHAIN" ] ||
        fail "macos keychain-access-lists security calls: $(security_calls)"
      expect_native
      for suffix in -d -g -w extra "--profile mainnet"; do
        : >"$STATE/system.log"
        set -f
        # shellcheck disable=SC2086 # The suffix words split on spaces by design.
        refused_without_native cli-launch keychain-access-lists $suffix
        set +f
        [ -z "$(security_calls)" ] || fail "macos keychain-access-lists $suffix called security"
      done
    else
      refused_without_native cli-launch keychain-access-lists
      [ -z "$(system_calls)" ] || fail "linux keychain-access-lists made system calls: $(system_calls)"
    fi
  done
}

# Starts a copy of /bin/sleep at path $1 and sets SLEEPER to its process
# ID. The copy is ad hoc signed on macOS, which kills an unsigned copy of a
# platform binary. A file at $1 is put back once the copy runs.
start_sleeper() {
  local staged="$1.staged"
  mkdir -p "$(dirname "$1")"
  cp /bin/sleep "$staged"
  if [ "$HOST_PLATFORM" = macos ]; then
    codesign --force -s - "$staged" 2>/dev/null
  fi
  if [ -e "$1" ]; then
    mv "$1" "$1.saved"
  fi
  mv "$staged" "$1"
  "$1" 60 &
  SLEEPER=$!
  sleep 0.3
  kill -0 "$SLEEPER" || fail "the copy of sleep at $1 did not start"
  if [ -e "$1.saved" ]; then
    mv -f "$1.saved" "$1"
  fi
}

# Stops the copy of sleep that start_sleeper started.
stop_sleeper() {
  kill "$SLEEPER" 2>/dev/null || true
  wait "$SLEEPER" 2>/dev/null || true
}

case_serve_refuses_running_mcp() {
  local platform form
  for platform in $PLATFORMS; do
    reset_platform "$platform"
    answer default 1
    start_sleeper "$PREFIX/bin/stellar-agent-mcp"
    for form in "approve serve --open-by-operator" "approve serve --remote --confirm-remote-exposure"; do
      : >"$STATE/calls.jsonl"
      set -f
      # shellcheck disable=SC2086 # The form words split on spaces by design.
      run cli-launch $form
      set +f
      expect_refusal 66 "the wallet MCP server is running" "'$form'"
      expect_native
    done
    stop_sleeper
    start_sleeper "$PREFIX/bin/stellar-agent"
    : >"$STATE/calls.jsonl"
    run mcp-launch
    expect_refusal 66 "a wallet CLI process is running" mcp-launch
    expect_native
    stop_sleeper
    # A copy at another path is no match; the native exit 1 passes through
    # from a native verb that runs under the wrapper's process ID.
    start_sleeper "$BASE/elsewhere/bin/stellar-agent-mcp"
    for form in "approve serve --open-by-operator" "approve serve --remote --confirm-remote-exposure"; do
      : >"$STATE/calls.jsonl"
      set -f
      # shellcheck disable=SC2086 # The form words split on spaces by design.
      run cli-launch $form
      set +f
      [ "$RC" -eq 1 ] || fail "$P '$form' with an unrelated process exited $RC: $ERR"
      [ "$(native_field 2 pid)" = "$PID" ] || fail "$P '$form' did not run under the wrapper's process ID"
    done
    stop_sleeper
    start_sleeper "$BASE/elsewhere/bin/stellar-agent"
    : >"$STATE/calls.jsonl"
    run mcp-launch
    [ "$RC" -eq 1 ] || fail "$P mcp-launch with an unrelated process exited $RC: $ERR"
    [ "$(native_field 2 pid)" = "$PID" ] || fail "$P mcp-launch did not run under the wrapper's process ID"
    stop_sleeper
  done
}

# The classified forms, each with its native call.
CLASSIFIED="approve credential enroll --open-by-operator|stellar-agent approve credential enroll --open-by-operator --profile mainnet
approve serve --open-by-operator|stellar-agent approve serve --open-by-operator --profile mainnet
approve --id probe-2 --open-by-operator|stellar-agent approve --id probe-2 --open-by-operator --profile mainnet
approve --id probe-2|stellar-agent approve --id probe-2 --profile mainnet"
ORIGIN_CHECK="stellar-agent profile policy-check --profile mainnet --origin"
SIGNED_LINE="the profile has a signed origin, and operator-open forms are unavailable"
LOCAL_LINE="the profile is local-only; use approve --id <approval-id> --open-by-operator"

# Prints $1 as a JSON string, the form the native stub logs.
json_string() {
  "$PYTHON" -I -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$1"
}

# Prints the arguments $@ as a JSON list, the form the native stub logs.
json_list() {
  "$PYTHON" -I -c 'import json, sys; print(json.dumps(sys.argv[1:]))' "$@"
}

# Prints the SHA-256 of the content of file $1.
file_sha() {
  "$PYTHON" -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"
}

# Installs the policy body on platform $P.
install_policy() {
  mkdir -m 700 "$DATA_ROOT/policies"
  printf '%s' "$POLICY_TEXT" >"$POLICY_FILE"
  chmod 600 "$POLICY_FILE"
}

# Runs classified form $2 on a reset platform $P with policy state $1:
# missing, or the exit code of policy-check --origin.
run_classified() {
  reset_platform "$P"
  if [ "$1" != missing ]; then
    install_policy
    answer origin "$1"
  fi
  set -f
  # shellcheck disable=SC2086 # The form words split on spaces by design.
  run cli-launch $2
  set +f
}

case_signed_origin_classification() {
  local platform form call origin
  for platform in $PLATFORMS; do
    use "$platform"
    while IFS='|' read -r form call; do
      for origin in missing 0 3 65 1; do
        run_classified "$origin" "$form"
        case "$origin/$form" in
          "missing/approve --id probe-2")
            expect_refusal 65 "$LOCAL_LINE" "'$form' $origin"
            expect_native "$PREDICATE"
            ;;
          missing/*)
            [ "$RC" -eq 0 ] || fail "$P '$form' $origin exited $RC: $ERR"
            expect_native "$PREDICATE" "$call"
            ;;
          "0/approve --id probe-2")
            expect_refusal 65 "$LOCAL_LINE" "'$form' $origin"
            expect_native "$PREDICATE" "$ORIGIN_CHECK"
            ;;
          0/*)
            [ "$RC" -eq 0 ] || fail "$P '$form' $origin exited $RC: $ERR"
            expect_native "$PREDICATE" "$ORIGIN_CHECK" "$call"
            ;;
          "3/approve --id probe-2")
            [ "$RC" -eq 0 ] || fail "$P '$form' $origin exited $RC: $ERR"
            expect_native "$PREDICATE" "$ORIGIN_CHECK" "$call"
            ;;
          3/*)
            expect_refusal 65 "$SIGNED_LINE" "'$form' $origin"
            expect_native "$PREDICATE" "$ORIGIN_CHECK"
            ;;
          *)
            expect_refusal 65 "the policy origin is unreadable" "'$form' $origin"
            expect_native "$PREDICATE" "$ORIGIN_CHECK"
            ;;
        esac
        if [ "$origin" != missing ]; then
          [ "$(native_field 2 stdin)" = "$(json_string "$POLICY_TEXT")" ] ||
            fail "$P policy-check --origin did not read the installed policy on standard input"
        fi
      done
    done <<<"$CLASSIFIED"
    # A symlinked policy refuses before the classification.
    reset_platform "$platform"
    install_policy
    swap_for_symlink "$POLICY_FILE"
    run cli-launch approve --id probe-2
    expect_refusal 65 "the installed policy is a symlink" "a symlinked policy"
    expect_native "$PREDICATE"
    restore_from_symlink "$POLICY_FILE"
  done
}

case_signed_origin_operator_open_refused_at_launch() {
  local platform form call
  for platform in $PLATFORMS; do
    use "$platform"
    while IFS='|' read -r form call; do
      case "$form" in
        *--open-by-operator) ;;
        *) continue ;;
      esac
      run_classified 3 "$form"
      expect_refusal 65 "$SIGNED_LINE" "'$form'"
      expect_native "$PREDICATE" "$ORIGIN_CHECK"
      if native_calls | grep -qxF "$call"; then
        fail "$P '$form' reached its native verb"
      fi
    done <<<"$CLASSIFIED"
  done
}

case_approve_id_local_only_bare_refused() {
  local platform origin
  for platform in $PLATFORMS; do
    use "$platform"
    for origin in missing 0; do
      run_classified "$origin" "approve --id probe-3"
      expect_refusal 65 "$LOCAL_LINE" "bare approve --id ($origin)"
      if native_calls | grep -q "^stellar-agent approve "; then
        fail "$P bare approve --id reached the native approve verb"
      fi
    done
  done
}

case_approve_id_signed_origin_form() {
  local platform
  for platform in $PLATFORMS; do
    use "$platform"
    run_classified 3 "approve --id abc_DEF-1"
    [ "$RC" -eq 0 ] || fail "$P signed-origin approve --id exited $RC: $ERR"
    expect_native "$PREDICATE" "$ORIGIN_CHECK" "stellar-agent approve --id abc_DEF-1 --profile mainnet"
    [ "$(native_field 3 pid)" = "$PID" ] || fail "$P approve --id did not run under the wrapper's process ID"
  done
}

# Prints the names in directory $1, one per line, dot files included.
names_in() {
  ls -A "$1"
}

# Prints "<uid> <mode>" of path $1 through the host's stat.
host_facts() {
  if [ "$HOST_PLATFORM" = macos ]; then
    /usr/bin/stat -f '%u %Lp' "$1"
  else
    /usr/bin/stat -c '%u %a' "$1"
  fi
}

case_policy_install_stdin() {
  local platform code
  for platform in $PLATFORMS; do
    reset_platform "$platform"
    STDIN_TEXT=$POLICY_TEXT run provision policy-install
    [ "$RC" -eq 0 ] || fail "$P policy-install exited $RC: $ERR"
    [ "$(cat "$POLICY_FILE"; printf x)" = "${POLICY_TEXT}x" ] || fail "$P the installed policy differs from the input"
    [ "$(host_facts "$POLICY_FILE")" = "$ACCOUNT_UID 600" ] || fail "$P the policy is $(host_facts "$POLICY_FILE")"
    [ "$(host_facts "$DATA_ROOT/policies")" = "$ACCOUNT_UID 700" ] || fail "$P the policy directory is not 0700"
    [ "$(names_in "$DATA_ROOT/policies")" = mainnet.toml ] || fail "$P a temporary file remains"
    expect_native "$PREDICATE" "stellar-agent profile policy-check --profile mainnet"
    [ "$(native_field 2 stdin)" = "$(json_string "$POLICY_TEXT")" ] ||
      fail "$P policy-check did not read the staged policy"
    for code in 65 1; do
      printf 'installed = true\n' >"$POLICY_FILE"
      answer check "$code"
      : >"$STATE/calls.jsonl"
      STDIN_TEXT=$POLICY_TEXT run provision policy-install
      expect_refusal 65 "the policy did not pass profile policy-check, and the installed policy is unchanged" \
        "policy-install ($code)"
      [ "$(cat "$POLICY_FILE")" = "installed = true" ] || fail "$P a refused policy changed the installed one"
      [ "$(names_in "$DATA_ROOT/policies")" = mainnet.toml ] || fail "$P a refused policy left a temporary file"
    done
    answer check 0
    : >"$STATE/calls.jsonl"
    STDIN_TEXT="" run provision policy-install
    expect_refusal 65 "standard input is empty" "an empty policy"
    expect_native "$PREDICATE"
    [ "$(names_in "$DATA_ROOT/policies")" = mainnet.toml ] || fail "$P an empty policy left a temporary file"
  done
}

case_remote_pem_writes_land_0600() {
  local platform
  for platform in $PLATFORMS; do
    reset_platform "$platform"
    STDIN_TEXT=$CERT_PEM run provision remote-cert
    [ "$RC" -eq 0 ] || fail "$P remote-cert exited $RC: $ERR"
    STDIN_TEXT=$KEY_PEM run provision remote-key
    [ "$RC" -eq 0 ] || fail "$P remote-key exited $RC: $ERR"
    [ "$(cat "$DATA_ROOT/remote/cert.pem"; printf x)" = "${CERT_PEM}x" ] || fail "$P cert.pem differs"
    [ "$(cat "$DATA_ROOT/remote/key.pem"; printf x)" = "${KEY_PEM}x" ] || fail "$P key.pem differs"
    [ "$(host_facts "$DATA_ROOT/remote")" = "$ACCOUNT_UID 700" ] || fail "$P remote/ is not 0700"
    [ "$(host_facts "$DATA_ROOT/remote/cert.pem")" = "$ACCOUNT_UID 600" ] || fail "$P cert.pem is not 0600"
    [ "$(host_facts "$DATA_ROOT/remote/key.pem")" = "$ACCOUNT_UID 600" ] || fail "$P key.pem is not 0600"
    STDIN_TEXT=$KEY_PEM run provision remote-cert
    expect_refusal 65 "standard input is not a PEM certificate" "a key as the certificate"
    STDIN_TEXT=$CERT_PEM run provision remote-key
    expect_refusal 65 "standard input is not a PEM private key" "a certificate as the key"
    STDIN_TEXT="" run provision remote-key
    expect_refusal 65 "standard input is empty" "an empty key"
    [ "$(cat "$DATA_ROOT/remote/cert.pem"; printf x)" = "${CERT_PEM}x" ] || fail "$P a refusal changed cert.pem"
    [ "$(cat "$DATA_ROOT/remote/key.pem"; printf x)" = "${KEY_PEM}x" ] || fail "$P a refusal changed key.pem"
    [ "$(names_in "$DATA_ROOT/remote" | tr '\n' ' ')" = "cert.pem key.pem " ] || fail "$P a temporary file remains"
  done
}

# Fails unless destination $1, a directory or a symlink to directory $2
# as variant $3 says, is unchanged and $2 is empty.
expect_destination_kept() {
  if [ "$3" = directory ]; then
    [ -d "$1" ] && [ ! -L "$1" ] || fail "$P the directory at $1 is gone"
    [ -z "$(names_in "$1")" ] || fail "$P the install wrote into the directory $1"
  else
    [ -L "$1" ] && [ "$(readlink "$1")" = "$2" ] || fail "$P the symlink at $1 changed"
  fi
  [ -z "$(names_in "$2")" ] || fail "$P the install wrote into $2"
}

case_stdin_destinations_refuse_directories() {
  local platform form variant destination reason input parent target
  for platform in $PLATFORMS; do
    for form in remote-cert remote-key policy-install; do
      for variant in directory symlink; do
        reset_platform "$platform"
        case "$form" in
          remote-cert)
            destination="$DATA_ROOT/remote/cert.pem" reason="the remote certificate path is a directory" input=$CERT_PEM
            ;;
          remote-key) destination="$DATA_ROOT/remote/key.pem" reason="the remote key path is a directory" input=$KEY_PEM ;;
          policy-install) destination=$POLICY_FILE reason="the installed policy path is a directory" input=$POLICY_TEXT ;;
        esac
        parent=$(dirname "$destination")
        mkdir -m 700 "$parent"
        target="$BASE/elsewhere-$form-$variant"
        mkdir "$target"
        if [ "$variant" = directory ]; then
          mkdir "$destination"
        else
          ln -s "$target" "$destination"
        fi
        STDIN_TEXT=$input run provision "$form"
        expect_refusal 65 "$reason" "$form onto a $variant"
        expect_destination_kept "$destination" "$target" "$variant"
        [ "$(names_in "$parent")" = "$(basename "$destination")" ] ||
          fail "$P $form onto a $variant left $(names_in "$parent" | tr '\n' ' ')"
        if [ "$form" = policy-install ]; then
          expect_native "$PREDICATE" "stellar-agent profile policy-check --profile mainnet"
        else
          expect_native "$PREDICATE"
        fi
      done
    done
  done
}

case_rename_refuses_a_directory_after_the_check() {
  local platform form destination name input parent
  for platform in $PLATFORMS; do
    for form in remote-cert remote-key policy-install; do
      reset_platform "$platform"
      case "$form" in
        remote-cert) destination="$DATA_ROOT/remote/cert.pem" name="the remote certificate path" input=$CERT_PEM ;;
        remote-key) destination="$DATA_ROOT/remote/key.pem" name="the remote key path" input=$KEY_PEM ;;
        policy-install) destination=$POLICY_FILE name="the installed policy path" input=$POLICY_TEXT ;;
      esac
      parent=$(dirname "$destination")
      : >"$STATE/rename_hook"
      STDIN_TEXT=$input run provision "$form"
      [ -e "$STATE/rename_hook.used" ] || fail "$P $form never reached the rename"
      mv "$STATE/rename_hook.used" "$STATE/rename_hook.done"
      expect_refusal 65 "$name was not replaced, and the installed file is unchanged" "$form onto a late directory"
      [ -d "$destination" ] && [ ! -L "$destination" ] || fail "$P $form replaced the late directory"
      [ -z "$(names_in "$destination")" ] || fail "$P $form wrote into the late directory"
      [ "$(names_in "$parent")" = "$(basename "$destination")" ] ||
        fail "$P $form onto a late directory left $(names_in "$parent" | tr '\n' ' ')"
    done
    use "$platform"
    destination="$PREFIX/bin/stellar-agent-mcp"
    reset_account
    echo yes >"$STATE/account_exists"
    : >"$STATE/rename_hook"
    bootstrap_args
    run_bootstrap "${BOOT_ARGS[@]}"
    [ -e "$STATE/rename_hook.used" ] || fail "$P bootstrap never reached the rename"
    mv "$STATE/rename_hook.used" "$STATE/rename_hook.done"
    [ "$BOOT_RC" -eq 65 ] || fail "$P bootstrap onto a late directory exited $BOOT_RC: $BOOT_ERR"
    [ "$BOOT_ERR" = "bootstrap: refused: $PREFIX/bin/stellar-agent was not replaced, and the installed file is unchanged" ] ||
      fail "$P bootstrap onto a late directory printed: $BOOT_ERR"
    destination="$PREFIX/bin/stellar-agent"
    [ -d "$destination" ] && [ -z "$(names_in "$destination")" ] || fail "$P bootstrap wrote into the late directory"
    if names_in "$PREFIX/bin" | grep -q '^\.stellar-agent\.'; then
      fail "$P bootstrap onto a late directory left a staged file"
    fi
    rmdir "$destination"
    mv "$destination.raced" "$destination"
  done
}

case_providers_fragment_accepted() {
  local platform fragment
  for platform in $PLATFORMS; do
    reset_platform "$platform"
    answer fragment_stderr 'applying\ncredential-roles: primary oracle'
    feed_tty "first-value" "second-value"
    STDIN_TEXT=$FRAGMENT run provision providers
    close_tty
    [ "$RC" -eq 0 ] || fail "$P providers exited $RC: $ERR"
    expect_native "$PREDICATE" "stellar-agent profile apply-fragment --profile mainnet" \
      "stellar-agent profile enroll-rpc-credential --role primary --stdin --force --profile mainnet" \
      "stellar-agent profile enroll-rpc-credential --role oracle --stdin --force --profile mainnet"
    [ "$(native_field 2 stdin)" = "$(json_string "$FRAGMENT")" ] ||
      fail "$P apply-fragment did not read the fragment byte for byte"
    [ "$(native_field 3 stdin)" = "{\"length\": 11, \"sha256\": \"$(sha first-value)\"}" ] ||
      fail "$P the primary credential is not the first prompted value"
    [ "$(native_field 4 stdin)" = "{\"length\": 12, \"sha256\": \"$(sha second-value)\"}" ] ||
      fail "$P the oracle credential is not the second prompted value"
    [ "$(native_field 4 pid)" = "$PID" ] || fail "$P the last credential call did not run under the wrapper's process ID"
    case "$ERR" in
      *applying* | *credential-roles*) fail "$P apply-fragment output reached the operator: $ERR" ;;
    esac
    reset_platform "$platform"
    STDIN_TEXT=$FRAGMENT run provision providers
    [ "$RC" -eq 0 ] || fail "$P providers without credentials exited $RC: $ERR"
    expect_native "$PREDICATE" "stellar-agent profile apply-fragment --profile mainnet"
    # Other TOML spellings of the same top-level key and https value.
    while IFS= read -r fragment; do
      fragment=$(printf '%b' "$fragment")$'\n'
      reset_platform "$platform"
      STDIN_TEXT=$fragment run provision providers
      [ "$RC" -eq 0 ] || fail "$P fragment '$fragment' exited $RC: $ERR"
      expect_native "$PREDICATE" "stellar-agent profile apply-fragment --profile mainnet"
      [ "$(native_field 2 stdin)" = "$(json_string "$fragment")" ] ||
        fail "$P apply-fragment did not read fragment '$fragment' byte for byte"
    done <<'FRAGMENTS'
oracle_provider_url = "https://oracle.example/v1" # production oracle
oracle_provider_url = 'https://oracle.example/v1'
oracle_provider_url = 'https://oracle.example/v1' # literal string
"oracle_provider_url" = "https://oracle.example/v1"
'oracle_provider_url'\t=\t"https://oracle.example/v1"\t# tabs
# oracle_provider_url = "http://oracle.example"\noracle_provider_url = "https://oracle.example/v1"
note = """\noracle_provider_url = "http://inside.example"\n"""\noracle_provider_url = "https://oracle.example/v1"
rpc = [\n  [1, 2],\n]\noracle_provider_url = "https://oracle.example/v1"\n\n[providers.primary]\nurl = "https://rpc.example"
oracle_provider_url = "https://oracle.example/v1"\r
FRAGMENTS
  done
}

# Fails unless fragment $2 on platform $P refuses with reason $1 before
# apply-fragment.
expect_oracle_refusal() {
  reset_platform "$P"
  STDIN_TEXT=$2 run provision providers
  expect_refusal 65 "$1" "fragment '$2'"
  expect_native "$PREDICATE"
}

case_providers_fragment_refused() {
  local platform refusal code
  local missing="the fragment has no top-level https oracle_provider_url"
  local insecure="the fragment's oracle_provider_url is not an https URL"
  for platform in $PLATFORMS; do
    use "$platform"
    expect_oracle_refusal "$missing" $'[providers.primary]\nurl = "https://rpc.example"\n'
    expect_oracle_refusal "$missing" $'[oracle]\noracle_provider_url = "https://oracle.example"\n'
    expect_oracle_refusal "$missing" $'oracle_provider = "https://oracle.example"\n'
    expect_oracle_refusal "$insecure" $'oracle_provider_url = "http://oracle.example"\n'
    expect_oracle_refusal "$insecure" $'oracle_provider_url = "ftp://oracle.example"\n'
    expect_oracle_refusal "$insecure" $'oracle_provider_url = "https://oracle example"\n'
    expect_oracle_refusal "$insecure" $'oracle_provider_url = https://oracle.example\n'
    expect_oracle_refusal "$insecure" $'oracle_provider_url = \'http://oracle.example\'\n'
    expect_oracle_refusal "$insecure" $'oracle_provider_url = "https://oracle.example" extra\n'
    expect_oracle_refusal "$insecure" $'oracle_provider_url = "https://oracle.example\'\n'
    expect_oracle_refusal "$insecure" $'oracle_provider_url = "HTTPS://oracle.example"\n'
    expect_oracle_refusal "$missing" $'note = """\noracle_provider_url = "https://inside.example"\n"""\n'
    expect_oracle_refusal "$missing" $'oracle_provider_url.host = "https://oracle.example"\n'
    expect_oracle_refusal "the fragment's oracle_provider_url holds an escape sequence; write the URL without backslashes" \
      $'oracle_provider_url = "\\u0068ttps://oracle.example"\n'
    expect_oracle_refusal "the fragment's oracle_provider_url is a multi-line string; write it on one line in double or single quotes" \
      $'oracle_provider_url = """https://oracle.example"""\n'
    expect_oracle_refusal "the fragment's oracle_provider_url is a multi-line string; write it on one line in double or single quotes" \
      $'oracle_provider_url = \'\'\'https://oracle.example\'\'\'\n'
    reset_platform "$platform"
    STDIN_TEXT="" run provision providers
    expect_refusal 65 "standard input is empty" "an empty fragment"
    expect_native "$PREDICATE"
    for refusal in "65|refused: profile.fragment_unknown_key" "1|internal error" "0|applied without roles"; do
      reset_platform "$platform"
      code=${refusal%%|*}
      answer fragment "$code"
      answer fragment_stderr "${refusal#*|}"
      feed_tty "unused-value"
      STDIN_TEXT=$FRAGMENT run provision providers
      close_tty
      case "$code" in
        65) expect_refusal 65 "the fragment was refused, and the profile is unchanged" "fragment refusal" ;;
        1) expect_refusal 65 "profile apply-fragment failed" "fragment failure" ;;
        0) expect_refusal 65 "profile apply-fragment reported no credential roles" "fragment without roles" ;;
      esac
      expect_native "$PREDICATE" "stellar-agent profile apply-fragment --profile mainnet"
    done
  done
}

case_providers_force_replaces_credential() {
  local platform round
  for platform in $PLATFORMS; do
    reset_platform "$platform"
    answer fragment_stderr "credential-roles: primary"
    for round in 1 2; do
      feed_tty "value-$round"
      STDIN_TEXT=$FRAGMENT run provision providers
      close_tty
      [ "$RC" -eq 0 ] || fail "$P providers round $round exited $RC: $ERR"
    done
    expect_native "$PREDICATE" "stellar-agent profile apply-fragment --profile mainnet" \
      "stellar-agent profile enroll-rpc-credential --role primary --stdin --force --profile mainnet" \
      "$PREDICATE" "stellar-agent profile apply-fragment --profile mainnet" \
      "stellar-agent profile enroll-rpc-credential --role primary --stdin --force --profile mainnet"
    [ "$(native_field 6 stdin)" = "{\"length\": 7, \"sha256\": \"$(sha value-2)\"}" ] ||
      fail "$P the second round did not enroll its own value"
  done
}

case_provider_credential_form() {
  local platform role
  for platform in $PLATFORMS; do
    for role in primary secondary oracle; do
      reset_platform "$platform"
      feed_tty "credential-$role"
      run provision provider-credential --role "$role"
      close_tty
      [ "$RC" -eq 0 ] || fail "$P provider-credential $role exited $RC: $ERR"
      [ -z "$ERR" ] || fail "$P provider-credential $role wrote to standard error: $ERR"
      [ "$TTY_OUTPUT" = "RPC credential for the $role provider: " ] ||
        fail "$P provider-credential $role wrote '$TTY_OUTPUT' to the terminal"
      expect_native "$PREDICATE" "stellar-agent profile enroll-rpc-credential --role $role --stdin --force --profile mainnet"
      [ "$(native_field 2 stdin)" = "{\"length\": $((${#role} + 11)), \"sha256\": \"$(sha "credential-$role")\"}" ] ||
        fail "$P the credential did not reach the native verb on standard input"
      [ "$(native_field 2 pid)" = "$PID" ] || fail "$P provider-credential did not run under the wrapper's process ID"
      if call_environment 2 | grep -q '^STELLAR_AGENT_PROVISION_SECRET='; then
        fail "$P provider-credential passed the secret variable"
      fi
    done
    # An empty answer: the prompt lands on the terminal, and the refusal is
    # the only standard error line.
    reset_platform "$platform"
    feed_tty ""
    run provision provider-credential --role primary
    close_tty
    expect_refusal 65 "the prompt received no value" "an empty credential"
    [ "$TTY_OUTPUT" = "RPC credential for the primary provider: " ] ||
      fail "$P the empty credential prompt wrote '$TTY_OUTPUT' to the terminal"
    expect_native "$PREDICATE"
    # A terminal that reads as empty refuses the same way.
    reset_platform "$platform"
    run provision provider-credential --role primary
    expect_refusal 65 "the prompt received no value" "a terminal without input"
    expect_native "$PREDICATE"
    reset_platform "$platform"
    rm "$TTY"
    run provision provider-credential --role primary
    expect_refusal 65 "no terminal is available for the prompt" "a missing terminal"
    expect_native "$PREDICATE"
  done
}

case_remote_config_fragment_is_exact() {
  local platform bind expected
  for platform in $PLATFORMS; do
    for bind in 127.0.0.1:8443 "[::1]:8443" 0.0.0.0:443; do
      reset_platform "$platform"
      run provision remote-config --bind "$bind" --rp-id wallet.example
      [ "$RC" -eq 0 ] || fail "$P remote-config $bind exited $RC: $ERR"
      expect_native "$PREDICATE" "stellar-agent profile apply-fragment --profile mainnet"
      expected="[remote_approval]
enabled = true
bind = \"$bind\"
rp_id = \"wallet.example\"
cert_path = \"$DATA_ROOT/remote/cert.pem\"
key_path = \"$DATA_ROOT/remote/key.pem\"
"
      [ "$(native_field 2 stdin)" = "$(json_string "$expected")" ] ||
        fail "$P the remote-config fragment is $(native_field 2 stdin)"
    done
    reset_platform "$platform"
    answer fragment 65
    answer fragment_stderr "refused: profile.remote_invalid"
    run provision remote-config --bind 127.0.0.1:8443 --rp-id wallet.example
    expect_refusal 65 "the fragment was refused, and the profile is unchanged" "remote-config refusal"
  done
}

case_refusal_lines_echo_no_caller_token() {
  local platform args token=CallerToken
  for platform in $PLATFORMS; do
    reset_platform "$platform"
    for args in "cli-launch $token" "cli-launch profile show $token" "cli-launch profile show --profile $token" \
      "cli-launch approve --id $token.x" "cli-launch approve --id x $token" \
      "provision provider-credential --role $token" "provision profile init --network mainnet --rpc-url http://$token" \
      "provision remote-config --bind $token:1 --rp-id wallet.example" \
      "provision remote-config --bind 127.0.0.1:1 --rp-id $token" "mcp-launch $token" \
      "provision profile $token" "cli-launch audit verify --audit-log $token"; do
      set -f
      # shellcheck disable=SC2086 # The argument words split on spaces by design.
      run $args
      set +f
      [ "$RC" -eq 64 ] || fail "$P '$args' exited $RC"
      [ "$(printf '%s\n' "$ERR" | wc -l | tr -d ' ')" -eq 1 ] || fail "$P '$args' wrote more than one line: $ERR"
      case "$ERR" in
        "$PREFIX_LINE"*) ;;
        *) fail "$P '$args' refusal has another form: $ERR" ;;
      esac
      case "$ERR" in
        *"$token"*) fail "$P '$args' echoed the caller token: $ERR" ;;
      esac
    done
  done
}

# Fails unless the run exited $1 with the refusal line of reason $2 alone,
# wrote nothing to standard output, and showed no subordinate diagnostic.
expect_quiet_refusal() {
  expect_refusal "$1" "$2" "$3"
  [ -z "$OUT" ] || fail "$P $3 wrote to standard output: $OUT"
}

case_native_diagnostics_stay_behind_refusals() {
  local platform code verb noise="error: CallerToken at line 1"
  for platform in $PLATFORMS; do
    reset_platform "$platform"
    answer noise "$noise"
    answer check 65
    STDIN_TEXT=$POLICY_TEXT run provision policy-install
    expect_quiet_refusal 65 "the policy did not pass profile policy-check, and the installed policy is unchanged" \
      "a refused policy-check"
    for code in 65 1; do
      reset_platform "$platform"
      answer noise "$noise"
      answer fragment "$code"
      answer fragment_stderr "refused: profile.fragment_unknown_key"
      STDIN_TEXT=$FRAGMENT run provision providers
      if [ "$code" = 65 ]; then
        expect_quiet_refusal 65 "the fragment was refused, and the profile is unchanged" "a refused fragment"
      else
        expect_quiet_refusal 65 "profile apply-fragment failed" "a failed fragment"
      fi
      reset_platform "$platform"
      answer noise "$noise"
      answer fragment "$code"
      answer fragment_stderr "refused: profile.remote_invalid"
      run provision remote-config --bind 127.0.0.1:8443 --rp-id wallet.example
      if [ "$code" = 65 ]; then
        expect_quiet_refusal 65 "the fragment was refused, and the profile is unchanged" "a refused remote-config"
      else
        expect_quiet_refusal 65 "profile apply-fragment failed" "a failed remote-config"
      fi
    done
    reset_platform "$platform"
    answer noise "$noise"
    answer fragment_stderr "credential-roles: primary oracle"
    answer default 1
    feed_tty "first-value" "second-value"
    STDIN_TEXT=$FRAGMENT run provision providers
    close_tty
    expect_quiet_refusal 65 "the provider credential was not enrolled" "a failed credential call"
    [ "$TTY_OUTPUT" = "RPC credential for the primary provider: " ] ||
      fail "$P the failed credential call wrote '$TTY_OUTPUT' to the terminal"
    if [ "$P" = macos ]; then
      for verb in create-keychain default-keychain unlock-keychain; do
        reset_platform "$platform"
        answer noise "$noise"
        answer "security_$verb" 1
        STDIN_TEXT=$'value\nvalue\n' run cli-launch keychain-unlock
        case "$verb" in
          create-keychain) expect_quiet_refusal 65 "the login keychain was not created" "a failed $verb" ;;
          default-keychain) expect_quiet_refusal 65 "the login keychain was not selected" "a failed $verb" ;;
          unlock-keychain) expect_quiet_refusal 65 "the login keychain did not unlock" "a failed $verb" ;;
        esac
      done
    fi
  done
}

case_wrappers_write_no_stdout() {
  local platform line code
  for platform in $PLATFORMS; do
    while IFS= read -r line; do
      for code in 3 0 1; do
        run_form "$platform" "$line" "$code"
        [ -z "$OUT" ] || fail "$P '$FORM_ARGS' wrote to standard output: $OUT"
      done
    done <<<"$FORMS"
    reset_platform "$platform"
    STDIN_TEXT=$'{"jsonrpc":"2.0","id":1,"method":"ping"}\n' run mcp-launch
    [ "$RC" -eq 0 ] || fail "$P mcp-launch exited $RC: $ERR"
    [ "$OUT" = '{"jsonrpc":"2.0","id":1,"method":"ping"}' ] || fail "$P mcp-launch standard output is not the server's: $OUT"
    expect_native "$PREDICATE" "stellar-agent-mcp --profile mainnet"
    [ "$(native_field 2 pid)" = "$PID" ] || fail "$P the MCP server did not run under the wrapper's process ID"
  done
}

case_wrappers_handle_the_space_in_the_macos_data_root() {
  reset_platform macos
  case "$DATA_ROOT" in
    *" "*) ;;
    *) fail "the macOS data root has no space: $DATA_ROOT" ;;
  esac
  run cli-launch audit verify
  [ "$RC" -eq 0 ] || fail "audit verify exited $RC: $ERR"
  [ "$(native_field 2 argv)" = "$(json_list audit verify "$DATA_ROOT/audit/mainnet.jsonl" --profile mainnet)" ] ||
    fail "audit verify split the data root: $(native_field 2 argv)"
  run cli-launch approve credential enroll --origin-from-installed
  [ "$RC" -eq 0 ] || fail "enroll --origin-from-installed exited $RC: $ERR"
  [ "$(native_field 4 argv)" = "$(json_list approve credential enroll --origin-from "$DATA_ROOT/policies/mainnet.toml" --profile mainnet)" ] ||
    fail "enroll --origin-from-installed split the data root: $(native_field 4 argv)"
  STDIN_TEXT=$POLICY_TEXT run provision policy-install
  [ "$RC" -eq 0 ] || fail "policy-install in the spaced data root exited $RC: $ERR"
  [ -f "$POLICY_FILE" ] || fail "policy-install wrote no policy in the spaced data root"
  STDIN_TEXT=$CERT_PEM run provision remote-cert
  [ "$RC" -eq 0 ] || fail "remote-cert in the spaced data root exited $RC: $ERR"
  [ -f "$DATA_ROOT/remote/cert.pem" ] || fail "remote-cert wrote no file in the spaced data root"
  run provision remote-config --bind 127.0.0.1:8443 --rp-id wallet.example
  [ "$RC" -eq 0 ] || fail "remote-config with the spaced data root exited $RC: $ERR"
  case "$(native_field 9 stdin)" in
    *"cert_path = \\\"$DATA_ROOT/remote/cert.pem\\\""*) ;;
    *) fail "remote-config split the data root: $(native_field 9 stdin)" ;;
  esac
  run cli-launch profile show
  [ "$RC" -eq 0 ] || fail "profile show with the spaced data root exited $RC: $ERR"
}

case_wrappers_share_identical_checks() {
  local name block reference=""
  for name in mcp-launch cli-launch provision; do
    block=$(awk '/^# --- shared wrapper checks: begin ---$/,/^# --- shared wrapper checks: end ---$/' "$DEPLOY/$name")
    [ -n "$block" ] || fail "$name has no shared block"
    if [ -z "$reference" ]; then
      reference=$block
    elif [ "$block" != "$reference" ]; then
      fail "the shared block of $name differs from the one of mcp-launch"
    fi
  done
}

# Prints the sudoers lines of the deployment for operator $1, account $2,
# and wrapper prefix $3.
sudoers_literal() {
  printf '%s ALL=(%s) NOPASSWD: %s/mcp-launch, %s/cli-launch, %s/provision\n' "$1" "$2" "$3" "$3" "$3"
  printf 'Defaults!%s/mcp-launch !requiretty\n' "$3"
  printf 'Defaults!%s/cli-launch !requiretty\n' "$3"
  printf 'Defaults!%s/provision !requiretty\n' "$3"
}

# Prints the system log of platform $P with each tab as a space.
system_log() {
  tr '\t' ' ' <"$STATE/system.log"
}

case_bootstrap_renders_exact_sudoers() {
  local platform rendered expected
  rendered=$(sed -e 's|@OPERATOR@|operator|g' -e 's|@ACCOUNT@|stellar-agent|g' \
    -e 's|@PREFIX@|/usr/local/libexec/stellar-agent|g' "$DEPLOY/sudoers"; printf x)
  expected=$(sudoers_literal operator stellar-agent /usr/local/libexec/stellar-agent; printf x)
  [ "$rendered" = "$expected" ] || fail "the sudoers template with the fixed values differs:
$rendered"
  for platform in $PLATFORMS; do
    use "$platform"
    echo yes >"$STATE/account_exists"
    bootstrap_args
    : >"$STATE/system.log"
    run_bootstrap "${BOOT_ARGS[@]}"
    [ "$BOOT_RC" -eq 0 ] || fail "$P bootstrap exited $BOOT_RC: $BOOT_ERR"
    expected=$(sudoers_literal "$OPERATOR" "$ACCOUNT" "$PREFIX"; printf x)
    [ "$(cat "$BASE/sudoers.d/stellar-agent"; printf x)" = "$expected" ] || fail "$P the rendered sudoers differs:
$(cat "$BASE/sudoers.d/stellar-agent")"
    [ "$(host_facts "$BASE/sudoers.d/stellar-agent")" = "$ACCOUNT_UID 440" ] || fail "$P sudoers is not 0440"
    system_log | grep -qE "^visudo -cf $BASE/sudoers\.d/\.stellar-agent\.[A-Za-z0-9]+\$" ||
      fail "$P visudo did not check the staged sudoers file"
    system_log | grep -qE "^chown 0:0 $BASE/sudoers\.d/\.stellar-agent\.[A-Za-z0-9]+\$" ||
      fail "$P the staged sudoers file was not made root-owned"
    [ "$(names_in "$BASE/sudoers.d")" = stellar-agent ] || fail "$P a staged sudoers file remains"
    # A visudo refusal keeps the installed file.
    answer visudo 1
    printf 'installed\n' >"$WORK/installed-sudoers"
    mv -f "$WORK/installed-sudoers" "$BASE/sudoers.d/stellar-agent"
    run_bootstrap "${BOOT_ARGS[@]}"
    answer visudo 0
    [ "$BOOT_RC" -eq 65 ] || fail "$P a visudo refusal exited $BOOT_RC"
    [ "$BOOT_ERR" = "bootstrap: refused: visudo refuses the rendered sudoers file" ] ||
      fail "$P a visudo refusal printed: $BOOT_ERR"
    [ "$(cat "$BASE/sudoers.d/stellar-agent")" = installed ] || fail "$P a refused sudoers file replaced the installed one"
    [ "$(names_in "$BASE/sudoers.d")" = stellar-agent ] || fail "$P a refused sudoers file remains staged"
    run_bootstrap "${BOOT_ARGS[@]}"
    [ "$BOOT_RC" -eq 0 ] || fail "$P bootstrap exited $BOOT_RC: $BOOT_ERR"
  done
}

case_bootstrap_refuses_without_root() {
  local platform
  for platform in $PLATFORMS; do
    use "$platform"
    echo "$ACCOUNT_UID" >"$STATE/root_uid"
    : >"$STATE/system.log"
    cp "$PREFIX/cli-launch" "$WORK/cli-launch.before"
    bootstrap_args
    run_bootstrap "${BOOT_ARGS[@]}"
    echo 0 >"$STATE/root_uid"
    [ "$BOOT_RC" -eq 65 ] || fail "$P a bootstrap without root exited $BOOT_RC"
    [ "$BOOT_ERR" = "bootstrap: refused: bootstrap runs as root" ] || fail "$P a bootstrap without root printed: $BOOT_ERR"
    [ "$(system_log)" = "id -u" ] || fail "$P a bootstrap without root ran: $(system_log)"
    cmp -s "$PREFIX/cli-launch" "$WORK/cli-launch.before" || fail "$P a bootstrap without root changed a wrapper"
  done
}

case_bootstrap_refuses_test_helpers_binary() {
  local platform literal reason
  for platform in $PLATFORMS; do
    use "$platform"
    echo yes >"$STATE/account_exists"
    for literal in "STELLAR_AGENT_TEST_HOOKS" "STELLAR_AGENT_HOME" "STELLAR_AGENT_BUILD_MAINNET_WRITE=off" ""; do
      if [ -n "$literal" ]; then
        write_native_stub "$WORK/candidate" "STELLAR_AGENT_BUILD_MAINNET_WRITE=on $literal"
      else
        write_native_stub "$WORK/candidate" "a binary without the marker"
      fi
      case "$literal" in
        STELLAR_AGENT_TEST_HOOKS) reason="the --cli binary embeds the test override literal STELLAR_AGENT_TEST_" ;;
        STELLAR_AGENT_HOME) reason="the --cli binary embeds the test override literal STELLAR_AGENT_HOME" ;;
        *=off) reason="the --cli binary carries the STELLAR_AGENT_BUILD_MAINNET_WRITE=off marker" ;;
        *) reason="the --cli binary lacks the STELLAR_AGENT_BUILD_MAINNET_WRITE=on marker" ;;
      esac
      : >"$STATE/system.log"
      cp "$PREFIX/bin/stellar-agent" "$WORK/installed.before"
      run_bootstrap --operator "$OPERATOR" --project "$PROJECT" --cli "$WORK/candidate" --mcp "$BASE/src/stellar-agent-mcp"
      [ "$BOOT_RC" -eq 65 ] || fail "$P a binary with '$literal' exited $BOOT_RC"
      [ "$BOOT_ERR" = "bootstrap: refused: $reason" ] || fail "$P a binary with '$literal' printed: $BOOT_ERR"
      cmp -s "$PREFIX/bin/stellar-agent" "$WORK/installed.before" || fail "$P a refused binary replaced the installed one"
      if system_log | grep -qE "^(sysadminctl|useradd|usermod|dscl|chown|visudo) "; then
        fail "$P a refused binary reached a root step: $(system_log)"
      fi
    done
    write_native_stub "$WORK/candidate" "STELLAR_AGENT_BUILD_MAINNET_WRITE=on STELLAR_AGENT_TEST_HOOKS"
    run_bootstrap --operator "$OPERATOR" --project "$PROJECT" --cli "$BASE/src/stellar-agent" --mcp "$WORK/candidate"
    [ "$BOOT_RC" -eq 65 ] || fail "$P a test-helpers MCP binary exited $BOOT_RC"
    [ "$BOOT_ERR" = "bootstrap: refused: the --mcp binary embeds the test override literal STELLAR_AGENT_TEST_" ] ||
      fail "$P a test-helpers MCP binary printed: $BOOT_ERR"
  done
}

case_bootstrap_refuses_directory_destinations() {
  local platform destination variant target parent index=0
  for platform in $PLATFORMS; do
    use "$platform"
    for destination in "$PREFIX/bin/stellar-agent" "$PREFIX/cli-launch" "$BASE/etc/project" \
      "$BASE/sudoers.d/stellar-agent"; do
      for variant in directory symlink; do
        parent=$(dirname "$destination")
        index=$((index + 1))
        target="$BASE/bootstrap-elsewhere-$index"
        mkdir "$target"
        mv "$destination" "$destination.saved"
        if [ "$variant" = directory ]; then
          mkdir "$destination"
        else
          ln -s "$target" "$destination"
        fi
        reset_account
        echo yes >"$STATE/account_exists"
        bootstrap_args
        run_bootstrap "${BOOT_ARGS[@]}"
        [ "$BOOT_RC" -eq 65 ] || fail "$P a $variant at $destination exited $BOOT_RC: $BOOT_ERR"
        [ "$BOOT_ERR" = "bootstrap: refused: $destination is a directory" ] ||
          fail "$P a $variant at $destination printed: $BOOT_ERR"
        expect_destination_kept "$destination" "$target" "$variant"
        if names_in "$parent" | grep -q '^\.stellar-agent\.'; then
          fail "$P a $variant at $destination left a staged file"
        fi
        if [ "$variant" = directory ]; then
          rmdir "$destination"
        else
          rm "$destination"
        fi
        mv "$destination.saved" "$destination"
      done
    done
  done
}

case_bootstrap_takes_no_secret() {
  local platform option line
  for platform in $PLATFORMS; do
    use "$platform"
    echo yes >"$STATE/account_exists"
    bootstrap_args
    for option in --password --secret --passphrase; do
      run_bootstrap "${BOOT_ARGS[@]}" "$option" "$MARKER"
      [ "$BOOT_RC" -eq 64 ] || fail "$P the option $option exited $BOOT_RC"
    done
    # Bootstrap leaves a held standard input unread.
    rm -f "$WORK/stdin"
    mkfifo "$WORK/stdin"
    exec 9<>"$WORK/stdin"
    printf '%s\n' "$MARKER" >&9
    BOOT_RC=0
    "$BASE/deploy/bootstrap.sh" "${BOOT_ARGS[@]}" <&9 >"$WORK/boot.out" 2>"$WORK/boot.err" 9>&- || BOOT_RC=$?
    [ "$BOOT_RC" -eq 0 ] || fail "$P bootstrap exited $BOOT_RC: $(cat "$WORK/boot.err")"
    line=""
    IFS= read -r -t 2 line <&9 || true
    exec 9>&-
    rm -f "$WORK/stdin"
    [ "$line" = "$MARKER" ] || fail "$P bootstrap read its standard input"
    # A first run creates the account without a password argument.
    reset_account
    : >"$STATE/system.log"
    run_bootstrap "${BOOT_ARGS[@]}"
    [ "$BOOT_RC" -eq 0 ] || fail "$P a creating bootstrap exited $BOOT_RC: $BOOT_ERR"
    case "$P" in
      macos)
        system_log | grep -qxF "sysadminctl -addUser $ACCOUNT -fullName Stellar agent wallet -home $HOME_DIR -shell /usr/bin/false" &&
          system_log | grep -qxF "dscl . -create /Users/$ACCOUNT UserShell /usr/bin/false" &&
          system_log | grep -qxF "dscl . -create /Users/$ACCOUNT Passwd *" &&
          system_log | grep -qxF "dscl . -delete /Users/$ACCOUNT AuthenticationAuthority" &&
          system_log | grep -qxF "dscl . -create /Users/$ACCOUNT IsHidden 1"
        ;;
      linux)
        system_log | grep -qxF "useradd --system --user-group --home-dir $HOME_DIR --no-create-home --shell /usr/sbin/nologin $ACCOUNT" &&
          system_log | grep -qxF "usermod --shell /usr/sbin/nologin $ACCOUNT" &&
          system_log | grep -qxF "usermod --lock $ACCOUNT"
        ;;
    esac || fail "$P R1 and R2 calls differ: $(system_log)"
    if system_log | grep -E "^(sysadminctl|useradd|usermod|dscl) " | grep -qiE " (-p|--?pass(word)?|-password)( |\$)"; then
      fail "$P a user database call carried a password argument"
    fi
    expect_marker_nowhere
  done
}

# Prints the checksum, mode, and modification time of every file and
# directory below the data root of platform $P.
data_snapshot() {
  "$PYTHON" -I - "$DATA_ROOT" <<'PY'
import hashlib
import os
import sys

root = sys.argv[1]
for directory, dirs, files in os.walk(root):
    dirs.sort()
    for name in sorted(dirs + files):
        path = os.path.join(directory, name)
        info = os.lstat(path)
        digest = "-"
        if os.path.isfile(path):
            with open(path, "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
        print(os.path.relpath(path, root), oct(info.st_mode), info.st_mtime_ns, digest)
PY
}

case_bootstrap_rerun_converges() {
  local platform before after directory
  for platform in $PLATFORMS; do
    reset_platform "$platform"
    echo yes >"$STATE/account_exists"
    bootstrap_args
    mkdir -m 700 "$DATA_ROOT/audit" "$DATA_ROOT/policies" "$DATA_ROOT/keys"
    printf 'audit line\n' >"$DATA_ROOT/audit/mainnet.jsonl"
    printf 'policy\n' >"$POLICY_FILE"
    printf 'key material\n' >"$DATA_ROOT/keys/entry"
    chmod 640 "$PROFILE_FILE"
    chmod 644 "$POLICY_FILE"
    chmod 600 "$DATA_ROOT/audit/mainnet.jsonl" "$DATA_ROOT/keys/entry"
    chmod 750 "$DATA_ROOT/profiles"
    touch -t 202001010000 "$PROFILE_FILE" "$POLICY_FILE" "$DATA_ROOT/audit/mainnet.jsonl"
    before=$(data_snapshot)
    chmod 755 "$HOME_DIR" "$RUN_DIR" "$DATA_ROOT"
    rmdir "$HOME_DIR/tmp"
    write_native_stub "$WORK/upgrade-cli" "STELLAR_AGENT_BUILD_MAINNET_WRITE=on upgrade"
    : >"$STATE/system.log"
    run_bootstrap --operator "$OPERATOR" --project "$PROJECT" --cli "$WORK/upgrade-cli" --mcp "$BASE/src/stellar-agent-mcp"
    [ "$BOOT_RC" -eq 0 ] || fail "$P the rerun exited $BOOT_RC: $BOOT_ERR"
    case "$BOOT_OUT" in
      *"R7 verifies the existing account $ACCOUNT"*) ;;
      *) fail "$P the rerun did not verify the existing account: $BOOT_OUT" ;;
    esac
    if system_log | grep -qE "^(sysadminctl|useradd) "; then
      fail "$P the rerun created the account again"
    fi
    cmp -s "$WORK/upgrade-cli" "$PREFIX/bin/stellar-agent" || fail "$P the rerun did not install the new binary"
    [ "$(host_facts "$PREFIX/bin/stellar-agent")" = "$ACCOUNT_UID 755" ] || fail "$P the new binary is not 0755"
    system_log | grep -qxF "chown 0:0 $PREFIX" || fail "$P the prefix was not made root-owned"
    after=$(data_snapshot)
    [ "$after" = "$before" ] || fail "$P the rerun changed the tree below the data root:
before:
$before
after:
$after"
    for directory in "$HOME_DIR" "$RUN_DIR" "$HOME_DIR/tmp" "$DATA_ROOT"; do
      [ "$(host_facts "$directory")" = "$ACCOUNT_UID 700" ] ||
        fail "$P the rerun left $directory at $(host_facts "$directory")"
    done
    [ "$(system_log | grep -cxF "chown $ACCOUNT .")" -ge 4 ] || fail "$P the rerun did not give the directories to the account"
    [ "$(cat "$BASE/etc/project")" = "$PROJECT" ] || fail "$P the project file differs"
    [ "$(host_facts "$BASE/etc/project")" = "$ACCOUNT_UID 644" ] || fail "$P the project file is not 0644"
    cp "$BASE/src/stellar-agent" "$PREFIX/bin/stellar-agent"
    # A symlink in place of a named directory refuses before a root step
    # follows it.
    rmdir "$HOME_DIR/tmp"
    ln -s "$WORK" "$HOME_DIR/tmp"
    run_bootstrap "${BOOT_ARGS[@]}"
    rm "$HOME_DIR/tmp"
    mkdir -m 700 "$HOME_DIR/tmp"
    [ "$BOOT_RC" -eq 65 ] || fail "$P a symlinked tmp directory exited $BOOT_RC"
    [ "$BOOT_ERR" = "bootstrap: refused: $(cd -P "$HOME_DIR" && pwd -P)/tmp is a symlink" ] ||
      fail "$P a symlinked tmp directory printed: $BOOT_ERR"
  done
}

case_bootstrap_rerun_refuses_admin_account() {
  local platform group groups
  for platform in $PLATFORMS; do
    use "$platform"
    echo yes >"$STATE/account_exists"
    bootstrap_args
    case "$P" in
      macos) groups="admin" ;;
      linux) groups="sudo wheel adm" ;;
    esac
    for group in $groups; do
      echo "staff $group" >"$STATE/account_groups"
      : >"$STATE/system.log"
      run_bootstrap "${BOOT_ARGS[@]}"
      [ "$BOOT_RC" -eq 65 ] || fail "$P an account in $group exited $BOOT_RC"
      [ "$BOOT_ERR" = "bootstrap: refused: the existing account $ACCOUNT belongs to the admin group $group" ] ||
        fail "$P an account in $group printed: $BOOT_ERR"
      if system_log | grep -qE "^(usermod|chown|visudo) |^dscl \. -(create|delete) "; then
        fail "$P a refused rerun changed the account: $(system_log)"
      fi
    done
    reset_account
    echo yes >"$STATE/account_exists"
    echo "$WORK/elsewhere" >"$STATE/account_home"
    : >"$STATE/system.log"
    run_bootstrap "${BOOT_ARGS[@]}"
    [ "$BOOT_RC" -eq 65 ] || fail "$P an account with another home exited $BOOT_RC"
    [ "$BOOT_ERR" = "bootstrap: refused: the existing account $ACCOUNT has another home" ] ||
      fail "$P an account with another home printed: $BOOT_ERR"
    if system_log | grep -qE "^(usermod|chown|visudo) |^dscl \. -(create|delete) "; then
      fail "$P a refused rerun changed the account: $(system_log)"
    fi
    reset_account
    echo yes >"$STATE/account_exists"
  done
}

# Writes the logging stand-in of wrapper $2 into directory $1 for the
# validation scripts. It logs its arguments and the digest of a file on
# its standard input, answers the MCP stdio check, prints a keychain dump
# with one wallet item and one other item, and refuses a form with a
# caller profile. In mode b, read from the mode file, profile show refuses
# with an unreadable state, the approval forms refuse with an unreadable
# origin, the --state verb is unknown to the binary, and the keychain dump
# holds no wallet item. In mode d the dump holds no wallet item and the
# signer enrollment fails.
write_validation_wrapper() {
  {
    printf '#!/bin/bash -p\nLOG=%q\nMODE_FILE=%q\nNAME=%q\nPYTHON=%q\n' \
      "$1/../calls.log" "$1/../mode" "$2" "$PYTHON"
    cat <<'STUB'
{
  printf '%s' "$NAME"
  for word in "$@"; do
    printf '\t%s' "$word"
  done
  printf '\n'
} >>"$LOG"
MODE=$(cat "$MODE_FILE")
case "$NAME ${1-}" in
  "mcp-launch ")
    IFS= read -r line || true
    printf '{"jsonrpc":"2.0","id":1,"result":{}}\n'
    ;;
  "provision remote-key" | "provision remote-cert" | "provision policy-install" | "provision providers")
    printf 'stdin\t%s\n' "$("$PYTHON" -I -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')" >>"$LOG"
    ;;
  "cli-launch keychain-access-lists")
    printf 'keychain: "/home/login.keychain-db"\nversion: 512\nclass: "genp"\nattributes:\n'
    if [ "$MODE" != b ] && [ "$MODE" != d ]; then
      printf '    "svce"<blob>="stellar-agent-signer-mainnet"\naccess: 1 entries\n    entry 0:\n        authorizations (1): decrypt\n'
      printf 'keychain: "/home/login.keychain-db"\nversion: 512\nclass: "genp"\nattributes:\n'
    fi
    printf '    "svce"<blob>="com.example.other"\naccess: 1 entries\n    entry 0:\n        authorizations (1): any\n'
    ;;
  "cli-launch profile")
    for word in "$@"; do
      if [ "$word" = --profile ]; then
        echo "stellar-agent-wrapper: refused: the form is not one of the listed forms" >&2
        exit 64
      fi
    done
    if [ "$MODE" = b ] && [ "${2-}" = show ]; then
      echo "stellar-agent-wrapper: refused: the mainnet state is unreadable; run cli-launch profile enable-mainnet --state" >&2
      exit 65
    fi
    if [ "$MODE" = b ] && [ "${3-}" = --state ]; then
      echo "error: unexpected argument '--state' found" >&2
      exit 2
    fi
    ;;
  "provision profile")
    if [ "$MODE" = d ] && [ "${2-}" = enroll-signer ]; then
      echo "error: the keyring refused the signer item" >&2
      exit 1
    fi
    ;;
  "cli-launch approve")
    if [ "$MODE" = b ]; then
      echo "stellar-agent-wrapper: refused: the policy origin is unreadable" >&2
      exit 65
    fi
    ;;
esac
exit 0
STUB
  } >"$1/$2"
  chmod 755 "$1/$2"
}

# Expected record entries of validation script $1.
validation_entries() {
  local common="account ownership refusal-64 refusal-65 keychain-unlock keychain-lock keychain-unlock-again provisioning-order platform-read-write refusal-66 mcp-stdio cross-user-file-denial cross-user-keyring-denial approval-round-trip"
  case "$1" in
    macos) echo "$common access-lists designated-requirement signed-upgrade dialog-counts no-desktop-session" ;;
    linux) echo "$common daemon-reuse" ;;
  esac
}

# Writes the tool stubs of the validation root $1. Each logs its call. In
# mode a the keychain read attempt is refused with the platform's
# access-denial text, and the user database tools answer. Its SecurityAgent
# log holds one item-access, one password, and one other line. In
# mode b the read attempt succeeds, the log holds no item-access line, and
# dscl and getent are missing. In mode c the read attempt fails on a
# missing keychain or a D-Bus autolaunch failure and the log is empty. In
# mode d the read attempt is refused with the access-denial text and the
# log holds one password line and one redacted line. In modes e and f the
# Linux read attempt fails with an authentication error: AuthFailed in
# mode e and exhausted mechanisms in mode f. The macOS read attempt is
# refused with the access-denial text. The log of mode e holds the filter
# banner and the column header only, and the log of mode f one password
# line after them. In mode g the macOS log holds one item-access event with
# a hexadecimal thread id and one password event with a decimal one.
# Every log but the empty one of mode c starts with the filter banner and
# the column header. secret-tool always prints a stand-in secret, which
# the record must never hold.
write_validation_tools() {
  local name
  for name in codesign launchctl who; do
    printf '#!/bin/bash\nprintf "%%s\\n" "%s $*" >>%q\n' "$name" "$1/tools.log" >"$1/stubs/$name"
  done
  for name in dscl getent; do
    {
      printf '#!/bin/bash\nprintf "%%s\\n" "%s $*" >>%q\n' "$name" "$1/tools.log"
      # shellcheck disable=SC2016 # The stub body expands when the stub runs.
      printf 'if [ "$(cat %q)" = b ]; then\n  echo "%s: command not found" >&2\n  exit 127\nfi\n' "$1/mode" "$name"
    } >"$1/stubs/$name"
  done
  {
    # shellcheck disable=SC2016 # The stub body expands when the stub runs.
    printf '#!/bin/bash\nprintf "%%s\\n" "security $*" >>%q\nMODE=$(cat %q)\n' "$1/tools.log" "$1/mode"
    cat <<'STUB'
if [ "${1-}" = find-generic-password ]; then
  case "$MODE" in
    a | d | e | f)
      echo "security: SecKeychainSearchCopyNext: User interaction is not allowed." >&2
      exit 36
      ;;
    c)
      echo "security: SecKeychainSearchCopyNext: The specified keychain could not be found." >&2
      exit 50
      ;;
  esac
  printf 'keychain: "%s"\nclass: "genp"\n' "${4-}"
fi
STUB
  } >"$1/stubs/security"
  {
    # shellcheck disable=SC2016 # The stub body expands when the stub runs.
    printf '#!/bin/bash\nprintf "%%s\\n" "secret-tool $* bus=${DBUS_SESSION_BUS_ADDRESS-}" >>%q\n' "$1/tools.log"
    # shellcheck disable=SC2016 # The stub body expands when the stub runs.
    printf 'echo %q\nMODE=$(cat %q)\n' "SECRET-$MARKER" "$1/mode"
    cat <<'STUB'
case "$MODE" in
  a | d)
    echo "Could not connect: Permission denied" >&2
    exit 1
    ;;
  c)
    echo "Cannot autolaunch D-Bus without X11 \$DISPLAY" >&2
    exit 1
    ;;
  e)
    echo "Could not connect: GDBus.Error:org.freedesktop.DBus.Error.AuthFailed: Authentication failed" >&2
    exit 1
    ;;
  f)
    echo "Could not connect: Exhausted all available authentication mechanisms (tried: EXTERNAL, DBUS_COOKIE_SHA1, ANONYMOUS) (available: EXTERNAL)" >&2
    exit 1
    ;;
esac
STUB
  } >"$1/stubs/secret-tool"
  {
    printf '#!/bin/bash\nprintf "%%s\\n" "log $*" >>%q\n' "$1/tools.log"
    # shellcheck disable=SC2016 # The stub body expands when the stub runs.
    printf 'MODE=$(cat %q)\n' "$1/mode"
    cat <<'STUB'
[ "$MODE" != c ] || exit 0
echo 'Filtering the log data using "process == "SecurityAgent""'
echo 'Timestamp               Ty Process[PID:TID]'
[ "$MODE" != e ] || exit 0
case "$MODE" in
  a) echo '2026-01-01 10:00:01.000 Df SecurityAgent[90:91] stellar-agent wants to use your confidential information stored in "stellar-agent-signer-mainnet" in your keychain.' ;;
  g) echo '2026-01-01 10:00:01.000 Df SecurityAgent[90:9a] stellar-agent wants to use your confidential information stored in "stellar-agent-signer-mainnet" in your keychain.' ;;
esac
echo '2026-01-01 10:00:02.000 Df SecurityAgent[90:91] stellar-agent wants to use the "login" keychain.'
case "$MODE" in
  d) echo '2026-01-01 10:00:03.000 Df SecurityAgent[90:91] <private>' ;;
  a | b) echo '2026-01-01 10:00:03.000 Df SecurityAgent[90:91] session started' ;;
esac
STUB
  } >"$1/stubs/log"
  chmod 755 "$1/stubs"/*
}

# Runs validation script $1 of root $2 in mode $3 into the record
# directory record-$3. Sets RC.
run_validation() {
  local script=$1 root=$2 mode=$3
  printf '%s\n' "$mode" >"$root/mode"
  : >"$root/calls.log"
  : >"$root/sudo.log"
  : >"$root/tools.log"
  rm -f "$root/tty"
  mkfifo "$root/tty"
  exec 8<>"$root/tty"
  printf 'probe-approval\n\n\n\n' >&8
  RC=0
  PATH="$root/stubs:$PATH" bash "$script" --record "$root/record-$mode" --rpc-url https://rpc.example \
    --providers "$root/providers.toml" --policy "$root/policy.toml" --cert "$root/cert.pem" \
    --key "$root/key.pem" --bind 127.0.0.1:8443 --rp-id wallet.example \
    </dev/null >"$root/out-$mode" 2>"$root/err-$mode" 8>&- || RC=$?
  exec 8>&-
}

# Prints the status line that follows command line $2 in record entry $1.
status_after() {
  awk -v command="command: $2" '
    $0 == command { found = 1; next }
    found && /^status: / { print; exit }
  ' "$1"
}

# Prints the record file of entry $2 in record directory $1.
entry_file() {
  printf '%s/%s\n' "$1" "$(names_in "$1" | grep -E "^[0-9]+-$2\.txt$")"
}

# Prepares validation root $2 for platform $1: the wrapper, tool, and sudo
# stubs, and the input files. Its copy of the validation script has the
# fixed paths pointing into the root. Sets VALIDATION_SCRIPT.
prepare_validation() {
  local platform=$1 root=$2 name script
  mkdir -p "$root/prefix/bin" "$root/home" "$root/stubs"
  for name in mcp-launch cli-launch provision; do
    write_validation_wrapper "$root/prefix" "$name"
  done
  {
    printf '#!/bin/bash -p\nLOG=%q\nACCOUNT=%q\n' "$root/sudo.log" "$ACCOUNT"
    cat <<'STUB'
printf '%s\n' "$*" >>"$LOG"
if [ "${1-}" != -n ] || [ "${2-}" != -u ] || [ "${3-}" != "$ACCOUNT" ]; then
  echo "sudo stub: not a wrapper call" >&2
  exit 1
fi
shift 3
exec "$@"
STUB
  } >"$root/stubs/sudo"
  write_validation_tools "$root"
  script="$root/validate-$platform.sh"
  cp "$DEPLOY/validate-$platform.sh" "$script"
  replace_line "$script" "ACCOUNT=stellar-agent" "ACCOUNT='$ACCOUNT'"
  replace_line "$script" "PREFIX=/usr/local/libexec/stellar-agent" "PREFIX='$root/prefix'"
  case "$platform" in
    macos) replace_line "$script" "HOME_DIR=/Users/stellar-agent" "HOME_DIR='$root/home'" ;;
    linux) replace_line "$script" "HOME_DIR=/var/lib/stellar-agent" "HOME_DIR='$root/home'" ;;
  esac
  replace_line "$script" "PROJECT_FILE=/usr/local/etc/stellar-agent/project" "PROJECT_FILE='$root/project'"
  replace_line "$script" "SUDOERS_FILE=/etc/sudoers.d/stellar-agent" "SUDOERS_FILE='$root/sudoers'"
  replace_line "$script" "SUDO=/usr/bin/sudo" "SUDO='$root/stubs/sudo'"
  if [ "$platform" = macos ]; then
    replace_line "$script" "SECURITY=/usr/bin/security" "SECURITY='$root/stubs/security'"
  fi
  replace_line "$script" "TTY_PATH=/dev/tty" "TTY_PATH='$root/tty'"
  replace_line "$script" "SETTLE_SECONDS=3" "SETTLE_SECONDS=1"
  replace_line "$script" "RESPONSE_SECONDS=5" "RESPONSE_SECONDS=1"
  printf '%s' "$KEY_PEM" | sed "s/MIIEtest/$MARKER/" >"$root/key.pem"
  printf '%s' "$CERT_PEM" >"$root/cert.pem"
  printf '%s' "$POLICY_TEXT" >"$root/policy.toml"
  printf '%s' "$FRAGMENT" >"$root/providers.toml"
  VALIDATION_SCRIPT=$script
}

case_validation_scripts_record_every_item() {
  local platform script root entries name sudo_line record file presence_line
  for platform in $PLATFORMS; do
    root="$WORK/validate-$platform"
    prepare_validation "$platform" "$root"
    script=$VALIDATION_SCRIPT
    presence_line="$root/stubs/sudo -n -u $ACCOUNT $root/prefix/cli-launch keychain-access-lists"

    run_validation "$script" "$root" a
    record="$root/record-a"
    [ "$RC" -eq 0 ] || fail "validate-$platform.sh exited $RC: $(cat "$root/err-a")"
    entries=$(names_in "$record" | sed -E 's/^[0-9]+-//; s/\.txt$//' | tr '\n' ' ')
    [ "$entries" = "$(validation_entries "$platform") " ] || fail "validate-$platform.sh entries: $entries"
    for name in $(names_in "$record"); do
      grep -q '^status: ' "$record/$name" || fail "validate-$platform.sh $name records no status"
    done
    grep -qx 'status: refused' "$(entry_file "$record" refusal-64)" ||
      fail "validate-$platform.sh records no refusal for the caller profile"
    grep -qx 'status: ok (the first standard output line is a JSON-RPC message)' "$(entry_file "$record" mcp-stdio)" ||
      fail "validate-$platform.sh records no MCP stdio response"
    while IFS= read -r sudo_line; do
      case "$sudo_line" in
        "-n -u $ACCOUNT $root/prefix/mcp-launch" | "-n -u $ACCOUNT $root/prefix/cli-launch "* | \
          "-n -u $ACCOUNT $root/prefix/provision "*) ;;
        *) fail "validate-$platform.sh called sudo outside the wrappers: $sudo_line" ;;
      esac
    done <"$root/sudo.log"
    grep -qxF "cli-launch${TAB}approve${TAB}--id${TAB}probe-approval${TAB}--open-by-operator" "$root/calls.log" ||
      fail "validate-$platform.sh did not run the guided approval"
    grep -qxF "stdin${TAB}$(file_sha "$root/key.pem")" "$root/calls.log" ||
      fail "validate-$platform.sh did not hand the key file to the wrapper on standard input"
    # The keyring read attempt of the operator account is refused with the
    # access-denial text for a signer item that exists, which is a denial.
    file=$(entry_file "$record" cross-user-keyring-denial)
    if [ "$platform" = macos ]; then
      [ "$(status_after "$file" "$presence_line")" = "status: ok (the dump holds the stellar-agent-signer-mainnet item)" ] ||
        fail "macos records no signer item before the keychain read: $(cat "$file")"
      [ "$(status_after "$file" "$root/stubs/security find-generic-password -s stellar-agent-signer-mainnet $root/home/Library/Keychains/login.keychain-db")" = "status: denied" ] ||
        fail "macos records no denied keychain read: $(cat "$file")"
      grep -qx 'exit: 36' "$file" || fail "macos records no exit code of the keychain read"
      grep -qF 'User interaction is not allowed.' "$file" || fail "macos records no error of the keychain read"
    else
      grep -qx 'signer item: present (provision profile enroll-signer exited 0 in this run)' "$file" ||
        fail "linux records no signer item before the keyring read: $(cat "$file")"
      [ "$(status_after "$file" "env DBUS_SESSION_BUS_ADDRESS=unix:path=$root/home/run/bus secret-tool lookup service stellar-agent-signer-mainnet")" = "status: denied" ] ||
        fail "linux records no denied keyring read: $(cat "$file")"
      grep -qx 'exit: 1' "$file" || fail "linux records no exit code of the keyring read"
      grep -qF 'Could not connect: Permission denied' "$file" || fail "linux records no error of the keyring read"
      grep -qxF "secret-tool lookup service stellar-agent-signer-mainnet bus=unix:path=$root/home/run/bus" "$root/tools.log" ||
        fail "linux did not ask the wallet account's session bus"
    fi
    if [ "$platform" = macos ]; then
      # The access lists keep the wallet's item only, read without -d, -g, or -w.
      file=$(entry_file "$record" access-lists)
      grep -qx 'status: ok (1 wallet items)' "$file" || fail "macos access lists: $(cat "$file")"
      grep -qF '"svce"<blob>="stellar-agent-signer-mainnet"' "$file" || fail "macos access lists miss the wallet item"
      grep -qF 'authorizations (1): decrypt' "$file" || fail "macos access lists miss the wallet item's access list"
      if grep -qF 'com.example.other' "$file"; then
        fail "macos access lists record another item"
      fi
      grep -qxF "cli-launch${TAB}keychain-access-lists" "$root/calls.log" ||
        fail "macos did not read the access lists through the wrapper"
      if grep -E '^security ' "$root/tools.log" | grep -qE ' -(d|g|w)( |$)'; then
        fail "macos called security with -d, -g, or -w: $(cat "$root/tools.log")"
      fi
      # The dialog counts tell the item-access prompt from the others.
      file=$(entry_file "$record" dialog-counts)
      grep -qx 'item-access prompts: 1' "$file" || fail "macos dialog counts: $(cat "$file")"
      grep -qx 'password prompts: 1' "$file" || fail "macos password prompts: $(cat "$file")"
      grep -qx 'other SecurityAgent lines: 1' "$file" || fail "macos other lines: $(cat "$file")"
      grep -qx 'status: failed (item-access prompts appeared)' "$file" ||
        fail "macos dialog counts with an item-access prompt: $(cat "$file")"
      grep -E '^log show --style compact --start ' "$root/tools.log" | grep -qF ' --end ' ||
        fail "macos read the log without a bounded window: $(cat "$root/tools.log")"
    fi

    run_validation "$script" "$root" b
    record="$root/record-b"
    [ "$RC" -eq 0 ] || fail "validate-$platform.sh in mode b exited $RC: $(cat "$root/err-b")"
    # An unreadable state or policy origin is a refusal, and only a missing
    # command or an unknown verb is not available.
    file=$(entry_file "$record" refusal-65)
    [ "$(status_after "$file" "wallet cli-launch profile show")" = "status: refused" ] ||
      fail "validate-$platform.sh records an unreadable state as: $(cat "$file")"
    grep -qF 'the mainnet state is unreadable' "$file" || fail "validate-$platform.sh drops the refusal text"
    file=$(entry_file "$record" approval-round-trip)
    [ "$(grep -cx 'status: refused' "$file")" -eq 2 ] ||
      fail "validate-$platform.sh records an unreadable origin as: $(cat "$file")"
    grep -qF 'the policy origin is unreadable' "$file" || fail "validate-$platform.sh drops the origin refusal text"
    file=$(entry_file "$record" provisioning-order)
    [ "$(status_after "$file" "wallet cli-launch profile enable-mainnet --state")" = "status: not available" ] ||
      fail "validate-$platform.sh records an unknown option as: $(cat "$file")"
    if grep -qx 'status: not available' "$(entry_file "$record" refusal-65)"; then
      fail "validate-$platform.sh records a refusal as not available"
    fi
    file=$(entry_file "$record" account)
    case "$platform" in
      macos) name="dscl . -read /Users/$ACCOUNT UserShell NFSHomeDirectory IsHidden" ;;
      linux) name="getent passwd $ACCOUNT" ;;
    esac
    [ "$(status_after "$file" "$name")" = "status: not available" ] ||
      fail "validate-$platform.sh records a missing command as: $(cat "$file")"
    file=$(entry_file "$record" cross-user-keyring-denial)
    grep -qx 'status: failed (the read succeeded)' "$file" ||
      fail "validate-$platform.sh records a successful keyring read as: $(cat "$file")"
    if [ "$platform" = macos ]; then
      grep -qx 'status: failed (the dump holds no wallet item)' "$(entry_file "$record" access-lists)" ||
        fail "macos access lists without a wallet item: $(cat "$(entry_file "$record" access-lists)")"
      file=$(entry_file "$record" dialog-counts)
      grep -qx 'item-access prompts: 0' "$file" || fail "macos dialog counts in mode b: $(cat "$file")"
      grep -qx 'readable SecurityAgent lines: 2' "$file" || fail "macos readable lines in mode b: $(cat "$file")"
      grep -qx 'status: ok (no item-access prompt)' "$file" ||
        fail "macos dialog counts without an item-access prompt: $(cat "$file")"
    fi
    if grep -rqF -- "$MARKER" "$root/record-a" "$root/record-b" "$root/out-a" "$root/out-b" "$root/err-a" \
      "$root/err-b" "$root/calls.log" "$root/sudo.log" "$root/tools.log"; then
      fail "validate-$platform.sh recorded the key material or the keyring secret"
    fi
    rm -f "$root/key.pem"
  done
}

# A failed read attempt is a denial only with the platform's access-denial
# text for a signer item that exists. The dialog counts are ok only on
# readable SecurityAgent event records. Each of these records
# inconclusive: a missing keychain, a D-Bus autolaunch or authentication
# error, an absent signer item, an empty or banner-only log, and a
# redacted record.
case_validation_read_needs_denial_evidence() {
  local platform script root record file read_line presence_line
  for platform in $PLATFORMS; do
    root="$WORK/evidence-$platform"
    prepare_validation "$platform" "$root"
    script=$VALIDATION_SCRIPT
    presence_line="$root/stubs/sudo -n -u $ACCOUNT $root/prefix/cli-launch keychain-access-lists"
    case "$platform" in
      macos) read_line="$root/stubs/security find-generic-password -s stellar-agent-signer-mainnet $root/home/Library/Keychains/login.keychain-db" ;;
      linux) read_line="env DBUS_SESSION_BUS_ADDRESS=unix:path=$root/home/run/bus secret-tool lookup service stellar-agent-signer-mainnet" ;;
    esac

    run_validation "$script" "$root" c
    record="$root/record-c"
    [ "$RC" -eq 0 ] || fail "validate-$platform.sh in mode c exited $RC: $(cat "$root/err-c")"
    file=$(entry_file "$record" cross-user-keyring-denial)
    [ "$(status_after "$file" "$read_line")" = "status: inconclusive (no access-denial text in standard error)" ] ||
      fail "validate-$platform.sh records a read without denial text as: $(cat "$file")"
    if grep -qx 'status: denied' "$file"; then
      fail "validate-$platform.sh records a read without denial text as denied"
    fi
    if [ "$platform" = macos ]; then
      grep -qx 'exit: 50' "$file" || fail "macos records no exit code of the missing keychain"
      grep -qF 'The specified keychain could not be found.' "$file" || fail "macos drops the missing keychain text"
      file=$(entry_file "$record" dialog-counts)
      grep -qx 'output lines: 0' "$file" || fail "macos empty log line count: $(cat "$file")"
      grep -qx 'readable SecurityAgent lines: 0' "$file" || fail "macos empty log readable lines: $(cat "$file")"
      grep -qx 'status: inconclusive (no dialog lines observed)' "$file" ||
        fail "macos records an empty log as: $(cat "$file")"
      grep -qE "^command: log show --style compact --start '.*' --end '.*' --predicate 'process == \"SecurityAgent\"'$" "$file" ||
        fail "macos records no log query for an empty log: $(cat "$file")"
    else
      grep -qx 'exit: 1' "$file" || fail "linux records no exit code of the autolaunch failure"
      grep -qF 'Cannot autolaunch D-Bus without X11' "$file" || fail "linux drops the autolaunch text"
    fi

    run_validation "$script" "$root" d
    record="$root/record-d"
    [ "$RC" -eq 0 ] || fail "validate-$platform.sh in mode d exited $RC: $(cat "$root/err-d")"
    file=$(entry_file "$record" cross-user-keyring-denial)
    [ "$(status_after "$file" "$read_line")" = "status: inconclusive (the signer item is not shown present)" ] ||
      fail "validate-$platform.sh records a refused read of an absent item as: $(cat "$file")"
    if [ "$platform" = macos ]; then
      [ "$(status_after "$file" "$presence_line")" = "status: failed (the dump holds no stellar-agent-signer-mainnet item)" ] ||
        fail "macos records an absent signer item as: $(cat "$file")"
      grep -qF 'User interaction is not allowed.' "$file" || fail "macos drops the refusal text"
      file=$(entry_file "$record" dialog-counts)
      grep -qx 'redacted SecurityAgent lines: 1' "$file" || fail "macos redacted lines: $(cat "$file")"
      grep -qx 'item-access prompts: 0' "$file" || fail "macos item prompts in a redacted log: $(cat "$file")"
      grep -qx 'status: inconclusive (redacted dialog lines observed)' "$file" ||
        fail "macos records a redacted log as: $(cat "$file")"
    else
      grep -qx 'signer item: not shown present (provision profile enroll-signer exited 1 in this run)' "$file" ||
        fail "linux records a failed enrollment as: $(cat "$file")"
      grep -qF 'Could not connect: Permission denied' "$file" || fail "linux drops the refusal text"
    fi

    run_validation "$script" "$root" e
    record="$root/record-e"
    [ "$RC" -eq 0 ] || fail "validate-$platform.sh in mode e exited $RC: $(cat "$root/err-e")"
    if [ "$platform" = macos ]; then
      file=$(entry_file "$record" dialog-counts)
      grep -qx 'output lines: 2' "$file" || fail "macos banner-only log line count: $(cat "$file")"
      grep -qx 'readable SecurityAgent lines: 0' "$file" || fail "macos counts the banner as a record: $(cat "$file")"
      grep -qx 'status: inconclusive (no dialog lines observed)' "$file" ||
        fail "macos records a banner-only log as: $(cat "$file")"
    else
      file=$(entry_file "$record" cross-user-keyring-denial)
      grep -qx 'signer item: present (provision profile enroll-signer exited 0 in this run)' "$file" ||
        fail "linux records no signer item before the AuthFailed read: $(cat "$file")"
      [ "$(status_after "$file" "$read_line")" = "status: inconclusive (authentication error without an access denial)" ] ||
        fail "linux records an AuthFailed read as: $(cat "$file")"
      grep -qF 'org.freedesktop.DBus.Error.AuthFailed' "$file" || fail "linux drops the AuthFailed text"
    fi

    run_validation "$script" "$root" f
    record="$root/record-f"
    [ "$RC" -eq 0 ] || fail "validate-$platform.sh in mode f exited $RC: $(cat "$root/err-f")"
    if [ "$platform" = macos ]; then
      file=$(entry_file "$record" dialog-counts)
      grep -qx 'readable SecurityAgent lines: 1' "$file" || fail "macos records beside the banner: $(cat "$file")"
      grep -qx 'password prompts: 1' "$file" || fail "macos password prompt beside the banner: $(cat "$file")"
      grep -qx 'other SecurityAgent lines: 0' "$file" || fail "macos counts the banner as another line: $(cat "$file")"
      grep -qx 'status: ok (no item-access prompt)' "$file" ||
        fail "macos records one password event beside the banner as: $(cat "$file")"

      # A hexadecimal thread id is part of an event record.
      run_validation "$script" "$root" g
      record="$root/record-g"
      [ "$RC" -eq 0 ] || fail "validate-macos.sh in mode g exited $RC: $(cat "$root/err-g")"
      file=$(entry_file "$record" dialog-counts)
      grep -qx 'readable SecurityAgent lines: 2' "$file" || fail "macos drops a hexadecimal thread id: $(cat "$file")"
      grep -qx 'password prompts: 1' "$file" || fail "macos password prompt in mode g: $(cat "$file")"
      grep -qx 'item-access prompts: 1' "$file" || fail "macos item-access prompt in mode g: $(cat "$file")"
      grep -qx 'status: failed (item-access prompts appeared)' "$file" ||
        fail "macos records an item-access event with a hexadecimal thread id as: $(cat "$file")"
      if grep -rqF -- "$MARKER" "$record" "$root/out-g" "$root/err-g"; then
        fail "validate-macos.sh recorded the key material or the keyring secret in mode g"
      fi
    else
      file=$(entry_file "$record" cross-user-keyring-denial)
      [ "$(status_after "$file" "$read_line")" = "status: inconclusive (authentication error without an access denial)" ] ||
        fail "linux records an exhausted authentication as: $(cat "$file")"
      grep -qF 'Exhausted all available authentication mechanisms' "$file" ||
        fail "linux drops the exhausted authentication text"
    fi
    if grep -rqF -- "$MARKER" "$root/record-c" "$root/record-d" "$root/record-e" "$root/record-f" "$root/out-c" \
      "$root/out-d" "$root/out-e" "$root/out-f" "$root/err-c" "$root/err-d" "$root/err-e" "$root/err-f" \
      "$root/calls.log" "$root/sudo.log" "$root/tools.log"; then
      fail "validate-$platform.sh recorded the key material or the keyring secret"
    fi
    rm -f "$root/key.pem"
  done
}

CASES="wrapper_refuses_unlisted_verb
wrapper_refuses_foreign_home_owner
wrapper_eligibility_follows_nonce
predicate_exempt_forms_run_with_unreadable_nonce
unreadable_nonce_refuses_every_other_form
wrapper_environment
secret_appears_in_no_argv_env_dump_log_or_file
keychain_unlock_password_reaches_only_stdin
keychain_access_lists_form
serve_refuses_running_mcp
signed_origin_classification
signed_origin_operator_open_refused_at_launch
approve_id_local_only_bare_refused
approve_id_signed_origin_form
policy_install_stdin
remote_pem_writes_land_0600
stdin_destinations_refuse_directories
rename_refuses_a_directory_after_the_check
providers_fragment_accepted
providers_fragment_refused
providers_force_replaces_credential
provider_credential_form
remote_config_fragment_is_exact
refusal_lines_echo_no_caller_token
native_diagnostics_stay_behind_refusals
wrappers_write_no_stdout
wrappers_handle_the_space_in_the_macos_data_root
wrappers_share_identical_checks
bootstrap_refuses_without_root
bootstrap_renders_exact_sudoers
bootstrap_refuses_test_helpers_binary
bootstrap_refuses_directory_destinations
bootstrap_takes_no_secret
bootstrap_rerun_converges
bootstrap_rerun_refuses_admin_account
validation_scripts_record_every_item
validation_read_needs_denial_evidence"

main() {
  local selected=$CASES name passed=0 total=0 failures="" rc platform
  if [ "$#" -gt 0 ]; then
    if [ "$#" -ne 2 ] || [ "$1" != --case ]; then
      echo "usage: test-deploy.sh [--case <name>]" >&2
      exit 2
    fi
    case " $(printf '%s' "$CASES" | tr '\n' ' ') " in
      *" $2 "*) selected=$2 ;;
      *)
        echo "usage: test-deploy.sh [--case <name>]" >&2
        exit 2
        ;;
    esac
  fi
  write_native_body
  write_tty_fixture
  for platform in $PLATFORMS; do
    install_platform "$platform"
  done
  mkdir -p "$WORK/logs"
  for name in $selected; do
    total=$((total + 1))
    set +e
    (
      set -e
      "case_$name"
    ) >"$WORK/logs/$name.log" 2>&1
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
      passed=$((passed + 1))
    else
      failures="$failures $name"
    fi
  done
  for name in $failures; do
    echo "FAILED $name"
    sed 's/^/  /' "$WORK/logs/$name.log"
  done
  echo "deploy test: $passed of $total passed"
  if [ -n "$failures" ]; then
    exit 1
  fi
}

main "$@"
