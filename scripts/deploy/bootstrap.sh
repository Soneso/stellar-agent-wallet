#!/bin/bash
# Sets up the dedicated wallet account and its sudo wrappers on this host.
#
# Usage: bootstrap.sh --operator <account> --project <name> --cli <path> [--mcp <path>]
#
#   --operator <account>  the existing account that may run the wrappers
#   --project <name>      the project name the wallet processes run under
#   --cli <path>          the stellar-agent release executable to install
#                         under both names, stellar-agent and stellar-agent-mcp
#   --mcp <path>          optional: the release archive's stellar-agent-mcp
#                         file, which must pass the same checks and hold the
#                         bytes of --cli; it is compared and never installed
#
# Runs as root, once per host and again for an upgrade. It takes no secret
# and executes no binary. Each step runs as root for a reason:
#
#   R1  creates the non-admin account without a password argument, because
#       only root writes the user database;
#   R2  sets a non-login shell, disables password login, and on macOS hides
#       the account, in the same database;
#   R3  creates the home, <home>/run, <home>/tmp, the data root, and its
#       parents, each account-owned with mode 0700, because handing a
#       directory in a root-owned parent to another account needs root;
#   R4  installs the wrappers and the executable under both names
#       root-owned with mode 0755 under the prefix, so the wallet cannot
#       write its own executables;
#   R5  writes the root-owned project file;
#   R6  renders the sudoers file, checks it with visudo, and installs it
#       root-owned with mode 0440.
#
# One run at a time holds the bootstrap lock beside the prefix; a second run
# refuses while it is held. After the install, the two installed names must
# hold equal bytes, or the run refuses and names both paths. A run that ends
# between the two renames leaves a pair the next validation records as
# failed; a rerun with the same --cli source installs both names again.
#
# A rerun converges (R7). It verifies that the existing account is a
# non-admin account with the fixed home, then applies R2 to R6 again. R3
# creates only missing directories and resets the owner and mode of the
# directories it names. Nothing below the data root is read, written, moved,
# or changed in mode. Bootstrap writes no profile, key, policy, or audit log;
# every later step runs as the operator through the wrappers.
#
# The wrapper and sudoers sources beside this script are templates. The
# installed files are self-contained: they source nothing and carry the
# fixed paths and values below.
#
# Exit codes: 0 when the host is set up, 64 for a usage error, and 65 when a
# check refuses.
set -euo pipefail
umask 022
shopt -u patsub_replacement 2>/dev/null || true

# Fixed values.
ACCOUNT=stellar-agent
PROFILE=mainnet
PREFIX=/usr/local/libexec/stellar-agent
PROJECT_FILE=/usr/local/etc/stellar-agent/project
SUDOERS_FILE=/etc/sudoers.d/stellar-agent
MACOS_HOME=/Users/stellar-agent
LINUX_HOME=/var/lib/stellar-agent
WRAPPER_PATH=/usr/bin:/bin
TTY_PATH=/dev/tty
SECURITY_TOOL=/usr/bin/security
DBUS_DAEMON_TOOL=/usr/bin/dbus-daemon
GNOME_KEYRING_DAEMON_TOOL=/usr/bin/gnome-keyring-daemon
ENV_TOOL=/usr/bin/env
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
HOST_SYSTEM=$(uname -s)

SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
MARKER_ON=STELLAR_AGENT_BUILD_MAINNET_WRITE=on
MARKER_OFF=STELLAR_AGENT_BUILD_MAINNET_WRITE=off
STAGED_FILES=()

cleanup() {
  local file
  for file in ${STAGED_FILES[@]+"${STAGED_FILES[@]}"}; do
    rm -f -- "$file"
  done
}
trap cleanup EXIT

say() {
  printf 'bootstrap: %s\n' "$1"
}

refuse() {
  printf 'bootstrap: refused: %s\n' "$2" >&2
  exit "$1"
}

usage() {
  echo "usage: bootstrap.sh --operator <account> --project <name> --cli <path> [--mcp <path>]" >&2
  exit 64
}

# Succeeds when $1 is a project name: one or more characters without
# whitespace, quotes, or control characters.
valid_project() {
  local pattern='^[^[:space:][:cntrl:]"'"'"']+$'
  [[ "$1" =~ $pattern ]]
}

# Prints $1 with every extended regular expression metacharacter escaped.
regex_escape() {
  local text=$1 escaped="" char
  while [ -n "$text" ]; do
    char=${text:0:1}
    text=${text:1}
    case "$char" in
      . | '[' | ']' | \\ | '*' | '^' | '$' | '(' | ')' | + | '?' | '{' | '}' | '|')
        escaped="$escaped\\$char"
        ;;
      *) escaped="$escaped$char" ;;
    esac
  done
  printf '%s' "$escaped"
}

# Refuses a rendered value that cannot sit inside a single-quoted shell
# word on one line.
require_plain_value() {
  case "$1" in
    *"'"* | *$'\n'*) refuse 65 "a fixed value holds a quote or a line break" ;;
  esac
}

# Renders template $1 into file $2, replacing each placeholder with its
# fixed value, and refuses when a placeholder remains.
render() {
  local line
  : >"$2"
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line//@PLATFORM@/$PLATFORM}
    line=${line//@ACCOUNT@/$ACCOUNT}
    line=${line//@OPERATOR@/$OPERATOR}
    line=${line//@HOME@/$HOME_DIR}
    line=${line//@DATA_ROOT@/$DATA_ROOT}
    line=${line//@PROFILE@/$PROFILE}
    line=${line//@PREFIX_RE@/$PREFIX_RE}
    line=${line//@PREFIX@/$PREFIX}
    line=${line//@PROJECT_FILE@/$PROJECT_FILE}
    line=${line//@PATH@/$WRAPPER_PATH}
    line=${line//@TTY@/$TTY_PATH}
    line=${line//@SECURITY@/$SECURITY_TOOL}
    line=${line//@DBUS_DAEMON@/$DBUS_DAEMON_TOOL}
    line=${line//@GNOME_KEYRING_DAEMON@/$GNOME_KEYRING_DAEMON_TOOL}
    line=${line//@ENV@/$ENV_TOOL}
    printf '%s\n' "$line" >>"$2"
  done <"$1"
  if grep -qE '@[A-Z_]+@' "$2"; then
    refuse 65 "a placeholder of $(basename "$1") has no value"
  fi
}

# Refuses a binary without the mainnet-write on marker, with the off
# marker, or with a test override literal, so production excludes the test
# helpers. The checks read the file and never execute it.
check_binary() {
  local literal
  if ! LC_ALL=C grep -aFq "$MARKER_ON" "$1"; then
    refuse 65 "$2 lacks the $MARKER_ON marker"
  fi
  if LC_ALL=C grep -aFq "$MARKER_OFF" "$1"; then
    refuse 65 "$2 carries the $MARKER_OFF marker"
  fi
  for literal in STELLAR_AGENT_HOME STELLAR_AGENT_TEST_; do
    if LC_ALL=C grep -aFq "$literal" "$1"; then
      refuse 65 "$2 embeds the test override literal $literal"
    fi
  done
}

# Creates a staged file in directory $1 and sets STAGED to its path. The
# name starts with a dot, which sudo skips in its include directory.
stage_in() {
  STAGED=$(mktemp "$1/.stellar-agent.XXXXXX")
  STAGED_FILES+=("$STAGED")
}

# Makes staged file $1 root-owned with mode $2 and renames it to $3. A
# destination that is a directory, or a symlink to one, refuses before the
# rename. The rename is a plain rename(2) through perl, which replaces a
# symlink itself and never descends into a directory. A directory that
# appears after the check fails the rename, and the exit trap removes the
# staged file.
install_staged() {
  if [ -d "$3" ]; then
    refuse 65 "$3 is a directory"
  fi
  chown 0:0 "$1"
  chmod "$2" "$1"
  if ! perl -e 'rename($ARGV[0], $ARGV[1]) or exit 1' "$1" "$3" 2>/dev/null; then
    refuse 65 "$3 was not replaced, and the installed file is unchanged"
  fi
}

# Takes the bootstrap lock for the rest of the run: an flock on the
# root-owned file .stellar-agent-bootstrap.lock beside the prefix, held
# through descriptor 9 of this shell until it exits. The file stays readable
# for mcp-launch, which holds a shared lock on it while it compares the two
# installed names. The wait for the lock lasts up to five seconds. A second
# run then refuses while the first holds it, so two runs never interleave
# their installs. A lock call that fails for another reason, such as a file
# system without locking, refuses with that reason.
take_lock() {
  local directory reason rc=0
  directory=$(dirname "$PREFIX")
  LOCK_FILE="$directory/.stellar-agent-bootstrap.lock"
  mkdir -p -- "$directory"
  if [ -L "$LOCK_FILE" ]; then
    refuse 65 "$LOCK_FILE is a symlink"
  fi
  exec 9>>"$LOCK_FILE"
  reason=$(perl -e 'use Fcntl qw(:flock); open(my $lock, ">&=", 9) or do { print "$!"; exit 2 };
    for (1 .. 50) { exit 0 if flock($lock, LOCK_EX | LOCK_NB);
      do { print "$!"; exit 2 } unless $!{EWOULDBLOCK}; select(undef, undef, undef, 0.1) } exit 1') || rc=$?
  case "$rc" in
    0) ;;
    1) refuse 65 "another bootstrap run holds $LOCK_FILE; run bootstrap again after it ends" ;;
    *) refuse 65 "the bootstrap lock $LOCK_FILE could not be taken: ${reason:-perl exited $rc}" ;;
  esac
}

# Prints the home directory the user database records for the account.
account_home() {
  local record
  case "$PLATFORM" in
    macos)
      record=$(dscl . -read "/Users/$ACCOUNT" NFSHomeDirectory) || return 1
      record=${record#NFSHomeDirectory:}
      record=${record#"${record%%[![:space:]]*}"}
      printf '%s\n' "$record"
      ;;
    linux)
      record=$(getent passwd "$ACCOUNT") || return 1
      printf '%s\n' "$record" | cut -d: -f6
      ;;
  esac
}

# R7: refuses an existing account with another home, with UID 0, or in an
# admin group.
verify_account() {
  local home group
  home=$(account_home) || refuse 65 "the user database has no home for $ACCOUNT"
  if [ "$home" != "$HOME_DIR" ]; then
    refuse 65 "the existing account $ACCOUNT has another home"
  fi
  if [ "$(id -u "$ACCOUNT")" = 0 ]; then
    refuse 65 "the existing account $ACCOUNT has UID 0"
  fi
  for group in $(id -Gn "$ACCOUNT"); do
    case " $ADMIN_GROUPS " in
      *" $group "*) refuse 65 "the existing account $ACCOUNT belongs to the admin group $group" ;;
    esac
  done
}

# R1: creates the account with no password argument.
create_account() {
  say "R1 creates the account $ACCOUNT"
  case "$PLATFORM" in
    macos)
      sysadminctl -addUser "$ACCOUNT" -fullName "Stellar agent wallet" -home "$HOME_DIR" -shell /usr/bin/false
      ;;
    linux)
      useradd --system --user-group --home-dir "$HOME_DIR" --no-create-home --shell /usr/sbin/nologin "$ACCOUNT"
      ;;
  esac
  if ! id -u "$ACCOUNT" >/dev/null 2>&1; then
    refuse 65 "the account $ACCOUNT was not created"
  fi
}

# R2: non-login shell, no password login, and on macOS a hidden account.
restrict_account() {
  say "R2 disables login for $ACCOUNT"
  case "$PLATFORM" in
    macos)
      dscl . -create "/Users/$ACCOUNT" UserShell /usr/bin/false
      dscl . -create "/Users/$ACCOUNT" Passwd '*'
      if dscl . -read "/Users/$ACCOUNT" AuthenticationAuthority >/dev/null 2>&1; then
        dscl . -delete "/Users/$ACCOUNT" AuthenticationAuthority
      fi
      dscl . -create "/Users/$ACCOUNT" IsHidden 1
      ;;
    linux)
      usermod --shell /usr/sbin/nologin "$ACCOUNT"
      usermod --lock "$ACCOUNT"
      ;;
  esac
}

# Enters directory $1 of the current directory, creating it when missing,
# and gives it to the account with mode 0700. The change goes through ".",
# after a check that the entered directory is the named one, so a symlink
# the account swaps in cannot redirect a root operation.
enter_private_dir() {
  local expected
  if [ -L "$1" ]; then
    refuse 65 "$(pwd -P)/$1 is a symlink"
  fi
  if [ ! -d "$1" ]; then
    mkdir -m 700 -- "$1"
  fi
  expected="$(pwd -P)/$1"
  cd -P -- "$1"
  if [ "$(pwd -P)" != "$expected" ]; then
    refuse 65 "$expected changed during the bootstrap"
  fi
  chown "$ACCOUNT" .
  chmod 700 .
}

# R3: the home, its run and tmp directories, and the data root with its
# parents. Directories below the data root stay as they are.
create_directories() {
  local component
  say "R3 sets up the home and data root of $ACCOUNT"
  (
    cd -P -- "$(dirname "$HOME_DIR")"
    enter_private_dir "$(basename "$HOME_DIR")"
    (enter_private_dir run)
    (enter_private_dir tmp)
    IFS=/
    for component in $DATA_RELATIVE; do
      enter_private_dir "$component"
    done
  )
}

# R4: the executable under both names and the rendered wrappers, root-owned
# with mode 0755. The --cli source is staged and checked once; the second
# staged file is a copy of that staged file, compared with it before either
# name is installed.
install_executables() {
  local directory wrapper canonical
  say "R4 installs the wrappers and binaries under $PREFIX"
  for directory in "$PREFIX" "$PREFIX/bin"; do
    if [ -L "$directory" ]; then
      refuse 65 "$directory is a symlink"
    fi
    mkdir -p -- "$directory"
    chown 0:0 "$directory"
    chmod 755 "$directory"
  done
  stage_in "$PREFIX/bin"
  cp -- "$CLI_SOURCE" "$STAGED"
  check_binary "$STAGED" "the --cli binary"
  canonical=$STAGED
  stage_in "$PREFIX/bin"
  cp -- "$canonical" "$STAGED"
  if ! cmp -s -- "$canonical" "$STAGED"; then
    refuse 65 "the staged copies of the --cli binary differ"
  fi
  install_staged "$canonical" 755 "$PREFIX/bin/stellar-agent"
  install_staged "$STAGED" 755 "$PREFIX/bin/stellar-agent-mcp"
  if ! cmp -s -- "$PREFIX/bin/stellar-agent" "$PREFIX/bin/stellar-agent-mcp"; then
    refuse 65 "$PREFIX/bin/stellar-agent and $PREFIX/bin/stellar-agent-mcp differ; run bootstrap again with the same --cli source"
  fi
  for wrapper in mcp-launch cli-launch provision; do
    stage_in "$PREFIX"
    render "$SOURCE_DIR/$wrapper" "$STAGED"
    install_staged "$STAGED" 755 "$PREFIX/$wrapper"
  done
}

# R5: the project file, root-owned with mode 0644 and one line.
write_project_file() {
  local directory
  say "R5 writes $PROJECT_FILE"
  directory=$(dirname "$PROJECT_FILE")
  mkdir -p -- "$directory"
  chown 0:0 "$directory"
  chmod 755 "$directory"
  stage_in "$directory"
  printf '%s\n' "$PROJECT" >"$STAGED"
  install_staged "$STAGED" 644 "$PROJECT_FILE"
}

# R6: the sudoers file, checked by visudo before it replaces the installed
# one.
install_sudoers() {
  local directory
  say "R6 installs $SUDOERS_FILE"
  directory=$(dirname "$SUDOERS_FILE")
  if [ ! -d "$directory" ]; then
    mkdir -m 755 -- "$directory"
  fi
  stage_in "$directory"
  render "$SOURCE_DIR/sudoers" "$STAGED"
  if ! visudo -cf "$STAGED" >/dev/null; then
    refuse 65 "visudo refuses the rendered sudoers file"
  fi
  install_staged "$STAGED" 440 "$SUDOERS_FILE"
}

main() {
  local source value
  OPERATOR="" PROJECT="" CLI_SOURCE="" MCP_SOURCE="" STAGED=""
  if [ "$(id -u)" != 0 ]; then
    refuse 65 "bootstrap runs as root"
  fi
  while [ "$#" -gt 0 ]; do
    [ "$#" -ge 2 ] || usage
    case "$1" in
      --operator) [ -z "$OPERATOR" ] || usage; OPERATOR=$2 ;;
      --project) [ -z "$PROJECT" ] || usage; PROJECT=$2 ;;
      --cli) [ -z "$CLI_SOURCE" ] || usage; CLI_SOURCE=$2 ;;
      --mcp) [ -z "$MCP_SOURCE" ] || usage; MCP_SOURCE=$2 ;;
      *) usage ;;
    esac
    shift 2
  done
  if [ -z "$OPERATOR" ] || [ -z "$PROJECT" ] || [ -z "$CLI_SOURCE" ]; then
    usage
  fi
  case "$HOST_SYSTEM" in
    Darwin)
      PLATFORM=macos
      HOME_DIR=$MACOS_HOME
      DATA_RELATIVE="Library/Application Support/Soneso.stellar-agent"
      ADMIN_GROUPS="admin"
      ;;
    Linux)
      PLATFORM=linux
      HOME_DIR=$LINUX_HOME
      DATA_RELATIVE=".local/share/stellar-agent"
      ADMIN_GROUPS="sudo wheel adm"
      ;;
    *) refuse 65 "this host is neither macOS nor Linux" ;;
  esac
  DATA_ROOT="$HOME_DIR/$DATA_RELATIVE"
  PREFIX_RE=$(regex_escape "$PREFIX")
  if [[ ! "$OPERATOR" =~ ^[A-Za-z_][A-Za-z0-9_.-]{0,31}$ ]]; then
    refuse 64 "the operator is not an account name"
  fi
  if [ "$OPERATOR" = "$ACCOUNT" ] || ! id -u "$OPERATOR" >/dev/null 2>&1 || [ "$(id -u "$OPERATOR")" = 0 ]; then
    refuse 64 "the operator must be an existing account other than root and $ACCOUNT"
  fi
  if ! valid_project "$PROJECT"; then
    refuse 64 "the project name holds whitespace, a quote, or a control character"
  fi
  for source in "$CLI_SOURCE" ${MCP_SOURCE:+"$MCP_SOURCE"}; do
    if [ ! -f "$source" ]; then
      refuse 64 "$source is not a file"
    fi
  done
  check_binary "$CLI_SOURCE" "the --cli binary"
  if [ -n "$MCP_SOURCE" ]; then
    check_binary "$MCP_SOURCE" "the --mcp binary"
    if ! cmp -s -- "$CLI_SOURCE" "$MCP_SOURCE"; then
      refuse 65 "the --mcp binary differs from the --cli binary; both names install one executable"
    fi
  fi
  for value in "$ACCOUNT" "$OPERATOR" "$HOME_DIR" "$DATA_ROOT" "$PROFILE" "$PREFIX" "$PREFIX_RE" \
    "$PROJECT_FILE" "$WRAPPER_PATH" "$TTY_PATH" "$SECURITY_TOOL" "$DBUS_DAEMON_TOOL" "$GNOME_KEYRING_DAEMON_TOOL" \
    "$ENV_TOOL"; do
    require_plain_value "$value"
  done

  take_lock
  if id -u "$ACCOUNT" >/dev/null 2>&1; then
    say "R7 verifies the existing account $ACCOUNT"
  else
    create_account
  fi
  verify_account
  restrict_account
  create_directories
  install_executables
  write_project_file
  install_sudoers
  say "done; MCP clients run: sudo -n -u $ACCOUNT $PREFIX/mcp-launch"
}

main "$@"
