//! MCP stdio server for the Stellar agent wallet.
//!
//! Exposes wallet functionality to MCP-aware agents (Claude Code, Cursor) over
//! stdio JSON-RPC.  Tool dispatch routes through the same command-handler types
//! as `stellar-agent-cli`; an MCP tool call is therefore a CLI invocation by
//! another name.
//!
//! # Stdout / stderr separation
//!
//! `stdout` is **reserved** for the MCP JSON-RPC transport.  The structured-log
//! subscriber writes to `stderr`.  Mixing log output with the protocol stream
//! would corrupt the wire format.  Clients that redirect stderr receive
//! already-redacted log output (the `RedactingLayer` runs inside the
//! subscriber pipeline before bytes reach the write handle).
//!
//! # Process isolation
//!
//! On Linux the process sets `PR_SET_DUMPABLE 0` and `PR_SET_NO_NEW_PRIVS 1`
//! via raw `libc::prctl` at startup.  Details and the macOS / Windows operator
//! discipline are documented in `docs/runbooks/mcp-process-isolation.md`.
//!
//! # Transport safety
//!
//! The rmcp default `IntoTransport` adapter builds `JsonRpcMessageCodec` with
//! `max_length = usize::MAX` — a DoS surface.  The server is constructed with
//! an explicit 1 MiB bound via
//! `stellar_agent_mcp::STELLAR_AGENT_MCP_MAX_LINE_BYTES`.
//!
//! # Non-goals
//!
//! - HTTP/SSE transport.
//! - Write-tool dispatch on mainnet (gated by `NoopPolicyEngine`).
//!
//! # Primary consumers
//!
//! Claude Code, Cursor, and any MCP-aware agent harness that spawns
//! `stellar-agent-mcp` as a subprocess with piped stdin/stdout.
//!
//! # Related crates
//!
//! - [`stellar-agent-core`] — profile config, policy engine, error types.
//! - [`stellar-agent-network`] — `fetch_account` and `AccountView`.

// Binary crates set `deny` rather than `forbid` because the process-isolation
// prctl calls below require a localised unsafe block.
#![deny(unsafe_code)]
#![warn(missing_docs)]

use stellar_agent_core::observability;
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::name::{
    PROFILE_ENV_VAR, ProfileNameSource, ResolvedProfileName, resolve_profile_name,
    validate_path_component_ascii_safe,
};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::transport;
use stellar_agent_network::keyring::init_platform_keyring_store;

/// Linux-only process-isolation hardening.
///
/// Sets `PR_SET_DUMPABLE 0` to block `ptrace`-attach by non-root processes and
/// `PR_SET_NO_NEW_PRIVS 1` to block setuid escalation paths.
///
/// Both flags are compatible with the supported Linux keyring backends (GNOME
/// Keyring / Secret Service and KWallet run as user-space D-Bus IPC and do not
/// require setuid escalation).  Future Linux backend additions that require
/// setuid must analyse compatibility before landing.
///
/// macOS / Windows: operator discipline described in
/// `docs/runbooks/mcp-process-isolation.md`.
#[cfg(target_os = "linux")]
fn harden_process() {
    // SAFETY: prctl is a pure syscall that modifies only process-level kernel
    // attributes.  The three trailing `0` arguments are unused for the flags
    // we use (PR_SET_DUMPABLE, PR_SET_NO_NEW_PRIVS) per the Linux kernel ABI.
    // No pointer aliasing; no memory is read or written through these arguments.
    // Return value is checked; a non-zero return (errno-set failure) is logged
    // to stderr and the process continues — the hardening is belt-and-braces,
    // not a correctness invariant of the wallet logic.
    #[allow(unsafe_code, reason = "raw prctl syscall; see SAFETY comment")]
    unsafe {
        let rc = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        if rc != 0 {
            // Subscriber not yet installed; eprintln is the pre-subscriber path.
            #[allow(clippy::print_stderr, reason = "pre-subscriber fatal startup path")]
            {
                eprintln!(
                    "stellar-agent-mcp: PR_SET_DUMPABLE failed (errno {}); \
                     ptrace-hardening not active",
                    *libc::__errno_location()
                );
            }
        }
        let rc = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if rc != 0 {
            #[allow(clippy::print_stderr, reason = "pre-subscriber fatal startup path")]
            {
                eprintln!(
                    "stellar-agent-mcp: PR_SET_NO_NEW_PRIVS failed (errno {}); \
                     setuid-escalation hardening not active",
                    *libc::__errno_location()
                );
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn harden_process() {
    // macOS / Windows: operator discipline documented in
    // docs/runbooks/mcp-process-isolation.md.  Neither platform provides a
    // direct equivalent of PR_SET_DUMPABLE; relying on the keyring backend's
    // per-app entitlement model and operator policy.
}

/// Exit code for an unusable invocation: an argument that cannot be parsed, or
/// a profile name that cannot be a path component.
///
/// Distinct from the exit code `1` every later startup refusal uses, and the
/// same code clap gives the `stellar-agent` CLI for a usage error.
const EXIT_USAGE: i32 = 2;

/// The accepted flags, printed by `--help` and repeated with every usage
/// refusal so a rejected invocation carries its own correction.
const USAGE: &str = "\
Usage: stellar-agent-mcp [OPTIONS]

Options:
      --profile <NAME>  Profile to serve. Defaults to the STELLAR_AGENT_PROFILE
                        environment variable, then to `default`. Accepts
                        `--profile=<NAME>` as well.
  -h, --help            Print this help and exit.
  -V, --version         Print the version and exit.

The selected profile binds at startup and stays bound for the life of the
process.";

/// What a parsed argv asks the process to do.
#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    /// Start the server, with an explicitly named profile when one was given.
    Serve {
        /// The `--profile` value, or `None` when the flag was absent.
        profile: Option<String>,
    },
    /// Print the version and exit.
    Version,
    /// Print the usage text and exit.
    Help,
}

/// Why an argv could not be parsed.
#[derive(Debug, PartialEq, Eq)]
enum ArgvError {
    /// A token that is not one of the accepted flags.
    Unrecognised(String),
    /// `--profile` was the last token, or was followed by another flag.
    ProfileValueMissing,
    /// `--profile` was given an empty value.
    ProfileValueEmpty,
}

impl std::fmt::Display for ArgvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unrecognised(token) => write!(f, "unrecognised argument '{token}'"),
            Self::ProfileValueMissing => f.write_str("--profile requires a profile name"),
            Self::ProfileValueEmpty => f.write_str("--profile requires a non-empty profile name"),
        }
    }
}

/// Parses the process arguments (argv without the program name).
///
/// Accepts `--profile <NAME>` and `--profile=<NAME>`; the last occurrence wins.
/// `--version`/`-V` and `--help`/`-h` return as soon as they are reached, so
/// `--profile alice --help` prints help rather than starting a server.
///
/// Every other token is rejected. The binary has never taken a meaningful
/// argument and every documented client stanza passes an empty argument list,
/// so nothing that works today is refused — while a mistyped `--profil
/// mainnet-prod` in an unreviewed client config becomes an error instead of a
/// silent start on the wrong profile, which is the failure this parser exists
/// to prevent.
///
/// In the two-token form a value beginning with `-` is treated as a missing
/// value rather than a profile name, matching the convention the CLI's argument
/// parser follows: `--profile --help` is a mistake, not a request for a profile
/// called `--help`.
fn parse_argv<I>(args: I) -> Result<Invocation, ArgvError>
where
    I: IntoIterator<Item = String>,
{
    let mut profile: Option<String> = None;
    let mut tokens = args.into_iter();
    while let Some(token) = tokens.next() {
        match token.as_str() {
            "--version" | "-V" => return Ok(Invocation::Version),
            "--help" | "-h" => return Ok(Invocation::Help),
            "--profile" => {
                let value = tokens.next().ok_or(ArgvError::ProfileValueMissing)?;
                if value.starts_with('-') {
                    return Err(ArgvError::ProfileValueMissing);
                }
                if value.is_empty() {
                    return Err(ArgvError::ProfileValueEmpty);
                }
                profile = Some(value);
            }
            other => {
                let value = other
                    .strip_prefix("--profile=")
                    .ok_or_else(|| ArgvError::Unrecognised(token.clone()))?;
                if value.is_empty() {
                    return Err(ArgvError::ProfileValueEmpty);
                }
                profile = Some(value.to_owned());
            }
        }
    }
    Ok(Invocation::Serve { profile })
}

/// Parses argv and returns the requested profile name, printing and exiting for
/// `--version`, `--help`, and unusable invocations.
///
/// Runs before subscriber installation, so output goes through `println!` /
/// `eprintln!`: `tracing` macros would write nowhere if subscriber init failed.
#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "pre-subscriber usage and --version/--help path"
)]
fn requested_profile_from_argv() -> Option<String> {
    match parse_argv(std::env::args().skip(1)) {
        Ok(Invocation::Serve { profile }) => profile,
        Ok(Invocation::Version) => {
            println!("stellar-agent-mcp {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        Ok(Invocation::Help) => {
            println!("stellar-agent-mcp {}", env!("CARGO_PKG_VERSION"));
            println!("Stdio MCP server for the Stellar agent wallet.");
            println!(
                "Configure it as a subprocess in your MCP client (Claude Code, Cursor, etc.)."
            );
            println!();
            println!("{USAGE}");
            std::process::exit(0);
        }
        Err(err) => {
            eprintln!("stellar-agent-mcp: {err}");
            eprintln!();
            eprintln!("{USAGE}");
            std::process::exit(EXIT_USAGE);
        }
    }
}

/// Resolves the profile name from the flag, the environment, or the default,
/// and refuses a name that cannot be a filesystem path component.
///
/// The name becomes `<profile_dir>/<name>.toml`, so it is checked here — before
/// the subscriber, the keyring, and the loader — as well as inside the loader,
/// which validates before every join for the callers that do not.
#[allow(clippy::print_stderr, reason = "pre-subscriber fatal startup path")]
fn resolve_and_validate_profile_name(requested: Option<&str>) -> ResolvedProfileName {
    let resolved = resolve_profile_name(requested);
    if let Err(reason) = validate_path_component_ascii_safe(&resolved.name) {
        let origin = match resolved.source {
            ProfileNameSource::Flag => "--profile",
            ProfileNameSource::Env | ProfileNameSource::Default => PROFILE_ENV_VAR,
        };
        eprintln!(
            "stellar-agent-mcp: profile name '{}' from {origin} is not a valid \
             profile name: {reason}",
            resolved.name
        );
        std::process::exit(EXIT_USAGE);
    }
    resolved
}

/// Loads the profile the operator selected.
///
/// A profile named through `--profile` or `STELLAR_AGENT_PROFILE` is loaded
/// with no fallback: the synthesised first-run profile is a **testnet**,
/// **Noop-engine** configuration, so substituting it for a named-but-missing
/// profile would silently answer on the wrong network and downgrade a V1
/// profile's fail-closed governance to an unsigned-policy engine. The fallback
/// applies only when no name was given at all, which is the first-run case it
/// exists for.
///
/// The branch keys on the resolved name's [`ProfileNameSource`], never on the
/// name itself: `--profile default` on a host with no `default.toml` is a named
/// profile that must refuse, not a first run.
fn load_selected_profile(
    resolved: &ResolvedProfileName,
) -> Result<Profile, loader::ProfileLoadError> {
    if resolved.source.is_explicit() {
        loader::load(&resolved.name, None)
    } else {
        loader::load_default_or_testnet_fallback()
    }
}

#[tokio::main]
async fn main() {
    // ── 0. Argument parsing and profile-name resolution ──────────────────────
    // Runs before any other startup step: a CLI probe for --version / --help,
    // a mistyped flag, and an unusable profile name must not touch the
    // subscriber, keyring, or profile loader. The name is resolved here so the
    // load step below knows both the name AND where it came from.
    let resolved_profile =
        resolve_and_validate_profile_name(requested_profile_from_argv().as_deref());

    // ── 1. Process isolation (Linux prctl) ──────────────────────────────────
    // Runs before subscriber installation: even the subscriber startup itself
    // executes in the hardened process context.
    harden_process();

    // ── 2. Tracing subscriber + RedactingLayer ───────────────────────────────
    // MUST be installed before rmcp transport startup so that rmcp's internal
    // tracing::debug! calls (e.g. async_rw.rs raw-line logging) are routed
    // through the redaction pipeline.
    let init_result = observability::init_subscriber(None);
    if let Err(err) = &init_result {
        #[allow(clippy::print_stderr, reason = "pre-subscriber fatal startup path")]
        {
            eprintln!("stellar-agent-mcp: subscriber init failed ({err}); continuing without logs");
        }
    }

    // ── 3. Initialise platform keyring store ─────────────────────────────────
    // Registers the OS keyring backend as the process default so signing tools
    // can resolve it later. It must run before any keyring access.
    //
    // A missing backend (for example a headless host with no D-Bus secret
    // service) is not fatal: the server still starts and serves its read-only
    // and simulate surface. The default-profile fallback uses the Noop policy
    // engine, which never reads the keyring. Signing tools fail closed with a
    // keyring error at call time, and a profile that selects the v1 policy
    // engine fails to start because building it requires the owner key from the
    // keyring. No key material is exposed and no gate is bypassed by degrading
    // here, so a read-only deployment does not require a keyring backend.
    if let Err(err) = init_platform_keyring_store() {
        tracing::warn!(
            error = %err,
            "stellar-agent-mcp: platform keyring store unavailable; read-only and \
             simulate tools remain available, but signing tools will be refused \
             until a keyring backend is configured"
        );
    }

    // ── 4. Load the selected profile ─────────────────────────────────────────
    // The profile is selected by `--profile <name>`, then
    // `STELLAR_AGENT_PROFILE`, then the name `default`. A named profile is
    // loaded with no fallback (see `load_selected_profile`); only the unnamed
    // case falls back to a synthesised testnet default when no profile file
    // exists yet (the first-run case, before `stellar-agent profile init`).
    // The fallback profile is a synthesised testnet default with placeholder
    // keyring coordinates, including an audit chain-root coordinate that was
    // never minted. Any commit/submit tool that signs or moves value (e.g.
    // `stellar_create_account_commit`) refuses `audit.chain_key_unavailable`
    // from its audit pre-flight before ever probing the signer keyring — the
    // MCP server's fallback profile is not origin-aware the way the CLI's
    // zero-config `pay`/`claim`/`accounts create` synthesis is, so this
    // refusal is unconditional here. The user must run
    // `stellar-agent profile init` to create a real profile, then
    // `stellar-agent profile rotate-audit-key` and
    // `stellar-agent profile enroll-signer` to register the audit key and a
    // signing key.  Note that `profile init` writes `engine = "v1"` by
    // default, and a v1 profile
    // makes THIS server refuse to start until the V1 ceremony completes
    // (owner key, attestation key, audit key, signed policy); an operator who
    // wants the server up immediately initialises with `--engine noop`.  This
    // is the intended behaviour: the fallback profile enables
    // `stellar_balances` and `stellar_create_account` (simulate step, which
    // does NOT touch the signer keyring) without requiring a prior setup step.
    let profile = match load_selected_profile(&resolved_profile) {
        Ok(p) => {
            // The resolved name and its source are logged together: a report of
            // a server answering from the wrong profile is diagnosable only if
            // the log says which name was used and which input supplied it.
            tracing::info!(
                profile = %resolved_profile.name,
                profile_source = resolved_profile.source.as_str(),
                chain_id = %p.chain_id,
                "stellar-agent-mcp: profile loaded"
            );
            p
        }
        Err(loader::ProfileLoadError::NotFound { name, path }) => {
            let origin = match resolved_profile.source {
                ProfileNameSource::Flag => "the --profile flag",
                ProfileNameSource::Env | ProfileNameSource::Default => PROFILE_ENV_VAR,
            };
            tracing::error!(
                profile = %name,
                path = %path.display(),
                profile_source = resolved_profile.source.as_str(),
                "stellar-agent-mcp: profile '{name}' was named by {origin} but no profile \
                 file exists at '{}'; create it with `stellar-agent profile init --profile \
                 {name}`. A named profile is never replaced by the synthesised first-run \
                 testnet profile: that would serve testnet under the requested name and \
                 downgrade its policy engine",
                path.display()
            );
            std::process::exit(1);
        }
        Err(err) => {
            tracing::error!(
                error = %err,
                profile = %resolved_profile.name,
                profile_source = resolved_profile.source.as_str(),
                "stellar-agent-mcp: failed to load profile; aborting"
            );
            std::process::exit(1);
        }
    };

    // ── 4b. Per-profile MCP kill-switch ──────────────────────────────────────
    // A profile with `mcp_disabled = true` is an operator kill-switch: refuse to
    // start so the MCP surface cannot be used for that profile.
    if let Some(code) = transport::mcp_disabled_refusal(&profile) {
        tracing::error!(
            code,
            chain_id = %profile.chain_id,
            "stellar-agent-mcp: MCP is disabled for this profile (mcp_disabled = true); refusing to start"
        );
        std::process::exit(1);
    }

    // ── 4c. Reconcile the selected name with the profile's own name ──────────
    // Runs BEFORE the server is built. The server derives the name it uses for
    // per-profile state from the profile's contents; if that disagrees with the
    // name the profile was loaded under, every per-profile path — signed
    // policy, approval store, window state — belongs to a different profile.
    // Building first would report the other profile's missing owner key instead,
    // a misleading second message for a single cause.
    if let Some(mismatch) =
        transport::profile_name_mismatch_refusal(&profile, &resolved_profile.name)
    {
        // Rendered under this surface's own state layout: every per-profile
        // store here keys on the derived name, which is not the CLI's layout.
        tracing::error!(
            profile = %resolved_profile.name,
            "stellar-agent-mcp: refusing to start: {}",
            mismatch.message(transport::STARTUP_STATE_LAYOUT)
        );
        std::process::exit(1);
    }

    // ── 5. Build the server ──────────────────────────────────────────────────
    // Constructed separately from serving so the typed BuildRegistryError can
    // be matched: the V1 startup ceremony fails at three successive walls, and
    // naming only the first one sends the operator into a non-actionable exit
    // one step later.
    let server = match transport::build_server(profile) {
        Ok(server) => server,
        Err(err) => {
            report_build_failure(&err, &resolved_profile.name);
            std::process::exit(1);
        }
    };

    // ── 6. Start MCP server ───────────────────────────────────────────────────
    if let Err(err) = transport::serve(server).await {
        tracing::error!(error = %err, "stellar-agent-mcp: server error");
        std::process::exit(1);
    }
}

/// Logs a server-construction failure, naming the command that fixes it for the
/// refusals an operator can act on.
///
/// The V1 engine is what `stellar-agent profile init` writes by default, and
/// bringing it up is a ceremony: the owner key must be enrolled, then the policy
/// file signed, before the server will start. Each of those steps is a distinct
/// `BuildRegistryError`, so each gets the command that clears it. Variants that
/// already carry a classified code and their own recovery text — a keyring that
/// cannot be read at all, a policy-window store that must be reset — are logged
/// as they are.
fn report_build_failure(err: &stellar_agent_core::policy::BuildRegistryError, profile_name: &str) {
    use stellar_agent_core::policy::BuildRegistryError as E;
    let next_step = match err {
        E::OwnerKeyAbsent { .. } => Some(format!(
            "enrol the policy owner key with `stellar-agent profile enroll-owner-key \
             --profile {profile_name}`, then sign the policy file with \
             `stellar-agent profile sign-policy --profile {profile_name}`. A profile \
             that does not need V1 governance can be re-created with \
             `stellar-agent profile init --profile <name> --engine noop`"
        )),
        // Fires when the keyring store itself was never initialised, which is
        // the headless-host case: startup only warns about a missing backend,
        // so a v1 profile reaches here rather than at the keyring step.
        E::OwnerKeyringEntryUnreadable { .. } => Some(
            "no usable keyring backend is configured for this process; set \
             STELLAR_AGENT_KEYRING_BACKEND=headless-dpapi (Windows) or \
             =headless-env with STELLAR_AGENT_HEADLESS_KEYRING_KEY (any platform), \
             or run from an interactive desktop session"
                .to_owned(),
        ),
        E::OwnerKeyDecodeFailed { .. } | E::OwnerKeyLengthMismatch { .. } => Some(format!(
            "the stored owner key is not a usable ed25519 public key; re-enrol it with \
             `stellar-agent profile enroll-owner-key --profile {profile_name}`"
        )),
        E::PolicyFileLoadFailed { .. } => Some(format!(
            "the V1 policy file is missing, unreadable, or not signed by the enrolled \
             owner key; write and sign it with `stellar-agent profile sign-policy \
             --profile {profile_name}`"
        )),
        _ => None,
    };
    match next_step {
        Some(next_step) => tracing::error!(
            error = %err,
            profile = %profile_name,
            "stellar-agent-mcp: cannot start the server for profile '{profile_name}': {err}; \
             {next_step}"
        ),
        None => tracing::error!(
            error = %err,
            profile = %profile_name,
            "stellar-agent-mcp: cannot start the server for profile '{profile_name}': {err}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{ArgvError, Invocation, parse_argv};

    /// Parses a borrowed token list the way `std::env::args().skip(1)` yields
    /// argv.
    fn parse(tokens: &[&str]) -> Result<Invocation, ArgvError> {
        parse_argv(tokens.iter().map(|token| (*token).to_owned()))
    }

    fn serve_with(profile: Option<&str>) -> Invocation {
        Invocation::Serve {
            profile: profile.map(ToOwned::to_owned),
        }
    }

    #[test]
    fn empty_argv_serves_without_a_named_profile() {
        assert_eq!(parse(&[]), Ok(serve_with(None)));
    }

    #[test]
    fn profile_flag_two_token_form() {
        assert_eq!(
            parse(&["--profile", "alice"]),
            Ok(serve_with(Some("alice")))
        );
    }

    #[test]
    fn profile_flag_equals_form() {
        assert_eq!(parse(&["--profile=alice"]), Ok(serve_with(Some("alice"))));
    }

    #[test]
    fn profile_flag_is_read_anywhere_in_argv() {
        // The flag is honoured at any argv position and the last occurrence
        // wins: a parser that inspected only one position would ignore the
        // rest, which is the shape of a silent wrong-profile start.
        assert_eq!(
            parse(&["--profile", "alice", "--profile=bob"]),
            Ok(serve_with(Some("bob"))),
            "the last occurrence wins"
        );
    }

    #[test]
    fn profile_flag_without_a_value_is_an_error() {
        assert_eq!(parse(&["--profile"]), Err(ArgvError::ProfileValueMissing));
    }

    #[test]
    fn profile_flag_followed_by_a_flag_is_a_missing_value() {
        assert_eq!(
            parse(&["--profile", "--help"]),
            Err(ArgvError::ProfileValueMissing),
            "`--help` is a mistyped invocation, not a profile name"
        );
    }

    #[test]
    fn empty_profile_value_is_an_error() {
        assert_eq!(parse(&["--profile", ""]), Err(ArgvError::ProfileValueEmpty));
        assert_eq!(parse(&["--profile="]), Err(ArgvError::ProfileValueEmpty));
    }

    #[test]
    fn unknown_flag_is_rejected() {
        // The likeliest failure mode this rejection exists for: a typo in an
        // unreviewed MCP client config must not start a server on `default`.
        assert_eq!(
            parse(&["--profil", "mainnet-prod"]),
            Err(ArgvError::Unrecognised("--profil".to_owned()))
        );
    }

    #[test]
    fn unknown_positional_token_is_rejected() {
        assert_eq!(
            parse(&["mainnet-prod"]),
            Err(ArgvError::Unrecognised("mainnet-prod".to_owned()))
        );
    }

    #[test]
    fn version_and_help_are_honoured_after_other_flags() {
        assert_eq!(
            parse(&["--profile", "alice", "--help"]),
            Ok(Invocation::Help)
        );
        assert_eq!(parse(&["--profile=alice", "-h"]), Ok(Invocation::Help));
        assert_eq!(
            parse(&["--profile", "alice", "--version"]),
            Ok(Invocation::Version)
        );
        assert_eq!(parse(&["-V"]), Ok(Invocation::Version));
    }

    #[test]
    fn traversal_profile_names_parse_and_are_refused_by_validation() {
        // The parser is not the traversal guard: it accepts the token, and
        // `validate_path_component_ascii_safe` refuses it at step 0 (and the
        // loader refuses it again at the join).
        assert_eq!(
            parse(&["--profile", "../../etc/passwd"]),
            Ok(serve_with(Some("../../etc/passwd")))
        );
        assert!(
            stellar_agent_core::profile::name::validate_path_component_ascii_safe(
                "../../etc/passwd"
            )
            .is_err()
        );
    }

    #[test]
    fn usage_text_documents_the_profile_flag_and_environment_variable() {
        assert!(super::USAGE.contains("--profile <NAME>"));
        assert!(super::USAGE.contains("STELLAR_AGENT_PROFILE"));
        assert!(
            !super::USAGE.contains("Takes no arguments"),
            "the help text must not claim the binary takes no arguments"
        );
    }
}
