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
//! discipline are documented in `docs/mcp.md#launching-the-server`.
//!
//! # Transport safety
//!
//! The rmcp default `IntoTransport` adapter builds `JsonRpcMessageCodec` with
//! `max_length = usize::MAX` — a DoS surface.  The server is constructed with
//! an explicit 1 MiB bound via
//! [`crate::STELLAR_AGENT_MCP_MAX_LINE_BYTES`].
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
//! - [`stellar_agent_core`] — profile config, policy engine, error types.
//! - [`stellar_agent_network`] — `fetch_account` and `AccountView`.

use crate::transport;
use stellar_agent_core::observability;
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::name::{
    PROFILE_ENV_VAR, ProfileNameSource, ResolvedProfileName, resolve_profile_name,
    validate_path_component_ascii_safe,
};
use stellar_agent_network::keyring::init_platform_keyring_store;

/// Usage name for the server executable or an executable invoked by this name.
pub const INVOKED_NAME_ROUTE: &str = "stellar-agent-mcp";

/// Usage name for the CLI's server subcommand.
pub const SUBCOMMAND_ROUTE: &str = "stellar-agent mcp serve";

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
/// `docs/mcp.md#launching-the-server`.
#[cfg(target_os = "linux")]
fn harden_process() {
    stellar_agent_core::test_trace::record("hardening");
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
    stellar_agent_core::test_trace::record("hardening");
    // macOS / Windows: operator discipline documented in
    // docs/mcp.md#launching-the-server.  Neither platform provides a
    // direct equivalent of PR_SET_DUMPABLE; relying on the keyring backend's
    // per-app entitlement model and operator policy.
}

/// Exit code for an unusable invocation: an argument that cannot be parsed, or
/// a profile name that cannot be a path component.
///
/// Distinct from the exit code `1` every later startup refusal uses.
const EXIT_USAGE: i32 = 2;

/// The accepted flags, printed by `--help` and repeated with every usage
/// refusal so a rejected invocation carries its own correction.
fn usage(display_name: &str) -> String {
    format!(
        "\
Usage: {display_name} [OPTIONS]

Options:
      --profile <NAME>  Profile to serve. Defaults to the STELLAR_AGENT_PROFILE
                        environment variable, then to `default`. Accepts
                        `--profile=<NAME>` as well.
  -h, --help            Print this help and exit.
  -V, --version         Print the version and exit.

The selected profile binds at startup and stays bound for the life of the
process. A mainnet profile needs `--profile <NAME>`, including `--profile default`.
STELLAR_AGENT_PROFILE never selects a mainnet profile."
    )
}

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
    Unrecognised,
    /// `--profile` was the last token, or was followed by another flag.
    ProfileValueMissing,
    /// `--profile` was given an empty value.
    ProfileValueEmpty,
}

impl std::fmt::Display for ArgvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unrecognised => f.write_str("unrecognised command-line argument"),
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
                    .ok_or(ArgvError::Unrecognised)?;
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
fn requested_profile_from_argv<I: IntoIterator<Item = String>>(
    display_name: &'static str,
    args: I,
) -> Option<String> {
    match parse_argv(args) {
        Ok(Invocation::Serve { profile }) => profile,
        Ok(Invocation::Version) => {
            println!("stellar-agent-mcp {}", env!("CARGO_PKG_VERSION"));
            println!("{}", stellar_agent_core::build_info::MAINNET_WRITE_MARKER);
            std::process::exit(0);
        }
        Ok(Invocation::Help) => {
            println!("stellar-agent-mcp {}", env!("CARGO_PKG_VERSION"));
            println!("Stdio MCP server for the Stellar agent wallet.");
            println!(
                "Configure it as a subprocess in your MCP client (Claude Code, Cursor, etc.)."
            );
            println!();
            println!("{}", usage(display_name));
            std::process::exit(0);
        }
        Err(err) => {
            eprintln!("stellar-agent-mcp: {err}");
            eprintln!();
            eprintln!("{}", usage(display_name));
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
            "stellar-agent-mcp: the profile name from {origin} is not a valid \
             profile name: {reason}"
        );
        std::process::exit(EXIT_USAGE);
    }
    resolved
}

/// Exit code of a second shutdown event during the shutdown wait or the exit
/// drain.
///
/// No other outcome of the binary uses it: `0` is help, version, and a clean
/// shutdown, `1` a startup or server failure, and `2` a usage refusal.
const EXIT_SECOND_SIGNAL: i32 = 3;

/// Environment variable that names shutdown listeners whose registration
/// fails, as a comma-separated list of [`ShutdownEvent::name`] values.
///
/// Compiled only with the `test-helpers` feature, so a release binary always
/// registers every listener. A subprocess test sets it to observe the warning
/// and the listeners that stay active.
#[cfg(feature = "test-helpers")]
const LISTENER_FAILURE_ENV: &str = "STELLAR_AGENT_TEST_SHUTDOWN_LISTENER_FAILURE";

/// An event that starts a graceful shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownEvent {
    /// SIGINT on Unix, Ctrl-C on Windows.
    Interrupt,
    /// SIGTERM on Unix.
    #[cfg(unix)]
    Terminate,
    /// A Ctrl-Break event on Windows.
    #[cfg(windows)]
    CtrlBreak,
    /// A console close event on Windows.
    #[cfg(windows)]
    ConsoleClose,
}

impl ShutdownEvent {
    /// The event's name in logs and in the test-only failure variable.
    fn name(self) -> &'static str {
        match self {
            #[cfg(unix)]
            Self::Interrupt => "sigint",
            #[cfg(not(unix))]
            Self::Interrupt => "ctrl-c",
            #[cfg(unix)]
            Self::Terminate => "sigterm",
            #[cfg(windows)]
            Self::CtrlBreak => "ctrl-break",
            #[cfg(windows)]
            Self::ConsoleClose => "ctrl-close",
        }
    }

    /// Logs that the event's listener is not registered, so that event ends
    /// the process without the exit drain.
    fn warn_unregistered(self, error: &std::io::Error) {
        match self {
            #[cfg(unix)]
            Self::Interrupt => tracing::warn!(
                error = %error,
                "stellar-agent-mcp: cannot listen for SIGINT; the server will not drain on Ctrl-C"
            ),
            #[cfg(not(unix))]
            Self::Interrupt => tracing::warn!(
                error = %error,
                "stellar-agent-mcp: cannot listen for Ctrl-C; the server does not drain on Ctrl-C"
            ),
            #[cfg(unix)]
            Self::Terminate => tracing::warn!(
                error = %error,
                "stellar-agent-mcp: cannot listen for SIGTERM; the server will not drain on \
                 SIGTERM"
            ),
            #[cfg(windows)]
            Self::CtrlBreak => tracing::warn!(
                error = %error,
                "stellar-agent-mcp: cannot listen for Ctrl-Break; the server does not drain on \
                 Ctrl-Break"
            ),
            #[cfg(windows)]
            Self::ConsoleClose => tracing::warn!(
                error = %error,
                "stellar-agent-mcp: cannot listen for console close; the server does not drain \
                 when its console closes"
            ),
        }
    }

    /// The registration failure the test-only variable names for this event.
    fn injected_registration_failure(self) -> Option<std::io::Error> {
        #[cfg(feature = "test-helpers")]
        if std::env::var(LISTENER_FAILURE_ENV)
            .is_ok_and(|names| names.split(',').any(|name| name.trim() == self.name()))
        {
            return Some(std::io::Error::other(
                "the listener registration failure the test requested",
            ));
        }
        None
    }
}

/// Registers one listener and forwards each of its events to `$events`, and
/// evaluates to whether the listener is registered.
///
/// A failed registration logs a warning and leaves that listener inactive;
/// every other listener stays registered. The task skips an event that the
/// native console close handler forwards itself.
macro_rules! listen {
    ($events:expr, $event:expr, $register:expr) => {{
        let event: ShutdownEvent = $event;
        let registered = match event.injected_registration_failure() {
            Some(error) => Err(error),
            None => $register,
        };
        match registered {
            Ok(mut listener) => {
                let events = $events.clone();
                tokio::spawn(async move {
                    while listener.recv().await.is_some() {
                        if forwarded_natively(event) {
                            continue;
                        }
                        if events.send(event).is_err() {
                            break;
                        }
                    }
                });
                true
            }
            Err(error) => {
                event.warn_unregistered(&error);
                false
            }
        }
    }};
}

/// Whether the native console close handler forwards `event` itself.
#[cfg(unix)]
fn forwarded_natively(_event: ShutdownEvent) -> bool {
    false
}

/// Whether the native console close handler forwards `event` itself.
#[cfg(windows)]
fn forwarded_natively(event: ShutdownEvent) -> bool {
    event == ShutdownEvent::ConsoleClose && console_close::forwarded()
}

/// The native console close handler on Windows.
///
/// Windows ends the process when a `CTRL_CLOSE_EVENT` handler returns, and
/// asynchronous forwarding alone cannot keep the process alive until the
/// supervisor logs the event and the exit drain runs.
#[cfg(windows)]
mod console_close {
    #![allow(
        unsafe_code,
        reason = "SetConsoleCtrlHandler registration and its callback"
    )]

    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::sync::mpsc::UnboundedSender;
    use windows_sys::Win32::Foundation::{FALSE, TRUE};
    use windows_sys::Win32::System::Console::{CTRL_CLOSE_EVENT, SetConsoleCtrlHandler};
    use windows_sys::core::BOOL;

    use super::ShutdownEvent;

    /// The supervisor channel the handler sends the close event to.
    static EVENTS: OnceLock<UnboundedSender<ShutdownEvent>> = OnceLock::new();

    /// Set while the handler sends the close event, and cleared when the
    /// send fails.
    ///
    /// A successful send parks the handler thread, so Tokio's handler never
    /// sees that event. A failed send means the supervisor's receiver is
    /// closed. The handler then clears the flag and returns `FALSE`. A send
    /// of the Tokio listener's task fails the same way, because it uses the
    /// same channel.
    ///
    /// A close that Tokio receives before this handler is installed reaches
    /// that task. The task forwards it while the flag is clear and drops it
    /// once the flag is set.
    ///
    /// The flag holds no event identity. It merges a notification that
    /// awaits forwarding from before installation with a later native
    /// notification, and identifies neither. Two distinct closes can then
    /// reach the supervisor as one.
    static FORWARDED: AtomicBool = AtomicBool::new(false);

    /// Whether the flag is set: the handler's send of the close event is
    /// underway or complete.
    pub(super) fn forwarded() -> bool {
        FORWARDED.load(Ordering::SeqCst)
    }

    /// Registers [`on_console_event`] after the Tokio listeners, so Windows
    /// calls it first: the last registered handler runs first.
    ///
    /// # Errors
    ///
    /// When the handler is already installed or the registration fails.
    pub(super) fn install(events: &UnboundedSender<ShutdownEvent>) -> std::io::Result<()> {
        EVENTS
            .set(events.clone())
            .map_err(|_| std::io::Error::other("the console close handler is already installed"))?;
        // SAFETY: the handler is a `'static` function with the signature
        // `PHANDLER_ROUTINE` requires, and the call reads no other memory.
        let registered = unsafe { SetConsoleCtrlHandler(Some(on_console_event), TRUE) };
        if registered == FALSE {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Sends [`ShutdownEvent::ConsoleClose`] to the supervisor on
    /// `CTRL_CLOSE_EVENT` and blocks until the process ends.
    ///
    /// Invariant: the handler blocks until the process ends, because Windows
    /// ends the process when it returns. The supervisor's exit drain ends the
    /// process through its own exit; otherwise Windows ends it at its
    /// close deadline. Windows runs each handler on a thread of its own, so
    /// the blocked thread holds up no runtime work. Every other event kind
    /// returns `FALSE`, so Windows calls the next handler. A close event whose
    /// send fails on a closed channel returns `FALSE` as well.
    unsafe extern "system" fn on_console_event(kind: u32) -> BOOL {
        if kind != CTRL_CLOSE_EVENT {
            return FALSE;
        }
        let Some(events) = EVENTS.get() else {
            return FALSE;
        };
        FORWARDED.store(true, Ordering::SeqCst);
        if events.send(ShutdownEvent::ConsoleClose).is_err() {
            FORWARDED.store(false, Ordering::SeqCst);
            return FALSE;
        }
        loop {
            std::thread::park();
        }
    }
}

/// Registers the platform's shutdown listeners, each forwarding to `events`.
#[cfg(unix)]
fn register_shutdown_listeners(events: &tokio::sync::mpsc::UnboundedSender<ShutdownEvent>) {
    use tokio::signal::unix::{SignalKind, signal};
    listen!(
        events,
        ShutdownEvent::Interrupt,
        signal(SignalKind::interrupt())
    );
    listen!(
        events,
        ShutdownEvent::Terminate,
        signal(SignalKind::terminate())
    );
}

/// Registers the platform's shutdown listeners, each forwarding to `events`.
#[cfg(windows)]
fn register_shutdown_listeners(events: &tokio::sync::mpsc::UnboundedSender<ShutdownEvent>) {
    listen!(
        events,
        ShutdownEvent::Interrupt,
        tokio::signal::windows::ctrl_c()
    );
    listen!(
        events,
        ShutdownEvent::CtrlBreak,
        tokio::signal::windows::ctrl_break()
    );
    let close_listened = listen!(
        events,
        ShutdownEvent::ConsoleClose,
        tokio::signal::windows::ctrl_close()
    );
    // The native handler is registered after the Tokio listeners, so it runs
    // first. A failed installation leaves the console close listener above.
    if close_listened && let Err(error) = console_close::install(events) {
        tracing::warn!(
            error = %error,
            "stellar-agent-mcp: cannot install the native console close handler; console \
             close reaches the supervisor through its listener only"
        );
    }
}

/// Starts the shutdown supervisor and returns a future that resolves on the
/// first shutdown event.
///
/// The events are SIGINT and SIGTERM on Unix, and Ctrl-C, Ctrl-Break, and
/// console close on Windows. The server races the returned future against the
/// stdio session. When it resolves, the transport cancels the session and
/// returns, and `main` drains the audit outboxes of the writers this process
/// cached before it exits.
///
/// The supervisor is a task of its own that counts the events it receives.
/// The exit drain runs on a blocking thread, so the supervisor stays
/// responsive during it. A second event during the shutdown wait or the drain
/// exits the process at once with [`EXIT_SECOND_SIGNAL`]. Client EOF is not an
/// event: after EOF the first signal still starts no forced exit.
///
/// When no listener can be registered, the returned future never resolves.
fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
    register_shutdown_listeners(&events_tx);
    drop(events_tx);
    let (first_tx, first_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut first = Some(first_tx);
        while let Some(event) = events_rx.recv().await {
            if let Some(first) = first.take() {
                tracing::info!(
                    event = event.name(),
                    "stellar-agent-mcp: shutdown event received; stopping the session and \
                     draining the audit outboxes"
                );
                // A dropped receiver means the session already ended, so the
                // drain is running or done and nothing awaits the event.
                first.send(()).ok();
            } else {
                // A forced exit is a crash for the outbox: rows it did not
                // drain stay queued, and a later draining writer delivers them.
                tracing::warn!(
                    event = event.name(),
                    exit_code = EXIT_SECOND_SIGNAL,
                    "stellar-agent-mcp: second shutdown event received; exiting at once, and \
                     undrained audit rows stay queued for the next draining writer"
                );
                std::process::exit(EXIT_SECOND_SIGNAL);
            }
        }
    });
    async move {
        if first_rx.await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Runs the MCP server on its own multi-thread runtime and exits the process.
///
/// `args` contains only server options, without the executable or subcommand.
/// `display_name` identifies the invocation route in usage text.
///
/// # Panics
///
/// Panics if the Tokio runtime cannot be built, as `#[tokio::main]` does.
pub fn run_server_process<I: IntoIterator<Item = String>>(
    display_name: &'static str,
    args: I,
) -> ! {
    stellar_agent_core::test_trace::record("runtime");
    #[allow(
        clippy::expect_used,
        reason = "the #[tokio::main] expansion; no runtime means no server"
    )]
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime");
    runtime.block_on(serve(display_name, args))
}

async fn serve<I: IntoIterator<Item = String>>(display_name: &'static str, args: I) -> ! {
    // ── 0. Argument parsing and profile-name resolution ──────────────────────
    // Runs before any other startup step: a CLI probe for --version / --help,
    // a mistyped flag, and an unusable profile name must not touch the
    // subscriber, keyring, or profile loader. The name is resolved here so the
    // load step below knows both the name AND where it came from.
    let resolved_profile = resolve_and_validate_profile_name(
        requested_profile_from_argv(display_name, args).as_deref(),
    );

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
    // loaded with no fallback (see `transport::load_selected_profile`); only
    // the unnamed case falls back to a synthesised testnet default when no
    // profile file exists yet (the first-run case, before
    // `stellar-agent profile init`).
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
    let (profile, origin) = match transport::load_selected_profile(&resolved_profile) {
        Ok(loaded) => loaded,
        Err(loader::ProfileLoadError::MainnetRequiresExplicitProfile { named_by, .. }) => {
            let err = loader::ProfileLoadError::MainnetRequiresExplicitProfile {
                name: "<name>".to_owned(),
                named_by,
            };
            tracing::error!(
                profile_source = resolved_profile.source.as_str(),
                code = err.to_validation_error().code(),
                "stellar-agent-mcp: {err}; run `stellar-agent-mcp --profile <name>`"
            );
            std::process::exit(1);
        }
        Err(loader::ProfileLoadError::NotFound) => {
            // The name may be a value typed into the wrong place, so neither it
            // nor the path that ends in it is logged.
            let origin = match resolved_profile.source {
                ProfileNameSource::Flag => "the --profile flag",
                ProfileNameSource::Env | ProfileNameSource::Default => PROFILE_ENV_VAR,
            };
            tracing::error!(
                profile_source = resolved_profile.source.as_str(),
                "stellar-agent-mcp: the profile named by {origin} has no profile file; create \
                 it with `stellar-agent profile init --profile <name>`. A named profile is \
                 never replaced by the synthesised first-run testnet profile: that would serve \
                 testnet under the requested name and downgrade its policy engine"
            );
            std::process::exit(1);
        }
        Err(err) => {
            tracing::error!(
                error = %err,
                profile_source = resolved_profile.source.as_str(),
                code = err.to_validation_error().code(),
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
    //
    // The key-scope check follows: the profile's keyring coordinates must
    // belong to it alone on this host. A mainnet conflict refuses to start; a
    // testnet conflict, and every finding after the refusing one, is logged at
    // `warn` on target `profile.key_scope`.
    if let Some(mismatch) =
        transport::profile_name_mismatch_refusal(&profile, &resolved_profile.name)
    {
        // Rendered under this surface's own state layout: every per-profile
        // store here keys on the derived name, which is not the CLI's layout.
        tracing::error!(
            "stellar-agent-mcp: refusing to start: {}",
            mismatch.message(transport::STARTUP_STATE_LAYOUT)
        );
        std::process::exit(1);
    }
    tracing::info!(
        profile = %resolved_profile.name,
        profile_source = resolved_profile.source.as_str(),
        chain_id = %profile.chain_id,
        "stellar-agent-mcp: profile loaded"
    );
    if let Err(conflict) =
        stellar_agent_core::profile::key_scope::enforce_key_scope(&profile, &resolved_profile.name)
    {
        let error = stellar_agent_core::error::ValidationError::from(conflict);
        tracing::error!(
            code = error.code(),
            "stellar-agent-mcp: refusing to start: {error}"
        );
        std::process::exit(1);
    }

    // ── 5. Build the server ──────────────────────────────────────────────────
    // Constructed separately from serving so the typed BuildRegistryError can
    // be matched: the V1 startup ceremony fails at three successive walls, and
    // naming only the first one sends the operator into a non-actionable exit
    // one step later.
    // The origin fixes the audit binding check for the server's lifetime: a
    // profile read from a file records an absent binding, and the synthesized
    // fallback only compares.
    let server = match transport::build_selected_server(
        profile,
        resolved_profile.source,
        origin.binding_check(),
    ) {
        Ok(server) => server,
        Err(err) => {
            report_build_failure(&err, &resolved_profile.name);
            std::process::exit(1);
        }
    };

    #[cfg(feature = "test-helpers")]
    for registration in inventory::iter::<stellar_agent_core::policy::McpToolRegistration>() {
        stellar_agent_core::test_trace::record(&format!("tool:{}", registration.name));
    }

    // ── 6. Start MCP server ───────────────────────────────────────────────────
    let result = transport::serve_until(server, shutdown_signal()).await;

    // ── 7. Drain the audit outboxes this process cached ───────────────────────
    // The transport returns on client EOF and on the first shutdown event:
    // SIGINT or SIGTERM on Unix, Ctrl-C, Ctrl-Break, or console close on
    // Windows. Either way a `profile halt` or `profile resume` row queued while
    // this server held the writer must reach the log now. A halted profile may
    // see no further keyed command for a long time. The drain waits at most two
    // seconds for each cached writer's mutex; a writer still held then keeps
    // its queued rows. The bound covers the mutex wait only, not the drain's
    // filesystem or keyring work. A failed check is logged by the registry; a
    // refused drain leaves the outbox unchanged, so delivery stays at least
    // once. The exit code is unaffected. The drain runs on a blocking thread,
    // so the shutdown supervisor still exits with code 3 on a second event.
    let drained = match tokio::task::spawn_blocking(
        stellar_agent_core::audit_log::AuditWriterRegistry::drain_cached_outboxes,
    )
    .await
    {
        Ok(drained) => drained,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "stellar-agent-mcp: the exit drain did not finish; undrained audit rows stay \
                 queued for the next draining writer"
            );
            0
        }
    };
    tracing::info!(
        writers = drained,
        "stellar-agent-mcp: drained cached audit outboxes at exit"
    );

    if let Err(err) = result {
        tracing::error!(error = %err, "stellar-agent-mcp: server error");
        std::process::exit(1);
    }

    // The stdio transport reads through `tokio::io::stdin()`, whose blocking
    // read cannot be cancelled. With the client still holding the pipe open,
    // dropping the runtime waits for that read to return, so a normal return
    // would hang after a signal-triggered shutdown. The outboxes are drained
    // above and the subscriber writes synchronously to stderr, so exit here.
    std::process::exit(0);
}

/// Logs a server-construction failure, naming the command that fixes it for the
/// refusals an operator can act on.
///
/// The V1 engine is what `stellar-agent profile init` writes by default, and
/// bringing it up is a ceremony: the owner key must be enrolled, then the policy
/// file signed, before the server will start. The owner-key step gets its
/// command here. The loader refuses a policy file without a `[signature]` table
/// with a message that names `stellar-agent profile sign-policy` with the profile.
/// A policy file that fails any other check gets no hint.
/// Variants that carry their own refusal text, such as a policy-window store
/// that fails its integrity check, are logged as they are.
fn report_build_failure(err: &stellar_agent_core::policy::BuildRegistryError, profile_name: &str) {
    match build_failure_next_step(err, profile_name) {
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

/// Returns the command that clears a server-construction failure, or `None`
/// for a failure whose own message is the guidance.
///
/// A V1 policy file that is read but fails a body check, such as an unknown
/// key, gets no hint: re-signing does not clear it, and the error names the key's
/// location and the accepted keys.
fn build_failure_next_step(
    err: &stellar_agent_core::policy::BuildRegistryError,
    profile_name: &str,
) -> Option<String> {
    use stellar_agent_core::policy::BuildRegistryError as E;
    use stellar_agent_core::policy::PolicyError;
    match err {
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
        E::OwnerKeyOlderForm { profile } => Some(format!(
            "re-enrol the owner public key with `stellar-agent profile enroll-owner-key --profile {profile} --force`"
        )),
        E::OwnerKeyDecodeFailed { .. } => Some(format!(
            "the stored owner key is not a usable ed25519 public key; re-enrol it with \
             `stellar-agent profile enroll-owner-key --profile {profile_name} --force`"
        )),
        E::PolicyFileLoadFailed {
            source: PolicyError::PolicyFileLoadFailed { .. },
            ..
        } => Some(format!(
            "the V1 policy file could not be read; create it if it is missing, then sign it with \
             `stellar-agent profile sign-policy --profile {profile_name}`"
        )),
        E::PolicyFileLoadFailed {
            source: PolicyError::OwnerSignatureInvalid { .. },
            ..
        } => Some(format!(
            "review the V1 policy file and re-sign it with `stellar-agent profile \
             sign-policy --profile {profile_name}`"
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use stellar_agent_core::policy::{BuildRegistryError, PolicyError};

    use super::{ArgvError, Invocation, build_failure_next_step, parse_argv};

    fn policy_load_failure(source: PolicyError) -> BuildRegistryError {
        BuildRegistryError::PolicyFileLoadFailed {
            profile: "alice".to_owned(),
            source,
        }
    }

    /// An owner-signature failure, with or without rule indexes, points at
    /// review and re-signing.
    #[test]
    fn owner_signature_failure_hint_asks_to_review_and_re_sign() {
        for rules_with_signed_optional_keys in [vec![], vec![0, 2]] {
            let err = policy_load_failure(PolicyError::OwnerSignatureInvalid {
                profile: "alice".to_owned(),
                rules_with_signed_optional_keys,
            });
            assert_eq!(
                build_failure_next_step(&err, "alice").as_deref(),
                Some(
                    "review the V1 policy file and re-sign it with `stellar-agent profile \
                     sign-policy --profile alice`"
                )
            );
        }
    }

    /// A policy file that fails a body check, such as an unknown key, gets no
    /// signing hint: re-signing does not clear it.
    #[test]
    fn policy_parse_failure_gets_no_signing_hint() {
        let err = policy_load_failure(PolicyError::PolicyFileParseFailed {
            detail: "rule[0]: unknown key; a rule accepts match, criteria, decision, reason, \
                     ttl_secs, allow_opaque_signing"
                .to_owned(),
        });
        assert_eq!(build_failure_next_step(&err, "alice"), None);
    }

    /// A policy file that cannot be read points at creating it if missing,
    /// then signing it.
    #[test]
    fn unreadable_policy_file_hint_asks_to_create_and_sign_it() {
        let err = policy_load_failure(PolicyError::PolicyFileLoadFailed {
            detail: "alice.toml: No such file or directory".to_owned(),
        });
        assert_eq!(
            build_failure_next_step(&err, "alice").as_deref(),
            Some(
                "the V1 policy file could not be read; create it if it is missing, \
                 then sign it with `stellar-agent profile sign-policy --profile alice`"
            )
        );
    }

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
            Err(ArgvError::Unrecognised)
        );
    }

    #[test]
    fn unknown_positional_token_is_rejected() {
        assert_eq!(parse(&["mainnet-prod"]), Err(ArgvError::Unrecognised));
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
        let usage = super::usage(super::INVOKED_NAME_ROUTE);
        assert!(usage.contains("--profile <NAME>"));
        assert!(usage.contains("STELLAR_AGENT_PROFILE"));
        assert!(usage.contains("A mainnet profile needs `--profile <NAME>`"));
        assert!(usage.contains("STELLAR_AGENT_PROFILE never selects a mainnet profile"));
        assert!(
            !usage.contains("Takes no arguments"),
            "the help text must not claim the binary takes no arguments"
        );
    }
    #[test]
    fn new_policy_codes_are_rendered_from_typed_causes() {
        let capture = stellar_agent_test_support::CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        for error in [
            PolicyError::SequenceRollback,
            PolicyError::SequenceFork,
            PolicyError::StateLockBusy,
            PolicyError::StateLockIo {
                kind: std::io::ErrorKind::PermissionDenied,
            },
            PolicyError::MainnetTableOnTestnet,
            PolicyError::MainnetMinimumUnmet {
                requirement: "scope",
                rule: None,
            },
        ] {
            let code = error.wire_code();
            super::report_build_failure(&policy_load_failure(error), "operator");
            assert!(capture.captured_str().contains(code));
        }
    }
}
