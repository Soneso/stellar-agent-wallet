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

#[tokio::main]
async fn main() {
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

    // ── 4. Load active profile ───────────────────────────────────────────────
    // Per-invocation profile selection (a `--profile <name>` flag) is not wired;
    // the server loads the default profile, or falls back to a synthesised
    // testnet default if no profile file exists yet (covers the first-run case
    // where the user has not run `stellar-agent profile init`).
    // The fallback profile is a synthesised testnet default with placeholder
    // keyring coordinates.  Any tool that touches the keyring (e.g.
    // `stellar_create_account_commit`) will return `KeyringNotFound` until the
    // user runs `stellar-agent profile init` to create a real profile and
    // register a signing key.  This is the intended behaviour: the fallback
    // profile enables `stellar_balances` and `stellar_create_account` (simulate
    // step, which does NOT touch the signer keyring) without requiring a prior
    // setup step.
    let profile = match loader::load_default_or_testnet_fallback() {
        Ok(p) => {
            tracing::info!(
                chain_id = %p.chain_id,
                "stellar-agent-mcp: profile loaded"
            );
            p
        }
        Err(err) => {
            tracing::error!(
                error = %err,
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

    // ── 5. Start MCP server ───────────────────────────────────────────────────
    if let Err(err) = transport::run(profile).await {
        tracing::error!(error = %err, "stellar-agent-mcp: server error");
        std::process::exit(1);
    }
}
