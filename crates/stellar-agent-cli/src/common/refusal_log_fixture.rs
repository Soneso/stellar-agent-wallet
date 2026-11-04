//! Debug-level log capture for commands refused on an absent profile.
//!
//! A profile name that resolves to no profile file is rejected input. The
//! refusal event a command emits names the class of the failure and never the
//! requested name. The helpers here run a command against an empty
//! `STELLAR_AGENT_HOME` under a credential-like profile name and return what a
//! debug-level subscriber captured, so each command family pins that rule on
//! its own command path.

#![allow(
    clippy::expect_used,
    reason = "test-only fixture; a failed runtime or temp dir aborts the test"
)]

use std::future::Future;
use std::path::Path;

use stellar_agent_test_support::log_capture::{CaptureWriter, inert_dispatcher};

/// The requested profile name.
///
/// It is a valid path component, so the loader reaches the profile directory
/// and refuses with its not-found class rather than a name-validation class.
pub(crate) const ABSENT_PROFILE_MARKER: &str = "CREDMARKER7";

/// The loader's not-found text, which the refusal event carries in `error`.
const NOT_FOUND_TEXT: &str = "the requested profile was not found";

/// Runs the command `start` builds under a debug-level capture and returns
/// its exit code with the captured text.
///
/// `start` receives the empty home directory the command runs against. The
/// command runs to completion on a current-thread runtime, so every event it
/// emits reaches the thread's default subscriber. An inert dispatcher created
/// before the capture's and kept alive until the command ends makes `tracing`
/// consult the capture for every callsite, and the interest cache is rebuilt
/// once the capture is the default, so a neighboring test cannot leave a
/// callsite cached as disabled.
///
/// The caller holds `#[serial]`: the helper sets `STELLAR_AGENT_HOME` for the
/// duration of the command.
pub(crate) fn capture_absent_profile_refusal<F, Fut>(start: F) -> (i32, String)
where
    F: FnOnce(&Path) -> Fut,
    Fut: Future<Output = i32>,
{
    let home = tempfile::tempdir().expect("test home");
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");
    let capture = CaptureWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(capture.clone())
        .finish();
    let inert = inert_dispatcher();
    let code = tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        runtime.block_on(start(home.path()))
    });
    drop(inert);
    (code, capture.captured_str())
}

/// Asserts that the command refused the absent profile, that the capture
/// holds the refusal event `message` with the loader's not-found class, and
/// that no captured event carries the requested name.
pub(crate) fn assert_refusal_omits_requested_profile(code: i32, logs: &str, message: &str) {
    assert_eq!(code, 1, "an absent profile must refuse the command");
    assert!(
        logs.contains(message),
        "the capture must hold the refusal event `{message}`; captured: {logs}"
    );
    assert!(
        logs.contains(NOT_FOUND_TEXT),
        "the refusal event must carry the loader's not-found class; captured: {logs}"
    );
    assert!(
        !logs.contains(ABSENT_PROFILE_MARKER),
        "no captured event may carry the requested profile name; captured: {logs}"
    );
}
