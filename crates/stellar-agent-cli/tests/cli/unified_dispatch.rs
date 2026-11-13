//! Process-role selection and initialization through copied executables.

#![allow(clippy::expect_used, clippy::unwrap_used, reason = "test assertions")]

use std::path::PathBuf;
use std::process::{Child, Command, Output};
use std::time::Duration;

use serial_test::serial;

pub(super) struct Binary {
    pub(super) home: tempfile::TempDir,
    path: PathBuf,
}

impl Binary {
    pub(super) fn new(name: &str) -> Self {
        let home = tempfile::tempdir().expect("isolated home");
        let path = home
            .path()
            .join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
        std::fs::copy(env!("CARGO_BIN_EXE_stellar-agent"), &path).expect("copy executable");
        Self { home, path }
    }

    pub(super) fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.path);
        command
            .args(args)
            .current_dir(self.home.path())
            .env("STELLAR_AGENT_HOME", self.home.path())
            .env(
                "STELLAR_AGENT_TEST_INIT_TRACE",
                self.home.path().join("trace"),
            )
            .env_remove("STELLAR_AGENT_PROFILE")
            .env_remove("RUST_LOG")
            .env("STELLAR_AGENT_LOG", "error")
            .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
            .env(
                "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            );
        command
    }

    fn retry_start<T>(mut start: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
        // Forks can retain the copy's write handle until exec; only ExecutableFileBusy retries,
        // at most 50 tries, 20 ms apart.
        let mut attempts = 0;
        loop {
            attempts += 1;
            match start() {
                Err(error)
                    if error.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 50 =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                result => return result,
            }
        }
    }

    pub(super) fn spawn(command: &mut Command) -> std::io::Result<Child> {
        Self::retry_start(|| command.spawn())
    }

    pub(super) fn output(command: &mut Command) -> std::io::Result<Output> {
        Self::retry_start(|| command.output())
    }

    fn run(&self, args: &[&str]) -> Output {
        Self::output(&mut self.command(args)).expect("copied executable runs")
    }
}

#[test]
fn start_retries_only_executable_file_busy() {
    use std::io::ErrorKind;

    let mut attempts = 0;
    let started = std::time::Instant::now();
    Binary::retry_start(|| {
        attempts += 1;
        if attempts == 1 {
            Err(ErrorKind::ExecutableFileBusy.into())
        } else {
            Ok(())
        }
    })
    .expect("busy executable becomes runnable");
    assert_eq!(attempts, 2);
    assert!(started.elapsed() >= Duration::from_millis(20));

    for kind in [
        ErrorKind::PermissionDenied,
        ErrorKind::NotFound,
        ErrorKind::Interrupted,
        ErrorKind::WouldBlock,
        ErrorKind::ExecutableFileBusy,
    ] {
        let mut attempts = 0;
        let result = Binary::retry_start(|| {
            attempts += 1;
            Err::<(), _>(std::io::Error::from(kind))
        });
        assert_eq!(result.expect_err("start fails").kind(), kind);
        assert_eq!(
            attempts,
            if kind == ErrorKind::ExecutableFileBusy {
                50
            } else {
                1
            }
        );
    }
}

fn version(output: &Output, name: &str) {
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        text.lines().next(),
        Some(format!("{name} {}", env!("CARGO_PKG_VERSION")).as_str())
    );
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
#[serial]
fn server_name_copy_serves() {
    version(
        &Binary::new("stellar-agent-mcp").run(&["--version"]),
        "stellar-agent-mcp",
    );
}

#[test]
#[serial]
fn renamed_copies_run_the_tool() {
    for name in ["wallet-x", "stellar-agent-mcp-old"] {
        version(&Binary::new(name).run(&["--version"]), "stellar-agent");
    }
}

#[test]
#[serial]
fn mcp_serve_only_as_first_two_args() {
    let binary = Binary::new("wallet-x");
    version(
        &binary.run(&["mcp", "serve", "--version"]),
        "stellar-agent-mcp",
    );
    for (args, code) in [
        (&["pay", "mcp", "serve"][..], "validation.address_invalid"),
        (&["mcp"][..], "validation.usage_error"),
    ] {
        let output = binary.run(args);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("usage envelope");
        assert_eq!(envelope["ok"], false);
        assert_eq!(envelope["error"]["code"], code);
    }
}

fn usage(name: &str, args: &[&str], display_name: &str) {
    let output = Binary::new(name).run(args);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .lines()
            .any(|line| line == format!("Usage: {display_name} [OPTIONS]")),
        "{output:?}"
    );
}

#[test]
#[serial]
fn mcp_serve_usage_names_the_subcommand() {
    usage(
        "wallet-x",
        &["mcp", "serve", "--bogus"],
        "stellar-agent mcp serve",
    );
}

#[test]
#[serial]
fn server_name_usage_is_unchanged() {
    usage("stellar-agent-mcp", &["--bogus"], "stellar-agent-mcp");
}

#[test]
#[serial]
fn mcp_serve_forwards_profile() {
    let binary = Binary::new("wallet-x");
    for flag in [true, false] {
        let mut command = binary.command(&["mcp", "serve"]);
        let origin = if flag {
            command.args(["--profile", "missing-profile"]);
            "--profile"
        } else {
            command.env("STELLAR_AGENT_PROFILE", "missing-profile");
            "STELLAR_AGENT_PROFILE"
        };
        let output = Binary::output(&mut command).expect("profile refusal");
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(origin), "{stderr}");
        assert!(stderr.contains("has no profile file"), "{stderr}");
    }
}

#[test]
#[serial]
fn init_once_per_route() {
    // A newly added, uninstrumented boundary must not evade the runtime trace.
    let cli = include_str!("../../src/main.rs");
    let entry = include_str!("../../../stellar-agent-mcp/src/entry.rs");
    for source in [cli, entry] {
        assert_eq!(source.matches("Builder::new_multi_thread()").count(), 1);
        assert_eq!(source.matches("observability::init_subscriber(").count(), 1);
        assert!(
            !source.contains("set_hook("),
            "panic hooks belong to observability"
        );
    }
    assert_eq!(cli.matches("process_hardening::harden_process").count(), 1);
    for (name, args, server) in [
        ("stellar-agent-mcp", &[][..], true),
        ("wallet-x", &["mcp", "serve"][..], true),
        ("wallet-x", &["--version"][..], false),
    ] {
        let binary = Binary::new(name);
        let stderr = if server {
            super::unified_protocol::session(&binary, args).1
        } else {
            let output = binary.run(args);
            assert!(output.status.success(), "{output:?}");
            String::from_utf8(output.stderr).expect("stderr text")
        };
        assert!(!stderr.contains("subscriber init failed"), "{stderr}");
        let trace = std::fs::read_to_string(binary.home.path().join("trace"))
            .expect("initialization trace");
        for boundary in ["runtime", "hardening", "subscriber", "panic-hook"] {
            assert_eq!(
                trace.lines().filter(|line| *line == boundary).count(),
                1,
                "{name} {args:?}: {trace}"
            );
        }
        assert_eq!(
            trace
                .lines()
                .filter(|line| !line.starts_with("tool:"))
                .count(),
            4,
            "{trace}"
        );
    }
}
