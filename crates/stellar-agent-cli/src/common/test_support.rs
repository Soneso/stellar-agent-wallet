//! Output capture and filesystem snapshots for CLI tests.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test assertions")]

/// Snapshots sorted relative paths and file contents beneath the root.
pub(crate) fn tree(root: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    fn walk(
        root: &std::path::Path,
        dir: &std::path::Path,
        out: &mut Vec<(std::path::PathBuf, Vec<u8>)>,
    ) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            out.push((
                path.strip_prefix(root).unwrap().to_owned(),
                if path.is_file() {
                    std::fs::read(&path).unwrap()
                } else {
                    Vec::new()
                },
            ));
            if path.is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut result = Vec::new();
    walk(root, root, &mut result);
    result.sort();
    result
}

/// Captures the real output streams of one unit-test process.
pub(crate) fn capture(name: &str) -> Option<(String, String)> {
    capture_with_env(name, &[])
}

const CHILD: &str = "CLI_TEST_CAPTURE_CHILD";

/// The child test process that runs only `name`, with `env` overlaid.
fn child_command(name: &str, env: &[(&str, &str)]) -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([name, "--nocapture", "--test-threads=1", "--format=terse"])
        .env(CHILD, name)
        .envs(env.iter().copied())
        .env("STELLAR_AGENT_TEST_PRESENCE_NO_BROWSER", "1")
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY");
    command
}

/// Captures one test with explicit child environment overlays.
pub(crate) fn capture_with_env(name: &str, env: &[(&str, &str)]) -> Option<(String, String)> {
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return None;
    }
    let output = child_command(name, env).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("1 passed"), "{stdout}");
    Some((stdout, stderr))
}

/// A child process that is killed and reaped when the guard drops, so a
/// panic on any path leaves no child running.
struct ChildGuard(std::process::Child);

impl ChildGuard {
    /// Kills and reaps the child; a child that already exits is reaped only.
    fn stop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Captures one test like [`capture`], ending the child at `deadline`.
///
/// A child still running at the deadline is killed, and the call fails with
/// the elapsed time and the output captured so far.
pub(crate) fn capture_within(
    name: &str,
    deadline: std::time::Duration,
) -> Option<(String, String)> {
    use std::io::Read as _;
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return None;
    }
    let started = std::time::Instant::now();
    let mut child = ChildGuard(
        child_command(name, &[])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let drain = |mut pipe: Box<dyn std::io::Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes).unwrap();
            String::from_utf8_lossy(&bytes).into_owned()
        })
    };
    let stdout = drain(Box::new(child.0.stdout.take().unwrap()));
    let stderr = drain(Box::new(child.0.stderr.take().unwrap()));
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break Some(status);
        }
        if started.elapsed() >= deadline {
            child.stop();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let (stdout, stderr) = (stdout.join().unwrap(), stderr.join().unwrap());
    assert!(
        status.is_some(),
        "the child runs past {deadline:?}; {:?} elapse before it stops\n{stdout}\n{stderr}",
        started.elapsed()
    );
    assert!(status.unwrap().success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("1 passed"), "{stdout}");
    Some((stdout, stderr))
}

/// Asserts one stdout envelope and exactly one localhost URL line on stderr.
pub(crate) fn assert_url_output(stdout: &str, stderr: &str) {
    assert!(
        !stdout.contains("http://"),
        "URL stays off stdout: {stdout}"
    );
    let lines: Vec<_> = stderr
        .lines()
        .filter(|line| line.starts_with("Open this URL in your browser: "))
        .collect();
    assert_eq!(lines.len(), 1, "one URL line: {stderr}");
    assert!(lines[0].contains("http://localhost:"), "{stderr}");
    let payload: Vec<_> = stdout
        .lines()
        .filter(|line| {
            !line.trim().is_empty()
                && *line != "running 1 test"
                && *line != "."
                && !line.starts_with("test result: ok.")
        })
        .collect();
    assert_eq!(payload.len(), 1, "one envelope: {stdout}");
    let envelope: serde_json::Value =
        serde_json::from_str(payload[0]).expect("stdout is one JSON envelope");
    assert!(envelope.get("ok").is_some());
}
