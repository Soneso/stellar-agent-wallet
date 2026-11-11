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

/// Captures one test with explicit child environment overlays.
pub(crate) fn capture_with_env(name: &str, env: &[(&str, &str)]) -> Option<(String, String)> {
    const CHILD: &str = "CLI_TEST_CAPTURE_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return None;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([name, "--nocapture", "--test-threads=1", "--format=terse"])
        .env(CHILD, name)
        .envs(env.iter().copied())
        .env("STELLAR_AGENT_TEST_PRESENCE_NO_BROWSER", "1")
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stdout}\n{stderr}");
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
