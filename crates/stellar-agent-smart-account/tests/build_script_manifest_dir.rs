//! The build script refuses a `CARGO_MANIFEST_DIR` that is not valid UTF-8
//! with a fixed line on stderr that holds none of the refused bytes.

#![cfg(unix)]
#![allow(clippy::unwrap_used, reason = "test assertions")]

#[path = "../build.rs"]
mod build_script;

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::process::Command;

const CHILD_SWITCH: &str = "STELLAR_AGENT_BUILD_SCRIPT_CHILD";
const TEST_NAME: &str = "a_manifest_dir_outside_utf8_stays_out_of_the_refusal";

#[test]
fn a_manifest_dir_outside_utf8_stays_out_of_the_refusal() {
    if std::env::var_os(CHILD_SWITCH).is_some() {
        build_script::main();
        return;
    }

    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
        .env(CHILD_SWITCH, "1")
        .env(
            "CARGO_MANIFEST_DIR",
            OsStr::from_bytes(b"/tmp/credmarker7\xff"),
        )
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert_eq!(
        stderr.trim_end(),
        "build.rs: CARGO_MANIFEST_DIR must name the project directory using valid UTF-8; \
         rebuild from the project directory."
    );
}
