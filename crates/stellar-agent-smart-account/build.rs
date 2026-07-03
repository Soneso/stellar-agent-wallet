//! Build-time integrity checks for vendored smart-account WASM artefacts.

#![allow(clippy::print_stdout)]

use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

struct WasmPin {
    label: &'static str,
    path: &'static str,
    expected_sha256: &'static str,
}

const WASM_PINS: &[WasmPin] = &[
    WasmPin {
        label: "stellar_accounts.wasm",
        path: "../../vendor/oz-stellar-accounts/v0.7.1/stellar_accounts.wasm",
        expected_sha256: "5603378c6039b5ccd4038d04a261d5f08467d5f68046e863b40ca85e4d779322",
    },
    WasmPin {
        label: "multisig_account_example.wasm",
        path: "../../vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm",
        expected_sha256: "06186e938a0ba1585a5d8a6d2ec802f3d184aaf9ec298d8c8aece50ca56cb239",
    },
    WasmPin {
        label: "multisig_webauthn_verifier_example.wasm",
        path: "../../vendor/oz-webauthn-verifier/v0.7.1/multisig_webauthn_verifier_example.wasm",
        expected_sha256: "678006909b50c6c365c033f137197e910d8396a2c68e9281327a2ed7dbf4b27a",
    },
    WasmPin {
        label: "multicall.wasm",
        path: "../../vendor/multicall/v0.1.0/multicall.wasm",
        expected_sha256: "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4",
    },
    // OZ timelock-controller-example v0.7.1 WASM.
    WasmPin {
        label: "timelock_controller_example.wasm",
        path: "../../vendor/oz-timelock-controller/v0.7.1/timelock_controller_example.wasm",
        expected_sha256: "36299255cf77678a59d7fdfe9823d803be2bdddb9cc375be3130daed265295eb",
    },
];

fn main() {
    if let Err(err) = run() {
        let _ = writeln!(io::stderr(), "build.rs: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map_err(|err| format!("failed to read CARGO_MANIFEST_DIR: {err}"))?;
    let manifest_dir = PathBuf::from(manifest_dir);

    for pin in WASM_PINS {
        verify_wasm_pin(&manifest_dir, pin)?;
    }

    Ok(())
}

fn verify_wasm_pin(manifest_dir: &Path, pin: &WasmPin) -> Result<(), String> {
    let path = manifest_dir.join(pin.path);
    println!("cargo:rerun-if-changed={}", path.display());

    let bytes = fs::read(&path)
        .map_err(|err| format!("failed to read {} at {}: {err}", pin.label, path.display()))?;
    let actual = hex_lower(Sha256::digest(bytes));

    if actual == pin.expected_sha256 {
        return Ok(());
    }

    Err(format!(
        "WASM SHA-256 mismatch for {} at {}: expected {}, got {}. \
         Re-vendor the WASM, update the matching *_WASM_SHA256 const and \
         PROVENANCE.md, then rebuild.",
        pin.label,
        path.display(),
        pin.expected_sha256,
        actual
    ))
}

fn hex_lower(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }

    out
}
