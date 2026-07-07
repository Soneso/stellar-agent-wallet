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
        path: "vendor/oz-stellar-accounts/v0.7.2/stellar_accounts.wasm",
        expected_sha256: "b0ac8ad7156957757de89ea3dc00ed4d7d0148d273c12af52dfaa15252240c83",
    },
    WasmPin {
        label: "multisig_account_example.wasm",
        path: "vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm",
        expected_sha256: "5bc710da20f401665f0b48ceb008c4cd313c933dbb4aeb7b54d2aacd5646e286",
    },
    WasmPin {
        label: "multisig_webauthn_verifier_example.wasm",
        path: "vendor/oz-webauthn-verifier/v0.7.2/multisig_webauthn_verifier_example.wasm",
        expected_sha256: "9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7",
    },
    WasmPin {
        label: "multicall.wasm",
        path: "vendor/multicall/v0.1.0/multicall.wasm",
        expected_sha256: "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4",
    },
    // OZ timelock-controller-example v0.7.2 WASM.
    WasmPin {
        label: "timelock_controller_example.wasm",
        path: "vendor/oz-timelock-controller/v0.7.2/timelock_controller_example.wasm",
        expected_sha256: "ef360d61a44648176f0aae923b9884c6ac5e5a9229af5eb8ab120e81cc4cc1f4",
    },
    // OZ multisig-threshold-policy-example v0.7.2 WASM. This is the deploy-time
    // artefact embedded by policy_identification.rs::THRESHOLD_POLICY_WASM
    // (THRESHOLD_POLICY_WASM_HASHES[0]); every deploy-time artefact carries a
    // compile-time pin here.
    WasmPin {
        label: "multisig_threshold_policy_example.wasm",
        path: "vendor/oz-threshold-policy/v0.7.2/multisig_threshold_policy_example.wasm",
        expected_sha256: "4c14f402df29675d4155283698c436ee588aacb39adc313845010a565c07567d",
    },
    // OZ multisig-ed25519-verifier-example v0.7.2 WASM. Deploy-time artefact
    // embedded by ed25519_verifier.rs::ED25519_VERIFIER_WASM; the deployable
    // Ed25519 signature verifier for External-Ed25519 signers.
    WasmPin {
        label: "multisig_ed25519_verifier_example.wasm",
        path: "vendor/oz-ed25519-verifier/v0.7.2/multisig_ed25519_verifier_example.wasm",
        expected_sha256: "ea13b07083a8275e7bade954e4ccc1827495f253c18dc06edcc49104c11fb725",
    },
    // OZ multisig-spending-limit-policy-example v0.7.2 WASM. Deploy-time artefact
    // embedded by spending_limit_policy.rs::SPENDING_LIMIT_POLICY_WASM; the
    // deployable per-network spending-limit policy singleton.
    WasmPin {
        label: "multisig_spending_limit_policy_example.wasm",
        path: "vendor/oz-spending-limit-policy/v0.7.2/multisig_spending_limit_policy_example.wasm",
        expected_sha256: "0e8da0ccff5c444520085ac1973d3c8023fdd04f727ee11ae7290a49dffbbaf5",
    },
    // OZ multisig-weighted-threshold-policy-example v0.7.2 WASM. Deploy-time
    // artefact embedded by
    // weighted_threshold_policy.rs::WEIGHTED_THRESHOLD_POLICY_WASM; the
    // deployable per-network weighted-threshold policy singleton.
    WasmPin {
        label: "multisig_weighted_threshold_policy_example.wasm",
        path: "vendor/oz-weighted-threshold-policy/v0.7.2/multisig_weighted_threshold_policy_example.wasm",
        expected_sha256: "e3d8cc5ab9668526d5cf2bab17ee42e84ee4b972ba7cca8d3a37b2ed8d9baee3",
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
