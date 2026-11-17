- The build dependency `zip` moves from 8.6.0 to 9.5.1 through
  `libsodium-sys-stable` 1.24.6, which resolves RUSTSEC-2026-0545,
  RUSTSEC-2026-0546, RUSTSEC-2026-0547, and RUSTSEC-2026-0548. `zip` runs only
  in the `libsodium-sys-stable` build script and is not linked into the
  binaries.
- `deny.toml` accepts RUSTSEC-2026-0543: `chrono` 0.4.45 is unmaintained, and
  no release resolves the advisory. Only `rmcp`, `schemars`, and `serde-aux`
  depend on it, and no wallet crate calls it.
