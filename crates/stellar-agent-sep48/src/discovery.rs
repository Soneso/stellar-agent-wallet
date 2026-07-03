//! SEP-47 Contract Interface Discovery.
//!
//! # Overview
//!
//! SEP-47 ("Contract Interface Discovery") defines a way for contracts to claim
//! which Stellar Ecosystem Proposals (SEPs) they implement. A contract stores a
//! comma-separated list of SEP identifiers in the `sep` key of the SEP-46
//! `Contract Meta` (`contractmetav0`) custom section of its WASM file.
//!
//! This module provides a separate, lighter read path for discovering claimed
//! SEPs from a contract's `contractmetav0` section. It shares the WASM fetch
//! with the spec-section parse but parses a different section, so callers that
//! only need SEP-47 claim-discovery do not pay the cost of parsing the full
//! `contractspecv0` section.
//!
//! # SEP-47 specification
//!
//! The SEP-47 specification §"Specification":
//! - Meta entry key: `sep`.
//! - Meta entry value: comma-separated SEP identifiers with leading zeros
//!   stripped; e.g. `"41,40"`.
//! - Multiple `sep` entries may exist; their values are joined with `,`.
//!
//! # KMP reference
//!
//! KMP Stellar SDK `SorobanContractParser.kt`: splits `metaEntries["sep"]` on
//! `,`, trims, deduplicates. This module mirrors that logic.
//!
//! # WASM fetch path
//!
//! The WASM bytes are fetched via [`crate::spec::fetch_wasm_bytes`].
//! NOTE: The in-process SPEC_CACHE stores parsed `Vec<ScSpecEntry>` (not raw
//! WASM bytes), so `discover_claimed_seps` fetches the WASM independently of
//! the SEP-48 spec path. The two caches are separate: SPEC_CACHE covers the
//! SEP-48 spec-section parse; the SEP-47 discovery path always re-fetches
//! WASM bytes from the RPC on a cache miss.
//!
//! # Unverified-claim notice
//!
//! Per SEP-47 semantics, the `sep` meta entry is an UNVERIFIED contract
//! self-claim. A contract may list any SEP identifier without proof that it
//! actually implements the SEP's interface. Callers MUST NOT trust the SEP
//! list as a security gate without independent verification.

use crate::error::Sep48Error;

/// Discovers which SEPs a contract claims to implement.
///
/// Fetches the contract WASM and reads the `contractmetav0` `sep` meta entry
/// per SEP-47. The result is a sorted, deduplicated list of SEP identifier
/// strings with leading zeros stripped.
///
/// # Arguments
///
/// * `rpc_url` — the Stellar RPC endpoint to query.
/// * `contract_strkey` — the C-strkey of the contract.
///
/// # Returns
///
/// A sorted, deduplicated `Vec<String>` of SEP identifiers. Returns an empty
/// Vec if the contract has no `sep` meta entry.
///
/// # UNVERIFIED SELF-CLAIM
///
/// The returned `supported_seps` list is an unverified contract self-claim per
/// SEP-47 semantics. A contract may list any SEP identifier without proof that
/// it actually implements the SEP's interface.
///
/// # Errors
///
/// - [`Sep48Error::InvalidContractAddress`] — invalid C-strkey.
/// - [`Sep48Error::RpcFetchFailure`] — WASM fetch failed.
pub async fn discover_claimed_seps(
    rpc_url: &str,
    contract_strkey: &str,
) -> Result<Vec<String>, Sep48Error> {
    let wasm_bytes = crate::spec::fetch_wasm_bytes(rpc_url, contract_strkey).await?;
    let seps = extract_seps_from_wasm(&wasm_bytes);
    Ok(seps)
}

/// Extracts the claimed SEP identifiers from the `contractmetav0` custom
/// section of a WASM file.
///
/// Uses `wasmparser` to iterate WASM payloads and find the `contractmetav0`
/// custom section. This replaces any byte-search approach which is vulnerable
/// to data-section collision: a malicious WASM could plant the section name
/// marker in a data section or function body, producing false positives.
/// `wasmparser::Parser::parse_all` correctly identifies only actual custom
/// sections.
///
/// # SEP-47 parsing logic
///
/// 1. Iterate WASM payloads via `wasmparser::Parser::parse_all` matching
///    `Payload::CustomSection { name: "contractmetav0", .. }`.
/// 2. Decode the section data as a stream of `SCMetaEntry` XDR values.
/// 3. Collect all `key == "sep"` values.
/// 4. Join with `,`, split on `,`, trim, strip leading zeros, deduplicate,
///    sort numerically.
///
/// Returns an empty Vec if the `contractmetav0` section is absent or has no
/// `sep` entry.
///
/// # UNVERIFIED SELF-CLAIM
///
/// The returned SEP identifiers are unverified contract self-claims per SEP-47
/// semantics.
///
/// # Why `soroban_spec_tools::contract::Spec::new` is NOT used here
///
/// `soroban_spec_tools::contract::Spec::new` is intentionally not reused for
/// the meta section because it decodes with `Limits::none()` (unbounded
/// depth/length — the untrusted-XDR DoS vector this crate guards against) and
/// fails hard on a malformed tail, whereas this function applies
/// `untrusted_decode_limits` and tolerates a malformed tail.
///
/// # KMP reference
///
/// KMP Stellar SDK `SorobanContractParser.kt`: iterates `SCMetaEntryXdr`
/// from the `contractmetav0` section; `SorobanContractInfo.supportedSeps`
/// splits and trims the `"sep"` value.
pub fn extract_seps_from_wasm(wasm_bytes: &[u8]) -> Vec<String> {
    use stellar_agent_xdr_limits::untrusted_decode_limits;
    use stellar_xdr::{ReadXdr, ScMetaEntry, ScMetaV0};
    use wasmparser::{Parser, Payload};

    // ── 1. Find the contractmetav0 custom section via wasmparser ─────────────
    // `wasmparser::Parser::parse_all` correctly iterates all WASM sections
    // without false-positives from data sections or function bodies.
    let parser = Parser::new(0);
    let mut meta_data: Option<Vec<u8>> = None;
    for payload in parser.parse_all(wasm_bytes) {
        let payload = match payload {
            Ok(p) => p,
            Err(_) => break, // malformed WASM — stop iteration, return empty
        };
        if let Payload::CustomSection(section) = payload
            && section.name() == "contractmetav0"
        {
            meta_data = Some(section.data().to_vec());
            break;
        }
    }

    let meta_data = match meta_data {
        Some(d) if !d.is_empty() => d,
        _ => return vec![],
    };

    // ── 2. Decode SCMetaEntry XDR stream ─────────────────────────────────────
    // The section is a stream of XDR-encoded `SCMetaEntry` values appended
    // with no frame — identical to the contractspecv0 section encoding per the
    // SEP-48 specification §"XDR Encoding".
    // The meta section bytes originate from the network (untrusted on-chain
    // source); bounded depth+len limits prevent stack exhaustion and oversized
    // allocations.
    let mut sep_values: Vec<String> = Vec::new();
    let mut cursor = std::io::Cursor::new(meta_data.as_slice());
    let mut limited =
        stellar_xdr::Limited::new(&mut cursor, untrusted_decode_limits(meta_data.len()));

    // Iterate the XDR stream; stop on the first parse error or non-V0 entry.
    // Malformed tail entries are common in real contracts and should not abort
    // the whole read. `while let` terminates on Err OR on a non-ScMetaV0
    // variant (unknown/future entry types), which is the safe default per the
    // SEP-47 spec's "stop on unknown" convention.
    while let Ok(ScMetaEntry::ScMetaV0(ScMetaV0 { key, val })) = ScMetaEntry::read_xdr(&mut limited)
    {
        if key.to_utf8_string_lossy() == "sep" {
            sep_values.push(val.to_utf8_string_lossy());
        }
    }

    if sep_values.is_empty() {
        return vec![];
    }

    // ── 3. Join, split, trim, deduplicate, sort ───────────────────────────────
    // Per SEP-47: multiple `sep` entries are joined.
    let combined = sep_values.join(",");
    let mut seps: Vec<String> = combined
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        // Strip leading zeros per SEP-47 §"Meta Entry Value": identifiers
        // should be included without leading zeros (e.g. `41,40`).
        .map(strip_leading_zeros)
        .collect();

    seps.sort_by(|a, b| {
        // Numeric sort: "41" < "10" if both parse, else lexicographic fallback.
        match (a.parse::<u32>(), b.parse::<u32>()) {
            (Ok(an), Ok(bn)) => an.cmp(&bn),
            _ => a.cmp(b),
        }
    });
    seps.dedup();
    seps
}

/// Strips leading zeros from a SEP identifier string.
///
/// Per the SEP-47 specification: identifiers are stored without leading zeros
/// (e.g. `"41"` not `"041"`).
fn strip_leading_zeros(s: &str) -> String {
    let stripped = s.trim_start_matches('0');
    if stripped.is_empty() {
        "0".to_owned()
    } else {
        stripped.to_owned()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in unit tests"
)]
mod tests {
    use super::*;
    use stellar_xdr::{Limits, ScMetaEntry, ScMetaV0, WriteXdr};

    // ── WASM custom-section builder ───────────────────────────────────────────

    /// Builds a minimal valid WASM byte sequence containing a single custom
    /// section with the given `section_name` and `section_data`.
    ///
    /// WASM custom section binary layout (WASM spec §5.5.7):
    ///   `id=0x00 | size (LEB128) | name_len (LEB128) | name_bytes | data_bytes`
    ///
    /// Sizes must fit in a single LEB128 byte (< 128). All realistic
    /// `contractmetav0` payloads used in unit tests are well within this limit.
    fn build_wasm_with_custom_section(section_name: &str, data: &[u8]) -> Vec<u8> {
        let name_bytes = section_name.as_bytes();
        assert!(
            name_bytes.len() < 128,
            "section name too long for single-byte LEB128"
        );
        // Section body = 1 byte (name_len) + name_bytes + data
        let body_len = 1 + name_bytes.len() + data.len();
        assert!(
            body_len < 128,
            "section body too large for single-byte LEB128 in test"
        );
        let mut wasm = b"\x00asm\x01\x00\x00\x00".to_vec();
        wasm.push(0x00); // custom section id
        wasm.push(body_len as u8); // section size (LEB128)
        wasm.push(name_bytes.len() as u8); // name length (LEB128)
        wasm.extend_from_slice(name_bytes);
        wasm.extend_from_slice(data);
        wasm
    }

    /// XDR-encodes a stream of `ScMetaV0` entries into a byte vec.
    fn encode_meta_entries(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut buf = Vec::new();
        for (key, val) in entries {
            let entry = ScMetaEntry::ScMetaV0(ScMetaV0 {
                key: key.parse().unwrap(),
                val: val.parse().unwrap(),
            });
            entry
                .write_xdr(&mut stellar_xdr::Limited::new(&mut buf, Limits::none()))
                .unwrap();
        }
        buf
    }

    // ── strip_leading_zeros ───────────────────────────────────────────────────

    #[test]
    fn strip_leading_zeros_normal() {
        assert_eq!(strip_leading_zeros("041"), "41");
        assert_eq!(strip_leading_zeros("40"), "40");
        assert_eq!(strip_leading_zeros("41"), "41");
    }

    #[test]
    fn strip_leading_zeros_all_zeros() {
        assert_eq!(strip_leading_zeros("00"), "0");
        assert_eq!(strip_leading_zeros("0"), "0");
    }

    // ── extract_seps_from_wasm edge cases ─────────────────────────────────────

    #[test]
    fn extract_seps_empty_wasm() {
        // An empty WASM byte slice has no custom sections.
        let seps = extract_seps_from_wasm(&[]);
        assert!(seps.is_empty(), "empty WASM must return empty SEP list");
    }

    #[test]
    fn extract_seps_no_meta_section() {
        // A minimal valid WASM magic+version with no custom sections.
        // Magic: \0asm, version: 1 (4 bytes LE).
        let wasm = b"\0asm\x01\x00\x00\x00";
        let seps = extract_seps_from_wasm(wasm);
        assert!(seps.is_empty(), "WASM without contractmetav0 returns empty");
    }

    // ── extract_seps_from_wasm: contractmetav0 section coverage ───────────────

    /// A WASM with a `contractmetav0` section containing a single `sep` entry
    /// returns the exact parsed SEP identifier.
    ///
    /// Covers the main body of `extract_seps_from_wasm`:
    /// - wasmparser finds the `contractmetav0` section
    /// - XDR stream is decoded
    /// - Single SEP is returned without dedup
    #[test]
    fn extract_seps_single_sep_entry() {
        let data = encode_meta_entries(&[("sep", "41")]);
        let wasm = build_wasm_with_custom_section("contractmetav0", &data);
        let seps = extract_seps_from_wasm(&wasm);
        assert_eq!(
            seps,
            vec!["41".to_owned()],
            "single sep entry '41' must return [\"41\"]"
        );
    }

    /// A `sep` value with multiple comma-separated identifiers is split and
    /// each identifier is returned individually, sorted numerically.
    ///
    /// Covers the join/split/sort/dedup pipeline.
    #[test]
    fn extract_seps_comma_separated_in_single_entry() {
        let data = encode_meta_entries(&[("sep", "41,40,10")]);
        let wasm = build_wasm_with_custom_section("contractmetav0", &data);
        let seps = extract_seps_from_wasm(&wasm);
        // Numeric sort: 10 < 40 < 41
        assert_eq!(
            seps,
            vec!["10".to_owned(), "40".to_owned(), "41".to_owned()],
            "comma-separated SEP values must be split and sorted numerically"
        );
    }

    /// Multiple `sep` meta entries have their values joined before splitting.
    ///
    /// Per SEP-47: multiple `sep` entries are valid; their values are concatenated
    /// with `,` before splitting. Covers the `sep_values.join(",")` path.
    #[test]
    fn extract_seps_multiple_sep_entries_are_joined() {
        let data = encode_meta_entries(&[("sep", "41"), ("sep", "40")]);
        let wasm = build_wasm_with_custom_section("contractmetav0", &data);
        let seps = extract_seps_from_wasm(&wasm);
        // Both entries joined: "41,40" → sorted: ["40", "41"]
        assert_eq!(
            seps,
            vec!["40".to_owned(), "41".to_owned()],
            "multiple sep entries must be joined and returned as sorted list"
        );
    }

    /// A meta entry with a key other than `"sep"` is ignored; only `"sep"` keys
    /// contribute to the result.
    ///
    /// Covers the `if key == "sep"` filter.
    #[test]
    fn extract_seps_non_sep_meta_keys_are_ignored() {
        let data = encode_meta_entries(&[("version", "1.0"), ("sep", "41"), ("author", "test")]);
        let wasm = build_wasm_with_custom_section("contractmetav0", &data);
        let seps = extract_seps_from_wasm(&wasm);
        assert_eq!(
            seps,
            vec!["41".to_owned()],
            "only 'sep' keys must contribute to the result; 'version' and 'author' are ignored"
        );
    }

    /// Leading zeros in SEP identifiers are stripped per SEP-47.
    ///
    /// Covers the `strip_leading_zeros` map call.
    #[test]
    fn extract_seps_leading_zeros_are_stripped() {
        let data = encode_meta_entries(&[("sep", "041,040")]);
        let wasm = build_wasm_with_custom_section("contractmetav0", &data);
        let seps = extract_seps_from_wasm(&wasm);
        // "041" → "41", "040" → "40", sorted: ["40", "41"]
        assert_eq!(
            seps,
            vec!["40".to_owned(), "41".to_owned()],
            "leading zeros must be stripped from SEP identifiers"
        );
    }

    /// Duplicate SEP identifiers (across entries or within a comma list) are
    /// deduped in the output.
    ///
    /// Covers the `seps.dedup()` call.
    #[test]
    fn extract_seps_duplicates_are_removed() {
        let data = encode_meta_entries(&[("sep", "41,41,40"), ("sep", "41")]);
        let wasm = build_wasm_with_custom_section("contractmetav0", &data);
        let seps = extract_seps_from_wasm(&wasm);
        assert_eq!(
            seps,
            vec!["40".to_owned(), "41".to_owned()],
            "duplicate SEP identifiers must be deduped"
        );
    }

    /// A non-numeric SEP identifier participates in the lexicographic sort
    /// fallback (the `_ => a.cmp(b)` arm in the sort closure).
    ///
    /// Covers the `_ => a.cmp(b)` arm in the sort closure.
    #[test]
    fn extract_seps_non_numeric_identifier_uses_lexicographic_sort() {
        let data = encode_meta_entries(&[("sep", "DRAFT-3,41")]);
        let wasm = build_wasm_with_custom_section("contractmetav0", &data);
        let seps = extract_seps_from_wasm(&wasm);
        // "41" parses as u32; "DRAFT-3" does not. Mixed: numeric come first via
        // `(Ok, Err)` → the `_` arm fires for that pair; lexicographic comparison
        // puts "41" before "DRAFT-3" because '4' (0x34) < 'D' (0x44).
        assert_eq!(
            seps,
            vec!["41".to_owned(), "DRAFT-3".to_owned()],
            "numeric '41' must precede non-numeric 'DRAFT-3' via lexicographic fallback"
        );
    }

    /// A `contractmetav0` section that exists but contains zero bytes returns an
    /// empty SEP list. This covers the `Some(d) if !d.is_empty()` guard
    /// which returns `vec![]` for an empty data slice.
    #[test]
    fn extract_seps_empty_meta_section_data_returns_empty() {
        // Build WASM with contractmetav0 section but no data bytes.
        let wasm = build_wasm_with_custom_section("contractmetav0", &[]);
        let seps = extract_seps_from_wasm(&wasm);
        assert!(
            seps.is_empty(),
            "contractmetav0 section with no data must return empty SEP list"
        );
    }

    /// A `contractmetav0` section that contains truncated/garbage XDR bytes
    /// (not valid `ScMetaEntry` XDR) returns an empty SEP list rather than
    /// panicking. The `while let Ok(...)` loop terminates on the first parse error.
    ///
    /// Covers the `while let Ok(ScMetaEntry::ScMetaV0(...))` early-termination
    /// path when XDR parse fails.
    #[test]
    fn extract_seps_malformed_xdr_in_meta_section_returns_empty() {
        let garbage = b"\xff\xfe\xfd\xfc\x00\x00\x00\x00bad_xdr_content";
        let wasm = build_wasm_with_custom_section("contractmetav0", garbage);
        let seps = extract_seps_from_wasm(&wasm);
        assert!(
            seps.is_empty(),
            "malformed XDR in contractmetav0 section must return empty (not panic), got: {seps:?}"
        );
    }

    /// A non-`contractmetav0` custom section with the same data is not confused
    /// as a SEP-47 meta section. Only sections named exactly "contractmetav0"
    /// are processed.
    ///
    /// Covers the `section.name() == "contractmetav0"` name-check gate.
    #[test]
    fn extract_seps_wrong_section_name_is_ignored() {
        let data = encode_meta_entries(&[("sep", "41")]);
        // Use "contractmetav1" (a hypothetical future name) — must NOT be read.
        let wasm = build_wasm_with_custom_section("contractmetav1", &data);
        let seps = extract_seps_from_wasm(&wasm);
        assert!(
            seps.is_empty(),
            "section named 'contractmetav1' must be ignored; only 'contractmetav0' is valid"
        );
    }

    /// When the meta section contains a valid entry followed by garbage XDR, the
    /// valid entries before the parse error are still processed and the
    /// `while let` terminates cleanly without panicking.
    ///
    /// Covers the partial-parse-and-stop behavior of the XDR stream loop.
    #[test]
    fn extract_seps_valid_entry_then_garbage_returns_partial_result() {
        // First entry: valid "sep" = "41"
        let mut data = encode_meta_entries(&[("sep", "41")]);
        // Append garbage that will fail the next XDR parse iteration.
        data.extend_from_slice(b"\xff\xfe\xfd\xfc");
        let wasm = build_wasm_with_custom_section("contractmetav0", &data);
        let seps = extract_seps_from_wasm(&wasm);
        // The first entry is decoded successfully; the loop terminates on the
        // garbage tail without losing the already-accumulated value.
        assert_eq!(
            seps,
            vec!["41".to_owned()],
            "valid entry before garbage tail must be included in result"
        );
    }

    /// Verifies that a WASM with a code section containing the bytes
    /// "contractmetav0" does NOT return false SEP entries — the wasmparser
    /// approach correctly identifies custom sections only.
    ///
    /// A prior byte-search approach was vulnerable to data-section collision:
    /// a malicious WASM planting the marker in a function body would have
    /// produced false SEP entries. `wasmparser` only yields
    /// `Payload::CustomSection` for actual custom sections.
    #[test]
    fn code_section_contractmetav0_marker_not_confused_as_custom_section() {
        // Minimal valid WASM with a code section that contains the
        // "contractmetav0" byte sequence inside a function body.
        // WASM binary layout:
        //   \0asm\x01\x00\x00\x00          (magic + version)
        //   section_id=0x0a (code section)
        //     size (LEB128)
        //     ... "\x0econtractmetav0" bytes embedded in code body ...
        //
        // We embed the exact bytes that would trip a byte-search:
        // 0x0e (LEB128 14) + "contractmetav0" (14 bytes) = the old pattern.
        // wasmparser parses this as a code section body, NOT a custom section.
        let marker = b"\x0econtractmetav0";
        // A minimal code section: 1 function, body = [0x0b (end)] with marker prepended.
        // Code section body format: count (1) + body_size (LEB128) + locals_count (0) + expr
        let mut code_body: Vec<u8> = Vec::new();
        code_body.push(0x01); // 1 function
        let func_body_content: Vec<u8> = {
            let mut b = vec![0x00u8]; // 0 locals
            b.extend_from_slice(marker); // embed the marker bytes
            b.push(0x0b); // end
            b
        };
        // body_size as single-byte LEB128
        #[allow(clippy::cast_possible_truncation)]
        code_body.push(func_body_content.len() as u8);
        code_body.extend_from_slice(&func_body_content);

        let mut wasm_bytes: Vec<u8> = b"\x00asm\x01\x00\x00\x00".to_vec();
        wasm_bytes.push(0x0a); // code section id
        #[allow(clippy::cast_possible_truncation)]
        wasm_bytes.push(code_body.len() as u8); // section size
        wasm_bytes.extend_from_slice(&code_body);

        let seps = extract_seps_from_wasm(&wasm_bytes);
        assert!(
            seps.is_empty(),
            "contractmetav0 bytes inside code section must NOT produce false SEP entries, got: {seps:?}"
        );
    }
}
