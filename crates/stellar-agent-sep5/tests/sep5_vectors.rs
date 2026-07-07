//! SEP-5 published test-vector verification.
//!
//! This file verifies:
//! 1. The `m/44'/148'` intermediate key (hex) matches the published value for
//!    each test — this localises path-vs-leaf bugs.
//! 2. Each derived `G...` public address matches the published value for
//!    accounts 0-9 per test.
//! 3. Negative: invalid mnemonic → `DeriveError::InvalidMnemonic`.
//! 4. Negative: `index >= 2^31` → `DeriveError::IndexOutOfRange`.
//!
//! SECURITY NOTE: No `S...` strkey (Stellar secret seed) appears anywhere in
//! this file.  The test corpus is derived from the published G-address column
//! and the `m/44'/148'` hex-key column only.  The `S...` column in the spec
//! was deliberately omitted.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use stellar_agent_sep5::{DeriveError, Sep5Wallet};
use zeroize::Zeroizing;

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Derive the m/44'/148' intermediate key (32 bytes) from a 64-byte BIP-39
/// seed by running just the master + purpose + coin-type steps.
///
/// This is a white-box helper that re-runs the first two folds of
/// `Sep5Wallet::derive_account` but stops before the account index fold, so
/// the intermediate key can be asserted against the published hex.
///
/// `slip10` is a private module, so this helper re-computes the intermediate
/// key inline using the same `hmac` / `sha2` algorithm the crate uses.
fn compute_m44_148_key(seed_hex: &str) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha512;

    let seed_bytes = hex::decode(seed_hex).expect("valid hex seed");
    assert_eq!(seed_bytes.len(), 64, "BIP-39 seed must be 64 bytes");

    // Master key: HMAC-SHA512("ed25519 seed", seed)
    let mut mac = Hmac::<Sha512>::new_from_slice(b"ed25519 seed").unwrap();
    mac.update(&seed_bytes);
    let master = mac.finalize().into_bytes();

    // m/44': hardened child of master
    let m44 = hardened_ckd(&master[..32], &master[32..], 44);

    // m/44'/148': hardened child of m/44'
    let m44_148 = hardened_ckd(&m44[..32], &m44[32..], 148);

    let mut out = [0u8; 32];
    out.copy_from_slice(&m44_148[..32]);
    out
}

/// Single hardened CKD step: returns the 64-byte HMAC output.
fn hardened_ckd(key_par: &[u8], chain_par: &[u8], index: u32) -> Vec<u8> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha512;

    let mut data = [0u8; 37];
    // data[0] = 0x00
    data[1..33].copy_from_slice(key_par);
    let hardened = index | 0x8000_0000;
    data[33..37].copy_from_slice(&hardened.to_be_bytes());

    let mut mac = Hmac::<Sha512>::new_from_slice(chain_par).unwrap();
    mac.update(&data);
    mac.finalize().into_bytes().to_vec()
}

// ─── Test 1 ──────────────────────────────────────────────────────────────────

/// SEP-5 Test 1: 12-word mnemonic, empty passphrase.
///
/// Source: SEP-0005, Test 1.
/// G-addresses and m/44'/148' key transcribed from the published table
/// (the secret-key column is omitted).
#[test]
fn test1_intermediate_key() {
    // m/44'/148' key published in SEP-0005, Test 1.
    let expected = "e0eec84fe165cd427cb7bc9b6cfdef0555aa1cb6f9043ff1fe986c3c8ddd22e3";
    let seed_hex = "e4a5a632e70943ae7f07659df1332160937fad82587216a4c64315a0fb39497ee4a01f76ddab4cba68147977f3a147b6ad584c41808e8238a07f6cc4b582f186";
    let got = compute_m44_148_key(seed_hex);
    assert_eq!(
        hex::encode(got),
        expected,
        "Test 1: m/44'/148' intermediate key mismatch"
    );
}

#[test]
fn test1_g_addresses() {
    // Published G-addresses for SEP-0005, Test 1.
    // NO S... strkeys.
    const EXPECTED: &[&str] = &[
        "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6",
        "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX",
        "GAY5PRAHJ2HIYBYCLZXTHID6SPVELOOYH2LBPH3LD4RUMXUW3DOYTLXW",
        "GAOD5NRAEORFE34G5D4EOSKIJB6V4Z2FGPBCJNQI6MNICVITE6CSYIAE",
        "GBCUXLFLSL2JE3NWLHAWXQZN6SQC6577YMAU3M3BEMWKYPFWXBSRCWV4",
        "GBRQY5JFN5UBG5PGOSUOL4M6D7VRMAYU6WW2ZWXBMCKB7GPT3YCBU2XZ",
        "GBY27SJVFEWR3DUACNBSMJB6T4ZPR4C7ZXSTHT6GMZUDL23LAM5S2PQX",
        "GAY7T23Z34DWLSTEAUKVBPHHBUE4E3EMZBAQSLV6ZHS764U3TKUSNJOF",
        "GDJTCF62UUYSAFAVIXHPRBR4AUZV6NYJR75INVDXLLRZLZQ62S44443R",
        "GBTVYYDIYWGUQUTKX6ZMLGSZGMTESJYJKJWAATGZGITA25ZB6T5REF44",
    ];
    let wallet = Sep5Wallet::from_mnemonic(
        "illness spike retreat truth genius clock brain pass fit cave bargain toe",
        "",
    )
    .expect("Test 1 mnemonic must parse");

    for (idx, &expected_g) in EXPECTED.iter().enumerate() {
        let account = wallet
            .derive_account(idx as u32)
            .unwrap_or_else(|e| panic!("Test 1 account {idx} derivation failed: {e}"));
        let got = account.public_key_strkey();
        assert_eq!(
            got, expected_g,
            "Test 1 account {idx}: G-address mismatch\n  got:      {got}\n  expected: {expected_g}"
        );
    }
}

// ─── Test 2 ──────────────────────────────────────────────────────────────────

/// SEP-5 Test 2: 15-word mnemonic, empty passphrase.
///
/// Source: SEP-0005, Test 2.
#[test]
fn test2_intermediate_key() {
    let expected = "2e5d4e6b54a4b96c5e887c9ec92f619a3c134d8b1059dcef15c1a9b228ae3751";
    let seed_hex = "7b36d4e725b48695c3ffd2b4b317d5552cb157c1a26c46d36a05317f0d3053eb8b3b6496ba39ebd9312d10e3f9937b47a6790541e7c577da027a564862e92811";
    let got = compute_m44_148_key(seed_hex);
    assert_eq!(
        hex::encode(got),
        expected,
        "Test 2: m/44'/148' intermediate key mismatch"
    );
}

#[test]
fn test2_g_addresses() {
    const EXPECTED: &[&str] = &[
        "GAVXVW5MCK7Q66RIBWZZKZEDQTRXWCZUP4DIIFXCCENGW2P6W4OA34RH",
        "GDFCYVCICATX5YPJUDS22KM2GW5QU2KKSPPPT2IC5AQIU6TP3BZSLR5K",
        "GAUA3XK3SGEQFNCBM423WIM5WCZ4CR4ZDPDFCYSFLCTODGGGJMPOHAAE",
        "GAH3S77QXTAPZ77REY6LGFIJ2XWVXFOKXHCFLA6HQTL3POLVZJDHHUDM",
        "GCSCZVGV2Y3EQ2RATJ7TE6PVWTW5OH5SMG754AF6W6YM3KJF7RMNPB4Y",
        "GDKWYAJE3W6PWCXDZNMFNFQSPTF6BUDANE6OVRYMJKBYNGL62VKKCNCC",
        "GCDTVB4XDLNX22HI5GUWHBXJFBCPB6JNU6ZON7E57FA3LFURS74CWDJH",
        "GBTDPL5S4IOUQHDLCZ7I2UXJ2TEHO6DYIQ3F2P5OOP3IS7JSJI4UMHQJ",
        "GD3KWA24OIM7V3MZKDAVSLN3NBHGKVURNJ72ZCTAJSDTF7RIGFXPW5FQ",
        "GB3C6RRQB3V7EPDXEDJCMTS45LVDLSZQ46PTIGKZUY37DXXEOAKJIWSV",
    ];
    let wallet = Sep5Wallet::from_mnemonic(
        "resource asthma orphan phone ice canvas fire useful arch jewel impose vague theory cushion top",
        "",
    )
    .expect("Test 2 mnemonic must parse");

    for (idx, &expected_g) in EXPECTED.iter().enumerate() {
        let account = wallet
            .derive_account(idx as u32)
            .unwrap_or_else(|e| panic!("Test 2 account {idx} derivation failed: {e}"));
        let got = account.public_key_strkey();
        assert_eq!(
            got, expected_g,
            "Test 2 account {idx}: G-address mismatch\n  got:      {got}\n  expected: {expected_g}"
        );
    }
}

// ─── Test 3 ──────────────────────────────────────────────────────────────────

/// SEP-5 Test 3: 24-word mnemonic, empty passphrase.
///
/// Source: SEP-0005, Test 3.
#[test]
fn test3_intermediate_key() {
    let expected = "df474e0dc2711089b89af6b089aceeb77e73120e9f895bd330a36fa952835ea8";
    let seed_hex = "937ae91f6ab6f12461d9936dfc1375ea5312d097f3f1eb6fed6a82fbe38c85824da8704389831482db0433e5f6c6c9700ff1946aa75ad8cc2654d6e40f567866";
    let got = compute_m44_148_key(seed_hex);
    assert_eq!(
        hex::encode(got),
        expected,
        "Test 3: m/44'/148' intermediate key mismatch"
    );
}

#[test]
fn test3_g_addresses() {
    const EXPECTED: &[&str] = &[
        "GC3MMSXBWHL6CPOAVERSJITX7BH76YU252WGLUOM5CJX3E7UCYZBTPJQ",
        "GB3MTYFXPBZBUINVG72XR7AQ6P2I32CYSXWNRKJ2PV5H5C7EAM5YYISO",
        "GDYF7GIHS2TRGJ5WW4MZ4ELIUIBINRNYPPAWVQBPLAZXC2JRDI4DGAKU",
        "GAFLH7DGM3VXFVUID7JUKSGOYG52ZRAQPZHQASVCEQERYC5I4PPJUWBD",
        "GAXG3LWEXWCAWUABRO6SMAEUKJXLB5BBX6J2KMHFRIWKAMDJKCFGS3NN",
        "GA6RUD4DZ2NEMAQY4VZJ4C6K6VSEYEJITNSLUQKLCFHJ2JOGC5UCGCFQ",
        "GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS",
        "GBJ646Q524WGBN5X5NOAPIF5VQCR2WZCN6QZIDOSY6VA2PMHJ2X636G4",
        "GDHX4LU6YBSXGYTR7SX2P4ZYZSN24VXNJBVAFOB2GEBKNN3I54IYSRM4",
        "GDXOY6HXPIDT2QD352CH7VWX257PHVFR72COWQ74QE3TEV4PK2KCKZX7",
    ];
    let wallet = Sep5Wallet::from_mnemonic(
        "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better",
        "",
    )
    .expect("Test 3 mnemonic must parse");

    for (idx, &expected_g) in EXPECTED.iter().enumerate() {
        let account = wallet
            .derive_account(idx as u32)
            .unwrap_or_else(|e| panic!("Test 3 account {idx} derivation failed: {e}"));
        let got = account.public_key_strkey();
        assert_eq!(
            got, expected_g,
            "Test 3 account {idx}: G-address mismatch\n  got:      {got}\n  expected: {expected_g}"
        );
    }
}

// ─── Test 4 ──────────────────────────────────────────────────────────────────

/// SEP-5 Test 4: 24-word mnemonic WITH BIP-39 passphrase `p4ssphr4se`.
///
/// Source: SEP-0005, Test 4.
/// This is the one published test with a non-empty BIP-39 passphrase; it
/// verifies the `to_seed_normalized` passphrase path in `Sep5Wallet::from_mnemonic`.
#[test]
fn test4_intermediate_key() {
    let expected = "c83c61dc97d37832f0f20e258c3ba4040a258800fd14abaff124a4dee114b17e";
    let seed_hex = "d425d39998fb42ce4cf31425f0eaec2f0a68f47655ea030d6d26e70200d8ff8bd4326b4bdf562ea8640a1501ae93ccd0fd7992116da5dfa24900e570a742a489";
    let got = compute_m44_148_key(seed_hex);
    assert_eq!(
        hex::encode(got),
        expected,
        "Test 4: m/44'/148' intermediate key mismatch"
    );
}

#[test]
fn test4_g_addresses() {
    const EXPECTED: &[&str] = &[
        "GDAHPZ2NSYIIHZXM56Y36SBVTV5QKFIZGYMMBHOU53ETUSWTP62B63EQ",
        "GDY47CJARRHHL66JH3RJURDYXAMIQ5DMXZLP3TDAUJ6IN2GUOFX4OJOC",
        "GCLAQF5H5LGJ2A6ACOMNEHSWYDJ3VKVBUBHDWFGRBEPAVZ56L4D7JJID",
        "GBC36J4KG7ZSIQ5UOSJFQNUP4IBRN6LVUFAHQWT2ODEQ7Y3ASWC5ZN3B",
        "GA6NHA4KPH5LFYD6LZH35SIX3DU5CWU3GX6GCKPJPPTQCCQPP627E3CB",
        "GBOWMXTLABFNEWO34UJNSJJNVEF6ESLCNNS36S5SX46UZT2MNYJOLA5L",
        "GBL3F5JUZN3SQKZ7SL4XSXEJI2SNSVGO6WZWNJLG666WOJHNDDLEXTSZ",
        "GA5XPPWXL22HFFL5K5CE37CEPUHXYGSP3NNWGM6IK6K4C3EFHZFKSAND",
        "GDS5I7L7LWFUVSYVAOHXJET2565MGGHJ4VHGVJXIKVKNO5D4JWXIZ3XU",
        "GBOSMFQYKWFDHJWCMCZSMGUMWCZOM4KFMXXS64INDHVCJ2A2JAABCYRR",
    ];
    let wallet = Sep5Wallet::from_mnemonic(
        "cable spray genius state float twenty onion head street palace net private method loan turn phrase state blanket interest dry amazing dress blast tube",
        "p4ssphr4se",
    )
    .expect("Test 4 mnemonic must parse");

    for (idx, &expected_g) in EXPECTED.iter().enumerate() {
        let account = wallet
            .derive_account(idx as u32)
            .unwrap_or_else(|e| panic!("Test 4 account {idx} derivation failed: {e}"));
        let got = account.public_key_strkey();
        assert_eq!(
            got, expected_g,
            "Test 4 account {idx}: G-address mismatch\n  got:      {got}\n  expected: {expected_g}"
        );
    }
}

// ─── Test 5 ──────────────────────────────────────────────────────────────────

/// SEP-5 Test 5: 12-word all-zero-entropy mnemonic, empty passphrase.
///
/// Source: SEP-0005, Test 5.
/// Entropy bytes: `00000000000000000000000000000000`.
/// This pins the all-zero-entropy edge case.
#[test]
fn test5_intermediate_key() {
    let expected = "03df7921b4f789040e361d07d5e4eddad277c376350d7b5d585400a0ef18f2f5";
    let seed_hex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    let got = compute_m44_148_key(seed_hex);
    assert_eq!(
        hex::encode(got),
        expected,
        "Test 5: m/44'/148' intermediate key mismatch"
    );
}

#[test]
fn test5_g_addresses() {
    const EXPECTED: &[&str] = &[
        "GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX",
        "GDVSYYTUAJ3ACHTPQNSTQBDQ4LDHQCMNY4FCEQH5TJUMSSLWQSTG42MV",
        "GBFPWBTN4AXHPWPTQVQBP4KRZ2YVYYOGRMV2PEYL2OBPPJDP7LECEVHR",
        "GCCCOWAKYVFY5M6SYHOW33TSNC7Z5IBRUEU2XQVVT34CIZU7CXZ4OQ4O",
        "GCQ3J35MKPKJX7JDXRHC5YTXTULFMCBMZ5IC63EDR66QA3LO7264ZL7Q",
        "GDTA7622ZA5PW7F7JL7NOEFGW62M7GW2GY764EQC2TUJ42YJQE2A3QUL",
        "GD7A7EACTPTBCYCURD43IEZXGIBCEXNBHN3OFWV2FOX67XKUIGRCTBNU",
        "GAF4AGPVLQXFKEWQV3DZU5YEFU6YP7XJHAEEQH4G3R664MSF77FLLRK3",
        "GABTYCZJMCP55SS6I46SR76IHETZDLG4L37MLZRZKQDGBLS5RMP65TSX",
        "GAKFARYSPI33KUJE7HYLT47DCX2PFWJ77W3LZMRBPSGPGYPMSDBE7W7X",
    ];
    let wallet = Sep5Wallet::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
    )
    .expect("Test 5 mnemonic must parse");

    for (idx, &expected_g) in EXPECTED.iter().enumerate() {
        let account = wallet
            .derive_account(idx as u32)
            .unwrap_or_else(|e| panic!("Test 5 account {idx} derivation failed: {e}"));
        let got = account.public_key_strkey();
        assert_eq!(
            got, expected_g,
            "Test 5 account {idx}: G-address mismatch\n  got:      {got}\n  expected: {expected_g}"
        );
    }
}

// ─── Negative tests ───────────────────────────────────────────────────────────

/// Invalid mnemonic (bad checksum) returns `DeriveError::InvalidMnemonic`.
#[test]
fn invalid_mnemonic_bad_checksum() {
    // "abandon" × 12 fails the BIP-39 checksum (valid mnemonic is "abandon"×11 + "about").
    let result = Sep5Wallet::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        "",
    );
    assert!(
        matches!(result, Err(DeriveError::InvalidMnemonic(_))),
        "expected InvalidMnemonic, got {result:?}"
    );
}

/// Wrong word count returns `DeriveError::InvalidMnemonic`.
#[test]
fn invalid_mnemonic_wrong_word_count() {
    let result = Sep5Wallet::from_mnemonic("illness spike retreat", "");
    assert!(
        matches!(result, Err(DeriveError::InvalidMnemonic(_))),
        "expected InvalidMnemonic, got {result:?}"
    );
}

/// Unknown word returns `DeriveError::InvalidMnemonic`.
#[test]
fn invalid_mnemonic_unknown_word() {
    let result = Sep5Wallet::from_mnemonic(
        "notaword spike retreat truth genius clock brain pass fit cave bargain toe",
        "",
    );
    assert!(
        matches!(result, Err(DeriveError::InvalidMnemonic(_))),
        "expected InvalidMnemonic, got {result:?}"
    );
}

/// `index = 2^31` (== `0x80000000`) is rejected as `IndexOutOfRange`.
#[test]
fn index_at_boundary_rejected() {
    let wallet = Sep5Wallet::from_mnemonic(
        "illness spike retreat truth genius clock brain pass fit cave bargain toe",
        "",
    )
    .unwrap();
    let result = wallet.derive_account(0x8000_0000);
    assert!(
        matches!(
            result,
            Err(DeriveError::IndexOutOfRange { index: 0x8000_0000 })
        ),
        "expected IndexOutOfRange at 2^31, got {result:?}"
    );
}

/// `index = u32::MAX` is rejected as `IndexOutOfRange`.
#[test]
fn index_max_u32_rejected() {
    let wallet = Sep5Wallet::from_mnemonic(
        "illness spike retreat truth genius clock brain pass fit cave bargain toe",
        "",
    )
    .unwrap();
    let result = wallet.derive_account(u32::MAX);
    assert!(
        matches!(
            result,
            Err(DeriveError::IndexOutOfRange { index: u32::MAX })
        ),
        "expected IndexOutOfRange at u32::MAX, got {result:?}"
    );
}

/// `index = 2^31 - 1` (== `0x7FFF_FFFF`) is the maximum valid index.
#[test]
fn index_max_valid_accepted() {
    let wallet = Sep5Wallet::from_mnemonic(
        "illness spike retreat truth genius clock brain pass fit cave bargain toe",
        "",
    )
    .unwrap();
    assert!(
        wallet.derive_account(0x7FFF_FFFF).is_ok(),
        "index 2^31-1 must be accepted"
    );
}

/// `Debug` output of `Sep5Wallet` must not contain the seed.
#[test]
fn wallet_debug_redacted() {
    let wallet = Sep5Wallet::from_mnemonic(
        "illness spike retreat truth genius clock brain pass fit cave bargain toe",
        "",
    )
    .unwrap();
    let debug = format!("{wallet:?}");
    assert!(
        debug.contains("[redacted]"),
        "Debug must be redacted, got: {debug}"
    );
}

/// `Debug` output of `DerivedAccount` must not contain the secret seed bytes.
#[test]
fn account_debug_redacted() {
    let wallet = Sep5Wallet::from_mnemonic(
        "illness spike retreat truth genius clock brain pass fit cave bargain toe",
        "",
    )
    .unwrap();
    let account = wallet.derive_account(0).unwrap();
    let debug = format!("{account:?}");
    assert!(
        debug.contains("[redacted]"),
        "DerivedAccount debug must be redacted, got: {debug}"
    );
    assert!(
        debug.contains("GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6"),
        "DerivedAccount debug should contain the public key"
    );
}

/// Round-trip: `from_bip39_seed_zeroizing` with a known seed hex produces the
/// expected account.
#[test]
fn from_bip39_seed_zeroizing_roundtrip() {
    // Test 1 seed hex from SEP-0005.
    let seed_hex = "e4a5a632e70943ae7f07659df1332160937fad82587216a4c64315a0fb39497ee4a01f76ddab4cba68147977f3a147b6ad584c41808e8238a07f6cc4b582f186";
    let seed_bytes = hex::decode(seed_hex).unwrap();
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&seed_bytes);
    let wallet = Sep5Wallet::from_bip39_seed_zeroizing(Zeroizing::new(seed));
    let account = wallet.derive_account(0).unwrap();
    assert_eq!(
        account.public_key_strkey(),
        "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6",
        "from_bip39_seed_zeroizing round-trip must match Test 1 account 0"
    );
}

/// `secret_seed` exposes the 32-byte ed25519 seed; re-deriving the public key
/// from it reproduces the account's `G...` address.
#[test]
fn secret_seed_reproduces_public_key() {
    use ed25519_dalek::SigningKey;
    use secrecy::ExposeSecret;
    use stellar_strkey::ed25519::PublicKey as StrkeyPublicKey;

    let wallet = Sep5Wallet::from_mnemonic(
        "illness spike retreat truth genius clock brain pass fit cave bargain toe",
        "",
    )
    .unwrap();
    let account = wallet.derive_account(0).unwrap();
    let addr = account.public_key_strkey();

    let seed: [u8; 32] = *account.secret_seed().expose_secret();
    let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let strkey = StrkeyPublicKey(public_key).to_string();

    assert_eq!(
        strkey.as_str(),
        addr,
        "public key re-derived from secret_seed must match the account address"
    );
    assert_eq!(
        addr,
        "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6"
    );
}
