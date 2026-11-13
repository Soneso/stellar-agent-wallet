//! Compatibility guards for signed version 2 policies.
//!
//! Signed documents preserve their canonical bytes, digest, and signature. An
//! existing signed version 2 document keeps loading and keeps its
//! counterparty denial byte for byte. Address alternatives govern raw calls,
//! debit legs, and transfer bundles. A policy with equal `unlisted` tables on
//! two rules reproduces its literal bytes, digest, and signed text, loads, and
//! decides as its tables state.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]

use ed25519_dalek::{Signer as _, SigningKey};
use stellar_agent_core::{
    policy::{
        DenyReason, McpToolRegistration, ToolDescriptor, ToolValueKind,
        v1::{
            EvalContext, PolicyStateStore,
            canonical::canonical_bytes,
            criteria::{
                Criterion,
                counterparty_allowlist::{CounterpartyAllowlistCriterion, RecipientClass},
                state_store::policy_now_ms,
            },
            loader::load_signed_policy_text,
            mainnet_minimum,
            value::{ActionKind, ValueClass, ValueLeg},
        },
    },
    profile::{
        caip2::{MAINNET_PASSPHRASE, TESTNET_PASSPHRASE},
        schema::Profile,
    },
};
use toml_edit::DocumentMut;

pub(crate) const FIXTURE: &str = include_str!("../fixtures/policy-v2.toml");

/// The canonical bytes the owner signature of the fixture covers.
pub(crate) const FIXTURE_CANONICAL: &str = r#"version = 2
scope = "profile:operator"
sequence = 7

[mainnet]
profile = "operator"
endpoint_host = "rpc.example.invalid"
installation_nonce_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
classic_max_fee_per_op_stroops = 500
authorization_ttl_seconds = 60
approval_credentials = [{ credential_id_b64url = "WlpaWlpaWlpaWlpaWlpaWg", public_key_sec1_b64url = "BEYtuhrk_BqWi02s8gzdbb4frjSqlxUUpj00BcPRz9ODtYu7CMEzg0KMWFPHHEyFHhNLBWgh5Gj-Cpd6v0MT3eE" }]

[mainnet.cross_check_thresholds]
"USD:GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF" = "100"
native = "10000000000"

[[rules]]
match = { chain = "stellar:mainnet", tool = "stellar_pay" }
criteria = [{ assets = ["native"], kind = "asset_allowlist" }, { allowlist = ["GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"], kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"] }, { asset = "native", kind = "per_tx_cap", max_stroops = "100" }, { asset = "native", kind = "per_period_cap", max_stroops = "200", window = "1d" }, { kind = "rate_limit", max_calls = 10, window = "1d" }]
decision = "require_approval"
reason = "review"
ttl_secs = 3600
allow_opaque_signing = false
"#;

/// The BLAKE3 digest of [`FIXTURE_CANONICAL`], in lowercase hex.
pub(crate) const FIXTURE_DIGEST_HEX: &str =
    "27215114bd1abcb23ed88923946dead88dde5de7251c571e2ee4adc451b3bc74";

/// A well-formed account outside the fixture's counterparty allowlist.
const UNLISTED: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// The fixed evaluation time of the guards, in Unix milliseconds.
const NOW_MS: u64 = 1_700_000_000_000;

fn mainnet_profile() -> Profile {
    Profile::builder_mainnet_named(
        "operator",
        "https://rpc.example.invalid",
        "s",
        "a",
        "n",
        "a",
    )
    .build()
}

fn owner_key() -> SigningKey {
    SigningKey::from_bytes(&[11; 32])
}

struct AddressFixture {
    name: &'static str,
    raw: &'static str,
    signed: &'static str,
    canonical: &'static str,
    digest: &'static str,
}

const ADDRESS_FIXTURES: &[AddressFixture] = &[
    AddressFixture {
        name: "g_entry_deny",
        raw: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\"], unlisted = { mode = \"deny\" } }]\ndecision = \"allow\"\n",
        signed: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\"], unlisted = { mode = \"deny\" } }]\ndecision = \"allow\"\n\n[signature]\nowner_id = \"GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2\"\nsig = \"58df262a8fe85064d94a7e44c3dbe13bfc004ebfd077fe5c86c1a1789f7951bf545b95f7f67975b61d9d7b190fe94979d2ec17c1c9b85042ede9236c901b4805\"\n",
        canonical: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"*\" }\ncriteria = [{ allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\"], kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], unlisted = { mode = \"deny\" } }]\ndecision = \"allow\"\n",
        digest: "8683a02e6276b2be22e5995819eebf66b145b5f332652cf853bfd92b85e026dd",
    },
    AddressFixture {
        name: "m_entry_deny",
        raw: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"MAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAAAAAAAAAAAA6TAI\"], unlisted = { mode = \"deny\" } }]\ndecision = \"allow\"\n",
        signed: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"MAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAAAAAAAAAAAA6TAI\"], unlisted = { mode = \"deny\" } }]\ndecision = \"allow\"\n\n[signature]\nowner_id = \"GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2\"\nsig = \"7276a8f2d34ad146987d033e2465cd10aa50db1a1197bb75d30aaedc7f5fefc39b6eb78f19babcf2aa3e4122044486afe872d2ba59168a84a17c7e0446356d06\"\n",
        canonical: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"*\" }\ncriteria = [{ allowlist = [\"MAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAAAAAAAAAAAA6TAI\"], kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], unlisted = { mode = \"deny\" } }]\ndecision = \"allow\"\n",
        digest: "f3b762be608d8a9b16ccfe16bd7b95e88f26394eed2fc3115a9e415517fb20fe",
    },
    AddressFixture {
        name: "g_c_entries_deny",
        raw: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\", \"CABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGCK3\"], unlisted = { mode = \"deny\" } }]\ndecision = \"allow\"\n",
        signed: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\", \"CABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGCK3\"], unlisted = { mode = \"deny\" } }]\ndecision = \"allow\"\n\n[signature]\nowner_id = \"GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2\"\nsig = \"64db3b5899e3b533daaddba78f791436d978cd36e77d4f45364d0f71b19b7b868e23028f49829bc6fb453d2afb1699788b09b9651dae4f726b194c315988a10f\"\n",
        canonical: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"*\" }\ncriteria = [{ allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\", \"CABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGCK3\"], kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], unlisted = { mode = \"deny\" } }]\ndecision = \"allow\"\n",
        digest: "19462943dd93b3a52711a1debd07d8d691dbe1ccbb5afd3144e854dbbb846469",
    },
    AddressFixture {
        name: "g_c_empty_approval",
        raw: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], allowlist = [], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n",
        signed: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], allowlist = [], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n\n[signature]\nowner_id = \"GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2\"\nsig = \"2490ba3d3757f6da860456eb9687fa0eb55a66fd074f932d06583f200b39e53e5b2a6fe0fce8363e09d10c73e24202b513299d5310fb3637241ffd0f77997401\"\n",
        canonical: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"*\" }\ncriteria = [{ allowlist = [], kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n",
        digest: "8ee533724f0787119fd22ade55caf6edbc2fdedebb0fb1c7b714bd1b85bced47",
    },
    AddressFixture {
        name: "g_c_empty_budget",
        raw: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], allowlist = [], unlisted = { mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, asset = \"native\", window = \"1d\" } }]\ndecision = \"allow\"\n",
        signed: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], allowlist = [], unlisted = { mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, asset = \"native\", window = \"1d\" } }]\ndecision = \"allow\"\n\n[signature]\nowner_id = \"GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2\"\nsig = \"359365e1810424905d5da06ef806c5fa66f9a2f6f43d4386597f3617371230bfceb9e84e2158d4713ef7101b2c3aea29fcb8cbbcdc3086ae403818ebf46dec06\"\n",
        canonical: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"*\" }\ncriteria = [{ allowlist = [], kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], unlisted = { asset = \"native\", mode = \"budget\", per_period_stroops = 20, per_tx_stroops = 10, window = \"1d\" } }]\ndecision = \"allow\"\n",
        digest: "1d54db83e1fffdfdc60059854d7dc0d1c76d2d2287627ba5b63f41fcd2097c88",
    },
    AddressFixture {
        name: "g_c_other_approval",
        raw: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], allowlist = [\"GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA\"], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n",
        signed: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], allowlist = [\"GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA\"], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n\n[signature]\nowner_id = \"GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2\"\nsig = \"71997f266f77971e3d826a07af042ce5cc90a48979a58db7c79088eef1ef5e5e0fe28f47c6b2a66380664b4d1f13b7114f2fd6cc6d270de2e18cfa78c1573c0e\"\n",
        canonical: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"*\" }\ncriteria = [{ allowlist = [\"GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA\"], kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n",
        digest: "e7e7bb69a2db62f719d496bcda5109a1d4c4bb4dc2fc9fffdb46106927aa6812",
    },
    AddressFixture {
        name: "g_c_other_budget",
        raw: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], allowlist = [\"GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA\"], unlisted = { mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, asset = \"native\", window = \"1d\" } }]\ndecision = \"allow\"\n",
        signed: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], allowlist = [\"GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA\"], unlisted = { mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, asset = \"native\", window = \"1d\" } }]\ndecision = \"allow\"\n\n[signature]\nowner_id = \"GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2\"\nsig = \"f140833a03759414851e9e861f6a29210680de0915a93ceca29c611f2c89a3ff691b6368ba9be053144d004c06add0ce39f9c652f8953d923022b64bc4de2d07\"\n",
        canonical: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"*\" }\ncriteria = [{ allowlist = [\"GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA\"], kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], unlisted = { asset = \"native\", mode = \"budget\", per_period_stroops = 20, per_tx_stroops = 10, window = \"1d\" } }]\ndecision = \"allow\"\n",
        digest: "5eaea005362f03a5c7bee6a20fa013fb68103d7b80c4cf19511a598ae9e3fb71",
    },
    AddressFixture {
        name: "issuer_approval",
        raw: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"KNOWN_ISSUER\"], allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\"], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n",
        signed: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"KNOWN_ISSUER\"], allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\"], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n\n[signature]\nowner_id = \"GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2\"\nsig = \"ef7084a7231780eb9b4438620867d12f9a186f24a1d0e60aa98e86260e5ada07de9ec6f607508f2e18d2e199c03b41dc806d6b23027b8a69365e7625198f910f\"\n",
        canonical: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"*\" }\ncriteria = [{ allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\"], kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"KNOWN_ISSUER\"], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n",
        digest: "ed5335fec7e29826df2133d873c30dcae1f16b7a0e2da02e3e0ab34f696b67e1",
    },
    AddressFixture {
        name: "issuer_budget",
        raw: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"KNOWN_ISSUER\"], allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\"], unlisted = { mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, asset = \"USD:GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA\", window = \"1d\" } }]\ndecision = \"allow\"\n",
        signed: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"KNOWN_ISSUER\"], allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\"], unlisted = { mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, asset = \"USD:GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA\", window = \"1d\" } }]\ndecision = \"allow\"\n\n[signature]\nowner_id = \"GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2\"\nsig = \"66dabd5c6540661a66e8e899606c76c26865409f18af8a02650cc360c580be1e504f7ee47d0bdc07cd86b42e4f661c7c7da3a54e7237e0231d04849b9c5ac708\"\n",
        canonical: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"*\" }\ncriteria = [{ allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\"], kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"KNOWN_ISSUER\"], unlisted = { asset = \"USD:GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA\", mode = \"budget\", per_period_stroops = 20, per_tx_stroops = 10, window = \"1d\" } }]\ndecision = \"allow\"\n",
        digest: "b26d994151493cfde4ec09cf66113427508b3aea25ceb460d09f1f890525a5e2",
    },
    AddressFixture {
        name: "domain_listed_approval",
        raw: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"HOME_DOMAIN\"], allowlist = [\"example.com\"], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n",
        signed: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"HOME_DOMAIN\"], allowlist = [\"example.com\"], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n\n[signature]\nowner_id = \"GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2\"\nsig = \"eb819a9c0c890a3eb64ca3808be5f4bb85ebd438f47893047a37b8e623c634c0156e4dbe038556bd8844ab40e3f7d4f415d2c7ba9df0e2bd27bdce92b90e7505\"\n",
        canonical: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"*\" }\ncriteria = [{ allowlist = [\"example.com\"], kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"HOME_DOMAIN\"], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n",
        digest: "9b75c5e25f4cbb954de46b043329a867ccd68a0cfef79d0fe240a1d813a2b806",
    },
    AddressFixture {
        name: "domain_listed_budget",
        raw: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"HOME_DOMAIN\"], allowlist = [\"example.com\"], unlisted = { mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, asset = \"native\", window = \"1d\" } }]\ndecision = \"allow\"\n",
        signed: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"HOME_DOMAIN\"], allowlist = [\"example.com\"], unlisted = { mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, asset = \"native\", window = \"1d\" } }]\ndecision = \"allow\"\n\n[signature]\nowner_id = \"GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2\"\nsig = \"7f903abd66cadfa21f1ad1697895b64a18d16d84d952159697bc6851ca5a18243573be16e9ef8c6cd8b5974eb08dcf9710f7486dcad1e3caf82452c72e309704\"\n",
        canonical: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"*\" }\ncriteria = [{ allowlist = [\"example.com\"], kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"HOME_DOMAIN\"], unlisted = { asset = \"native\", mode = \"budget\", per_period_stroops = 20, per_tx_stroops = 10, window = \"1d\" } }]\ndecision = \"allow\"\n",
        digest: "7b20a77df61ced3b06c57307f66ba80cc3fb5ff0a456b0ea1a2a4349654976b0",
    },
    AddressFixture {
        name: "domain_empty_approval",
        raw: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"HOME_DOMAIN\"], allowlist = [], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n",
        signed: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"HOME_DOMAIN\"], allowlist = [], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n\n[signature]\nowner_id = \"GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2\"\nsig = \"e30ee8579705f33721c3793b3885662b1dfa805bdff3ae2d1796e708a8e20c712da95e11148adadd232ddef0e5cab6434ede12568b2ca445b558ef6b5b763801\"\n",
        canonical: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"*\" }\ncriteria = [{ allowlist = [], kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"HOME_DOMAIN\"], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n",
        digest: "3026a6f63090675cb2352b0070aab6bf16d4d8cc7e0885468943cf7ec23bdfbc",
    },
    AddressFixture {
        name: "domain_empty_budget",
        raw: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"HOME_DOMAIN\"], allowlist = [], unlisted = { mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, asset = \"native\", window = \"1d\" } }]\ndecision = \"allow\"\n",
        signed: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"HOME_DOMAIN\"], allowlist = [], unlisted = { mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, asset = \"native\", window = \"1d\" } }]\ndecision = \"allow\"\n\n[signature]\nowner_id = \"GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2\"\nsig = \"687cd88e9164d099c76dda770e585e190442d7739dd585e734722bcf36909652710b7df55239727910d8e588c3b0c6f77d06f165630c41ea213ce983e29c8009\"\n",
        canonical: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"*\" }\ncriteria = [{ allowlist = [], kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"HOME_DOMAIN\"], unlisted = { asset = \"native\", mode = \"budget\", per_period_stroops = 20, per_tx_stroops = 10, window = \"1d\" } }]\ndecision = \"allow\"\n",
        digest: "7bf726de943b84c3cc46fb3d030a4fc6e43edbe73d22fe23b8d9531b1f7bddfd",
    },
    AddressFixture {
        name: "g_only_approval",
        raw: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\"], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n",
        signed: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\"], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n\n[signature]\nowner_id = \"GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2\"\nsig = \"feacdb91bb021445a2d8c661644480359c47d14c76ec5fca33b9666ff84cff2845516f64f5635af5de7e20fea643ba7c5a885708f109ec30480f926452d7440e\"\n",
        canonical: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"*\" }\ncriteria = [{ allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\"], kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], unlisted = { mode = \"approval\" } }]\ndecision = \"allow\"\n",
        digest: "9637f683bcff3349ee13108a98cc1e58e62b4b37444a1f3aab407cf940c0fd40",
    },
    AddressFixture {
        name: "g_only_budget",
        raw: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\"], unlisted = { mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, asset = \"native\", window = \"1d\" } }]\ndecision = \"allow\"\n",
        signed: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = [{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\"], unlisted = { mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, asset = \"native\", window = \"1d\" } }]\ndecision = \"allow\"\n\n[signature]\nowner_id = \"GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2\"\nsig = \"4aa5bb50e58ba76ec3db4eed2042125c6e8a4948ce5a38b9cb62d826ca37861f0ed93ad76c85028c69c290bccd26203512298289eb13d805d00e03d0ac339108\"\n",
        canonical: "version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"*\" }\ncriteria = [{ allowlist = [\"GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H\"], kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], unlisted = { asset = \"native\", mode = \"budget\", per_period_stroops = 20, per_tx_stroops = 10, window = \"1d\" } }]\ndecision = \"allow\"\n",
        digest: "a0c10d8c0aa8daaad188bb3ad0fc2eaffd82f81ebb3591a7715dfb865242b149",
    },
];

fn address_engine(name: &str) -> stellar_agent_core::PolicyEngineV1 {
    let fixture = ADDRESS_FIXTURES
        .iter()
        .find(|fixture| fixture.name == name)
        .unwrap();
    let bytes = canonical_bytes(fixture.raw).unwrap();
    assert_eq!(bytes, fixture.canonical.as_bytes());
    assert_eq!(blake3::hash(&bytes).to_hex().as_str(), fixture.digest);
    assert_eq!(signed(fixture.raw, &owner_key()), fixture.signed);
    assert_eq!(
        canonical_bytes(fixture.signed).unwrap(),
        fixture.canonical.as_bytes()
    );
    let document = load_signed_policy_text(
        fixture.signed,
        "operator",
        &owner_key().verifying_key().to_bytes(),
        stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
    )
    .unwrap();
    stellar_agent_core::PolicyEngineV1::new(document, "operator".into())
}

/// The counterparty criterion of the named fixture's only rule, as loaded.
fn address_criterion(name: &str) -> CounterpartyAllowlistCriterion {
    let fixture = ADDRESS_FIXTURES
        .iter()
        .find(|fixture| fixture.name == name)
        .unwrap();
    let document = load_signed_policy_text(
        fixture.signed,
        "operator",
        &owner_key().verifying_key().to_bytes(),
        stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
    )
    .unwrap();
    let criterion: &dyn Criterion = document.rules[0].criteria[0].as_ref();
    (criterion as &dyn std::any::Any)
        .downcast_ref::<CounterpartyAllowlistCriterion>()
        .unwrap()
        .clone()
}
fn address_g() -> String {
    format!("{}", stellar_strkey::ed25519::PublicKey([1; 32]))
}
fn address_c() -> String {
    format!("{}", stellar_strkey::Contract([3; 32]))
}
fn address_m() -> String {
    format!(
        "{}",
        stellar_strkey::ed25519::MuxedAccount {
            ed25519: [1; 32],
            id: 7
        }
    )
}
fn address_profile() -> Profile {
    Profile::builder_testnet_named("operator", "s", "a", "n", "a").build()
}
fn address_tool(name: &'static str, kind: ToolValueKind) -> ToolDescriptor {
    ToolDescriptor::from_registration(&McpToolRegistration {
        name,
        destructive_hint: false,
        read_only_hint: true,
        chain_id_required: false,
        value_kind: kind,
    })
}
fn address_payment(destination: &str, asset: &str, amount: i128) -> ValueClass {
    ValueClass::single(ValueLeg {
        kind: ActionKind::Payment,
        destination: Some(destination.into()),
        asset: Some(asset.into()),
        amount: Some(amount),
    })
}
fn address_decide(
    engine: &stellar_agent_core::PolicyEngineV1,
    value: ValueClass,
) -> stellar_agent_core::policy::Decision {
    use stellar_agent_core::policy::PolicyEngine;
    engine
        .evaluate_with_value(
            &address_tool("stellar_pay", ToolValueKind::MovesValue),
            &serde_json::Value::Null,
            &address_profile(),
            value,
            None,
            None,
            None,
            None,
            None,
            NOW_MS,
        )
        .unwrap()
}
fn address_assert_mode(decision: &stellar_agent_core::policy::Decision, mode: &str) {
    use stellar_agent_core::policy::Decision;
    if mode == "approval" {
        assert!(
            matches!(decision, Decision::RequireApproval(_)),
            "{decision:?}"
        );
    } else {
        assert_eq!(*decision, Decision::Allow);
    }
}

#[test]
fn signed_raw_muxed_destination_matches_exact_or_base_entry() {
    use stellar_agent_core::policy::{Decision, PolicyEngine};
    for fixture in ["g_entry_deny", "m_entry_deny"] {
        let engine = address_engine(fixture);
        let args = serde_json::json!({"destination": address_m()});
        assert_eq!(
            engine
                .evaluate(
                    &address_tool("registry_read", ToolValueKind::ReadOnly),
                    &args,
                    &address_profile(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    NOW_MS,
                )
                .unwrap(),
            Decision::Allow
        );
    }
}
#[test]
fn signed_raw_g_and_c_destinations_are_listed() {
    use stellar_agent_core::policy::{Decision, PolicyEngine};
    let engine = address_engine("g_c_entries_deny");
    for destination in [address_g(), address_c()] {
        assert_eq!(
            engine
                .evaluate(
                    &address_tool("registry_read", ToolValueKind::ReadOnly),
                    &serde_json::json!({"destination": destination}),
                    &address_profile(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    NOW_MS,
                )
                .unwrap(),
            Decision::Allow
        );
    }
}

#[test]
fn v1_address_alternatives_and_rule_approval() {
    use stellar_agent_core::policy::{Decision, PolicyEngine};
    use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
    for fixture in ["g_entry_deny", "m_entry_deny", "g_c_entries_deny"] {
        let raw = ADDRESS_FIXTURES
            .iter()
            .find(|f| f.name == fixture)
            .unwrap()
            .raw
            .replace("version = 2", "version = 1")
            .replace("sequence = 1\n", "")
            .replace(", unlisted = { mode = \"deny\" }", "");
        for approval in [false, true] {
            let raw = if approval {
                raw.replace(
                    "decision = \"allow\"",
                    "decision = \"require_approval\"\nreason = \"review\"",
                )
            } else {
                raw.clone()
            };
            let engine = stellar_agent_core::PolicyEngineV1::new(
                load_signed_policy_text(
                    &signed(&raw, &owner_key()),
                    "operator",
                    &owner_key().verifying_key().to_bytes(),
                    TESTNET_PASSPHRASE,
                )
                .unwrap(),
                "operator".into(),
            );
            let destinations = if fixture == "g_c_entries_deny" {
                vec![address_g(), address_c()]
            } else {
                vec![address_m()]
            };
            for destination in destinations {
                let decision = engine
                    .evaluate(
                        &address_tool("registry_read", ToolValueKind::ReadOnly),
                        &serde_json::json!({"destination": destination}),
                        &address_profile(),
                        None,
                        None,
                        None,
                        None,
                        None,
                        NOW_MS,
                    )
                    .unwrap();
                if approval {
                    assert!(matches!(decision, Decision::RequireApproval(_)));
                } else {
                    assert_eq!(decision, Decision::Allow);
                }
            }
            if fixture == "g_c_entries_deny" {
                use stellar_agent_core::policy::v1::bundle::{
                    BundleStateOverlay, BundleView, InnerOpDescriptor,
                };
                let value =
                    ValueClass::Value(stellar_agent_core::policy::v1::value::ValueEffects::new(
                        [address_g(), address_c()]
                            .iter()
                            .map(|destination| ValueLeg {
                                kind: ActionKind::Payment,
                                destination: Some(destination.clone()),
                                asset: Some("native".into()),
                                amount: Some(1),
                            })
                            .collect(),
                    ));
                let decision = address_decide(&engine, value);
                if approval {
                    assert!(matches!(decision, Decision::RequireApproval(_)));
                } else {
                    assert_eq!(decision, Decision::Allow);
                }
                let inners: Vec<_> = [address_g(), address_c()]
                    .iter()
                    .map(|to| InnerOpDescriptor::TokenTransfer {
                        asset: "native".into(),
                        from: address_g(),
                        to: to.clone(),
                        amount: 1,
                    })
                    .collect();
                let overlay = BundleStateOverlay::default();
                let decision = engine
                    .evaluate_bundle(
                        &address_tool("wallet_multicall", ToolValueKind::MovesValue),
                        &serde_json::Value::Null,
                        &address_profile(),
                        &BundleView {
                            inners: &inners,
                            overlay: &overlay,
                        },
                    )
                    .unwrap();
                if approval {
                    assert!(matches!(decision, Decision::RequireApproval(_)));
                } else {
                    assert_eq!(decision, Decision::Allow);
                }
            }
        }
    }
}
#[test]
fn signed_unlisted_g_reaches_unlisted_mode() {
    for list in ["empty", "other"] {
        for mode in ["approval", "budget"] {
            let engine = address_engine(&format!("g_c_{list}_{mode}"));
            address_assert_mode(
                &address_decide(&engine, address_payment(&address_g(), "native", 1)),
                mode,
            );
        }
    }
}
#[test]
fn signed_unlisted_issuer_reaches_unlisted_mode() {
    let asset = format!("USD:{}", stellar_strkey::ed25519::PublicKey([2; 32]));
    for mode in ["approval", "budget"] {
        let engine = address_engine(&format!("issuer_{mode}"));
        address_assert_mode(
            &address_decide(&engine, address_payment(&address_g(), &asset, 1)),
            mode,
        );
    }
}

struct AddressIdentity(String);
impl stellar_agent_core::policy::v1::AccountIdentityView for AddressIdentity {
    fn account_id(&self) -> &str {
        &self.0
    }
    fn home_domain(&self) -> Option<String> {
        Some("example.com".into())
    }
}
struct AddressCache(bool);
impl stellar_agent_core::policy::v1::CounterpartyCacheView for AddressCache {
    fn has_resolved(&self, _: &str) -> bool {
        self.0
    }
    fn is_account_listed(&self, _: &str, _: &str) -> bool {
        self.0
    }
}
#[test]
fn signed_verified_domain_reaches_unlisted_mode() {
    use stellar_agent_core::policy::{Decision, PolicyEngine};
    let identity = AddressIdentity(address_g());
    for list in ["listed", "empty"] {
        for mode in ["approval", "budget"] {
            let name = format!("domain_{list}_{mode}");
            let engine = address_engine(&name);
            let criterion = address_criterion(&name);
            for verified in [true, false] {
                let tool = address_tool("stellar_pay", ToolValueKind::MovesValue);
                let args = serde_json::Value::Null;
                let profile = address_profile();
                let store = PolicyStateStore::new();
                let cache = AddressCache(verified);
                let ctx = EvalContext::new(&tool, &args, "operator", &profile, &store, NOW_MS)
                    .with_value(address_payment(&address_g(), "native", 1))
                    .with_identity_view(&identity)
                    .with_counterparty_cache(&cache);
                assert_eq!(
                    criterion.recipient_class(&ctx).unwrap(),
                    Some(if verified {
                        RecipientClass::Unlisted
                    } else {
                        RecipientClass::Unverifiable
                    })
                );
                let decision = engine
                    .evaluate_with_value(
                        &address_tool("stellar_pay", ToolValueKind::MovesValue),
                        &serde_json::Value::Null,
                        &address_profile(),
                        address_payment(&address_g(), "native", 1),
                        None,
                        Some(&identity),
                        Some(&AddressCache(verified)),
                        None,
                        None,
                        NOW_MS,
                    )
                    .unwrap();
                if verified {
                    address_assert_mode(&decision, mode);
                } else {
                    // The address check precedes HOME_DOMAIN in `kinds`, so its
                    // denial is the first; the unverified domain keeps it final.
                    assert_eq!(
                        decision,
                        Decision::Deny(DenyReason::CounterpartyDenied {
                            kind: "G_ACCOUNT".into(),
                            value: address_g(),
                        })
                    );
                }
            }
        }
    }
}
#[test]
fn signed_mixed_g_c_debits_and_bundle_admit() {
    use stellar_agent_core::policy::{
        Decision,
        v1::{
            bundle::{BundleStateOverlay, BundleView, InnerOpDescriptor},
            value::ValueEffects,
        },
    };
    let _clock =
        stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(NOW_MS);
    let engine = address_engine("g_c_entries_deny");
    let legs = [address_g(), address_c()]
        .iter()
        .map(|destination| ValueLeg {
            kind: ActionKind::Payment,
            amount: Some(1),
            asset: Some("native".into()),
            destination: Some(destination.clone()),
        })
        .collect();
    assert_eq!(
        address_decide(&engine, ValueClass::Value(ValueEffects::new(legs))),
        Decision::Allow
    );
    for (engine, amount) in [(engine, 1), (address_engine("g_c_empty_budget"), 6)] {
        let inners: Vec<_> = [address_g(), address_c()]
            .iter()
            .map(|to| InnerOpDescriptor::TokenTransfer {
                asset: "native".into(),
                from: address_g(),
                to: to.clone(),
                amount,
            })
            .collect();
        let overlay = BundleStateOverlay::default();
        let bundle = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let tool = address_tool("wallet_multicall", ToolValueKind::MovesValue);
        assert_eq!(
            engine
                .evaluate_bundle(&tool, &serde_json::Value::Null, &address_profile(), &bundle)
                .unwrap(),
            Decision::Allow
        );
        if amount == 6 {
            let mut over = inners.clone();
            over.push(InnerOpDescriptor::TokenTransfer {
                asset: "native".into(),
                from: address_g(),
                to: address_c(),
                amount: 9,
            });
            assert!(matches!(
                engine
                    .evaluate_bundle(
                        &tool,
                        &serde_json::Value::Null,
                        &address_profile(),
                        &BundleView {
                            inners: &over,
                            overlay: &overlay
                        }
                    )
                    .unwrap(),
                Decision::Deny(DenyReason::BundleDenied { inner_index: 2, .. })
            ));
        }
        let entries = engine
            .record_confirmed_bundle(&tool, &address_profile(), &bundle)
            .unwrap();
        if amount == 6 {
            assert_eq!(entries.iter().map(|entry| entry.amount()).sum::<i128>(), 12);
            assert_eq!(
                engine
                    .state_store()
                    .query_window(
                        &stellar_agent_core::policy::v1::criteria::state_store::StateKey::new(
                            "operator",
                            1,
                            "unlisted:native",
                            86_400
                        ),
                        NOW_MS
                    )
                    .unwrap(),
                (12, 2)
            );
        }
    }
}
#[test]
fn signed_x402_contract_under_g_only_reaches_mode() {
    use stellar_agent_core::policy::PolicyEngine;
    let native = stellar_agent_core::asset_id::CanonicalAsset::Native
        .sac_contract_id(stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE)
        .unwrap();
    for mode in ["approval", "budget"] {
        let engine = address_engine(&format!("g_only_{mode}"));
        let evaluation = engine
            .evaluate_with_value_full(
                &address_tool("stellar_x402_create_payment", ToolValueKind::MovesValue),
                &serde_json::Value::Null,
                &address_profile(),
                ValueClass::single(ValueLeg {
                    kind: ActionKind::X402Payment,
                    amount: Some(1),
                    asset: Some(native.clone()),
                    destination: Some(address_c()),
                }),
                None,
                None,
                None,
                None,
                None,
                NOW_MS,
            )
            .unwrap();
        address_assert_mode(&evaluation.decision, mode);
        assert_eq!(evaluation.value_effects.unwrap().recipient_class(),
            Some(stellar_agent_core::policy::v1::criteria::counterparty_allowlist::RecipientClass::Unlisted));
    }
}

/// Signs `raw` with `key` over the BLAKE3 digest of its canonical bytes.
fn signed(raw: &str, key: &SigningKey) -> String {
    let canonical = canonical_bytes(raw).unwrap();
    let signature = key.sign(blake3::hash(&canonical).as_bytes());
    format!(
        "{raw}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
        stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()),
        stellar_agent_core::hex::encode(&signature.to_bytes())
    )
}

#[test]
fn existing_v2_loads_unchanged() {
    let key = owner_key();
    let document = load_signed_policy_text(
        &signed(FIXTURE, &key),
        "operator",
        &key.verifying_key().to_bytes(),
        MAINNET_PASSPHRASE,
    )
    .unwrap();
    assert_eq!(document.version, 2);
    assert_eq!(document.rules.len(), 1);
    let kinds: Vec<_> = document.rules[0]
        .criteria
        .iter()
        .map(|c| c.kind())
        .collect();
    assert_eq!(
        kinds,
        [
            "asset_allowlist",
            "counterparty_allowlist",
            "per_tx_cap",
            "per_period_cap",
            "rate_limit"
        ]
    );
    let doc = FIXTURE.parse::<DocumentMut>().unwrap();
    mainnet_minimum::validate(&doc, &mainnet_profile(), "operator").unwrap();
}

#[test]
fn existing_v2_canonical_bytes_and_digest_match_literals() {
    let canonical = canonical_bytes(FIXTURE).unwrap();
    assert_eq!(
        String::from_utf8(canonical.clone()).unwrap(),
        FIXTURE_CANONICAL
    );
    assert_eq!(
        stellar_agent_core::hex::encode(blake3::hash(&canonical).as_bytes()),
        FIXTURE_DIGEST_HEX
    );
}

#[test]
fn counterparty_deny_mode_is_byte_identical() {
    let key = owner_key();
    let document = load_signed_policy_text(
        &signed(FIXTURE, &key),
        "operator",
        &key.verifying_key().to_bytes(),
        MAINNET_PASSPHRASE,
    )
    .unwrap();
    let criterion = document.rules[0]
        .criteria
        .iter()
        .find(|c| c.kind() == "counterparty_allowlist")
        .unwrap();
    let tool = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_pay",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    });
    let profile = mainnet_profile();
    let args = serde_json::json!({
        "destination": UNLISTED,
        "asset": "native",
        "amount_stroops": "50",
    });
    let store = PolicyStateStore::new();
    let ctx = EvalContext::new(
        &tool,
        &args,
        "operator",
        &profile,
        &store,
        1_700_000_000_000,
    )
    .with_value(ValueClass::single(ValueLeg {
        kind: ActionKind::Payment,
        amount: Some(50),
        asset: Some("native".to_owned()),
        destination: Some(UNLISTED.to_owned()),
    }));
    let denial: DenyReason = criterion.evaluate(&ctx).unwrap().unwrap();
    assert_eq!(
        serde_json::to_string(&denial).unwrap(),
        format!(r#"{{"CounterpartyDenied":{{"kind":"G_ACCOUNT","value":"{UNLISTED}"}}}}"#)
    );
    assert_eq!(denial.code(), "counterparty_denied");
    assert_eq!(denial.wire_code(), "policy.deny.counterparty_denied");
    let error = stellar_agent_core::error::WalletError::PolicyDenied {
        reason: Box::new(denial),
    };
    assert_eq!(error.code(), "policy.deny.counterparty_denied");
}

#[test]
fn absent_origin_keys_keep_canonical_bytes() {
    let v1 = "version = 1\nscope = \"profile:operator\"\n[[rules]]\nmatch = { tool = \"stellar_balances\", chain = \"*\" }\ncriteria = []\ndecision = \"allow\"\n";
    let v2 = v1.replace("version = 1", "version = 2\nsequence = 7");
    let expected = [
        (
            "version = 1\nscope = \"profile:operator\"\n\n[[rules]]\nmatch = { tool = \"stellar_balances\", chain = \"*\" }\ncriteria = []\ndecision = \"allow\"\n",
            "11db81b838a1f823ea6534c98b2c20939fdd84750aee8e4a0399b071dd0f5df7",
            "7fccb1671fd1d35fa12de252cd3a3f38d02e34a884a7acd3f166a6f74295d0eb3cd56b7845858d51437ad4a0bcc36cf2683f66bb7bd76a613bff70cd2e299004",
        ),
        (
            "version = 2\nscope = \"profile:operator\"\nsequence = 7\n\n[[rules]]\nmatch = { chain = \"*\", tool = \"stellar_balances\" }\ncriteria = []\ndecision = \"allow\"\n",
            "3f5dbe3df74a7499e75e93ca1f6f907ea2de22f6aa232669e192955064acd334",
            "e1b7f1d7d27bc3cf78f0ef6fe4202a5e428700e35c1e4dbd3b9cfc1f529fd35a886522205a1f30956cca8c3283fd4e4e7753be0c47c7ad9eedf7afcf6fe0540c",
        ),
        (
            FIXTURE_CANONICAL,
            "27215114bd1abcb23ed88923946dead88dde5de7251c571e2ee4adc451b3bc74",
            "2405f4764555bdb0c2a4dee21c4f213c2b74df40759eaf2f432fde5e2c45df7fba196e0684c1b71337a25965e7ea75335830090d49438c3a22aecbc2b103f205",
        ),
    ];
    for (raw, (expected_bytes, expected_digest, expected_sig)) in
        [v1, v2.as_str(), FIXTURE].into_iter().zip(expected)
    {
        let bytes = canonical_bytes(raw).unwrap();
        let digest = blake3::hash(&bytes);
        let sig = owner_key().sign(digest.as_bytes());
        assert_eq!(bytes, expected_bytes.as_bytes());
        assert_eq!(digest.to_hex().as_str(), expected_digest);
        assert_eq!(
            stellar_agent_core::hex::encode(&sig.to_bytes()),
            expected_sig
        );
        load_signed_policy_text(
            &signed(raw, &owner_key()),
            "operator",
            &owner_key().verifying_key().to_bytes(),
            MAINNET_PASSPHRASE,
        )
        .unwrap();
    }
}

#[test]
fn absent_origin_keys_keep_evaluation() {
    use stellar_agent_core::policy::{
        ApprovalRequest, Decision, PolicyEngine,
        v1::{PolicyEngineV1, criteria::counterparty_allowlist::RecipientClass},
    };
    let mut tool = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_pay",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    });
    tool.chain_id = "stellar:mainnet".into();
    let args = serde_json::json!({"destination": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", "asset": "native", "amount_stroops": "50"});
    // A leading rule for another tool moves the deciding rule to ordinal 1.
    let leading = "[[rules]]\nmatch = { chain = \"stellar:mainnet\", tool = \"stellar_balances\" }\ncriteria = []\ndecision = \"allow\"\n\n[[rules]]";
    for (decision, ordinal) in [
        ("allow", 0),
        ("require_approval", 0),
        ("deny", 0),
        ("allow", 1),
        ("require_approval", 1),
        ("deny", 1),
    ] {
        let raw = FIXTURE.replace(
            "decision = \"require_approval\"",
            &format!("decision = \"{decision}\""),
        );
        let raw = if ordinal == 1 {
            raw.replace("[[rules]]", leading)
        } else {
            raw
        };
        let raw = if decision == "require_approval" {
            raw
        } else {
            raw.replace("reason = \"review\"\n", "")
                .replace("ttl_secs = 3600\n", "")
        };
        let document = load_signed_policy_text(
            &signed(&raw, &owner_key()),
            "operator",
            &owner_key().verifying_key().to_bytes(),
            MAINNET_PASSPHRASE,
        )
        .unwrap();
        let engine = PolicyEngineV1::new(document, "operator".into());
        let result = engine
            .evaluate_full(
                &tool,
                &args,
                &mainnet_profile(),
                None,
                None,
                None,
                None,
                None,
                NOW_MS,
            )
            .unwrap();
        let expected = match decision {
            "allow" => Decision::Allow,
            "require_approval" => Decision::RequireApproval(
                ApprovalRequest::new(String::new(), 3600).with_reason("review".into()),
            ),
            _ => Decision::Deny(DenyReason::ExplicitRuleDeny),
        };
        assert_eq!(result.decision, expected);
        assert!(!result.provisional);
        assert_eq!(result.rule_ordinal, Some(ordinal));
        if decision == "deny" {
            assert!(result.value_effects.is_none());
        } else {
            let effects = result.value_effects.unwrap();
            assert_eq!(
                effects.legs(),
                &[ValueLeg {
                    kind: ActionKind::Payment,
                    amount: Some(50),
                    asset: Some("native".into()),
                    destination: Some(
                        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".into()
                    ),
                }]
            );
            assert_eq!(effects.memo(), None);
            assert_eq!(effects.recipient_class(), Some(RecipientClass::Listed));
        }
        let provisional = engine
            .evaluate_provisional(
                &tool,
                &args,
                &mainnet_profile(),
                stellar_agent_core::policy::v1::value::derive_value_class("stellar_pay", &args),
                None,
                None,
                None,
                None,
                None,
                NOW_MS,
            )
            .unwrap();
        assert_eq!(provisional.decision, expected);
        assert!(provisional.provisional);
        assert_eq!(provisional.rule_ordinal, Some(ordinal));
    }
}

/// A policy whose two rules carry equal `unlisted` tables.
const SHARED_BUDGET: &str = r#"version = 2
scope = "profile:operator"
sequence = 1

[[rules]]
match = { tool = "stellar_pay", chain = "stellar:testnet" }
criteria = [{ kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = [], unlisted = { mode = "budget", asset = "native", per_tx_stroops = 10, per_period_stroops = 20, window = "1d" } }]
decision = "allow"

[[rules]]
match = { tool = "stellar_x402_create_payment", chain = "stellar:testnet" }
criteria = [{ kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = [], unlisted = { mode = "budget", asset = "native", per_tx_stroops = 10, per_period_stroops = 20, window = "1d" } }]
decision = "allow"
"#;

const SHARED_DENY: &str = r#"version = 2
scope = "profile:operator"
sequence = 1

[[rules]]
match = { tool = "stellar_pay", chain = "stellar:testnet" }
criteria = [{ kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = ["GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H"], unlisted = { mode = "deny" } }]
decision = "allow"

[[rules]]
match = { tool = "stellar_x402_create_payment", chain = "stellar:testnet" }
criteria = [{ kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = ["GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H"], unlisted = { mode = "deny" } }]
decision = "allow"
"#;

const SHARED_APPROVAL: &str = r#"version = 2
scope = "profile:operator"
sequence = 1

[[rules]]
match = { tool = "stellar_pay", chain = "stellar:testnet" }
criteria = [{ kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = [], unlisted = { mode = "approval" } }]
decision = "allow"

[[rules]]
match = { tool = "stellar_x402_create_payment", chain = "stellar:testnet" }
criteria = [{ kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = [], unlisted = { mode = "approval" } }]
decision = "allow"
"#;

/// The signature block the owner key appends to [`SHARED_BUDGET`].
const SHARED_BUDGET_SIGNATURE: &str = r#"
[signature]
owner_id = "GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2"
sig = "e38a30112f0f15d013624231ccae20472abe256ec7bee6a7fa7ab552df8c1dc568287b081fc100091ed7a9a033f24b98f05e3e107cae3df10a3764e375210206"
"#;

const SHARED_BUDGET_CANONICAL: &str = r#"version = 2
scope = "profile:operator"
sequence = 1

[[rules]]
match = { chain = "stellar:testnet", tool = "stellar_pay" }
criteria = [{ allowlist = [], kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], unlisted = { asset = "native", mode = "budget", per_period_stroops = 20, per_tx_stroops = 10, window = "1d" } }]
decision = "allow"

[[rules]]
match = { chain = "stellar:testnet", tool = "stellar_x402_create_payment" }
criteria = [{ allowlist = [], kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], unlisted = { asset = "native", mode = "budget", per_period_stroops = 20, per_tx_stroops = 10, window = "1d" } }]
decision = "allow"
"#;

const SHARED_BUDGET_DIGEST_HEX: &str =
    "3f3cb09a64a83e1ff984e205acc39e23084474a04091fdf3c1effbec0356be40";

/// The signature block the owner key appends to [`SHARED_DENY`].
const SHARED_DENY_SIGNATURE: &str = r#"
[signature]
owner_id = "GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2"
sig = "a67a67062f104f37c9e75d23447ba4023760c056700486986d0556aa5272238047a1631846f3aca8700d9a8a8b8946f5ddb79ed903dece08190fa940e3fcce0b"
"#;

const SHARED_DENY_CANONICAL: &str = r#"version = 2
scope = "profile:operator"
sequence = 1

[[rules]]
match = { chain = "stellar:testnet", tool = "stellar_pay" }
criteria = [{ allowlist = ["GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H"], kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], unlisted = { mode = "deny" } }]
decision = "allow"

[[rules]]
match = { chain = "stellar:testnet", tool = "stellar_x402_create_payment" }
criteria = [{ allowlist = ["GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H"], kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], unlisted = { mode = "deny" } }]
decision = "allow"
"#;

const SHARED_DENY_DIGEST_HEX: &str =
    "f291e9f2d24e55aa90d6d83f0d99ee2059cbdc7293711f18643eaf2620cc7369";

/// The signature block the owner key appends to [`SHARED_APPROVAL`].
const SHARED_APPROVAL_SIGNATURE: &str = r#"
[signature]
owner_id = "GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2"
sig = "038d0aaba11f159d2513f50abcc7934d9af35c9dd39848c37d10106b25c5de9eca4afb239043ba68b8379ff79ecbecbb3419909135e9d50781dfb0ad30074b03"
"#;

const SHARED_APPROVAL_CANONICAL: &str = r#"version = 2
scope = "profile:operator"
sequence = 1

[[rules]]
match = { chain = "stellar:testnet", tool = "stellar_pay" }
criteria = [{ allowlist = [], kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], unlisted = { mode = "approval" } }]
decision = "allow"

[[rules]]
match = { chain = "stellar:testnet", tool = "stellar_x402_create_payment" }
criteria = [{ allowlist = [], kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], unlisted = { mode = "approval" } }]
decision = "allow"
"#;

const SHARED_APPROVAL_DIGEST_HEX: &str =
    "86b3574a446f7c2f3b284698a5b10e865855969323b02fe38e5deed2043f12c9";

/// The G strkey of `[1; 32]`, the recipient of the shared-table decisions.
const RECIPIENT: &str = "GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H";

/// Asserts that `raw` reproduces its literal canonical bytes, digest, and
/// signed text, and loads the signed text on the test network into an engine.
fn shared_engine(
    raw: &str,
    signature: &str,
    canonical: &str,
    digest_hex: &str,
) -> stellar_agent_core::policy::v1::PolicyEngineV1 {
    let bytes = canonical_bytes(raw).unwrap();
    assert_eq!(String::from_utf8(bytes.clone()).unwrap(), canonical);
    assert_eq!(
        stellar_agent_core::hex::encode(blake3::hash(&bytes).as_bytes()),
        digest_hex
    );
    let text = format!("{raw}{signature}");
    assert_eq!(signed(raw, &owner_key()), text);
    let document = load_signed_policy_text(
        &text,
        "operator",
        &owner_key().verifying_key().to_bytes(),
        TESTNET_PASSPHRASE,
    )
    .unwrap();
    assert_eq!(document.rules.len(), 2);
    stellar_agent_core::policy::v1::PolicyEngineV1::new_with_store(
        document,
        "operator".to_owned(),
        PolicyStateStore::new(),
    )
}

fn testnet_tool(name: &'static str) -> ToolDescriptor {
    let mut tool = ToolDescriptor::from_registration(&McpToolRegistration {
        name,
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    });
    tool.chain_id = "stellar:testnet".into();
    tool
}

fn testnet_profile() -> Profile {
    Profile::builder_testnet_named("operator", "s", "a", "n", "a").build()
}

/// A native payment of `amount` stroops to [`RECIPIENT`].
fn native_payment(amount: i128) -> ValueClass {
    ValueClass::single(ValueLeg {
        kind: ActionKind::Payment,
        amount: Some(amount),
        asset: Some("native".to_owned()),
        destination: Some(RECIPIENT.to_owned()),
    })
}

fn shared_evaluate(
    engine: &stellar_agent_core::policy::v1::PolicyEngineV1,
    tool: &ToolDescriptor,
    amount: i128,
) -> stellar_agent_core::policy::Evaluation {
    use stellar_agent_core::policy::PolicyEngine as _;
    engine
        .evaluate_with_value_full(
            tool,
            &serde_json::Value::Null,
            &testnet_profile(),
            native_payment(amount),
            None,
            None,
            None,
            None,
            None,
            policy_now_ms().unwrap(),
        )
        .unwrap()
}

/// Equal budget tables on `stellar_pay` and `stellar_x402_create_payment`
/// load and draw on one counter.
#[test]
fn equal_budget_tables_share_one_counter() {
    use stellar_agent_core::policy::{Decision, UnlistedBound};
    let engine = shared_engine(
        SHARED_BUDGET,
        SHARED_BUDGET_SIGNATURE,
        SHARED_BUDGET_CANONICAL,
        SHARED_BUDGET_DIGEST_HEX,
    );
    let pay = testnet_tool("stellar_pay");
    let x402 = testnet_tool("stellar_x402_create_payment");
    assert_eq!(shared_evaluate(&engine, &x402, 1).decision, Decision::Allow);
    for _ in 0..2 {
        let evaluation = shared_evaluate(&engine, &pay, 10);
        assert_eq!(evaluation.decision, Decision::Allow);
        engine
            .record_confirmed(
                &pay,
                &testnet_profile(),
                &ValueClass::Value(evaluation.value_effects.unwrap()),
            )
            .unwrap();
    }
    let exceeded = Decision::Deny(DenyReason::UnlistedBudgetExceeded {
        asset: "native".to_owned(),
        bound: UnlistedBound::PerPeriod,
        max_stroops: 20,
        attempted_stroops: 1,
    });
    let refusal = shared_evaluate(&engine, &x402, 1).decision;
    assert_eq!(refusal, exceeded);
    let Decision::Deny(reason) = refusal else {
        unreachable!()
    };
    assert_eq!(reason.code(), "unlisted_budget_exceeded");
    assert_eq!(shared_evaluate(&engine, &pay, 1).decision, exceeded);
}

/// Equal `deny` tables on two rules load, and a listed recipient passes.
#[test]
fn equal_deny_tables_load_and_allow_listed() {
    use stellar_agent_core::policy::Decision;
    let engine = shared_engine(
        SHARED_DENY,
        SHARED_DENY_SIGNATURE,
        SHARED_DENY_CANONICAL,
        SHARED_DENY_DIGEST_HEX,
    );
    for tool in ["stellar_pay", "stellar_x402_create_payment"] {
        let evaluation = shared_evaluate(&engine, &testnet_tool(tool), 1);
        assert_eq!(evaluation.decision, Decision::Allow, "{tool}");
    }
}

/// Equal `approval` tables on two rules load, and an unlisted recipient
/// requires approval.
#[test]
fn equal_approval_tables_load_and_escalate() {
    use stellar_agent_core::policy::Decision;
    let engine = shared_engine(
        SHARED_APPROVAL,
        SHARED_APPROVAL_SIGNATURE,
        SHARED_APPROVAL_CANONICAL,
        SHARED_APPROVAL_DIGEST_HEX,
    );
    for tool in ["stellar_pay", "stellar_x402_create_payment"] {
        let evaluation = shared_evaluate(&engine, &testnet_tool(tool), 1);
        assert!(
            matches!(evaluation.decision, Decision::RequireApproval(_)),
            "{tool}: {:?}",
            evaluation.decision
        );
    }
}
