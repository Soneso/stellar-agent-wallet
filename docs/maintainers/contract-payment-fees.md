# Contract transfer fee bounds

Policy versions 1 and 2 accept the optional root integer
`contract_transfer_max_fee_stroops` in `0..=4294967295`.
The owner signature covers a present value. Omission preserves the canonical
bytes of an older policy. Zero permits only a zero transaction fee.

Presets and mainnet enablement insert 1,000,000 stroops (0.1 XLM) when the
field is absent. Enablement and rotation preserve explicit values, including
zero. A rewritten body requires renewed owner signing.

The bound covers the full transaction fee: inclusion, resources, and any
restoration. The network determines the charged fee. The bound limits that fee;
it is not a tariff. There is no separate resource ceiling.
The loader refuses `soroban_resource_fee_cap` as an unknown criterion kind.

## Lookup and arithmetic API

`sep43_fee_check` in `crates/stellar-agent-mcp/src/tools/sep43_effects.rs` is
the single production caller of both functions. It applies them to every SEP-43
transaction whose fee effect carries a resource fee.

The network crate exports both functions from `fees` and its crate root:

```rust
pub fn contract_transfer_fee_cap(
    chain: Caip2,
    policy: Option<&VerifiedPolicy>,
) -> Result<ContractTransferFeeCap, WalletError>;

pub fn check_contract_transfer_fee_cap(
    total_stroops: u64,
    cap: ContractTransferFeeCap,
) -> Result<(), WalletError>;
```

`Caip2`, `VerifiedPolicy`, `WalletError`, and `ContractTransferFeeCap` are core
types. The cap has `stroops: u32` and `signed: bool`. Lookup selects verified
metadata, or the 1,000,000 testnet default when that metadata is absent.
Mainnet absence returns `validation.contract_transfer_fee_cap_required`.
A profile's classic fee cap cannot supply this consent.

The checker widens the cap to u64. Equality passes; any greater total returns
`validation.contract_transfer_fee_exceeded`. It never narrows the candidate.
Its caller-supplied `signed` flag is descriptive and grants no authority.
The offline SAC validator continues to accept `ContractTransferFeeLimits`
through its existing API.

The policy metadata and arithmetic APIs do not enable contract-call execution.
G/M payments retain their classic fee rules and do not require the new field.
Verified classic-asset SAC transfers describe payment value; their full fee
bound is separate from per-operation classic limits.

## Reporting

Spending summaries and `profile policy-check` include `contract_transfer_fee_cap`:

| Member | Meaning |
|---|---|
| `configured_stroops` | Root value, or `null` when absent. |
| `effective_stroops` | Verified cap or testnet fallback, or `null` when unavailable. |
| `status` | `verified`, `requires_signature`, `testnet_default`, `required`, or `unavailable`. |

Unsigned policy-check input reports a declared cap as `requires_signature`,
even when it contains a signature table. Mainnet inspection derives authority
from a verified load. An invalid signature produces no spending summary.
A failed freshness check labels the readable signed body's report `unavailable`.

## Supplied fee measurements

These supplied measurements ran on 2026-11-12 on testnet protocol 30,
ledgers 5698460 through 5698955. They are not independently reproduced here.
Each cell with three values follows the three ledgers in that row.
All fee columns are stroops; all twelve transactions succeeded.

| Recipient balance | Ledgers | Resource allocation | Inclusion bids | Submitted totals | Charged fee | Instructions / read bytes / write bytes |
|---|---|---:|---|---|---:|---|
| Native, existing | 5698461 / 5698708 / 5698952 | 11,085 | 100 / 200 / 100 | 11,185 / 11,285 / 11,185 | 6,276 | 264269 / 144 / 368 |
| Native, missing | 5698462 / 5698709 / 5698953 | 119,874 | 100 / 200 / 100 | 119,974 / 120,074 / 119,974 | 100,874 | 242286 / 144 / 368 |
| Issued FEEP, existing | 5698463 / 5698710 / 5698954 | 11,328 | 100 / 200 / 100 | 11,428 / 11,528 / 11,428 | 6,499 | 290537 / 116 / 340 |
| Issued FEEP, missing | 5698464 / 5698711 / 5698955 | 121,022 | 100 / 200 / 100 | 121,122 / 121,222 / 121,122 | 102,002 | 289380 / 260 / 340 |

Setup used a funded G source, one SourceAccount authorization, deployed native
and issued asset contracts, and contract recipients with checked balance states.
The measurement tool submitted the returned allocation and authorization.
Charged inclusion was 100 stroops in every run.

Configuration snapshots span ledgers 5698460 through 5698951. Instruction fees
were 3 per 10,000 instructions. Disk reads cost 781 per entry and 223 per KB;
writes cost 1,250 per entry and 437 per KB.
Bandwidth, history, and event rates were 203, 2,029, and 2,500 per KB.
KB means 1,024 bytes. The persistent rent denominator was 1,215, minimum
persistent TTL was 120,960, and derived rent rate was 1,000 per KB.

A new 224-byte balance computes to 93,334 rent plus 1,271 TTL-write stroops
under those testnet settings. The supplied mainnet configuration computes
374,605 stroops for that rent and TTL write.
Applying the measured allocation ratio, 121,022 / 94,605, gives roughly
480,000 stroops on mainnet. Twice that, rounded upward to one significant
digit, motivates the 1,000,000 default.
These are configuration-dependent computations, not measured mainnet fees.

Restoration was not measured. The supplied estimate of roughly 95,000 through
101,000 stroops describes those testnet conditions only.
The protocol references supplied for rent calculations are
`soroban-env-host-30.0.0/src/fees.rs:290`, `:397`, and `storage_types.rs:8`.
The supplied restoration reference is `e2e_invoke.rs:889` in that version.
These references are not a claim of local source verification.
The offline validator requires same-transaction restoration indices and refuses
memos on contract invocations, as described in [security internals](security-internals.md).
