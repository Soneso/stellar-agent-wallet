# Agent delegation

Hand an autonomous agent a scoped, budgeted, revocable slice of a smart
account: one target contract, a spending cap, and its own key — instead of
the account's full authority. The agent transacts with a key it holds
directly; it never sees, and never needs, the wallet's own signing material.

This builds entirely on the [context rule](concepts.md#smart-account-context-rules)
and policy machinery: a `CallContract` rule scopes what the agent's signer
may invoke, and a spending-limit policy caps how much it may move. Nothing
here grants the agent any new administrative capability — creating, scoping,
capping, and revoking a rule are all operator/CLI-side actions. The agent's
side of the picture is unchanged in kind, only in degree: it signs with a key
the wallet's context-rule machinery now recognizes as a first-class signer
type.

## Recommended agent-signer doctrine

A context-rule signer is either **Delegated** (a classic `G...` account) or
**External** (authenticated through a verifier contract, with a raw key of
the verifier's own choosing). Two External shapes matter for an agent:

- **External Ed25519** (this guide) — a raw ed25519 public key, verified
  on-chain by a deployed Ed25519-verifier contract. No funded classic account
  is required: the key only ever appears as a signature over an auth digest,
  never as a source account. It can be held in an HSM, a keyring, or any
  process that can produce an ed25519 signature, and rotating it is a
  `signers remove` + `signers add` pair — not a re-funding operation.
- **Delegated** — a classic `G...` account, which the agent would need to
  hold funded on its own. Workable, but it ties the agent's identity to a
  funded account and makes rotation a funding operation, not a policy edit.

External Ed25519 is the recommended shape for an agent's own key precisely
because it avoids both of those costs. Passkeys (WebAuthn) remain the right
choice for a *human* consent factor — they require a user-verification
ceremony that an unattended agent process cannot perform.

## Setting up the delegation

The walkthrough below scopes an agent to `transfer` calls on one SEP-41
token contract, under a spending cap. Every write verb here is
testnet-only and structurally refuses `mainnet`; see
[CLI reference: smart-account](cli-reference/smart-account.md) for the full
flag reference.

### 1. Deploy the verifier and the policy (once per network)

Both are per-network singletons: deploy once, then every rule and account on
that network reuses the same deployed contract. Each deploy is idempotent —
re-running it after the first success returns `status: "already_deployed"`
with no RPC traffic.

```bash
stellar-agent smart-account deploy-ed25519-verifier --deployer-secret-env DEPLOYER_SK
stellar-agent smart-account deploy-spending-limit-policy --deployer-secret-env DEPLOYER_SK
```

Both addresses are recorded in the local verifier registry
(`~/.config/stellar-agent/networks.toml`); later commands resolve them from
there automatically.

### 2. Generate the agent's Ed25519 key

Generate a fresh ed25519 keypair for the agent using whatever tooling you
already trust for key material on your platform (a keyring, an HSM, or, for
a first testnet trial, any ed25519 keypair generator). You need the 32-byte
public key as 64-char hex; the seed stays with the agent process and never
touches any wallet command in this guide.

### 3. Create the scoped `CallContract` rule

`rules create` needs at least one signer at creation time, so start with a
bootstrap signer — typically your own operator key — then attach the
agent's key in the next step:

```bash
stellar-agent smart-account rules create \
  --account CABC...WXYZ \
  --name agent-ops \
  --context call-contract:CTOK...WXYZ \
  --signer-delegated GOPS...WXYZ \
  --signer-secret-env WALLET_SK
```

`--context call-contract:<C_STRKEY>` is what scopes the rule: on-chain
authorization for this rule only ever matches invocations of that one
contract. Record the returned `rule_id` — every following command needs it.

### 4. Attach the agent's key to that rule

```bash
stellar-agent smart-account signers add \
  --account CABC...WXYZ \
  --rule-id <RULE_ID> \
  --signer-ed25519 <AGENT_HEX_PUBKEY_64> \
  --signer-secret-env WALLET_SK
```

`--verifier` is optional here — omitted, it resolves the network's
registered Ed25519 verifier from step 1, failing closed if none is
registered.

Whether to keep the bootstrap operator signer on the rule afterward is a
choice: leaving it in place gives you a recovery path if the agent's key is
ever lost or compromised (you can still administer or retire the rule
yourself); removing it (`smart-account signers remove --signer-id <ID>`)
makes the rule agent-only. There is no wrong answer — pick based on how much
you trust your own key-recovery process versus wanting a hard "agent only"
boundary.

### 5. Attach the spending-limit policy

```bash
stellar-agent smart-account rules add-policy \
  --account CABC...WXYZ \
  --rule-id <RULE_ID> \
  --kind spending-limit \
  --limit 50000000 \
  --period 17280 \
  --signer-secret-env WALLET_SK
```

`--limit` is in stroops (`50000000` = 5 XLM); `--period` is a rolling window
in ledgers (`17280` ≈ 24 hours at 5 s/ledger). The cumulative amount moved
through this rule within the trailing window may never exceed `--limit`; a
transfer that would push it over is refused on-chain, not client-side —
there is no way to bypass the cap by racing the check.

The wallet refuses `--kind spending-limit` client-side, before any network
call, if `--limit` is not positive or `--period` is zero, and if the target
rule's context type is not `call-contract` — a spending limit is only
meaningful against a scoped contract, and the OpenZeppelin policy contract
itself rejects both conditions the same way.

## What the agent can and cannot do

With the rule and policy in place, the agent — holding only its own ed25519
seed — can authorize `transfer(smart_account, recipient, amount)` calls on
the one contract the rule names, up to the spending cap, and nothing else:

- **A call to the scoped contract, under budget** succeeds on-chain, the
  same as any other smart-account operation.
- **A call that would push cumulative spend over the cap** is refused
  on-chain with the policy's own `SpendingLimitExceeded` error — a
  distinct, checkable failure, not a generic authorization refusal.
- **A call to any contract other than the one the rule names** is refused
  on-chain as a scope mismatch (`UnvalidatedContext`), even though the same
  key signed it. The rule's context type is checked before any policy is
  even consulted.
- **Anything that is not a SEP-41 `transfer(from, to, amount)`** — including
  administrative smart-account calls — is refused; the spending-limit
  policy's `enforce` only recognizes that one invocation shape.

## Observing and retuning the spending cap

`SpendingLimitExceeded` and `RuleExpired` do not have to be surprises the
agent discovers mid-task. The operator can read the cap's current state at
any time with `smart-account rules get-spending-limit`: the configured
limit, the rolling-window period, how much of the window is already spent,
and the remaining budget as of the ledger the read observed. The agent can
read the same state about its own rules through the read-only MCP tools
`stellar_rules_list` and `stellar_rules_get` — no new write authority is
granted by exposing these; both tools are `read_only_hint=true,
destructive_hint=false`. `stellar_rules_get`'s `policies` field also reports
each attached policy's best-effort classification (`threshold`,
`spending-limit`, or `unknown`), degrading rather than failing when a policy
cannot be identified.

The returned budget numbers are a point-in-time estimate, not a guarantee:
they are exact only as of the `as_of_ledger` they were read at. Forward
ledger movement only grows headroom (older spend entries fall out of the
rolling window), but an intervening spend shrinks it — a submission that
looked affordable a moment earlier can still fail `SpendingLimitExceeded`.

The operator retunes the limit without tearing the rule down via
`smart-account rules set-spending-limit --rule-id <N> --limit <STROOPS>`.
This changes only the limit; the rolling spend history is preserved, so a
retune cannot be used to reset the window early. The period is immutable
once installed — changing it requires removing and re-adding the policy,
which does reset the history (see [CLI reference:
smart-account](cli-reference/smart-account.md#smart-account-rules-set-spending-limit)).

Revoking the delegation is the same lifecycle every other context rule
uses: `smart-account rules delete`, `smart-account rules set-valid-until`
to set an expiry, or `smart-account signers remove` to drop just the
agent's key while leaving the rule (and any other signers on it) intact.

The signing substrate that authenticates an External-Ed25519 call — supplying
the agent's key alongside the verifier address to the same production
submission path every other smart-account operation uses — is what makes
this delegation real rather than a paper scope: the wallet does not merely
record the rule, it enforces it on every submission that carries that
signer's signature.

## Related pages

- [Concepts](concepts.md#smart-account-context-rules) — context rules, auth
  digest, the policy engine.
- [CLI reference: smart-account](cli-reference/smart-account.md) — full flag
  reference for every command used above.
