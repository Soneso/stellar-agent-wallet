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

The walkthrough below has the operator author the rule directly via the CLI.
An agent can also PROPOSE a rule for the operator to review and consent to,
via the `stellar_rule_create` / `stellar_rule_create_commit` MCP tool pair
(see [MCP: tool catalog](mcp.md#tool-catalog)) — the agent resolves and
simulates the definition (signers, policies, context, expiry) but never
installs it; installation only proceeds after the operator attests to the
EXACT resolved definition on one of the three approval surfaces (CLI
`approve`, the loopback inbox, the remote inbox), each of which renders the
full rule — including a prominent callout when the proposed context is
`Default` (account-wide authority) — before the operator can consent. This is
the same "no new administrative capability without operator sign-off"
posture as the CLI-authored path above; only the AUTHORING step moves from
operator-typed flags to agent-resolved, operator-reviewed JSON.

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

## Submitting an agent-signed call

Everything above sets the delegation UP; `smart-account execute` is how the
agent's key actually SUBMITS a call under it. The agent process holds only
its own ed25519 seed — it never touches the operator's wallet key — and
`execute` is the one CLI verb built for that shape: it signs the smart-account
auth digest with the agent's External-Ed25519 key while a separate,
funded key pays the transaction fee and signs the envelope.

```bash
stellar-agent smart-account execute \
  --account CABC...WXYZ \
  --contract CTOK...WXYZ \
  --function transfer \
  --arg <base64-xdr-ScVal:Address(smart_account)> \
  --arg <base64-xdr-ScVal:Address(recipient)> \
  --arg <base64-xdr-ScVal:I128(amount)> \
  --auth-rule-id <RULE_ID> \
  --rule-signer-ed25519-secret-env AGENT_SK \
  --signer-secret-env FEE_PAYER_SK
```

- `--account` is the smart account whose rule authorizes the call;
  `--contract` is the external contract being invoked (here, the SEP-41
  token from step 3) — for most delegated calls these are different
  addresses.
- `--arg` takes one standard-base64 XDR `ScVal` per contract argument,
  repeated in order. Encode each argument with the `stellar-xdr` MCP tools
  or `stellar-xdr encode`; the wallet validates well-formedness client-side
  but never re-encodes the value.
- `--auth-rule-id` has NO default on this verb — unlike every other
  smart-account write command, it must always be given explicitly. A
  delegated agent call always names a specific scoped rule; defaulting to
  the account-wide bootstrap rule would either succeed against the wrong
  authority or fail on-chain in a way that hides the real mistake.
- `--rule-signer-ed25519-secret-env` names the environment variable holding
  the agent's S-strkey seed — never the operator's wallet key. Add
  `--expect-rule-signer <64_HEX>` to fail closed, before any signing, if the
  environment variable ever resolves to the wrong key.
- `--verifier` is optional, resolving from the registered Ed25519 verifier
  (step 1) when omitted, the same as `signers add --signer-ed25519`.
- `--signer-secret-env` / `--sign-with-ledger` is the ordinary fee-payer
  signer group used by every other smart-account write verb: a funded
  source account that pays the transaction fee and signs the envelope. It
  is deliberately a different key from the rule signer — the agent's key
  never needs its own funded classic account.

A call that clears the rule's scope and the spending cap returns
`status: "submitted"` with the confirmed `tx_hash`. A call that does not —
over budget, wrong contract, expired rule — surfaces the same typed
on-chain error every other smart-account write verb renders (see below).

There is currently no MCP tool for this verb; see
[MCP: why there is no agent-facing execute tool](mcp.md#why-there-is-no-agent-facing-execute-tool)
for the reasoning and what would change it.

## What the agent can and cannot do

With the rule and policy in place, the agent — holding only its own ed25519
seed, submitting via `smart-account execute` as shown above — can authorize
`transfer(smart_account, recipient, amount)` calls on the one contract the
rule names, up to the spending cap, and nothing else:

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

## Weighted quorums for multiple agents

The simple threshold-policy above is signer-count based: any `N` of the
configured signers authorize equally. When a rule delegates to several
agents (or an operator plus several agents) whose keys should NOT carry
equal authority — for example, an agent that alone can authorize small
transfers but needs a co-signer for larger ones — attach a
weighted-threshold policy instead
([`smart-account deploy-policy --kind weighted-threshold`](cli-reference/smart-account.md#smart-account-deploy-policy),
[`rules add-policy --kind weighted-threshold`](cli-reference/smart-account.md#smart-account-rules-add-policy)).
Each signer (Delegated or External — a passkey or an agent's own
External-Ed25519 key work the same as above) carries an independent weight;
the policy's `enforce` sums the weights of whichever signers are present in
the auth entry and compares against the configured threshold. Retune the
threshold or an individual signer's weight without reinstalling the rule via
[`signers set-weighted-threshold`](cli-reference/smart-account.md#smart-account-signers-set-weighted-threshold)
/
[`signers set-signer-weight`](cli-reference/smart-account.md#smart-account-signers-set-signer-weight).
A submission that needs more than one signer's weight to clear the
threshold is built the same multi-signer way any other quorum-authorized
call is (`AuthorizationInfo` / `SignerGroup`) — the weighted-threshold
policy does not change how the wallet gathers signatures, only how the
policy contract itself decides whether the gathered set is sufficient.

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
