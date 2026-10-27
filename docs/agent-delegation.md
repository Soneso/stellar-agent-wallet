# Agent delegation

Hand an autonomous agent a scoped, budgeted, revocable slice of a smart
account: one target contract, a spending cap, and its own key, instead of
the account's full authority. The agent transacts with a key it holds
directly; it never sees, and never needs, the wallet's own signing material.

This builds entirely on the [context rule](concepts.md#smart-account-context-rules)
and policy machinery: a `CallContract` rule scopes what the agent's signer
may invoke, and a spending-limit policy caps how much it may move. Nothing
here grants the agent any new administrative capability. Creating, scoping,
capping, and revoking a rule are all operator/CLI-side actions. The agent's
side of the picture is unchanged in kind, only in degree: it signs with a key
the wallet's context-rule machinery now recognizes as a first-class signer
type.

The walkthrough below has the operator author the rule directly via the CLI.
An agent can also PROPOSE a rule for the operator to review and consent to,
via the `stellar_rule_create` / `stellar_rule_create_commit` MCP tool pair
(see [MCP: tool catalog](mcp.md#tool-catalog)). The agent resolves and
simulates the definition (signers, policies, context, expiry) but never
installs it. Installation only proceeds after the operator attests to the
EXACT resolved definition on one of the three approval surfaces (CLI
`approve`, the loopback inbox, the remote inbox). Each surface renders the
full rule, including a prominent callout when the proposed context is
`Default` (account-wide authority), before the operator can consent. This is
the same "no new administrative capability without operator sign-off"
posture as the CLI-authored path above; only the AUTHORING step moves from
operator-typed flags to agent-resolved, operator-reviewed JSON.

## Recommended agent-signer doctrine

A context-rule signer is either **Delegated** or **External**. A Delegated
signer is a classic `G...` account, or a `C...` contract whose own
authorization decides for it. An External signer is authenticated through a
verifier contract, with a raw key of the verifier's own choosing. Two
External shapes matter for an agent:

- **External Ed25519** (this guide): a raw ed25519 public key, verified
  on-chain by a deployed Ed25519-verifier contract. No funded classic account
  is required: the key only ever appears as a signature over an auth digest,
  never as a source account. It can be held in an HSM, a keyring, or any
  process that can produce an ed25519 signature, and rotating it is a
  `signers remove` + `signers add` pair, not a re-funding operation.
- **Delegated**: a classic `G...` account, which the agent would need to
  hold funded on its own. A delegated `C...` contract fits a signer that is
  itself a contract, not an agent's key. Workable, but it ties the agent's identity to a
  funded account and makes rotation a funding operation, not a policy edit.

External Ed25519 is the recommended shape for an agent's own key precisely
because it avoids both of those costs. Passkeys (WebAuthn) remain the right
choice for a *human* consent factor: they require a user-verification
ceremony that an unattended agent process cannot perform.

## Setting up the delegation

The walkthrough below scopes an agent to `transfer` calls on one SEP-41
token contract, under a spending cap. Every write verb here is
testnet-only and structurally refuses `mainnet`; see
[CLI reference: smart-account](cli-reference/smart-account.md) for the full
flag reference.

Each signing step reads the seed it needs into an environment variable
without echo, as [Pass a secret seed](getting-started.md#pass-a-secret-seed)
describes, and removes it from the shell at the end of the step.

### 1. Deploy the verifier and the policy (once per network)

Both are per-network singletons: deploy once, then every rule and account on
that network reuses the same deployed contract. Each deploy is idempotent:
re-running it after the first success returns `status: "already_deployed"`
with no RPC traffic. Run this line on its own, paste the deployer seed when
prompted, and press Enter:

```bash
printf 'DEPLOYER_SK seed: ' && read -rs DEPLOYER_SK && echo && export DEPLOYER_SK
```

```bash
stellar-agent smart-account deploy-ed25519-verifier --deployer-secret-env DEPLOYER_SK
stellar-agent smart-account deploy-spending-limit-policy --deployer-secret-env DEPLOYER_SK
unset DEPLOYER_SK
```

Both addresses are recorded in the local verifier registry
(`<canonical_data_root>/networks.toml`); later commands resolve them from
there automatically.

### 2. Generate the agent's Ed25519 key

Generate a fresh ed25519 keypair for the agent using whatever tooling you
already trust for key material on your platform (a keyring, an HSM, or, for
a first testnet trial, any ed25519 keypair generator). You need the 32-byte
public key as 64-char hex. The agent's seed stays with the agent: in this
guide, only `smart-account execute` reads it, from `AGENT_SK` (see
[Submitting an agent-signed call](#submitting-an-agent-signed-call)).

### 3. Create the scoped `CallContract` rule

`rules create` installs the rule with the agent's key as its signer. The
operator key signs the install under the default `--auth-rule-id 0`, the
bootstrap rule from `accounts deploy-c`. Run this line on its own, paste the
operator seed when prompted, and press Enter:

```bash
printf 'WALLET_SK seed: ' && read -rs WALLET_SK && echo && export WALLET_SK
```

```bash
stellar-agent smart-account rules create \
  --account CABC...WXYZ \
  --name agent-ops \
  --context call-contract:CTOK...WXYZ \
  --signer-ed25519 <AGENT_HEX_PUBKEY_64> \
  --accept-no-delegated-fallback \
  --signer-secret-env WALLET_SK
unset WALLET_SK
```

`--context call-contract:<C_STRKEY>` is what scopes the rule: on-chain
authorization for this rule only ever matches invocations of that one
contract. Record the returned `rule_id`. Every following command needs it.

`--verifier` is optional here. Omitted, it resolves the network's
registered Ed25519 verifier from step 1, failing closed if none is
registered. `--accept-no-delegated-fallback` acknowledges that the agent's
External key is the rule's only signer.

### 4. Keep administration on the bootstrap rule

`signers add` and `signers remove` authorize a change with the rule being
changed. A `CallContract` rule matches only calls to its own contract, so it
cannot authorize changes to the smart account. Rule 0 keeps that authority.
If the agent's key is lost or compromised, retire the scoped rule from rule 0.
Read the operator seed as above, then run:

```bash
stellar-agent smart-account rules delete \
  --account CABC...WXYZ \
  --rule-id <RULE_ID> \
  --auth-rule-id 0 \
  --signer-secret-env WALLET_SK
unset WALLET_SK
```

### 5. Attach the spending-limit policy

Run this line on its own, paste the operator seed when prompted, and press
Enter:

```bash
printf 'WALLET_SK seed: ' && read -rs WALLET_SK && echo && export WALLET_SK
```

```bash
stellar-agent smart-account rules add-policy \
  --account CABC...WXYZ \
  --rule-id <RULE_ID> \
  --kind spending-limit \
  --limit 50000000 \
  --period 17280 \
  --auth-rule-id 0 \
  --signer-secret-env WALLET_SK
unset WALLET_SK
```

`--auth-rule-id 0` authorizes the attachment with the bootstrap rule. The
default is the rule being changed, which a `CallContract` rule cannot
authorize.

`--limit` is in stroops (`50000000` = 5 XLM); `--period` is a rolling window
in ledgers (`17280` ≈ 24 hours at 5 s/ledger). The cumulative amount moved
through this rule within the trailing window may never exceed `--limit`. A
transfer that would push it over is refused on-chain, not client-side:
there is no way to bypass the cap by racing the check.

The wallet refuses `--kind spending-limit` client-side, before any network
call, if `--limit` is not positive or `--period` is zero. It refuses a target
rule whose context type is not `call-contract` after reading the rule, before
simulation and submission. A spending limit is only
meaningful against a scoped contract, and the OpenZeppelin policy contract
itself rejects both conditions the same way.

Because `rules create` pinned the rule, the wallet probes the policy against
the policy allowlist before submitting and, once the add confirms, pins its
hash in a `SaContextRulePinsUpdated` audit row, so every later signing verb
under the rule checks the policy as well.

## Submitting an agent-signed call

Everything above sets the delegation UP; `smart-account execute` is how the
agent's key actually SUBMITS a call under it. The agent process holds only
its own ed25519 seed and never touches the operator's wallet key.
`execute` is the one CLI verb built for that shape. It signs the smart-account
auth digest with the agent's External-Ed25519 key while a separate,
funded key pays the transaction fee and signs the envelope.

The command reads two seeds. Run each line on its own, paste the seed its
prompt names, and press Enter:

```bash
printf 'AGENT_SK seed: ' && read -rs AGENT_SK && echo && export AGENT_SK
```

```bash
printf 'FEE_PAYER_SK seed: ' && read -rs FEE_PAYER_SK && echo && export FEE_PAYER_SK
```

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
unset AGENT_SK FEE_PAYER_SK
```

- `--account` is the smart account whose rule authorizes the call;
  `--contract` is the external contract being invoked (here, the SEP-41
  token from step 3). For most delegated calls these are different
  addresses.
- `--arg` takes one standard-base64 XDR `ScVal` per contract argument,
  repeated in order. Encode each argument with the `stellar-xdr` MCP tools
  or `stellar-xdr encode`; the wallet validates well-formedness client-side
  but never re-encodes the value.
- `--auth-rule-id` has NO default on this verb, unlike every other
  smart-account write command. It must always be given explicitly. A
  delegated agent call always names a specific scoped rule; defaulting to
  the account-wide bootstrap rule would either succeed against the wrong
  authority or fail on-chain in a way that hides the real mistake.
- `--rule-signer-ed25519-secret-env` names the environment variable holding
  the agent's S-strkey seed, never the operator's wallet key. Add
  `--expect-rule-signer <64_HEX>` to fail closed, before any signing, if the
  environment variable ever resolves to the wrong key.
- `--verifier` is optional, resolving from the registered Ed25519 verifier
  (step 1) when omitted, the same as `signers add --signer-ed25519`.
- `--signer-secret-env` / `--sign-with-ledger` is the ordinary fee-payer
  signer group used by every other smart-account write verb: a funded
  source account that pays the transaction fee and signs the envelope. It
  is deliberately a different key from the rule signer. The agent's key
  never needs its own funded classic account.

A call that clears the rule's scope and the spending cap returns
`status: "submitted"` with the confirmed `tx_hash`. A call that does not (over budget, wrong contract, expired rule) surfaces the same typed
on-chain error every other smart-account write verb renders (see below).

There is currently no MCP tool for this verb; see
[MCP: why there is no agent-facing execute tool](mcp.md#why-there-is-no-agent-facing-execute-tool)
for the reasoning and what would change it.

## What the agent can and cannot do

With the rule and policy in place, the agent, holding only its own ed25519
seed, submitting via `smart-account execute` as above, can authorize
`transfer(smart_account, recipient, amount)` calls on the one contract the rule names. The spending cap bounds these calls, and the agent can authorize nothing else:

- **A call to the scoped contract, under budget** succeeds on-chain, the
  same as any other smart-account operation.
- **A call that would push cumulative spend over the cap** is refused
  on-chain with the policy's own `SpendingLimitExceeded` error, a
  distinct, checkable failure, not a generic authorization refusal.
- **A call to any contract other than the one the rule names** is refused
  on-chain as a scope mismatch (`UnvalidatedContext`), even though the same
  key signed it. The rule's context type is checked before any policy is
  even consulted.
- **Anything that is not a SEP-41 `transfer(from, to, amount)`**, including
  administrative smart-account calls, is refused; the spending-limit
  policy's `enforce` only recognizes that one invocation shape.

## Observing and retuning the spending cap

`SpendingLimitExceeded` and `RuleExpired` do not have to be surprises the
agent discovers mid-task. The operator can read the cap's current state at
any time with `smart-account rules get-spending-limit`: the configured
limit, the rolling-window period, how much of the window is already spent,
and the remaining budget as of the ledger the read observed. The agent can
read the same state about its own rules through the read-only MCP tools
`stellar_rules_list` and `stellar_rules_get`. No new write authority is
granted by exposing these; both tools are `read_only_hint=true,
destructive_hint=false`. `stellar_rules_get`'s `policies` field also reports
each attached policy's best-effort classification (`threshold`,
`spending-limit`, or `unknown`). A policy whose code hash is absent or
unrecognized reports `unknown`. A failed rule read or hash fetch fails the
request.

The returned budget numbers are a point-in-time estimate, not a guarantee:
they are exact only as of the `as_of_ledger` they were read at. Forward
ledger movement only grows headroom (older spend entries fall out of the
rolling window), but an intervening spend shrinks it. A submission that
looked affordable a moment earlier can still fail `SpendingLimitExceeded`.

The operator retunes the limit without tearing the rule down via
`smart-account rules set-spending-limit --rule-id <N> --limit <STROOPS>`.
This changes only the limit; the rolling spend history is preserved, so a
retune cannot be used to reset the window early. The period is immutable
once installed. Changing it requires removing and re-adding the policy,
which does reset the history (see [CLI reference:
smart-account](cli-reference/smart-account.md#smart-account-rules-set-spending-limit)).

Revoking the delegation uses `smart-account rules delete`, or
`smart-account rules set-valid-until` to set an expiry, each with
`--auth-rule-id 0`. `smart-account signers remove` authorizes with the rule
being changed, so it cannot drop a signer from a `CallContract` rule.

## Weighted quorums for multiple agents

The simple threshold-policy above is signer-count based: any `N` of the
configured signers authorize equally. When a rule delegates to several
agents (or an operator plus several agents) whose keys should NOT carry
equal authority, attach a weighted-threshold policy.
For example, an operator key can meet the threshold alone while two agent keys
must sign together. The quorum is the same for every call, whatever the
transfer amount
([`smart-account deploy-policy --kind weighted-threshold`](cli-reference/smart-account.md#smart-account-deploy-policy),
[`rules add-policy --kind weighted-threshold`](cli-reference/smart-account.md#smart-account-rules-add-policy)).
Each signer (Delegated or External) carries an independent weight.
A passkey or an agent's own External-Ed25519 key works the same as above.
The policy's `enforce` sums the weights of whichever signers are present in
the auth entry and compares against the configured threshold. Retune the
threshold or an individual signer's weight without reinstalling the rule via
[`signers set-weighted-threshold`](cli-reference/smart-account.md#smart-account-signers-set-weighted-threshold)
/
[`signers set-signer-weight`](cli-reference/smart-account.md#smart-account-signers-set-signer-weight).
A submission that needs more than one signer's weight to clear the
threshold is built the same multi-signer way any other quorum-authorized
call is (`AuthorizationInfo` / `SignerGroup`). The weighted-threshold
policy does not change how the wallet gathers signatures, only how the
policy contract itself decides whether the gathered set is sufficient.

The signing substrate authenticates an External-Ed25519 call, supplying
the agent's key alongside the verifier address to the same production
submission path every other smart-account operation uses. This makes
this delegation real rather than a paper scope. The wallet records the rule
and enforces it on every submission that carries that
signer's signature.

## Related pages

- [Concepts](concepts.md#smart-account-context-rules): context rules, auth
  digest, the policy engine.
- [CLI reference: smart-account](cli-reference/smart-account.md): full flag
  reference for every command used above.
