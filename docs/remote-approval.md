# Remote approval

Approve or reject pending agent actions from a device other than the wallet
host, without an SSH tunnel. `approve serve --remote` binds a TLS-protected
HTTP listener beyond loopback, authenticates you with a registered passkey,
and requires a fresh passkey assertion for every approve or reject action.

If the agent and the wallet run on the same machine you approve from, you do
not need this: `stellar-agent approve serve` (see
[cli-reference/profile-and-governance.md](cli-reference/profile-and-governance.md))
is loopback-only and simpler. Remote approval is for the case where the agent
runs on a headless host or a different machine than the one you carry around.

## Trust model

The wallet host mints an attestation under the serving profile name and CAIP-2 chain id.
The shared HMAC also binds the pending nonce, digest, and process uid.
The detail page shows the profile, network, endpoint authority, and enrolled signer above the request summary.
Summary rows render challenge-bound entry data. Header rows come from the serving profile. The profile and network rows are inputs of the view digest the challenge covers; the endpoint authority and enrolled signer rows are display context.
A payment, claim, or trustline summary is decoded from the transaction envelope whose digest the challenge and the attestation bind, so the page shows the transaction an approval signs.
The detail page carries a digest of the request it renders: its terms, nonce, requester, lifetime, profile, and network. Approve sends that digest when it asks for a challenge. The listener mints a challenge only while the digest names the current pending request, and the challenge is derived over it, so the passkey assertion commits to the request the page showed. The approval gate compares the same digest with the request it attests.
A request that changed after the page loaded is refused with HTTP 409 `approval.presence_changed` before any passkey prompt, or at the decision when it changed after the prompt, and nothing is attested. Reload the page to review the current request.
Every summary value renders control characters as visible escapes such as `\u{1b}` and `\u{202e}`.
Memos retain their type: `none`, `text "<escaped value>"`, `id <n>`, `hash <hex>`, or `return <hex>`.
MPP terms and the network are checked against the authorization fingerprint before display or attestation; the charge commit checks the transport, authority, and target against the prepared request.
The simulated fee reads `not bound to this approval`.
A request whose stored digest is not the digest of its stored envelope, whose envelope does not decode, whose MPP terms do not match its fingerprint, or whose rule proposal digest does not match what it shows appears as `INCONSISTENT` and offers only Reject; an approve of it is refused with the status `inconsistent` and attests nothing.
Each pending approval records who approved it: the local operator, or the operator credential the remote listener verified. The HMAC covers that approver, so an edited or deleted approver invalidates the approval.
Mainnet remote consent requires an approval origin and leaf SPKI pin in the current verified owner-signed policy.
Without them, startup refuses with `approval.mainnet_remote_unsupported` before binding.
Ordinary remote authorization never supplies mainnet presence.
Signed-origin consent records attestation version 5 with a version 2 presence receipt and a mainnet passkey approver.
The receipt binds the signed origin, policy digest and served leaf pin.
The audit log distinguishes remote `ApprovalAttestedRemote` / `ApprovalRejectedRemote` events from loopback `ApprovalAttested` / `ApprovalRejected` events.
Each row is written before the decision takes effect; a decision whose row cannot be written is refused and the entry stays pending.

On testnet, two independent layers must hold for an approve or reject to take effect:

- The HTTP layer verifies a fresh WebAuthn passkey assertion, computed over a
  challenge cryptographically bound to the exact pending entry you are
  deciding. An assertion produced for one entry can never authorize a
  different one, and a stolen session cookie alone can neither approve nor
  reject anything (it carries no assertion).
- The wallet's own approval gate independently re-checks that the passkey
  credential is on the profile's allowlist as the profile file reads at that
  moment, and still enrolled. Either layer refuses alone even if the other
  were somehow mis-wired.

TLS is mandatory; there is no plaintext remote path. Session cookies are
`HttpOnly`, `Secure`, and short-lived (see [Operational notes](#operational-notes)).

## Prerequisites

### The `[remote_approval]` profile block

Absent by default: remote mode does not exist for a profile until you add
this block. Field by field:

```toml
[remote_approval]
enabled = true
bind = "0.0.0.0:8443"
rp_id = "wallet.example.internal"
allowed_credentials = ["c9k3JGxPq1c_..."]
```

- **`enabled`**: must be `true`, together with the CLI's
  `--confirm-remote-exposure` flag, for `--remote` to actually start the
  listener. The block alone is not consent; both are required.
- **`bind`**: the socket address to bind, e.g. `"0.0.0.0:8443"` to listen on
  all interfaces, or a specific interface address. Validated as a real socket
  address before anything else happens; a malformed value refuses to start.
- **`rp_id`**: the WebAuthn Relying Party ID. This MUST be a DNS hostname
  that resolves to the wallet host from the device you will approve from. An
  IP address is not a valid Relying Party ID per WebAuthn Level 2 §5.1.2 and
  is refused outright, not silently accepted. See the worked example below.
- **`cert_path` and `key_path`**: explicit PEM files, both required on mainnet.
  Use absolute paths for both files.
  Relative values resolve against the process working directory.
  Testnet loads an explicit pair or provisions its default pair when both fields are absent.
  An incomplete pair refuses on every network; configured files never trigger generation.
- **`allowed_credentials`** (testnet only): the base64url WebAuthn credential IDs permitted
  to approve or reject. A credential enrolled (see below) but absent from
  this list is refused exactly like an unrecognized credential. Enrollment
  and authorization are two separate, both-required steps. The running
  listener reads this list at every login and every decision. Removing an
  id revokes that credential at once: its next login is refused, and its open
  sessions cannot approve or reject. This list does not change the mainnet
  approval credentials of the signed policy. An empty list authorizes no
  one. To revoke a credential for good, remove its id here first, then run
  `approve operator remove --credential-id <B64URL>` (see
  [CLI reference: `approve operator remove`](cli-reference/profile-and-governance.md#approve-operator-remove)).

### Making `rp_id` resolve

The approving device needs to resolve `rp_id` to the wallet host. Two common
ways, depending on your setup:

- **Internal DNS**: if the wallet host already has an internal name, use that name as `rp_id` and skip straight to enrollment. Examples include a home network with a local DNS resolver, or a company VPN with split-horizon DNS.
- **A hosts-file entry on the approving device**: if there is no internal
  DNS, add a line to the approving device's hosts file mapping the chosen
  hostname to the wallet host's IP address:

  ```
  # /etc/hosts (macOS/Linux) or C:\Windows\System32\drivers\etc\hosts (Windows)
  192.168.1.42   wallet.example.internal
  ```

  Use the same hostname as `rp_id` in the profile. This is a one-time,
  per-approving-device edit; it does not require control over any real DNS
  zone.

Either way, `rp_id` is never an IP literal. WebAuthn binds credentials to a
domain, not an address, and a browser will not run the ceremony against one.

## Signed-origin mainnet consent

Sign `approval_origin` and `approval_cert_spki_sha256` in the policy.
The pin is SHA-256 over the leaf certificate's SPKI DER.
It differs from the complete certificate fingerprint printed by testnet startup.
Set the profile's `rp_id` to the signed host, including every host label.
Configure the backend `bind`, `enabled = true`, `cert_path` and `key_path`.
The public origin may use a different port from the backend socket.

Only credentials in the current verified policy authorize login, approval and rejection.
The profile allowlist and enrolled public keys grant no mainnet trust.
The operator store supplies counters only; missing rows are created with policy metadata.
Each verified login or decision updates the counter once under the store lock.
Equal nonzero and lower counts refuse; zero may follow zero.
Receipt verification and commit make no counter update.
Rejection requires a fresh action assertion; a session cookie and CSRF value alone cannot reject.

The browser must trust the certificate independently of the wallet's SPKI pin.
Use a public-CA certificate or install the issuing private CA on the approving device.
Certificate issuance, renewal automation and TLS-terminating proxies are outside this listener's scope.
Replace files and restart after TLS rotation.
Running listeners never reload TLS.
Restart after policy signing, including a same-pin re-sign.
Fresh challenges and persistence reject a stale policy identity with `approval.listener_policy_stale`.

Missing, unreadable, malformed or mismatched PEM files report `approve.remote_tls_unavailable`, naming the field.
A loose private-key permission keeps the existing TLS provisioning refusal.
A different leaf key reports `approval.cert_pin_mismatch`.
A profile RP mismatch reports `approval.origin_profile_mismatch`.
Foreign Host or Origin headers refuse; forwarded headers supply no authority.

Signed-origin serving requires explicit `cert_path` and `key_path`, enabled remote configuration, and a profile RP matching the signed host.
The listener trusts current policy credentials and enforces their counters once per login or decision.
Restart it after policy signing or TLS replacement.
Persistent serve requires `--confirm-remote-exposure`, accepts `--no-open`, and uses no display or browser opener.
One-shot consent needs no exposure flag and prints `<signed-origin>/approvals/<id>` to stderr without a token.
Login continues to that id; completion, cancellation, expiry and interruption close the listener.
An occupied configured socket reports `approval.listener_busy`; use the running inbox.

### Enrolling a mainnet approval credential at the signed origin

The signed consent listener serves no `/enroll` page and no `/static/enroll.js` helper.
Enroll a mainnet approval credential for the signed RP with its own listener instead:

```bash
stellar-agent approve credential enroll --origin-from bootstrap.toml --profile mainnet
```

The bootstrap file is the unsigned policy body with `approval_origin` and `approval_cert_spki_sha256` together.
It needs no signature and no approval credential, and it need not be installed.
The command validates it as `profile policy-check` does and takes the origin, the RP and the pin from it.
It uses the same `bind`, `rp_id`, `cert_path` and `key_path` as signed consent, with the same startup refusals.
The approving device must already trust the certificate, as for consent.

The terminal prints the URL, `<signed-origin>/enroll`, and an eight-digit enrollment code.
On the approving device, open the URL and type the enrollment code.
The code works once, admits five attempts and lives the timeout, at most ten minutes.
Then create the passkey; the page shows a confirmation code.
Type that confirmation code at the terminal before the timeout.
Only that match exports the credential entry, with `rp_id` set to the signed host.
The command writes no profile, policy, store or keyring item.
Add the entry to `approval_credentials`, sign the policy and restart the listener.
Run enrollment and the `[remote_approval]` setup in the provisioning tier, never as a runtime service.

## Starting the testnet listener

```bash
stellar-agent approve serve --remote --confirm-remote-exposure --profile default
```

When both TLS paths are absent, testnet provisions a self-signed TLS certificate (via
`rcgen`) for `rp_id` and prints:

```
Remote approval inbox: https://wallet.example.internal:8443/
Certificate SHA-256 fingerprint (verify out-of-band before trusting): ab:cd:...
"wallet.example.internal" must resolve to this host from the approving device...
```

Verify the fingerprint out-of-band before trusting the certificate on the
approving device. Read it over a channel other than the connection you are
about to trust (a phone call, a message on an already-trusted channel, or
simply because you are standing at both machines). The certificate is
persisted and reused across restarts, so this verification is a one-time step
per wallet host, not a per-session one.

Do this before enrolling a passkey: the enrollment page below runs entirely
over this same TLS connection, so the certificate must already be trusted
before you point a browser at it.

## Enrolling a testnet operator credential

`approve operator enroll` has two modes, and which one applies here comes
down to one fact: a WebAuthn credential is bound to the origin that created
it. The browser requires the page's domain to match the credential's
Relying Party ID at creation time.

- This listener's `rp_id` is a real domain (`wallet.example.internal` in the
  examples above), so the credential has to be created by a page served from
  `https://<rp_id>` itself. That page can only be the remote listener's own
  `/enroll` page. A local file, or any other origin, cannot produce a
  credential usable against this listener. This section covers that path:
  **argument-import mode**.
- If you instead want to approve from the wallet host itself, or through an
  SSH tunnel (no `[remote_approval]` domain involved at all), use
  `approve operator enroll --interactive` on the wallet host directly. See
  [CLI reference: `approve operator enroll`](cli-reference/profile-and-governance.md#approve-operator-enroll).
  That mode verifies the registration against its own challenge and enrolls
  the credential only after you type the code its page shows at the
  terminal. It only ever produces `rp_id: "localhost"` credentials, which is
  why it cannot be used for this listener's domain-bound `rp_id`.

### Argument-import mode: enrolling via this listener's `/enroll` page

The testnet listener serves exactly the page this mode needs. A signed-origin
listener does not; see
[Enrolling a mainnet approval credential at the signed origin](#enrolling-a-mainnet-approval-credential-at-the-signed-origin).
On the approving device, after verifying the certificate fingerprint above:

1. Open `https://<rp_id>:<port>/enroll`.
2. Click "Create passkey" and complete your platform's passkey prompt.
3. The page displays the new credential's id, public key, and a best-effort
   seeded sign count, plus a ready-to-run command:

   ```bash
   stellar-agent approve operator enroll \
     --credential-id <B64URL> \
     --public-key <B64URL> \
     --rp-id wallet.example.internal \
     --label "my-laptop" \
     --sign-count <N>
   ```

4. Run that command on the **wallet host** (not the approving device).
   `approve operator enroll` validates the values and writes them to the
   profile's dedicated operator-approval credential store. This step never
   touches the network; it is a local write on the machine running the
   wallet.

The `/enroll` page itself saves nothing: it has no corresponding write
endpoint, and the wallet's network-exposed surface never accepts a new
credential over the wire (see [Trust model](#trust-model)). It only runs the
registration ceremony and displays the result for you to copy. The actual
enrollment write happens when you run the command above, on the wallet host.
This import path does not verify the registration on the server: unlike
`--interactive`, it has no server challenge and no terminal confirmation
code. Treat the displayed values as you would any other credential material
you are about to hand to a CLI command over a channel you already trust.

- `--credential-id`: the base64url `PublicKeyCredential.id`, prefilled in
  the displayed command.
- `--public-key`: the base64url-encoded 65-byte uncompressed SEC1 public key
  (`0x04 || X || Y`), prefilled in the displayed command.
- `--rp-id`: must match the profile's `rp_id` exactly; prefilled.
- `--label`: a name you choose, so `credentials list`-style tooling can show
  which device a credential belongs to (e.g. `"laptop"`, `"phone"`). Replace
  the placeholder in the displayed command before running it.
- `--sign-count`: the counter the page read at enrollment time, prefilled.
  It seeds the clone-detection baseline that assertion-time verification
  checks against; it never affects authorization by itself.

Finally, add the enrolled credential's id to the profile's
`[remote_approval] allowed_credentials` list (see
[Prerequisites](#the-remote_approval-profile-block)). Enrollment and
authorization are two separate, both-required steps, in EITHER mode.
A running `approve serve --remote` reads `allowed_credentials` and the
credential store at every login and every decision, so a credential you add
can log in without a restart. The other `[remote_approval]` settings are read
when the listener starts: restart it after changing `bind`. A running
listener refuses every login and decision while the profile disables remote
approval, names another `rp_id` or another chain, or cannot be read.

## Logging in and approving

1. Open `https://<rp_id>:<port>/` on the approving device. You will see a
   "Sign in with passkey" button, with no credential picker or password field;
   the passkey ceremony IS the sign-in.
2. Click it and complete the passkey prompt your platform shows (Touch ID,
   Windows Hello, or a security key), same as any other passkey sign-in.
3. You land on the inbox: the pending approvals list, updating automatically.
4. Click an entry to see the wallet-decoded summary of the parked action:
   payment, claim, or trustline, decoded from its transaction envelope. A
   trustline names the full holder and issuer, asset code, and limit. A claim
   names the balance by id; its asset and amount are not part of the signed
   claim transaction.
5. Click Approve or Reject. Each one prompts a FRESH passkey assertion.
   The browser calls out to your authenticator again, over a challenge bound
   to that exact entry, before the decision is applied. This is by design:
   see [Operational notes](#operational-notes).
6. On approve, the attestation appears with a copy button; hand it to the
   agent to complete the commit, the same as the local inbox's flow.

## Operational notes

- **Session TTL is 30 minutes, absolute.** There is no idle-timeout renewal;
  after 30 minutes from login you must sign in again, regardless of activity.
  An expired session is refused exactly like no session at all.
- **A passkey prompt on every approve or reject is intentional**, not a bug to
  route around. The per-action ceremony is what makes what-you-see-is-what-you-sign
  real for a network-exposed surface: the challenge is bound to the entry you
  are looking at and to the terms the page shows, so an assertion produced for
  one entry can never be replayed to authorize a different one or other terms.
- **The pre-authentication login endpoint is rate-limited** by an in-process
  token bucket, to bound how fast an unauthenticated caller can mint login
  challenges. This is not a substitute for network-level protection.
- **Firewalling the listener is your responsibility.** Binding `0.0.0.0` (or
  any non-loopback address) makes the port reachable from wherever your
  network routes to it; restrict access with your host or network firewall to
  the addresses that should reach it, the same discipline as any other
  exposed service.
