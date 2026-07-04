# Remote approval

Approve or reject pending agent actions from a device other than the wallet
host — without an SSH tunnel. `approve serve --remote` binds a TLS-protected
HTTP listener beyond loopback, authenticates you with a registered passkey,
and requires a fresh passkey assertion for every approve or reject action.

If the agent and the wallet run on the same machine you approve from, you do
not need this: `stellar-agent approve serve` (see
[cli-reference/profile-and-governance.md](cli-reference/profile-and-governance.md))
is loopback-only and simpler. Remote approval is for the case where the agent
runs on a headless host or a different machine than the one you carry around.

## Trust model

Nothing about what an approval means changes. The attestation is still minted
on the wallet host, from the same HMAC preimage, over the same pending-entry
data the wallet itself parked — remote mode changes *who* may consent and
*from where*, never what consent produces. A commit cannot tell whether an
attestation came from the local inbox or the remote listener; only the audit
log records the distinction (`ApprovalAttestedRemote` / `ApprovalRejectedRemote`
event kinds, separate from the loopback `ApprovalAttested` / `ApprovalRejected`
ones).

Two independent layers must both hold for a remote approve or reject to take
effect:

- The HTTP layer verifies a fresh WebAuthn passkey assertion, computed over a
  challenge cryptographically bound to the exact pending entry you are
  deciding — an assertion produced for one entry can never authorize a
  different one, and a stolen session cookie alone can neither approve nor
  reject anything (it carries no assertion).
- The wallet's own approval gate independently re-checks that the passkey
  credential is on the profile's allowlist. Either layer refuses alone even
  if the other were somehow mis-wired.

TLS is mandatory; there is no plaintext remote path. Session cookies are
`HttpOnly`, `Secure`, and short-lived (see [Operational notes](#operational-notes)).

## Prerequisites

### The `[remote_approval]` profile block

Absent by default — remote mode does not exist for a profile until you add
this block. Field by field:

```toml
[remote_approval]
enabled = true
bind = "0.0.0.0:8443"
rp_id = "wallet.example.internal"
allowed_credentials = ["c9k3JGxPq1c_..."]
```

- **`enabled`** — must be `true`, together with the CLI's
  `--confirm-remote-exposure` flag, for `--remote` to actually start the
  listener. The block alone is not consent; both are required.
- **`bind`** — the socket address to bind, e.g. `"0.0.0.0:8443"` to listen on
  all interfaces, or a specific interface address. Validated as a real socket
  address before anything else happens; a malformed value refuses to start.
- **`rp_id`** — the WebAuthn Relying Party ID. This MUST be a DNS hostname
  that resolves to the wallet host from the device you will approve from — an
  IP address is not a valid Relying Party ID per WebAuthn Level 2 §5.1.2 and
  is refused outright, not silently accepted. See the worked example below.
- **`allowed_credentials`** — the base64url WebAuthn credential IDs permitted
  to approve or reject. A credential enrolled (see below) but absent from
  this list is refused exactly like an unrecognized credential — enrollment
  and authorization are two separate, both-required steps.

### Making `rp_id` resolve

The approving device needs to resolve `rp_id` to the wallet host. Two common
ways, depending on your setup:

- **Internal DNS** — if the wallet host already has an internal name (e.g. on
  a home network with a local DNS resolver, or a company VPN with split-horizon
  DNS), use that name as `rp_id` and skip straight to enrollment.
- **A hosts-file entry on the approving device** — if there is no internal
  DNS, add a line to the approving device's hosts file mapping the chosen
  hostname to the wallet host's IP address:

  ```
  # /etc/hosts (macOS/Linux) or C:\Windows\System32\drivers\etc\hosts (Windows)
  192.168.1.42   wallet.example.internal
  ```

  Use the same hostname as `rp_id` in the profile. This is a one-time,
  per-approving-device edit; it does not require control over any real DNS
  zone.

Either way, `rp_id` is never an IP literal — WebAuthn binds credentials to a
domain, not an address, and a browser will not run the ceremony against one.

## Starting the listener

```bash
stellar-agent approve serve --remote --confirm-remote-exposure --profile default
```

On first start the wallet provisions a self-signed TLS certificate (via
`rcgen`) for `rp_id` and prints:

```
Remote approval inbox: https://wallet.example.internal:8443/
Certificate SHA-256 fingerprint (verify out-of-band before trusting): ab:cd:...
"wallet.example.internal" must resolve to this host from the approving device...
```

Verify the fingerprint out-of-band before trusting the certificate on the
approving device — read it over a channel other than the connection you are
about to trust (a phone call, a message on an already-trusted channel, or
simply because you are standing at both machines). The certificate is
persisted and reused across restarts, so this verification is a one-time step
per wallet host, not a per-session one.

Do this before enrolling a passkey: the enrollment page below runs entirely
over this same TLS connection, so the certificate must already be trusted
before you point a browser at it.

## Enrolling a passkey credential

A WebAuthn credential is bound to the origin that created it: the browser
requires the page's domain to match the credential's Relying Party ID at
creation time. This means the credential has to be created by a page served
from `https://<rp_id>` itself — a page opened from a local file, or from any
other origin, cannot produce a credential usable against this listener.

The wallet serves exactly such a page. On the approving device, after
verifying the certificate fingerprint above:

1. Open `https://<rp_id>:<port>/enroll`.
2. Click "Create passkey" and complete your platform's passkey prompt.
3. The page displays the new credential's id and public key, and a ready-to-run
   command:

   ```bash
   stellar-agent approve operator enroll \
     --credential-id <B64URL> \
     --public-key <B64URL> \
     --rp-id wallet.example.internal \
     --label "my-laptop"
   ```

4. Run that command on the **wallet host** (not the approving device).
   `approve operator enroll` validates the two values and writes them to the
   profile's dedicated operator-approval credential store — this step never
   touches the network; it is a local write on the machine running the
   wallet.

The `/enroll` page itself saves nothing: it has no corresponding write
endpoint, and the wallet's network-exposed surface never accepts a new
credential over the wire (see [Trust model](#trust-model)). It only runs the
registration ceremony and displays the result for you to copy — the actual
enrollment write happens when you run the command above, on the wallet host.
Server-verified registration (the wallet confirming the ceremony's
attestation itself) is not implemented in this alpha; treat the displayed
values as you would any other credential material you are about to hand to a
CLI command over a channel you already trust.

- `--credential-id` — the base64url `PublicKeyCredential.id`, prefilled in
  the displayed command.
- `--public-key` — the base64url-encoded 65-byte uncompressed SEC1 public key
  (`0x04 || X || Y`), prefilled in the displayed command.
- `--rp-id` — must match the profile's `rp_id` exactly; prefilled.
- `--label` — a name you choose, so `credentials list`-style tooling can show
  which device a credential belongs to (e.g. `"laptop"`, `"phone"`) — replace
  the placeholder in the displayed command before running it.

Finally, add the enrolled credential's id to the profile's
`[remote_approval] allowed_credentials` list (see
[Prerequisites](#the-remote_approval-profile-block)) — enrollment and
authorization are two separate, both-required steps. `allowed_credentials` is
read once when the listener starts, so restart `approve serve --remote` after
editing it — the newly enrolled credential is not recognized until you do.

## Logging in and approving

1. Open `https://<rp_id>:<port>/` on the approving device. You will see a
   "Sign in with passkey" button — no credential picker or password field;
   the passkey ceremony IS the sign-in.
2. Click it and complete the passkey prompt your platform shows (Touch ID,
   Windows Hello, or a security key), same as any other passkey sign-in.
3. You land on the inbox: the pending approvals list, updating automatically.
4. Click an entry to see its detail page — the wallet-decoded summary
   (destination, amount, asset, fee) the server itself parked, never the
   agent's description of it.
5. Click Approve or Reject. Each one prompts a FRESH passkey assertion —
   the browser calls out to your authenticator again, over a challenge bound
   to that exact entry — before the decision is applied. This is by design:
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
  are looking at, so an assertion produced for one entry can never be replayed
  to authorize a different one.
- **The pre-authentication login endpoint is rate-limited** by an in-process
  token bucket, to bound how fast an unauthenticated caller can mint login
  challenges. This is not a substitute for network-level protection.
- **Firewalling the listener is your responsibility.** Binding `0.0.0.0` (or
  any non-loopback address) makes the port reachable from wherever your
  network routes to it; restrict access with your host or network firewall to
  the addresses that should reach it, the same discipline as any other
  exposed service.
