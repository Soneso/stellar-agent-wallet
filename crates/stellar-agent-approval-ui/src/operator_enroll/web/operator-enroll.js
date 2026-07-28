// Stellar Agent Wallet — interactive operator-enrollment ceremony (loopback).
//
// Same-origin, no build step. Served only after the operator's browser has
// exchanged the one-time bootstrap token for a session cookie at
// GET /bootstrap/{token}; this file and the /enroll page it runs inside are
// both gated on that cookie. Runs navigator.credentials.create() against
// rp.id "localhost" — the only rp.id a loopback HTTP origin can claim (a
// WebAuthn credential is bound to its rp.id at creation) — extracts the
// uncompressed SEC1 public key and a best-effort sign-count seed
// client-side, and POSTs the result, with the session cookie and a
// session-derived CSRF header, to POST /enroll/credential, which persists it
// via
// stellar_agent_core::approval::operator_credentials::OperatorApprovalCredentialStore.
//
// Attestation is requested as "none" and its statement is never inspected:
// enrolling a credential here grants nothing by itself — the profile's
// [remote_approval] allowed_credentials allowlist is the authorization gate
// (see the crate::operator_enroll module docs for the full rationale).

(function () {
  "use strict";

  function b64urlFromBytes(bytes) {
    var bin = "";
    var arr = new Uint8Array(bytes);
    for (var i = 0; i < arr.length; i++) {
      bin += String.fromCharCode(arr[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // Extracts the uncompressed SEC1 EC point (65 bytes: 0x04 || X || Y) from a
  // P-256 SubjectPublicKeyInfo DER blob, as returned by
  // PublicKeyCredential.response.getPublicKey(). A P-256 SPKI's ASN.1 header
  // (the algorithm identifier for id-ecPublicKey + the prime256v1 OID) is
  // fixed-length, so the raw point is always exactly the LAST 65 bytes.
  function sec1FromSpki(spkiBuf) {
    var bytes = new Uint8Array(spkiBuf);
    return bytes.slice(bytes.length - 65);
  }

  // Extracts the 32-bit big-endian signature counter from authenticatorData
  // bytes [33..37) — rp_id_hash (0..32) + flags (32) + counter (33..37) —
  // the same offsets stellar-agent-approval-remote::verify reads at
  // assertion time. Returns 0 ("counter unsupported", per WebAuthn Level 2)
  // when the browser lacks getAuthenticatorData() rather than parsing the
  // CBOR attestationObject client-side; the seed is best-effort by design
  // (see OperatorApprovalCredential::sign_count rustdoc).
  function extractSignCount(response) {
    if (typeof response.getAuthenticatorData !== "function") {
      return 0;
    }
    var authData = new Uint8Array(response.getAuthenticatorData());
    if (authData.length < 37) {
      return 0;
    }
    return (
      ((authData[33] << 24) |
        (authData[34] << 16) |
        (authData[35] << 8) |
        authData[36]) >>>
      0
    );
  }

  function readIsland(id) {
    var el = document.getElementById(id);
    if (!el) {
      return null;
    }
    try {
      return JSON.parse(el.textContent);
    } catch (e) {
      return null;
    }
  }

  // Sets the operator-visible status line and the page's ceremony state.
  // `state` is one of "busy", "ok", "error"; the stylesheet turns it into the
  // pill's colour and the brand mark's face. Writes are textContent only.
  function setStatus(text, state) {
    var el = document.getElementById("status");
    if (el) {
      el.textContent = text;
      el.setAttribute("data-state", state);
    }
    document.documentElement.setAttribute("data-state", state);
  }

  // A rejected fetch means the transport never completed — in practice the
  // enrollment server has already shut down, because its window is one-shot.
  // The passkey itself WAS created by then, so reporting "passkey creation
  // failed" would be false; the operator's actual situation is a link that no
  // longer resolves. The raw reason (a browser-specific TypeError) goes to the
  // console instead, where it is available for diagnosis.
  function postCredential(island, credentialIdB64url, pubkeyB64url, label, signCount) {
    return fetch("/enroll/credential", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "content-type": "application/json",
        "x-stellar-approval-csrf": island.csrfToken,
      },
      body: JSON.stringify({
        credential_id_b64url: credentialIdB64url,
        public_key_sec1_b64: pubkeyB64url,
        label: label,
        sign_count: signCount,
      }),
    }).catch(function (e) {
      console.error("stellar-agent enrollment: request transport failed", e);
      var err = new Error(
        "Error: could not reach the wallet. The link has likely expired."
      );
      // Tagged so the outer handler can tell a dead link from a passkey the
      // operator declined; a DOMException from credentials.create() also
      // carries a message, so the message alone cannot distinguish them.
      err.walletTransport = true;
      throw err;
    });
  }

  function enroll(island) {
    var labelInput = document.getElementById("label-input");
    var label = labelInput ? labelInput.value.trim() : "";
    if (!label) {
      setStatus("Enter a label first.", "error");
      return;
    }

    setStatus("Creating passkey\u2026", "busy");
    var challenge = crypto.getRandomValues(new Uint8Array(32));
    var userId = crypto.getRandomValues(new Uint8Array(16));
    navigator.credentials
      .create({
        publicKey: {
          rp: { id: island.rpId, name: "Stellar Agent Wallet" },
          user: { id: userId, name: "operator", displayName: "Operator" },
          challenge: challenge,
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: {
            residentKey: "required",
            userVerification: "required",
          },
          attestation: "none",
        },
      })
      .then(function (credential) {
        if (typeof credential.response.getPublicKey !== "function") {
          setStatus("Your authenticator did not return a usable public key. Try a different authenticator.", "error");
          return;
        }
        var spki = credential.response.getPublicKey();
        if (!spki) {
          setStatus("Your authenticator did not return a usable public key. Try a different authenticator.", "error");
          return;
        }
        var credentialId = b64urlFromBytes(credential.rawId);
        var pubkey = b64urlFromBytes(sec1FromSpki(spki));
        var signCount = extractSignCount(credential.response);
        setStatus("Passkey created. Finishing enrollment\u2026", "busy");
        return postCredential(island, credentialId, pubkey, label, signCount);
      })
      .then(function (resp) {
        // An unusable-public-key branch above returns without posting; its
        // status line is the accurate one, so it stands.
        if (!resp) {
          return;
        }
        if (resp.ok) {
          setStatus(
            "Enrolled. This credential must still be added to this profile's " +
              "[remote_approval] allowed_credentials list before it can approve anything. " +
              "You may close this tab.",
            "ok"
          );
          return;
        }
        return resp
          .json()
          .then(function (body) {
            setStatus("Enrollment failed: " + (body && body.error ? body.error : "unknown error"), "error");
          })
          .catch(function () {
            setStatus("Enrollment failed.", "error");
          });
      })
      .catch(function (e) {
        // The passkey-creation rejection and the transport rejection land here
        // together. The passkey was already created by the time a transport
        // failure can happen, so reporting creation failure would be false.
        setStatus(
          e && e.walletTransport
            ? e.message
            : "Passkey creation failed. Try again.",
          "error"
        );
      });
  }

  var island = readIsland("enroll-data");
  var btn = document.getElementById("enroll-btn");
  if (btn && island) {
    btn.addEventListener("click", function () {
      enroll(island);
    });
  }
})();
