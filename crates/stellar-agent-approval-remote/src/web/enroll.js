// Stellar Agent Wallet — remote-approval passkey enrollment helper page.
//
// Same-origin, no build step. Served ungated at GET /static/enroll.js: like
// the login ceremony, enrollment must run before any session exists. Runs
// navigator.credentials.create() against THIS origin's rp_id (read from the
// #enroll-data island — a WebAuthn credential is bound to its rp.id at
// creation, so this page must be served from https://<rp_id> for the result
// to be usable against this listener) and displays the resulting credential
// id, SEC1-uncompressed public key, and a best-effort seeded sign count for
// manual entry into the loopback-only `approve operator enroll` CLI command.
// This page persists nothing: there is no write endpoint on the
// remote-approval surface.

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

  function setStatus(text) {
    var el = document.getElementById("status");
    if (el) {
      el.textContent = text;
    }
  }

  function labeledOutput(container, label, value, outputId) {
    var wrap = document.createElement("div");
    var lbl = document.createElement("p");
    lbl.textContent = label;
    wrap.appendChild(lbl);
    var area = document.createElement("textarea");
    area.readOnly = true;
    area.rows = 2;
    area.id = outputId;
    area.value = value;
    wrap.appendChild(area);
    container.appendChild(wrap);
  }

  function renderResult(container, rpId, credentialIdB64url, pubkeyB64url, signCount) {
    container.textContent = "";

    labeledOutput(container, "Credential id:", credentialIdB64url, "cred-id-output");
    labeledOutput(container, "Public key:", pubkeyB64url, "pubkey-output");
    labeledOutput(container, "Sign count (seed):", String(signCount), "sign-count-output");

    var cmdLabel = document.createElement("p");
    cmdLabel.textContent = "Run on the wallet host to finish enrollment:";
    container.appendChild(cmdLabel);

    var cmd = document.createElement("textarea");
    cmd.readOnly = true;
    cmd.rows = 6;
    cmd.id = "enroll-command-output";
    cmd.value =
      "stellar-agent approve operator enroll \\\n" +
      "  --credential-id " + credentialIdB64url + " \\\n" +
      "  --public-key " + pubkeyB64url + " \\\n" +
      "  --rp-id " + rpId + " \\\n" +
      "  --label \"my-device\" \\\n" +
      "  --sign-count " + signCount;
    container.appendChild(cmd);
  }

  function enroll(island) {
    setStatus("Creating passkey...");
    var challenge = crypto.getRandomValues(new Uint8Array(32));
    var userId = crypto.getRandomValues(new Uint8Array(16));
    return navigator.credentials
      .create({
        publicKey: {
          rp: { id: island.rp_id, name: "Stellar Agent Wallet" },
          user: { id: userId, name: "operator", displayName: "Operator" },
          challenge: challenge,
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: {
            residentKey: "required",
            userVerification: "required",
          },
        },
      })
      .then(function (credential) {
        var credentialId = b64urlFromBytes(credential.rawId);
        var pubkey = b64urlFromBytes(sec1FromSpki(credential.response.getPublicKey()));
        var signCount = extractSignCount(credential.response);
        setStatus("Passkey created. Copy the values below.");
        renderResult(document.getElementById("result"), island.rp_id, credentialId, pubkey, signCount);
      })
      .catch(function () {
        setStatus("Passkey creation failed. Try again.");
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
