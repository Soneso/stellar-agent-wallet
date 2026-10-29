// Stellar Agent Wallet — interactive operator-enrollment ceremony (loopback).
//
// Same-origin, no build step. Served only after the operator's browser has
// exchanged the one-time bootstrap token for a session cookie at
// GET /bootstrap/{token}; this file and the /enroll page it runs inside are
// both gated on that cookie. The bootstrap page also stored a session proof
// in this tab's sessionStorage (see /static/session-bootstrap.js); both POSTs
// carry it in the X-Session-Proof header, and a tab without it refuses to
// start the ceremony, because the server would refuse the result.
//
// The ceremony:
//
// 1. POST /enroll/challenge returns the server's single-use registration
//    challenge and options.
// 2. navigator.credentials.create() registers a credential over that
//    challenge against rp.id "localhost", the only rp.id a loopback HTTP
//    origin can claim (a WebAuthn credential is bound to its rp.id at
//    creation).
// 3. POST /enroll/credential sends the credential ID, the uncompressed SEC1
//    public key, the label, and the authenticator's clientDataJSON and
//    attestationObject, which the server verifies against its challenge.
//    The server stages the credential; it does not enroll it.
// 4. The page computes the confirmation code from the credential its own
//    ceremony created, never from anything the server returns, and shows it.
//    The operator types it at the terminal, which enrolls the credential
//    only when the codes match.
//
// The code is the first 16 hex characters of SHA-256 over
// "stellar-agent-operator-enrollment-confirmation:v1" || challenge (32) ||
// u32 big-endian credential-ID length || credential ID || SEC1 key (65),
// shown as four groups of four.

(function () {
  "use strict";

  var PROOF_KEY = "stellar-agent-operator-enroll-session-proof";
  var CODE_DOMAIN = "stellar-agent-operator-enrollment-confirmation:v1";

  function readProof() {
    try {
      var proof = window.sessionStorage.getItem(PROOF_KEY);
      return typeof proof === "string" && proof.length > 0 ? proof : null;
    } catch (e) {
      return null;
    }
  }

  function b64urlFromBytes(bytes) {
    var bin = "";
    var arr = new Uint8Array(bytes);
    for (var i = 0; i < arr.length; i++) {
      bin += String.fromCharCode(arr[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function bytesFromB64url(text) {
    var padded = text.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4 !== 0) {
      padded += "=";
    }
    var bin = atob(padded);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  // Extracts the uncompressed SEC1 EC point (65 bytes: 0x04 || X || Y) from a
  // P-256 SubjectPublicKeyInfo DER blob, as returned by
  // PublicKeyCredential.response.getPublicKey(). A P-256 SPKI's ASN.1 header
  // (the algorithm identifier for id-ecPublicKey + the prime256v1 OID) is
  // fixed-length, so the raw point is always exactly the LAST 65 bytes. The
  // server checks it against the key the attestation object carries.
  function sec1FromSpki(spkiBuf) {
    var bytes = new Uint8Array(spkiBuf);
    return bytes.slice(bytes.length - 65);
  }

  // The confirmation code of the credential this page's ceremony created.
  function confirmationCode(challenge, credentialId, sec1) {
    var length = CODE_DOMAIN.length + challenge.length + 4 + credentialId.length + sec1.length;
    var input = new Uint8Array(length);
    var offset = 0;
    for (var i = 0; i < CODE_DOMAIN.length; i++) {
      input[offset++] = CODE_DOMAIN.charCodeAt(i);
    }
    input.set(challenge, offset);
    offset += challenge.length;
    var idLength = credentialId.length;
    input[offset++] = (idLength >>> 24) & 0xff;
    input[offset++] = (idLength >>> 16) & 0xff;
    input[offset++] = (idLength >>> 8) & 0xff;
    input[offset++] = idLength & 0xff;
    input.set(credentialId, offset);
    offset += credentialId.length;
    input.set(sec1, offset);
    return crypto.subtle.digest("SHA-256", input).then(function (digest) {
      var bytes = new Uint8Array(digest);
      var hex = "";
      for (var j = 0; j < 8; j++) {
        hex += (bytes[j] < 16 ? "0" : "") + bytes[j].toString(16);
      }
      return hex.slice(0, 4) + "-" + hex.slice(4, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16);
    });
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

  // Shows the confirmation code in its own element, or clears it.
  function showCode(code) {
    var el = document.getElementById("confirmation-code");
    if (el) {
      el.textContent = code || "";
      el.hidden = !code;
    }
  }

  // A rejected fetch means the transport never completed — in practice the
  // enrollment server has already shut down, because its window is one-shot.
  // The raw reason (a browser-specific TypeError) goes to the console, where
  // it is available for diagnosis.
  function post(island, proof, path, body) {
    return fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "content-type": "application/json",
        "x-stellar-approval-csrf": island.csrfToken,
        "x-session-proof": proof,
      },
      body: JSON.stringify(body),
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

  // Reads a refused response's error code into a tagged error.
  function refused(resp) {
    return resp
      .json()
      .catch(function () {
        return null;
      })
      .then(function (body) {
        var err = new Error(
          "Enrollment failed: " + (body && body.error ? body.error : "unknown error")
        );
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
    var proof = readProof();
    if (!proof) {
      setStatus(
        "This tab has no wallet session. Use the tab the command opened, or restart it for a new link.",
        "error"
      );
      return;
    }

    showCode(null);
    setStatus("Requesting a challenge from the wallet…", "busy");
    var ceremony = {};
    post(island, proof, "/enroll/challenge", {})
      .then(function (resp) {
        if (!resp.ok) {
          return refused(resp);
        }
        return resp.json();
      })
      .then(function (options) {
        ceremony.challenge = bytesFromB64url(options.challenge);
        setStatus("Creating passkey…", "busy");
        return navigator.credentials.create({
          publicKey: {
            rp: { id: options.rp_id, name: "Stellar Agent Wallet" },
            user: {
              id: crypto.getRandomValues(new Uint8Array(16)),
              name: "operator",
              displayName: "Operator",
            },
            challenge: ceremony.challenge,
            pubKeyCredParams: [{ type: "public-key", alg: options.alg }],
            authenticatorSelection: {
              residentKey: options.resident_key,
              userVerification: options.user_verification,
            },
            attestation: options.attestation,
            timeout: options.timeout_ms,
          },
        });
      })
      .then(function (credential) {
        var response = credential.response;
        var spki = typeof response.getPublicKey === "function" ? response.getPublicKey() : null;
        if (!spki || !response.clientDataJSON || !response.attestationObject) {
          var unusable = new Error(
            "Your authenticator did not return a usable public key. Try a different authenticator."
          );
          unusable.walletTransport = true;
          throw unusable;
        }
        ceremony.credentialId = new Uint8Array(credential.rawId);
        ceremony.sec1 = sec1FromSpki(spki);
        setStatus("Passkey created. Sending it to the wallet…", "busy");
        return post(island, proof, "/enroll/credential", {
          credential_id_b64url: b64urlFromBytes(ceremony.credentialId),
          public_key_sec1_b64: b64urlFromBytes(ceremony.sec1),
          label: label,
          client_data_json: b64urlFromBytes(response.clientDataJSON),
          attestation_object: b64urlFromBytes(response.attestationObject),
        });
      })
      .then(function (resp) {
        if (!resp.ok) {
          return refused(resp);
        }
        return confirmationCode(ceremony.challenge, ceremony.credentialId, ceremony.sec1);
      })
      .then(function (code) {
        showCode(code);
        setStatus(
          "Awaiting confirmation. Type the code " + code + " at the terminal that " +
            "started this enrollment. The credential is enrolled only after the " +
            "terminal accepts the code, and it must still be added to this profile's " +
            "[remote_approval] allowed_credentials list before it can approve anything.",
          "ok"
        );
      })
      .catch(function (e) {
        showCode(null);
        // A passkey-creation rejection is a DOMException; every refusal and
        // transport failure this page raises itself is tagged.
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
