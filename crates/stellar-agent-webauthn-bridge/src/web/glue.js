/*
 * Stellar Agent Wallet WebAuthn bridge — browser glue.
 *
 * Loaded by both `register.html` and `approve.html` after the vendored
 * `@simplewebauthn/browser` UMD bundle (which exposes the global
 * `SimpleWebAuthnBrowser`).  This file:
 *
 *   1. Reads the server-rendered `<script type="application/json"
 *      id="webauthn-options">` data island.
 *   2. Selects the registration or authentication ceremony based on the
 *      `flow` field.
 *   3. Calls `SimpleWebAuthnBrowser.startRegistration` or `.startAuthentication`.
 *   4. POSTs the resulting credential / assertion back to the bridge with
 *      the `X-Stellar-Approval-CSRF` header.
 *
 * # Security model
 *
 * - Inputs (challenge / RP-ID / credential-ID / CSRF) come exclusively from
 *   the server-rendered data island.  `window.location` is NEVER consulted
 *   by this wallet-authored glue.  (The vendored `@simplewebauthn/browser`
 *   bundle reads `globalThis.location.hostname` only in the `SecurityError`
 *   exception-mapping branch to compose error-message strings; that path
 *   never affects ceremony input selection, only the diagnostic surfaced
 *   to the operator via `textContent`.)
 * - For registration, the challenge comes from the data island: the bridge
 *   issued it with the pending registration and verifies the browser's
 *   response against it, together with the origin, the RP-ID hash and the
 *   credential the authenticator data names.  The page shows the
 *   confirmation code of its own credential only after the bridge accepted
 *   the response; the operator types that code at the terminal, which
 *   registers the passkey only when the code matches the credential the
 *   bridge recorded.
 * - For authentication, the challenge IS the wallet's `auth_digest` bytes
 *   (the SHA-256 over the signing context).  The bridge re-binds this
 *   server-side at submit time.
 * - No external network access: only `/register/<nonce>/credential` and
 *   `/approve/<nonce>/assertion` on the same origin.  `script-src 'self'`
 *   blocks anything else even if this glue is replaced at runtime.
 *
 * Both challenges are server-rendered into the page; error rendering is
 * generic (the bridge collapses error details before they reach the browser).
 *
 * # Presentation
 *
 * Every visible update goes through `setStatus`, which writes `textContent`
 * (never `innerHTML`) and mirrors the ceremony state onto two `data-state`
 * attributes: the status pill's, which selects the pill's colour, and the
 * document element's, which selects the brand mark's face. The stylesheet owns
 * both mappings; this file never touches styles or geometry.
 */

(function () {
  "use strict";

  // Wallet-authored glue runs as an IIFE; no globals exposed.

  // Sets the operator-visible status line and the page's ceremony state.
  // `state` is one of "busy", "ok", "error"; the stylesheet turns it into the
  // pill's colour and the brand mark's face.
  function setStatus(msg, state) {
    var el = document.getElementById("status");
    if (el) {
      el.textContent = msg;
      el.setAttribute("data-state", state);
    }
    document.documentElement.setAttribute("data-state", state);
  }

  function setStatusError(msg) {
    setStatus("Error: " + msg, "error");
  }

  // Shows the registration's confirmation code in `#confirmation-code`.
  function showConfirmationCode(code) {
    var el = document.getElementById("confirmation-code");
    if (el) {
      el.textContent = code;
      el.hidden = false;
    }
  }

  // Hides and empties `#confirmation-code`, so a failed or refused
  // registration never leaves a code on the page.
  function clearConfirmationCode() {
    var el = document.getElementById("confirmation-code");
    if (el) {
      el.textContent = "";
      el.hidden = true;
    }
  }

  // ───── Encoding helpers ─────────────────────────────────────────────

  function hexToBytes(hex) {
    if (typeof hex !== "string" || hex.length % 2 !== 0) {
      throw new Error("invalid hex string");
    }
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) {
      var b = parseInt(hex.substr(i * 2, 2), 16);
      if (isNaN(b)) {
        throw new Error("invalid hex byte");
      }
      out[i] = b;
    }
    return out;
  }

  function bytesToBase64url(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) {
      s += String.fromCharCode(bytes[i]);
    }
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64urlToBytes(b64u) {
    var b64 = b64u.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) {
      b64 += "=";
    }
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < out.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  function bytesToBase64Standard(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) {
      s += String.fromCharCode(bytes[i]);
    }
    return btoa(s);
  }

  // Extract the SEC1 uncompressed point (0x04 || X(32) || Y(32) = 65 bytes)
  // from a P-256 SPKI DER blob.  The SPKI structure ends with the BIT STRING
  // containing exactly the 65-byte SEC1 point, so the SEC1 form is the last
  // 65 bytes of the DER.  Validates the leading 0x04 marker.
  function spkiToSec1Uncompressed(spkiBytes) {
    if (spkiBytes.length < 65) {
      throw new Error("publicKey too short (got " + spkiBytes.length + ")");
    }
    var sec1 = spkiBytes.slice(spkiBytes.length - 65);
    if (sec1[0] !== 0x04) {
      throw new Error("publicKey not SEC1 uncompressed (marker byte not 0x04)");
    }
    return sec1;
  }

  // The domain separator of a passkey registration's confirmation code; the
  // terminal computes the code under the same domain.
  var PASSKEY_REGISTRATION_CODE_DOMAIN =
    "stellar-agent-passkey-registration-confirmation:v1";

  // The confirmation code, under `domain`, of the credential this page's
  // ceremony created: the first 16 hexadecimal digits of SHA-256 over the
  // domain, the 32-byte challenge, the credential ID's length as a
  // big-endian u32, the ID, and the 65-byte SEC1 key, in four groups of four.
  function confirmationCode(domain, challenge, credentialId, sec1) {
    var length = domain.length + challenge.length + 4 + credentialId.length + sec1.length;
    var input = new Uint8Array(length);
    var offset = 0;
    for (var i = 0; i < domain.length; i++) {
      input[offset++] = domain.charCodeAt(i);
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

  // The island's registration challenge as 32 bytes, or null when it is
  // missing or not 32 bytes of base64url.
  function islandChallenge(opts) {
    if (typeof opts.challenge !== "string") {
      return null;
    }
    var bytes;
    try {
      bytes = base64urlToBytes(opts.challenge);
    } catch (e) {
      return null;
    }
    return bytes.length === 32 ? bytes : null;
  }

  // ───── Network helpers ─────────────────────────────────────────────

  // POST `payload` (a plain object) as JSON to `path` with the CSRF header.
  // Returns the parsed response on 2xx; throws on non-2xx with a generic
  // message (the bridge collapses error details before responding).
  //
  // A rejected fetch means the transport never completed — in practice the
  // bridge has already shut down because its one-shot link expired. That is
  // the operator's actual situation, so it is reported as such; the raw
  // reason (a browser-specific TypeError) goes to the console instead, where
  // it is available for diagnosis without being the headline.
  function postJson(path, csrfToken, payload) {
    return fetch(path, {
      method: "POST",
      mode: "same-origin",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      headers: {
        "Content-Type": "application/json",
        "X-Stellar-Approval-CSRF": csrfToken,
      },
      body: JSON.stringify(payload),
    })
      .catch(function (e) {
        console.error("stellar-agent bridge: request transport failed", e);
        throw new Error(
          "could not reach the wallet. The link has likely expired."
        );
      })
      .then(function (resp) {
        if (!resp.ok) {
          throw new Error("HTTP " + resp.status);
        }
        return resp.json().catch(function () {
          return {};
        });
      });
  }

  // ───── Registration flow ────────────────────────────────────────────

  function doRegister(opts) {
    clearConfirmationCode();
    // The bridge verifies the response against the challenge it issued;
    // without that challenge no passkey is created.
    var challenge = islandChallenge(opts);
    if (challenge === null) {
      throw new Error("the registration page has no valid challenge");
    }
    var challengeB64 = bytesToBase64url(challenge);
    var credentialId = null;
    var sec1 = null;

    setStatus("Tap your authenticator to register a new passkey\u2026", "busy");

    var optionsJSON = {
      challenge: challengeB64,
      rp: { id: opts.rpId, name: "Stellar Agent Wallet" },
      user: {
        id: opts.userHandle,
        name: "stellar-agent-wallet-user",
        displayName: "Stellar Agent Wallet",
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "required",
      },
      attestation: "none",
      timeout: 60000,
    };

    return SimpleWebAuthnBrowser.startRegistration({ optionsJSON: optionsJSON })
      .then(function (cred) {
        if (!cred || !cred.response) {
          throw new Error("missing credential response");
        }
        if (!cred.response.publicKey) {
          throw new Error(
            "authenticator did not return publicKey; this browser is too old"
          );
        }
        var spkiBytes = base64urlToBytes(cred.response.publicKey);
        sec1 = spkiToSec1Uncompressed(spkiBytes);
        credentialId = base64urlToBytes(cred.rawId);
        var publicKeySec1B64 = bytesToBase64Standard(sec1);

        var body = {
          id: cred.id,
          rawId: cred.rawId,
          type: cred.type || "public-key",
          response: {
            clientDataJSON: cred.response.clientDataJSON,
            attestationObject: cred.response.attestationObject,
            publicKeySec1B64: publicKeySec1B64,
            transports: cred.response.transports || [],
          },
        };

        setStatus("Submitting credential to the wallet\u2026", "busy");
        return postJson(
          "/register/" + encodeURIComponent(opts.nonce) + "/credential",
          opts.csrfToken,
          body
        );
      })
      .then(function () {
        // The bridge accepted the response; the code names the credential
        // this ceremony created.
        return confirmationCode(PASSKEY_REGISTRATION_CODE_DOMAIN, challenge, credentialId, sec1);
      })
      .then(function (code) {
        showConfirmationCode(code);
        setStatus(
          "Passkey created. Type the code " +
            code +
            " at the terminal that started this registration. The passkey is registered only after the terminal accepts the code.",
          "ok"
        );
      })
      .catch(function (e) {
        clearConfirmationCode();
        throw e;
      });
  }

  // ───── Authentication flow ──────────────────────────────────────────

  function doApprove(opts) {
    setStatus("Tap your authenticator to authorise the transaction\u2026", "busy");

    var challengeBytes = hexToBytes(opts.authDigest);
    var challengeB64 = bytesToBase64url(challengeBytes);

    var optionsJSON = {
      challenge: challengeB64,
      rpId: opts.rpId,
      allowCredentials: [
        {
          type: "public-key",
          id: opts.credentialId,
        },
      ],
      userVerification: "required",
      timeout: 60000,
    };

    return SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: optionsJSON })
      .then(function (asn) {
        if (!asn || !asn.response) {
          throw new Error("missing assertion response");
        }
        var body = {
          id: asn.id,
          rawId: asn.rawId,
          type: asn.type || "public-key",
          response: {
            clientDataJSON: asn.response.clientDataJSON,
            authenticatorData: asn.response.authenticatorData,
            signature: asn.response.signature,
            userHandle: asn.response.userHandle || null,
          },
        };

        setStatus("Submitting authorisation to the wallet\u2026", "busy");
        return postJson(
          "/approve/" + encodeURIComponent(opts.nonce) + "/assertion",
          opts.csrfToken,
          body
        );
      })
      .then(function () {
        setStatus("Authorisation complete. You can close this window.", "ok");
      });
  }

  // ───── Entry point ──────────────────────────────────────────────────

  function main() {
    if (typeof SimpleWebAuthnBrowser !== "object" || SimpleWebAuthnBrowser === null) {
      setStatusError("WebAuthn bundle missing; reload the page.");
      return;
    }

    var island = document.getElementById("webauthn-options");
    if (!island) {
      setStatusError("server data island missing");
      return;
    }
    var opts;
    try {
      opts = JSON.parse(island.textContent);
    } catch (e) {
      setStatusError("server data island is not valid JSON");
      return;
    }
    if (typeof opts !== "object" || opts === null) {
      setStatusError("server data island has wrong shape");
      return;
    }

    var flow;
    try {
      if (opts.flow === "register") {
        flow = doRegister(opts);
      } else if (opts.flow === "approve") {
        flow = doApprove(opts);
      } else {
        setStatusError("unknown flow");
        return;
      }
    } catch (e) {
      setStatusError(e && e.message ? e.message : "unexpected glue error");
      return;
    }

    flow.catch(function (e) {
      // Bridge already collapses error details; we surface the
      // browser-side error (e.g. user-cancel, authenticator timeout, network)
      // to the operator at the same redaction level (no credential bytes).
      var msg = e && e.message ? e.message : "unexpected glue error";
      setStatusError(msg);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", main);
  } else {
    main();
  }
})();
