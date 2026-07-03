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
 * - For registration, the challenge is generated client-side via
 *   `crypto.getRandomValues`.  The bridge does NOT verify the challenge
 *   value at registration time — the approval-store nonce (path-bound,
 *   one-shot per `AlreadyAttested`) is the actual replay defence.
 * - For authentication, the challenge IS the wallet's `auth_digest` bytes
 *   (the SHA-256 over the signing context).  The bridge re-binds this
 *   server-side at submit time.
 * - No external network access: only `/register/<nonce>/credential` and
 *   `/approve/<nonce>/assertion` on the same origin.  `script-src 'self'`
 *   blocks anything else even if this glue is replaced at runtime.
 *
 * The challenge is server-rendered into the page; error rendering is generic
 * (the bridge collapses error details before they reach the browser).
 */

(function () {
  "use strict";

  // Wallet-authored glue runs as an IIFE; no globals exposed.

  function setStatus(msg) {
    var el = document.getElementById("status");
    if (el) {
      el.textContent = msg;
    }
  }

  function setStatusError(msg) {
    setStatus("Error: " + msg);
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

  // ───── Network helpers ─────────────────────────────────────────────

  // POST `payload` (a plain object) as JSON to `path` with the CSRF header.
  // Returns the parsed response on 2xx; throws on non-2xx with a generic
  // message (the bridge collapses error details before responding).
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
    }).then(function (resp) {
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
    setStatus("Tap your authenticator to register a new passkey...");

    // 32 bytes of CSPRNG — bridge does not bind this; the approval nonce is
    // the actual one-shot guard.
    var challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);
    var challengeB64 = bytesToBase64url(challenge);

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
        var sec1 = spkiToSec1Uncompressed(spkiBytes);
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

        setStatus("Submitting credential to the wallet...");
        return postJson(
          "/register/" + encodeURIComponent(opts.nonce) + "/credential",
          opts.csrfToken,
          body
        );
      })
      .then(function () {
        setStatus("Passkey registered. You can close this window.");
      });
  }

  // ───── Authentication flow ──────────────────────────────────────────

  function doApprove(opts) {
    setStatus("Tap your authenticator to authorise the transaction...");

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

        setStatus("Submitting authorisation to the wallet...");
        return postJson(
          "/approve/" + encodeURIComponent(opts.nonce) + "/assertion",
          opts.csrfToken,
          body
        );
      })
      .then(function () {
        setStatus("Authorisation complete. You can close this window.");
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
