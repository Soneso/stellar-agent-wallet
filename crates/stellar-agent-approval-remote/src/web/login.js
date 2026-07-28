// Stellar Agent Wallet — remote-approval login-page browser glue.
//
// Same-origin, no build step. Served ungated at GET /static/login.js: the
// passkey login ceremony IS the authentication step, so there is no session
// yet for this script to run behind. Runs the WebAuthn login ceremony —
// mints a single-use login challenge, invokes navigator.credentials.get,
// posts the resulting assertion — and on success navigates to /inbox (the
// server has already set the session cookie by the time the POST resolves).

(function () {
  "use strict";

  function b64urlToBytes(b64url) {
    var b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    var pad = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    var bin = atob(pad);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
  }

  function bytesToB64url(bytes) {
    var bin = "";
    var arr = new Uint8Array(bytes);
    for (var i = 0; i < arr.length; i++) {
      bin += String.fromCharCode(arr[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function assertionToWire(assertion) {
    return {
      id: assertion.id,
      response: {
        authenticator_data: bytesToB64url(assertion.response.authenticatorData),
        client_data_json: bytesToB64url(assertion.response.clientDataJSON),
        signature: bytesToB64url(assertion.response.signature),
      },
    };
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

  function login() {
    setStatus("Requesting challenge\u2026", "busy");
    return fetch("/login/challenge", { method: "POST" })
      .then(function (resp) {
        if (!resp.ok) {
          throw new Error("challenge_failed");
        }
        return resp.json();
      })
      .then(function (body) {
        return navigator.credentials.get({
          publicKey: {
            challenge: b64urlToBytes(body.challenge),
            userVerification: "required",
            timeout: 60000,
          },
        });
      })
      .then(function (assertion) {
        setStatus("Verifying\u2026", "busy");
        return fetch("/login/assertion", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ assertion: assertionToWire(assertion) }),
        });
      })
      .then(function (resp) {
        if (!resp.ok) {
          throw new Error("login_failed");
        }
        setStatus("Signed in.", "ok");
        window.location.href = "/inbox";
      })
      .catch(function () {
        setStatus("Sign-in failed. Try again.", "error");
      });
  }

  var btn = document.getElementById("login-btn");
  if (btn) {
    btn.addEventListener("click", function () {
      login();
    });
  }
})();
