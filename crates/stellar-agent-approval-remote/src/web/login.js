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

  function setStatus(text) {
    var el = document.getElementById("status");
    if (el) {
      el.textContent = text;
    }
  }

  function login() {
    setStatus("Requesting challenge...");
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
        setStatus("Verifying...");
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
        setStatus("Signed in.");
        window.location.href = "/inbox";
      })
      .catch(function () {
        setStatus("Sign-in failed. Try again.");
      });
  }

  var btn = document.getElementById("login-btn");
  if (btn) {
    btn.addEventListener("click", function () {
      login();
    });
  }
})();
