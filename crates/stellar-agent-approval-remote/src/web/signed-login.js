// Stellar Agent Wallet signed-origin login-page browser glue.
//
// Same-origin, no build step. The public script runs before a session exists.
// It mints a login challenge, invokes navigator.credentials.get, and posts the assertion.
// A successful login sets the session cookie and navigates to the validated destination.

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

  function login(retries) {
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
            rpId: body.rp_id,
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
        if (resp.status === 503) {
          return resp.json().then(function (body) {
            if (body.error === "store_busy" && body.retriable === true) {
              if (retries > 0) {
                return login(retries - 1);
              }
              throw new Error("store_busy");
            }
            throw new Error("login_failed");
          });
        }
        if (!resp.ok) {
          throw new Error("login_failed");
        }
        setStatus("Signed in.", "ok");
        var data = JSON.parse(document.getElementById("login-destination").textContent);
        window.location.href = data.destination;
      })
      .catch(function (error) {
        var message = error.message === "store_busy"
          ? "Wallet is busy. Try again."
          : "Sign-in failed. Try again.";
        setStatus(message, "error");
      });
  }

  var btn = document.getElementById("login-btn");
  if (btn) {
    btn.addEventListener("click", function () {
      login(3);
    });
  }
})();
