// Stellar Agent Wallet — remote-approval post-authentication browser glue.
//
// Same-origin, no build step. Served behind the session cookie at
// GET /static/app.js, and loaded AFTER /static/app-shared.js, which carries the
// rendering both approval surfaces share; this file holds only what is specific
// to the remote server: its CSRF header and the per-action passkey ceremony.
// Loaded on both the inbox shell and the per-approval detail page; detects
// which page it is on by the presence of the corresponding JSON data island
// (#pending-data or #approval-data).
//
// Inbox: reads #pending-data, renders one row per pending approval (each a
// link to /approval/<nonce>), then re-fetches /pending.json every two
// seconds to keep the rows and the document-title badge current.
//
// Detail: reads #approval-data (nonce + CSRF value) and wires the Approve /
// Reject buttons to the full per-action ceremony: mint a challenge bound to
// THIS approval (POST /approval/<nonce>/challenge), run
// navigator.credentials.get over it, then POST the resulting assertion to
// /approval/<nonce>/decision. A fresh passkey assertion is required for
// every approve or reject, not just for login.
//
// # DOM discipline
//
// Every node is built with createElement and filled with textContent. Nothing
// here assigns innerHTML or inserts markup, so no server-supplied value can
// become an element regardless of what it contains.

(function () {
  "use strict";

  var shared = stellarAgentApproval;
  var CSRF_HEADER = "x-stellar-remote-approval-csrf";

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

  // ── Inbox ──────────────────────────────────────────────────────────────

  function updateBadge(count) {
    var base = "Stellar Agent Wallet — Remote Approval";
    document.title = count > 0 ? "(" + count + ") " + base : base;
  }

  function startInbox(island) {
    var container = document.getElementById("inbox");
    var status = document.getElementById("status");

    function apply(data) {
      var pending = data.pending || [];
      shared.renderInbox(container, pending);
      updateBadge(pending.length);
      if (status) {
        status.textContent = shared.subtitleText(pending.length, 0);
      }
    }

    apply(island);

    function poll() {
      fetch("/pending.json", { headers: { Accept: "application/json" } })
        .then(function (r) {
          return r.ok ? r.json() : null;
        })
        .then(function (data) {
          if (data) {
            apply(data);
          }
        })
        .catch(function () {
          /* transient; next tick retries */
        });
    }

    setInterval(poll, 2000);
  }

  // ── Detail / per-action ceremony ──────────────────────────────────────

  // Mints a challenge bound to THIS approval, signs it with the operator's
  // passkey, then posts the decision. Both POSTs are status-checked: a refused
  // decision (rejected assertion, stale CSRF value, entry already resolved)
  // means nothing was signed, and renders in the refusal treatment rather than
  // as a status line the operator could read as success.
  function decide(nonce, csrf, decision, result) {
    result.className = "result";
    result.textContent = "Requesting challenge…";
    shared.setPageState("busy");
    var encodedNonce = encodeURIComponent(nonce);
    return fetch("/approval/" + encodedNonce + "/challenge", {
      method: "POST",
      headers: (function () {
        var h = {};
        h[CSRF_HEADER] = csrf;
        return h;
      })(),
    })
      .then(function (resp) {
        if (!resp.ok) {
          throw new Error("challenge_failed");
        }
        return resp.json();
      })
      .then(function (body) {
        result.textContent = "Waiting for passkey…";
        return navigator.credentials.get({
          publicKey: {
            challenge: b64urlToBytes(body.challenge),
            userVerification: "required",
            timeout: 60000,
          },
        });
      })
      .then(function (assertion) {
        result.textContent = "Working…";
        var headers = { "content-type": "application/json" };
        headers[CSRF_HEADER] = csrf;
        return fetch("/approval/" + encodedNonce + "/decision", {
          method: "POST",
          headers: headers,
          body: JSON.stringify({
            decision: decision,
            assertion: assertionToWire(assertion),
          }),
        });
      })
      .then(function (resp) {
        return resp
          .json()
          .catch(function () {
            return {};
          })
          .then(function (data) {
            return { ok: resp.ok, status: resp.status, data: data };
          });
      })
      .then(function (res) {
        if (res.ok) {
          shared.renderResult(result, res.data);
          shared.setPageState("ok");
          return;
        }
        shared.renderRefusal(result, res.data, "HTTP " + res.status);
        shared.setPageState("error");
      })
      .catch(function (e) {
        console.error("stellar-agent approval: decision ceremony failed", e);
        result.className = "result refused";
        result.textContent = "Not recorded: the request failed. Reload this page and try again.";
        shared.setPageState("error");
      });
  }

  function startDetail(island) {
    var result = document.getElementById("result");
    var nonce = island.nonce;
    var csrf = island.csrf;

    shared.refreshTimestamps();
    setInterval(shared.refreshTimestamps, 1000);

    var approveBtn = document.getElementById("approve-btn");
    if (approveBtn) {
      approveBtn.addEventListener("click", function () {
        decide(nonce, csrf, "approve", result);
      });
    }
    var rejectBtn = document.getElementById("reject-btn");
    if (rejectBtn) {
      rejectBtn.addEventListener("click", function () {
        decide(nonce, csrf, "reject", result);
      });
    }
  }

  var inboxIsland = shared.readIsland("pending-data");
  if (inboxIsland) {
    startInbox(inboxIsland);
  } else {
    var detailIsland = shared.readIsland("approval-data");
    if (detailIsland) {
      startDetail(detailIsland);
    }
  }
})();
