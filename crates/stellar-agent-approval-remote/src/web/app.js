// Stellar Agent Wallet — remote-approval post-authentication browser glue.
//
// Same-origin, no build step. Served behind the session cookie at
// GET /static/app.js. Loaded on both the inbox shell and the per-approval
// detail page; detects which page it is on by the presence of the
// corresponding JSON data island (#pending-data or #approval-data).
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

(function () {
  "use strict";

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

  // ── Inbox ──────────────────────────────────────────────────────────────

  function renderInbox(container, pending) {
    container.textContent = "";
    if (!pending || pending.length === 0) {
      var empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = "No pending approvals.";
      container.appendChild(empty);
      return;
    }
    pending.forEach(function (view) {
      var row = document.createElement("div");
      row.className = "row";
      var link = document.createElement("a");
      link.href = "/approval/" + encodeURIComponent(view.approval_nonce);
      link.textContent = view.kind_name;
      row.appendChild(link);
      var span = document.createElement("span");
      span.textContent = " — expires at " + view.expires_at_unix_ms;
      row.appendChild(span);
      container.appendChild(row);
    });
  }

  function updateBadge(count) {
    var base = "Stellar Agent Wallet — Remote Approval";
    document.title = count > 0 ? "(" + count + ") " + base : base;
  }

  function startInbox(island) {
    var container = document.getElementById("inbox");
    var status = document.getElementById("status");

    function apply(data) {
      var pending = data.pending || [];
      renderInbox(container, pending);
      updateBadge(pending.length);
      if (status) {
        status.textContent =
          pending.length + " pending — updated " + new Date().toLocaleTimeString();
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

  function renderResult(result, data) {
    result.textContent = "";
    var line = document.createElement("p");
    line.textContent = "Status: " + (data.status || "unknown");
    result.appendChild(line);

    var blob = data.attestation;
    if (blob) {
      var note = document.createElement("p");
      note.textContent = "Present this attestation to the matching commit tool:";
      result.appendChild(note);

      var area = document.createElement("textarea");
      area.readOnly = true;
      area.rows = 3;
      area.style.width = "100%";
      area.value = blob;
      result.appendChild(area);

      var copy = document.createElement("button");
      copy.type = "button";
      copy.textContent = "Copy attestation";
      copy.addEventListener("click", function () {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(blob).then(
            function () {
              copy.textContent = "Copied";
            },
            function () {
              area.select();
            }
          );
        } else {
          area.select();
        }
      });
      result.appendChild(copy);
    }
  }

  function decide(nonce, csrf, decision, result) {
    result.textContent = "Requesting challenge...";
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
        result.textContent = "Waiting for passkey...";
        return navigator.credentials.get({
          publicKey: {
            challenge: b64urlToBytes(body.challenge),
            userVerification: "required",
            timeout: 60000,
          },
        });
      })
      .then(function (assertion) {
        result.textContent = "Working...";
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
        return resp.json();
      })
      .then(function (data) {
        renderResult(result, data);
      })
      .catch(function () {
        result.textContent = "Request failed. Try again.";
      });
  }

  function startDetail(island) {
    var result = document.getElementById("result");
    var nonce = island.nonce;
    var csrf = island.csrf;

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

  var inboxIsland = readIsland("pending-data");
  if (inboxIsland) {
    startInbox(inboxIsland);
  } else {
    var detailIsland = readIsland("approval-data");
    if (detailIsland) {
      startDetail(detailIsland);
    }
  }
})();
