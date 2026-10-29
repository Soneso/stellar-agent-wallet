// Loopback approval-inbox browser glue for the Stellar agent wallet.
//
// Same-origin, no build step, no external dependency. Loaded on both the inbox
// shell and the per-approval detail page AFTER /static/app-shared.js, which
// carries the rendering both approval surfaces share; this file holds only what
// is specific to the loopback server: its poll query, its CSRF header, and its
// decision endpoints. It detects which page it is on by the presence of the
// corresponding JSON data island.
//
// Inbox: reads #pending-data, renders one row per pending approval (each a link
// to /approval/<nonce>), then re-fetches /pending.json every 2 seconds to keep
// the rows and the document-title badge current.
//
// Detail: reads #approval-data (nonce + CSRF value), wires the Approve / Reject
// buttons to POST /approval/<nonce>/{approve,reject} with the
// X-Stellar-Approval-CSRF header and the X-Session-Proof header, and renders
// the JSON response.
//
// # Session proof and activity
//
// The bootstrap page stored the session proof in this tab's sessionStorage
// (see /static/session-bootstrap.js). Every state-changing request carries it
// in X-Session-Proof; the server refuses a request without it. The session
// expires after a period without operator activity, and the background poll
// does not count: only a trusted user interaction (a pointer press, a key
// press, a wheel turn, a touch) sends POST /session/activity, at most once a
// minute across this tab's page loads. Timers never send it.
//
// # DOM discipline
//
// Every node is built with createElement and filled with textContent. Nothing
// here assigns innerHTML or inserts markup, so no server-supplied value can
// become an element regardless of what it contains.

(function () {
  "use strict";

  var shared = stellarAgentApproval;

  var PROOF_KEY = "stellar-agent-approval-session-proof";
  var ACTIVITY_AT_KEY = "stellar-agent-approval-session-activity-at";
  var ACTIVITY_INTERVAL_MS = 60000;
  var ACTIVITY_EVENTS = ["pointerdown", "keydown", "wheel", "touchstart"];

  function storageGet(key) {
    try {
      return window.sessionStorage.getItem(key);
    } catch (e) {
      return null;
    }
  }

  function storageSet(key, value) {
    try {
      window.sessionStorage.setItem(key, value);
    } catch (e) {
      /* the throttle falls back to this page load */
    }
  }

  function readProof() {
    var proof = storageGet(PROOF_KEY);
    return typeof proof === "string" && proof.length > 0 ? proof : null;
  }

  // Sends POST /session/activity for a trusted user interaction, at most once
  // per ACTIVITY_INTERVAL_MS. The last send time lives in sessionStorage so
  // navigating between pages does not reset the throttle. `keepalive` lets the
  // request finish when the interaction is a click that leaves the page.
  function watchActivity(activityCsrf) {
    var proof = readProof();
    if (!proof || typeof activityCsrf !== "string" || activityCsrf.length === 0) {
      return;
    }
    var lastSent = Number(storageGet(ACTIVITY_AT_KEY)) || 0;
    function onInteraction(event) {
      if (!event || event.isTrusted !== true) {
        return;
      }
      var now = Date.now();
      if (now - lastSent < ACTIVITY_INTERVAL_MS) {
        return;
      }
      lastSent = now;
      storageSet(ACTIVITY_AT_KEY, String(now));
      fetch("/session/activity", {
        method: "POST",
        keepalive: true,
        headers: { "X-Stellar-Approval-CSRF": activityCsrf, "X-Session-Proof": proof },
      }).catch(function () {
        /* the next interaction after the interval retries */
      });
    }
    for (var i = 0; i < ACTIVITY_EVENTS.length; i++) {
      document.addEventListener(ACTIVITY_EVENTS[i], onInteraction, { capture: true, passive: true });
    }
  }

  function updateBadge(count) {
    var base = "Stellar Agent Wallet — Approvals";
    document.title = count > 0 ? "(" + count + ") " + base : base;
  }

  function startInbox(island) {
    var container = document.getElementById("inbox");
    var status = document.getElementById("status");
    var includeExpired = island.include_expired ? 1 : 0;

    function apply(data) {
      var pending = data.pending || [];
      shared.renderInbox(container, pending);
      updateBadge(pending.length);
      if (status) {
        status.textContent = shared.subtitleText(pending.length, data.expired_count || 0);
      }
    }

    apply(island);

    function poll() {
      fetch("/pending.json?include_expired=" + includeExpired, {
        headers: { Accept: "application/json" },
      })
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

  // Posts a decision and renders what the server actually did with it. A
  // non-2xx is a refusal — a stale CSRF value, an entry that resolved
  // elsewhere, a store that could not be written — and means nothing was
  // signed, so it renders in the refusal treatment rather than as a status
  // line the operator could read as success.
  //
  // A tab without the session proof cannot act: the decision would be refused,
  // so nothing is sent and the refusal names the way back.
  function post(url, csrf, result) {
    var proof = readProof();
    if (!proof) {
      result.className = "result refused";
      result.textContent =
        "Not recorded: this tab has no wallet session. Use the tab the " +
        "command opened, or restart it for a new link.";
      shared.setPageState("error");
      return;
    }
    result.className = "result";
    result.textContent = "Working…";
    shared.setPageState("busy");
    fetch(url, {
      method: "POST",
      headers: {
        "X-Stellar-Approval-CSRF": csrf,
        "X-Session-Proof": proof,
        Accept: "application/json",
      },
    })
      .then(function (r) {
        return r
          .json()
          .catch(function () {
            return {};
          })
          .then(function (data) {
            return { ok: r.ok, status: r.status, data: data };
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
        console.error("stellar-agent approval: decision request failed", e);
        result.className = "result refused";
        result.textContent =
          "Not recorded: could not reach the wallet. Reload this page and try again.";
        shared.setPageState("error");
      });
  }

  function startDetail(island) {
    var result = document.getElementById("result");
    var nonce = encodeURIComponent(island.nonce);
    var csrf = island.csrf;

    shared.refreshTimestamps();
    setInterval(shared.refreshTimestamps, 1000);

    var approveBtn = document.getElementById("approve-btn");
    if (approveBtn) {
      approveBtn.addEventListener("click", function () {
        post("/approval/" + nonce + "/approve", csrf, result);
      });
    }
    var rejectBtn = document.getElementById("reject-btn");
    if (rejectBtn) {
      rejectBtn.addEventListener("click", function () {
        post("/approval/" + nonce + "/reject", csrf, result);
      });
    }
  }

  var inboxIsland = shared.readIsland("pending-data");
  if (inboxIsland) {
    watchActivity(inboxIsland.activity_csrf);
    startInbox(inboxIsland);
    return;
  }
  var detailIsland = shared.readIsland("approval-data");
  if (detailIsland) {
    watchActivity(detailIsland.activity_csrf);
    startDetail(detailIsland);
  }
})();
