// Approval-inbox browser glue for the Stellar agent wallet.
//
// Same-origin, no build step, no external dependency. Loaded on both the inbox
// shell and the per-approval detail page; it detects which page it is on by the
// presence of the corresponding JSON data island.
//
// Inbox: reads #pending-data, renders one row per pending approval (each a link
// to /approval/<nonce>), then re-fetches /pending.json every 2 seconds to keep
// the rows and the document-title badge current.
//
// Detail: reads #approval-data (nonce + CSRF value), wires the Approve / Reject
// buttons to POST /approval/<nonce>/{approve,reject} with the
// X-Stellar-Approval-CSRF header, and renders the JSON response.

(function () {
  "use strict";

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

  function summaryText(view) {
    var s = view.summary || {};
    switch (s.kind) {
      case "payment":
        return "pay " + s.amount_stroops + " stroops " + s.asset + " to " + s.to;
      case "claim":
        return "claim " + s.amount_stroops + " stroops " + s.asset;
      case "sign_with_passkey":
        return "sign with passkey for " + s.smart_account_redacted;
      case "register_passkey":
        return "register passkey for " + s.smart_account_redacted;
      case "toolset_first_invoke_gate":
        return "toolset '" + s.toolset_name + "' requests " + s.capability;
      case "trustline_clawback_opt_in":
        return "clawback opt-in for " + s.code;
      case "rejected":
        return "rejected (" + s.original_kind_name + ")";
      default:
        return view.kind_name + " entry";
    }
  }

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
      span.textContent = " — " + summaryText(view);
      if (view.expired) {
        span.textContent += " (expired)";
      }
      row.appendChild(span);
      container.appendChild(row);
    });
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
      renderInbox(container, pending);
      updateBadge(pending.length);
      if (status) {
        var extra =
          data.expired_count > 0
            ? " (" + data.expired_count + " expired not shown)"
            : "";
        status.textContent =
          pending.length + " pending" + extra + " — updated " + new Date().toLocaleTimeString();
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

  function post(url, csrf, result) {
    result.textContent = "Working…";
    fetch(url, {
      method: "POST",
      headers: { "X-Stellar-Approval-CSRF": csrf, Accept: "application/json" },
    })
      .then(function (r) {
        return r.json().then(function (data) {
          return { ok: r.ok, data: data };
        });
      })
      .then(function (res) {
        renderResult(result, res.data);
      })
      .catch(function () {
        result.textContent = "Request failed. Try again.";
      });
  }

  function startDetail(island) {
    var result = document.getElementById("result");
    var nonce = encodeURIComponent(island.nonce);
    var csrf = island.csrf;

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

  var inboxIsland = readIsland("pending-data");
  if (inboxIsland) {
    startInbox(inboxIsland);
    return;
  }
  var detailIsland = readIsland("approval-data");
  if (detailIsland) {
    startDetail(detailIsland);
  }
})();
