// Approval-surface rendering shared by the loopback and remote inboxes.
//
// Same-origin, no build step, no external dependency. Both approval servers
// serve THESE bytes at GET /static/app-shared.js: the loopback one from its own
// `web::APP_SHARED_JS`, the remote one from that same const via the
// `stellar-agent-approval-ui` dependency. There is one copy of this file, so
// the two surfaces cannot render an approval differently.
//
// Each page loads this file first and its server-specific glue second: a
// script element sourcing /static/app-shared.js, then one sourcing
// /static/app.js. Two same-origin script sources, which `script-src 'self'`
// permits; no inline script and no bundler.
//
// This file carries no literal closing script tag, in a comment or anywhere
// else. It is always served as its own resource, so one would be harmless
// there — but it would silently truncate any tool that inlines these bytes
// into a page.
//
// # The one global
//
// This file publishes exactly one name, `stellarAgentApproval`, because two
// separate <script> files cannot otherwise share a scope. Everything else stays
// inside the IIFE. The consuming glue reads the namespace once and never adds
// to it.
//
// # DOM discipline
//
// Every node is built with createElement and filled with textContent. Nothing
// here assigns innerHTML or inserts markup, so no server-supplied value can
// become an element regardless of what it contains.
//
// # What this file may and may not decide
//
// It composes readable summaries out of fields the server already rendered, and
// converts the two absolute timestamps into readable text. It never derives a
// value the operator consents to: the detail page's amount and destination are
// server-rendered, and a stroop count reaching this file is shifted as a digit
// string rather than divided, so no float rounding can move a displayed value.

var stellarAgentApproval = (function () {
  "use strict";

  var TEN_MINUTES_MS = 10 * 60 * 1000;
  // Non-ASCII literals are written as escapes so the file stays reviewable
  // in any editor and diffable byte-for-byte.
  var MIDDOT = "\u00B7";
  var CHEVRON = "\u203A";

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

  // ── Value formatting ───────────────────────────────────────────────────

  // Renders a stroop count in its 7-decimal denomination. The wire carries
  // stroops as a decimal string precisely so values above 2^53 survive; the
  // decimal point is inserted by shifting digits, never by dividing, so the
  // rendered value is exactly the value received. Returns null for anything
  // that is not a plain integer, so callers can fall back rather than print a
  // guess.
  function stroopsToDecimal(stroops) {
    var digits = String(stroops === null || stroops === undefined ? "" : stroops).trim();
    var negative = digits.charAt(0) === "-";
    if (negative) {
      digits = digits.slice(1);
    }
    if (!/^[0-9]+$/.test(digits)) {
      return null;
    }
    while (digits.length <= 7) {
      digits = "0" + digits;
    }
    var whole = digits.slice(0, digits.length - 7);
    var fraction = digits.slice(digits.length - 7);
    return (negative ? "-" : "") + whole + "." + fraction;
  }

  // The short code of an asset identifier ("XLM" or "<code>:<issuer>").
  function assetCode(asset) {
    var text = String(asset === null || asset === undefined ? "" : asset);
    var colon = text.indexOf(":");
    return colon === -1 ? text : text.slice(0, colon);
  }

  // Returns null rather than a rendering when the amount is absent or is not a
  // plain integer: a headline reading "null stroops" would state an amount the
  // request does not carry, and the caller has a kind label to fall back on.
  function amountText(stroops, asset) {
    var decimal = stroopsToDecimal(stroops);
    if (decimal === null) {
      return null;
    }
    return decimal + " " + assetCode(asset);
  }

  // Compact duration for the inbox column ("45 s", "4 min", "2 h 10 min").
  function shortDuration(ms) {
    var seconds = Math.floor(ms / 1000);
    if (seconds < 60) {
      return seconds + " s";
    }
    var minutes = Math.floor(seconds / 60);
    if (minutes < 60) {
      return minutes + " min";
    }
    var hours = Math.floor(minutes / 60);
    if (hours < 24) {
      var restMinutes = minutes % 60;
      return restMinutes ? hours + " h " + restMinutes + " min" : hours + " h";
    }
    var days = Math.floor(hours / 24);
    var restHours = hours % 24;
    return restHours ? days + " d " + restHours + " h" : days + " d";
  }

  function plural(count, unit) {
    return count + " " + unit + (count === 1 ? "" : "s");
  }

  // Spelled-out duration for the detail page ("4 minutes", "2 hours").
  function longDuration(ms) {
    var seconds = Math.floor(ms / 1000);
    if (seconds < 60) {
      return plural(seconds, "second");
    }
    var minutes = Math.floor(seconds / 60);
    if (minutes < 60) {
      return plural(minutes, "minute");
    }
    var hours = Math.floor(minutes / 60);
    if (hours < 24) {
      var restMinutes = minutes % 60;
      return restMinutes
        ? plural(hours, "hour") + " " + plural(restMinutes, "minute")
        : plural(hours, "hour");
    }
    return plural(Math.floor(hours / 24), "day");
  }

  function pad2(n) {
    return n < 10 ? "0" + n : String(n);
  }

  function clockText(date) {
    return pad2(date.getHours()) + ":" + pad2(date.getMinutes());
  }

  function isoDate(date) {
    return (
      date.getFullYear() + "-" + pad2(date.getMonth() + 1) + "-" + pad2(date.getDate())
    );
  }

  // "today" / "yesterday" / "tomorrow" for the neighbouring local days, and the
  // ISO date otherwise: a bare clock time is ambiguous across a day boundary.
  function dayLabel(date, now) {
    var dayMs = 24 * 60 * 60 * 1000;
    var today = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    var that = new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
    if (that === today) {
      return "today";
    }
    if (that === today - dayMs) {
      return "yesterday";
    }
    if (that === today + dayMs) {
      return "tomorrow";
    }
    return isoDate(date);
  }

  function absoluteText(unixMs) {
    var date = new Date(unixMs);
    return dayLabel(date, new Date()) + " " + clockText(date);
  }

  // The remaining-time phrase for an expiry that has NOT passed. The server
  // selects the sentence this fills, so a passed expiry is the caller's
  // `absoluteText` case and never composes into "expires expired (...)".
  function remainingText(unixMs) {
    // A bare clock time is ambiguous once the expiry is not today, so the day
    // label comes along in that case.
    var date = new Date(unixMs);
    var day = dayLabel(date, new Date());
    var when = day === "today" ? clockText(date) : day + " " + clockText(date);
    return "in " + longDuration(unixMs - Date.now()) + " (" + when + ")";
  }

  // ── Approval summaries ─────────────────────────────────────────────────

  var KIND_LABELS = {
    payment: "PAYMENT",
    claim: "CLAIM",
    mpp_charge: "CHARGE",
    rule_proposal: "RULE PROPOSAL",
    sign_with_passkey: "PASSKEY",
    register_passkey: "PASSKEY",
    toolset_first_invoke_gate: "TOOLSET GATE",
    trustline_clawback_opt_in: "CLAWBACK OPT-IN",
    rejected: "REJECTED",
  };

  // The two passkey kinds take the amber pill: their ceremony runs in the
  // browser bridge, so they are the kinds an inbox cannot approve.
  function isPasskeyKind(view) {
    var kind = (view.summary || {}).kind;
    return kind === "sign_with_passkey" || kind === "register_passkey";
  }

  function kindLabel(view) {
    var kind = (view.summary || {}).kind;
    if (KIND_LABELS.hasOwnProperty(kind)) {
      return KIND_LABELS[kind];
    }
    return String(view.kind_name || "approval").toUpperCase();
  }

  // The row's headline: what this request is, in one line. Total over the nine
  // kinds, with a plain fallback for a kind this build does not know.
  function headlineText(view) {
    var s = view.summary || {};
    switch (s.kind) {
      case "payment":
      case "claim":
        return amountText(s.amount_stroops, s.asset) || kindLabel(view);
      case "mpp_charge":
        // Base units of an arbitrary token contract, whose decimal scale the
        // wallet does not have here.
        return /^[0-9]+$/.test(String(s.amount))
          ? s.amount + " base units"
          : kindLabel(view);
      case "rule_proposal":
        return s.summary_line;
      case "sign_with_passkey":
        return "Transaction signature";
      case "register_passkey":
        return "New passkey registration";
      case "toolset_first_invoke_gate":
        return "Toolset capability request";
      case "trustline_clawback_opt_in":
        return "Clawback opt-in for " + s.code;
      case "rejected":
        return "Rejected " + s.original_kind_name;
      default:
        return String(view.kind_name || "Approval") + " request";
    }
  }

  // The row's second line: the identifying detail, truncated by CSS when long.
  function metaText(view) {
    var s = view.summary || {};
    switch (s.kind) {
      case "payment":
        return "to " + s.to;
      case "claim":
        return "balance " + s.balance_id_strkey;
      case "mpp_charge":
        // authority and target are separate bound fields (an HTTPS authority
        // and a path, or an MCP server and an operation name); concatenating
        // them would read as one value.
        return s.authority + " " + MIDDOT + " " + s.target + " " + MIDDOT + " " + s.currency;
      case "rule_proposal":
        return s.smart_account_redacted + " " + MIDDOT + " " + s.chain_id;
      case "sign_with_passkey":
      case "register_passkey":
        return s.smart_account_redacted + " " + MIDDOT + " rp " + s.rp_id;
      case "toolset_first_invoke_gate":
        return s.toolset_name + " requests " + s.capability;
      case "trustline_clawback_opt_in":
        return s.code + " " + MIDDOT + " " + s.issuer_redacted;
      case "rejected":
        return "no action required";
      default:
        return String(view.kind_name || "");
    }
  }

  // ── Inbox ──────────────────────────────────────────────────────────────

  function appendExpiry(el, view) {
    el.textContent = "";
    var remaining = Number(view.expires_at_unix_ms) - Date.now();
    if (view.expired || !isFinite(remaining) || remaining <= 0) {
      var gone = document.createElement("b");
      gone.className = "soon";
      gone.textContent = "expired";
      el.appendChild(gone);
      return;
    }
    el.appendChild(document.createTextNode("expires in"));
    el.appendChild(document.createElement("br"));
    var value = document.createElement("b");
    if (remaining < TEN_MINUTES_MS) {
      value.className = "soon";
    }
    value.textContent = shortDuration(remaining);
    el.appendChild(value);
  }

  function approvalRow(view) {
    var row = document.createElement("a");
    row.className = "approval";
    row.href = "/approval/" + encodeURIComponent(view.approval_nonce);

    var kind = document.createElement("span");
    kind.className = isPasskeyKind(view) ? "kind warn" : "kind";
    kind.textContent = kindLabel(view);
    row.appendChild(kind);

    var main = document.createElement("div");
    main.className = "ap-main";
    var title = document.createElement("div");
    title.className = "ap-title";
    title.textContent = headlineText(view);
    main.appendChild(title);
    var meta = document.createElement("div");
    meta.className = "ap-meta";
    meta.textContent = metaText(view);
    main.appendChild(meta);
    row.appendChild(main);

    var expiry = document.createElement("div");
    expiry.className = "ap-exp";
    appendExpiry(expiry, view);
    row.appendChild(expiry);

    var chevron = document.createElement("span");
    chevron.className = "chev";
    chevron.textContent = CHEVRON;
    row.appendChild(chevron);

    return row;
  }

  function renderInbox(container, pending) {
    container.textContent = "";
    pending.forEach(function (view) {
      container.appendChild(approvalRow(view));
    });
    var empty = document.getElementById("empty-state");
    if (empty) {
      empty.hidden = pending.length !== 0;
    }
  }

  function subtitleText(count, expiredCount) {
    var base =
      count === 0
        ? "No requests are waiting for your decision."
        : count === 1
          ? "1 request is waiting for your decision."
          : count + " requests are waiting for your decision.";
    if (expiredCount > 0) {
      return base + " " + expiredCount + " expired and not shown.";
    }
    return base;
  }

  // ── Detail ─────────────────────────────────────────────────────────────

  // Replaces the server-rendered raw unix-millisecond values with readable
  // text. The raw values stay in the data- attributes, so this can re-run on a
  // timer without losing the source of truth.
  //
  // The server chooses the surrounding sentence and marks it with
  // `data-expiry-form`: "remaining" for a live request, "absolute" for one that
  // can no longer be approved. This only fills the two slots.
  function refreshTimestamps() {
    var line = document.getElementById("expiry-line");
    if (!line) {
      return;
    }
    var created = Number(line.getAttribute("data-created-ms"));
    var expires = Number(line.getAttribute("data-expires-ms"));
    var createdEl = document.getElementById("created-text");
    if (createdEl && isFinite(created)) {
      createdEl.textContent = absoluteText(created);
    }
    var expiresEl = document.getElementById("expires-text");
    if (expiresEl && isFinite(expires)) {
      expiresEl.textContent =
        line.getAttribute("data-expiry-form") === "remaining" && expires > Date.now()
          ? remainingText(expires)
          : absoluteText(expires);
    }
  }

  // Renders a decision the server accepted: its status line and, when the
  // decision produced one, the attestation blob to hand to the commit tool.
  function renderResult(result, data) {
    result.textContent = "";
    result.className = "result";
    var line = document.createElement("p");
    line.textContent = "Status: " + (data.status || "unknown");
    result.appendChild(line);

    var blob = data.attestation;
    if (blob) {
      var note = document.createElement("p");
      note.textContent = "Present this attestation to the matching commit tool:";
      result.appendChild(note);

      var area = document.createElement("textarea");
      area.className = "output";
      area.readOnly = true;
      area.rows = 3;
      area.value = blob;
      result.appendChild(area);

      var copy = document.createElement("button");
      copy.className = "copy-btn";
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

  // Renders a decision the server REFUSED. A refusal is not a status to read
  // past: a rejected passkey assertion, a stale CSRF value, or an entry that
  // resolved elsewhere all mean nothing was signed, and the panel has to say so
  // in its own treatment rather than as "Status: unknown".
  function renderRefusal(result, data, fallback) {
    result.textContent = "";
    result.className = "result refused";
    var line = document.createElement("p");
    var detail = data && (data.error || data.status);
    line.textContent = detail
      ? "Not recorded: " + detail
      : "Not recorded: " + fallback;
    result.appendChild(line);
  }

  // The ceremony state the brand mark reads. "ok" / "error" / "busy".
  function setPageState(state) {
    document.documentElement.setAttribute("data-state", state);
  }

  return {
    readIsland: readIsland,
    stroopsToDecimal: stroopsToDecimal,
    assetCode: assetCode,
    amountText: amountText,
    absoluteText: absoluteText,
    remainingText: remainingText,
    kindLabel: kindLabel,
    headlineText: headlineText,
    metaText: metaText,
    approvalRow: approvalRow,
    renderInbox: renderInbox,
    subtitleText: subtitleText,
    refreshTimestamps: refreshTimestamps,
    renderResult: renderResult,
    renderRefusal: renderRefusal,
    setPageState: setPageState,
  };
})();
