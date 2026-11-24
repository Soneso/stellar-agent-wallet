// Session bootstrap for the loopback approval inbox, the enrollment pages and
// the mainnet consent page.
//
// Same-origin, no build step, no external dependency. Served by both loopback
// servers at GET /static/session-bootstrap.js and loaded only by the page the
// successful bootstrap exchange returns. That page carries the session proof
// in the #session-bootstrap-data JSON island; this file stores the proof in
// sessionStorage under the key the island names, removes it from the page,
// and replaces the location with the island's landing path.
//
// sessionStorage is scoped to the full origin (scheme, host and port), while
// the session cookie is scoped to the host only. A service on another
// loopback port therefore receives the cookie but can never read the proof,
// and the server refuses every state-changing request that lacks it.
//
// If the proof cannot be stored and read back, the page stops here and says
// so: navigating on would open a page whose every action is refused.
//
// The landing path is admitted by the storage key it arrives with: the inbox
// key lands on /inbox, the two enrollment keys on /enroll, and the mainnet
// consent key on the consent page of exactly one pending entry,
// /approval/<nonce> with the 22-character base64url approval nonce. Any other
// combination is refused rather than followed.

(function () {
  "use strict";

  var FIXED_LANDINGS = [
    ["stellar-agent-approval-session-proof", "/inbox"],
    ["stellar-agent-operator-enroll-session-proof", "/enroll"],
    ["stellar-agent-mainnet-approval-enroll-session-proof", "/enroll"],
  ];
  var CONSENT_KEY = "stellar-agent-mainnet-presence-session-proof";
  var CONSENT_PATH = /^\/approval\/[A-Za-z0-9_-]{22}$/;

  function admitted(storageKey, next) {
    if (typeof next !== "string") {
      return false;
    }
    if (storageKey === CONSENT_KEY) {
      return CONSENT_PATH.test(next);
    }
    for (var i = 0; i < FIXED_LANDINGS.length; i += 1) {
      if (FIXED_LANDINGS[i][0] === storageKey) {
        return FIXED_LANDINGS[i][1] === next;
      }
    }
    return false;
  }

  function fail(text) {
    var status = document.getElementById("bootstrap-status");
    if (status) {
      status.textContent = text;
    }
    document.documentElement.setAttribute("data-state", "error");
  }

  var island = document.getElementById("session-bootstrap-data");
  var data = null;
  try {
    data = island ? JSON.parse(island.textContent) : null;
  } catch (e) {
    data = null;
  }
  if (
    !data ||
    typeof data.proof !== "string" ||
    data.proof.length === 0 ||
    typeof data.storageKey !== "string" ||
    data.storageKey.length === 0 ||
    !admitted(data.storageKey, data.next)
  ) {
    fail("This link could not be opened. Restart the command for a new link.");
    return;
  }

  var stored = false;
  try {
    window.sessionStorage.setItem(data.storageKey, data.proof);
    stored = window.sessionStorage.getItem(data.storageKey) === data.proof;
  } catch (e) {
    stored = false;
  }
  island.textContent = "";
  if (!stored) {
    fail(
      "This browser did not let the wallet keep its session in this tab, so " +
        "no action could be confirmed. Allow site data for this page and " +
        "restart the command for a new link."
    );
    return;
  }

  window.location.replace(data.next);
})();
