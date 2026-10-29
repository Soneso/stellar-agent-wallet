// Session bootstrap for the loopback approval inbox and operator enrollment.
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
// The landing path is one of two fixed values; anything else in the island is
// refused rather than followed.

(function () {
  "use strict";

  var LANDING_PATHS = ["/inbox", "/enroll"];

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
    LANDING_PATHS.indexOf(data.next) === -1
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
