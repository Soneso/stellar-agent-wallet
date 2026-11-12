// Stellar Agent Wallet: enrollment code form at a signed approval origin.
//
// Same-origin, no build step, no external dependency. Served without a
// session by a signed-origin enrollment listener only, at
// GET /static/operator-enroll-code.js, for the form GET /enroll renders
// before a session exists.
//
// The operator types the eight-digit code the terminal shows. The script
// posts {code} to POST /enroll/code with fetch, since the page CSP sets
// form-action 'none'. A match answers with the session cookie and the proof
// page of the session bootstrap. The script reads that page's JSON island as
// text and never executes the fetched HTML. It admits only the mainnet
// approval enrollment proof key and the /enroll landing. It stores the proof
// in this tab's sessionStorage and navigates to /enroll, where the session
// renders the registration page.

(function () {
  "use strict";

  var STORAGE_KEY = "stellar-agent-mainnet-approval-enroll-session-proof";
  var LANDING = "/enroll";
  var ISLAND_OPEN = '<script type="application/json" id="session-bootstrap-data">';
  var ISLAND_CLOSE = "</script>";
  var MESSAGES = {
    code_invalid: "That code does not match. Check the terminal and try again.",
    code_exhausted: "The attempt limit is reached. Restart the command for a new code.",
    code_expired: "The code expired. Restart the command for a new code.",
  };

  var input = document.getElementById("code-input");
  var button = document.getElementById("code-btn");
  var status = document.getElementById("status");
  if (!input || !button || !status) {
    return;
  }

  function show(text) {
    status.textContent = text;
  }

  // The bootstrap island of `html`, parsed as JSON, or null.
  function islandOf(html) {
    if (typeof html !== "string") {
      return null;
    }
    var start = html.indexOf(ISLAND_OPEN);
    if (start < 0) {
      return null;
    }
    start += ISLAND_OPEN.length;
    var end = html.indexOf(ISLAND_CLOSE, start);
    if (end < 0) {
      return null;
    }
    try {
      return JSON.parse(html.slice(start, end));
    } catch (e) {
      return null;
    }
  }

  function storeProof(data) {
    if (
      !data ||
      typeof data.proof !== "string" ||
      data.proof.length === 0 ||
      data.storageKey !== STORAGE_KEY ||
      data.next !== LANDING
    ) {
      return false;
    }
    try {
      window.sessionStorage.setItem(STORAGE_KEY, data.proof);
      return window.sessionStorage.getItem(STORAGE_KEY) === data.proof;
    } catch (e) {
      return false;
    }
  }

  function submit() {
    var code = String(input.value || "").replace(/\s+/g, "");
    if (!/^[0-9]{8}$/.test(code)) {
      show("Type the eight digits the terminal shows.");
      return;
    }
    button.disabled = true;
    show("Checking the code...");
    fetch("/enroll/code", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: code }),
    })
      .then(function (response) {
        if (response.ok) {
          return response.text().then(function (html) {
            if (storeProof(islandOf(html))) {
              window.location.replace(LANDING);
              return;
            }
            show(
              "This browser did not keep the enrollment session in this tab. Allow site " +
                "data for this page and restart the command for a new code."
            );
          });
        }
        return response.json().then(
          function (body) {
            var error = body && body.error;
            show(MESSAGES[error] || MESSAGES.code_invalid);
            button.disabled = error === "code_exhausted" || error === "code_expired";
          },
          function () {
            show(MESSAGES.code_invalid);
            button.disabled = false;
          }
        );
      })
      .catch(function () {
        show("The wallet did not answer. Check the terminal and try again.");
        button.disabled = false;
      });
  }

  button.addEventListener("click", submit);
})();
