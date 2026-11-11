// The mainnet consent page: one WebAuthn assertion per trusted click.
//
// Same-origin, no build step, no external dependency. Loaded after
// /static/app-shared.js, whose renderers show every decision outcome, so this
// page and the testnet detail page render a result the same way.
//
// The #presence-data island names the entry, its CSRF value, the digest of the
// rendered consent view, the sessionStorage key of the session proof, and the
// listener's mode. It marks a page served at a signed approval origin.
// Nothing runs on page load. A ceremony starts only on a trusted click of
// "Approve with passkey". It asks for user verification with the credentials
// and relying-party ID the server's challenge names. It posts the authenticator's
// raw response bytes. In the inbox a successful assertion records the consent
// and the page shows the attestation; in a command's ceremony the command
// records it, and the page says so. At a signed origin a Reject click runs the
// same ceremony and posts its assertion with the rejection; the loopback inbox
// posts the rejection alone. A response without a JSON body means the session
// has ended. Once every handler is wired, the root element carries
// data-presence="ready".

(function () {
  'use strict';
  var shared = stellarAgentApproval;
  var SESSION_ENDED = 'The consent session has ended. Restart the command for a new link.';
  var UNAVAILABLE = 'The consent request cannot complete. Reload the page.';
  var data = JSON.parse(document.getElementById('presence-data').textContent);
  var inbox = data.mode === 'inbox';
  var signedOrigin = data.signed_origin === true;
  var approve = document.getElementById('presence-approve');
  var cancel = document.getElementById('presence-cancel');
  var reject = document.getElementById('presence-reject');
  var result = document.getElementById('presence-result');
  var busy = false;
  var done = false;
  shared.refreshTimestamps();
  setInterval(shared.refreshTimestamps, 1000);
  function decode(value) {
    return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), function (c) { return c.charCodeAt(0); });
  }
  function encode(value) {
    var bytes = new Uint8Array(value);
    var text = '';
    bytes.forEach(function (byte) { text += String.fromCharCode(byte); });
    return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function SessionEnded() {}
  // Sends one guarded POST and resolves to its status and JSON body. A body
  // that is not JSON, a bare 404 of an ended session among them, rejects
  // with SessionEnded.
  async function send(action, body) {
    var response = await fetch('/approval/' + encodeURIComponent(data.nonce) + '/' + action, {
      method: 'POST', credentials: 'same-origin', headers: {
        'Content-Type': 'application/json', 'X-Stellar-Approval-CSRF': data.csrf,
        'X-Session-Proof': window.sessionStorage.getItem(data.storageKey) || ''
      }, body: JSON.stringify(body)
    });
    var value;
    try {
      value = await response.json();
    } catch (error) {
      throw new SessionEnded();
    }
    return { ok: response.ok, status: response.status, value: value || {} };
  }
  async function post(action, body) {
    var reply = await send(action, body);
    if (!reply.ok) {
      throw new Error(typeof reply.value.message === 'string' ? reply.value.message : UNAVAILABLE);
    }
    return reply.value;
  }
  function failed(error) {
    result.className = 'result refused';
    result.textContent = error instanceof SessionEnded ? SESSION_ENDED : error.message;
  }
  async function end(reason) {
    await post('cancel', { reason: reason });
    result.className = 'result refused';
    result.textContent = reason === 'browser_unavailable'
      ? 'Mainnet consent requires a local browser with WebAuthn user verification; no approval is recorded.'
      : 'Mainnet consent is canceled; no approval is recorded.';
  }
  // Runs one ceremony: a challenge for the rendered consent view and an
  // assertion with user verification over it. Resolves to the raw response
  // bytes to post, or to null once the ceremony has ended and the result shows
  // why.
  async function ceremony() {
    if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.get) {
      await end('browser_unavailable'); return null;
    }
    var options = await post('challenge', { consent_view_digest: data.consent_view_digest });
    if (typeof options.challenge !== 'string' || typeof options.rp_id !== 'string') {
      shared.renderRefusal(result, options, UNAVAILABLE); return null;
    }
    var credential;
    try {
      credential = await navigator.credentials.get({ publicKey: {
        challenge: decode(options.challenge), rpId: options.rp_id,
        allowCredentials: options.allow_credentials.map(function (id) { return { type: 'public-key', id: decode(id) }; }),
        userVerification: 'required', timeout: options.timeout_ms
      } });
    } catch (error) {
      await end(error && error.name === 'NotAllowedError' ? 'authenticator_canceled' : 'browser_unavailable');
      return null;
    }
    if (!credential) { await end('authenticator_canceled'); return null; }
    return {
      request_id: options.request_id, credential_id_b64url: encode(credential.rawId),
      authenticator_data_b64url: encode(credential.response.authenticatorData),
      client_data_json_b64url: encode(credential.response.clientDataJSON),
      signature_der_b64url: encode(credential.response.signature)
    };
  }
  approve.addEventListener('click', async function (event) {
    if (!event.isTrusted || busy || done) { return; }
    busy = true;
    approve.disabled = true;
    try {
      var signed = await ceremony();
      if (!signed) { return; }
      var response = await post('assertion', signed);
      if (inbox) {
        shared.renderResult(result, response);
        done = response.status === 'attested' || response.status === 'grant_active';
      } else if (response.status === 'presence_verified') {
        result.className = 'result';
        result.textContent = 'Presence verified. Check the command result.';
        done = true;
      } else {
        shared.renderRefusal(result, response, UNAVAILABLE);
      }
    } catch (error) {
      failed(error);
    } finally {
      busy = false;
      approve.disabled = done;
    }
  });
  if (cancel) {
    cancel.addEventListener('click', async function (event) {
      if (!event.isTrusted || done) { return; }
      try { await end('operator_cancel'); done = true; approve.disabled = true; } catch (error) { failed(error); }
    });
  }
  if (reject) {
    reject.addEventListener('click', async function (event) {
      if (!event.isTrusted || busy || done) { return; }
      busy = true;
      try {
        var body = {};
        if (signedOrigin) {
          body = await ceremony();
          if (!body) { return; }
        }
        var reply = await send('reject', body);
        shared.renderRefusal(result, reply.value, 'HTTP ' + reply.status);
        if (reply.ok) { done = true; approve.disabled = true; }
      } catch (error) {
        failed(error);
      } finally {
        busy = false;
      }
    });
  }
  // Every handler is wired; a driver waits for this marker before it clicks.
  document.documentElement.setAttribute('data-presence', 'ready');
}());
