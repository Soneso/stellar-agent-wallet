// An eligible inbox page revokes only the nonce its data island names.
(function () {
  'use strict';
  var data = JSON.parse(document.getElementById('revoke-data').textContent);
  var button = document.getElementById('revoke-btn');
  var result = document.getElementById('revoke-result');
  var busy = false;
  function decode(value) {
    return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), function (c) { return c.charCodeAt(0); });
  }
  function encode(value) {
    var text = '';
    new Uint8Array(value).forEach(function (byte) { text += String.fromCharCode(byte); });
    return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  async function post(action, body) {
    var headers = { 'Content-Type': 'application/json', 'X-Stellar-Approval-CSRF': data.csrf };
    if (!data.signed_origin) {
      headers['X-Session-Proof'] = window.sessionStorage.getItem(data.storageKey) || '';
    }
    var response = await fetch('/approval/' + encodeURIComponent(data.nonce) + '/' + action, {
      method: 'POST', credentials: 'same-origin', headers: headers, body: JSON.stringify(body)
    });
    var value = await response.json();
    if (!response.ok || value.error) {
      throw new Error(value.message || 'The revocation request is refused.');
    }
    return value;
  }
  button.addEventListener('click', async function (event) {
    if (!event.isTrusted || busy || button.disabled) { return; }
    busy = true;
    button.disabled = true;
    try {
      var body = {};
      if (data.signed_origin) {
        var options = await post('challenge', { consent_view_digest: data.consent_view_digest });
        var credential = await navigator.credentials.get({ publicKey: {
          challenge: decode(options.challenge), rpId: options.rp_id,
          allowCredentials: options.allow_credentials.map(function (id) { return { type: 'public-key', id: decode(id) }; }),
          userVerification: 'required', timeout: options.timeout_ms
        } });
        if (!credential) { throw new Error('A fresh passkey assertion is required.'); }
        body = {
          request_id: options.request_id, credential_id_b64url: encode(credential.rawId),
          authenticator_data_b64url: encode(credential.response.authenticatorData),
          client_data_json_b64url: encode(credential.response.clientDataJSON),
          signature_der_b64url: encode(credential.response.signature)
        };
      }
      var reply = await post('revoke', body);
      if (!reply.view) { throw new Error('The revocation request is refused.'); }
      result.textContent = Object.keys(reply.view).map(function (key) {
        return key + ': ' + String(reply.view[key]);
      }).join('\n');
    } catch (error) {
      result.textContent = error.message || 'The revocation request cannot complete. Reload the page.';
      button.disabled = false;
    } finally {
      busy = false;
    }
  });
}());
