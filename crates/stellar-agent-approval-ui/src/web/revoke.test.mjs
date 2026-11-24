import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('./revoke.js', import.meta.url), 'utf8');

test('revocation_action_posts_only_the_selected_record', async () => {
  for (const signed of [false, true]) {
    for (const omit of ['', 'session', 'csrf', ...(signed ? ['assertion'] : ['proof'])]) {
      const nonce = 'selected/nonce';
      const calls = [];
      let mutations = 0;
      let handler;
      const button = { disabled: false, addEventListener: (_, callback) => { handler = callback; } };
      const result = { textContent: '' };
      const data = { nonce, csrf: omit === 'csrf' ? '' : 'csrf', storageKey: 'proof-key',
        signed_origin: signed, consent_view_digest: 'digest' };
      const credential = { rawId: new Uint8Array([1]), response: {
        authenticatorData: new Uint8Array([2]), clientDataJSON: new Uint8Array([3]), signature: new Uint8Array([4])
      } };
      vm.runInNewContext(source, {
        document: { getElementById: id => ({ 'revoke-data': { textContent: JSON.stringify(data) },
          'revoke-btn': button, 'revoke-result': result })[id] },
        window: { sessionStorage: { getItem: key => { assert.equal(key, 'proof-key'); return omit === 'proof' ? null : 'proof'; } } },
        navigator: { credentials: { get: async options => {
          assert.equal(options.publicKey.rpId, 'approve.example.invalid');
          assert.equal(options.publicKey.userVerification, 'required');
          return omit === 'assertion' ? null : credential;
        } } },
        Uint8Array, atob, btoa,
        fetch: async (path, options) => {
          calls.push(path);
          assert.ok(path.startsWith('/approval/selected%2Fnonce/'));
          assert.equal(options.method, 'POST');
          assert.equal(options.credentials, 'same-origin');
          const body = JSON.parse(options.body);
          const authorized = omit !== 'session' && options.headers['X-Stellar-Approval-CSRF'] === 'csrf'
            && (signed || options.headers['X-Session-Proof'] === 'proof');
          if (!authorized) { return { ok: false, json: async () => ({ error: 'refused', message: 'refused' }) }; }
          if (path.endsWith('/challenge')) {
            assert.equal(body.consent_view_digest, 'digest');
            return { ok: true, json: async () => ({ challenge: 'AQ', rp_id: 'approve.example.invalid',
              allow_credentials: ['AQ'], timeout_ms: 1000, request_id: 'request' }) };
          }
          assert.ok(path.endsWith('/revoke'));
          if (signed) {
            assert.equal(body.request_id, 'request');
            assert.equal(body.credential_id_b64url, 'AQ');
            assert.equal(body.authenticator_data_b64url, 'Ag');
            assert.equal(body.client_data_json_b64url, 'Aw');
            assert.equal(body.signature_der_b64url, 'BA');
          } else { assert.deepEqual(body, {}); }
          mutations++;
          return { ok: true, json: async () => ({ view: { state: 'revoked' } }) };
        }
      });
      await handler({ isTrusted: false });
      assert.equal(calls.length, 0);
      await handler({ isTrusted: true });
      assert.equal(mutations, omit ? 0 : 1, `${signed}/${omit}`);
      if (!omit) { assert.equal(result.textContent, 'state: revoked'); }
    }
  }
});
