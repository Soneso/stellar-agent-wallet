import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

async function login(file, destination, accepted = true) {
  let click;
  const calls = [];
  const window = { location: { href: '' } };
  const context = {
    window, Uint8Array, atob, btoa,
    document: {
      documentElement: { setAttribute() {} },
      getElementById(id) {
        if (id === 'login-btn') return { addEventListener(_, callback) { click = callback; } };
        if (id === 'login-destination') return { textContent: JSON.stringify({ destination }) };
        return { setAttribute() {}, textContent: '' };
      },
    },
    navigator: { credentials: { async get(options) {
      calls.push(options);
      return { id: 'credential', response: { authenticatorData: new Uint8Array([1]), clientDataJSON: new Uint8Array([2]), signature: new Uint8Array([3]) } };
    } } },
    async fetch(path, options) {
      calls.push({ path, options });
      return { ok: path === '/login/challenge' || accepted, async json() { return { challenge: 'AQ', rp_id: 'approve.example.invalid' }; } };
    },
  };
  vm.runInNewContext(readFileSync(new URL(file, import.meta.url), 'utf8'), context);
  click();
  await new Promise(resolve => setImmediate(resolve));
  return { window, calls };
}

test('signed login navigates to the server destination and uses the signed RP', async () => {
  const { window, calls } = await login('./signed-login.js', '/approval/selected-id');
  assert.equal(window.location.href, '/approval/selected-id');
  assert.equal(calls[1].publicKey.rpId, 'approve.example.invalid');
  assert.equal(calls[2].path, '/login/assertion');
  assert.equal(JSON.parse(calls[2].options.body).assertion.response.signature, 'Aw');
});

test('a refused signed login leaves navigation unchanged', async () => {
  assert.equal((await login('./signed-login.js', '/approval/selected-id', false)).window.location.href, '');
});

test('testnet login keeps its inbox destination', async () => {
  const { window, calls } = await login('./login.js', '/approval/selected-id');
  assert.equal(window.location.href, '/inbox');
  assert.equal(calls[1].publicKey.rpId, undefined);
});
