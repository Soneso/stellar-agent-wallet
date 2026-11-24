import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

async function login(file, destination, accepted = true, responses = []) {
  let click;
  const calls = [];
  const window = { location: { href: '' } };
  const status = { setAttribute() {}, textContent: '' };
  let challenge = 0;
  const context = {
    window, Uint8Array, atob, btoa,
    document: {
      documentElement: { setAttribute() {} },
      getElementById(id) {
        if (id === 'login-btn') return { addEventListener(_, callback) { click = callback; } };
        if (id === 'login-destination') return { textContent: JSON.stringify({ destination }) };
        return status;
      },
    },
    navigator: { credentials: { async get(options) {
      calls.push(options);
      return { id: 'credential', response: { authenticatorData: new Uint8Array([1]), clientDataJSON: new Uint8Array([2]), signature: new Uint8Array([3]) } };
    } } },
    async fetch(path, options) {
      calls.push({ path, options });
      if (path === '/login/challenge') {
        challenge += 1;
        return { ok: true, async json() { return { challenge: btoa(String.fromCharCode(challenge)), rp_id: 'approve.example.invalid' }; } };
      }
      const response = responses.shift();
      return response || { ok: accepted };
    },
  };
  vm.runInNewContext(readFileSync(new URL(file, import.meta.url), 'utf8'), context);
  click();
  await new Promise(resolve => setImmediate(resolve));
  return { window, calls, status };
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

function busy() {
  return { ok: false, status: 503, async json() { return { error: 'store_busy', retriable: true }; } };
}

for (const file of ['./signed-login.js', './login.js']) {
  test(`${file} retries busy login with a fresh challenge and assertion`, async () => {
    const { window, calls } = await login(file, '/approval/selected-id', true, [busy(), busy(), busy()]);
    assert.equal(window.location.href, file.includes('signed-') ? '/approval/selected-id' : '/inbox');
    assert.deepEqual(calls.filter(call => call.publicKey).map(call => call.publicKey.challenge[0]), [1, 2, 3, 4]);
    assert.deepEqual(calls.filter(call => call.path).map(call => call.path), Array(4).fill(['/login/challenge', '/login/assertion']).flat());
  });

  test(`${file} stops after three busy retries`, async () => {
    const { window, calls, status } = await login(file, '/inbox', true, Array.from({ length: 5 }, busy));
    assert.equal(window.location.href, '');
    assert.equal(calls.filter(call => call.path === '/login/assertion').length, 4);
    assert.equal(status.textContent, 'Wallet is busy. Try again.');
  });

  test(`${file} does not retry invalid assertions or other unavailable responses`, async () => {
    for (const response of [
      { ok: false, status: 400 },
      { ok: false, status: 503, async json() { return { error: 'store_unavailable', retriable: false }; } },
    ]) {
      const { window, calls, status } = await login(file, '/inbox', true, [response]);
      assert.equal(window.location.href, '');
      assert.equal(calls.filter(call => call.path === '/login/assertion').length, 1);
      assert.equal(status.textContent, 'Sign-in failed. Try again.');
    }
  });
}
