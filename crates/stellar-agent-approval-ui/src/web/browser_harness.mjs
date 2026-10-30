// The minimal browser the page-script tests run in: a fresh VM context
// with a fake DOM, a recorded sessionStorage, a recorded fetch, and a manual
// clock, so a test observes exactly what a script stores, requests, and
// navigates to. Shared by app_shared.test.mjs, mainnet-presence.test.mjs and
// the WebAuthn bridge's glue.test.mjs.

import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import vm from "node:vm";

export function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

export function jsonReply(status, body) {
  return Promise.resolve({ ok: status >= 200 && status < 300, status, json: () => Promise.resolve(body) });
}

export function source(relative) {
  return readFileSync(new URL(relative, import.meta.url), "utf8");
}

export function fakeElement(name) {
  return {
    name,
    textContent: "",
    className: "",
    hidden: false,
    value: "",
    children: [],
    attributes: {},
    listeners: {},
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    setAttribute(key, value) {
      this.attributes[key] = String(value);
    },
    getAttribute(key) {
      return key in this.attributes ? this.attributes[key] : null;
    },
    addEventListener(type, listener) {
      (this.listeners[type] ||= []).push(listener);
    },
  };
}

export function browser({
  islands = {},
  attributes = {},
  elements = [],
  storage = {},
  storageThrows = false,
  readBackDiffers = false,
  reply = () => new Promise(() => {}),
  credential = () => {
    throw new Error("this page creates no credential");
  },
  // Further globals the page script reads, such as a vendored library.
  globals = {},
} = {}) {
  const byId = {};
  for (const [id, value] of Object.entries(islands)) {
    byId[id] = fakeElement(id);
    byId[id].textContent = typeof value === "string" ? value : JSON.stringify(value);
  }
  for (const id of elements) {
    byId[id] ||= fakeElement(id);
  }
  for (const [id, values] of Object.entries(attributes)) {
    byId[id] ||= fakeElement(id);
    for (const [key, value] of Object.entries(values)) {
      byId[id].setAttribute(key, value);
    }
  }
  const stored = new Map(Object.entries(storage));
  const log = [];
  const fetches = [];
  const intervals = [];
  const documentListeners = {};
  const clock = { now: 1_000_000 };
  const sessionStorage = {
    getItem(key) {
      if (storageThrows) throw new Error("storage denied");
      return stored.has(key) ? stored.get(key) : null;
    },
    setItem(key, value) {
      if (storageThrows) throw new Error("storage denied");
      log.push(["setItem", key]);
      stored.set(key, readBackDiffers ? "other" : String(value));
    },
  };
  class FakeDate extends Date {
    static now() {
      return clock.now;
    }
  }
  const document = {
    documentElement: fakeElement("html"),
    getElementById(id) {
      return byId[id] || null;
    },
    createElement(tag) {
      return fakeElement(tag);
    },
    createTextNode(text) {
      return { textContent: text, children: [] };
    },
    addEventListener(type, listener) {
      (documentListeners[type] ||= []).push(listener);
    },
  };
  const credentialCalls = [];
  const context = {
    document,
    window: {
      sessionStorage,
      location: {
        replace(url) {
          log.push(["replace", url]);
        },
      },
    },
    navigator: {
      credentials: {
        create(options) {
          credentialCalls.push(options);
          return Promise.resolve(credential());
        },
      },
    },
    crypto: { getRandomValues: (array) => array.fill(3), subtle: webcrypto.subtle },
    btoa,
    atob,
    console,
    Date: FakeDate,
    setInterval(callback, ms) {
      intervals.push({ callback, ms });
      return intervals.length;
    },
    fetch(url, init) {
      fetches.push({ url, init: init || {} });
      return reply(url, init || {});
    },
  };
  Object.assign(context, globals);
  vm.createContext(context);
  return {
    byId,
    stored,
    log,
    fetches,
    intervals,
    clock,
    credentialCalls,
    run(file) {
      vm.runInContext(source(file), context, { filename: file });
    },
    dispatch(type, isTrusted) {
      for (const listener of documentListeners[type] || []) {
        listener({ type, isTrusted });
      }
    },
  };
}

export async function until(predicate, what) {
  const deadline = performance.now() + 5000;
  let turns = 0;
  while (!predicate()) {
    if (performance.now() >= deadline) {
      throw new Error(`Timed out waiting for ${what}`);
    }
    await new Promise((resolve) => setImmediate(resolve));
    if (++turns % 10 === 0) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }
}
