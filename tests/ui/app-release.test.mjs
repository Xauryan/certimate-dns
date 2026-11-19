import assert from "node:assert/strict";
import { test } from "node:test";

import { APP_DOCUMENT_URL, APP_DOWNLOAD_URL, APP_REPO_URL, RELEASE_CACHE_KEY, fetchUpdate, readCachedUpdate } from "../../ui/src/domain/appRelease.ts";

const fork = "https://github.com/Xauryan/certimate-dns";
const currentVersion = "v0.4.38";
const release = (tag_name, fields = {}) => ({ tag_name, draft: false, prerelease: false, ...fields });

function cache(values = {}) {
  const entries = new Map(Object.entries(values));
  return {
    getItem: (key) => entries.get(key) ?? null,
    setItem: (key, value) => entries.set(key, value),
    removeItem: (key) => entries.delete(key),
  };
}

test("only the official fork feed supplies the highest newer stable tag and its URL", async (t) => {
  const fetch = t.mock.method(globalThis, "fetch", async () =>
    Response.json([
      release("v0.4.39", { name: "v9.0.0" }),
      release("v1.3.0", { prerelease: true }),
      release("v1.2.0", { draft: true }),
      release("v1.1.0-beta.1"),
      release("v0.10.0", { name: "DNS milestone", html_url: "https://example.test/not-the-fork" }),
      release("v1.2.0/../../latest"),
      release("v0.4.38"),
      release("v0.4.37"),
    ])
  );

  const storage = cache({ "certimate-ui-newver": "v99.0.0" });
  assert.equal(readCachedUpdate(currentVersion, storage), null);
  assert.equal(await fetchUpdate(currentVersion, storage), `${fork}/releases/tag/v0.10.0`);
  assert.equal(readCachedUpdate(currentVersion, storage), `${fork}/releases/tag/v0.10.0`);
  assert.equal(readCachedUpdate("v0.10.0", storage), null);
  assert.equal(storage.getItem(RELEASE_CACHE_KEY), "v0.10.0");
  assert.equal(fetch.mock.callCount(), 1);
  assert.deepEqual(fetch.mock.calls[0].arguments, ["https://api.github.com/repos/Xauryan/certimate-dns/releases?per_page=100", { redirect: "error" }]);
  assert.equal(APP_REPO_URL, fork);
  assert.equal(APP_DOWNLOAD_URL, `${fork}/releases`);
  assert.equal(APP_DOCUMENT_URL, `${fork}/blob/main/docs/dns-development.zh-CN.md`);
});

test("an empty or non-newer release list clears a previous fork notification", async (t) => {
  for (const releases of [[], [release("v0.4.38"), release("v0.4.37"), release("v0.4.40", { draft: true })]]) {
    t.mock.method(globalThis, "fetch", async () => Response.json(releases));
    const storage = cache({ [RELEASE_CACHE_KEY]: "v0.4.39" });
    assert.equal(await fetchUpdate(currentVersion, storage), null);
    assert.equal(storage.getItem(RELEASE_CACHE_KEY), null);
    assert.equal(readCachedUpdate(currentVersion, storage), null);
    t.mock.restoreAll();
  }
});

test("a stable version supersedes the corresponding local development version", async (t) => {
  t.mock.method(globalThis, "fetch", async () => Response.json([release(currentVersion)]));
  assert.equal(await fetchUpdate(`${currentVersion}-dev`, cache()), `${fork}/releases/tag/${currentVersion}`);
});

test("an unavailable or invalid feed does not fall back to upstream or clear known fork data", async (t) => {
  for (const response of [new Response(null, { status: 503 }), Response.json({ message: "Invalid payload" })]) {
    const fetch = t.mock.method(globalThis, "fetch", async () => response);
    const storage = cache({ [RELEASE_CACHE_KEY]: "v0.4.39" });
    await assert.rejects(fetchUpdate(currentVersion, storage));
    assert.equal(readCachedUpdate(currentVersion, storage), `${fork}/releases/tag/v0.4.39`);
    assert.equal(fetch.mock.callCount(), 1);
    t.mock.restoreAll();
  }
});
