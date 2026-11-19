const assert = require("node:assert/strict");

module.exports = async function testOrderBatch(page) {
  const make = (id, state, allowedActions, certificateId) => ({
    id,
    state,
    allowedActions,
    certificateId,
    domain: id + ".example.test",
    provider: "aliyun",
    accessId: "account01",
    algorithm: "RSA2048",
    version: 4,
  });
  const draft = make("draft-a", "draft", ["delete"]);
  const stale = make("draft-b", "draft", ["delete"]);
  const settled = make("settled", "cancelled", ["reset"]);
  const issued = make("issued", "issued", ["refresh"], "cert02");
  const previous = make("issued-history", "expired", ["reset"], "cert-old");
  const orders = [draft, stale, settled, issued, previous];
  const writes = [];
  let enabled = false;
  let revision = 7;
  await page.route((url) => url.pathname.startsWith("/api/dnscert/orders"), async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname.slice("/api/dnscert/orders".length);
    if (path === "") return route.fulfill({ json: { items: orders, total: orders.length } });
    if (req.method() === "GET" && path.endsWith("/renewal")) return route.fulfill({ json: { enabled, version: revision, currentOrderId: issued.id } });
    if (req.method() !== "POST") return route.fallback();
    const body = req.postDataJSON();
    writes.push([path, body]);
    if (path === "/draft-a/delete") orders.splice(orders.indexOf(draft), 1);
    else if (path === "/draft-b/delete") return route.fulfill({ status: 409, json: { message: "Order changed" } });
    else if (path === "/settled/reset") settled.allowedActions = [];
    else if (path === "/issued/renewal") {
      enabled = body.enabled;
      revision++;
    } else {
      throw new Error("Unexpected batch mutation " + path);
    }
    return route.fulfill({ json: {} });
  });

  await page.reload();
  function row(id) { return page.getByRole("row", { name: new RegExp(id + "\\.example\\.test") }); }
  async function check(id, value) { await row(id).getByRole("checkbox").setChecked(value); }
  async function operation(action) {
    await page.getByRole("button", { name: /Batch actions/ }).click();
    await page.getByRole("menuitem", { name: action, exact: true }).click();
  }
  const dialog = page.getByRole("dialog");
  const apply = dialog.getByRole("button", { name: "Apply to selected orders" });
  const close = dialog.getByRole("button", { name: "Close", exact: true }).last();
  await check("draft-a", true);
  await check("draft-b", true);
  await operation("Delete drafts");
  assert.deepEqual(writes, []);
  await apply.click();
  await dialog.getByText("Order changed", { exact: true }).waitFor();
  await dialog.getByText("Succeeded", { exact: true }).waitFor();
  await close.click();
  assert.deepEqual(writes, [["/draft-a/delete", { version: 4 }], ["/draft-b/delete", { version: 4 }]]);
  await row("draft-a").waitFor({ state: "detached" });
  assert.equal(await row("draft-b").getByRole("checkbox").isChecked(), true);
  await check("draft-b", false);
  await check("settled", true);
  await check("issued", true);
  await operation("Start new drafts");
  await dialog.getByText("Unavailable in the current order state.").waitFor();
  await apply.click();
  await dialog.getByText("Succeeded", { exact: true }).waitFor();
  await close.click();
  assert.deepEqual(writes.at(-1), ["/settled/reset", { version: 4 }]);
  await operation("Enable automatic renewal");
  assert.equal(await apply.isEnabled(), false);
  await dialog.getByRole("combobox").click();
  await page.getByText("example.test · dns01", { exact: true }).click();
  assert.equal(await apply.isEnabled(), false);
  await dialog.getByRole("checkbox").check();
  await apply.click();
  await dialog.getByText("Succeeded", { exact: true }).waitFor();
  await close.click();
  assert.deepEqual(writes.at(-1), ["/issued/renewal", { version: 7, enabled: true, zoneId: "zone01", confirmQuota: true }]);
  await check("issued", true);
  await check("issued-history", true);
  await operation("Disable automatic renewal");
  await apply.click();
  await dialog.getByText("Succeeded", { exact: true }).nth(1).waitFor();
  await close.click();
  assert.deepEqual(writes.at(-1), ["/issued/renewal", { version: 8, enabled: false }]);
  assert.equal(writes.length, 5);
};
