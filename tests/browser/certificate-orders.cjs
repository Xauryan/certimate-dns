// Run against the local console using DNS_UI_BASE. All API requests are served by this fixture.
const assert = require("node:assert/strict");
const { chromium } = require("playwright-core");

(async () => {
  const base = new URL(process.env.DNS_UI_BASE || "http://localhost:4173");
  assert.ok(["localhost", "127.0.0.1", "[::1]"].includes(base.hostname));
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
  try {
    const page = await browser.newPage({ locale: "en-US" });
    page.setDefaultTimeout(10000);
    await page.addInitScript(() => {
      const record = { id: "fixtureowner", collectionName: "_superusers", collectionId: "_pb_users_auth_" };
      const token = "eyJhbGciOiJIUzI1NiJ9." + btoa(JSON.stringify({ type: "auth", exp: Math.floor(Date.now() / 1000) + 600 })) + ".fixture";
      localStorage.setItem("pocketbase_auth", JSON.stringify({ record, token }));
      localStorage.setItem("certimate-ui-lang", "en");
    });

    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const account = { id: "account01", name: "Issuer fixture", provider: "aliyun" };
    const order = {
      id: "order01",
      accessId: account.id,
      provider: account.provider,
      domain: "www.example.test",
      algorithm: "RSA2048",
      state: "issued",
      version: 3,
      certificateId: "cert01",
      allowedActions: ["refresh", "revoke"],
    };
    const orders = [order];
    const zones = [{ id: "zone01", name: "example.test", accountId: "dns01" }];
    const changes = [];
    let renewal = { enabled: false, status: "disabled", version: 0 };
    await page.route(
      (url) => url.pathname.startsWith("/api/"),
      async (route) => {
        const req = route.request(),
          path = new URL(req.url()).pathname;
        if (path === "/api/dnscert/accounts") return route.fulfill({ json: { items: [account] } });
        if (path === "/api/dnscert/zones") return route.fulfill({ json: { items: zones, total: 1 } });
        if (path.startsWith("/api/dnscert/orders/") && path.endsWith("/events")) {
          return route.fulfill({ json: { items: [{ id: 1, created: 1763539200, action: "download", state: "issued", success: true }], total: 1 } });
        }
        if (path.endsWith("/notification")) return route.fulfill({ json: { accessId: "", status: "" } });
        if (path.endsWith("/notification-channels")) return route.fulfill({ json: { code: 0, data: [] } });
        if (path.endsWith("/renewal")) {
          if (req.method() === "POST") {
            const fields = req.postDataJSON();
            assert.deepEqual(fields, { version: 0, enabled: true, zoneId: "zone01", confirmQuota: true });
            changes.push("renew");
            renewal = { enabled: true, status: "scheduled", version: 1, zoneId: "zone01" };
          }
          return route.fulfill({ json: renewal });
        }
        if (path === "/api/dnscert/orders" && req.method() === "GET") return route.fulfill({ json: { items: orders, total: orders.length } });
        if (path === "/api/dnscert/orders" && req.method() === "POST") {
          const { accessId, request } = req.postDataJSON();
          assert.equal(accessId, account.id);
          assert.deepEqual(request, { domain: "new.example.test", algorithm: "RSA3072", sourceZoneId: "zone01" });
          const draft = { ...order, ...request, id: "draft01", state: "draft", version: 1, certificateId: "", allowedActions: ["edit", "create", "cancel"] };
          orders.unshift(draft);
          changes.push("draft");
          return route.fulfill({ json: draft });
        }
        if (path === "/api/dnscert/orders/draft01/create") {
          assert.deepEqual(req.postDataJSON(), { version: 1 });
          changes.push("reserve");
          Object.assign(orders[0], { state: "reserved", version: 2, allowedActions: ["submit", "refresh", "cancel"], remoteId: "remote01" });
          return route.fulfill({ json: orders[0] });
        }
        if (path.includes("/collections/")) return route.fulfill({ json: { items: [], totalItems: 0, totalPages: 1 } });
        return route.fulfill({ json: { code: 0, data: {} } });
      }
    );
    await page.goto(new URL("#/dns-cert", base).href);
    await page.getByRole("button", { name: "New order", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByRole("combobox", { name: "Issuer account" }).click();
    await page.getByText("Issuer fixture · Alibaba Cloud", { exact: true }).click();
    await dialog.getByRole("textbox", { name: "Domain name" }).fill("new.example.test");
    await dialog.getByRole("combobox", { name: "Linked DNS zone (optional)" }).click();
    await page.getByText("example.test · dns01", { exact: true }).click();
    await dialog.getByRole("combobox", { name: "Key algorithm" }).click();
    await page.getByText("RSA 3072", { exact: true }).click();
    await dialog.getByRole("button", { name: "Save draft" }).click();
    await page
      .getByRole("row", { name: /new.example.test/ })
      .getByRole("button", { name: "Reserve order" })
      .click();
    assert.deepEqual(changes, ["draft"]);
    await dialog.getByRole("button", { name: "Reserve order" }).click();
    await page
      .getByRole("row", { name: /new.example.test/ })
      .getByRole("button", { name: "Submit application" })
      .waitFor();

    await page
      .getByRole("row", { name: /www.example.test/ })
      .locator(".ant-table-row-expand-icon")
      .click();
    await page.getByRole("cell", { name: "Succeeded", exact: true }).waitFor();
    await page.getByRole("button", { name: "Enable renewal" }).click();
    await dialog.getByRole("combobox", { name: "DNS zone for validation" }).click();
    await page.getByText("example.test · dns01", { exact: true }).click();
    await dialog.locator("button.ant-btn-primary").click();
    await dialog.getByText("Confirm quota use to enable renewal.").waitFor();
    assert.deepEqual(changes, ["draft", "reserve"]);
    await dialog.getByRole("checkbox").check();
    await dialog.locator("button.ant-btn-primary").click();
    await page.getByRole("button", { name: "Disable renewal" }).waitFor();
    assert.deepEqual(changes, ["draft", "reserve", "renew"]);
    assert.deepEqual(errors, []);
    console.log("PASS certificate order draft, zone scoping, explicit reservation, history and confirmed renewal");
  } finally {
    await browser.close();
  }
})().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
