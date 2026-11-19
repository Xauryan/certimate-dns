const assert = require("node:assert/strict");

async function session(browser, collectionName, viewport, address) {
  const context = await browser.newContext({ locale: "en-US", viewport });
  await context.route(/^https?:\/\//, (route) => (new URL(route.request().url()).origin === address ? route.fallback() : route.abort()));
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  await page.addInitScript((collectionName) => {
    localStorage.setItem("certimate-ui-lang", "en");
    // Seed once so a reload cannot silently restore a cleared session.
    if (sessionStorage.getItem("initialized")) return;
    sessionStorage.setItem("initialized", "1");
    const record = { id: "fixtureidentity", collectionName, email: "viewer@example.test" };
    const token = "eyJhbGciOiJIUzI1NiJ9." + btoa(JSON.stringify({ type: "auth", exp: Math.floor(Date.now() / 1000) + 3600 })) + ".fixture";
    localStorage.setItem("pocketbase_auth", JSON.stringify({ record, token }));
  }, collectionName);
  return page;
}

const ok = (route, data) => route.fulfill({ json: { code: 0, data } });

async function testDNSPermissions(browser, address) {
  const admin = await session(browser, "_superusers", { width: 390, height: 844 }, address);
  const member = { id: "readerfixture", email: "reader@example.test", disabled: false };
  const workspace = { id: "workspaceone", name: "Operations" };
  const account = { id: "accessfixture", name: "DNS credential" };
  const zone = { id: "zonefixture", name: "allowed.example.test", accountRef: account.id, present: true };
  const rows = {
    dns_members: [member],
    dns_workspaces: [workspace],
    access: [account],
    dnsZone: [zone],
    dns_workspace_zones: [],
    dns_zone_grants: [],
    dns_workspace_grants: [],
  };
  const errors = [];
  admin.on("pageerror", (e) => errors.push(e.message));
  const writes = [];
  try {
    await admin.route("**/api/**", async (route) => {
      const req = route.request();
      const u = new URL(req.url());
      if (u.pathname === "/api/dns-member/zones") return ok(route, { items: [], total: 0 });
      if (u.pathname === "/api/dns/providers" || u.pathname === "/api/dns-catalog/accounts") return ok(route, []);
      const match = u.pathname.match(/^\/api\/collections\/([^/]+)\/records(?:\/([^/]+))?$/);
      if (!match) return ok(route, null);
      const [, collection, id] = match;
      const items = rows[collection] || [];
      if (req.method() === "GET") {
        return route.fulfill({ json: { items, totalPages: 1, totalItems: items.length, page: 1, perPage: 500 } });
      }
      if (collection === "dns_workspace_grants" && req.method() === "POST") {
        const grant = { ...req.postDataJSON(), id: "newgrant" };
        rows[collection].push(grant);
        writes.push(req.method());
        return route.fulfill({ json: grant });
      }
      if (collection === "dns_workspace_grants" && req.method() === "DELETE" && id === "newgrant") {
        rows[collection] = [];
        writes.push(req.method());
        return route.fulfill({ status: 204 });
      }
      return route.fulfill({ status: 400, json: { message: "Unexpected fixture operation" } });
    });
    await admin.goto(address + "/#/dns");
    await admin.getByRole("button", { name: "Open navigation" }).click();
    const nav = admin.getByRole("dialog");
    await nav.getByRole("menuitem", { name: "DNS permissions", exact: true }).click();
    await admin.getByRole("heading", { name: "DNS permissions" }).waitFor();
    await admin.getByRole("tab", { name: "Access grants" }).click();
    const panel = admin.getByRole("tabpanel", { name: "Access grants" });
    async function select(label, value) {
      await panel.getByRole("combobox", { name: label }).click();
      await admin.locator(".ant-select-dropdown:visible").getByText(value, { exact: true }).click();
    }
    await select("Member", member.email);
    await select("Resource", workspace.name);
    await panel.getByRole("button", { name: "Grant access" }).click();
    const row = panel.getByRole("row").filter({ hasText: member.email });
    await row.getByText("Reader", { exact: true }).waitFor();
    assert.deepEqual(rows.dns_workspace_grants, [{ member: member.id, workspace: workspace.id, role: "reader", id: "newgrant" }]);
    await row.getByRole("button", { name: "Revoke" }).click();
    await admin.locator(".ant-popconfirm .ant-btn-primary").click();
    await row.waitFor({ state: "detached" });
    assert.deepEqual(writes, ["POST", "DELETE"]);

    // A sign-in in another tab must also close this tab's administrator views.
    const sibling = await admin.context().newPage();
    try {
      await sibling.goto(address + "/robots.txt");
      await sibling.evaluate(() => {
        const record = { id: "tenanttwo", collectionName: "dns_members", email: "tenanttwo@example.test" };
        const token = "synthetic." + btoa(JSON.stringify({ id: record.id, exp: Math.floor(Date.now() / 1000) + 300 })) + ".fixture";
        localStorage.setItem("pocketbase_auth", JSON.stringify({ record, token }));
      });
      await admin.getByRole("heading", { name: "DNS member console" }).waitFor();
      assert.equal(await admin.getByRole("tab", { name: "Access grants" }).count(), 0);
    } finally {
      await sibling.close();
    }
  } finally {
    await admin.context().close();
  }

  const viewer = await session(browser, "dns_members", { width: 390, height: 844 }, address);
  viewer.on("pageerror", (e) => errors.push(e.message));
  const requested = [];
  let denied = false;
  try {
    await viewer.route("**/api/**", async (route) => {
      const u = new URL(route.request().url());
      if (route.request().method() === "GET" && u.pathname === "/api/appearance") {
        return route.fulfill({ json: { theme: "dark" } });
      }
      requested.push(u.pathname);
      if (u.pathname === "/api/dns-member/zones") {
        return ok(route, {
          items: [{ id: zone.id, zoneId: "providerzone", name: zone.name, provider: "aliyun", accessId: account.id, status: "active", canWrite: false }],
          total: 1,
        });
      }
      if (u.pathname === "/api/dns/capabilities/aliyun") return ok(route, { types: ["TXT"], minTTL: 60, maxTTL: 86400, defaultTTL: 600 });
      if (u.pathname.endsWith("/records") && !denied)
        return ok(route, {
          result: [{ id: "txtrecord", type: "TXT", name: zone.name, content: "fixture value", ttl: 600 }],
          result_info: { page: 1, total_count: 1 },
        });
      return route.fulfill({ status: 403, json: { code: 403, message: "This zone grant has been revoked" } });
    });
    await viewer.goto(address + "/#/dns-permissions");
    await viewer.getByRole("heading", { name: "DNS member console" }).waitFor();
    assert.equal(new URL(viewer.url()).hash, "#/dns-member");
    assert.equal(await viewer.getByRole("button", { name: "Open navigation" }).count(), 0);
    await viewer.getByRole("button", { name: zone.name, exact: true }).click();
    await viewer.getByRole("cell", { name: "fixture value" }).waitFor();
    for (const name of ["Add record", "Edit record", "Delete", "Ranked CDN addresses"]) {
      assert.equal(await viewer.getByRole("button", { name, exact: true }).count(), 0);
    }
    denied = true;
    await viewer.getByRole("button", { name: "Refresh", exact: true }).click();
    await viewer.getByRole("alert").getByText("This zone grant has been revoked").waitFor();
    assert.equal(await viewer.getByRole("cell", { name: "fixture value" }).count(), 0);
    assert.equal(await viewer.evaluate(() => JSON.parse(localStorage.getItem("pocketbase_auth"))?.record.collectionName), "dns_members");
    assert.deepEqual(requested.filter((p) => !p.startsWith("/api/dns-member/") && !p.startsWith("/api/dns/")), []);
    assert.deepEqual(errors, []);
    console.log("PASS mobile navigation, grant and revoke, member route isolation, read-only controls, and denied zone access");
  } finally {
    await viewer.context().close();
  }
}
module.exports = { testDNSPermissions };
