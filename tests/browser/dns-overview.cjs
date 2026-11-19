const assert = require("node:assert/strict");
const { chromium } = require("playwright-core");
const { withConsole } = require("./serve-console.cjs");

withConsole(async (address) => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome", headless: true, args: ["--no-sandbox"] });
  try {
    const page = await browser.newPage({ locale: "en-US" });
    page.setDefaultTimeout(7000);
    await page.addInitScript(() => {
      const record = { id: "testadmin", collectionName: "_superusers" };
      const token = "eyJhbGciOiJIUzI1NiJ9." + btoa(JSON.stringify({ type: "auth", exp: Math.floor(Date.now() / 1000) + 3600 })) + ".mock";
      localStorage.setItem("pocketbase_auth", JSON.stringify({ token, record, model: record }));
      localStorage.setItem("certimate-ui-lang", "en");
    });

    const zone = {
      id: "catalog-fixture",
      accessId: "access-fixture",
      zoneId: "provider-zone",
      provider: "cloudflare",
      name: "example.test",
      enabled: true,
      present: true,
    };
    const errors = [];
    const methods = [];
    const now = Math.floor(Date.now() / 1000);
    const last = { status: "failed", at: now - 60 };
    const responses = {
      "/api/statistics": {},
      "/api/dns/providers": [zone.provider],
      "/api/dns-catalog/accounts": [{ id: zone.accessId, name: "Cloudflare fixture", provider: zone.provider, enabled: true }],
      ["/api/dns-catalog/domains/" + zone.id]: zone,
      "/api/dns/capabilities/cloudflare": { types: ["A"], minTTL: 1, maxTTL: 86400, defaultTTL: 1 },
      "/api/dns/cloudflare/access-fixture/zones/provider-zone/optimize/tasks": [],
      "/api/dns/cloudflare/access-fixture/zones/provider-zone/optimize/history": [{ id: 1, status: "failed", started: last.at, actor: "scheduler" }],
    };
    let failNext = true;
    let noTarget = false;
    page.on("pageerror", (err) => errors.push(err.message));
    await page.route(/^https?:\/\//, (route) => (new URL(route.request().url()).origin === address ? route.fallback() : route.abort()));
    await page.route("**/api/**", async (route) => {
      const request = route.request();
      const { pathname } = new URL(request.url());
      methods.push(request.method());
      let data = responses[pathname];
      if (pathname === "/api/appearance") return route.fulfill({ json: { theme: "system" } });
      if (pathname.startsWith("/api/collections/")) return route.fulfill({ json: { page: 1, perPage: 20, totalItems: 0, totalPages: 0, items: [] } });
      if (pathname === "/api/dns-overview") {
        if (failNext) {
          failNext = false;
          return route.fulfill({ status: 500, json: { message: "fixture internal detail" } });
        }
        data = {
          domains: 3,
          scheduled: 4,
          failover: { total: 3, active: 2, primary: 2, backup: 1, running: true, heartbeat: now },
          optimization: {
            total: 2,
            active: 1,
            succeeded: 1,
            failed: 1,
            heartbeat: now,
            last: noTarget ? last : { ...last, catalogId: zone.id, access: zone.accessId, provider: zone.provider, zone: zone.zoneId },
          },
          orders: { total: 7, issued: 3, failed: 1, expiring: 2, expired: 1 },
          deployments: { total: 5, pending: 1, succeeded: 3, failed: 1 },
        };
      }
      if (pathname === "/api/dns/cloudflare/access-fixture/zones/provider-zone/records") {
        return route.fulfill({ status: 502, json: { message: "Fixture provider unavailable" } });
      }
      return route.fulfill({ json: { code: 0, msg: "success", data: data ?? {} } });
    });

    await page.goto(address + "/#/");
    const overview = page.getByRole("region", { name: "DNS operations" });
    await overview.getByText("Could not load the DNS overview.").waitFor();
    assert.equal(await overview.getByText("fixture internal detail").count(), 0);
    await overview.getByRole("button", { name: "Refresh" }).click();
    const link = (name) => overview.getByRole("link", { name, exact: true });
    await link("3 DNS domains").waitFor();
    for (const [name, href] of [
      ["3 DNS domains", "#/dns/catalog"],
      ["Failover monitors", "#/dns/automation"],
      ["Commercial CA orders", "#/dns-cert"],
      ["Certificate deployments", "#/dns-cert/deployments"],
      ["Failed", "#/dns-cert/deployments?status=-1"],
    ])
      assert.equal(await link(name).getAttribute("href"), href);
    await overview.getByText("Running", { exact: true }).waitFor();
    assert.equal(
      await overview
        .locator("dt", { hasText: /^Scheduled changes$/ })
        .locator("xpath=following-sibling::dd")
        .textContent(),
      "4"
    );

    await link("CDN address optimization").click();
    const drawer = page.getByRole("dialog", { name: /Ranked CDN addresses/ });
    await drawer.getByRole("tab", { name: "Run history", selected: true }).waitFor();
    await drawer.getByRole("cell", { name: "scheduler" }).waitFor();
    await drawer.getByRole("button", { name: "Close", exact: true }).click();
    await drawer.waitFor({ state: "hidden" });
    assert.ok(!page.url().includes("optimizer="));

    noTarget = true;
    await page.goto(address + "/#/");
    await link("CDN address optimization").waitFor();
    assert.equal(await link("CDN address optimization").getAttribute("href"), "#/dns/catalog");
    assert.ok(methods.every((method) => method === "GET"));
    assert.deepEqual(errors, []);
    console.log("PASS DNS admin overview, retry, native links and optimizer history with a provider error");
  } finally {
    await browser.close();
  }
}).catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
