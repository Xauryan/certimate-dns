const { chromium } = require("playwright-core");
const assert = require("node:assert/strict");
const { withConsole } = require("./serve-console.cjs");
withConsole(async (address) => {
  const { testDNSBatch } = require("./dns-batch.cjs");
  const { testDNSPermissions } = require("./dns-permissions.cjs");
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome", headless: true, args: ["--no-sandbox"] });
  try {
    const page = await browser.newPage({ locale: "en-US" });
    page.setDefaultTimeout(7000);
    await page.route(/^https?:\/\//, (route) => (new URL(route.request().url()).origin === address ? route.fallback() : route.abort()));
    const errs = [];
    page.on("pageerror", (e) => errs.push(e.message));
    await page.addInitScript(() => {
      const record = { id: "testadmin", collectionName: "_superusers" };
      const token = "eyJhbGciOiJIUzI1NiJ9." + btoa(JSON.stringify({ type: "auth", exp: Math.floor(Date.now() / 1000) + 3600 })) + ".mock";
      localStorage.setItem("pocketbase_auth", JSON.stringify({ token, record, model: record }));
    });
    const zone = { id: "a".repeat(32), name: "example.org", status: "active" };
    const id = "b".repeat(32);
    let records = [];
    const methods = [];
    let failNextPatch = true;
    let allowRichEdit = false;
    await page.route("**/api/**", async (route) => {
      const req = route.request(),
        u = new URL(req.url());
      let data;
      const m = req.method();
      if (u.pathname === "/api/dns/providers") data = ["cloudflare", "powerdns"];
      else if (u.pathname === "/api/dns-catalog/accounts")
        data = [
          { id: "testaccess", provider: "cloudflare", name: "Test account", enabled: true },
          { id: "powerfixture", provider: "powerdns", name: "Second provider", enabled: true },
          { id: "disabledfixture", provider: "cloudflare", name: "Disabled account", enabled: false },
          { id: "unsupportedfixture", provider: "other", name: "Unsupported credential", enabled: true },
        ];
      else if (u.pathname === "/api/dns/capabilities/cloudflare")
        data = {
          types: ["A", "AAAA", "CNAME", "TXT", "MX"],
          priorityTypes: ["MX"],
          minTTL: 30,
          maxTTL: 86400,
          defaultTTL: 1,
          specialTTLs: [1],
          line: true,
          description: true,
          export: true,
        };
      else if (u.pathname.endsWith("/advanced/details")) data = { name: zone.name, lines: [{ id: "0", name: "DNS only" }] };
      else if (u.pathname.endsWith("/zones")) data = { result: [zone], result_info: { page: 1, total_count: 1 } };
      else if (u.pathname.endsWith("/export")) data = 'example.org. 300 IN TXT "test"';
      else if (m === "GET") data = { result: records, result_info: { page: 1, total_count: records.length }, edit: { rename: allowRichEdit, retype: allowRichEdit, priority: allowRichEdit } };
      else {
        methods.push(m);
        if (m === "POST") records = [{ id, ...req.postDataJSON(), proxied: false }];
        if (m === "PATCH" && failNextPatch) {
          failNextPatch = false;
          return route.fulfill({ json: { code: 500, msg: "Fixture denied change", data: null } });
        }
        if (m === "PATCH") {
          const { expected, ...desired } = req.postDataJSON();
          if (allowRichEdit) {
            assert.equal(u.searchParams.get("page"), "1");
            assert.deepEqual(expected, records[0]);
            assert.equal(desired.name, "mail.example.org");
            assert.equal(desired.type, "MX");
            assert.equal(desired.priority, 15);
          } else {
            assert.equal(expected, undefined);
            assert.deepEqual(Object.keys(desired).sort(), ["content", "ttl"]);
            allowRichEdit = true;
          }
          Object.assign(records[0], desired);
        }
        if (m === "DELETE") records = [];
        data = id;
      }
      await route.fulfill({ json: { code: 0, msg: "success", data } });
    });
    await page.goto(address + "/#/dns");
    await page.locator("#dns-account").click();
    await page.getByText(/Second provider/).waitFor();
    assert.equal(await page.getByText("Disabled account", { exact: false }).count(), 0);
    assert.equal(await page.getByText("Unsupported credential", { exact: false }).count(), 0);
    await page.keyboard.press("Escape");
    await page.getByRole("button", { name: "example.org", exact: true }).click();
    await page.getByRole("button", { name: /Add record|添加记录/ }).click();
    let modal = page.getByRole("dialog");
    await modal.locator("#type").click();
    await page.locator(".ant-select-dropdown:visible").getByText("MX", { exact: true }).click();
    await modal.locator("#priority").waitFor();
    await modal.locator("#type").click();
    await page.locator(".ant-select-dropdown:visible").getByText("A", { exact: true }).click();
    await modal.locator("#priority").waitFor({ state: "detached" });
    await modal.locator("input#name").fill("www.example.org");
    await modal.locator("textarea").fill("192.0.2.1");
    await modal.locator("button.ant-btn-primary").click();
    await page.getByRole("cell", { name: "www.example.org" }).waitFor();
    await page.getByRole("button", { name: /Edit record|编辑记录/ }).click();
    modal = page.getByRole("dialog");
    await modal.locator("textarea").fill("192.0.2.2");
    await modal.locator("button.ant-btn-primary").click();
    await page.getByText("Fixture denied change").waitFor();
    assert.equal(records[0].content, "192.0.2.1");
    await modal.locator("button.ant-btn-primary").click();
    await page.getByRole("cell", { name: "192.0.2.2" }).waitFor();
    await page.reload();
    await page.getByRole("cell", { name: "www.example.org" }).waitFor();
    await page.getByRole("button", { name: /Edit record|编辑记录/ }).click();
    modal = page.getByRole("dialog");
    await modal.locator("#type").click();
    await page.locator(".ant-select-dropdown:visible").getByText("MX", { exact: true }).click();
    await modal.locator("input#name").fill("mail.example.org");
    await modal.locator("#priority").fill("15");
    await modal.locator("textarea").fill("mx.example.org");
    await modal.locator("button.ant-btn-primary").click();
    await page.getByRole("cell", { name: "mail.example.org", exact: true }).waitFor();
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: /Export BIND|导出 BIND/ }).click();
    assert.equal((await download).suggestedFilename(), "example.org.zone");
    await page.getByRole("button", { name: /^Delete$|^删除$/ }).click();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: /^Delete$|^删除$/ })
      .click();
    await page.getByRole("cell", { name: "mail.example.org" }).waitFor({ state: "detached" });
    assert.deepEqual(methods, ["POST", "PATCH", "PATCH", "PATCH", "DELETE"]);
    assert.deepEqual(errs, []);
    await page.goto(address + "/#/dns?access=disabledfixture");
    await page
      .getByRole("alert")
      .getByText(/unavailable|不可用/)
      .waitFor();
    assert.equal(await page.getByRole("button", { name: "example.org" }).count(), 0);
    console.log("PASS admin DNS records, server capabilities, enabled accounts, deep links, export and deletion");
    await page.close();
    await testDNSPermissions(browser, address);
    await testDNSBatch(browser, address);
  } finally {
    await browser.close();
  }
}).catch((e) => {
  console.error(e);
  process.exit(1);
});
