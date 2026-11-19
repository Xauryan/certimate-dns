const assert = require("node:assert/strict");
const { chromium } = require("playwright-core");
const { withConsole } = require("./serve-console.cjs");

async function run(base) {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
  try {
    for (const collectionName of ["_superusers", "dns_members"]) {
      const page = await browser.newPage({ locale: "en-US", viewport: { width: 1440, height: 900 } });
      page.setDefaultTimeout(15000);
      await page.addInitScript((name) => {
        localStorage.setItem("certimate-ui-lang", "en");
        const record = { id: "proxyfixture00001", collectionName: name };
        const token = "eyJhbGciOiJIUzI1NiJ9." + btoa(JSON.stringify({ type: "auth", exp: Math.floor(Date.now() / 1000) + 3600 })) + ".fixture";
        localStorage.setItem("pocketbase_auth", JSON.stringify({ token, record }));
      }, collectionName);
      let reads = 0;
      const writes = [];
      const tests = [];
      const status = { enabled: true, configured: true, scheme: "https", server: "https://proxy.example.test:8443", hasUsername: true, hasPassword: true };
      await page.route("**/api/**", async (route) => {
        const req = route.request();
        const path = new URL(req.url()).pathname;
        if (path === "/api/dns-proxy/settings") {
          if (req.method() === "GET") {
            reads++;
            return route.fulfill({ json: status });
          }
          assert.equal(req.method(), "PUT");
          const data = req.postDataJSON();
          writes.push(data);
          if ("server" in data) {
            if (data.server !== status.server) status.hasPassword = status.hasUsername = false;
            status.server = data.server;
            status.configured = !!data.server;
          }
          status.enabled = data.enabled;
          if ("username" in data) status.hasUsername = !!data.username;
          if ("password" in data) status.hasPassword = !!data.password;
          return route.fulfill({ status: 204 });
        }
        if (path === "/api/dns-proxy/test") {
          assert.equal(req.method(), "POST");
          tests.push(req.postDataJSON());
          return route.fulfill({ json: { ok: true, latencyMs: 23 } });
        }
        return route.fulfill({ json: { items: [], page: 1, totalItems: 0, totalPages: 1, perPage: 20 } });
      });
      if (collectionName === "dns_members") {
        await page.goto(base + "/#/settings/dns-proxy");
        await page.waitForURL(/#\/dns-member/);
        assert.equal(reads, 0);
        assert.equal(await page.getByRole("button", { name: "Test saved proxy" }).count(), 0);
        await page.close();
        continue;
      }
      await page.goto(base + "/#/settings/diagnostics");
      await page.getByRole("menuitem", { name: "DNS proxy", exact: true }).click();
      await page.waitForURL(/#\/settings\/dns-proxy$/);
      const server = page.getByLabel("Proxy server", { exact: true });
      const password = page.getByLabel("Proxy password", { exact: true });
      const username = page.getByLabel("Proxy username", { exact: true });
      const toggle = page.getByRole("switch");
      const test = page.getByRole("button", { name: "Test saved proxy" });
      const save = page.getByRole("button", { name: "Save changes" });
      await test.waitFor();
      assert.equal(await server.inputValue(), status.server);
      assert.equal(await password.inputValue(), "");
      assert.equal(await username.inputValue(), "");
      assert.equal(await password.getAttribute("type"), "password");
      await test.click();
      await page.getByText("Proxy responded in 23 ms.").waitFor();
      assert.deepEqual(tests, [{}]);
      const saveForm = async () => {
        await Promise.all([page.waitForResponse((r) => r.url().endsWith("/api/dns-proxy/settings") && r.request().method() === "GET"), save.click()]);
        await page.waitForFunction(() => document.querySelector('button[type="submit"]')?.disabled);
      };
      await toggle.click();
      assert.equal(await test.isDisabled(), true);
      await saveForm();
      assert.deepEqual(writes[0], { enabled: false });
      await password.fill("synthetic-replacement");
      await saveForm();
      assert.deepEqual(writes[1], { enabled: false, password: "synthetic-replacement" });
      assert.equal(await password.inputValue(), "");
      await page.getByRole("checkbox", { name: "Clear saved username and password" }).check();
      await saveForm();
      assert.deepEqual(writes[2], { enabled: false, username: "", password: "" });
      await server.fill("https://example.test/proxy");
      await save.click();
      await page.locator(".ant-form-item-explain-error").first().waitFor();
      assert.equal(writes.length, 3);
      await server.fill("socks5h://new.example.test:1080");
      await saveForm();
      assert.deepEqual(writes[3], { enabled: false, server: "socks5h://new.example.test:1080" });
      await page.getByRole("button", { name: "Remove proxy" }).click();
      await Promise.all([
        page.waitForResponse((r) => r.url().endsWith("/api/dns-proxy/settings") && r.request().method() === "GET"),
        page.locator(".ant-popconfirm .ant-btn-primary").click(),
      ]);
      await page.waitForFunction(() => document.querySelector("#server")?.value === "");
      assert.equal(await test.isDisabled(), true);
      assert.deepEqual(writes[4], { enabled: false, server: "", username: "", password: "" });
      await page.close();
    }
  } finally {
    await browser.close();
  }
}

withConsole(run).catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
