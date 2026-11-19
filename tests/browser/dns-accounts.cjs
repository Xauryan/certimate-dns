const assert = require("node:assert/strict");
const path = require("node:path");
const { chromium } = require("playwright-core");

const dist = path.resolve(process.env.CERTIMATE_UI_DIST || path.join(__dirname, "../../ui/dist"));
const origin = "http://localhost";
const account = {
  id: "accountfixture01",
  name: "Fixture credential",
  provider: "cloudflare",
};
let config = { apiToken: "fixture-record-token", apiTokenForZone: "fixture-zone-token", extraConsumerSetting: "retain" };
const updates = [];

async function main() {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome", headless: true, args: ["--no-sandbox"] });
  try {
    const page = await browser.newPage({ locale: "en-US" });
    page.setDefaultTimeout(9000);
    const errors = [];
    page.on("pageerror", (err) => errors.push(err.message));
    await page.addInitScript(() => {
      const record = { id: "testadmin", collectionName: "_superusers" };
      const token = "eyJhbGciOiJIUzI1NiJ9." + btoa(JSON.stringify({ type: "auth", exp: Math.floor(Date.now() / 1000) + 3600 })) + ".mock";
      localStorage.setItem("pocketbase_auth", JSON.stringify({ token, record, model: record }));
    });
    await page.route("**/*", async (route) => {
      const req = route.request();
      const u = new URL(req.url());
      if (u.origin !== origin) return route.abort("blockedbyclient");
      if (!u.pathname.startsWith("/api/")) {
        const file = path.resolve(dist, "." + (u.pathname === "/" ? "/index.html" : u.pathname));
        assert.ok(file.startsWith(dist + path.sep));
        await route.fulfill({ path: file });
      } else if (u.pathname === "/api/collections/access/records") {
        if (req.method() === "GET") {
          assert.ok(!u.searchParams.get("fields").split(",").includes("config"));
          await route.fulfill({ json: { page: 1, perPage: 65535, totalPages: 1, totalItems: 1, items: [account] } });
        } else {
          assert.equal(req.method(), "POST");
          assert.ok(!u.searchParams.get("fields").split(",").includes("config"));
          updates.push(req.postDataJSON());
          await route.fulfill({ json: { ...account, name: "Created fixture" } });
        }
      } else if (u.pathname === "/api/collections/access/records/" + account.id) {
        if (req.method() === "GET") {
          await route.fulfill({ json: { ...account, config } });
        } else {
          assert.equal(req.method(), "PATCH");
          assert.ok(!u.searchParams.get("fields").split(",").includes("config"));
          updates.push(req.postDataJSON());
          config = req.postDataJSON().config;
          await route.fulfill({ json: account });
        }
      } else {
        await route.fulfill({ json: { code: 0, msg: "success", data: null, items: [], page: 1, totalItems: 0, totalPages: 1 } });
      }
    });

    await page.goto(origin + "/#/accesses/new?usage=dns-management");
    const cards = page.locator(".ant-card");
    await cards.first().waitFor();
    assert.equal(await cards.count(), 22);
    await cards.filter({ hasText: "Hurricane Electric" }).click();
    const field = (name) => page.locator('input[id$="_' + name + '"]:visible');
    await field("name").fill("Created fixture");
    await field("config_username").fill("fixture-user");
    assert.equal(await field("config_password").getAttribute("type"), "password");
    await page.getByRole("button", { name: "Submit", exact: true }).click();
    await page.locator(".ant-form-item-explain-error:visible").first().waitFor();
    assert.equal(updates.length, 0);
    await field("config_password").fill("fixture-password");
    assert.equal(await page.getByRole("radio", { name: "Use environment settings" }).isChecked(), true);
    await page.getByRole("radio", { name: "Connect directly" }).check();
    await page.getByRole("button", { name: "Submit", exact: true }).click();

    const cell = page.getByText(account.name, { exact: true });
    await cell.waitFor();
    assert.equal(updates[0].provider, "henet");
    assert.deepEqual(updates[0].config, { username: "fixture-user", password: "fixture-password", dnsManagementProxy: false });
    await cell.click();
    const drawer = page.locator(".ant-drawer-content:visible, .ant-drawer-section:visible").last();
    const save = drawer.getByRole("button", { name: "Save changes", exact: true });
    const recordToken = field("config_apiToken");
    await recordToken.waitFor();
    assert.equal(await recordToken.getAttribute("type"), "password");
    assert.equal(await drawer.getByRole("radio", { name: "Use environment settings" }).isChecked(), true);
    await drawer.getByRole("radio", { name: "Require instance DNS proxy" }).check();
    await field("config_accountId").fill("a".repeat(32));
    await save.click();
    await drawer.waitFor({ state: "hidden" });
    assert.equal(config.dnsManagementProxy, true);
    assert.equal(config.extraConsumerSetting, "retain");
    assert.equal(config.apiTokenForZone, "fixture-zone-token");
    assert.equal(config.apiToken, "fixture-record-token");

    await cell.click();
    await drawer.getByRole("radio", { name: "Require instance DNS proxy", checked: true }).waitFor();
    await drawer.getByRole("radio", { name: "Use environment settings" }).check();
    await drawer.getByRole("radio", { name: "Global API Key", exact: true }).check();
    await field("config_email").fill("dns@example.org");
    await field("config_apiKey").fill("fixture-global-key");
    await save.click();
    await drawer.waitFor({ state: "hidden" });
    assert.deepEqual(config, { accountId: "a".repeat(32), authMethod: "globalapikey", email: "dns@example.org", apiKey: "fixture-global-key", extraConsumerSetting: "retain" });
    await page.goto(origin + "/#/accesses/new?usage=dns-management");
    await cards.filter({ hasText: "DNSMgr (remote site)" }).click();
    await field("name").fill("DNSMgr fixture");
    await field("config_serverUrl").fill("https://dns.example.org");
    await field("config_uid").fill("75");
    await field("config_apiKey").fill("fixture-dnsmgr-key");
    assert.equal(await page.getByRole("radio", { name: "Legacy", exact: true }).isChecked(), true);
    await page.getByRole("radio", { name: "V2", exact: true }).check();
    await page.getByRole("button", { name: "Submit", exact: true }).click();
    await cell.waitFor();
    assert.equal(updates[3].config.signatureMode, "v2");
    assert.equal(Object.hasOwn(updates[3].config, "dnsManagementProxy"), false);
    assert.equal(updates.length, 4);
    await page.goto(origin + "/#/accesses/new?usage=dns");
    await cards.getByText("Cloudflare", { exact: true }).click();
    await field("config_apiToken").waitFor();
    assert.equal(await page.getByRole("radio", { name: "Require instance DNS proxy" }).count(), 0);
    assert.ok(!page.url().includes("fixture-"));
    assert.deepEqual(errors, []);
    console.log("PASS 22 DNS credential choices, HE creation, Cloudflare edits, DNS management proxy modes and DNSMgr V2");
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
