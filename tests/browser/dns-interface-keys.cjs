// Run against a local Vite dev/preview server with DNS_UI_BASE=http://127.0.0.1:port.
const assert = require("node:assert/strict");
const { chromium } = require("playwright-core");

async function main() {
  const base = new URL(process.env.DNS_UI_BASE || "http://127.0.0.1:4173");
  assert.ok(["127.0.0.1", "localhost", "[::1]"].includes(base.hostname));
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
  try {
    const page = await browser.newPage({ locale: "en-US" });
    page.setDefaultTimeout(15000);
    await page.addInitScript(() => {
      const record = { id: "fixtureowner", collectionId: "_pb_users_auth_", collectionName: "_superusers" };
      const token = "eyJhbGciOiJIUzI1NiJ9." + btoa(JSON.stringify({ type: "auth", exp: Math.floor(Date.now() / 1000) + 600 })) + ".fixture";
      localStorage.setItem("pocketbase_auth", JSON.stringify({ token, record }));
      localStorage.setItem("certimate-ui-lang", "en");
    });
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const mutations = [];
    const zone = (n) => ({ id: "local-zone-" + n, accessId: "access01", provider: "cloudflare", name: n + ".example.test", canWrite: n === 11 });
    const rows = [];
    const secret = "synthetic-ui-test-key";
    await page.route(
      (url) => url.pathname.startsWith("/api/"),
      async (route) => {
        const request = route.request();
        const url = new URL(request.url());
        const path = url.pathname;
        if (path === "/api/dns-keys/actions") return route.fulfill({ json: ["domain.read", "record.read", "record.update"] });
        if (path === "/api/dns-member/zones") {
          const items = url.searchParams.get("page") === "1" ? Array.from({ length: 10 }, (_, i) => zone(i + 1)) : [zone(11)];
          return route.fulfill({ json: { code: 0, data: { items, total: 11 } } });
        }
        if (path === "/api/collections/access/records") return route.fulfill({ json: { items: [], totalPages: 1, totalItems: 0 } });
        if (path === "/api/dns-keys" && request.method() === "GET") return route.fulfill({ json: rows });
        if (path === "/api/dns-keys" && request.method() === "POST") {
          const { label, zones, actions, interfaces, accounts, global } = request.postDataJSON();
          mutations.push({ label, zones, actions, interfaces, accounts, global });
          rows.push({ uid: "42", label, scope: { zones, actions, interfaces } });
          return route.fulfill({ status: 201, json: { uid: "42", apikey: secret } });
        }
        if (path === "/api/dns-keys/42" && request.method() === "DELETE") {
          mutations.push("revoke");
          rows.pop();
          return route.fulfill({ status: 204 });
        }
        return route.fulfill({ json: { code: 0, data: {} } });
      }
    );
    await page.goto(new URL("#/dns-interfaces", base).href);
    await page.getByRole("button", { name: "Issue key" }).click();
    const form = page.getByRole("dialog");
    await form.getByLabel("Key name").fill("Fixture key");
    await form.getByRole("checkbox", { name: "MCP" }).check();
    await form.getByRole("checkbox", { name: "1.example.test", exact: true }).check();
    const actions = form.getByRole("combobox", { name: "Allowed actions" });
    await actions.fill("record.update");
    await actions.press("Enter");
    await actions.press("Escape");
    const readOnly = form.getByRole("checkbox", { name: "1.example.test", exact: true });
    assert.ok(await readOnly.isDisabled());
    assert.ok(!(await readOnly.isChecked()));
    await form.locator(".ant-pagination-item-2").click();
    await form.getByRole("checkbox", { name: "11.example.test", exact: true }).check();
    await form.getByRole("button", { name: "Issue key" }).click();
    await page.getByText(secret, { exact: true }).waitFor();
    assert.deepEqual(mutations, [
      {
        label: "Fixture key",
        zones: ["local-zone-11"],
        actions: ["domain.read", "record.read", "record.update"],
        interfaces: ["api", "mcp"],
        accounts: undefined,
        global: undefined,
      },
    ]);
    await page.getByRole("button", { name: "Done", exact: true }).click();
    await page.getByText(secret).waitFor({ state: "detached" });
    const retained = await page.evaluate(() => JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)]));
    assert.ok(!retained.includes(secret));
    await page.getByRole("cell", { name: "Fixture key" }).waitFor();
    const revoke = page.getByRole("button", { name: "Revoke", exact: true });
    await revoke.click();
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    await page.getByRole("dialog").waitFor({ state: "hidden" });
    assert.equal(mutations.length, 1);
    await revoke.click();
    await page.getByRole("dialog").getByRole("button", { name: "Revoke" }).click();
    await page.getByRole("cell", { name: "Fixture key" }).waitFor({ state: "detached" });
    assert.equal(mutations[1], "revoke");
    assert.deepEqual(errors, []);
    console.log("PASS interface keys: live action grant, paginated domain selection, one-time key, cancel and confirm revocation");
  } finally {
    await browser.close();
  }
}
main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
