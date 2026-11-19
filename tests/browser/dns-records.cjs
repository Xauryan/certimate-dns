const { chromium } = require("playwright-core");
const http = require("node:http"),
  fs = require("node:fs/promises"),
  path = require("node:path"),
  assert = require("node:assert/strict");
(async () => {
  const root = path.resolve(__dirname, "../../ui/dist");
  const server = http.createServer(async (req, res) => {
    const p = new URL(req.url, "http://localhost").pathname;
    const types = { ".js": "text/javascript", ".css": "text/css", ".html": "text/html", ".svg": "image/svg+xml" };
    const name = path.join(root, p === "/" ? "index.html" : p);
    try {
      const data = await fs.readFile(name);
      res.writeHead(200, { "Content-Type": types[path.extname(name)] || "application/octet-stream" });
      res.end(data);
    } catch {
      res.writeHead(404).end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome", headless: true, args: ["--no-sandbox"] });
  try {
    const page = await browser.newPage({ locale: "en-US" });
    page.setDefaultTimeout(7000);
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
    await page.route("**/api/**", async (route) => {
      const req = route.request(),
        u = new URL(req.url());
      let data;
      if (u.pathname.includes("/collections/access/records"))
        return route.fulfill({
          json: { page: 1, perPage: 20, totalPages: 1, totalItems: 1, items: [{ id: "testaccess", provider: "cloudflare", name: "Test account" }] },
        });
      const m = req.method();
      if (u.pathname.endsWith("/zones")) data = { result: [zone], result_info: { page: 1, total_count: 1 } };
      else if (u.pathname.endsWith("/export")) data = 'example.org. 300 IN TXT "test"';
      else if (m === "GET") data = { result: records, result_info: { page: 1, total_count: records.length } };
      else {
        methods.push(m);
        if (m === "POST") records = [{ id, ...req.postDataJSON(), proxied: false }];
        if (m === "PATCH" && failNextPatch) {
          failNextPatch = false;
          return route.fulfill({ json: { code: 500, msg: "Fixture denied change", data: null } });
        }
        if (m === "PATCH") {
          assert.deepEqual(Object.keys(req.postDataJSON()).sort(), ["content", "ttl"]);
          Object.assign(records[0], req.postDataJSON());
        }
        if (m === "DELETE") records = [];
        data = id;
      }
      await route.fulfill({ json: { code: 0, msg: "success", data } });
    });
    await page.goto("http://127.0.0.1:" + server.address().port + "/#/dns");
    await page.getByRole("button", { name: "example.org", exact: true }).click();
    await page.getByRole("button", { name: /Add record|添加记录/ }).click();
    let modal = page.getByRole("dialog");
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
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: /Export BIND|导出 BIND/ }).click();
    assert.equal((await download).suggestedFilename(), "example.org.zone");
    await page.getByRole("button", { name: /^Delete$|^删除$/ }).click();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: /^Delete$|^删除$/ })
      .click();
    await page.getByRole("cell", { name: "www.example.org" }).waitFor({ state: "detached" });
    assert.deepEqual(methods, ["POST", "PATCH", "PATCH", "DELETE"]);
    assert.deepEqual(errs, []);
    console.log("PASS authenticated UI fixture: select zone, add, edit, export, confirm deletion");
  } finally {
    await browser.close();
    server.closeAllConnections();
    server.close();
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
