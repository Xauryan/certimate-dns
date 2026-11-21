const assert = require("node:assert/strict");
const { chromium } = require("playwright-core");
const { withConsole } = require("./serve-console.cjs");

withConsole(async (address) => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
  try {
    const page = await browser.newPage({ locale: "en-US" });
    page.setDefaultTimeout(8000);
    await page.addInitScript(() => {
      const record = { id: "fixtureowner", collectionName: "_superusers" };
      const token = "eyJhbGciOiJIUzI1NiJ9." + btoa(JSON.stringify({ type: "auth", exp: Math.floor(Date.now() / 1000) + 600 })) + ".fixture";
      localStorage.setItem("pocketbase_auth", JSON.stringify({ token, record }));
      localStorage.setItem("certimate-ui-lang", localStorage.getItem("certimate-ui-lang") ?? "en");
    });

    const root = "/api/ddns/nodes";
    const nodePath = root + "/fixture";
    const bindingPath = nodePath + "/bindings/fixture-binding";
    const node = { id: "fixture", name: "Test laptop", enabled: true, hostname: "", online: false, lastSeen: null, interfaces: [], bindings: [] };
    const nodes = [];
    const operations = [];
    const errors = [];
    const token = "synthetic-ddns-registration-token";
    const replacement = "synthetic-ddns-replacement-token";
    const catalog = { id: "catalog-id", provider: "cloudflare", zoneId: "provider-zone", name: "example.test", enabled: true, present: true };
    const target = { provider: catalog.provider, accessId: "cloud-access", zoneId: catalog.zoneId, recordId: "writable-aaaa", interfaceName: "eth0" };
    const oldRecord = "test.example.test";
    const newRecord = "renamed.example.test";
    const edit = { recordName: newRecord, interfaceName: "eth1", expectedRecordName: oldRecord, expectedInterfaceName: target.interfaceName };
    const conflict = "The DNS record changed or the requested name already has a conflicting record.";
    const pending = "The DNS rename could not be confirmed.";
    let renameAttempts = 0;
    page.on("pageerror", (error) => errors.push(error.message));
    await page.route(/^https?:\/\//, (route) => (new URL(route.request().url()).origin === address ? route.fallback() : route.abort()));
    await page.route("**/api/**", async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const path = url.pathname;
      const method = request.method();
      const ok = (data) => route.fulfill({ json: { code: 0, data } });
      if (path === root && method === "GET") return route.fulfill({ json: nodes });
      if (path === root && method === "POST") {
        operations.push(request.postDataJSON());
        nodes.push(node);
        return route.fulfill({ status: 201, json: { id: node.id, token } });
      }
      if (path === nodePath + "/rotate" && method === "POST") {
        operations.push("rotate");
        return route.fulfill({ json: { id: node.id, token: replacement } });
      }
      if (path === nodePath + "/bindings" && method === "POST") {
        operations.push(request.postDataJSON());
        node.bindings.push({
          ...target,
          id: "fixture-binding",
          zoneName: catalog.name,
          recordName: oldRecord,
          recordType: "AAAA",
          syncStatus: "synced",
          lastAddress: "2001:db8::24",
          updatedAt: "2026-10-05T11:20:00Z",
        });
        return route.fulfill({ status: 201, json: node.bindings[0] });
      }
      if (path === bindingPath && method === "PUT") {
        operations.push({ edit: request.postDataJSON() });
        renameAttempts += 1;
        if (renameAttempts === 1) return route.fulfill({ status: 409, json: { message: conflict } });
        if (renameAttempts === 2) {
          node.bindings[0].pendingRename = { recordName: newRecord, interfaceName: edit.interfaceName, submitted: true };
          node.online = false;
          node.interfaces = [];
          return route.fulfill({ status: 409, json: { message: pending } });
        }
        Object.assign(node.bindings[0], { recordName: newRecord, interfaceName: edit.interfaceName, syncStatus: "pending", lastAddress: "" });
        delete node.bindings[0].pendingRename;
        return route.fulfill({ json: node.bindings[0] });
      }
      if (path === bindingPath && method === "DELETE") {
        operations.push("unbind");
        node.bindings.pop();
        return route.fulfill({ status: 204 });
      }
      if (path === nodePath && method === "DELETE") {
        operations.push("delete");
        nodes.pop();
        return route.fulfill({ status: 204 });
      }
      if (path === "/api/dns-catalog/accounts") {
        return ok([
          { id: "cloud-access", provider: "cloudflare", name: "Test DNS account", enabled: true },
          { id: "disabled-account", provider: "tencentcloud", name: "Disabled account", enabled: false },
        ]);
      }
      if (path === "/api/dns-catalog/domains") {
        assert.equal(url.searchParams.get("accessId"), target.accessId);
        return ok({ items: [catalog], total: 1 });
      }
      if (path === "/api/dns/cloudflare/cloud-access/zones/provider-zone/records") {
        const result = [
          { id: target.recordId, name: oldRecord, type: "AAAA", content: "2001:db8::1" },
          { id: "readonly-a", name: "readonly.example.test", type: "A", content: "192.0.2.12", readOnly: true },
          { id: "cname", name: "alias.example.test", type: "CNAME", content: "test.example.test" },
        ];
        return ok({ result, result_info: { page: 1, total_count: result.length } });
      }
      if (path.startsWith("/api/collections/")) return route.fulfill({ json: { page: 1, totalPages: 0, totalItems: 0, items: [] } });
      return ok({});
    });

    await page.goto(address + "/#/accesses");
    await page.getByRole("menuitem", { name: "DNS management", exact: true }).click();
    const nav = page.getByRole("menuitem", { name: "DDNS management" });
    await nav.click();
    assert.equal(new URL(page.url()).hash, "#/dns/ddns");
    await page.getByText("No DDNS nodes registered.").waitFor();
    await page.getByRole("button", { name: "Register node" }).click();
    const dialog = () => page.getByRole("dialog");
    await dialog().getByLabel("Node name").fill(node.name);
    await dialog().getByRole("button", { name: "Register node" }).click();
    const tokenInput = dialog().getByLabel("Node token", { exact: true });
    await tokenInput.waitFor();
    assert.equal(await tokenInput.inputValue(), token);
    await dialog().getByRole("button", { name: "Done" }).click();
    await tokenInput.waitFor({ state: "detached" });
    await page.getByText("Offline", { exact: true }).waitFor();
    assert.ok(await page.getByRole("button", { name: "Bind record" }).isDisabled());

    Object.assign(node, {
      online: true,
      hostname: "test-laptop",
      lastSeen: "2026-10-05T11:20:00Z",
      interfaces: [
        { name: "eth0", mac: "02:00:00:00:00:01", ipv4: ["192.0.2.24"], ipv6: ["2001:db8::24", "2001:db8::25"] },
        { name: "eth1", mac: "", ipv4: [], ipv6: [] },
      ],
    });
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    for (const text of ["Online", "Last report", node.hostname, "eth1", "02:00:00:00:00:01", "192.0.2.24", "2001:db8::25"]) {
      await page.getByText(text, { exact: true }).waitFor();
    }

    await page.getByRole("button", { name: "Bind record", exact: true }).click();
    const choose = async (label, option) => {
      await dialog().getByRole("combobox", { name: label }).click();
      await page.locator(".ant-select-item-option:visible").filter({ hasText: option }).click();
    };
    await choose("DNS account", "Test DNS account");
    await choose("Zone", "example.test");
    await dialog().getByRole("combobox", { name: "DNS record" }).click();
    const option = page.locator(".ant-select-item-option:visible").filter({ hasText: /^test.example.test/ });
    const dropdown = page.locator(".ant-select-dropdown:visible").filter({ has: option });
    await option.waitFor();
    assert.equal(await dropdown.locator(".ant-select-item-option").count(), 1);
    await option.click();
    await choose("Network interface", "eth0");
    await dialog().getByRole("button", { name: "Bind record" }).click();
    await page.getByText("Synced", { exact: true }).waitFor();

    const originalRow = page.locator("tr").filter({ hasText: oldRecord });
    await originalRow.getByRole("button", { name: "Edit binding", exact: true }).click();
    await dialog().getByText("Edit binding", { exact: true }).waitFor();
    const recordName = dialog().getByLabel("Record name", { exact: true });
    assert.equal(await recordName.inputValue(), oldRecord);
    await dialog().getByText(catalog.name, { exact: true }).waitFor();
    await dialog().getByText("AAAA", { exact: true }).waitFor();
    await dialog().locator(".ant-select").getByText(/^eth0/).waitFor();
    const saveInterface = dialog().getByRole("button", { name: "Save binding", exact: true });
    assert.ok(await saveInterface.isDisabled());
    await choose("Network interface", "eth1");
    await saveInterface.and(page.locator("button:enabled")).waitFor();
    await recordName.fill(newRecord);
    const saveBinding = dialog().getByRole("button", { name: "Rename record and save", exact: true });
    await saveBinding.click();
    await dialog().getByText(conflict, { exact: true }).waitFor();
    await originalRow.getByText("Synced", { exact: true }).waitFor();
    assert.equal(await recordName.inputValue(), newRecord);
    await dialog().locator(".ant-select").getByText("eth1", { exact: true }).waitFor();
    await saveBinding.click();
    await page.getByText(pending, { exact: true }).waitFor();
    await page.reload();
    await page.getByText("Offline", { exact: true }).waitFor();
    await originalRow.getByText("Rename awaiting confirmation", { exact: true }).waitFor();
    await originalRow.getByRole("button", { name: "Review pending rename", exact: true }).click();
    await dialog().getByText(newRecord, { exact: true }).waitFor();
    await dialog().getByText("eth1", { exact: true }).waitFor();
    await dialog().getByRole("button", { name: "Confirm rename", exact: true }).click();
    await dialog().waitFor({ state: "hidden" });
    const revisedRow = page.getByRole("row").filter({ hasText: newRecord });
    await revisedRow.getByText("Pending", { exact: true }).waitFor();
    await revisedRow.getByText("AAAA", { exact: true }).waitFor();
    await revisedRow.getByText("eth1", { exact: true }).waitFor();
    await originalRow.waitFor({ state: "detached" });

    const confirm = async (label) => {
      await page.getByRole("button", { name: label, exact: true }).click();
      await page.locator(".ant-popconfirm:visible").getByRole("button", { name: "OK", exact: true }).click();
    };
    await confirm("Rotate token");
    await tokenInput.waitFor();
    assert.equal(await tokenInput.inputValue(), replacement);
    await dialog().getByRole("button", { name: "Done" }).click();
    await tokenInput.waitFor({ state: "detached" });
    const storage = await page.evaluate(() => JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)]));
    assert.ok(!storage.includes(token) && !storage.includes(replacement));

    await confirm("Unbind");
    await page.getByText("No DNS records bound.").waitFor();
    await confirm("Delete node");
    await page.getByText("No DDNS nodes registered.").waitFor();
    assert.deepEqual(operations, [{ name: node.name }, target, { edit }, { edit }, { edit }, "rotate", "unbind", "delete"]);
    await page.evaluate(() => localStorage.setItem("certimate-ui-lang", "zh"));
    await page.reload();
    await page.getByRole("heading", { name: "DDNS 管理" }).waitFor();
    await page.getByRole("button", { name: "注册节点" }).waitFor();
    assert.deepEqual(errors, []);
    console.log("PASS DDNS management: registration, rotation, record renaming, pending confirmation after reload, unbinding and deletion");
  } finally {
    await browser.close();
  }
}).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
