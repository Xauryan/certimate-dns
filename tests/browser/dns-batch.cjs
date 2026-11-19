const assert = require("node:assert/strict");
const fs = require("node:fs/promises");

async function testDNSBatch(browser, address) {
  const page = await browser.newPage({ locale: "en-US" });
  page.setDefaultTimeout(10000);
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  try {
    await page.addInitScript(() => {
      const record = {
        id: "batch-member",
        collectionName: "dns_members",
        email: "member@example.test",
      };
      const token =
        "synthetic." +
        btoa(
          JSON.stringify({
            type: "auth",
            exp: Math.floor(Date.now() / 1000) + 3600,
          })
        ) +
        ".fixture";
      localStorage.setItem("pocketbase_auth", JSON.stringify({ token, record, model: record }));
    });
    const provider = "aliyun",
      accessId = "grant";
    const zones = ["alpha.test", "bravo.test", "readonly.test"].map((name, i) => ({
      id: "local" + i,
      zoneId: i < 2 ? "shared-zone" : "zone" + i,
      name,
      provider: i === 1 ? "powerdns" : provider,
      accessId: i === 1 ? "second" : accessId,
      status: "active",
      canWrite: i < 2,
    }));
    zones.push({ ...zones[1], id: "duplicate", zoneId: "alpha-copy", name: "alpha.test" });
    const records = zones.map((z) => ({
      id: "record",
      name: "www." + z.name,
      type: "A",
      updatedAt: "2025-01-01T00:00:00Z",
      ttl: 300,
      content: "127.0.0.1",
      proxied: false,
    }));
    const paths = zones.map((z) => "/api/dns/" + z.provider + "/" + z.accessId + "/zones/" + z.zoneId);
    const capabilities = {
      types: ["A", "MX"],
      minTTL: 1,
      maxTTL: 604800,
      defaultTTL: 600,
      priorityTypes: ["MX"],
      line: true,
    };
    const plans = new Map(),
      previews = [],
      writes = [];
    const archive = {
      schema: "certimate.dns.zone",
      version: 1,
      provider,
      accessId,
      zoneId: zones[0].zoneId,
      zone: zones[0].name,
      groups: [{ id: "g1", name: "Mail" }],
      records: [
        {
          id: "source",
          name: "mail.alpha.test",
          type: "MX",
          content: "smtp.alpha.test",
          ttl: 600,
          priority: 0,
          description: "mail route",
          status: "disabled",
          group: "g1",
          proxied: false,
        },
        {
          id: "managed",
          name: "alpha.test",
          type: "SOA",
          content: "ns.alpha.test. hostmaster.alpha.test. 1 2 3 4 5",
          ttl: 300,
          readOnly: true,
          proxied: false,
        },
      ],
    };
    await page.route(address + "/api/**", async (route) => {
      const req = route.request(),
        u = new URL(req.url()),
        p = u.pathname;
      let data;
      const i = paths.findIndex((path) => p.startsWith(path + "/"));
      if (p.includes("/zones/") && i < 0) throw new Error("Request crossed account and native zone identifiers: " + p);
      if (p === "/api/dns-member/zones") data = { items: zones, total: zones.length };
      else if (p.startsWith("/api/dns/capabilities/")) data = capabilities;
      else if (p.endsWith("/advanced/features")) data = { details: false };
      else if (p.endsWith("/features"))
        data = {
          capabilities: i === 1 ? { ...capabilities, types: ["A"], minTTL: 120, line: false, priorityTypes: [] } : capabilities,
          fields: i === 1 ? [] : ["status", "remark", "group"],
          edit: { rename: i !== 1, retype: i !== 1, priority: i !== 1 },
          groups: i !== 1,
          logs: false,
        };
      else if (p.endsWith("/groups")) {
        assert.notEqual(i, 1, "second provider has no groups");
        data = archive.groups;
      } else if (p.endsWith("/records") || p.endsWith("/search"))
        data = {
          result: [records[i]],
          result_info: { total_count: 1, page: 1 },
        };
      else if (p.endsWith("/export") && u.searchParams.get("format") === "archive") data = archive;
      else if (p.endsWith("/preview")) {
        const { changes } = req.postDataJSON(),
          id = "plan" + (previews.length + 1);
        previews.push({ path: paths[i], changes });
        const plan = {
          id,
          actor: "member-" + zones[i].accessId,
          created: 1000,
          state: "preview",
          items: changes.map((c) => ({
            action: c.action,
            id: c.id,
            state: "ready",
          })),
        };
        plans.set(id, plan);
        data = {
          plan,
          rows: changes.map((c) => ({
            change: c,
            ...(c.id ? { before: records[i] } : {}),
            ...(c.action === "replace"
              ? {
                  after: {
                    name: c.name ?? records[i].name,
                    type: c.type ?? records[i].type,
                    content: c.content ?? records[i].content,
                    ttl: c.ttl ?? records[i].ttl,
                    priority: c.priority,
                  },
                }
              : {}),
          })),
        };
      } else if (p.endsWith("/apply")) {
        const id = p.split("/").at(-2),
          { changes, confirm } = req.postDataJSON();
        assert.equal(confirm, true);
        assert.deepEqual(previews[Number(id.slice(4)) - 1], {
          path: paths[i],
          changes,
        });
        writes.push(id);
        data = plans.get(id);
        data.state = "completed";
        data.items.forEach((it) => {
          it.state = "applied";
        });
      } else if (p.endsWith("/history")) {
        const items = Array.from(plans.values()).filter((plan) => previews[Number(plan.id.slice(4)) - 1].path === paths[i]);
        data = { items, total: items.length };
      } else
        return route.fulfill({
          json: { code: 404, msg: "Unknown fixture route", data: null },
        });
      await route.fulfill({ json: { code: 0, data, msg: "ok" } });
    });
    await page.goto(address + "/#/dns-member");
    await page.getByRole("button", { name: "alpha.test", exact: true }).first().click();
    await page.getByRole("button", { name: "Batch records", exact: true }).click();
    const drawer = page.getByRole("dialog");
    await drawer.getByRole("button", { name: "Find more zones" }).click();
    await drawer.getByRole("combobox", { name: "Target zones" }).click();
    await page.locator(".ant-select-item-option").filter({ hasText: "bravo.test" }).click();
    await page.keyboard.press("Escape");
    for (const name of ["alpha", "bravo"])
      await drawer
        .getByRole("checkbox", {
          name: new RegExp("Select record www." + name),
        })
        .check();
    const sorted = page.waitForRequest((r) => new URL(r.url()).searchParams.get("sort") === "updatedAt");
    await drawer.getByRole("columnheader", { name: "Updated" }).first().click();
    await sorted;
    await drawer.getByRole("combobox", { name: "Bulk action" }).click();
    assert.equal(await page.locator(".ant-select-dropdown:visible").getByText("Change status", { exact: true }).count(), 0);
    assert.equal(await page.locator(".ant-select-dropdown:visible").getByText("Edit name, type or priority", { exact: true }).count(), 0);
    await page.keyboard.press("Escape");
    await drawer.getByRole("spinbutton", { name: "New TTL" }).fill("30");
    assert.equal(await drawer.getByRole("button", { name: "Preview selected changes" }).isDisabled(), true);
    await drawer.getByRole("spinbutton", { name: "New TTL" }).fill("120");
    await drawer.getByRole("button", { name: "Preview selected changes" }).click();
    await drawer.getByText("Awaiting confirmation", { exact: false }).first().waitFor();
    assert.deepEqual(writes, []);
    assert.deepEqual(
      previews.map((p) => p.path),
      paths.slice(0, 2)
    );
    await drawer.getByRole("button", { name: "Apply changes" }).first().click();
    await page.getByRole("button", { name: "Confirm changes" }).click();
    await drawer.getByRole("cell", { name: "Applied", exact: true }).waitFor();
    assert.deepEqual(writes, ["plan1"]);
    assert.equal(await drawer.getByRole("button", { name: "Apply changes" }).count(), 1);
    await drawer.getByRole("button", { name: "Apply changes" }).click();
    await page.getByRole("button", { name: "Confirm changes" }).click();
    await drawer.getByRole("cell", { name: "Applied", exact: true }).nth(1).waitFor();
    assert.deepEqual(writes, ["plan1", "plan2"]);
    await drawer.getByRole("tab", { name: "Export", exact: true }).click();
    const workbookDownload = page.waitForEvent("download");
    await drawer.getByRole("button", { name: "Export XLSX" }).click();
    const workbook = await workbookDownload;
    const download = page.waitForEvent("download");
    await drawer.getByRole("button", { name: "Export JSON" }).click();
    const file = await download;
    assert.equal(file.suggestedFilename(), "alpha.test.json");
    await drawer.getByRole("tab", { name: "Add and import" }).click();
    await drawer.getByRole("radio", { name: "Excel", exact: true }).check();
    await drawer.getByLabel("Excel workbook").setInputFiles({
      name: workbook.suggestedFilename(),
      mimeType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      buffer: await fs.readFile(await workbook.path()),
    });
    await drawer.getByRole("button", { name: "Parse records" }).click();
    await drawer.getByRole("cell", { name: "Valid", exact: true }).waitFor();
    await drawer.getByRole("radio", { name: "JSON archive", exact: true }).check();
    await drawer.getByLabel("JSON archive file").setInputFiles(await file.path());
    await drawer.getByRole("button", { name: "Parse records" }).click();
    await drawer.getByRole("cell", { name: "Valid", exact: true }).waitFor();
    assert.equal(await drawer.getByRole("button", { name: "Preview new records" }).isDisabled(), true);
    await drawer.getByRole("checkbox", { name: /Skip invalid rows/ }).check();
    await drawer.getByRole("button", { name: "Preview new records" }).click();
    await drawer.getByText(/record may resolve between those operations/).waitFor();
    const imported = previews.at(-1).changes[0];
    assert.equal(previews.at(-1).changes.length, 1);
    assert.equal(imported.group, "g1");
    assert.equal(imported.priority, 0);
    assert.equal(imported.description, "mail route");
    assert.equal(imported.status, "disabled");
    assert.deepEqual(writes, ["plan1", "plan2"]);
    await drawer.getByRole("tab", { name: "Add and import" }).click();
    await drawer.getByRole("radio", { name: "Smart paste", exact: true }).check();
    await drawer.getByRole("textbox", { name: "Records to parse" }).fill(Array.from({ length: 201 }, (_, i) => "rec" + i + ".alpha.test 127.0.0.1").join("\n"));
    await drawer.getByRole("button", { name: "Parse records" }).click();
    await drawer.getByRole("button", { name: "Preview new records" }).click();
    await drawer.getByText("alpha.test · aliyun · grant · 2 / 2", { exact: true }).waitFor();
    assert.deepEqual(
      previews.slice(-2).map((p) => p.changes.length),
      [200, 1]
    );
    assert.deepEqual(writes, ["plan1", "plan2"]);
    await drawer.getByRole("tab", { name: "History", exact: true }).click();
    const history = drawer.getByRole("tabpanel", { name: "History" });
    await history.getByRole("cell", { name: "member-grant", exact: true }).first().waitFor();
    await history.getByRole("combobox", { name: "View zone" }).click();
    await page.locator(".ant-select-item-option:visible:not(.ant-select-item-option-selected)").filter({ hasText: "bravo.test · powerdns · second" }).click();
    await history.getByRole("cell", { name: "member-second", exact: true }).waitFor();
    assert.equal(await history.getByRole("cell", { name: "member-grant", exact: true }).count(), 0);
    await drawer.getByRole("combobox", { name: "Target zones" }).click();
    await page.locator(".ant-select-item-option").filter({ hasText: "alpha.test · powerdns · second" }).click();
    await page.keyboard.press("Escape");
    await drawer.getByRole("tab", { name: "Add and import" }).click();
    await drawer.getByText("Select an account and zone to resolve duplicate zone names.").waitFor();
    await drawer.getByRole("combobox", { name: "Target for files and relative names" }).click();
    await page.locator(".ant-select-item-option:visible:not(.ant-select-item-option-selected)").filter({ hasText: "alpha.test · powerdns · second" }).click();
    await drawer.getByRole("textbox", { name: "Records to parse" }).fill("mail.alpha.test 127.0.0.1\nnew.bravo.test 127.0.0.2");
    await drawer.getByRole("button", { name: "Parse records" }).click();
    await drawer.getByRole("button", { name: "Preview new records" }).click();
    await drawer.getByText("Awaiting confirmation", { exact: false }).first().waitFor();
    assert.deepEqual(
      previews.slice(-2).map((p) => p.path),
      [paths[1], paths[3]]
    );
    assert.deepEqual(writes, ["plan1", "plan2"]);
    await page.reload();
    await page.getByRole("button", { name: "alpha.test", exact: true }).first().click();
    await page.getByRole("button", { name: "Batch records", exact: true }).click();
    await drawer.getByRole("button", { name: "Find more zones" }).click();
    await drawer.getByRole("combobox", { name: "Target zones" }).click();
    await page.locator(".ant-select-item-option:visible").filter({ hasText: "alpha.test · powerdns · second" }).click();
    await page.keyboard.press("Escape");
    const selected = drawer.getByRole("checkbox", { name: /Select record www\.alpha\.test/ });
    await selected.first().check();
    await selected.nth(1).check();
    await drawer.getByRole("combobox", { name: "Bulk action" }).click();
    await page.locator(".ant-select-item-option:visible").filter({ hasText: "Edit name, type or priority" }).click();
    const newName = drawer.getByRole("textbox", { name: "New record name" });
    const previewSelected = drawer.getByRole("button", { name: "Preview selected changes" });
    await newName.fill("outside.test.");
    assert.equal(await previewSelected.isDisabled(), true);
    await newName.fill("renamed");
    await drawer.getByRole("combobox", { name: "New record type" }).click();
    await page.locator(".ant-select-item-option:visible").getByText("MX", { exact: true }).click();
    await drawer.getByRole("spinbutton", { name: "New priority" }).fill("0");
    await drawer.getByRole("textbox", { name: "New record value" }).fill("mail.example.test.");
    await previewSelected.click();
    await drawer.getByRole("cell", { name: /renamed\.alpha\.test · MX · mail\.example\.test\. · TTL 300 · Priority 0/ }).nth(1).waitFor();
    const expectedChange = { action: "replace", id: "record", name: "renamed.alpha.test", type: "MX", priority: 0, content: "mail.example.test." };
    assert.deepEqual(previews.slice(-2), [paths[0], paths[3]].map((path) => ({ path, changes: [expectedChange] })));
    assert.deepEqual(writes, ["plan1", "plan2"]);
    await drawer.getByRole("button", { name: "Apply changes" }).last().click();
    await page.getByRole("button", { name: "Confirm changes" }).click();
    await drawer.getByRole("cell", { name: "Applied", exact: true }).waitFor();
    assert.deepEqual(writes, ["plan1", "plan2", "plan" + previews.length]);
    await page.reload();
    await page.getByRole("button", { name: "readonly.test", exact: true }).click();
    await page.getByRole("button", { name: "Batch records", exact: true }).click();
    await drawer.getByRole("cell", { name: "www.readonly.test", exact: true }).waitFor();
    assert.equal(await drawer.getByRole("button", { name: "Preview selected changes" }).count(), 0);
    assert.equal(await drawer.getByRole("tab", { name: "Add and import" }).count(), 0);
    assert.deepEqual(errors, []);
    console.log(
      "PASS member batch records: account and provider isolation with colliding zone and record IDs, explicit duplicate-domain selection, rename/retype/priority previews, XLSX/JSON and partial import, isolated confirms, reader controls"
    );
  } finally {
    await page.close();
  }
}

module.exports = { testDNSBatch };
