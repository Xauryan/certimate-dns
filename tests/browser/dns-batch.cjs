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
      zoneId: "zone" + i,
      name,
      provider,
      accessId,
      status: "active",
      canWrite: i < 2,
    }));
    const records = zones.map((z) => ({
      id: "record",
      name: "www." + z.name,
      type: "A",
      updatedAt: "2025-01-01T00:00:00Z",
      ttl: 300,
      content: "127.0.0.1",
      proxied: false,
    }));
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
      const i = Math.max(
        0,
        zones.findIndex((z) => p.includes("/zones/" + z.zoneId + "/"))
      );
      if (p === "/api/dns-member/zones") data = { items: zones, total: zones.length };
      else if (p.startsWith("/api/dns/capabilities/")) data = capabilities;
      else if (p.endsWith("/advanced/features")) data = { details: false };
      else if (p.endsWith("/features"))
        data = {
          capabilities,
          fields: ["status", "remark", "group"],
          groups: true,
          logs: false,
        };
      else if (p.endsWith("/groups")) data = archive.groups;
      else if (p.endsWith("/records") || p.endsWith("/search"))
        data = {
          result: [records[i]],
          result_info: { total_count: 1, page: 1 },
        };
      else if (p.endsWith("/export") && u.searchParams.get("format") === "archive") data = archive;
      else if (p.endsWith("/preview")) {
        const { changes } = req.postDataJSON(),
          id = "plan" + (previews.length + 1);
        previews.push({ zone: zones[i].zoneId, changes });
        const plan = {
          id,
          actor: "member",
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
          })),
        };
      } else if (p.endsWith("/apply")) {
        const id = p.split("/").at(-2),
          { changes, confirm } = req.postDataJSON();
        assert.equal(confirm, true);
        assert.deepEqual(previews[Number(id.slice(4)) - 1], {
          zone: zones[i].zoneId,
          changes,
        });
        writes.push(id);
        data = plans.get(id);
        data.state = "completed";
        data.items.forEach((it) => {
          it.state = "applied";
        });
      } else if (p.endsWith("/history")) data = { items: Array.from(plans.values()), total: plans.size };
      else
        return route.fulfill({
          json: { code: 404, msg: "Unknown fixture route", data: null },
        });
      await route.fulfill({ json: { code: 0, data, msg: "ok" } });
    });
    await page.goto(address + "/#/dns-member");
    await page.getByRole("button", { name: "alpha.test", exact: true }).click();
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
    await drawer.getByRole("spinbutton", { name: "New TTL" }).fill("120");
    await drawer.getByRole("button", { name: "Preview selected changes" }).click();
    await drawer.getByText("Awaiting confirmation", { exact: false }).first().waitFor();
    assert.deepEqual(writes, []);
    assert.equal(previews.length, 2);
    await drawer.getByRole("button", { name: "Apply changes" }).first().click();
    await page.getByRole("button", { name: "Confirm changes" }).click();
    await drawer.getByRole("cell", { name: "Applied", exact: true }).waitFor();
    assert.deepEqual(writes, ["plan1"]);
    assert.equal(await drawer.getByRole("button", { name: "Apply changes" }).count(), 1);
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
    await drawer
      .getByLabel("Excel workbook")
      .setInputFiles({
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
    assert.deepEqual(writes, ["plan1"]);
    await drawer.getByRole("tab", { name: "Add and import" }).click();
    await drawer.getByRole("radio", { name: "Smart paste", exact: true }).check();
    await drawer.getByRole("textbox", { name: "Records to parse" }).fill(Array.from({ length: 201 }, (_, i) => "rec" + i + ".alpha.test 127.0.0.1").join("\n"));
    await drawer.getByRole("button", { name: "Parse records" }).click();
    await drawer.getByRole("button", { name: "Preview new records" }).click();
    await drawer.getByText("alpha.test · 2 / 2", { exact: true }).waitFor();
    assert.deepEqual(
      previews.slice(-2).map((p) => p.changes.length),
      [200, 1]
    );
    assert.deepEqual(writes, ["plan1"]);
    await page.reload();
    await page.getByRole("button", { name: "readonly.test", exact: true }).click();
    await page.getByRole("button", { name: "Batch records", exact: true }).click();
    await drawer.getByRole("cell", { name: "www.readonly.test", exact: true }).waitFor();
    assert.equal(await drawer.getByRole("button", { name: "Preview selected changes" }).count(), 0);
    assert.equal(await drawer.getByRole("tab", { name: "Add and import" }).count(), 0);
    assert.deepEqual(errors, []);
    console.log("PASS member batch records: two-zone previews, isolated confirmation, JSON archive metadata, disabled creation warning, reader controls");
  } finally {
    await page.close();
  }
}

module.exports = { testDNSBatch };
