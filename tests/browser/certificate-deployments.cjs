const assert = require("node:assert/strict");
const { chromium } = require("playwright-core");
const { withConsole } = require("./serve-console.cjs");

const api = "/api/dnscert/deployments";
const order = { id: "order-one", domain: "www.example.test", state: "issued" };
const next = { id: "order-two", domain: "renewed.example.test", state: "issued" };
const target = {
  accessId: "access-one",
  accessName: "Fixture account",
  provider: "ssh",
  workflowId: "workflow-one",
  workflowName: "Published workflow",
  nodeId: "node-one",
  nodeName: "Fixture node",
};
const now = Math.floor(Date.now() / 1000);
const paused = {
  id: "new-task",
  orderId: order.id,
  domain: order.domain,
  orderState: order.state,
  ...target,
  remark: "",
  active: false,
  status: 0,
  version: 1,
  processId: "",
  started: 0,
  finished: 0,
  created: now,
  automatic: false,
  followRenewal: false,
  policyCurrent: false,
};

function initialize(collectionName) {
  const record = { id: "fixture-user", collectionName };
  const token = "eyJhbGciOiJIUzI1NiJ9." + btoa(JSON.stringify({ type: "auth", exp: Math.floor(Date.now() / 1000) + 600 })) + ".fixture";
  localStorage.setItem("pocketbase_auth", JSON.stringify({ token, record, model: record }));
  localStorage.setItem("certimate-ui-lang", "en");
}

withConsole(async (address) => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
  try {
    const page = await browser.newPage({ locale: "en-US" });
    page.setDefaultTimeout(9000);
    await page.addInitScript(initialize, "_superusers");
    const failures = [];
    const reads = [];
    const changes = [];
    const attempt = {
      id: "first-attempt",
      certificateId: "fixture-cert-id",
      orderId: order.id,
      domain: order.domain,
      accessId: target.accessId,
      workflowId: target.workflowId,
      nodeId: target.nodeId,
      provider: target.provider,
      trigger: "schedule",
      started: now - 60,
      finished: now - 59,
      outcome: "needs_reconciliation",
      privateKey: "SYNTHETIC-FIXTURE-KEY",
    };
    const tasks = [
      { ...paused, id: "failed", remark: "Partial update", active: true, status: -1, version: 4, processId: attempt.id, started: attempt.started, finished: attempt.finished },
      ...Array.from({ length: 20 }, (_, index) => ({
        ...paused,
        id: "filler-" + index,
        orderId: "filler-order-" + index,
        domain: "fixture-" + index + ".example.test",
      })),
    ];
    const expectedMethods = [];
    let conflict = false;
    page.on("pageerror", (err) => failures.push(err.message));
    await page.route(/^https?:\/\//, (route) => (new URL(route.request().url()).origin === address ? route.fallback() : route.abort()));
    await page.route("**/api/**", async (route) => {
      const req = route.request();
      const url = new URL(req.url());
      const { pathname, searchParams } = url;
      const params = Object.fromEntries(searchParams);
      const method = req.method();
      if (pathname === "/api/appearance") return route.fulfill({ json: { theme: "system" } });
      if (pathname.startsWith("/api/collections/")) return route.fulfill({ json: { items: [], totalItems: 0, totalPages: 0 } });
      if (pathname === "/api/dnscert/accounts") return route.fulfill({ json: { items: [{ id: "issuer", name: "CA fixture", provider: "aliyun" }] } });
      if (pathname === "/api/dnscert/orders") return route.fulfill({ json: { items: [{ ...order, provider: "aliyun", accessId: "issuer", version: 1 }], total: 1 } });
      if (!pathname.startsWith(api)) return route.fulfill({ json: { code: 0, data: {} } });
      const [, id, action] = pathname.slice(api.length).split("/");
      if (method === "GET") {
        reads.push({ id, action, params });
        if (id === "orders") {
          return route.fulfill({ json: { items: [order, next].filter((item) => (!params.id || item.id === params.id) && (!params.q || item.domain.includes(params.q))) } });
        }
        if (id === "targets") {
          const valid = params.nodeId === target.nodeId || !params.nodeId;
          return route.fulfill({ json: { items: valid && (!params.q || target.workflowName.toLowerCase().includes(params.q)) ? [target] : [] } });
        }
        if (action === "logs") return route.fulfill({ json: { items: id === "failed" ? [attempt] : [], total: id === "failed" ? 1 : 0 } });
        if (id) {
          const task = tasks.find((item) => item.id === id);
          return route.fulfill({ json: { ...task, result: task.status === -1 ? "Provider did not confirm completion" : "" } });
        }
        const matches = tasks.filter((task) => {
          for (const key of ["status", "orderId", "accessId", "provider"]) {
            if (params[key] && String(task[key]) !== params[key]) return false;
          }
          return (
            (!params.domain || task.domain.includes(params.domain)) &&
            (!params.remark || task.remark.includes(params.remark)) &&
            (!params.q || [task.domain, task.remark, task.workflowName].join(" ").includes(params.q))
          );
        });
        const start = (Number(params.page) - 1) * 20;
        return route.fulfill({ json: { items: matches.slice(start, start + 20), total: matches.length } });
      }

      const body = req.postDataJSON();
      const entry = { method, path: pathname.slice(api.length), body };
      changes.push(entry);
      assert.deepEqual(entry, expectedMethods.shift());
      assert.equal(body.confirmed, true);
      const task = tasks.find((item) => item.id === id);
      const apply = (action, task, pickedOrder) => {
        switch (action) {
          case "enable":
            task.active = true;
            break;
          case "pause":
            task.active = false;
            break;
          case "rebind":
            Object.assign(task, { orderId: pickedOrder.id, domain: pickedOrder.domain, orderState: pickedOrder.state });
            // fall through to clear the result and turn off automation
          case "reset":
            Object.assign(task, { automatic: false, followRenewal: false, policyCurrent: false, status: 0, started: 0, finished: 0, processId: "" });
            break;
          case "delete":
            tasks.splice(tasks.indexOf(task), 1);
            break;
        }
        task.version += 1;
      };
      if (!id) {
        tasks.unshift({ ...paused, remark: body.remark, automatic: body.automatic, followRenewal: body.followRenewal, policyCurrent: body.automatic });
      } else if (id === "batch") {
        for (const snapshot of body.tasks) {
          const task = tasks.find((item) => item.id === snapshot.id);
          assert.equal(task.version, snapshot.version);
          apply(body.action, task, [order, next].find((order) => order.id === body.orderId));
        }
      } else {
        assert.equal(task.version, body.version);
        if (conflict) {
          conflict = false;
          ++task.version;
          return route.fulfill({ status: 409, json: { message: "SYNTHETIC internal detail" } });
        }
        if (method === "PATCH") {
          const selected = [order, next].find((item) => item.id === body.orderId);
          if (body.rebind) apply("rebind", task, selected);
          else task.version += 1;
          Object.assign(task, { remark: body.remark, automatic: body.automatic, followRenewal: body.followRenewal, policyCurrent: body.automatic });
        } else if (action === "process") {
          Object.assign(task, { started: now, finished: now, status: 1, processId: "manual-attempt", version: task.version + 1 });
        } else {
          apply(method === "DELETE" ? "delete" : action === "active" ? (body.active ? "enable" : "pause") : action, task);
        }
      }
      return route.fulfill({ json: { id: id || "new-task" } });
    });

    const dialog = () => page.getByRole("dialog");
    const row = (domain) => page.getByRole("row", { name: new RegExp(domain.replaceAll(".", "\\.")) });
    const expect = (method, path, body) => expectedMethods.push({ method, path, body: { confirmed: true, ...body } });
    const button = (scope, name) => scope.getByRole("button", { name, exact: true });
    const clickAction = async (scope, name) => {
      await button(scope, "Task actions").click();
      await page.getByRole("menuitem", { name, exact: true }).click();
    };
    const confirm = async (name) => {
      await button(dialog(), name).click();
      await dialog().waitFor({ state: "hidden" });
    };
    const choose = async (name, search, option) => {
      const select = dialog().getByRole("combobox", { name, exact: true });
      await select.click();
      if (search) await select.fill(search);
      await page.getByText(option, { exact: true }).click();
    };
    const batch = async (name, domain, count = 1) => {
      await row(domain).getByRole("checkbox").check();
      await button(page, "Batch actions (" + count + ")").click();
      await page.getByRole("menuitem", { name, exact: true }).click();
    };

    await page.goto(address + "/#/dns-cert/deployments?status=-1");
    await page.getByRole("heading", { name: "Certificate deployments" }).waitFor();
    assert.equal(await page.getByText("Failed", { exact: true }).count(), 1);
    const failedRow = row(order.domain);
    await button(failedRow, order.domain).click();
    await dialog().getByText("first-attempt", { exact: true }).last().waitFor();
    await dialog().getByRole("cell", { name: "Schedule", exact: true }).waitFor();
    await dialog().getByText("Certificate ID · fixture-cert-id", { exact: true }).waitFor();
    assert.equal(await dialog().getByText("SYNTHETIC-FIXTURE-KEY").count(), 0);
    await button(dialog(), "Close").click();
    await dialog().waitFor({ state: "hidden" });
    assert.equal(await button(failedRow, "Deploy now").isDisabled(), true);
    await clickAction(failedRow, "Reset");
    assert.equal(await button(dialog(), "Reset").isDisabled(), true);
    await dialog().getByRole("checkbox").check();
    expect("POST", "/failed/reset", { version: 4, reconciled: true });
    await confirm("Reset");
    await page.getByText("No deployment tasks match these filters", { exact: true }).waitFor();
    assert.ok(reads.some((read) => read.params.status === "-1"));

    await button(page, "Clear filters").click();
    await page.locator(".ant-pagination-item-2").click();
    await row("fixture-19.example.test").waitFor();
    assert.ok(reads.some((read) => read.params.page === "2"));
    await page.getByRole("link", { name: "Certificate orders", exact: true }).click();
    const orderLink = row(order.domain).getByRole("link", { name: "Deployment tasks" });
    assert.equal(await orderLink.getAttribute("href"), "#/dns-cert/deployments?orderId=" + order.id);
    await orderLink.click();
    await button(page, "New task").click();
    await dialog().getByText(order.domain + " · " + order.id + " · Issued", { exact: true }).waitFor();
    await choose("Published deployment target", "published", [target.workflowName, target.nodeName, target.accessName, target.provider].join(" · "));
    assert.ok(reads.some((read) => read.id === "targets" && read.params.q === "published"));
    await dialog().getByRole("textbox", { name: "Remark" }).fill("New deployment");
    await dialog().getByRole("checkbox", { name: "Deploy automatically after the certificate is ready" }).check();
    await dialog().getByRole("checkbox", { name: "Also deploy successfully renewed certificates" }).check();
    await button(dialog(), "Review task").click();
    await dialog().getByText("New tasks start paused. Enable the task when it is ready.").waitFor();
    assert.equal(changes.length, 1);
    const fields = { orderId: order.id, accessId: target.accessId, workflowId: target.workflowId, nodeId: target.nodeId, remark: "New deployment" };
    expect("POST", "", { ...fields, automatic: true, followRenewal: true });
    await confirm("Confirm and save");
    const newTask = page.getByRole("row", { name: /New deployment/ });
    await newTask.getByText("Paused", { exact: true }).waitFor();
    await newTask.getByText("Follows renewal", { exact: true }).waitFor();
    assert.equal(await button(newTask, "Deploy now").isDisabled(), true);
    await clickAction(newTask, "Enable");
    expect("POST", "/new-task/active", { version: 1, active: true });
    await confirm("Enable");
    const firstDeploy = button(newTask, "Deploy now");
    await firstDeploy.click();
    assert.equal(changes.length, 3);
    expect("POST", "/new-task/process", { version: 2 });
    await confirm("Deploy now");
    await button(newTask, "Deploy again").click();
    expect("POST", "/new-task/process", { version: 3, runAgain: true });
    await confirm("Deploy again");

    await clickAction(newTask, "Pause");
    conflict = true;
    expect("POST", "/new-task/active", { version: 4, active: false });
    await confirm("Pause");
    await page.getByText(/Review the latest task state and destination/).waitFor();
    assert.equal(await page.getByText("SYNTHETIC internal detail").count(), 0);
    await clickAction(newTask, "Pause");
    expect("POST", "/new-task/active", { version: 5, active: false });
    await confirm("Pause");

    await clickAction(newTask, "Edit");
    await dialog().getByText([target.workflowName, target.nodeName, target.accessName, target.provider].join(" · "), { exact: true }).waitFor();
    assert.ok(reads.some((read) => read.id === "targets" && read.params.nodeId === target.nodeId && read.params.accessId === target.accessId));
    await choose("Certificate order", "renewed", next.domain + " · " + next.id + " · Issued");
    await dialog().getByRole("checkbox", { name: "Deploy automatically after the certificate is ready" }).uncheck();
    await button(dialog(), "Review task").click();
    await dialog().getByText("Confirm the order change", { exact: true }).waitFor();
    expect("PATCH", "/new-task", { ...fields, orderId: next.id, automatic: false, followRenewal: false, rebind: true, version: 6 });
    await confirm("Confirm and save");
    await newTask.waitFor({ state: "hidden" });

    await button(page, "Clear filters").click();
    await batch("Rebind order", next.domain);
    await choose("New certificate order", "www", order.domain + " · " + order.id + " · Issued");
    expect("POST", "/batch", { action: "rebind", orderId: order.id, tasks: [{ id: "new-task", version: 7 }] });
    await confirm("Rebind order");
    await newTask.getByText(order.id, { exact: true }).waitFor();

    await newTask.getByRole("checkbox").check();
    await row("fixture-0.example.test").getByRole("checkbox").check();
    await button(page, "Batch actions (2)").click();
    await page.getByRole("menuitem", { name: "Enable", exact: true }).click();
    expect("POST", "/batch", { action: "enable", tasks: [{ id: "new-task", version: 8 }, { id: "filler-0", version: 1 }] });
    await confirm("Enable");
    await newTask.getByText("Enabled", { exact: true }).waitFor();
    await newTask.getByRole("checkbox").check();
    await button(page, "Batch actions (1)").click();
    await page.getByRole("menuitem", { name: "Pause", exact: true }).click();
    expect("POST", "/batch", { action: "pause", tasks: [{ id: "new-task", version: 9 }] });
    await confirm("Pause");
    await newTask.getByText("Paused", { exact: true }).waitFor();
    await newTask.getByRole("checkbox").check();
    await button(page, "Batch actions (1)").click();
    await page.getByRole("menuitem", { name: "Reset", exact: true }).click();
    expect("POST", "/batch", { action: "reset", tasks: [{ id: "new-task", version: 10 }] });
    await confirm("Reset");

    await batch("Delete", "fixture-0.example.test");
    expect("POST", "/batch", { action: "delete", tasks: [{ id: "filler-0", version: 2 }] });
    await confirm("Delete");
    await row("fixture-0.example.test").waitFor({ state: "hidden" });
    await clickAction(newTask, "Delete");
    expect("DELETE", "/new-task", { version: 11 });
    await confirm("Delete");
    await newTask.waitFor({ state: "hidden" });

    await button(page, "More filters").click();
    await page.getByRole("textbox", { name: "Domain", exact: true }).fill("fixture-3.");
    await page.getByRole("textbox", { name: "Provider identifier" }).fill(target.provider);
    await button(page, "Apply filters").click();
    await row("fixture-3.example.test").waitFor();
    await row("fixture-4.example.test").waitFor({ state: "hidden" });
    assert.ok(reads.some((read) => read.params.domain === "fixture-3." && read.params.provider === "ssh"));

    const member = await browser.newPage();
    await member.addInitScript(initialize, "dns_members");
    let reachedDeployment = false;
    await member.route(/^https?:\/\//, (route) => (new URL(route.request().url()).origin === address ? route.fallback() : route.abort()));
    await member.route("**/api/**", async (route) => {
      if (new URL(route.request().url()).pathname.startsWith(api)) reachedDeployment = true;
      return route.fulfill({ status: 403, json: { message: "Fixture permission check" } });
    });
    await member.goto(address + "/#/dns-cert/deployments");
    await member.waitForURL("**/#/dns-member");
    assert.equal(reachedDeployment, false);
    assert.deepEqual(expectedMethods, []);
    assert.deepEqual(failures, []);
    console.log("PASS certificate deployment navigation, paging, filters, published target, confirmations, stale versions, batch actions, attempts and member boundary");
  } finally {
    await browser.close();
  }
}).catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
