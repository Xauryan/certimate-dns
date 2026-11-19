const assert = require("node:assert/strict");

module.exports = async function testGoogleEABSettings(page, base) {
  const path = "/api/collections/settings/records";
  const id = "settingfixture";
  const provider = "googletrustservices";
  let config = { eabKid: "fixture-legacy-kid", eabHmacKey: "fixture-legacy-mac" };
  let writes = 0;
  const settings = () => ({ id, name: "sslProvider", content: { provider, configs: { [provider]: config } } });
  await page.route((url) => url.pathname === path || url.pathname === path + "/" + id, async (route) => {
    const req = route.request();
    if (req.method() === "GET") return route.fulfill({ json: { items: [settings()], totalItems: 1, totalPages: 1 } });
    assert.equal(req.method(), "PATCH");
    config = req.postDataJSON().content.configs[provider];
    writes++;
    return route.fulfill({ json: settings() });
  });

  await page.goto(new URL("#/settings/ssl-provider", base).href);
  const eab = page.getByRole("combobox", { name: "EAB credentials" });
  const save = page.getByRole("button", { name: "Save changes", exact: true }).first();
  await page.getByRole("textbox", { name: "ACME EAB KID" }).and(page.locator('input[value="fixture-legacy-kid"]')).waitFor();
  await eab.click();
  await page.getByText("Create EAB key in a Google Cloud project", { exact: true }).click();
  await page.getByRole("combobox", { name: "ACME environment" }).click();
  await page.getByText("Staging", { exact: true }).click();
  const project = page.getByRole("textbox", { name: "GCP project ID" });
  const key = page.getByRole("textbox", { name: "Google service account key JSON" });
  await project.fill("https://fixture.invalid");
  await key.fill('{"type":"external_account"}');
  await save.click();
  await page.getByText("Enter a valid Google Cloud project ID.").waitFor();
  await page.getByText("Enter a Google service account key JSON file.").waitFor();
  assert.equal(writes, 0);

  const syntheticKey = '{"type":"service_account","client_email":"fixture@example.test","private_key":"synthetic-browser-fixture"}';
  await project.fill("fixture-project");
  await key.fill(syntheticKey);
  await Promise.all([page.waitForResponse((r) => new URL(r.url()).pathname === path + "/" + id), save.click()]);
  assert.equal(writes, 1);
  assert.deepEqual(config, { mode: "staging", eabMode: "auto", projectId: "fixture-project", serviceAccountKey: syntheticKey });
};
