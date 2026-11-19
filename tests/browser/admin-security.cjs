const assert = require("node:assert/strict");
const { chromium } = require("playwright-core");
const { withConsole } = require("./serve-console.cjs");

withConsole(async (base) => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
  const page = await browser.newPage({ locale: "en-US" });
  page.setDefaultTimeout(15000);
  await page.addInitScript(() => localStorage.setItem("certimate-ui-lang", "en"));
  await page.route(/^https?:\/\//, (route) => (new URL(route.request().url()).origin === base ? route.fallback() : route.abort()));

  const record = { id: "adminauthfixture", collectionName: "_superusers", email: "admin@example.test" };
  const token = "synthetic." + Buffer.from(JSON.stringify({ type: "auth", exp: Math.floor(Date.now() / 1000) + 300 })).toString("base64url") + ".fixture";
  const password = "synthetic-browser-password";
  const pixel = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+X4lEAAAAASUVORK5CYII=";
  let captcha = true;
  let challenge = 0;
  let signedIn = false;
  let replaced = false;
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const authPath = "/api/dns-identity/admin";
  await page.route("**/api/**", (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === authPath + "/captcha") {
      return route.fulfill({ json: captcha ? { required: true, id: "image-" + ++challenge, image: pixel } : { required: false } });
    }
    if (path === "/api/collections/_superusers/auth-with-password") {
      assert.deepEqual(request.postDataJSON(), { identity: record.email, password, captchaId: "image-" + challenge, captcha: "SAMPLE" });
      if (challenge === 1) return route.fulfill({ status: 400, json: { message: "Invalid or expired image code." } });
      return route.fulfill({ status: 401, json: { totpId: "synthetic-totp-challenge" } });
    }
    if (path === authPath + "/totp/login") {
      assert.deepEqual(request.postDataJSON(), { totpId: "synthetic-totp-challenge", code: "183502" });
      signedIn = true;
      return route.fulfill({ json: { token, record } });
    }
    if (path === authPath + "/security") {
      assert.equal(request.headers().authorization, token);
      return route.fulfill({ json: { captcha, active: true, available: true } });
    }
    if (path === authPath + "/policy") {
      assert.equal(request.method(), "PUT");
      assert.deepEqual(request.postDataJSON(), { password, code: "378514", captcha: false });
      captcha = false;
      return route.fulfill({ status: 204 });
    }
    if (path === authPath + "/totp/generate") {
      assert.deepEqual(request.postDataJSON(), { password, code: "669421" });
      return route.fulfill({ json: { uri: "otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP" } });
    }
    if (path === authPath + "/totp/bind") {
      assert.deepEqual(request.postDataJSON(), { password, code: "861064" });
      replaced = true;
      return route.fulfill({ status: 204 });
    }
    if (path === "/api/appearance") return route.fulfill({ json: { theme: "light" } });
    return route.fulfill({ json: { items: [], totalPages: 0, totalItems: 0, page: 1, perPage: 20 } });
  });
  try {
    await page.goto(base + "/#/login");
    await page.getByPlaceholder("Username/Email").fill(record.email);
    await page.getByPlaceholder("Password", { exact: true }).fill(password);
    const loginButton = page.getByRole("button", { name: "Log-in", exact: true });
    const captchaInput = page.getByLabel("Password sign-in image code");
    await captchaInput.fill("sample");
    await loginButton.click();
    await page.getByText("Invalid or expired image code.", { exact: true }).waitFor();
    await page.waitForFunction(() => document.querySelector("#admin-captcha")?.value === "");
    assert.equal(await loginButton.isDisabled(), true);
    await captchaInput.fill("sample");
    await loginButton.click();
    await page.getByLabel("Authenticator code", { exact: true }).fill("183502");
    assert.equal(await page.evaluate(() => JSON.parse(localStorage.getItem("pocketbase_auth") || "{}").token || ""), "");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.waitForURL((url) => url.hash === "#/");
    assert.equal(signedIn, true);

    await page.goto(base + "/#/settings/account");
    await page.getByRole("heading", { name: "Administrator sign-in security" }).waitFor();
    await page.getByRole("button", { name: "Disable image verification" }).click();
    await page.getByLabel("Current password", { exact: true }).fill(password);
    await page.getByLabel("Authenticator code", { exact: true }).fill("378514");
    await page.getByRole("button", { name: "Disable image verification" }).click();
    await page.getByText("Image verification is disabled for administrator sign-in.").waitFor();
    await page.getByRole("button", { name: "Replace authenticator" }).click();
    await page.getByLabel("Current password", { exact: true }).fill(password);
    await page.getByLabel("Authenticator code", { exact: true }).fill("669421");
    await page.getByRole("button", { name: "Replace authenticator" }).click();
    await page.locator(".ant-qrcode").waitFor();
    await page.getByLabel("Current password", { exact: true }).fill(password);
    await page.getByLabel("Code from the new authenticator").fill("861064");
    await page.getByRole("button", { name: "Confirm enrollment" }).click();
    await page.waitForURL((url) => url.hash === "#/login");
    assert.equal(replaced, true);
    assert.equal(await page.evaluate(() => JSON.parse(localStorage.getItem("pocketbase_auth") || "{}").token || ""), "");
    assert.deepEqual(errors, []);
    console.log("PASS administrator CAPTCHA, authenticator sign-in, settings and replacement");
  } catch (error) {
    console.error("Administrator fixture route", new URL(page.url()).hash, errors);
    throw error;
  } finally {
    await browser.close();
  }
}).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
