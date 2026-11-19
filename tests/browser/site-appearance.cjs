const assert = require("node:assert/strict");
const { chromium } = require("playwright-core");
const { withConsole } = require("./serve-console.cjs");

async function run(base) {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
  let siteTheme = "light";
  const writes = [];

  async function open(path, { collectionName, existingTheme, colorScheme = "light" } = {}) {
    const page = await browser.newPage({ locale: "en-US", viewport: { width: 1440, height: 900 }, colorScheme });
    page.setDefaultTimeout(15000);
    await page.addInitScript(
      ({ collectionName, existingTheme }) => {
        localStorage.setItem("certimate-ui-lang", "en");
        if (sessionStorage.getItem("appearance-fixture")) return;
        sessionStorage.setItem("appearance-fixture", "ready");
        if (existingTheme) localStorage.setItem("certimate-ui-theme", existingTheme);
        if (collectionName) {
          const record = { id: "appearancefixture", collectionName, email: "viewer@example.test" };
          const token = "synthetic." + btoa(JSON.stringify({ type: "auth", exp: Math.floor(Date.now() / 1000) + 300 })) + ".fixture";
          localStorage.setItem("pocketbase_auth", JSON.stringify({ token, record }));
        }
      },
      { collectionName, existingTheme }
    );
    await page.route(/^https?:\/\//, (route) => (new URL(route.request().url()).origin === base ? route.fallback() : route.abort()));
    await page.route("**/api/**", (route) => {
      const req = route.request();
      const path = new URL(req.url()).pathname;
      if (path === "/api/appearance") {
        if (req.method() === "GET") {
          assert.equal(req.headers().authorization || "", "");
        } else {
          assert.equal(req.method(), "PUT");
          assert.equal(collectionName, "_superusers");
          assert.match(req.headers().authorization, /^synthetic\./);
          const body = req.postDataJSON();
          writes.push(body);
          siteTheme = body.theme;
        }
        return route.fulfill({ json: { theme: siteTheme } });
      }
      if (path === "/api/dns-member/zones") return route.fulfill({ json: { code: 0, data: { items: [], total: 0 } } });
      if (path === "/api/dns-identity/captcha") return route.fulfill({ json: { required: false } });
      if (path.endsWith("/dns_members/auth-methods")) {
        return route.fulfill({ json: { password: { enabled: false }, otp: { enabled: false }, oauth2: { enabled: false, providers: [] } } });
      }
      return route.fulfill({ json: { items: [], totalPages: 0, totalItems: 0, page: 1, perPage: 20 } });
    });
    await page.goto(base + "/#" + path);
    return page;
  }

  async function chooseBrowserTheme(page, option) {
    await page.getByRole("button", { name: /^Browser theme/ }).click();
    await page.getByRole("menuitem", { name: option, exact: true }).click();
  }

  try {
    const guest = await open("/login");
    await guest.locator("html.light").waitFor();
    assert.equal(await guest.evaluate(() => localStorage.getItem("certimate-ui-theme")), null);
    await guest.close();

    const member = await open("/dns-member", { collectionName: "dns_members", existingTheme: "dark" });
    await member.locator("html.dark").waitFor();
    await chooseBrowserTheme(member, "Use site default");
    await member.locator("html.light").waitFor();
    await chooseBrowserTheme(member, "Dark");
    await member.locator("html.dark").waitFor();
    await member.reload();
    await member.getByRole("button", { name: /Browser theme.*Dark/ }).waitFor();
    await member.locator("html.dark").waitFor();
    assert.equal(await member.getByRole("combobox", { name: "Default site theme" }).count(), 0);
    await member.close();

    const admin = await open("/settings/appearance", { collectionName: "_superusers" });
    await admin.locator("html.light").waitFor();
    await admin.getByRole("combobox", { name: "Default site theme" }).click();
    await admin.locator(".ant-select-dropdown:visible").getByText("Auto", { exact: true }).click();
    await admin.getByText("Saved successfully").waitFor();
    assert.deepEqual(writes, [{ theme: "system" }]);
    await admin.emulateMedia({ colorScheme: "dark" });
    await admin.locator("html.dark").waitFor();
    await admin.close();

    const memberLogin = await open("/dns-member", { colorScheme: "dark" });
    await memberLogin.locator("html.dark").waitFor();
    await chooseBrowserTheme(memberLogin, "Light");
    await memberLogin.locator("html.light").waitFor();
    await memberLogin.close();
  } finally {
    await browser.close();
  }
}

withConsole(run).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
