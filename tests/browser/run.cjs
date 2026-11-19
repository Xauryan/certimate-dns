const path = require("node:path");
const { spawn } = require("node:child_process");
const { withConsole } = require("./serve-console.cjs");

const fixtures = [
  "dns-records.cjs",
  "dns-accounts.cjs",
  "dns-interface-keys.cjs",
  "certificate-orders.cjs",
  "certificate-deployments.cjs",
  "dns-proxy.cjs",
  "dns-overview.cjs",
  "site-appearance.cjs",
  "admin-security.cjs",
];

withConsole(async (base) => {
  for (const fixture of fixtures) {
    await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [path.join(__dirname, fixture)], {
        env: { ...process.env, DNS_UI_BASE: base },
        stdio: "inherit",
      });
      child.once("error", reject);
      child.once("exit", (code) => (code === 0 ? resolve() : reject(new Error(fixture + " exited with " + code))));
    });
  }
}).catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
