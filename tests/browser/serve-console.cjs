const http = require("node:http");
const fs = require("node:fs/promises");
const path = require("node:path");

// Serve the bundled console on a temporary loopback port for browser fixtures.
async function withConsole(run) {
  if (process.env.DNS_UI_BASE) {
    const base = new URL(process.env.DNS_UI_BASE);
    if (!["localhost", "127.0.0.1", "[::1]"].includes(base.hostname)) throw new Error("DNS_UI_BASE must be a loopback URL");
    return run(base.origin);
  }
  const root = path.resolve(__dirname, "../../ui/dist");
  const server = http.createServer(async (req, res) => {
    const p = new URL(req.url, "http://localhost").pathname;
    const types = { ".js": "text/javascript", ".css": "text/css", ".html": "text/html", ".svg": "image/svg+xml", ".txt": "text/plain; charset=utf-8" };
    const name = path.join(root, p === "/" ? "index.html" : p);
    if (!name.startsWith(root + path.sep)) {
      res.writeHead(404).end();
      return;
    }
    try {
      const data = await fs.readFile(name);
      res.writeHead(200, { "Content-Type": types[path.extname(name)] || "application/octet-stream" });
      res.end(data);
    } catch {
      res.writeHead(404).end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    return await run("http://127.0.0.1:" + server.address().port);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}
module.exports = { withConsole };
