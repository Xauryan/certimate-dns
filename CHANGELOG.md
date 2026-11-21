# Certimate DNS v0.4.40

- Fix administrator password changes that returned `Invalid request body.` for valid JSON over HTTP. The identity API now handles requests whose final body bytes arrive together with the end-of-stream signal.

# Certimate DNS v0.4.39

- Manage DDNS nodes, view interface addresses and bind existing A and AAAA records from the DNS console.
- Report from Linux x64 and Windows x64 with the one-shot Rust agent. Each node holds its own reporting token. Certimate manages DNS credentials and verifies provider updates.
- Download agent ZIPs alongside the server archives and verify them with `checksums.txt`.

Earlier upstream changes are available in the [Certimate release history](https://github.com/certimate-go/certimate/releases).
