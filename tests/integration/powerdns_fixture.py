"""A loopback PowerDNS HTTP fixture with independent per-key zone inventories."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
from threading import Thread
from urllib.parse import unquote, urlsplit


class Provider:
    def __init__(self):
        self.calls = 0
        self.patches = 0
        self.keys = [secrets.token_urlsafe(24) for _ in range(2)]
        # Zone identifiers can coincide in independent accounts.
        self.zones = {
            self.keys[0]: {"shared.test.": {}, "private.test.": {}},
            self.keys[1]: {"shared.test.": {}},
        }

    def config(self, account):
        return {"serverUrl": self.url, "apiKey": self.keys[account]}


@contextmanager
def powerdns():
    provider = Provider()
    prefix = "/api/v1/servers/localhost/zones"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, data=None):
            body = b"" if data is None else json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def route(self):
            provider.calls += 1
            zones = provider.zones.get(self.headers.get("X-API-Key"))
            if zones is None:
                return self.reply(403)
            path = unquote(urlsplit(self.path).path)
            if self.command == "GET" and path == prefix:
                return self.reply(200, [{"id": name, "name": name} for name in zones])
            if not path.startswith(prefix + "/"):
                return self.reply(404)
            name = path[len(prefix) + 1:]
            sets = zones.get(name)
            if sets is None:
                return self.reply(404)
            if self.command == "GET":
                return self.reply(200, {"id": name, "name": name, "rrsets": list(sets.values())})

            # Stage the changes so a failed PATCH leaves the zone intact.
            provider.patches += 1
            updated = {k: dict(v, records=list(v["records"])) for k, v in sets.items()}
            try:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                for change in body["rrsets"]:
                    key = (change["name"], change["type"])
                    op = change["changetype"]
                    if op == "DELETE":
                        updated.pop(key, None)
                        continue
                    rrset = updated.setdefault(key, {"name": key[0], "type": key[1], "records": []})
                    rrset["ttl"] = change["ttl"]
                    records = change["records"]
                    if op == "REPLACE":
                        rrset["records"] = records
                    elif op == "EXTEND":
                        rrset["records"].extend(records)
                    elif op == "PRUNE":
                        for record in records:
                            rrset["records"].remove(record)
                    else:
                        return self.reply(422)
                    if not rrset["records"]:
                        del updated[key]
            except (KeyError, TypeError, ValueError):
                return self.reply(422)
            zones[name] = updated
            self.reply(204)

        do_GET = route
        do_PATCH = route

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        provider.url = f"http://127.0.0.1:{server.server_port}"
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield provider
        finally:
            server.shutdown()
            thread.join()
