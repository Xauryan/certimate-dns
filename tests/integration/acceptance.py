"""Exercise the candidate Certimate binary against disposable PocketBase databases."""

import argparse
from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlencode

from powerdns_fixture import powerdns


ROOT = Path(__file__).resolve().parents[2]
ADMIN_EMAIL = "dns-admin@example.test"
MEMBER_EMAIL = "dns-member@example.test"
MEMBERS = "/api/dns-member/zones"
CATALOG = "/api/dns-catalog"
# Public Certimate credential IDs for the 22 entries in DNSMgr e0997e98's DnsHelper.
DNS_PROVIDERS = {
    "aliyun", "aliyunesa", "aws", "baiducloud", "bt", "cloudflare", "dnsla", "dnsmgr",
    "dynv6", "goedge", "henet", "huaweicloud", "jdcloud", "namesilo", "powerdns",
    "qingcloud", "spaceship", "technitiumdns", "tencentcloud", "tencenteo", "volcengine", "westcn",
}
DNS_COLLECTIONS = {
    "dnsAccount", "dnsZone", "dns_members", "dns_workspace_zones",
    "dns_workspaces", "dns_zone_grants", "dns_workspace_grants",
}


def check(ok, description):
    if not ok:
        raise AssertionError(description)


def baseline_binary(directory):
    # The digest covers all 19 migration files in the upstream tag, including
    # the two snapshot packages and tracer. A shallow checkout is sufficient.
    files = sorted(p for p in (ROOT / "migrations").rglob("*.go")
                   if p.name <= "1788364800_upgrade_v0.4.33.go"
                   or "snaps" in p.parts or p.name == "tracer.go")
    digest = hashlib.sha256()
    for p in files:
        digest.update(p.relative_to(ROOT).as_posix().encode() + b"\0" + p.read_bytes() + b"\0")
    check(digest.hexdigest() == "c0f375fc3b9b42addaef4d5c334d51dd0cca7e2f5b241b8fb4837c0319fd3799",
          "v0.4.38 migration sources differ from e23f669")
    check("github.com/pocketbase/pocketbase v0.39.10\n" in (ROOT / "go.mod").read_text(),
          "baseline helper requires v0.4.38's PocketBase version; use --baseline-binary for other versions")
    exe = directory / "baseline"
    subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-o", str(exe),
                    "./tests/integration/baseline"], cwd=ROOT, check=True)
    return exe


class Client:
    def __init__(self, port):
        self.port = port
        self.admin = None

    def request(self, method, path, token=None, data=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=8)
        try:
            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = token
            body = None if data is None else json.dumps(data)
            conn.request(method, path, body, headers)
            response = conn.getresponse()
            raw = response.read()
            try:
                return response.status, json.loads(raw) if raw else None
            except ValueError:
                raise AssertionError(f"{method} {path} returned non-JSON (HTTP {response.status})") from None
        finally:
            conn.close()

    def pb(self, method, path, token=None, data=None, expected=200):
        status, value = self.request(method, path, token, data)
        check(status == expected, f"{method} {path} expected HTTP {expected}, got {status}")
        return value

    def api(self, method, path, token=None, data=None, expected=(0,)):
        status, value = self.request(method, path, token, data)
        code = value.get("code") if status == 200 and isinstance(value, dict) else status
        check(code in expected, f"{method} {path} expected code {expected}, got {code} (HTTP {status})")
        return value.get("data") if isinstance(value, dict) else None

    def login(self, collection, email, password):
        path = f"/api/collections/{collection}/auth-with-password"
        return self.pb("POST", path, data={"identity": email, "password": password})["token"]

    def create(self, collection, data):
        return self.pb("POST", f"/api/collections/{collection}/records", self.admin, data)["id"]

    def get(self, collection, record):
        return self.pb("GET", f"/api/collections/{collection}/records/{record}", self.admin)


@contextmanager
def serve(exe, directory, password):
    directory.mkdir(exist_ok=True)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    # Only loopback is required, and no user or CI provider credentials enter the child.
    env = {"HOME": str(directory), "PATH": os.defpath, "TZ": "UTC",
           "CERTIMATE_ADMIN_USERNAME": ADMIN_EMAIL, "CERTIMATE_ADMIN_PASSWORD": password,
           "HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1",
           "NO_PROXY": "localhost,127.0.0.1"}
    api = Client(port)
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen([str(exe), "serve", "--dir", str(directory / "pb_data"),
                                    "--http", f"127.0.0.1:{port}", "--dev=false"],
                                   cwd=directory, env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                check(process.poll() is None, f"{exe.name} exited during startup ({process.returncode})")
                try:
                    if api.pb("GET", "/api/health").get("code") == 200:
                        break
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(0.12)
            else:
                raise AssertionError(f"{exe.name} did not become healthy")
            api.admin = api.login("_superusers", ADMIN_EMAIL, password)
            yield api
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def pb_collections(api):
    return {row["name"]: row for row in
            api.pb("GET", "/api/collections?perPage=500", api.admin)["items"]}


def seed_legacy(api, provider):
    check("dnsZone" not in pb_collections(api), "baseline already has the new DNS schema")
    access = api.create("access", {"name": "Legacy DNS", "provider": "powerdns", "config": provider.config(0)})
    node = {"id": "challenge", "type": "bizApply", "data": {"name": "Obtain",
            "config": {"domains": "shared.test;*.shared.test", "challengeType": "dns-01",
                       "provider": "powerdns", "providerAccessId": access}}}
    graph = {"nodes": [{"id": "start", "type": "start", "data": {"name": "Start"}},
                       node, {"id": "end", "type": "end", "data": {"name": "End"}}]}
    draft = json.loads(json.dumps(graph))
    draft["nodes"][1]["data"]["name"] = "Draft obtain"
    flow = api.create("workflow", {"name": "Legacy workflow", "trigger": "manual", "enabled": False,
                      "hasContent": True, "hasDraft": True, "graphContent": graph, "graphDraft": draft})
    return access, flow, graph, draft


def verify_legacy(api, provider, legacy):
    access, flow, graph, draft = legacy
    check(api.get("access", access)["config"] == provider.config(0), "legacy credential configuration changed")
    row = api.get("workflow", flow)
    check(row["graphContent"] == graph and row["graphDraft"] == draft,
          "legacy workflow graph, node IDs, or providerAccessId changed")


def verify_locked(api, member, access):
    collections = pb_collections(api)
    check(DNS_COLLECTIONS <= collections.keys(), "expected DNS collection missing")
    names = {"access", "workflow"} | {name for name in collections if name.lower().startswith("dns")}
    for name in sorted(names):
        for rule in ("listRule", "viewRule", "createRule", "updateRule", "deleteRule"):
            check(collections[name][rule] is None, f"{name}.{rule} is unlocked")
        api.pb("GET", f"/api/collections/{name}/records", member, expected=403)
    for token in (member, None):
        api.pb("GET", f"/api/collections/access/records/{access}", token, expected=403)
        api.pb("POST", "/api/collections/dns_zone_grants/records", token, {}, expected=403)


def zone_page(api, token, page=1):
    return api.api("GET", MEMBERS + "?" + urlencode({"page": page, "perPage": 1}), token)


def records(access, zone):
    return f"/api/dns/powerdns/{access}/zones/{zone}/records"


def public(value, provider):
    encoded = json.dumps(value)
    check(all(key not in encoded for key in provider.keys) and '"config"' not in encoded,
          "credential configuration appeared in a projected DNS response")


def exercise_rich_edit(api, provider, member, path, prior):
    selected = path + "/" + prior["id"]
    api.api("PATCH", selected, member, {"content": prior["content"], "ttl": 900})
    api.api("POST", path, member,
            {"name": prior["name"], "type": "TXT", "content": "retained answer", "ttl": 900})
    target = "mail.shared.test"
    api.api("POST", path, member,
            {"name": target, "type": "MX", "content": "mx-existing.shared.test", "ttl": 600, "priority": 5})
    observed = api.api("GET", path, member)
    check(observed["edit"] == {"rename": True, "retype": True, "priority": True},
          "record list did not expose PowerDNS replacement capabilities")
    current = {r["id"]: r for r in observed["result"]}
    original = current[prior["id"]]
    check(original["ttl"] == 900 and len(current) == 3, "setup lost a source or destination record")
    desired = {"name": target, "type": "MX", "content": "mx-new.shared.test", "ttl": 600, "priority": 15}
    before = provider.patches
    api.api("PATCH", selected, member, {**desired, "expected": prior}, expected=(409,))
    check(provider.patches == before, "stale record snapshot reached the provider write endpoint")
    confirmed = api.api("PATCH", selected, member, {**desired, "expected": original})
    check(confirmed != prior["id"] and provider.patches == before + 1,
          "record replacement did not return a new identity or sent more than one provider PATCH")
    after = {r["id"]: r for r in api.api("GET", path, api.admin)["result"]}
    changed = after.pop(confirmed, {})
    check((changed.get("name"), changed.get("type"), changed.get("ttl"), changed.get("priority")) ==
          (target, "MX", 600, 15) and
          changed.get("content", "").rstrip(".").split() in (["mx-new.shared.test"], ["15", "mx-new.shared.test"]),
          "record replacement did not serialize the requested MX preference, target and TTL")
    del current[prior["id"]]
    check(after == current, "record replacement changed an existing source or destination answer")
    for record_id in [confirmed, *after]:
        api.api("DELETE", path + "/" + record_id, member)


def exercise_batch(api, provider, member, access, zone):
    record_path = records(access, zone["zoneId"])
    base = record_path.removesuffix("/records") + "/batch"
    changes = [
        {"action": "create", "name": "shared.test", "type": "MX", "content": "mail.shared.test",
         "priority": 10, "ttl": 300},
        {"action": "create", "name": "batch.shared.test", "type": "TXT", "content": "batch proof",
         "ttl": 600},
    ]
    preview = api.api("POST", base + "/preview", member, {"changes": changes})
    plan_id = preview["plan"]["id"]
    check(preview["plan"]["state"] == "preview" and len(preview["rows"]) == 2, "batch preview incomplete")
    check(api.api("GET", record_path, member)["result"] == [], "batch preview mutated the zone")
    apply = f"{base}/plans/{plan_id}/apply"
    confirmation = {"confirm": True, "changes": changes}
    result = api.api("POST", apply, member, confirmation)
    check(result["state"] == "completed" and [row["state"] for row in result["items"]] == ["applied"] * 2,
          "batch per-row results do not confirm both writes")
    before = provider.calls
    api.api("POST", apply, member, confirmation, expected=(409,))
    check(provider.calls == before, "repeating the confirmation reached the provider")

    archive = api.api("GET", base + "/export?format=archive", member)
    public(archive, provider)
    check((archive["schema"], archive["version"], archive["accessId"], archive["zoneId"]) ==
          ("certimate.dns.zone", 1, access, zone["zoneId"]), "archive source identity changed")
    rows = {r["type"]: r for r in archive["records"]}
    check(len(archive["records"]) == 2 and rows["MX"]["priority"] == 10 and
          rows["MX"]["content"].rstrip(".").split() in (["mail.shared.test"], ["10", "mail.shared.test"]) and
          rows["TXT"]["content"] == "batch proof" and rows["TXT"]["ttl"] == 600,
          "batch archive lost a record or changed its value, TTL, or MX priority")

    changes = [{"action": "delete", "id": r["id"]} for r in archive["records"]]
    pending = api.api("POST", base + "/preview", member, {"changes": changes})
    return f"{base}/plans/{pending['plan']['id']}/apply", {"confirm": True, "changes": changes}


def exercise(api, provider, legacy, member_password):
    first, flow = legacy[:2]
    second = api.create("access", {"name": "Another DNS", "provider": "powerdns", "config": provider.config(1)})
    admin = api.admin
    registered = api.api("GET", "/api/dns/providers", admin)
    check(len(set(registered)) == len(registered) and DNS_PROVIDERS <= set(registered),
          "provider registry missing a pinned DNSMgr driver or contains duplicates")
    accounts = api.api("GET", CATALOG + "/accounts", admin)
    public(accounts, provider)
    check({r["id"] for r in accounts if r["enabled"]} == {first, second}, "expected two DNS accounts")
    for access, count in [(first, 2), (second, 1)]:
        synced = api.api("POST", f"{CATALOG}/accounts/{access}/sync", admin)
        check(synced == count, "unexpected zone sync result")
    inventory = api.api("GET", CATALOG + "/domains", admin)
    check(inventory["total"] == 3, "zone identities across accounts were merged")
    public(inventory, provider)
    zones = {(z["accessId"], z["name"]): z for z in inventory["items"]}
    shared = zones[first, "shared.test"]
    private = zones[first, "private.test"]
    other = zones[second, "shared.test"]
    check(shared["id"] != other["id"], "zone identity must include its account")
    detail = api.api("GET", f"{CATALOG}/domains/{shared['id']}", admin)
    check([r["id"] for r in detail["workflows"]] == [flow], "legacy workflow missing in domain detail")
    public(detail, provider)

    member_id = api.create("dns_members", {"email": MEMBER_EMAIL, "password": member_password,
                                           "passwordConfirm": member_password})
    member = api.login("dns_members", MEMBER_EMAIL, member_password)
    verify_locked(api, member, first)
    check(zone_page(api, member) == {"items": [], "total": 0}, "ungranted member can see zones")
    for route in (CATALOG + "/accounts", CATALOG + "/domains/" + other["id"]):
        api.api("GET", route, member, expected=(403,))
    api.api("GET", MEMBERS, expected=(401, 403))

    workspace = api.create("dns_workspaces", {"name": "Temporary workspace"})
    api.create("dns_workspace_zones", {"workspace": workspace, "zone": shared["id"]})
    api.create("dns_workspace_grants", {"workspace": workspace, "member": member_id, "role": "reader"})
    entry = zone_page(api, member)
    check(entry["total"] == 1 and len(entry["items"]) == 1 and entry["items"][0]["id"] == shared["id"]
          and not entry["items"][0]["canWrite"], "reader scope/count is incorrect")
    public(entry, provider)
    check(zone_page(api, member, 2) == {"items": [], "total": 1}, "authorization applied after pagination")

    allowed = records(first, shared["zoneId"])
    check(api.api("GET", allowed, member)["result"] == [], "reader expected empty record list")
    form = {"name": "proof.shared.test", "type": "TXT", "content": "initial", "ttl": 300}
    before = provider.calls
    for token, path, expected in [(member, records(first, private["zoneId"]), (403, 404)),
                                  (member, records(second, other["zoneId"]), (403, 404)),
                                  (None, allowed, (401, 403))]:
        for method, suffix, data in [("GET", "", None), ("POST", "", form),
                                      ("PATCH", "/unused", {"content": "update", "ttl": 300}),
                                      ("DELETE", "/unused", None)]:
            api.api(method, path + suffix, token, data, expected)
        api.api("GET", path.removesuffix("/records") + "/export", token, expected=expected)
    api.api("POST", allowed, member, form, expected=(403,))
    check(provider.calls == before, "authorization rejection reached the provider")

    grant = api.create("dns_zone_grants", {"zone": shared["id"], "member": member_id, "role": "editor"})
    page = zone_page(api, member)
    check(page["total"] == 1 and page["items"][0]["canWrite"], "overlapping grants lost editor role or doubled count")
    api.api("POST", allowed, member, form)
    row, = api.api("GET", allowed, member)["result"]
    check((row["name"], row["content"]) == ("proof.shared.test", "initial"), "editor create did not round-trip")
    api.api("PATCH", allowed + "/" + row["id"], member, {"content": "updated", "ttl": 600})
    row, = api.api("GET", allowed, admin)["result"]
    check((row["content"], row["ttl"]) == ("updated", 600), "editor update did not round-trip")
    exercise_rich_edit(api, provider, member, allowed, row)
    check(api.api("GET", allowed, admin)["result"] == [], "editor delete did not round-trip")
    pending, confirmation = exercise_batch(api, provider, member, first, shared)
    api.pb("DELETE", f"/api/collections/dns_zone_grants/records/{grant}", admin, expected=204)
    check(not zone_page(api, member)["items"][0]["canWrite"], "revocation did not affect an existing session")
    before = provider.calls
    api.api("POST", allowed, member, form, expected=(403,))
    api.api("POST", pending, member, confirmation, expected=(403,))

    api.api("PATCH", f"{CATALOG}/accounts/{first}", admin, {"enabled": False})
    check(zone_page(api, member) == {"items": [], "total": 0}, "disabled account is still visible to member")
    for token in (admin, member):
        api.api("GET", allowed, token, expected=(403, 404, 409))
        api.api("POST", allowed, token, form, expected=(403, 404, 409))
    api.api("POST", f"{CATALOG}/accounts/{first}/sync", admin, expected=(403, 404, 409))
    check(provider.calls == before, "revoked or disabled credential reached the provider")
    check(zone_page(api, admin)["total"] == 1, "disabling one account affected unrelated scope")
    return member_id, allowed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="candidate Certimate executable")
    parser.add_argument("--baseline-binary", type=Path, help="optional original Certimate v0.4.38 executable")
    args = parser.parse_args()
    exe = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="certimate-acceptance-") as tmp, powerdns() as provider:
        directory = Path(tmp)
        baseline = args.baseline_binary.resolve(strict=True) if args.baseline_binary else baseline_binary(directory)
        admin_password = secrets.token_urlsafe(30)
        member_password = secrets.token_urlsafe(30)
        with serve(exe, directory / "fresh", admin_password) as api:
            check(DNS_COLLECTIONS <= pb_collections(api).keys(), "fresh DNS migrations incomplete")
            # Exercise production route registration alongside the SPA's GET catch-all.
            for method in ("GET", "POST", "DELETE"):
                response = api.pb(method, "/mcp", expected=401)
                check(response.get("jsonrpc") == "2.0" and response.get("error", {}).get("code") == -32001,
                      f"{method} /mcp did not reach the interface authentication handler")
            proxy = api.pb("GET", "/api/dns-proxy/settings", api.admin)
            check(proxy.get("enabled") is False, "fresh DNS proxy must be disabled")
        print("PASS fresh schema and administrator login", flush=True)
        db = directory / "upgrade"
        with serve(baseline, db, admin_password) as api:
            legacy = seed_legacy(api, provider)
            verify_legacy(api, provider, legacy)
            admin_token = api.admin
        with serve(exe, db, admin_password) as api:
            api.pb("GET", "/api/collections/workflow/records/" + legacy[1], admin_token)
            verify_legacy(api, provider, legacy)
            print("PASS upgrade from v0.4.38 with existing login, workflow and credential", flush=True)
            member_id, allowed = exercise(api, provider, legacy, member_password)
        print("PASS synchronized catalog, collection locks, scoped DNS CRUD and replacement, batch confirmation and revocation", flush=True)
        with serve(exe, db, admin_password) as api:
            verify_legacy(api, provider, legacy)
            member = api.login("dns_members", MEMBER_EMAIL, member_password)
            check(zone_page(api, member) == {"items": [], "total": 0}, "disabled account reactivated at restart")
            api.api("PATCH", f"{CATALOG}/accounts/{legacy[0]}", api.admin, {"enabled": True})
            check(zone_page(api, member)["total"] == 1, "workspace grant missing after restart")
            api.api("GET", allowed, member)
            api.pb("PATCH", f"/api/collections/dns_members/records/{member_id}", api.admin, {"disabled": True})
            before = provider.calls
            api.api("GET", allowed, member, expected=(401, 403, 404))
            check(provider.calls == before, "disabled member reached the provider")
        print("PASS second open, persisted grants, account re-enable and member disable")


if __name__ == "__main__":
    main()
