"""Exercise the DDNS agent, HTTP routes and worker with a loopback provider."""

import argparse
from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
from threading import Thread
import time

from acceptance import ADMIN_EMAIL, CATALOG, MEMBER_EMAIL, check, public, records, serve
from powerdns_fixture import powerdns


NODES = "/api/ddns/nodes"
REPORT = "/api/ddns/report"
HOST = "host.shared.test"
RENAMED_HOST = "renamed.shared.test"
KEEP_HOST = "keep.shared.test"
INTERFACE = "test-ethernet"
SECOND_INTERFACE = "test-failover"
MAC = "02:12:34:56:78:9a"
IPV4 = ("198.18.1.10", "198.18.1.20", "198.18.1.30", "198.18.1.40")
IPV6 = ("2001:2::10", "2001:2::20", "2001:2::30")


@contextmanager
def tls_proxy(directory, backend_port):
    root = directory / "test-ca.pem"
    cert, key = directory / "tls-cert.pem", directory / "tls-key.pem"

    def openssl(*args):
        subprocess.run(["openssl", *args], cwd=directory, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "test-ca.key",
            "-out", root.name, "-days", "1", "-subj", "/CN=Certimate DDNS Test CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key.name,
            "-out", "tls.csr", "-subj", "/CN=localhost")
    extensions = directory / "tls.ext"
    extensions.write_text("basicConstraints=critical,CA:FALSE\n"
                          "keyUsage=critical,digitalSignature,keyEncipherment\n"
                          "extendedKeyUsage=serverAuth\n"
                          "subjectAltName=DNS:localhost,IP:127.0.0.1\n", encoding="ascii")
    openssl("x509", "-req", "-in", "tls.csr", "-CA", root.name, "-CAkey", "test-ca.key",
            "-CAcreateserial", "-out", cert.name, "-days", "1", "-extfile", extensions.name)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            backend = http.client.HTTPConnection("127.0.0.1", backend_port, timeout=8)
            try:
                backend.request("POST", self.path, self.rfile.read(int(self.headers["Content-Length"])),
                                {key: self.headers[key] for key in ("Authorization", "Content-Type")})
                response = backend.getresponse()
                response.read()
                self.send_response(response.status)
                self.send_header("Content-Length", "0")
                self.end_headers()
            finally:
                backend.close()

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"https://127.0.0.1:{server.server_port}", root
        finally:
            server.shutdown()
            thread.join()


def run_agent(exe, directory, api, token):
    with tls_proxy(directory, api.port) as (origin, root):
        config = directory / "ddns-agent.json"
        with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
            json.dump({"server": origin, "token": token, "hostname": "real-agent"}, output)
        command = [str(exe), "--config", str(config), "--once"]
        env = {"PATH": os.defpath}
        result = subprocess.run(command, timeout=15, env=env, capture_output=True)
        check(result.returncode > 0, "the agent did not reject the untrusted test CA")
        subprocess.run(command, check=True, timeout=15, env={**env, "SSL_CERT_FILE": str(root)})


def snapshot(index, second_ipv4=()):
    return {"hostname": "ddns-vm", "interfaces": [
        {"name": INTERFACE, "mac": MAC, "ipv4": [IPV4[index]], "ipv6": [IPV6[index]]},
        {"name": SECOND_INTERFACE, "mac": "", "ipv4": list(second_ipv4), "ipv6": []},
    ]}


def read_fleet(api, provider, *tokens):
    nodes = api.pb("GET", NODES, api.admin)
    public(nodes, provider)
    encoded = json.dumps(nodes)
    check(all(token not in encoded for token in tokens), "the DDNS list disclosed a device token")
    return {node["id"]: node for node in nodes}


def wait_for_sync(api, provider, node_id, expected, *tokens):
    deadline = time.monotonic() + 35
    statuses = {}
    while time.monotonic() < deadline:
        bindings = read_fleet(api, provider, *tokens)[node_id]["bindings"]
        observed = {(binding["recordName"], binding["recordType"]): binding["lastAddress"] for binding in bindings
                    if binding["syncStatus"] == "synced"}
        if observed == expected:
            return bindings
        statuses = {binding["recordName"] + " " + binding["recordType"]:
                    (binding["syncStatus"], binding["lastError"]) for binding in bindings}
        time.sleep(0.25)
    raise AssertionError(f"the DDNS worker did not confirm both provider updates ({statuses})")


def exercise(api, provider, agent, directory):
    admin = api.admin
    password = secrets.token_urlsafe(29)
    api.create("dns_members", {"email": MEMBER_EMAIL, "password": password, "passwordConfirm": password})
    member = api.login("dns_members", MEMBER_EMAIL, password)
    enrolled = api.pb("POST", NODES, admin, {"name": "VM acceptance"}, expected=201)
    node_id, token = enrolled["id"], enrolled["token"]
    node_path = f"{NODES}/{node_id}"
    binding_path = node_path + "/bindings"
    node = read_fleet(api, provider, token)[node_id]
    check(node["enabled"] and not node["online"] and node["lastSeen"] is None and node["interfaces"] == [],
          "an enrolled node without a report was presented as online")

    before = provider.calls
    for credential in (None, member, f"Bearer {token}"):
        for method, path, body in (("GET", NODES, None), ("POST", NODES, {"name": "Restricted"}),
                                   ("POST", binding_path, {}), ("POST", node_path + "/rotate", None),
                                   ("PATCH", node_path, {"enabled": False}), ("DELETE", node_path, None)):
            status, _ = api.request(method, path, credential, body)
            check(status in (401, 403), f"{method} {path} accepted a non-administrator")
    for credential in (None, member, admin, token):
        api.pb("POST", REPORT, credential, snapshot(1), expected=401)
    invalid = snapshot(1)
    invalid["interfaces"][0]["ipv6"] = [IPV4[1]]
    api.pb("POST", REPORT, f"Bearer {token}", invalid, expected=400)
    check(provider.calls == before, "a denied DDNS request reached the provider")

    run_agent(agent, directory, api, token)
    node = read_fleet(api, provider, token)[node_id]
    check(node["hostname"] == "real-agent" and node["online"] and node["lastSeen"],
          "the agent report did not mark its node online")
    api.pb("POST", REPORT, f"Bearer {token}", snapshot(1), expected=204)
    node = read_fleet(api, provider, token)[node_id]
    check(node["hostname"] == "ddns-vm" and node["interfaces"] == snapshot(1)["interfaces"],
          "the reported hostname, MAC address or IPs differ from the administrator projection")

    access = api.create("access", {"name": "DDNS fixture", "provider": "powerdns", "config": provider.config(0)})
    api.api("POST", f"{CATALOG}/accounts/{access}/sync", admin)
    inventory = api.api("GET", f"{CATALOG}/domains", admin)["items"]
    zone, = [item for item in inventory if item["name"] == "shared.test"]
    record_path = records(access, zone["zoneId"])
    seed = ((HOST, "A", IPV4[0], 400), (HOST, "AAAA", IPV6[0], 600),
            (KEEP_HOST, "A", IPV4[1], 800), (HOST, "TXT", "retained answer", 900))
    for name, record_type, address, ttl in seed:
        api.api("POST", record_path, admin, {"name": name, "type": record_type, "content": address, "ttl": ttl})
    original = {(row["name"], row["type"]): row for row in api.api("GET", record_path, admin)["result"]}

    def selection(record_type):
        return {"provider": "powerdns", "accessId": access, "zoneId": zone["zoneId"],
                "recordId": original[HOST, record_type]["id"], "interfaceName": INTERFACE}

    before = provider.calls
    api.api("PATCH", f"{record_path}/{selection('A')['recordId']}", f"Bearer {token}",
            {"content": IPV4[2], "ttl": 400}, expected=(401, 403))
    check(provider.calls == before, "device token reached the provider through a direct DNS route")
    api.pb("POST", binding_path, admin, selection("TXT"), expected=400)
    api.pb("POST", binding_path, admin, {**selection("A"), "interfaceName": "unknown"}, expected=400)
    for record_type in ("A", "AAAA"):
        binding = api.pb("POST", binding_path, admin, selection(record_type), expected=201)
        check((binding["recordName"], binding["recordType"], binding["interfaceName"]) ==
              (HOST, record_type, INTERFACE), "DDNS binding points to a different record or interface")

    def assert_provider(expected):
        rows = api.api("GET", record_path, admin)["result"]
        records_by_owner = {(row["name"], row["type"]): row for row in rows}
        actual = {key: (row["content"], row["ttl"]) for key, row in records_by_owner.items()}
        check(len(rows) == len(expected) and actual == expected, "provider content, TTL or unbound records changed unexpectedly")
        return records_by_owner

    initial = {(HOST, "A"): IPV4[1], (HOST, "AAAA"): IPV6[1]}
    wait_for_sync(api, provider, node_id, initial, token)
    expected = {key: (initial.get(key, row["content"]), row["ttl"]) for key, row in original.items()}
    assert_provider(expected)
    other = api.pb("POST", NODES, admin, {"name": "Second node"}, expected=201)
    other_token = other["token"]
    other_path = f"{NODES}/{other['id']}"
    api.pb("POST", REPORT, f"Bearer {other_token}", snapshot(2), expected=204)
    nodes = read_fleet(api, provider, token, other_token)
    check(nodes[node_id]["interfaces"] == snapshot(1)["interfaces"] and not nodes[other["id"]]["bindings"],
          "a report with the same hostname affected the existing node")
    active_a, = [binding for binding in nodes[node_id]["bindings"] if binding["recordType"] == "A"]
    api.pb("POST", other_path + "/bindings", admin,
           {**selection("A"), "recordId": active_a["recordId"]}, expected=409)

    edit_path = f"{binding_path}/{active_a['id']}"
    target = {"recordName": RENAMED_HOST, "interfaceName": SECOND_INTERFACE,
              "expectedRecordName": HOST, "expectedInterfaceName": INTERFACE}
    for credential in (None, member, f"Bearer {token}"):
        status, _ = api.request("PUT", edit_path, credential, target)
        check(status in (401, 403), "a non-administrator could modify a DDNS binding")
    api.pb("PUT", f"{other_path}/bindings/{active_a['id']}", admin, target, expected=404)
    api.pb("PUT", edit_path, admin, {**target, "recordName": KEEP_HOST}, expected=409)
    persisted_a, = [binding for binding in read_fleet(api, provider, token)[node_id]["bindings"]
                    if binding["id"] == active_a["id"]]
    check((persisted_a["recordId"], persisted_a["recordName"], persisted_a["interfaceName"]) ==
          (active_a["recordId"], HOST, INTERFACE), "a rejected edit changed or removed the original binding")
    assert_provider(expected)
    api.pb("DELETE", other_path, admin, expected=204)

    rotated = api.pb("POST", node_path + "/rotate", admin)
    new_token = rotated["token"]
    check(rotated["id"] == node_id and new_token != token, "rotation did not preserve the node and change its token")
    check(not read_fleet(api, provider, token, new_token)[node_id]["online"], "rotation kept the old report active")
    before = provider.patches
    provider.fail_readback_after_patch = True
    try:
        reason = api.pb("PUT", edit_path, admin, target, expected=409)
        check("could not be confirmed" in reason["message"].lower() and provider.patches == before + 1,
              "the acknowledged DNS write was not reported as pending when readback failed")
        pending, = [binding for binding in read_fleet(api, provider, token, new_token)[node_id]["bindings"]
                    if binding["id"] == active_a["id"]]
        check(pending["recordId"] == active_a["recordId"] and pending["recordName"] == HOST and pending["interfaceName"] == INTERFACE and
              pending.get("pendingRename") == {"recordName": RENAMED_HOST, "interfaceName": SECOND_INTERFACE, "submitted": True},
              "the pending rename and the original binding were not both visible after readback failed")
    finally:
        provider.fail_readback_after_patch = False
        provider.unavailable_zone = None

    edited = api.pb("PUT", edit_path, admin, target)
    check(provider.patches == before + 1 and not edited.get("pendingRename"),
          "confirming the pending rename dispatched a duplicate provider write or left it pending")
    expected[RENAMED_HOST, "A"] = expected.pop((HOST, "A"))
    renamed = assert_provider(expected)[RENAMED_HOST, "A"]
    check((edited["id"], edited["recordId"], edited["recordName"], edited["interfaceName"]) ==
          (active_a["id"], renamed["id"], RENAMED_HOST, SECOND_INTERFACE) and renamed["id"] != active_a["recordId"],
          "renaming did not preserve the binding ID and point it at the new provider identity")
    check(edited["syncStatus"] == "pending" and not edited["lastAddress"],
          "the edited interface kept the previous interface's synchronization state")
    before = provider.patches
    replay = api.pb("PUT", edit_path, admin, target)
    check(replay["id"] == edited["id"] and provider.patches == before, "retrying an applied rename wrote DNS again")
    api.pb("PUT", edit_path, admin, {**target, "recordName": "stale.shared.test"}, expected=409)
    assert_provider(expected)
    api.pb("POST", REPORT, f"Bearer {token}", snapshot(2), expected=401)
    api.pb("POST", REPORT, f"Bearer {new_token}", snapshot(2, second_ipv4=(IPV4[3],)), expected=204)
    rebound = {(RENAMED_HOST, "A"): IPV4[3], (HOST, "AAAA"): IPV6[2]}
    bindings = wait_for_sync(api, provider, node_id, rebound, token, new_token)
    for key, content in rebound.items():
        expected[key] = (content, expected[key][1])
    synced = assert_provider(expected)[RENAMED_HOST, "A"]
    active_edited, = [binding for binding in bindings if binding["id"] == edited["id"]]
    check(active_edited["recordId"] == synced["id"] and active_edited["interfaceName"] == SECOND_INTERFACE,
          "the worker did not persist the new record identity and interface after publishing")
    api.pb("PATCH", node_path, admin, {"enabled": False}, expected=204)
    api.pb("POST", REPORT, f"Bearer {new_token}", snapshot(0), expected=401)
    check(not read_fleet(api, provider, token, new_token)[node_id]["online"], "disabled node was still online")
    api.pb("DELETE", node_path, admin, expected=204)
    api.pb("POST", REPORT, f"Bearer {new_token}", snapshot(0), expected=401)
    check(not read_fleet(api, provider, token, new_token), "deleted DDNS node remained visible")
    assert_provider(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--agent", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="certimate-ddns-acceptance-") as tmp, powerdns() as provider:
        directory = Path(tmp)
        with serve(args.binary.resolve(), directory / "server", secrets.token_urlsafe(29)) as api:
            exercise(api, provider, args.agent.resolve(), directory)
    print("PASS DDNS agent, binding edits, device authorization and PowerDNS A/AAAA synchronization", flush=True)


if __name__ == "__main__":
    main()
