#!/usr/bin/python3 -I
"""Privileged FNOS helper. Accept only certificate and key PEM on stdin."""

import base64
import contextlib
import fcntl
import ipaddress
import json
import os
import pathlib
import re
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time


CATALOG = "/usr/trim/etc/network_cert_all.conf"
LOCK = "/run/certimate-fnos-cert.lock"
MAX_FILE = 4 << 20


MAX_INPUT = 512 << 10
KEY_TYPES = {"PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"}
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def pem_blocks(text, allowed, limit):
    # The TLS library can ignore arbitrary text around PEM blocks. Reject
    # anything outside the allowed PEM structure before installing the input.
    if not isinstance(text, str) or not text.isascii():
        raise ValueError("invalid PEM")
    lines = iter(text.replace("\r\n", "\n").strip("\n").split("\n"))
    count = 0
    for line in lines:
        if line == "":
            continue
        if not line.startswith("-----BEGIN ") or not line.endswith("-----"):
            raise ValueError("invalid PEM header")
        kind = line[len("-----BEGIN "):-5]
        if kind not in allowed or count >= limit:
            raise ValueError("unexpected PEM block")
        body = []
        for line in lines:
            if line == "-----END " + kind + "-----":
                break
            body.append(line)
        else:
            raise ValueError("missing PEM footer")
        if not base64.b64decode("".join(body), validate=True):
            raise ValueError("invalid PEM content")
        count += 1
    if not count:
        raise ValueError("empty PEM")


def canonical_name(name):
    try:
        return str(ipaddress.ip_address(name))
    except ValueError:
        pass
    name = name.lower().rstrip(".")
    base = name[2:] if name.startswith("*.") else name
    if len(name) > 253 or not all(DNS_LABEL.fullmatch(label) for label in base.split(".")):
        raise ValueError("invalid DNS name")
    return name


def verified_update(stream):
    def unique_fields(pairs):
        fields = dict(pairs)
        if len(fields) != len(pairs):
            raise ValueError("duplicate fields")
        return fields

    data = stream.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise ValueError("oversized input")
    message = json.loads(data, object_pairs_hook=unique_fields)
    if not isinstance(message, dict) or set(message) != {"certificate", "key"}:
        raise ValueError("unexpected input fields")
    pem_blocks(message["certificate"], {"CERTIFICATE"}, 16)
    pem_blocks(message["key"], KEY_TYPES, 1)
    # CPython/OpenSSL validates the certificate chain file format and checks
    # the private/public key pair. Anonymous Linux files leave no PEM on disk.
    with contextlib.ExitStack() as stack:
        paths = {}
        for key in ("certificate", "key"):
            fd = os.memfd_create("certimate-fnos-" + key)
            file = stack.enter_context(os.fdopen(fd, "wb"))
            file.write(message[key].encode("ascii"))
            file.flush()
            paths[key] = "/proc/self/fd/" + str(fd)
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
            paths["certificate"], paths["key"], password=lambda: b""
        )
        # CPython's OpenSSL certificate decoder returns structured SAN and
        # issuer fields; displayed name strings may contain escaped separators.
        leaf = ssl._ssl._test_decode_cert(paths["certificate"])
    names = {canonical_name(value) for kind, value in leaf.get("subjectAltName", ())
             if kind in ("DNS", "IP Address")}
    before = ssl.cert_time_to_seconds(leaf["notBefore"])
    after = ssl.cert_time_to_seconds(leaf["notAfter"])
    issuer = next((value for part in leaf["issuer"] for kind, value in part
                   if kind == "commonName"), "")
    if not names or not before <= time.time() < after or len(issuer) > 512 or any(
        ord(char) < 32 or ord(char) == 127 for char in issuer
    ):
        raise ValueError("invalid certificate metadata or validity")
    return {**message, "names": names, "issuer": issuer,
            "notBefore": before * 1000, "notAfter": after * 1000}


def covered(name, names):
    if name in names:
        return True
    _, dot, parent = name.partition(".")
    return bool(dot) and "*." + parent in names


def targets(catalog, names):
    if isinstance(catalog, dict):
        catalog = catalog.values()
    seen = set()
    pairs = []
    for row in catalog:
        sans = {canonical_name(name) for name in (row.get("san") or [])}
        if not names.intersection(sans):
            continue
        if not all(covered(name, names) for name in sans):
            raise SystemExit(12)
        pair = (pathlib.Path(row["certificate"]), pathlib.Path(row["privateKey"]))
        if pair in pairs:
            continue
        if pair[0] == pair[1] or seen.intersection(pair):
            raise ValueError("certificate path conflict")
        seen.update(pair)
        pairs.append(pair)
    if not pairs:
        raise SystemExit(11)
    return pairs


def stage(path, data, info, mode):
    fd, name = tempfile.mkstemp(prefix=".certimate-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fchown(file.fileno(), info.st_uid, info.st_gid)
            os.fchmod(file.fileno(), mode)
            os.fsync(file.fileno())
        return pathlib.Path(name)
    except BaseException:
        os.unlink(name)
        raise


def check_parents(path):
    if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
        raise ValueError("untrusted catalog path")
    for parent in path.parents:
        directory = parent.lstat()
        if directory.st_uid != 0 or directory.st_mode & 0o022:
            raise ValueError("untrusted catalog directory")


def prepare(path, is_key, pem, cleanup):
    # Root's catalog selects existing PEM files. Refuse links, special files,
    # untrusted directories and paths pointing at unrelated host resources.
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("invalid catalog path")
    check_parents(path)
    with open(
        path, "rb", opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW | os.O_NONBLOCK)
    ) as file:
        info = os.fstat(file.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > MAX_FILE):
            raise ValueError("invalid file")
        old = file.read(MAX_FILE + 1)
    mark = b" PRIVATE KEY-----" if is_key else b"-----BEGIN CERTIFICATE-----"
    if len(old) > MAX_FILE or mark not in old.splitlines()[0]:
        raise ValueError("unexpected PEM type")
    mode = info.st_mode & (0o640 if is_key else 0o644)
    pending = stage(path, pem.encode(), info, mode)
    cleanup.callback(pending.unlink, missing_ok=True)
    backup = stage(path, old, info, mode)
    cleanup.callback(backup.unlink, missing_ok=True)
    return path, pending, backup


def update_database(pairs, update):
    # psql :'var' escapes values as SQL literals on the server connection.
    command = [
        "/usr/bin/sudo", "-n", "-u", "postgres", "--", "/usr/bin/psql", "-X", "-q",
        "-d", "trim_connect", "-v", "ON_ERROR_STOP=1",
        "-v", "issuer=" + update["issuer"],
        "-v", "valid_from=" + str(int(update["notBefore"])),
        "-v", "valid_to=" + str(int(update["notAfter"])),
        "-v", "updated=" + str(time.time_ns() // 1000000),
    ]
    sql = ["BEGIN;"]
    for i, (_, key) in enumerate(pairs):
        var = "key" + str(i)
        command.extend(["-v", var + "=" + str(key)])
        # A zero or ambiguous match aborts the whole transaction.
        sql.append(
            "WITH changed AS (UPDATE cert SET valid_to=:'valid_to', "
            "valid_from=:'valid_from', issued_by=:'issuer', updated_time=:'updated' "
            "WHERE private_key=:'" + var + "' RETURNING 1) "
            "SELECT 1 / CASE WHEN count(*)=1 THEN 1 ELSE 0 END FROM changed;"
        )
    sql.append("COMMIT;")
    subprocess.run(command, cwd="/", check=True, timeout=30,
                   input="\n".join(sql).encode(), stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)


def install(update):
    try:
        path = pathlib.Path(CATALOG)
        check_parents(path)
        with open(path, "rb", opener=lambda p, flags: os.open(
            p, flags | os.O_NOFOLLOW | os.O_NONBLOCK
        )) as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise ValueError("untrusted certificate catalog")
            raw = file.read(MAX_FILE + 1)
        if len(raw) > MAX_FILE:
            raise ValueError("oversized inventory")
        pairs = targets(json.loads(raw), {x.lower().rstrip(".") for x in update["names"]})
    except (KeyError, ValueError, TypeError, AttributeError, OSError):
        raise SystemExit(10)

    with contextlib.ExitStack() as cleanup:
        files = []
        try:
            for cert, key in pairs:
                files.append(prepare(cert, False, update["certificate"], cleanup))
                files.append(prepare(key, True, update["key"], cleanup))
        except (OSError, ValueError, IndexError):
            raise SystemExit(13)

        replaced = []
        try:
            for path, pending, backup in files:
                os.replace(pending, path)
                replaced.append((path, backup))
            update_database(pairs, update)
        except (OSError, ValueError, subprocess.SubprocessError):
            for path, backup in reversed(replaced):
                os.replace(backup, path)
            raise SystemExit(14)

    try:
        subprocess.run(["/usr/bin/systemctl", "restart", "webdav.service", "smbftpd.service",
                        "trim_nginx.service"], check=True, timeout=60,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        raise SystemExit(15)


def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        raise SystemExit(16)
    os.environ.clear()
    os.environ.update(PATH="/usr/sbin:/usr/bin:/sbin:/bin", HOME="/root", LC_ALL="C")
    os.chdir("/")
    os.umask(0o077)
    # Read before acquiring the system lock. Slow or abandoned writers cannot
    # hold it indefinitely. Once writes begin, finish the bounded transaction
    # and restart even if the caller disconnects.
    signal.alarm(15)
    try:
        update = verified_update(sys.stdin.buffer)
    except (ValueError, TypeError, KeyError, OSError, RecursionError, OverflowError):
        raise SystemExit(16)
    finally:
        signal.alarm(0)
    locked_install(update)


def locked_install(update):
    lock_path = pathlib.Path(LOCK)
    try:
        check_parents(lock_path)
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    except (OSError, ValueError):
        raise SystemExit(17)
    with os.fdopen(fd, "r+b") as lock:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise SystemExit(17)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SystemExit(17)
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGHUP, signal.SIGINT, signal.SIGTERM})
        try:
            install(update)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, blocked)


if __name__ == "__main__":
    main()
