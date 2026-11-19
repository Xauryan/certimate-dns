import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { URL } from "node:url";
import { TextDecoder } from "node:util";
import vm from "node:vm";

import { parseArchive } from "./files.archive.ts";
import { parseSheetRows, parseSmartPaste } from "./files.rows.ts";

const lib = await readFile(new URL("./files-vendor/xlsx.full.min.js", import.meta.url), "utf8");
const workerScript = await readFile(new URL("./files.worker.js", import.meta.url), "utf8");
const script = vm.createContext({ ArrayBuffer, DataView, Uint8Array, TextDecoder });
script.self = script;
script.importScripts = () => {
  vm.runInContext(lib, script);
};
script.importScripts();
vm.runInContext(workerScript, script);
const { XLSX } = script;
function job(data) {
  let result;
  script.postMessage = (message) => {
    result = message;
  };
  script.onmessage({ data });
  if (result.error) throw new Error(result.error);
  return result.data;
}
function sample(sheet, bookType) {
  const book = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(book, sheet, "Records");
  XLSX.utils.book_append_sheet(book, XLSX.utils.aoa_to_sheet([["Ignored sheet"]]), "Other");
  return XLSX.write(book, { type: "array", bookType });
}

const zone = "example.test";
const capabilities = {
  types: ["A", "AAAA", "TXT", "MX", "SRV", "CAA", "ANAME", "APP", "NS", "PTR", "URI"],
  minTTL: 60,
  maxTTL: 1000000,
  defaultTTL: 600,
  specialTTLs: [1],
  priorityTypes: ["MX", "URI"],
  line: true,
  weight: true,
  description: true,
};
const grid = [
  ["主机记录", "记录类型", "记录值", "TTL", "线路值", "线路类型"],
  ["@", "TXT", "=literal text", 90, "", "默认"],
  ["www", "A", "10.0.0.1", 600, "line-2", "Custom"],
];

for (const bookType of ["xls", "xlsx"]) {
  test("first worksheet of " + bookType + " preserves literal text, names and line IDs", () => {
    const buffer = sample(XLSX.utils.aoa_to_sheet(grid), bookType);
    const rows = parseSheetRows(job({ operation: "read", buffer, kind: bookType }), { zone, capabilities });
    assert.equal(rows.length, 2);
    assert.equal(rows[0].change.name, zone);
    assert.equal(rows[0].change.content, "=literal text");
    assert.equal(rows[1].change.name, "www." + zone);
    assert.equal(rows[1].change.line, "line-2");
    assert.ok(rows.every((row) => !row.error));
  });
}

test("formula cells, unknown metadata and malformed values get row-specific errors", () => {
  const sheet = XLSX.utils.aoa_to_sheet([...grid, ["test", "A", "10.0.0.5", "abc"]]);
  sheet.C2 = { t: "n", f: "1+1", v: 2 };
  sheet.E3 = { t: "s", v: "" };
  const rows = parseSheetRows(job({ operation: "read", buffer: sample(sheet, "xlsx"), kind: "xlsx" }), { zone });
  assert.deepEqual(
    Array.from(rows, (row) => row.row),
    [2, 3, 4]
  );
  assert.match(rows[0].error, /formula/);
  assert.match(rows[1].error, /routing line/);
  assert.match(rows[2].error, /TTL/);
  const namedLine = parseSheetRows(
    [
      { row: 1, values: grid[0] },
      { row: 2, values: ["www", "A", "10.0.0.8", "600", "", "Local"] },
    ],
    { zone, capabilities, lines: [{ id: "local-id", name: "Local" }] }
  );
  assert.equal(namedLine[0].change.line, "local-id");
  const metadata = parseSheetRows(
    [
      { row: 1, values: ["Name", "Type", "Value", "Remark"] },
      { row: 2, values: ["@", "TXT", "hello", "keep me"] },
    ],
    { zone }
  );
  assert.match(metadata[0].error, /metadata/);
});

test("workbook export writes text cells rather than formulas", () => {
  const bytes = job({ operation: "write", rows: grid });
  const wb = XLSX.read(bytes, { type: "array", sheets: 0 });
  const cell = wb.Sheets[wb.SheetNames[0]].C2;
  assert.equal(cell.v, "=literal text");
  assert.equal(cell.t, "s");
  assert.equal(cell.f, undefined);
});

test("smart paste resolves four input formats, longest matching zone and malformed lines", () => {
  const text = [
    "www 10.0.0.2",
    "app target.example.org child.example.test",
    "fd00::1 x.child.example.test",
    "example.test",
    "",
    "host 999.1.1.1",
    "www 10.0.0.1 outside.test",
  ].join("\n");
  const rows = parseSmartPaste(text, { zone, zones: [zone, "child.example.test"], value: "10.0.0.4", ttl: 900 });
  assert.deepEqual(
    rows.slice(0, 4).map(({ zone: z, change, error }) => [z, change.name, change.type, change.content, error]),
    [
      [zone, "www.example.test", "A", "10.0.0.2", undefined],
      ["child.example.test", "app.child.example.test", "CNAME", "target.example.org", undefined],
      ["child.example.test", "x.child.example.test", "AAAA", "fd00::1", undefined],
      [zone, zone, "A", "10.0.0.4", undefined],
    ]
  );
  assert.equal(rows[4].row, 6);
  assert.match(rows[4].error, /address/);
  assert.match(rows[5].error, /unavailable/);
});

test("wrong signatures, oversized sheets and duplicate headers are rejected", () => {
  assert.throws(() => job({ operation: "read", kind: "xlsx", buffer: Uint8Array.from([1, 2, 3]).buffer }), /Expected an Excel/);
  const sheet = XLSX.utils.aoa_to_sheet([["cell"]]);
  sheet.A20002 = { t: "s", v: "last" };
  sheet["!ref"] = "A1:A20002";
  const buffer = sample(sheet, "xlsx");
  assert.throws(() => job({ operation: "read", kind: "xlsx", buffer }), /20000 records/);
  assert.throws(() => parseSheetRows([{ row: 1, values: ["name", "主机记录"] }], { zone }), /Duplicate/);
});

test("a workbook can span multiple 200-change preview plans", () => {
  const data = Array.from({ length: 250 }, (_, n) => ["www" + n, "A", "10.0.0.1", 600]);
  const buffer = sample(XLSX.utils.aoa_to_sheet([grid[0], ...data]), "xlsx");
  const rows = parseSheetRows(job({ operation: "read", kind: "xlsx", buffer }), { zone });
  assert.equal(rows.length, 250);
  assert.equal(rows[249].change.name, "www249.example.test");
  assert.ok(rows.every((row) => !row.error));
});

test("native types, TTL exceptions, MX presentation and secondary attributes are restored from a worksheet", () => {
  const header = { row: 1, values: ["Name", "Type", "Value", "TTL", "Weight", "Remark", "Status"] };
  const rows = parseSheetRows([header, { row: 2, values: ["@", "MX", "mx.example.test | 21", "1", "0", "sheet note", "暂停"] }], {
    zone,
    capabilities,
    fields: ["status"],
  });
  assert.equal(rows[0].error, undefined);
  assert.deepEqual(rows[0].change, {
    action: "create",
    name: zone,
    type: "MX",
    content: "mx.example.test",
    priority: 21,
    ttl: 1,
    weight: 0,
    description: "sheet note",
    status: "disabled",
  });
  const paste = parseSmartPaste("srv\t10 5 443 gateway.example.test.\texample.test", { zone, capabilities, type: "SRV", ttl: 900000 });
  assert.equal(paste[0].change.content, "10 5 443 gateway.example.test.");
  assert.equal(paste[0].error, undefined);
});

test("versioned archives preserve structured rdata, status, proxy, group mappings and explicit zero metadata", () => {
  const archive = {
    schema: "certimate.dns.zone",
    version: 1,
    provider: "cloudflare",
    zone,
    accessId: "source-account",
    zoneId: "origin-id",
    groups: [{ id: "old-group", name: "Edge" }],
    records: [
      {
        id: "mail",
        type: "URI",
        name: "uri." + zone,
        content: '2 "https://example.test/path"',
        ttl: 1,
        priority: 0,
        description: "archive note",
        group: "old-group",
        status: "enabled",
        line: "0",
        proxied: false,
      },
      { id: "edge", type: "A", name: "edge." + zone, content: "10.0.0.1", ttl: 600, status: "disabled", line: "1", proxied: true },
      { id: "srv", type: "SRV", name: "_www._tcp." + zone, content: "10 5 443 app.example.test.", ttl: 600, priority: 10 },
      { id: "managed", type: "NS", name: zone, content: "ns.example.test.", ttl: 600, readOnly: true },
      { id: "unknown", type: "AAAA", name: "v6." + zone, content: "fd00::1", ttl: 600, newRouting: { on: true } },
    ],
  };
  const options = {
    zone,
    provider: "cloudflare",
    capabilities,
    fields: ["status"],
    accessId: "target-account",
    zoneId: "target-id",
    groups: [{ id: "new-group", name: "Edge" }],
  };
  const rows = parseArchive(JSON.stringify(archive), options);
  assert.equal(rows[0].error, undefined);
  assert.deepEqual(rows[0].change, {
    action: "create",
    name: "uri." + zone,
    type: "URI",
    content: '2 "https://example.test/path"',
    ttl: 1,
    priority: 0,
    description: "archive note",
    line: "0",
    status: "enabled",
    group: "new-group",
  });
  assert.equal(rows[1].error, undefined);
  assert.equal(rows[1].change.status, "disabled");
  assert.equal(rows[1].change.line, "1");
  assert.equal(rows[2].error, undefined);
  assert.equal(rows[2].change.content, archive.records[2].content);
  assert.match(rows[3].error, /Protected/);
  assert.match(rows[4].error, /newRouting/);
  assert.throws(() => parseArchive(JSON.stringify({ ...archive, version: 2 }), options), /version 1/);
  assert.throws(() => parseArchive(JSON.stringify({ ...archive, zone: "other.test" }), options), /must match/);
  const cross = parseArchive(JSON.stringify(archive), { zone, provider: "example", capabilities, groups: [] });
  assert.match(cross[0].error, /group/);
  assert.match(cross[1].error, /proxied/);
});

test("opaque source lines, foreign owners and unknown statuses are flagged before restore", () => {
  const archive = {
    schema: "certimate.dns.zone",
    version: 1,
    provider: "other",
    zone,
    records: [{ name: "foreign.test", type: "A", content: "10.0.0.2", ttl: 300, line: "unique", status: "unrecognized" }],
  };
  const [record] = parseArchive(JSON.stringify(archive), { zone, provider: "aliyun", capabilities });
  assert.match(record.error, /outside/);
  assert.match(record.error, /routing line/);
  assert.match(record.error, /Unknown record status/);
});

test("workbook group IDs stay scoped and SRV apex targets remain part of the pasted value", () => {
  const header = { row: 1, values: ["Name", "Type", "Value", "TTL", "源服务商", "源账号ID", "源域名ID", "分组ID", "分组名称"] };
  const record = { row: 2, values: ["app", "A", "10.0.0.6", "600", "dnsmgr", "original", "zone-1", "source-id", "Web"] };
  const options = { zone, capabilities, provider: "dnsmgr", accessId: "different", zoneId: "zone-2", groups: [{ id: "destination-id", name: "Web" }] };
  const [row] = parseSheetRows([header, record], options);
  assert.equal(row.error, undefined);
  assert.equal(row.change.group, "destination-id");
  assert.match(
    parseSheetRows([header, record], {
      ...options,
      groups: [
        { id: "one", name: "Web" },
        { id: "two", name: "Web" },
      ],
    })[0].error,
    /unique/
  );
  const [srv] = parseSmartPaste("_tcp 0 5 443 example.test", { zone, capabilities, type: "SRV" });
  assert.equal(srv.change.content, "0 5 443 example.test");
  assert.equal(srv.error, undefined);
});
