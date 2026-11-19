import { type BatchFileOptions, type BatchFileRow, type ImportRecord, projectRecord } from "./files.rows.ts";

import { groupIndex, restoreScope } from "./files.scope.ts";

type Dictionary = Record<string, unknown>;
const object = (value: unknown): value is Dictionary => !!value && typeof value === "object" && !Array.isArray(value);
const normal = (value: string) => value.trim().replace(/\.$/, "").toLowerCase();
const recordFields = new Set([
  "id",
  "updatedAt",
  "name",
  "type",
  "content",
  "ttl",
  "line",
  "status",
  "readOnly",
  "description",
  "weight",
  "priority",
  "proxied",
  "group",
]);

function hasValue(v: unknown) {
  if (v == null || v === "") return false;
  if (Array.isArray(v)) return v.length > 0;
  if (object(v)) return Object.keys(v).length > 0;
  return true;
}

function groupList(value: unknown): { id: string; name: string }[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((g) => !object(g) || typeof g.id !== "string" || typeof g.name !== "string"))
    throw new Error("Invalid archive group list.");
  return value.map(({ id, name }) => ({ id, name }));
}

export function parseArchive(text: string, options: BatchFileOptions): BatchFileRow[] {
  if (text.length > 64 * 1024 * 1024) throw new Error("Archive exceeds 64 MiB.");
  let archive: unknown;
  try {
    archive = JSON.parse(text);
  } catch {
    throw new Error("Invalid JSON archive.");
  }
  if (!object(archive) || archive.schema !== "certimate.dns.zone" || archive.version !== 1)
    throw new Error("Expected a Certimate DNS zone archive, version 1.");
  const zoneName = object(archive.zone) ? archive.zone.name : archive.zone;
  if (typeof zoneName !== "string" || typeof archive.provider !== "string" || !archive.provider || !Array.isArray(archive.records))
    throw new Error("Invalid archive header.");
  const zone = normal(zoneName);
  if (!zone || zone !== normal(options.zone)) throw new Error("The archive zone must match the selected zone.");
  if (!archive.records.length || archive.records.length > 20000) throw new Error("An archive must contain 1 to 20000 records.");
  const sourceGroups = groupIndex(groupList(archive.groups));
  const targetGroups = groupIndex(options.groups);
  const sourceProvider = archive.provider;
  const source = {
    provider: sourceProvider,
    accessId: typeof archive.accessId === "string" ? archive.accessId : undefined,
    zoneId: typeof archive.zoneId === "string" ? archive.zoneId : undefined,
  };
  return archive.records.map((value: unknown, index: number) => {
    const item = object(value) ? value : {};
    const errors: string[] = [];
    const unknown = Object.keys(item).filter((k) => !recordFields.has(k) && hasValue(item[k]));
    if (unknown.length) errors.push("Unsupported record metadata: " + unknown.join(", ") + ".");
    const readText = (k: string, required = false) => {
      if (typeof item[k] === "string") return item[k];
      if (required || item[k] != null) errors.push("Expected text for " + k + ".");
      return "";
    };
    const number = (k: string) => {
      if (item[k] == null) return undefined;
      if (typeof item[k] === "number" && Number.isSafeInteger(item[k])) return item[k];
      errors.push("Expected an integer for " + k + ".");
      return undefined;
    };
    const bool = (k: string) => {
      if (item[k] == null) return undefined;
      if (typeof item[k] === "boolean") return item[k];
      errors.push("Expected a boolean for " + k + ".");
      return undefined;
    };
    const owner = readText("name", true);
    // The archive format stores absolute owner names. Never reinterpret an
    // unrecognized owner as a relative host under the destination zone.
    const fqdn = normal(owner);
    if (fqdn !== zone && !fqdn.endsWith("." + zone)) errors.push("Archived owner is outside the selected zone.");
    const record: ImportRecord = {
      name: owner,
      type: readText("type", true),
      content: readText("content", true),
      ttl: number("ttl") ?? NaN,
      priority: number("priority"),
      weight: number("weight"),
      description: readText("description"),
      status: readText("status"),
      line: readText("line"),
      proxied: bool("proxied"),
      readOnly: bool("readOnly"),
    };
    const group = readText("group");
    errors.push(...restoreScope(record, source, options, targetGroups, group, sourceGroups.ids.get(group)?.name));
    return projectRecord(index + 1, zone, record, options, errors.join(" ") || undefined);
  });
}
