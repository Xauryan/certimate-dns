import { groupIndex, proxyLines, restoreScope } from "./files.scope.ts";

export interface BatchFileCapabilities {
  types: string[];
  minTTL: number;
  maxTTL: number;
  defaultTTL?: number;
  specialTTLs?: number[];
  priorityTypes?: string[];
  weight?: boolean;
  description?: boolean;
  line?: boolean;
}

export interface BatchFileOptions {
  provider?: string;
  capabilities?: BatchFileCapabilities;
  fields?: string[];
  priority?: number;
  weight?: number;
  description?: string;
  status?: "enabled" | "disabled";
  accessId?: string;
  zoneId?: string;
  groups?: { id: string; name: string }[];
  zone: string;
  zones?: string[];
  ttl?: number;
  type?: string;
  value?: string;
  line?: string;
  lines?: { id: string; name: string }[];
}

export interface BatchFileRow {
  row: number;
  zone: string;
  change: {
    action: "create";
    name: string;
    type: string;
    content: string;
    ttl: number;
    line?: string;
    priority?: number;
    weight?: number;
    description?: string;
    status?: "enabled" | "disabled";
    group?: string;
  };
  error?: string;
}

export interface SheetRow {
  row: number;
  values: string[];
  error?: string;
}

const canonical = (name: string) => name.trim().replace(/\.$/, "").toLowerCase();
const inZone = (name: string, zone: string) => !!zone && (name === zone || name.endsWith("." + zone));
const isDefaultLine = (line: string) => ["", "default", "默认", "默认线路", "全网默认"].includes(line.toLowerCase());

function ipv4(value: string) {
  const labels = value.split(".");
  return labels.length === 4 && labels.every((label) => /^(0|[1-9]\d{0,2})$/.test(label) && Number(label) <= 255);
}

function ipv6(value: string) {
  if (!/^[0-9a-f:.]+$/i.test(value) || !value.includes(":")) return false;
  try {
    return new URL("http://[" + value + "]").hostname.startsWith("[");
  } catch {
    return false;
  }
}

function domainName(value: string) {
  const host = canonical(value);
  return host.length > 0 && host.length <= 253 && host.split(".").every((label) => /^[a-z0-9_*-]{1,63}$/i.test(label));
}

// The optional fallback is for plain input without a loaded provider. Callers
// supply the capabilities returned by the batch endpoint for provider-native types.
const basic: BatchFileCapabilities = { types: ["A", "AAAA", "CNAME", "NS", "PTR", "TXT"], minTTL: 1, maxTTL: 604800, defaultTTL: 600 };

export interface ImportRecord {
  name: string;
  type: string;
  content: string;
  ttl: number;
  line?: string;
  priority?: number;
  weight?: number;
  description?: string;
  status?: string;
  proxied?: boolean;
  readOnly?: boolean;
  group?: string;
}

export function projectRecord(row: number, zone: string, input: ImportRecord, options: BatchFileOptions, problem?: string): BatchFileRow {
  const caps = options.capabilities ?? basic;
  const fields = options.fields ?? [];
  const host = canonical(input.name);
  const name = host === "@" ? zone : !host || inZone(host, zone) || input.name.endsWith(".") ? host : host + "." + zone;
  const type = input.type.toUpperCase();
  const change: BatchFileRow["change"] = { action: "create", name, type, content: input.content, ttl: input.ttl };
  const errors: string[] = problem ? [problem] : [];
  if (input.readOnly || (name === zone && ["NS", "SOA"].includes(type))) errors.push("Protected or provider-managed record.");
  if (!domainName(name) || !inZone(name, zone)) errors.push("Choose an owner inside the selected zone.");
  if (!caps.types.includes(type)) errors.push("Unsupported record type: " + type + ".");
  if (!Number.isSafeInteger(input.ttl) || (!caps.specialTTLs?.includes(input.ttl) && (input.ttl < caps.minTTL || input.ttl > caps.maxTTL))) {
    errors.push("TTL is outside the selected provider's supported range.");
  }
  if (!change.content || change.content.includes("\0") || change.content.length > 65535) errors.push("Invalid or missing record value.");
  if ((type === "A" && !ipv4(change.content)) || (type === "AAAA" && !ipv6(change.content))) errors.push("Invalid address for this record type.");
  if (["CNAME", "NS", "PTR", "ANAME", "DNAME", "ALIAS"].includes(type) && !domainName(change.content)) errors.push("Invalid record target.");

  let line = input.line ?? "";
  if (proxyLines(options.provider)) {
    if (input.proxied !== undefined) {
      const expected = input.proxied ? "1" : "0";
      if (!isDefaultLine(line) && line !== expected) errors.push("Proxy flag and routing line disagree.");
      line = expected;
    }
    if (line === "1" && !["A", "AAAA", "CNAME"].includes(type)) errors.push("Proxy is available only for A, AAAA and CNAME.");
    if (!isDefaultLine(line) && line !== "0" && line !== "1") errors.push("A proxy line must be 0 or 1.");
  } else if (input.proxied) {
    errors.push("This provider cannot restore a proxied record.");
  }
  if (line && !isDefaultLine(line)) {
    if (new TextEncoder().encode(line).length > 255 || /[\p{Cc}]/u.test(line) || line !== line.trim()) errors.push("Invalid routing line ID.");
    if (caps.line) change.line = line;
    else errors.push("This provider cannot restore routing lines.");
  }
  if (input.description) {
    if (new TextEncoder().encode(input.description).length > 512 || /[\p{Cc}]/u.test(input.description)) errors.push("Invalid description (up to 512 bytes).");
    if (caps.description || fields.includes("remark")) change.description = input.description;
    else errors.push("This provider cannot restore description metadata.");
  }
  // Some list APIs repeat wire-format SRV priority/weight as display fields.
  // The complete SRV rdata already carries these numbers.
  const srv = type === "SRV" ? /^(\d+)\s+(\d+)\s+\d+\s+\S+\s*$/.exec(change.content) : null;
  if (input.priority !== undefined) {
    if (!Number.isInteger(input.priority) || input.priority < 0 || input.priority > 65535) errors.push("Invalid record priority.");
    else if (caps.priorityTypes?.includes(type)) change.priority = input.priority;
    else if (srv ? Number(srv[1]) !== input.priority : input.priority !== 0) errors.push("This record type cannot restore separate priority metadata.");
  }
  if (input.weight !== undefined) {
    if (!Number.isSafeInteger(input.weight) || input.weight < 0 || input.weight > 65535) errors.push("Invalid record weight.");
    else if (caps.weight || fields.includes("weight")) change.weight = input.weight;
    else if (!srv || Number(srv[2]) !== input.weight) errors.push("This provider cannot restore weight metadata.");
  }
  // DNSMgr exports MX priorities as "host | priority". Drivers also return
  // zone-file "priority host" or separate priority fields. Use one canonical input.
  if (type === "MX") {
    const presentation = /^(\d+)\s+(\S+)$/.exec(change.content);
    const dnsMgr = /^(\S+)\s*\|\s*(\d+)$/.exec(change.content);
    const priority = presentation ? Number(presentation[1]) : dnsMgr ? Number(dnsMgr[2]) : undefined;
    if (priority !== undefined && caps.priorityTypes?.includes("MX")) {
      if (priority > 65535 || (change.priority !== undefined && priority !== change.priority)) errors.push("Conflicting or invalid MX priority.");
      change.priority = priority;
      change.content = presentation ? presentation[2] : dnsMgr![1];
    }
  }
  if (input.status) {
    const raw = input.status.trim().toLowerCase();
    const enable = ["enabled", "enable", "active", "normal", "1", "true", "启用", "开启"].includes(raw);
    const disable = ["disabled", "disable", "paused", "0", "false", "暂停", "禁用", "关闭"].includes(raw);
    if (!enable && !disable) errors.push("Unknown record status: " + input.status + ".");
    else if (disable && !fields.includes("status")) errors.push("This provider cannot restore disabled records.");
    else if (fields.includes("status")) change.status = enable ? "enabled" : "disabled";
  }
  if (input.group) {
    if (new TextEncoder().encode(input.group).length > 255 || /[\p{Cc}]/u.test(input.group)) errors.push("Invalid record group ID.");
    change.group = input.group;
  }
  return { row, zone, change, ...(errors.length ? { error: errors.join(" ") } : {}) };
}

export function parseSmartPaste(text: string, options: BatchFileOptions): BatchFileRow[] {
  if (text.length > 4 * 1024 * 1024) throw new Error("Pasted text exceeds 4 MiB.");
  const fallback = canonical(options.zone);
  const zones = Array.from(new Set([fallback, ...(options.zones ?? []).map(canonical)]))
    .filter(Boolean)
    .sort((a, b) => b.length - a.length);
  const matchZone = (name: string) => zones.find((zone) => inZone(canonical(name), zone));
  const rows: BatchFileRow[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    const tabs = lines[i].includes("\t");
    const parts = tabs ? lines[i].split("\t").map((part) => part.trim()) : lines[i].trim().split(/\s+/);
    // Tab-delimited values preserve spaces inside SRV, CAA, URI, TXT or APP data.
    if (!tabs && options.type && ["CAA", "SRV", "URI", "TXT", "SPF", "APP", "MX"].includes(options.type) && parts.length > 2) {
      const last = parts[parts.length - 1];
      // Multi-token values may themselves end in the zone (e.g. an SRV
      // target at the apex). Tab delimiters allow an explicit zone after such data.
      const explicit = parts.length === 3 && !/^\d+$/.test(parts[1]) && zones.includes(canonical(last));
      const content = parts.slice(1, explicit ? -1 : undefined).join(" ");
      parts.splice(1, parts.length - 1, content, ...(explicit ? [last] : []));
    }
    let [owner, value = ""] = parts;
    let zone = fallback;
    let error: string | undefined;
    if (parts.length === 1) {
      zone = matchZone(owner) ?? "";
      value = options.value ?? "";
      if (!value || !zone) error = "A single owner needs a matching zone and a default record value.";
    } else if (parts.length === 2) {
      const reverseZone = matchZone(value);
      // An unqualified owner and a CNAME target in the same zone are ambiguous.
      // Ask for the third column, which makes the direction of the mapping explicit.
      if (reverseZone && !ipv4(owner) && !ipv6(owner) && domainName(owner) && !owner.includes(".")) {
        error = "Ambiguous owner and value. Use three columns: owner, value, zone.";
      } else if (reverseZone) {
        [owner, value] = [value, owner];
        zone = reverseZone;
      } else if (matchZone(owner)) {
        zone = matchZone(owner)!;
      }
    } else if (parts.length === 3) {
      zone = canonical(parts[2]);
      if (!zones.includes(zone)) error = "The specified zone is unavailable.";
    } else {
      error = "Use one to three columns per line.";
    }
    const type = options.type || (/^\d+\.\d+\.\d+\.\d+$/.test(value) ? "A" : value.includes(":") ? "AAAA" : domainName(value) ? "CNAME" : "TXT");
    rows.push(
      projectRecord(
        i + 1,
        zone,
        {
          name: owner,
          type,
          content: value,
          ttl: options.ttl ?? options.capabilities?.defaultTTL ?? 600,
          line: options.line,
          priority: options.priority,
          weight: options.weight,
          description: options.description,
          status: options.status,
        },
        options,
        error
      )
    );
    if (rows.length > 20000) throw new Error("An import may contain up to 20000 records.");
  }
  if (!rows.length) throw new Error("Enter at least one DNS record.");
  return rows;
}

const columns = {
  id: ["记录ID", "recordid", "id"],
  updatedAt: ["更新时间", "updatetime", "updatedat"],
  name: ["主机记录", "主机名", "name"],
  provider: ["源服务商", "provider"],
  accessId: ["源账号ID", "accessid"],
  zoneId: ["源域名ID", "zoneid"],
  groupId: ["分组ID", "groupid", "group"],
  groupName: ["分组名称", "groupname"],
  type: ["记录类型", "类型", "type"],
  lineId: ["线路值", "lineid"],
  lineName: ["线路类型", "线路", "linename", "line"],
  content: ["记录值", "value", "content"],
  ttl: ["ttl"],
  weight: ["权重", "weight"],
  remark: ["备注", "remark", "description"],
  status: ["状态", "status"],
  proxied: ["代理", "proxied"],
  readOnly: ["只读", "readonly"],
  priority: ["优先级", "priority"],
};

export function parseSheetRows(rows: SheetRow[], options: BatchFileOptions): BatchFileRow[] {
  const [header, ...body] = rows;
  if (!header || header.error) throw new Error("A header row with literal column names is required.");
  const headers = header.values.map((cell) => cell.trim().toLowerCase());
  const indexes = new Map<string, number>();
  for (const [key, names] of Object.entries(columns)) {
    const found = headers.map((name, i) => (names.some((alias) => alias.toLowerCase() === name) ? i : -1)).filter((i) => i !== -1);
    if (found.length > 1) throw new Error("Duplicate workbook column: " + key);
    if (found.length) indexes.set(key, found[0]);
  }
  if (!["name", "type", "content"].every((key) => indexes.has(key))) throw new Error("The first worksheet must include Name, Type and Value columns.");
  if (!body.length || body.length > 20000) throw new Error("The first worksheet must contain between 1 and 20000 records.");
  const targetGroups = groupIndex(options.groups);
  const knownColumns = new Set(indexes.values());
  return body.map(({ row, values, error }) => {
    const get = (key: string) => values[indexes.get(key) ?? -1] ?? "";
    const name = get("name").trim();
    let type = get("type").trim().toUpperCase();
    if (type === "显性URL") type = options.capabilities?.types.includes("EXPLICIT_URL") ? "EXPLICIT_URL" : "REDIRECT_URL";
    if (type === "隐性URL") type = options.capabilities?.types.includes("IMPLICIT_URL") ? "IMPLICIT_URL" : "FORWARD_URL";
    const rawTTL = get("ttl").trim();
    const ttl = rawTTL ? (/^\d+$/.test(rawTTL) ? Number(rawTTL) : NaN) : (options.ttl ?? options.capabilities?.defaultTTL ?? 600);
    const description = get("lineName").trim();
    const id = get("lineId").trim();
    let line = id || options.line || "";
    if (!id && !isDefaultLine(description)) {
      const match = options.lines?.find((item) => item.id === description || item.name === description);
      if (match) line = match.id;
      else error ??= "Unknown routing line. Select an available line ID before importing.";
    }
    const unknownColumn = headers.findIndex((_, i) => !knownColumns.has(i) && values[i]);
    if (unknownColumn >= 0) error ||= "Unsupported workbook column: " + headers[unknownColumn] + ".";
    const flag = (key: string) => {
      const flag = get(key).trim().toLowerCase();
      if (flag === "") return undefined;
      if (["false", "0", "否"].includes(flag)) return false;
      if (["true", "1", "是"].includes(flag)) return true;
      error ||= "Expected a boolean in " + key + ".";
      return undefined;
    };
    const number = (key: string, fallback?: number) => {
      const value = get(key).trim();
      if (!value) return fallback;
      return /^\d+$/.test(value) ? Number(value) : NaN;
    };
    const value = get("content");
    const record: ImportRecord = {
      name,
      type,
      content: ["TXT", "APP", "SPF"].includes(type) ? value : value.trim(),
      ttl,
      line,
      priority: number("priority", options.priority),
      weight: number("weight", options.weight),
      description: get("remark") || options.description,
      status: get("status") || options.status,
      readOnly: flag("readOnly"),
      proxied: flag("proxied"),
    };
    const scopeErrors = restoreScope(
      record,
      { provider: get("provider"), accessId: get("accessId"), zoneId: get("zoneId") },
      options,
      targetGroups,
      get("groupId"),
      get("groupName")
    );
    return projectRecord(row, canonical(options.zone), record, options, [error, ...scopeErrors].filter(Boolean).join(" ") || undefined);
  });
}
