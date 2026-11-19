export type NamedGroup = { id: string; name: string };
export type SourceScope = { provider?: string; accessId?: string; zoneId?: string };

export const proxyLines = (provider?: string) => provider === "cloudflare" || provider === "aliyunesa";
export function sameScope(source: SourceScope, target: SourceScope) {
  return (
    !!source.provider &&
    source.provider === target.provider &&
    !!source.accessId &&
    source.accessId === target.accessId &&
    !!source.zoneId &&
    source.zoneId === target.zoneId
  );
}

// Ambiguous group IDs or names cannot select a destination.
export function groupIndex(groups: NamedGroup[] = []) {
  const ids = new Map<string, NamedGroup | null>(),
    names = new Map<string, NamedGroup | null>();
  for (const group of groups) {
    ids.set(group.id, ids.has(group.id) ? null : group);
    names.set(group.name, names.has(group.name) ? null : group);
  }
  return { ids, names };
}

export function restoreScope(
  record: { line?: string; proxied?: boolean; group?: string },
  source: SourceScope,
  target: SourceScope,
  groups: ReturnType<typeof groupIndex>,
  groupId: string,
  groupName?: string
): string[] {
  const errors: string[] = [];
  const same = sameScope(source, target);
  if (proxyLines(source.provider) && (record.line === "0" || record.line === "1")) {
    const proxy = record.line === "1";
    if (record.proxied !== undefined && record.proxied !== proxy) errors.push("Proxy flag and source line disagree.");
    record.proxied = proxy;
    record.line = undefined;
  } else if (source.provider && !same && record.line && !["default", "默认"].includes(record.line.toLowerCase())) {
    errors.push("Provider routing line IDs require the original account and zone.");
  }
  if (groupId || groupName) {
    const matched = (same && groupId ? groups.ids.get(groupId) : undefined) || (groupName ? groups.names.get(groupName) : undefined);
    if (matched) record.group = matched.id;
    else errors.push("A unique matching record group is required on the destination.");
  }
  return errors;
}
