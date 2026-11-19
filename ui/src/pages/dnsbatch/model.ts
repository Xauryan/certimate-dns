import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { type DNSRecord, type Zone, dnsRequest } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";
import type { BatchFileCapabilities } from "./files.rows";

export type BatchZone = Zone & { canWrite?: boolean; provider: string; accessId: string; key: string; label: string };
export type ZoneInput = Zone & { canWrite?: boolean; provider?: string; accessId?: string };
export function targetZone(zone: ZoneInput, base: string): BatchZone {
  const provider = zone.provider ?? decodeURIComponent(base.split("/")[3]);
  const accessId = zone.accessId ?? decodeURIComponent(base.split("/")[4]);
  const key = "/api/dns/" + [provider, accessId].map(encodeURIComponent).join("/") + "/zones/" + encodeURIComponent(zone.id);
  return { ...zone, provider, accessId, key, label: [zone.name, provider, accessId].join(" · ") };
}
export type BatchRecord = DNSRecord & { updatedAt?: string; status?: string; description?: string; priority?: number; weight?: number };
type EditCapabilities = { rename: boolean; retype: boolean; priority: boolean };
export type Features = { capabilities: BatchFileCapabilities; edit?: EditCapabilities; fields: string[]; createLine?: boolean; groups: boolean; logs: boolean };
export type Group = { id: string; name: string };
export type Change = {
  action: string;
  id?: string;
  name?: string;
  type?: string;
  content?: string;
  ttl?: number;
  value?: string;
  line?: string;
  weight?: number;
  priority?: number;
  description?: string;
  status?: "disabled" | "enabled";
  group?: string;
};
export type PreviewRow = {
  before?: BatchRecord;
  after?: Pick<BatchRecord, "name" | "type" | "content" | "ttl" | "priority">;
  change: Change;
  previousValue?: string;
};
export type Summary = { id: string; actor: string; state: string; created: number };
export type Plan = Summary & { items: { id?: string; action: string; state: string }[] };
export type Review = { batch?: string; zone: BatchZone; plan: Plan; rows: PreviewRow[] };
export type Draft = { zone: BatchZone; payload: { changes: Change[] } | { zoneFile: string } };
export type Preview = (drafts: Draft[]) => void;
export type Label = (zh: string, en: string) => string;

export function useLabel(): Label {
  const { i18n } = useTranslation();
  const zh = i18n.language.toLowerCase().startsWith("zh");
  return (cn, en) => (zh ? cn : en);
}

export function actionLabel(action: string, l: Label) {
  const names: Record<string, string> = {
    create: l("新增", "Create"),
    patch: l("改值或 TTL", "Edit value or TTL"),
    replace: l("修改名称、类型或优先级", "Edit name, type or priority"),
    delete: l("删除", "Delete"),
    remark: l("修改备注", "Change remark"),
    line: l("修改线路", "Change line"),
    status: l("启停记录", "Change status"),
    group: l("移动分组", "Move to group"),
  };
  return names[action] ?? action;
}

export function stateLabel(state: string, l: Label) {
  const names: Record<string, string> = {
    preview: l("待确认", "Awaiting confirmation"),
    applying: l("执行中", "Applying"),
    completed: l("完成", "Completed"),
    uncertain: l("待核对", "Needs reconciliation"),
    partial: l("部分完成", "Partial"),
    conflict: l("记录已变更", "Record changed"),
    sending: l("发送中", "Sending"),
    ready: l("待执行", "Ready"),
    unknown: l("结果未知", "Unknown outcome"),
    applied: l("已执行", "Applied"),
    observed: l("已核实", "Observed"),
    not_sent: l("未发送", "Not sent"),
  };
  return names[state] ?? state;
}

export type TargetFeatures = Record<string, Features>;
export function useTargetFeatures(keys: string[], revision: number) {
  const signature = JSON.stringify(keys);
  const [result, setResult] = useState<{ signature: string; revision: number; features: TargetFeatures; errors: string[] }>();
  useEffect(() => {
    let live = true;
    const scopes: string[] = JSON.parse(signature);
    Promise.allSettled(scopes.map((scope) => dnsRequest<Features>(scope + "/batch/features"))).then((responses) => {
      if (!live) return;
      const features: TargetFeatures = {};
      const errors: string[] = [];
      responses.forEach((r, i) => {
        if (r.status === "fulfilled") features[scopes[i]] = r.value;
        else errors.push(scopes[i] + " · " + unwrapErrMsg(r.reason));
      });
      setResult({ signature, revision, features, errors });
    });
    return () => {
      live = false;
    };
  }, [signature, revision]);
  return result?.signature === signature && result.revision === revision ? result : undefined;
}

export function useData<T>(url: string | undefined, revision = 0) {
  const [result, setResult] = useState<{ url: string; revision: number; data?: T; error?: string }>();
  useEffect(() => {
    if (!url) return;
    let live = true;
    dnsRequest<T>(url).then(
      (data) => {
        if (live) setResult({ url, revision, data });
      },
      (err) => {
        if (live) setResult({ url, revision, error: unwrapErrMsg(err) });
      }
    );
    return () => {
      live = false;
    };
  }, [url, revision]);
  return result?.url === url && result?.revision === revision ? result : undefined;
}

// The server binds each confirmation to one exact payload of at most 200 changes.
export function splitDraft(draft: Draft): Array<Draft & { batch?: string }> {
  if (!("changes" in draft.payload) || draft.payload.changes.length <= 200) return [draft];
  const { changes } = draft.payload;
  const parts: Array<Draft & { batch?: string }> = [];
  for (let start = 0; start < changes.length; start += 200) {
    parts.push({
      zone: draft.zone,
      payload: { changes: changes.slice(start, start + 200) },
      batch: String(start / 200 + 1) + " / " + Math.ceil(changes.length / 200),
    });
  }
  return parts;
}

export function metadataSummary(change: Pick<Change, "line" | "priority" | "weight" | "status" | "description" | "group">, l: Label, provider?: string) {
  return [
    change.line &&
      (provider === "cloudflare" && ["0", "1"].includes(change.line)
        ? change.line === "1"
          ? l("开启代理", "Proxied")
          : l("仅 DNS", "DNS only")
        : l("线路 ", "Line ") + change.line),
    change.group && l("分组 ", "Group ") + change.group,
    change.priority != null && l("优先级 ", "Priority ") + change.priority,
    change.weight != null && l("权重 ", "Weight ") + change.weight,
    change.status && (change.status === "disabled" ? l("暂停", "Disabled") : l("启用", "Enabled")),
    change.description && l("备注 ", "Remark ") + change.description,
  ]
    .filter(Boolean)
    .join(" · ");
}
