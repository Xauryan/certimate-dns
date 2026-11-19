import { useEffect, useRef, useState } from "react";
import { Alert, Button, Modal, Select, Space } from "antd";

import { dnsRequest, type DNSRecord, type Page } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";
import { Editor, LoadError, useLabel, useResource } from "./shared";

type Target = { account: string; accessId: string; provider: string; owner: string; zone: string; zoneId: string };
type Line = { id: string; name: string };
type Details = { lines: Line[]; minTTL?: number };

function targetBase(target: Target) {
  return "/api/dns/" + [target.provider, target.accessId, "zones", target.zoneId].map(encodeURIComponent).join("/");
}

async function ensureTXT(target: Target, name: string, value: string, ttl: number, line?: string) {
  const url = targetBase(target) + "/records";
  for (let page = 1; page <= 100; page++) {
    const rows = await dnsRequest<Page<DNSRecord>>(url + "?" + new URLSearchParams({ page: String(page), name }));
    const match = rows.result.find(
      (record) =>
        record.name.toLowerCase().replace(/\.$/, "") === name.toLowerCase().replace(/\.$/, "") &&
        record.type === "TXT" &&
        (record.content === value || record.content === JSON.stringify(value)) &&
        (!line || !record.line || record.line === line)
    );
    if (match) return;
    if (!rows.result.length || (rows.result_info?.total_count > 0 && page * 20 >= rows.result_info.total_count) || rows.result.length < 20) {
      await dnsRequest(url, "POST", { type: "TXT", name, content: value, ttl, line });
      return;
    }
  }
  throw new Error("Could not verify the existing TXT records");
}

function AddVerification({ target, name, value }: { target: Target; name: string; value: string }) {
  const l = useLabel();
  const [edit, setEdit] = useState(false);
  const base = targetBase(target);
  const features = useResource<{ details: boolean }>(base + "/advanced/features");
  return (
    <>
      {features.error && <LoadError text={features.error} retry={features.reload} />}
      <Button disabled={!features.data} onClick={() => setEdit(true)}>
        {l("Add verification TXT", "添加验证 TXT")}
      </Button>
      {edit &&
        (features.data?.details ? (
          <WithDetails base={base} target={target} name={name} value={value} close={() => setEdit(false)} />
        ) : (
          <AddForm base={base} target={target} name={name} value={value} close={() => setEdit(false)} />
        ))}
    </>
  );
}

type Props = { base: string; target: Target; name: string; value: string; close: () => void };
function WithDetails(props: Props) {
  const details = useResource<Details>(props.base + "/advanced/details");
  if (details.error) return <LoadError text={details.error} retry={details.reload} />;
  return details.data ? <AddForm {...props} details={details.data} /> : null;
}

function AddForm({ target, name, value, details, close }: Props & { details?: Details }) {
  const l = useLabel();
  const lines = details?.lines ?? [];
  return (
    <Editor
      title={l("Add verification TXT", "添加验证 TXT")}
      close={close}
      fields={[
        { key: "ttl", label: "TTL", initial: String(target.provider === "cloudflare" ? 1 : Math.max(600, details?.minTTL ?? 0)), required: true },
        ...(lines.length ? [{ key: "line", label: l("DNS line", "解析线路"), options: lines.map((v) => v.id), initial: lines[0].id }] : []),
      ]}
      save={async (fields) => {
        const ttl = Number(fields.ttl);
        if (!Number.isInteger(ttl) || ttl < 1) throw new Error(l("Enter a positive TTL in seconds.", "TTL 请输入正整数秒。"));
        await ensureTXT(target, name, value, ttl, fields.line);
      }}
    >
      <p>
        {target.account} · {target.zone}
      </p>
      <p>
        {name} · TXT · {value}
      </p>
      {lines.length > 0 && <p>{lines.map((v) => v.id + " = " + v.name).join(" · ")}</p>}
    </Editor>
  );
}

export default function VerificationTargets({ base, name, value }: { base: string; name: string; value: string }) {
  const l = useLabel();
  const data = useResource<Target[]>(base + "/targets?" + new URLSearchParams({ name }));
  const [index, setIndex] = useState(0);
  const selected = data.data?.[index];
  return (
    <Space wrap>
      {data.error && <LoadError text={data.error} retry={data.reload} />}
      {data.data?.length === 0 && l("No matching enabled zone in the DNS catalog.", "DNS 目录中没有匹配的已启用域名。")}
      {!!data.data?.length && (
        <Select
          aria-label={l("Verification zone", "验证域名")}
          value={index}
          onChange={setIndex}
          options={data.data.map((t, i) => ({ value: i, label: t.account + " · " + t.zone + " · " + t.owner }))}
        />
      )}
      {selected && <AddVerification key={selected.accessId + selected.zoneId} target={selected} name={name} value={value} />}
    </Space>
  );
}

type VerificationEntry = { name: string; value: string };
type BulkRow = VerificationEntry & { targets: Target[]; targetIndex?: number; error?: string; done?: boolean };
export function BulkVerification({ base, entries, close }: { base: string; entries: VerificationEntry[]; close: () => void }) {
  const l = useLabel();
  const [rows, setRows] = useState<BulkRow[]>();
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  // A parent refresh can reconstruct entries while the review is open.
  const entryKey = JSON.stringify(entries);
  useEffect(() => {
    let active = true;
    async function load() {
      const unique = [...new Map((JSON.parse(entryKey) as VerificationEntry[]).map((v) => [JSON.stringify(v), v])).values()];
      const records: BulkRow[] = [];
      for (const entry of unique) {
        if (!active) return;
        try {
          const targets = await dnsRequest<Target[]>(base + "/targets?" + new URLSearchParams({ name: entry.name }));
          records.push({ ...entry, targets, targetIndex: targets.length === 1 ? 0 : undefined });
        } catch (e) {
          records.push({ ...entry, targets: [], error: unwrapErrMsg(e) });
        }
      }
      if (active) setRows(records);
    }
    void load();
    return () => {
      active = false;
    };
  }, [base, entryKey]);
  const chosen = rows?.filter((r) => r.targetIndex !== undefined && !r.done) ?? [];
  async function apply() {
    if (running.current || !rows) return;
    running.current = true;
    setBusy(true);
    try {
      const results = [...rows];
      for (const row of chosen) {
        const target = row.targets[row.targetIndex!],
          url = targetBase(target);
        const index = results.indexOf(row);
        try {
          const features = await dnsRequest<{ details: boolean }>(url + "/advanced/features");
          const details = features.details ? await dnsRequest<Details>(url + "/advanced/details") : undefined;
          await ensureTXT(target, row.name, row.value, target.provider === "cloudflare" ? 1 : Math.max(600, details?.minTTL ?? 0), details?.lines?.[0]?.id);
          results[index] = { ...row, done: true, error: undefined };
        } catch (e) {
          results[index] = { ...row, error: unwrapErrMsg(e) };
        }
        setRows([...results]);
      }
    } finally {
      setBusy(false);
      running.current = false;
    }
  }
  return (
    <Modal
      open
      title={l("Verify selected TXT records", "批量验证 TXT 记录")}
      onOk={apply}
      onCancel={close}
      closable={!busy}
      keyboard={!busy}
      mask={{ closable: !busy }}
      cancelButtonProps={{ disabled: busy }}
      confirmLoading={busy}
      okButtonProps={{ disabled: chosen.length === 0 }}
      okText={l("Add selected records", "添加所选记录")}
    >
      {!rows && l("Finding matching DNS zones…", "正在匹配解析域名…")}
      {rows?.length === 0 && l("The selected hostnames have no pending TXT challenges.", "所选主机名没有待处理的 TXT 验证。")}
      {rows?.map((r, i) => (
        <div key={JSON.stringify([r.name, r.value])} className="my-3">
          <strong>{r.name}</strong>
          <p className="break-all">{r.value}</p>
          {r.targets.length > 0 ? (
            <Select
              disabled={busy || r.done}
              allowClear
              placeholder={l("Select verification zone", "选择验证域名")}
              style={{ width: "100%" }}
              value={r.targetIndex}
              onChange={(v) => setRows((old) => old?.map((row, j) => (j === i ? { ...row, targetIndex: v } : row)))}
              options={r.targets.map((t, n) => ({ value: n, label: t.account + " · " + t.zone + " · " + t.owner }))}
            />
          ) : (
            l("No matching enabled zone", "没有匹配的已启用域名")
          )}
          {r.error && <Alert type="error" title={r.error} />}
          {r.done && <Alert type="success" title={l("TXT record present", "TXT 记录已就绪")} />}
        </div>
      ))}
    </Modal>
  );
}
