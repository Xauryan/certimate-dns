import { useState } from "react";
import { Alert, Button, Card, Input, InputNumber, Select, Space, Table, Typography } from "antd";

import { type Page } from "@/api/dns";

import {
  type BatchRecord,
  type BatchZone,
  type Change,
  type Features,
  type Group,
  type Preview,
  type TargetFeatures,
  actionLabel,
  useData,
  useLabel,
} from "./model";

function desiredOwner(name: string, origin: string) {
  const suffix = origin.toLowerCase().replace(/\.$/, "");
  if (name === "@") return suffix;
  if (name.endsWith(".")) return name.slice(0, -1);
  if (name === suffix || name.endsWith("." + suffix)) return name;
  return name + "." + suffix;
}

type Selection = Record<string, BatchRecord[]>;

function Inventory({
  zone,
  path,
  features,
  revision,
  selected,
  onChange,
}: {
  zone: BatchZone;
  path: string;
  features?: Features;
  revision: number;
  selected: BatchRecord[];
  onChange: (rows: BatchRecord[]) => void;
}) {
  const l = useLabel();
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({ q: "", type: "", line: "", status: "", group: "" });
  const [applied, setApplied] = useState(filters);
  const groups = useData<Group[]>(features?.groups ? path + "/groups" : undefined);
  const [sort, setSort] = useState({ sort: "", order: "" });
  const query = new URLSearchParams({ ...applied, ...(sort.sort ? sort : {}), page: String(page) });
  const data = useData<Page<BatchRecord>>(path + "/search?" + query, revision);
  const current = data?.data?.result ?? [];
  return (
    <Card title={zone.label} size="small">
      <form
        onSubmit={(event) => {
          event.preventDefault();
          setApplied({ ...filters });
          setPage(1);
        }}
      >
        <Space wrap>
          <Input
            aria-label={l("搜索记录名或记录值", "Search names or values")}
            placeholder={l("搜索记录名或记录值", "Search names or values")}
            value={filters.q}
            onChange={(e) => setFilters({ ...filters, q: e.target.value })}
            allowClear
          />
          <Input
            aria-label={l("筛选记录类型", "Filter by record type")}
            placeholder={l("记录类型", "Record type")}
            value={filters.type}
            style={{ width: 120 }}
            onChange={(e) => setFilters({ ...filters, type: e.target.value })}
          />
          <Input
            aria-label={l("筛选线路", "Filter by line")}
            placeholder={l("线路", "Line")}
            value={filters.line}
            style={{ width: 120 }}
            onChange={(e) => setFilters({ ...filters, line: e.target.value })}
          />
          <Input
            aria-label={l("筛选状态", "Filter by status")}
            placeholder={l("状态", "Status")}
            value={filters.status}
            style={{ width: 120 }}
            onChange={(e) => setFilters({ ...filters, status: e.target.value })}
          />
          {features?.groups && (
            <Select
              aria-label={l("筛选分组", "Filter by group")}
              placeholder={l("分组", "Group")}
              allowClear
              style={{ minWidth: 130 }}
              options={groups?.data?.map((g) => ({ value: g.id, label: g.name }))}
              value={filters.group || undefined}
              onChange={(v) => setFilters({ ...filters, group: v ?? "" })}
            />
          )}
          <Button htmlType="submit">{l("搜索", "Search")}</Button>
        </Space>
      </form>
      {(data?.error || groups?.error) && <Alert type="error" showIcon title={data?.error || groups?.error} />}
      <Table<BatchRecord>
        size="small"
        scroll={{ x: 650 }}
        rowKey="id"
        loading={!data}
        dataSource={current}
        rowSelection={
          zone.canWrite === false
            ? undefined
            : {
                selectedRowKeys: selected.map((r) => r.id),
                preserveSelectedRowKeys: true,
                getCheckboxProps: (r) => ({ disabled: r.readOnly, "aria-label": l("选择记录 ", "Select record ") + r.name + " · " + r.content }),
                onChange: (keys) => {
                  const all = new Map([...selected, ...current].map((r) => [r.id, r]));
                  onChange(
                    keys.flatMap((key) => {
                      const row = all.get(String(key));
                      return row && !row.readOnly ? [row] : [];
                    })
                  );
                },
              }
        }
        pagination={{ current: page, pageSize: 20, total: data?.data?.result_info.total_count ?? 0, showSizeChanger: false }}
        onChange={(pagination, _filters, sorter, extra) => {
          if (extra.action === "sort") {
            const s = Array.isArray(sorter) ? sorter[0] : sorter;
            setSort({ sort: s.order ? String(s.field) : "", order: s.order === "ascend" ? "asc" : "desc" });
            setPage(1);
          } else setPage(pagination.current ?? 1);
        }}
        columns={[
          { title: l("记录名", "Name"), dataIndex: "name", sorter: true },
          { title: l("类型", "Type"), dataIndex: "type", sorter: true },
          { title: l("记录值", "Value"), dataIndex: "content", sorter: true, render: (v: string) => <span className="break-all">{v}</span> },
          { title: "TTL", dataIndex: "ttl", sorter: true },
          ...(current.some((r) => r.updatedAt) || sort.sort === "updatedAt" ? [{ title: l("更新时间", "Updated"), dataIndex: "updatedAt", sorter: true }] : []),
          { title: l("线路", "Line"), dataIndex: "line" },
          { title: l("状态", "Status"), dataIndex: "status" },
        ]}
      />
    </Card>
  );
}

function TargetValue({ action, zone, value, onChange }: { action: string; zone: BatchZone; value?: string; onChange: (v: string) => void }) {
  const l = useLabel();
  const advanced = useData<{ details: boolean }>(action === "line" ? zone.key + "/advanced/features" : undefined);
  const details = useData<{ lines: Group[] }>(advanced?.data?.details ? zone.key + "/advanced/details" : undefined);
  const groups = useData<Group[]>(action === "group" ? zone.key + "/batch/groups" : undefined);
  const label = (action === "group" ? l("目标分组", "Target group") : l("目标线路", "Target line")) + " · " + zone.label;
  const options = action === "group" ? groups?.data : details?.data?.lines;
  const error = groups?.error || advanced?.error || details?.error;
  if (error) return <Alert type="error" title={zone.label + " · " + error} />;
  const manual = action === "line" && (advanced?.data?.details === false || options?.length === 0);
  return (
    <label>
      {label}{" "}
      {manual ? (
        <Input aria-label={label} value={value ?? ""} onChange={(e) => onChange(e.target.value)} />
      ) : (
        <Select
          aria-label={label}
          loading={!options}
          disabled={!options?.length}
          options={options?.map((g) => ({ value: g.id, label: g.name }))}
          style={{ minWidth: 160 }}
          value={value || undefined}
          onChange={onChange}
        />
      )}
    </label>
  );
}

export default function RecordSelection({
  zones,
  features,
  revision,
  preview,
  busy,
}: {
  zones: BatchZone[];
  features: TargetFeatures;
  revision: number;
  preview: Preview;
  busy: boolean;
}) {
  const l = useLabel();
  const [selected, setSelected] = useState<Selection>({});
  const [action, setAction] = useState("patch");
  const [owner, setOwner] = useState("");
  const [recordType, setRecordType] = useState("");
  const [priority, setPriority] = useState<number | null>(null);
  const [value, setValue] = useState("");
  const [ttl, setTTL] = useState<number | null>(null);
  const chosen = zones.filter((z) => z.canWrite !== false && selected[z.key]?.length);
  const count = chosen.reduce((n, z) => n + selected[z.key].length, 0);
  const [targetValues, setTargetValues] = useState<Record<string, string>>({});
  const targets = chosen.length ? chosen : zones.filter((z) => z.canWrite !== false);
  const fields = features[targets[0]?.key]?.fields ?? [];
  const commonEdit = (field: "rename" | "retype" | "priority") => targets.length > 0 && targets.every((z) => features[z.key]?.edit?.[field]);
  const canRename = commonEdit("rename");
  const canRetype = commonEdit("retype");
  const canPriority =
    commonEdit("priority") &&
    chosen.length > 0 &&
    chosen.every((z) => selected[z.key].every((r) => features[z.key].capabilities.priorityTypes?.includes(recordType || r.type)));
  const rich = canRename || canRetype || canPriority;
  const types = (features[targets[0]?.key]?.capabilities.types ?? []).filter((t) => targets.every((z) => features[z.key]?.capabilities.types.includes(t)));
  const options = ["patch", "delete", ...(rich ? ["replace"] : []), ...fields.filter((f) => targets.every((z) => features[z.key]?.fields.includes(f)))];
  const scoped = action === "group" || action === "line";
  const newOwner = owner.trim().toLowerCase();
  let invalidValue = action !== "remark" && action !== "delete" && !value;
  if (scoped) invalidValue = chosen.some((z) => !targetValues[z.key]);
  if (action === "patch") invalidValue = !value && ttl == null;
  if (action === "replace") invalidValue = !newOwner && !recordType && priority == null;
  const invalidTargets = chosen.filter((z) => {
    const caps = features[z.key]?.capabilities;
    if (!caps || !options.includes(action)) return true;
    if (action !== "patch" && action !== "replace") return false;
    if (ttl != null && !(ttl >= caps.minTTL && ttl <= caps.maxTTL) && !caps.specialTTLs?.includes(ttl)) return true;
    if (action === "patch") return selected[z.key].some((r) => !caps.types.includes(r.type));
    if ((newOwner && !canRename) || (recordType && !canRetype) || (priority != null && !canPriority)) return true;
    if (newOwner) {
      const suffix = z.name.toLowerCase().replace(/\.$/, "");
      const dest = desiredOwner(newOwner, z.name);
      if (dest !== suffix && !dest.endsWith("." + suffix)) return true;
    }
    return selected[z.key].some((r) => !caps.types.includes(recordType || r.type));
  });
  function build() {
    preview(
      chosen.map((zone) => ({
        zone,
        payload: {
          changes: selected[zone.key].map((r): Change => {
            switch (action) {
              case "patch":
                return { action, id: r.id, ttl: ttl ?? r.ttl, content: value || r.content };
              case "replace":
                return {
                  action,
                  id: r.id,
                  ...(newOwner && { name: desiredOwner(newOwner, zone.name) }),
                  ...(recordType && { type: recordType }),
                  ...(priority != null && { priority }),
                  ...(value && { content: value }),
                  ...(ttl != null && { ttl }),
                };
              case "delete":
                return { action, id: r.id };
              default:
                return { action, id: r.id, value: scoped ? targetValues[zone.key] : value };
            }
          }),
        },
      }))
    );
  }
  return (
    <Space orientation="vertical" style={{ width: "100%" }}>
      {zones.map((z) => (
        <Inventory
          key={z.key}
          path={z.key + "/batch"}
          zone={z}
          features={features[z.key]}
          revision={revision}
          selected={selected[z.key] ?? []}
          onChange={(rows) => setSelected((v) => ({ ...v, [z.key]: rows }))}
        />
      ))}
      {zones.some((z) => z.canWrite !== false) && (
        <Space wrap>
          <Typography.Text>
            {l("已选记录", "Selected records")} · {count}
          </Typography.Text>
          <Select
            style={{ minWidth: 160 }}
            aria-label={l("批量操作", "Bulk action")}
            value={action}
            options={Array.from(new Set(options)).map((v) => ({ value: v, label: actionLabel(v, l) }))}
            onChange={(a) => {
              setAction(a);
              setTargetValues({});
              setValue("");
              setTTL(null);
              setOwner("");
              setRecordType("");
              setPriority(null);
            }}
          />
          {action === "replace" && (
            <>
              {canRename && (
                <Input
                  aria-label={l("新记录名", "New record name")}
                  placeholder={l("相对名或以点结尾的完整名称", "Relative name or fully qualified name ending in a dot")}
                  value={owner}
                  onChange={(e) => setOwner(e.target.value)}
                />
              )}
              {canRetype && (
                <Select
                  aria-label={l("新记录类型", "New record type")}
                  allowClear
                  placeholder={l("保留原类型", "Keep current type")}
                  style={{ minWidth: 160 }}
                  value={recordType || undefined}
                  options={types.map((t) => ({ value: t, label: t }))}
                  onChange={(v) => {
                    setRecordType(v ?? "");
                    setPriority(null);
                  }}
                />
              )}
              {canPriority && (
                <InputNumber
                  min={0}
                  max={65535}
                  precision={0}
                  aria-label={l("新优先级", "New priority")}
                  placeholder={l("优先级", "Priority")}
                  value={priority}
                  onChange={setPriority}
                />
              )}
            </>
          )}
          {(action === "patch" || action === "replace") && (
            <>
              <Input
                placeholder={l("保留原记录值", "Keep current value")}
                aria-label={l("新记录值", "New record value")}
                value={value}
                onChange={(e) => setValue(e.target.value)}
              />
              <InputNumber
                placeholder={l("保留原 TTL", "Keep current TTL")}
                aria-label={l("新 TTL", "New TTL")}
                min={1}
                precision={0}
                style={{ width: 150 }}
                value={ttl}
                onChange={setTTL}
              />
            </>
          )}
          {action === "status" && (
            <Select
              style={{ minWidth: 130 }}
              aria-label={l("目标状态", "Target status")}
              value={value || undefined}
              onChange={setValue}
              options={[
                { value: "enabled", label: l("启用", "Enabled") },
                { value: "disabled", label: l("暂停", "Disabled") },
              ]}
            />
          )}
          {scoped &&
            chosen.map((z) => (
              <TargetValue
                key={z.key + "/" + action}
                zone={z}
                action={action}
                value={targetValues[z.key]}
                onChange={(v) => setTargetValues((prev) => ({ ...prev, [z.key]: v }))}
              />
            ))}
          {invalidTargets.length > 0 && (
            <Alert
              type="warning"
              title={l("所选域名不支持此操作、记录类型或 TTL。", "This action, record type or TTL is unavailable for the selected zones.")}
              description={invalidTargets.map((z) => z.label).join(", ")}
            />
          )}
          {!["patch", "replace", "status", "group", "line", "delete"].includes(action) && (
            <Input
              aria-label={actionLabel(action, l)}
              value={value}
              placeholder={action === "remark" ? l("留空将清除备注", "Leave blank to clear remark") : actionLabel(action, l)}
              onChange={(e) => setValue(e.target.value)}
            />
          )}
          <Button type="primary" loading={busy} disabled={!count || invalidValue || !!invalidTargets.length} onClick={build}>
            {l("预览所选变更", "Preview selected changes")}
          </Button>
        </Space>
      )}
    </Space>
  );
}
