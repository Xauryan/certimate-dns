import { useState } from "react";
import { Alert, Button, Card, Input, InputNumber, Select, Space, Table, Typography } from "antd";

import { type Page } from "@/api/dns";

import { type BatchRecord, type BatchZone, type Change, type Features, type Group, type Preview, actionLabel, batchPath, useData, useLabel } from "./model";

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
    <Card title={zone.name} size="small">
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

export default function RecordSelection({
  base,
  zones,
  features,
  revision,
  preview,
  busy,
}: {
  base: string;
  zones: BatchZone[];
  features?: Features;
  revision: number;
  preview: Preview;
  busy: boolean;
}) {
  const l = useLabel();
  const [selected, setSelected] = useState<Selection>({});
  const [action, setAction] = useState("patch");
  const [value, setValue] = useState("");
  const [ttl, setTTL] = useState<number | null>(null);
  const chosen = zones.filter((z) => z.canWrite !== false && selected[z.id]?.length);
  const count = chosen.reduce((n, z) => n + selected[z.id].length, 0);
  const options = ["patch", "delete", ...(features?.fields ?? [])];
  const groups = useData<Group[]>(action === "group" && chosen.length === 1 ? batchPath(base, chosen[0]) + "/groups" : undefined);
  const invalidValue = action === "patch" ? !value && ttl == null : action !== "remark" && action !== "delete" && !value;
  function build() {
    preview(
      chosen.map((zone) => ({
        zone,
        payload: {
          changes: selected[zone.id].map((r): Change => {
            switch (action) {
              case "patch":
                return { action, id: r.id, ttl: ttl ?? r.ttl, content: value || r.content };
              case "delete":
                return { action, id: r.id };
              default:
                return { action, id: r.id, value };
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
          key={z.id}
          path={batchPath(base, z)}
          zone={z}
          features={features}
          revision={revision}
          selected={selected[z.id] ?? []}
          onChange={(rows) => setSelected((v) => ({ ...v, [z.id]: rows }))}
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
              setValue("");
              setTTL(null);
            }}
          />
          {action === "patch" && (
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
                min={Math.min(features?.capabilities?.minTTL ?? 1, ...(features?.capabilities?.specialTTLs ?? []))}
                max={features?.capabilities?.maxTTL ?? 604800}
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
          {action === "group" && (
            <>
              {chosen.length === 1 ? (
                <Select
                  aria-label={l("目标分组", "Target group")}
                  loading={!groups}
                  placeholder={l("选择分组", "Select group")}
                  style={{ minWidth: 180 }}
                  value={value || undefined}
                  options={groups?.data?.map((g) => ({ value: g.id, label: g.name }))}
                  onChange={setValue}
                />
              ) : (
                <Typography.Text>{l("请在单个域名内选择要移动的记录。", "Select records from a single zone to move groups.")}</Typography.Text>
              )}
              {groups?.error && <Alert type="error" title={groups.error} />}
            </>
          )}
          {!["patch", "status", "group", "delete"].includes(action) && (
            <Input
              aria-label={actionLabel(action, l)}
              value={value}
              placeholder={action === "remark" ? l("留空将清除备注", "Leave blank to clear remark") : actionLabel(action, l)}
              onChange={(e) => setValue(e.target.value)}
            />
          )}
          <Button
            type="primary"
            loading={busy}
            disabled={!count || invalidValue || (action === "group" && (chosen.length !== 1 || !groups?.data?.some((g) => g.id === value)))}
            onClick={build}
          >
            {l("预览所选变更", "Preview selected changes")}
          </Button>
        </Space>
      )}
    </Space>
  );
}
