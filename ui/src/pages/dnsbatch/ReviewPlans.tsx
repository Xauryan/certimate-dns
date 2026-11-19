import { useRef, useState } from "react";
import { Alert, Button, Card, Popconfirm, Space, Table, Typography } from "antd";

import { dnsRequest } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";

import { type Plan, type PreviewRow, type Review, actionLabel, metadataSummary, stateLabel, useLabel } from "./model";

type Props = { review: Review; canWrite: boolean; onPlan: (plan: Plan) => void; onApplied?: () => void };

export function ItemTable({ plan, rows, provider }: { plan: Plan; rows?: PreviewRow[]; provider?: string }) {
  const l = useLabel();
  return (
    <Table
      size="small"
      scroll={{ x: 620 }}
      rowKey="index"
      pagination={plan.items.length > 10 ? { pageSize: 10, showSizeChanger: false } : false}
      dataSource={plan.items.map((item, index) => ({ ...item, index, preview: rows?.[index] }))}
      columns={[
        { title: l("操作", "Action"), dataIndex: "action", render: (v: string) => actionLabel(v, l) },
        { title: l("记录", "Record"), render: (_, row) => row.preview?.before?.name ?? row.preview?.change.name ?? row.id ?? "—" },
        ...(rows
          ? [
              {
                title: l("原值", "Before"),
                render: (_: unknown, row: { preview?: PreviewRow }) => {
                  const old = row.preview?.before;
                  if (old && row.preview?.change.action === "replace") {
                    return [old.name, old.type, old.content, "TTL " + old.ttl, metadataSummary({ priority: old.priority }, l, provider)]
                      .filter(Boolean)
                      .join(" · ");
                  }
                  return row.preview?.previousValue ?? (old ? old.content + " (TTL " + old.ttl + ")" : "—");
                },
              },
              {
                title: l("目标", "After"),
                render: (_: unknown, row: { preview?: PreviewRow }) => {
                  const c = row.preview?.change;
                  if (!c || c.action === "delete") return "—";
                  const after = row.preview?.after;
                  if (after)
                    return [after.name, after.type, after.content, "TTL " + after.ttl, metadataSummary(after, l, provider)].filter(Boolean).join(" · ");
                  return c.value ?? [c.type, c.content, "TTL " + c.ttl, metadataSummary(c, l, provider)].filter(Boolean).join(" · ");
                },
              },
            ]
          : []),
        { title: l("结果", "Result"), dataIndex: "state", render: (s: string) => stateLabel(s, l) },
      ]}
    />
  );
}

export default function ReviewPlan({ review, canWrite, onPlan, onApplied }: Props) {
  const l = useLabel();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const locked = useRef(false);
  const { plan, rows, zone } = review;
  const path = zone.key + "/batch/plans/" + encodeURIComponent(plan.id);
  async function execute() {
    if (locked.current || plan.state !== "preview" || !canWrite) return;
    locked.current = true;
    setBusy(true);
    setError("");
    try {
      const updated = await dnsRequest<Plan>(path + "/apply", "POST", { confirm: true, changes: rows.map((r) => r.change) });
      onPlan(updated);
    } catch (e) {
      setError(unwrapErrMsg(e));
      // A lost response can follow a successful provider write. Refresh its saved state before allowing another action.
      try {
        onPlan(await dnsRequest<Plan>(path));
      } catch {
        onPlan({ ...plan, state: "uncertain" });
      }
    } finally {
      locked.current = false;
      setBusy(false);
      onApplied?.();
    }
  }
  return (
    <Card size="small" title={[zone.label, review.batch].filter(Boolean).join(" · ")}>
      <Space orientation="vertical" style={{ width: "100%" }}>
        <Typography.Text>
          {stateLabel(plan.state, l)} · {plan.items.length} {l("条记录", "records")}
        </Typography.Text>
        {error && <Alert type="error" showIcon title={error} />}
        {plan.state === "preview" && rows.some((r) => r.change.action === "create" && r.change.status === "disabled") && (
          <Alert
            type="warning"
            showIcon
            title={l(
              "服务商会先创建记录，再暂停解析。两次操作之间记录可能短暂生效。",
              "The provider creates each record before disabling it. The record may resolve between those operations."
            )}
          />
        )}
        <ItemTable plan={plan} rows={rows} provider={zone.provider} />
        {plan.state === "preview" && canWrite && (
          <Popconfirm
            title={l("执行此域名的全部预览变更？", "Apply the previewed changes to this zone?")}
            description={zone.label + " · " + plan.items.length + " " + l("条记录", "records")}
            okText={l("确认执行", "Confirm changes")}
            cancelText={l("取消", "Cancel")}
            onConfirm={execute}
          >
            <Button type="primary" danger={rows.some((row) => row.change.action === "delete")} loading={busy}>
              {l("执行变更", "Apply changes")}
            </Button>
          </Popconfirm>
        )}
      </Space>
    </Card>
  );
}
