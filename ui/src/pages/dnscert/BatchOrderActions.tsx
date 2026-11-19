import { useEffect, useRef, useState } from "react";
import { Alert, Button, Checkbox, Dropdown, Modal, Space, Table, Typography } from "antd";

import { unwrapErrMsg } from "@/utils/error";
import ZoneField from "./ZoneField";
import { type Order, request, useLabel } from "./order";

const operations = {
  delete: ["Delete drafts", "删除草稿"],
  reset: ["Start new drafts", "重新申请"],
  open: ["Enable automatic renewal", "启用自动续期"],
  close: ["Disable automatic renewal", "停用自动续期"],
} as const;

type Operation = keyof typeof operations;
type Label = ReturnType<typeof useLabel>;
type Policy = { version: number; enabled: boolean; currentOrderId: string };
type Outcome = { ok: boolean; message: string };

function unavailable(o: Order, op: Operation, label: Label): string {
  if ((op === "reset" || op === "delete") && !o.allowedActions?.includes(op)) {
    return label("Unavailable in the current order state.", "当前订单状态不支持此操作。");
  }
  if (op === "open" && (!o.certificateId || !["issued", "expired"].includes(o.state))) {
    return label("Import the issued certificate before enabling renewal.", "请先将已签发的证书导入证书库。");
  }
  return "";
}

function BatchDialog({ orders, op, close }: { orders: Order[]; op: Operation; close: (completed: string[]) => void }) {
  const label = useLabel();
  const renewal = op === "open" || op === "close";
  const [policies, setPolicies] = useState<Record<string, Policy>>({});
  const [policyErrors, setPolicyErrors] = useState<Record<string, string>>({});
  const [zones, setZones] = useState<Record<string, string | undefined>>({});
  const [confirmed, setConfirmed] = useState(false);
  const [loading, setLoading] = useState(renewal);
  const [progress, setProgress] = useState<"ready" | "running" | "done">("ready");
  const [outcomes, setOutcomes] = useState<Record<string, Outcome>>({});
  const running = useRef(false);

  useEffect(() => {
    if (!renewal) return;
    let active = true;
    void Promise.all(
      orders.map(async (o) => {
        try {
          const policy = await request<Policy>("/orders/" + encodeURIComponent(o.id) + "/renewal");
          if (active) setPolicies((prev) => ({ ...prev, [o.id]: policy }));
        } catch (err) {
          if (active) setPolicyErrors((prev) => ({ ...prev, [o.id]: unwrapErrMsg(err) }));
        }
      })
    ).then(() => {
      if (active) setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [orders, renewal]);

  function satisfied(o: Order) {
    return renewal && policies[o.id]?.enabled === (op === "open");
  }

  function reason(o: Order) {
    return policyErrors[o.id] || (satisfied(o) ? "" : unavailable(o, op, label));
  }

  function renewalOrder(o: Order) {
    return policies[o.id]?.currentOrderId || o.id;
  }

  const renewalOrders = new Map<string, string>();
  if (op === "open") {
    for (const o of orders) {
      const id = renewalOrder(o);
      if (!reason(o) && !satisfied(o) && !renewalOrders.has(id)) renewalOrders.set(id, o.id);
    }
  }
  const enable = renewalOrders.size > 0;
  const needsZone = enable && Array.from(renewalOrders.keys()).some((id) => !zones[id]);
  const locked = progress !== "ready";

  async function apply() {
    if (running.current || locked || loading || needsZone || (enable && !confirmed)) return;
    running.current = true;
    setProgress("running");
    const renewalResults = new Map<string, Outcome>();
    for (const o of orders) {
      const blocked = reason(o);
      const currentOrderId = renewalOrder(o);
      const renewalResult = renewalResults.get(currentOrderId);
      let result: Outcome;
      if (blocked) {
        result = { ok: false, message: blocked };
      } else if (satisfied(o)) {
        result = { ok: true, message: label("Already set", "已是目标状态") };
      } else if (renewalResult) {
        result = renewalResult;
      } else {
        const path = "/orders/" + encodeURIComponent(o.id);
        try {
          if (renewal) {
            const policy = policies[o.id];
            if (!policy) throw new Error(label("Renewal settings unavailable", "无法读取续期设置"));
            await request(path + "/renewal", {
              version: policy.version,
              enabled: op === "open",
              ...(op === "open" ? { zoneId: zones[currentOrderId], confirmQuota: confirmed } : {}),
            });
          } else {
            await request(path + "/" + op, { version: o.version });
          }
          result = { ok: true, message: label("Succeeded", "成功") };
        } catch (err) {
          result = { ok: false, message: unwrapErrMsg(err) };
        }
        if (renewal) renewalResults.set(currentOrderId, result);
      }
      setOutcomes((prev) => ({ ...prev, [o.id]: result }));
    }
    setProgress("done");
    running.current = false;
  }

  function finish() {
    if (!running.current) close(Object.keys(outcomes).filter((id) => outcomes[id].ok));
  }

  return (
    <Modal
      open
      width={800}
      title={label(operations[op][0], operations[op][1])}
      onCancel={finish}
      closable={progress !== "running"}
      keyboard={progress !== "running"}
      mask={{ closable: false }}
      footer={
        <Space>
          <Button disabled={progress === "running"} onClick={finish}>
            {progress === "done" ? label("Close", "关闭") : label("Cancel", "取消")}
          </Button>
          {progress !== "done" && (
            <Button
              type="primary"
              danger={op === "delete"}
              loading={progress === "running"}
              disabled={loading || needsZone || (enable && !confirmed)}
              onClick={() => void apply()}
            >
              {label("Apply to selected orders", "应用到所选订单")}
            </Button>
          )}
        </Space>
      }
    >
      {op === "reset" && (
        <Alert
          showIcon
          type="info"
          title={label(
            "Each eligible order gets a new local draft. Submit each application separately.",
            "将为符合条件的订单新建本地草稿，签发申请需另行提交。"
          )}
        />
      )}
      <Table<Order>
        size="small"
        rowKey="id"
        pagination={false}
        loading={loading}
        dataSource={orders}
        scroll={{ x: 550, y: 420 }}
        columns={[
          {
            title: label("Order", "订单"),
            render: (_, o) => (
              <Space orientation="vertical" size={0}>
                <span>{o.domain}</span>
                <Typography.Text type="secondary">{o.id}</Typography.Text>
              </Space>
            ),
          },
          ...(op === "open"
            ? [
                {
                  title: label("DNS zone for validation", "域名验证 DNS 区域"),
                  render: (_: unknown, o: Order) => {
                    const id = renewalOrder(o);
                    return policies[o.id] && renewalOrders.get(id) === o.id ? (
                      <ZoneField orderId={id} disabled={locked} value={zones[id]} onChange={(v) => setZones((prev) => ({ ...prev, [id]: v }))} />
                    ) : null;
                  },
                },
              ]
            : []),
          {
            title: label("Status", "状态"),
            render: (_, o) => {
              const result = outcomes[o.id];
              const blocked = reason(o);
              return (
                <Typography.Text type={result ? (result.ok ? "success" : "danger") : blocked ? "warning" : undefined}>
                  {result?.message || blocked || (satisfied(o) ? label("Already set", "已是目标状态") : label("Pending", "待处理"))}
                </Typography.Text>
              );
            },
          },
        ]}
      />
      {enable && (
        <Checkbox disabled={locked} checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)}>
          {label(
            "Allow these issuer accounts to use certificate quota for automatic renewal starting 15 days before expiry.",
            "允许所选签发账号从证书到期前 15 天起使用证书额度自动续期。"
          )}
        </Checkbox>
      )}
    </Modal>
  );
}

export default function BatchOrderActions({ selected, disabled, finish }: { selected: Order[]; disabled: boolean; finish: (completed: string[]) => void }) {
  const label = useLabel();
  const [batch, setBatch] = useState<{ orders: Order[]; op: Operation }>();
  return (
    <>
      <Dropdown
        disabled={disabled || !selected.length}
        trigger={["click"]}
        menu={{
          items: (Object.keys(operations) as Operation[]).map((op) => ({
            key: op,
            label: label(operations[op][0], operations[op][1]),
            danger: op === "delete",
          })),
          onClick: ({ key }) => setBatch({ orders: selected, op: key as Operation }),
        }}
      >
        <Button disabled={disabled || !selected.length}>
          {label("Batch actions", "批量操作")}
          {selected.length ? ` (${selected.length})` : ""}
        </Button>
      </Dropdown>
      {batch && (
        <BatchDialog
          orders={batch.orders}
          op={batch.op}
          close={(completed) => {
            setBatch(undefined);
            finish(completed);
          }}
        />
      )}
    </>
  );
}
