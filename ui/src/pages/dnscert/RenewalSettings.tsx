import { useRef, useState } from "react";
import { Alert, Button, Checkbox, Form, Modal, Space, Typography } from "antd";

import { unwrapErrMsg } from "@/utils/error";
import ZoneField from "./ZoneField";
import { type Order, request, useLabel, useResource } from "./order";

type Renewal = {
  enabled: boolean;
  version: number;
  zoneId?: string;
  status: string;
  nextAt?: number;
  pendingOrderId?: string;
};
type Fields = { zoneId: string; confirmQuota?: boolean };

const statuses = {
  scheduled: ["Scheduled", "已安排续期"],
  processing: ["Processing", "正在续期"],
  retry: ["Retry scheduled", "等待重试"],
  disabled: ["Disabled", "已停用"],
  needs_review: ["Review the order", "订单需要人工核对"],
} satisfies Record<string, [string, string]>;

function RenewalForm({ order, policy, close, save }: { order: Order; policy: Renewal; close: () => void; save: (fields: Fields) => Promise<void> }) {
  const label = useLabel();
  const [form] = Form.useForm<Fields>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const running = useRef(false);
  async function submit(fields: Fields) {
    if (running.current) return;
    running.current = true;
    setBusy(true);
    setError("");
    try {
      await save(fields);
      close();
    } catch (err) {
      setError(unwrapErrMsg(err));
    } finally {
      running.current = false;
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      title={label("Automatic renewal", "自动续期")}
      onCancel={close}
      onOk={() => form.submit()}
      confirmLoading={busy}
      closable={!busy}
      keyboard={!busy}
      mask={{ closable: !busy }}
      cancelButtonProps={{ disabled: busy }}
    >
      {error && <Alert type="error" showIcon title={error} />}
      <Form form={form} layout="vertical" disabled={busy} onFinish={submit} initialValues={{ zoneId: policy.zoneId || undefined }}>
        <Form.Item label={label("DNS zone for validation", "域名验证 DNS 区域")} name="zoneId" rules={[{ required: true }]}>
          <ZoneField orderId={order.id} />
        </Form.Item>
        <Form.Item
          name="confirmQuota"
          valuePropName="checked"
          rules={[
            {
              validator: (_, v) =>
                v ? Promise.resolve() : Promise.reject(new Error(label("Confirm quota use to enable renewal.", "请确认允许使用证书额度。"))),
            },
          ]}
        >
          <Checkbox>
            {label(
              "Allow automatic orders for this domain using this issuer account and its certificate quota, starting 15 days before expiration.",
              "允许从证书到期前 15 天起，使用该签发账号及证书额度为此域名自动下新订单。"
            )}
          </Checkbox>
        </Form.Item>
      </Form>
    </Modal>
  );
}

export default function RenewalSettings({ order }: { order: Order }) {
  const label = useLabel();
  const path = "/orders/" + encodeURIComponent(order.id) + "/renewal";
  const policy = useResource<Renewal>(path);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const running = useRef(false);
  const p = policy.data;

  async function save(fields?: Fields) {
    if (!p || running.current) return;
    running.current = true;
    setBusy(true);
    setError("");
    try {
      const updated = await request<Renewal>(path, { version: p.version, enabled: !!fields, ...fields });
      policy.mutate(updated);
    } catch (err) {
      policy.refresh();
      throw err;
    } finally {
      running.current = false;
      setBusy(false);
    }
  }

  if (policy.error) return <Alert type="error" showIcon title={unwrapErrMsg(policy.error)} />;
  if (!p) return null;
  return (
    <Space wrap>
      <Typography.Text>
        {label("Automatic renewal", "自动续期")} · {Object.hasOwn(statuses, p.status) ? label(...statuses[p.status as keyof typeof statuses]) : p.status}
      </Typography.Text>
      {!!p.nextAt && (
        <Typography.Text>
          {label("Next check", "下次检查")} · {new Date(p.nextAt * 1000).toLocaleString()}
        </Typography.Text>
      )}
      {p.pendingOrderId && <Typography.Text copyable>{p.pendingOrderId}</Typography.Text>}
      {(p.enabled || order.state === "issued") && (
        <Button size="small" disabled={busy || policy.loading} onClick={() => setOpen(true)}>
          {p.enabled ? label("Configure renewal", "配置续期") : label("Enable renewal", "启用续期")}
        </Button>
      )}
      {p.enabled && (
        <Button
          size="small"
          disabled={busy || policy.loading}
          onClick={() => {
            void save().catch((err) => setError(unwrapErrMsg(err)));
          }}
        >
          {label("Disable renewal", "停用续期")}
        </Button>
      )}
      {error && <Alert type="error" showIcon title={error} />}
      {open && <RenewalForm key={p.version} order={order} policy={p} close={() => setOpen(false)} save={save} />}
    </Space>
  );
}
