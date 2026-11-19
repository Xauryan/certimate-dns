import { Alert, Checkbox, Form, Input, Modal, Space, Typography } from "antd";

import ZoneField from "./ZoneField";
import { type Action, type Order, actions, confirmations, useLabel } from "./order";

interface ExtraFields {
  remoteId?: string;
  zoneId?: string;
  confirmUnbound?: boolean;
}

export default function OrderActionDialog({
  order,
  action,
  busy,
  error,
  close,
  run,
}: {
  order: Order;
  action: Exclude<Action, "refresh" | "edit">;
  busy: boolean;
  error?: string;
  close: () => void;
  run: (fields: ExtraFields) => void;
}) {
  const label = useLabel();
  const [form] = Form.useForm<ExtraFields>();
  return (
    <Modal
      open
      title={label(...actions[action])}
      onCancel={close}
      okText={label(...actions[action])}
      okButtonProps={{ danger: action === "revoke" || action === "cancel" || action === "delete", disabled: busy }}
      confirmLoading={busy}
      onOk={() => form.submit()}
      closable={!busy}
      keyboard={!busy}
      mask={{ closable: !busy }}
      cancelButtonProps={{ disabled: busy }}
    >
      <Space orientation="vertical" className="w-full">
        <Typography.Text strong>{order.domain}</Typography.Text>
        <Typography.Text>{label(...confirmations[action])}</Typography.Text>
        {error && <Alert type="error" showIcon title={error} />}
        <Form form={form} disabled={busy} layout="vertical" onFinish={run}>
          {action === "recover" && (
            <Form.Item name="remoteId" label={label("Provider order ID", "云端订单 ID")} rules={[{ required: true, whitespace: true }]}>
              <Input autoComplete="off" maxLength={255} />
            </Form.Item>
          )}
          {action === "recover" && order.provider === "ucloud" && (
            <Form.Item name="confirmUnbound" valuePropName="checked">
              <Checkbox>
                {label("I verified that this unbound UCloud free-plan instance belongs to this order.", "我已核对这个尚未绑定域名的优刻得免费实例属于此订单。")}
              </Checkbox>
            </Form.Item>
          )}
          {action === "present" && (
            <Form.Item name="zoneId" label={label("DNS zone", "DNS 区域")} rules={[{ required: true }]}>
              <ZoneField orderId={order.id} />
            </Form.Item>
          )}
        </Form>
      </Space>
    </Modal>
  );
}
