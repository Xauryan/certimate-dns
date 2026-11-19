import { useState } from "react";
import { Alert, Button, Select, Space, Typography } from "antd";

import { type ResourceLink, useCatalog } from "@/pages/dnscatalog/catalog";
import { getPocketBase } from "@/repository/_pocketbase";
import { unwrapErrMsg } from "@/utils/error";

import { useLabel, useResource } from "./order";

const statuses: Record<string, [string, string]> = {
  pending: ["Queued", "等待发送"],
  sending: ["Sending", "正在发送"],
  retrying: ["Waiting to retry", "等待重试"],
  failed: ["Failed", "发送失败"],
  accepted: ["Accepted by provider", "服务商已受理"],
  cancelled: ["Cancelled", "已取消"],
};

export default function OrderNotification({ orderId }: { orderId: string }) {
  const label = useLabel();
  const path = "/orders/" + encodeURIComponent(orderId) + "/notification";
  const settings = useResource<{ accessId: string; status: string }>(path);
  const channels = useCatalog<ResourceLink[]>("/notification-channels", 0);
  const [change, setChange] = useState<string>();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function save() {
    if (change === undefined || saving) return;
    setSaving(true);
    setError("");
    try {
      await getPocketBase().send("/api/dnscert" + path, { method: "PUT", body: { accessId: change }, requestKey: null });
      await settings.refreshAsync();
      setChange(undefined);
    } catch (err) {
      setError(unwrapErrMsg(err));
    } finally {
      setSaving(false);
    }
  }

  const status = settings.data?.status;
  return (
    <Space orientation="vertical">
      <Space wrap>
        <Typography.Text>{label("Order notification channel", "订单通知渠道")}</Typography.Text>
        <Select
          aria-label={label("Order notification channel", "订单通知渠道")}
          style={{ minWidth: 160 }}
          disabled={saving || !settings.data}
          value={change ?? settings.data?.accessId}
          onChange={setChange}
          options={[{ value: "", label: label("Off", "关闭") }, ...(channels?.data ?? []).map((item) => ({ value: item.id, label: item.name }))]}
        />
        <Button onClick={save} loading={saving} disabled={change === undefined || change === settings.data?.accessId}>
          {label("Save", "保存")}
        </Button>
        {status && (
          <Typography.Text type="secondary">
            {label("Last delivery", "最近发送")} · {statuses[status] ? label(...statuses[status]) : status}
          </Typography.Text>
        )}
      </Space>
      {(error || settings.error || channels?.error) && <Alert showIcon type="error" title={error || channels?.error || unwrapErrMsg(settings.error)} />}
    </Space>
  );
}
