import { useState } from "react";
import { Alert, Table } from "antd";

import { unwrapErrMsg } from "@/utils/error";
import { type Action, type Page, actions, states, useLabel, useResource } from "./order";

interface Event {
  id: number;
  action: string;
  state: string;
  success: boolean;
  created: number;
}

export default function OrderHistory({ orderId }: { orderId: string }) {
  const label = useLabel();
  const [page, setPage] = useState(1);
  const events = useResource<Page<Event>>("/orders/" + encodeURIComponent(orderId) + "/events?page=" + page);
  if (events.error) return <Alert type="error" showIcon title={unwrapErrMsg(events.error)} />;
  return (
    <Table<Event>
      size="small"
      loading={events.loading}
      rowKey="id"
      dataSource={events.data?.items ?? []}
      pagination={{ current: page, total: events.data?.total ?? 0, pageSize: 20, hideOnSinglePage: true, onChange: setPage, showSizeChanger: false }}
      locale={{ emptyText: label("No order activity", "暂无操作记录") }}
      columns={[
        { title: label("Time", "时间"), dataIndex: "created", render: (v: number) => new Date(v * 1000).toLocaleString() },
        { title: label("Operation", "操作"), dataIndex: "action", render: (v: string) => (Object.hasOwn(actions, v) ? label(...actions[v as Action]) : v) },
        { title: label("Status", "状态"), dataIndex: "state", render: (v: string) => (states[v] ? label(...states[v]) : v) },
        { title: label("Result", "结果"), dataIndex: "success", render: (ok: boolean) => (ok ? label("Succeeded", "成功") : label("Failed", "失败")) },
      ]}
    />
  );
}
