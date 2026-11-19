import { useState } from "react";
import { Alert, Button, Descriptions, Drawer, Space, Spin, Table, Tag, Typography } from "antd";

import {
  type Deployment,
  type DeploymentAttempt,
  deploymentPath,
  deploymentStatus,
  formatDeploymentTime,
  pageSize,
  statusLabels,
  useDeploymentError,
  useDeploymentResource,
} from "./deployment";
import { type Page, states, useLabel } from "./order";

const statusColors = { pending: "default", running: "processing", succeeded: "success", reconcile: "warning" };

export function DeploymentStatus({ task }: { task: Deployment }) {
  const label = useLabel();
  const status = deploymentStatus(task);
  return <Tag color={statusColors[status]}>{label(...statusLabels[status])}</Tag>;
}

export function DeploymentPolicy({ task }: { task: Deployment }) {
  const label = useLabel();
  return (
    <Space orientation="vertical" size={0}>
      {!task.automatic && label("Manual", "手动部署")}
      {task.automatic && (
        <Tag color={task.policyCurrent ? "blue" : "warning"}>
          {task.policyCurrent ? label("Automatic", "自动部署") : label("Review approval", "待重新授权")}
        </Tag>
      )}
      {task.followRenewal && <Typography.Text type="secondary">{label("Follows renewal", "跟随续期")}</Typography.Text>}
    </Space>
  );
}

export default function DeploymentDetails({ id, close }: { id: string; close: () => void }) {
  const label = useLabel();
  const describeError = useDeploymentError();
  const [page, setPage] = useState(1);
  const detail = useDeploymentResource<Deployment>(deploymentPath(id));
  const logs = useDeploymentResource<Page<DeploymentAttempt>>(deploymentPath(id) + "/logs?page=" + page, !!detail.data);
  const task = detail.data;
  const blocked = task?.result === "Deployment stopped before sending certificate material";
  const detailRows = task
    ? [
        [label("Task ID", "任务 ID"), task.id],
        [label("Order ID", "订单 ID"), task.orderId],
        [label("Order status", "订单状态"), Object.hasOwn(states, task.orderState) ? label(...states[task.orderState]) : task.orderState || "—"],
        [label("Provider", "服务商"), task.provider || "—"],
        [label("Deployment account", "部署账号"), task.accessName ? task.accessName + " · " + task.accessId : task.accessId],
        [label("Workflow", "工作流"), task.workflowName ? task.workflowName + " · " + task.workflowId : task.workflowId],
        [label("Node", "节点"), task.nodeId],
        [label("State", "启用状态"), task.active ? label("Enabled", "已启用") : label("Paused", "已暂停")],
        [label("Status", "部署结果"), <DeploymentStatus task={task} />],
        [label("Policy", "部署策略"), <DeploymentPolicy task={task} />],
        [label("Remark", "备注"), task.remark || "—"],
        [label("Created", "创建时间"), formatDeploymentTime(task.created)],
        [label("Last attempt ID", "最近尝试 ID"), task.processId || "—"],
        [label("Started", "开始时间"), formatDeploymentTime(task.started)],
        [label("Finished", "结束时间"), formatDeploymentTime(task.finished)],
      ]
    : [];
  const outcomes: Record<string, [string, string]> = {
    claimed: ["Started", "已开始"],
    completed: ["Completed", "已完成"],
    blocked: ["Blocked", "已拦截"],
    needs_reconciliation: ["Needs reconciliation", "待核对目标"],
  };
  const triggers: Record<string, [string, string]> = {
    admin: ["Administrator", "管理员"],
    interface: ["Interface key", "接口密钥"],
    schedule: ["Schedule", "计划任务"],
  };

  return (
    <Drawer
      open
      size="large"
      title={task?.domain ? label("Deployment details", "部署详情") + " · " + task.domain : label("Deployment details", "部署详情")}
      onClose={close}
      extra={
        <Button
          loading={detail.loading || logs.loading}
          onClick={() => {
            detail.refresh();
            if (task) logs.refresh();
          }}
        >
          {label("Refresh details", "刷新详情")}
        </Button>
      }
    >
      <Space orientation="vertical" size="middle" className="w-full">
        {detail.loading && !task && <Spin />}
        {detail.error && <Alert type="error" showIcon title={describeError(detail.error)} />}
        {task && (
          <>
            <Descriptions
              column={1}
              size="small"
              bordered
              items={detailRows.map(([name, value]) => ({ key: String(name), label: name, children: <span className="break-all">{value}</span> }))}
            />
            {blocked && <Alert type="warning" showIcon title={label("Deployment stopped before sending the certificate.", "部署已在发送证书前停止。")} />}
            {!blocked && deploymentStatus(task) === "reconcile" && (
              <Alert
                type="warning"
                showIcon
                title={label("Check the deployment target before resetting this task.", "重置任务前请核对部署目标。")}
                description={label(
                  "A previous attempt may have changed the destination even though completion could not be confirmed.",
                  "上一次尝试可能已修改部署目标，但系统无法确认部署是否完成。"
                )}
              />
            )}
            <Typography.Title level={4}>{label("Deployment attempts", "部署尝试记录")}</Typography.Title>
            {logs.error && <Alert type="error" showIcon title={describeError(logs.error)} />}
            <Table<DeploymentAttempt>
              size="small"
              rowKey="id"
              loading={logs.loading}
              dataSource={logs.data?.items ?? []}
              scroll={{ x: 690 }}
              locale={{ emptyText: label("No recorded attempts", "暂无部署尝试记录") }}
              pagination={{ current: page, pageSize, total: logs.data?.total ?? 0, showSizeChanger: false, onChange: setPage }}
              columns={[
                { title: label("Attempt ID", "尝试 ID"), dataIndex: "id" },
                {
                  title: label("Order and target", "订单与目标"),
                  render: (_, row) => (
                    <Space orientation="vertical" size={0} className="break-all">
                      {row.domain || row.orderId}
                      {row.certificateId && (
                        <Typography.Text type="secondary">
                          {label("Certificate ID", "证书 ID")} · {row.certificateId}
                        </Typography.Text>
                      )}
                      <Typography.Text type="secondary">{[row.provider, row.accessId, row.workflowId, row.nodeId].filter(Boolean).join(" · ")}</Typography.Text>
                    </Space>
                  ),
                },
                {
                  title: label("Trigger", "触发来源"),
                  dataIndex: "trigger",
                  render: (value: string) => (Object.hasOwn(triggers, value) ? label(...triggers[value]) : "—"),
                },
                {
                  title: label("Outcome", "结果"),
                  dataIndex: "outcome",
                  render: (value: string) => (Object.hasOwn(outcomes, value) ? label(...outcomes[value]) : "—"),
                },
                { title: label("Started", "开始时间"), dataIndex: "started", render: formatDeploymentTime },
                { title: label("Finished", "结束时间"), dataIndex: "finished", render: formatDeploymentTime },
              ]}
            />
          </>
        )}
      </Space>
    </Drawer>
  );
}
