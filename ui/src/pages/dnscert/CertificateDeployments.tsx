import { type Key, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Alert, App, Button, Collapse, Dropdown, Form, Input, Select, Space, Table, Tag, Typography } from "antd";

import {
  type BatchAction,
  type Deployment,
  type DeploymentChange,
  type SingleAction,
  actionLabels,
  deploymentRequest,
  deploymentStatus,
  formatDeploymentTime,
  pageSize,
  statusLabels,
  useDeploymentError,
  useDeploymentResource,
} from "./deployment";
import DeploymentDetails, { DeploymentPolicy, DeploymentStatus } from "./DeploymentDetails";
import { DeploymentActionDialog, DeploymentEditor } from "./DeploymentDialogs";
import { type Page, useLabel } from "./order";

const filterNames = ["q", "status", "orderId", "accessId", "domain", "remark", "provider"] as const;
type Filters = Partial<Record<(typeof filterNames)[number], string>>;
type Dialog = { kind: "editor"; task?: Deployment } | { kind: "action"; action: SingleAction | BatchAction; tasks: Deployment[]; batch: boolean };

function DeploymentFilters({ filters, apply }: { filters: Filters; apply: (filters: Filters) => void }) {
  const label = useLabel();
  const [form] = Form.useForm<Filters>();
  const fields = [
    { name: "domain", label: label("Domain", "域名") },
    { name: "remark", label: label("Remark", "备注") },
    { name: "orderId", label: label("Order ID", "订单 ID") },
    { name: "accessId", label: label("Deployment account ID", "部署账号 ID") },
    { name: "provider", label: label("Provider identifier", "服务商标识") },
  ];
  const maxLengthRule = {
    validator: (_: unknown, value?: string) =>
      new TextEncoder().encode(value ?? "").length <= 256 ? Promise.resolve() : Promise.reject(new Error(label("Use at most 256 bytes.", "最多 256 字节。"))),
  };
  return (
    <Form form={form} layout="vertical" initialValues={filters} onFinish={apply}>
      <div className="grid items-start gap-x-4 sm:grid-cols-[minmax(0,1fr)_12rem_auto]">
        <Form.Item name="q" label={label("Search deployments", "搜索部署任务")} rules={[maxLengthRule]}>
          <Input allowClear maxLength={256} placeholder={label("Domain, remark, account or workflow", "域名、备注、账号或工作流")} />
        </Form.Item>
        <Form.Item name="status" label={label("Deployment status", "部署状态")}>
          <Select
            allowClear
            placeholder={label("All statuses", "全部状态")}
            options={[
              { value: "0", label: label("Pending or in progress", "待部署或部署中") },
              { value: "1", label: label(...statusLabels.succeeded) },
              { value: "-1", label: label("Failed", "失败") },
            ]}
          />
        </Form.Item>
        <Space className="sm:mt-8" wrap>
          <Button type="primary" htmlType="submit">
            {label("Apply filters", "应用筛选")}
          </Button>
          <Button
            onClick={() => {
              form.resetFields();
              apply({});
            }}
          >
            {label("Clear filters", "清除筛选")}
          </Button>
        </Space>
      </div>
      <Collapse
        ghost
        defaultActiveKey={fields.some(({ name }) => filters[name as keyof Filters]) ? ["advanced"] : []}
        items={[
          {
            key: "advanced",
            label: label("More filters", "更多筛选条件"),
            children: (
              <div className="grid gap-x-4 sm:grid-cols-2 lg:grid-cols-3">
                {fields.map((field) => (
                  <Form.Item key={field.name} name={field.name} label={field.label} rules={[maxLengthRule]}>
                    <Input allowClear maxLength={256} />
                  </Form.Item>
                ))}
              </div>
            ),
          },
        ]}
      />
    </Form>
  );
}

export default function CertificateDeployments() {
  const label = useLabel();
  const describeError = useDeploymentError();
  const { message } = App.useApp();
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = Object.fromEntries(
    filterNames.flatMap((name) => {
      const value = searchParams.get(name)?.trim();
      return value ? [[name, value]] : [];
    })
  ) as Filters;
  if (filters.status && !["0", "1", "-1"].includes(filters.status)) delete filters.status;
  const rawPage = Number(searchParams.get("page"));
  const page = Number.isInteger(rawPage) && rawPage > 0 && rawPage <= 1_000_000 ? rawPage : 1;
  const params = new URLSearchParams(filters);
  const filterKey = params.toString();
  params.set("page", String(page));
  const list = useDeploymentResource<Page<Deployment>>("?" + params);
  const [selection, setSelection] = useState<{ key: string; ids: Key[] }>({ key: "", ids: [] });
  const [detailId, setDetailId] = useState("");
  const [dialog, setDialog] = useState<Dialog>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const running = useRef(false);
  const items = list.data?.items ?? [];
  const selectedIds = selection.key === params.toString() ? selection.ids : [];
  const selected = items.filter((task) => selectedIds.includes(task.id));
  const disabled = busy || list.loading || !!list.error || !list.data;

  async function send(change: DeploymentChange) {
    if (running.current) return;
    running.current = true;
    setBusy(true);
    setError("");
    try {
      await deploymentRequest(change.path, change.method, change.body);
      message.success(label("Deployment tasks updated.", "部署任务已更新。"));
    } catch (err) {
      setError(describeError(err));
    } finally {
      setDialog(undefined);
      setSelection({ key: "", ids: [] });
      list.refresh();
      running.current = false;
      setBusy(false);
    }
  }

  function apply(filters: Filters, page = 1) {
    const next = new URLSearchParams();
    for (const name of filterNames) {
      const value = filters[name]?.trim();
      if (value) next.set(name, value);
    }
    if (page > 1) next.set("page", String(page));
    setSearchParams(next);
    setSelection({ key: "", ids: [] });
    setError("");
  }

  const chosenRunning = selected.some((task) => deploymentStatus(task) === "running");
  const chosenUnfinished = selected.some((task) => task.started && !task.finished);
  const batchActions: { key: BatchAction; disabled?: boolean; danger?: boolean }[] = [
    { key: "enable", disabled: chosenUnfinished || selected.every((task) => task.active) },
    { key: "pause", disabled: chosenUnfinished || selected.every((task) => !task.active) },
    { key: "reset", disabled: chosenRunning },
    { key: "rebind", disabled: selected.some((task) => task.started && (task.status !== 1 || !task.finished)) },
    { key: "delete", disabled: chosenUnfinished, danger: true },
  ];

  return (
    <main className="flex flex-col gap-4 p-4 md:p-6">
      <Typography.Title level={2} style={{ margin: 0 }}>
        {label("Certificate deployments", "证书部署任务")}
      </Typography.Title>
      <Space wrap>
        <Button type="primary" disabled={busy} onClick={() => setDialog({ kind: "editor" })}>
          {label("New task", "新建任务")}
        </Button>
        <Dropdown
          trigger={["click"]}
          disabled={disabled || selected.length === 0}
          menu={{
            items: batchActions.map((item) => ({ ...item, label: label(...actionLabels[item.key]) })),
            onClick: ({ key }) => setDialog({ kind: "action", action: key as BatchAction, tasks: selected, batch: true }),
          }}
        >
          <Button>
            {label("Batch actions", "批量操作")}
            {selected.length > 0 && " (" + selected.length + ")"}
          </Button>
        </Dropdown>
        <Button disabled={busy} loading={list.loading} onClick={list.refresh}>
          {label("Refresh list", "刷新列表")}
        </Button>
        <Link to="/dns-cert">{label("Certificate orders", "证书订单")}</Link>
        <Link to="/workflows">{label("Deployment workflows", "部署工作流")}</Link>
      </Space>
      <DeploymentFilters key={filterKey} filters={filters} apply={apply} />
      {error && <Alert type="error" showIcon title={error} />}
      {list.error && <Alert type="error" showIcon title={describeError(list.error)} />}
      <Table<Deployment>
        rowKey="id"
        rowSelection={{
          selectedRowKeys: selectedIds,
          onChange: (ids) => setSelection({ key: params.toString(), ids }),
          getCheckboxProps: () => ({ disabled }),
        }}
        dataSource={items}
        loading={list.loading}
        scroll={{ x: 960 }}
        locale={{ emptyText: label("No deployment tasks match these filters", "没有符合筛选条件的部署任务") }}
        pagination={{
          current: page,
          pageSize,
          total: list.data?.total ?? 0,
          showSizeChanger: false,
          onChange: (newPage) => apply(filters, newPage),
        }}
        columns={[
          {
            title: label("Domain and order", "域名与订单"),
            render: (_, task) => (
              <Space orientation="vertical" size={0} className="break-all">
                <Button type="link" style={{ height: "auto", padding: 0, whiteSpace: "normal", textAlign: "start" }} onClick={() => setDetailId(task.id)}>
                  {task.domain || task.orderId}
                </Button>
                {task.domain && <Typography.Text type="secondary">{task.orderId}</Typography.Text>}
              </Space>
            ),
          },
          {
            title: label("Published target", "已发布目标"),
            render: (_, task) => (
              <Space orientation="vertical" size={0} className="break-all">
                {task.workflowName || task.workflowId} · {task.nodeId}
                <Typography.Text type="secondary">{[task.accessName || task.accessId, task.provider].filter(Boolean).join(" · ")}</Typography.Text>
              </Space>
            ),
          },
          { title: label("Remark", "备注"), dataIndex: "remark", render: (value: string) => <span className="break-all">{value || "—"}</span> },
          {
            title: label("Status", "状态"),
            render: (_, task) => (
              <Space orientation="vertical" size={0}>
                <DeploymentStatus task={task} />
                <Tag color={task.active ? "green" : "default"}>{task.active ? label("Enabled", "已启用") : label("Paused", "已暂停")}</Tag>
              </Space>
            ),
          },
          { title: label("Policy", "部署策略"), render: (_, task) => <DeploymentPolicy task={task} /> },
          { title: label("Last attempt", "最近尝试"), render: (_, task) => formatDeploymentTime(task.finished || task.started) },
          {
            title: label("Actions", "操作"),
            render: (_, task) => {
              const unfinished = !!task.started && !task.finished;
              const status = deploymentStatus(task);
              const canDeploy = task.active && task.orderState === "issued" && (status === "pending" || status === "succeeded");
              const actions: { key: SingleAction; danger?: boolean }[] = [
                { key: task.active ? "pause" : "enable" },
                { key: "reset" },
                { key: "delete", danger: true },
              ];
              return (
                <Space wrap>
                  <Button
                    size="small"
                    disabled={disabled || !canDeploy}
                    onClick={() => setDialog({ kind: "action", action: "process", tasks: [task], batch: false })}
                  >
                    {status === "succeeded" ? label("Deploy again", "再次部署") : label(...actionLabels.process)}
                  </Button>
                  <Dropdown
                    trigger={["click"]}
                    disabled={disabled}
                    menu={{
                      items: [
                        { key: "edit", label: label("Edit", "编辑"), disabled: unfinished },
                        ...actions.map((item) => ({
                          ...item,
                          label: label(...actionLabels[item.key]),
                          disabled: item.key === "reset" ? status === "running" : unfinished,
                        })),
                      ],
                      onClick: ({ key }) =>
                        setDialog(key === "edit" ? { kind: "editor", task } : { kind: "action", action: key as SingleAction, tasks: [task], batch: false }),
                    }}
                  >
                    <Button size="small" aria-label={label("Task actions", "任务操作")}>
                      {label("More", "更多")}
                    </Button>
                  </Dropdown>
                </Space>
              );
            },
          },
        ]}
      />
      {detailId && <DeploymentDetails key={detailId} id={detailId} close={() => setDetailId("")} />}
      {dialog?.kind === "editor" && (
        <DeploymentEditor task={dialog.task} orderId={filters.orderId ?? ""} busy={busy} close={() => setDialog(undefined)} send={send} />
      )}
      {dialog?.kind === "action" && <DeploymentActionDialog {...dialog} busy={busy} close={() => setDialog(undefined)} send={send} />}
    </main>
  );
}
