import { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Alert, App, Button, Empty, Space, Table, Tag, Typography } from "antd";
import { ClientResponseError } from "pocketbase";

import { unwrapErrMsg } from "@/utils/error";
import DraftForm, { type FormValues } from "./DraftForm";
import OrderHistory from "./OrderHistory";
import OrderNotification from "./OrderNotification";
import RenewalSettings from "./RenewalSettings";
import OrderActionDialog from "./OrderActionDialog";
import { type Account, type Action, type Order, type Page, actions, providers, request, states, useLabel, useResource } from "./order";

export default function CertificateOrders() {
  const label = useLabel();
  const { message } = App.useApp();
  const [page, setPage] = useState(1);
  const accounts = useResource<{ items: Account[] }>("/accounts");
  const orders = useResource<Page<Order>>("/orders?page=" + page);
  const [editing, setEditing] = useState<Order & { request: Omit<FormValues, "accessId"> }>();
  const [draftOpen, setDraftOpen] = useState(false);
  const [dialog, setDialog] = useState<{ action: Exclude<Action, "refresh" | "edit">; order: Order }>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const running = useRef(false);
  const matchingAccounts = (accounts.data?.items ?? []).filter((a) => Object.hasOwn(providers, a.provider));
  const accountName = (order: Order) => matchingAccounts.find((a) => a.id === order.accessId)?.name ?? order.accessId;
  const refresh = () => {
    accounts.refresh();
    orders.refresh();
  };

  async function run(order: Order, action: Action, fields: { remoteId?: string; zoneId?: string } = {}) {
    if (running.current) return;
    running.current = true;
    setBusy(order.id);
    setError("");
    try {
      await request<Order>("/orders/" + encodeURIComponent(order.id) + "/" + action, { version: order.version, ...fields });
      message.success(label("Order updated", "订单已更新"));
      setDialog(undefined);
    } catch (err) {
      if (err instanceof ClientResponseError && err.status === 409) {
        message.warning(label("The order changed. Check its latest status before trying again.", "订单状态已变化，请核对最新状态后重试。"));
        setDialog(undefined);
      } else {
        setError(unwrapErrMsg(err));
      }
    } finally {
      orders.refresh();
      running.current = false;
      setBusy("");
    }
  }

  async function choose(order: Order, action: Action) {
    setError("");
    if (action === "edit") {
      if (running.current) return;
      running.current = true;
      setBusy(order.id);
      try {
        const draft = await request<Order & { request?: Omit<FormValues, "accessId"> }>("/orders/" + encodeURIComponent(order.id));
        if (draft.state === "draft" && draft.request) {
          setEditing({ ...draft, request: draft.request });
          setDraftOpen(true);
        } else {
          orders.refresh();
          message.warning(label("The order changed. Check its latest status.", "订单状态已变化，请核对最新状态。"));
        }
      } catch (err) {
        setError(unwrapErrMsg(err));
      } finally {
        running.current = false;
        setBusy("");
      }
    } else if (action === "refresh") void run(order, action);
    else setDialog({ order, action });
  }

  function details(order: Order) {
    const challenges = order.challenges ?? [];
    return (
      <Space orientation="vertical" className="w-full">
        <Typography.Text type="secondary">
          {label("Local order ID", "本地订单 ID")} · {order.id}
        </Typography.Text>
        {order.remoteId && (
          <Typography.Text type="secondary">
            {label("Provider order ID", "云端订单 ID")} · <Typography.Text copyable>{order.remoteId}</Typography.Text>
          </Typography.Text>
        )}
        {challenges.length > 0 && (
          <>
            <Typography.Text strong>{label("DNS validation records", "DNS 验证记录")}</Typography.Text>
            <Table
              size="small"
              pagination={false}
              rowKey={(r) => JSON.stringify([r.type, r.name, r.value])}
              dataSource={challenges}
              columns={[
                { title: label("Type", "类型"), dataIndex: "type", width: 85 },
                {
                  title: label("Record name", "记录名称"),
                  dataIndex: "name",
                  render: (v: string) => (
                    <Typography.Text className="break-all" copyable>
                      {v}
                    </Typography.Text>
                  ),
                },
                {
                  title: label("Value", "记录值"),
                  dataIndex: "value",
                  render: (v: string) => (
                    <Typography.Text className="break-all" copyable>
                      {v}
                    </Typography.Text>
                  ),
                },
              ]}
            />
            <Link to="/dns">{label("Manage DNS records", "管理 DNS 记录")}</Link>
          </>
        )}
        <OrderHistory key={order.id + "-" + order.version} orderId={order.id} />
        <OrderNotification orderId={order.id} />
        {order.certificateId && <RenewalSettings key={order.id} order={order} />}
        {order.certificateId && (
          <Link to={"/certificates?keyword=" + encodeURIComponent(order.certificateId)}>{label("View or download certificate", "查看或下载证书")}</Link>
        )}
      </Space>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <Typography.Title level={2} style={{ margin: 0 }}>
        {label("Certificate orders", "商业 CA 证书订单")}
      </Typography.Title>
      <Space wrap>
        <Button
          type="primary"
          onClick={() => {
            setEditing(undefined);
            setDraftOpen(true);
          }}
          disabled={accounts.loading || !matchingAccounts.length}
        >
          {label("New order", "新建订单")}
        </Button>
        <Button onClick={refresh} loading={orders.loading || accounts.loading}>
          {label("Refresh list", "刷新列表")}
        </Button>
        <Link to="/accesses">{label("Access credentials", "授权账号")}</Link>
        <Link to="/certificates">{label("Certificate inventory", "证书库")}</Link>
        <Link to="/workflows">{label("Deployment workflows", "部署工作流")}</Link>
      </Space>
      {!accounts.loading && !accounts.error && !matchingAccounts.length && (
        <Alert
          type="info"
          showIcon
          title={label(
            "Add an Alibaba Cloud, Tencent Cloud or UCloud account in Access credentials to create an order.",
            "请在授权账号中添加阿里云、腾讯云或优刻得账号后创建订单。"
          )}
        />
      )}
      {accounts.error && <Alert type="error" showIcon title={unwrapErrMsg(accounts.error)} />}
      {orders.error && <Alert type="error" showIcon title={unwrapErrMsg(orders.error)} />}
      {error && !dialog && <Alert type="error" showIcon title={error} />}
      <Table<Order>
        rowKey="id"
        dataSource={orders.data?.items ?? []}
        loading={orders.loading}
        scroll={{ x: 800 }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={label("No certificate orders", "暂无证书订单")} /> }}
        pagination={{ current: page, pageSize: 20, showSizeChanger: false, total: orders.data?.total ?? 0, onChange: setPage }}
        expandable={{ expandedRowRender: details }}
        columns={[
          {
            title: label("Domain", "域名"),
            dataIndex: "domain",
            render: (v: string) => (
              <Typography.Text strong className="break-all">
                {v}
              </Typography.Text>
            ),
          },
          {
            title: label("Issuer account", "签发账号"),
            render: (_, r) => (
              <Space orientation="vertical" size={0}>
                {accountName(r)}
                <Typography.Text type="secondary">
                  {providers[r.provider as keyof typeof providers] ? label(...providers[r.provider as keyof typeof providers]) : r.provider}
                </Typography.Text>
              </Space>
            ),
          },
          { title: label("Algorithm", "算法"), dataIndex: "algorithm" },
          { title: label("Status", "状态"), dataIndex: "state", render: (v: string) => <Tag>{states[v] ? label(...states[v]) : v}</Tag> },
          {
            title: label("Actions", "操作"),
            render: (_, r) => (
              <Space wrap size="small">
                {(r.allowedActions ?? [])
                  .filter((a) => Object.hasOwn(actions, a))
                  .map((a) => (
                    <Button
                      key={a}
                      size="small"
                      danger={a === "revoke" || a === "cancel" || a === "delete"}
                      disabled={!!busy || orders.loading || !!orders.error}
                      onClick={() => choose(r, a)}
                    >
                      {label(...actions[a])}
                    </Button>
                  ))}
                {r.certificateId && <Link to={"/certificates?keyword=" + encodeURIComponent(r.certificateId)}>{label("View certificate", "查看证书")}</Link>}
              </Space>
            ),
          },
        ]}
      />
      {draftOpen && (
        <DraftForm
          draft={editing}
          accounts={matchingAccounts}
          close={() => setDraftOpen(false)}
          saved={() => {
            setDraftOpen(false);
            if (editing) orders.refresh();
            else {
              setPage(1);
              if (page === 1) orders.refresh();
            }
          }}
        />
      )}
      {dialog && (
        <OrderActionDialog
          order={dialog.order}
          action={dialog.action}
          error={error}
          busy={!!busy}
          close={() => {
            if (!running.current) {
              setDialog(undefined);
              setError("");
            }
          }}
          run={(fields) => void run(dialog.order, dialog.action, fields)}
        />
      )}
    </div>
  );
}
