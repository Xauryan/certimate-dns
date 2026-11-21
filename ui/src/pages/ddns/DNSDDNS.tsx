import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useRequest } from "ahooks";
import { Alert, App, Button, Card, Descriptions, Form, Input, Modal, Popconfirm, Space, Spin, Table, Tag, Typography } from "antd";

import { unwrapErrMsg } from "@/utils/error";
import BindingEditForm from "./BindingEditForm";
import BindingForm from "./BindingForm";
import BindingRenameReview from "./BindingRenameReview";
import { type Binding, type BindingEditValues, type IssuedToken, type NetworkInterface, type Node, bindingPath, ddnsRequest, nodePath } from "./model";

const statusColors: Record<string, string> = {
  pending: "default",
  synced: "success",
  failed: "error",
  waiting: "warning",
};

const loadNodes = () => ddnsRequest<Node[]>("");

export default function DNSDDNS() {
  const { t, i18n } = useTranslation();
  const { message } = App.useApp();
  const { data: nodes, loading, error, refresh } = useRequest(loadNodes, { pollingInterval: 10_000, pollingWhenHidden: false });
  const [register, setRegister] = useState(false);
  const [issued, setIssued] = useState<IssuedToken>();
  const [bindingEditor, setBindingEditor] = useState<{ node: Node; binding?: Binding }>();
  const [bindingError, setBindingError] = useState("");
  const [busy, setBusy] = useState(false);
  const writing = useRef(false);
  const bindingNode = nodes?.find((node) => node.id === bindingEditor?.node.id) ?? bindingEditor?.node;
  const currentBinding = bindingNode?.bindings.find((row) => row.id === bindingEditor?.binding?.id) ?? bindingEditor?.binding;
  const pendingRename = currentBinding?.pendingRename;
  const canContinueRename = pendingRename?.submitted || bindingNode?.interfaces.some((item) => item.name === pendingRename?.interfaceName);
  const timeFormat = new Intl.DateTimeFormat(i18n.resolvedLanguage, { dateStyle: "medium", timeStyle: "short" });
  const formatTime = (value: string | null) => (value ? timeFormat.format(new Date(value)) : "—");

  async function write<T>(request: () => Promise<T>, onSuccess?: (result: T) => void, onError?: (reason: string) => void) {
    if (writing.current) return;
    writing.current = true;
    setBusy(true);
    try {
      const result = await request();
      onSuccess?.(result);
      refresh();
    } catch (err) {
      const reason = unwrapErrMsg(err);
      if (onError) onError(reason);
      else void message.error(reason);
    } finally {
      writing.current = false;
      setBusy(false);
    }
  }

  function openBinding(node: Node, binding?: Binding) {
    setBindingError("");
    setBindingEditor({ node, binding });
  }

  function writeBinding(request: () => Promise<unknown>) {
    setBindingError("");
    void write(
      request,
      () => setBindingEditor(undefined),
      (reason) => {
        setBindingError(reason);
        refresh();
      }
    );
  }

  function saveBindingEdit({ recordName, interfaceName }: BindingEditValues, binding = bindingEditor?.binding) {
    if (!bindingEditor || !binding) return;
    const path = bindingPath(bindingEditor.node.id, binding.id);
    writeBinding(() =>
      ddnsRequest(path, "PUT", {
        recordName,
        interfaceName,
        expectedRecordName: binding.recordName,
        expectedInterfaceName: binding.interfaceName,
      })
    );
  }

  const interfaces = [
    { title: t("ddns.interface"), dataIndex: "name" },
    { title: t("ddns.mac"), dataIndex: "mac", render: (value: string) => value || "—" },
    {
      title: "IPv4",
      dataIndex: "ipv4",
      render: (value: string[]) => (value.length ? value.map((address) => <div key={address}>{address}</div>) : "—"),
    },
    {
      title: "IPv6",
      dataIndex: "ipv6",
      render: (value: string[]) => (value.length ? value.map((address) => <div key={address}>{address}</div>) : "—"),
    },
  ];

  function bindingColumns(node: Node) {
    return [
      {
        title: t("ddns.record"),
        render: (_: unknown, row: Binding) => (
          <>
            {row.recordName} <Tag>{row.recordType}</Tag>
          </>
        ),
      },
      { title: t("ddns.interface"), dataIndex: "interfaceName" },
      { title: t("ddns.lastAddress"), dataIndex: "lastAddress", render: (value: string) => value || "—" },
      {
        title: t("ddns.syncStatus"),
        render: (_: unknown, row: Binding) =>
          row.pendingRename ? (
            <>
              <Tag color="warning">{t(row.pendingRename.submitted ? "ddns.renameAwaiting" : "ddns.renamePrepared")}</Tag>
              <div className="mt-1 wrap-break-word">
                {row.pendingRename.recordName} · {row.pendingRename.interfaceName}
              </div>
            </>
          ) : (
            <>
              <Tag color={statusColors[row.syncStatus]}>{t("ddns.sync." + row.syncStatus, { defaultValue: row.syncStatus })}</Tag>
              {row.lastError && <div className="mt-1 wrap-break-word">{row.lastError}</div>}
            </>
          ),
      },
      { title: t("ddns.lastSync"), dataIndex: "updatedAt", render: formatTime },
      {
        title: t("dns.actions"),
        render: (_: unknown, row: Binding) =>
          row.pendingRename ? (
            <Button disabled={busy} onClick={() => openBinding(node, row)}>
              {t("ddns.reviewRename")}
            </Button>
          ) : (
            <Space wrap>
              <Button disabled={busy} onClick={() => openBinding(node, row)}>
                {t("ddns.editBinding")}
              </Button>
              <Popconfirm title={t("ddns.confirmUnbind")} onConfirm={() => write(() => ddnsRequest(bindingPath(node.id, row.id), "DELETE"))}>
                <Button danger disabled={busy}>
                  {t("ddns.unbind")}
                </Button>
              </Popconfirm>
            </Space>
          ),
      },
    ];
  }

  return (
    <main className="p-4 md:p-6">
      <Space className="mb-4 flex flex-wrap justify-between" align="start">
        <Typography.Title level={3} className="m-0!">
          {t("ddns.title")}
        </Typography.Title>
        <Space wrap>
          <Button onClick={refresh}>{t("dns.refresh")}</Button>
          <Button type="primary" disabled={busy} onClick={() => setRegister(true)}>
            {t("ddns.register")}
          </Button>
        </Space>
      </Space>
      {error && <Alert className="mb-4" type="error" showIcon title={unwrapErrMsg(error)} />}
      {loading && !nodes && <Spin />}
      {nodes?.length === 0 && <Typography.Paragraph type="secondary">{t("ddns.noNodes")}</Typography.Paragraph>}
      <div className="flex flex-col gap-4">
        {nodes?.map((node) => (
          <Card
            key={node.id}
            title={
              <Space wrap>
                {node.name}
                <Tag color={node.online ? "success" : "default"}>{t(!node.enabled ? "ddns.disabled" : node.online ? "ddns.online" : "ddns.offline")}</Tag>
              </Space>
            }
          >
            <Descriptions
              size="small"
              column={{ xs: 1, sm: 1, md: 2 }}
              items={[
                { key: "hostname", label: t("ddns.hostname"), children: node.hostname || "—" },
                { key: "lastSeen", label: t("ddns.lastSeen"), children: formatTime(node.lastSeen) },
              ]}
            />
            <Typography.Title level={5}>{t("ddns.interfaces")}</Typography.Title>
            <Table<NetworkInterface>
              columns={interfaces}
              dataSource={node.interfaces}
              locale={{ emptyText: t("ddns.noInterfaces") }}
              pagination={false}
              rowKey="name"
              scroll={{ x: 540 }}
              size="small"
            />
            <Space className="mt-4 mb-2 flex flex-wrap justify-between" align="center">
              <Typography.Title level={5} className="m-0!">
                {t("ddns.bindings")}
              </Typography.Title>
              <Button disabled={busy || !node.interfaces.length} onClick={() => openBinding(node)}>
                {t("ddns.bind")}
              </Button>
            </Space>
            <Table<Binding>
              columns={bindingColumns(node)}
              dataSource={node.bindings}
              locale={{ emptyText: t("ddns.noBindings") }}
              pagination={false}
              rowKey="id"
              scroll={{ x: 760 }}
              size="small"
            />
            <Space className="mt-4" wrap>
              <Popconfirm
                title={t("ddns.confirmRotate")}
                onConfirm={() => write(() => ddnsRequest<IssuedToken>(nodePath(node.id) + "/rotate", "POST"), setIssued)}
              >
                <Button disabled={busy}>{t("ddns.rotate")}</Button>
              </Popconfirm>
              <Popconfirm title={t("ddns.confirmDelete")} onConfirm={() => write(() => ddnsRequest(nodePath(node.id), "DELETE"))}>
                <Button danger disabled={busy}>
                  {t("ddns.delete")}
                </Button>
              </Popconfirm>
            </Space>
          </Card>
        ))}
      </div>
      <Modal
        title={t("ddns.register")}
        open={register}
        footer={null}
        destroyOnHidden
        closable={!busy}
        mask={{ closable: false }}
        onCancel={() => !busy && setRegister(false)}
      >
        <Form<{ name: string }>
          layout="vertical"
          disabled={busy}
          onFinish={({ name }) =>
            write(
              () => ddnsRequest<IssuedToken>("", "POST", { name: name.trim() }),
              (token) => {
                setRegister(false);
                setIssued(token);
              }
            )
          }
        >
          <Form.Item label={t("ddns.nodeName")} name="name" rules={[{ required: true, whitespace: true }]}>
            <Input maxLength={80} autoFocus />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={busy}>
            {t("ddns.register")}
          </Button>
        </Form>
      </Modal>
      <Modal
        title={t(pendingRename ? "ddns.reviewRename" : bindingEditor?.binding ? "ddns.editBinding" : "ddns.bind")}
        open={Boolean(bindingEditor)}
        footer={null}
        destroyOnHidden
        closable={!busy}
        mask={{ closable: false }}
        onCancel={() => !busy && setBindingEditor(undefined)}
      >
        {bindingNode &&
          (pendingRename && currentBinding ? (
            <BindingRenameReview
              rename={pendingRename}
              canContinue={Boolean(canContinueRename)}
              busy={busy}
              error={bindingError}
              onCheck={() => saveBindingEdit(pendingRename, currentBinding)}
              onCancel={() => writeBinding(() => ddnsRequest(bindingPath(bindingNode.id, currentBinding.id) + "/rename", "DELETE"))}
              onConfirmRecord={(recordId) =>
                writeBinding(() => ddnsRequest(bindingPath(bindingNode.id, currentBinding.id) + "/rename/confirm", "POST", { recordId }))
              }
            />
          ) : bindingEditor?.binding ? (
            <BindingEditForm
              key={bindingEditor.binding.id}
              binding={bindingEditor.binding}
              interfaces={bindingNode.interfaces}
              busy={busy}
              error={bindingError}
              onSave={saveBindingEdit}
            />
          ) : (
            <BindingForm
              key={bindingNode.id}
              interfaces={bindingNode.interfaces}
              busy={busy}
              onBind={(target) =>
                write(
                  () => ddnsRequest(nodePath(bindingNode.id) + "/bindings", "POST", target),
                  () => setBindingEditor(undefined)
                )
              }
            />
          ))}
      </Modal>
      <Modal title={t("ddns.token")} open={Boolean(issued)} footer={null} destroyOnHidden mask={{ closable: false }} onCancel={() => setIssued(undefined)}>
        {issued && (
          <Space className="w-full" orientation="vertical">
            <Typography.Paragraph>{t("ddns.tokenHelp")}</Typography.Paragraph>
            <Input.Password aria-label={t("ddns.token")} autoComplete="off" readOnly value={issued.token} />
            <Space wrap>
              <Button
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(issued.token);
                    void message.success(t("ddns.tokenCopied"));
                  } catch {
                    void message.error(t("ddns.copyFailed"));
                  }
                }}
              >
                {t("ddns.copyToken")}
              </Button>
              <Button type="primary" onClick={() => setIssued(undefined)}>
                {t("ddns.close")}
              </Button>
            </Space>
          </Space>
        )}
      </Modal>
    </main>
  );
}
