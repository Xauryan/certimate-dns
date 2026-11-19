import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { Alert, App, Button, Form, Input, InputNumber, Modal, Select, Space, Table, Typography } from "antd";

import { type DNSRecord, type Page, type Zone, dnsRequest } from "@/api/dns";
import { list as listAccesses } from "@/repository/access";
import { unwrapErrMsg } from "@/utils/error";

const types = ["A", "AAAA", "CNAME", "TXT"];
type Fields = Pick<DNSRecord, "name" | "type" | "content" | "ttl">;

function useDNSPage<T>(url: string, revision: number) {
  const [response, setResponse] = useState<{ url: string; revision: number; data?: Page<T>; error?: string }>();
  useEffect(() => {
    let current = true;
    dnsRequest<Page<T>>(url).then(
      (data) => {
        if (current) setResponse({ url, revision, data });
      },
      (error) => {
        if (current) setResponse({ url, revision, error: unwrapErrMsg(error) });
      }
    );
    return () => {
      current = false;
    };
  }, [url, revision]);
  return response?.url === url && response.revision === revision ? response : undefined;
}

function Records({ base, zone, back }: { base: string; zone: Zone; back: () => void }) {
  const { t } = useTranslation();
  const { message, modal } = App.useApp();
  const [page, setPage] = useState(1);
  const [filter, setFilter] = useState("");
  const [revision, setRevision] = useState(0);
  const [editor, setEditor] = useState<DNSRecord | "new" | null>(null);
  const [busy, setBusy] = useState(false);
  const writing = useRef(false);
  const [exporting, setExporting] = useState(false);
  const records = base + "/zones/" + encodeURIComponent(zone.id) + "/records";
  const response = useDNSPage<DNSRecord>(records + "?" + new URLSearchParams({ page: String(page), name: filter }), revision);
  const refresh = () => setRevision((value) => value + 1);

  async function save(fields: Fields) {
    if (!editor || writing.current) return;
    writing.current = true;
    setBusy(true);
    try {
      if (editor === "new") await dnsRequest(records, "POST", fields);
      else await dnsRequest(records + "/" + editor.id, "PATCH", { content: fields.content, ttl: fields.ttl });
      setEditor(null);
      message.success(t("dns.saved"));
    } catch (error) {
      message.error(unwrapErrMsg(error));
    } finally {
      writing.current = false;
      setBusy(false);
      refresh();
    }
  }

  function remove(row: DNSRecord) {
    modal.confirm({
      title: t("dns.confirmDelete"),
      content: (
        <div className="break-all">
          {row.type} · {row.name}
          <br />
          {row.content}
        </div>
      ),
      okText: t("dns.delete"),
      okButtonProps: { danger: true },
      onOk: async () => {
        try {
          await dnsRequest(records + "/" + row.id, "DELETE");
          if (response?.data?.result.length === 1 && page > 1) setPage(page - 1);
          message.success(t("dns.deleted"));
        } catch (error) {
          message.error(unwrapErrMsg(error));
        } finally {
          refresh();
        }
      },
    });
  }

  async function download() {
    setExporting(true);
    try {
      const text = await dnsRequest<string>(base + "/zones/" + encodeURIComponent(zone.id) + "/export");
      const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = zone.name + ".zone";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      message.error(unwrapErrMsg(error));
    } finally {
      setExporting(false);
    }
  }

  return (
    <>
      <Space wrap>
        <Button onClick={back}>{t("dns.zones")}</Button>
        <Typography.Title level={4} style={{ margin: 0 }}>
          {zone.name}
        </Typography.Title>
      </Space>
      <Space wrap>
        <Input.Search
          aria-label={t("dns.search")}
          placeholder={t("dns.search")}
          allowClear
          onSearch={(value) => {
            setFilter(value.trim());
            setPage(1);
          }}
        />
        <Button type="primary" onClick={() => setEditor("new")}>
          {t("dns.create")}
        </Button>
        <Button loading={exporting} onClick={download}>
          {t("dns.export")}
        </Button>
        <Button onClick={refresh}>{t("dns.refresh")}</Button>
      </Space>
      {response?.error && <Alert type="error" showIcon title={response.error} />}
      <Table<DNSRecord>
        rowKey="id"
        loading={!response}
        scroll={{ x: 750 }}
        dataSource={response?.data?.result ?? []}
        pagination={{ current: page, pageSize: 20, total: response?.data?.result_info.total_count ?? 0, showSizeChanger: false, onChange: setPage }}
        columns={[
          { title: t("dns.name"), dataIndex: "name" },
          { title: t("dns.type"), dataIndex: "type" },
          { title: t("dns.content"), dataIndex: "content", render: (v: string) => <span className="break-all">{v}</span> },
          { title: "TTL", dataIndex: "ttl", render: (v: number) => (v === 1 ? t("dns.auto") : v) },
          { title: t("dns.proxy"), dataIndex: "proxied", render: (v: boolean) => (v ? t("dns.on") : t("dns.off")) },
          {
            title: t("dns.actions"),
            render: (_, row) => (
              <Space>
                {types.includes(row.type) && (
                  <Button type="link" onClick={() => setEditor(row)}>
                    {t("dns.edit")}
                  </Button>
                )}
                <Button type="link" danger onClick={() => remove(row)}>
                  {t("dns.delete")}
                </Button>
              </Space>
            ),
          },
        ]}
      />
      {editor && (
        <Modal
          open
          title={t(editor === "new" ? "dns.create" : "dns.edit")}
          onCancel={() => {
            if (!busy) setEditor(null);
          }}
          okButtonProps={{ form: "dns-record-editor", htmlType: "submit" }}
          confirmLoading={busy}
          closable={!busy}
          maskClosable={!busy}
        >
          <Form<Fields>
            id="dns-record-editor"
            layout="vertical"
            preserve={false}
            initialValues={editor === "new" ? { type: "A", ttl: 1 } : editor}
            onFinish={save}
          >
            <Form.Item name="type" label={t("dns.type")} rules={[{ required: true }]}>
              <Select disabled={editor !== "new"} options={types.map((value) => ({ value }))} />
            </Form.Item>
            <Form.Item name="name" label={t("dns.name")} rules={[{ required: true, whitespace: true }]}>
              <Input disabled={editor !== "new"} placeholder={"www." + zone.name} />
            </Form.Item>
            <Form.Item name="content" label={t("dns.content")} rules={[{ required: true }]}>
              <Input.TextArea autoSize />
            </Form.Item>
            <Form.Item
              name="ttl"
              label="TTL"
              extra={t("dns.ttlHelp")}
              rules={[
                { required: true },
                {
                  validator: (_, v) =>
                    v === 1 || (Number.isInteger(v) && v >= 30 && v <= 86400) ? Promise.resolve() : Promise.reject(new Error(t("dns.ttlHelp"))),
                },
              ]}
            >
              <InputNumber precision={0} min={1} max={86400} />
            </Form.Item>
          </Form>
        </Modal>
      )}
    </>
  );
}

function Zones({ base }: { base: string }) {
  const { t } = useTranslation();
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [zone, setZone] = useState<Zone>();
  const response = useDNSPage<Zone>(base + "/zones?page=" + page, revision);
  if (zone) return <Records key={zone.id} base={base} zone={zone} back={() => setZone(undefined)} />;
  return (
    <>
      <Space>
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t("dns.zones")}
        </Typography.Title>
        <Button onClick={() => setRevision((v) => v + 1)}>{t("dns.refresh")}</Button>
      </Space>
      {response?.error && <Alert type="error" showIcon title={response.error} />}
      <Table<Zone>
        loading={!response}
        rowKey="id"
        dataSource={response?.data?.result ?? []}
        pagination={{ current: page, pageSize: 20, total: response?.data?.result_info.total_count ?? 0, showSizeChanger: false, onChange: setPage }}
        columns={[
          {
            title: t("dns.zone"),
            dataIndex: "name",
            render: (name: string, row) => (
              <Button type="link" onClick={() => setZone(row)}>
                {name}
              </Button>
            ),
          },
          { title: t("dns.status"), dataIndex: "status" },
        ]}
      />
    </>
  );
}

export default function DNSManager() {
  const { t } = useTranslation();
  const [accounts, setAccounts] = useState<{ value: string; label: string }[]>();
  const [account, setAccount] = useState<string>();
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let current = true;
    listAccesses()
      .then(({ items }) => {
        if (!current) return;
        const options = items.filter((item) => item.provider === "cloudflare").map((item) => ({ value: item.id, label: item.name }));
        setAccounts(options);
        setAccount(options[0]?.value);
        setError("");
      })
      .catch((err) => {
        if (current) setError(unwrapErrMsg(err));
      });
    return () => {
      current = false;
    };
  }, [revision]);
  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <Typography.Title level={3} style={{ margin: 0 }}>
        {t("dns.heading")}
      </Typography.Title>
      {error && <Alert type="error" title={error} action={<Button onClick={() => setRevision((v) => v + 1)}>{t("dns.refresh")}</Button>} />}
      <Space wrap>
        <label htmlFor="dns-account">{t("dns.account")}</label>
        <Select id="dns-account" loading={!accounts && !error} style={{ minWidth: 200 }} options={accounts} value={account} onChange={setAccount} />
        <Link to="/accesses">{t("dns.accounts")}</Link>
      </Space>
      {accounts?.length === 0 && <Alert type="info" title={t("dns.noAccounts")} />}
      {account && <Zones key={account} base={"/api/dns/cloudflare/" + encodeURIComponent(account)} />}
    </div>
  );
}
