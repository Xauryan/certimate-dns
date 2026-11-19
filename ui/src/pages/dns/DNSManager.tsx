import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router-dom";
import { Alert, App, Button, Form, Input, InputNumber, Modal, Select, Space, Spin, Table, Tabs, Typography } from "antd";

import { type DNSRecord, type Page, type Zone, dnsRequest } from "@/api/dns";
import { dnsAccountProviderLabels } from "@/domain/dnsAccount";
import DNSAdvanced from "@/pages/dnsadvanced/DNSAdvanced";
import DNSBatch from "@/pages/dnsbatch/DNSBatch";
import { type Account, type Zone as CatalogZone } from "@/pages/dnscatalog/catalog";
import DNSOptimize from "@/pages/dnsoptimize/DNSOptimize";
import { unwrapErrMsg } from "@/utils/error";

interface Capabilities {
  types: string[];
  priorityTypes?: string[];
  line?: boolean;
  description?: boolean;
  weight?: boolean;
  minTTL: number;
  maxTTL: number;
  defaultTTL: number;
  specialTTLs?: number[];
  export?: boolean;
}
type ZoneDetails = { minTTL?: number; lines?: { id: string; name: string }[] };

type Fields = Pick<DNSRecord, "name" | "type" | "content" | "ttl" | "line" | "priority" | "description" | "weight">;

function useDNSData<T>(url?: string, revision = 0) {
  const [response, setResponse] = useState<{ url: string; revision: number; data?: T; error?: string }>();
  useEffect(() => {
    if (!url) return;
    let current = true;
    dnsRequest<T>(url).then(
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
  return response && response.url === url && response.revision === revision ? response : undefined;
}

type RecordViewProps = {
  base: string;
  zone: Zone;
  provider: string;
  canWrite: boolean;
  back: () => void;
  adminAccess?: string;
};

function RecordList({ base, zone, provider, canWrite, adminAccess }: Omit<RecordViewProps, "back">) {
  const { t } = useTranslation();
  const { message, modal } = App.useApp();
  const [page, setPage] = useState(1);
  const [filter, setFilter] = useState("");
  const [revision, setRevision] = useState(0);
  const [editor, setEditor] = useState<DNSRecord | "new" | null>(null);
  const [busy, setBusy] = useState(false);
  const writing = useRef(false);
  const [exporting, setExporting] = useState(false);
  const cf = provider === "cloudflare";
  const capability = useDNSData<Capabilities>("/api/dns/capabilities/" + encodeURIComponent(provider), revision);
  const features = capability?.data;
  const details = useDNSData<ZoneDetails>(editor && features?.line ? base + "/zones/" + encodeURIComponent(zone.id) + "/advanced/details" : undefined);
  const minTTL = Math.max(features?.minTTL ?? 1, details?.data?.minTTL ?? 0);
  const maxTTL = features?.maxTTL ?? 604800;
  const specialTTLs = features?.specialTTLs ?? [];
  const ttlHelp = t("dns.ttlRange", { min: minTTL, max: maxTTL }) + (specialTTLs.length ? " " + t("dns.ttlSpecial", { values: specialTTLs.join(", ") }) : "");
  const types = features?.types ?? [];
  const records = base + "/zones/" + encodeURIComponent(zone.id) + "/records";
  const response = useDNSData<Page<DNSRecord>>(records + "?" + new URLSearchParams({ page: String(page), name: filter }), revision);
  const refresh = () => setRevision((value) => value + 1);

  async function save(fields: Fields) {
    if (!editor || writing.current) return;
    writing.current = true;
    setBusy(true);
    try {
      if (editor === "new") {
        const payload = Object.fromEntries(Object.entries(fields).filter(([, value]) => value != null && value !== ""));
        await dnsRequest(records, "POST", payload);
      } else await dnsRequest(records + "/" + encodeURIComponent(editor.id), "PATCH", { content: fields.content, ttl: fields.ttl });
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
          await dnsRequest(records + "/" + encodeURIComponent(row.id), "DELETE");
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
        <Input.Search
          aria-label={t("dns.search")}
          placeholder={t("dns.search")}
          allowClear
          onSearch={(value) => {
            setFilter(value.trim());
            setPage(1);
          }}
        />
        {canWrite && features && response?.data && (
          <Button type="primary" onClick={() => setEditor("new")}>
            {t("dns.create")}
          </Button>
        )}
        {features?.export && response?.data && (
          <Button loading={exporting} onClick={download}>
            {t("dns.export")}
          </Button>
        )}
        <Button onClick={refresh}>{t("dns.refresh")}</Button>
        {response?.data && <DNSBatch base={base} zone={zone} canWrite={canWrite} onApplied={refresh} />}
        {adminAccess && response?.data && <DNSOptimize provider={provider} access={adminAccess} zone={zone} onApplied={refresh} />}
      </Space>
      {capability?.error && <Alert type="error" showIcon title={capability.error} />}
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
          { title: "TTL", dataIndex: "ttl", render: (v: number) => (cf && v === 1 ? t("dns.auto") : v) },
          cf
            ? { title: t("dns.proxy"), dataIndex: "proxied", render: (v: boolean) => (v ? t("dns.on") : t("dns.off")) }
            : { title: t("dns.line"), dataIndex: "line" },
          ...(features?.priorityTypes?.length ? [{ title: t("dns.priority"), dataIndex: "priority" }] : []),
          ...(features?.description ? [{ title: t("dns.description"), dataIndex: "description" }] : []),
          ...(features?.weight ? [{ title: t("dns.weight"), dataIndex: "weight" }] : []),
          ...(canWrite
            ? [
                {
                  title: t("dns.actions"),
                  render: (_: unknown, row: DNSRecord) => (
                    <Space>
                      {!row.readOnly && types.includes(row.type) && (
                        <Button type="link" onClick={() => setEditor(row)}>
                          {t("dns.edit")}
                        </Button>
                      )}
                      {!row.readOnly && (
                        <Button type="link" danger onClick={() => remove(row)}>
                          {t("dns.delete")}
                        </Button>
                      )}
                    </Space>
                  ),
                },
              ]
            : []),
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
            initialValues={editor === "new" ? { type: types[0], ttl: features?.defaultTTL } : editor}
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
            {editor === "new" && features?.priorityTypes?.length ? (
              <Form.Item noStyle shouldUpdate={(previous, next) => previous.type !== next.type}>
                {({ getFieldValue }) =>
                  features.priorityTypes?.includes(getFieldValue("type")) ? (
                    <Form.Item name="priority" label={t("dns.priority")} preserve={false}>
                      <InputNumber min={0} max={65535} precision={0} />
                    </Form.Item>
                  ) : null
                }
              </Form.Item>
            ) : null}
            {editor === "new" && features?.line && (
              <Form.Item name="line" label={t("dns.line")}>
                {details?.data?.lines?.length ? (
                  <Select allowClear options={details.data.lines.map(({ id, name }) => ({ value: id, label: name || id }))} />
                ) : (
                  <Input />
                )}
              </Form.Item>
            )}
            {editor === "new" && features?.description && (
              <Form.Item name="description" label={t("dns.description")}>
                <Input />
              </Form.Item>
            )}
            {editor === "new" && features?.weight && (
              <Form.Item name="weight" label={t("dns.weight")}>
                <InputNumber min={0} precision={0} />
              </Form.Item>
            )}
            <Form.Item
              name="ttl"
              label="TTL"
              extra={ttlHelp}
              rules={[
                { required: true },
                {
                  validator: (_, v) =>
                    Number.isInteger(v) && (specialTTLs.includes(v) || (v >= minTTL && v <= maxTTL)) ? Promise.resolve() : Promise.reject(new Error(ttlHelp)),
                },
              ]}
            >
              <InputNumber precision={0} min={Math.min(minTTL, ...specialTTLs)} max={maxTTL} />
            </Form.Item>
          </Form>
        </Modal>
      )}
    </>
  );
}

export function Records({ back, ...view }: RecordViewProps) {
  const { t } = useTranslation();
  return (
    <>
      <Space wrap>
        <Button onClick={back}>{t("dns.zones")}</Button>
        <Typography.Title level={4} style={{ margin: 0 }}>
          {view.zone.name}
        </Typography.Title>
      </Space>
      <Tabs
        destroyOnHidden
        items={[
          {
            key: "records",
            label: t("dns.records"),
            children: (
              <div className="flex flex-col gap-4">
                <RecordList {...view} />
              </div>
            ),
          },
          { key: "advanced", label: t("dns.advanced"), children: <DNSAdvanced base={view.base} zone={view.zone} canWrite={view.canWrite} /> },
        ]}
      />
    </>
  );
}

function Zones({ access, provider }: { access: string; provider: string }) {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const [revision, setRevision] = useState(0);
  const pageValue = Number(params.get("page"));
  const page = Number.isSafeInteger(pageValue) && pageValue > 0 ? pageValue : 1;
  const base = "/api/dns/" + encodeURIComponent(provider) + "/" + encodeURIComponent(access);
  const zoneId = params.get("zone");
  const catalogId = zoneId && params.get("catalogId");
  const response = useDNSData<Page<Zone>>(!catalogId ? base + "/zones?page=" + page : undefined, revision);
  const catalog = useDNSData<CatalogZone>(catalogId ? "/api/dns-catalog/domains/" + encodeURIComponent(catalogId) : undefined, revision);
  const setSelection = (nextPage: number, selected?: Zone) => {
    const next = new URLSearchParams({ access, provider, page: String(nextPage) });
    if (selected) {
      next.set("zone", selected.id);
    }
    setParams(next);
  };

  if (zoneId) {
    const item = catalog?.data;
    const zone = catalogId
      ? item?.accessId === access && item?.provider === provider && item.zoneId === zoneId && item.enabled && item.present
        ? { id: item.zoneId, name: item.name, status: item.status }
        : undefined
      : response?.data?.result.find((z) => z.id === zoneId);
    if (zone) return <Records key={zone.id} base={base} zone={zone} provider={provider} canWrite adminAccess={access} back={() => setSelection(page)} />;
    if (!catalog && !response) return <Spin />;
    return (
      <Alert
        type="warning"
        title={catalog?.error || response?.error || t("dns.zoneUnavailable")}
        action={<Button onClick={() => setSelection(1)}>{t("dns.zones")}</Button>}
      />
    );
  }
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
        pagination={{
          current: page,
          pageSize: 20,
          total: response?.data?.result_info.total_count ?? 0,
          showSizeChanger: false,
          onChange: (p) => setSelection(p),
        }}
        columns={[
          {
            title: t("dns.zone"),
            dataIndex: "name",
            render: (name: string, row) => (
              <Button type="link" onClick={() => setSelection(page, row)}>
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
  const [params, setParams] = useSearchParams();
  const [revision, setRevision] = useState(0);
  const providers = useDNSData<string[]>("/api/dns/providers", revision);
  const accounts = useDNSData<Account[]>("/api/dns-catalog/accounts", revision);
  const options =
    accounts?.data
      ?.filter((a) => a.enabled && providers?.data?.includes(a.provider))
      .map((a) => ({
        value: a.id,
        label: a.name + " · " + t(dnsAccountProviderLabels.get(a.provider) ?? a.provider),
        provider: a.provider,
      })) ?? [];
  const requested = params.get("access");
  const account = requested ? options.find((a) => a.value === requested && (!params.has("provider") || params.get("provider") === a.provider)) : options[0];
  const error = accounts?.error || providers?.error;
  const loaded = !!accounts?.data && !!providers?.data;
  return (
    <main className="flex flex-col gap-4 p-4 md:p-6">
      <Typography.Title level={3} style={{ margin: 0 }}>
        {t("dns.heading")}
      </Typography.Title>
      {error && <Alert type="error" showIcon title={error} action={<Button onClick={() => setRevision((v) => v + 1)}>{t("dns.refresh")}</Button>} />}
      <Space wrap>
        <label htmlFor="dns-account">{t("dns.account")}</label>
        <Select
          id="dns-account"
          loading={!loaded && !error}
          style={{ minWidth: 200, maxWidth: "80vw" }}
          options={options}
          value={account?.value}
          onChange={(access) => setParams({ access })}
        />
        <Link to="/accesses?usage=dns-management">{t("dns.manageLink")}</Link>
        <Link to="/dns/catalog">{t("dns.catalog")}</Link>
      </Space>
      {loaded && !options.length && <Alert type="info" title={t("dns.noAccounts")} />}
      {loaded && requested && !account && <Alert type="warning" title={t("dns.accountUnavailable")} />}
      {account && <Zones key={account.value} provider={account.provider} access={account.value} />}
    </main>
  );
}
