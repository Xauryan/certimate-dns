import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert, App, Button, Descriptions, Form, Input, Modal, Pagination, Popconfirm, Select, Space, Table, Tabs } from "antd";

import { type DNSRecord, type Page, dnsRequest } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";

type Props = { base: string; zone: { id: string; name: string }; canWrite: boolean };
type Line = { id: string; name: string; parent?: string };
type Details = { status?: string; plan?: string; minTTL?: number; lines: Line[]; nameservers?: string[] };
type Weight = { name: string; type: string; line: string; enabled: boolean };
type Alias = { id: string; name: string };
type Features = { details: boolean; aliases: boolean; weights: boolean };
type Attributes = { fields: string[]; groups: boolean; logs: boolean };

function useLabels() {
  const { i18n } = useTranslation();
  return (en: string, zh: string) => ((i18n.resolvedLanguage ?? i18n.language).startsWith("zh") ? zh : en);
}
function useData<T>(url: string, revision = 0) {
  const [state, set] = useState<{ url: string; revision: number; data?: T; error?: string }>();
  useEffect(() => {
    if (!url) return;
    let active = true;
    dnsRequest<T>(url).then(
      (data) => {
        if (active) set({ url, revision, data });
      },
      (error) => {
        if (active) set({ url, revision, error: unwrapErrMsg(error) });
      }
    );
    return () => {
      active = false;
    };
  }, [url, revision]);
  return state?.url === url && state.revision === revision ? state : undefined;
}

function DetailsView({ path }: { path: string }) {
  const l = useLabels();
  const result = useData<Details>(path + "/details");
  if (result?.error) return <Alert type="error" showIcon title={result.error} />;
  const d = result?.data;
  return (
    <Space orientation="vertical" className="w-full">
      <Descriptions
        column={2}
        items={[
          { key: "plan", label: l("Plan", "套餐"), children: d?.plan || "—" },
          { key: "ttl", label: l("Minimum TTL (seconds)", "最小 TTL（秒）"), children: d?.minTTL || "—" },
          { key: "status", label: l("Status", "状态"), children: d?.status || "—" },
          { key: "ns", label: l("Nameservers", "权威域名服务器"), children: d?.nameservers?.join(", ") || "—" },
        ]}
      />
      <Table<Line>
        size="small"
        rowKey="id"
        dataSource={d?.lines ?? []}
        loading={!result}
        pagination={{ pageSize: 20, showSizeChanger: false }}
        columns={[
          { title: l("Record line", "解析线路"), dataIndex: "name" },
          { title: "ID", dataIndex: "id" },
          { title: l("Parent", "上级线路"), dataIndex: "parent" },
        ]}
      />
    </Space>
  );
}

function Aliases({ path, canWrite }: { path: string; canWrite: boolean }) {
  const l = useLabels();
  const { message } = App.useApp();
  const [revision, reload] = useState(0);
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");
  const r = useData<Alias[]>(path + "/aliases", revision);
  async function change(id?: string) {
    setBusy(true);
    try {
      if (id) await dnsRequest(path + "/aliases/" + encodeURIComponent(id), "DELETE");
      else await dnsRequest(path + "/aliases", "POST", { name: name.trim() });
      setName("");
      message.success(l("Saved", "已保存"));
    } catch (e) {
      message.error(unwrapErrMsg(e));
    } finally {
      setBusy(false);
      reload((n) => n + 1);
    }
  }
  return (
    <Space orientation="vertical" className="w-full">
      {canWrite && (
        <Space.Compact>
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="alias.example.org" aria-label={l("New alias", "新别名")} maxLength={253} />
          <Button disabled={!name.trim() || busy} onClick={() => change()}>
            {l("Add alias", "新增域名别名")}
          </Button>
        </Space.Compact>
      )}
      {r?.error && <Alert type="error" showIcon title={r.error} />}
      <Table<Alias>
        rowKey="id"
        size="small"
        loading={!r}
        dataSource={r?.data}
        columns={[
          { title: l("Alias", "域名别名"), dataIndex: "name" },
          ...(canWrite
            ? [
                {
                  title: "",
                  render: (_: unknown, a: Alias) => (
                    <Popconfirm title={l("Delete this alias?", "删除此别名？")} onConfirm={() => change(a.id)}>
                      <Button size="small" danger disabled={busy}>
                        {l("Delete", "删除")}
                      </Button>
                    </Popconfirm>
                  ),
                },
              ]
            : []),
        ]}
      />
    </Space>
  );
}
function Weights({ path, canWrite, zone }: { path: string; canWrite: boolean; zone: string }) {
  const l = useLabels();
  const { message } = App.useApp();
  const [revision, reload] = useState(0);
  const [busy, setBusy] = useState(false);
  const [page, setPage] = useState(1);
  const [name, search] = useState("");
  const [editor, setEditor] = useState<Weight>();
  const r = useData<Page<Weight>>(path + "/weights?" + new URLSearchParams({ page: String(page), name }), revision);
  async function save(rule: Weight) {
    setBusy(true);
    try {
      await dnsRequest(path + "/weights", "PUT", rule);
      setEditor(undefined);
      message.success(l("Saved", "已保存"));
    } catch (e) {
      message.error(unwrapErrMsg(e));
    } finally {
      setBusy(false);
      reload((n) => n + 1);
    }
  }
  return (
    <Space orientation="vertical" className="w-full">
      <Space wrap>
        <Input.Search
          placeholder={l("Filter by host", "按主机记录筛选")}
          allowClear
          onSearch={(v) => {
            search(v.trim());
            setPage(1);
          }}
        />
        {canWrite && <Button onClick={() => setEditor({ name: zone, type: "A", line: "", enabled: true })}>{l("Configure weighting", "配置权重开关")}</Button>}
      </Space>
      {r?.error && <Alert type="error" showIcon title={r.error} />}
      <Table<Weight>
        size="small"
        rowKey={(r) => JSON.stringify([r.name, r.type, r.line])}
        loading={!r}
        dataSource={r?.data?.result}
        pagination={false}
        columns={[
          { title: l("Name", "记录名"), dataIndex: "name" },
          { title: l("Type", "类型"), dataIndex: "type" },
          { title: l("Line", "线路"), dataIndex: "line" },
          { title: l("Weighting", "权重配置"), render: (_, r) => (r.enabled ? l("On", "已启用") : l("Off", "已停用")) },
          ...(canWrite
            ? [
                {
                  title: "",
                  render: (_: unknown, r: Weight) => (r.type === "A" || r.type === "AAAA") && <Button onClick={() => setEditor(r)}>{l("Edit", "编辑")}</Button>,
                },
              ]
            : []),
        ]}
      />
      <Pagination current={page} pageSize={20} total={r?.data?.result_info.total_count ?? 0} onChange={setPage} showSizeChanger={false} hideOnSinglePage />
      {editor && (
        <Modal
          open
          title={l("Configure weighting", "配置权重开关")}
          onCancel={() => !busy && setEditor(undefined)}
          okButtonProps={{ form: "dns-weight", htmlType: "submit" }}
          confirmLoading={busy}
        >
          <Form<Weight> id="dns-weight" initialValues={editor} layout="vertical" onFinish={save}>
            <Form.Item name="name" label={l("Fully qualified name", "完整记录名")} rules={[{ required: true }]}>
              <Input maxLength={253} />
            </Form.Item>
            <Form.Item name="type" label={l("Type", "类型")} rules={[{ required: true }]}>
              <Select options={["A", "AAAA"].map((value) => ({ value }))} />
            </Form.Item>
            <Form.Item name="line" label={l("Line ID (optional)", "线路 ID（可选）")}>
              <Input maxLength={128} />
            </Form.Item>
            <Form.Item name="enabled" label={l("Weighting", "权重配置")}>
              <Select
                options={[
                  { value: true, label: l("On", "启用") },
                  { value: false, label: l("Off", "停用") },
                ]}
              />
            </Form.Item>
          </Form>
        </Modal>
      )}
    </Space>
  );
}
function AttributesView({ path, features, canWrite, hasDetails }: { path: string; features: Attributes; canWrite: boolean; hasDetails: boolean }) {
  const l = useLabels();
  const { message } = App.useApp();
  const [page, setPage] = useState(1);
  const [filter, search] = useState("");
  const [revision, reload] = useState(0);
  const [record, edit] = useState<DNSRecord>();
  const [probe, setProbe] = useState<{ name: string; url: string; revision: number }>();
  const checked = useData<{ status: "active" | "mismatch" | "not_found"; expected?: string; actual: string[] }>(probe?.url ?? "", probe?.revision);

  const [field, setField] = useState("");
  const [value, setValue] = useState("");
  const [plan, setPlan] = useState<{ id: string; before: string }>();
  const [busy, setBusy] = useState(false);
  const rows = useData<Page<DNSRecord>>(path + "/records?" + new URLSearchParams({ page: String(page), name: filter }), revision);
  const groups = useData<Alias[]>(record && field === "group" ? path + "/batch/groups" : "");
  const zone = useData<Details>(record && field === "line" && hasDetails ? path + "/advanced/details" : "");
  const labels: Record<string, string> = {
    remark: l("Remark", "备注"),
    group: l("Group", "分组"),
    line: l("Line", "线路"),
    status: l("Status", "状态"),
    weight: l("Weight", "权重"),
  };
  async function save() {
    if (!record || !field) return;
    setBusy(true);
    const changes = [{ action: field, id: record.id, value }];
    try {
      if (!plan) {
        const r = await dnsRequest<{ plan: { id: string }; rows: { previousValue?: string }[] }>(path + "/batch/preview", "POST", { changes });
        setPlan({ id: r.plan.id, before: r.rows[0].previousValue ?? "" });
      } else {
        const r = await dnsRequest<{ state: string; items: { state: string }[] }>(path + "/batch/plans/" + encodeURIComponent(plan.id) + "/apply", "POST", {
          confirm: true,
          changes,
        });
        if (r.items[0]?.state === "applied") {
          message.success(l("Saved", "已保存"));
        } else {
          message.warning(l("Provider result", "服务商处理结果") + " · " + r.state + " / " + r.items[0]?.state);
        }
        edit(undefined);
        reload((n) => n + 1);
      }
    } catch (e) {
      message.error(unwrapErrMsg(e));
    } finally {
      setBusy(false);
    }
  }
  let choices: { label: string; value: string }[] | undefined;
  if (field === "status")
    choices = [
      { value: "enabled", label: l("Enabled", "启用") },
      { value: "disabled", label: l("Disabled", "停用") },
    ];
  if (field === "group") choices = groups?.data?.map((g) => ({ label: g.name, value: g.id })) ?? [];
  if (field === "line" && zone?.data?.lines?.length) choices = zone.data.lines.map((g) => ({ label: g.name, value: g.id }));
  return (
    <Space orientation="vertical" className="w-full">
      <Input.Search
        placeholder={l("Search record names", "按记录名搜索")}
        allowClear
        onSearch={(v) => {
          search(v.trim());
          setPage(1);
        }}
      />
      {rows?.error && <Alert type="error" title={rows.error} />}
      <Table<DNSRecord & { description?: string; weight?: number; status?: string }>
        rowKey="id"
        size="small"
        loading={!rows}
        dataSource={rows?.data?.result}
        pagination={{ current: page, pageSize: 20, total: rows?.data?.result_info.total_count ?? 0, showSizeChanger: false, onChange: setPage }}
        columns={[
          { title: l("Name", "记录名"), dataIndex: "name" },
          { title: l("Type", "类型"), dataIndex: "type" },
          { title: l("Content", "记录值"), dataIndex: "content", render: (v) => <span className="break-all">{v}</span> },
          { title: labels.remark, dataIndex: "description" },
          { title: labels.weight, dataIndex: "weight" },
          { title: labels.status, dataIndex: "status" },
          {
            title: "",
            render: (_, r) =>
              ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "PTR", "LOC"].includes(r.type) && (
                <Button
                  onClick={() =>
                    setProbe({
                      revision: Date.now(),
                      name: r.name,
                      url: path + "/advanced/records/" + encodeURIComponent(r.id) + "/check?" + new URLSearchParams({ page: String(page), name: filter }),
                    })
                  }
                >
                  {l("Check DNS", "检查解析")}
                </Button>
              ),
          },
          ...(canWrite && features.fields.length
            ? [
                {
                  title: "",
                  render: (_: unknown, r: DNSRecord) =>
                    !r.readOnly && (
                      <Button
                        onClick={() => {
                          edit(r);
                          setField(features.fields[0]);
                          setValue("");
                          setPlan(undefined);
                        }}
                      >
                        {l("Edit", "编辑")}
                      </Button>
                    ),
                },
              ]
            : []),
        ]}
      />
      {probe && (
        <Modal open title={probe.name} onCancel={() => setProbe(undefined)} footer={null} loading={!checked}>
          {checked?.error && <Alert type="error" title={checked.error} />}
          {checked?.data && (
            <Descriptions
              column={1}
              items={[
                {
                  key: "status",
                  label: l("Result", "检查结果"),
                  children:
                    {
                      active: l("Matching answer", "解析匹配"),
                      mismatch: l("Different answer", "解析不匹配"),
                      not_found: l("No matching DNS answer", "无此类型解析"),
                    }[checked.data.status] ?? checked.data.status,
                },
                ...(checked.data.expected ? [{ key: "expected", label: l("Expected", "预期值"), children: checked.data.expected }] : []),
                { key: "actual", label: l("DNS answers", "实际解析值"), children: checked.data.actual.join(" · ") || "—" },
              ]}
            />
          )}
        </Modal>
      )}
      {record && (
        <Modal
          open
          title={record.name + " · " + record.type}
          onCancel={() => !busy && edit(undefined)}
          confirmLoading={busy}
          onOk={save}
          okText={plan ? l("Apply", "执行修改") : l("Preview", "预览修改")}
          okButtonProps={{ disabled: field !== "remark" && !value }}
        >
          <Form layout="vertical">
            <Form.Item label={l("Attribute", "属性")}>
              <Select
                disabled={busy || !!plan}
                value={field}
                options={features.fields.map((f) => ({ value: f, label: labels[f] ?? f }))}
                onChange={(f) => {
                  setField(f);
                  setValue("");
                }}
              />
            </Form.Item>
            <Form.Item label={l("New value", "新值")}>
              {choices ? (
                <Select disabled={busy || !!plan} options={choices} value={value || undefined} onChange={setValue} showSearch optionFilterProp="label" />
              ) : (
                <Input disabled={busy || !!plan} value={value} maxLength={512} onChange={(e) => setValue(e.target.value)} />
              )}
            </Form.Item>
            {groups?.error && <Alert type="error" title={groups.error} />}
            {zone?.error && <Alert type="error" title={zone.error} />}
            {plan && <Alert type="info" title={l("Confirm attribute change", "确认属性变更")} description={(plan.before || "∅") + " → " + (value || "∅")} />}
          </Form>
        </Modal>
      )}
    </Space>
  );
}
function Logs({ path }: { path: string }) {
  const l = useLabels();
  const [page, setPage] = useState(1);
  const r = useData<Page<{ time: string; action: string }>>(path + "/batch/logs?page=" + page);
  return (
    <>
      {r?.error && <Alert type="error" title={r.error} />}
      <Table
        rowKey="key"
        size="small"
        loading={!r}
        dataSource={r?.data?.result.map((row, i) => ({ ...row, key: page + "-" + i }))}
        pagination={{ current: page, total: r?.data?.result_info.total_count ?? 0, pageSize: 20, onChange: setPage, showSizeChanger: false }}
        columns={[
          { title: l("Time", "时间"), dataIndex: "time" },
          { title: l("Operation", "操作"), dataIndex: "action" },
        ]}
      />
    </>
  );
}

export default function DNSAdvanced({ base, zone, canWrite }: Props) {
  const l = useLabels();
  const path = base + "/zones/" + encodeURIComponent(zone.id);
  const advanced = path + "/advanced";
  const r = useData<Features>(advanced + "/features");
  const b = useData<Attributes>(path + "/batch/features");
  const f = r?.data;
  const tabs = [
    ...(f?.details ? [{ key: "details", label: l("Zone details", "域名详情"), children: <DetailsView path={advanced} /> }] : []),
    ...(b?.data
      ? [
          {
            key: "records",
            label: l("Record settings", "记录属性"),
            children: <AttributesView path={path} features={b.data} hasDetails={!!f?.details} canWrite={canWrite} />,
          },
        ]
      : []),
    ...(f?.aliases ? [{ key: "aliases", label: l("Domain aliases", "域名别名"), children: <Aliases path={advanced} canWrite={canWrite} /> }] : []),
    ...(f?.weights
      ? [{ key: "weights", label: l("Weight rules", "权重规则"), children: <Weights path={advanced} zone={zone.name} canWrite={canWrite} /> }]
      : []),
    ...(b?.data?.logs ? [{ key: "logs", label: l("Provider history", "服务商操作日志"), children: <Logs path={path} /> }] : []),
  ];
  return (
    <div>
      {(r?.error || b?.error) && <Alert showIcon type="error" title={r?.error || b?.error} />}
      {tabs.length > 0 ? <Tabs key={path} items={tabs} destroyOnHidden /> : null}
    </div>
  );
}
