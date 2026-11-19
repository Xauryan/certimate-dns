import { useRef, useState } from "react";
import { useRequest } from "ahooks";
import { Alert, Button, Checkbox, Form, Input, Modal, Select, Table } from "antd";

import { getPocketBase } from "@/repository/_pocketbase";
import { list as listAccesses } from "@/repository/access";
import { unwrapErrMsg } from "@/utils/error";

import { type Issued, type KeyScope, type Label, type Zone, keyRequest, listZones, pageSize, useLabel } from "./model";

type Values = Omit<KeyScope, "zones"> & { label: string; zones: Zone[] };

// The key issuer requires an editor grant only for actions that can change the zone.
const writesZone = (action: string) =>
  !action.endsWith(".read") && action !== "domain.login" && ["record.", "domain.", "cf.hostname."].some((prefix) => action.startsWith(prefix));

function ZonePicker({ value = [], onChange, write, l }: { value?: Zone[]; onChange?: (zones: Zone[]) => void; write: boolean; l: Label }) {
  const [page, setPage] = useState(1);
  const zones = useRequest(() => listZones(page), { refreshDeps: [page] });
  return (
    <>
      {zones.error && <Alert type="error" showIcon title={unwrapErrMsg(zones.error)} action={<Button onClick={zones.refresh}>{l("Retry", "重试")}</Button>} />}
      <Table<Zone>
        size="small"
        rowKey="id"
        loading={zones.loading}
        dataSource={zones.error || zones.loading ? [] : zones.data?.items}
        pagination={{ current: page, pageSize, total: zones.data?.total ?? 0, showSizeChanger: false, onChange: setPage }}
        rowSelection={{
          preserveSelectedRowKeys: true,
          selectedRowKeys: value.map((z) => z.id),
          onChange: (ids) => {
            const known = new Map([...value, ...(zones.data?.items ?? [])].map((z) => [z.id, z]));
            onChange?.(ids.flatMap((id) => known.get(String(id)) ?? []));
          },
          getCheckboxProps: (zone) => ({ disabled: write && !zone.canWrite, "aria-label": zone.name }),
        }}
        columns={[
          { title: l("Domain", "域名"), dataIndex: "name" },
          { title: l("Provider / account ID", "服务商 / 账号 ID"), render: (_, zone) => zone.provider + " · " + zone.accessId },
          { title: l("Access", "权限"), render: (_, zone) => (zone.canWrite ? l("Read / write", "读写") : l("Read only", "只读")) },
        ]}
      />
    </>
  );
}

export default function IssueKey({ close, issued }: { close: () => void; issued: (value: Issued) => void }) {
  const l = useLabel();
  const [form] = Form.useForm<Values>();
  const actions = useRequest(() => keyRequest<string[]>("/actions"));
  const admin = getPocketBase().authStore.isSuperuser;
  const accounts = useRequest(listAccesses, { ready: admin });
  const selectedActions: string[] = Form.useWatch("actions", form) ?? [];
  const writing = selectedActions.some(writesZone);
  const pending = useRef(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  async function submit(values: Values) {
    if (pending.current) return;
    pending.current = true;
    setSaving(true);
    setError("");
    try {
      const result = await keyRequest<Issued>("", "POST", { ...values, label: values.label.trim(), zones: values.zones.map((z) => z.id) });
      issued(result);
    } catch (err) {
      setError(unwrapErrMsg(err));
    } finally {
      pending.current = false;
      setSaving(false);
    }
  }
  return (
    <Modal
      open
      width={720}
      title={l("Issue interface key", "签发接口密钥")}
      onCancel={() => {
        if (!pending.current) close();
      }}
      okText={l("Issue key", "签发密钥")}
      okButtonProps={{ htmlType: "submit", form: "dns-issue-key", disabled: !actions.data?.length }}
      confirmLoading={saving}
    >
      {error && <Alert type="error" showIcon title={error} />}
      {actions.error && (
        <Alert type="error" showIcon title={unwrapErrMsg(actions.error)} action={<Button onClick={actions.refresh}>{l("Retry", "重试")}</Button>} />
      )}
      <Form<Values>
        id="dns-issue-key"
        form={form}
        disabled={saving}
        layout="vertical"
        initialValues={{ interfaces: ["api"], actions: ["domain.read", "record.read"], zones: [] }}
        onFinish={submit}
        onValuesChange={(changed, values) => {
          if (changed.actions && values.actions.some(writesZone) && values.zones.some((z) => !z.canWrite)) {
            form.setFieldValue(
              "zones",
              values.zones.filter((z) => z.canWrite)
            );
          }
        }}
      >
        <Form.Item
          name="label"
          label={l("Key name", "密钥名称")}
          rules={[
            { required: true, whitespace: true },
            {
              validator: (_, v?: string) =>
                new TextEncoder().encode(v?.trim()).length <= 100
                  ? Promise.resolve()
                  : Promise.reject(new Error(l("Use up to 100 UTF-8 bytes.", "名称最多可使用 100 个 UTF-8 字节。"))),
            },
          ]}
        >
          <Input maxLength={100} autoComplete="off" />
        </Form.Item>
        <Form.Item name="interfaces" label={l("Interfaces", "接口")} rules={[{ required: true, type: "array", min: 1 }]}>
          <Checkbox.Group
            options={[
              { value: "api", label: "REST API" },
              { value: "mcp", label: "MCP" },
            ]}
          />
        </Form.Item>
        <Form.Item name="actions" label={l("Allowed actions", "允许的操作")} rules={[{ required: true, type: "array", min: 1 }]}>
          <Select mode="multiple" loading={actions.loading} options={actions.data?.map((value) => ({ value }))} />
        </Form.Item>
        {admin && (
          <>
            <Form.Item name="accounts" label={l("Authorized accounts", "授权账号")}>
              <Select
                mode="multiple"
                maxCount={100}
                loading={accounts.loading}
                showSearch={{ optionFilterProp: "label" }}
                options={accounts.data?.items.map((a) => ({ value: a.id, label: a.name + " · " + a.provider + " · " + a.id }))}
              />
            </Form.Item>
            {accounts.error && (
              <Alert type="error" showIcon title={unwrapErrMsg(accounts.error)} action={<Button onClick={accounts.refresh}>{l("Retry", "重试")}</Button>} />
            )}
            <Form.Item name="global" valuePropName="checked">
              <Checkbox>{l("Allow global operations included in the selected actions", "允许所选操作中的全局操作")}</Checkbox>
            </Form.Item>
          </>
        )}
        <Form.Item
          name="zones"
          label={l("Authorized domains", "授权域名")}
          dependencies={["accounts", "global"]}
          rules={[
            ({ getFieldValue }) => ({
              validator: (_, zones: Zone[]) => {
                if (zones.length > 100) return Promise.reject(new Error(l("Select up to 100 domains.", "最多可选择 100 个域名。")));
                if (!zones.length && !(admin && (getFieldValue("global") || getFieldValue("accounts")?.length))) {
                  return Promise.reject(
                    new Error(
                      admin ? l("Select domains, accounts, or global operations.", "请选择域名、账号或全局操作。") : l("Select a domain.", "请选择域名。")
                    )
                  );
                }
                return Promise.resolve();
              },
            }),
          ]}
        >
          <ZonePicker write={writing} l={l} />
        </Form.Item>
      </Form>
    </Modal>
  );
}
