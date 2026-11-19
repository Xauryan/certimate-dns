import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { Alert, App, Button, Form, Input, Modal, Popconfirm, Select, Space, Table, Tabs, Typography } from "antd";

import { getPocketBase } from "@/repository/_pocketbase";
import { unwrapErrMsg } from "@/utils/error";
import QuickLink from "./QuickLink";

type Role = "reader" | "editor";
type Scope = "workspace" | "zone";
interface Member {
  id: string;
  email: string;
  disabled: boolean;
  apiEnabled: boolean;
}
interface Workspace {
  id: string;
  name: string;
}
interface Zone {
  id: string;
  name: string;
  accountRef: string;
  present: boolean;
  quickLoginEnabled: boolean;
}
interface WorkspaceZone {
  id: string;
  zone: string;
  workspace: string;
}
interface Grant {
  id: string;
  member: string;
  target: string;
  scope: Scope;
  role: Role;
}

const pb = getPocketBase();
const grantCollection = (scope: Scope) => (scope === "workspace" ? "dns_workspace_grants" : "dns_zone_grants");

async function loadPermissions() {
  const list = <T,>(collection: string, fields: string, sort: string) => pb.collection(collection).getFullList<T>({ fields, sort, requestKey: null });
  const [members, workspaces, zones, accounts, links, workspaceGrants, zoneGrants] = await Promise.all([
    list<Member>("dns_members", "id,email,disabled,apiEnabled", "email"),
    list<Workspace>("dns_workspaces", "id,name", "name"),
    list<Zone>("dnsZone", "id,name,accountRef,present,quickLoginEnabled", "name,id"),
    list<{ id: string; name: string }>("access", "id,name", "name"),
    list<WorkspaceZone>("dns_workspace_zones", "id,workspace,zone", "id"),
    list<{ id: string; member: string; workspace: string; role: Role }>("dns_workspace_grants", "id,member,workspace,role", "id"),
    list<{ id: string; member: string; zone: string; role: Role }>("dns_zone_grants", "id,member,zone,role", "id"),
  ]);
  const grants: Grant[] = [
    ...workspaceGrants.map((g) => ({ ...g, scope: "workspace" as const, target: g.workspace })),
    ...zoneGrants.map((g) => ({ ...g, scope: "zone" as const, target: g.zone })),
  ];
  return { members, workspaces, zones, accounts, links, grants };
}

export default function DNSPermissions() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [data, setData] = useState<Awaited<ReturnType<typeof loadPermissions>>>();
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);
  const [pending, setPending] = useState(false);
  const writing = useRef(false);
  const [reset, setReset] = useState<Member>();
  const [rename, setRename] = useState<{ collection: string; id: string; field: string; value: string }>();
  const [memberForm] = Form.useForm<{ email: string; password: string }>();
  const [grantForm] = Form.useForm<{ member: string; scope: Scope; target: string; role: Role }>();
  const scope = Form.useWatch("scope", grantForm) ?? "workspace";

  useEffect(() => {
    let current = true;
    loadPermissions().then(
      (next) => {
        if (current) {
          setData(next);
          setError("");
        }
      },
      (err) => {
        if (current) setError(unwrapErrMsg(err));
      }
    );
    return () => {
      current = false;
    };
  }, [revision]);

  async function mutate(action: () => Promise<unknown>, done?: () => void) {
    if (writing.current) return;
    writing.current = true;
    setPending(true);
    try {
      await action();
      done?.();
      setRevision((v) => v + 1);
    } catch (err) {
      message.error(unwrapErrMsg(err));
    } finally {
      writing.current = false;
      setPending(false);
    }
  }

  const memberOptions = data?.members.map((m) => ({ value: m.id, label: m.email })) ?? [];
  const workspaceOptions = data?.workspaces.map((w) => ({ value: w.id, label: w.name })) ?? [];
  const accountNames = new Map(data?.accounts.map((a) => [a.id, a.name]));
  const zoneOptions =
    data?.zones.map((z) => ({ value: z.id, label: z.name + " · " + (accountNames.get(z.accountRef) || z.accountRef), disabled: !z.present })) ?? [];
  const wsNames = new Map(workspaceOptions.map((o) => [o.value, o.label]));
  const zoneNames = new Map(zoneOptions.map((o) => [o.value, o.label]));
  const emails = new Map(memberOptions.map((o) => [o.value, o.label]));
  const roles = ["reader", "editor"].map((value) => ({ value, label: t("dnsauth." + value) }));
  const required = [{ required: true }];
  const search = { optionFilterProp: "label" };
  const revoke = (collection: string, id: string, label: string) => (
    <Popconfirm title={t("dnsauth.confirm")} onConfirm={() => mutate(() => pb.collection(collection).delete(id))}>
      <Button disabled={pending} danger type="link">
        {label}
      </Button>
    </Popconfirm>
  );

  const members = (
    <>
      <Form
        form={memberForm}
        layout="inline"
        disabled={pending}
        onFinish={(values) =>
          mutate(
            () =>
              pb
                .collection("dns_members")
                .create({ email: values.email.trim(), password: values.password, passwordConfirm: values.password }, { fields: "id" }),
            () => memberForm.resetFields()
          )
        }
      >
        <Form.Item name="email" label={t("dnsauth.email")} rules={[{ required: true, type: "email" }]}>
          <Input type="email" autoComplete="off" />
        </Form.Item>
        <Form.Item name="password" label={t("dnsauth.password")} rules={[{ required: true, min: 10 }]}>
          <Input.Password autoComplete="new-password" />
        </Form.Item>
        <Form.Item>
          <Button htmlType="submit" type="primary">
            {t("dnsauth.addMember")}
          </Button>
        </Form.Item>
      </Form>
      <Table<Member>
        rowKey="id"
        dataSource={data?.members}
        columns={[
          { title: t("dnsauth.email"), dataIndex: "email" },
          { title: t("dns.status"), render: (_, m) => t(m.disabled ? "dnsauth.disabled" : "dnsauth.enabled") },
          {
            title: t("dnsauth.interfaceKeys"),
            render: (_, m) => (
              <Popconfirm
                title={t("dnsauth.confirm")}
                onConfirm={() => mutate(() => pb.collection("dns_members").update(m.id, { apiEnabled: !m.apiEnabled }, { fields: "id" }))}
              >
                <Button disabled={pending}>{t(m.apiEnabled ? "dnsauth.disable" : "dnsauth.enable")}</Button>
              </Popconfirm>
            ),
          },
          {
            title: t("dns.actions"),
            render: (_, m) => (
              <Space>
                <Popconfirm
                  title={t("dnsauth.confirm")}
                  onConfirm={() => mutate(() => pb.collection("dns_members").update(m.id, { disabled: !m.disabled }, { fields: "id" }))}
                >
                  <Button type="link" disabled={pending}>
                    {t(m.disabled ? "dnsauth.enable" : "dnsauth.disable")}
                  </Button>
                </Popconfirm>
                <Button type="link" disabled={pending} onClick={() => setRename({ collection: "dns_members", id: m.id, field: "email", value: m.email })}>
                  {t("dnsauth.editEmail")}
                </Button>
                <Button type="link" disabled={pending} onClick={() => setReset(m)}>
                  {t("dnsauth.resetPassword")}
                </Button>
                {revoke("dns_members", m.id, t("dnsauth.removeMember"))}
              </Space>
            ),
          },
        ]}
      />
    </>
  );

  const workspaces = (
    <>
      <Form layout="inline" disabled={pending} onFinish={(v) => mutate(() => pb.collection("dns_workspaces").create({ name: v.name.trim() }))}>
        <Form.Item name="name" label={t("dnsauth.workspaceName")} rules={[{ required: true, whitespace: true }]}>
          <Input maxLength={160} />
        </Form.Item>
        <Form.Item>
          <Button htmlType="submit">{t("dnsauth.createWorkspace")}</Button>
        </Form.Item>
      </Form>
      <Table<Workspace>
        rowKey="id"
        dataSource={data?.workspaces}
        columns={[
          { title: t("dnsauth.workspace"), dataIndex: "name" },
          {
            title: t("dns.actions"),
            render: (_, w) => (
              <Space>
                <Button type="link" onClick={() => setRename({ collection: "dns_workspaces", id: w.id, field: "name", value: w.name })}>
                  {t("dnsauth.rename")}
                </Button>
                {revoke("dns_workspaces", w.id, t("dnsauth.removeWorkspace"))}
              </Space>
            ),
          },
        ]}
      />
      <Form layout="inline" disabled={pending} onFinish={(v) => mutate(() => pb.collection("dns_workspace_zones").create(v))}>
        <Form.Item name="workspace" label={t("dnsauth.workspace")} rules={required}>
          <Select style={{ minWidth: 170 }} showSearch={search} options={workspaceOptions} />
        </Form.Item>
        <Form.Item name="zone" label={t("dns.zone")} rules={required}>
          <Select style={{ minWidth: 210 }} showSearch={search} options={zoneOptions} />
        </Form.Item>
        <Form.Item>
          <Button htmlType="submit" type="primary">
            {t("dnsauth.addZone")}
          </Button>
        </Form.Item>
      </Form>
      <Table<WorkspaceZone>
        rowKey="id"
        dataSource={data?.links}
        columns={[
          { title: t("dnsauth.workspace"), render: (_, row) => wsNames.get(row.workspace) },
          { title: t("dns.zone"), render: (_, row) => zoneNames.get(row.zone) },
          { title: t("dns.actions"), render: (_, row) => revoke("dns_workspace_zones", row.id, t("dnsauth.removeZone")) },
        ]}
      />
    </>
  );

  const grants = (
    <>
      <Typography.Paragraph>{t("dnsauth.roleHelp")}</Typography.Paragraph>
      <Form
        layout="inline"
        disabled={pending}
        form={grantForm}
        initialValues={{ scope: "workspace", role: "reader" }}
        onFinish={(v) =>
          mutate(() => {
            const existing = data?.grants.find((g) => g.member === v.member && g.scope === v.scope && g.target === v.target);
            const collection = pb.collection(grantCollection(v.scope));
            return existing ? collection.update(existing.id, { role: v.role }) : collection.create({ member: v.member, [v.scope]: v.target, role: v.role });
          })
        }
      >
        <Form.Item name="member" label={t("dnsauth.member")} rules={required}>
          <Select style={{ minWidth: 180 }} showSearch={search} options={memberOptions} />
        </Form.Item>
        <Form.Item name="scope" label={t("dnsauth.scope")} rules={required}>
          <Select
            onChange={() => grantForm.setFieldValue("target", undefined)}
            options={[
              { value: "workspace", label: t("dnsauth.workspace") },
              { value: "zone", label: t("dns.zone") },
            ]}
          />
        </Form.Item>
        <Form.Item name="target" label={t("dnsauth.scopeTarget")} rules={required}>
          <Select style={{ minWidth: 180 }} showSearch={search} options={scope === "workspace" ? workspaceOptions : zoneOptions} />
        </Form.Item>
        <Form.Item name="role" label={t("dnsauth.role")} rules={required}>
          <Select options={roles} />
        </Form.Item>
        <Form.Item>
          <Button htmlType="submit" type="primary">
            {t("dnsauth.grant")}
          </Button>
        </Form.Item>
      </Form>
      <Table<Grant>
        rowKey={(g) => g.scope + g.id}
        dataSource={data?.grants}
        columns={[
          { title: t("dnsauth.member"), render: (_, g) => emails.get(g.member) },
          { title: t("dnsauth.scope"), render: (_, g) => t(g.scope === "workspace" ? "dnsauth.workspace" : "dns.zone") },
          { title: t("dnsauth.scopeTarget"), render: (_, g) => (g.scope === "workspace" ? wsNames : zoneNames).get(g.target) },
          { title: t("dnsauth.role"), render: (_, g) => t("dnsauth." + g.role) },
          { title: t("dns.actions"), render: (_, g) => revoke(grantCollection(g.scope), g.id, t("dnsauth.revoke")) },
        ]}
      />
    </>
  );

  return (
    <main className="flex flex-col gap-4 p-4 md:p-6">
      <Space wrap>
        <Typography.Title level={3} style={{ margin: 0 }}>
          {t("dnsauth.permissions")}
        </Typography.Title>
        <Button onClick={() => setRevision((v) => v + 1)}>{t("dns.refresh")}</Button>
        <Link to="/dns-member">{t("dnsauth.portal")}</Link>
      </Space>
      {error && <Alert type="error" showIcon title={error} />}
      <Tabs
        items={[
          ["members", members],
          ["workspaces", workspaces],
          ["grants", grants],
          [
            "quickLinks",
            <Table<Zone>
              rowKey="id"
              dataSource={data?.zones}
              columns={[
                { title: t("dns.zone"), render: (_, row) => zoneNames.get(row.id) },
                { title: t("dns.status"), render: (_, row) => t(row.quickLoginEnabled ? "dnsauth.enabled" : "dnsauth.disabled") },
                {
                  title: t("dns.actions"),
                  render: (_, row) => (
                    <Space>
                      <Popconfirm
                        title={t("dnsauth.confirm")}
                        onConfirm={() => mutate(() => pb.collection("dnsZone").update(row.id, { quickLoginEnabled: !row.quickLoginEnabled }, { fields: "id" }))}
                      >
                        <Button type="link" disabled={pending}>
                          {t(row.quickLoginEnabled ? "dnsauth.disable" : "dnsauth.enable")}
                        </Button>
                      </Popconfirm>
                      {row.present && row.quickLoginEnabled && <QuickLink id={row.id} name={row.name} canWrite />}
                    </Space>
                  ),
                },
              ]}
            />,
          ],
        ].map(([key, pane]) => ({
          key: String(key),
          label: t("dnsauth." + key),
          children: <div className="flex flex-col gap-5">{pane}</div>,
        }))}
      />
      {rename && (
        <Modal open footer={null} title={t(rename.field === "email" ? "dnsauth.editEmail" : "dnsauth.rename")} onCancel={() => setRename(undefined)}>
          <Form
            layout="vertical"
            disabled={pending}
            initialValues={{ value: rename.value }}
            onFinish={({ value }) =>
              mutate(
                () => pb.collection(rename.collection).update(rename.id, { [rename.field]: value.trim() }, { fields: "id" }),
                () => setRename(undefined)
              )
            }
          >
            <Form.Item
              name="value"
              label={t(rename.field === "email" ? "dnsauth.email" : "dnsauth.workspaceName")}
              rules={[{ required: true, whitespace: true }, ...(rename.field === "email" ? [{ type: "email" as const }] : [])]}
            >
              <Input />
            </Form.Item>
            <Button type="primary" htmlType="submit">
              {t("dnsauth.save")}
            </Button>
          </Form>
        </Modal>
      )}
      {reset && (
        <Modal open title={t("dnsauth.resetPassword") + " · " + reset.email} footer={null} onCancel={() => setReset(undefined)}>
          <Form
            layout="vertical"
            disabled={pending}
            onFinish={(v) =>
              mutate(
                () =>
                  pb.collection("dns_members").update(
                    reset.id,
                    {
                      password: v.password,
                      passwordConfirm: v.password,
                    },
                    { fields: "id" }
                  ),
                () => setReset(undefined)
              )
            }
          >
            <Form.Item name="password" label={t("dnsauth.password")} rules={[{ required: true, min: 10 }]}>
              <Input.Password autoComplete="new-password" />
            </Form.Item>
            <Button htmlType="submit" type="primary">
              {t("dnsauth.savePassword")}
            </Button>
          </Form>
        </Modal>
      )}
    </main>
  );
}
