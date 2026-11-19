import { useState, type Key } from "react";
import { AccountActions, BatchActions, Categories } from "./CatalogActions";
import { Link, useSearchParams } from "react-router-dom";
import { Alert, App, Button, Checkbox, Input, Select, Space, Switch, Table, Tabs, Tag, Typography } from "antd";

import { dnsRequest } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";
import { type Account, base, useCatalog, useLabels, type Zone } from "./catalog";
import DomainDetail from "./DomainDetail";

export default function DomainCatalog() {
  const l = useLabels();
  const { message } = App.useApp();
  const [params, setParams] = useSearchParams();
  const id = params.get("id");
  const [revision, setRevision] = useState(0);
  const [tab, setTab] = useState("domains");
  const [accountId, setAccountId] = useState("");
  const [search, setSearch] = useState("");
  const [group, setGroup] = useState("");
  const [tag, setTag] = useState("");
  const [due, setDue] = useState(false);
  const [page, setPage] = useState(1);
  const [actions, setActions] = useState<Account | null>(null);
  const [selected, setSelected] = useState<Key[]>([]);
  const [busy, setBusy] = useState("");
  const accounts = useCatalog<Account[]>("/accounts", revision);
  const query = new URLSearchParams({ accessId: accountId, q: search, group, tag, due: String(due), page: String(page) });
  const zones = useCatalog<{ items: Zone[]; total: number }>("/domains?" + query, revision);
  const refresh = () => setRevision((n) => n + 1);
  async function changeAccount(row: Account, enabled?: boolean) {
    setBusy(row.id);
    try {
      if (enabled === undefined) {
        const count = await dnsRequest<number>(base + "/accounts/" + row.id + "/sync", "POST");
        message.success(l.synced + " · " + count);
      } else {
        await dnsRequest(base + "/accounts/" + row.id, "PATCH", { enabled });
        message.success(l.saved);
      }
      refresh();
    } catch (err) {
      message.error(unwrapErrMsg(err));
    } finally {
      setBusy("");
    }
  }
  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      {actions && <AccountActions account={actions} onSaved={refresh} onClose={() => setActions(null)} />}
      {id ? (
        <DomainDetail key={id} id={id} back={() => setParams({})} />
      ) : (
        <>
          <Typography.Title level={3} style={{ margin: 0 }}>
            {l.title}
          </Typography.Title>
          {accounts?.error && <Alert type="error" title={accounts.error} />}
          <Tabs
            activeKey={tab}
            onChange={setTab}
            tabBarExtraContent={<Button onClick={refresh}>{l.refresh}</Button>}
            items={[
              {
                key: "domains",
                label: l.domains,
                children: (
                  <div className="flex flex-col gap-3">
                    <Space wrap>
                      <Select
                        aria-label={l.account}
                        allowClear
                        placeholder={l.allAccounts}
                        style={{ minWidth: 180 }}
                        value={accountId || undefined}
                        options={accounts?.data?.map((a) => ({ value: a.id, label: a.name }))}
                        onChange={(v) => {
                          setAccountId(v || "");
                          setPage(1);
                        }}
                      />
                      <Input.Search
                        aria-label={l.search}
                        placeholder={l.search}
                        allowClear
                        onSearch={(v) => {
                          setSearch(v.trim());
                          setPage(1);
                        }}
                      />
                      <Input.Search
                        aria-label={l.groupFilter}
                        placeholder={l.groupFilter}
                        allowClear
                        onSearch={(v) => {
                          setGroup(v.trim());
                          setPage(1);
                        }}
                      />
                      <Input.Search
                        aria-label={l.tagFilter}
                        placeholder={l.tagFilter}
                        allowClear
                        onSearch={(v) => {
                          setTag(v.trim());
                          setPage(1);
                        }}
                      />
                      <Checkbox
                        checked={due}
                        onChange={(e) => {
                          setDue(e.target.checked);
                          setPage(1);
                        }}
                      >
                        {l.due}
                      </Checkbox>
                    </Space>
                    {zones?.error && <Alert type="error" title={zones.error} />}
                    <BatchActions
                      ids={selected}
                      revision={revision}
                      onSaved={() => {
                        setSelected([]);
                        refresh();
                      }}
                    />
                    <Table<Zone>
                      rowSelection={{ selectedRowKeys: selected, onChange: setSelected }}
                      rowKey="id"
                      scroll={{ x: 720 }}
                      loading={!zones}
                      dataSource={zones?.data?.items ?? []}
                      pagination={{ current: page, pageSize: 25, showSizeChanger: false, total: zones?.data?.total ?? 0, onChange: setPage }}
                      columns={[
                        { title: l.name, render: (_, z) => <Link to={"?id=" + z.id}>{z.name}</Link> },
                        { title: l.account, dataIndex: "accountName" },
                        { title: l.group, dataIndex: "groupName" },
                        { title: l.tags, render: (_, z) => z.tags?.map((t) => <Tag key={t}>{t}</Tag>) },
                        { title: l.expiry, dataIndex: "expiresOn" },
                        { title: l.status, render: (_, z) => (!z.enabled ? l.disabled : !z.present ? l.missing : z.status || l.active) },
                      ]}
                    />
                  </div>
                ),
              },
              {
                key: "categories",
                label: l.category,
                children: <Categories onSaved={refresh} revision={revision} />,
              },
              {
                key: "accounts",
                label: l.accounts,
                children: (
                  <div className="flex flex-col gap-3">
                    <Link to="/accesses?usage=dns-management">{l.access}</Link>
                    <Table<Account>
                      rowKey="id"
                      scroll={{ x: 540 }}
                      loading={!accounts}
                      dataSource={accounts?.data ?? []}
                      columns={[
                        { title: l.name, dataIndex: "name" },
                        { title: l.provider, dataIndex: "provider" },
                        { title: l.notes, dataIndex: "notes" },
                        { title: l.domains, dataIndex: "domainCount" },
                        { title: l.manage, render: (_, a) => <Button onClick={() => setActions(a)}>{l.manage}</Button> },
                        {
                          title: l.enabled,
                          render: (_, a) => (
                            <Switch aria-label={l.enabled + " · " + a.name} checked={a.enabled} disabled={!!busy} onChange={(v) => changeAccount(a, v)} />
                          ),
                        },
                        {
                          title: l.domains,
                          render: (_, a) => (
                            <Button disabled={!a.enabled || !!busy} loading={busy === a.id} onClick={() => changeAccount(a)}>
                              {l.sync}
                            </Button>
                          ),
                        },
                      ]}
                    />
                  </div>
                ),
              },
            ]}
          />
        </>
      )}
    </div>
  );
}
