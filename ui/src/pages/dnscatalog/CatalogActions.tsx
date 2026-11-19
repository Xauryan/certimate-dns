import { useState } from "react";
import { Alert, App, Button, Checkbox, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Table } from "antd";
import type { Key } from "react";
import { dnsRequest, type Zone as RemoteZone, type Page } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";
import { base, type Account, type Category, useCatalog, useLabels } from "./catalog";

export function AccountActions({ account, onClose, onSaved }: { account: Account; onClose: () => void; onSaved: () => void }) {
  const l = useLabels(),
    { message, modal } = App.useApp();
  const [page, setPage] = useState(1),
    [selected, setSelected] = useState<Key[]>([]),
    [revision, setRevision] = useState(0);
  const [name, setName] = useState(""),
    [notes, setNotes] = useState(account.notes),
    [busy, setBusy] = useState(false);
  const url = "/accounts/" + account.id;
  const remote = useCatalog<Page<RemoteZone>>(account.enabled ? url + "/discover?page=" + page : undefined, revision);
  const capabilities = useCatalog<{ zoneCreate: boolean }>(
    account.enabled ? "/api/dns/capabilities/" + encodeURIComponent(account.provider) : undefined,
    revision,
    true
  );
  async function submit(path: string, body: object, method = "POST") {
    setBusy(true);
    try {
      await dnsRequest(base + url + path, method, body);
      message.success(l.saved);
      setRevision((v) => v + 1);
      setSelected([]);
      setName("");
      onSaved();
    } catch (e) {
      message.error(unwrapErrMsg(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal open title={account.name} onCancel={onClose} footer={null} width={740}>
      <Form layout="vertical">
        <Form.Item label={l.notes}>
          <Space.Compact block>
            <Input value={notes} maxLength={2048} onChange={(e) => setNotes(e.target.value)} />
            <Button loading={busy} onClick={() => submit("", { notes }, "PATCH")}>
              {l.save}
            </Button>
          </Space.Compact>
        </Form.Item>
      </Form>
      {account.enabled && (
        <>
          {capabilities?.error && <Alert type="error" title={capabilities.error} />}
          {capabilities?.data?.zoneCreate && (
            <Form layout="vertical">
              <Form.Item label={l.createRemote}>
                <Space.Compact block>
                  <Input aria-label={l.name} value={name} onChange={(e) => setName(e.target.value)} />
                  <Button
                    disabled={!name.trim() || busy}
                    onClick={() => modal.confirm({ title: l.createRemote, content: name, onOk: () => submit("/zones", { name: name.trim() }) })}
                  >
                    {l.createRemote}
                  </Button>
                </Space.Compact>
              </Form.Item>
            </Form>
          )}
          {remote?.error && <Alert type="error" title={remote.error} />}
          <Table<RemoteZone>
            size="small"
            rowKey="id"
            loading={!remote}
            dataSource={remote?.data?.result ?? []}
            rowSelection={{ preserveSelectedRowKeys: true, selectedRowKeys: selected, onChange: setSelected }}
            columns={[
              { title: l.name, dataIndex: "name" },
              { title: l.status, dataIndex: "status" },
            ]}
            pagination={{ current: page, pageSize: 20, showSizeChanger: false, total: remote?.data?.result_info.total_count ?? 0, onChange: setPage }}
          />
          <Button type="primary" disabled={!selected.length || selected.length > 500} loading={busy} onClick={() => submit("/import", { zoneIds: selected })}>
            {l.importZones} ({selected.length})
          </Button>
        </>
      )}
    </Modal>
  );
}

export function BatchActions({ ids, onSaved, revision }: { ids: Key[]; onSaved: () => void; revision: number }) {
  const l = useLabels(),
    { modal, message } = App.useApp();
  const [action, setAction] = useState("notes"),
    [notes, setNotes] = useState(""),
    [enabled, setEnabled] = useState(true),
    [categoryId, setCategory] = useState("");
  const [busy, setBusy] = useState(false);
  const categories = useCatalog<Category[]>("/categories", revision);
  async function submit() {
    setBusy(true);
    try {
      await dnsRequest(base + "/domains/batch", "POST", { ids, action, notes, enabled, categoryId });
      message.success(l.saved);
      onSaved();
    } catch (e) {
      message.error(unwrapErrMsg(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Space wrap>
      <Select
        aria-label={l.batch}
        value={action}
        onChange={setAction}
        options={[
          { value: "notes", label: l.notes },
          { value: "notice", label: l.reminder },
          { value: "category", label: l.category },
          { value: "delete", label: l.removeLocal },
        ]}
      />
      {action === "notes" && <Input aria-label={l.notes} maxLength={2048} value={notes} onChange={(e) => setNotes(e.target.value)} />}
      {action === "notice" && (
        <Checkbox checked={enabled} onChange={(e) => setEnabled(e.target.checked)}>
          {l.reminder}
        </Checkbox>
      )}
      {action === "category" && (
        <Select
          aria-label={l.category}
          value={categoryId}
          style={{ minWidth: 130 }}
          onChange={setCategory}
          options={[{ value: "", label: l.empty }, ...(categories?.data ?? []).map((c) => ({ value: c.id, label: c.name }))]}
        />
      )}
      {action === "category" && categories?.error && <Alert type="error" title={categories.error} />}
      <Button
        loading={busy}
        disabled={!ids.length || ids.length > 500}
        danger={action === "delete"}
        onClick={() => (action === "delete" ? modal.confirm({ title: l.removeLocal, content: l.removeExplanation, onOk: submit }) : submit())}
      >
        {l.batch} ({ids.length})
      </Button>
    </Space>
  );
}

export function Categories({ revision, onSaved }: { revision: number; onSaved: () => void }) {
  const l = useLabels(),
    { message } = App.useApp(),
    result = useCatalog<Category[]>("/categories", revision);
  const [draft, setDraft] = useState<Partial<Category> | null>(null),
    [busy, setBusy] = useState(false);
  async function write(method: string, c: Partial<Category>) {
    setBusy(true);
    try {
      await dnsRequest(
        base + "/categories" + (c.id ? "/" + c.id : ""),
        method,
        method === "DELETE" ? undefined : { name: c.name, remark: c.remark || "", sort: c.sort || 0 }
      );
      message.success(l.saved);
      setDraft(null);
      onSaved();
    } catch (e) {
      message.error(unwrapErrMsg(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="flex flex-col gap-3">
      <Space>
        <Button type="primary" onClick={() => setDraft({ name: "", remark: "", sort: 0 })}>
          {l.addCategory}
        </Button>
      </Space>
      {result?.error && <Alert type="error" title={result.error} />}
      <Table<Category>
        rowKey="id"
        dataSource={result?.data ?? []}
        loading={!result}
        columns={[
          { title: l.name, dataIndex: "name" },
          { title: l.notes, dataIndex: "remark" },
          { title: l.sort, dataIndex: "sort" },
          { title: l.domains, dataIndex: "domain_count" },
          {
            title: l.manage,
            render: (_, c) => (
              <Space>
                <Button onClick={() => setDraft(c)}>{l.edit}</Button>
                <Popconfirm title={l.removeCategory} onConfirm={() => write("DELETE", c)}>
                  <Button danger disabled={c.domain_count > 0 || busy}>
                    {l.removeCategory}
                  </Button>
                </Popconfirm>
              </Space>
            ),
          },
        ]}
      />
      {draft && (
        <Modal
          open
          title={l.category}
          onCancel={() => setDraft(null)}
          confirmLoading={busy}
          onOk={() => write(draft.id ? "PATCH" : "POST", draft)}
          okButtonProps={{ disabled: !draft.name?.trim() }}
        >
          <Form layout="vertical">
            <Form.Item label={l.name}>
              <Input maxLength={128} value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
            </Form.Item>
            <Form.Item label={l.notes}>
              <Input maxLength={100} value={draft.remark} onChange={(e) => setDraft({ ...draft, remark: e.target.value })} />
            </Form.Item>
            <Form.Item label={l.sort}>
              <InputNumber precision={0} value={draft.sort} onChange={(v) => setDraft({ ...draft, sort: v ?? 0 })} />
            </Form.Item>
          </Form>
        </Modal>
      )}
    </div>
  );
}
