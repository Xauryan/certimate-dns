import { useState } from "react";
import { Alert, App, Button, Descriptions, Modal, Space, Table, Typography } from "antd";
import { dnsRequest } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";
import { Editor, LoadError, PageControls, useConfirm, useLabel, usePage, useResource, type Field, type Values } from "./shared";

import VerificationTargets, { BulkVerification } from "./VerificationTargets";

type Verification = Record<string, string>;
type Hostname = {
  id: string;
  hostname: string;
  status: string;
  custom_origin_server?: string;
  ssl: { status?: string; method?: string; settings?: { min_tls_version?: string }; validation_records?: Verification[] };
  ownership_verification?: Verification;
  ownership_verification_http?: Verification;
};

function ZoneSettings({ base }: { base: string }) {
  const l = useLabel();
  const confirm = useConfirm();
  const [editing, setEditing] = useState(false);
  const fallback = useResource<{ origin: string; status?: string }>(base + "/fallback");
  const dcv = useResource<{ uuid: string }>(base + "/dcv");
  return (
    <div className="flex flex-col gap-2">
      {fallback.error && <LoadError text={fallback.error} retry={fallback.reload} />}
      <Space wrap>
        <strong>{l("Fallback origin", "回退源站")}</strong>
        {fallback.data?.origin || "—"} {fallback.data?.status}
        <Button disabled={!fallback.data} onClick={() => setEditing(true)}>
          {l("Set origin", "设置源站")}
        </Button>
        {fallback.data?.origin && (
          <Button
            danger
            onClick={() =>
              confirm(l("Remove fallback origin?", "删除回退源站？"), fallback.data!.origin, () => dnsRequest(base + "/fallback", "DELETE"), fallback.reload)
            }
          >
            {l("Remove", "删除")}
          </Button>
        )}
      </Space>
      {editing && (
        <Editor
          title={l("Set fallback origin", "设置回退源站")}
          fields={[
            { key: "origin", label: l("Origin hostname", "源站域名"), required: true, initial: fallback.data?.origin },
          ]}
          close={() => setEditing(false)}
          save={async ({ origin }) => {
            await dnsRequest(base + "/fallback", "PUT", { origin });
            fallback.reload();
          }}
        />
      )}
      {dcv.error ? (
        <LoadError text={dcv.error} retry={dcv.reload} />
      ) : (
        <Space wrap>
          <strong>{l("DCV delegation UUID", "DCV 委派 UUID")}</strong>
          <Typography.Text copyable={!!dcv.data?.uuid}>{dcv.data?.uuid || "—"}</Typography.Text>
        </Space>
      )}
    </div>
  );
}

function VerificationDetails({ row, base }: { row: Hostname; base: string }) {
  const groups = [row.ownership_verification, row.ownership_verification_http, ...(row.ssl.validation_records ?? [])];
  return (
    <>
      {groups.map((group, i) => {
        const fields = Object.entries(group ?? {}).filter(([, v]) => !!v);
        const txtName = group?.txt_name || (group?.type?.toLowerCase() === "txt" && group.name);
        const txtValue = group?.txt_value || group?.value;
        return (
          fields.length > 0 && (
            <div key={i}>
              <Descriptions
                column={1}
                size="small"
                bordered
                items={fields.map(([k, v]) => ({
                  key: k,
                  label: k,
                  children: (
                    <Typography.Text className="break-all" copyable>
                      {v}
                    </Typography.Text>
                  ),
                }))}
              />
              {txtName && txtValue && <VerificationTargets base={base} name={txtName} value={txtValue} />}
            </div>
          )
        );
      })}
    </>
  );
}

export default function Hostnames({ base }: { base: string }) {
  const l = useLabel(),
    confirm = useConfirm();
  const { modal } = App.useApp();
  const url = base + "/hostnames";
  const list = usePage<Hostname>(url);
  const [selected, setSelected] = useState<string[]>([]);
  const [editor, setEditor] = useState<Hostname | "add" | "edit" | "delete" | null>(null);
  const [details, setDetails] = useState<Hostname>();
  const [verify, setVerify] = useState<"certificate" | "ownership">();
  const [outcomes, setOutcomes] = useState<{ item: string; error?: string }[]>();
  const row = typeof editor === "object" ? editor : null;
  const multi = editor === "edit";
  const tls = ["1.0", "1.1", "1.2", "1.3"];
  const keep = l("Keep existing", "保留现有设置");
  const fallback = l("Use fallback", "使用回退源站");
  const fields: Field[] =
    editor === "delete"
      ? []
      : [
          ...(editor === "add" ? [{ key: "hosts", label: l("Hostnames (one per line)", "主机名（每行一个）"), required: true, multiline: true }] : []),
          ...(multi
            ? [{ key: "originMode", label: l("Origin update", "源站变更"), options: [keep, fallback, l("Set origin", "设置源站")], initial: keep }]
            : []),
          { key: "origin", label: l("Custom origin (blank uses fallback)", "自定义源站（留空使用回退源站）"), initial: row?.custom_origin_server },
          {
            key: "method",
            label: l("Validation method", "验证方式"),
            options: multi ? [keep, "http", "txt"] : ["http", "txt"],
            initial: multi ? keep : (row?.ssl?.method ?? "txt"),
            required: true,
          },
          {
            key: "minTLS",
            label: l("Minimum TLS", "最低 TLS 版本"),
            options: multi ? [keep, ...tls] : tls,
            initial: multi ? keep : (row?.ssl?.settings?.min_tls_version ?? "1.2"),
            required: true,
          },
        ];
  const removeTitle = l("Delete selected hostnames?", "删除选中的主机名？");
  async function save(values: Values) {
    const items = editor === "add" ? Array.from(new Set((values.hosts ?? "").split(/\s+/).filter(Boolean))) : row ? [row.id] : selected;
    if (items.length < 1 || items.length > 100) throw new Error(l("Select 1 to 100 hostnames.", "每次可处理 1 至 100 个主机名。"));
    const body: Record<string, string> = {};
    if (!multi || values.originMode !== keep) {
      if (multi && values.originMode !== fallback && !values.origin?.trim()) throw new Error(l("Enter a custom origin.", "请输入自定义源站。"));
      body.origin = multi && values.originMode === fallback ? "" : (values.origin ?? "");
    }
    if (values.method && values.method !== keep) body.method = values.method;
    if (values.minTLS && values.minTLS !== keep) body.minTLS = values.minTLS;
    if (multi && !Object.keys(body).length) throw new Error(l("Select a setting to change.", "请选择需要修改的设置。"));
    const results: { item: string; error?: string }[] = [];
    for (const item of items) {
      const label = list.rows.find((r) => r.id === item)?.hostname ?? item;
      try {
        if (editor === "delete") await dnsRequest(url + "/" + encodeURIComponent(item), "DELETE");
        else if (editor === "add") await dnsRequest(url, "POST", { ...body, hostname: item });
        else await dnsRequest(url + "/" + encodeURIComponent(item), "PATCH", body);
        results.push({ item: label });
      } catch (e) {
        results.push({ item: label, error: unwrapErrMsg(e) });
      }
    }
    setOutcomes(results);
    setSelected([]);
    list.reload();
  }
  return (
    <>
      <ZoneSettings base={base} />
      <Space wrap>
        <Button type="primary" onClick={() => setEditor("add")}>
          {l("Add hostnames", "添加主机名")}
        </Button>
        <Button disabled={!selected.length} onClick={() => setEditor("edit")}>
          {l("Edit selected", "批量编辑")}
        </Button>
        <Button disabled={!selected.length} onClick={() => setVerify("ownership")}>
          {l("Verify hostname ownership", "批量主机名 TXT 验证")}
        </Button>
        <Button disabled={!selected.length} onClick={() => setVerify("certificate")}>
          {l("Verify certificates", "批量证书 TXT 验证")}
        </Button>
        <Button danger disabled={!selected.length} onClick={() => setEditor("delete")}>
          {l("Delete selected", "批量删除")}
        </Button>
        <Button onClick={list.reload}>{l("Refresh", "刷新")}</Button>
      </Space>
      {outcomes && (
        <Alert
          closable
          onClose={() => setOutcomes(undefined)}
          type={outcomes.some((x) => x.error) ? "warning" : "success"}
          title={l("Completed", "已成功") + " " + outcomes.filter((x) => !x.error).length + " / " + outcomes.length}
          description={outcomes
            .filter((x) => x.error)
            .map((x) => (
              <div key={x.item}>
                {x.item} · {x.error}
              </div>
            ))}
        />
      )}
      {list.error && <LoadError text={list.error} retry={list.reload} />}
      <Table<Hostname>
        rowKey="id"
        dataSource={list.rows}
        loading={list.loading}
        pagination={false}
        scroll={{ x: 850 }}
        rowSelection={{ selectedRowKeys: selected, onChange: (keys) => setSelected(keys.map(String)) }}
        columns={[
          {
            title: l("Hostname", "主机名"),
            dataIndex: "hostname",
            render: (name: string, r) => (
              <Button type="link" onClick={() => setDetails(r)}>
                {name}
              </Button>
            ),
          },
          { title: l("Origin", "源站"), dataIndex: "custom_origin_server" },
          { title: l("Status", "状态"), dataIndex: "status" },
          { title: "TLS", render: (_, r) => [r.ssl?.status, r.ssl?.method, r.ssl?.settings?.min_tls_version].filter(Boolean).join(" · ") },
          {
            title: l("Actions", "操作"),
            render: (_, r) => (
              <Space>
                <Button onClick={() => setEditor(r)}>{l("Edit", "编辑")}</Button>
                <Button
                  onClick={() =>
                    modal.confirm({
                      title: l("Revalidate hostname?", "重新验证主机名？"),
                      content: r.hostname,
                      onOk: async () => {
                        try {
                          await dnsRequest(url + "/" + r.id + "/revalidate", "POST");
                        } catch (e) {
                          modal.error({ title: unwrapErrMsg(e) });
                        } finally {
                          list.reload();
                        }
                      },
                    })
                  }
                >
                  {l("Revalidate", "重新验证")}
                </Button>
                <Button
                  danger
                  onClick={() => confirm(l("Delete hostname?", "删除主机名？"), r.hostname, () => dnsRequest(url + "/" + r.id, "DELETE"), list.reload)}
                >
                  {l("Delete", "删除")}
                </Button>
              </Space>
            ),
          },
        ]}
      />
      <PageControls
        {...list}
        count={list.rows.length}
        setPage={(p) => {
          setSelected([]);
          list.setPage(p);
        }}
      />
      {verify && (
        <BulkVerification
          base={base}
          close={() => setVerify(undefined)}
          entries={list.rows
            .filter((r) => selected.includes(r.id))
            .flatMap((r) =>
              verify === "ownership"
                ? r.ownership_verification?.type?.toLowerCase() === "txt" && r.ownership_verification.name && r.ownership_verification.value
                  ? [{ name: r.ownership_verification.name, value: r.ownership_verification.value }]
                  : []
                : (r.ssl?.validation_records ?? []).filter((v) => v.txt_name && v.txt_value).map((v) => ({ name: v.txt_name, value: v.txt_value }))
            )}
        />
      )}
      {details && (
        <Modal open title={details.hostname} onCancel={() => setDetails(undefined)} footer={null}>
          <VerificationDetails base={base} row={details} />
        </Modal>
      )}
      {editor && (
        <Editor
          title={
            editor === "delete" ? removeTitle : (row?.hostname ?? (multi ? l("Edit selected hostnames", "批量编辑主机名") : l("Add hostnames", "添加主机名")))
          }
          fields={fields}
          save={save}
          close={() => setEditor(null)}
        >
          {(multi || editor === "delete") && (
            <p>
              {list.rows
                .filter((r) => selected.includes(r.id))
                .map((r) => r.hostname)
                .join(", ")}
            </p>
          )}
        </Editor>
      )}
    </>
  );
}
