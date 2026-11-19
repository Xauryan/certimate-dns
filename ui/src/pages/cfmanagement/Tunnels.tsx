import { useState } from "react";
import { Button, Space, Table, Tabs } from "antd";
import { dnsRequest } from "@/api/dns";
import { Editor, ScopeSelect, LoadError, PageControls, useConfirm, useLabel, usePage, useResource } from "./shared";

type Tunnel = { id: string; name: string; status: string; config_src: string };
type Route = { id: string; network?: string; hostname?: string; virtual_network_id?: string; comment?: string };
type Rule = { hostname: string; path?: string; service?: string };
function PrivateRoutes({ url, kind }: { url: string; kind: "cidr" | "hostname" }) {
  const l = useLabel(),
    confirm = useConfirm();
  const list = usePage<Route>(url);
  const [add, setAdd] = useState(false);
  const name = kind === "cidr" ? "CIDR" : l("Hostname", "主机名");
  return (
    <div className="flex flex-col gap-2">
      <Space>
        <Button type="primary" onClick={() => setAdd(true)}>
          {l("Add route", "添加路由")}
        </Button>
        <Button onClick={list.reload}>{l("Refresh", "刷新")}</Button>
      </Space>
      {list.error && <LoadError text={list.error} retry={list.reload} />}
      <Table<Route>
        rowKey="id"
        dataSource={list.rows}
        loading={list.loading}
        pagination={false}
        columns={[
          { title: name, dataIndex: kind === "cidr" ? "network" : "hostname" },
          { title: l("Comment", "备注"), dataIndex: "comment" },
          ...(kind === "cidr" ? [{ title: l("Virtual network", "虚拟网络"), dataIndex: "virtual_network_id" }] : []),
          {
            title: l("Actions", "操作"),
            render: (_, r) => (
              <Button
                danger
                onClick={() =>
                  confirm(l("Delete route?", "删除路由？"), r.hostname ?? r.network ?? r.id, () => dnsRequest(url + "/" + r.id, "DELETE"), list.reload)
                }
              >
                {l("Delete", "删除")}
              </Button>
            ),
          },
        ]}
      />
      <PageControls {...list} count={list.rows.length} />
      {add && (
        <Editor
          title={l("Add route", "添加路由")}
          close={() => setAdd(false)}
          fields={[
            { key: "value", label: name, required: true },
            { key: "comment", label: l("Comment", "备注") },
            ...(kind === "cidr" ? [{ key: "virtual_network_id", label: l("Virtual network ID (optional)", "虚拟网络 ID（选填）") }] : []),
          ]}
          save={async (v) => {
            await dnsRequest(url, "POST", v);
            list.reload();
          }}
        />
      )}
    </div>
  );
}

function Published({ url, tunnel, zonesUrl }: { url: string; tunnel: string; zonesUrl: string }) {
  const l = useLabel(),
    confirm = useConfirm();
  const [zone, setZone] = useState<string>();
  const data = useResource<{ version: number; rules: Rule[] }>(url);
  const [editing, setEditing] = useState<{ rule?: Rule; version: number }>();
  return (
    <div className="flex flex-col gap-2">
      <Space>
        <ScopeSelect url={zonesUrl} label={l("DNS zone for the published hostname", "公网主机名所属域名")} value={zone} choose={setZone} />
        <Button type="primary" disabled={!data.data || !zone} onClick={() => setEditing({ version: data.data!.version })}>
          {l("Publish hostname", "添加公网主机名")}
        </Button>
        <Button onClick={data.reload}>{l("Refresh", "刷新")}</Button>
      </Space>
      <span>
        {l("DNS CNAME target", "DNS CNAME 目标")} <code>{tunnel}.cfargotunnel.com</code>
      </span>
      {data.error && <LoadError text={data.error} retry={data.reload} />}
      <Table<Rule>
        rowKey={(r) => JSON.stringify([r.hostname, r.path])}
        pagination={false}
        dataSource={data.data?.rules}
        loading={data.loading}
        columns={[
          { title: l("Hostname", "主机名"), dataIndex: "hostname" },
          { title: l("Path", "路径"), dataIndex: "path" },
          { title: l("Origin service", "源站服务"), dataIndex: "service" },
          {
            title: l("Actions", "操作"),
            render: (_, r) => (
              <Space>
                <Button disabled={!zone} onClick={() => setEditing({ rule: r, version: data.data!.version })}>
                  {l("Edit", "编辑")}
                </Button>
                <Button
                  danger
                  disabled={!zone}
                  onClick={() =>
                    confirm(
                      l("Remove published hostname?", "删除公网主机名？"),
                      r.hostname + " " + (r.path ?? ""),
                      () => dnsRequest(url, "DELETE", { zone, hostname: r.hostname, path: r.path, version: data.data!.version }),
                      data.reload
                    )
                  }
                >
                  {l("Delete", "删除")}
                </Button>
              </Space>
            ),
          },
        ]}
      />
      {editing && (
        <Editor
          title={editing.rule?.hostname ?? l("Publish hostname", "添加公网主机名")}
          close={() => setEditing(undefined)}
          fields={[
            ...(!editing.rule
              ? [
                  { key: "hostname", label: l("Hostname", "主机名"), required: true },
                  { key: "path", label: l("Path expression (optional)", "路径表达式（选填）") },
                ]
              : []),
            { key: "service", label: l("Origin service (HTTP or HTTPS)", "源站服务（HTTP 或 HTTPS）"), required: true, initial: editing.rule?.service },
          ]}
          save={async (v) => {
            try {
              await dnsRequest(url, "PUT", { zone, ...editing.rule, ...v, version: editing.version });
            } finally {
              data.reload();
            }
          }}
        />
      )}
    </div>
  );
}

export default function Tunnels({ base, zonesUrl }: { base: string; zonesUrl: string }) {
  const l = useLabel(),
    confirm = useConfirm();
  const list = usePage<Tunnel>(base);
  const [selected, setSelected] = useState<Tunnel>();
  const [renaming, setRenaming] = useState<Tunnel | "new">();
  const [connector, setConnector] = useState<Tunnel>();
  if (selected) {
    const url = base + "/" + selected.id;
    return (
      <>
        <Space>
          <Button onClick={() => setSelected(undefined)}>{l("Back to tunnels", "返回 Tunnel 列表")}</Button>
          <strong>{selected.name}</strong>
        </Space>
        <Tabs
          destroyOnHidden
          items={[
            ...(selected.config_src === "local"
              ? []
              : [
                  {
                    key: "published",
                    label: l("Published hostnames", "公网主机名"),
                    children: <Published zonesUrl={zonesUrl} url={url + "/published"} tunnel={selected.id} />,
                  },
                ]),
            { key: "cidr", label: l("CIDR routes", "CIDR 路由"), children: <PrivateRoutes kind="cidr" url={url + "/routes/cidr"} /> },
            {
              key: "hostname",
              label: l("Private hostname routes", "私有主机名路由"),
              children: <PrivateRoutes kind="hostname" url={url + "/routes/hostname"} />,
            },
          ]}
        />
      </>
    );
  }
  return (
    <>
      <Space>
        <Button type="primary" onClick={() => setRenaming("new")}>
          {l("Create tunnel", "创建 Tunnel")}
        </Button>
        <Button onClick={list.reload}>{l("Refresh", "刷新")}</Button>
      </Space>
      {list.error && <LoadError text={list.error} retry={list.reload} />}
      <Table<Tunnel>
        rowKey="id"
        loading={list.loading}
        pagination={false}
        dataSource={list.rows}
        columns={[
          {
            title: l("Tunnel name", "Tunnel 名称"),
            dataIndex: "name",
            render: (name: string, r) => (
              <Button type="link" onClick={() => setSelected(r)}>
                {name}
              </Button>
            ),
          },
          { title: l("Status", "状态"), dataIndex: "status" },
          { title: l("Configuration source", "配置来源"), dataIndex: "config_src" },
          {
            title: l("Actions", "操作"),
            render: (_, r) => (
              <Space>
                {r.config_src !== "local" && <Button onClick={() => setConnector(r)}>{l("Export connector token", "导出连接器令牌")}</Button>}
                <Button onClick={() => setRenaming(r)}>{l("Rename", "重命名")}</Button>
                <Button
                  danger
                  onClick={() => confirm(l("Delete tunnel?", "删除 Tunnel？"), r.name, () => dnsRequest(base + "/" + r.id, "DELETE"), list.reload)}
                >
                  {l("Delete", "删除")}
                </Button>
              </Space>
            ),
          },
        ]}
      />
      <PageControls {...list} count={list.rows.length} />
      {connector && (
        <Editor
          title={l("Download encrypted connector token", "下载加密的连接器令牌")}
          fields={[{ key: "publicKey", label: l("Recipient RSA public key (PEM)", "接收方 RSA 公钥（PEM）"), multiline: true, required: true }]}
          close={() => setConnector(undefined)}
          save={async ({ publicKey }) => {
            const encrypted = await dnsRequest<string>(base + "/" + connector.id + "/connector", "POST", { publicKey });
            const link = document.createElement("a");
            const file = URL.createObjectURL(new Blob([encrypted], { type: "application/jose" }));
            link.href = file;
            link.download = connector.id + ".jwe";
            link.click();
            window.setTimeout(() => URL.revokeObjectURL(file), 1000);
          }}
        >
          <p>
            {l(
              "Decrypt the JWE on the connector host using the matching private key (RSA-OAEP-256 / A256GCM).",
              "请在连接器主机上使用配对私钥解密 JWE 文件（RSA-OAEP-256 / A256GCM）。"
            )}
          </p>
        </Editor>
      )}
      {renaming && (
        <Editor
          title={renaming === "new" ? l("Create tunnel", "创建 Tunnel") : l("Rename tunnel", "重命名 Tunnel")}
          fields={[{ key: "name", label: l("Name", "名称"), initial: renaming === "new" ? undefined : renaming.name, required: true }]}
          close={() => setRenaming(undefined)}
          save={async (values) => {
            await dnsRequest(renaming === "new" ? base : base + "/" + renaming.id, renaming === "new" ? "POST" : "PATCH", values);
            list.reload();
          }}
        />
      )}
    </>
  );
}
