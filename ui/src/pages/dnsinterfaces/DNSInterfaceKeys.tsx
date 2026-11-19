import { useState, useSyncExternalStore } from "react";
import { useRequest } from "ahooks";
import { Alert, App, Button, Descriptions, Modal, Space, Table, Typography } from "antd";

import { getPocketBase } from "@/repository/_pocketbase";
import { unwrapErrMsg } from "@/utils/error";
import { withBasePath } from "@/utils/url";

import IssueKey from "./IssueKey";
import { type Issued, type KeyRow, keyRequest, useLabel } from "./model";

function owner() {
  const store = getPocketBase().authStore;
  return store.isValid && store.record ? [store.record.collectionId, store.record.id, store.record.apiEnabled === true].join("/") : "";
}
function watchOwner(fn: () => void) {
  return getPocketBase().authStore.onChange(fn);
}

export default function DNSInterfaceKeys() {
  const id = useSyncExternalStore(watchOwner, owner);
  return id ? <OwnerKeys key={id} /> : null;
}

function OwnerKeys() {
  const l = useLabel();
  const auth = getPocketBase().authStore;
  const canIssue = auth.isSuperuser || auth.record?.apiEnabled === true;
  const { message, modal } = App.useApp();
  const keys = useRequest(() => keyRequest<KeyRow[]>());
  const [issuing, setIssuing] = useState(false);
  const [issued, setIssued] = useState<Issued>();
  const [revoking, setRevoking] = useState<KeyRow>();
  const [busy, setBusy] = useState(false);
  const interfaceName = (id: string) => (id === "api" ? "REST API" : id.toUpperCase());
  const endpoint = (path: string) => new URL(withBasePath(path), window.location.origin).href;

  async function revoke() {
    if (!revoking || busy) return;
    setBusy(true);
    try {
      await keyRequest("/" + encodeURIComponent(revoking.uid), "DELETE");
      setRevoking(undefined);
      keys.refresh();
    } catch (err) {
      message.error(unwrapErrMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="flex flex-col gap-4">
      <Typography.Title level={3} style={{ margin: 0 }}>
        {l("DNS interface keys", "DNS 接口密钥")}
      </Typography.Title>
      {!canIssue && (
        <Alert
          type="info"
          showIcon
          title={l("An administrator can enable API access for this member to issue keys.", "管理员可为此成员启用 API 权限以签发密钥。")}
        />
      )}
      <Space wrap>
        <Button type="primary" disabled={!canIssue} onClick={() => setIssuing(true)}>
          {l("Issue key", "签发密钥")}
        </Button>
        <Button onClick={keys.refresh} loading={keys.loading}>
          {l("Refresh", "刷新")}
        </Button>
        <Button
          onClick={() =>
            modal.info({
              title: l("Interface endpoints", "接口地址"),
              width: 640,
              content: (
                <>
                  <Descriptions
                    size="small"
                    column={1}
                    items={["api", "mcp"].map((id) => ({
                      key: id,
                      label: interfaceName(id),
                      children: (
                        <Typography.Text code copyable>
                          {endpoint("/" + id)}
                        </Typography.Text>
                      ),
                    }))}
                  />
                  <Typography.Paragraph>
                    {l("MCP authentication header", "MCP 认证请求头")}
                    <br />
                    <Typography.Text code>Authorization: Bearer UID:API_KEY</Typography.Text>
                  </Typography.Paragraph>
                  <Typography.Title level={5}>{l("REST form signatures", "REST 表单签名")}</Typography.Title>
                  <Typography.Paragraph>
                    {l(
                      "POST a URL-encoded form using a timestamp within five minutes of server time. Use v2 for writes, certificate export, and domain info with loginurl=1. Ordinary reads also accept legacy MD5.",
                      "以 POST 提交 URL 编码表单，时间戳与服务器时间相差最多 5 分钟。写入、证书导出和带 loginurl=1 的域名详情查询需要 v2 签名。普通读取也支持旧版 MD5 签名。"
                    )}
                  </Typography.Paragraph>
                  <Typography.Paragraph>
                    {l(
                      "For v2, send uid, timestamp (Unix seconds), sign_version=2 and a fresh nonce (16 random bytes encoded as 32 lowercase hex digits).",
                      "v2 表单需包含 uid、timestamp（Unix 秒）、sign_version=2 和 nonce。每次请求用 16 个随机字节生成新的 nonce，编码为 32 位小写十六进制字符串。"
                    )}
                  </Typography.Paragraph>
                  <Typography.Paragraph>
                    {l(
                      "Encode every form field except sign with Go’s url.Values.Encode(). Use the escaped request path and the encoded form in the following expression, with LF between lines. Submit the lowercase hex result as sign.",
                      "使用 Go 的 url.Values.Encode() 编码 sign 以外的全部表单字段，将编码后的表单与请求的转义路径代入下式。分隔符为换行符 LF，将结果的小写十六进制字符串作为 sign 提交。"
                    )}
                    <br />
                    <Typography.Text className="break-all" code>
                      {'HMAC-SHA256(apikey, "DNSMgr-v2\\nPOST\\n" + URL.EscapedPath() + "\\n" + encodedForm)'}
                    </Typography.Text>
                  </Typography.Paragraph>
                  <Typography.Paragraph>
                    {l("Legacy read signatures use uid, timestamp (Unix seconds) and sign.", "旧版读取签名使用 uid、timestamp（Unix 秒）及 sign。")}
                    <br />
                    <Typography.Text code>sign = md5(uid + timestamp + apikey)</Typography.Text>
                  </Typography.Paragraph>
                </>
              ),
            })
          }
        >
          {l("Interface endpoints", "接口地址")}
        </Button>
      </Space>
      {keys.error && <Alert showIcon type="error" title={unwrapErrMsg(keys.error)} />}
      <Table<KeyRow>
        rowKey="uid"
        loading={keys.loading}
        dataSource={keys.data}
        scroll={{ x: 630 }}
        expandable={{
          expandedRowRender: ({ scope }) => (
            <Descriptions
              column={1}
              size="small"
              items={[
                { key: "actions", label: l("Allowed actions", "允许的操作"), children: scope.actions.join(", ") },
                { key: "zones", label: l("Domain IDs", "域名 ID"), children: scope.zones?.join(", ") || "—" },
                { key: "accounts", label: l("Account IDs", "账号 ID"), children: scope.accounts?.join(", ") || "—" },
                { key: "global", label: l("Global operations", "全局操作"), children: scope.global ? l("Allowed", "允许") : l("Off", "关闭") },
              ]}
            />
          ),
        }}
        columns={[
          { title: l("Key name", "密钥名称"), dataIndex: "label" },
          { title: "UID", dataIndex: "uid" },
          { title: l("Interfaces", "接口"), render: (_, row) => row.scope.interfaces.map(interfaceName).join(", ") },
          {
            title: l("Actions", "操作"),
            render: (_, row) => (
              <Button type="link" danger onClick={() => setRevoking(row)}>
                {l("Revoke", "撤销")}
              </Button>
            ),
          },
        ]}
      />
      {issuing && (
        <IssueKey
          close={() => setIssuing(false)}
          issued={(key) => {
            setIssuing(false);
            setIssued(key);
            keys.refresh();
          }}
        />
      )}
      {issued && (
        <Modal
          open
          title={l("Save the new key", "保存新密钥")}
          onCancel={() => setIssued(undefined)}
          footer={
            <Button type="primary" onClick={() => setIssued(undefined)}>
              {l("Done", "完成")}
            </Button>
          }
        >
          <Typography.Paragraph>
            {l("Copy the API key before closing this dialog. It is shown once.", "请在关闭前复制 API 密钥，它仅在签发时显示一次。")}
          </Typography.Paragraph>
          <Descriptions
            column={1}
            items={[
              { key: "uid", label: "UID", children: <Typography.Text copyable>{issued.uid}</Typography.Text> },
              {
                key: "apikey",
                label: "API key",
                children: (
                  <Typography.Text className="break-all" code copyable>
                    {issued.apikey}
                  </Typography.Text>
                ),
              },
            ]}
          />
        </Modal>
      )}
      {revoking && (
        <Modal
          open
          title={l("Revoke interface key?", "撤销接口密钥？")}
          onCancel={() => {
            if (!busy) setRevoking(undefined);
          }}
          okText={l("Revoke", "撤销")}
          okButtonProps={{ danger: true }}
          confirmLoading={busy}
          onOk={revoke}
        >
          <Typography.Paragraph>
            {revoking.label} · {revoking.uid}
          </Typography.Paragraph>
          <Typography.Paragraph>{l("Clients using this key will lose access immediately.", "使用此密钥的客户端将立即失去访问权限。")}</Typography.Paragraph>
        </Modal>
      )}
    </section>
  );
}
