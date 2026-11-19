import { useRef, useState } from "react";
import { useDebounce } from "ahooks";
import { Link } from "react-router-dom";
import { Alert, App, Button, Form, Input, Modal, Select, Space } from "antd";

import { unwrapErrMsg } from "@/utils/error";
import { type Account, type Order, providers, request, useLabel } from "./order";

import ZoneField from "./ZoneField";

const contactFields = {
  email: ["Contact email", "联系邮箱"],
  contactName: ["Contact name", "联系人姓名"],
  phone: ["Phone number", "联系电话"],
  organization: ["Organization", "组织名称"],
  address: ["Street address", "街道地址"],
  city: ["City", "城市"],
  province: ["Province or state", "省份或州"],
  country: ["Country code", "国家代码"],
  postalCode: ["Postal code", "邮政编码"],
  department: ["Department", "部门"],
  title: ["Job title", "职务"],
} satisfies Record<string, [string, string]>;

export type FormValues = Partial<Record<keyof typeof contactFields | "sourceZoneId" | "instanceId" | "contactId", string>> & {
  accessId: string;
  domain: string;
  algorithm: string;
};

type Draft = Order & { request: Omit<FormValues, "accessId"> };
export default function DraftForm({ accounts, draft, close, saved }: { accounts: Account[]; draft?: Draft; close: () => void; saved: () => void }) {
  const label = useLabel();
  const { message } = App.useApp();
  const [form] = Form.useForm<FormValues>();
  const domain = Form.useWatch("domain", form) as string | undefined;
  const typedDomain = useDebounce(domain?.trim() ?? "", { wait: 350 });
  const accountId = Form.useWatch("accessId", form);
  const provider = accounts.find((item) => item.id === accountId)?.provider;
  const [error, setError] = useState("");
  const running = useRef(false);
  const [busy, setBusy] = useState<"save" | "check">();

  async function check() {
    if (running.current || !accountId) return;
    running.current = true;
    setBusy("check");
    setError("");
    try {
      await request("/accounts/" + encodeURIComponent(accountId) + "/check", {});
      message.success(label("Account verified", "账号验证通过"));
    } catch (err) {
      setError(unwrapErrMsg(err));
    } finally {
      running.current = false;
      setBusy(undefined);
    }
  }

  async function save({ accessId, ...fields }: FormValues) {
    if (running.current) return;
    running.current = true;
    setBusy("save");
    setError("");
    try {
      if (draft) {
        await request<Order>("/orders/" + encodeURIComponent(draft.id) + "/edit", { version: draft.version, request: fields });
      } else {
        await request<Order>("/orders", { accessId, request: fields });
      }
      message.success(label("Draft saved", "订单草稿已保存"));
      saved();
    } catch (err) {
      setError(unwrapErrMsg(err));
    } finally {
      running.current = false;
      setBusy(undefined);
    }
  }

  return (
    <Modal
      open
      title={draft ? label("Edit draft", "编辑草稿") : label("New certificate order", "新建证书订单")}
      onCancel={close}
      closable={!busy}
      keyboard={!busy}
      mask={{ closable: !busy }}
      okText={label("Save draft", "保存草稿")}
      onOk={() => form.submit()}
      confirmLoading={busy === "save"}
      okButtonProps={{ disabled: !accounts.length || !!busy }}
      cancelButtonProps={{ disabled: !!busy }}
    >
      {error && <Alert type="error" showIcon title={error} />}
      <Form
        form={form}
        layout="vertical"
        preserve={false}
        disabled={!!busy}
        initialValues={draft ? { ...draft.request, accessId: draft.accessId } : { algorithm: "RSA2048" }}
        onFinish={save}
      >
        <Form.Item
          label={label("Issuer account", "签发账号")}
          name="accessId"
          rules={[{ required: true }]}
          extra={
            <Space wrap>
              {accountId && (
                <Button type="link" size="small" loading={busy === "check"} onClick={check}>
                  {label("Check account access", "检查账号权限")}
                </Button>
              )}
              <Link to="/accesses">{label("Manage access credentials", "管理授权账号")}</Link>
            </Space>
          }
        >
          <Select
            disabled={!!draft}
            onChange={() => form.setFieldValue("algorithm", "RSA2048")}
            options={accounts.map((a) => ({ value: a.id, label: a.name + " · " + label(...providers[a.provider as keyof typeof providers]) }))}
            placeholder={label("Select an account", "选择签发账号")}
          />
        </Form.Item>
        <Form.Item
          name="domain"
          label={label("Domain name", "域名")}
          extra={label("One fully qualified domain per order.", "每个订单申请一个完整域名。")}
          rules={[{ required: true, whitespace: true }]}
        >
          <Input
            placeholder="www.example.org"
            onChange={() => {
              if (!draft?.request.sourceZoneId) form.setFieldValue("sourceZoneId", undefined);
            }}
          />
        </Form.Item>
        {(draft?.request.sourceZoneId || /^[^\s.]+(?:\.[^\s.]+)+\.?$/u.test(typedDomain)) && (
          <Form.Item
            name="sourceZoneId"
            label={label("Linked DNS zone (optional)", "关联 DNS 区域（可选）")}
            extra={label(
              "Link a zone to allow interface keys scoped to that zone and issuer account to use this order.",
              "关联后，具备相应区域和签发账号授权的接口密钥可操作此订单。"
            )}
          >
            {draft?.request.sourceZoneId ? <Input readOnly /> : <ZoneField key={typedDomain} domain={typedDomain} disabled={domain?.trim() !== typedDomain} />}
          </Form.Item>
        )}
        <Form.Item name="algorithm" label={label("Key algorithm", "密钥算法")} rules={[{ required: true }]}>
          <Select
            options={[
              { value: "RSA2048", label: "RSA 2048" },
              ...(["aliyun", "ucloud"].includes(provider ?? "") ? [{ value: "RSA3072", label: "RSA 3072" }] : []),
              { value: "EC256", label: "ECDSA P-256" },
              ...(provider === "ucloud" ? [{ value: "EC384", label: "ECDSA P-384" }] : []),
            ]}
          />
        </Form.Item>
        {(Object.keys(contactFields) as (keyof typeof contactFields)[])
          .filter((key) => provider === "ucloud" || (provider === "tencentcloud" && key === "email"))
          .map((key) => (
            <Form.Item
              key={key}
              name={key}
              label={label(...contactFields[key])}
              rules={[{ required: true, whitespace: true }, ...(key === "email" ? [{ type: "email" as const }] : [])]}
            >
              <Input type={key === "email" ? "email" : key === "phone" ? "tel" : "text"} maxLength={key === "country" ? 2 : 255} />
            </Form.Item>
          ))}
        {provider === "aliyun" && (
          <Form.Item name="instanceId" label={label("Certificate instance ID (optional)", "证书实例 ID（可选）")}>
            <Input />
          </Form.Item>
        )}
        {provider === "aliyun" && (
          <Form.Item key={provider} name="contactId" label={label("Contact ID (optional)", "联系人 ID（可选）")}>
            <Input />
          </Form.Item>
        )}
      </Form>
    </Modal>
  );
}
