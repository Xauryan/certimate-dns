import { useTranslation } from "react-i18next";
import { Form, Input } from "antd";

import { useFormNestedFieldsContext } from "./_context";

function Field({ name, label, type = "text", optional = false }: { name: string; label: string; type?: "text" | "email" | "password"; optional?: boolean }) {
  const { t } = useTranslation();
  const { parentNamePath } = useFormNestedFieldsContext();
  return (
    <Form.Item
      name={[parentNamePath, name]}
      label={t(label)}
      rules={[{ required: !optional, whitespace: true }, ...(type === "email" ? [{ type: "email" as const }] : [])]}
    >
      {type === "password" ? <Input.Password autoComplete="new-password" /> : <Input type={type} autoComplete="off" />}
    </Form.Item>
  );
}

function MailFields() {
  return (
    <>
      <Field name="senderAddress" label="access.form.email_sender_address.label" type="email" />
      <Field name="senderName" label="access.form.email_sender_name.label" optional />
      <Field name="receiverAddress" label="access.form.api_mail_receiver" type="email" />
    </>
  );
}

export function SendCloudFields() {
  return (
    <>
      <Field name="apiUser" label="access.form.sendcloud_user" />
      <Field name="apiKey" label="access.form.sendcloud_key" type="password" />
      <MailFields />
    </>
  );
}

export function AliyunMailFields() {
  return (
    <>
      <Field name="accessKeyId" label="access.form.aliyun_access_key_id.label" />
      <Field name="accessKeySecret" label="access.form.aliyun_access_key_secret.label" type="password" />
      <MailFields />
    </>
  );
}

export function WxPusherFields() {
  return (
    <>
      <Field name="appToken" label="access.form.wxpusher_token" type="password" />
      <Field name="uid" label="access.form.wxpusher_uid" />
    </>
  );
}
