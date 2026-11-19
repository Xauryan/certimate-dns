import { useTranslation } from "react-i18next";
import { Form, Input, Radio } from "antd";
import { createSchemaFieldRule } from "antd-zod";
import { z } from "zod";

import { useFormNestedFieldsContext } from "./_context";

type Field = {
  name: string;
  label: string;
  kind?: "password" | "url";
};

function DNSAccountFields({ fields }: { fields: Field[] }) {
  const { t } = useTranslation();
  const { parentNamePath } = useFormNestedFieldsContext();
  const required = z.string().trim().min(1);
  const url = z.url({ protocol: z.core.regexes.httpProtocol });
  const schema = z.object({
    [parentNamePath]: z.object(Object.fromEntries(fields.map((field) => [field.name, field.kind === "url" ? url : required]))),
  });
  const rule = createSchemaFieldRule(schema);

  return fields.map(({ name, label, kind }) => (
    <Form.Item key={name} name={[parentNamePath, name]} label={t(`access.form.dns_account.${label}`)} rules={[rule]} required>
      {kind === "password" ? <Input.Password autoComplete="new-password" /> : <Input type={kind ?? "text"} autoComplete="off" />}
    </Form.Item>
  ));
}

export function BaotaDNSFields() {
  return (
    <DNSAccountFields
      fields={[
        { name: "accountId", label: "account_id" },
        { name: "accessKey", label: "access_key", kind: "password" },
        { name: "secretKey", label: "secret_key", kind: "password" },
      ]}
    />
  );
}

export function DNSMgrFields() {
  const { t } = useTranslation();
  const { parentNamePath } = useFormNestedFieldsContext();
  return (
    <>
      <DNSAccountFields
        fields={[
          { name: "serverUrl", label: "site_url", kind: "url" },
          { name: "uid", label: "user_id" },
          { name: "apiKey", label: "api_key", kind: "password" },
        ]}
      />
      <Form.Item
        name={[parentNamePath, "signatureMode"]}
        initialValue="legacy"
        label={t("access.form.dns_account.dnsmgr_signature")}
        rules={[{ type: "enum", enum: ["legacy", "v2"], required: true }]}
      >
        <Radio.Group
          options={[
            { value: "legacy", label: t("access.form.dns_account.dnsmgr_legacy") },
            { value: "v2", label: "V2" },
          ]}
        />
      </Form.Item>
    </>
  );
}

export function HENetFields() {
  return (
    <DNSAccountFields
      fields={[
        { name: "username", label: "username" },
        { name: "password", label: "password", kind: "password" },
      ]}
    />
  );
}
