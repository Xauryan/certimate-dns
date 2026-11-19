import type { getI18n } from "react-i18next";
import { useTranslation } from "react-i18next";
import { Form, Input, Radio } from "antd";
import { createSchemaFieldRule } from "antd-zod";
import { z } from "zod";

import { useFormNestedFieldsContext } from "./_context";

const AccessConfigFormFieldsProviderCloudflare = ({ dnsManagement = false }: { dnsManagement?: boolean }) => {
  const { i18n, t } = useTranslation();

  const { parentNamePath } = useFormNestedFieldsContext();
  const authMethod = Form.useWatch([parentNamePath, "authMethod"], Form.useFormInstance());
  const globalKey = dnsManagement && authMethod === "globalapikey";
  const formSchema = z.object({
    [parentNamePath]: getSchema({ i18n, globalKey }),
  });
  const formRule = createSchemaFieldRule(formSchema);
  const initialValues = getInitialValues();

  return (
    <>
      {dnsManagement && (
        <Form.Item name={[parentNamePath, "authMethod"]} label={t("access.form.dns_account.authentication")} initialValue="apitoken">
          <Radio.Group
            options={[
              { value: "apitoken", label: t("access.form.cloudflare_api_token.label") },
              { value: "globalapikey", label: t("access.form.dns_account.global_key") },
            ]}
          />
        </Form.Item>
      )}
      {globalKey ? (
        <>
          <Form.Item name={[parentNamePath, "email"]} label={t("access.form.dns_account.cloudflare_email")} rules={[formRule]} required>
            <Input type="email" autoComplete="off" />
          </Form.Item>
          <Form.Item name={[parentNamePath, "apiKey"]} label={t("access.form.dns_account.global_key")} rules={[formRule]} required>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </>
      ) : (
        <>
          <Form.Item
            name={[parentNamePath, "apiToken"]}
            initialValue={initialValues.apiToken}
            label={t("access.form.cloudflare_api_token.label")}
            rules={[formRule]}
            tooltip={<span dangerouslySetInnerHTML={{ __html: t("access.form.cloudflare_api_token.tooltip") }}></span>}
          >
            <Input.Password autoComplete="new-password" placeholder={t("access.form.cloudflare_api_token.placeholder")} />
          </Form.Item>

          <Form.Item
            name={[parentNamePath, "apiTokenForZone"]}
            initialValue={initialValues.apiTokenForZone}
            label={t("access.form.cloudflare_api_token_for_zone.label")}
            extra={<span dangerouslySetInnerHTML={{ __html: t("access.form.cloudflare_api_token_for_zone.help") }}></span>}
            rules={[formRule]}
            tooltip={<span dangerouslySetInnerHTML={{ __html: t("access.form.cloudflare_api_token_for_zone.tooltip") }}></span>}
          >
            <Input.Password allowClear autoComplete="new-password" placeholder={t("access.form.cloudflare_api_token_for_zone.placeholder")} />
          </Form.Item>
        </>
      )}
      {dnsManagement && (
        <Form.Item name={[parentNamePath, "accountId"]} label={t("access.form.dns_account.cloudflare_account")} rules={[formRule]}>
          <Input allowClear autoComplete="off" />
        </Form.Item>
      )}
    </>
  );
};

const getInitialValues = (): Nullish<z.infer<ReturnType<typeof getSchema>>> => {
  return {
    apiToken: "",
  };
};

const getSchema = ({ globalKey = false }: { i18n: ReturnType<typeof getI18n>; globalKey?: boolean }) => {
  return z.object({
    email: globalKey ? z.email() : z.string().nullish(),
    apiKey: globalKey ? z.string().nonempty() : z.string().nullish(),
    accountId: z
      .string()
      .regex(/^[a-f\d]{32}$/i)
      .or(z.literal(""))
      .nullish(),
    apiToken: globalKey ? z.string().nullish() : z.string().nonempty(),
    apiTokenForZone: z.string().nullish(),
  });
};

const _default = Object.assign(AccessConfigFormFieldsProviderCloudflare, {
  getInitialValues,
  getSchema,
});

export default _default;
