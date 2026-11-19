import { getI18n, useTranslation } from "react-i18next";
import { Form, Input, Select } from "antd";
import { createSchemaFieldRule } from "antd-zod";
import { z } from "zod";

import FileTextInput from "@/components/FileTextInput";
import Tips from "@/components/Tips";

import { useFormNestedFieldsContext } from "./_context";

const AccessConfigFormFieldsProviderGoogleTrustServices = () => {
  const { i18n, t } = useTranslation();

  const { parentNamePath } = useFormNestedFieldsContext();
  const scope = parentNamePath ? [parentNamePath] : [];
  const eabMode = Form.useWatch([...scope, "eabMode"]);
  const schema = getSchema({ i18n });
  const formRule = parentNamePath ? createSchemaFieldRule(z.object({ [parentNamePath]: schema })) : createSchemaFieldRule(schema);
  const initialValues = getInitialValues();
  const automatic = eabMode === "auto";

  return (
    <>
      <Form.Item name={[...scope, "mode"]} initialValue={initialValues.mode} label={t("access.form.googletrustservices_eab.environment")} rules={[formRule]}>
        <Select
          options={[
            { value: "live", label: t("access.form.googletrustservices_eab.environment_live") },
            { value: "staging", label: t("access.form.googletrustservices_eab.environment_staging") },
          ]}
        />
      </Form.Item>

      <Form.Item name={[...scope, "eabMode"]} initialValue={initialValues.eabMode} label={t("access.form.googletrustservices_eab.mode")} rules={[formRule]}>
        <Select
          options={[
            { value: "manual", label: t("access.form.googletrustservices_eab.mode_manual") },
            { value: "auto", label: t("access.form.googletrustservices_eab.mode_auto") },
          ]}
        />
      </Form.Item>

      {automatic ? (
        <>
          <Form.Item name={[...scope, "projectId"]} preserve={false} label={t("access.form.googlecloud_project_id.label")} rules={[formRule]}>
            <Input />
          </Form.Item>
          <Form.Item
            name={[...scope, "serviceAccountKey"]}
            preserve={false}
            label={t("access.form.googletrustservices_eab.service_account_key")}
            extra={t("access.form.googletrustservices_eab.service_account_key_help")}
            rules={[formRule]}
          >
            <FileTextInput accept=".json,application/json" autoComplete="off" autoSize={{ minRows: 3, maxRows: 10 }} />
          </Form.Item>
        </>
      ) : (
        <>
          <Form.Item name={[...scope, "eabKid"]} preserve={false} label={t("access.form.shared_acme_eab_kid.label")} rules={[formRule]}>
            <Input autoComplete="new-password" placeholder={t("access.form.shared_acme_eab_kid.placeholder")} />
          </Form.Item>
          <Form.Item name={[...scope, "eabHmacKey"]} preserve={false} label={t("access.form.shared_acme_eab_hmac_key.label")} rules={[formRule]}>
            <Input.Password autoComplete="new-password" placeholder={t("access.form.shared_acme_eab_hmac_key.placeholder")} />
          </Form.Item>
        </>
      )}

      <Form.Item>
        <Tips message={<span dangerouslySetInnerHTML={{ __html: t("access.form.googletrustservices_eab.guide") }}></span>} />
      </Form.Item>
    </>
  );
};

const getInitialValues = (): Nullish<z.infer<ReturnType<typeof getSchema>>> => {
  return {
    mode: "live",
    eabMode: "manual",
  };
};

const serviceAccountKeySchema = z.object({ type: z.literal("service_account"), client_email: z.email(), private_key: z.string().nonempty() });

function isServiceAccountKey(value = "") {
  try {
    return serviceAccountKeySchema.safeParse(JSON.parse(value)).success;
  } catch {
    return false;
  }
}

const getSchema = ({ i18n = getI18n() }: { i18n: ReturnType<typeof getI18n> }) => {
  const { t } = i18n;

  return z
    .object({
      mode: z.enum(["live", "staging"]).optional(),
      eabMode: z.enum(["manual", "auto"]).optional(),
      eabKid: z.string().optional(),
      eabHmacKey: z.string().optional(),
      projectId: z.string().optional(),
      serviceAccountKey: z.string().optional(),
    })
    .superRefine((values, ctx) => {
      if (values.eabMode === "auto") {
        if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(values.projectId ?? "")) {
          ctx.addIssue({ code: "custom", path: ["projectId"], message: t("access.form.googletrustservices_eab.project_id_invalid") });
        }
        if (!isServiceAccountKey(values.serviceAccountKey)) {
          ctx.addIssue({ code: "custom", path: ["serviceAccountKey"], message: t("access.form.googletrustservices_eab.service_account_key_invalid") });
        }
      } else {
        for (const field of ["eabKid", "eabHmacKey"] as const) {
          if (!values[field]?.trim()) ctx.addIssue({ code: "custom", path: [field], message: t("access.form.shared_acme_eab_pair.errmsg") });
        }
      }
    });
};

const _default = Object.assign(AccessConfigFormFieldsProviderGoogleTrustServices, {
  getInitialValues,
  getSchema,
});

export default _default;
