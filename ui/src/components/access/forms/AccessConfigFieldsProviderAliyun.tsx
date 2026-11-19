import { getI18n, useTranslation } from "react-i18next";
import { Form, Input, Select } from "antd";
import { createSchemaFieldRule } from "antd-zod";
import { z } from "zod";

import { useFormNestedFieldsContext } from "./_context";

const AccessConfigFormFieldsProviderAliyun = ({ esa = false }: { esa?: boolean }) => {
  const { i18n, t } = useTranslation();

  const { parentNamePath } = useFormNestedFieldsContext();
  const formSchema = z.object({
    [parentNamePath]: getSchema({ i18n }),
  });
  const formRule = createSchemaFieldRule(formSchema);
  const initialValues = getInitialValues();

  return (
    <>
      <Form.Item
        name={[parentNamePath, "accessKeyId"]}
        initialValue={initialValues.accessKeyId}
        label={t("access.form.aliyun_access_key_id.label")}
        rules={[formRule]}
        tooltip={<span dangerouslySetInnerHTML={{ __html: t("access.form.aliyun_access_key_id.tooltip") }}></span>}
      >
        <Input autoComplete="new-password" placeholder={t("access.form.aliyun_access_key_id.placeholder")} />
      </Form.Item>

      <Form.Item
        name={[parentNamePath, "accessKeySecret"]}
        initialValue={initialValues.accessKeySecret}
        label={t("access.form.aliyun_access_key_secret.label")}
        rules={[formRule]}
        tooltip={<span dangerouslySetInnerHTML={{ __html: t("access.form.aliyun_access_key_secret.tooltip") }}></span>}
      >
        <Input.Password autoComplete="new-password" placeholder={t("access.form.aliyun_access_key_secret.placeholder")} />
      </Form.Item>

      {esa && (
        <Form.Item name={[parentNamePath, "region"]} initialValue="cn-hangzhou" label={t("access.form.dns_account.endpoint")} rules={[formRule]}>
          <Select
            options={[
              { value: "cn-hangzhou", label: t("access.form.dns_account.mainland") },
              { value: "ap-southeast-1", label: t("access.form.dns_account.international") },
            ]}
          />
        </Form.Item>
      )}

      <Form.Item
        name={[parentNamePath, "resourceGroupId"]}
        initialValue={initialValues.resourceGroupId}
        label={t("access.form.aliyun_resource_group_id.label")}
        rules={[formRule]}
        tooltip={<span dangerouslySetInnerHTML={{ __html: t("access.form.aliyun_resource_group_id.tooltip") }}></span>}
      >
        <Input allowClear placeholder={t("access.form.aliyun_resource_group_id.placeholder")} />
      </Form.Item>
    </>
  );
};

const getInitialValues = (): Nullish<z.infer<ReturnType<typeof getSchema>>> => {
  return {
    accessKeyId: "",
    accessKeySecret: "",
  };
};

const getSchema = ({ i18n = getI18n() }: { i18n: ReturnType<typeof getI18n> }) => {
  const { t: _ } = i18n;

  return z.object({
    accessKeyId: z.string().nonempty(),
    accessKeySecret: z.string().nonempty(),
    resourceGroupId: z.string().nullish(),
    region: z.enum(["cn-hangzhou", "ap-southeast-1"]).nullish(),
  });
};

const _default = Object.assign(AccessConfigFormFieldsProviderAliyun, {
  getInitialValues,
  getSchema,
});

export default _default;
