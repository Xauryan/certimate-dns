import type { getI18n } from "react-i18next";
import { useTranslation } from "react-i18next";
import { Form, Input, InputNumber, Radio, Switch } from "antd";
import { createSchemaFieldRule } from "antd-zod";
import { z } from "zod";

import { useFormNestedFieldsContext } from "./_context";

const AccessConfigFormFieldsProviderGoEdge = ({ dnsManagement = false }: { dnsManagement?: boolean }) => {
  const { i18n, t } = useTranslation();

  const { parentNamePath } = useFormNestedFieldsContext();
  const formInst = Form.useFormInstance();
  const allowInsecure = Form.useWatch([parentNamePath, "allowInsecureConnections"], formInst) === true;
  const formSchema = z.object({
    [parentNamePath]: getSchema({ i18n, dnsManagement, allowInsecure }),
  });
  const formRule = createSchemaFieldRule(formSchema);
  const initialValues = getInitialValues();
  const role = Form.useWatch([parentNamePath, "apiRole"], formInst);

  return (
    <>
      <Form.Item
        name={[parentNamePath, "serverUrl"]}
        dependencies={[[parentNamePath, "allowInsecureConnections"]]}
        initialValue={dnsManagement ? undefined : initialValues.serverUrl}
        label={t("access.form.goedge_server_url.label")}
        extra={dnsManagement && t("access.form.dns_account.goedge_url_help")}
        rules={[formRule]}
      >
        <Input type="url" placeholder={t("access.form.goedge_server_url.placeholder")} />
      </Form.Item>

      <Form.Item name={[parentNamePath, "apiRole"]} initialValue={initialValues.apiRole} label={t("access.form.goedge_api_role.label")} rules={[formRule]}>
        <Radio.Group
          options={["user", "admin"].map((s) => ({
            label: t(`access.form.goedge_api_role.option.${s}.label`),
            value: s,
          }))}
        />
      </Form.Item>

      <Form.Item
        name={[parentNamePath, "accessKeyId"]}
        initialValue={initialValues.accessKeyId}
        label={t("access.form.goedge_access_key_id.label")}
        rules={[formRule]}
        tooltip={<span dangerouslySetInnerHTML={{ __html: t("access.form.goedge_access_key_id.tooltip") }}></span>}
      >
        <Input autoComplete="new-password" placeholder={t("access.form.goedge_access_key_id.placeholder")} />
      </Form.Item>

      <Form.Item
        name={[parentNamePath, "accessKey"]}
        initialValue={initialValues.accessKey}
        label={t("access.form.goedge_access_key.label")}
        rules={[formRule]}
        tooltip={<span dangerouslySetInnerHTML={{ __html: t("access.form.goedge_access_key.tooltip") }}></span>}
      >
        <Input.Password autoComplete="new-password" placeholder={t("access.form.goedge_access_key.placeholder")} />
      </Form.Item>

      <Form.Item
        name={[parentNamePath, "nsClusterId"]}
        label={t("access.form.dns_account.goedge_cluster")}
        extra={!dnsManagement && t("access.form.dns_account.goedge_cluster_help")}
        required={dnsManagement}
        rules={[formRule]}
      >
        <InputNumber className="w-full" min={1} max={Number.MAX_SAFE_INTEGER} precision={0} />
      </Form.Item>

      {role === "admin" && (
        <Form.Item name={[parentNamePath, "userId"]} label={t("access.form.dns_account.goedge_user")} rules={[formRule]}>
          <InputNumber className="w-full" min={1} max={Number.MAX_SAFE_INTEGER} precision={0} />
        </Form.Item>
      )}

      <Form.Item
        name={[parentNamePath, "allowInsecureConnections"]}
        initialValue={initialValues.allowInsecureConnections}
        label={t(dnsManagement ? "access.form.dns_account.goedge_insecure" : "access.form.shared_allow_insecure_conns.label")}
        rules={[formRule]}
      >
        <Switch />
      </Form.Item>
    </>
  );
};

const getInitialValues = (): Nullish<z.infer<ReturnType<typeof getSchema>>> => {
  return {
    serverUrl: "http://<your-host-addr>:7788/",
    apiRole: "user",
    accessKeyId: "",
    accessKey: "",
  };
};

function allowedDNSNodeURL(value: string, allowInsecure: boolean) {
  const authority = /^https?:\/\/([^/]+)(?:\/|$)/.exec(value);
  if (!authority || /[?#\\]/.test(value) || authority[1].includes("@")) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.protocol === "https:") return true;
  if (url.protocol !== "http:" || !allowInsecure) return false;

  const host = url.hostname;
  if (host === "localhost" || host === "[::1]" || /^\[f[cd][0-9a-f]{2}:/.test(host)) return true;
  // Reject historical abbreviated or octal IPv4 forms accepted by browser URL parsing.
  if (!host.startsWith("[") && authority[1].split(":")[0] !== host) return false;
  // URL normalizes bracketed IPv6, including IPv4-mapped addresses.
  const mapped = /^\[::ffff:([a-f0-9]+):[a-f0-9]+\]$/.exec(host);
  const prefix = mapped ? parseInt(mapped[1], 16) : undefined;
  if (prefix === undefined && !/^\d+\.\d+\.\d+\.\d+$/.test(host)) return false;
  const [first, second] = prefix === undefined ? host.split(".").map(Number) : [prefix >> 8, prefix & 255];
  return first === 127 || first === 10 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168);
}

const getSchema = ({
  i18n,
  dnsManagement = false,
  allowInsecure = false,
}: {
  i18n: ReturnType<typeof getI18n>;
  dnsManagement?: boolean;
  allowInsecure?: boolean;
}) => {
  const positiveId = z.coerce.number().int().positive().max(Number.MAX_SAFE_INTEGER);

  return z.object({
    serverUrl: dnsManagement
      ? z.url().refine((s) => allowedDNSNodeURL(s, allowInsecure), i18n.t("access.form.dns_account.goedge_url_help"))
      : z.url({ protocol: z.core.regexes.httpProtocol }),
    nsClusterId: dnsManagement ? positiveId : positiveId.nullish(),
    userId: positiveId.nullish(),
    apiRole: z.enum(["user", "admin"]),
    accessKeyId: z.string().nonempty(),
    accessKey: z.string().nonempty(),
    allowInsecureConnections: z.boolean().nullish(),
  });
};

const _default = Object.assign(AccessConfigFormFieldsProviderGoEdge, {
  getInitialValues,
  getSchema,
});

export default _default;
