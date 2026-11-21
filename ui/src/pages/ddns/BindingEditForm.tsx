import { useTranslation } from "react-i18next";
import { Alert, Button, Descriptions, Form, Input, Select, Typography } from "antd";

import { type Binding, type BindingEditValues, type NetworkInterface } from "./model";

type Props = {
  binding: Binding;
  interfaces: NetworkInterface[];
  busy: boolean;
  error: string;
  onSave: (values: BindingEditValues) => void;
};

export default function BindingEditForm({ binding, interfaces, busy, error, onSave }: Props) {
  const { t } = useTranslation();
  const [form] = Form.useForm<BindingEditValues>();
  const recordName = Form.useWatch("recordName", form)?.trim() ?? binding.recordName;
  const interfaceName = Form.useWatch("interfaceName", form) ?? binding.interfaceName;
  const renamed = recordName !== binding.recordName;
  const saveLabel = t(renamed ? "ddns.renameAndSave" : "ddns.saveBinding");
  const changed = renamed || interfaceName !== binding.interfaceName;
  const available = interfaces.some((item) => item.name === interfaceName);
  const options = interfaces.map((item) => ({ value: item.name, label: [item.name, item.mac].filter(Boolean).join(" · ") }));
  if (!interfaces.some((item) => item.name === binding.interfaceName)) {
    options.unshift({ value: binding.interfaceName, label: binding.interfaceName });
  }

  return (
    <Form<BindingEditValues>
      form={form}
      layout="vertical"
      disabled={busy}
      initialValues={{ recordName: binding.recordName, interfaceName: binding.interfaceName }}
      onFinish={(values) => {
        if (changed && available) onSave({ recordName: values.recordName.trim(), interfaceName: values.interfaceName });
      }}
    >
      <Typography.Paragraph type="secondary">{t("ddns.editBindingHelp")}</Typography.Paragraph>
      <Descriptions
        className="mb-4"
        size="small"
        column={1}
        items={[
          { key: "zone", label: t("dns.zone"), children: binding.zoneName || binding.zoneId },
          { key: "type", label: t("ddns.recordType"), children: binding.recordType },
        ]}
      />
      {error && <Alert className="mb-4" type="error" title={error} showIcon />}
      <Form.Item name="recordName" label={t("ddns.recordName")} extra={t("ddns.recordNameHelp")} rules={[{ required: true, whitespace: true }]}>
        <Input autoComplete="off" />
      </Form.Item>
      <Form.Item name="interfaceName" label={t("ddns.interface")} rules={[{ required: true }]}>
        <Select aria-label={t("ddns.interface")} options={options} />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={busy} disabled={!recordName || !changed || !available} aria-label={saveLabel}>
        {saveLabel}
      </Button>
    </Form>
  );
}
