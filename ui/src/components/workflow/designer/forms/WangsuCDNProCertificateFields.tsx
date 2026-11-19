import { useTranslation } from "react-i18next";
import { Form, Input } from "antd";

import { useFormNestedFieldsContext } from "./_context";

const WangsuCDNProCertificateFields = () => {
  const { t } = useTranslation();
  const { parentNamePath } = useFormNestedFieldsContext();
  return (
    <Form.Item
      name={[parentNamePath, "certificateId"]}
      label={t("workflow_node.deploy.form.wangsu_cdnpro_publish.label")}
      extra={t("workflow_node.deploy.form.wangsu_cdnpro_publish.help")}
      rules={[{ required: true }, { pattern: /^[A-Za-z0-9-]{1,128}$/ }]}
    >
      <Input maxLength={128} />
    </Form.Item>
  );
};

export default WangsuCDNProCertificateFields;
