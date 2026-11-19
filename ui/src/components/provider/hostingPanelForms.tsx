import { useTranslation } from "react-i18next";
import { Form, Input, InputNumber } from "antd";
import { createSchemaFieldRule } from "antd-zod";
import { z } from "zod";

import { type HostingField, panelFieldsSchema } from "@/domain/hostingPanelFields";

export function hostingPanelForms(
  definitions: Record<string, HostingField[]>,
  useNestedFields: () => { parentNamePath: string }
): Record<string, React.ComponentType> {
  return Object.fromEntries(
    Object.entries(definitions).map(([provider, fields]) => {
      function HostingPanelFields() {
        const { t } = useTranslation();
        const { parentNamePath } = useNestedFields();
        const formRule = createSchemaFieldRule(z.object({ [parentNamePath]: panelFieldsSchema(fields, t("provider.panel_fields.kangleAuth")) }));

        return fields.map((field) => (
          <Form.Item
            key={field.name}
            name={[parentNamePath, field.name]}
            label={t(`provider.panel_fields.${field.label ?? field.name}`)}
            extra={field.help ? t(`provider.panel_fields.${field.help}`) : field.kind === "list" ? t("provider.panel_fields.listHelp") : undefined}
            dependencies={
              provider === "kangle" && field.optional && field.kind === "secret"
                ? [[parentNamePath, field.name === "password" ? "securityKey" : "password"]]
                : undefined
            }
            initialValue={field.initial}
            required={!field.optional}
            rules={[formRule]}
          >
            {field.kind === "secret" ? (
              <Input.Password autoComplete="new-password" />
            ) : field.kind === "port" ? (
              <InputNumber className="w-full" min={1} max={65535} />
            ) : field.kind === "list" ? (
              <Input.TextArea autoSize={{ minRows: 2, maxRows: 8 }} />
            ) : (
              <Input type={field.kind === "https" ? "url" : field.kind === "email" ? "email" : "text"} autoComplete="off" />
            )}
          </Form.Item>
        ));
      }

      return [provider, HostingPanelFields];
    })
  );
}
