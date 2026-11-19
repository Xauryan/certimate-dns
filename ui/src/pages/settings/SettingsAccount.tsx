import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { useRequest } from "ahooks";
import { Alert, App, Button, Divider, Flex, Form, Input, Space, Typography } from "antd";
import { createSchemaFieldRule } from "antd-zod";
import { z } from "zod";

import { useAntdForm } from "@/hooks";
import { type AdminSecurityStatus, changeAdminPassword, getAdminSecurity, getAuthStore, save as saveAdmin } from "@/repository/admin";
import { unwrapErrMsg } from "@/utils/error";

import SettingsAdminSecurity from "./SettingsAdminSecurity";

const SettingsAccount = () => {
  const { t } = useTranslation();
  const { data: security, error: securityError, refresh } = useRequest(getAdminSecurity);

  return (
    <>
      <h2>{t("settings.account.username.title")}</h2>
      <SettingsAccountUsername className="md:max-w-160" />

      <Divider />

      <h2>{t("settings.account.password.title")}</h2>
      <SettingsAccountPassword className="md:max-w-160" security={security} />

      <Divider />

      <h2>{t("dnsidentity.adminSecurity")}</h2>
      {securityError && (
        <Space className="mb-4" wrap>
          <Alert type="error" title={unwrapErrMsg(securityError)} showIcon />
          <Button onClick={refresh}>{t("dns.refresh")}</Button>
        </Space>
      )}
      {security && <SettingsAdminSecurity status={security} onChange={refresh} />}
    </>
  );
};

const SettingsAccountUsername = ({ className, style }: { className?: string; style?: React.CSSProperties }) => {
  const navigate = useNavigate();

  const { t } = useTranslation();

  const { message, notification } = App.useApp();

  const formSchema = z.object({
    username: z.email(),
  });
  const formRule = createSchemaFieldRule(formSchema);
  const {
    form: formInst,
    formPending,
    formProps,
  } = useAntdForm<z.infer<typeof formSchema>>({
    initialValues: {
      username: getAuthStore().record?.email,
    },
    onSubmit: async (values) => {
      try {
        await saveAdmin({ email: values.username });

        message.success(t("common.text.operation_succeeded"));

        setTimeout(() => {
          getAuthStore().clear();
          navigate("/login");
        }, 500);
      } catch (err) {
        notification.error({ title: t("common.text.request_error"), description: unwrapErrMsg(err) });

        throw err;
      }
    },
  });
  const [formVisible, setFormVisible] = useState(false);
  const [formChanged, setFormChanged] = useState(false);

  const handleInputChange = () => {
    setFormChanged(formInst.getFieldValue("username") !== formProps.initialValues?.username);
  };

  const handleEditClick = () => {
    setFormVisible(true);
    formInst.resetFields();
  };

  const handleCancelClick = () => {
    setFormVisible(false);
    setFormChanged(false);
  };

  return (
    <div className={className} style={style}>
      <Form {...formProps} form={formInst} disabled={formPending} layout="vertical">
        {formVisible ? (
          <>
            <Form.Item name="username" label={t("settings.account.username.form.email.label")} rules={[formRule]}>
              <Input autoFocus placeholder={t("settings.account.username.form.email.placeholder")} onChange={handleInputChange} />
            </Form.Item>

            <Form.Item>
              <Flex align="center" gap="small">
                <Button type="primary" htmlType="submit" disabled={!formChanged} loading={formPending}>
                  {t("common.button.save")}
                </Button>
                <Button disabled={formPending} onClick={handleCancelClick}>
                  {t("common.button.cancel")}
                </Button>
              </Flex>
            </Form.Item>
          </>
        ) : (
          <>
            <div className="mb-2">
              <Typography.Text type="secondary">{t("settings.account.username.tips")}</Typography.Text>
            </div>
            <div className="mb-2">
              <Typography.Text>{getAuthStore().record?.email}</Typography.Text>
            </div>

            <Button onClick={handleEditClick}>{t("settings.account.username.button.label")}</Button>
          </>
        )}
      </Form>
    </div>
  );
};

const SettingsAccountPassword = ({ className, security }: { className?: string; security?: AdminSecurityStatus }) => {
  const navigate = useNavigate();

  const { t } = useTranslation();

  const { message, notification } = App.useApp();

  const formSchema = z
    .object({
      oldPassword: z.string().min(10).max(256),
      newPassword: z.string().min(10).max(256),
      confirmPassword: z.string().min(10).max(256),
      code: z.string().optional(),
    })
    .refine((values) => values.newPassword === values.confirmPassword, {
      error: t("settings.account.password.form.email.password.errmsg.not_matched"),
      path: ["confirmPassword"],
    });
  const formRule = createSchemaFieldRule(formSchema);
  const {
    form: formInst,
    formPending,
    formProps,
  } = useAntdForm({
    initialValues: {
      oldPassword: "",
      newPassword: "",
      confirmPassword: "",
    },
    onSubmit: async (values) => {
      try {
        await changeAdminPassword({ password: values.oldPassword, code: values.code }, values.newPassword, values.confirmPassword);

        message.success(t("common.text.operation_succeeded"));

        setTimeout(() => {
          getAuthStore().clear();
          navigate("/login");
        }, 500);
      } catch (err) {
        notification.error({ title: t("common.text.request_error"), description: unwrapErrMsg(err) });

        throw err;
      }
    },
  });
  const [formVisible, setFormVisible] = useState(false);
  const [formChanged, setFormChanged] = useState(false);

  const handleInputChange = () => {
    const values = formInst.getFieldsValue();
    setFormChanged(!!values.oldPassword && !!values.newPassword && !!values.confirmPassword);
  };

  const handleEditClick = () => {
    setFormVisible(true);
    formInst.resetFields();
  };

  const handleCancelClick = () => {
    setFormVisible(false);
    setFormChanged(false);
  };

  return (
    <div className={className}>
      <Form {...formProps} form={formInst} disabled={formPending} layout="vertical">
        {formVisible ? (
          <>
            <Form.Item name="oldPassword" label={t("settings.account.password.form.email.old_password.label")} rules={[formRule]}>
              <Input.Password
                autoFocus
                autoComplete="current-password"
                placeholder={t("settings.account.password.form.email.old_password.placeholder")}
                onChange={handleInputChange}
              />
            </Form.Item>

            <Form.Item name="newPassword" label={t("settings.account.password.form.email.new_password.label")} rules={[formRule]}>
              <Input.Password
                autoComplete="new-password"
                placeholder={t("settings.account.password.form.email.new_password.placeholder")}
                onChange={handleInputChange}
              />
            </Form.Item>

            <Form.Item name="confirmPassword" label={t("settings.account.password.form.email.confirm_password.label")} rules={[formRule]}>
              <Input.Password
                autoComplete="new-password"
                placeholder={t("settings.account.password.form.email.confirm_password.placeholder")}
                onChange={handleInputChange}
              />
            </Form.Item>
            {security?.active && (
              <Form.Item name="code" label={t("dnsidentity.authCode")} rules={[{ required: true, pattern: /^\d{6}$/ }]}>
                <Input inputMode="numeric" autoComplete="one-time-code" maxLength={6} />
              </Form.Item>
            )}

            <Form.Item>
              <Flex align="center" gap="small">
                <Button type="primary" htmlType="submit" disabled={!formChanged} loading={formPending}>
                  {t("common.button.save")}
                </Button>
                <Button disabled={formPending} onClick={handleCancelClick}>
                  {t("common.button.cancel")}
                </Button>
              </Flex>
            </Form.Item>
          </>
        ) : (
          <>
            <div className="mb-2">
              <Typography.Text type="secondary">{t("settings.account.password.tips")}</Typography.Text>
            </div>

            <Button disabled={!security} onClick={handleEditClick}>
              {t("settings.account.password.button.label")}
            </Button>
          </>
        )}
      </Form>
    </div>
  );
};

export default SettingsAccount;
