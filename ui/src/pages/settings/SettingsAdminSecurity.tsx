import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { Alert, Button, Form, Input, QRCode, Space, Typography } from "antd";

import {
  type AdminSecurityStatus,
  bindAdminAuthenticator,
  generateAdminAuthenticator,
  getAuthStore,
  removeAdminAuthenticator,
  setAdminCaptcha,
} from "@/repository/admin";
import { unwrapErrMsg } from "@/utils/error";

type Action = "captcha" | "setup" | "confirm" | "remove";

interface Credentials {
  password: string;
  code?: string;
}

export default function SettingsAdminSecurity({ status, onChange }: { status: AdminSecurityStatus; onChange: () => void }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [form] = Form.useForm<Credentials>();
  const [action, setAction] = useState<Action>();
  const [uri, setURI] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const select = (next?: Action) => {
    setAction(next);
    setURI("");
    setError("");
    form.resetFields();
  };

  const submit = async (credentials: Credentials) => {
    setBusy(true);
    setError("");
    try {
      switch (action) {
        case "captcha":
          await setAdminCaptcha(!status.captcha, credentials);
          select();
          onChange();
          break;
        case "setup":
          setURI((await generateAdminAuthenticator(credentials)).uri);
          setAction("confirm");
          form.resetFields();
          break;
        case "confirm":
        case "remove":
          if (action === "confirm") await bindAdminAuthenticator(credentials);
          else await removeAdminAuthenticator(credentials);
          select();
          getAuthStore().clear();
          await navigate("/login");
          break;
      }
    } catch (err) {
      setError(unwrapErrMsg(err));
    } finally {
      setBusy(false);
    }
  };

  const captchaAction = t(status.captcha ? "dnsidentity.adminCaptchaDisable" : "dnsidentity.adminCaptchaEnable");
  const setupAction = t(status.active ? "dnsidentity.adminAuthenticatorReplace" : "dnsidentity.enroll");
  const title =
    action === "captcha" ? captchaAction : action === "setup" ? setupAction : action === "confirm" ? t("dnsidentity.confirm") : t("dnsidentity.remove");

  return (
    <Space className="w-full md:max-w-160" orientation="vertical">
      <Typography.Paragraph>{t(status.captcha ? "dnsidentity.adminCaptchaOn" : "dnsidentity.adminCaptchaOff")}</Typography.Paragraph>
      <Typography.Paragraph>{t(status.active ? "dnsidentity.adminAuthenticatorOn" : "dnsidentity.adminAuthenticatorOff")}</Typography.Paragraph>
      {!status.available && <Alert type="info" title={t("dnsidentity.keyNeeded")} showIcon />}
      {!action && (
        <Space wrap>
          <Button onClick={() => select("captcha")}>{captchaAction}</Button>
          <Button disabled={!status.available} onClick={() => select("setup")}>
            {setupAction}
          </Button>
          {status.active && (
            <Button danger disabled={!status.available} onClick={() => select("remove")}>
              {t("dnsidentity.remove")}
            </Button>
          )}
        </Space>
      )}
      <Form form={form} layout="vertical" disabled={busy} onFinish={submit}>
        {action && (
          <>
            {error && <Alert className="mb-4" type="error" title={error} showIcon />}
            {action === "confirm" && uri && (
              <>
                <Typography.Paragraph>{t("dnsidentity.adminScan")}</Typography.Paragraph>
                <QRCode className="mb-4" value={uri} />
              </>
            )}
            {action !== "captcha" && <Typography.Paragraph>{t("dnsidentity.authenticatorHelp")}</Typography.Paragraph>}
            <Form.Item name="password" label={t("dnsidentity.adminCurrentPassword")} rules={[{ required: true }]}>
              <Input.Password autoComplete="current-password" />
            </Form.Item>
            {(action === "confirm" || status.active) && (
              <Form.Item
                name="code"
                label={t(action === "confirm" ? "dnsidentity.adminNewCode" : "dnsidentity.authCode")}
                rules={[{ required: true, pattern: /^\d{6}$/ }]}
              >
                <Input inputMode="numeric" autoComplete="one-time-code" maxLength={6} />
              </Form.Item>
            )}
            <Space wrap>
              <Button type="primary" htmlType="submit" danger={action === "remove"} loading={busy}>
                {title}
              </Button>
              <Button onClick={() => select()}>{t("common.button.cancel")}</Button>
            </Space>
          </>
        )}
      </Form>
    </Space>
  );
}
