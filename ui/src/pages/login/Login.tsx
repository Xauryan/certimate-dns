import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router-dom";
import { IconArrowRight, IconLock, IconMail } from "@tabler/icons-react";
import { useRequest } from "ahooks";
import { Alert, App, Button, Card, Divider, Form, Input, Space, Typography } from "antd";
import { createSchemaFieldRule } from "antd-zod";
import { ClientResponseError } from "pocketbase";
import { z } from "zod";

import AppDocument from "@/components/AppDocument";
import AppLocale from "@/components/AppLocale";
import AppTheme from "@/components/AppTheme";
import AppVersion from "@/components/AppVersion";
import { useAntdForm, useBrowserTheme } from "@/hooks";
import { authWithAdminEmailCode, authWithAuthenticator, authWithPassword, getAdminCaptcha, requestAdminEmailCode } from "@/repository/admin";
import { unwrapErrMsg } from "@/utils/error";
import { withBasePath } from "@/utils/url";

const Login = () => {
  const navigate = useNavigate();

  const { t } = useTranslation();

  const { notification } = App.useApp();
  const { theme: browserTheme } = useBrowserTheme();
  const { data: captcha, loading: captchaLoading, error: captchaError, refresh } = useRequest(getAdminCaptcha);
  const [answer, setAnswer] = useState("");
  const [totpId, setTotpId] = useState("");
  const [mfa, setMfa] = useState<{ id: string; email: string }>();
  const [otpId, setOtpId] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState("");

  const refreshCaptcha = () => {
    setAnswer("");
    refresh();
  };

  const proof = { captchaId: captcha?.id, captcha: answer };
  const captchaReady = !!captcha && !captchaLoading && !captchaError && (!captcha.required || !!answer);
  const displayError = error || (captchaError && unwrapErrMsg(captchaError));

  const finish = async (action: () => Promise<unknown>, email?: string) => {
    setError("");
    try {
      await action();
      await navigate("/");
    } catch (err) {
      const data = err instanceof ClientResponseError && err.status === 401 ? err.response : {};
      if (typeof data.totpId === "string") {
        setTotpId(data.totpId);
        formInst.setFieldValue("password", "");
        return;
      }
      if (typeof data.mfaId === "string" && email) {
        setMfa({ id: data.mfaId, email });
        setOtpId("");
        formInst.setFieldValue("password", "");
      } else {
        setError(unwrapErrMsg(err));
      }
      if (!totpId) refreshCaptcha();
    }
  };

  const startAgain = () => {
    setTotpId("");
    setMfa(undefined);
    setOtpId("");
    setError("");
    refreshCaptcha();
  };

  const bgStyle = useMemo<React.CSSProperties>(() => {
    let svg = "";
    let mask = "";
    if (browserTheme === "dark") {
      svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32" fill="none" stroke="rgb(202 78 13 / 0.12)"><path d="M0 .5H31.5V32"/></svg>`;
      mask = "white";
    } else {
      svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32" fill="none" stroke="rgb(249 115 22 / 0.08)"><path d="M0 .5H31.5V32"/></svg>`;
      mask = "black";
    }

    return {
      backgroundImage: `url('data:image/svg+xml;base64,${btoa(svg)}')`,
      maskImage: `linear-gradient(to bottom right, transparent, ${mask}, transparent)`,
    };
  }, [browserTheme]);

  const formSchema = z.object({
    username: z.email(),
    password: z.string().min(10).max(256),
  });
  const formRule = createSchemaFieldRule(formSchema);
  const {
    form: formInst,
    formPending,
    formProps,
  } = useAntdForm<z.infer<typeof formSchema>>({
    initialValues: {
      username: "",
      password: "",
    },
    onSubmit: async (values) => {
      await finish(() => authWithPassword(values.username, values.password, proof), values.username);
    },
  });

  const captchaFields = (
    <>
      {captcha?.required && (
        <Form.Item label={t("dnsidentity.captcha")} htmlFor="admin-captcha">
          <Space className="mb-2">
            <img width={128} height={50} src={captcha.image} alt={t("dnsidentity.captcha")} />
            <Button loading={captchaLoading} onClick={refreshCaptcha}>
              {t("dns.refresh")}
            </Button>
          </Space>
          <Input id="admin-captcha" autoComplete="off" value={answer} onChange={(event) => setAnswer(event.target.value.toUpperCase())} />
        </Form.Item>
      )}
      {!captcha && !captchaLoading && <Button onClick={refreshCaptcha}>{t("dns.refresh")}</Button>}
    </>
  );

  return (
    <>
      <div className="pointer-events-none fixed min-h-screen w-full" style={bgStyle}></div>

      <div className="flex h-screen w-full flex-col items-center justify-center">
        <Card className="w-120 max-w-full rounded-md shadow-md max-sm:size-full max-sm:rounded-none">
          <div className="px-4 py-8">
            <div className="mb-12 flex items-center justify-center">
              <img src={withBasePath("/logo.svg")} className="w-16" />
            </div>

            {displayError && <Alert className="mb-4" type="error" title={displayError} showIcon />}
            {totpId || mfa ? (
              <Form<{ code: string }>
                key={totpId ? "authenticator" : "email"}
                layout="vertical"
                disabled={verifying}
                onFinish={async ({ code }) => {
                  setVerifying(true);
                  try {
                    if (totpId) {
                      await finish(() => authWithAuthenticator(totpId, code));
                    } else if (mfa) {
                      await finish(() => authWithAdminEmailCode(otpId, code, mfa.id, proof), mfa.email);
                    }
                  } finally {
                    setVerifying(false);
                  }
                }}
              >
                {!totpId && mfa && (
                  <Button
                    className="mb-4"
                    onClick={async () => {
                      setVerifying(true);
                      try {
                        setOtpId((await requestAdminEmailCode(mfa.email)).otpId);
                      } catch (err) {
                        notification.error({ title: t("common.text.request_error"), description: unwrapErrMsg(err) });
                      } finally {
                        setVerifying(false);
                      }
                    }}
                  >
                    {t("dnsidentity.sendOtp")}
                  </Button>
                )}
                <Form.Item
                  name="code"
                  label={t(totpId ? "dnsidentity.authCode" : "dnsidentity.emailCode")}
                  rules={[{ required: true, pattern: totpId ? /^\d{6}$/ : undefined }]}
                >
                  <Input autoFocus inputMode="numeric" autoComplete="one-time-code" maxLength={totpId ? 6 : 12} />
                </Form.Item>
                {!totpId && captchaFields}
                <Space wrap>
                  <Button type="primary" htmlType="submit" loading={verifying} disabled={!totpId && (!otpId || !captchaReady)}>
                    {t("dnsidentity.signIn")}
                  </Button>
                  <Button onClick={startAgain}>{t("dnsidentity.restart")}</Button>
                </Space>
                {totpId && <Typography.Paragraph className="mt-4">{t("dnsidentity.adminRecovery")}</Typography.Paragraph>}
              </Form>
            ) : (
              <Form {...formProps} form={formInst} disabled={formPending} layout="vertical" validateTrigger="onBlur">
                <Form.Item name="username" label={t("login.form.username.label")} rules={[formRule]}>
                  <Space.Compact block>
                    <Space.Addon>
                      <IconMail size="1.25em" />
                    </Space.Addon>
                    <Input autoComplete="username" autoFocus placeholder={t("login.form.username.placeholder")} size="large" />
                  </Space.Compact>
                </Form.Item>

                <Form.Item name="password" label={t("login.form.password.label")} rules={[formRule]}>
                  <Space.Compact block>
                    <Space.Addon>
                      <IconLock size="1.25em" />
                    </Space.Addon>
                    <Input.Password autoComplete="current-password" placeholder={t("login.form.password.placeholder")} size="large" />
                  </Space.Compact>
                </Form.Item>

                {captchaFields}
                <Form.Item className="mt-8 mb-0">
                  <Button
                    block
                    type="primary"
                    htmlType="submit"
                    icon={<IconArrowRight size="1.25em" />}
                    iconPlacement="end"
                    loading={formPending}
                    disabled={!captchaReady}
                    size="large"
                  >
                    {t("login.form.submit.button")}
                  </Button>
                </Form.Item>
              </Form>
            )}
            <div className="mt-4 text-center">
              <Link to="/dns-member">{t("dnsauth.portal")}</Link>
            </div>

            <div className="mt-12">
              <div className="block max-sm:hidden">
                <div className="flex items-center justify-center">
                  <Space align="center" separator={<Divider orientation="vertical" />} size={4}>
                    <AppLocale.LinkButton />
                    <AppTheme.LinkButton />
                    <AppDocument.LinkButton />
                    <AppVersion />
                  </Space>
                </div>
              </div>
              <div className="hidden max-sm:block">
                <div className="flex items-center justify-center">
                  <Space align="center" separator={<Divider orientation="vertical" />} size={4}>
                    <AppLocale.LinkButton />
                    <AppTheme.LinkButton />
                    <AppDocument.LinkButton />
                  </Space>
                </div>
                <div className="mt-6 flex items-center justify-center">
                  <Space align="center" separator={<Divider orientation="vertical" />} size={4}>
                    <AppVersion />
                  </Space>
                </div>
              </div>
            </div>
          </div>
        </Card>
      </div>
    </>
  );
};

export default Login;
