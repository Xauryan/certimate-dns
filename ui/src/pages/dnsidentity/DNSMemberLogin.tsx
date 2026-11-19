import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert, Button, Card, Form, Input, Space, Typography } from "antd";
import { type AuthMethodsList, ClientResponseError, type RecordAuthResponse } from "pocketbase";
import AppTheme from "@/components/AppTheme";
import { getPocketBase } from "@/repository/_pocketbase";
import { unwrapErrMsg } from "@/utils/error";

interface Captcha {
  required: boolean;
  id?: string;
  image?: string;
}
type Method = "password" | "otp" | "oauth2";
const pb = getPocketBase();
const members = pb.collection("dns_members");
const endpoint = "/api/dns-identity";

export default function DNSMemberLogin() {
  const { t } = useTranslation();
  const [methods, setMethods] = useState<AuthMethodsList>();
  const [captcha, setCaptcha] = useState<Captcha>();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [answer, setAnswer] = useState("");
  const [otp, setOtp] = useState("");
  const [otpID, setOtpID] = useState("");
  const [code, setCode] = useState("");
  const [totpID, setTotpID] = useState("");
  const [mfa, setMfa] = useState<{ id: string; first: Method }>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const refresh = async () => {
    setAnswer("");
    setCaptcha(await pb.send<Captcha>(endpoint + "/captcha", { method: "GET", requestKey: null }));
  };
  useEffect(() => {
    Promise.all([members.listAuthMethods({ requestKey: null }).then(setMethods), refresh()]).catch((err) => setError(unwrapErrMsg(err)));
  }, []);
  const run = async (method: Method, action: () => Promise<unknown>) => {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (err) {
      const data = err instanceof ClientResponseError ? err.response : {};
      if (typeof data.mfaId === "string") {
        setMfa({ id: data.mfaId, first: method });
        setOtp("");
        setOtpID("");
        setTotpID("");
        setPassword("");
      } else if (typeof data.totpId === "string") {
        setTotpID(data.totpId);
        setCode("");
        setPassword("");
        setOtp("");
      } else {
        setError(unwrapErrMsg(err));
      }
      if (method === "password" && captcha?.required) await refresh().catch((cause) => setError(unwrapErrMsg(cause)));
    } finally {
      setBusy(false);
    }
  };
  const options = mfa ? { query: { mfaId: mfa.id } } : {};
  const show = (m: Method) => mfa?.first !== m;
  const reset = () => {
    setMfa(undefined);
    setTotpID("");
    setOtpID("");
    setPassword("");
    setCode("");
    setOtp("");
    setError("");
    refresh().catch((err) => setError(unwrapErrMsg(err)));
  };
  return (
    <main className="mx-auto w-full max-w-md p-4 md:p-8">
      <header className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <Typography.Title level={3} style={{ margin: 0 }}>
          {t("dnsauth.portal")}
        </Typography.Title>
        <AppTheme.LinkButton />
      </header>
      <Card>
        {error && <Alert type="error" title={error} showIcon />}
        {mfa && <Alert type="info" title={t("dnsidentity.mfaPrompt")} showIcon />}
        {totpID ? (
          <Form
            layout="vertical"
            onFinish={() =>
              run("password", async () => {
                const data = await pb.send<RecordAuthResponse>(endpoint + "/totp/login", { method: "POST", body: { totpId: totpID, code } });
                pb.authStore.save(data.token, data.record);
              })
            }
          >
            <Form.Item label={t("dnsidentity.authCode")}>
              <Input inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} maxLength={6} />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={busy}>
              {t("dnsidentity.signIn")}
            </Button>
          </Form>
        ) : (
          <Space orientation="vertical" className="w-full">
            {((methods?.password.enabled && show("password")) || (methods?.otp.enabled && show("otp"))) && (
              <Form.Item label={t("dnsauth.email")}>
                <Input
                  type="email"
                  autoComplete="username"
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    setOtpID("");
                  }}
                />
              </Form.Item>
            )}
            {methods?.password.enabled && show("password") && (
              <Form
                layout="vertical"
                onFinish={() =>
                  run("password", () =>
                    members.authWithPassword(email, password, { ...options, body: { identity: email, password, captcha: answer, captchaId: captcha?.id } })
                  )
                }
              >
                <Form.Item label={t("dnsauth.password")}>
                  <Input.Password autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
                </Form.Item>
                {captcha?.required && (
                  <Form.Item label={t("dnsidentity.captcha")}>
                    <Space>
                      <img width={128} height={50} src={captcha.image} alt={t("dnsidentity.captcha")} />
                      <Button onClick={() => refresh().catch((err) => setError(unwrapErrMsg(err)))}>{t("dns.refresh")}</Button>
                    </Space>
                    <Input value={answer} onChange={(e) => setAnswer(e.target.value.toUpperCase())} autoComplete="off" />
                  </Form.Item>
                )}
                <Button type="primary" htmlType="submit" loading={busy} disabled={!email || !password || !captcha}>
                  {t("dnsidentity.passwordSignIn")}
                </Button>
              </Form>
            )}
            {methods?.otp.enabled && show("otp") && (
              <>
                <Button disabled={!email || busy} onClick={() => run("otp", async () => setOtpID((await members.requestOTP(email)).otpId))}>
                  {t("dnsidentity.sendOtp")}
                </Button>
                {otpID && (
                  <Form layout="vertical" onFinish={() => run("otp", () => members.authWithOTP(otpID, otp, options))}>
                    <Form.Item label={t("dnsidentity.emailCode")}>
                      <Input autoComplete="one-time-code" value={otp} onChange={(e) => setOtp(e.target.value)} />
                    </Form.Item>
                    <Button htmlType="submit" loading={busy}>
                      {t("dnsidentity.signIn")}
                    </Button>
                  </Form>
                )}
              </>
            )}
            {methods?.oauth2.enabled &&
              show("oauth2") &&
              methods.oauth2.providers.map((p) => (
                <Button key={p.name} disabled={busy} onClick={() => run("oauth2", () => members.authWithOAuth2({ provider: p.name, ...options }))}>
                  {p.displayName || p.name}
                </Button>
              ))}
          </Space>
        )}
        {(mfa || totpID) && (
          <Button type="link" onClick={reset}>
            {t("dnsidentity.restart")}
          </Button>
        )}
      </Card>
    </main>
  );
}
