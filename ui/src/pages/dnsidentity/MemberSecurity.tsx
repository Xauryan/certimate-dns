import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert, Button, Collapse, Form, Input, QRCode, Space, Typography } from "antd";
import { getPocketBase } from "@/repository/_pocketbase";
import { unwrapErrMsg } from "@/utils/error";

export default function MemberSecurity() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<{ active: boolean; available: boolean }>();
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [uri, setUri] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const endpoint = "/api/dns-identity/member/totp";
  useEffect(() => {
    getPocketBase()
      .send(endpoint, { method: "GET", requestKey: null })
      .then(setStatus)
      .catch((err) => setError(unwrapErrMsg(err)));
  }, []);
  async function submit() {
    setError("");
    setBusy(true);
    try {
      const pb = getPocketBase();
      if (!uri && !status?.active) {
        const data = await pb.send<{ uri: string }>(endpoint + "/generate", { method: "POST", body: { password } });
        setUri(data.uri);
      } else {
        await pb.send(endpoint + (uri ? "/bind" : "/remove"), { method: "POST", body: { password, code } });
        setUri("");
        setCode("");
        setPassword("");
        pb.authStore.clear();
      }
    } catch (err) {
      setError(unwrapErrMsg(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Collapse
      items={[
        {
          key: "security",
          label: t("dnsidentity.authenticator"),
          children: (
            <Space orientation="vertical">
              {error && <Alert type="error" title={error} showIcon />}
              {status && !status.available && <Alert type="info" title={t("dnsidentity.keyNeeded")} />}
              {status?.available && (
                <Form layout="vertical" onFinish={submit}>
                  <Form.Item label={t("dnsauth.password")}>
                    <Input.Password autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
                  </Form.Item>
                  {uri && (
                    <Space orientation="vertical">
                      <QRCode value={uri} />
                      <Typography.Text code>{new URL(uri).searchParams.get("secret")}</Typography.Text>
                    </Space>
                  )}
                  {(uri || status.active) && (
                    <Form.Item label={t("dnsidentity.authCode")}>
                      <Input inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} />
                    </Form.Item>
                  )}
                  <Typography.Paragraph>{t("dnsidentity.authenticatorHelp")}</Typography.Paragraph>
                  <Button htmlType="submit" loading={busy} disabled={!password || ((!!uri || status.active) && code.length !== 6)}>
                    {t(status.active ? "dnsidentity.remove" : uri ? "dnsidentity.confirm" : "dnsidentity.enroll")}
                  </Button>
                </Form>
              )}
            </Space>
          ),
        },
      ]}
    />
  );
}
