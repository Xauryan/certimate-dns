import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert, Button, Card, Form, Input, Space, Switch, Typography } from "antd";
import { getPocketBase } from "@/repository/_pocketbase";
import { unwrapErrMsg } from "@/utils/error";

type Settings = { enabled: boolean; appId: string; openId: string; confirmedAt: number; secretConfigured: boolean };
const endpoint = "/api/dns-identity";

export default function DNSIdentity() {
  const { t } = useTranslation();
  const [policy] = Form.useForm();
  const [oidc] = Form.useForm();
  const [qq] = Form.useForm();
  const [dest, setDest] = useState<Settings>();
  const [pairCode, setPairCode] = useState("");
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const pb = getPocketBase();
  const load = useCallback(async () => {
    const [policyData, oidcData, qqData] = await Promise.all([
      pb.send(endpoint + "/member-policy", { method: "GET", requestKey: null }),
      pb.send(endpoint + "/oidc", { method: "GET", requestKey: null }),
      pb.send<Settings>(endpoint + "/qq", { method: "GET", requestKey: null }),
    ]);
    policy.setFieldsValue(policyData);
    oidc.setFieldsValue({ ...oidcData, clientSecret: "" });
    qq.setFieldsValue(qqData);
    setDest(qqData);
  }, [pb, policy, oidc, qq]);
  useEffect(() => {
    load().catch((err) => setError(unwrapErrMsg(err)));
  }, [load]);
  const save = async (path: string, body?: object, method = "PUT") => {
    setBusy(true);
    setError("");
    setStatus("");
    setPairCode("");
    try {
      const result = await pb.send<{ code?: string }>(endpoint + path, { method, body });
      if (result?.code) setPairCode(result.code);
      await load();
      setStatus(t(path === "/qq/test" ? "dnsidentity.sent" : "dnsidentity.saved"));
    } catch (err) {
      setError(unwrapErrMsg(err));
    } finally {
      setBusy(false);
    }
  };
  const submit = (
    <Button htmlType="submit" type="primary" loading={busy}>
      {t("dnsidentity.save")}
    </Button>
  );
  return (
    <Space className="w-full max-w-3xl" orientation="vertical">
      <Typography.Title level={3}>{t("dnsidentity.title")}</Typography.Title>
      {error && <Alert type="error" title={error} showIcon />}
      {status && <Alert type="success" title={status} showIcon />}
      <Card title={t("dnsidentity.policy")}>
        <Form form={policy} disabled={busy || !dest} layout="vertical" onFinish={(v) => save("/member-policy", v)}>
          {["captcha", "otp", "mfa"].map((name) => (
            <Form.Item key={name} label={t("dnsidentity." + name)} name={name} valuePropName="checked">
              <Switch />
            </Form.Item>
          ))}
          {submit}
        </Form>
      </Card>
      <Card title="OpenID Connect">
        <Form form={oidc} disabled={busy || !dest} layout="vertical" onFinish={(v) => save("/oidc", v)}>
          <Form.Item label={t("dnsauth.enable")} name="enabled" valuePropName="checked">
            <Switch />
          </Form.Item>
          {["displayName", "clientId", "authUrl", "tokenUrl", "userInfoUrl"].map((name) => (
            <Form.Item key={name} label={t("dnsidentity." + name)} name={name}>
              <Input />
            </Form.Item>
          ))}
          <Form.Item label={t("dnsidentity.clientSecret")} name="clientSecret" extra={t("dnsidentity.secretHelp")}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Typography.Paragraph>
            {t("dnsidentity.redirect")} <Typography.Text code>{new URL(pb.buildURL("/api/oauth2-redirect"), location.origin).href}</Typography.Text>
          </Typography.Paragraph>
          {submit}
        </Form>
      </Card>
      <Card title="QQ Bot">
        <Form form={qq} disabled={busy || !dest} layout="vertical" onFinish={(v) => save("/qq", v)}>
          <Form.Item label={t("dnsauth.enable")} name="enabled" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item label="App ID" name="appId">
            <Input />
          </Form.Item>
          <Form.Item label={t("dnsidentity.recipient")} name="openId">
            <Input />
          </Form.Item>
          <Typography.Paragraph>
            {t("dnsidentity.webhook")} <Typography.Text code>{new URL(pb.buildURL(endpoint + "/qq/webhook"), location.origin).href}</Typography.Text>
          </Typography.Paragraph>
          {dest && !dest.secretConfigured && <Typography.Paragraph>{t("dnsidentity.qqSecret")}</Typography.Paragraph>}
          {dest && dest.confirmedAt > 0 && (
            <Typography.Paragraph>
              {t("dnsidentity.confirmedAt")} {new Date(dest.confirmedAt * 1000).toLocaleString()}
            </Typography.Paragraph>
          )}
          <Space wrap>
            {submit}
            <Button disabled={!dest?.enabled} onClick={() => save("/qq/bind", undefined, "POST")}>
              {t("dnsidentity.pair")}
            </Button>
            <Button disabled={!dest?.enabled || !dest?.openId} onClick={() => save("/qq/test", undefined, "POST")}>
              {t("dnsidentity.test")}
            </Button>
            <Button onClick={() => load().catch((err) => setError(unwrapErrMsg(err)))}>{t("dns.refresh")}</Button>
          </Space>
          {pairCode && (
            <Typography.Paragraph>
              {t("dnsidentity.pairHelp")} <Typography.Text code>{pairCode}</Typography.Text>
            </Typography.Paragraph>
          )}
        </Form>
      </Card>
    </Space>
  );
}
