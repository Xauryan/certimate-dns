import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useMount } from "ahooks";
import { Alert, App, Button, Checkbox, Form, Input, Popconfirm, Skeleton, Space, Switch } from "antd";

import { getPocketBase } from "@/repository/_pocketbase";

type ProxySettings = {
  enabled: boolean;
  configured: boolean;
  scheme: string;
  server: string;
  hasUsername: boolean;
  hasPassword: boolean;
};

type FormValues = {
  enabled: boolean;
  server: string;
  username?: string;
  password?: string;
  clearAuthentication?: boolean;
};

const settingsURL = "/api/dns-proxy/settings";

function validServer(value: string): boolean {
  try {
    const url = new URL(value);
    const port = value.match(/:(\d+)\/?$/)?.[1];
    // URL.port normalizes well-known ports away, so check the original authority for its port.
    return (
      /^(https?|socks4|socks5h?):\/\/([^/@?#\s]+):\d{1,5}\/?$/i.test(value) &&
      Number(port) >= 1 &&
      Number(port) <= 65535 &&
      !url.username &&
      !url.password &&
      !!url.hostname &&
      (!url.pathname || url.pathname === "/") &&
      !url.search &&
      !url.hash
    );
  } catch {
    return false;
  }
}

const SettingsDNSProxy = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<FormValues>();
  const [saved, setSaved] = useState<ProxySettings | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [busy, setBusy] = useState<"save" | "test" | null>(null);
  const [dirty, setDirty] = useState(false);
  const [testResult, setTestResult] = useState<{ latencyMs: number } | "failed" | null>(null);
  const clearAuth = Form.useWatch("clearAuthentication", form);
  const currentServer = Form.useWatch("server", form)?.trim() ?? "";
  const sameServer = currentServer === saved?.server;
  const socks4 = currentServer.toLowerCase().startsWith("socks4://");

  const load = async () => {
    try {
      const data = await getPocketBase().send<ProxySettings>(settingsURL, { method: "GET", requestKey: null });
      setLoadError(false);
      form.setFieldsValue({ enabled: data.enabled, server: data.server, username: "", password: "", clearAuthentication: false });
      setSaved(data);
      setDirty(false);
    } catch {
      setLoadError(true);
    }
  };

  useMount(() => {
    void load();
  });

  const save = async (values: FormValues, remove = false) => {
    if (!saved) return;
    const body: { enabled: boolean; server?: string; username?: string; password?: string } = { enabled: values.enabled };
    const server = (values.server ?? "").trim();
    if (server !== saved.server || remove) body.server = server;
    if (values.clearAuthentication || remove) {
      body.username = "";
      body.password = "";
    } else {
      if (values.username) body.username = values.username;
      if (values.password && !socks4) body.password = values.password;
    }
    setBusy("save");
    setTestResult(null);
    try {
      await getPocketBase().send(settingsURL, { method: "PUT", body, requestKey: null });
      form.setFieldsValue({ username: "", password: "" });
      void message.success(t("common.text.operation_succeeded"));
      await load();
    } catch {
      void message.error(t("settings.dns_proxy.save_error"));
    } finally {
      setBusy(null);
    }
  };

  const test = async () => {
    setBusy("test");
    setTestResult(null);
    try {
      const result = await getPocketBase().send<{ ok: boolean; latencyMs: number }>("/api/dns-proxy/test", {
        method: "POST",
        body: {},
        requestKey: null,
      });
      setTestResult(result.ok ? { latencyMs: result.latencyMs } : "failed");
    } catch {
      setTestResult("failed");
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="md:max-w-160">
      <h2>{t("settings.dns_proxy.tab")}</h2>
      {loadError ? (
        <Alert type="error" showIcon title={t("settings.dns_proxy.load_error")} action={<Button onClick={load}>{t("common.button.reload")}</Button>} />
      ) : !saved ? (
        <Skeleton active />
      ) : (
        <Form
          form={form}
          layout="vertical"
          disabled={busy !== null}
          onFinish={(values) => save(values)}
          onValuesChange={() => {
            setDirty(true);
            setTestResult(null);
          }}
        >
          <Form.Item name="enabled" label={t("settings.dns_proxy.enabled")} extra={t("settings.dns_proxy.enabled_help")} valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item
            name="server"
            label={t("settings.dns_proxy.server")}
            extra={t("settings.dns_proxy.server_help")}
            dependencies={["enabled"]}
            rules={[
              {
                validator: async (_, value?: string) => {
                  const server = value?.trim() || "";
                  if (server ? !validServer(server) : saved.configured || form.getFieldValue("enabled")) {
                    throw new Error(t("settings.dns_proxy.invalid_server"));
                  }
                },
              },
            ]}
          >
            <Input autoComplete="off" placeholder="http://proxy.example:3128" />
          </Form.Item>
          <Form.Item name="username" label={t("settings.dns_proxy.username")}>
            <Input
              disabled={clearAuth || !!busy}
              autoComplete="off"
              maxLength={255}
              placeholder={sameServer && saved.hasUsername ? t("settings.dns_proxy.keep_saved") : undefined}
            />
          </Form.Item>
          <Form.Item
            name="password"
            label={t("settings.dns_proxy.password")}
            extra={socks4 ? t("settings.dns_proxy.socks4_help") : undefined}
            dependencies={["username", "server", "clearAuthentication"]}
            rules={[
              {
                validator: async (_, value?: string) => {
                  if (value && !clearAuth && !socks4 && !(sameServer && saved.hasUsername) && !form.getFieldValue("username")) {
                    throw new Error(t("settings.dns_proxy.username_required"));
                  }
                },
              },
            ]}
          >
            <Input.Password
              disabled={clearAuth || !!busy || socks4}
              maxLength={255}
              autoComplete="new-password"
              placeholder={sameServer && saved.hasPassword ? t("settings.dns_proxy.keep_saved") : undefined}
            />
          </Form.Item>
          {(saved.hasUsername || saved.hasPassword) && (
            <Form.Item name="clearAuthentication" valuePropName="checked">
              <Checkbox>{t("settings.dns_proxy.clear_auth")}</Checkbox>
            </Form.Item>
          )}
          <Space wrap>
            <Button type="primary" htmlType="submit" disabled={!dirty || !!busy} loading={busy === "save"}>
              {t("common.button.save")}
            </Button>
            <Button onClick={test} disabled={!saved.configured || dirty || !!busy} loading={busy === "test"}>
              {t("settings.dns_proxy.test")}
            </Button>
            {saved.configured && (
              <Popconfirm title={t("settings.dns_proxy.remove_confirm")} onConfirm={() => save({ enabled: false, server: "" }, true)}>
                <Button danger>{t("settings.dns_proxy.remove")}</Button>
              </Popconfirm>
            )}
          </Space>
          {testResult && (
            <div className="mt-4" role="status">
              <Alert
                type={testResult === "failed" ? "error" : "success"}
                showIcon
                title={testResult === "failed" ? t("settings.dns_proxy.test_failed") : t("settings.dns_proxy.test_success", { latency: testResult.latencyMs })}
              />
            </div>
          )}
        </Form>
      )}
    </section>
  );
};

export default SettingsDNSProxy;
