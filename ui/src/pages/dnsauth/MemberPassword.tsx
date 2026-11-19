import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert, Button, Form, Input, Modal } from "antd";

import { dnsRequest } from "@/api/dns";
import { getPocketBase } from "@/repository/_pocketbase";
import { unwrapErrMsg } from "@/utils/error";

export default function MemberPassword() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function save(values: { current: string; password: string }) {
    setBusy(true);
    setError("");
    try {
      await dnsRequest("/api/dns-member/password", "POST", values);
      getPocketBase().authStore.clear();
    } catch (err) {
      setError(unwrapErrMsg(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Button
        onClick={() => {
          setError("");
          setOpen(true);
        }}
      >
        {t("dnsauth.changePassword")}
      </Button>
      <Modal open={open} destroyOnHidden footer={null} title={t("dnsauth.changePassword")} onCancel={() => setOpen(false)}>
        <Form layout="vertical" disabled={busy} onFinish={save}>
          {error && <Alert type="error" title={error} />}
          <Form.Item name="current" label={t("dnsauth.currentPassword")} rules={[{ required: true }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Form.Item name="password" label={t("dnsauth.newPassword")} rules={[{ required: true, min: 10 }]}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Button type="primary" loading={busy} htmlType="submit">
            {t("dnsauth.savePassword")}
          </Button>
        </Form>
      </Modal>
    </>
  );
}
