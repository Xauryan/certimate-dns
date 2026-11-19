import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert, Button, Checkbox, Modal, Space, Typography } from "antd";

import { dnsRequest } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";

export default function QuickLink({ id, name, canWrite }: { id: string; name: string; canWrite: boolean }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [write, setWrite] = useState(false);
  const [busy, setBusy] = useState(false);
  const [link, setLink] = useState("");
  const [error, setError] = useState("");

  async function issue() {
    setBusy(true);
    setError("");
    try {
      const data = await dnsRequest<{ link: string }>(`/api/dns-member/zones/${encodeURIComponent(id)}/links`, "POST", { write });
      const url = new URL(window.location.href);
      url.hash = data.link;
      setLink(url.toString());
    } catch (err) {
      setError(unwrapErrMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Button
        type="link"
        onClick={() => {
          setOpen(true);
          setWrite(false);
          setLink("");
          setError("");
        }}
      >
        {t("dnsauth.quickLink")}
      </Button>
      <Modal open={open} title={name} footer={null} onCancel={() => setOpen(false)}>
        <Space orientation="vertical">
          <Typography.Paragraph>{t("dnsauth.linkHelp")}</Typography.Paragraph>
          {error && <Alert type="error" title={error} />}
          {link ? (
            <Typography.Paragraph copyable style={{ wordBreak: "break-all" }}>
              {link}
            </Typography.Paragraph>
          ) : (
            <>
              {canWrite && (
                <Checkbox checked={write} onChange={(event) => setWrite(event.target.checked)}>
                  {t("dnsauth.allowWrites")}
                </Checkbox>
              )}
              <Button type="primary" loading={busy} onClick={issue}>
                {t("dnsauth.issueLink")}
              </Button>
            </>
          )}
        </Space>
      </Modal>
    </>
  );
}
