import { useState } from "react";
import { Link } from "react-router-dom";
import { Alert, App, Button, Card, Checkbox, Form, Input, InputNumber, Select, Space, Spin, Tabs, Typography } from "antd";

import { dnsRequest } from "@/api/dns";
import DNSAdvanced from "@/pages/dnsadvanced/DNSAdvanced";
import { unwrapErrMsg } from "@/utils/error";
import { base, type Details, type Metadata, type ResourceLink, useCatalog, useLabels } from "./catalog";

function MetadataForm({ zone, onSaved }: { zone: Details; onSaved: () => void }) {
  const l = useLabels();
  const { message } = App.useApp();
  const [busy, setBusy] = useState(false);
  const channels = useCatalog<ResourceLink[]>("/notification-channels", 0);
  const [form] = Form.useForm<Metadata>();
  const enabled = Form.useWatch("reminderEnabled", form);
  const autoRefresh = Form.useWatch("autoRefresh", form);
  async function save(data: Metadata) {
    setBusy(true);
    try {
      await dnsRequest(base + "/domains/" + zone.id + "/metadata", "PUT", { ...data, notificationId: data.notificationId || "", tags: data.tags || [] });
      message.success(l.saved);
      onSaved();
    } catch (err) {
      message.error(unwrapErrMsg(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Form form={form} layout="vertical" initialValues={zone} onFinish={save} style={{ maxWidth: 640 }}>
      <Form.Item label={l.group} name="groupName">
        <Input maxLength={128} />
      </Form.Item>
      <Form.Item label={l.tags} name="tags">
        <Select mode="tags" tokenSeparators={[",", "，"]} maxCount={32} />
      </Form.Item>
      <Form.Item label={l.notes} name="notes">
        <Input.TextArea rows={3} maxLength={2048} />
      </Form.Item>
      <Form.Item name="hidden" valuePropName="checked">
        <Checkbox>{l.hidden}</Checkbox>
      </Form.Item>
      <Form.Item name="autoRefresh" valuePropName="checked">
        <Checkbox>{l.autoRefresh}</Checkbox>
      </Form.Item>
      <Form.Item label={l.registered}>
        <Typography.Text>{zone.registeredOn || l.empty}</Typography.Text>
      </Form.Item>
      <Form.Item label={l.lastCheck}>
        <Space wrap>
          <Typography.Text>{zone.registrationChecked ? new Date(zone.registrationChecked).toLocaleString() : l.empty}</Typography.Text>
          {zone.registrationStatus && (
            <Typography.Text type={zone.registrationStatus === "ok" ? "success" : "warning"}>
              {zone.registrationStatus === "ok" ? l.ok : l.failed}
            </Typography.Text>
          )}
          <Button
            disabled={!zone.enabled || !zone.present}
            loading={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await dnsRequest(base + "/domains/" + zone.id + "/registration", "POST");
                message.success(l.saved);
              } catch (e) {
                message.error(unwrapErrMsg(e));
              } finally {
                setBusy(false);
                onSaved();
              }
            }}
          >
            {l.refreshDates}
          </Button>
        </Space>
      </Form.Item>
      <Form.Item label={l.expiry} name="expiresOn" rules={[{ required: enabled && !autoRefresh }]}>
        <Input type="date" />
      </Form.Item>
      <Form.Item name="reminderEnabled" valuePropName="checked">
        <Checkbox>{l.reminder}</Checkbox>
      </Form.Item>
      <Form.Item label={l.days} name="reminderDays" rules={[{ required: enabled }]}>
        <InputNumber min={0} max={365} precision={0} disabled={!enabled} />
      </Form.Item>
      <Form.Item label={l.channel} name="notificationId">
        <Select
          disabled={!enabled}
          loading={!channels}
          options={[{ label: l.inbox, value: "" }, ...(channels?.data || []).map((c) => ({ value: c.id, label: c.name }))]}
        />
      </Form.Item>
      {channels?.error && <Alert type="error" title={channels.error} />}
      <Button type="primary" htmlType="submit" loading={busy}>
        {l.save}
      </Button>
    </Form>
  );
}

export default function DomainDetail({ id, back }: { id: string; back: () => void }) {
  const l = useLabels();
  const [revision, setRevision] = useState(0);
  const response = useCatalog<Details>("/domains/" + encodeURIComponent(id), revision);
  const zone = response?.data;
  const refresh = () => setRevision((r) => r + 1);
  return (
    <div className="flex flex-col gap-4">
      <Space>
        <Button onClick={back}>{l.back}</Button>
        <Button onClick={refresh}>{l.refresh}</Button>
      </Space>
      {response?.error && <Alert type="error" title={response.error} />}
      {!response && <Spin />}
      {zone && (
        <>
          <Typography.Title level={3} style={{ margin: 0 }}>
            {zone.name}
          </Typography.Title>
          <Space wrap>
            <Typography.Text>
              {zone.accountName} · {zone.provider}
            </Typography.Text>
            {zone.enabled && zone.present ? (
              <Link
                to={"/dns?" + new URLSearchParams({ catalogId: zone.id, access: zone.accessId, provider: zone.provider, zone: zone.zoneId, name: zone.name })}
              >
                {l.records}
              </Link>
            ) : (
              <Typography.Text type="warning">{zone.enabled ? l.missing : l.disabled}</Typography.Text>
            )}
          </Space>
          <Tabs
            items={[
              { key: "metadata", label: l.metadata, children: <MetadataForm zone={zone} onSaved={refresh} /> },
              {
                key: "resources",
                label: [l.certs, l.workflows, l.tasks].join(" / "),
                children: (
                  <div className="grid gap-3 lg:grid-cols-3">
                    <Card title={l.certs}>
                      <Space orientation="vertical">
                        {zone.certificates.map((c) => (
                          <Link key={c.id} to={"/certificates?keyword=" + encodeURIComponent(c.id)}>
                            {c.subjectName || c.subjectAltNames || c.id} · {c.expires.slice(0, 10)}
                          </Link>
                        ))}
                        {!zone.certificates.length && l.empty}
                      </Space>
                    </Card>
                    <Card title={l.workflows}>
                      <Space orientation="vertical">
                        {zone.workflows.map((w) => (
                          <Link key={w.id} to={"/workflows/" + w.id}>
                            {w.name}
                          </Link>
                        ))}
                        {!zone.workflows.length && l.empty}
                      </Space>
                    </Card>
                    <Card title={l.tasks}>
                      <Space orientation="vertical">
                        {zone.tasks.map((t) => (
                          <Link key={t.id} to={"/dns/automation?task=" + encodeURIComponent(t.id)}>
                            {t.name}
                          </Link>
                        ))}
                        {!zone.tasks.length && l.empty}
                      </Space>
                    </Card>
                  </div>
                ),
              },
              ...(zone.enabled && zone.present
                ? [
                    {
                      key: "provider",
                      label: l.advanced,
                      children: (
                        <DNSAdvanced
                          base={"/api/dns/" + encodeURIComponent(zone.provider) + "/" + encodeURIComponent(zone.accessId)}
                          zone={{ id: zone.zoneId, name: zone.name }}
                          canWrite
                        />
                      ),
                    },
                  ]
                : []),
            ]}
          />
        </>
      )}
    </div>
  );
}
