import { useState } from "react";
import { Alert, Checkbox, Form, Input, InputNumber, Modal, Select, Space, Typography } from "antd";
import { dnsRequest } from "@/api/dns";
import { type Account, type ResourceLink, useCatalog } from "@/pages/dnscatalog/catalog";
import { unwrapErrMsg } from "@/utils/error";
import TargetPicker from "./TargetPicker";
import { type Definition, type Label, type Target, type Task, base } from "./types";

export default function Editor({ task, label, onClose, onSaved }: { task?: Task; label: Label; onClose: () => void; onSaved: () => void }) {
  const [form] = Form.useForm<Definition>();
  const [target, setTarget] = useState<Target | undefined>(task?.definition.target);
  const channels = useCatalog<ResourceLink[]>("/notification-channels", 0);
  const accounts = useCatalog<Account[]>("/accounts", 0);
  const provider = accounts?.data?.find((a) => a.id === target?.accountId)?.provider;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const kind = Form.useWatch("kind", form);
  const action = Form.useWatch("action", form);
  const cycle = Form.useWatch(["schedule", "cycle"], form);
  const protocol = Form.useWatch(["monitor", "protocol"], form);
  const required = [{ required: true }];
  function options(entries: string[][]) {
    return entries.map(([value, cn, en]) => ({ value, label: label(cn, en) }));
  }
  const defaults = {
    kind: "schedule",
    action: "update",
    schedule: { cycle: "once", at: "", day: 1, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC" },
    monitor: { interval: 60, timeout: 5, protocol: "https", port: 443, failureThreshold: 3, recoveryThreshold: 2, cooldown: 120, healthyLimit: 0 },
  };
  async function save(v: Definition) {
    if (!target || busy) return;
    setError("");
    setBusy(true);
    try {
      const d = { ...v, target };
      d.backupProxied = !!(provider === "cloudflare" && d.kind === "failover" && d.action === "replace" && v.backupProxied);
      if (d.schedule && (provider !== "cloudflare" || d.kind !== "schedule" || d.action !== "update")) d.schedule = { ...d.schedule, proxied: undefined };
      if (d.kind === "schedule" && d.schedule.cycle === "once") {
        const at = new Date(d.schedule.at);
        if (!Number.isFinite(at.valueOf()) || at <= new Date()) throw new Error(label("请选择未来的执行时间", "Choose a future execution time"));
        d.schedule = { ...d.schedule, at: at.toISOString() };
      }
      if (d.kind === "failover" && d.action !== "standby") {
        const ports: Record<string, number> = { http: 80, https: 443, ping: 0 };
        d.monitor = { ...d.monitor, port: ports[d.monitor.protocol] ?? d.monitor.port };
      }
      if (task) await dnsRequest(base + "/" + task.id, "PUT", { version: task.version, definition: d });
      else await dnsRequest(base, "POST", d);
      onSaved();
    } catch (e) {
      setError(unwrapErrMsg(e));
    } finally {
      setBusy(false);
    }
  }
  const initial = task ? { ...task.definition } : defaults;
  if (task?.definition.kind === "schedule" && task.definition.schedule.cycle === "once") {
    const at = new Date(task.definition.schedule.at);
    initial.schedule = { ...task.definition.schedule, at: new Date(at.valueOf() - at.getTimezoneOffset() * 60000).toISOString().slice(0, 16) };
  }
  return (
    <Modal
      open
      width={650}
      title={task ? label("编辑任务", "Edit task") : label("新建任务", "New task")}
      okText={label("保存草稿", "Save draft")}
      okButtonProps={{ disabled: !target }}
      confirmLoading={busy}
      onOk={() => form.submit()}
      onCancel={() => {
        if (!busy) onClose();
      }}
    >
      {(error || channels?.error || accounts?.error) && <Alert type="error" showIcon title={error || channels?.error || accounts?.error} />}
      <Form form={form} layout="vertical" disabled={busy} initialValues={initial} onFinish={save}>
        <Form.Item name="name" label={label("任务名称", "Task name")} rules={required}>
          <Input maxLength={128} />
        </Form.Item>
        {task ? (
          <Typography.Paragraph>{[target?.name, target?.type, target?.zoneId].join(" · ")}</Typography.Paragraph>
        ) : (
          <TargetPicker
            label={label}
            onChange={(t, primary) => {
              setTarget(t);
              form.setFieldValue("primary", primary);
            }}
          />
        )}
        <Form.Item name="kind" label={label("任务类型", "Task type")} rules={required}>
          <Select
            options={options([
              ["schedule", "定时变更", "Schedule"],
              ["failover", "健康监控与容灾", "Health monitor and failover"],
            ])}
            onChange={(k) => form.setFieldValue("action", k === "schedule" ? "update" : "observe")}
          />
        </Form.Item>
        <Form.Item name="action" label={label("操作", "Action")} rules={required}>
          <Select
            options={options(
              kind === "failover"
                ? [
                    ["observe", "仅监控", "Monitor only"],
                    ["replace", "切换记录值", "Replace record value"],
                    ["disable", "故障时暂停记录", "Disable unhealthy record"],
                    ["standby", "按健康记录数开启备用记录", "Enable standby by healthy peer count"],
                  ]
                : [
                    ["update", "修改记录值", "Update record value"],
                    ["enable", "启用记录", "Enable record"],
                    ["disable", "暂停记录", "Disable record"],
                    ["delete", "删除记录", "Delete record"],
                  ]
            )}
            onChange={(v) => {
              if (v === "delete") {
                form.setFieldValue(["schedule", "cycle"], "once");
                form.setFieldValue(["schedule", "at"], "");
              }
            }}
          />
        </Form.Item>
        {kind === "schedule" && (
          <>
            {action === "update" && (
              <Form.Item name="value" label={label("目标记录值", "New record value")} rules={required}>
                <Input />
              </Form.Item>
            )}
            {action === "update" && provider === "cloudflare" && (
              <Form.Item
                name={["schedule", "proxied"]}
                getValueProps={(v) => ({ value: v == null ? undefined : v ? 1 : 0 })}
                getValueFromEvent={(v) => (v == null ? undefined : v === 1)}
                label={label("Cloudflare 代理模式", "Cloudflare proxy mode")}
              >
                <Select
                  allowClear
                  placeholder={label("保留原设置", "Keep current setting")}
                  getPopupContainer={(n) => n.parentElement ?? document.body}
                  options={[
                    { value: 1, label: label("启用代理", "Proxied") },
                    { value: 0, label: label("仅 DNS", "DNS only") },
                  ]}
                />
              </Form.Item>
            )}
            {action === "delete" && (
              <Alert
                showIcon
                type="warning"
                title={label(
                  "删除会移除 DNS 记录。恢复该记录需要在服务商侧核对全部属性。",
                  "Deletion removes the DNS record. Restoring it requires checking its full provider settings."
                )}
              />
            )}
            <Form.Item name={["schedule", "cycle"]} label={label("周期", "Frequency")} rules={required}>
              <Select
                disabled={action === "delete"}
                options={options([
                  ["once", "一次", "Once"],
                  ["daily", "每天", "Daily"],
                  ["weekly", "每周", "Weekly"],
                  ["monthly", "每月", "Monthly"],
                ])}
                onChange={() => form.setFieldValue(["schedule", "at"], "")}
              />
            </Form.Item>
            <Space wrap>
              <Form.Item
                name={["schedule", "at"]}
                label={cycle === "once" ? label("执行时间（本地时区）", "Run at (local time)") : label("执行时间", "Time of day")}
                rules={required}
              >
                <Input type={cycle === "once" ? "datetime-local" : "time"} />
              </Form.Item>
              {cycle !== "once" && (
                <Form.Item name={["schedule", "timezone"]} label={label("时区", "Time zone")} rules={required}>
                  <Input placeholder="Asia/Shanghai" />
                </Form.Item>
              )}
              {cycle === "weekly" && (
                <Form.Item name={["schedule", "day"]} label={label("星期", "Weekday")} rules={required}>
                  <Select
                    style={{ minWidth: 120 }}
                    options={Array.from({ length: 7 }, (_, i) => ({
                      value: i,
                      label: new Date(Date.UTC(2023, 0, 1 + i)).toLocaleDateString(undefined, { timeZone: "UTC", weekday: "long" }),
                    }))}
                  />
                </Form.Item>
              )}
              {cycle === "monthly" && (
                <Form.Item name={["schedule", "day"]} label={label("每月第几天", "Day of month")} rules={required}>
                  <InputNumber precision={0} min={1} max={31} />
                </Form.Item>
              )}
            </Space>
          </>
        )}
        {kind === "failover" && (
          <>
            {action !== "standby" && (
              <>
                <Form.Item name="primary" label={label("主记录值", "Primary record value")} rules={required}>
                  <Input />
                </Form.Item>
                {target?.type === "CNAME" && (
                  <Form.Item name={["monitor", "origin"]} label={label("已授权的探测 IP", "Authorized origin IP")} rules={required}>
                    <Input />
                  </Form.Item>
                )}
                {action === "replace" && provider === "cloudflare" && (
                  <Form.Item name="backupProxied" valuePropName="checked">
                    <Checkbox>
                      {label("故障时开启代理，恢复时还原 DNS 模式与 TTL", "Proxy the backup, then restore DNS-only mode and TTL on recovery")}
                    </Checkbox>
                  </Form.Item>
                )}
                {action === "replace" && (
                  <Form.Item name="backup" label={label("备用记录值", "Backup value")} rules={required}>
                    <Input />
                  </Form.Item>
                )}
                <Typography.Paragraph type="secondary">
                  {label("探测地址须在服务端 CERTIMATE_DNS_PROBE_IPS 中列出。", "List each probe address in CERTIMATE_DNS_PROBE_IPS on the server.")}
                </Typography.Paragraph>
                <Space wrap>
                  <Form.Item name={["monitor", "protocol"]} label={label("探测协议", "Protocol")} rules={required}>
                    <Select style={{ minWidth: 100 }} options={["https", "http", "tcp", "ping"].map((value) => ({ value, label: value.toUpperCase() }))} />
                  </Form.Item>
                  {protocol === "tcp" && (
                    <Form.Item name={["monitor", "port"]} label={label("端口", "Port")} rules={required}>
                      <Select options={[80, 443].map((value) => ({ value, label: String(value) }))} />
                    </Form.Item>
                  )}
                  <Form.Item name={["monitor", "timeout"]} label={label("超时（秒）", "Timeout (s)")} rules={required}>
                    <InputNumber min={1} max={15} precision={0} />
                  </Form.Item>
                </Space>
              </>
            )}
            {action === "standby" && (
              <Form.Item
                name={["monitor", "healthyLimit"]}
                label={label("当健康记录数小于或等于此值时启用", "Enable when the healthy peer count is at most")}
                rules={required}
              >
                <InputNumber min={0} max={100} precision={0} />
              </Form.Item>
            )}
            <Space wrap>
              {(
                [
                  ["interval", label("间隔（秒）", "Interval (s)"), 5, 86400],
                  ["failureThreshold", label("连续失败次数", "Consecutive failures"), 1, 100],
                  ["recoveryThreshold", label("连续恢复次数", "Consecutive recoveries"), 1, 100],
                  ["cooldown", label("切换冷却（秒）", "Cooldown (s)"), 0, 604800],
                ] as const
              ).map(([field, title, min, max]) => (
                <Form.Item key={field} name={["monitor", field]} label={title} rules={required}>
                  <InputNumber min={min} max={max} precision={0} />
                </Form.Item>
              ))}
            </Space>
          </>
        )}
        <Form.Item name="notifyAccessId" label={label("通知账户", "Notification account")}>
          <Select allowClear options={channels?.data?.map((a) => ({ value: a.id, label: a.name }))} />
        </Form.Item>
      </Form>
    </Modal>
  );
}
