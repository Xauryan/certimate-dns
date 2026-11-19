import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { Alert, App, Button, Checkbox, Descriptions, Drawer, Form, Input, InputNumber, Popconfirm, Select, Space, Table, Tabs, Tag, Typography } from "antd";

import { dnsRequest } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";

type Props = { provider: string; access: string; zone: { id: string; name: string }; onApplied?: () => void };
type Spec = {
  name: string;
  source: string;
  cdn: string;
  family: string;
  sourceLine: string;
  targetLine: string;
  ttl: number;
  ranks: number[];
  replaceCname: boolean;
};
type Task = { id: string; spec: Spec; interval: number; enabled: boolean; lastRun: number; due: number; status: string };
type Change = { action: string; id?: string; type: string; before?: string; after?: string; previousTtl?: number };
type Plan = { name: string; type: string; line: string; ttl: number; desired: string[]; changes: Change[]; digest: string };
type Run = { id: number; started: number; task: string; actor: string; status: string; snapshot: string };
const lines = ["DEF", "CT", "CU", "CM"];
const carrierProviders = ["aliyun", "tencentcloud", "huaweicloud", "westcn", "dnsla", "volcengine", "baiducloud", "jdcloud", "bt", "qingcloud"];
const defaultProviders = ["cloudflare", "aws", "namesilo", "henet", "powerdns", "spaceship", "aliyunesa", "tencenteo", "dnsmgr", "goedge"];
const sources = ["xingpingcn", "hostmonit", "wetest"];
const networks = ["cloudflare", "cloudfront", "gcore", "edgeone"];
const options = (values: string[]) => values.map((value) => ({ value, label: value }));
const date = (value: number) => (value ? new Date(value * 1000).toLocaleString() : "—");

function PlanView({ plan, zh }: { plan: Plan; zh: boolean }) {
  const opLabel = (action: string) => (zh ? ({ create: "新增", update: "修改", delete: "删除" }[action] ?? action) : action);
  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      <Descriptions
        size="small"
        column={1}
        bordered
        items={[
          { key: "name", label: zh ? "记录" : "Record", children: plan.name + " · " + plan.type + " · " + plan.line },
          { key: "desired", label: zh ? "目标地址" : "Desired addresses", children: plan.desired.join(", ") },
          { key: "ttl", label: "TTL", children: plan.ttl },
        ]}
      />
      {plan.changes.length > 0 ? (
        <Table
          size="small"
          pagination={false}
          dataSource={plan.changes}
          rowKey={(r) => r.id || r.after!}
          columns={[
            { title: zh ? "操作" : "Operation", dataIndex: "action", render: opLabel },
            { title: zh ? "类型" : "Type", dataIndex: "type" },
            { title: zh ? "原记录" : "Before", render: (_, r) => (r.before ? r.before + " (TTL " + r.previousTtl + ")" : "—") },
            { title: zh ? "目标记录" : "After", render: (_, r) => r.after || "—" },
          ]}
        />
      ) : (
        <Tag color="green">{zh ? "记录已匹配" : "Records match"}</Tag>
      )}
    </Space>
  );
}

function Panel({ provider, access, zone, onApplied, zh, initialTab }: Props & { zh: boolean; initialTab: string }) {
  const { message } = App.useApp();
  const label = (cn: string, en: string) => (zh ? cn : en);
  const lineLabel = (value: string) =>
    ({ DEF: label("默认", "Default"), CT: label("电信", "China Telecom"), CU: label("联通", "China Unicom"), CM: label("移动", "China Mobile") })[value] ??
    value;
  const base = "/api/dns/" + [provider, access].map(encodeURIComponent).join("/") + "/zones/" + encodeURIComponent(zone.id) + "/optimize";
  const initial = (): Spec => ({
    name: zone.name,
    source: "xingpingcn",
    cdn: "cloudflare",
    family: "v4",
    sourceLine: "CT",
    targetLine: "DEF",
    ranks: [],
    ttl: 600,
    replaceCname: false,
  });
  const [spec, setSpec] = useState(initial);
  const [interval, setInterval] = useState(30);
  const [task, setTask] = useState<Task>();
  const [tasks, setTasks] = useState<Task[]>([]);
  const [history, setHistory] = useState<Run[]>([]);
  const [feed, setFeed] = useState<Record<string, string[]>>();
  const [quota, setQuota] = useState<{ unlimited: boolean; remaining: number }>();
  const [plan, setPlan] = useState<Plan>();
  const [tab, setTab] = useState(initialTab);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);
  const working = useRef(false);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  useEffect(() => {
    let live = true;
    Promise.all([dnsRequest<Task[]>(base + "/tasks"), dnsRequest<Run[]>(base + "/history")]).then(
      ([rows, runs]) => {
        if (live) {
          setTasks(rows);
          setHistory(runs);
        }
      },
      (err) => {
        if (live) setError(unwrapErrMsg(err));
      }
    );
    return () => {
      live = false;
    };
  }, [base, revision]);
  const refresh = () => setRevision((r) => r + 1);
  async function run(fn: () => Promise<void>) {
    if (working.current) return;
    working.current = true;
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (err) {
      if (mounted.current) {
        setError(unwrapErrMsg(err));
        setPlan(undefined);
      }
    } finally {
      working.current = false;
      if (mounted.current) setBusy(false);
    }
  }
  function update(patch: Partial<Spec>) {
    setSpec({ ...spec, ...patch });
    setPlan(undefined);
    setError("");
  }
  function edit(row?: Task) {
    setTask(row);
    setSpec(row?.spec ?? initial());
    setInterval(row?.interval ?? 30);
    setPlan(undefined);
    setFeed(undefined);
    setQuota(undefined);
    setError("");
    setTab("settings");
  }
  function candidates() {
    return run(async () => {
      const q = new URLSearchParams({ source: spec.source, cdn: spec.cdn, family: spec.family });
      const data = await dnsRequest<Record<string, string[]>>(base + "/candidates?" + q);
      setFeed(data);
      setPlan(undefined);
    });
  }
  function preview() {
    return run(async () => setPlan(await dnsRequest<Plan>(base + "/preview", "POST", { spec })));
  }
  function save() {
    return run(async () => {
      const id = await dnsRequest<string>(base + "/tasks" + (task ? "/" + task.id : ""), task ? "PUT" : "POST", { spec, interval });
      setTask({ id, spec, interval, enabled: false, lastRun: 0, due: 0, status: "" });
      refresh();
      message.success(label("已保存停用的任务", "Saved disabled schedule"));
    });
  }
  function apply() {
    return run(async () => {
      if (!plan) return;
      try {
        if (currentSaved && task) {
          await dnsRequest(base + "/tasks/" + task.id + "/run", "POST", { digest: plan.digest });
        } else {
          await dnsRequest(base + "/apply", "POST", { spec, digest: plan.digest });
        }
        message.success(label("已回读并核对解析", "Verified DNS records"));
      } finally {
        setPlan(undefined);
        refresh();
        onApplied?.();
      }
    });
  }
  function toggle(row: Task, enabled: boolean) {
    return run(async () => {
      await dnsRequest(base + "/tasks/" + row.id + "/state", "POST", { enabled, digest: plan?.digest });
      setPlan(undefined);
      setTask(undefined);
      setTab("tasks");
      refresh();
    });
  }
  const lockSettings = busy || !!task?.enabled;
  const currentSaved = task && JSON.stringify(task.spec) === JSON.stringify(spec) && task.interval === interval;
  const lineOptions = lines.map((value) => ({ value, label: lineLabel(value) }));
  const editor = (
    <Space direction="vertical" style={{ width: "100%" }}>
      <Form layout="vertical" disabled={lockSettings}>
        <Form.Item label={label("完整记录名", "Fully qualified record name")}>
          <Input value={spec.name} onChange={(e) => update({ name: e.target.value })} />
        </Form.Item>
        <Space wrap align="start">
          <Form.Item label={label("候选数据源", "Ranked address feed")}>
            <Select
              value={spec.source}
              style={{ width: 145 }}
              options={options(sources)}
              onChange={(source) => {
                setFeed(undefined);
                setQuota(undefined);
                update({ source, cdn: "cloudflare", family: "v4", sourceLine: "CT", ranks: [] });
              }}
            />
          </Form.Item>
          <Form.Item label="CDN">
            <Select
              value={spec.cdn}
              style={{ width: 145 }}
              options={options(spec.source === "wetest" ? networks : ["cloudflare"])}
              onChange={(cdn) => {
                setFeed(undefined);
                update({ cdn, ranks: [] });
              }}
            />
          </Form.Item>
          <Form.Item label={label("地址族", "Address family")}>
            <Select
              value={spec.family}
              options={options(spec.source === "xingpingcn" ? ["v4"] : ["v4", "v6"])}
              onChange={(family) => {
                setFeed(undefined);
                update({ family, ranks: [] });
              }}
            />
          </Form.Item>
        </Space>
        <Space>
          <Button onClick={() => run(async () => setQuota(await dnsRequest(base + "/quota?" + new URLSearchParams({ source: spec.source }))))}>
            {label("查询数据源额度", "Check feed quota")}
          </Button>
          {quota && <span>{quota.unlimited ? label("不限次数", "Unlimited") : label("剩余次数", "Remaining requests") + " · " + quota.remaining}</span>}
        </Space>
        {spec.source !== "xingpingcn" && (
          <Typography.Paragraph type="secondary">
            {label("服务端密钥环境变量", "Server API key environment variable")} <code>{"CERTIMATE_DNS_" + spec.source.toUpperCase() + "_KEY"}</code>
          </Typography.Paragraph>
        )}
        <Space wrap align="start">
          <Form.Item label={label("候选线路", "Feed carrier")}>
            <Select
              style={{ width: 155 }}
              value={spec.sourceLine}
              options={lineOptions.filter(({ value }) => spec.source !== "xingpingcn" || value !== "DEF")}
              onChange={(sourceLine) => update({ sourceLine, ranks: [] })}
            />
          </Form.Item>
          <Form.Item label={label("写入 DNS 线路", "Destination DNS line")}>
            <Select
              style={{ width: 155 }}
              value={spec.targetLine}
              options={lineOptions.filter(({ value }) => value === "DEF" || carrierProviders.includes(provider))}
              onChange={(targetLine) => update({ targetLine })}
            />
          </Form.Item>
        </Space>
        <Form.Item
          label={label("选择候选排名", "Selected feed ranks")}
          extra={label("定时任务每次使用所选排名的最新地址。", "Scheduled runs use the current address at each selected rank.")}
        >
          <Space.Compact style={{ width: "100%" }}>
            <Select
              mode="multiple"
              allowClear
              style={{ flex: 1 }}
              value={spec.ranks}
              onChange={(ranks: number[]) => update({ ranks: [...ranks].sort((a, b) => a - b) })}
              options={(feed?.[spec.sourceLine] ?? []).map((ip, i) => ({ value: i + 1, label: "#" + (i + 1) + " · " + ip }))}
            />
            <Button onClick={candidates}>{label("获取候选", "Load candidates")}</Button>
          </Space.Compact>
        </Form.Item>
        <Space wrap align="start">
          <Form.Item label="TTL">
            <InputNumber value={spec.ttl} min={1} max={604800} precision={0} onChange={(ttl) => update({ ttl: ttl ?? 0 })} />
          </Form.Item>
          <Form.Item label={label("更新间隔（分钟）", "Interval (minutes)")}>
            <InputNumber value={interval} min={10} max={10080} precision={0} onChange={(v) => setInterval(v ?? 0)} />
          </Form.Item>
        </Space>
        <Checkbox checked={spec.replaceCname} onChange={(e) => update({ replaceCname: e.target.checked })}>
          {label("允许删除所选线路的冲突 CNAME", "Allow removal of a conflicting CNAME on the selected line")}
        </Checkbox>
      </Form>
      <Space wrap>
        <Button type="primary" disabled={busy || !spec.ranks.length} onClick={preview}>
          {label("预览 DNS 变更", "Preview DNS changes")}
        </Button>
        <Button disabled={lockSettings || !spec.ranks.length} onClick={save}>
          {label("保存为停用任务", "Save disabled schedule")}
        </Button>
        {task && (
          <Button disabled={busy} onClick={() => edit()}>
            {label("新建任务", "New schedule")}
          </Button>
        )}
      </Space>
      {plan && (
        <>
          <PlanView plan={plan} zh={zh} />
          <Space wrap>
            {(plan.changes.length > 0 || currentSaved) && (
              <Popconfirm title={label("执行上方 DNS 变更？", "Apply these DNS changes?")} onConfirm={apply}>
                <Button disabled={busy} danger>
                  {label("执行变更", "Apply changes")}
                </Button>
              </Popconfirm>
            )}
            {currentSaved && !task.enabled && (
              <Popconfirm
                title={label("按所选排名定时更新此 DNS 线路？", "Continuously update this DNS line using the selected ranks?")}
                onConfirm={() => toggle(task, true)}
              >
                <Button disabled={busy}>{label("启用定时更新", "Enable schedule")}</Button>
              </Popconfirm>
            )}
          </Space>
        </>
      )}
    </Space>
  );
  const schedules = (
    <Table
      size="small"
      rowKey="id"
      dataSource={tasks}
      pagination={{ pageSize: 10 }}
      scroll={{ x: 680 }}
      columns={[
        {
          title: label("记录", "Record"),
          render: (_, r) => (
            <Space direction="vertical" size={0}>
              <span>
                {r.spec.name} · {r.spec.family}
              </span>
              <small>
                {r.spec.source} · {lineLabel(r.spec.sourceLine)} → {lineLabel(r.spec.targetLine)} · {r.interval} min
              </small>
            </Space>
          ),
        },
        {
          title: label("状态", "Status"),
          render: (_, r) => (
            <Space direction="vertical" size={0}>
              <Tag color={r.enabled ? "green" : undefined}>{r.enabled ? label("启用", "Enabled") : label("停用", "Disabled")}</Tag>
              {r.status}
            </Space>
          ),
        },
        {
          title: label("最近 / 下次执行", "Last / next run"),
          render: (_, r) => (
            <>
              {date(r.lastRun)}
              <br />
              {date(r.due)}
            </>
          ),
        },
        {
          title: label("操作", "Actions"),
          render: (_, r) => (
            <Space wrap>
              <Button disabled={busy} size="small" onClick={() => edit(r)}>
                {label("查看 / 编辑", "View / edit")}
              </Button>
              {r.enabled ? (
                <Button disabled={busy} size="small" onClick={() => toggle(r, false)}>
                  {label("暂停", "Pause")}
                </Button>
              ) : (
                <Popconfirm
                  title={label("删除此任务？", "Delete this schedule?")}
                  onConfirm={() =>
                    run(async () => {
                      await dnsRequest(base + "/tasks/" + r.id, "DELETE");
                      if (task?.id === r.id) edit();
                      setTab("tasks");
                      refresh();
                    })
                  }
                >
                  <Button disabled={busy} danger size="small">
                    {label("删除", "Delete")}
                  </Button>
                </Popconfirm>
              )}
            </Space>
          ),
        },
      ]}
    />
  );
  const audit = (
    <Table
      size="small"
      rowKey="id"
      dataSource={history}
      pagination={{ pageSize: 10 }}
      expandable={{ expandedRowRender: (r) => <PlanView zh={zh} plan={JSON.parse(r.snapshot) as Plan} /> }}
      columns={[
        { title: label("执行时间", "Started"), dataIndex: "started", render: date },
        { title: label("操作者", "Actor"), dataIndex: "actor" },
        { title: label("结果", "Result"), dataIndex: "status" },
      ]}
    />
  );
  return (
    <>
      {error && <Alert type="error" showIcon title={error} />}
      <Tabs
        activeKey={tab}
        onChange={setTab}
        items={[
          { key: "settings", label: label("变更计划", "Change plan"), children: editor },
          { key: "tasks", label: label("定时任务", "Schedules"), children: schedules },
          { key: "history", label: label("执行记录", "Run history"), children: audit },
        ]}
      />
    </>
  );
}

export default function DNSOptimize(props: Props) {
  const { i18n } = useTranslation();
  const [open, setOpen] = useState(false);
  const [params, setParams] = useSearchParams();
  const showHistory = params.get("optimizer") === "history";
  const initialTab = showHistory ? "history" : "settings";
  const visible = open || showHistory;
  const close = () => {
    setOpen(false);
    if (showHistory) {
      const next = new URLSearchParams(params);
      next.delete("optimizer");
      setParams(next, { replace: true });
    }
  };
  const zh = i18n.language.toLowerCase().startsWith("zh");
  const title = zh ? "CDN 优选 IP" : "Ranked CDN addresses";
  if (![...carrierProviders, ...defaultProviders].includes(props.provider)) return null;
  return (
    <>
      <Button onClick={() => setOpen(true)}>{title}</Button>
      <Drawer title={title + " · " + props.zone.name} open={visible} onClose={close} size="large" destroyOnHidden>
        {visible && <Panel key={[props.provider, props.access, props.zone.id, initialTab].join("/")} {...props} zh={zh} initialTab={initialTab} />}
      </Drawer>
    </>
  );
}
