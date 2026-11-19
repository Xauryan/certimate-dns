import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { Alert, App, Button, Descriptions, Drawer, Space, Table, Tag, Typography } from "antd";

import { dnsRequest } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";
import Editor from "./Editor";
import { type Label, type Run, type Task, base, time } from "./types";

interface List<T> {
  items: T[];
  total: number;
}

function History({ id, label, close }: { id: string; label: Label; close: () => void }) {
  const [task, setTask] = useState<Task>();
  const [rows, setRows] = useState<List<Run>>();
  const [page, setPage] = useState(1);
  const [error, setError] = useState("");
  useEffect(() => {
    let current = true;
    const url = base + "/" + encodeURIComponent(id);
    Promise.all([dnsRequest<Task>(url), dnsRequest<List<Run>>(url + "/history?page=" + page)]).then(
      ([t, rs]) => {
        if (current) {
          setTask(t);
          setRows(rs);
          setError("");
        }
      },
      (e) => {
        if (current) setError(unwrapErrMsg(e));
      }
    );
    return () => {
      current = false;
    };
  }, [id, page]);
  return (
    <Drawer open title={task?.definition.name ?? label("任务详情", "Task details")} size="large" onClose={close}>
      {error && <Alert type="error" title={error} />}
      {task && (
        <Descriptions
          size="small"
          bordered
          column={2}
          items={[
            { key: "target", label: label("记录", "Record"), children: task.definition.target.name + " · " + task.definition.target.type, span: 2 },
            { key: "state", label: label("状态", "State"), children: task.state },
            { key: "position", label: label("当前主备", "Position"), children: task.position },
            { key: "fail", label: label("连续失败", "Consecutive failures"), children: task.failures },
            { key: "recover", label: label("连续恢复", "Consecutive recoveries"), children: task.recoveries },
            { key: "last", label: label("最近执行", "Last run"), children: time(task.lastAt) },
            { key: "next", label: label("下次执行", "Next run"), children: time(task.nextAt) },
            { key: "switch", label: label("上次切换", "Last transition"), children: time(task.switchAt) },
          ]}
        />
      )}
      <Typography.Title level={5}>{label("执行与变更记录", "Run and change history")}</Typography.Title>
      <Table<Run>
        size="small"
        rowKey="id"
        dataSource={rows?.items}
        scroll={{ x: 550 }}
        pagination={{ pageSize: 20, showSizeChanger: false, current: page, total: rows?.total, onChange: setPage }}
        expandable={{
          rowExpandable: (r) => !!r.before,
          expandedRowRender: (r) => (
            <Space direction="vertical">
              <span>{label("变更前", "Before")}</span>
              <code className="break-all">{r.before}</code>
              <span>{label("预期变更后", "Expected after")}</span>
              <code className="break-all">{r.after}</code>
            </Space>
          ),
        }}
        columns={[
          { title: label("时间", "Started"), dataIndex: "started", render: time },
          { title: label("操作", "Action"), dataIndex: "action" },
          { title: label("结果", "Outcome"), dataIndex: "outcome" },
          { title: label("操作者", "Actor"), dataIndex: "actor" },
          { title: label("通知", "Notification"), dataIndex: "notification" },
        ]}
      />
    </Drawer>
  );
}

export default function DNSAutomation() {
  const { i18n } = useTranslation();
  const { modal, message } = App.useApp();
  const label: Label = (cn, en) => (i18n.language.toLowerCase().startsWith("zh") ? cn : en);
  const [params, setParams] = useSearchParams();
  const [rows, setRows] = useState<List<Task>>();
  const [heartbeat, setHeartbeat] = useState(0);
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [editor, setEditor] = useState<Task | "new">();
  const [selection, setSelection] = useState<React.Key[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const history = params.get("task");
  const refresh = () => setRevision((v) => v + 1);
  const openHistory = (id?: string) =>
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (id) next.set("task", id);
      else next.delete("task");
      return next;
    });
  useEffect(() => {
    let active = true;
    Promise.all([dnsRequest<List<Task>>(base + "?page=" + page), dnsRequest<{ lastTick: number }>(base + "/heartbeat")]).then(
      ([rs, h]) => {
        if (active) {
          setRows(rs);
          setHeartbeat(h.lastTick);
          setError("");
        }
      },
      (e) => {
        if (active) setError(unwrapErrMsg(e));
      }
    );
    return () => {
      active = false;
    };
  }, [page, revision]);
  const names: Record<string, string> = {
    activate: label("启用", "Activate"),
    pause: label("暂停", "Pause"),
    run: label("立即执行", "Run now"),
    rollback: label("回滚上次变更", "Roll back last change"),
    reconcile: label("核对服务商状态", "Reconcile provider state"),
    archive: label("归档", "Archive"),
    active: label("运行中", "Active"),
    paused: label("已暂停", "Paused"),
    review: label("待核对", "Needs review"),
    completed: label("已完成", "Completed"),
    draft: label("草稿", "Draft"),
    observe: label("仅监控", "Monitor only"),
    replace: label("切换主备", "Replace"),
    update: label("修改记录值", "Update value"),
    enable: label("启用记录", "Enable record"),
    disable: label("暂停记录", "Disable record"),
    standby: label("条件启用", "Conditional standby"),
    delete: label("删除记录", "Delete record"),
  };
  const allowed = (task: Task, action: string) =>
    ({
      activate: ["paused", "draft"].includes(task.state),
      pause: task.state === "active",
      run: task.state === "active",
      rollback: ["paused", "completed"].includes(task.state) && task.definition.action !== "delete" && task.definition.action !== "observe",
      reconcile: task.state === "review",
      archive: task.state !== "active",
    })[action];
  function control(tasks: Task[], action: string) {
    modal.confirm({
      title: names[action] + " · " + tasks.length,
      content: tasks.map((t) => (
        <div key={t.id}>
          {t.definition.name} · {t.definition.target.name}
        </div>
      )),
      okText: names[action],
      okButtonProps: { danger: ["run", "rollback", "archive"].includes(action) },
      onOk: async () => {
        setBusy(true);
        const errors: string[] = [];
        for (const task of tasks) {
          try {
            await dnsRequest(base + "/" + task.id + "/" + action, "POST", { version: task.version });
          } catch (e) {
            errors.push(task.definition.name + " · " + unwrapErrMsg(e));
          }
        }
        setBusy(false);
        setSelection([]);
        refresh();
        if (errors.length)
          modal.error({ title: label("部分操作未完成", "Operations requiring attention"), content: errors.map((e, i) => <div key={i}>{e}</div>) });
        else message.success(names[action]);
      },
    });
  }
  const selected = rows?.items.filter((r) => selection.includes(r.id)) ?? [];
  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <Typography.Title level={3} style={{ margin: 0 }}>
        {label("DNS 定时任务与容灾", "DNS schedules and failover")}
      </Typography.Title>
      {error && <Alert type="error" showIcon title={error} />}
      <Space wrap>
        <Button type="primary" onClick={() => setEditor("new")}>
          {label("新建任务", "New task")}
        </Button>
        <Button onClick={refresh}>{label("刷新", "Refresh")}</Button>
        <Typography.Text type="secondary">
          {label("调度器心跳", "Scheduler heartbeat")} · {time(heartbeat)}
        </Typography.Text>
      </Space>
      {selected.length > 0 && (
        <Space wrap>
          {["activate", "pause", "archive"].map((a) => (
            <Button key={a} disabled={busy || !selected.every((t) => allowed(t, a))} onClick={() => control(selected, a)}>
              {names[a]} ({selected.length})
            </Button>
          ))}
        </Space>
      )}
      <Table<Task>
        rowKey="id"
        loading={!rows && !error}
        dataSource={rows?.items ?? []}
        rowSelection={{ selectedRowKeys: selection, onChange: setSelection }}
        scroll={{ x: 950 }}
        pagination={{
          pageSize: 20,
          current: page,
          total: rows?.total,
          showSizeChanger: false,
          onChange: (p) => {
            setSelection([]);
            setPage(p);
          },
        }}
        columns={[
          {
            title: label("任务与记录", "Task and record"),
            render: (_, t) => (
              <Space direction="vertical" size={0}>
                <Button size="small" type="link" onClick={() => openHistory(t.id)}>
                  {t.definition.name}
                </Button>
                <span>
                  {t.definition.target.type} · {t.definition.target.name}
                </span>
              </Space>
            ),
          },
          { title: label("操作", "Operation"), render: (_, t) => names[t.definition.action] },
          {
            title: label("状态", "Status"),
            render: (_, t) => <Tag color={t.state === "active" ? "green" : t.state === "review" ? "orange" : undefined}>{names[t.state] ?? t.state}</Tag>,
          },
          { title: label("下次执行", "Next run"), dataIndex: "nextAt", render: time },
          {
            title: label("管理", "Manage"),
            render: (_, t) => (
              <Space wrap>
                {["draft", "paused", "completed"].includes(t.state) && (
                  <Button size="small" disabled={busy} onClick={() => setEditor(t)}>
                    {label("编辑", "Edit")}
                  </Button>
                )}
                {["activate", "pause", "run", "rollback", "reconcile", "archive"]
                  .filter((a) => allowed(t, a))
                  .map((a) => (
                    <Button key={a} size="small" disabled={busy} onClick={() => control([t], a)}>
                      {names[a]}
                    </Button>
                  ))}
              </Space>
            ),
          },
        ]}
      />
      {editor && (
        <Editor
          key={editor === "new" ? "new" : editor.id}
          task={editor === "new" ? undefined : editor}
          label={label}
          onClose={() => setEditor(undefined)}
          onSaved={() => {
            setEditor(undefined);
            setPage(1);
            refresh();
          }}
        />
      )}
      {history && <History key={history} id={history} label={label} close={() => openHistory()} />}
    </div>
  );
}
