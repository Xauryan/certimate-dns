import { useState } from "react";
import { Alert, Button, Card, Space, Table } from "antd";

import { type Page, dnsRequest } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";

import { type Features, type Plan, type Summary, stateLabel, useData, useLabel } from "./model";
import { ItemTable } from "./ReviewPlans";

function Detail({ path, state, canWrite, refresh }: { path: string; state: string; canWrite: boolean; refresh: () => void }) {
  const l = useLabel();
  const detail = useData<Plan>(path);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [reconciled, setReconciled] = useState<Plan>();
  const plan = reconciled ?? detail?.data;
  async function reconcile() {
    setBusy(true);
    setError("");
    try {
      setReconciled(await dnsRequest<Plan>(path + "/reconcile", "POST"));
      refresh();
    } catch (e) {
      setError(unwrapErrMsg(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Space orientation="vertical" style={{ width: "100%" }}>
      {(error || detail?.error) && <Alert type="error" title={error || detail?.error} showIcon />}
      {plan && <ItemTable plan={plan} />}
      {canWrite && ["uncertain", "applying"].includes(plan?.state ?? state) && (
        <Button loading={busy} onClick={reconcile}>
          {l("与服务商记录核对", "Reconcile with provider records")}
        </Button>
      )}
    </Space>
  );
}

export default function History({ path, canWrite, features, revision }: { path: string; canWrite: boolean; features?: Features; revision: number }) {
  const l = useLabel();
  const [page, setPage] = useState(1);
  const [logPage, setLogPage] = useState(1);
  const [reload, setReload] = useState(0);
  const data = useData<{ items: Summary[]; total: number }>(path + "/history?page=" + page, revision + reload);
  const logs = useData<Page<{ time: string; action: string }>>(features?.logs ? path + "/logs?page=" + logPage : undefined, revision + reload);
  const refresh = () => setReload((v) => v + 1);
  return (
    <Space orientation="vertical" style={{ width: "100%" }}>
      <Button onClick={refresh}>{l("刷新历史", "Refresh history")}</Button>
      {data?.error && <Alert type="error" title={data.error} showIcon />}
      <Table
        size="small"
        rowKey="id"
        loading={!data}
        dataSource={data?.data?.items ?? []}
        pagination={{ current: page, pageSize: 20, total: data?.data?.total ?? 0, showSizeChanger: false, onChange: setPage }}
        columns={[
          { title: l("创建时间", "Created"), dataIndex: "created", render: (time: number) => new Date(time * 1000).toLocaleString() },
          { title: l("操作者", "Operator"), dataIndex: "actor" },
          { title: l("状态", "Status"), dataIndex: "state", render: (s: string) => stateLabel(s, l) },
        ]}
        expandable={{
          expandedRowRender: (row) => <Detail path={path + "/plans/" + encodeURIComponent(row.id)} state={row.state} canWrite={canWrite} refresh={refresh} />,
        }}
      />
      {features?.logs && (
        <Card size="small" title={l("服务商操作日志", "Provider log")}>
          {logs?.error && <Alert type="error" title={logs.error} showIcon />}
          <Table
            size="small"
            rowKey="index"
            loading={!logs}
            dataSource={logs?.data?.result.map((row, index) => ({ ...row, index })) ?? []}
            pagination={{ current: logPage, pageSize: 20, total: logs?.data?.result_info.total_count ?? 0, showSizeChanger: false, onChange: setLogPage }}
            columns={[
              { title: l("时间", "Time"), dataIndex: "time" },
              { title: l("操作", "Action"), dataIndex: "action" },
            ]}
          />
        </Card>
      )}
    </Space>
  );
}
