import { useEffect, useRef, useState } from "react";
import { Alert, Button, Drawer, Pagination, Select, Space, Tabs, Typography } from "antd";
import { saveAs } from "file-saver";

import { type Zone, dnsRequest } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";

import History from "./History";
import ImportRecords from "./ImportRecords";
import {
  type BatchRecord,
  type BatchZone,
  type Draft,
  type Plan,
  type PreviewRow,
  type Review,
  type ZoneInput,
  splitDraft,
  targetZone,
  useLabel,
  useTargetFeatures,
} from "./model";
import RecordSelection from "./RecordSelection";
import ReviewPlan from "./ReviewPlans";

type Props = { base: string; zone: Zone; canWrite?: boolean; zones?: ZoneInput[]; onApplied?: () => void };
type Archive = { provider: string; accessId: string; zoneId: string; groups?: { id: string; name: string }[]; records: BatchRecord[] };
type Grant = { zoneId: string; name: string; status: string; provider: string; accessId: string; canWrite: boolean };

function Panel({ base, zone, zones, canWrite = true, onApplied }: Props) {
  const l = useLabel();
  const [request, setRequest] = useState({ page: 0, attempt: 0 });
  const { page } = request;
  const [more, setMore] = useState(true);
  const [options, setOptions] = useState<BatchZone[]>(() => {
    const all = new Map(
      zones?.map((z) => {
        const target = targetZone(z, base);
        return [target.key, target];
      })
    );
    const initial = targetZone({ ...zone, canWrite }, base);
    initial.canWrite = canWrite && all.get(initial.key)?.canWrite !== false;
    all.set(initial.key, initial);
    return [...all.values()];
  });
  const initialKey = targetZone(zone, base).key;
  const [selected, setSelected] = useState<string[]>([initialKey]);
  const [active, setActive] = useState(initialKey);
  const [tab, setTab] = useState("records");
  const [reviews, setReviews] = useState<Review[]>([]);
  const [reviewPage, setReviewPage] = useState(1);
  const [previewErrors, setPreviewErrors] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [discoveryError, setDiscoveryError] = useState("");
  const [busy, setBusy] = useState(false);
  const [loadedRequest, setLoadedRequest] = useState(request);
  const loadingZones = request !== loadedRequest;
  const [revision, setRevision] = useState(0);
  const pending = useRef(false);
  const present = useRef(true);
  useEffect(() => {
    present.current = true;
    return () => {
      present.current = false;
    };
  }, []);
  useEffect(() => {
    if (zones || page === 0) return;
    let current = true;
    dnsRequest<{ items: Grant[]; total: number }>("/api/dns-member/zones?page=" + page + "&perPage=100")
      .then(
        (data) => {
          if (!current) return;
          setOptions((prev) => {
            const all = new Map(prev.map((z) => [z.key, z]));
            for (const grant of data.items) {
              const z = targetZone(
                { id: grant.zoneId, name: grant.name, status: grant.status, provider: grant.provider, accessId: grant.accessId, canWrite: grant.canWrite },
                base
              );
              if (z.key === initialKey && !canWrite) z.canWrite = false;
              all.set(z.key, z);
            }
            return [...all.values()];
          });
          setMore(page * 100 < data.total);
        },
        (err) => {
          if (current) setDiscoveryError(unwrapErrMsg(err));
        }
      )
      .finally(() => {
        if (current) setLoadedRequest(request);
      });
    return () => {
      current = false;
    };
  }, [base, request, page, zones, initialKey, canWrite]);
  const chosen = options.filter((z) => selected.includes(z.key));
  const writable = chosen.filter((z) => z.canWrite !== false);
  const viewing = chosen.find((z) => z.key === active) ?? chosen[0];
  const path = viewing.key + "/batch";
  const result = useTargetFeatures(
    chosen.map((z) => z.key),
    revision
  );
  const features = result?.features ?? {};
  const refresh = () => {
    setRevision((v) => v + 1);
    onApplied?.();
  };
  async function preview(drafts: Draft[]) {
    if (pending.current || !drafts.length) return;
    pending.current = true;
    setBusy(true);
    setError("");
    setPreviewErrors([]);
    const result: Review[] = [];
    const errors: string[] = [];
    try {
      for (const draft of drafts.flatMap(splitDraft)) {
        if (!present.current) return;
        try {
          const data = await dnsRequest<{ plan: Plan; rows: PreviewRow[] }>(draft.zone.key + "/batch/preview", "POST", draft.payload);
          result.push({ ...data, zone: draft.zone, batch: draft.batch });
        } catch (e) {
          errors.push([draft.zone.label, draft.batch, unwrapErrMsg(e)].filter(Boolean).join(" · "));
        }
      }
      if (present.current) {
        setReviewPage(1);
        setReviews(result);
        setPreviewErrors(errors);
        setTab("review");
      }
    } finally {
      pending.current = false;
      if (present.current) setBusy(false);
    }
  }
  async function download(format: "bind" | "json" | "xlsx") {
    if (pending.current) return;
    pending.current = true;
    setBusy(true);
    setError("");
    try {
      if (format === "bind") {
        const text = await dnsRequest<string>(path + "/export?format=bind");
        saveAs(new Blob([text], { type: "text/plain;charset=utf-8" }), viewing.name + ".zone");
      } else {
        const archive = await dnsRequest<Archive>(path + "/export?format=archive");
        if (format === "xlsx") {
          const { downloadWorkbook } = await import("./files");
          await downloadWorkbook(archive.records, viewing.name, archive);
        } else saveAs(new Blob([JSON.stringify(archive, null, 2)], { type: "application/json" }), viewing.name + ".json");
      }
    } catch (e) {
      setError(unwrapErrMsg(e));
    } finally {
      pending.current = false;
      setBusy(false);
    }
  }
  const readZoneSelector = chosen.length > 1 && (
    <Select
      style={{ minWidth: 220 }}
      aria-label={l("查看域名", "View zone")}
      value={viewing.key}
      options={chosen.map((z) => ({ value: z.key, label: z.label }))}
      onChange={setActive}
    />
  );
  return (
    <Space orientation="vertical" style={{ width: "100%" }}>
      <Space wrap>
        <label>{l("目标域名", "Target zones")}</label>
        <Select
          aria-label={l("目标域名", "Target zones")}
          mode="multiple"
          style={{ minWidth: 240, maxWidth: "100%" }}
          value={selected}
          disabled={busy}
          options={options.map((z) => ({ value: z.key, label: z.label + (z.canWrite === false ? l("（只读）", " (read-only)") : "") }))}
          showSearch={{ optionFilterProp: "label" }}
          onChange={(ids) => {
            if (ids.length) {
              setSelected(ids);
              setError("");
            }
          }}
        />
        {!zones && (more || discoveryError) && (
          <Button
            loading={loadingZones}
            disabled={busy}
            onClick={() => {
              setRequest({ page: discoveryError ? page : page + 1, attempt: request.attempt + 1 });
              setDiscoveryError("");
            }}
          >
            {discoveryError ? l("重试加载", "Retry loading zones") : page === 0 ? l("选择更多域名", "Find more zones") : l("加载更多域名", "Load more zones")}
          </Button>
        )}
      </Space>
      {discoveryError && <Alert type="error" showIcon title={discoveryError} />}
      {error && <Alert type="error" showIcon title={error} />}
      {result?.errors.map((err) => (
        <Alert key={err} type="error" showIcon title={err} />
      ))}
      <Tabs
        activeKey={tab}
        onChange={setTab}
        items={[
          {
            key: "records",
            label: l("批量编辑", "Bulk edit"),
            children: <RecordSelection zones={chosen} features={features} revision={revision} preview={preview} busy={busy} />,
          },
          ...(writable.length
            ? [
                {
                  key: "import",
                  label: l("新增与导入", "Add and import"),
                  children: writable.every((z) => features[z.key]?.capabilities) ? (
                    <ImportRecords key={JSON.stringify(writable.map((z) => z.key))} zones={writable} features={features} busy={busy} preview={preview} />
                  ) : (
                    <Typography.Text>{l("正在读取服务商支持的记录类型…", "Loading supported provider record types…")}</Typography.Text>
                  ),
                },
              ]
            : []),
          {
            key: "review",
            label: l("变更预览", "Change previews"),
            children: (
              <Space orientation="vertical" style={{ width: "100%" }}>
                {previewErrors.map((msg) => (
                  <Alert type="error" showIcon key={msg} title={msg} />
                ))}
                {!reviews.length && !previewErrors.length && (
                  <Typography.Text>{l("从批量编辑或导入生成预览。", "Preview a batch edit or import to review its changes.")}</Typography.Text>
                )}
                {reviews.slice((reviewPage - 1) * 5, reviewPage * 5).map((item) => (
                  <ReviewPlan
                    key={item.zone.key + "/" + item.plan.id}
                    review={item}
                    canWrite={writable.some((z) => z.key === item.zone.key)}
                    onPlan={(updated) =>
                      setReviews((prev) => prev.map((r) => (r.zone.key === item.zone.key && r.plan.id === updated.id ? { ...r, plan: updated } : r)))
                    }
                    onApplied={refresh}
                  />
                ))}
                {reviews.length > 5 && <Pagination current={reviewPage} pageSize={5} total={reviews.length} onChange={setReviewPage} showSizeChanger={false} />}
              </Space>
            ),
          },
          {
            key: "history",
            label: l("执行历史", "History"),
            children: (
              <Space orientation="vertical" style={{ width: "100%" }}>
                {readZoneSelector}
                <History key={path} path={path} canWrite={viewing.canWrite !== false} features={features[viewing.key]} revision={revision} />
              </Space>
            ),
          },
          {
            key: "export",
            label: l("导出", "Export"),
            children: (
              <Space wrap>
                {readZoneSelector}
                {(["bind", "xlsx", "json"] as const).map((format) => (
                  <Button disabled={busy} key={format} onClick={() => download(format)}>
                    {l("导出 ", "Export ")}
                    {format.toUpperCase()}
                  </Button>
                ))}
              </Space>
            ),
          },
        ]}
      />
    </Space>
  );
}

export default function DNSBatch(props: Props) {
  const l = useLabel();
  const [open, setOpen] = useState(false);
  const changed = useRef(false);
  const visible = useRef(false);
  function close() {
    visible.current = false;
    setOpen(false);
    if (changed.current) {
      changed.current = false;
      props.onApplied?.();
    }
  }
  const title = l("批量记录", "Batch records");
  return (
    <>
      <Button
        onClick={() => {
          visible.current = true;
          setOpen(true);
        }}
      >
        {title}
      </Button>
      <Drawer title={title + " · " + props.zone.name} open={open} onClose={close} size="large" destroyOnHidden>
        {open && (
          <Panel
            key={props.base + "/" + props.zone.id}
            {...props}
            onApplied={() => {
              if (visible.current) changed.current = true;
              else props.onApplied?.();
            }}
          />
        )}
      </Drawer>
    </>
  );
}
