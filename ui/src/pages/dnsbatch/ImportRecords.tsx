import { useRef, useState } from "react";
import { Alert, Button, Checkbox, Input, InputNumber, Radio, Select, Space, Table, Typography } from "antd";

import { dnsRequest } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";

import { type BatchFileOptions, type BatchFileRow, workbookLicenseURL } from "./files";
import { type BatchZone, type Change, type Draft, type Group, type Preview, type TargetFeatures, metadataSummary, useData, useLabel } from "./model";

function replaceOrigin(name: string, origin: string, target: string) {
  const fqdn = name.toLowerCase().replace(/\.$/, "");
  const source = origin.toLowerCase().replace(/\.$/, "");
  if (fqdn === source) return target;
  if (fqdn.endsWith("." + source)) return fqdn.slice(0, -source.length) + target;
  throw new Error("Record is outside the selected source zone.");
}

type Props = { zones: BatchZone[]; features: TargetFeatures; preview: Preview; busy: boolean };
type TargetRow = BatchFileRow & { target: BatchZone };

export default function ImportRecords(props: Props) {
  const l = useLabel();
  const { zones } = props;
  const duplicate = zones.some((z, i) => zones.slice(0, i).some((other) => other.name.toLowerCase() === z.name.toLowerCase()));
  const [originKey, setOrigin] = useState<string | undefined>(duplicate ? undefined : zones[0].key);
  const origin = zones.find((z) => z.key === originKey);
  return (
    <Space orientation="vertical" style={{ width: "100%" }}>
      {zones.length > 1 && (
        <label>
          {l("文件及相对记录名的目标", "Target for files and relative names")}{" "}
          <Select
            aria-label={l("文件及相对记录名的目标", "Target for files and relative names")}
            style={{ minWidth: 240 }}
            value={originKey}
            options={zones.map((z) => ({ value: z.key, label: z.label }))}
            onChange={setOrigin}
          />
        </label>
      )}
      {origin ? (
        <ImportEditor key={origin.key} {...props} origin={origin} />
      ) : (
        <Alert type="info" title={l("存在同名域名，请先选择目标账号和域名。", "Select an account and zone to resolve duplicate zone names.")} />
      )}
    </Space>
  );
}

function ImportEditor({ zones, preview, busy, features: allFeatures, origin }: Props & { origin: BatchZone }) {
  const l = useLabel();
  const features = allFeatures[origin.key];
  const caps = features.capabilities;
  const createLine = caps.line;
  const [mode, setMode] = useState<"paste" | "excel" | "bind" | "archive">("paste");
  const advanced = origin.key + "/advanced";
  const capabilities = useData<{ details: boolean }>(createLine ? advanced + "/features" : undefined);
  const details = useData<{ lines: Group[] }>(capabilities?.data?.details ? advanced + "/details" : undefined);
  const groups = useData<Group[]>(mode !== "bind" && features.groups ? origin.key + "/batch/groups" : undefined);
  const [group, setGroup] = useState("");
  const [omitInvalid, setOmitInvalid] = useState(false);
  const [repeat, setRepeat] = useState(false);
  const [text, setText] = useState("");
  const [file, setFile] = useState<File>();
  const [rrtype, setType] = useState("");
  const [ttl, setTTL] = useState<number | null>(null);
  const [priority, setPriority] = useState<number | null>(null);
  const [weight, setWeight] = useState<number | null>(null);
  const [description, setDescription] = useState("");
  const [status, setStatus] = useState<"disabled" | "enabled">();
  const [line, setLine] = useState("");
  const [defaultValue, setDefaultValue] = useState("");
  const [rows, setRows] = useState<TargetRow[]>();
  const [error, setError] = useState("");
  const [parsing, setParsing] = useState(false);
  const locked = useRef(false);
  const reset = () => {
    setRows(undefined);
    setOmitInvalid(false);
    setError("");
  };
  const cross = zones.length > 1;
  const invalidCount = rows?.filter((r) => r.error).length ?? 0;
  const validCount = (rows?.length ?? 0) - invalidCount;
  async function parse() {
    if (locked.current) return;
    locked.current = true;
    setParsing(true);
    reset();
    try {
      const { parseSmartPaste, readWorkbook, parseArchive } = await import("./files");
      const inputs = mode === "archive" || (mode === "excel" && !repeat) ? [origin] : zones;
      const parsed: TargetRow[] = [];
      const visited = new Set<number>();
      const namedTargets = new Map<string, BatchZone[]>();
      for (const z of zones) {
        const name = z.name.toLowerCase().replace(/\.$/, "");
        const matches = namedTargets.get(name) ?? [];
        matches.push(z);
        namedTargets.set(name, matches);
      }
      for (const target of inputs) {
        const targetFeatures = allFeatures[target.key];
        const targetCaps = targetFeatures.capabilities;
        let targetLines = target.key === origin.key ? details?.data?.lines : undefined;
        let targetGroups = target.key === origin.key ? groups?.data : undefined;
        if (mode === "excel" && target.key !== origin.key) {
          if (targetFeatures.groups) targetGroups = await dnsRequest<Group[]>(target.key + "/batch/groups");
          if (targetCaps.line) {
            const advanced = await dnsRequest<{ details: boolean }>(target.key + "/advanced/features");
            if (advanced.details) targetLines = (await dnsRequest<{ lines: Group[] }>(target.key + "/advanced/details")).lines;
          }
        }
        const options: BatchFileOptions = {
          provider: target.provider,
          accessId: target.accessId,
          zoneId: target.id,
          zone: mode === "paste" ? origin.name : target.name,
          zones: repeat ? [origin.name] : zones.map((z) => z.name),
          capabilities: targetCaps,
          fields: targetFeatures.fields,
          groups: targetGroups,
          lines: targetLines,
          type: rrtype,
          ttl: ttl ?? targetCaps.defaultTTL,
          value: defaultValue,
          line: cross ? "" : line,
          priority: mode === "paste" && caps.priorityTypes?.includes(rrtype) ? (priority ?? undefined) : undefined,
          weight: mode === "paste" ? (weight ?? undefined) : undefined,
          description: mode === "paste" ? description : undefined,
          status: mode === "paste" ? status : undefined,
        };
        let projected: BatchFileRow[];
        if (mode === "archive") {
          if (file && file.size > 64 * 1024 * 1024) throw new Error(l("归档文件超过 64 MiB。", "Archive exceeds 64 MiB."));
          projected = parseArchive(file ? await file.text() : text, options);
        } else if (mode === "excel" && file) {
          projected = await readWorkbook(file, options);
        } else projected = parseSmartPaste(text, options);
        for (const row of projected) {
          if (mode === "paste" && !repeat) {
            const match = namedTargets.get(row.zone.toLowerCase()) ?? [];
            const dest = match.length === 1 ? match[0] : match.find((z) => z.key === origin.key);
            if (!dest) {
              if (!visited.has(row.row)) {
                visited.add(row.row);
                parsed.push({
                  ...row,
                  target: origin,
                  error: row.error ?? l("无法确定账号及域名，请选择唯一目标。", "Choose a unique target account and zone."),
                });
              }
              continue;
            }
            if (dest.key !== target.key) continue;
          }
          const change = { ...row.change };
          if (mode === "paste" && repeat && !row.error) change.name = replaceOrigin(change.name, origin.name, target.name);
          if (mode === "paste" && !cross && group) change.group = group;
          parsed.push({ ...row, change, target });
        }
      }
      setRows(parsed);
    } catch (e) {
      setError(unwrapErrMsg(e));
    } finally {
      locked.current = false;
      setParsing(false);
    }
  }
  function build() {
    setError("");
    try {
      if (mode === "bind") {
        preview([{ zone: origin, payload: { zoneFile: text } }]);
        return;
      }
      const grouped = new Map<string, Change[]>();
      for (const row of rows ?? []) {
        if (row.error) {
          if (omitInvalid) continue;
          throw new Error(row.error);
        }
        const changes = grouped.get(row.target.key) ?? [];
        changes.push(row.change);
        grouped.set(row.target.key, changes);
      }
      const drafts: Draft[] = zones.filter((z) => grouped.has(z.key)).map((zone) => ({ zone, payload: { changes: grouped.get(zone.key)! } }));
      if (drafts.length) preview(drafts);
    } catch (e) {
      setError(unwrapErrMsg(e));
    }
  }
  return (
    <Space orientation="vertical" style={{ width: "100%" }}>
      <Space wrap>
        <Radio.Group
          value={mode}
          disabled={parsing}
          aria-label={l("导入格式", "Import format")}
          options={[
            { value: "paste", label: l("智能粘贴", "Smart paste") },
            { value: "excel", label: "Excel" },
            { value: "bind", label: "BIND" },
            { value: "archive", label: l("JSON 归档", "JSON archive") },
          ]}
          onChange={(e) => {
            setMode(e.target.value);
            setText("");
            setFile(undefined);
            setRepeat(false);
            reset();
          }}
        />
      </Space>
      {(mode === "paste" || mode === "excel") && (
        <>
          {cross && (
            <Checkbox
              checked={repeat}
              disabled={parsing}
              onChange={(e) => {
                setRepeat(e.target.checked);
                reset();
              }}
            >
              {l("将相同相对记录名添加到每个已选域名", "Create the same relative names in each selected zone")}
            </Checkbox>
          )}
          {mode === "paste" && (
            <Space wrap>
              <Select
                disabled={parsing}
                aria-label={l("默认记录类型", "Default record type")}
                value={rrtype}
                style={{ minWidth: 160 }}
                options={["", ...caps.types].map((v) => ({ value: v, label: v || l("自动识别类型", "Detect record type") }))}
                onChange={(v) => {
                  setType(v);
                  reset();
                }}
              />
              <Input
                disabled={parsing}
                aria-label={l("默认记录值", "Default value")}
                placeholder={l("默认记录值", "Default value")}
                value={defaultValue}
                onChange={(e) => {
                  setDefaultValue(e.target.value);
                  reset();
                }}
              />
            </Space>
          )}
          <Space wrap>
            <label>
              TTL{" "}
              <InputNumber
                disabled={parsing}
                value={ttl}
                placeholder={String(caps.defaultTTL ?? 600)}
                min={Math.min(caps.minTTL, ...(caps.specialTTLs ?? []))}
                max={caps.maxTTL}
                precision={0}
                onChange={(v) => {
                  setTTL(v);
                  reset();
                }}
              />
            </label>
            {mode === "paste" && (
              <>
                {!cross && features.groups && (
                  <Select
                    disabled={parsing}
                    allowClear
                    aria-label={l("新记录分组", "New record group")}
                    placeholder={l("分组", "Group")}
                    style={{ minWidth: 140 }}
                    value={group || undefined}
                    onChange={(v) => {
                      setGroup(v ?? "");
                      reset();
                    }}
                    options={groups?.data?.map((g) => ({ value: g.id, label: g.name }))}
                  />
                )}
                {caps.priorityTypes?.includes(rrtype) && (
                  <label>
                    {l("优先级", "Priority")}{" "}
                    <InputNumber
                      aria-label={l("优先级", "Priority")}
                      precision={0}
                      min={0}
                      value={priority}
                      disabled={parsing}
                      onChange={(v) => {
                        setPriority(v);
                        reset();
                      }}
                    />
                  </label>
                )}
                {(caps.weight || features.fields.includes("weight")) && (
                  <label>
                    {l("权重", "Weight")}{" "}
                    <InputNumber
                      aria-label={l("权重", "Weight")}
                      precision={0}
                      min={0}
                      value={weight}
                      disabled={parsing}
                      onChange={(v) => {
                        setWeight(v);
                        reset();
                      }}
                    />
                  </label>
                )}
                {(caps.description || features.fields.includes("remark")) && (
                  <Input
                    placeholder={l("备注", "Remark")}
                    aria-label={l("备注", "Remark")}
                    disabled={parsing}
                    value={description}
                    onChange={(e) => {
                      setDescription(e.target.value);
                      reset();
                    }}
                  />
                )}
                {features.fields.includes("status") && (
                  <Select
                    allowClear
                    disabled={parsing}
                    aria-label={l("新记录状态", "Status of new records")}
                    placeholder={l("服务商默认状态", "Default provider status")}
                    style={{ minWidth: 185 }}
                    value={status}
                    options={[
                      { value: "enabled", label: l("启用", "Enabled") },
                      { value: "disabled", label: l("暂停", "Disabled") },
                    ]}
                    onChange={(v) => {
                      setStatus(v);
                      reset();
                    }}
                  />
                )}
              </>
            )}
            {!cross &&
              createLine &&
              (details?.data?.lines?.length ? (
                <Select
                  allowClear
                  showSearch={{ optionFilterProp: "label" }}
                  disabled={parsing}
                  aria-label={l("默认线路 ID", "Default line ID")}
                  placeholder={l("默认线路", "Default line")}
                  value={line || undefined}
                  style={{ minWidth: 170 }}
                  options={details.data.lines.map((v) => ({ value: v.id, label: v.name }))}
                  onChange={(v) => {
                    setLine(v ?? "");
                    reset();
                  }}
                />
              ) : (
                <Input
                  disabled={parsing}
                  aria-label={l("默认线路 ID", "Default line ID")}
                  placeholder={l("默认线路 ID（选填）", "Default line ID (optional)")}
                  value={line}
                  onChange={(e) => {
                    setLine(e.target.value);
                    reset();
                  }}
                />
              ))}
          </Space>
        </>
      )}
      {mode === "archive" && (
        <input
          disabled={parsing}
          type="file"
          accept=".json,application/json"
          aria-label={l("JSON 归档文件", "JSON archive file")}
          onChange={(e) => {
            setFile(e.target.files?.[0]);
            setText("");
            reset();
          }}
        />
      )}
      {mode === "excel" ? (
        <Space wrap>
          <input
            disabled={parsing}
            type="file"
            accept=".xls,.xlsx"
            aria-label={l("Excel 工作簿", "Excel workbook")}
            onChange={(e) => {
              setFile(e.target.files?.[0]);
              reset();
            }}
          />
          <a href={workbookLicenseURL} target="_blank" rel="noreferrer">
            SheetJS CE
          </a>
        </Space>
      ) : (
        <Input.TextArea
          disabled={parsing || (mode === "archive" && !!file)}
          rows={6}
          aria-label={
            mode === "archive"
              ? l("JSON 归档内容", "JSON archive text")
              : mode === "bind"
                ? l("BIND 区域文件", "BIND zone file")
                : l("待解析记录", "Records to parse")
          }
          placeholder={
            mode === "archive"
              ? l("选择归档文件，或在此粘贴 JSON。", "Choose an archive or paste its JSON here.")
              : mode === "bind"
                ? "www 600 IN CNAME target.example.test."
                : "www target.example.test"
          }
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            reset();
          }}
        />
      )}
      {mode !== "bind" && (
        <Button
          loading={parsing}
          disabled={
            ((mode === "archive" || mode === "excel") && features.groups && !groups?.data) ||
            (mode === "excel" ? !file : !(text.trim() || (mode === "archive" && file)))
          }
          onClick={parse}
        >
          {l("解析记录", "Parse records")}
        </Button>
      )}
      {(mode === "archive" || mode === "excel") && groups?.error && <Alert type="error" showIcon title={groups.error} />}
      {error && <Alert type="error" title={error} showIcon />}
      {rows && (
        <Table
          size="small"
          scroll={{ x: 620 }}
          rowKey={(r) => r.target.key + "/" + r.row}
          dataSource={rows}
          pagination={{ pageSize: 10, showSizeChanger: false }}
          columns={[
            { title: l("行", "Row"), dataIndex: "row" },
            { title: l("目标", "Target"), render: (_, r) => r.target.label },
            { title: l("名称", "Name"), render: (_, r) => r.change.name },
            { title: l("记录类型", "Type"), render: (_, r) => r.change.type },
            { title: l("记录值", "Value"), render: (_, r) => r.change.content },
            { title: "TTL", render: (_, r) => r.change.ttl },
            { title: l("记录属性", "Record attributes"), render: (_, r) => metadataSummary(r.change, l, r.target.provider) || "—" },
            { title: l("校验", "Validation"), render: (_, r) => (r.error ? <Typography.Text type="danger">{r.error}</Typography.Text> : l("通过", "Valid")) },
          ]}
        />
      )}
      {!!invalidCount && (
        <Checkbox checked={omitInvalid} disabled={!!busy || !validCount} onChange={(e) => setOmitInvalid(e.target.checked)}>
          {l("跳过校验失败的记录", "Skip invalid rows")} ({invalidCount}) · {l("参与预览", "Include in preview")} ({validCount})
        </Checkbox>
      )}
      <Button
        type="primary"
        loading={busy}
        disabled={parsing || (mode === "bind" ? !text.trim() : !validCount || (!!invalidCount && !omitInvalid))}
        onClick={build}
      >
        {l("预览新增记录", "Preview new records")}
      </Button>
    </Space>
  );
}
