import { useRef, useState } from "react";
import { Alert, Button, Checkbox, Input, InputNumber, Radio, Select, Space, Table, Typography } from "antd";

import { unwrapErrMsg } from "@/utils/error";

import { type BatchFileRow, workbookLicenseURL } from "./files";
import { type BatchZone, type Change, type Draft, type Features, type Preview, metadataSummary, useData, useLabel } from "./model";

function replaceOrigin(name: string, origin: string, target: string) {
  const fqdn = name.toLowerCase().replace(/\.$/, "");
  const source = origin.toLowerCase().replace(/\.$/, "");
  if (fqdn === source) return target;
  if (fqdn.endsWith("." + source)) return fqdn.slice(0, -source.length) + target;
  throw new Error("Record is outside the selected source zone.");
}

export default function ImportRecords({
  base,
  zones,
  preview,
  busy,
  features,
}: {
  base: string;
  zones: BatchZone[];
  preview: Preview;
  busy: boolean;
  features: Features;
}) {
  const l = useLabel();
  const provider = decodeURIComponent(base.split("/")[3]);
  const caps = features.capabilities;
  const createLine = caps.line;
  const [mode, setMode] = useState<"paste" | "excel" | "bind" | "archive">("paste");
  const [originId, setOriginId] = useState(zones[0].id);
  const origin = zones.find((z) => z.id === originId) ?? zones[0];
  const advanced = base + "/zones/" + encodeURIComponent(origin.id) + "/advanced";
  const capabilities = useData<{ details: boolean }>(createLine ? advanced + "/features" : undefined);
  const details = useData<{ lines: { id: string; name: string }[] }>(capabilities?.data?.details ? advanced + "/details" : undefined);
  const groups = useData<{ id: string; name: string }[]>(
    mode !== "bind" && features.groups ? base + "/zones/" + encodeURIComponent(origin.id) + "/batch/groups" : undefined
  );
  const [group, setGroup] = useState("");
  const [omitInvalid, setOmitInvalid] = useState(false);
  const [repeat, setRepeat] = useState(false);
  const [text, setText] = useState("");
  const [file, setFile] = useState<File>();
  const [rrtype, setType] = useState("");
  const [ttl, setTTL] = useState<number | null>(caps.defaultTTL ?? 600);
  const [priority, setPriority] = useState<number | null>(null);
  const [weight, setWeight] = useState<number | null>(null);
  const [description, setDescription] = useState("");
  const [status, setStatus] = useState<"disabled" | "enabled">();
  const [line, setLine] = useState("");
  const [defaultValue, setDefaultValue] = useState("");
  const [rows, setRows] = useState<BatchFileRow[]>();
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
      const options = {
        provider,
        accessId: decodeURIComponent(base.split("/")[4]),
        zoneId: origin.id,
        groups: groups?.data,
        capabilities: caps,
        fields: features.fields,
        priority: mode === "paste" && caps.priorityTypes?.includes(rrtype) ? (priority ?? undefined) : undefined,
        weight: mode === "paste" ? (weight ?? undefined) : undefined,
        description: mode === "paste" ? description : undefined,
        status: mode === "paste" ? status : undefined,
        zone: origin.name,
        zones: repeat ? [origin.name] : zones.map((z) => z.name),
        type: rrtype,
        ttl: ttl ?? undefined,
        value: defaultValue,
        line,
        lines: details?.data?.lines,
      };
      let parsed: BatchFileRow[];
      if (mode === "archive") {
        if (file && file.size > 64 * 1024 * 1024) throw new Error(l("归档文件超过 64 MiB。", "Archive exceeds 64 MiB."));
        parsed = parseArchive(file ? await file.text() : text, options);
      } else if (mode === "excel" && file) parsed = await readWorkbook(file, options);
      else {
        parsed = parseSmartPaste(text, options);
        if (group && !cross) parsed = parsed.map((r) => ({ ...r, change: { ...r.change, group } }));
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
        const targets = mode === "archive" ? [origin] : repeat ? zones : zones.filter((z) => z.name.toLowerCase() === row.zone.toLowerCase());
        if (!targets.length) throw new Error(l("记录不属于所选域名", "Record is outside the selected zones") + " · " + row.change.name);
        if (!repeat && targets.length !== 1)
          throw new Error(l("存在同名域名，请只选择一个目标。", "Select one target when multiple zones have the same name."));
        for (const target of targets) {
          const changes = grouped.get(target.id) ?? [];
          changes.push({ ...row.change, name: repeat && mode !== "archive" ? replaceOrigin(row.change.name, origin.name, target.name) : row.change.name });
          grouped.set(target.id, changes);
        }
      }
      const drafts: Draft[] = zones.filter((z) => grouped.has(z.id)).map((zone) => ({ zone, payload: { changes: grouped.get(zone.id)! } }));
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
        {cross && (
          <Select
            disabled={parsing}
            aria-label={l("相对名称所属域名", "Zone for relative names")}
            style={{ minWidth: 210 }}
            value={origin.id}
            options={zones.map((z) => ({ value: z.id, label: z.name }))}
            onChange={(v) => {
              setOriginId(v);
              reset();
            }}
          />
        )}
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
            {createLine &&
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
            (mode === "excel" ? !file : !(text.trim() || (mode === "archive" && file))) ||
            (mode !== "archive" && !ttl)
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
          rowKey="row"
          dataSource={rows}
          pagination={{ pageSize: 10, showSizeChanger: false }}
          columns={[
            { title: l("行", "Row"), dataIndex: "row" },
            { title: l("域名", "Zone"), dataIndex: "zone" },
            { title: l("名称", "Name"), render: (_, r) => r.change.name },
            { title: l("记录类型", "Type"), render: (_, r) => r.change.type },
            { title: l("记录值", "Value"), render: (_, r) => r.change.content },
            { title: "TTL", render: (_, r) => r.change.ttl },
            { title: l("记录属性", "Record attributes"), render: (_, r) => metadataSummary(r.change, l, provider) || "—" },
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
