import type { DNSRecord } from "@/api/dns";
import { type BatchFileOptions, type BatchFileRow, type SheetRow, parseSheetRows } from "./files.rows";

export { parseArchive } from "./files.archive";
export { type BatchFileCapabilities, type BatchFileOptions, type BatchFileRow, parseSmartPaste } from "./files.rows";

export const workbookLicenseURL = new URL("./files-vendor/LICENSE.txt", import.meta.url).href;
const libraryURL = new URL("./files-vendor/xlsx.full.min.js", import.meta.url).href;
const workerURL = new URL("./files.worker.js?no-inline", import.meta.url).href;

type WorkbookSource = { provider: string; accessId: string; zoneId: string; groups?: { id: string; name: string }[] };
type ExportRecord = DNSRecord & { updatedAt?: string; group?: string; status?: string; description?: string; weight?: number; priority?: number };
type WorkerRequest = { operation: "read"; buffer: ArrayBuffer; kind: "xls" | "xlsx" } | { operation: "write"; rows: (string | number)[][] };

function workbookJob<T>(input: WorkerRequest): Promise<T> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(workerURL);
    const close = () => {
      clearTimeout(timer);
      worker.terminate();
    };
    const timer = setTimeout(() => {
      close();
      reject(new Error("Workbook processing exceeded the time limit."));
    }, 30000);
    worker.onerror = () => {
      close();
      reject(new Error("The workbook reader could not start."));
    };
    worker.onmessage = ({ data }) => {
      close();
      if (data.error) reject(new Error(data.error));
      else resolve(data.data as T);
    };
    worker.postMessage({ ...input, libraryURL }, input.operation === "read" ? [input.buffer] : []);
  });
}

export async function readWorkbook(file: File, options: BatchFileOptions): Promise<BatchFileRow[]> {
  const suffix = file.name.toLowerCase().split(".").pop();
  if (suffix !== "xls" && suffix !== "xlsx") throw new Error("Choose an .xls or .xlsx file.");
  if (file.size > 16 * 1024 * 1024) throw new Error("Workbooks must be 16 MiB or smaller.");
  const buffer = await file.arrayBuffer();
  const rows = await workbookJob<SheetRow[]>({ operation: "read", kind: suffix, buffer });
  return parseSheetRows(rows, options);
}

export async function downloadWorkbook(records: ExportRecord[], zone: string, source?: WorkbookSource): Promise<void> {
  const rows: (string | number)[][] = [
    [
      "记录ID",
      "主机记录",
      "记录类型",
      "线路值",
      "线路类型",
      "记录值",
      "TTL",
      "权重",
      "备注",
      "优先级",
      "状态",
      "代理",
      "只读",
      "更新时间",
      "源服务商",
      "源账号ID",
      "源域名ID",
      "分组ID",
      "分组名称",
    ],
  ];
  const suffix = "." + zone.toLowerCase().replace(/\.$/, "");
  const groups = new Map(source?.groups?.map((g) => [g.id, g.name]));
  for (const record of records) {
    const name = record.name.replace(/\.$/, "");
    let owner = name + ".";
    if ("." + name.toLowerCase() === suffix) owner = "@";
    else if (name.toLowerCase().endsWith(suffix)) owner = name.slice(0, -suffix.length);
    const cells = [
      record.id,
      owner,
      record.type,
      record.line ?? "",
      record.line ?? "",
      record.content,
      record.ttl,
      record.weight ?? "",
      record.description ?? "",
      record.priority ?? "",
      record.status ?? "",
      record.proxied ? "true" : "",
      record.readOnly ? "true" : "",
      record.updatedAt ?? "",
      source?.provider ?? "",
      source?.accessId ?? "",
      source?.zoneId ?? "",
      record.group ?? "",
      groups.get(record.group ?? "") ?? "",
    ];
    if (cells.some((cell) => typeof cell === "string" && cell.length > 32767)) throw new Error("A record exceeds Excel's 32767-character cell limit.");
    rows.push(cells);
  }
  const bytes = await workbookJob<ArrayBuffer>({ operation: "write", rows });
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }));
  const anchor = document.createElement("a");
  anchor.download = zone + "_解析记录_" + new Date().toISOString().slice(0, 10) + ".xlsx";
  anchor.href = url;
  try {
    anchor.click();
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
