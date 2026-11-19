/* global self, importScripts, XLSX, TextDecoder */

// This classic worker runs the local standalone reader in isolation. Workbook
// input never supplies script URLs. Only literal cell values cross the boundary.
const maxBytes = 16 * 1024 * 1024;
const maxUnpacked = 64 * 1024 * 1024;
const maxDataRows = 20000;

function checkFormat(buffer, kind) {
  if (!buffer.byteLength || buffer.byteLength > maxBytes) throw new Error("Workbooks must be 16 MiB or smaller.");
  const bytes = new Uint8Array(buffer);
  if (kind === "xls") {
    if (![0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1].every((byte, index) => bytes[index] === byte)) {
      throw new Error("Expected an Excel .xls workbook.");
    }
    return;
  }
  const view = new DataView(buffer);
  if (bytes.length < 22 || view.getUint32(0, true) !== 0x04034b50) throw new Error("Expected an Excel .xlsx workbook.");
  let end = bytes.length - 22;
  const earliest = Math.max(0, end - 65535);
  for (; end >= earliest; end--) {
    if (view.getUint32(end, true) === 0x06054b50 && end + 22 + view.getUint16(end + 20, true) === bytes.length) break;
  }
  if (end < earliest) throw new Error("Invalid workbook ZIP directory.");
  const entries = view.getUint16(end + 10, true);
  if (entries > 1024) throw new Error("Workbook contains too many ZIP entries.");
  let entry = view.getUint32(end + 16, true);
  let size = 0;
  let hasWorkbook = false;
  for (let i = 0; i < entries; i++) {
    if (entry + 46 > end || view.getUint32(entry, true) !== 0x02014b50) throw new Error("Invalid workbook ZIP entry.");
    const fileNameLength = view.getUint16(entry + 28, true);
    if (entry + 46 + fileNameLength > end) throw new Error("Invalid workbook entry name.");
    const name = new TextDecoder().decode(bytes.subarray(entry + 46, entry + 46 + fileNameLength));
    if (name === "xl/workbook.xml") hasWorkbook = true;
    size += view.getUint32(entry + 24, true);
    if (size > maxUnpacked) throw new Error("Expanded workbook exceeds 64 MiB.");
    entry += 46 + view.getUint16(entry + 28, true) + view.getUint16(entry + 30, true) + view.getUint16(entry + 32, true);
  }
  if (entry !== end) throw new Error("Invalid workbook ZIP bounds.");
  if (!hasWorkbook) throw new Error("Expected an Open XML spreadsheet workbook.");
}

function readSheet(buffer, kind) {
  checkFormat(buffer, kind);
  const workbook = XLSX.read(buffer, { type: "array", sheets: 0, sheetRows: maxDataRows + 2, cellFormula: true, cellHTML: false, cellText: false });
  const sheet = workbook.Sheets[workbook.SheetNames[0]];
  if (!sheet || !sheet["!ref"]) throw new Error("The first worksheet is empty.");
  const range = XLSX.utils.decode_range(sheet["!fullref"] || sheet["!ref"]);
  if (range.e.r > maxDataRows || range.e.c >= 64) throw new Error("A worksheet may contain a header and up to 20000 records in 64 columns.");
  const rows = [];
  for (let r = range.s.r; r <= range.e.r; r++) {
    const values = [];
    let error = "";
    for (let c = range.s.c; c <= range.e.c; c++) {
      const cell = sheet[XLSX.utils.encode_cell({ r, c })];
      if (cell?.f != null || cell?.F != null || cell?.t === "e") error = "Replace formula and error cells with literal values.";
      values.push(cell == null || cell.v == null ? "" : String(cell.v));
    }
    if (error || values.some((value) => value !== "")) rows.push({ row: r + 1, values, ...(error ? { error } : {}) });
  }
  return rows;
}

self.onmessage = ({ data }) => {
  try {
    importScripts(data.libraryURL);
    if (data.operation === "read") {
      self.postMessage({ data: readSheet(data.buffer, data.kind) });
    } else {
      const workbook = XLSX.utils.book_new();
      // String cells (including literal TXT values beginning with '=') retain their type.
      const sheet = XLSX.utils.aoa_to_sheet(data.rows);
      XLSX.utils.book_append_sheet(workbook, sheet, "解析记录");
      const bytes = XLSX.write(workbook, { type: "array", bookType: "xlsx", compression: true });
      self.postMessage({ data: bytes }, [bytes]);
    }
  } catch (error) {
    self.postMessage({ error: error instanceof Error ? error.message : "Unable to process workbook." });
  }
};
