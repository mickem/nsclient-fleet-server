// Pure parsing for the facts import wizard: file format detection, an RFC 4180 CSV reader,
// table extraction from JSON/YAML documents, flattening nested records to dotted columns
// and nesting mapped columns back into documents, and cell type coercion. Nothing here
// touches React or the network, so it is unit tested on its own (parse.test.ts).

import { parse as parseYaml } from "yaml";

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export type Format = "csv" | "json" | "yaml";
export const FORMATS: Format[] = ["csv", "json", "yaml"];

/** A delimiter the CSV reader can be told to use; `auto` sniffs one of the others. */
export type Delimiter = "," | ";" | "\t" | "|";
export const DELIMITERS: Delimiter[] = [",", ";", "\t", "|"];

/** One parsed file as rows of cells under named columns. A cell is `undefined` where a
 *  record had no value at that column (JSON/YAML); CSV cells are always strings. */
export type Table = {
  columns: string[];
  rows: (JsonValue | undefined)[][];
  /** Something worth telling the operator about how the table was read. */
  note?: string;
};

export type ColumnType = "auto" | "string" | "number" | "boolean";
export const COLUMN_TYPES: ColumnType[] = ["auto", "string", "number", "boolean"];

const isObj = (v: unknown): v is JsonObject =>
  typeof v === "object" && v !== null && !Array.isArray(v);

// --- format detection ------------------------------------------------------------------

/** The format a file is in: by extension when it has a telling one, else by content. */
export function detectFormat(fileName: string, text: string): Format {
  const ext = /\.([^.]+)$/.exec(fileName.toLowerCase())?.[1] ?? "";
  if (ext === "csv" || ext === "tsv") return "csv";
  if (ext === "json") return "json";
  if (ext === "yaml" || ext === "yml") return "yaml";
  return sniffFormat(text);
}

/** Content sniffing: `{`/`[` first means JSON; otherwise whichever of JSON and YAML reads it
 *  as a structure (YAML reads almost any text as a plain string, which is not a table);
 *  else CSV. */
export function sniffFormat(text: string): Format {
  const t = stripBom(text).trimStart();
  if (t.startsWith("{") || t.startsWith("[")) return "json";
  try {
    JSON.parse(t);
    return "json";
  } catch {
    /* not JSON */
  }
  try {
    const doc: unknown = parseYaml(t);
    if (typeof doc === "object" && doc !== null) return "yaml";
  } catch {
    /* not YAML */
  }
  return "csv";
}

const stripBom = (s: string) => (s.charCodeAt(0) === 0xfeff ? s.slice(1) : s);

// --- CSV -------------------------------------------------------------------------------

/** RFC 4180 CSV: quoted fields may hold the delimiter, `""` for a quote, and line breaks;
 *  records end at CRLF, LF or CR. A trailing line break does not start an empty record,
 *  and blank lines are skipped. */
export function parseCsv(text: string, delimiter: Delimiter): string[][] {
  const s = stripBom(text);
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  // Whether the current record has seen anything at all, so a blank line is not a record.
  let started = false;
  let i = 0;
  const endField = () => {
    row.push(field);
    field = "";
  };
  const endRow = () => {
    endField();
    if (started) rows.push(row);
    row = [];
    started = false;
  };
  while (i < s.length) {
    const c = s[i];
    if (quoted) {
      if (c === '"') {
        if (s[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        quoted = false;
        i++;
        continue;
      }
      field += c;
      i++;
      continue;
    }
    if (c === '"' && field === "") {
      quoted = true;
      started = true;
      i++;
    } else if (c === delimiter) {
      endField();
      started = true;
      i++;
    } else if (c === "\r" || c === "\n") {
      endRow();
      i += c === "\r" && s[i + 1] === "\n" ? 2 : 1;
    } else {
      field += c;
      started = true;
      i++;
    }
  }
  if (started || field !== "" || row.length > 0) endRow();
  return rows;
}

/** The delimiter that splits the start of the file most consistently into the most
 *  columns. Comma when nothing splits it at all. */
export function detectDelimiter(text: string): Delimiter {
  // Enough lines to judge by; cut at a line break so a sample does not end mid-record
  // more than once.
  const sample = text.length > 65536 ? text.slice(0, text.lastIndexOf("\n", 65536) + 1 || 65536) : text;
  let best: Delimiter = ",";
  let bestScore = 0;
  for (const d of DELIMITERS) {
    const rows = parseCsv(sample, d).slice(0, 20);
    if (rows.length === 0) continue;
    const counts = rows.map((r) => r.length);
    const first = counts[0];
    if (first < 2) continue;
    const consistent = counts.filter((n) => n === first).length / counts.length;
    const score = consistent * first;
    if (score > bestScore) {
      bestScore = score;
      best = d;
    }
  }
  return best;
}

/** Column names from a header row: blanks become `colN`, repeats get `_2`, `_3`, … */
function uniqueColumns(names: string[]): string[] {
  const seen = new Set<string>();
  return names.map((raw, i) => {
    const base = raw.trim() || `col${i + 1}`;
    let name = base;
    for (let n = 2; seen.has(name); n++) name = `${base}_${n}`;
    seen.add(name);
    return name;
  });
}

/** CSV records as a table: the first record names the columns when `header`, else they
 *  are `col1…colN`. Short records are padded with empty cells. */
export function csvToTable(records: string[][], header: boolean): Table {
  const body = header ? records.slice(1) : records;
  const width = Math.max(header ? (records[0]?.length ?? 0) : 0, ...body.map((r) => r.length), 0);
  const names = header ? (records[0] ?? []).slice() : [];
  while (names.length < width) names.push("");
  const columns = header
    ? uniqueColumns(names)
    : Array.from({ length: width }, (_, i) => `col${i + 1}`);
  const rows = body.map((r) => {
    const out: string[] = r.slice(0, width);
    while (out.length < width) out.push("");
    return out;
  });
  return { columns, rows };
}

// --- JSON / YAML -----------------------------------------------------------------------

/** Parse a JSON or YAML document. Throws with the parser's message when it does not. */
export function parseDocument(text: string, format: "json" | "yaml"): unknown {
  const t = stripBom(text);
  return format === "json" ? JSON.parse(t) : parseYaml(t);
}

/** The synthetic column holding the member name when a document is an object of records. */
export const KEY_COLUMN = "_key";

const isRecordArray = (v: unknown): v is JsonObject[] => Array.isArray(v) && v.every(isObj);

/** The records a document holds, in one of three shapes:
 *  (a) an array of objects;
 *  (b) an object whose values are all objects — each member is a record, its name in `_key`;
 *  (c) an object with exactly one member that is an array of objects — that member. */
export function extractRecords(doc: unknown): { records: JsonObject[]; note?: string } {
  if (Array.isArray(doc)) {
    if (!isRecordArray(doc)) throw new Error("The array holds values that are not objects.");
    return { records: doc };
  }
  if (!isObj(doc)) throw new Error("The document is neither an array nor an object of records.");
  const entries = Object.entries(doc);
  if (entries.length > 0 && entries.every(([, v]) => isObj(v))) {
    const records = entries.map(([k, v]) => {
      const rec: JsonObject = {};
      setOwn(rec, KEY_COLUMN, k);
      for (const [rk, rv] of Object.entries(v as JsonObject)) {
        if (rk !== KEY_COLUMN) setOwn(rec, rk, rv);
      }
      return rec;
    });
    return { records, note: `Each member is a record; its name is in the "${KEY_COLUMN}" column.` };
  }
  const arrays = entries.filter(([, v]) => Array.isArray(v) && v.length > 0 && isRecordArray(v));
  if (arrays.length === 1) {
    const [name, v] = arrays[0];
    return { records: v as JsonObject[], note: `Using the records in "${name}".` };
  }
  if (arrays.length > 1) {
    throw new Error(
      `The document has several lists of records (${arrays.map(([n]) => n).join(", ")}); ` +
        "import one at a time.",
    );
  }
  throw new Error(
    "No records found: expected an array of objects, an object of objects, or an object " +
      "with one array of objects.",
  );
}

/** A record's values by dotted path: nested objects are walked, everything else (scalars,
 *  arrays, empty objects) is a value. */
export function flattenRecord(rec: JsonObject, prefix = ""): [string, JsonValue][] {
  const out: [string, JsonValue][] = [];
  for (const [k, v] of Object.entries(rec)) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (isObj(v) && Object.keys(v).length > 0) out.push(...flattenRecord(v, path));
    else out.push([path, v]);
  }
  return out;
}

/** Records as a table, one column per dotted path in the order paths first appear. */
export function recordsToTable(records: JsonObject[], note?: string): Table {
  const index = new Map<string, number>();
  const columns: string[] = [];
  const flat = records.map((r) => flattenRecord(r));
  for (const entries of flat) {
    for (const [p] of entries) {
      if (!index.has(p)) {
        index.set(p, columns.length);
        columns.push(p);
      }
    }
  }
  const rows = flat.map((entries) => {
    const row: (JsonValue | undefined)[] = new Array<JsonValue | undefined>(columns.length).fill(
      undefined,
    );
    for (const [p, v] of entries) row[index.get(p)!] = v;
    return row;
  });
  return { columns, rows, note };
}

/** Options for reading a file into a table. */
export type ReadOptions = {
  format: Format;
  /** CSV only; `auto` detects one. */
  delimiter: Delimiter | "auto";
  /** CSV only. */
  header: boolean;
};

export type ReadResult =
  | { ok: true; table: Table; delimiter?: Delimiter }
  | { ok: false; error: string };

/** A whole file as a table, or why it could not be read as one. */
export function readTable(text: string, opts: ReadOptions): ReadResult {
  try {
    if (opts.format === "csv") {
      const delimiter = opts.delimiter === "auto" ? detectDelimiter(text) : opts.delimiter;
      const table = csvToTable(parseCsv(text, delimiter), opts.header);
      if (table.columns.length === 0) return { ok: false, error: "The file is empty." };
      return { ok: true, table, delimiter };
    }
    const { records, note } = extractRecords(parseDocument(text, opts.format));
    return { ok: true, table: recordsToTable(records, note) };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

// --- mapping ---------------------------------------------------------------------------

/** Longest fact path a selector stores (`MAX_FACT_PATH_LEN` in crates/core/src/selector.rs). */
export const MAX_TARGET_LEN = 512;

/** Why `path` cannot name a column in the stored document, or null when it can.
 *
 *  A target is a selector path (`FactPath::parse`) restricted to what nesting can produce:
 *  dot-separated keys, none empty. `[id]` picks select records out of a list, and an
 *  imported document is built of nested maps, so a bracket has no meaning here. */
export function targetPathError(path: string): string | null {
  if (path === "") return "Required";
  if (path.length > MAX_TARGET_LEN) return `Longer than ${MAX_TARGET_LEN} characters`;
  if (/[[\]]/.test(path)) return "[ and ] are not allowed";
  if (path.split(".").some((k) => k === "")) return "Empty key (leading, trailing or double dot)";
  return null;
}

/** A target suggested for a column name: whitespace and brackets become `_`, empty
 *  segments are dropped. Valid whenever the name has anything usable in it. */
export function suggestTarget(column: string): string {
  const s = column
    .trim()
    .replace(/[\s[\]]+/g, "_")
    .split(".")
    .filter((k) => k !== "")
    .join(".");
  return s.length > MAX_TARGET_LEN ? s.slice(0, MAX_TARGET_LEN) : s;
}

/** Targets that collide: the same path twice, or one path inside another (`a` and `a.b`
 *  cannot both be stored — `a` would be a value and a map at once). By index. */
export function targetConflicts(targets: string[]): Map<number, string> {
  const out = new Map<number, string>();
  for (let i = 0; i < targets.length; i++) {
    for (let j = 0; j < targets.length; j++) {
      if (i === j) continue;
      const a = targets[i];
      const b = targets[j];
      if (!a || !b) continue;
      if (a === b) out.set(i, `Same target as another column`);
      else if (b.startsWith(`${a}.`)) out.set(i, `"${b}" is nested inside this path`);
      else if (a.startsWith(`${b}.`)) out.set(i, `Nested inside "${b}", which is a value`);
    }
  }
  return out;
}

/** Assign without going through a setter, so a key such as `__proto__` is just a key. */
function setOwn(obj: JsonObject, key: string, value: JsonValue) {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

/** Dotted paths back into a nested document. Paths are assumed conflict free
 *  (`targetConflicts`); a later path through an existing value replaces it. */
export function unflatten(entries: [string, JsonValue][]): JsonObject {
  const root: JsonObject = {};
  for (const [path, value] of entries) {
    const keys = path.split(".");
    let node = root;
    for (const k of keys.slice(0, -1)) {
      const next = Object.prototype.hasOwnProperty.call(node, k) ? node[k] : undefined;
      if (isObj(next)) {
        node = next;
      } else {
        const fresh: JsonObject = {};
        setOwn(node, k, fresh);
        node = fresh;
      }
    }
    setOwn(node, keys[keys.length - 1], value);
  }
  return root;
}

const NUMBER_RE = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;
const TRUE_WORDS = new Set(["true", "yes", "y", "on", "1"]);
const FALSE_WORDS = new Set(["false", "no", "n", "off", "0"]);

export type Coerced = { value: JsonValue | undefined } | { error: string };

/** A cell as the type its column is set to. `value: undefined` leaves the key out of the
 *  document: an empty cell has no value rather than an empty one, except as a `string`.
 *
 *  `auto` only converts what reads back the same: `42`, `-1.5`, `true`, `false`. A number
 *  with a leading zero (`007`, a serial or a postcode) or beyond what a double holds
 *  exactly stays text. Non-string cells (JSON/YAML values) pass through `auto` untouched. */
export function coerceCell(cell: JsonValue | undefined, type: ColumnType): Coerced {
  if (cell === undefined) return { value: undefined };
  if (typeof cell !== "string") {
    switch (type) {
      case "auto":
        return { value: cell };
      case "string":
        if (cell === null) return { value: undefined };
        return { value: typeof cell === "object" ? JSON.stringify(cell) : String(cell) };
      case "number":
        if (typeof cell === "number" || cell === null) return { value: cell ?? undefined };
        if (typeof cell === "boolean") return { value: cell ? 1 : 0 };
        return { error: "Not a number" };
      case "boolean":
        if (typeof cell === "boolean" || cell === null) return { value: cell ?? undefined };
        if (typeof cell === "number" && (cell === 0 || cell === 1)) return { value: cell === 1 };
        return { error: "Not a boolean" };
    }
  }
  if (type === "string") return { value: cell };
  const t = cell.trim();
  if (t === "") return { value: undefined };
  switch (type) {
    case "auto": {
      if (t === "true") return { value: true };
      if (t === "false") return { value: false };
      if (NUMBER_RE.test(t)) {
        const n = Number(t);
        const exact = !/^-?\d+$/.test(t) || Number.isSafeInteger(n);
        if (Number.isFinite(n) && exact) return { value: n };
      }
      return { value: cell };
    }
    case "number": {
      const n = Number(t);
      if (!Number.isFinite(n) || !/^[-+]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(t)) {
        return { error: `"${truncate(t)}" is not a number` };
      }
      return { value: n };
    }
    case "boolean": {
      const l = t.toLowerCase();
      if (TRUE_WORDS.has(l)) return { value: true };
      if (FALSE_WORDS.has(l)) return { value: false };
      return { error: `"${truncate(t)}" is not a boolean` };
    }
  }
}

const truncate = (s: string) => (s.length > 40 ? `${s.slice(0, 40)}…` : s);

/** A cell as key text: what the server normalizes and compares. */
export function keyText(cell: JsonValue | undefined): string {
  if (cell === undefined || cell === null) return "";
  if (typeof cell === "string") return cell;
  if (typeof cell === "object") return JSON.stringify(cell);
  return String(cell);
}

/** How one column is mapped. `target` is the dotted path in the stored document. */
export type ColumnMapping = {
  include: boolean;
  target: string;
  type: ColumnType;
};

export type CellError = { row: number; column: number; message: string };

/** The documents the mapped table produces, one per row, and every cell that would not
 *  coerce (capped, so a wrongly typed column does not produce 10,000 messages). */
export function buildDocuments(
  table: Table,
  mapping: ColumnMapping[],
  maxErrors = 50,
): { documents: JsonObject[]; errors: CellError[]; errorCount: number } {
  const errors: CellError[] = [];
  let errorCount = 0;
  const used = mapping
    .map((m, i) => ({ ...m, i }))
    .filter((m) => m.include && targetPathError(m.target) === null);
  const documents = table.rows.map((row, r) => {
    const entries: [string, JsonValue][] = [];
    for (const m of used) {
      const c = coerceCell(row[m.i], m.type);
      if ("error" in c) {
        errorCount++;
        if (errors.length < maxErrors) errors.push({ row: r, column: m.i, message: c.error });
      } else if (c.value !== undefined) {
        entries.push([m.target, c.value]);
      }
    }
    return unflatten(entries);
  });
  return { documents, errors, errorCount };
}

// --- import name -----------------------------------------------------------------------

/** Longest import name: the server stores `import:<name>` under a 64-character limit. */
export const MAX_IMPORT_NAME_LEN = 64 - "import:".length;

/** Why `name` cannot name an import, or null when it can. Mirrors `valid_source` in
 *  crates/core/src/facts.rs, less the `:` the prefix already uses. */
export function importNameError(name: string): string | null {
  if (name === "") return "Required";
  if (name.length > MAX_IMPORT_NAME_LEN) return `At most ${MAX_IMPORT_NAME_LEN} characters`;
  if (!/^[a-z][a-z0-9_.-]*$/.test(name)) {
    return "Lowercase letters, digits, _ . - only, starting with a letter";
  }
  return null;
}

/** A default import name from a file name: `CMDB Export 2026.csv` → `cmdb_export_2026`. */
export function suggestImportName(fileName: string): string {
  const base = fileName
    .replace(/\.[^.]+$/, "")
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, "_")
    .replace(/^[^a-z]+/, "")
    .replace(/_+$/, "")
    .slice(0, MAX_IMPORT_NAME_LEN);
  return base || "import";
}
