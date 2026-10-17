import { describe, expect, it } from "vitest";
import {
  buildDocuments,
  coerceCell,
  csvToTable,
  detectDelimiter,
  detectFormat,
  extractRecords,
  flattenRecord,
  importNameError,
  JsonObject,
  keyText,
  parseCsv,
  readTable,
  recordsToTable,
  sniffFormat,
  suggestImportName,
  suggestTarget,
  targetConflicts,
  targetPathError,
  unflatten,
} from "./parse";

describe("parseCsv", () => {
  it("splits plain fields and records", () => {
    expect(parseCsv("a,b,c\n1,2,3\n", ",")).toEqual([
      ["a", "b", "c"],
      ["1", "2", "3"],
    ]);
  });

  it("handles quoted fields with delimiters and escaped quotes", () => {
    expect(parseCsv('name,note\n"Smith, J","said ""hi"""\n', ",")).toEqual([
      ["name", "note"],
      ["Smith, J", 'said "hi"'],
    ]);
  });

  it("keeps line breaks inside quotes", () => {
    expect(parseCsv('a,b\n"line1\nline2",x\r\n"cr\r\nlf",y', ",")).toEqual([
      ["a", "b"],
      ["line1\nline2", "x"],
      ["cr\r\nlf", "y"],
    ]);
  });

  it("treats CRLF, LF and CR as record ends and skips blank lines", () => {
    expect(parseCsv("a,b\r\n1,2\r\n\r\n3,4\r5,6\r\n", ",")).toEqual([
      ["a", "b"],
      ["1", "2"],
      ["3", "4"],
      ["5", "6"],
    ]);
  });

  it("keeps empty fields, including trailing ones", () => {
    expect(parseCsv("a,,c,\n,,,\n", ",")).toEqual([
      ["a", "", "c", ""],
      ["", "", "", ""],
    ]);
  });

  it("strips a BOM and handles no trailing newline", () => {
    expect(parseCsv("﻿x;y\n1;2", ";")).toEqual([
      ["x", "y"],
      ["1", "2"],
    ]);
  });

  it("reads an empty quoted field as a record", () => {
    expect(parseCsv('""\n', ",")).toEqual([[""]]);
  });
});

describe("detectDelimiter", () => {
  it("detects comma, semicolon, tab and pipe", () => {
    expect(detectDelimiter("a,b,c\n1,2,3\n")).toBe(",");
    expect(detectDelimiter("a;b;c\n1;2,5;3\n")).toBe(";");
    expect(detectDelimiter("a\tb\n1\t2\n")).toBe("\t");
    expect(detectDelimiter("a|b|c|d\n1|2|3|4\n")).toBe("|");
  });

  it("ignores delimiters inside quotes", () => {
    expect(detectDelimiter('a;b\n"1,2,3,4";x\n"5,6,7,8";y\n')).toBe(";");
  });

  it("falls back to comma for a single column", () => {
    expect(detectDelimiter("hostname\nweb-01\n")).toBe(",");
  });
});

describe("csvToTable", () => {
  const records = [
    ["host", "", "host"],
    ["a", "b", "c"],
    ["d"],
  ];

  it("names columns from the header, filling blanks and repeats", () => {
    const t = csvToTable(records, true);
    expect(t.columns).toEqual(["host", "col2", "host_2"]);
    expect(t.rows).toEqual([
      ["a", "b", "c"],
      ["d", "", ""],
    ]);
  });

  it("names columns col1..N without a header", () => {
    const t = csvToTable(records, false);
    expect(t.columns).toEqual(["col1", "col2", "col3"]);
    expect(t.rows).toHaveLength(3);
    expect(t.rows[0]).toEqual(["host", "", "host"]);
  });
});

describe("format detection", () => {
  it("goes by extension first", () => {
    expect(detectFormat("x.csv", "{}")).toBe("csv");
    expect(detectFormat("x.JSON", "a,b")).toBe("json");
    expect(detectFormat("x.yml", "a,b")).toBe("yaml");
  });

  it("sniffs content otherwise", () => {
    expect(sniffFormat('  [{"a":1}]')).toBe("json");
    expect(sniffFormat("- a: 1\n- a: 2\n")).toBe("yaml");
    expect(sniffFormat("hosts:\n  web: {ip: 1}\n")).toBe("yaml");
    expect(sniffFormat("a,b\n1,2\n")).toBe("csv");
    expect(detectFormat("export.txt", "a;b\n1;2")).toBe("csv");
  });
});

describe("extractRecords", () => {
  it("(a) accepts an array of objects", () => {
    const r = extractRecords([{ a: 1 }, { a: 2 }]);
    expect(r.records).toEqual([{ a: 1 }, { a: 2 }]);
    expect(r.note).toBeUndefined();
  });

  it("(a) refuses an array of scalars", () => {
    expect(() => extractRecords([1, 2])).toThrow();
  });

  it("(b) turns an object of objects into records with _key", () => {
    const r = extractRecords({ web: { ip: "1" }, db: { ip: "2" } });
    expect(r.records).toEqual([
      { _key: "web", ip: "1" },
      { _key: "db", ip: "2" },
    ]);
    expect(Object.keys(r.records[0])[0]).toBe("_key");
  });

  it("(c) picks the single array-of-objects member", () => {
    const r = extractRecords({ meta: { v: 1 }, total: 2, hosts: [{ a: 1 }, { a: 2 }] });
    expect(r.records).toEqual([{ a: 1 }, { a: 2 }]);
    expect(r.note).toContain("hosts");
  });

  it("(c) refuses several candidate arrays", () => {
    expect(() => extractRecords({ a: [{ x: 1 }], b: [{ y: 1 }] })).toThrow(/several/);
  });

  it("refuses scalars", () => {
    expect(() => extractRecords("x")).toThrow();
    expect(() => extractRecords({ a: 1 })).toThrow();
  });
});

describe("readTable", () => {
  it("reads YAML into a flattened table", () => {
    const r = readTable("- name: web\n  hw:\n    cpu: 4\n- name: db\n  tags: [a, b]\n", {
      format: "yaml",
      delimiter: "auto",
      header: true,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.table.columns).toEqual(["name", "hw.cpu", "tags"]);
    expect(r.table.rows).toEqual([
      ["web", 4, undefined],
      ["db", undefined, ["a", "b"]],
    ]);
  });

  it("reads CSV with an auto delimiter and reports it", () => {
    const r = readTable("a;b\n1;2\n", { format: "csv", delimiter: "auto", header: true });
    expect(r.ok && r.delimiter).toBe(";");
    expect(r.ok && r.table.rows).toEqual([["1", "2"]]);
  });

  it("reports a parse error", () => {
    const r = readTable("{nope", { format: "json", delimiter: "auto", header: true });
    expect(r.ok).toBe(false);
  });
});

describe("flatten / unflatten", () => {
  it("round trips nested records", () => {
    const rec: JsonObject = {
      name: "web",
      hw: { cpu: { cores: 4, model: "x" }, ram: 8 },
      list: [1, { a: 2 }],
      empty: {},
      nil: null,
    };
    const flat = flattenRecord(rec);
    expect(flat.map(([p]) => p)).toEqual([
      "name",
      "hw.cpu.cores",
      "hw.cpu.model",
      "hw.ram",
      "list",
      "empty",
      "nil",
    ]);
    expect(unflatten(flat)).toEqual(rec);
  });

  it("treats __proto__ as a plain key", () => {
    const doc = unflatten([["__proto__.x", 1]]);
    expect(Object.prototype.hasOwnProperty.call(doc, "__proto__")).toBe(true);
    expect(JSON.stringify(doc)).toBe('{"__proto__":{"x":1}}');
    expect(({} as Record<string, unknown>).x).toBeUndefined();
  });

  it("builds a table whose columns follow first appearance", () => {
    const t = recordsToTable([{ b: 1 }, { a: { c: 2 }, b: 3 }]);
    expect(t.columns).toEqual(["b", "a.c"]);
    expect(t.rows).toEqual([
      [1, undefined],
      [3, 2],
    ]);
  });
});

describe("coerceCell", () => {
  it("auto converts numbers and booleans that read back the same", () => {
    expect(coerceCell("42", "auto")).toEqual({ value: 42 });
    expect(coerceCell(" -1.5 ", "auto")).toEqual({ value: -1.5 });
    expect(coerceCell("1e3", "auto")).toEqual({ value: 1000 });
    expect(coerceCell("true", "auto")).toEqual({ value: true });
    expect(coerceCell("false", "auto")).toEqual({ value: false });
  });

  it("auto keeps text that only looks numeric", () => {
    expect(coerceCell("007", "auto")).toEqual({ value: "007" });
    expect(coerceCell("12345678901234567890", "auto")).toEqual({ value: "12345678901234567890" });
    expect(coerceCell("1.2.3", "auto")).toEqual({ value: "1.2.3" });
    expect(coerceCell("True", "auto")).toEqual({ value: "True" });
  });

  it("omits empty cells except as string", () => {
    expect(coerceCell("", "auto")).toEqual({ value: undefined });
    expect(coerceCell("  ", "number")).toEqual({ value: undefined });
    expect(coerceCell("", "boolean")).toEqual({ value: undefined });
    expect(coerceCell("", "string")).toEqual({ value: "" });
    expect(coerceCell(undefined, "string")).toEqual({ value: undefined });
  });

  it("string keeps text verbatim and stringifies values", () => {
    expect(coerceCell(" 42 ", "string")).toEqual({ value: " 42 " });
    expect(coerceCell(42, "string")).toEqual({ value: "42" });
    expect(coerceCell(true, "string")).toEqual({ value: "true" });
  });

  it("number and boolean refuse what does not fit", () => {
    expect(coerceCell("3.5", "number")).toEqual({ value: 3.5 });
    expect(coerceCell("007", "number")).toEqual({ value: 7 });
    expect("error" in coerceCell("abc", "number")).toBe(true);
    expect(coerceCell("Yes", "boolean")).toEqual({ value: true });
    expect(coerceCell("0", "boolean")).toEqual({ value: false });
    expect("error" in coerceCell("maybe", "boolean")).toBe(true);
    expect("error" in coerceCell("x", "number")).toBe(true);
  });

  it("auto passes non-string values through", () => {
    expect(coerceCell(3, "auto")).toEqual({ value: 3 });
    expect(coerceCell(["a"], "auto")).toEqual({ value: ["a"] });
    expect(coerceCell(null, "auto")).toEqual({ value: null });
  });
});

describe("mapping helpers", () => {
  it("validates target paths like the selector grammar", () => {
    expect(targetPathError("cmdb.owner")).toBeNull();
    expect(targetPathError("Serial Number")).toBeNull();
    expect(targetPathError("")).not.toBeNull();
    expect(targetPathError("a..b")).not.toBeNull();
    expect(targetPathError(".a")).not.toBeNull();
    expect(targetPathError("a.")).not.toBeNull();
    expect(targetPathError("a[b]")).not.toBeNull();
    expect(targetPathError("x".repeat(513))).not.toBeNull();
  });

  it("suggests usable targets", () => {
    expect(suggestTarget(" Serial Number ")).toBe("Serial_Number");
    expect(suggestTarget("a..b.")).toBe("a.b");
    expect(suggestTarget("x[1]")).toBe("x_1_");
  });

  it("finds colliding targets", () => {
    const c = targetConflicts(["a", "a.b", "c", "c", "d"]);
    expect([...c.keys()].sort()).toEqual([0, 1, 2, 3]);
    expect(targetConflicts(["ab", "a.b"]).size).toBe(0);
  });

  it("builds nested documents and reports bad cells", () => {
    const table = { columns: ["host", "owner", "cpu", "ok"], rows: [["web", "ann", "4", "x"]] };
    const { documents, errors, errorCount } = buildDocuments(table, [
      { include: false, target: "host", type: "auto" },
      { include: true, target: "cmdb.owner", type: "string" },
      { include: true, target: "cmdb.cpu", type: "number" },
      { include: true, target: "ok", type: "boolean" },
    ]);
    expect(documents).toEqual([{ cmdb: { owner: "ann", cpu: 4 } }]);
    expect(errorCount).toBe(1);
    expect(errors[0]).toMatchObject({ row: 0, column: 3 });
  });

  it("renders key text", () => {
    expect(keyText(undefined)).toBe("");
    expect(keyText(42)).toBe("42");
    expect(keyText("ABC")).toBe("ABC");
  });
});

describe("import names", () => {
  it("mirrors valid_source without ':'", () => {
    expect(importNameError("cmdb")).toBeNull();
    expect(importNameError("cmdb_2026.v1-a")).toBeNull();
    expect(importNameError("")).not.toBeNull();
    expect(importNameError("Cmdb")).not.toBeNull();
    expect(importNameError("1cmdb")).not.toBeNull();
    expect(importNameError("a:b")).not.toBeNull();
    expect(importNameError("a".repeat(57))).toBeNull();
    expect(importNameError("a".repeat(58))).not.toBeNull();
  });

  it("suggests a name from the file name", () => {
    expect(suggestImportName("CMDB Export 2026.csv")).toBe("cmdb_export_2026");
    expect(suggestImportName("2026.json")).toBe("import");
  });
});
