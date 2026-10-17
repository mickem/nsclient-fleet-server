import { getIniValue, listIniKeys, removeIniKey, renameIniKey, setIniValue } from "../ini";
import { type BundleTemplate, type TablePreset, type TemplateField } from "./types";

/** Entry names must be safe as INI keys and settings-path segments, and must not shadow
 *  the scheduler's `default` subsection. */
export const TABLE_KEY_RE = /^[A-Za-z0-9_-]{1,64}$/;

export function validTableKey(key: string): boolean {
  return TABLE_KEY_RE.test(key) && key !== "default";
}

/** Whether `key` is acceptable as an entry name of this table (see `keyPattern`). */
export function validTableRowKey(f: TemplateField & { kind: "table" }, key: string): boolean {
  return f.keyPattern ? f.keyPattern.test(key) : validTableKey(key);
}

/** Whether `value` is acceptable in this table (see `valuePattern`). */
export function validTableRowValue(f: TemplateField & { kind: "table" }, value: string): boolean {
  return f.valuePattern ? f.valuePattern.test(value) : true;
}

/** Current value of a field as read from the INI text ("" when absent / no match). */
export function fieldValue(ini: string, f: TemplateField): string {
  if (f.kind === "table" || f.kind === "facts") return "";
  if (f.kind === "choice") {
    const match = f.options.find((o) =>
      Object.entries(o.set).every(([section, kv]) =>
        Object.entries(kv).every(([k, v]) => (getIniValue(ini, section, k) ?? "") === v),
      ),
    );
    return match?.value ?? "";
  }
  const raw = getIniValue(ini, f.section, f.key);
  if (raw !== undefined) return raw;
  if (f.kind === "bool") return f.default ? "true" : "false";
  if (f.kind === "select") return f.default;
  return "";
}

/** Whether a key-bound field's key exists in the document (optional fields' switch). */
export function fieldPresent(ini: string, f: TemplateField): boolean {
  return (
    f.kind !== "choice" &&
    f.kind !== "table" &&
    f.kind !== "facts" &&
    getIniValue(ini, f.section, f.key) !== undefined
  );
}

/** Default written when a field appears or is switched on: the explicit default, else
 *  whatever the template's base INI carries for that key. */
export function fieldDefault(t: BundleTemplate, f: TemplateField): string {
  if (f.kind === "choice" || f.kind === "table" || f.kind === "facts") return "";
  if (f.kind === "bool") return f.default ? "true" : "false";
  if (f.kind === "select") return f.default;
  return f.default ?? getIniValue(t.ini, f.section, f.key) ?? "";
}

export function fieldVisible(ini: string, t: BundleTemplate, f: TemplateField): boolean {
  if (!f.when) return true;
  const parent = t.fields.find((x) => x.id === f.when!.field);
  if (!parent) return true;
  // Visibility chains: a hidden parent hides its dependents too (declaration order
  // forbids cycles). Otherwise a hidden select's default would leak dependents in.
  if (!fieldVisible(ini, t, parent)) return false;
  const v = fieldValue(ini, parent);
  if (f.when.notEmpty) return v.trim() !== "";
  return f.when.in?.includes(v) ?? true;
}

/** Apply one field edit to the INI text, then reconcile conditional fields: keys of
 *  fields that just became hidden are removed, fields that just became visible get
 *  their default written. Returns the new INI document. */
export function applyFieldChange(
  ini: string,
  t: BundleTemplate,
  f: TemplateField,
  value: string,
): string {
  const wasVisible = new Map(t.fields.map((x) => [x.id, fieldVisible(ini, t, x)]));

  let next = ini;
  if (f.kind === "table" || f.kind === "facts") {
    // Rows and fact sets are edited through their own helpers, not as one value.
    return ini;
  } else if (f.kind === "choice") {
    const opt = f.options.find((o) => o.value === value);
    if (opt) {
      for (const [section, kv] of Object.entries(opt.set)) {
        for (const [k, v] of Object.entries(kv)) next = setIniValue(next, section, k, v);
      }
    }
  } else if (value.trim() === "" && (f.kind === "text" || f.kind === "select")) {
    // Empty text, or an optional select switched off: the key leaves the document.
    next = removeIniKey(next, f.section, f.key);
  } else {
    next = setIniValue(next, f.section, f.key, value);
  }

  for (const field of t.fields) {
    if (!field.when || field.kind === "choice" || field.kind === "table" || field.kind === "facts") {
      continue;
    }
    const visible = fieldVisible(next, t, field);
    const present = getIniValue(next, field.section, field.key) !== undefined;
    if (!visible && present) {
      next = removeIniKey(next, field.section, field.key);
    } else if (visible && !wasVisible.get(field.id) && !present) {
      const def = fieldDefault(t, field);
      if (def !== "") next = setIniValue(next, field.section, field.key, def);
    }
  }
  return next;
}

// --- table field row operations (each returns the new INI document) ---

export function tableRows(ini: string, f: TemplateField & { kind: "table" }) {
  return listIniKeys(ini, f.section);
}

/** Insert a preset (or a blank custom row), deduplicating the name with a numeric
 *  suffix (or, for `uniqueKeys` tables, leaving the document alone) and enabling any
 *  modules the check needs. */
export function tableAddRow(
  ini: string,
  f: TemplateField & { kind: "table" },
  preset: TablePreset,
): string {
  const existing = new Set(listIniKeys(ini, f.section).map((r) => r.key));
  let key = preset.key;
  if (f.uniqueKeys && existing.has(key)) return ini;
  for (let n = 2; existing.has(key); n++) key = `${preset.key}_${n}`;
  let next = setIniValue(ini, f.section, key, preset.value);
  for (const m of preset.modules ?? []) next = setIniValue(next, "/modules", m, "enabled");
  return next;
}

export function tableRenameRow(
  ini: string,
  f: TemplateField & { kind: "table" },
  oldKey: string,
  newKey: string,
): string {
  const key = newKey.trim();
  if (key === oldKey || !validTableRowKey(f, key)) return ini;
  if (listIniKeys(ini, f.section).some((r) => r.key === key)) return ini;
  return renameIniKey(ini, f.section, oldKey, key);
}

export function tableSetRow(
  ini: string,
  f: TemplateField & { kind: "table" },
  key: string,
  value: string,
): string {
  return setIniValue(ini, f.section, key, value);
}

export function tableRemoveRow(
  ini: string,
  f: TemplateField & { kind: "table" },
  key: string,
): string {
  return removeIniKey(ini, f.section, key);
}
