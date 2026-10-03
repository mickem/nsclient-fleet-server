// Wizard-level model for the facts import: how columns are mapped, the key target options,
// and turning a mapped table into the request body the server takes. Pure, like parse.ts.

import type {
  HostView,
  ImportKeyTarget,
  ImportNormalize,
  ImportRequest,
  ImportResolveResponse,
  ImportRowResult,
  ImportRowStatus,
} from "../api";
import type { KnownFacts } from "../SelectorBuilder";
import { ColumnMapping, JsonObject, keyText, suggestTarget, Table } from "./parse";

/** `MAX_IMPORT_ROWS` on the server. */
export const MAX_IMPORT_ROWS = 10_000;
/** Most key columns one import may match on. */
export const MAX_KEYS = 4;

export const DEFAULT_NORMALIZE: ImportNormalize = {
  trim: true,
  case_insensitive: true,
  short_hostname: false,
};

/** How one column of the table is used: as a value in the document (`include`), as a key
 *  to find the host (`key`), or both. */
export type MapColumn = ColumnMapping & {
  key: boolean;
  /** What the key is matched against; null until chosen. */
  keyTarget: ImportKeyTarget | null;
};

export const keyTargetId = (t: ImportKeyTarget): string =>
  t.kind === "host" ? `host:${t.field}` : t.kind === "tag" ? `tag:${t.key}` : `fact:${t.source}:${t.path}`;

export function keyTargetLabel(t: ImportKeyTarget): string {
  switch (t.kind) {
    case "host":
      return t.field === "id" ? "Host ID" : "Hostname";
    case "tag":
      return `tag ${t.key}`;
    case "fact":
      return `${t.source}: ${t.path}`;
  }
}

export type KeyOption = {
  group: "Host fields" | "Tags" | "Facts";
  target: ImportKeyTarget;
  label: string;
  /** Host count, when known. */
  hosts?: number;
};

/** Everything a key column can be matched against: the host fields, every tag key the
 *  fleet carries, and every scalar fact path of every source in the catalog. */
export function keyOptions(hosts: HostView[], facts: KnownFacts | null): KeyOption[] {
  const out: KeyOption[] = [
    { group: "Host fields", target: { kind: "host", field: "hostname" }, label: "Hostname" },
    { group: "Host fields", target: { kind: "host", field: "id" }, label: "Host ID" },
  ];
  const tagHosts = new Map<string, Set<string>>();
  for (const h of hosts) {
    for (const t of h.tags) {
      let s = tagHosts.get(t.key);
      if (!s) tagHosts.set(t.key, (s = new Set()));
      s.add(h.id);
    }
  }
  for (const key of [...tagHosts.keys()].sort()) {
    out.push({
      group: "Tags",
      target: { kind: "tag", key },
      label: key,
      hosts: tagHosts.get(key)!.size,
    });
  }
  for (const [source, { paths }] of facts ?? []) {
    for (const p of [...paths.values()].sort((a, b) => a.path.localeCompare(b.path))) {
      if (p.kind !== "scalar") continue;
      out.push({
        group: "Facts",
        target: { kind: "fact", source, path: p.path },
        label: `${source}: ${p.path}`,
        hosts: p.hosts,
      });
    }
  }
  return out;
}

/** A first guess at what a key column matches, by its name. */
export function guessKeyTarget(column: string, options: KeyOption[]): ImportKeyTarget {
  const n = column.trim().toLowerCase();
  if (n === "id" || n === "host_id" || n === "hostid") return { kind: "host", field: "id" };
  const tag = options.find((o) => o.target.kind === "tag" && o.target.key.toLowerCase() === n);
  if (tag) return tag.target;
  const fact = options.find(
    (o) => o.target.kind === "fact" && o.target.path.toLowerCase() === n,
  );
  if (fact) return fact.target;
  return { kind: "host", field: "hostname" };
}

const HOSTNAME_NAMES = new Set(["hostname", "host", "host_name", "fqdn", "name", "computer", "computername", "server", "_key"]);

/** The starting mapping for a freshly read table: every column included under a suggested
 *  path, typed `auto`, and the first column that looks like a host name as the key. */
export function defaultMapping(table: Table, options: KeyOption[]): MapColumn[] {
  const keyIndex = Math.max(
    0,
    table.columns.findIndex((c) => HOSTNAME_NAMES.has(c.trim().toLowerCase())),
  );
  return table.columns.map((c, i) => ({
    include: true,
    target: suggestTarget(c),
    type: "auto",
    key: i === keyIndex,
    keyTarget: i === keyIndex ? guessKeyTarget(c, options) : null,
  }));
}

/** The request body for a mapped table: keys in column order, one row per table row. */
export function buildRequest(
  name: string,
  table: Table,
  mapping: MapColumn[],
  documents: JsonObject[],
  normalize: ImportNormalize,
  overrides: Record<number, string>,
  collectedAt: string | undefined,
  skip: ReadonlySet<number> = new Set(),
): ImportRequest {
  const keyCols = mapping.flatMap((m, i) => (m.key && m.keyTarget ? [i] : []));
  return {
    name,
    keys: keyCols.map((i) => mapping[i].keyTarget!),
    normalize,
    ...(collectedAt ? { collected_at: collectedAt } : {}),
    rows: table.rows.map((row, r) => ({
      keys: keyCols.map((i) => keyText(row[i])),
      facts: documents[r],
      ...(overrides[r] ? { host_id: overrides[r] } : {}),
    })),
    skip: [...skip].sort((a, b) => a - b),
  };
}

/** Whether a row, as the server resolved it, makes a commit refuse: anything neither
 *  matched nor skipped. Skips are sent with the resolve, so a fresh result already says
 *  which rows are skipped and what that did to duplicates. */
export const isBlocking = (r: ImportRowResult): boolean => r.status !== "matched" && r.status !== "skipped";

/** Rows that would make the server refuse a commit. */
export function blockingRows(res: ImportResolveResponse): number[] {
  return res.rows.filter(isBlocking).map((r) => r.index);
}

/** A resolve result with some rows replaced (from a 409), its stats recounted. */
export function mergeRows(res: ImportResolveResponse, rows: ImportRowResult[]): ImportResolveResponse {
  const byIndex = new Map(rows.map((r) => [r.index, r]));
  const merged = res.rows.map((r) => byIndex.get(r.index) ?? r);
  const stats: Record<ImportRowStatus, number> = {
    matched: 0,
    ambiguous: 0,
    unmatched: 0,
    duplicate: 0,
    skipped: 0,
  };
  for (const r of merged) stats[r.status]++;
  return { ...res, rows: merged, stats };
}
