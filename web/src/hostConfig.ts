// What a host's configuration comes to: its bundles' config.json fragments and its host
// override, layered the way the agent layers them (JSON Merge Patch, RFC 7396), with each
// setting remembering where it came from and what it replaced.
//
// The agent renders the result to fleet.ini: nested objects become "/"-joined section
// paths, leaves become `key=value`. Rows here use the same section/key split, so what the
// table shows is what lands in the file.

import { type ConfigObject } from "./ini";

/** One input to the layering: a bundle's config fragment, or the host override. */
export type Layer = {
  id: string;
  /** "base@1.2.0" for a bundle, "host override" for the override. */
  label: string;
  kind: "bundle" | "override";
  config: ConfigObject;
};

export type Provenance = { value: string; layer: Layer };

export type EffectiveRow = {
  /** Canonical section path, "/settings/mysql" ("/" for the root). */
  section: string;
  key: string;
  /** The value in force, or null when a layer removed the key. */
  value: string | null;
  /** The layer that set the value — or removed it. */
  layer: Layer;
  /** Values this one replaced, oldest first. */
  replaced: Provenance[];
};

/** How the agent renders a leaf (mirrors `formatValue` in ini.ts). */
function render(v: unknown): string {
  if (typeof v === "string") return v;
  if (typeof v === "boolean") return v ? "true" : "false";
  if (Array.isArray(v)) return v.map(render).join(",");
  return JSON.stringify(v);
}

const isObject = (v: unknown): v is ConfigObject =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const rowId = (section: string, key: string) => `${section}\u0000${key}`;
const sectionOf = (segments: string[]) => "/" + segments.join("/");

/** Layer `layers` in order, later winning. A `null` leaf removes that key or, when it
 *  names a section, everything under it — exactly as a merge patch does. Removals made by
 *  the host override are kept as rows (value null) so they can be shown; a bundle that
 *  removes something simply makes it go away. */
export function layerConfigs(layers: Layer[]): EffectiveRow[] {
  const rows = new Map<string, EffectiveRow>();

  const removeUnder = (segments: string[], layer: Layer) => {
    const section = sectionOf(segments);
    const parent = sectionOf(segments.slice(0, -1));
    const key = segments[segments.length - 1];
    for (const [id, row] of rows) {
      const hit =
        (row.section === parent && row.key === key) ||
        row.section === section ||
        row.section.startsWith(section + "/");
      if (!hit) continue;
      if (layer.kind === "override" && row.value !== null) {
        rows.set(id, {
          ...row,
          value: null,
          layer,
          replaced: [...row.replaced, { value: row.value, layer: row.layer }],
        });
      } else {
        rows.delete(id);
      }
    }
    // A removal of something nothing set is still worth showing for the override: it is a
    // line in the override that currently does nothing.
    if (layer.kind === "override" && !rows.has(rowId(parent, key)) && ![...rows.values()].some(
      (r) => r.section === section || r.section.startsWith(section + "/"),
    )) {
      rows.set(rowId(parent, key), { section: parent, key, value: null, layer, replaced: [] });
    }
  };

  const walk = (node: ConfigObject, path: string[], layer: Layer) => {
    for (const [k, v] of Object.entries(node)) {
      const segments = [...path, k];
      if (v === null) {
        removeUnder(segments, layer);
      } else if (isObject(v)) {
        walk(v, segments, layer);
      } else {
        const section = sectionOf(path);
        // A removal row standing for a whole section stops meaning anything once a later
        // layer sets something inside it again.
        for (const [id, row] of rows) {
          const removed = (row.section === "/" ? "" : row.section) + "/" + row.key;
          if (row.value === null && (section === removed || section.startsWith(removed + "/"))) {
            rows.delete(id);
          }
        }
        const id = rowId(section, k);
        const prev = rows.get(id);
        const replaced = prev
          ? prev.value === null
            ? prev.replaced
            : [...prev.replaced, { value: prev.value, layer: prev.layer }]
          : [];
        rows.set(id, { section, key: k, value: render(v), layer, replaced });
      }
    }
  };

  for (const layer of layers) walk(layer.config, [], layer);
  return [...rows.values()].sort(
    (a, b) => a.section.localeCompare(b.section) || a.key.localeCompare(b.key),
  );
}

/** A path the override removes: the segments of a `null` leaf. */
export type Removal = string[];

export const removalLabel = (r: Removal) => sectionOf(r.slice(0, -1)) + " · " + r[r.length - 1];

/** Every path a merge patch removes: the segments of each `null` leaf. */
export function removalsOf(patch: ConfigObject): Removal[] {
  const out: Removal[] = [];
  const walk = (node: ConfigObject, path: string[]) => {
    for (const [k, v] of Object.entries(node)) {
      if (v === null) out.push([...path, k]);
      else if (isObject(v)) walk(v, [...path, k]);
    }
  };
  walk(patch, []);
  return out;
}

/** The settings rows put in force, as one config document (removals left out). */
export function configFromRows(rows: EffectiveRow[]): ConfigObject {
  const out: ConfigObject = {};
  for (const r of rows) {
    if (r.value === null) continue;
    const path = removalFor(r.section, r.key);
    let node = out;
    for (const segment of path.slice(0, -1)) {
      const next = node[segment];
      if (!isObject(next)) node[segment] = {};
      node = node[segment] as ConfigObject;
    }
    node[path[path.length - 1]] = r.value;
  }
  return out;
}

/** Leaves of a config document by row id, values rendered as the agent writes them. */
function leaves(config: ConfigObject): Map<string, { path: Removal; value: string }> {
  const out = new Map<string, { path: Removal; value: string }>();
  const walk = (node: ConfigObject, path: string[]) => {
    for (const [k, v] of Object.entries(node)) {
      if (v === null) continue;
      if (isObject(v)) walk(v, [...path, k]);
      else out.set(rowId(sectionOf(path), k), { path: [...path, k], value: render(v) });
    }
  };
  walk(config, []);
  return out;
}

/** Drop objects left with nothing in them. An empty object in a merge patch changes
 *  nothing, but it makes an override that does nothing look like one that does. */
function pruneEmpty(node: ConfigObject): ConfigObject {
  for (const [k, v] of Object.entries(node)) {
    if (isObject(v)) {
      pruneEmpty(v);
      if (Object.keys(v).length === 0) delete node[k];
    }
  }
  return node;
}

const isPrefix = (p: Removal, q: Removal) => p.length <= q.length && p.every((s, i) => s === q[i]);

/** The override that turns `base` (what the host's bundles give it) into `working` (the
 *  configuration as edited): every setting `working` adds or changes, and a removal for
 *  every setting it drops. `{}` means "no override".
 *
 *  `kept` are removals the override already makes. One still in force — nothing under it
 *  set again — is kept as it is, so removing a whole section stays one line rather than
 *  becoming one per key the bundles happen to set today (and keeps removing what they add
 *  there later). Everything else dropped is removed key by key. */
export function overrideDiff(base: ConfigObject, working: ConfigObject, kept: Removal[]): ConfigObject {
  const had = leaves(base);
  const has = leaves(working);
  const patch: ConfigObject = {};
  const put = (path: Removal, value: string | null) => {
    let node = patch;
    for (const segment of path.slice(0, -1)) {
      const next = node[segment];
      if (next === undefined) node[segment] = {};
      else if (!isObject(next)) return; // a removal of a key whose section is set: moot
      node = node[segment] as ConfigObject;
    }
    const last = path[path.length - 1];
    if (node[last] === undefined) node[last] = value;
  };

  for (const [id, w] of has) {
    if (had.get(id)?.value !== w.value) put(w.path, w.value);
  }
  const covered = new Set<string>();
  for (const r of kept) {
    if ([...has.values()].some((w) => isPrefix(r, w.path))) continue;
    put(r, null);
    for (const [id, b] of had) if (isPrefix(r, b.path)) covered.add(id);
  }
  for (const [id, b] of had) {
    if (!has.has(id) && !covered.has(id)) put(b.path, null);
  }
  return pruneEmpty(patch);
}

/** The settings of `base` a removal takes away, as (section, key, value). */
export function removedBy(base: ConfigObject, r: Removal): { section: string; key: string; value: string }[] {
  return [...leaves(base).values()]
    .filter((b) => isPrefix(r, b.path))
    .map((b) => ({ section: sectionOf(b.path.slice(0, -1)), key: b.path[b.path.length - 1], value: b.value }));
}

/** The override with every value blanked, as `GET …/override/shape` returns it. */
export function shapeOf(patch: ConfigObject): ConfigObject {
  const out: ConfigObject = {};
  for (const [k, v] of Object.entries(patch)) {
    out[k] = v === null ? null : isObject(v) ? shapeOf(v) : "";
  }
  return out;
}

export const sameRemoval = (a: Removal, b: Removal) =>
  a.length === b.length && a.every((s, i) => s === b[i]);

/** The removal that deletes one row's key. */
export function removalFor(section: string, key: string): Removal {
  return [...section.split("/").filter((s) => s !== ""), key];
}
