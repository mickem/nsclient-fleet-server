// What a host's configuration comes to: its bundles' config.json fragments and its host
// override, layered the way the agent layers them (JSON Merge Patch, RFC 7396), with each
// setting remembering where it came from and what it replaced.
//
// The agent renders the result to fleet.ini: nested objects become "/"-joined section
// paths, leaves become `key=value`. Rows here use the same section/key split, so what the
// table shows is what lands in the file.

import { type ConfigObject, iniToJson, jsonToIni } from "./ini";

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

/** Split a stored override into what the editor shows: its values as INI text, and its
 *  removals as a list (INI has no way to say "delete this key"). */
export function splitOverride(patch: ConfigObject): { ini: string; removals: Removal[] } {
  const removals: Removal[] = [];
  const walk = (node: ConfigObject, path: string[]) => {
    for (const [k, v] of Object.entries(node)) {
      if (v === null) removals.push([...path, k]);
      else if (isObject(v)) walk(v, [...path, k]);
    }
  };
  walk(patch, []);
  return { ini: jsonToIni(patch), removals };
}

/** The editor's INI text and removals back into one merge patch. A removal of a path the
 *  INI also sets is dropped: the value is the more specific instruction. Throws
 *  `IniParseError` for text that does not parse. */
export function joinOverride(ini: string, removals: Removal[]): ConfigObject {
  const patch = iniToJson(ini);
  for (const r of removals) {
    let node: ConfigObject = patch;
    let blocked = false;
    for (const segment of r.slice(0, -1)) {
      const next = node[segment];
      if (next === undefined) {
        const child: ConfigObject = {};
        node[segment] = child;
        node = child;
      } else if (isObject(next)) {
        node = next;
      } else {
        blocked = true;
        break;
      }
    }
    const last = r[r.length - 1];
    if (!blocked && node[last] === undefined) node[last] = null;
  }
  return patch;
}

export const sameRemoval = (a: Removal, b: Removal) =>
  a.length === b.length && a.every((s, i) => s === b[i]);

/** The removal that deletes one row's key. */
export function removalFor(section: string, key: string): Removal {
  return [...section.split("/").filter((s) => s !== ""), key];
}
