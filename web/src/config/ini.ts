// INI <-> JSON conversion for the bundle config editor.
//
// The mapping mirrors the agent's renderer (nscp libs/onboarding/sync.cpp,
// collect_ini/render_ini): nested JSON objects become "/"-joined section paths,
// leaves become key=value lines, strings render raw, bools as true/false,
// arrays comma-joined. Parsing (INI -> JSON) keeps every value as a string —
// the agent renders values raw, so the final fleet.ini is byte-identical
// whether a value travelled as a JSON string or a native number/bool.

export type ConfigObject = { [key: string]: ConfigValue };
type ConfigValue = ConfigObject | string | number | boolean | null | ConfigValue[];

function formatValue(v: ConfigValue): string {
  if (typeof v === "string") return v;
  if (typeof v === "boolean") return v ? "true" : "false";
  if (Array.isArray(v)) return v.map(formatValue).join(",");
  return JSON.stringify(v);
}

function isObject(v: ConfigValue): v is ConfigObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function jsonToIni(config: ConfigObject): string {
  const sections = new Map<string, Map<string, string>>();

  const collect = (obj: ConfigObject, path: string) => {
    for (const key of Object.keys(obj)) {
      const value = obj[key];
      if (value === null) continue; // merge-patch deletion marker; nothing to show
      if (isObject(value)) {
        collect(value, `${path}/${key}`);
      } else {
        const section = path === "" ? "/" : path;
        if (!sections.has(section)) sections.set(section, new Map());
        sections.get(section)!.set(key, formatValue(value));
      }
    }
  };
  collect(config, "");

  const orderedSections = Array.from(sections.keys()).sort();
  const lines: string[] = [];
  for (const section of orderedSections) {
    if (lines.length > 0) lines.push("");
    lines.push(`[${section}]`);
    const entries = sections.get(section)!;
    for (const key of Array.from(entries.keys()).sort()) {
      lines.push(`${key}=${entries.get(key)}`);
    }
  }
  return lines.join("\n") + (lines.length > 0 ? "\n" : "");
}

export class IniParseError extends Error {
  line: number;
  constructor(line: number, message: string) {
    super(`line ${line}: ${message}`);
    this.line = line;
  }
}

export function iniToJson(text: string): ConfigObject {
  const root: ConfigObject = {};
  // Path segments of the current section; [] = root ("[/]").
  let current: string[] | null = null;

  const sectionObject = (segments: string[], line: number): ConfigObject => {
    let node: ConfigObject = root;
    for (const segment of segments) {
      const existing = node[segment];
      if (existing === undefined) {
        const child: ConfigObject = {};
        node[segment] = child;
        node = child;
      } else if (isObject(existing)) {
        node = existing;
      } else {
        throw new IniParseError(
          line,
          `section path segment "${segment}" collides with a value of the same name`,
        );
      }
    }
    return node;
  };

  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const line = lines[i].trim();
    if (line === "" || line.startsWith(";") || line.startsWith("#")) continue;

    if (line.startsWith("[")) {
      if (!line.endsWith("]")) throw new IniParseError(lineNo, "unterminated section header");
      const header = line.slice(1, -1).trim();
      const segments = header.split("/").filter((s) => s !== "");
      if (segments.some((s) => s.trim() === "")) {
        throw new IniParseError(lineNo, "empty section path segment");
      }
      current = segments;
      sectionObject(segments, lineNo); // materialize even if the section stays empty
      continue;
    }

    const eq = line.indexOf("=");
    if (eq <= 0) {
      throw new IniParseError(lineNo, `expected "key=value" or "[section]"`);
    }
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    if (key === "") throw new IniParseError(lineNo, "empty key");

    const target = sectionObject(current ?? [], lineNo);
    const existing = target[key];
    if (isObject(existing)) {
      throw new IniParseError(lineNo, `key "${key}" collides with a section of the same name`);
    }
    if (existing !== undefined) {
      throw new IniParseError(lineNo, `duplicate key "${key}" in this section`);
    }
    target[key] = value;
  }
  return root;
}

// ---------------------------------------------------------------------------
// Surgical single-key edits on the INI *text*. The template form view uses these
// instead of a parse → re-render round trip so comments, ordering and keys the
// form does not govern survive untouched.

/** Canonical form of a section path: "/a/b" (root = "/"). */
function canonicalSection(path: string): string {
  const segments = path.split("/").filter((s) => s.trim() !== "");
  return "/" + segments.join("/");
}

/** Line classification shared by the helpers below. */
function scanLines(text: string): { lines: string[]; sectionOf: string[] } {
  const lines = text.split(/\r?\n/);
  const sectionOf: string[] = [];
  let current = "/";
  for (const raw of lines) {
    const line = raw.trim();
    if (line.startsWith("[") && line.endsWith("]")) {
      current = canonicalSection(line.slice(1, -1));
    }
    sectionOf.push(current);
  }
  return { lines, sectionOf };
}

function isKeyLine(raw: string, key: string): boolean {
  const line = raw.trim();
  if (line === "" || line.startsWith(";") || line.startsWith("#") || line.startsWith("[")) {
    return false;
  }
  const eq = line.indexOf("=");
  return eq > 0 && line.slice(0, eq).trim() === key;
}

/** Value of `key` in `section`, or undefined when absent. Tolerant of syntax errors
 *  elsewhere in the document — only headers and the requested key line matter. */
export function getIniValue(text: string, section: string, key: string): string | undefined {
  const target = canonicalSection(section);
  const { lines, sectionOf } = scanLines(text);
  for (let i = 0; i < lines.length; i++) {
    if (sectionOf[i] === target && isKeyLine(lines[i], key)) {
      const line = lines[i].trim();
      return line.slice(line.indexOf("=") + 1).trim();
    }
  }
  return undefined;
}

/** Set `key = value` in `section`, replacing an existing line in place, appending to the
 *  section (after its last non-blank line), or appending a new section at the end. */
export function setIniValue(text: string, section: string, key: string, value: string): string {
  const target = canonicalSection(section);
  const { lines, sectionOf } = scanLines(text);
  let sectionSeen = false;
  let lastContentInSection = -1;
  for (let i = 0; i < lines.length; i++) {
    if (sectionOf[i] !== target) continue;
    if (isKeyLine(lines[i], key)) {
      lines[i] = `${key} = ${value}`;
      return lines.join("\n");
    }
    const trimmed = lines[i].trim();
    if (trimmed !== "") {
      sectionSeen = true;
      lastContentInSection = i;
    }
  }
  if (sectionSeen) {
    lines.splice(lastContentInSection + 1, 0, `${key} = ${value}`);
    return lines.join("\n");
  }
  const doc = text.replace(/\n*$/, "");
  const header = target === "/" ? "[/]" : `[${target}]`;
  return `${doc}${doc === "" ? "" : "\n\n"}${header}\n${key} = ${value}\n`;
}

/** All `key = value` entries of `section`, in document order. */
export function listIniKeys(text: string, section: string): { key: string; value: string }[] {
  const target = canonicalSection(section);
  const { lines, sectionOf } = scanLines(text);
  const out: { key: string; value: string }[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (sectionOf[i] !== target) continue;
    const line = lines[i].trim();
    if (line === "" || line.startsWith(";") || line.startsWith("#") || line.startsWith("[")) {
      continue;
    }
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    out.push({ key: line.slice(0, eq).trim(), value: line.slice(eq + 1).trim() });
  }
  return out;
}

/** Rename `oldKey` to `newKey` in `section`, keeping the line's position and value. */
export function renameIniKey(text: string, section: string, oldKey: string, newKey: string): string {
  const target = canonicalSection(section);
  const { lines, sectionOf } = scanLines(text);
  for (let i = 0; i < lines.length; i++) {
    if (sectionOf[i] === target && isKeyLine(lines[i], oldKey)) {
      const line = lines[i].trim();
      lines[i] = `${newKey} = ${line.slice(line.indexOf("=") + 1).trim()}`;
      break;
    }
  }
  return lines.join("\n");
}

/** Remove `key` from `section` if present (the section itself is kept). */
export function removeIniKey(text: string, section: string, key: string): string {
  const target = canonicalSection(section);
  const { lines, sectionOf } = scanLines(text);
  const kept = lines.filter((line, i) => !(sectionOf[i] === target && isKeyLine(line, key)));
  return kept.join("\n");
}

/// Suggest the next version: bump the last numeric dot-component ("1.0.3" -> "1.0.4",
/// "2" -> "3"); if nothing numeric, append ".1".
export function suggestNextVersion(version: string): string {
  const parts = version.split(".");
  for (let i = parts.length - 1; i >= 0; i--) {
    if (/^\d+$/.test(parts[i])) {
      parts[i] = String(parseInt(parts[i], 10) + 1);
      return parts.join(".");
    }
  }
  return version + ".1";
}
