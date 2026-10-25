// Script languages a bundle can ship: where each kind of file lives under the bundle's
// scripts/ folder, the starter a new one begins as, and the configuration that makes the
// agent run it. Shared by the script templates and the bundle editor's "Add script".
//
// The agent stages every scripts/ entry under ${fleet-folder}/scripts and
// `script root = fleet` points the script modules there (see "Bundles that ship scripts"
// in the NSClient fleet docs). External scripts start in ${fleet-folder}, so a command
// says `scripts\x.bat`; Python and Lua entries are searched for in scripts/python and
// scripts/lua. Shell scripts are written without an execute bit, so they run through `sh`.

import { listIniKeys, setIniValue } from "../ini";

export type ScriptLanguageId = "batch" | "shell" | "python" | "lua";

export type ScriptLanguage = {
  id: ScriptLanguageId;
  label: string;
  /** Extensions recognised as this language, the first being what new files get. */
  extensions: string[];
  /** Folder under the bundle root new files of this language go in. */
  dir: string;
  /** NSClient module that runs the script. */
  module: string;
  /** Spaces a Tab key press inserts in the editor. */
  indent: number;
  /** Starter content for a new script whose check command is `name`. */
  starter: (name: string) => string;
  /** The `[section] key = value` that registers the script at `path` as check `name`. */
  entry: (name: string, path: string) => { section: string; key: string; value: string };
};

/** Bundle-relative path minus the folder the module searches, as a module entry names it. */
function searchRelative(path: string, dir: string): string {
  if (path.startsWith(dir)) return path.slice(dir.length);
  return path.startsWith("scripts/") ? path.slice("scripts/".length) : path;
}

export const SCRIPT_LANGUAGES: ScriptLanguage[] = [
  {
    id: "batch",
    label: "Batch (Windows)",
    extensions: [".bat", ".cmd"],
    dir: "scripts/",
    module: "CheckExternalScripts",
    indent: 2,
    starter: (name) => `@echo off
rem ${name} - a fleet-managed check run by CheckExternalScripts.
rem
rem The exit code is the status: 0 = OK, 1 = WARNING, 2 = CRITICAL, 3 = UNKNOWN.
rem The first line printed is the message; anything after a "|" is performance data
rem (escape it as ^| in batch).

rem Example: warn when the Windows Update service is not running.
sc query wuauserv | find "RUNNING" >nul
if errorlevel 1 (
  echo WARNING: Windows Update service is not running
  exit /b 1
)
echo OK: Windows Update service is running
exit /b 0
`,
    entry: (name, path) => ({
      section: "/settings/external scripts/scripts",
      key: name,
      value: path.replace(/\//g, "\\"),
    }),
  },
  {
    id: "shell",
    label: "Shell (Linux)",
    extensions: [".sh"],
    dir: "scripts/",
    module: "CheckExternalScripts",
    indent: 2,
    starter: (name) => `#!/bin/sh
# ${name} - a fleet-managed check run by CheckExternalScripts.
#
# The exit code is the status: 0 = OK, 1 = WARNING, 2 = CRITICAL, 3 = UNKNOWN.
# The first line printed is the message; anything after a "|" is performance data.

# Example: warn when the root filesystem is filling up.
WARN=80
CRIT=90
USED=$(df -P / | awk 'NR == 2 { sub("%", "", $5); print $5 }')

if [ -z "$USED" ]; then
  echo "UNKNOWN: could not read the usage of /"
  exit 3
fi
PERF="'used'=\${USED}%;\${WARN};\${CRIT}"
if [ "$USED" -ge "$CRIT" ]; then
  echo "CRITICAL: / is \${USED}% full|\${PERF}"
  exit 2
fi
if [ "$USED" -ge "$WARN" ]; then
  echo "WARNING: / is \${USED}% full|\${PERF}"
  exit 1
fi
echo "OK: / is \${USED}% full|\${PERF}"
exit 0
`,
    // Staged without an execute bit, so it runs through its interpreter.
    entry: (name, path) => ({
      section: "/settings/external scripts/scripts",
      key: name,
      value: `sh ${path}`,
    }),
  },
  {
    id: "python",
    label: "Python",
    extensions: [".py"],
    dir: "scripts/python/",
    module: "PythonScript",
    indent: 4,
    starter: (name) => `# ${name} - a fleet-managed check run in-process by the PythonScript module.
#
# init() runs when the script loads and registers the check command. The check returns
# (status, message, performance data).
import os

from NSCP import Registry, status


def ${pyIdent(name)}(args):
    # Example: warn when the system is busier than it has CPUs for.
    if not hasattr(os, "getloadavg"):
        return (status.UNKNOWN, "load average is not available on this platform", "")
    load = os.getloadavg()[0]
    cpus = os.cpu_count() or 1
    perf = "'load1'=%.2f;%d;%d" % (load, cpus, cpus * 2)
    if load > cpus * 2:
        return (status.CRITICAL, "load is %.2f on %d CPUs" % (load, cpus), perf)
    if load > cpus:
        return (status.WARNING, "load is %.2f on %d CPUs" % (load, cpus), perf)
    return (status.OK, "load is %.2f on %d CPUs" % (load, cpus), perf)


def init(plugin_id, plugin_alias, script_alias):
    reg = Registry.get(plugin_id)
    reg.simple_function("${name}", ${pyIdent(name)}, "Example check from a fleet bundle")
`,
    entry: (name, path) => ({
      section: "/settings/python/scripts",
      key: name,
      value: searchRelative(path, "scripts/python/"),
    }),
  },
  {
    id: "lua",
    label: "Lua",
    extensions: [".lua"],
    dir: "scripts/lua/",
    module: "LUAScript",
    indent: 2,
    starter: (name) => `-- ${name} - a fleet-managed check run in-process by the LUAScript module.
--
-- The top level runs when the script loads and registers the check command. The check
-- returns status ("ok", "warning", "critical", "unknown"), message and performance data.

local function ${luaIdent(name)}(command, args)
  -- Example: run the built-in uptime check and pass on its result without perfdata.
  local code, message, perf = Core():simple_query("check_uptime", args)
  return code, message, ""
end

Registry():simple_query("${name}", ${luaIdent(name)}, "Example check from a fleet bundle")
`,
    entry: (name, path) => ({
      section: "/settings/lua/scripts",
      key: name,
      value: searchRelative(path, "scripts/lua/"),
    }),
  },
];

/** Check names are INI keys and command names; scripts make functions of them. */
function pyIdent(name: string): string {
  return name.replace(/[^A-Za-z0-9_]/g, "_").replace(/^(?=\d)/, "_");
}
const luaIdent = pyIdent;

export function scriptLanguageById(id: ScriptLanguageId): ScriptLanguage {
  return SCRIPT_LANGUAGES.find((l) => l.id === id)!;
}

/** The language a bundle path is written in, by extension; undefined for other files
 *  (helpers, data, PowerShell…), which are shipped but not registered. */
export function scriptLanguageOf(path: string): ScriptLanguage | undefined {
  const lower = path.toLowerCase();
  return SCRIPT_LANGUAGES.find((l) => l.extensions.some((e) => lower.endsWith(e)));
}

/** Whether the module finds a script at `path`: Python and Lua modules only search their
 *  own folder (scripts/python/, scripts/lua/), external scripts run from anywhere. */
export function registrableAt(lang: ScriptLanguage, path: string): boolean {
  return path.startsWith(lang.dir);
}

/** The INI entries that run the script at `path`, as "Add script" wrote them — so removing
 *  the file can offer to remove them too. Compared ignoring case and slash direction. */
export function registrationsOf(ini: string, path: string): { section: string; key: string }[] {
  const lang = scriptLanguageOf(path);
  if (lang === undefined) return [];
  const norm = (v: string) => v.trim().replace(/\\/g, "/").toLowerCase();
  const { section, value } = lang.entry("", path);
  return listIniKeys(ini, section)
    .filter((e) => norm(e.value) === norm(value))
    .map((e) => ({ section, key: e.key }));
}

/** Add what makes the agent run the script at `path` as check `name`: the module, the
 *  script root, and the entry. Existing values are overwritten, so re-registering a
 *  script is harmless. */
export function registerScript(ini: string, lang: ScriptLanguage, name: string, path: string): string {
  let out = setIniValue(ini, "/modules", lang.module, "enabled");
  out = setIniValue(out, "/settings/default", "script root", "fleet");
  const { section, key, value } = lang.entry(name, path);
  return setIniValue(out, section, key, value);
}
