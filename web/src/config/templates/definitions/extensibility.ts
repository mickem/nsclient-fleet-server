import { type BundleTemplate, type TemplateField } from "../types";
import { scriptLanguageById, type ScriptLanguageId } from "../scripts";

/** A bundle that ships one starter script of `lang` and registers it as check `name`.
 *  The script itself is edited (or replaced by an upload) in the editor's Scripts section;
 *  the form edits what runs it. */
function scriptTemplate(
  langId: ScriptLanguageId,
  id: string,
  title: string,
  name: string,
  description: string,
): BundleTemplate {
  const lang = scriptLanguageById(langId);
  const path = `${lang.dir}${name}${lang.extensions[0]}`;
  const entry = lang.entry(name, path);
  const external = lang.module === "CheckExternalScripts";
  const fields: TemplateField[] = [];
  if (external) {
    fields.push({
      kind: "bool",
      id: "allow_arguments",
      label: "Allow caller-supplied arguments",
      section: "/settings/external scripts",
      key: "allow arguments",
      default: false,
      help: "Keep off unless a check really needs arguments from the monitoring server.",
    });
  }
  fields.push({
    kind: "table",
    id: "scripts",
    label: external ? "Checks" : "Loaded scripts",
    section: entry.section,
    presets: [],
    keyLabel: external ? "Check name" : "Alias",
    valueLabel: external ? "Command" : "Script",
    addLabel: "Add entry",
    emptyText: "Nothing registered — the bundle's scripts are shipped but never run.",
    custom: {
      keyLabel: external ? "Check name" : "Alias",
      valueLabel: external ? "Command" : "Script",
      valueHelp: external
        ? "Runs in the fleet folder, so scripts/ is this bundle's scripts/ folder."
        : `Path relative to the bundle's ${lang.dir} folder.`,
    },
    help: external
      ? "Each entry is a check command and the command line that runs it."
      : "Each entry loads one script; the script registers its own check commands.",
  });
  return {
    id,
    title,
    category: "Extensibility",
    description,
    fields,
    ini: `[/modules]
${lang.module} = enabled

[/settings/default]
; Load scripts from the tree the fleet sync owns (\${fleet-folder}/scripts), where the
; scripts/ folder of every assigned bundle is staged.
script root = fleet
${
  external
    ? `
[/settings/external scripts]
; Keep this off unless a check really needs caller-supplied arguments.
allow arguments = false
`
    : ""
}
[${entry.section}]
${entry.key} = ${entry.value}
`,
    scripts: [{ path, content: lang.starter(name) }],
  };
}

export const EXTENSIBILITY: BundleTemplate[] = [
  scriptTemplate(
    "batch",
    "batch-script",
    "Batch script",
    "check_batch_example",
    "Ship a Windows batch file in the bundle and run it as a check. Starts from an " +
      "example you can edit, or upload your own.",
  ),
  scriptTemplate(
    "shell",
    "shell-script",
    "Shell script",
    "check_shell_example",
    "Ship a POSIX shell script in the bundle and run it as a check on Linux. Starts from " +
      "an example you can edit, or upload your own.",
  ),
  scriptTemplate(
    "python",
    "python-script",
    "Python script",
    "check_python_example",
    "Ship a Python script that runs inside the agent (PythonScript) and registers its own " +
      "checks. Starts from an example you can edit, or upload your own.",
  ),
  scriptTemplate(
    "lua",
    "lua-script",
    "Lua script",
    "check_lua_example",
    "Ship a Lua script that runs inside the agent (LUAScript) and registers its own " +
      "checks. Starts from an example you can edit, or upload your own.",
  ),
  // --------------------------------------------------------------- Extensibility
  {
    id: "external-scripts",
    title: "External scripts",
    category: "Extensibility",
    description:
      "Register scripts already on the host as monitoring checks. To ship the scripts " +
      "with the bundle, use one of the script templates instead.",
    fields: [
      {
        kind: "bool",
        id: "allow_arguments",
        label: "Allow caller-supplied arguments",
        section: "/settings/external scripts",
        key: "allow arguments",
        default: false,
        help: "Keep off unless a check really needs arguments from the monitoring server.",
      },
      {
        kind: "text",
        id: "check_my_app",
        label: "Example script (check_my_app)",
        section: "/settings/external scripts/scripts",
        key: "check_my_app",
        help: "Path relative to the NSClient install directory.",
      },
    ],
    ini: `[/modules]
CheckExternalScripts = enabled

[/settings/external scripts]
; Keep this off unless a check really needs caller-supplied arguments.
allow arguments = false

[/settings/external scripts/scripts]
; name = path relative to the NSClient install directory
check_my_app = scripts\\check_my_app.bat

; PowerShell scripts keep their exit codes when run via the ps1 wrapping:
; [/settings/external scripts/wrapped scripts]
; check_my_ps = check_my_ps.ps1
`,
  },
];
