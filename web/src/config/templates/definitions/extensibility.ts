import { type BundleTemplate } from "../types";

export const EXTENSIBILITY: BundleTemplate[] = [
  // --------------------------------------------------------------- Extensibility
  {
    id: "external-scripts",
    title: "External scripts",
    category: "Extensibility",
    description:
      "Run your own scripts and batch files as monitoring checks. Script files can be " +
      "added to the bundle zip under scripts/.",
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
