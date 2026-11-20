import { type FactSet } from "./factSets";

const SYSTEM_WINDOWS = "/settings/system/windows/diagnostics";
const SYSTEM_UNIX = "/settings/system/unix/diagnostics";
const EVENTLOG = "/settings/eventlog/diagnostics";

/** The diagnostics tables an agent can keep with a failed check (and so send as failure
 *  context). Like a fact set, a table is switched on in the module that produces it, so
 *  they share the checklist shape: `id` is the table shown to the operator, `key` the
 *  switch. The Windows event log tables are their own entries, apart from the Linux
 *  switch of the same name, because ticking one loads CheckEventLog, which only exists
 *  on Windows. Nothing here is collected until `capture diagnostics` is on in
 *  [/settings/core/failed checks]. */
export const DIAGNOSTIC_SETS: FactSet[] = [
  {
    id: "processes.top_cpu",
    key: "processes",
    label: "Top processes",
    description:
      "The processes using the most CPU and the most memory (processes.top_cpu and " +
      "processes.top_memory): name, pid, CPU share and memory — never the command line.",
    cost: "one extra process-table read a second",
    targets: [
      { section: SYSTEM_WINDOWS, module: "CheckSystem", platform: "Windows" },
      { section: SYSTEM_UNIX, module: "CheckSystem", platform: "Linux" },
    ],
  },
  {
    id: "services.problems",
    key: "services",
    label: "Services in trouble",
    description:
      "Services that are not where they should be — an automatic service that is not " +
      "running, one that stopped with an error or keeps restarting — with state, exit " +
      "code, executable (never its arguments) and account. On Linux this also gives the " +
      "service manager's journal messages (services.events).",
    cost: "low: read every 30 seconds",
    targets: [
      { section: SYSTEM_WINDOWS, module: "CheckSystem", platform: "Windows" },
      { section: SYSTEM_UNIX, module: "CheckSystem", platform: "Linux" },
    ],
  },
  {
    id: "services.events",
    key: "services",
    label: "Service events",
    description:
      "The service control manager's events for a service that terminated unexpectedly " +
      "or failed to start. Loads CheckEventLog.",
    cost: "low: an event log subscription",
    targets: [{ section: EVENTLOG, module: "CheckEventLog", platform: "Windows" }],
  },
  {
    id: "eventlog.errors",
    key: "errors",
    label: "Event log errors",
    description:
      "The last critical and error events in the Application and System logs, with their " +
      "message — which programs fill with whatever they like. Loads CheckEventLog.",
    cost: "low: an event log subscription",
    targets: [{ section: EVENTLOG, module: "CheckEventLog", platform: "Windows" }],
  },
  {
    id: "journal.errors",
    key: "errors",
    label: "Journal errors",
    description:
      "The last journal entries at priority err or worse (reported as eventlog.errors): " +
      "unit, identifier, level and message. The agent must be able to read the system " +
      "journal.",
    cost: "low: journalctl every 10 seconds",
    targets: [{ section: SYSTEM_UNIX, module: "CheckSystem", platform: "Linux" }],
  },
  {
    id: "disk.growth_spots",
    key: "growth spots",
    label: "Disk growth spots",
    description:
      "The size of the places that usually fill a disk: temp and log directories, page " +
      "and swap files and, on Windows, shadow-copy storage. Paths and sizes leave the host.",
    cost: "moderate: a background directory walk every 10 minutes",
    targets: [{ section: "/settings/disk/diagnostics", module: "CheckDisk", platform: "Windows & Linux" }],
  },
];
