import { DIAGNOSTIC_SETS } from "../diagnosticSets";
import { FACT_SETS } from "../factSets";
import { LINUX_SERVICE_PRESETS, SERVICE_NAME_RE, TAG_NAME_RE, WINDOWS_SERVICE_PRESETS } from "../shared";
import { type BundleTemplate } from "../types";

const FLEET_SECTION = "/settings/fleet";
const FACTS_SECTION = "/settings/facts";
const FAILED_CHECKS = "/settings/core/failed checks";

export const FLEET: BundleTemplate[] = [
  // --------------------------------------------------------------------- Fleet
  {
    id: "fleet-agent",
    title: "Fleet agent settings",
    category: "Fleet",
    description:
      "How an enrolled agent talks to this server, in one place: how often it polls, how " +
      "often it refreshes its inventory, and what it sends when a check fails. Everything " +
      "is optional and left to the agent's defaults until switched on, so one bundle on a " +
      "broad group sets the fleet's pace and a host override bends it for a single machine. " +
      "The polling and failure-report settings are read when the agent's service starts: " +
      "a change reaches the host on its next poll and takes effect at its next restart.",
    fields: [
      {
        kind: "text",
        id: "poll_interval",
        label: "Initial poll interval",
        section: FLEET_SECTION,
        key: "poll interval",
        default: "60s",
        optional: true,
        valueLabel: "interval",
        help:
          "Used only until the server names an interval, which its first answer does; " +
          "after that the two bounds below are what matter. E.g. 60s or 5m.",
      },
      {
        kind: "text",
        id: "min_poll_interval",
        label: "Shortest poll interval",
        section: FLEET_SECTION,
        key: "min poll interval",
        default: "1s",
        optional: true,
        valueLabel: "interval",
        help:
          "The host never polls more often than this, whatever the server asks for: set " +
          "5m for hosts on a metered or slow link. The agent's default of 1s leaves the " +
          "choice to the server. A host that stays silent for a day shows as offline " +
          "here, so keep it well under that.",
      },
      {
        kind: "text",
        id: "max_poll_interval",
        label: "Longest poll interval",
        section: FLEET_SECTION,
        key: "max poll interval",
        default: "1d",
        optional: true,
        valueLabel: "interval",
        help:
          "The host never polls less often than this, so a configuration change reaches " +
          "it within that time. Raised to the shortest interval when set below it. This " +
          "server does not answer faster than its own minimum poll interval — an agent " +
          "that asks sooner is told to wait — so a value below that gains nothing.",
      },
      {
        kind: "text",
        id: "timeout",
        label: "Request timeout",
        section: FLEET_SECTION,
        key: "timeout",
        default: "60s",
        optional: true,
        valueLabel: "timeout",
        help:
          "How long one request to the server may take before the agent abandons it and " +
          "retries; at least 1s. Raise it for hosts that download large bundles over a " +
          "slow link.",
      },
      {
        kind: "text",
        id: "facts_interval",
        label: "Inventory refresh interval",
        section: FACTS_SECTION,
        key: "interval",
        default: "1h",
        optional: true,
        valueLabel: "interval",
        help:
          "How often every module refreshes the fact sets it collects, e.g. 30m or 6h. " +
          "Which sets are collected is chosen with the Host inventory (facts) template; " +
          "set the interval in one of the two bundles, not both.",
      },
      {
        kind: "text",
        id: "facts_max_size",
        label: "Maximum inventory size",
        section: FACTS_SECTION,
        key: "max size",
        default: "1048576",
        optional: true,
        valueLabel: "bytes",
        help:
          "Size budget for the whole inventory document; the agent's default is 1 MiB. A " +
          "set that would push it past this is rejected and its previous value kept.",
      },
      {
        kind: "facts",
        id: "agent_facts",
        label: "Report the agent itself",
        sets: FACT_SETS.filter((s) => s.id === "agent"),
        help:
          "The one fact set the agent's core produces, so it is switched on here rather " +
          "than in a module: worth having on every host to see which NSClient++ versions " +
          "are out there.",
      },
      {
        kind: "bool",
        id: "failure_context",
        label: "Send failure context",
        section: FLEET_SECTION,
        key: "failure context",
        default: true,
        help:
          "When checks fail, report one of them to this server — what it said, plus the " +
          "metrics and diagnostics captured below — with a count of the others. Sent only " +
          "while failure context is switched on for the tenant here; off sends nothing, " +
          "whatever the server asks.",
      },
      {
        kind: "text",
        id: "failure_context_interval",
        label: "Failure report interval",
        section: FLEET_SECTION,
        key: "failure context interval",
        default: "1h",
        optional: true,
        valueLabel: "interval",
        help:
          "The least time between two reports (at least 5s). Failures in between are " +
          "summarised in the next one. The server can ask for a longer interval, never a " +
          "shorter one.",
      },
      {
        kind: "select",
        id: "record_arguments",
        label: "Record check arguments",
        section: FAILED_CHECKS,
        key: "record arguments",
        options: [
          { value: "none", label: "None" },
          { value: "safe", label: "Safe — thresholds, filters and what was checked" },
          { value: "all", label: "All — every option (passwords and tokens masked)" },
        ],
        default: "safe",
        optional: true,
        valueLabel: "arguments",
        help:
          "Which of a failed check's arguments are kept and reported. Safe, the agent's " +
          "default, drops anything naming a host, URL, command or query. Under all, a " +
          "secret passed under a name that does not mention a password or token is kept " +
          "as written.",
      },
      {
        kind: "text",
        id: "statuses",
        label: "Results that count as failed",
        section: FAILED_CHECKS,
        key: "statuses",
        default: "warning, critical, unknown",
        optional: true,
        valueLabel: "statuses",
        help:
          "A comma-separated list of warning, critical and unknown. Drop warning to log " +
          "and report only the results someone has to act on.",
      },
      {
        kind: "bool",
        id: "capture_metrics",
        label: "Capture metrics with each failure",
        section: FAILED_CHECKS,
        key: "capture metrics",
        default: false,
        help:
          "Keep the agent's latest metrics snapshot (CPU, memory, disks, network) with " +
          "every failed check, so the report shows what the system looked like. Off by " +
          "default on the agent: a snapshot can hold host details the check output does " +
          "not. Around 100 KB per report on a busy Windows host.",
      },
      {
        kind: "text",
        id: "prune_metrics",
        label: "Trim the metrics snapshot",
        section: FAILED_CHECKS,
        key: "prune metrics",
        default: "zeros, empty, duplicates",
        optional: true,
        valueLabel: "rules",
        help:
          "Any of zeros (values that are 0), empty (empty strings) and duplicates (values " +
          "that restate others, and instances identical to an earlier one — idle disks, " +
          "unused adapters). Makes reports smaller and easier to read.",
      },
      {
        kind: "text",
        id: "prune_pattern",
        label: "Leave out metrics matching",
        section: FAILED_CHECKS,
        key: "prune pattern",
        default: "Hyper-V Virtual, VirtualBox",
        optional: true,
        valueLabel: "patterns",
        help:
          "A comma-separated list of text: every metric whose key contains one is left " +
          "out, as is a diagnostics table whose name matches. For the instances that are " +
          "noise on your hosts.",
      },
      {
        kind: "bool",
        id: "capture_diagnostics",
        label: "Capture diagnostics with each failure",
        section: FAILED_CHECKS,
        key: "capture diagnostics",
        default: false,
        help:
          "Keep small tables of what is going on with every failed check. With no table " +
          "ticked below, that is the last failed checks only. Off by default on the " +
          "agent: the tables hold process names and other host details.",
      },
      {
        kind: "facts",
        id: "diagnostics_tables",
        label: "Diagnostics tables to capture",
        sets: DIAGNOSTIC_SETS,
        help:
          "Each table is switched on in the module that produces it, and only captured " +
          "while the switch above is on. Ticking a table also loads its module; the event " +
          "log ones load CheckEventLog, which belongs on a Windows group. Unticking " +
          "removes the switch from this bundle rather than forcing it off.",
      },
      {
        kind: "text",
        id: "diagnostics_rows",
        label: "Rows per diagnostics table",
        section: FAILED_CHECKS,
        key: "diagnostics rows",
        default: "10",
        optional: true,
        valueLabel: "rows",
        help: "The most rows kept per table, 1–50; the agent's default is 10.",
      },
    ],
    ini: `; How enrolled agents talk to the fleet server. Every key below is optional: one that
; is absent keeps the agent's default, and a key a host sets in its own nsclient.ini wins
; over this bundle.
;
; [/settings/fleet] is read when the agent's service starts, so a change here takes
; effect at each host's next restart. The other two sections are re-read on the reload
; that applies the bundle (the inventory interval at the next restart).
[/settings/fleet]
; The server names the poll interval in every answer; these bound it from the host's side.
; poll interval = 60s
; min poll interval = 5m
; max poll interval = 1h
; timeout = 60s
; One failed check, with what was captured for it, at most once per interval.
; failure context = true
; failure context interval = 1h

[/settings/facts]
; interval = 1h
; max size = 1048576
; agent = true

; What is kept with a failed check, and so what a failure report carries.
[/settings/core/failed checks]
; record arguments = safe
; statuses = warning, critical, unknown
; capture metrics = true
; prune metrics = zeros, empty, duplicates
; capture diagnostics = true
; diagnostics rows = 10
`,
  },
  {
    id: "detect-services",
    title: "Service tags",
    category: "Fleet",
    description:
      "Publish a host tag for each service you care about (SQL Server, IIS, PostgreSQL, …) " +
      "so groups can select hosts by what runs on them. Assign this bundle broadly; the " +
      "tags then drive which application bundles each host receives. These are tags the " +
      "host reports about itself, so a group selecting on one is a group hosts can place " +
      "themselves in — keep anything carrying scripts or secrets on operator-set tags.",
    fields: [
      {
        kind: "table",
        id: "windows_services",
        label: "Windows services",
        section: "/settings/system/windows/service-tags",
        help:
          "Each row maps a Windows service (its short name, as in services.msc) to the tag " +
          "to publish. The agent checks the services when it starts: a running one gives " +
          "the host <tag> = enabled, a stopped or absent one removes the tag. A service " +
          "that stops later keeps its tag until the agent restarts. Give every service " +
          "its own tag. " +
          "SQL Server is also detected from the registry on every Windows host as " +
          "sqlserver = detected, running or not.",
        keyLabel: "Service",
        valueLabel: "Tag",
        addLabel: "Add service",
        emptyText: "No services yet — add one below.",
        keyPattern: SERVICE_NAME_RE,
        valuePattern: TAG_NAME_RE,
        uniqueKeys: true,
        custom: {
          keyLabel: "Service name",
          valueLabel: "Tag",
          keyHelp: "Short name, e.g. MSSQL$SQLEXPRESS — not the display name.",
          valueHelp: "Letters, digits, - _ . — e.g. sql-server.",
        },
        presets: WINDOWS_SERVICE_PRESETS,
      },
      {
        kind: "table",
        id: "linux_services",
        label: "Linux systemd units",
        section: "/settings/system/unix/service-tags",
        help:
          "Same idea for Linux: unit name (without .service) to tag. Unit names vary by " +
          "distribution — apache2 on Debian/Ubuntu is httpd on RHEL — so add the one your " +
          "hosts actually use.",
        keyLabel: "Unit",
        valueLabel: "Tag",
        addLabel: "Add unit",
        emptyText: "No units yet — add one below.",
        keyPattern: SERVICE_NAME_RE,
        valuePattern: TAG_NAME_RE,
        uniqueKeys: true,
        custom: {
          keyLabel: "Unit name",
          valueLabel: "Tag",
          keyHelp: "As systemctl knows it, e.g. postgresql or php8.2-fpm.",
          valueHelp: "Letters, digits, - _ . — e.g. postgres.",
        },
        presets: LINUX_SERVICE_PRESETS,
      },
    ],
    ini: `; Turn "what runs here" into host tags. Each entry is service = tag; when the agent
; starts it publishes tag = enabled for a running service and removes the tag otherwise,
; so a group selector on sql-server = enabled follows reality without anyone editing tags.
; That selector must read host-reported tags ("source": "agent"), which the group editor
; picks for you when you choose one of these keys — a clause left on operator tags, the
; default, will not match one of these.
; Windows hosts additionally report sqlserver = detected when SQL Server is installed.
[/modules]
CheckSystem = enabled

[/settings/system/windows/service-tags]
; MSSQLSERVER = sql-server
; W3SVC = iis

[/settings/system/unix/service-tags]
; postgresql = postgres
; nginx = nginx
`,
  },
  {
    id: "host-inventory",
    title: "Host inventory (facts)",
    category: "Fleet",
    description:
      "Have hosts report what they are — OS, hardware, network interfaces, volumes, " +
      "installed software and services, and optionally scheduled tasks, Hyper-V VMs, " +
      "Docker, MySQL and SQL Server — shown on each host's page. Pick the fact sets to collect; " +
      "nothing is collected until a set is switched on. Hosts send only a hash on each " +
      "poll, and the inventory itself only when it changed.",
    fields: [
      {
        kind: "facts",
        id: "fact_sets",
        label: "Fact sets to collect",
        sets: FACT_SETS,
        help:
          "Each set is switched on in the module that produces it, for Windows and Linux " +
          "alike — a host simply ignores the other platform's section. Unticking a set " +
          "removes its switch from this bundle rather than forcing it off, so another " +
          "bundle can still enable it. Ticking a set also loads its module; the Windows-only " +
          "ones (scheduled tasks, Hyper-V, SQL Server) belong on a Windows group.",
      },
      {
        kind: "text",
        id: "interval",
        label: "Refresh interval",
        section: "/settings/facts",
        key: "interval",
        default: "1h",
        optional: true,
        help:
          "How often every module refreshes its sets, e.g. 30m or 6h; the agent's default " +
          "is 1h. Hosts also refresh at start and on every settings reload.",
      },
      {
        kind: "text",
        id: "max_size",
        label: "Maximum inventory size",
        section: "/settings/facts",
        key: "max size",
        default: "1048576",
        optional: true,
        valueLabel: "bytes",
        help:
          "Size budget for the whole document; the agent's default is 1 MiB. A set that " +
          "would push it past this is rejected and its previous value kept.",
      },
    ],
    ini: `; Host inventory: which fact sets the agent collects and sends to the fleet server.
; A set is enabled in the module that produces it; a host ignores the section of the
; platform it is not on, so one bundle serves a mixed group. Each set is its own key,
; so another bundle turning on software.installed adds to this one.
[/modules]
CheckSystem = enabled
CheckDisk = enabled

; CheckSystem on Windows hosts
[/settings/system/windows/facts]
os = true
hardware = true
network.interfaces = true

; CheckSystem on Linux hosts
[/settings/system/unix/facts]
os = true
hardware = true
network.interfaces = true

[/settings/disk/facts]
storage.volumes = true
`,
  },
];
