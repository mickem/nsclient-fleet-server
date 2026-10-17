import { FACT_SETS } from "../factSets";
import { LINUX_SERVICE_PRESETS, SERVICE_NAME_RE, TAG_NAME_RE, WINDOWS_SERVICE_PRESETS } from "../shared";
import { type BundleTemplate } from "../types";

export const FLEET: BundleTemplate[] = [
  // --------------------------------------------------------------------- Fleet
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
