import { aliasField } from "../shared";
import { type BundleTemplate } from "../types";

export const SYSTEM_HEALTH: BundleTemplate[] = [
  // ------------------------------------------------------------- System health
  {
    id: "windows-server-health",
    title: "Windows server health",
    category: "System health",
    description:
      "Baseline CPU, memory, disk and uptime checks for a Windows server, exposed as " +
      "argument-free aliases. Pair with a delivery template (NRPE, Check_MK, NSCA, …).",
    fields: [
      aliasField("alias_cpu", "CPU check", "warn/crit on average load over the time window"),
      aliasField("alias_memory", "Memory check"),
      aliasField("alias_disk", "Disk check", "checks every fixed drive"),
      aliasField("alias_uptime", "Uptime check", "alerts on recently rebooted machines"),
    ],
    ini: `; Baseline Windows health checks as transport-neutral aliases.
[/modules]
CheckSystem = enabled
CheckDisk = enabled
CheckHelpers = enabled

[/settings/check helpers/alias]
alias_cpu = check_cpu time=5m "warn=load > 80" "crit=load > 90"
alias_memory = check_memory "warn=free < 20%" "crit=free < 10%"
alias_disk = check_drivesize drive=* "filter=type in ('fixed')" "warn=free < 20%" "crit=free < 10%"
alias_uptime = check_uptime "warn=uptime < 2d"
`,
  },
  {
    id: "linux-server-health",
    title: "Linux server health",
    category: "System health",
    description:
      "Load, CPU, memory/swap, root-disk and systemd-service checks for a Linux server, " +
      "exposed as argument-free aliases.",
    fields: [
      aliasField("alias_load", "Load average check"),
      aliasField("alias_cpu", "CPU utilization check"),
      aliasField("alias_memory", "Memory check"),
      aliasField("alias_swap", "Swap activity check"),
      aliasField("alias_disk", "Root disk check"),
      aliasField("alias_services", "Systemd services check"),
    ],
    ini: `; Baseline Linux health checks as transport-neutral aliases.
[/modules]
CheckSystem = enabled
CheckDisk = enabled
CheckHelpers = enabled

[/settings/check helpers/alias]
alias_load = check_load "warn=load5 > 4" "crit=load5 > 8"
alias_cpu = check_cpu_utilization "warn=total > 90" "crit=total > 95"
alias_memory = check_memory "warn=used > 80%" "crit=used > 90%"
alias_swap = check_swap_io "warn=swap_out > 100" "crit=swap_out > 1000"
alias_disk = check_drivesize drive=/ "warn=free < 20%" "crit=free < 10%"
alias_services = check_service
`,
  },
  {
    id: "disk-space",
    title: "Disk space alerting",
    category: "System health",
    description:
      "Alert when fixed drives run low on free space; includes a safety-net check for " +
      "completely full volumes.",
    fields: [
      aliasField("alias_disk", "Free-space check", "warn/crit thresholds on every fixed drive"),
      aliasField("alias_disk_full", "Full-volume safety net"),
    ],
    ini: `[/modules]
CheckDisk = enabled
CheckHelpers = enabled

[/settings/check helpers/alias]
alias_disk = check_drivesize drive=* "filter=type in ('fixed')" "warn=free < 20%" "crit=free < 10%"
; Safety net: any volume (incl. mounted folders) nearly full is critical.
alias_disk_full = check_drivesize drive=all-volumes "crit=free < 1M"
`,
  },
  {
    id: "service-monitoring",
    title: "Service & process monitoring",
    category: "System health",
    description:
      "Ensure automatically started services are running, and watch specific services or " +
      "processes you care about.",
    fields: [
      aliasField(
        "alias_services",
        "Services check",
        "all auto-start services must be running; excludes are the usual .NET noise",
      ),
    ],
    ini: `[/modules]
CheckSystem = enabled
CheckHelpers = enabled

[/settings/check helpers/alias]
; All auto-start services should be running (excludes are the usual .NET noise).
alias_services = check_service "exclude=clr_optimization_v4.0.30319_32" "exclude=clr_optimization_v4.0.30319_64"
; Watch specific services/processes — adjust to your host:
; alias_service_spooler = check_service service=Spooler
; alias_process_myapp = check_process process=myapp.exe "warn=working_set > 500m" "crit=working_set > 1g"
`,
  },
  {
    id: "performance-counters",
    title: "Performance counters (PDH)",
    category: "System health",
    description:
      "Read Windows performance counters, collect one continuously (RRD) so checks can " +
      "average it over time, and alert on thresholds.",
    fields: [
      {
        kind: "text",
        id: "counter",
        label: "Collected counter",
        section: "/settings/system/windows/counters/disk_q",
        key: "counter",
        help: "PDH counter path collected once per second for averaging.",
      },
      aliasField("alias_disk_queue", "Disk-queue check", "averages the collected counter"),
      aliasField("alias_cpu_pdh", "Direct PDH check"),
    ],
    ini: `[/modules]
CheckSystem = enabled
CheckHelpers = enabled

; Collect the counter continuously so checks can average over a time window.
[/settings/system/windows/counters/disk_q]
collection strategy = rrd
counter = \\\\PhysicalDisk(_Total)\\\\Avg. Disk Write Queue Length

[/settings/check helpers/alias]
alias_disk_queue = check_pdh counter=disk_q time=30s "warn=value > 5" "crit=value > 10"
alias_cpu_pdh = check_pdh "counter=\\Processor(_Total)\\% Processor Time" "warn=value > 80" "crit=value > 95"
`,
  },
  {
    id: "realtime-monitoring",
    title: "Real-time system alerts",
    category: "System health",
    description:
      "Push CPU and memory alerts the second they happen instead of waiting for the next " +
      "poll. Results go to the channel of the passive delivery template you assign " +
      "alongside (NSCA, NSCA-NG, …).",
    fields: [
      {
        kind: "text",
        id: "cpu_filter",
        label: "CPU alert condition",
        section: "/settings/system/windows/real-time/cpu/high_cpu",
        key: "filter",
      },
      {
        kind: "text",
        id: "cpu_time",
        label: "CPU averaging window",
        section: "/settings/system/windows/real-time/cpu/high_cpu",
        key: "time",
        help: "The alert fires when the average over this window matches the condition.",
      },
      {
        kind: "select",
        id: "cpu_destination",
        label: "CPU alert destination",
        section: "/settings/system/windows/real-time/cpu/high_cpu",
        key: "destination",
        options: [
          { value: "NSCA", label: "NSCA" },
          { value: "NSCA-NG", label: "NSCA-NG" },
          { value: "NRDP", label: "NRDP" },
          { value: "GRAPHITE", label: "Graphite" },
          { value: "events", label: "Event bus (REST)" },
        ],
        default: "NSCA",
        help: "Channel provided by your passive delivery template.",
      },
      {
        kind: "text",
        id: "mem_filter",
        label: "Memory alert condition",
        section: "/settings/system/windows/real-time/memory/low_memory",
        key: "filter",
      },
      {
        kind: "select",
        id: "mem_destination",
        label: "Memory alert destination",
        section: "/settings/system/windows/real-time/memory/low_memory",
        key: "destination",
        options: [
          { value: "NSCA", label: "NSCA" },
          { value: "NSCA-NG", label: "NSCA-NG" },
          { value: "NRDP", label: "NRDP" },
          { value: "GRAPHITE", label: "Graphite" },
          { value: "events", label: "Event bus (REST)" },
        ],
        default: "NSCA",
      },
    ],
    ini: `; Real-time filters evaluate every sample and push through a passive channel.
; Windows paths shown; on Linux use /settings/system/unix/real-time/... instead.
; (Each filter is one subsection; the docs' shorthand "name = expr" section keys
; cannot be expressed in a bundle, so the filter lives in the subsection.)
[/modules]
CheckSystem = enabled

[/settings/system/windows/real-time/cpu/high_cpu]
filter = load > 80
time = 5m
destination = NSCA

[/settings/system/windows/real-time/memory/low_memory]
filter = used > 90%
destination = NSCA
`,
  },
];
