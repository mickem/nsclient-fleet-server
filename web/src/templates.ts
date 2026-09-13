// Pre-defined bundle templates, distilled from the NSClient scenario guides
// (docs/docs/scenarios in the nscp repo). Each template covers ONE concern so bundles
// stay composable: check templates define transport-neutral aliases, and each delivery
// mechanism (NRPE, Check_MK, NSCA, Icinga, …) is its own template — assign one of each
// to a group instead of baking the transport into every check bundle.
//
// The chosen template's id is recorded in the bundle's manifest (bundle.toml,
// `template = "<id>"`) by both save paths — the server's compose and the client-built
// encrypted zip — so the editor can show the association when the bundle is edited later.
//
// A template's `fields` drive the visual (form) editor view. Every field is bound to
// real INI keys and the INI TEXT stays the single source of truth: fields read their
// value out of it and write back with surgical line edits (see getIniValue/setIniValue),
// so switching between the form and the raw INI is lossless and comments survive.

import { getIniValue, listIniKeys, removeIniKey, renameIniKey, setIniValue } from "./ini";

/** Show a field only when another field's value matches. Declare parents BEFORE their
 *  dependents — reconciliation walks fields in order. */
export type FieldWhen = {
  field: string;
  /** Visible when the parent's value is one of these… */
  in?: string[];
  /** …or, alternatively, when the parent's value is non-empty. */
  notEmpty?: boolean;
};

export type SelectOption = { value: string; label: string };

/** One option of a `choice` field: picking it writes a coherent set of keys
 *  (section → key → value). The choice reads back as whichever option's keys all match. */
export type ChoiceOption = {
  value: string;
  label: string;
  set: Record<string, Record<string, string>>;
};

export type TemplateField =
  | {
      kind: "text";
      id: string;
      label: string;
      section: string;
      key: string;
      /** Written when the field first becomes visible or is toggled on; falls back to the
       *  value in the template's base INI. Empty input removes the key. */
      default?: string;
      /** Rendered with an on/off switch: off = key absent (the check is not defined),
       *  on = key present with its default, editable. */
      optional?: boolean;
      /** Label of the inner control when `optional` puts the field's own label on the
       *  switch (defaults to "value"). */
      valueLabel?: string;
      help?: string;
      when?: FieldWhen;
    }
  | {
      kind: "bool";
      id: string;
      label: string;
      section: string;
      key: string;
      default: boolean;
      help?: string;
      when?: FieldWhen;
    }
  | {
      kind: "select";
      id: string;
      label: string;
      section: string;
      key: string;
      options: SelectOption[];
      default: string;
      /** As for text fields: off = key absent (inherited from elsewhere), on = set here. */
      optional?: boolean;
      valueLabel?: string;
      help?: string;
      when?: FieldWhen;
    }
  | {
      kind: "choice";
      id: string;
      label: string;
      options: ChoiceOption[];
      help?: string;
      when?: FieldWhen;
    }
  | {
      /** Every `name = command` entry of a section as an editable table: rename, edit,
       *  delete rows, and add rows from a list of common presets. */
      kind: "table";
      id: string;
      label: string;
      section: string;
      presets: TablePreset[];
      help?: string;
      when?: FieldWhen;
      /** Column headings; default "Name" / "Command" (the check-table origin of this
       *  field). Other uses of a `key = value` section rename them. */
      keyLabel?: string;
      valueLabel?: string;
      /** Label of the add-row dropdown (default "Add check"). */
      addLabel?: string;
      /** Shown when the section has no entries (default "No checks yet — add one below."). */
      emptyText?: string;
      /** Entry-name rule; defaults to `validTableKey` (safe as an INI key and settings-path
       *  segment). A section whose keys are foreign identifiers — Windows service names
       *  like `MSSQL$SQLEXPRESS` — needs its own. */
      keyPattern?: RegExp;
      /** Value rule; unrestricted by default. */
      valuePattern?: RegExp;
      /** Entry names are identifiers of real things (a service), not labels: a preset whose
       *  name is already listed is not added again, instead of getting a numeric suffix. */
      uniqueKeys?: boolean;
      /** Offer "Custom…" in the add dropdown: a small form where both the entry name and
       *  its value are typed before the row is inserted. Presets only need a rename. */
      custom?: {
        keyLabel: string;
        valueLabel: string;
        keyHelp?: string;
        valueHelp?: string;
      };
    };

export type TablePreset = {
  label: string;
  /** Suggested entry name (deduplicated on insert). */
  key: string;
  value: string;
  /** Modules the check needs; enabled in [/modules] when the preset is added. */
  modules?: string[];
};

/** Entry names must be safe as INI keys and settings-path segments, and must not shadow
 *  the scheduler's `default` subsection. */
export const TABLE_KEY_RE = /^[A-Za-z0-9_-]{1,64}$/;
export function validTableKey(key: string): boolean {
  return TABLE_KEY_RE.test(key) && key !== "default";
}

/** Whether `key` is acceptable as an entry name of this table (see `keyPattern`). */
export function validTableRowKey(f: TemplateField & { kind: "table" }, key: string): boolean {
  return f.keyPattern ? f.keyPattern.test(key) : validTableKey(key);
}

/** Whether `value` is acceptable in this table (see `valuePattern`). */
export function validTableRowValue(f: TemplateField & { kind: "table" }, value: string): boolean {
  return f.valuePattern ? f.valuePattern.test(value) : true;
}

export type BundleTemplate = {
  /** Stored in bundle.toml; must match the bundle token charset [A-Za-z0-9._-]. */
  id: string;
  title: string;
  category: string;
  description: string;
  /** Carries credentials — the editor suggests saving these encrypted. */
  sensitive?: boolean;
  fields: TemplateField[];
  /** Base INI document; defaults here match the fields' defaults. */
  ini: string;
};

export function templateById(id: string): BundleTemplate | undefined {
  return TEMPLATES.find((t) => t.id === id);
}

/** Current value of a field as read from the INI text ("" when absent / no match). */
export function fieldValue(ini: string, f: TemplateField): string {
  if (f.kind === "table") return "";
  if (f.kind === "choice") {
    const match = f.options.find((o) =>
      Object.entries(o.set).every(([section, kv]) =>
        Object.entries(kv).every(([k, v]) => (getIniValue(ini, section, k) ?? "") === v),
      ),
    );
    return match?.value ?? "";
  }
  const raw = getIniValue(ini, f.section, f.key);
  if (raw !== undefined) return raw;
  if (f.kind === "bool") return f.default ? "true" : "false";
  if (f.kind === "select") return f.default;
  return "";
}

/** Whether a key-bound field's key exists in the document (optional fields' switch). */
export function fieldPresent(ini: string, f: TemplateField): boolean {
  return (
    f.kind !== "choice" && f.kind !== "table" && getIniValue(ini, f.section, f.key) !== undefined
  );
}

/** Default written when a field appears or is switched on: the explicit default, else
 *  whatever the template's base INI carries for that key. */
export function fieldDefault(t: BundleTemplate, f: TemplateField): string {
  if (f.kind === "choice" || f.kind === "table") return "";
  if (f.kind === "bool") return f.default ? "true" : "false";
  if (f.kind === "select") return f.default;
  return f.default ?? getIniValue(t.ini, f.section, f.key) ?? "";
}

export function fieldVisible(ini: string, t: BundleTemplate, f: TemplateField): boolean {
  if (!f.when) return true;
  const parent = t.fields.find((x) => x.id === f.when!.field);
  if (!parent) return true;
  // Visibility chains: a hidden parent hides its dependents too (declaration order
  // forbids cycles). Otherwise a hidden select's default would leak dependents in.
  if (!fieldVisible(ini, t, parent)) return false;
  const v = fieldValue(ini, parent);
  if (f.when.notEmpty) return v.trim() !== "";
  return f.when.in?.includes(v) ?? true;
}

/** Apply one field edit to the INI text, then reconcile conditional fields: keys of
 *  fields that just became hidden are removed, fields that just became visible get
 *  their default written. Returns the new INI document. */
export function applyFieldChange(
  ini: string,
  t: BundleTemplate,
  f: TemplateField,
  value: string,
): string {
  const wasVisible = new Map(t.fields.map((x) => [x.id, fieldVisible(ini, t, x)]));

  let next = ini;
  if (f.kind === "table") {
    // Rows are edited through the table helpers below, not as one value.
    return ini;
  } else if (f.kind === "choice") {
    const opt = f.options.find((o) => o.value === value);
    if (opt) {
      for (const [section, kv] of Object.entries(opt.set)) {
        for (const [k, v] of Object.entries(kv)) next = setIniValue(next, section, k, v);
      }
    }
  } else if (value.trim() === "" && (f.kind === "text" || f.kind === "select")) {
    // Empty text, or an optional select switched off: the key leaves the document.
    next = removeIniKey(next, f.section, f.key);
  } else {
    next = setIniValue(next, f.section, f.key, value);
  }

  for (const field of t.fields) {
    if (!field.when || field.kind === "choice" || field.kind === "table") continue;
    const visible = fieldVisible(next, t, field);
    const present = getIniValue(next, field.section, field.key) !== undefined;
    if (!visible && present) {
      next = removeIniKey(next, field.section, field.key);
    } else if (visible && !wasVisible.get(field.id) && !present) {
      const def = fieldDefault(t, field);
      if (def !== "") next = setIniValue(next, field.section, field.key, def);
    }
  }
  return next;
}

// --- table field row operations (each returns the new INI document) ---

export function tableRows(ini: string, f: TemplateField & { kind: "table" }) {
  return listIniKeys(ini, f.section);
}

/** Insert a preset (or a blank custom row), deduplicating the name with a numeric
 *  suffix (or, for `uniqueKeys` tables, leaving the document alone) and enabling any
 *  modules the check needs. */
export function tableAddRow(
  ini: string,
  f: TemplateField & { kind: "table" },
  preset: TablePreset,
): string {
  const existing = new Set(listIniKeys(ini, f.section).map((r) => r.key));
  let key = preset.key;
  if (f.uniqueKeys && existing.has(key)) return ini;
  for (let n = 2; existing.has(key); n++) key = `${preset.key}_${n}`;
  let next = setIniValue(ini, f.section, key, preset.value);
  for (const m of preset.modules ?? []) next = setIniValue(next, "/modules", m, "enabled");
  return next;
}

export function tableRenameRow(
  ini: string,
  f: TemplateField & { kind: "table" },
  oldKey: string,
  newKey: string,
): string {
  const key = newKey.trim();
  if (key === oldKey || !validTableRowKey(f, key)) return ini;
  if (listIniKeys(ini, f.section).some((r) => r.key === key)) return ini;
  return renameIniKey(ini, f.section, oldKey, key);
}

export function tableSetRow(
  ini: string,
  f: TemplateField & { kind: "table" },
  key: string,
  value: string,
): string {
  return setIniValue(ini, f.section, key, value);
}

export function tableRemoveRow(
  ini: string,
  f: TemplateField & { kind: "table" },
  key: string,
): string {
  return removeIniKey(ini, f.section, key);
}

/** Display order of picker groups. */
export const TEMPLATE_CATEGORIES = [
  "System health",
  "Applications & network",
  "Security & events",
  "Monitoring delivery",
  "Extensibility",
];

const ALIAS = "/settings/check helpers/alias";

/** Shorthand for the ubiquitous alias command fields of check templates. Each check is
 *  optional: switched off, the alias is simply not defined in the bundle. */
function aliasField(id: string, label: string, help?: string): TemplateField {
  return {
    kind: "text",
    id,
    label,
    section: ALIAS,
    key: id,
    help,
    optional: true,
    valueLabel: "command",
  };
}

/** A Windows service short name or a systemd unit name: `MSSQL$SQLEXPRESS`, `php8.2-fpm`,
 *  `getty@tty1`. No whitespace or path separators, since the name is written as an INI key. */
export const SERVICE_NAME_RE = /^[A-Za-z0-9_.@$:+-]{1,128}$/;

/** A host-tag name as group selectors will reference it. */
export const TAG_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;

/** Windows services people commonly want a host tag for: short names as `sc query` and
 *  the service-tags section expect them. Every preset publishes its own tag — the agent
 *  processes entries in name order and a stopped service removes its tag, so two services
 *  sharing one tag would fight over it. */
const WINDOWS_SERVICE_PRESETS: TablePreset[] = [
  { label: "SQL Server (default instance)", key: "MSSQLSERVER", value: "sql-server" },
  { label: "SQL Server Express", key: "MSSQL$SQLEXPRESS", value: "sql-server-express" },
  { label: "SQL Server Agent", key: "SQLSERVERAGENT", value: "sql-server-agent" },
  { label: "IIS (World Wide Web Publishing)", key: "W3SVC", value: "iis" },
  { label: "Exchange Information Store", key: "MSExchangeIS", value: "exchange" },
  { label: "Active Directory Domain Services", key: "NTDS", value: "active-directory" },
  { label: "Active Directory Certificate Services", key: "CertSvc", value: "adcs" },
  { label: "Azure AD Connect sync", key: "ADSync", value: "azure-ad-connect" },
  { label: "DNS Server", key: "DNS", value: "dns-server" },
  { label: "DHCP Server", key: "DHCPServer", value: "dhcp-server" },
  { label: "Hyper-V Virtual Machine Management", key: "vmms", value: "hyper-v" },
  { label: "Failover Clustering", key: "ClusSvc", value: "failover-cluster" },
  { label: "Print Spooler", key: "Spooler", value: "print-server" },
  { label: "WSUS", key: "WsusService", value: "wsus" },
  { label: "Veeam Backup Service", key: "VeeamBackupSvc", value: "veeam" },
  { label: "Apache HTTP Server", key: "Apache2.4", value: "apache" },
  { label: "nginx", key: "nginx", value: "nginx" },
  { label: "MySQL 8", key: "MySQL80", value: "mysql" },
  { label: "PostgreSQL 16", key: "postgresql-x64-16", value: "postgres" },
  { label: "MongoDB", key: "MongoDB", value: "mongodb" },
  { label: "Redis", key: "Redis", value: "redis" },
  { label: "RabbitMQ", key: "RabbitMQ", value: "rabbitmq" },
  { label: "Elasticsearch", key: "elasticsearch-service-x64", value: "elasticsearch" },
  { label: "Apache Tomcat 9", key: "Tomcat9", value: "tomcat" },
  { label: "Jenkins", key: "jenkins", value: "jenkins" },
  { label: "Docker Engine", key: "docker", value: "docker" },
];

/** systemd units, by the names the common distributions ship. */
const LINUX_SERVICE_PRESETS: TablePreset[] = [
  { label: "PostgreSQL", key: "postgresql", value: "postgres" },
  { label: "MySQL", key: "mysql", value: "mysql" },
  { label: "MariaDB", key: "mariadb", value: "mariadb" },
  { label: "nginx", key: "nginx", value: "nginx" },
  { label: "Apache (Debian/Ubuntu: apache2)", key: "apache2", value: "apache" },
  { label: "Apache (RHEL/Fedora: httpd)", key: "httpd", value: "httpd" },
  { label: "HAProxy", key: "haproxy", value: "haproxy" },
  { label: "Redis (redis-server)", key: "redis-server", value: "redis" },
  { label: "MongoDB (mongod)", key: "mongod", value: "mongodb" },
  { label: "RabbitMQ", key: "rabbitmq-server", value: "rabbitmq" },
  { label: "Elasticsearch", key: "elasticsearch", value: "elasticsearch" },
  { label: "Apache Tomcat", key: "tomcat", value: "tomcat" },
  { label: "Jenkins", key: "jenkins", value: "jenkins" },
  { label: "Docker Engine", key: "docker", value: "docker" },
  { label: "containerd", key: "containerd", value: "containerd" },
  { label: "Kubernetes node (kubelet)", key: "kubelet", value: "kubernetes" },
  { label: "k3s", key: "k3s", value: "k3s" },
  { label: "BIND DNS (Debian/Ubuntu: bind9)", key: "bind9", value: "bind9" },
  { label: "BIND DNS (RHEL/Fedora: named)", key: "named", value: "named" },
  { label: "Samba (smbd)", key: "smbd", value: "samba" },
  { label: "NFS server", key: "nfs-server", value: "nfs" },
  { label: "OpenSSH server", key: "sshd", value: "sshd" },
];

/** Channels NSClient modules listen on — the possible targets of a scheduled check.
 *  Values are the module defaults from the reference docs. */
const CHANNEL_OPTIONS: SelectOption[] = [
  { value: "NSCA", label: "NSCA" },
  { value: "NSCA-NG", label: "NSCA-NG" },
  { value: "NRDP", label: "NRDP (Nagios)" },
  { value: "ICINGA", label: "Icinga 2" },
  { value: "GRAPHITE", label: "Graphite" },
  { value: "check_mk-mrpe", label: "Checkmk (MRPE)" },
  { value: "check_mk-local", label: "Checkmk (local)" },
  { value: "op5", label: "op5" },
  { value: "syslog", label: "Syslog" },
  { value: "SMTP", label: "Email (SMTP)" },
  { value: "NSCP", label: "NSCP relay" },
  { value: "FILE", label: "File (SimpleFileWriter)" },
  { value: "noop", label: "Discard (noop — run without reporting)" },
];

export const TEMPLATES: BundleTemplate[] = [
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
    id: "detect-services",
    title: "Detect installed services",
    category: "System health",
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
          "to publish. While the service is running the host carries <tag> = enabled; when " +
          "it is stopped or absent the tag is removed. Give every service its own tag. " +
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
    ini: `; Turn "what runs here" into host tags. Each entry is service = tag; the agent
; publishes tag = enabled while the service is running and removes it otherwise, so a
; group selector on sql-server = enabled follows reality without anyone editing tags.
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

  // ---------------------------------------------------- Applications & network
  {
    id: "sql-server",
    title: "SQL Server monitoring",
    category: "Applications & network",
    description:
      "Microsoft SQL Server essentials: connectivity/uptime, database state, log usage, " +
      "backups and Agent jobs. Uses Windows integrated auth by default.",
    sensitive: true,
    fields: [
      {
        kind: "text",
        id: "hostname",
        label: "SQL Server host",
        section: "/settings/mssql",
        key: "hostname",
        help: "host, host\\INSTANCE or host,port — e.g. localhost\\SQLEXPRESS.",
      },
      {
        kind: "text",
        id: "user",
        label: "SQL login (optional)",
        section: "/settings/mssql",
        key: "user",
        help: "Leave empty for Windows integrated auth as the service account.",
      },
      {
        kind: "text",
        id: "password",
        label: "SQL password",
        section: "/settings/mssql",
        key: "password",
        when: { field: "user", notEmpty: true },
      },
      aliasField("alias_mssql", "Connectivity/uptime check"),
      aliasField("alias_mssql_databases", "Database state check"),
      aliasField("alias_mssql_log_usage", "Log usage check"),
      aliasField("alias_mssql_backup", "Backup age check"),
      aliasField("alias_mssql_jobs", "Agent jobs check"),
    ],
    ini: `[/modules]
CheckMSSQL = enabled
CheckHelpers = enabled

[/settings/mssql]
hostname = localhost
; Windows integrated auth as the service account — no credentials needed.

[/settings/check helpers/alias]
alias_mssql = check_mssql "warning=uptime < 1h"
alias_mssql_databases = check_mssql_databases
alias_mssql_log_usage = check_mssql_databases "warning=log_used_pct > 80" "critical=log_used_pct > 90"
alias_mssql_backup = check_mssql_backup
alias_mssql_jobs = check_mssql_jobs "warning=last_run_age > 25h"
`,
  },
  {
    id: "network-checks",
    title: "Network checks",
    category: "Applications & network",
    description:
      "Ping, TCP port and HTTP/HTTPS health checks against hosts and endpoints this agent " +
      "can reach.",
    fields: [
      aliasField("alias_ping", "Ping check", "put the target in host=…"),
      aliasField("alias_http", "HTTP health check", "put the endpoint in url=…"),
      aliasField("alias_tcp_https", "TCP port check", "put the target in host=…/port=…"),
    ],
    ini: `[/modules]
CheckNet = enabled
CheckHelpers = enabled

[/settings/check helpers/alias]
alias_ping = check_ping host=192.168.0.1 "warn=time > 30 or loss > 0%" "crit=time > 80 or loss > 25%"
alias_http = check_http url=https://myapp.example.com/health
alias_tcp_https = check_tcp host=myserver.example.com port=443 "warn=time > 200" "crit=time > 1000"
`,
  },

  // --------------------------------------------------------- Security & events
  {
    id: "security-posture",
    title: "Host security posture",
    category: "Security & events",
    description:
      "Certificate expiry/hygiene, logon sessions, firewall, antivirus, BitLocker and " +
      "Secure Boot on Windows hosts.",
    fields: [
      aliasField("alias_cert", "Certificate hygiene check"),
      aliasField("alias_users", "Logon sessions check"),
      aliasField("alias_firewall", "Firewall check"),
      aliasField("alias_antivirus", "Antivirus check"),
      aliasField("alias_bitlocker", "BitLocker check"),
      aliasField("alias_secureboot", "Secure Boot check"),
    ],
    ini: `[/modules]
CheckSecurity = enabled
CheckHelpers = enabled

[/settings/check helpers/alias]
alias_cert = check_certificate store=My "crit=expired = 1 or expires_in < 10 or weak_signature = 1"
alias_users = check_users "warn=count > 5" "crit=count > 10"
alias_firewall = check_firewall
alias_antivirus = check_antivirus
alias_bitlocker = check_bitlocker "filter=drive = 'C:'" "crit=protected = 0"
alias_secureboot = check_secureboot "warn=supported = 0" "crit=supported = 1 and enabled = 0"
`,
  },
  {
    id: "event-log",
    title: "Event log monitoring",
    category: "Security & events",
    description:
      "Alert on errors and critical entries in the Windows Event Log over a scan window.",
    fields: [
      aliasField("alias_eventlog_errors", "Error-level check"),
      aliasField("alias_eventlog_critical", "Critical-level check"),
    ],
    ini: `[/modules]
CheckEventLog = enabled
CheckHelpers = enabled

[/settings/check helpers/alias]
alias_eventlog_errors = check_eventlog scan-range=-24h "filter=level = 'error'" "warn=count > 0"
alias_eventlog_critical = check_eventlog scan-range=-24h "filter=level = 'critical'" "crit=count > 0"
`,
  },

  // -------------------------------------------------------- Monitoring delivery
  {
    id: "nrpe-server",
    title: "NRPE server (active)",
    category: "Monitoring delivery",
    description:
      "Let your monitoring server poll this agent over NRPE (port 5666). Checks come " +
      "from the check templates' aliases, so arguments stay disabled.",
    fields: [
      {
        kind: "text",
        id: "allowed_hosts",
        label: "Allowed hosts",
        section: "/settings/NRPE/server",
        key: "allowed hosts",
        help: "IPs/CIDRs of your monitoring servers, comma separated.",
      },
      {
        kind: "text",
        id: "port",
        label: "Port",
        section: "/settings/NRPE/server",
        key: "port",
      },
      {
        kind: "choice",
        id: "security",
        label: "Security level",
        help:
          "Insecure = legacy ADH for old check_nrpe -2 clients. TLS encrypts but " +
          "authenticates nobody (combine with allowed hosts). Mutual TLS additionally " +
          "requires clients to present a certificate signed by your CA.",
        options: [
          {
            value: "insecure",
            label: "Insecure (legacy check_nrpe -2)",
            set: { "/settings/NRPE/server": { insecure: "true", "verify mode": "none" } },
          },
          {
            value: "tls",
            label: "TLS (encryption only)",
            set: { "/settings/NRPE/server": { insecure: "false", "verify mode": "none" } },
          },
          {
            value: "mtls",
            label: "Mutual TLS (require client certificates)",
            set: {
              "/settings/NRPE/server": { insecure: "false", "verify mode": "peer-cert" },
            },
          },
        ],
      },
      {
        kind: "text",
        id: "certificate",
        label: "Server certificate",
        section: "/settings/NRPE/server",
        key: "certificate",
        default: "${certificate-path}/certificate.pem",
        when: { field: "security", in: ["tls", "mtls"] },
      },
      {
        kind: "text",
        id: "certificate_key",
        label: "Certificate key file",
        section: "/settings/NRPE/server",
        key: "certificate key",
        help: "Leave empty if the certificate file bundles its private key.",
        when: { field: "security", in: ["tls", "mtls"] },
      },
      {
        kind: "text",
        id: "ca",
        label: "CA certificate",
        section: "/settings/NRPE/server",
        key: "ca",
        default: "${certificate-path}/ca.pem",
        help: "Clients must present a certificate signed by this CA.",
        when: { field: "security", in: ["mtls"] },
      },
      {
        kind: "bool",
        id: "allow_arguments",
        label: "Allow command arguments",
        section: "/settings/NRPE/server",
        key: "allow arguments",
        default: false,
        help: "Aliases from check templates are argument-free — keep this off.",
      },
    ],
    ini: `[/modules]
NRPEServer = enabled

[/settings/NRPE/server]
port = 5666
allowed hosts = 10.0.0.1
; Aliases from check templates are argument-free, so keep arguments off.
allow arguments = false
allow nasty characters = false
insecure = false
verify mode = none
certificate = \${certificate-path}/certificate.pem
`,
  },
  {
    id: "check-mk-agent",
    title: "Checkmk agent",
    category: "Monitoring delivery",
    description:
      "Serve a Checkmk-compatible agent dump on TCP/6556 for your Checkmk site to poll.",
    fields: [
      {
        kind: "text",
        id: "allowed_hosts",
        label: "Allowed hosts",
        section: "/settings/check_mk/server",
        key: "allowed hosts",
        help: "Your Checkmk site's IP(s), comma separated.",
      },
      {
        kind: "text",
        id: "port",
        label: "Port",
        section: "/settings/check_mk/server",
        key: "port",
      },
    ],
    ini: `[/modules]
CheckMKServer = enabled

[/settings/check_mk/server]
port = 6556
allowed hosts = 127.0.0.1, 10.0.0.5

; Expose NSClient checks as Checkmk services if you like:
; [/settings/check_mk/server/mrpe]
; Uptime = command=check_uptime warn=uptime<2d
`,
  },
  {
    id: "prometheus",
    title: "Prometheus scraping",
    category: "Monitoring delivery",
    description:
      "Expose metrics on /api/v2/openmetrics for Prometheus, behind a dedicated " +
      "least-privilege web user. Metrics come from whichever check modules are enabled.",
    sensitive: true,
    fields: [
      {
        kind: "text",
        id: "password",
        label: "Scrape user password",
        section: "/settings/WEB/server/users/prometheus",
        key: "password",
        help: "Strong random password Prometheus will use (basic auth, user 'prometheus').",
      },
      {
        kind: "text",
        id: "allowed_hosts",
        label: "Allowed hosts",
        section: "/settings/WEB/server",
        key: "allowed hosts",
        help: "Restrict who may reach the web server, comma separated.",
      },
    ],
    ini: `[/modules]
WEBServer = enabled

[/settings/WEB/server]
allowed hosts = 127.0.0.1, 10.0.0.0/24

; A role that can ONLY read metrics and log in — not administer the agent.
[/settings/WEB/server/roles]
prometheus = openmetrics.list,login.get

[/settings/WEB/server/users/prometheus]
role = prometheus
password = change-me
`,
  },
  {
    id: "nsca-client",
    title: "NSCA passive delivery",
    category: "Monitoring delivery",
    description:
      "Push results to an NSCA server on a schedule. Sets the scheduler's default " +
      "channel; add the 'Scheduled baseline checks' template (or your own schedules) for " +
      "what to run.",
    sensitive: true,
    fields: [
      {
        kind: "text",
        id: "address",
        label: "NSCA server address",
        section: "/settings/NSCA/client/targets/default",
        key: "address",
      },
      {
        kind: "select",
        id: "encryption",
        label: "Encryption",
        section: "/settings/NSCA/client/targets/default",
        key: "encryption",
        options: [
          { value: "none", label: "None (not safe)" },
          { value: "xor", label: "XOR (obfuscation only)" },
          { value: "des", label: "DES" },
          { value: "3des", label: "3DES" },
          { value: "aes128", label: "AES-128" },
          { value: "aes192", label: "AES-192" },
          { value: "aes256", label: "AES-256" },
          { value: "blowfish", label: "Blowfish" },
          { value: "serpent", label: "Serpent" },
          { value: "gost", label: "GOST" },
        ],
        default: "aes256",
        help: "Must match the NSCA server's configured algorithm.",
      },
      {
        kind: "text",
        id: "password",
        label: "NSCA password",
        section: "/settings/NSCA/client/targets/default",
        key: "password",
        when: { field: "encryption", in: ["xor", "des", "3des", "aes128", "aes192", "aes256", "blowfish", "serpent", "gost"] },
      },
      {
        kind: "text",
        id: "hostname",
        label: "Reported hostname",
        section: "/settings/NSCA/client",
        key: "hostname",
        help: "auto = computer name; or a fixed name, or e.g. ${host_lc}.${domain_lc}.",
      },
      {
        kind: "text",
        id: "interval",
        label: "Default check interval",
        section: "/settings/scheduler/schedules/default",
        key: "interval",
      },
    ],
    ini: `[/modules]
NSCAClient = enabled
Scheduler = enabled

[/settings/NSCA/client]
hostname = auto

[/settings/NSCA/client/targets/default]
address = 10.0.0.1
encryption = aes256
password = change-me

; Scheduled checks report through this channel unless they override it.
[/settings/scheduler/schedules/default]
channel = NSCA
interval = 5m
report = all
`,
  },
  {
    id: "nsca-ng-client",
    title: "NSCA-NG passive delivery",
    category: "Monitoring delivery",
    description:
      "Push results to an NSCA-NG server (TLS successor to NSCA) using a pre-shared key " +
      "or client certificates. Sets the scheduler's default channel; pair with scheduled " +
      "checks.",
    sensitive: true,
    fields: [
      {
        kind: "text",
        id: "address",
        label: "NSCA-NG server address",
        section: "/settings/NSCA-NG/client/targets/default",
        key: "address",
      },
      {
        kind: "text",
        id: "port",
        label: "Port",
        section: "/settings/NSCA-NG/client/targets/default",
        key: "port",
      },
      {
        kind: "choice",
        id: "auth",
        label: "Authentication",
        help:
          "TLS-PSK uses an identity + shared secret; client certificates use a CA-signed " +
          "certificate pair instead.",
        options: [
          {
            value: "psk",
            label: "Pre-shared key (TLS-PSK)",
            set: {
              "/settings/NSCA-NG/client/targets/default": {
                "use psk": "true",
                "verify mode": "none",
              },
            },
          },
          {
            value: "cert",
            label: "Client certificate (TLS)",
            set: {
              "/settings/NSCA-NG/client/targets/default": {
                "use psk": "false",
                "verify mode": "peer-cert",
              },
            },
          },
        ],
      },
      {
        kind: "text",
        id: "identity",
        label: "PSK identity",
        section: "/settings/NSCA-NG/client/targets/default",
        key: "identity",
        default: "agent01",
        when: { field: "auth", in: ["psk"] },
      },
      {
        kind: "text",
        id: "password",
        label: "Shared secret",
        section: "/settings/NSCA-NG/client/targets/default",
        key: "password",
        default: "change-me",
        when: { field: "auth", in: ["psk"] },
      },
      {
        kind: "text",
        id: "ca",
        label: "CA certificate",
        section: "/settings/NSCA-NG/client/targets/default",
        key: "ca",
        default: "${certificate-path}/ca.pem",
        when: { field: "auth", in: ["cert"] },
      },
      {
        kind: "text",
        id: "certificate",
        label: "Client certificate",
        section: "/settings/NSCA-NG/client/targets/default",
        key: "certificate",
        default: "${certificate-path}/agent.pem",
        when: { field: "auth", in: ["cert"] },
      },
      {
        kind: "text",
        id: "certificate_key",
        label: "Client certificate key",
        section: "/settings/NSCA-NG/client/targets/default",
        key: "certificate key",
        default: "${certificate-path}/agent.key",
        when: { field: "auth", in: ["cert"] },
      },
      {
        kind: "text",
        id: "interval",
        label: "Default check interval",
        section: "/settings/scheduler/schedules/default",
        key: "interval",
      },
    ],
    ini: `[/modules]
NSCANgClient = enabled
Scheduler = enabled

[/settings/NSCA-NG/client/targets/default]
address = nsca-ng.example.com
port = 5668
use psk = true
verify mode = none
identity = agent01
password = change-me

[/settings/scheduler/schedules/default]
channel = NSCA-NG
interval = 5m
report = all
`,
  },
  {
    id: "icinga-client",
    title: "Icinga 2 passive delivery",
    category: "Monitoring delivery",
    description:
      "Submit scheduled check results to the Icinga 2 REST API. Sets the scheduler's " +
      "default channel; pair with scheduled checks.",
    sensitive: true,
    fields: [
      {
        kind: "text",
        id: "address",
        label: "Icinga 2 API URL",
        section: "/settings/Icinga/client/targets/default",
        key: "address",
      },
      {
        kind: "text",
        id: "username",
        label: "API username",
        section: "/settings/Icinga/client/targets/default",
        key: "username",
      },
      {
        kind: "text",
        id: "password",
        label: "API password",
        section: "/settings/Icinga/client/targets/default",
        key: "password",
      },
      {
        kind: "select",
        id: "verify",
        label: "Server verification",
        section: "/settings/Icinga/client/targets/default",
        key: "verify mode",
        options: [
          { value: "peer-cert", label: "Verify certificate chain + hostname (peer-cert)" },
          { value: "none", label: "No verification (trust anything)" },
        ],
        default: "peer-cert",
      },
      {
        kind: "text",
        id: "ca",
        label: "Icinga CA certificate",
        section: "/settings/Icinga/client/targets/default",
        key: "ca",
        default: "${certificate-path}/icinga2-ca.crt",
        help: "Path on the agent to the CA that signed the Icinga API certificate.",
        when: { field: "verify", in: ["peer-cert"] },
      },
      {
        kind: "bool",
        id: "ensure_objects",
        label: "Auto-create host/service objects",
        section: "/settings/Icinga/client/targets/default",
        key: "ensure objects",
        default: false,
        help: "Create missing Icinga objects via the API before submitting results.",
      },
      {
        kind: "text",
        id: "host_template",
        label: "Host template",
        section: "/settings/Icinga/client/targets/default",
        key: "host template",
        default: "generic-host",
        when: { field: "ensure_objects", in: ["true"] },
      },
      {
        kind: "text",
        id: "service_template",
        label: "Service template",
        section: "/settings/Icinga/client/targets/default",
        key: "service template",
        default: "generic-service",
        when: { field: "ensure_objects", in: ["true"] },
      },
      {
        kind: "text",
        id: "interval",
        label: "Default check interval",
        section: "/settings/scheduler/schedules/default",
        key: "interval",
      },
    ],
    ini: `[/modules]
IcingaClient = enabled
Scheduler = enabled

[/settings/Icinga/client]
hostname = auto

[/settings/Icinga/client/targets/default]
address = https://icinga2.example.com:5665/
username = nscp
password = change-me
verify mode = peer-cert
ca = \${certificate-path}/icinga2-ca.crt

[/settings/scheduler/schedules/default]
channel = ICINGA
interval = 5m
report = all
`,
  },
  {
    id: "graphite-client",
    title: "Graphite metrics delivery",
    category: "Monitoring delivery",
    description:
      "Push perfdata and system metrics to a Graphite/carbon backend for graphing. Sets " +
      "the scheduler's default channel; pair with scheduled checks.",
    fields: [
      {
        kind: "text",
        id: "address",
        label: "Carbon address",
        section: "/settings/graphite/client/targets/default",
        key: "address",
        help: "host:port of carbon's line receiver (or a TLS proxy in front of it).",
      },
      {
        kind: "bool",
        id: "ssl",
        label: "TLS to the carbon endpoint",
        section: "/settings/graphite/client/targets/default",
        key: "ssl",
        default: false,
        help: "Carbon itself is plaintext — enable when a TLS proxy (stunnel, …) fronts it.",
      },
      {
        kind: "select",
        id: "verify",
        label: "Server verification",
        section: "/settings/graphite/client/targets/default",
        key: "verify mode",
        options: [
          { value: "peer-cert", label: "Verify certificate chain + hostname (peer-cert)" },
          { value: "none", label: "No verification (trust anything)" },
        ],
        default: "peer-cert",
        when: { field: "ssl", in: ["true"] },
      },
      {
        kind: "text",
        id: "ca",
        label: "CA certificate",
        section: "/settings/graphite/client/targets/default",
        key: "ca",
        default: "${certificate-path}/ca.pem",
        when: { field: "verify", in: ["peer-cert"] },
      },
      {
        kind: "bool",
        id: "send_perfdata",
        label: "Send perfdata",
        section: "/settings/graphite/client/targets/default",
        key: "send perfdata",
        default: true,
      },
      {
        kind: "bool",
        id: "send_status",
        label: "Send status codes",
        section: "/settings/graphite/client/targets/default",
        key: "send status",
        default: true,
      },
      {
        kind: "text",
        id: "hostname",
        label: "Reported hostname",
        section: "/settings/graphite/client",
        key: "hostname",
        help: "auto = computer name; or e.g. ${host_lc}.${domain_lc}.",
      },
      {
        kind: "text",
        id: "interval",
        label: "Default check interval",
        section: "/settings/scheduler/schedules/default",
        key: "interval",
      },
    ],
    ini: `[/modules]
GraphiteClient = enabled
Scheduler = enabled

[/settings/graphite/client]
hostname = auto

[/settings/graphite/client/targets/default]
address = graphite.example.com:2003
send perfdata = true
send status = true
path = nsclient.\${hostname}.\${check_alias}.\${perf_alias}
status path = nsclient.\${hostname}.\${check_alias}.status
metric path = nsclient.\${hostname}.\${metric}

[/settings/scheduler/schedules/default]
channel = GRAPHITE
interval = 1m
report = all
`,
  },
  {
    id: "nrdp-client",
    title: "NRDP passive delivery",
    category: "Monitoring delivery",
    description:
      "Push results to a Nagios NRDP endpoint over HTTP(S). Sets the scheduler's default " +
      "channel; pair with scheduled checks.",
    sensitive: true,
    fields: [
      {
        kind: "text",
        id: "address",
        label: "NRDP URL",
        section: "/settings/NRDP/client/targets/default",
        key: "address",
      },
      {
        kind: "text",
        id: "token",
        label: "NRDP token",
        section: "/settings/NRDP/client/targets/default",
        key: "token",
      },
      {
        kind: "text",
        id: "interval",
        label: "Default check interval",
        section: "/settings/scheduler/schedules/default",
        key: "interval",
      },
    ],
    ini: `[/modules]
NRDPClient = enabled
Scheduler = enabled

[/settings/NRDP/client/targets/default]
address = http://nagios-server/nrdp/
token = change-me

[/settings/scheduler/schedules/default]
channel = NRDP
interval = 5m
report = all
`,
  },
  {
    id: "scheduled-baseline-checks",
    title: "Scheduled baseline checks",
    category: "Monitoring delivery",
    description:
      "What to run on a timer for passive setups: host-alive, CPU, memory and disk. " +
      "Channel and interval come from the delivery template's scheduler defaults.",
    fields: [
      {
        kind: "select",
        id: "channel",
        label: "Set the default target in this bundle",
        section: "/settings/scheduler/schedules/default",
        key: "channel",
        options: CHANNEL_OPTIONS,
        default: "NSCA",
        optional: true,
        valueLabel: "target channel",
        help:
          "Off: inherited from the delivery bundle (NSCA, Icinga, …) assigned to the same " +
          "group. On: this bundle decides where results go — if a delivery bundle also " +
          "sets it, the higher-priority assignment wins.",
      },
      {
        kind: "text",
        id: "interval",
        label: "Set the default interval in this bundle",
        section: "/settings/scheduler/schedules/default",
        key: "interval",
        default: "5m",
        optional: true,
        valueLabel: "interval",
        help:
          "How often each check below runs, e.g. 30s, 5m, 1h. Off: inherited from the " +
          "delivery bundle.",
      },
      {
        kind: "table",
        id: "schedules",
        label: "Scheduled checks",
        section: "/settings/scheduler/schedules",
        help:
          "Each row is one schedule: the name is what the monitoring server sees, the " +
          "command is what runs. Rows inherit channel/interval from the delivery template.",
        presets: [
          { label: "Host alive", key: "host_check", value: "check_ok", modules: ["CheckHelpers"] },
          { label: "CPU load", key: "cpu", value: "check_cpu", modules: ["CheckSystem"] },
          { label: "Memory", key: "memory", value: "check_memory", modules: ["CheckSystem"] },
          {
            label: "Disk C:",
            key: "disk_c",
            value: 'check_drivesize drive=C: "warn=free < 20%" "crit=free < 10%"',
            modules: ["CheckDisk"],
          },
          {
            label: "All fixed disks",
            key: "disk_all",
            value:
              "check_drivesize drive=* \"filter=type in ('fixed')\" \"warn=free < 20%\" \"crit=free < 10%\"",
            modules: ["CheckDisk"],
          },
          {
            label: "Uptime",
            key: "uptime",
            value: 'check_uptime "warn=uptime < 2d"',
            modules: ["CheckSystem"],
          },
          {
            label: "Auto-start services running",
            key: "services",
            value: "check_service",
            modules: ["CheckSystem"],
          },
          {
            label: "Specific process running",
            key: "process",
            value: "check_process process=myapp.exe",
            modules: ["CheckSystem"],
          },
          {
            label: "Event log errors (24h)",
            key: "eventlog_errors",
            value: "check_eventlog scan-range=-24h \"filter=level = 'error'\" \"warn=count > 0\"",
            modules: ["CheckEventLog"],
          },
          {
            label: "Network throughput",
            key: "network",
            value: 'check_network mode=adapter "warn=total > 100M" "crit=total > 500M"',
            modules: ["CheckSystem"],
          },
          {
            label: "Ping a host",
            key: "ping",
            value: "check_ping host=192.168.0.1",
            modules: ["CheckNet"],
          },
          {
            label: "HTTP health URL",
            key: "http",
            value: "check_http url=https://myapp.example.com/health",
            modules: ["CheckNet"],
          },
          {
            label: "Certificate expiry",
            key: "certificates",
            value: 'check_certificate store=My "crit=expired = 1 or expires_in < 10"',
            modules: ["CheckSecurity"],
          },
          { label: "Custom command…", key: "new_check", value: "check_ok" },
        ],
      },
    ],
    ini: `; Entries inherit channel/interval/report from [/settings/scheduler/schedules/default],
; which your delivery template (NSCA, Icinga, Graphite, ...) sets — unless you set them
; in this bundle instead.
[/modules]
Scheduler = enabled
CheckSystem = enabled
CheckDisk = enabled
CheckHelpers = enabled

[/settings/scheduler/schedules]
host_check = check_ok
cpu = check_cpu
memory = check_memory
disk_c = check_drivesize drive=C: "warn=free < 20%" "crit=free < 10%"
`,
  },

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
