import { getIniValue, removeIniKey, setIniValue } from "../ini";

/** Where a fact set is switched on: the producing module's own `facts` section. */
export type FactTarget = {
  /** Settings section holding the switch. */
  section: string;
  /** Module to enable in `[/modules]`; absent for the core's own sets. */
  module?: string;
  /** Which hosts read this section — shown to the operator, not used in matching. */
  platform: string;
};

/** A fact set the agent can collect. The server holds this map because the agent does not:
 *  a set is enabled in the module that produces it, and which module that is depends on the
 *  platform (see "Host Facts" in the NSClient++ docs). */
export type FactSet = {
  /** The set id, which is also the settings key: `network.interfaces`. */
  id: string;
  label: string;
  description: string;
  /** What collecting it costs the host, as the agent documents it. */
  cost: string;
  targets: FactTarget[];
};

const FACTS_WINDOWS = "/settings/system/windows/facts";

const FACTS_UNIX = "/settings/system/unix/facts";

/** CheckSystem's sets: one section per platform, same keys in both. */
function systemTargets(): FactTarget[] {
  return [
    { section: FACTS_WINDOWS, module: "CheckSystem", platform: "Windows" },
    { section: FACTS_UNIX, module: "CheckSystem", platform: "Linux" },
  ];
}

/** A set produced by a single module, under its default settings alias: a module loaded
 *  under another alias reads `/settings/<alias>/facts` instead. */
function moduleTarget(alias: string, module: string, platform: string): FactTarget {
  return { section: `/settings/${alias}/facts`, module, platform };
}

export const FACT_SETS: FactSet[] = [
  {
    id: "os",
    label: "Operating system",
    description: "Family, name, version, architecture, virtualization and domain.",
    cost: "none — read once at start",
    targets: systemTargets(),
  },
  {
    id: "hardware",
    label: "Hardware",
    description: "Manufacturer, model, CPU cores and memory.",
    cost: "none — read once at start",
    targets: systemTargets(),
  },
  {
    id: "network.interfaces",
    label: "Network interfaces",
    description: "One record per interface: MAC, link state, speed and addresses.",
    cost: "low",
    targets: systemTargets(),
  },
  {
    id: "storage.volumes",
    label: "Volumes",
    description: "One record per volume check_drivesize sees: device, filesystem, type, size.",
    cost: "low",
    targets: [
      { section: "/settings/disk/facts", module: "CheckDisk", platform: "Windows & Linux" },
    ],
  },
  {
    id: "software.installed",
    label: "Installed software",
    description:
      "One record per installed program or package: name, version, publisher, architecture. " +
      "Up to 2500 records — the largest set by far.",
    cost: "the highest: a registry walk or a package-manager query every round",
    targets: systemTargets(),
  },
  {
    id: "services.installed",
    label: "Installed services",
    description:
      "Every Windows service or systemd unit, enabled or not: name, display name, startup " +
      "type — never state or accounts. Up to 2500 records.",
    cost: "an SCM enumeration or bounded systemctl queries every round except startup",
    targets: systemTargets(),
  },
  {
    id: "tasks.scheduled",
    label: "Scheduled tasks",
    description:
      "Every task, including disabled and hidden ones: path, name, folder, enabled, hidden. " +
      "Up to 2500 records.",
    cost: "a Task Scheduler walk every round except startup",
    targets: [moduleTarget("task schedule", "CheckTaskSched", "Windows")],
  },
  {
    id: "hyperv.vms",
    label: "Hyper-V virtual machines",
    description:
      "Name, generation, configuration version, vCPUs, memory, checkpoints and replica " +
      "role. Only useful on Hyper-V hosts.",
    cost: "moderate: the WMI queries check_hyperv_vms runs, every round except startup",
    targets: [moduleTarget("hyperv", "CheckHyperV", "Windows")],
  },
  {
    id: "docker",
    label: "Docker daemon",
    description: "Daemon version, OS, storage and cgroup drivers, CPUs, memory, swarm state.",
    cost: "low: one Docker API call every round except startup",
    targets: [moduleTarget("docker", "CheckDocker", "Windows & Linux")],
  },
  {
    id: "docker.containers",
    label: "Docker containers",
    description: "One record per container: image, created, ports, compose project and service.",
    cost: "low: one Docker API call every round except startup",
    targets: [moduleTarget("docker", "CheckDocker", "Windows & Linux")],
  },
  {
    id: "docker.images",
    label: "Docker images",
    description: "One record per image: tags, created, size.",
    cost: "low: one Docker API call every round except startup",
    targets: [moduleTarget("docker", "CheckDocker", "Windows & Linux")],
  },
  {
    id: "mysql",
    label: "MySQL server",
    description:
      "Flavor, version, port, server id, character set and collation. Connects with the " +
      "credentials in [/settings/mysql] — keep those in an encrypted bundle.",
    cost: "low: one query every round except startup",
    targets: [moduleTarget("mysql", "CheckMySQL", "Windows & Linux")],
  },
  {
    id: "mysql.databases",
    label: "MySQL databases",
    description: "One record per schema: character set and collation.",
    cost: "low: one query on the same connection",
    targets: [moduleTarget("mysql", "CheckMySQL", "Windows & Linux")],
  },
  {
    id: "mssql",
    label: "SQL Server",
    description:
      "Instance, version, CU level, edition, collation, authentication mode, clustering " +
      "and Always On, over CheckMSSQL's connection.",
    cost: "low: one query every round except startup",
    targets: [moduleTarget("mssql", "CheckMSSQL", "Windows")],
  },
  {
    id: "mssql.databases",
    label: "SQL Server databases",
    description: "One record per database: recovery model, collation, compatibility level.",
    cost: "low: one query on the same connection",
    targets: [moduleTarget("mssql", "CheckMSSQL", "Windows")],
  },
  {
    id: "agent",
    label: "NSClient++ agent",
    description: "Agent version, the loaded modules, and whether it is enrolled.",
    cost: "none",
    targets: [{ section: "/settings/facts", platform: "Windows & Linux" }],
  },
];

const isTrue = (v: string | undefined) =>
  v !== undefined && ["true", "1", "yes", "enabled"].includes(v.trim().toLowerCase());

/** How many of a set's switches the document turns on, out of how many there are. A set
 *  switched on for one platform only (hand-edited) reads as partial. */
export function factSetState(ini: string, set: FactSet): "on" | "off" | "partial" {
  const on = set.targets.filter((t) => isTrue(getIniValue(ini, t.section, set.id))).length;
  if (on === 0) return "off";
  return on === set.targets.length ? "on" : "partial";
}

/** Switch a set on (every platform's key, plus the producing modules) or off (the keys
 *  removed, the modules left alone — other bundles may need them). */
export function setFactSet(ini: string, set: FactSet, on: boolean): string {
  let next = ini;
  for (const t of set.targets) {
    next = on ? setIniValue(next, t.section, set.id, "true") : removeIniKey(next, t.section, set.id);
  }
  if (on) {
    for (const m of new Set(set.targets.flatMap((t) => (t.module ? [t.module] : [])))) {
      next = setIniValue(next, "/modules", m, "enabled");
    }
  }
  return next;
}
