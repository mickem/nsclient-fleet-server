import { type SelectOption, type TablePreset, type TemplateField } from "./types";

const ALIAS = "/settings/check helpers/alias";

/** Shorthand for the ubiquitous alias command fields of check templates. Each check is
 *  optional: switched off, the alias is simply not defined in the bundle. */
export function aliasField(id: string, label: string, help?: string): TemplateField {
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
export const WINDOWS_SERVICE_PRESETS: TablePreset[] = [
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
export const LINUX_SERVICE_PRESETS: TablePreset[] = [
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
export const CHANNEL_OPTIONS: SelectOption[] = [
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
