import { aliasField } from "../shared";
import { type BundleTemplate } from "../types";

export const APPLICATIONS: BundleTemplate[] = [
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
];
