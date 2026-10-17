import { CHANNEL_OPTIONS } from "../shared";
import { type BundleTemplate } from "../types";

export const DELIVERY: BundleTemplate[] = [
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
];
