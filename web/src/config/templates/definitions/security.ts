import { aliasField } from "../shared";
import { type BundleTemplate } from "../types";

export const SECURITY: BundleTemplate[] = [
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
];
