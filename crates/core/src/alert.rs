//! The alert-context document: what an agent sends when a check goes WARNING or CRITICAL.
//!
//! A check result on its own is a sentence — `CRITICAL: C:\ used 95.2%`. That is enough for
//! a human who already knows the host, and not enough for anything else. The context
//! document is the same result plus what the agent could see around it at the moment it
//! fired: the command and arguments that produced it, every detail line and performance
//! sample, the facts the fleet already knows about the host, and the output of whatever
//! *context commands* the operator attached to that check (top processes, the largest
//! directories, the tail of an event log).
//!
//! It exists to be read by something that was not there — an operator arriving at a console
//! hours later, or the language model that writes the description for them. Everything in
//! here follows from that:
//!
//!   * **The agent decides what is worth sending, the server decides what it will keep.**
//!     Every bound in this module is enforced on ingest, because the agent is the one
//!     machine in the system we do not control.
//!   * **It is data, never instruction.** Process names, log lines and script output are
//!     written by whatever is running on the customer's host. By the time it reaches a
//!     prompt it has to be framed as quoted evidence, and this module's job is to make sure
//!     it arrives intact and bounded rather than to sanitise it into something else.
//!   * **The same problem is one row, not one row per execution.** Checks run on a timer;
//!     a disk that is full at 10:00 is still full at 10:01. [`AlertContext::fingerprint`]
//!     is what lets the store collapse those into a single record with an occurrence
//!     count — see [`crate::alert::fingerprint`] for what is and is not part of it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Alerts accepted in one request body.
///
/// An agent that has just booted, or one whose host has genuinely fallen over, can have
/// dozens of checks failing at once. Posting them one at a time would spend the host's
/// entire per-minute request budget on the first few, so the endpoint takes a batch — and
/// this is what stops "a batch" from meaning "everything, forever".
pub const MAX_ALERTS_PER_REPORT: usize = 32;

/// Bytes of JSON accepted in one request body, before parsing.
///
/// The per-field caps below bound a *well-formed* document. This bounds a hostile one: it
/// is what the ingest handler applies to the raw body so a 50 MB array of empty objects is
/// refused at the socket rather than after it has been parsed into memory.
pub const MAX_REPORT_BYTES: usize = 512 * 1024;

/// Characters kept from a check's command name.
pub const MAX_COMMAND_LEN: usize = 128;
/// Characters kept from a check's alias.
pub const MAX_ALIAS_LEN: usize = 128;
/// Arguments kept from one check invocation, and characters kept from each.
pub const MAX_ARGUMENTS: usize = 32;
pub const MAX_ARGUMENT_LEN: usize = 512;
/// Detail lines kept from one check result, and characters kept from each.
///
/// A filter check with an empty `top-syntax` can emit one line per matched object — a
/// `check_files` over a large tree produces thousands. Twenty is what a person reads.
pub const MAX_LINES: usize = 20;
pub const MAX_LINE_LEN: usize = 2048;
/// Performance samples kept per detail line.
pub const MAX_PERF_PER_LINE: usize = 32;
/// Context commands kept per alert, and characters kept from each one's output.
///
/// The output cap is the largest single number here: context command output is the part
/// that actually explains the alert, and truncating a process table to a few hundred bytes
/// would leave the most useful evidence on the floor.
pub const MAX_CONTEXT_ITEMS: usize = 8;
pub const MAX_CONTEXT_OUTPUT_LEN: usize = 8192;
pub const MAX_CONTEXT_NAME_LEN: usize = 64;

/// Host facts carried with the alert, and characters kept from each value.
pub const MAX_HOST_FACTS: usize = 32;
pub const MAX_FACT_LEN: usize = 256;

/// The status a check reported. Only the two failing states are accepted: an OK result has
/// no error to describe, and UNKNOWN means the check itself did not run, which is an agent
/// problem rather than a host problem and is already visible in the state report's errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatus {
    Warning,
    Critical,
}

impl AlertStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "warning" => Some(Self::Warning),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// One performance sample, in the shape the agent's perfdata already has.
///
/// Every field but `value` is optional because Nagios perfdata makes them optional, and a
/// check that reports a bare number is still telling us something. `value` is an `f64`
/// rather than a string: it is the one field a reader might want to compare or plot, and
/// keeping it typed here means a malformed number is rejected on ingest instead of
/// discovered later.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerfSample {
    pub alias: String,
    pub value: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<f64>,
}

/// One detail line of a check result, with the samples that belong to it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultLine {
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub perf: Vec<PerfSample>,
}

/// The output of one context command the agent ran because the check failed.
///
/// `command` is kept alongside `output` so a reader can tell what produced it — an operator
/// looking at a process table needs to know whether it was sorted by CPU or by memory, and
/// a model asked to explain an alert should not have to guess.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextItem {
    /// Operator-chosen label, e.g. `top-processes`.
    pub name: String,
    /// The command the agent ran, as invoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// What it printed. Truncated to [`MAX_CONTEXT_OUTPUT_LEN`]; `truncated` says so.
    pub output: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    /// Set when the context command itself failed, so a reader does not mistake an error
    /// message for evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One failing check, with everything the agent gathered about it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertContext {
    /// The registered check command, e.g. `check_drivesize`.
    pub command: String,
    /// The schedule or caller alias, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Arguments as the check received them, e.g. `["drive=C:", "critical=used>90%"]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<String>,
    /// What ran the check: `scheduler`, `nrpe`, `rest`, … Free-form; it is reported for a
    /// reader's benefit and never interpreted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub status: AlertStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<ResultLine>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<ContextItem>,
    /// Facts about the host at the moment the check fired (`os`, `os_version`, `uptime`,
    /// …). Distinct from the fleet's own tags, which the server already has and adds when
    /// it builds the prompt — these are the ones only the agent knew.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub host_facts: std::collections::BTreeMap<String, String>,
    /// When the check ran, as the agent's clock saw it. Advisory: the server stamps its own
    /// `last_seen_at` and never trusts this for ordering or retention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<i64>,
}

/// What the agent POSTs. An envelope rather than a bare array so the contract has somewhere
/// to grow without becoming a different endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertReport {
    pub alerts: Vec<AlertContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AlertError {
    #[error("too many alerts in one report (max {MAX_ALERTS_PER_REPORT})")]
    TooManyAlerts,
    #[error("report contained no alerts")]
    Empty,
    #[error("command is empty")]
    EmptyCommand,
    #[error("a performance sample carried a value that is not a finite number")]
    NonFiniteSample,
}

impl AlertContext {
    /// Bring one alert inside every bound in this module.
    ///
    /// Clamping rather than rejecting is deliberate for everything except the two cases in
    /// [`AlertError`]: a host that sends twenty-five arguments has a check we would still
    /// like to describe, and refusing the whole document over it would lose the alert to
    /// protect a column width. The two it does refuse are the ones where there is nothing
    /// left to keep (no command) or where accepting would store a value that cannot mean
    /// anything (a NaN masquerading as a measurement — it would compare false against every
    /// threshold and render as `NaN` to whoever read it).
    pub fn normalize(&mut self) -> Result<(), AlertError> {
        self.command = clamp(self.command.trim(), MAX_COMMAND_LEN);
        if self.command.is_empty() {
            return Err(AlertError::EmptyCommand);
        }
        self.alias = self
            .alias
            .take()
            .map(|a| clamp(a.trim(), MAX_ALIAS_LEN))
            .filter(|a| !a.is_empty());
        self.source = self
            .source
            .take()
            .map(|s| clamp(s.trim(), MAX_ALIAS_LEN))
            .filter(|s| !s.is_empty());

        self.arguments.truncate(MAX_ARGUMENTS);
        for a in &mut self.arguments {
            *a = clamp(a, MAX_ARGUMENT_LEN);
        }

        self.lines.truncate(MAX_LINES);
        for line in &mut self.lines {
            line.message = clamp(&line.message, MAX_LINE_LEN);
            line.perf.truncate(MAX_PERF_PER_LINE);
            for p in &line.perf {
                // Every optional field is checked, not just `value`: a threshold of NaN is
                // as meaningless as a reading of NaN, and serde accepts both.
                if !p.value.is_finite()
                    || [p.warning, p.critical, p.minimum, p.maximum]
                        .iter()
                        .flatten()
                        .any(|v| !v.is_finite())
                {
                    return Err(AlertError::NonFiniteSample);
                }
            }
            for p in &mut line.perf {
                p.alias = clamp(&p.alias, MAX_ALIAS_LEN);
                p.unit = p
                    .unit
                    .take()
                    .map(|u| clamp(&u, 32))
                    .filter(|u| !u.is_empty());
            }
        }

        self.context.truncate(MAX_CONTEXT_ITEMS);
        for item in &mut self.context {
            item.name = clamp(item.name.trim(), MAX_CONTEXT_NAME_LEN);
            item.command = item
                .command
                .take()
                .map(|c| clamp(&c, MAX_ARGUMENT_LEN))
                .filter(|c| !c.is_empty());
            if item.output.chars().count() > MAX_CONTEXT_OUTPUT_LEN {
                item.output = clamp(&item.output, MAX_CONTEXT_OUTPUT_LEN);
                item.truncated = true;
            }
            item.error = item
                .error
                .take()
                .map(|e| clamp(&e, MAX_LINE_LEN))
                .filter(|e| !e.is_empty());
        }

        // Facts are a map, so truncating means dropping whichever keys sort last rather
        // than whichever arrived last — stable, and stable is what the fingerprint needs.
        while self.host_facts.len() > MAX_HOST_FACTS {
            let last = self
                .host_facts
                .keys()
                .next_back()
                .expect("non-empty by loop condition")
                .clone();
            self.host_facts.remove(&last);
        }
        self.host_facts = std::mem::take(&mut self.host_facts)
            .into_iter()
            .map(|(k, v)| (clamp(&k, MAX_KEY_LEN_FACT), clamp(&v, MAX_FACT_LEN)))
            .filter(|(k, _)| !k.is_empty())
            .collect();

        Ok(())
    }

    /// The identity of the *problem*, as opposed to the identity of this execution.
    ///
    /// Two results share a fingerprint when they are the same check, invoked the same way,
    /// failing the same way. What is deliberately **not** in it:
    ///
    ///   * the detail lines and measurements — `95.2%` and `95.3%` are the same problem,
    ///     and including them would defeat the coalescing entirely for any check that
    ///     reports a number;
    ///   * the context command output, for the same reason, only more so;
    ///   * the timestamp.
    ///
    /// What **is** in it: the command, its arguments, and the status. Arguments matter
    /// because `check_drivesize drive=C:` and `drive=D:` are different problems on one
    /// host. Status matters because a check crossing from warning to critical is news — it
    /// gets its own row, its own description, and does not silently overwrite the warning's.
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        // Length-prefixed rather than separator-joined: an argument may contain any byte,
        // including whatever separator we picked, and `["a b"]` must not collide with
        // `["a", "b"]`.
        let mut field = |bytes: &[u8]| {
            h.update((bytes.len() as u64).to_be_bytes());
            h.update(bytes);
        };
        field(b"nsclient-fleet/alert-fingerprint/v1");
        field(self.command.as_bytes());
        field(self.status.as_str().as_bytes());
        field(&(self.arguments.len() as u64).to_be_bytes());
        for a in &self.arguments {
            field(a.as_bytes());
        }
        hex(&h.finalize())
    }

    /// The one-line summary shown in a list, before anyone opens the alert.
    ///
    /// The first detail line is what a Nagios-style check puts its verdict on, so it is the
    /// line worth showing; a check that produced none falls back to naming itself, which is
    /// still better than an empty cell.
    pub fn summary_line(&self) -> String {
        self.lines
            .first()
            .map(|l| l.message.trim())
            .filter(|m| !m.is_empty())
            .map(|m| clamp(m, 512))
            .unwrap_or_else(|| format!("{} returned {}", self.command, self.status.as_str()))
    }
}

/// Facts are agent-chosen keys, so they get the selector's key bound rather than a new one.
const MAX_KEY_LEN_FACT: usize = crate::selector::MAX_KEY_LEN;

impl AlertReport {
    /// Normalize every alert, dropping the ones that cannot be stored.
    ///
    /// Returns the reasons alerts were dropped alongside the survivors: a batch is
    /// partially accepted rather than wholly refused, because one malformed entry among
    /// thirty should not cost the other twenty-nine. A report that turns out to be empty —
    /// either as sent or after dropping — is the one case the caller is told about, since
    /// there is nothing left to acknowledge.
    pub fn normalize(&mut self) -> Result<Vec<AlertError>, AlertError> {
        if self.alerts.len() > MAX_ALERTS_PER_REPORT {
            return Err(AlertError::TooManyAlerts);
        }
        if self.alerts.is_empty() {
            return Err(AlertError::Empty);
        }
        let mut dropped = Vec::new();
        let mut kept = Vec::with_capacity(self.alerts.len());
        for mut alert in std::mem::take(&mut self.alerts) {
            match alert.normalize() {
                Ok(()) => kept.push(alert),
                Err(e) => dropped.push(e),
            }
        }
        if kept.is_empty() {
            return Err(dropped.into_iter().next().unwrap_or(AlertError::Empty));
        }
        self.alerts = kept;
        Ok(dropped)
    }
}

/// A fresh alert-context id.
///
/// A ULID like every other id in the schema: sortable by creation time, which makes the
/// primary key and the common ordering agree.
pub fn new_alert_id() -> String {
    ulid::Ulid::new().to_string()
}

/// Truncate to `max` *characters*, never splitting one.
///
/// `&str[..n]` panics on a byte index inside a multi-byte character, and check output is
/// full of them — a Windows path, a service name, a log line in any language but English.
fn clamp(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(command: &str, args: &[&str], status: AlertStatus) -> AlertContext {
        AlertContext {
            command: command.into(),
            alias: None,
            arguments: args.iter().map(|a| (*a).to_string()).collect(),
            source: None,
            status,
            lines: vec![],
            context: vec![],
            host_facts: Default::default(),
            observed_at: None,
        }
    }

    #[test]
    fn same_check_same_invocation_is_one_problem() {
        let mut a = alert("check_drivesize", &["drive=C:"], AlertStatus::Critical);
        let mut b = alert("check_drivesize", &["drive=C:"], AlertStatus::Critical);
        // Different readings, different moment, different detail text.
        a.lines = vec![ResultLine {
            message: "C:\\ used 95.2%".into(),
            perf: vec![PerfSample {
                alias: "C:\\ used".into(),
                value: 95.2,
                unit: Some("%".into()),
                warning: Some(80.0),
                critical: Some(90.0),
                minimum: None,
                maximum: None,
            }],
        }];
        b.lines = vec![ResultLine {
            message: "C:\\ used 96.8%".into(),
            perf: vec![],
        }];
        b.observed_at = Some(1_758_240_000);
        assert_eq!(
            a.fingerprint(),
            b.fingerprint(),
            "a moving measurement must not create a second row for one problem"
        );
    }

    #[test]
    fn different_target_and_different_severity_are_different_problems() {
        let c = alert("check_drivesize", &["drive=C:"], AlertStatus::Critical);
        let d = alert("check_drivesize", &["drive=D:"], AlertStatus::Critical);
        let warn = alert("check_drivesize", &["drive=C:"], AlertStatus::Warning);
        assert_ne!(c.fingerprint(), d.fingerprint());
        assert_ne!(
            c.fingerprint(),
            warn.fingerprint(),
            "crossing from warning to critical is news and needs its own description"
        );
    }

    #[test]
    fn argument_boundaries_cannot_be_forged() {
        let joined = alert("c", &["a b"], AlertStatus::Warning);
        let split = alert("c", &["a", "b"], AlertStatus::Warning);
        assert_ne!(joined.fingerprint(), split.fingerprint());
    }

    #[test]
    fn oversized_fields_are_clamped_not_refused() {
        let mut a = alert("check_x", &[], AlertStatus::Warning);
        a.arguments = (0..MAX_ARGUMENTS + 10).map(|i| i.to_string()).collect();
        a.lines = (0..MAX_LINES + 5)
            .map(|i| ResultLine {
                message: format!("line {i}"),
                perf: vec![],
            })
            .collect();
        a.context = (0..MAX_CONTEXT_ITEMS + 3)
            .map(|i| ContextItem {
                name: format!("ctx{i}"),
                command: None,
                output: "x".repeat(MAX_CONTEXT_OUTPUT_LEN + 100),
                truncated: false,
                error: None,
            })
            .collect();
        a.normalize().expect("clamping, not refusal");
        assert_eq!(a.arguments.len(), MAX_ARGUMENTS);
        assert_eq!(a.lines.len(), MAX_LINES);
        assert_eq!(a.context.len(), MAX_CONTEXT_ITEMS);
        assert_eq!(a.context[0].output.chars().count(), MAX_CONTEXT_OUTPUT_LEN);
        assert!(
            a.context[0].truncated,
            "a reader must be able to tell the evidence was cut"
        );
    }

    #[test]
    fn truncation_never_splits_a_character() {
        let mut a = alert("check_x", &[], AlertStatus::Warning);
        // Four-byte characters, so a byte-index truncation would panic or produce mojibake.
        a.context = vec![ContextItem {
            name: "ctx".into(),
            command: None,
            output: "🧟".repeat(MAX_CONTEXT_OUTPUT_LEN + 50),
            truncated: false,
            error: None,
        }];
        a.normalize().unwrap();
        assert_eq!(a.context[0].output.chars().count(), MAX_CONTEXT_OUTPUT_LEN);
    }

    #[test]
    fn a_measurement_that_is_not_a_number_is_refused() {
        let mut a = alert("check_x", &[], AlertStatus::Critical);
        a.lines = vec![ResultLine {
            message: "m".into(),
            perf: vec![PerfSample {
                alias: "p".into(),
                value: f64::NAN,
                unit: None,
                warning: None,
                critical: None,
                minimum: None,
                maximum: None,
            }],
        }];
        assert_eq!(a.normalize(), Err(AlertError::NonFiniteSample));

        let mut b = alert("check_x", &[], AlertStatus::Critical);
        b.lines = vec![ResultLine {
            message: "m".into(),
            perf: vec![PerfSample {
                alias: "p".into(),
                value: 1.0,
                unit: None,
                warning: Some(f64::INFINITY),
                critical: None,
                minimum: None,
                maximum: None,
            }],
        }];
        assert_eq!(
            b.normalize(),
            Err(AlertError::NonFiniteSample),
            "a threshold is as much a measurement as a reading"
        );
    }

    #[test]
    fn one_bad_alert_does_not_cost_the_rest_of_the_batch() {
        let mut report = AlertReport {
            alerts: vec![
                alert("check_a", &[], AlertStatus::Warning),
                alert("", &[], AlertStatus::Warning),
                alert("check_b", &[], AlertStatus::Critical),
            ],
        };
        let dropped = report.normalize().expect("partial acceptance");
        assert_eq!(dropped, vec![AlertError::EmptyCommand]);
        assert_eq!(report.alerts.len(), 2);
    }

    #[test]
    fn a_report_with_nothing_storable_is_refused() {
        let mut report = AlertReport {
            alerts: vec![alert("", &[], AlertStatus::Warning)],
        };
        assert_eq!(report.normalize(), Err(AlertError::EmptyCommand));

        let mut empty = AlertReport { alerts: vec![] };
        assert_eq!(empty.normalize(), Err(AlertError::Empty));
    }

    #[test]
    fn summary_prefers_the_verdict_line_and_always_says_something() {
        let mut a = alert("check_drivesize", &[], AlertStatus::Critical);
        assert_eq!(
            a.summary_line(),
            "check_drivesize returned critical",
            "an empty result still has to render as a row"
        );
        a.lines = vec![ResultLine {
            message: "  C:\\ used 95.2% > 90%  ".into(),
            perf: vec![],
        }];
        assert_eq!(a.summary_line(), "C:\\ used 95.2% > 90%");
    }

    #[test]
    fn facts_are_dropped_deterministically() {
        let mut a = alert("check_x", &[], AlertStatus::Warning);
        a.host_facts = (0..MAX_HOST_FACTS + 10)
            .map(|i| (format!("k{i:03}"), "v".to_string()))
            .collect();
        let mut b = a.clone();
        a.normalize().unwrap();
        b.normalize().unwrap();
        assert_eq!(a.host_facts.len(), MAX_HOST_FACTS);
        assert_eq!(
            a.host_facts, b.host_facts,
            "two agents sending the same facts must keep the same subset"
        );
    }

    #[test]
    fn status_round_trips_through_its_stored_form() {
        for s in [AlertStatus::Warning, AlertStatus::Critical] {
            assert_eq!(AlertStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(AlertStatus::parse("ok"), None);
        assert_eq!(AlertStatus::parse("unknown"), None);
    }
}
