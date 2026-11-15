//! Failure context: one failed check, with the metrics snapshot and the diagnostics tables
//! the agent held when it failed.
//!
//! The wire contract is the agent's (NSClient++ `service/failure_report.hpp`,
//! `include/onboarding/failure_context_pacer.hpp`), and this module is the server's side of
//! it. A failed check says what came back; the snapshot says what the host looked like at
//! that moment, which is what lets an operator — or a language model writing for one —
//! explain it rather than restate it.
//!
//! Three properties of the agent's design shape everything here:
//!
//! * **The server has to ask.** Every desired-state answer carries
//!   [`FAILURE_CONTEXT_HEADER`]; an agent that never sees it never posts. So the feature is
//!   opt-in from *both* ends, and a server that stops advertising stops receiving.
//! * **One report per host per interval, not per failure.** The agent sends the newest
//!   failure that still has its snapshot and summarises every other failure since its last
//!   report in [`Suppressed`]. A check that flapped thirty times in the hour arrives as one
//!   report and a count — so the volume this endpoint has to carry is set by the interval,
//!   not by how badly the fleet is doing.
//! * **It is the agent's JSON, faithfully.** Perfdata values and thresholds are numbers *or*
//!   strings (a Nagios range such as `"4:5"` is a string), `arguments` is absent rather than
//!   empty when the agent does not record them, and `metrics`/`metadata` are absent unless a
//!   snapshot was captured. This module models that as it is, rather than imposing a tidier
//!   shape the agent does not send.
//!
//! Everything in a report was produced by a machine we do not control, so every bound below
//! is enforced on ingest — see [`FailureReport::normalize`].

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Response header on desired-state answers by which a server says it takes reports.
/// Lowercase, as the agent looks it up.
pub const FAILURE_CONTEXT_HEADER: &str = "x-failure-context";

/// The only value the agent reads as "yes". It also accepts `accept; min-interval=<seconds>`,
/// which [`accept_header_value`] builds; anything else reads as "no".
pub const FAILURE_CONTEXT_ACCEPT: &str = "accept";

/// Bytes of JSON accepted in one report body, before parsing.
///
/// A snapshot measures ~70 KB of protobuf on a busy Windows host and ~120 KB rendered as
/// JSON with metadata, per the agent's own measurements. 1 MiB leaves a wide margin for a
/// host with far more modules publishing metrics while still bounding a hostile body — and
/// the margin matters, because the agent treats a `413` as permanent and drops the report
/// rather than retrying it.
pub const MAX_REPORT_BYTES: usize = 1024 * 1024;

/// Characters kept from a command, alias or subject.
pub const MAX_COMMAND_LEN: usize = 128;
/// Arguments kept, and characters kept from each.
pub const MAX_ARGUMENTS: usize = 32;
pub const MAX_ARGUMENT_LEN: usize = 512;
/// Detail lines kept, and characters kept from each.
pub const MAX_LINES: usize = 20;
pub const MAX_LINE_LEN: usize = 2048;
/// Performance samples kept per line.
pub const MAX_PERF_PER_LINE: usize = 64;
/// Metric keys kept from a snapshot.
///
/// The agent measured 521 keys on a host running CheckSystem, CheckDisk and CheckNet. This
/// is roomy enough for several times that while still bounding what one host can make the
/// server store and later render.
pub const MAX_METRICS: usize = 4096;
/// Characters kept from a metric key, and from a string metric's value.
pub const MAX_METRIC_KEY_LEN: usize = 256;
pub const MAX_METRIC_VALUE_LEN: usize = 512;
/// Groups kept in the suppressed summary.
pub const MAX_SUPPRESSED_GROUPS: usize = 64;
/// Diagnostics tables kept from a snapshot, and the columns and rows kept from each.
///
/// The agent's own caps are 16 tables and 50 rows (`diagnostics rows`), and its widest table
/// has seven columns. These are the agent's numbers with room in the column count, so a
/// well-behaved agent never loses anything here and a hostile one cannot store more than a
/// well-behaved one could.
pub const MAX_DIAGNOSTICS_SECTIONS: usize = 16;
pub const MAX_DIAGNOSTICS_COLUMNS: usize = 32;
pub const MAX_DIAGNOSTICS_ROWS: usize = 50;
/// Characters kept from a table cell: the agent's own cell cap, in characters.
pub const MAX_DIAGNOSTICS_CELL_LEN: usize = 1024;
/// Characters kept from a table's or a column's description, and from a table's error.
pub const MAX_DIAGNOSTICS_TEXT_LEN: usize = 512;

/// What became of the metrics snapshot a failure was recorded with, as the agent spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextState {
    /// The snapshot is in this report.
    Captured,
    /// It was captured but the agent's budget released it before the report went.
    Evicted,
    /// It was over the agent's per-snapshot cap and never kept.
    TooLarge,
    /// `capture metrics` is off on the agent.
    Disabled,
    /// No snapshot had been collected yet when the check failed.
    None,
}

impl ContextState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Captured => "captured",
            Self::Evicted => "evicted",
            Self::TooLarge => "too_large",
            Self::Disabled => "disabled",
            Self::None => "none",
        }
    }
}

/// One performance sample. Every field but the alias is free-form JSON because the agent's
/// own renderer emits numbers for plain thresholds and strings for Nagios range syntax, and
/// a string for a string-valued sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerfSample {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<serde_json::Value>,
}

/// One detail line, with its perfdata keyed by alias — the shape the agent's query endpoint
/// has always served.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ResultLine {
    #[serde(default)]
    pub message: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub perf: BTreeMap<String, PerfSample>,
}

/// The failed check, as `/api/v2/failures` renders an entry plus the report's `date`.
///
/// The agent removes its own `context` reference from this object and sends the context at
/// the top level of the report instead, so there is no field for it here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FailedCheck {
    /// The agent's log index. Restarts at 1 with the process, so it orders within one run
    /// and means nothing across runs — never use it as an identity.
    #[serde(default)]
    pub index: i64,
    /// Unix seconds, from the agent's clock.
    #[serde(default)]
    pub timestamp: i64,
    /// The same instant as an ISO-8601 string, as the agent formats it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// Who asked: the module that dispatched the query and, when known, the principal
    /// behind it (`WEBServer:admin`, `NRPEServer`, `Scheduler`).
    #[serde(default)]
    pub subject: String,
    /// 0 for a check a client asked for, 1+ for one a check ran on its behalf.
    #[serde(default)]
    pub depth: i64,
    pub command: String,
    #[serde(default)]
    pub alias: String,
    /// Nagios status number: 1 warning, 2 critical, 3 unknown. 0 (OK) is possible only if
    /// an operator configured the agent's log to record passing checks.
    #[serde(default)]
    pub status: i64,
    /// The same thing as a word (`CRITICAL`), as the agent spells it.
    #[serde(default)]
    pub result: String,
    /// The first line's text on its own.
    #[serde(default)]
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<ResultLine>,
    /// Absent when the agent does not record arguments — which is its default. A reader must
    /// be able to tell that from an empty list, so this stays an `Option`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,
}

/// The metrics snapshot, and what became of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsContext {
    pub state: ContextState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
    /// How stale the snapshot was when the check failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_seconds: Option<i64>,
    /// The flat `{key: value}` document, as `/api/v2/metrics` serves it. Present only when
    /// the state is `captured`. Values are numbers, or strings for the string metrics some
    /// modules publish (host names, OS versions, interface addresses).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metrics: BTreeMap<String, serde_json::Value>,
    /// Per-key `{type, help, unit, labels}`, as `/api/v2/metrics?meta=1` serves it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

/// One column of a diagnostics table.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct DiagnosticsColumn {
    #[serde(default)]
    pub name: String,
    /// `string`, `int`, `float`, `timestamp` or `bool`, as the agent spells it. Kept as text:
    /// it is the agent's vocabulary, and a type added later should render as a plain value
    /// rather than cost the table.
    #[serde(default, rename = "type")]
    pub kind: String,
    /// `bytes`, `percent`; absent when the column has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// One diagnostics table: rows and columns that name things (the processes using the most
/// CPU, the services in trouble, the last errors in the system logs) in the shape the
/// agent's `/api/v2/diagnostics/{section}` serves.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct DiagnosticsSection {
    /// The module that produced it, or `core`.
    #[serde(default)]
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// When this table was last refreshed, which can be older than the snapshot it is in: a
    /// table measured on a slow cadence is handed over as it last was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
    /// A cap cut the table: "10 rows" means "at least 10".
    #[serde(default)]
    pub truncated: bool,
    /// Why the table could not be collected. Does not rule out rows: a table read from two
    /// logs names the one that failed here and still carries the other's rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub columns: Vec<DiagnosticsColumn>,
    /// Each row keyed by column name. A missing value is null.
    #[serde(default)]
    pub rows: Vec<BTreeMap<String, serde_json::Value>>,
}

/// The diagnostics snapshot, and what became of it. The same reference a [`MetricsContext`]
/// is, with tables where that has metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticsContext {
    pub state: ContextState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
    /// How stale the snapshot was when the check failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_seconds: Option<i64>,
    /// Every table of the snapshot, keyed by name (`processes.top_cpu`). Present only when
    /// the state is `captured`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sections: BTreeMap<String, DiagnosticsSection>,
}

/// One group in the suppressed summary: a command and status that failed `count` times.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SuppressedGroup {
    pub command: String,
    #[serde(default)]
    pub status: i64,
    #[serde(default)]
    pub count: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<String>,
}

/// Every other failure since the agent's previous report.
///
/// This is what makes one report per interval honest rather than lossy: the thirty failures
/// that did not get their own report are still counted here, grouped by check and status.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Suppressed {
    /// The start of the window: the agent's previous report, or the oldest failure in it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// Failures listed in `by_check`.
    #[serde(default)]
    pub count: i64,
    /// Failures the agent's own log cap dropped before they could be reported. Nothing else
    /// tells us these happened, so it is worth keeping.
    #[serde(default)]
    pub evicted: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub by_check: Vec<SuppressedGroup>,
}

/// The body of `POST /agent/v1/failure-context`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureReport {
    /// When the agent sent it, by its own clock. Advisory: the server stamps its own times
    /// and never orders on this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<String>,
    pub failure: FailedCheck,
    pub context: MetricsContext,
    /// Absent from an agent that predates diagnostics, which is not the same as one that
    /// has them switched off (`state: disabled`), so this stays an `Option`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<DiagnosticsContext>,
    #[serde(default)]
    pub suppressed: Suppressed,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FailureError {
    #[error("the report names no command")]
    EmptyCommand,
}

/// Build the header value that tells an agent we take reports.
///
/// `min_interval` of 0 sends the bare `accept`; anything else adds the `min-interval`
/// parameter, which the agent raises its own interval to when ours is longer. It is a
/// minimum, not an instruction: an agent configured for a longer interval keeps it.
pub fn accept_header_value(min_interval: u32) -> String {
    if min_interval == 0 {
        FAILURE_CONTEXT_ACCEPT.to_string()
    } else {
        format!("{FAILURE_CONTEXT_ACCEPT}; min-interval={min_interval}")
    }
}

impl FailureReport {
    /// Bring a report inside every bound in this module.
    ///
    /// Clamping rather than rejecting, with one exception. The agent treats a `4xx` on this
    /// route as the report's own fault and drops or backs off on it, so refusing a report
    /// over a field that is merely too long would lose a failure to protect a column width.
    /// The exception is a report that names no command: there is nothing left to file it
    /// under, and nothing a reader or a model could say about it.
    pub fn normalize(&mut self) -> Result<(), FailureError> {
        let f = &mut self.failure;
        f.command = clamp(f.command.trim(), MAX_COMMAND_LEN);
        if f.command.is_empty() {
            return Err(FailureError::EmptyCommand);
        }
        f.alias = clamp(f.alias.trim(), MAX_COMMAND_LEN);
        f.subject = clamp(f.subject.trim(), MAX_COMMAND_LEN);
        f.result = clamp(f.result.trim(), 32);
        f.message = clamp(&f.message, MAX_LINE_LEN);
        f.date = f
            .date
            .take()
            .map(|d| clamp(&d, 64))
            .filter(|d| !d.is_empty());
        // An unrecognised status is reported as unknown rather than stored as a number
        // nothing can render. The agent only ever sends 0..=3.
        if !(0..=3).contains(&f.status) {
            f.status = 3;
        }

        if let Some(args) = f.arguments.as_mut() {
            args.truncate(MAX_ARGUMENTS);
            for a in args.iter_mut() {
                *a = clamp(a, MAX_ARGUMENT_LEN);
            }
        }

        f.lines.truncate(MAX_LINES);
        for line in &mut f.lines {
            line.message = clamp(&line.message, MAX_LINE_LEN);
            while line.perf.len() > MAX_PERF_PER_LINE {
                let last = line
                    .perf
                    .keys()
                    .next_back()
                    .expect("non-empty by loop condition")
                    .clone();
                line.perf.remove(&last);
            }
            line.perf = std::mem::take(&mut line.perf)
                .into_iter()
                .map(|(k, mut v)| {
                    v.unit = v
                        .unit
                        .take()
                        .map(|u| clamp(&u, 32))
                        .filter(|u| !u.is_empty());
                    (clamp(&k, MAX_COMMAND_LEN), v)
                })
                .collect();
        }

        let ctx = &mut self.context;
        ctx.captured_at = ctx
            .captured_at
            .take()
            .map(|d| clamp(&d, 64))
            .filter(|d| !d.is_empty());
        if ctx.age_seconds.is_some_and(|a| a < 0) {
            // A snapshot from after the failure is a clock that stepped; reported as
            // unknown rather than as a negative age nothing can read.
            ctx.age_seconds = None;
        }
        // The metrics only mean anything alongside the state that says they were captured.
        // A report claiming another state while carrying a document is taken at its word on
        // the state and the document is dropped, so the two can never disagree in storage.
        if ctx.state != ContextState::Captured {
            ctx.metrics.clear();
            ctx.metadata.clear();
        }
        trim_map(&mut ctx.metrics, MAX_METRICS);
        trim_map(&mut ctx.metadata, MAX_METRICS);
        ctx.metrics = std::mem::take(&mut ctx.metrics)
            .into_iter()
            .map(|(k, v)| (clamp(&k, MAX_METRIC_KEY_LEN), clamp_metric_value(v)))
            .collect();
        // Metadata for a key that did not survive is metadata for nothing.
        let kept: std::collections::BTreeSet<String> = ctx.metrics.keys().cloned().collect();
        ctx.metadata = std::mem::take(&mut ctx.metadata)
            .into_iter()
            .map(|(k, v)| (clamp(&k, MAX_METRIC_KEY_LEN), v))
            .filter(|(k, _)| kept.contains(k))
            .collect();

        if let Some(d) = self.diagnostics.as_mut() {
            d.normalize();
        }

        let s = &mut self.suppressed;
        s.since = s
            .since
            .take()
            .map(|d| clamp(&d, 64))
            .filter(|d| !d.is_empty());
        s.count = s.count.max(0);
        s.evicted = s.evicted.max(0);
        s.by_check.truncate(MAX_SUPPRESSED_GROUPS);
        for g in &mut s.by_check {
            g.command = clamp(g.command.trim(), MAX_COMMAND_LEN);
            g.count = g.count.max(0);
            g.first = g
                .first
                .take()
                .map(|d| clamp(&d, 64))
                .filter(|d| !d.is_empty());
            g.last = g
                .last
                .take()
                .map(|d| clamp(&d, 64))
                .filter(|d| !d.is_empty());
        }

        Ok(())
    }
}

/// The diagnostics state of a report whose agent sent no `diagnostics` key: a build that
/// predates them. Ours rather than the agent's, which has no word for a key it does not send.
pub const DIAGNOSTICS_NOT_SENT: &str = "not_sent";

impl FailureReport {
    /// What became of the diagnostics snapshot, as stored and listed: the agent's state, or
    /// [`DIAGNOSTICS_NOT_SENT`] for a report with no `diagnostics` key at all.
    pub fn diagnostics_state(&self) -> &'static str {
        self.diagnostics
            .as_ref()
            .map_or(DIAGNOSTICS_NOT_SENT, |d| d.state.as_str())
    }

    /// Tables in the report, 0 when it carries none.
    pub fn diagnostics_tables(&self) -> usize {
        self.diagnostics.as_ref().map_or(0, |d| d.sections.len())
    }
}

impl DiagnosticsContext {
    /// Bring the tables inside every bound in this module. Clamping, never refusing, for the
    /// reason [`FailureReport::normalize`] gives.
    fn normalize(&mut self) {
        self.captured_at = self
            .captured_at
            .take()
            .map(|d| clamp(&d, 64))
            .filter(|d| !d.is_empty());
        if self.age_seconds.is_some_and(|a| a < 0) {
            self.age_seconds = None;
        }
        // As with the metrics: the stored state and the stored tables must never disagree.
        if self.state != ContextState::Captured {
            self.sections.clear();
        }
        trim_map(&mut self.sections, MAX_DIAGNOSTICS_SECTIONS);
        self.sections = std::mem::take(&mut self.sections)
            .into_iter()
            .map(|(name, mut section)| {
                section.normalize();
                (clamp(name.trim(), MAX_COMMAND_LEN), section)
            })
            .filter(|(name, _)| !name.is_empty())
            .collect();
    }
}

impl DiagnosticsSection {
    fn normalize(&mut self) {
        let text = |t: Option<String>| {
            t.map(|t| clamp(t.trim(), MAX_DIAGNOSTICS_TEXT_LEN))
                .filter(|t| !t.is_empty())
        };
        self.source = clamp(self.source.trim(), MAX_COMMAND_LEN);
        self.description = text(self.description.take());
        self.error = text(self.error.take());
        self.captured_at = self
            .captured_at
            .take()
            .map(|d| clamp(&d, 64))
            .filter(|d| !d.is_empty());

        self.columns.truncate(MAX_DIAGNOSTICS_COLUMNS);
        for c in &mut self.columns {
            c.name = clamp(c.name.trim(), MAX_COMMAND_LEN);
            c.kind = clamp(c.kind.trim(), 32);
            c.unit = c
                .unit
                .take()
                .map(|u| clamp(u.trim(), 32))
                .filter(|u| !u.is_empty());
            c.description = text(c.description.take());
        }
        // A column needs a name to key a cell, and one name can key only one.
        let mut seen = std::collections::BTreeSet::new();
        self.columns
            .retain(|c| !c.name.is_empty() && seen.insert(c.name.clone()));

        // More rows than the cap means the table was cut here, and a reader must be able to
        // tell "50 rows" from "at least 50" exactly as it can for the agent's own cap.
        if self.rows.len() > MAX_DIAGNOSTICS_ROWS {
            self.rows.truncate(MAX_DIAGNOSTICS_ROWS);
            self.truncated = true;
        }
        // A row is its columns' cells and nothing else: the columns bound its width, and a
        // key no column names is a cell nothing would render.
        for row in &mut self.rows {
            *row = self
                .columns
                .iter()
                .map(|c| {
                    let cell = row.remove(&c.name).unwrap_or(serde_json::Value::Null);
                    (c.name.clone(), clamp_cell(cell))
                })
                .collect();
        }
    }
}

impl FailedCheck {
    /// The status as a word, for storage and display. The agent's own `result` is preferred
    /// when it sent one, so the two never disagree.
    pub fn status_word(&self) -> &str {
        if !self.result.is_empty() {
            return &self.result;
        }
        match self.status {
            0 => "OK",
            1 => "WARNING",
            2 => "CRITICAL",
            _ => "UNKNOWN",
        }
    }

    /// The one-line summary a list shows before anyone opens the failure.
    pub fn summary_line(&self) -> String {
        let candidate = if !self.message.trim().is_empty() {
            self.message.trim()
        } else {
            self.lines
                .first()
                .map(|l| l.message.trim())
                .unwrap_or_default()
        };
        if candidate.is_empty() {
            format!("{} returned {}", self.command, self.status_word())
        } else {
            clamp(candidate, 512)
        }
    }
}

/// A fresh failure-context id. A ULID like every other id in the schema, so the primary key
/// and the common ordering agree.
pub fn new_failure_id() -> String {
    ulid::Ulid::generate().to_string()
}

/// Drop entries beyond `max`, taking whichever keys sort last.
///
/// Stable by construction: two agents sending the same snapshot keep the same subset, which
/// a "drop whatever arrived last" rule would not give.
fn trim_map<V>(map: &mut BTreeMap<String, V>, max: usize) {
    while map.len() > max {
        let last = map
            .keys()
            .next_back()
            .expect("non-empty by loop condition")
            .clone();
        map.remove(&last);
    }
}

/// Bound a metric value. Numbers are kept as they are; a string metric's value is clamped;
/// anything else (an object, an array, a bool) is not something the flat document can hold
/// and becomes null rather than being stored as a shape no reader expects.
fn clamp_metric_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Number(n) => serde_json::Value::Number(n),
        serde_json::Value::String(s) => serde_json::Value::String(clamp(&s, MAX_METRIC_VALUE_LEN)),
        _ => serde_json::Value::Null,
    }
}

/// Bound a table cell. Strings are clamped; numbers and booleans are kept as they are;
/// anything else is not a cell and becomes null, which is also how the agent spells a
/// missing value.
fn clamp_cell(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::String(s) => {
            serde_json::Value::String(clamp(&s, MAX_DIAGNOSTICS_CELL_LEN))
        }
        v @ (serde_json::Value::Number(_) | serde_json::Value::Bool(_)) => v,
        _ => serde_json::Value::Null,
    }
}

/// Truncate to `max` *characters*, never splitting one. `&str[..n]` panics on a byte index
/// inside a multi-byte character, and check output is full of them — a Windows path, a
/// service name, a log line in any language but English.
fn clamp(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(command: &str, alias: &str, status: i64) -> FailedCheck {
        FailedCheck {
            index: 1,
            timestamp: 1_793_437_964,
            date: Some("2026-10-31T09:12:44Z".into()),
            subject: "Scheduler".into(),
            depth: 0,
            command: command.into(),
            alias: alias.into(),
            status,
            result: match status {
                1 => "WARNING".into(),
                2 => "CRITICAL".into(),
                _ => "UNKNOWN".into(),
            },
            message: "CRITICAL: 5m: 97%".into(),
            lines: vec![],
            arguments: None,
        }
    }

    fn report(failure: FailedCheck) -> FailureReport {
        FailureReport {
            sent_at: Some("2026-10-31T09:12:44Z".into()),
            failure,
            context: MetricsContext {
                state: ContextState::Captured,
                snapshot_id: Some(310),
                captured_at: Some("2026-10-31T09:12:39Z".into()),
                age_seconds: Some(5),
                metrics: [("system.cpu.total.idle".to_string(), serde_json::json!(3))]
                    .into_iter()
                    .collect(),
                metadata: [(
                    "system.cpu.total.idle".to_string(),
                    serde_json::json!({"type": "gauge", "unit": "percent"}),
                )]
                .into_iter()
                .collect(),
            },
            diagnostics: None,
            suppressed: Suppressed::default(),
        }
    }

    /// A report whose diagnostics were captured, with `sections` as the agent's JSON.
    fn report_with_tables(sections: serde_json::Value) -> FailureReport {
        let mut r = report(check("check_x", "a", 2));
        r.diagnostics = Some(
            serde_json::from_value(serde_json::json!({
                "state": "captured", "snapshot_id": 310,
                "captured_at": "2026-10-31T09:12:39Z", "age_seconds": 5,
                "sections": sections,
            }))
            .expect("the agent's shape"),
        );
        r
    }

    /// The example from the agent's own documentation (`docs/docs/setup/fleet.md`) must
    /// parse as it is written. This is the contract test: if the agent's renderer and this
    /// struct ever disagree, reports arrive and are refused in production, where the agent
    /// treats the refusal as permanent and drops them.
    #[test]
    fn the_agents_documented_report_parses() {
        let body = r#"{
          "sent_at": "2026-10-31T09:12:44Z",
          "failure": {
            "index": 42, "timestamp": 1793437964, "date": "2026-10-31T09:12:44Z",
            "subject": "Scheduler", "depth": 0, "command": "check_cpu", "alias": "cpu",
            "status": 2, "result": "CRITICAL", "message": "CRITICAL: 5m: 97%",
            "lines": [{ "message": "CRITICAL: 5m: 97%", "perf": { "total 5m": { "value": 97, "unit": "%" } } }]
          },
          "context": {
            "state": "captured", "snapshot_id": 310, "captured_at": "2026-10-31T09:12:39Z", "age_seconds": 5,
            "metrics": { "system.cpu.total.idle": 3, "system.mem.physical.used": 15032385536 },
            "metadata": { "system.cpu.total.idle": { "type": "gauge", "unit": "percent" } }
          },
          "diagnostics": {
            "state": "captured", "snapshot_id": 310, "captured_at": "2026-10-31T09:12:39Z", "age_seconds": 5,
            "sections": {
              "processes.top_cpu": {
                "source": "CheckSystem", "captured_at": "2026-10-31T09:12:38Z", "truncated": true,
                "columns": [{ "name": "name", "type": "string" }, { "name": "pid", "type": "int" },
                            { "name": "cpu", "type": "float", "unit": "percent" }],
                "rows": [{ "name": "acme-indexer.exe", "pid": 4242, "cpu": 87.5 }]
              }
            }
          },
          "suppressed": {
            "since": "2026-10-31T08:12:40Z", "count": 37, "evicted": 0,
            "by_check": [
              { "command": "check_cpu", "status": 2, "count": 30, "first": "2026-10-31T08:13:02Z", "last": "2026-10-31T09:11:40Z" },
              { "command": "check_drivesize", "status": 1, "count": 7, "first": "2026-10-31T08:40:00Z", "last": "2026-10-31T09:10:00Z" }
            ]
          }
        }"#;
        let mut r: FailureReport = serde_json::from_str(body).expect("the documented shape");
        r.normalize().expect("and it is storable");

        assert_eq!(r.failure.command, "check_cpu");
        assert_eq!(r.failure.alias, "cpu");
        assert_eq!(r.failure.status, 2);
        assert_eq!(r.failure.subject, "Scheduler");
        assert_eq!(
            r.failure.lines[0].perf["total 5m"].value,
            Some(serde_json::json!(97))
        );
        assert_eq!(
            r.failure.lines[0].perf["total 5m"].unit.as_deref(),
            Some("%")
        );
        assert_eq!(r.context.state, ContextState::Captured);
        assert_eq!(
            r.context.metrics["system.mem.physical.used"],
            15_032_385_536i64
        );
        assert_eq!(
            r.context.metadata["system.cpu.total.idle"]["unit"],
            "percent"
        );
        let d = r.diagnostics.as_ref().expect("the tables came with it");
        assert_eq!(d.state, ContextState::Captured);
        assert_eq!(d.age_seconds, Some(5));
        let top = &d.sections["processes.top_cpu"];
        assert_eq!(top.source, "CheckSystem");
        assert!(top.truncated);
        assert_eq!(top.columns[2].name, "cpu");
        assert_eq!(top.columns[2].kind, "float");
        assert_eq!(top.columns[2].unit.as_deref(), Some("percent"));
        assert_eq!(top.rows[0]["name"], "acme-indexer.exe");
        assert_eq!(top.rows[0]["pid"], 4242);
        assert_eq!(top.rows[0]["cpu"], 87.5);
        assert_eq!(r.diagnostics_state(), "captured");
        assert_eq!(r.diagnostics_tables(), 1);
        assert_eq!(r.suppressed.count, 37);
        assert_eq!(r.suppressed.by_check.len(), 2);
        assert_eq!(r.suppressed.by_check[0].command, "check_cpu");
        assert!(
            r.failure.arguments.is_none(),
            "absent must stay absent: it is how a reader tells 'not recorded' from 'none given'"
        );
    }

    /// The minimum an agent can send: the failure's command and the context state. Every
    /// other field has a default, because an older or differently-configured agent omits
    /// some of them and a missing field must not cost the report.
    #[test]
    fn a_minimal_report_parses() {
        let mut r: FailureReport = serde_json::from_str(
            r#"{"failure":{"command":"check_x"},"context":{"state":"disabled"}}"#,
        )
        .expect("the minimum");
        r.normalize().unwrap();
        assert_eq!(r.failure.command, "check_x");
        assert_eq!(r.context.state, ContextState::Disabled);
        assert_eq!(r.suppressed.count, 0);
        assert_eq!(
            r.failure.status_word(),
            "OK",
            "status defaults to 0, so does the word"
        );
    }

    #[test]
    fn a_report_without_diagnostics_is_told_from_one_with_them_switched_off() {
        // An agent that predates diagnostics sends no key; one with `capture diagnostics`
        // off sends `disabled`. The fix differs (upgrade, or flip a setting), so the two
        // must not be stored as the same thing.
        let old: FailureReport =
            serde_json::from_str(r#"{"failure":{"command":"c"},"context":{"state":"none"}}"#)
                .unwrap();
        assert_eq!(old.diagnostics_state(), DIAGNOSTICS_NOT_SENT);
        assert!(
            !serde_json::to_string(&old).unwrap().contains("diagnostics"),
            "and stays absent when stored"
        );

        let off: FailureReport = serde_json::from_str(
            r#"{"failure":{"command":"c"},"context":{"state":"none"},"diagnostics":{"state":"disabled"}}"#,
        )
        .unwrap();
        assert_eq!(off.diagnostics_state(), "disabled");
        assert_eq!(off.diagnostics_tables(), 0);
    }

    #[test]
    fn a_table_keeps_its_error_beside_its_rows_and_its_nulls() {
        // `eventlog.errors` reads two logs: when one cannot be read the table names it in
        // `error` and still carries the other's rows. A missing value is null.
        let mut r = report_with_tables(serde_json::json!({
            "disk.growth_spots": {
                "source": "CheckDisk", "truncated": false,
                "error": "shadow storage: access denied",
                "columns": [{ "name": "path", "type": "string" },
                            { "name": "size", "type": "int", "unit": "bytes", "description": "In use" }],
                "rows": [{ "path": "C:\\Windows\\Temp", "size": null },
                         { "path": "C:\\pagefile.sys", "size": 36507222016u64 }]
            }
        }));
        r.normalize().unwrap();
        let t = &r.diagnostics.as_ref().unwrap().sections["disk.growth_spots"];
        assert_eq!(t.error.as_deref(), Some("shadow storage: access denied"));
        assert_eq!(t.rows.len(), 2);
        assert!(t.rows[0]["size"].is_null());
        assert_eq!(t.rows[1]["size"], 36_507_222_016u64);
        assert_eq!(t.columns[1].description.as_deref(), Some("In use"));
    }

    #[test]
    fn oversized_tables_are_clamped_rather_than_refused() {
        let columns: Vec<_> = (0..MAX_DIAGNOSTICS_COLUMNS + 5)
            .map(|i| serde_json::json!({ "name": format!("c{i:03}"), "type": "string" }))
            .collect();
        let rows: Vec<_> = (0..MAX_DIAGNOSTICS_ROWS + 5)
            .map(|_| serde_json::json!({ "c000": "x".repeat(MAX_DIAGNOSTICS_CELL_LEN + 50) }))
            .collect();
        let sections: serde_json::Map<_, _> = (0..MAX_DIAGNOSTICS_SECTIONS + 4)
            .map(|i| {
                (
                    format!("t{i:03}"),
                    serde_json::json!({ "source": "m", "columns": columns, "rows": rows }),
                )
            })
            .collect();
        let mut r = report_with_tables(serde_json::Value::Object(sections));

        r.normalize().expect("clamping, not refusal");
        let d = r.diagnostics.as_ref().unwrap();
        assert_eq!(d.sections.len(), MAX_DIAGNOSTICS_SECTIONS);
        let t = &d.sections["t000"];
        assert_eq!(t.columns.len(), MAX_DIAGNOSTICS_COLUMNS);
        assert_eq!(t.rows.len(), MAX_DIAGNOSTICS_ROWS);
        assert!(
            t.truncated,
            "rows cut here must read as 'at least', as rows cut by the agent do"
        );
        assert_eq!(
            t.rows[0]["c000"].as_str().unwrap().chars().count(),
            MAX_DIAGNOSTICS_CELL_LEN
        );
    }

    #[test]
    fn a_row_is_its_columns_cells_and_nothing_else() {
        let mut r = report_with_tables(serde_json::json!({
            "t": {
                "source": "m",
                "columns": [{ "name": "name", "type": "string" }, { "name": "pid", "type": "int" },
                            { "name": "name", "type": "string" }, { "name": " ", "type": "string" }],
                "rows": [{ "name": "a", "stray": "not a column", "pid": { "nested": 1 } }, {}]
            }
        }));
        r.normalize().unwrap();
        let t = &r.diagnostics.as_ref().unwrap().sections["t"];
        assert_eq!(
            t.columns
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            ["name", "pid"],
            "a repeated or unnamed column cannot key a cell"
        );
        assert_eq!(t.rows[0].len(), 2, "a key no column names is dropped");
        assert_eq!(t.rows[0]["name"], "a");
        assert!(t.rows[0]["pid"].is_null(), "an object is not a cell");
        assert!(
            t.rows[1]["name"].is_null() && t.rows[1]["pid"].is_null(),
            "a cell the row left out reads as null"
        );
    }

    #[test]
    fn diagnostics_that_were_not_captured_cannot_smuggle_tables() {
        let mut r = report_with_tables(serde_json::json!({
            "t": { "source": "m", "columns": [{ "name": "a", "type": "string" }], "rows": [{ "a": "x" }] }
        }));
        let d = r.diagnostics.as_mut().unwrap();
        d.state = ContextState::Evicted;
        d.age_seconds = Some(-3);
        r.normalize().unwrap();
        let d = r.diagnostics.as_ref().unwrap();
        assert!(d.sections.is_empty());
        assert_eq!(d.age_seconds, None, "a stepped clock is not an age");
        assert_eq!(r.diagnostics_state(), "evicted");
    }

    #[test]
    fn a_nagios_range_threshold_survives_as_the_string_it_is() {
        let r: FailureReport = serde_json::from_str(
            r#"{"failure":{"command":"c","lines":[{"message":"m","perf":{"load":{"value":4.5,"warning":"4:5","critical":"6:7"}}}]},
                "context":{"state":"none"}}"#,
        )
        .unwrap();
        let perf = &r.failure.lines[0].perf["load"];
        assert_eq!(perf.warning, Some(serde_json::json!("4:5")));
        assert_eq!(perf.critical, Some(serde_json::json!("6:7")));
        assert_eq!(perf.value, Some(serde_json::json!(4.5)));
    }

    #[test]
    fn a_string_valued_sample_survives() {
        let r: FailureReport = serde_json::from_str(
            r#"{"failure":{"command":"c","lines":[{"message":"m","perf":{"state":{"value":"running"}}}]},
                "context":{"state":"none"}}"#,
        )
        .unwrap();
        assert_eq!(
            r.failure.lines[0].perf["state"].value,
            Some(serde_json::json!("running"))
        );
    }

    #[test]
    fn every_context_state_the_agent_can_send_is_understood() {
        for (text, expected) in [
            ("captured", ContextState::Captured),
            ("evicted", ContextState::Evicted),
            ("too_large", ContextState::TooLarge),
            ("disabled", ContextState::Disabled),
            ("none", ContextState::None),
        ] {
            let r: FailureReport = serde_json::from_str(&format!(
                r#"{{"failure":{{"command":"c"}},"context":{{"state":"{text}"}}}}"#
            ))
            .unwrap_or_else(|e| panic!("state {text:?} must parse: {e}"));
            assert_eq!(r.context.state, expected);
            assert_eq!(expected.as_str(), text);
        }
    }

    #[test]
    fn oversized_fields_are_clamped_rather_than_refused() {
        // The agent drops a report the server 4xxs, so losing one over a long field would
        // lose the failure outright.
        let mut r = report(check("check_x", "a", 2));
        r.failure.arguments = Some((0..MAX_ARGUMENTS + 10).map(|i| i.to_string()).collect());
        r.failure.lines = (0..MAX_LINES + 5)
            .map(|i| ResultLine {
                message: format!("line {i}"),
                perf: (0..MAX_PERF_PER_LINE + 10)
                    .map(|j| (format!("p{j:04}"), PerfSample::default_for_test()))
                    .collect(),
            })
            .collect();
        r.context.metrics = (0..MAX_METRICS + 100)
            .map(|i| (format!("k{i:06}"), serde_json::json!(i)))
            .collect();
        r.suppressed.by_check = (0..MAX_SUPPRESSED_GROUPS + 10)
            .map(|i| SuppressedGroup {
                command: format!("c{i}"),
                status: 2,
                count: 1,
                first: None,
                last: None,
            })
            .collect();

        r.normalize().expect("clamping, not refusal");
        assert_eq!(r.failure.arguments.as_ref().unwrap().len(), MAX_ARGUMENTS);
        assert_eq!(r.failure.lines.len(), MAX_LINES);
        assert_eq!(r.failure.lines[0].perf.len(), MAX_PERF_PER_LINE);
        assert_eq!(r.context.metrics.len(), MAX_METRICS);
        assert_eq!(r.suppressed.by_check.len(), MAX_SUPPRESSED_GROUPS);
    }

    #[test]
    fn metric_trimming_is_stable_across_hosts() {
        let build = || {
            let mut r = report(check("check_x", "a", 2));
            r.context.metrics = (0..MAX_METRICS + 50)
                .map(|i| (format!("k{i:06}"), serde_json::json!(i)))
                .collect();
            r
        };
        let (mut a, mut b) = (build(), build());
        a.normalize().unwrap();
        b.normalize().unwrap();
        assert_eq!(
            a.context.metrics, b.context.metrics,
            "two hosts sending the same snapshot must keep the same subset"
        );
    }

    #[test]
    fn metadata_cannot_outlive_the_metrics_it_describes() {
        let mut r = report(check("check_x", "a", 2));
        r.context.metadata.insert(
            "no.such.metric".into(),
            serde_json::json!({"type": "gauge"}),
        );
        r.normalize().unwrap();
        assert!(
            !r.context.metadata.contains_key("no.such.metric"),
            "metadata is keyed by the value document's keys"
        );
        assert!(r.context.metadata.contains_key("system.cpu.total.idle"));
    }

    #[test]
    fn a_state_that_is_not_captured_cannot_smuggle_a_snapshot() {
        let mut r = report(check("check_x", "a", 2));
        r.context.state = ContextState::Evicted;
        r.normalize().unwrap();
        assert!(
            r.context.metrics.is_empty() && r.context.metadata.is_empty(),
            "the stored state and the stored document must never disagree"
        );
    }

    #[test]
    fn a_metric_value_that_is_not_a_number_or_a_string_is_dropped() {
        let mut r = report(check("check_x", "a", 2));
        r.context
            .metrics
            .insert("weird".into(), serde_json::json!({"a": 1}));
        r.context
            .metrics
            .insert("list".into(), serde_json::json!([1, 2]));
        r.context.metrics.insert(
            "long".into(),
            serde_json::json!("x".repeat(MAX_METRIC_VALUE_LEN + 50)),
        );
        r.normalize().unwrap();
        assert!(r.context.metrics["weird"].is_null());
        assert!(r.context.metrics["list"].is_null());
        assert_eq!(
            r.context.metrics["long"].as_str().unwrap().chars().count(),
            MAX_METRIC_VALUE_LEN
        );
    }

    #[test]
    fn truncation_never_splits_a_character() {
        let mut r = report(check("check_x", "a", 2));
        r.failure.message = "🧟".repeat(MAX_LINE_LEN + 50);
        r.normalize().unwrap();
        assert_eq!(r.failure.message.chars().count(), MAX_LINE_LEN);
    }

    #[test]
    fn a_report_naming_no_command_is_the_one_refusal() {
        let mut r = report(check("   ", "a", 2));
        assert_eq!(r.normalize(), Err(FailureError::EmptyCommand));
    }

    #[test]
    fn a_status_outside_the_agents_range_reads_as_unknown() {
        let mut r = report(check("check_x", "a", 2));
        r.failure.status = 99;
        r.failure.result = String::new();
        r.normalize().unwrap();
        assert_eq!(r.failure.status, 3);
        assert_eq!(r.failure.status_word(), "UNKNOWN");
    }

    #[test]
    fn a_passing_check_is_accepted() {
        // Only reachable when an operator configures the agent's log to record OK results.
        // Refusing it would have the agent back off and retry a report it keeps producing,
        // and its snapshot is still the host's latest.
        let mut r = report(check("check_x", "a", 0));
        r.failure.status = 0;
        r.normalize().expect("accepted");
    }

    #[test]
    fn a_negative_snapshot_age_reads_as_unknown() {
        let mut r = report(check("check_x", "a", 2));
        r.context.age_seconds = Some(-42);
        r.normalize().unwrap();
        assert_eq!(r.context.age_seconds, None, "a stepped clock is not an age");
    }

    #[test]
    fn the_summary_always_says_something() {
        let mut c = check("check_drivesize", "d", 2);
        c.message = "  C:\\ used 95.2% > 90%  ".into();
        assert_eq!(c.summary_line(), "C:\\ used 95.2% > 90%");

        c.message = String::new();
        c.lines = vec![ResultLine {
            message: "from the first line".into(),
            perf: BTreeMap::new(),
        }];
        assert_eq!(c.summary_line(), "from the first line");

        c.lines.clear();
        assert_eq!(c.summary_line(), "check_drivesize returned CRITICAL");
    }

    #[test]
    fn the_accept_header_is_what_the_agent_parses() {
        // The agent lower-cases the value, splits on ';' and requires the first part to be
        // exactly `accept`; `min-interval` is read from the parameters.
        assert_eq!(accept_header_value(0), "accept");
        assert_eq!(accept_header_value(3600), "accept; min-interval=3600");
        assert!(accept_header_value(60).starts_with(FAILURE_CONTEXT_ACCEPT));
        assert_eq!(FAILURE_CONTEXT_HEADER, "x-failure-context");
    }

    impl PerfSample {
        fn default_for_test() -> Self {
            Self {
                value: Some(serde_json::json!(1)),
                unit: None,
                warning: None,
                critical: None,
                minimum: None,
                maximum: None,
            }
        }
    }
}
