//! Failure context: what an agent reports when one of its checks fails, kept as evidence for
//! explaining errors.
//!
//! This server is not the monitoring system. The monitoring system raises the alert, decides
//! how bad it is and tracks how long it has been open. What the fleet adds is context: when
//! someone holding an error asks why, the host's latest metrics snapshot, its inventory facts
//! and the agent's own record of the check are here to explain it against ([`explain`]).
//!
//! A failed check tells you what came back. The report tells you what the host looked like
//! when it came back: the check and its perfdata, who ran it, and — when the agent captures
//! them — the few hundred metrics it held at that moment.
//!
//! The traffic is paced from both ends:
//!
//! * The server has to ask. Every desired-state answer carries `X-Failure-Context`
//!   ([`exchange`]); an agent that never sees it posts nothing, and one that stops seeing it
//!   stops. So a tenant turns reporting off without touching a host.
//! * The agent sends at most one report per host per interval, whatever is failing.
//! * A stored row is the latest report for one check on one host; a new report for the same
//!   check replaces it. The table holds evidence, not history.
//!
//! See [`fleet_core::failures`] for the wire format.
//!
//! - [`exchange`] advertises the header that turns reporting on.
//! - [`ingest`] takes a report; the status codes it returns are part of the agent's contract.
//! - [`view`] is a host's reports, the settings, and the retention sweep.
//! - [`explain`] asks a model to explain an error against a host's evidence.

mod exchange;
mod explain;
mod ingest;
mod view;

pub use exchange::{advertise, with_header};
pub use explain::explain;
pub use ingest::{ingest, MAX_FAILURES_PER_HOST, RETENTION_SECS};
pub use view::{
    delete_context, get, get_settings, list, put_settings, sweep, ContextDetailView,
    ContextSummaryView, SettingsView,
};
