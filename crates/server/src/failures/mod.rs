//! Failure context: what an agent reports when one of its checks fails, and the description
//! a language model writes from it.
//!
//! A failed check tells you what came back. The report tells you what the host looked like
//! when it came back: the check and its perfdata, who ran it, and — when the agent captures
//! them — the few hundred metrics it held at that moment.
//!
//! The traffic is paced from both ends, which is what keeps a control plane from becoming a
//! time-series store:
//!
//! * The server has to ask. Every desired-state answer carries `X-Failure-Context`
//!   ([`exchange`]); an agent that never sees it posts nothing, and one that stops seeing it
//!   stops. So a tenant turns the whole feature off without touching a host.
//! * The agent sends at most one report per host per interval, whatever is failing, and
//!   summarises the rest of the window inside it.
//! * A stored row is a *problem*, not a report: a fingerprint over
//!   (command, alias, status, arguments) collapses a repeat onto the row already there.
//!
//! Together those make the arrival rate a function of the fleet and the interval, and make
//! the unit of enrichment a problem rather than a report — so the model is asked once per
//! problem, not once per hour per problem.
//!
//! See [`fleet_core::failures`] for the wire format and the fingerprint.
//!
//! - [`exchange`] advertises the header that turns the feature on.
//! - [`ingest`] takes a report; the status codes it returns are part of the agent's contract.
//! - [`view`] is the operator's list, detail, settings and retention sweep.
//! - [`enrichment`] is the background worker that asks a model to describe a failure.

pub mod enrichment;
mod exchange;
mod ingest;
mod view;

pub use exchange::{advertise, with_header};
pub use ingest::{ingest, MAX_FAILURES_PER_HOST, RETENTION_SECS};
pub use view::{
    delete_failure, describe, get, get_settings, list, put_settings, sweep, FailureDetailView,
    FailureSummaryView, SettingsView,
};
