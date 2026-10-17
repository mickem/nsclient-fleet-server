//! Host facts: the agent's inventory of the machine it runs on.
//!
//! The document is up to a megabyte and changes rarely, so it only travels when the server
//! does not already have it:
//!
//! * Every desired-state poll (`?facts_hash=`) and state report (`"facts_hash"`) carries the
//!   hash of the agent's current document.
//! * Every answer to those carries the hash *we* hold in `X-Facts-Hash` ([`advertise`]),
//!   `none` when we hold nothing. It is a header so that it rides on the 304 a host in sync
//!   gets on nearly every poll.
//! * The agent uploads to `POST /agent/v1/facts` ([`upload`]) only when the two differ.
//!
//! So a steady-state host costs one indexed read per poll and nothing more: no document, no
//! write. Sending the header at all is what tells an agent this server does facts — one
//! that never sees it never uploads.
//!
//! See [`fleet_core::facts`] for the wire format and the document diff.
//!
//! - [`exchange`] is the hash in both directions, and when an empty document may replace one.
//! - [`upload`] takes the agent's document; [`store`] writes it, with its history, and reads
//!   documents back.
//! - [`view`] is what the operator sees for one host; [`catalog`] is the tenant-wide index of
//!   paths and values that selectors are built from.
//! - [`import`] is documents from an operator's file rather than from agents.

mod catalog;
mod exchange;
pub mod import;
mod store;
mod upload;
mod view;

pub use catalog::{
    catalog, CatalogCache, CatalogChange, CatalogPath, CatalogSource, FactsCatalog, PathKind,
};
pub use exchange::{advertise, with_header, EMPTY_CLEAR_GRACE_SECS};
pub use store::{fold_host_facts, load_for_host, remove, remove_source, store};
pub use upload::{upload, MAX_FACTS_BODY_BYTES};
pub use view::{
    host_facts, status, FactsChangesView, FactsStatus, HostFactsView, OtherFactsView, RefusalView,
};
