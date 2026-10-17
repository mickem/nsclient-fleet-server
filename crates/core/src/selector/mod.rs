//! Restricted selector grammar for group definitions.
//!
//! v1 grammar: top-level was an implicit AND of leaf clauses (`eq`, `in`).
//! v1.1 adds compound nodes `and`, `or`, `not`, and the leaf `exists`. The top-level
//! `clauses: Vec<Expr>` is still an implicit AND, so all previously-stored selectors
//! deserialize unchanged. Whenever a single tree-shaped root is needed (e.g. as the
//! body of a `not`), use the recursive `Expr` enum.
//!
//! Stored as structured JSON, never raw text. UI-built. No code-execution surface.
//!
//! v1.2 adds `source` to every leaf, and it is the security-relevant part of this module.
//!
//! Group membership decides which bundles a host is served, and bundles carry scripts and
//! (in the plain format) secrets. A host reports its own tags, so if agent-reported values
//! can satisfy a selector then a compromised host picks its own groups: it claims
//! `role=sql_server`, joins the SQL group, and downloads that group's bundles. That manual
//! tags cannot be overwritten does not help, because supplementing is enough — a leaf
//! matches if *any* value under the key matches.
//!
//! So a leaf now says which source it will accept, and the default is
//! [`SourceFilter::Manual`]: operator-set facts only. An operator who does want to group on
//! what a host says about itself writes `"source": "agent"` or `"source": "any"`, and in
//! doing so states that hosts may place themselves in that group. Because `Manual` is the
//! serde default, every selector written before this change now means operator-set-only,
//! which is the safe reading of what it already said.
//!
//! v1.3 adds the `fact` leaf, which reads a host's facts documents (see [`crate::facts`])
//! instead of its tags. Tags are flat `key = value`; a facts document is a tree with lists
//! of records in it, so the leaf addresses a value by [`FactPath`] and has a `has` test for
//! what a list or map contains. Which document it reads is named, not filtered: `agent` is
//! the one the host uploads about itself and is host-controlled exactly like an agent tag,
//! while an imported source is not the host's to write.
//!
//! - [`tags`]: tag values and where they came from, and the filter a leaf applies to them.
//! - [`expr`]: the selector tree itself, its validation, and evaluation against a host.
//! - [`path`]: [`FactPath`], addressing a value inside a facts document.

mod expr;
mod path;
mod tags;

pub use expr::{Clause, Expr, FactTest, HostFacts, Selector, SelectorError};
pub use path::{scalar_text, FactPath, MAX_FACT_PATH_LEN};
pub use tags::{
    HostTags, SourceFilter, TagSource, TagValue, MAX_KEY_LEN, MAX_TAGS_PER_HOST, MAX_VALUE_LEN,
};

#[cfg(test)]
mod tests;
