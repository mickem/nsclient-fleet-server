use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Longest tag key a selector will compare, and therefore the longest one worth storing.
/// Public so the tag write paths enforce the same bound: a key longer than this can never
/// be matched, so accepting one is storing something that cannot be used.
pub const MAX_KEY_LEN: usize = 128;
/// Longest tag value, for the same reason.
pub const MAX_VALUE_LEN: usize = 256;
/// Most tags one host may carry. Selectors cap at 64 clauses, so a host with more tags than
/// this has more than any selector could distinguish; the cap exists so an agent cannot
/// grow a row set nothing bounds.
pub const MAX_TAGS_PER_HOST: usize = 128;

/// Where a stored tag came from. A fact about the row, not a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TagSource {
    /// Set by an operator, through the console or the API.
    Manual,
    /// Reported by the host about itself. Untrusted: the host may be lying.
    Agent,
}

impl TagSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Agent => "agent",
        }
    }

    /// Parse a `host_tags.source` column. Anything unrecognised reads as `Agent`, the
    /// less-trusted of the two: a row we cannot classify must not be promoted to an
    /// operator's assertion.
    pub fn from_db(s: &str) -> Self {
        match s {
            "manual" => Self::Manual,
            _ => Self::Agent,
        }
    }
}

/// Which sources a selector leaf will accept a value from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceFilter {
    /// Operator-set tags only. The default, and what an omitted `source` means — so a
    /// selector stored before this field existed cannot be satisfied by a host's own
    /// claims about itself.
    #[default]
    Manual,
    /// Agent-reported tags only.
    Agent,
    /// Either source. An explicit statement that hosts may put themselves in this group.
    Any,
}

impl SourceFilter {
    pub(super) fn accepts(self, source: TagSource) -> bool {
        match self {
            Self::Manual => source == TagSource::Manual,
            Self::Agent => source == TagSource::Agent,
            Self::Any => true,
        }
    }

    /// True when the host itself can influence whether a leaf with this filter matches.
    pub fn is_host_controlled(self) -> bool {
        matches!(self, Self::Agent | Self::Any)
    }

    pub(super) fn is_default(&self) -> bool {
        *self == Self::Manual
    }
}

/// One stored tag value, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagValue {
    pub value: String,
    pub source: TagSource,
}

impl TagValue {
    pub fn manual(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            source: TagSource::Manual,
        }
    }

    pub fn agent(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            source: TagSource::Agent,
        }
    }
}

/// A host's tags, keyed by tag key. A key can hold values from both sources at once, which
/// is exactly why each value carries its own: collapsing them into a plain string list is
/// what made an agent's claim indistinguishable from an operator's.
pub type HostTags = HashMap<String, Vec<TagValue>>;
