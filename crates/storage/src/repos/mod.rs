//! The repositories: one type per table (or tight group of tables), each borrowing the
//! pool. Split by domain; everything is re-exported here and from the crate root, so callers
//! name `fleet_storage::HostRepo` and never the file it lives in.

mod audit;
mod bundles;
mod facts;
mod groups;
mod hosts;
mod tenants;
mod users;

pub use audit::{AuditRepo, AuditRow};
pub use bundles::{
    BundleAssignmentsRepo, BundleRow, BundlesRepo, MovedBundle, RenameOutcome, RenamedInPlace,
};
pub use facts::{
    FactChangeRow, FactsHashes, FactsRefusal, HostFactsRepo, NewFacts, ReplaceOutcome, StoredFacts,
};
pub use groups::{GroupRow, GroupsRepo};
pub use hosts::{
    CertStanding, EnrolledCert, HostCertRepo, HostOverridesRepo, HostRepo, HostTagsRepo,
    StoredHostOverride,
};
pub use tenants::{
    CaSummary, PlatformSettingsRepo, StoredTenantSecrets, TenantBundleKeysRepo, TenantRepo,
    TenantSecretsRepo, TenantSummary,
};
pub use users::{ApiKeyRepo, MagicLinkRepo, SessionRepo, UserRepo};

#[cfg(test)]
mod tests;
