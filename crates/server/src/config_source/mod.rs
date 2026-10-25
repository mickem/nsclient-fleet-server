//! Groups and bundles as a directory of files, for configuration kept in git.
//!
//! `--export-config` writes the on-prem tenant's groups, bundles and assignments out as a
//! directory, and `--import-config` makes the database match one: to seed a new server,
//! copy configuration between servers, or go back to a known commit.
//!
//! Single-tenant only: a directory has no notion of which tenant it is for, so it belongs
//! to the on-prem `default` tenant. The database still holds the rows and everything
//! downstream reads them from there; see [`reconcile`].
//!
//! - [`layout`] is the directory format and its reader.
//! - [`reconcile`] makes the database match a directory.
//! - [`export`] writes the database out as one.

pub mod export;
mod layout;
pub mod reconcile;

use fleet_storage::{Db, TenantRepo};

pub use export::{export, ExportReport};
pub use reconcile::{reconcile, ReconcileError, ReloadReport};

/// The slug of the one tenant a configuration directory can belong to: the tenant the
/// on-prem bootstrap creates.
pub const TENANT_SLUG: &str = "default";

/// The tenant a configuration directory applies to.
pub async fn resolve_tenant(db: &Db) -> anyhow::Result<i64> {
    match TenantRepo::new(db).get_by_slug(TENANT_SLUG).await? {
        Some(t) => Ok(t.id),
        None => anyhow::bail!(
            "configuration files are for single-tenant (ON_PREM=true) installs, and there is \
             no '{TENANT_SLUG}' tenant — set ON_PREM=true and ON_PREM_ADMIN_EMAIL and start \
             the server once"
        ),
    }
}
