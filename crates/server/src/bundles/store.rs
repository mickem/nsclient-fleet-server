use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait BundleStore: Send + Sync {
    async fn put(&self, tenant_id: i64, bundle_id: &str, bytes: &[u8]) -> Result<()>;
    async fn get(&self, tenant_id: i64, bundle_id: &str) -> Result<Vec<u8>>;
    async fn delete(&self, tenant_id: i64, bundle_id: &str) -> Result<()>;
    /// Every stored file, for the housekeeping sweep of files no row points at.
    async fn list(&self) -> Result<Vec<StoredBundleFile>>;
}

/// One file in the store, as [`BundleStore::list`] reports it.
#[derive(Debug, Clone)]
pub struct StoredBundleFile {
    pub tenant_id: i64,
    pub bundle_id: String,
    /// Last modified, unix seconds.
    pub modified: i64,
}

#[derive(Clone)]
pub struct LocalBundleStore {
    base: Arc<PathBuf>,
}

impl LocalBundleStore {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self {
            base: Arc::new(base.into()),
        }
    }

    fn path_for(&self, tenant_id: i64, bundle_id: &str) -> PathBuf {
        self.base
            .join(tenant_id.to_string())
            .join(format!("{bundle_id}.zip"))
    }
}

#[async_trait]
impl BundleStore for LocalBundleStore {
    async fn put(&self, tenant_id: i64, bundle_id: &str, bytes: &[u8]) -> Result<()> {
        let path = self.path_for(tenant_id, bundle_id);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&path, bytes).await?;
        Ok(())
    }

    async fn get(&self, tenant_id: i64, bundle_id: &str) -> Result<Vec<u8>> {
        let path = self.path_for(tenant_id, bundle_id);
        Ok(tokio::fs::read(&path).await?)
    }

    async fn delete(&self, tenant_id: i64, bundle_id: &str) -> Result<()> {
        let path = self.path_for(tenant_id, bundle_id);
        tokio::fs::remove_file(&path).await?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<StoredBundleFile>> {
        let mut out = Vec::new();
        let mut tenants = match tokio::fs::read_dir(self.base.as_ref()).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        while let Some(tenant_dir) = tenants.next_entry().await? {
            // Only what this store writes: numeric tenant directories of `<id>.zip` files.
            let Some(tenant_id) = tenant_dir.file_name().to_str().and_then(|n| n.parse().ok())
            else {
                continue;
            };
            let mut files = tokio::fs::read_dir(tenant_dir.path()).await?;
            while let Some(file) = files.next_entry().await? {
                let name = file.file_name();
                let Some(bundle_id) = name.to_str().and_then(|n| n.strip_suffix(".zip")) else {
                    continue;
                };
                let modified = file
                    .metadata()
                    .await?
                    .modified()?
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs() as i64);
                out.push(StoredBundleFile {
                    tenant_id,
                    bundle_id: bundle_id.to_string(),
                    modified,
                });
            }
        }
        Ok(out)
    }
}
