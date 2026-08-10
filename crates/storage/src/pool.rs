use std::path::Path;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct Db {
    pub read: SqlitePool,
    pub write: SqlitePool,
}

impl Db {
    pub async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.read)
            .await?;
        Ok(())
    }
}

pub async fn open(path: impl AsRef<Path>) -> anyhow::Result<Db> {
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5))
        .foreign_keys(true);

    let read = SqlitePoolOptions::new()
        .max_connections(16)
        .connect_with(opts.clone())
        .await?;

    let write = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await?;

    Ok(Db { read, write })
}
