use sqlx::SqlitePool;

pub async fn run_migrations(write: &SqlitePool) -> anyhow::Result<i64> {
    sqlx::migrate!("../../migrations").run(write).await?;

    let version: Option<i64> =
        sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations WHERE success = 1")
            .fetch_one(write)
            .await?;

    Ok(version.unwrap_or(0))
}
