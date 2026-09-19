//! Reading and writing alert contexts, and the per-tenant model configuration.
//!
//! In its own module rather than in `repos.rs` because it is the one area of the schema
//! with a background worker attached: the claim/complete/fail cycle below is a small state
//! machine, and it reads better next to the queries it drives than three thousand lines
//! into the general repository file.

use anyhow::Result;
use fleet_core::time::now_unix;
use sqlx::Row;

use crate::Db;

/// Seconds in a day, for the UTC-day bucket `llm_usage` is keyed on.
const DAY: i64 = 86_400;

/// The UTC day `ts` falls in, as days since the epoch.
pub fn utc_day(ts: i64) -> i64 {
    ts.div_euclid(DAY)
}

/// One stored alert, as the API and the UI read it. The payload and the description stay
/// encrypted in this struct: decryption needs the master key, which storage does not have
/// and should not grow.
#[derive(Debug, Clone)]
pub struct AlertContextRow {
    pub id: String,
    pub tenant_id: i64,
    pub host_id: String,
    pub fingerprint: String,
    pub command: String,
    pub alias: Option<String>,
    pub status: String,
    pub message: String,
    pub payload_encrypted: Vec<u8>,
    pub payload_bytes: i64,
    pub occurrences: i64,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub enrichment_state: String,
    pub enrichment_attempts: i64,
    pub enrichment_error: Option<String>,
    pub enrichment_provider: Option<String>,
    pub enrichment_model: Option<String>,
    pub enrichment_encrypted: Option<Vec<u8>>,
    pub enriched_at: Option<i64>,
    pub enrichment_input_tokens: Option<i64>,
    pub enrichment_output_tokens: Option<i64>,
}

/// What an upsert did, so the caller can tell a new problem from a continuing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertOutcome {
    /// A problem not previously seen on this host. Queued for enrichment.
    Created,
    /// A repeat of a problem already on file: counted, re-stamped, not re-described.
    Updated,
}

/// Columns every read of this table selects. One constant so a column added later cannot
/// be picked up by three of five queries.
const COLUMNS: &str = "id, tenant_id, host_id, fingerprint, command, alias, status, message,
     payload_encrypted, payload_bytes, occurrences, first_seen_at, last_seen_at,
     enrichment_state, enrichment_attempts, enrichment_error, enrichment_provider,
     enrichment_model, enrichment_encrypted, enriched_at, enrichment_input_tokens,
     enrichment_output_tokens";

fn row_from(r: &sqlx::sqlite::SqliteRow) -> AlertContextRow {
    AlertContextRow {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        host_id: r.get("host_id"),
        fingerprint: r.get("fingerprint"),
        command: r.get("command"),
        alias: r.get("alias"),
        status: r.get("status"),
        message: r.get("message"),
        payload_encrypted: r.get("payload_encrypted"),
        payload_bytes: r.get("payload_bytes"),
        occurrences: r.get("occurrences"),
        first_seen_at: r.get("first_seen_at"),
        last_seen_at: r.get("last_seen_at"),
        enrichment_state: r.get("enrichment_state"),
        enrichment_attempts: r.get("enrichment_attempts"),
        enrichment_error: r.get("enrichment_error"),
        enrichment_provider: r.get("enrichment_provider"),
        enrichment_model: r.get("enrichment_model"),
        enrichment_encrypted: r.get("enrichment_encrypted"),
        enriched_at: r.get("enriched_at"),
        enrichment_input_tokens: r.get("enrichment_input_tokens"),
        enrichment_output_tokens: r.get("enrichment_output_tokens"),
    }
}

pub struct AlertContextRepo<'a> {
    db: &'a Db,
}

impl<'a> AlertContextRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    /// Record one alert, collapsing it onto the existing row for the same problem.
    ///
    /// The interesting half is what an update does *not* touch. `first_seen_at` is kept, so
    /// "this started on Tuesday" survives however many times the check has run since. The
    /// enrichment columns are kept too: a description already written for this problem is
    /// still a description of it, and clearing them on every repeat would re-run the model
    /// on a timer — the exact bill this design exists to avoid.
    ///
    /// What it does update is the payload, to the newest one. The stored evidence should be
    /// what the host looked like most recently, not what it looked like the first time.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert(
        &self,
        id: &str,
        tenant_id: i64,
        host_id: &str,
        fingerprint: &str,
        command: &str,
        alias: Option<&str>,
        status: &str,
        message: &str,
        payload_encrypted: &[u8],
        payload_bytes: i64,
    ) -> Result<UpsertOutcome> {
        let now = now_unix();
        // `occurrences = occurrences + 1` and the RETURNING clause together tell us which
        // branch ran without a second query: a fresh insert leaves it at the DEFAULT of 1.
        let row = sqlx::query(
            "INSERT INTO alert_contexts
               (id, tenant_id, host_id, fingerprint, command, alias, status, message,
                payload_encrypted, payload_bytes, occurrences, first_seen_at, last_seen_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
             ON CONFLICT(tenant_id, host_id, fingerprint) DO UPDATE SET
               message = excluded.message,
               alias = excluded.alias,
               payload_encrypted = excluded.payload_encrypted,
               payload_bytes = excluded.payload_bytes,
               occurrences = alert_contexts.occurrences + 1,
               last_seen_at = excluded.last_seen_at
             RETURNING id, occurrences",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(host_id)
        .bind(fingerprint)
        .bind(command)
        .bind(alias)
        .bind(status)
        .bind(message)
        .bind(payload_encrypted)
        .bind(payload_bytes)
        .bind(now)
        .bind(now)
        .fetch_one(&self.db.write)
        .await?;

        let occurrences: i64 = row.get("occurrences");
        Ok(if occurrences <= 1 {
            UpsertOutcome::Created
        } else {
            UpsertOutcome::Updated
        })
    }

    pub async fn get(&self, tenant_id: i64, id: &str) -> Result<Option<AlertContextRow>> {
        let row = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM alert_contexts WHERE tenant_id = ? AND id = ?"
        ))
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.as_ref().map(row_from))
    }

    /// Most-recent-first, optionally narrowed to one host and/or one status.
    pub async fn list(
        &self,
        tenant_id: i64,
        host_id: Option<&str>,
        status: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AlertContextRow>> {
        // Built rather than branched: two optional filters is four hand-written queries,
        // and the next one makes it eight. Every value is still bound, never interpolated.
        let mut sql = format!("SELECT {COLUMNS} FROM alert_contexts WHERE tenant_id = ?");
        if host_id.is_some() {
            sql.push_str(" AND host_id = ?");
        }
        if status.is_some() {
            sql.push_str(" AND status = ?");
        }
        sql.push_str(" ORDER BY last_seen_at DESC LIMIT ?");

        let mut q = sqlx::query(&sql).bind(tenant_id);
        if let Some(h) = host_id {
            q = q.bind(h);
        }
        if let Some(s) = status {
            q = q.bind(s);
        }
        let rows = q.bind(limit).fetch_all(&self.db.read).await?;
        Ok(rows.iter().map(row_from).collect())
    }

    pub async fn count_for_host(&self, tenant_id: i64, host_id: &str) -> Result<i64> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(*) FROM alert_contexts WHERE tenant_id = ? AND host_id = ?",
        )
        .bind(tenant_id)
        .bind(host_id)
        .fetch_one(&self.db.read)
        .await?)
    }

    pub async fn count_for_tenant(&self, tenant_id: i64) -> Result<i64> {
        Ok(
            sqlx::query_scalar("SELECT COUNT(*) FROM alert_contexts WHERE tenant_id = ?")
                .bind(tenant_id)
                .fetch_one(&self.db.read)
                .await?,
        )
    }

    /// Take up to `limit` rows that are ready to be described.
    ///
    /// This is a read, not a claim: with SQLite's single writer there is exactly one
    /// enrichment worker in one process, so there is no second claimant to race. Marking
    /// rows 'running' would buy nothing and would leave them stranded in that state if the
    /// process died mid-call — whereas a crash here simply means the row is still 'pending'
    /// on the next pass, which is the behaviour we want.
    pub async fn take_pending(&self, limit: i64) -> Result<Vec<AlertContextRow>> {
        let now = now_unix();
        let rows = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM alert_contexts
             WHERE enrichment_state = 'pending'
               AND (enrichment_next_attempt_at IS NULL OR enrichment_next_attempt_at <= ?)
             ORDER BY last_seen_at DESC
             LIMIT ?"
        ))
        .bind(now)
        .bind(limit)
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows.iter().map(row_from).collect())
    }

    pub async fn store_enrichment(
        &self,
        id: &str,
        provider: &str,
        model: &str,
        enrichment_encrypted: &[u8],
        input_tokens: Option<i64>,
        output_tokens: Option<i64>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE alert_contexts SET
               enrichment_state = 'done',
               enrichment_error = NULL,
               enrichment_next_attempt_at = NULL,
               enrichment_provider = ?,
               enrichment_model = ?,
               enrichment_encrypted = ?,
               enrichment_input_tokens = ?,
               enrichment_output_tokens = ?,
               enriched_at = ?
             WHERE id = ?",
        )
        .bind(provider)
        .bind(model)
        .bind(enrichment_encrypted)
        .bind(input_tokens)
        .bind(output_tokens)
        .bind(now_unix())
        .bind(id)
        .execute(&self.db.write)
        .await?;
        Ok(())
    }

    /// Record a failed attempt: retry after `retry_after_secs`, or give up when
    /// `max_attempts` is reached.
    ///
    /// Giving up is a real state rather than an ever-growing backoff because the common
    /// failures here are not transient — a revoked API key, a model name the provider does
    /// not serve, a tenant whose account is out of credit. Retrying those forever is a
    /// request-per-row-per-interval against somebody's paid endpoint that can never
    /// succeed. An operator who fixes the cause re-queues the rows explicitly.
    pub async fn record_failure(
        &self,
        id: &str,
        error: &str,
        max_attempts: i64,
        retry_after_secs: i64,
    ) -> Result<()> {
        let error = error.chars().take(512).collect::<String>();
        sqlx::query(
            "UPDATE alert_contexts SET
               enrichment_attempts = enrichment_attempts + 1,
               enrichment_error = ?,
               enrichment_state = CASE
                 WHEN enrichment_attempts + 1 >= ? THEN 'failed' ELSE 'pending' END,
               enrichment_next_attempt_at = ?
             WHERE id = ?",
        )
        .bind(error)
        .bind(max_attempts)
        .bind(now_unix() + retry_after_secs)
        .bind(id)
        .execute(&self.db.write)
        .await?;
        Ok(())
    }

    /// Park a row because the tenant has enrichment off, or has spent its budget.
    ///
    /// Not a failure and not a retry: it carries no attempt count, so a tenant who enables
    /// enrichment later starts from a clean slate rather than from rows that have already
    /// half-exhausted their retries against a provider they had not configured yet.
    pub async fn mark_skipped(&self, id: &str, reason: &str) -> Result<()> {
        sqlx::query(
            "UPDATE alert_contexts SET
               enrichment_state = 'skipped',
               enrichment_error = ?,
               enrichment_next_attempt_at = NULL
             WHERE id = ?",
        )
        .bind(reason.chars().take(512).collect::<String>())
        .bind(id)
        .execute(&self.db.write)
        .await?;
        Ok(())
    }

    /// Put a row back in the queue, clearing whatever stopped it last time.
    ///
    /// The escape hatch from both terminal states: an operator who has fixed the API key,
    /// switched provider, or raised the budget asks for the description again.
    pub async fn requeue(&self, tenant_id: i64, id: &str) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE alert_contexts SET
               enrichment_state = 'pending',
               enrichment_attempts = 0,
               enrichment_error = NULL,
               enrichment_next_attempt_at = NULL
             WHERE tenant_id = ? AND id = ?",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Re-queue every row a tenant has parked as 'skipped'.
    ///
    /// Called when a tenant turns enrichment on: the alerts that arrived while it was off
    /// are exactly the ones they now want described, and asking them to click each one
    /// would be a poor welcome.
    pub async fn requeue_skipped(&self, tenant_id: i64) -> Result<u64> {
        let res = sqlx::query(
            "UPDATE alert_contexts SET
               enrichment_state = 'pending',
               enrichment_attempts = 0,
               enrichment_error = NULL,
               enrichment_next_attempt_at = NULL
             WHERE tenant_id = ? AND enrichment_state = 'skipped'",
        )
        .bind(tenant_id)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn delete(&self, tenant_id: i64, id: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM alert_contexts WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(id)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Retention sweep: drop anything not seen for `max_age_secs`.
    ///
    /// Keyed on `last_seen_at`, so a problem that is still happening is never swept out
    /// from under the operator looking at it, however long ago it started.
    pub async fn delete_older_than(&self, max_age_secs: i64) -> Result<u64> {
        let cutoff = now_unix() - max_age_secs;
        let res = sqlx::query("DELETE FROM alert_contexts WHERE last_seen_at < ?")
            .bind(cutoff)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected())
    }

    /// Keep only the `keep` most recent alerts for a host, dropping the oldest beyond that.
    ///
    /// The bound that holds when retention does not: a host with a misconfigured check that
    /// produces a fresh fingerprint on every run (an argument carrying a timestamp, say)
    /// would otherwise fill the table with rows that are all too new to sweep.
    pub async fn trim_host(&self, tenant_id: i64, host_id: &str, keep: i64) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM alert_contexts
             WHERE tenant_id = ? AND host_id = ? AND id NOT IN (
               SELECT id FROM alert_contexts
               WHERE tenant_id = ? AND host_id = ?
               ORDER BY last_seen_at DESC LIMIT ?
             )",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(tenant_id)
        .bind(host_id)
        .bind(keep)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected())
    }
}

/// A tenant's model-provider configuration, with the API key still encrypted.
#[derive(Debug, Clone)]
pub struct TenantLlmSettings {
    pub tenant_id: i64,
    pub enabled: bool,
    pub provider: String,
    pub model: String,
    pub base_url: Option<String>,
    pub api_key_encrypted: Option<Vec<u8>>,
    pub daily_call_budget: i64,
    pub updated_at: i64,
}

/// A day's spend for one tenant.
#[derive(Debug, Clone, Default)]
pub struct LlmUsage {
    pub calls: i64,
    pub failures: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
}

pub struct TenantLlmRepo<'a> {
    db: &'a Db,
}

impl<'a> TenantLlmRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub async fn get(&self, tenant_id: i64) -> Result<Option<TenantLlmSettings>> {
        let row = sqlx::query(
            "SELECT tenant_id, enabled, provider, model, base_url, api_key_encrypted,
                    daily_call_budget, updated_at
             FROM tenant_llm_settings WHERE tenant_id = ?",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.map(|r| TenantLlmSettings {
            tenant_id: r.get("tenant_id"),
            enabled: r.get::<i64, _>("enabled") != 0,
            provider: r.get("provider"),
            model: r.get("model"),
            base_url: r.get("base_url"),
            api_key_encrypted: r.get("api_key_encrypted"),
            daily_call_budget: r.get("daily_call_budget"),
            updated_at: r.get("updated_at"),
        }))
    }

    /// Write the configuration. `api_key_encrypted` of `None` leaves the stored key alone,
    /// so the UI can save a changed model or budget without the browser having to hold —
    /// or round-trip — a credential it was never shown.
    #[allow(clippy::too_many_arguments)]
    pub async fn set(
        &self,
        tenant_id: i64,
        enabled: bool,
        provider: &str,
        model: &str,
        base_url: Option<&str>,
        api_key_encrypted: Option<&[u8]>,
        daily_call_budget: i64,
        updated_by_user: Option<i64>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenant_llm_settings
               (tenant_id, enabled, provider, model, base_url, api_key_encrypted,
                daily_call_budget, updated_at, updated_by_user)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(tenant_id) DO UPDATE SET
               enabled = excluded.enabled,
               provider = excluded.provider,
               model = excluded.model,
               base_url = excluded.base_url,
               api_key_encrypted = COALESCE(excluded.api_key_encrypted, tenant_llm_settings.api_key_encrypted),
               daily_call_budget = excluded.daily_call_budget,
               updated_at = excluded.updated_at,
               updated_by_user = excluded.updated_by_user",
        )
        .bind(tenant_id)
        .bind(i64::from(enabled))
        .bind(provider)
        .bind(model)
        .bind(base_url)
        .bind(api_key_encrypted)
        .bind(daily_call_budget)
        .bind(now_unix())
        .bind(updated_by_user)
        .execute(&self.db.write)
        .await?;
        Ok(())
    }

    /// Forget the stored credential without otherwise changing the configuration.
    pub async fn clear_api_key(&self, tenant_id: i64) -> Result<()> {
        sqlx::query("UPDATE tenant_llm_settings SET api_key_encrypted = NULL, updated_at = ? WHERE tenant_id = ?")
            .bind(now_unix())
            .bind(tenant_id)
            .execute(&self.db.write)
            .await?;
        Ok(())
    }

    pub async fn usage(&self, tenant_id: i64, day: i64) -> Result<LlmUsage> {
        let row = sqlx::query(
            "SELECT calls, failures, input_tokens, output_tokens
             FROM llm_usage WHERE tenant_id = ? AND day = ?",
        )
        .bind(tenant_id)
        .bind(day)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row
            .map(|r| LlmUsage {
                calls: r.get("calls"),
                failures: r.get("failures"),
                input_tokens: r.get("input_tokens"),
                output_tokens: r.get("output_tokens"),
            })
            .unwrap_or_default())
    }

    /// Count one attempt against the day's budget.
    ///
    /// Every attempt counts, successful or not, which is the only counting that bounds
    /// spend: a request that fails after the provider has read the prompt has usually been
    /// billed, and one that is rejected outright still costs a round trip. `failures` is
    /// tracked separately so the console can show "80 calls, 79 of them failing" — the
    /// shape of a misconfiguration — rather than just a budget quietly draining.
    pub async fn record_call(
        &self,
        tenant_id: i64,
        day: i64,
        failed: bool,
        input_tokens: i64,
        output_tokens: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO llm_usage (tenant_id, day, calls, failures, input_tokens, output_tokens)
             VALUES (?, ?, 1, ?, ?, ?)
             ON CONFLICT(tenant_id, day) DO UPDATE SET
               calls = llm_usage.calls + 1,
               failures = llm_usage.failures + excluded.failures,
               input_tokens = llm_usage.input_tokens + excluded.input_tokens,
               output_tokens = llm_usage.output_tokens + excluded.output_tokens",
        )
        .bind(tenant_id)
        .bind(day)
        .bind(i64::from(failed))
        .bind(input_tokens)
        .bind(output_tokens)
        .execute(&self.db.write)
        .await?;
        Ok(())
    }

    /// Drop usage rows older than `keep_days`, counted from `today`.
    pub async fn sweep_usage(&self, today: i64, keep_days: i64) -> Result<u64> {
        let res = sqlx::query("DELETE FROM llm_usage WHERE day < ?")
            .bind(today - keep_days)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database with one tenant and two hosts, migrations applied.
    async fn fixture() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::pool::open(dir.path().join("test.db").to_str().unwrap())
            .await
            .unwrap();
        crate::run_migrations(&db.write).await.unwrap();
        sqlx::query("INSERT INTO tenants (id, slug, name, tier, created_at) VALUES (1,'acme','Acme','free',0)")
            .execute(&db.write).await.unwrap();
        sqlx::query("INSERT INTO hosts (id, tenant_id, created_at) VALUES ('h1',1,0), ('h2',1,0)")
            .execute(&db.write)
            .await
            .unwrap();
        (dir, db)
    }

    async fn put(db: &Db, id: &str, host: &str, fp: &str, payload: &[u8]) -> UpsertOutcome {
        AlertContextRepo::new(db)
            .upsert(
                id,
                1,
                host,
                fp,
                "check_drivesize",
                Some("disk"),
                "critical",
                "C:\\ is full",
                payload,
                payload.len() as i64,
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn the_same_problem_reported_twice_is_one_row() {
        let (_d, db) = fixture().await;
        let repo = AlertContextRepo::new(&db);

        assert_eq!(
            put(&db, "a1", "h1", "fp1", b"first").await,
            UpsertOutcome::Created
        );
        assert_eq!(
            put(&db, "a2", "h1", "fp1", b"second").await,
            UpsertOutcome::Updated
        );
        assert_eq!(
            put(&db, "a3", "h1", "fp1", b"third").await,
            UpsertOutcome::Updated
        );

        let rows = repo.list(1, None, None, 100).await.unwrap();
        assert_eq!(
            rows.len(),
            1,
            "a check on a timer must not be a row per run"
        );
        assert_eq!(rows[0].occurrences, 3);
        assert_eq!(
            rows[0].id, "a1",
            "the row keeps the identity it was created with"
        );
        assert_eq!(
            rows[0].payload_encrypted, b"third",
            "the stored evidence is the most recent, not the first"
        );
    }

    #[tokio::test]
    async fn the_same_problem_on_two_hosts_is_two_rows() {
        let (_d, db) = fixture().await;
        put(&db, "a1", "h1", "fp1", b"x").await;
        assert_eq!(
            put(&db, "a2", "h2", "fp1", b"x").await,
            UpsertOutcome::Created
        );
        assert_eq!(
            AlertContextRepo::new(&db)
                .list(1, None, None, 100)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn a_repeat_keeps_the_description_already_written_for_it() {
        let (_d, db) = fixture().await;
        let repo = AlertContextRepo::new(&db);
        put(&db, "a1", "h1", "fp1", b"x").await;
        repo.store_enrichment(
            "a1",
            "anthropic",
            "claude-opus-5",
            b"ciphertext",
            Some(1200),
            Some(300),
        )
        .await
        .unwrap();

        put(&db, "a2", "h1", "fp1", b"y").await;

        let row = repo.get(1, "a1").await.unwrap().unwrap();
        assert_eq!(row.occurrences, 2);
        assert_eq!(
            row.enrichment_state, "done",
            "re-describing on every repeat is the bill this design exists to avoid"
        );
        assert_eq!(
            row.enrichment_encrypted.as_deref(),
            Some(&b"ciphertext"[..])
        );
        assert!(
            repo.take_pending(10).await.unwrap().is_empty(),
            "a described problem must not return to the queue when it recurs"
        );
    }

    #[tokio::test]
    async fn first_seen_survives_every_repeat() {
        let (_d, db) = fixture().await;
        let repo = AlertContextRepo::new(&db);
        put(&db, "a1", "h1", "fp1", b"x").await;
        let first = repo.get(1, "a1").await.unwrap().unwrap().first_seen_at;
        sqlx::query("UPDATE alert_contexts SET first_seen_at = 1000, last_seen_at = 1000")
            .execute(&db.write)
            .await
            .unwrap();
        put(&db, "a2", "h1", "fp1", b"x").await;
        let row = repo.get(1, "a1").await.unwrap().unwrap();
        assert_eq!(
            row.first_seen_at, 1000,
            "'this started on Tuesday' must survive"
        );
        assert!(row.last_seen_at > 1000);
        let _ = first;
    }

    #[tokio::test]
    async fn failures_back_off_and_then_give_up() {
        let (_d, db) = fixture().await;
        let repo = AlertContextRepo::new(&db);
        put(&db, "a1", "h1", "fp1", b"x").await;

        repo.record_failure("a1", "503 from provider", 3, 60)
            .await
            .unwrap();
        let row = repo.get(1, "a1").await.unwrap().unwrap();
        assert_eq!(row.enrichment_state, "pending");
        assert_eq!(row.enrichment_attempts, 1);
        assert!(
            repo.take_pending(10).await.unwrap().is_empty(),
            "a row inside its backoff window must not be picked up again immediately"
        );

        repo.record_failure("a1", "503", 3, 0).await.unwrap();
        assert_eq!(
            repo.take_pending(10).await.unwrap().len(),
            1,
            "eligible once the window passes"
        );

        repo.record_failure("a1", "401 invalid api key", 3, 0)
            .await
            .unwrap();
        let row = repo.get(1, "a1").await.unwrap().unwrap();
        assert_eq!(
            row.enrichment_state, "failed",
            "a revoked key must not be retried against a paid endpoint forever"
        );
        assert!(repo.take_pending(10).await.unwrap().is_empty());

        assert!(repo.requeue(1, "a1").await.unwrap());
        let row = repo.get(1, "a1").await.unwrap().unwrap();
        assert_eq!(row.enrichment_state, "pending");
        assert_eq!(
            row.enrichment_attempts, 0,
            "fixing the cause starts from a clean slate"
        );
    }

    #[tokio::test]
    async fn turning_enrichment_on_picks_up_what_arrived_while_it_was_off() {
        let (_d, db) = fixture().await;
        let repo = AlertContextRepo::new(&db);
        put(&db, "a1", "h1", "fp1", b"x").await;
        put(&db, "a2", "h1", "fp2", b"x").await;
        repo.mark_skipped("a1", "enrichment is not enabled")
            .await
            .unwrap();
        repo.mark_skipped("a2", "enrichment is not enabled")
            .await
            .unwrap();
        assert!(repo.take_pending(10).await.unwrap().is_empty());

        assert_eq!(repo.requeue_skipped(1).await.unwrap(), 2);
        assert_eq!(repo.take_pending(10).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_tenant_cannot_read_or_delete_another_tenants_alert() {
        let (_d, db) = fixture().await;
        let repo = AlertContextRepo::new(&db);
        put(&db, "a1", "h1", "fp1", b"x").await;
        assert!(repo.get(2, "a1").await.unwrap().is_none());
        assert!(!repo.delete(2, "a1").await.unwrap());
        assert!(!repo.requeue(2, "a1").await.unwrap());
        assert!(repo.get(1, "a1").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn listing_filters_by_host_and_status() {
        let (_d, db) = fixture().await;
        let repo = AlertContextRepo::new(&db);
        put(&db, "a1", "h1", "fp1", b"x").await;
        put(&db, "a2", "h2", "fp2", b"x").await;
        sqlx::query("UPDATE alert_contexts SET status = 'warning' WHERE id = 'a2'")
            .execute(&db.write)
            .await
            .unwrap();

        assert_eq!(repo.list(1, Some("h1"), None, 100).await.unwrap().len(), 1);
        assert_eq!(
            repo.list(1, None, Some("warning"), 100)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            repo.list(1, Some("h1"), Some("warning"), 100)
                .await
                .unwrap()
                .len(),
            0
        );
        assert_eq!(repo.count_for_host(1, "h1").await.unwrap(), 1);
        assert_eq!(repo.count_for_tenant(1).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn retention_keeps_problems_that_are_still_happening() {
        let (_d, db) = fixture().await;
        let repo = AlertContextRepo::new(&db);
        put(&db, "old", "h1", "fp1", b"x").await;
        put(&db, "live", "h1", "fp2", b"x").await;
        // 'old' started and stopped long ago; 'live' started long ago and is still firing.
        sqlx::query(
            "UPDATE alert_contexts SET first_seen_at = 0, last_seen_at = 0 WHERE id = 'old'",
        )
        .execute(&db.write)
        .await
        .unwrap();
        sqlx::query("UPDATE alert_contexts SET first_seen_at = 0 WHERE id = 'live'")
            .execute(&db.write)
            .await
            .unwrap();

        assert_eq!(repo.delete_older_than(3600).await.unwrap(), 1);
        let rows = repo.list(1, None, None, 100).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "live", "a long-running problem is not stale");
    }

    #[tokio::test]
    async fn a_host_inventing_fingerprints_is_capped() {
        let (_d, db) = fixture().await;
        let repo = AlertContextRepo::new(&db);
        for i in 0..10 {
            put(&db, &format!("a{i}"), "h1", &format!("fp{i}"), b"x").await;
            sqlx::query("UPDATE alert_contexts SET last_seen_at = ? WHERE id = ?")
                .bind(1000 + i)
                .bind(format!("a{i}"))
                .execute(&db.write)
                .await
                .unwrap();
        }
        put(&db, "other", "h2", "fp1", b"x").await;

        assert_eq!(repo.trim_host(1, "h1", 3).await.unwrap(), 7);
        let kept = repo.list(1, Some("h1"), None, 100).await.unwrap();
        assert_eq!(kept.len(), 3);
        assert_eq!(
            kept.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["a9", "a8", "a7"],
            "the newest are the ones worth keeping"
        );
        assert_eq!(
            repo.count_for_host(1, "h2").await.unwrap(),
            1,
            "trimming one host must not touch another"
        );
    }

    #[tokio::test]
    async fn deleting_a_host_takes_its_alerts_with_it() {
        let (_d, db) = fixture().await;
        let repo = AlertContextRepo::new(&db);
        put(&db, "a1", "h1", "fp1", b"x").await;
        sqlx::query("DELETE FROM hosts WHERE id = 'h1'")
            .execute(&db.write)
            .await
            .unwrap();
        assert_eq!(
            repo.count_for_tenant(1).await.unwrap(),
            0,
            "a decommissioned host must not leave its evidence behind"
        );
    }

    #[tokio::test]
    async fn saving_settings_without_a_key_keeps_the_stored_one() {
        let (_d, db) = fixture().await;
        let repo = TenantLlmRepo::new(&db);
        repo.set(
            1,
            true,
            "anthropic",
            "claude-opus-5",
            None,
            Some(b"secret"),
            200,
            None,
        )
        .await
        .unwrap();
        // The UI never sees the key, so a save that only changes the model sends none.
        repo.set(
            1,
            true,
            "anthropic",
            "claude-sonnet-5",
            None,
            None,
            500,
            None,
        )
        .await
        .unwrap();

        let s = repo.get(1).await.unwrap().unwrap();
        assert_eq!(s.model, "claude-sonnet-5");
        assert_eq!(s.daily_call_budget, 500);
        assert_eq!(
            s.api_key_encrypted.as_deref(),
            Some(&b"secret"[..]),
            "editing the model must not silently unconfigure the provider"
        );

        repo.clear_api_key(1).await.unwrap();
        assert!(repo
            .get(1)
            .await
            .unwrap()
            .unwrap()
            .api_key_encrypted
            .is_none());
    }

    #[tokio::test]
    async fn no_settings_row_means_disabled() {
        let (_d, db) = fixture().await;
        assert!(
            TenantLlmRepo::new(&db).get(1).await.unwrap().is_none(),
            "nothing leaves this server until someone has said it may"
        );
    }

    #[tokio::test]
    async fn usage_accumulates_per_day_and_counts_failures() {
        let (_d, db) = fixture().await;
        let repo = TenantLlmRepo::new(&db);
        let today = utc_day(now_unix());

        repo.record_call(1, today, false, 1200, 300).await.unwrap();
        repo.record_call(1, today, false, 800, 200).await.unwrap();
        repo.record_call(1, today, true, 0, 0).await.unwrap();

        let u = repo.usage(1, today).await.unwrap();
        assert_eq!(u.calls, 3, "a failed call still cost a round trip");
        assert_eq!(u.failures, 1);
        assert_eq!(u.input_tokens, 2000);
        assert_eq!(u.output_tokens, 500);

        assert_eq!(
            repo.usage(1, today - 1).await.unwrap().calls,
            0,
            "yesterday is its own bucket"
        );

        repo.record_call(1, today - 90, false, 1, 1).await.unwrap();
        assert_eq!(repo.sweep_usage(today, 30).await.unwrap(), 1);
        assert_eq!(repo.usage(1, today).await.unwrap().calls, 3);
    }

    #[test]
    fn utc_day_is_stable_across_the_epoch_boundary() {
        assert_eq!(utc_day(0), 0);
        assert_eq!(utc_day(86_399), 0);
        assert_eq!(utc_day(86_400), 1);
        // div_euclid, not integer division: a pre-epoch clock must not land on day 0 twice.
        assert_eq!(utc_day(-1), -1);
    }
}
