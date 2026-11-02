//! Failure contexts: the reports an agent sends about failed checks, and the per-tenant
//! settings that govern whether they are taken and how they are described.
//!
//! The claim/complete/fail cycle at the bottom is a small state machine, so it reads better
//! next to the queries that drive it than spread through the general repositories.

use anyhow::Result;
use fleet_core::time::now_unix;
use sqlx::{AssertSqlSafe, Row};

use crate::Db;

/// Seconds in a day, for the UTC-day bucket `llm_usage` is keyed on.
const DAY: i64 = 86_400;

/// The UTC day `ts` falls in, as days since the epoch.
pub fn utc_day(ts: i64) -> i64 {
    ts.div_euclid(DAY)
}

/// One stored report, as the API and the worker read it. The payload and the description
/// stay encrypted here: decryption needs the master key, which storage does not have and
/// should not grow.
#[derive(Debug, Clone)]
pub struct FailureContextRow {
    pub id: String,
    pub tenant_id: i64,
    pub host_id: String,
    pub fingerprint: String,
    pub command: String,
    pub alias: String,
    pub status: i64,
    pub status_word: String,
    pub message: String,
    pub subject: String,
    pub context_state: String,
    pub metrics_count: i64,
    pub window_suppressed: i64,
    pub window_evicted: i64,
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

/// The row a report landed on. The id is the row's, which for a repeat is the id the
/// *first* report created — so the caller never has to look it up to act on the row it
/// just wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upserted {
    pub id: String,
    pub outcome: UpsertOutcome,
    pub occurrences: i64,
}

/// What to store for one report.
#[derive(Debug, Clone)]
pub struct NewFailureContext<'a> {
    pub id: &'a str,
    pub tenant_id: i64,
    pub host_id: &'a str,
    pub fingerprint: &'a str,
    pub command: &'a str,
    pub alias: &'a str,
    pub status: i64,
    pub status_word: &'a str,
    pub message: &'a str,
    pub subject: &'a str,
    pub context_state: &'a str,
    pub metrics_count: i64,
    pub window_suppressed: i64,
    pub window_evicted: i64,
    pub payload_encrypted: &'a [u8],
    pub payload_bytes: i64,
}

/// Columns every read of this table selects. One constant so a column added later cannot be
/// picked up by three of five queries.
const COLUMNS: &str = "id, tenant_id, host_id, fingerprint, command, alias, status, status_word,
     message, subject, context_state, metrics_count, window_suppressed, window_evicted,
     payload_encrypted, payload_bytes, occurrences, first_seen_at, last_seen_at,
     enrichment_state, enrichment_attempts, enrichment_error, enrichment_provider,
     enrichment_model, enrichment_encrypted, enriched_at, enrichment_input_tokens,
     enrichment_output_tokens";

fn row_from(r: &sqlx::sqlite::SqliteRow) -> FailureContextRow {
    FailureContextRow {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        host_id: r.get("host_id"),
        fingerprint: r.get("fingerprint"),
        command: r.get("command"),
        alias: r.get("alias"),
        status: r.get("status"),
        status_word: r.get("status_word"),
        message: r.get("message"),
        subject: r.get("subject"),
        context_state: r.get("context_state"),
        metrics_count: r.get("metrics_count"),
        window_suppressed: r.get("window_suppressed"),
        window_evicted: r.get("window_evicted"),
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

pub struct FailureContextRepo<'a> {
    db: &'a Db,
}

impl<'a> FailureContextRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    /// Record one report, collapsing it onto the existing row for the same problem.
    ///
    /// The interesting half is what an update does *not* touch. `first_seen_at` is kept, so
    /// "this started on Tuesday" survives however many reports have arrived since. The
    /// enrichment columns are kept too: a description already written for this problem is
    /// still a description of it, and clearing them on every repeat would re-run the model
    /// once an interval forever — the bill this design exists to avoid.
    ///
    /// What it does replace is the payload, with the newest one. The stored evidence should
    /// be the most recent picture of the host, not the first.
    pub async fn upsert(&self, new: NewFailureContext<'_>) -> Result<Upserted> {
        let now = now_unix();
        // `occurrences + 1` with a RETURNING clause tells us which branch ran without a
        // second query: a fresh insert leaves it at the DEFAULT of 1.
        let row = sqlx::query(
            "INSERT INTO failure_contexts
               (id, tenant_id, host_id, fingerprint, command, alias, status, status_word,
                message, subject, context_state, metrics_count, window_suppressed,
                window_evicted, payload_encrypted, payload_bytes, occurrences,
                first_seen_at, last_seen_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
             ON CONFLICT(tenant_id, host_id, fingerprint) DO UPDATE SET
               status_word = excluded.status_word,
               message = excluded.message,
               subject = excluded.subject,
               context_state = excluded.context_state,
               metrics_count = excluded.metrics_count,
               window_suppressed = excluded.window_suppressed,
               window_evicted = excluded.window_evicted,
               payload_encrypted = excluded.payload_encrypted,
               payload_bytes = excluded.payload_bytes,
               occurrences = failure_contexts.occurrences + 1,
               last_seen_at = excluded.last_seen_at
             RETURNING id, occurrences",
        )
        .bind(new.id)
        .bind(new.tenant_id)
        .bind(new.host_id)
        .bind(new.fingerprint)
        .bind(new.command)
        .bind(new.alias)
        .bind(new.status)
        .bind(new.status_word)
        .bind(new.message)
        .bind(new.subject)
        .bind(new.context_state)
        .bind(new.metrics_count)
        .bind(new.window_suppressed)
        .bind(new.window_evicted)
        .bind(new.payload_encrypted)
        .bind(new.payload_bytes)
        .bind(now)
        .bind(now)
        .fetch_one(&self.db.write)
        .await?;

        let occurrences: i64 = row.get("occurrences");
        Ok(Upserted {
            id: row.get("id"),
            outcome: if occurrences <= 1 {
                UpsertOutcome::Created
            } else {
                UpsertOutcome::Updated
            },
            occurrences,
        })
    }

    pub async fn get(&self, tenant_id: i64, id: &str) -> Result<Option<FailureContextRow>> {
        // AssertSqlSafe: the only interpolation is the COLUMNS constant above. Every
        // caller value is bound.
        let row = sqlx::query(AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM failure_contexts WHERE tenant_id = ? AND id = ?"
        )))
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
        status: Option<i64>,
        limit: i64,
    ) -> Result<Vec<FailureContextRow>> {
        // Built rather than branched: two optional filters is four hand-written queries, and
        // the next one makes it eight. Every value is still bound, never interpolated.
        let mut sql = format!("SELECT {COLUMNS} FROM failure_contexts WHERE tenant_id = ?");
        if host_id.is_some() {
            sql.push_str(" AND host_id = ?");
        }
        if status.is_some() {
            sql.push_str(" AND status = ?");
        }
        sql.push_str(" ORDER BY last_seen_at DESC LIMIT ?");

        // AssertSqlSafe: `sql` is the COLUMNS constant plus the literal fragments
        // chosen above. The filters contribute a `?` each, never a value.
        let mut q = sqlx::query(AssertSqlSafe(sql)).bind(tenant_id);
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
            "SELECT COUNT(*) FROM failure_contexts WHERE tenant_id = ? AND host_id = ?",
        )
        .bind(tenant_id)
        .bind(host_id)
        .fetch_one(&self.db.read)
        .await?)
    }

    pub async fn count_for_tenant(&self, tenant_id: i64) -> Result<i64> {
        Ok(
            sqlx::query_scalar("SELECT COUNT(*) FROM failure_contexts WHERE tenant_id = ?")
                .bind(tenant_id)
                .fetch_one(&self.db.read)
                .await?,
        )
    }

    /// Take up to `limit` rows that are ready to be described.
    ///
    /// A read, not a claim: with SQLite's single writer there is exactly one enrichment
    /// worker in one process, so there is no second claimant to race. Marking rows
    /// 'running' would buy nothing and would strand them in that state if the process died
    /// mid-call — whereas a crash here leaves the row 'pending' for the next pass, which is
    /// the behaviour we want.
    pub async fn take_pending(&self, limit: i64) -> Result<Vec<FailureContextRow>> {
        let now = now_unix();
        // AssertSqlSafe: as above, only COLUMNS is interpolated.
        let rows = sqlx::query(AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM failure_contexts
             WHERE enrichment_state = 'pending'
               AND (enrichment_next_attempt_at IS NULL OR enrichment_next_attempt_at <= ?)
             ORDER BY last_seen_at DESC
             LIMIT ?"
        )))
        .bind(now)
        .bind(limit)
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows.iter().map(row_from).collect())
    }

    #[allow(clippy::too_many_arguments)]
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
            "UPDATE failure_contexts SET
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

    /// Record a failed attempt: retry after `retry_after_secs`, or give up once
    /// `max_attempts` is reached.
    ///
    /// Giving up is a real state rather than an ever-widening backoff because the common
    /// failures here are not transient — a revoked API key, a model the provider does not
    /// serve, an account out of credit. Retrying those is a request per row per interval
    /// against a paid endpoint that can never succeed. An operator who fixes the cause
    /// re-queues the rows explicitly.
    pub async fn record_failure(
        &self,
        id: &str,
        error: &str,
        max_attempts: i64,
        retry_after_secs: i64,
    ) -> Result<()> {
        let error = error.chars().take(512).collect::<String>();
        sqlx::query(
            "UPDATE failure_contexts SET
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

    /// Park a row: the tenant has enrichment off, has spent its budget, or the report is not
    /// a failure at all.
    ///
    /// Not a failure and not a retry, so it carries no attempt count: a tenant who enables
    /// enrichment later starts from a clean slate rather than from rows that already
    /// half-exhausted their retries against a provider they had not configured yet.
    pub async fn mark_skipped(&self, id: &str, reason: &str) -> Result<()> {
        sqlx::query(
            "UPDATE failure_contexts SET
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
    /// switched provider or raised the budget asks for the description again.
    pub async fn requeue(&self, tenant_id: i64, id: &str) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE failure_contexts SET
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

    /// Re-queue every row a tenant has parked as 'skipped', except the ones that are not
    /// failures at all.
    ///
    /// Called when a tenant turns enrichment on: the reports that arrived while it was off
    /// are exactly the ones they now want described, and asking them to click each one would
    /// be a poor welcome. A row parked because its check passed stays parked — enabling
    /// enrichment is not a reason to describe a success.
    pub async fn requeue_skipped(&self, tenant_id: i64) -> Result<u64> {
        let res = sqlx::query(
            "UPDATE failure_contexts SET
               enrichment_state = 'pending',
               enrichment_attempts = 0,
               enrichment_error = NULL,
               enrichment_next_attempt_at = NULL
             WHERE tenant_id = ? AND enrichment_state = 'skipped' AND status != 0",
        )
        .bind(tenant_id)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn delete(&self, tenant_id: i64, id: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM failure_contexts WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(id)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Retention sweep: drop anything not seen for `max_age_secs`.
    ///
    /// Keyed on `last_seen_at`, so a problem that is still being reported is never swept out
    /// from under the operator looking at it, however long ago it started.
    pub async fn delete_older_than(&self, max_age_secs: i64) -> Result<u64> {
        let cutoff = now_unix() - max_age_secs;
        let res = sqlx::query("DELETE FROM failure_contexts WHERE last_seen_at < ?")
            .bind(cutoff)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected())
    }

    /// Keep only the `keep` most recent rows for a host, dropping the oldest beyond that.
    ///
    /// The bound that holds when retention does not: a host whose checks carry something
    /// variable in their alias or arguments produces a fresh fingerprint every time, and
    /// every one of those rows is too new to sweep.
    pub async fn trim_host(&self, tenant_id: i64, host_id: &str, keep: i64) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM failure_contexts
             WHERE tenant_id = ? AND host_id = ? AND id NOT IN (
               SELECT id FROM failure_contexts
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

/// A tenant's settings for the feature, with the API key still encrypted.
#[derive(Debug, Clone)]
pub struct TenantFailureSettings {
    pub tenant_id: i64,
    pub reports_enabled: bool,
    pub min_interval_secs: i64,
    pub enrichment_enabled: bool,
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

/// What to write for a tenant's settings. `api_key_encrypted` of `None` leaves the stored key
/// alone, so the console can save a changed model or budget without the browser having to
/// hold — or round-trip — a credential it was never shown.
#[derive(Debug, Clone)]
pub struct NewFailureSettings<'a> {
    pub reports_enabled: bool,
    pub min_interval_secs: i64,
    pub enrichment_enabled: bool,
    pub provider: &'a str,
    pub model: &'a str,
    pub base_url: Option<&'a str>,
    pub api_key_encrypted: Option<&'a [u8]>,
    pub daily_call_budget: i64,
    pub updated_by_user: Option<i64>,
}

pub struct TenantFailureSettingsRepo<'a> {
    db: &'a Db,
}

impl<'a> TenantFailureSettingsRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub async fn get(&self, tenant_id: i64) -> Result<Option<TenantFailureSettings>> {
        let row = sqlx::query(
            "SELECT tenant_id, reports_enabled, min_interval_secs, enrichment_enabled, provider,
                    model, base_url, api_key_encrypted, daily_call_budget, updated_at
             FROM tenant_failure_settings WHERE tenant_id = ?",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.map(|r| TenantFailureSettings {
            tenant_id: r.get("tenant_id"),
            reports_enabled: r.get::<i64, _>("reports_enabled") != 0,
            min_interval_secs: r.get("min_interval_secs"),
            enrichment_enabled: r.get::<i64, _>("enrichment_enabled") != 0,
            provider: r.get("provider"),
            model: r.get("model"),
            base_url: r.get("base_url"),
            api_key_encrypted: r.get("api_key_encrypted"),
            daily_call_budget: r.get("daily_call_budget"),
            updated_at: r.get("updated_at"),
        }))
    }

    pub async fn set(&self, tenant_id: i64, new: NewFailureSettings<'_>) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenant_failure_settings
               (tenant_id, reports_enabled, min_interval_secs, enrichment_enabled, provider,
                model, base_url, api_key_encrypted, daily_call_budget, updated_at,
                updated_by_user)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(tenant_id) DO UPDATE SET
               reports_enabled = excluded.reports_enabled,
               min_interval_secs = excluded.min_interval_secs,
               enrichment_enabled = excluded.enrichment_enabled,
               provider = excluded.provider,
               model = excluded.model,
               base_url = excluded.base_url,
               api_key_encrypted = COALESCE(excluded.api_key_encrypted,
                                            tenant_failure_settings.api_key_encrypted),
               daily_call_budget = excluded.daily_call_budget,
               updated_at = excluded.updated_at,
               updated_by_user = excluded.updated_by_user",
        )
        .bind(tenant_id)
        .bind(i64::from(new.reports_enabled))
        .bind(new.min_interval_secs)
        .bind(i64::from(new.enrichment_enabled))
        .bind(new.provider)
        .bind(new.model)
        .bind(new.base_url)
        .bind(new.api_key_encrypted)
        .bind(new.daily_call_budget)
        .bind(now_unix())
        .bind(new.updated_by_user)
        .execute(&self.db.write)
        .await?;
        Ok(())
    }

    /// Forget the stored credential without otherwise changing the settings.
    pub async fn clear_api_key(&self, tenant_id: i64) -> Result<()> {
        sqlx::query(
            "UPDATE tenant_failure_settings SET api_key_encrypted = NULL, updated_at = ?
             WHERE tenant_id = ?",
        )
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
    /// billed, and one rejected outright still cost a round trip. `failures` is tracked
    /// separately so the console can show "80 calls, 79 of them failing" — the shape of a
    /// misconfiguration — rather than a budget quietly draining.
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
        let dir = tempfile::TempDir::new().unwrap();
        let db = crate::open(dir.path().join("test.db")).await.unwrap();
        crate::run_migrations(&db.write).await.unwrap();
        sqlx::query("INSERT INTO tenants (id, slug, name, tier, created_at) VALUES (1,'acme','Acme','free',0)")
            .execute(&db.write).await.unwrap();
        sqlx::query("INSERT INTO hosts (id, tenant_id, created_at) VALUES ('h1',1,0), ('h2',1,0)")
            .execute(&db.write)
            .await
            .unwrap();
        (dir, db)
    }

    fn new<'a>(
        id: &'a str,
        host: &'a str,
        fp: &'a str,
        payload: &'a [u8],
    ) -> NewFailureContext<'a> {
        NewFailureContext {
            id,
            tenant_id: 1,
            host_id: host,
            fingerprint: fp,
            command: "check_drivesize",
            alias: "disk_c",
            status: 2,
            status_word: "CRITICAL",
            message: "C:\\ is full",
            subject: "Scheduler",
            context_state: "captured",
            metrics_count: 521,
            window_suppressed: 3,
            window_evicted: 0,
            payload_encrypted: payload,
            payload_bytes: payload.len() as i64,
        }
    }

    async fn put(db: &Db, id: &str, host: &str, fp: &str, payload: &[u8]) -> UpsertOutcome {
        FailureContextRepo::new(db)
            .upsert(new(id, host, fp, payload))
            .await
            .unwrap()
            .outcome
    }

    #[tokio::test]
    async fn the_same_problem_reported_twice_is_one_row() {
        let (_d, db) = fixture().await;
        let repo = FailureContextRepo::new(&db);

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
        assert_eq!(rows.len(), 1, "an hourly report must not be a row per hour");
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
            FailureContextRepo::new(&db)
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
        let repo = FailureContextRepo::new(&db);
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
            "re-describing every interval is the bill this design exists to avoid"
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
    async fn a_repeat_refreshes_the_window_counts_and_the_snapshot_state() {
        let (_d, db) = fixture().await;
        let repo = FailureContextRepo::new(&db);
        put(&db, "a1", "h1", "fp1", b"x").await;

        // The next report's window found nothing suppressed and had no snapshot.
        let mut next = new("a2", "h1", "fp1", b"y");
        next.window_suppressed = 0;
        next.window_evicted = 4;
        next.context_state = "disabled";
        next.metrics_count = 0;
        repo.upsert(next).await.unwrap();

        let row = repo.get(1, "a1").await.unwrap().unwrap();
        assert_eq!(
            row.window_suppressed, 0,
            "the window is the latest one, not a total"
        );
        assert_eq!(row.window_evicted, 4);
        assert_eq!(row.context_state, "disabled");
        assert_eq!(row.metrics_count, 0);
    }

    #[tokio::test]
    async fn first_seen_survives_every_repeat() {
        let (_d, db) = fixture().await;
        let repo = FailureContextRepo::new(&db);
        put(&db, "a1", "h1", "fp1", b"x").await;
        sqlx::query("UPDATE failure_contexts SET first_seen_at = 1000, last_seen_at = 1000")
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
    }

    #[tokio::test]
    async fn failures_back_off_and_then_give_up() {
        let (_d, db) = fixture().await;
        let repo = FailureContextRepo::new(&db);
        put(&db, "a1", "h1", "fp1", b"x").await;

        repo.record_failure("a1", "503 from provider", 3, 60)
            .await
            .unwrap();
        let row = repo.get(1, "a1").await.unwrap().unwrap();
        assert_eq!(row.enrichment_state, "pending");
        assert_eq!(row.enrichment_attempts, 1);
        assert!(
            repo.take_pending(10).await.unwrap().is_empty(),
            "a row inside its backoff window must not be picked up again at once"
        );

        repo.record_failure("a1", "503", 3, 0).await.unwrap();
        assert_eq!(
            repo.take_pending(10).await.unwrap().len(),
            1,
            "eligible once it passes"
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
    async fn turning_enrichment_on_picks_up_failures_but_not_successes() {
        let (_d, db) = fixture().await;
        let repo = FailureContextRepo::new(&db);
        put(&db, "a1", "h1", "fp1", b"x").await;
        put(&db, "a2", "h1", "fp2", b"x").await;
        let mut ok = new("a3", "h1", "fp3", b"x");
        ok.status = 0;
        ok.status_word = "OK";
        repo.upsert(ok).await.unwrap();
        for id in ["a1", "a2", "a3"] {
            repo.mark_skipped(id, "enrichment is not enabled")
                .await
                .unwrap();
        }
        assert!(repo.take_pending(10).await.unwrap().is_empty());

        assert_eq!(repo.requeue_skipped(1).await.unwrap(), 2);
        let pending = repo.take_pending(10).await.unwrap();
        assert_eq!(pending.len(), 2);
        assert!(
            pending.iter().all(|r| r.status != 0),
            "enabling enrichment is not a reason to describe a success"
        );
    }

    #[tokio::test]
    async fn a_tenant_cannot_read_or_delete_another_tenants_report() {
        let (_d, db) = fixture().await;
        let repo = FailureContextRepo::new(&db);
        put(&db, "a1", "h1", "fp1", b"x").await;
        assert!(repo.get(2, "a1").await.unwrap().is_none());
        assert!(!repo.delete(2, "a1").await.unwrap());
        assert!(!repo.requeue(2, "a1").await.unwrap());
        assert!(repo.get(1, "a1").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn listing_filters_by_host_and_status() {
        let (_d, db) = fixture().await;
        let repo = FailureContextRepo::new(&db);
        put(&db, "a1", "h1", "fp1", b"x").await;
        let mut warn = new("a2", "h2", "fp2", b"x");
        warn.status = 1;
        warn.status_word = "WARNING";
        repo.upsert(warn).await.unwrap();

        assert_eq!(repo.list(1, Some("h1"), None, 100).await.unwrap().len(), 1);
        assert_eq!(repo.list(1, None, Some(1), 100).await.unwrap().len(), 1);
        assert_eq!(
            repo.list(1, Some("h1"), Some(1), 100).await.unwrap().len(),
            0
        );
        assert_eq!(repo.count_for_host(1, "h1").await.unwrap(), 1);
        assert_eq!(repo.count_for_tenant(1).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn retention_keeps_problems_that_are_still_being_reported() {
        let (_d, db) = fixture().await;
        let repo = FailureContextRepo::new(&db);
        put(&db, "old", "h1", "fp1", b"x").await;
        put(&db, "live", "h1", "fp2", b"x").await;
        sqlx::query(
            "UPDATE failure_contexts SET first_seen_at = 0, last_seen_at = 0 WHERE id = 'old'",
        )
        .execute(&db.write)
        .await
        .unwrap();
        sqlx::query("UPDATE failure_contexts SET first_seen_at = 0 WHERE id = 'live'")
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
        let repo = FailureContextRepo::new(&db);
        for i in 0..10 {
            put(&db, &format!("a{i}"), "h1", &format!("fp{i}"), b"x").await;
            sqlx::query("UPDATE failure_contexts SET last_seen_at = ? WHERE id = ?")
                .bind(1000 + i)
                .bind(format!("a{i}"))
                .execute(&db.write)
                .await
                .unwrap();
        }
        put(&db, "other", "h2", "fp1", b"x").await;

        assert_eq!(repo.trim_host(1, "h1", 3).await.unwrap(), 7);
        let kept = repo.list(1, Some("h1"), None, 100).await.unwrap();
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
    async fn deleting_a_host_takes_its_reports_with_it() {
        let (_d, db) = fixture().await;
        let repo = FailureContextRepo::new(&db);
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

    fn settings<'a>(
        provider: &'a str,
        model: &'a str,
        key: Option<&'a [u8]>,
    ) -> NewFailureSettings<'a> {
        NewFailureSettings {
            reports_enabled: true,
            min_interval_secs: 0,
            enrichment_enabled: true,
            provider,
            model,
            base_url: None,
            api_key_encrypted: key,
            daily_call_budget: 200,
            updated_by_user: None,
        }
    }

    #[tokio::test]
    async fn saving_settings_without_a_key_keeps_the_stored_one() {
        let (_d, db) = fixture().await;
        let repo = TenantFailureSettingsRepo::new(&db);
        repo.set(1, settings("anthropic", "claude-opus-5", Some(b"secret")))
            .await
            .unwrap();
        // The console never sees the key, so a save that only changes the model sends none.
        let mut changed = settings("anthropic", "claude-sonnet-5", None);
        changed.daily_call_budget = 500;
        repo.set(1, changed).await.unwrap();

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
    async fn no_settings_row_means_reports_taken_and_nothing_sent_onward() {
        let (_d, db) = fixture().await;
        assert!(
            TenantFailureSettingsRepo::new(&db)
                .get(1)
                .await
                .unwrap()
                .is_none(),
            "the default is a missing row, which the server reads as reports on, enrichment off"
        );
    }

    #[tokio::test]
    async fn usage_accumulates_per_day_and_counts_failures() {
        let (_d, db) = fixture().await;
        let repo = TenantFailureSettingsRepo::new(&db);
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
