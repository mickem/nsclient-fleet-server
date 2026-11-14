//! Failure contexts: the latest report an agent sent for each failed check, and the
//! per-tenant settings that govern whether reports are taken and how errors are explained.

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

/// One stored report: the newest one an agent sent for a check. The payload stays encrypted
/// here: decryption needs the master key, which storage does not have and should not grow.
#[derive(Debug, Clone)]
pub struct FailureContextRow {
    pub id: String,
    pub tenant_id: i64,
    pub host_id: String,
    pub command: String,
    pub alias: String,
    pub status: i64,
    pub status_word: String,
    pub message: String,
    pub subject: String,
    pub context_state: String,
    pub metrics_count: i64,
    pub payload_encrypted: Vec<u8>,
    pub payload_bytes: i64,
    pub reported_at: i64,
}

/// What to store for one report.
#[derive(Debug, Clone)]
pub struct NewFailureContext<'a> {
    pub id: &'a str,
    pub tenant_id: i64,
    pub host_id: &'a str,
    pub command: &'a str,
    pub alias: &'a str,
    pub status: i64,
    pub status_word: &'a str,
    pub message: &'a str,
    pub subject: &'a str,
    pub context_state: &'a str,
    pub metrics_count: i64,
    pub payload_encrypted: &'a [u8],
    pub payload_bytes: i64,
}

/// Columns every read of this table selects. One constant so a column added later cannot be
/// picked up by three of five queries.
const COLUMNS: &str = "id, tenant_id, host_id, command, alias, status, status_word, message,
     subject, context_state, metrics_count, payload_encrypted, payload_bytes, reported_at";

fn row_from(r: &sqlx::sqlite::SqliteRow) -> FailureContextRow {
    FailureContextRow {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        host_id: r.get("host_id"),
        command: r.get("command"),
        alias: r.get("alias"),
        status: r.get("status"),
        status_word: r.get("status_word"),
        message: r.get("message"),
        subject: r.get("subject"),
        context_state: r.get("context_state"),
        metrics_count: r.get("metrics_count"),
        payload_encrypted: r.get("payload_encrypted"),
        payload_bytes: r.get("payload_bytes"),
        reported_at: r.get("reported_at"),
    }
}

pub struct FailureContextRepo<'a> {
    db: &'a Db,
}

impl<'a> FailureContextRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    /// Record one report, replacing the previous report for the same check on this host.
    ///
    /// Everything is replaced, status included: the row is evidence of what the host looked
    /// like most recently, not a history of the check. Returns the row's id, which for a
    /// replacement is the id the first report created.
    pub async fn upsert(&self, new: NewFailureContext<'_>) -> Result<String> {
        let row = sqlx::query(
            "INSERT INTO failure_contexts
               (id, tenant_id, host_id, command, alias, status, status_word, message, subject,
                context_state, metrics_count, payload_encrypted, payload_bytes, reported_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(tenant_id, host_id, command, alias) DO UPDATE SET
               status = excluded.status,
               status_word = excluded.status_word,
               message = excluded.message,
               subject = excluded.subject,
               context_state = excluded.context_state,
               metrics_count = excluded.metrics_count,
               payload_encrypted = excluded.payload_encrypted,
               payload_bytes = excluded.payload_bytes,
               reported_at = excluded.reported_at
             RETURNING id",
        )
        .bind(new.id)
        .bind(new.tenant_id)
        .bind(new.host_id)
        .bind(new.command)
        .bind(new.alias)
        .bind(new.status)
        .bind(new.status_word)
        .bind(new.message)
        .bind(new.subject)
        .bind(new.context_state)
        .bind(new.metrics_count)
        .bind(new.payload_encrypted)
        .bind(new.payload_bytes)
        .bind(now_unix())
        .fetch_one(&self.db.write)
        .await?;
        Ok(row.get("id"))
    }

    /// One report, scoped to its host as well as its tenant: the API addresses reports under
    /// `/api/hosts/{host}/contexts/{id}`, and a report of another host must not answer there.
    pub async fn get(
        &self,
        tenant_id: i64,
        host_id: &str,
        id: &str,
    ) -> Result<Option<FailureContextRow>> {
        // AssertSqlSafe: the only interpolation is the COLUMNS constant above. Every
        // caller value is bound.
        let row = sqlx::query(AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM failure_contexts
             WHERE tenant_id = ? AND host_id = ? AND id = ?"
        )))
        .bind(tenant_id)
        .bind(host_id)
        .bind(id)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.as_ref().map(row_from))
    }

    /// A host's reports, newest first.
    pub async fn list_for_host(
        &self,
        tenant_id: i64,
        host_id: &str,
        limit: i64,
    ) -> Result<Vec<FailureContextRow>> {
        // AssertSqlSafe: as above, only COLUMNS is interpolated.
        let rows = sqlx::query(AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM failure_contexts
             WHERE tenant_id = ? AND host_id = ?
             ORDER BY reported_at DESC, id LIMIT ?"
        )))
        .bind(tenant_id)
        .bind(host_id)
        .bind(limit)
        .fetch_all(&self.db.read)
        .await?;
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

    pub async fn delete(&self, tenant_id: i64, host_id: &str, id: &str) -> Result<bool> {
        let res = sqlx::query(
            "DELETE FROM failure_contexts WHERE tenant_id = ? AND host_id = ? AND id = ?",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(id)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Retention sweep: drop reports older than `max_age_secs`. A check that keeps failing
    /// keeps being reported, and each report moves `reported_at`, so only evidence nobody
    /// has refreshed goes.
    pub async fn delete_older_than(&self, max_age_secs: i64) -> Result<u64> {
        let cutoff = now_unix() - max_age_secs;
        let res = sqlx::query("DELETE FROM failure_contexts WHERE reported_at < ?")
            .bind(cutoff)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected())
    }

    /// Keep only the `keep` most recent rows for a host, dropping the oldest beyond that.
    ///
    /// The bound that holds when retention does not: a check whose alias carries something
    /// variable — a timestamp, a PID, a generated name — is a new key on every report, and
    /// every one of those rows is too new to sweep.
    pub async fn trim_host(&self, tenant_id: i64, host_id: &str, keep: i64) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM failure_contexts
             WHERE tenant_id = ? AND host_id = ? AND id NOT IN (
               SELECT id FROM failure_contexts
               WHERE tenant_id = ? AND host_id = ?
               ORDER BY reported_at DESC, id LIMIT ?
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
    pub explain_enabled: bool,
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
    pub explain_enabled: bool,
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
            "SELECT tenant_id, reports_enabled, min_interval_secs, explain_enabled, provider,
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
            explain_enabled: r.get::<i64, _>("explain_enabled") != 0,
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
               (tenant_id, reports_enabled, min_interval_secs, explain_enabled, provider,
                model, base_url, api_key_encrypted, daily_call_budget, updated_at,
                updated_by_user)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(tenant_id) DO UPDATE SET
               reports_enabled = excluded.reports_enabled,
               min_interval_secs = excluded.min_interval_secs,
               explain_enabled = excluded.explain_enabled,
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
        .bind(i64::from(new.explain_enabled))
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
        alias: &'a str,
        payload: &'a [u8],
    ) -> NewFailureContext<'a> {
        NewFailureContext {
            id,
            tenant_id: 1,
            host_id: host,
            command: "check_drivesize",
            alias,
            status: 2,
            status_word: "CRITICAL",
            message: "C:\\ is full",
            subject: "Scheduler",
            context_state: "captured",
            metrics_count: 521,
            payload_encrypted: payload,
            payload_bytes: payload.len() as i64,
        }
    }

    async fn put(db: &Db, id: &str, host: &str, alias: &str, payload: &[u8]) -> String {
        FailureContextRepo::new(db)
            .upsert(new(id, host, alias, payload))
            .await
            .unwrap()
    }

    /// Pin a row's `reported_at`, so ordering does not depend on two reports landing in
    /// different seconds.
    async fn at(db: &Db, id: &str, ts: i64) {
        sqlx::query("UPDATE failure_contexts SET reported_at = ? WHERE id = ?")
            .bind(ts)
            .bind(id)
            .execute(&db.write)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_latest_report_for_a_check_replaces_the_previous_one() {
        let (_d, db) = fixture().await;
        let repo = FailureContextRepo::new(&db);

        assert_eq!(put(&db, "a1", "h1", "disk_c", b"first").await, "a1");
        let mut warn = new("a2", "h1", "disk_c", b"second");
        warn.status = 1;
        warn.status_word = "WARNING";
        warn.context_state = "disabled";
        warn.metrics_count = 0;
        assert_eq!(
            repo.upsert(warn).await.unwrap(),
            "a1",
            "the row keeps the identity it was created with"
        );

        let rows = repo.list_for_host(1, "h1", 100).await.unwrap();
        assert_eq!(rows.len(), 1, "an hourly report must not be a row per hour");
        let r = &rows[0];
        assert_eq!(
            r.payload_encrypted, b"second",
            "the evidence is the newest report"
        );
        assert_eq!(
            r.status, 1,
            "a status change is the same check, not a new row"
        );
        assert_eq!(r.context_state, "disabled");
        assert_eq!(r.metrics_count, 0);
    }

    #[tokio::test]
    async fn two_aliases_and_two_hosts_are_separate_rows() {
        let (_d, db) = fixture().await;
        let repo = FailureContextRepo::new(&db);
        put(&db, "a1", "h1", "disk_c", b"x").await;
        put(&db, "a2", "h1", "disk_d", b"x").await;
        put(&db, "a3", "h2", "disk_c", b"x").await;
        assert_eq!(repo.count_for_host(1, "h1").await.unwrap(), 2);
        assert_eq!(repo.count_for_host(1, "h2").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn a_report_is_only_reachable_under_its_own_tenant_and_host() {
        let (_d, db) = fixture().await;
        let repo = FailureContextRepo::new(&db);
        put(&db, "a1", "h1", "disk_c", b"x").await;
        assert!(repo.get(2, "h1", "a1").await.unwrap().is_none());
        assert!(repo.get(1, "h2", "a1").await.unwrap().is_none());
        assert!(!repo.delete(2, "h1", "a1").await.unwrap());
        assert!(!repo.delete(1, "h2", "a1").await.unwrap());
        assert!(repo.get(1, "h1", "a1").await.unwrap().is_some());
        assert!(repo.delete(1, "h1", "a1").await.unwrap());
    }

    #[tokio::test]
    async fn retention_drops_reports_nobody_has_refreshed() {
        let (_d, db) = fixture().await;
        let repo = FailureContextRepo::new(&db);
        put(&db, "old", "h1", "disk_c", b"x").await;
        at(&db, "old", 0).await;
        put(&db, "live", "h1", "disk_d", b"x").await;

        assert_eq!(repo.delete_older_than(3600).await.unwrap(), 1);
        let rows = repo.list_for_host(1, "h1", 100).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "live");
    }

    #[tokio::test]
    async fn a_host_inventing_aliases_is_capped() {
        let (_d, db) = fixture().await;
        let repo = FailureContextRepo::new(&db);
        for i in 0..10 {
            put(&db, &format!("a{i}"), "h1", &format!("alias{i}"), b"x").await;
            at(&db, &format!("a{i}"), 1000 + i).await;
        }
        put(&db, "other", "h2", "alias0", b"x").await;

        assert_eq!(repo.trim_host(1, "h1", 3).await.unwrap(), 7);
        let kept = repo.list_for_host(1, "h1", 100).await.unwrap();
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
        put(&db, "a1", "h1", "disk_c", b"x").await;
        sqlx::query("DELETE FROM hosts WHERE id = 'h1'")
            .execute(&db.write)
            .await
            .unwrap();
        assert_eq!(
            repo.count_for_host(1, "h1").await.unwrap(),
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
            explain_enabled: true,
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
        repo.set(1, settings("anthropic", "claude-opus-5-5", Some(b"secret")))
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
            "the default is a missing row, which the server reads as reports on, explanations off"
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
