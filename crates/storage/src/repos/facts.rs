use anyhow::Result;
use fleet_core::time::now_unix;
use sqlx::{AssertSqlSafe, Row};

use crate::Db;

/// A host's stored facts document from one source, verbatim.
pub struct StoredFacts {
    pub source: String,
    pub facts_hash: String,
    pub facts_json: String,
    pub collected_at: Option<String>,
    pub received_at: i64,
    pub size_bytes: i64,
}

/// The two hashes that decide a facts exchange: what we hold, and what the agent last said
/// it holds.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FactsHashes {
    pub held: Option<String>,
    pub reported: Option<String>,
    /// When `reported` last changed (unix seconds): how long the agent has been saying it.
    pub reported_since: Option<i64>,
    /// The last upload the server refused, if any.
    pub refused: Option<FactsRefusal>,
}

/// An upload the server refused. The agent does not retry a refused document, so this is
/// what stands between "on its way" and "never coming" until its inventory changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactsRefusal {
    /// What the agent reported holding when it was refused: the refusal applies while it
    /// still does. `None` when it had reported nothing.
    pub hash: Option<String>,
    pub at: i64,
    /// The HTTP status of the refusal: 400 or 413.
    pub status: u16,
}

pub struct FactChangeRow {
    pub id: i64,
    pub source: String,
    pub at: i64,
    pub facts_hash: String,
    pub changes_json: String,
}

/// A document to store with [`HostFactsRepo::replace`]. Named fields rather than positional
/// arguments: several are optional strings, and swapping two of them must not compile.
#[derive(Debug, Clone, Copy)]
pub struct NewFacts<'a> {
    pub source: &'a str,
    /// SHA-256 hex of exactly `facts_json`.
    pub facts_hash: &'a str,
    pub facts_json: &'a str,
    /// When the producer read the values, as it reported it.
    pub collected_at: Option<&'a str>,
    /// Hash of the document the caller read and diffed against; `None`: it saw none.
    pub expected_previous: Option<&'a str>,
    /// The history entry to record with it, if any.
    pub history: Option<&'a str>,
}

/// What [`HostFactsRepo::replace`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceOutcome {
    /// The document was stored, and the history entry with it.
    Stored,
    /// The source already holds a document with this hash: nothing written.
    Unchanged,
    /// Another write replaced the document since the caller read it: nothing written.
    Conflict,
    /// There is no such host in this tenant: nothing written.
    NoHost,
}

pub struct HostFactsRepo<'a> {
    db: &'a Db,
}

impl<'a> HostFactsRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    /// Both hashes of the agent's own document, in one read. `None` when there is no such
    /// host. Only the `agent` source takes part in the hash exchange; imported sources are
    /// never the agent's to upload.
    ///
    /// On the desired-state path, so it is one indexed lookup and never a write: every poll
    /// from every host asks it.
    pub async fn hashes(&self, tenant_id: i64, host_id: &str) -> Result<Option<FactsHashes>> {
        let row = sqlx::query(
            "SELECT h.facts_reported_hash AS reported, h.facts_reported_at AS reported_since,
                    h.facts_refused_hash AS refused_hash, h.facts_refused_at AS refused_at,
                    h.facts_refused_status AS refused_status,
                    f.facts_hash AS held
               FROM hosts h
               LEFT JOIN host_facts f
                      ON f.tenant_id = h.tenant_id AND f.host_id = h.id AND f.source = ?
              WHERE h.tenant_id = ? AND h.id = ?",
        )
        .bind(fleet_core::facts::AGENT_SOURCE)
        .bind(tenant_id)
        .bind(host_id)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.map(|r| {
            let refused_at: Option<i64> = r.get("refused_at");
            let refused_status: Option<i64> = r.get("refused_status");
            FactsHashes {
                held: r.get("held"),
                reported: r.get("reported"),
                reported_since: r.get("reported_since"),
                refused: refused_at
                    .zip(refused_status)
                    .map(|(at, status)| FactsRefusal {
                        hash: r.get("refused_hash"),
                        at,
                        status: u16::try_from(status).unwrap_or(0),
                    }),
            }
        }))
    }

    /// Record that an upload from this host was refused with `status`, against `hash` — the
    /// refused document's own, when the body said it — or else the hash the agent last
    /// reported, which is the document it was sending. Refusals are rare (the agent does not
    /// retry one), so this writes unconditionally.
    pub async fn record_refusal(
        &self,
        tenant_id: i64,
        host_id: &str,
        status: u16,
        hash: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE hosts SET facts_refused_hash = COALESCE(?, facts_reported_hash),
                              facts_refused_at = ?, facts_refused_status = ?
              WHERE tenant_id = ? AND id = ?",
        )
        .bind(hash)
        .bind(now_unix())
        .bind(i64::from(status))
        .bind(tenant_id)
        .bind(host_id)
        .execute(&self.db.write)
        .await?;
        Ok(())
    }

    /// Record the hash the agent says it holds, and since when. Returns true iff that
    /// changed the stored value. The comparison lives in the statement, so an unchanged
    /// hash — nearly every report — writes nothing, and the time stays when it first moved.
    pub async fn set_reported_hash(
        &self,
        tenant_id: i64,
        host_id: &str,
        hash: &str,
    ) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE hosts SET facts_reported_hash = ?, facts_reported_at = ?
              WHERE tenant_id = ? AND id = ?
                AND (facts_reported_hash IS NULL OR facts_reported_hash != ?)",
        )
        .bind(hash)
        .bind(now_unix())
        .bind(tenant_id)
        .bind(host_id)
        .bind(hash)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn get(
        &self,
        tenant_id: i64,
        host_id: &str,
        source: &str,
    ) -> Result<Option<StoredFacts>> {
        let row = sqlx::query(
            "SELECT source, facts_hash, facts_json, collected_at, received_at, size_bytes
               FROM host_facts WHERE tenant_id = ? AND host_id = ? AND source = ?",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(source)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.map(|r| StoredFacts {
            source: r.get("source"),
            facts_hash: r.get("facts_hash"),
            facts_json: r.get("facts_json"),
            collected_at: r.get("collected_at"),
            received_at: r.get("received_at"),
            size_bytes: r.get("size_bytes"),
        }))
    }

    /// Store a new document for a host from one source. Other sources' documents are
    /// untouched.
    ///
    /// A compare-and-set against `expected_previous`, the hash of the document the caller
    /// read and diffed against (`None`: it saw none). Diffing a megabyte document is not
    /// work to do while holding the single write connection, so the caller does it first,
    /// outside any transaction, and this only checks that nothing replaced the document in
    /// between. On [`ReplaceOutcome::Conflict`] the caller re-reads and tries again; two
    /// racing uploads therefore cannot both diff against the same predecessor and leave a
    /// history that skips a step.
    ///
    /// `history` is the entry to record, if any. At most `keep_history` entries are kept
    /// per host and source. The source name is checked here, at the one place any source
    /// writes, so no path can store one [`fleet_core::facts::valid_source`] refuses.
    pub async fn replace(
        &self,
        tenant_id: i64,
        host_id: &str,
        doc: &NewFacts<'_>,
        keep_history: i64,
    ) -> Result<ReplaceOutcome> {
        let NewFacts {
            source,
            facts_hash,
            facts_json,
            collected_at,
            expected_previous,
            history,
        } = *doc;
        anyhow::ensure!(
            fleet_core::facts::valid_source(source),
            "invalid facts source name {source:?}"
        );
        let now = now_unix();
        let mut tx = self.db.write.begin().await?;

        let host_exists = sqlx::query("SELECT 1 AS x FROM hosts WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(host_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
        if !host_exists {
            tx.rollback().await?;
            return Ok(ReplaceOutcome::NoHost);
        }

        let current: Option<String> = sqlx::query_scalar(
            "SELECT facts_hash FROM host_facts
              WHERE tenant_id = ? AND host_id = ? AND source = ?",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(source)
        .fetch_optional(&mut *tx)
        .await?;
        if current.as_deref() == Some(facts_hash) {
            tx.rollback().await?;
            return Ok(ReplaceOutcome::Unchanged);
        }
        if current.as_deref() != expected_previous {
            tx.rollback().await?;
            return Ok(ReplaceOutcome::Conflict);
        }

        // No tenant guard on the update: the host was just found in this tenant inside the
        // same transaction, and host ids are unique across tenants, so an existing row for
        // this host is this tenant's. A guard could only ever make the write silently skip.
        let written = sqlx::query(
            "INSERT INTO host_facts
               (tenant_id, host_id, source, facts_hash, facts_json, collected_at, received_at,
                size_bytes)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(host_id, source) DO UPDATE SET
               facts_hash = excluded.facts_hash,
               facts_json = excluded.facts_json,
               collected_at = excluded.collected_at,
               received_at = excluded.received_at,
               size_bytes = excluded.size_bytes",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(source)
        .bind(facts_hash)
        .bind(facts_json)
        .bind(collected_at)
        .bind(now)
        .bind(facts_json.len() as i64)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        // Never report Stored, or write a history row, for a document that did not land.
        if written != 1 {
            tx.rollback().await?;
            anyhow::bail!("facts write for host {host_id} affected {written} rows");
        }

        if let Some(entry) = history {
            sqlx::query(
                "INSERT INTO host_fact_changes
                   (tenant_id, host_id, source, at, facts_hash, changes_json)
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(tenant_id)
            .bind(host_id)
            .bind(source)
            .bind(now)
            .bind(facts_hash)
            .bind(entry)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "DELETE FROM host_fact_changes
                  WHERE tenant_id = ? AND host_id = ? AND source = ?
                    AND id NOT IN (SELECT id FROM host_fact_changes
                                    WHERE tenant_id = ? AND host_id = ? AND source = ?
                                    ORDER BY id DESC LIMIT ?)",
            )
            .bind(tenant_id)
            .bind(host_id)
            .bind(source)
            .bind(tenant_id)
            .bind(host_id)
            .bind(source)
            .bind(keep_history)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(ReplaceOutcome::Stored)
    }

    /// The agent stopped reporting a hash — a build without facts, or facts switched off in
    /// it — so it no longer vouches for the document we hold. Forget what it last said.
    /// Conditional, so the common case (nothing to forget) dirties nothing.
    pub async fn clear_reported_hash(&self, tenant_id: i64, host_id: &str) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE hosts SET facts_reported_hash = NULL, facts_reported_at = ?
              WHERE tenant_id = ? AND id = ? AND facts_reported_hash IS NOT NULL",
        )
        .bind(now_unix())
        .bind(tenant_id)
        .bind(host_id)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// The agent sent again the document we already hold: keep the document, record when it
    /// was collected and received. Writes only when the collection time actually moved.
    pub async fn refresh_collected_at(
        &self,
        tenant_id: i64,
        host_id: &str,
        source: &str,
        facts_hash: &str,
        collected_at: &str,
    ) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE host_facts SET collected_at = ?, received_at = ?
              WHERE tenant_id = ? AND host_id = ? AND source = ? AND facts_hash = ?
                AND (collected_at IS NULL OR collected_at != ?)",
        )
        .bind(collected_at)
        .bind(now_unix())
        .bind(tenant_id)
        .bind(host_id)
        .bind(source)
        .bind(facts_hash)
        .bind(collected_at)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// The most recent history entries of one source for a host, newest first.
    pub async fn list_changes(
        &self,
        tenant_id: i64,
        host_id: &str,
        source: &str,
        limit: i64,
    ) -> Result<Vec<FactChangeRow>> {
        let rows = sqlx::query(
            "SELECT id, source, at, facts_hash, changes_json FROM host_fact_changes
              WHERE tenant_id = ? AND host_id = ? AND source = ?
              ORDER BY id DESC LIMIT ?",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(source)
        .bind(limit)
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| FactChangeRow {
                id: r.get("id"),
                source: r.get("source"),
                at: r.get("at"),
                facts_hash: r.get("facts_hash"),
                changes_json: r.get("changes_json"),
            })
            .collect())
    }

    /// Hand every document a tenant holds from any of `sources` to `f`, as
    /// `(host_id, source, json)`, grouped by host (host id order). Streamed like
    /// [`Self::for_each_document`]: one query for the whole fleet, one row in memory at a
    /// time.
    ///
    /// `f` is awaited per row, so it can hand the row on to a blocking thread (parsing a
    /// document of megabytes is no work for an async worker) and wait when that falls behind.
    pub async fn for_each_host_document<F, Fut>(
        &self,
        tenant_id: i64,
        sources: &[String],
        mut f: F,
    ) -> Result<()>
    where
        F: FnMut(String, String, String) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        use futures_util::TryStreamExt;
        if sources.is_empty() {
            return Ok(());
        }
        let placeholders = vec!["?"; sources.len()].join(", ");
        let sql = format!(
            "SELECT host_id, source, facts_json FROM host_facts
              WHERE tenant_id = ? AND source IN ({placeholders})
              ORDER BY host_id, source"
        );
        let mut query = sqlx::query(AssertSqlSafe(sql)).bind(tenant_id);
        for s in sources {
            query = query.bind(s);
        }
        let mut rows = query.fetch(&self.db.read);
        while let Some(row) = rows.try_next().await? {
            f(row.get("host_id"), row.get("source"), row.get("facts_json")).await;
        }
        Ok(())
    }

    /// Hand each of a tenant's documents from one source to `f`, as `(host_id, json)`, at
    /// most `limit` of them, in host id order. Returns how many were read.
    ///
    /// Streamed: each row is dropped once `f` returns, so reading the whole fleet holds one
    /// document at a time rather than all of them — a tenant's inventories together can
    /// run to gigabytes. `f` is awaited per row, as in [`Self::for_each_host_document`].
    pub async fn for_each_document<F, Fut>(
        &self,
        tenant_id: i64,
        source: &str,
        limit: i64,
        mut f: F,
    ) -> Result<usize>
    where
        F: FnMut(String, String) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        use futures_util::TryStreamExt;
        let mut rows = sqlx::query(
            "SELECT host_id, facts_json FROM host_facts WHERE tenant_id = ? AND source = ?
              ORDER BY host_id LIMIT ?",
        )
        .bind(tenant_id)
        .bind(source)
        .bind(limit)
        .fetch(&self.db.read);
        let mut n = 0;
        while let Some(row) = rows.try_next().await? {
            f(row.get("host_id"), row.get("facts_json")).await;
            n += 1;
        }
        Ok(n)
    }

    /// Every document a host holds from a source other than `except`, sorted by source.
    pub async fn list_for_host_except(
        &self,
        tenant_id: i64,
        host_id: &str,
        except: &str,
    ) -> Result<Vec<StoredFacts>> {
        let rows = sqlx::query(
            "SELECT source, facts_hash, facts_json, collected_at, received_at, size_bytes
               FROM host_facts WHERE tenant_id = ? AND host_id = ? AND source != ?
              ORDER BY source",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(except)
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| StoredFacts {
                source: r.get("source"),
                facts_hash: r.get("facts_hash"),
                facts_json: r.get("facts_json"),
                collected_at: r.get("collected_at"),
                received_at: r.get("received_at"),
                size_bytes: r.get("size_bytes"),
            })
            .collect())
    }

    /// The hosts in a tenant holding a document from `source`, in host id order.
    pub async fn hosts_with_source(&self, tenant_id: i64, source: &str) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            "SELECT host_id FROM host_facts WHERE tenant_id = ? AND source = ? ORDER BY host_id",
        )
        .bind(tenant_id)
        .bind(source)
        .fetch_all(&self.db.read)
        .await?)
    }

    /// Delete one host's document from `source`, and its history. Returns true iff there
    /// was a document.
    pub async fn delete(&self, tenant_id: i64, host_id: &str, source: &str) -> Result<bool> {
        let mut tx = self.db.write.begin().await?;
        let res = sqlx::query(
            "DELETE FROM host_facts WHERE tenant_id = ? AND host_id = ? AND source = ?",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(source)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM host_fact_changes WHERE tenant_id = ? AND host_id = ? AND source = ?",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(source)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(res.rows_affected() > 0)
    }

    /// Delete every document of `source` in a tenant, and their history. Returns the hosts
    /// whose document was deleted.
    pub async fn delete_source(&self, tenant_id: i64, source: &str) -> Result<Vec<String>> {
        let mut tx = self.db.write.begin().await?;
        let hosts: Vec<String> = sqlx::query_scalar(
            "DELETE FROM host_facts WHERE tenant_id = ? AND source = ? RETURNING host_id",
        )
        .bind(tenant_id)
        .bind(source)
        .fetch_all(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM host_fact_changes WHERE tenant_id = ? AND source = ?")
            .bind(tenant_id)
            .bind(source)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(hosts)
    }

    /// The sources any host in the tenant holds a document from, sorted.
    pub async fn list_sources(&self, tenant_id: i64) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            "SELECT DISTINCT source FROM host_facts WHERE tenant_id = ? ORDER BY source",
        )
        .bind(tenant_id)
        .fetch_all(&self.db.read)
        .await?)
    }
}
