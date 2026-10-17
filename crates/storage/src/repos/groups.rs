use anyhow::Result;
use fleet_core::time::now_unix;
use sqlx::Row;

use crate::Db;

#[derive(Debug, Clone)]
pub struct GroupRow {
    pub id: String,
    pub tenant_id: i64,
    pub name: String,
    pub selector_json: String,
    pub created_at: i64,
}

pub struct GroupsRepo<'a> {
    db: &'a Db,
}

impl<'a> GroupsRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub async fn create(
        &self,
        tenant_id: i64,
        name: &str,
        selector_json: &str,
    ) -> Result<GroupRow> {
        use ulid::Ulid;
        let id = Ulid::generate().to_string();
        let now = now_unix();
        sqlx::query(
            "INSERT INTO groups (id, tenant_id, name, selector_json, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(name)
        .bind(selector_json)
        .bind(now)
        .execute(&self.db.write)
        .await?;
        Ok(GroupRow {
            id,
            tenant_id,
            name: name.to_owned(),
            selector_json: selector_json.to_owned(),
            created_at: now,
        })
    }

    pub async fn update(
        &self,
        tenant_id: i64,
        id: &str,
        name: Option<&str>,
        selector_json: Option<&str>,
    ) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE groups SET
               name = COALESCE(?, name),
               selector_json = COALESCE(?, selector_json)
             WHERE tenant_id = ? AND id = ?",
        )
        .bind(name)
        .bind(selector_json)
        .bind(tenant_id)
        .bind(id)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn delete(&self, tenant_id: i64, id: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM groups WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(id)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn get(&self, tenant_id: i64, id: &str) -> Result<Option<GroupRow>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, name, selector_json, created_at
             FROM groups WHERE tenant_id = ? AND id = ?",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.map(map_group))
    }

    pub async fn list(&self, tenant_id: i64) -> Result<Vec<GroupRow>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, name, selector_json, created_at
             FROM groups WHERE tenant_id = ? ORDER BY name",
        )
        .bind(tenant_id)
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows.into_iter().map(map_group).collect())
    }
}

fn map_group(r: sqlx::sqlite::SqliteRow) -> GroupRow {
    GroupRow {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        name: r.get("name"),
        selector_json: r.get("selector_json"),
        created_at: r.get("created_at"),
    }
}
