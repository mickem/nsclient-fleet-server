use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id_hash: String,
    pub tenant_id: i64,
    pub user_id: i64,
    pub expires_at: i64,
    pub last_used_at: i64,
    pub created_at: i64,
}
