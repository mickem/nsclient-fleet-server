use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub tenant_id: i64,
    pub email: String,
    pub role: String,
    pub created_at: i64,
}
