use serde::{Deserialize, Serialize};
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub tenant_id: i64,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub enrolled_at: Option<i64>,
    pub last_seen_at: Option<i64>,
    pub current_state_hash: Option<String>,
    pub created_at: i64,
}

pub fn new_host_id() -> String {
    Ulid::new().to_string()
}
