//! What enrolled agents talk to: the mTLS agent API, its per-host limits, and the
//! desired-state computation behind every poll.

pub mod api;
pub mod desired_state;
pub mod limits;
