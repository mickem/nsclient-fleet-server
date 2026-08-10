//! Wire constants and types shared between the control plane and the agent.

/// ALPN protocol name the agent offers when opening its mTLS connection.
///
/// This is a wire contract, not an implementation detail: the server routes on it to serve
/// agent mTLS and the operator UI from the same TCP port, so an agent that fails to offer
/// it gets the browser branch — a certificate it does not trust and no client-certificate
/// request. Any reimplementation of the agent must send this.
pub const AGENT_ALPN: &[u8] = b"nsclient-fleet/1";
