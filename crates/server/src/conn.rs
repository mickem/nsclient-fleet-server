//! Connection-level limits shared by every TLS listener.
//!
//! Accepting a socket costs us a task, a TLS buffer and a file descriptor, and none of
//! that is released until the peer decides to go away. Without a deadline anywhere on the
//! path, one client that opens connections and then says nothing — no ClientHello, or a
//! finished handshake and no request line — pins those resources until the process runs
//! out of descriptors. On the shared port that is the operator UI, every agent and ACME
//! renewal going down together, from an unauthenticated peer.
//!
//! Three limits, applied by both [`crate::mux`] and [`crate::mtls`]:
//!
//! - a deadline covering TCP accept through finished TLS handshake ([`HANDSHAKE_TIMEOUT`]),
//! - a header-read timeout on the HTTP connection ([`HEADER_READ_TIMEOUT`]) — hyper has a
//!   default here but silently ignores it unless the builder is given a timer, which is
//!   why [`http_builder`] exists and why nothing should construct the builder directly,
//! - a ceiling on connections in flight ([`ConnLimit`]).
//!
//! The plain-HTTP listener in `main.rs` gets none of these: it is the no-TLS development
//! path, it refuses to be the production one, and `axum::serve` exposes no builder to
//! configure.

use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto::Builder as HttpBuilder;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Longest a peer may take between having its TCP connection accepted and completing the
/// TLS handshake. Generous for a slow link on a fresh handshake, far short of forever.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest a peer may take to send a complete request head once TLS is up.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Connections served at once, per listener. Chosen to sit well under the 65536 file
/// descriptors the unit asks for while being more than a fleet of any size we target
/// needs: agents poll on an interval and hold nothing between polls.
pub const MAX_CONNECTIONS: usize = 2048;

/// An HTTP connection builder with the timer hyper needs for its own timeouts to apply.
///
/// `header_read_timeout` is documented as defaulting to 30 seconds, but it is enforced by
/// a `Timer` the builder does not have unless one is installed — so the default is not a
/// default at all, it is a no-op. Setting the timer turns it on; setting the value too
/// says what we actually want rather than depending on hyper's.
pub fn http_builder() -> HttpBuilder<TokioExecutor> {
    let mut b = HttpBuilder::new(TokioExecutor::new());
    b.http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    b.http2().timer(TokioTimer::new());
    b
}

/// A ceiling on how many connections a listener serves concurrently.
///
/// The permit is taken *before* `accept`, so at capacity we stop accepting rather than
/// accepting and dropping. Backpressure then lands in the kernel's listen backlog, where
/// a client sees a delay or a refused connection — which is what an overloaded server is
/// supposed to look like — instead of a connection that opens and dies for no stated
/// reason.
#[derive(Clone)]
pub struct ConnLimit {
    sem: Arc<Semaphore>,
    listener: &'static str,
    capacity: usize,
}

impl ConnLimit {
    pub fn new(listener: &'static str) -> Self {
        Self::with_capacity(listener, MAX_CONNECTIONS)
    }

    pub fn with_capacity(listener: &'static str, capacity: usize) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(capacity)),
            listener,
            capacity,
        }
    }

    /// Wait for room to serve one more connection. Hold the permit for the connection's
    /// whole life: dropping it is what lets the next peer in.
    pub async fn acquire(&self) -> OwnedSemaphorePermit {
        if self.sem.available_permits() == 0 {
            tracing::warn!(
                listener = self.listener,
                max = self.capacity,
                "connection limit reached — not accepting until one is released"
            );
        }
        self.sem
            .clone()
            .acquire_owned()
            .await
            .expect("connection semaphore is never closed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn acquire_blocks_at_capacity_and_resumes_when_a_permit_drops() {
        let limit = ConnLimit::with_capacity("test", 2);
        let a = limit.acquire().await;
        let _b = limit.acquire().await;

        // Third connection has to wait: this is the property that keeps a flood of idle
        // sockets from becoming a task and a file descriptor each.
        let third = tokio::time::timeout(Duration::from_millis(50), limit.acquire()).await;
        assert!(
            third.is_err(),
            "acquire should block once capacity is taken"
        );

        drop(a);
        let _c = tokio::time::timeout(Duration::from_millis(50), limit.acquire())
            .await
            .expect("a released permit lets the next connection in");
    }
}
