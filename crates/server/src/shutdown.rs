//! A shutdown signal every listener watches.
//!
//! The accept loops in [`crate::mux`] and [`crate::mtls`] used to be `loop { accept }` with
//! no way out, which was fine while the only way to stop the process was a signal that
//! killed it outright. A Windows service cannot be stopped that way: the service control
//! manager sends `SERVICE_CONTROL_STOP` and expects the process to report
//! `SERVICE_STOPPED` and exit, killing it only after a timeout — so there has to be
//! something to hand the stop request to.
//!
//! What "graceful" buys here is small but real. An agent's poll is a single request over a
//! connection it opened; cutting it mid-flight costs that agent one poll interval, no more.
//! The one that matters is an operator's write: a bundle upload or a config change that has
//! reached SQLite but not yet been answered leaves the operator unsure whether it landed.
//! Draining lets those finish.

use std::time::Duration;

use tokio::sync::watch;

/// How long the drain waits for connections already in flight before exiting anyway.
///
/// Shorter than the 30s `TimeoutStopSec` in the systemd unit and well inside the SCM's
/// default stop timeout, so the process is always the one that decides to exit rather than
/// the one that got killed for taking too long.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(15);

/// Handed to each listener; cloneable, and every clone fires at once.
#[derive(Clone, Debug)]
pub struct Shutdown(watch::Receiver<bool>);

/// The other end. Dropping it does not fire the signal — only [`Trigger::fire`] does.
#[derive(Clone, Debug)]
pub struct Trigger(watch::Sender<bool>);

/// Create a linked trigger and signal.
pub fn channel() -> (Trigger, Shutdown) {
    let (tx, rx) = watch::channel(false);
    (Trigger(tx), Shutdown(rx))
}

impl Trigger {
    /// Ask everything watching to stop. Idempotent — a second stop request while the first
    /// is draining is not an error, and the SCM does send one.
    pub fn fire(&self) {
        // An error means every receiver is gone, which is exactly the state `fire` wants.
        let _ = self.0.send(true);
    }

    /// A signal watching this trigger.
    pub fn subscribe(&self) -> Shutdown {
        Shutdown(self.0.subscribe())
    }
}

impl Shutdown {
    /// Resolve when shutdown has been asked for — immediately, if it already was.
    ///
    /// Takes `self` because the common use is `tokio::select!` inside an accept loop,
    /// where holding a borrow across the loop fights the borrow checker for no benefit.
    pub async fn wait(mut self) {
        // `changed()` only reports transitions, so a signal that fired before this call
        // would otherwise be waited on forever.
        if *self.0.borrow_and_update() {
            return;
        }
        // An error means the trigger is gone. Nothing can fire the signal after that, so
        // treating it as "shut down" is both the safe reading and the only terminating one.
        let _ = self.0.changed().await;
    }

    /// Whether shutdown has already been asked for, without waiting.
    pub fn is_fired(&self) -> bool {
        *self.0.borrow()
    }

    /// A signal that never fires, for callers that have no shutdown story — tests, and
    /// anything that runs to completion on its own.
    pub fn never() -> Self {
        let (tx, rx) = watch::channel(false);
        // Deliberately leaked: a dropped sender would make `wait` resolve at once, which
        // is the opposite of what this is for.
        std::mem::forget(tx);
        Shutdown(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wait_resolves_when_fired() {
        let (trigger, signal) = channel();
        let waiter = tokio::spawn(signal.wait());
        trigger.fire();
        waiter.await.unwrap();
    }

    /// The ordering that bit the first attempt: a signal handed to a listener that only
    /// starts waiting after the trigger has already fired must not wait forever.
    #[tokio::test]
    async fn wait_resolves_when_already_fired() {
        let (trigger, signal) = channel();
        trigger.fire();
        signal.clone().wait().await;
        assert!(signal.is_fired());
    }

    #[tokio::test]
    async fn every_clone_fires() {
        let (trigger, signal) = channel();
        let waiters: Vec<_> = (0..4)
            .map(|_| tokio::spawn(signal.clone().wait()))
            .collect();
        trigger.fire();
        for w in waiters {
            w.await.unwrap();
        }
    }

    #[tokio::test]
    async fn firing_twice_is_harmless() {
        let (trigger, signal) = channel();
        trigger.fire();
        trigger.fire();
        signal.wait().await;
    }

    #[tokio::test]
    async fn subscribing_after_firing_sees_it() {
        let (trigger, _signal) = channel();
        trigger.fire();
        trigger.subscribe().wait().await;
    }

    #[tokio::test]
    async fn a_dropped_trigger_releases_waiters() {
        let (trigger, signal) = channel();
        drop(trigger);
        signal.wait().await;
    }

    #[tokio::test]
    async fn never_does_not_resolve() {
        let signal = Shutdown::never();
        assert!(!signal.is_fired());
        let r = tokio::time::timeout(Duration::from_millis(50), signal.wait()).await;
        assert!(r.is_err(), "Shutdown::never() resolved");
    }
}
