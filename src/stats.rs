//! Process-lifetime monitoring counters, independent of deterministic state.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::time::{Instant, MissedTickBehavior, interval_at};
use tracing::info;

use crate::evil::EvilMode;

#[derive(Default)]
pub(crate) struct Stats {
    clients_total: AtomicU64,
    clients_active: AtomicU64,
    evil_updates: AtomicU64,
    evil_status_reads: AtomicU64,
    evil_rejected: AtomicU64,
    evil_resets: AtomicU64,
    mode_off: AtomicU64,
    mode_random: AtomicU64,
    mode_mutate: AtomicU64,
    mode_overflow: AtomicU64,
}

impl Stats {
    pub(crate) fn client_connected(self: &Arc<Self>) -> ClientConnection {
        self.clients_total.fetch_add(1, Ordering::Relaxed);
        self.clients_active.fetch_add(1, Ordering::Relaxed);
        ClientConnection(Arc::clone(self))
    }

    pub(crate) fn configuration_updated(&self) {
        self.evil_updates.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn status_read(&self) {
        self.evil_status_reads.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn command_rejected(&self) {
        self.evil_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn reset(&self) {
        self.evil_resets.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn mode_selected(&self, mode: EvilMode) {
        let counter = match mode {
            EvilMode::Off => &self.mode_off,
            EvilMode::Random => &self.mode_random,
            EvilMode::Mutate => &self.mode_mutate,
            EvilMode::Overflow => &self.mode_overflow,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) async fn report(&self) {
        let period = Duration::from_secs(1);
        let mut interval = interval_at(Instant::now() + period, period);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            self.log_summary();
        }
    }

    fn log_summary(&self) {
        // Relaxed loads avoid synchronizing proxy work for monitoring. Fields
        // may reflect slightly different instants during concurrent updates.
        info!(
            clients_total = self.clients_total.load(Ordering::Relaxed),
            clients_active = self.clients_active.load(Ordering::Relaxed),
            evil_updates = self.evil_updates.load(Ordering::Relaxed),
            evil_status_reads = self.evil_status_reads.load(Ordering::Relaxed),
            evil_rejected = self.evil_rejected.load(Ordering::Relaxed),
            evil_resets = self.evil_resets.load(Ordering::Relaxed),
            mode_off = self.mode_off.load(Ordering::Relaxed),
            mode_random = self.mode_random.load(Ordering::Relaxed),
            mode_mutate = self.mode_mutate.load(Ordering::Relaxed),
            mode_overflow = self.mode_overflow.load(Ordering::Relaxed),
            "proxy statistics"
        );
    }
}

pub(crate) struct ClientConnection(Arc<Stats>);

impl Drop for ClientConnection {
    fn drop(&mut self) {
        self.0.clients_active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_clients_share_totals_without_losing_updates() {
        let stats = Arc::new(Stats::default());
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let stats = Arc::clone(&stats);
                scope.spawn(move || {
                    for _ in 0..1000 {
                        let _connection = stats.client_connected();
                        stats.configuration_updated();
                        stats.mode_selected(EvilMode::Mutate);
                    }
                });
            }
        });
        assert_eq!(stats.clients_total.load(Ordering::Relaxed), 8000);
        assert_eq!(stats.clients_active.load(Ordering::Relaxed), 0);
        assert_eq!(stats.evil_updates.load(Ordering::Relaxed), 8000);
        assert_eq!(stats.mode_mutate.load(Ordering::Relaxed), 8000);
    }

    #[tokio::test]
    async fn connections_are_counted_through_completion_and_cancellation() {
        let stats = Arc::new(Stats::default());
        let first = stats.client_connected();
        let second = stats.client_connected();
        assert_eq!(stats.clients_total.load(Ordering::Relaxed), 2);
        assert_eq!(stats.clients_active.load(Ordering::Relaxed), 2);
        drop(first);
        assert_eq!(stats.clients_active.load(Ordering::Relaxed), 1);

        let task = tokio::spawn(async move {
            let _connection = second;
            std::future::pending::<()>().await;
        });
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(stats.clients_active.load(Ordering::Relaxed), 0);
        assert_eq!(stats.clients_total.load(Ordering::Relaxed), 2);
    }
}
