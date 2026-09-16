//! Fixed-cardinality, process-local counters. Never accepts request metadata.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use rekey_domain::ipc::{ChannelMetrics, DispatchMetrics, MetricsResponse};

#[derive(Default)]
pub(crate) struct Metrics {
    pub admin: ChannelCounters,
    pub agent: ChannelCounters,
    pub backup: DispatchCounters,
    pub fault_signals: AtomicU64,
}

impl Metrics {
    pub fn snapshot(&self, capabilities_active: u32, executions_in_flight: u32) -> MetricsResponse {
        MetricsResponse {
            admin: self.admin.snapshot(),
            agent: self.agent.snapshot(),
            backup: self.backup.snapshot(),
            fault_signals_total: self.fault_signals.load(Ordering::Relaxed),
            capabilities_active,
            executions_in_flight,
        }
    }
}

#[derive(Default)]
pub(crate) struct ChannelCounters {
    pub dispatch: DispatchCounters,
    pub peer_rejections: AtomicU64,
    pub capacity_rejections: AtomicU64,
    frame_read_failures: AtomicU64,
}

impl ChannelCounters {
    pub fn frame_failed(&self) {
        self.frame_read_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> ChannelMetrics {
        ChannelMetrics {
            dispatch: self.dispatch.snapshot(),
            peer_rejections_total: self.peer_rejections.load(Ordering::Relaxed),
            capacity_rejections_total: self.capacity_rejections.load(Ordering::Relaxed),
            frame_read_failures_total: self.frame_read_failures.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
pub(crate) struct DispatchCounters {
    requests: AtomicU64,
    finished: AtomicU64,
    errors: AtomicU64,
    cancelled: AtomicU64,
    duration_micros: AtomicU64,
    in_flight: AtomicU64,
}

impl DispatchCounters {
    pub fn start(&self) -> DispatchGuard<'_> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        DispatchGuard {
            counters: self,
            started: Instant::now(),
            completed: false,
        }
    }

    fn snapshot(&self) -> DispatchMetrics {
        DispatchMetrics {
            requests_total: self.requests.load(Ordering::Relaxed),
            finished_total: self.finished.load(Ordering::Relaxed),
            errors_total: self.errors.load(Ordering::Relaxed),
            cancelled_total: self.cancelled.load(Ordering::Relaxed),
            duration_micros_total: self.duration_micros.load(Ordering::Relaxed),
            requests_in_flight: self.in_flight.load(Ordering::Relaxed),
        }
    }
}

pub(crate) struct DispatchGuard<'a> {
    counters: &'a DispatchCounters,
    started: Instant,
    completed: bool,
}

impl DispatchGuard<'_> {
    pub fn finish(mut self, error: bool) {
        if error {
            self.counters.errors.fetch_add(1, Ordering::Relaxed);
        }
        self.completed = true;
    }
}

impl Drop for DispatchGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.counters.cancelled.fetch_add(1, Ordering::Relaxed);
        }
        self.counters.duration_micros.fetch_add(
            self.started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        self.counters.finished.fetch_add(1, Ordering::Relaxed);
        self.counters.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_and_returned_errors_have_distinct_accounting() {
        let counters = DispatchCounters::default();
        let cancelled = counters.start();
        let failure = counters.start();
        assert_eq!(counters.snapshot().requests_in_flight, 2);
        failure.finish(true);
        drop(cancelled);
        counters.start().finish(false);
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.requests_total, 3);
        assert_eq!(snapshot.finished_total, 3);
        assert_eq!(snapshot.errors_total, 1);
        assert_eq!(snapshot.cancelled_total, 1);
        assert_eq!(snapshot.requests_in_flight, 0);
    }
}
