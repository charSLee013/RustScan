use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct ScanProgress {
    ports_total: u64,
    total_ips: Option<u64>,
    total_sockets: Option<u64>,
    start: Instant,

    resolved_ips: AtomicU64,
    scheduled_sockets: AtomicU64,
    completed_sockets: AtomicU64,
    open_sockets: AtomicU64,
    open_ips: AtomicU64,
    last_socket: Mutex<Option<SocketAddr>>,
}

impl ScanProgress {
    pub fn new(ports_total: u64, total_ips: Option<u64>) -> Arc<Self> {
        let total_sockets = total_ips.and_then(|ips| ips.checked_mul(ports_total));

        Arc::new(Self {
            ports_total,
            total_ips,
            total_sockets,
            start: Instant::now(),
            resolved_ips: AtomicU64::new(0),
            scheduled_sockets: AtomicU64::new(0),
            completed_sockets: AtomicU64::new(0),
            open_sockets: AtomicU64::new(0),
            open_ips: AtomicU64::new(0),
            last_socket: Mutex::new(None),
        })
    }

    pub fn add_resolved_ips(&self, delta: u64) {
        self.resolved_ips.fetch_add(delta, Ordering::Relaxed);
    }

    pub fn scheduled_sockets(&self) -> u64 {
        self.scheduled_sockets.load(Ordering::Relaxed)
    }

    pub fn completed_sockets(&self) -> u64 {
        self.completed_sockets.load(Ordering::Relaxed)
    }

    pub fn set_scheduled_sockets(&self, value: u64) {
        self.scheduled_sockets.store(value, Ordering::Relaxed);
    }

    pub fn set_completed_sockets(&self, value: u64) {
        self.completed_sockets.store(value, Ordering::Relaxed);
    }

    pub fn inc_open_sockets(&self, delta: u64) {
        self.open_sockets.fetch_add(delta, Ordering::Relaxed);
    }

    pub fn inc_open_ips(&self, delta: u64) {
        self.open_ips.fetch_add(delta, Ordering::Relaxed);
    }

    pub fn set_last_socket(&self, socket: SocketAddr) {
        let mut guard = self
            .last_socket
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(socket);
    }

    pub fn snapshot(&self) -> ProgressSnapshot {
        let last_socket = self
            .last_socket
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .copied();

        ProgressSnapshot {
            ports_total: self.ports_total,
            total_ips: self.total_ips,
            total_sockets: self.total_sockets,
            resolved_ips: self.resolved_ips.load(Ordering::Relaxed),
            scheduled_sockets: self.scheduled_sockets.load(Ordering::Relaxed),
            completed_sockets: self.completed_sockets.load(Ordering::Relaxed),
            open_sockets: self.open_sockets.load(Ordering::Relaxed),
            open_ips: self.open_ips.load(Ordering::Relaxed),
            last_socket,
            elapsed: self.start.elapsed(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProgressSnapshot {
    pub ports_total: u64,
    pub total_ips: Option<u64>,
    pub total_sockets: Option<u64>,
    pub resolved_ips: u64,
    pub scheduled_sockets: u64,
    pub completed_sockets: u64,
    pub open_sockets: u64,
    pub open_ips: u64,
    pub last_socket: Option<SocketAddr>,
    pub elapsed: Duration,
}

impl ProgressSnapshot {
    pub fn inflight(&self) -> u64 {
        self.scheduled_sockets
            .saturating_sub(self.completed_sockets)
    }
}
