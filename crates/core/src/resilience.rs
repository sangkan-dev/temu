use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::warn;

const MAX_BACKOFF_LEVEL: u8 = 3;
const LEVEL_THREE_PAUSE: Duration = Duration::from_secs(30);

/// Snapshot of adaptive rate-limit and connection reuse state.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResilienceMetrics {
    pub configured_rps: u32,
    pub current_rps: u32,
    pub backoff_level: u8,
    pub active_connections: usize,
    pub total_requests: usize,
    pub retry_count: usize,
    pub reuse_rate: f64,
}

#[derive(Debug)]
struct RateState {
    configured_rps: u32,
    current_rps: u32,
    baseline_latency: Option<Duration>,
    backoff_level: u8,
    next_allowed_at: Instant,
    hosts_seen: HashSet<String>,
    reused_connections: usize,
}

/// Adaptive request pacer with throttling detection, exponential backoff, and metrics.
#[derive(Debug, Clone)]
pub struct AdaptiveRateLimiter {
    state: Arc<Mutex<RateState>>,
    active_connections: Arc<AtomicUsize>,
    total_requests: Arc<AtomicUsize>,
    retry_count: Arc<AtomicUsize>,
}

impl AdaptiveRateLimiter {
    /// Creates a limiter from configured requests per second.
    pub fn new(configured_rps: u32) -> Self {
        let rps = configured_rps.max(1);
        Self {
            state: Arc::new(Mutex::new(RateState {
                configured_rps: rps,
                current_rps: rps,
                baseline_latency: None,
                backoff_level: 0,
                next_allowed_at: Instant::now(),
                hosts_seen: HashSet::new(),
                reused_connections: 0,
            })),
            active_connections: Arc::new(AtomicUsize::new(0)),
            total_requests: Arc::new(AtomicUsize::new(0)),
            retry_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Waits until the next request slot is available and records host reuse.
    pub async fn before_request(&self, host: Option<&str>) {
        let wait = {
            let mut state = self.state.lock().await;
            if let Some(host) = host
                && !state.hosts_seen.insert(host.to_string())
            {
                state.reused_connections += 1;
            }

            let now = Instant::now();
            let wait = state.next_allowed_at.saturating_duration_since(now);
            let interval = Duration::from_secs_f64(1.0 / state.current_rps.max(1) as f64);
            state.next_allowed_at = now + wait + interval;
            wait
        };

        if !wait.is_zero() {
            sleep(wait).await;
        }
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Marks the active request as completed.
    pub fn finish_request(&self) {
        self.active_connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_sub(1)
            })
            .ok();
    }

    /// Records a retry attempt.
    pub fn record_retry(&self) {
        self.retry_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Updates adaptive state from an HTTP status and elapsed request duration.
    ///
    /// Returns `true` when level-3 throttling was observed and the caller should
    /// pause before retrying.
    pub async fn observe_response(&self, status: Option<u16>, elapsed: Duration) -> bool {
        let mut state = self.state.lock().await;
        let baseline = match state.baseline_latency {
            Some(current) => {
                if !is_throttled(status, elapsed, current) {
                    let mixed = (current.as_nanos() * 7 + elapsed.as_nanos()) / 8;
                    state.baseline_latency =
                        Some(Duration::from_nanos(mixed.min(u64::MAX as u128) as u64));
                }
                current
            }
            None => {
                state.baseline_latency = Some(elapsed.max(Duration::from_millis(1)));
                elapsed.max(Duration::from_millis(1))
            }
        };

        if is_throttled(status, elapsed, baseline) {
            let previous = state.current_rps;
            state.backoff_level = (state.backoff_level + 1).min(MAX_BACKOFF_LEVEL);
            state.current_rps = backoff_rps(state.configured_rps, state.backoff_level);
            if previous != state.current_rps {
                warn!(
                    "Rate adjusted: {previous} rps -> {} rps (server throttling detected)",
                    state.current_rps
                );
            }
            return state.backoff_level == MAX_BACKOFF_LEVEL;
        }

        if state.backoff_level > 0 {
            let previous = state.current_rps;
            state.backoff_level -= 1;
            state.current_rps = backoff_rps(state.configured_rps, state.backoff_level);
            if previous != state.current_rps {
                warn!(
                    "Rate adjusted: {previous} rps -> {} rps (traffic recovered)",
                    state.current_rps
                );
            }
        }

        false
    }

    /// Pauses for the level-3 throttling backoff duration.
    pub async fn pause_for_throttling(&self) {
        sleep(LEVEL_THREE_PAUSE).await;
    }

    /// Returns current resilience metrics.
    pub async fn metrics(&self) -> ResilienceMetrics {
        let state = self.state.lock().await;
        let total_requests = self.total_requests.load(Ordering::Relaxed);
        let reuse_rate = if total_requests == 0 {
            0.0
        } else {
            state.reused_connections as f64 / total_requests as f64
        };
        ResilienceMetrics {
            configured_rps: state.configured_rps,
            current_rps: state.current_rps,
            backoff_level: state.backoff_level,
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_requests,
            retry_count: self.retry_count.load(Ordering::Relaxed),
            reuse_rate,
        }
    }
}

/// Returns jittered retry delay for a 1-based retry attempt.
pub fn retry_delay(attempt: u32) -> Duration {
    let capped = attempt.clamp(1, 6);
    let base = 100_u64.saturating_mul(2_u64.saturating_pow(capped - 1));
    Duration::from_millis(base + jitter_millis(100))
}

fn is_throttled(status: Option<u16>, elapsed: Duration, baseline: Duration) -> bool {
    status == Some(429) || elapsed > baseline.saturating_mul(3)
}

fn backoff_rps(configured: u32, level: u8) -> u32 {
    match level {
        0 => configured.max(1),
        1 => (configured / 2).max(1),
        2 | 3 => (configured / 4).max(1),
        _ => 1,
    }
}

fn jitter_millis(max: u64) -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos() as u64)
        .unwrap_or_default();
    nanos % max.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_backs_off_on_429_and_recovers() {
        let limiter = AdaptiveRateLimiter::new(100);

        assert!(
            !limiter
                .observe_response(Some(200), Duration::from_millis(100))
                .await
        );
        assert!(
            !limiter
                .observe_response(Some(429), Duration::from_millis(100))
                .await
        );
        assert_eq!(limiter.metrics().await.current_rps, 50);

        assert!(
            !limiter
                .observe_response(Some(200), Duration::from_millis(100))
                .await
        );
        assert_eq!(limiter.metrics().await.current_rps, 100);
    }

    #[tokio::test]
    async fn test_metrics_track_reuse_and_active_connections() {
        let limiter = AdaptiveRateLimiter::new(1000);
        limiter.before_request(Some("example.com")).await;
        limiter.finish_request();
        limiter.before_request(Some("example.com")).await;
        limiter.finish_request();

        let metrics = limiter.metrics().await;
        assert_eq!(metrics.total_requests, 2);
        assert!(metrics.reuse_rate > 0.0);
        assert_eq!(metrics.active_connections, 0);
    }

    #[test]
    fn test_retry_delay_has_backoff() {
        assert!(retry_delay(2) >= retry_delay(1));
    }
}
