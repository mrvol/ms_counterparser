use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use moka::future::Cache as AsyncCache;
use moka::sync::Cache as SyncCache;
use time::OffsetDateTime;

use crate::config::Config;
use crate::dns::RdnsResult;

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Allow,
    /// `until` is a unix timestamp (seconds).
    Cooldown {
        service: String,
        until: i64,
    },
    Challenge,
}

pub struct IpStats {
    pub count: AtomicU64,
    pub window_start: AtomicI64,
    pub last_seen: AtomicI64,
}

impl IpStats {
    fn new(now: i64) -> Self {
        Self {
            count: AtomicU64::new(0),
            window_start: AtomicI64::new(now),
            last_seen: AtomicI64::new(now),
        }
    }
}

pub struct AppState {
    pub config: Config,
    pub ip_stats: DashMap<IpAddr, IpStats>,
    pub rdns_cache: AsyncCache<IpAddr, Arc<Option<RdnsResult>>>,
    /// Short-lived cache so `/respond` can reuse the verdict `/check` just computed,
    /// instead of re-running rate/DNS analysis for the same request.
    pub verdicts: SyncCache<IpAddr, Verdict>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let rdns_cache = AsyncCache::builder()
            .time_to_live(Duration::from_secs(6 * 3600))
            .max_capacity(100_000)
            .build();
        let verdicts = SyncCache::builder()
            .time_to_live(Duration::from_secs(30))
            .max_capacity(100_000)
            .build();
        Self {
            config,
            ip_stats: DashMap::new(),
            rdns_cache,
            verdicts,
        }
    }

    /// Records a hit for `ip`, resetting the fixed window if it has elapsed.
    /// Returns the request count within the current window (including this one).
    pub fn record_hit(&self, ip: IpAddr) -> u64 {
        let now = now_secs();
        let window_secs = self.config.thresholds.window_secs as i64;
        let entry = self.ip_stats.entry(ip).or_insert_with(|| IpStats::new(now));
        entry.last_seen.store(now, Ordering::Relaxed);

        let window_start = entry.window_start.load(Ordering::Relaxed);
        if now - window_start >= window_secs {
            entry.window_start.store(now, Ordering::Relaxed);
            entry.count.store(1, Ordering::Relaxed);
            1
        } else {
            entry.count.fetch_add(1, Ordering::Relaxed) + 1
        }
    }
}

pub fn now_secs() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ChallengeConfig, ServerConfig, ThresholdsConfig, WhitelistConfig};
    use std::collections::HashMap;

    fn test_config(window_secs: u64) -> Config {
        Config {
            server: ServerConfig {
                socket_path: "/tmp/x.sock".to_string(),
            },
            thresholds: ThresholdsConfig {
                window_secs,
                max_requests_per_window: 3,
            },
            whitelist: WhitelistConfig { cidrs: vec![] },
            bot_pools: HashMap::new(),
            cooldowns: HashMap::new(),
            challenge: ChallengeConfig {
                cookie_name: "cp_ok".to_string(),
                cookie_ttl_secs: 3600,
                hmac_secret: "test-secret".to_string(),
            },
        }
    }

    #[test]
    fn record_hit_counts_within_window() {
        let state = AppState::new(test_config(60));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(state.record_hit(ip), 1);
        assert_eq!(state.record_hit(ip), 2);
        assert_eq!(state.record_hit(ip), 3);
    }

    #[test]
    fn record_hit_resets_after_window_elapses() {
        let state = AppState::new(test_config(0));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(state.record_hit(ip), 1);
        // window_secs = 0 means every call is treated as a new window.
        assert_eq!(state.record_hit(ip), 1);
    }
}
