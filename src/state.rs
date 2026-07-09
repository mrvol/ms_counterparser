use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use moka::future::Cache as AsyncCache;
use moka::sync::Cache as SyncCache;
use serde::Serialize;
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

/// A currently-active cooldown, tracked independently of the short-lived `verdicts` cache so
/// `/stats` can report an accurate gauge regardless of that cache's 30s TTL.
struct CooldownEntry {
    service: String,
    until: i64,
}

#[derive(Default)]
struct Counters {
    total_requests: AtomicU64,
    allowed: AtomicU64,
    cooldown: AtomicU64,
    challenge: AtomicU64,
}

#[derive(Debug, Serialize)]
pub struct Stats {
    pub uptime_secs: u64,
    pub tracked_ips: usize,
    pub total_requests: u64,
    pub verdicts: VerdictCounts,
    pub active_cooldowns: usize,
    pub cooldowns_by_service: HashMap<String, usize>,
    pub rdns_cache_entries: u64,
}

#[derive(Debug, Serialize)]
pub struct VerdictCounts {
    pub allowed: u64,
    pub cooldown: u64,
    pub challenge: u64,
}

pub struct AppState {
    pub config: Config,
    pub ip_stats: DashMap<IpAddr, IpStats>,
    pub rdns_cache: AsyncCache<IpAddr, Arc<Option<RdnsResult>>>,
    /// Short-lived cache so `/respond` can reuse the verdict `/check` just computed,
    /// instead of re-running rate/DNS analysis for the same request.
    pub verdicts: SyncCache<IpAddr, Verdict>,
    cooldowns: DashMap<IpAddr, CooldownEntry>,
    counters: Counters,
    started_at: Instant,
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
            cooldowns: DashMap::new(),
            counters: Counters::default(),
            started_at: Instant::now(),
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

    /// Feeds a verdict into the lifetime counters and the active-cooldown gauge. Called once
    /// per `/check`, after `analyze` has decided what to do with the request.
    pub fn record_verdict(&self, ip: IpAddr, verdict: &Verdict) {
        self.counters.total_requests.fetch_add(1, Ordering::Relaxed);
        match verdict {
            Verdict::Allow => {
                self.counters.allowed.fetch_add(1, Ordering::Relaxed);
                self.cooldowns.remove(&ip);
            }
            Verdict::Cooldown { service, until } => {
                self.counters.cooldown.fetch_add(1, Ordering::Relaxed);
                self.cooldowns.insert(
                    ip,
                    CooldownEntry {
                        service: service.clone(),
                        until: *until,
                    },
                );
            }
            Verdict::Challenge => {
                self.counters.challenge.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Aggregate, non-identifying stats snapshot (no per-IP data) suitable for a `/stats`
    /// endpoint. Also opportunistically purges cooldown entries that have expired.
    pub fn stats(&self) -> Stats {
        let now = now_secs();
        self.cooldowns.retain(|_, entry| entry.until > now);

        let mut cooldowns_by_service: HashMap<String, usize> = HashMap::new();
        for entry in self.cooldowns.iter() {
            *cooldowns_by_service
                .entry(entry.service.clone())
                .or_insert(0) += 1;
        }

        Stats {
            uptime_secs: self.started_at.elapsed().as_secs(),
            tracked_ips: self.ip_stats.len(),
            total_requests: self.counters.total_requests.load(Ordering::Relaxed),
            verdicts: VerdictCounts {
                allowed: self.counters.allowed.load(Ordering::Relaxed),
                cooldown: self.counters.cooldown.load(Ordering::Relaxed),
                challenge: self.counters.challenge.load(Ordering::Relaxed),
            },
            active_cooldowns: self.cooldowns.len(),
            cooldowns_by_service,
            rdns_cache_entries: self.rdns_cache.entry_count(),
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

    #[test]
    fn stats_reflects_recorded_verdicts() {
        let state = AppState::new(test_config(60));
        let allowed_ip: IpAddr = "1.2.3.4".parse().unwrap();
        let cooling_ip: IpAddr = "5.6.7.8".parse().unwrap();
        let challenged_ip: IpAddr = "9.9.9.9".parse().unwrap();

        state.record_hit(allowed_ip);
        state.record_verdict(allowed_ip, &Verdict::Allow);

        state.record_hit(cooling_ip);
        state.record_verdict(
            cooling_ip,
            &Verdict::Cooldown {
                service: "unknown".to_string(),
                until: now_secs() + 600,
            },
        );

        state.record_hit(challenged_ip);
        state.record_verdict(challenged_ip, &Verdict::Challenge);

        let stats = state.stats();
        assert_eq!(stats.tracked_ips, 3);
        assert_eq!(stats.total_requests, 3);
        assert_eq!(stats.verdicts.allowed, 1);
        assert_eq!(stats.verdicts.cooldown, 1);
        assert_eq!(stats.verdicts.challenge, 1);
        assert_eq!(stats.active_cooldowns, 1);
        assert_eq!(stats.cooldowns_by_service.get("unknown"), Some(&1));
    }

    #[test]
    fn stats_purges_expired_cooldowns() {
        let state = AppState::new(test_config(60));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        state.record_verdict(
            ip,
            &Verdict::Cooldown {
                service: "unknown".to_string(),
                until: now_secs() - 1, // already expired
            },
        );

        let stats = state.stats();
        assert_eq!(stats.active_cooldowns, 0);
        // The lifetime counter still reflects it was issued.
        assert_eq!(stats.verdicts.cooldown, 1);
    }

    #[test]
    fn allow_clears_an_existing_cooldown() {
        let state = AppState::new(test_config(60));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        state.record_verdict(
            ip,
            &Verdict::Cooldown {
                service: "unknown".to_string(),
                until: now_secs() + 600,
            },
        );
        assert_eq!(state.stats().active_cooldowns, 1);

        state.record_verdict(ip, &Verdict::Allow);
        assert_eq!(state.stats().active_cooldowns, 0);
    }
}
