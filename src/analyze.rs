use std::net::IpAddr;

use crate::challenge;
use crate::dns::{self, Resolver};
use crate::ip_pools;
use crate::state::{now_secs, AppState, Verdict};

/// Decides what should happen to a request from `ip`. Always records the hit for
/// count/last-seen tracking, then classifies:
///
/// 1. Whitelisted CIDR -> `Allow`.
/// 2. Inside a known bot pool's official CIDR range -> `Allow`, no DNS needed.
/// 3. Under the rate threshold -> `Allow`.
/// 4. Over threshold, valid signed challenge cookie already presented -> `Allow`.
/// 5. Over threshold, reverse DNS forward-confirms into a known bot pool's suffix
///    (but the IP wasn't in that pool's CIDR list, otherwise step 2 would have matched) ->
///    `Cooldown{"impersonator"}`: this is the classic spoofed-Googlebot pattern, or the
///    static CIDR pool being stale.
/// 6. Over threshold, reverse DNS forward-confirms but doesn't match any known bot suffix ->
///    `Cooldown{"unknown"}`: a real host, just not one we recognize as anything special.
/// 7. Over threshold, no forward-confirmed reverse DNS at all -> `Challenge`.
pub async fn analyze(
    resolver: &dyn Resolver,
    state: &AppState,
    ip: IpAddr,
    challenge_cookie: Option<&str>,
) -> Verdict {
    let count = state.record_hit(ip);

    if state.config.is_whitelisted(ip) {
        return Verdict::Allow;
    }
    if ip_pools::pool_for_ip(&state.config, ip).is_some() {
        return Verdict::Allow;
    }
    if count <= state.config.thresholds.max_requests_per_window {
        return Verdict::Allow;
    }
    if let Some(cookie) = challenge_cookie {
        if challenge::verify(&state.config, ip, cookie) {
            return Verdict::Allow;
        }
    }

    match dns::verify_rdns(resolver, state, ip).await {
        Some(result) => {
            let service = match ip_pools::pool_for_rdns_suffix(&state.config, &result.hostname) {
                Some(_) => "impersonator",
                None => "unknown",
            };
            cooldown(state, service)
        }
        None => Verdict::Challenge,
    }
}

fn cooldown(state: &AppState, service: &str) -> Verdict {
    let until = now_secs() + state.config.cooldown_for(service).as_secs() as i64;
    Verdict::Cooldown {
        service: service.to_string(),
        until,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        BotPoolConfig, ChallengeConfig, Config, ServerConfig, ThresholdsConfig, WhitelistConfig,
    };
    use crate::dns::tests::FakeResolver;
    use std::collections::HashMap;

    fn test_config() -> Config {
        let mut bot_pools = HashMap::new();
        bot_pools.insert(
            "google".to_string(),
            BotPoolConfig {
                cidrs: vec!["66.249.64.0/19".parse().unwrap()],
                rdns_suffix: "googlebot.com".to_string(),
            },
        );
        let mut cooldowns = HashMap::new();
        cooldowns.insert("default".to_string(), "10m".to_string());
        cooldowns.insert("impersonator".to_string(), "24h".to_string());
        cooldowns.insert("unknown".to_string(), "5m".to_string());

        Config {
            server: ServerConfig {
                socket_path: "/tmp/x.sock".to_string(),
            },
            thresholds: ThresholdsConfig {
                window_secs: 60,
                max_requests_per_window: 2,
            },
            whitelist: WhitelistConfig {
                cidrs: vec!["10.0.0.0/8".parse().unwrap()],
            },
            bot_pools,
            cooldowns,
            challenge: ChallengeConfig {
                cookie_name: "cp_ok".to_string(),
                cookie_ttl_secs: 3600,
                hmac_secret: "test-secret".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn whitelisted_ip_always_allowed() {
        let state = AppState::new(test_config());
        let resolver = FakeResolver::default();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        for _ in 0..5 {
            assert_eq!(analyze(&resolver, &state, ip, None).await, Verdict::Allow);
        }
    }

    #[tokio::test]
    async fn known_pool_ip_always_allowed() {
        let state = AppState::new(test_config());
        let resolver = FakeResolver::default();
        let ip: IpAddr = "66.249.64.10".parse().unwrap();
        for _ in 0..5 {
            assert_eq!(analyze(&resolver, &state, ip, None).await, Verdict::Allow);
        }
    }

    #[tokio::test]
    async fn under_threshold_allowed() {
        let state = AppState::new(test_config());
        let resolver = FakeResolver::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(analyze(&resolver, &state, ip, None).await, Verdict::Allow);
        assert_eq!(analyze(&resolver, &state, ip, None).await, Verdict::Allow);
    }

    #[tokio::test]
    async fn spoofed_googlebot_gets_impersonator_cooldown() {
        let state = AppState::new(test_config());
        let mut resolver = FakeResolver::default();
        // Outside Google's official CIDR pool, but the PTR forward-confirms into googlebot.com.
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        resolver.ptr.insert(ip, "fake.googlebot.com".to_string());
        resolver
            .forward
            .lock()
            .unwrap()
            .insert("fake.googlebot.com".to_string(), vec![ip]);

        analyze(&resolver, &state, ip, None).await;
        analyze(&resolver, &state, ip, None).await;
        let verdict = analyze(&resolver, &state, ip, None).await;
        match verdict {
            Verdict::Cooldown { service, .. } => assert_eq!(service, "impersonator"),
            other => panic!("expected Cooldown, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unresolvable_ip_over_threshold_gets_challenged() {
        let state = AppState::new(test_config());
        let resolver = FakeResolver::default();
        let ip: IpAddr = "5.6.7.8".parse().unwrap();

        analyze(&resolver, &state, ip, None).await;
        analyze(&resolver, &state, ip, None).await;
        let verdict = analyze(&resolver, &state, ip, None).await;
        assert_eq!(verdict, Verdict::Challenge);
    }

    #[tokio::test]
    async fn valid_challenge_cookie_allows_through() {
        let state = AppState::new(test_config());
        let resolver = FakeResolver::default();
        let ip: IpAddr = "5.6.7.8".parse().unwrap();
        let token = challenge::issue(&state.config, ip);

        analyze(&resolver, &state, ip, None).await;
        analyze(&resolver, &state, ip, None).await;
        let verdict = analyze(&resolver, &state, ip, Some(&token)).await;
        assert_eq!(verdict, Verdict::Allow);
    }

    #[tokio::test]
    async fn known_host_without_bot_match_gets_unknown_cooldown() {
        let state = AppState::new(test_config());
        let mut resolver = FakeResolver::default();
        let ip: IpAddr = "5.6.7.8".parse().unwrap();
        resolver.ptr.insert(ip, "host.example.com".to_string());
        resolver
            .forward
            .lock()
            .unwrap()
            .insert("host.example.com".to_string(), vec![ip]);

        analyze(&resolver, &state, ip, None).await;
        analyze(&resolver, &state, ip, None).await;
        let verdict = analyze(&resolver, &state, ip, None).await;
        match verdict {
            Verdict::Cooldown { service, .. } => assert_eq!(service, "unknown"),
            other => panic!("expected Cooldown, got {other:?}"),
        }
    }
}
