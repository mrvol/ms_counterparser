use std::net::IpAddr;

use crate::config::Config;

/// Returns the name of the bot pool `ip` belongs to, if any.
pub fn pool_for_ip(config: &Config, ip: IpAddr) -> Option<&str> {
    config
        .bot_pools
        .iter()
        .find(|(_, pool)| pool.cidrs.iter().any(|net| net.contains(&ip)))
        .map(|(name, _)| name.as_str())
}

/// Returns the bot pool name whose expected rDNS suffix matches `hostname`, if any.
pub fn pool_for_rdns_suffix<'a>(config: &'a Config, hostname: &str) -> Option<&'a str> {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    config
        .bot_pools
        .iter()
        .find(|(_, pool)| {
            let suffix = pool.rdns_suffix.trim_end_matches('.').to_ascii_lowercase();
            hostname == suffix || hostname.ends_with(&format!(".{suffix}"))
        })
        .map(|(name, _)| name.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        BotPoolConfig, ChallengeConfig, ServerConfig, ThresholdsConfig, WhitelistConfig,
    };
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

        Config {
            server: ServerConfig {
                socket_path: "/tmp/x.sock".to_string(),
            },
            thresholds: ThresholdsConfig {
                window_secs: 60,
                max_requests_per_window: 100,
            },
            whitelist: WhitelistConfig {
                cidrs: vec!["10.0.0.0/8".parse().unwrap()],
            },
            bot_pools,
            cooldowns: HashMap::new(),
            challenge: ChallengeConfig {
                cookie_name: "cp_ok".to_string(),
                cookie_ttl_secs: 3600,
                hmac_secret: "test-secret".to_string(),
            },
        }
    }

    #[test]
    fn whitelist_matches_cidr() {
        let cfg = test_config();
        assert!(cfg.is_whitelisted("10.1.2.3".parse().unwrap()));
        assert!(!cfg.is_whitelisted("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn pool_matches_cidr() {
        let cfg = test_config();
        assert_eq!(
            pool_for_ip(&cfg, "66.249.64.10".parse().unwrap()),
            Some("google")
        );
        assert_eq!(pool_for_ip(&cfg, "1.2.3.4".parse().unwrap()), None);
    }

    #[test]
    fn pool_matches_rdns_suffix() {
        let cfg = test_config();
        assert_eq!(
            pool_for_rdns_suffix(&cfg, "crawl-66-249-64-10.googlebot.com"),
            Some("google")
        );
        assert_eq!(pool_for_rdns_suffix(&cfg, "googlebot.com"), Some("google"));
        assert_eq!(pool_for_rdns_suffix(&cfg, "evilgooglebot.com"), None);
        assert_eq!(pool_for_rdns_suffix(&cfg, "example.com"), None);
    }
}
