use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub thresholds: ThresholdsConfig,
    pub whitelist: WhitelistConfig,
    #[serde(default)]
    pub bot_pools: HashMap<String, BotPoolConfig>,
    pub cooldowns: HashMap<String, String>,
    pub challenge: ChallengeConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub socket_path: String,
}

#[derive(Debug, Deserialize)]
pub struct ThresholdsConfig {
    pub window_secs: u64,
    pub max_requests_per_window: u64,
}

#[derive(Debug, Deserialize)]
pub struct WhitelistConfig {
    #[serde(default)]
    pub cidrs: Vec<IpNet>,
}

#[derive(Debug, Deserialize)]
pub struct BotPoolConfig {
    pub cidrs: Vec<IpNet>,
    pub rdns_suffix: String,
}

#[derive(Debug, Deserialize)]
pub struct ChallengeConfig {
    pub cookie_name: String,
    pub cookie_ttl_secs: u64,
    /// Overridden by the COUNTERPARSER_HMAC_SECRET env var when set.
    #[serde(default)]
    pub hmac_secret: String,
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {path}: {e}"))?;
        let mut cfg: Config =
            toml::from_str(&raw).map_err(|e| anyhow::anyhow!("parsing config {path}: {e}"))?;

        if let Ok(secret) = std::env::var("COUNTERPARSER_HMAC_SECRET") {
            cfg.challenge.hmac_secret = secret;
        }
        if cfg.challenge.hmac_secret.is_empty() {
            anyhow::bail!(
                "challenge.hmac_secret is empty: set it in the config file or via COUNTERPARSER_HMAC_SECRET"
            );
        }

        Ok(cfg)
    }

    pub fn window(&self) -> Duration {
        Duration::from_secs(self.thresholds.window_secs)
    }

    pub fn cooldown_for(&self, service: &str) -> Duration {
        self.cooldowns
            .get(service)
            .or_else(|| self.cooldowns.get("default"))
            .and_then(|s| parse_duration(s))
            .unwrap_or(Duration::from_secs(600))
    }

    pub fn is_whitelisted(&self, ip: IpAddr) -> bool {
        self.whitelist.cidrs.iter().any(|net| net.contains(&ip))
    }
}

/// Parses simple durations like "10m", "24h", "30s", "1d".
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, unit) = s.split_at(s.len() - 1);
    let n: u64 = num.parse().ok()?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86400,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("10m"), Some(Duration::from_secs(600)));
        assert_eq!(parse_duration("24h"), Some(Duration::from_secs(86400)));
        assert_eq!(parse_duration("1d"), Some(Duration::from_secs(86400)));
        assert_eq!(parse_duration("bogus"), None);
    }
}
