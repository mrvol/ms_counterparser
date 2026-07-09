use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_resolver::TokioAsyncResolver;

use crate::state::AppState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdnsResult {
    pub hostname: String,
}

/// Abstraction over DNS so tests can inject a fake resolver instead of hitting the network.
#[async_trait]
pub trait Resolver: Send + Sync {
    async fn reverse_lookup(&self, ip: IpAddr) -> Option<String>;
    async fn forward_confirms(&self, hostname: &str, ip: IpAddr) -> bool;
}

pub struct HickoryResolver {
    inner: TokioAsyncResolver,
}

impl HickoryResolver {
    pub fn from_system_conf() -> anyhow::Result<Self> {
        let inner = TokioAsyncResolver::tokio_from_system_conf()?;
        Ok(Self { inner })
    }
}

#[async_trait]
impl Resolver for HickoryResolver {
    async fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
        let resp = self.inner.reverse_lookup(ip).await.ok()?;
        resp.into_iter().next().map(|name| name.to_string())
    }

    async fn forward_confirms(&self, hostname: &str, ip: IpAddr) -> bool {
        match self.inner.lookup_ip(hostname).await {
            Ok(resp) => resp.into_iter().any(|resolved| resolved == ip),
            Err(_) => false,
        }
    }
}

/// Reverse-DNS + forward-confirm `ip`, using `state`'s TTL cache to avoid repeat lookups.
/// Returns `Some` only when the PTR hostname resolves back to `ip` (forward-confirmed) —
/// an unconfirmed or absent PTR record is treated as untrusted (`None`).
pub async fn verify_rdns(
    resolver: &dyn Resolver,
    state: &AppState,
    ip: IpAddr,
) -> Option<RdnsResult> {
    if let Some(cached) = state.rdns_cache.get(&ip).await {
        return (*cached).clone();
    }

    let result = resolve_uncached(resolver, ip).await;
    state.rdns_cache.insert(ip, Arc::new(result.clone())).await;
    result
}

async fn resolve_uncached(resolver: &dyn Resolver, ip: IpAddr) -> Option<RdnsResult> {
    let hostname = resolver.reverse_lookup(ip).await?;
    if resolver.forward_confirms(&hostname, ip).await {
        Some(RdnsResult { hostname })
    } else {
        None
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::config::{ChallengeConfig, ServerConfig, ThresholdsConfig, WhitelistConfig};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A resolver whose answers are hardcoded per test, with no network access.
    #[derive(Default)]
    pub struct FakeResolver {
        pub ptr: HashMap<IpAddr, String>,
        pub forward: Mutex<HashMap<String, Vec<IpAddr>>>,
    }

    #[async_trait]
    impl Resolver for FakeResolver {
        async fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
            self.ptr.get(&ip).cloned()
        }

        async fn forward_confirms(&self, hostname: &str, ip: IpAddr) -> bool {
            self.forward
                .lock()
                .unwrap()
                .get(hostname)
                .is_some_and(|ips| ips.contains(&ip))
        }
    }

    fn test_config() -> crate::config::Config {
        crate::config::Config {
            server: ServerConfig {
                socket_path: "/tmp/x.sock".to_string(),
            },
            thresholds: ThresholdsConfig {
                window_secs: 60,
                max_requests_per_window: 100,
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

    #[tokio::test]
    async fn forward_confirmed_ptr_is_trusted() {
        let ip: IpAddr = "66.249.64.10".parse().unwrap();
        let mut resolver = FakeResolver::default();
        resolver
            .ptr
            .insert(ip, "crawl-66-249-64-10.googlebot.com".to_string());
        resolver
            .forward
            .lock()
            .unwrap()
            .insert("crawl-66-249-64-10.googlebot.com".to_string(), vec![ip]);

        let state = AppState::new(test_config());
        let result = verify_rdns(&resolver, &state, ip).await;
        assert_eq!(
            result,
            Some(RdnsResult {
                hostname: "crawl-66-249-64-10.googlebot.com".to_string()
            })
        );
    }

    #[tokio::test]
    async fn mismatched_forward_lookup_is_untrusted() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let mut resolver = FakeResolver::default();
        resolver.ptr.insert(ip, "spoofed.googlebot.com".to_string());
        // Forward lookup of the claimed hostname resolves elsewhere, not back to `ip`.
        resolver.forward.lock().unwrap().insert(
            "spoofed.googlebot.com".to_string(),
            vec!["9.9.9.9".parse().unwrap()],
        );

        let state = AppState::new(test_config());
        let result = verify_rdns(&resolver, &state, ip).await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn missing_ptr_is_untrusted() {
        let ip: IpAddr = "5.6.7.8".parse().unwrap();
        let resolver = FakeResolver::default();
        let state = AppState::new(test_config());
        let result = verify_rdns(&resolver, &state, ip).await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn result_is_cached() {
        let ip: IpAddr = "66.249.64.10".parse().unwrap();
        let mut resolver = FakeResolver::default();
        resolver.ptr.insert(ip, "host.googlebot.com".to_string());
        resolver
            .forward
            .lock()
            .unwrap()
            .insert("host.googlebot.com".to_string(), vec![ip]);

        let state = AppState::new(test_config());
        let first = verify_rdns(&resolver, &state, ip).await;
        // Remove the PTR record; a cache hit should still return the earlier result.
        let resolver2 = FakeResolver {
            forward: resolver.forward,
            ..Default::default()
        };
        let second = verify_rdns(&resolver2, &state, ip).await;
        assert_eq!(first, second);
    }
}
