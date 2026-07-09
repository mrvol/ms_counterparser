use rand::distributions::Alphanumeric;
use rand::seq::SliceRandom;
use rand::Rng;

use crate::config::Config;

const JOKES: &[&str] = &[
    "Protected by CounterParser. Inquiries: TODO@yourdomain.example.",
    "This page is guarded by a very small, very tired robot.",
    "Limited-time offer: buy a date, get a byte free.",
    "Nothing to see here. Please enjoy this complimentary silence.",
    "Our terms of service require you to guess a number between 1 and infinity.",
    "You have reached the bureaucracy department. Please hold.",
    "This response is intentionally unhelpful.",
];

/// A harmless-looking 200 page served instead of the real app while an IP is cooling down.
/// Padding is random-length so repeated responses don't share a fixed `Content-Length`.
pub fn cooldown_body() -> String {
    let mut rng = rand::thread_rng();
    let line = JOKES.choose(&mut rng).copied().unwrap_or(JOKES[0]);
    let padding = random_padding(&mut rng);
    format!("<!doctype html><html><body><p>{line}</p><!-- {padding} --></body></html>")
}

/// A 200 page for ambiguous IPs: sets a signed cookie via JS and reloads. Scripts that don't
/// execute JS (most naive scrapers) never store the cookie, so the retried request still gets
/// challenged; real browsers pass silently on the reload.
pub fn challenge_body(config: &Config, token: &str) -> String {
    let mut rng = rand::thread_rng();
    let padding = random_padding(&mut rng);
    format!(
        r#"<!doctype html><html><body>
<p>One moment, please.</p>
<script>document.cookie = "{name}={token}; path=/; max-age={ttl}; SameSite=Lax"; location.reload();</script>
<!-- {padding} -->
</body></html>"#,
        name = config.challenge.cookie_name,
        token = token,
        ttl = config.challenge.cookie_ttl_secs,
    )
}

fn random_padding(rng: &mut impl Rng) -> String {
    let len = rng.gen_range(50..500);
    (0..len).map(|_| rng.sample(Alphanumeric) as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ChallengeConfig, ServerConfig, ThresholdsConfig, WhitelistConfig};
    use std::collections::HashMap;

    fn test_config() -> Config {
        Config {
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

    #[test]
    fn cooldown_body_length_varies() {
        let lengths: std::collections::HashSet<usize> =
            (0..20).map(|_| cooldown_body().len()).collect();
        assert!(lengths.len() > 1, "expected varying response lengths");
    }

    #[test]
    fn challenge_body_embeds_cookie_and_token() {
        let cfg = test_config();
        let body = challenge_body(&cfg, "abc.def");
        assert!(body.contains("cp_ok=abc.def"));
        assert!(body.contains("max-age=3600"));
    }
}
