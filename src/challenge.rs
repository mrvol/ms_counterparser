use std::net::IpAddr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::Config;
use crate::state::now_secs;

type HmacSha256 = Hmac<Sha256>;

/// Issues a signed `ip|expiry` token for the JS challenge cookie. A client that stores and
/// replays this cookie proves it executed JavaScript (real bots that skip JS rendering never
/// see it), and the signature/expiry/IP binding stop it from being forged or replayed elsewhere.
pub fn issue(config: &Config, ip: IpAddr) -> String {
    let expiry = now_secs() + config.challenge.cookie_ttl_secs as i64;
    let payload = format!("{ip}|{expiry}");
    let sig = sign(config, &payload);
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&payload),
        URL_SAFE_NO_PAD.encode(sig)
    )
}

/// Verifies a cookie value against the expected `ip`, checking signature, expiry, and IP match.
pub fn verify(config: &Config, ip: IpAddr, cookie_value: &str) -> bool {
    let Some((payload_b64, sig_b64)) = cookie_value.split_once('.') else {
        return false;
    };
    let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(payload_b64) else {
        return false;
    };
    let Ok(payload) = String::from_utf8(payload_bytes) else {
        return false;
    };
    let Ok(given_sig) = URL_SAFE_NO_PAD.decode(sig_b64) else {
        return false;
    };

    let expected_sig = sign(config, &payload);
    if expected_sig.ct_eq(&given_sig).unwrap_u8() != 1 {
        return false;
    }

    let Some((payload_ip, expiry)) = payload.split_once('|') else {
        return false;
    };
    let Ok(expiry) = expiry.parse::<i64>() else {
        return false;
    };
    if now_secs() > expiry {
        return false;
    }

    payload_ip == ip.to_string()
}

fn sign(config: &Config, payload: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(config.challenge.hmac_secret.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(payload.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ChallengeConfig, ServerConfig, ThresholdsConfig, WhitelistConfig};
    use std::collections::HashMap;

    fn test_config(secret: &str) -> Config {
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
                hmac_secret: secret.to_string(),
            },
        }
    }

    #[test]
    fn valid_token_verifies() {
        let cfg = test_config("secret1");
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let token = issue(&cfg, ip);
        assert!(verify(&cfg, ip, &token));
    }

    #[test]
    fn wrong_ip_fails() {
        let cfg = test_config("secret1");
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let other: IpAddr = "9.9.9.9".parse().unwrap();
        let token = issue(&cfg, ip);
        assert!(!verify(&cfg, other, &token));
    }

    #[test]
    fn tampered_token_fails() {
        let cfg = test_config("secret1");
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let mut token = issue(&cfg, ip);
        token.push('x');
        assert!(!verify(&cfg, ip, &token));
    }

    #[test]
    fn expired_token_fails() {
        let mut cfg = test_config("secret1");
        cfg.challenge.cookie_ttl_secs = 0;
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let token = issue(&cfg, ip);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(!verify(&cfg, ip, &token));
    }

    #[test]
    fn wrong_secret_fails() {
        let cfg1 = test_config("secret1");
        let cfg2 = test_config("secret2");
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let token = issue(&cfg1, ip);
        assert!(!verify(&cfg2, ip, &token));
    }

    #[test]
    fn garbage_input_fails() {
        let cfg = test_config("secret1");
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(!verify(&cfg, ip, "not-a-valid-token"));
        assert!(!verify(&cfg, ip, ""));
    }
}
