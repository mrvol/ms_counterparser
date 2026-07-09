use std::net::IpAddr;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Json;
use axum::Router;

use crate::analyze::analyze;
use crate::challenge;
use crate::responses;
use crate::state::{Stats, Verdict};
use crate::Shared;

pub fn router(shared: Shared) -> Router {
    Router::new()
        .route("/check", get(check))
        .route("/respond", get(respond))
        .route("/healthz", get(healthz))
        // Aggregate-only (no per-IP data); not wired into nginx, so it's reachable only
        // by whoever can already talk to the daemon's unix socket directly.
        .route("/stats", get(stats))
        .with_state(shared)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn stats(State(shared): State<Shared>) -> Json<Stats> {
    Json(shared.state.stats())
}

/// Hit by nginx's `auth_request`. Body is discarded by nginx — only the status matters.
async fn check(State(shared): State<Shared>, headers: HeaderMap) -> StatusCode {
    let Some(ip) = extract_ip(&headers) else {
        tracing::warn!("check: missing/unparseable X-Real-IP header");
        return StatusCode::FORBIDDEN;
    };

    let cookie = extract_cookie(&headers, &shared.state.config.challenge.cookie_name);
    let verdict = analyze(
        shared.resolver.as_ref(),
        &shared.state,
        ip,
        cookie.as_deref(),
    )
    .await;
    shared.state.record_verdict(ip, &verdict);
    shared.state.verdicts.insert(ip, verdict.clone());

    match verdict {
        Verdict::Allow => StatusCode::NO_CONTENT,
        Verdict::Cooldown { .. } | Verdict::Challenge => StatusCode::FORBIDDEN,
    }
}

/// Hit via nginx's `error_page 403 = @respond` internal redirect. Always answers 200 so the
/// client sees a harmless page instead of an obvious block.
async fn respond(State(shared): State<Shared>, headers: HeaderMap) -> impl IntoResponse {
    let Some(ip) = extract_ip(&headers) else {
        return (StatusCode::OK, Html(responses::cooldown_body()));
    };

    let verdict = match shared.state.verdicts.get(&ip) {
        Some(v) => v,
        None => {
            let cookie = extract_cookie(&headers, &shared.state.config.challenge.cookie_name);
            analyze(
                shared.resolver.as_ref(),
                &shared.state,
                ip,
                cookie.as_deref(),
            )
            .await
        }
    };

    let body = match verdict {
        Verdict::Challenge => {
            let token = challenge::issue(&shared.state.config, ip);
            responses::challenge_body(&shared.state.config, &token)
        }
        Verdict::Cooldown { .. } | Verdict::Allow => responses::cooldown_body(),
    };

    (StatusCode::OK, Html(body))
}

fn extract_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse().ok())
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|kv| {
        let kv = kv.trim();
        let (k, v) = kv.split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ChallengeConfig, Config, ServerConfig, ThresholdsConfig, WhitelistConfig};
    use crate::dns::tests::FakeResolver;
    use crate::state::AppState;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn test_config() -> Config {
        Config {
            server: ServerConfig {
                socket_path: "/tmp/x.sock".to_string(),
            },
            thresholds: ThresholdsConfig {
                window_secs: 60,
                max_requests_per_window: 2,
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

    fn test_shared() -> Shared {
        Shared {
            state: Arc::new(AppState::new(test_config())),
            resolver: Arc::new(FakeResolver::default()),
        }
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let app = router(test_shared());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn stats_reflects_traffic_through_the_router() {
        let shared = test_shared();
        let app = router(shared);

        let check_req = Request::builder()
            .uri("/check")
            .header("x-real-ip", "203.0.113.5")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(check_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let stats_req = Request::builder()
            .uri("/stats")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(stats_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["total_requests"], 1);
        assert_eq!(json["tracked_ips"], 1);
        assert_eq!(json["verdicts"]["allowed"], 1);
        assert_eq!(json["active_cooldowns"], 0);
    }
}
