use std::net::IpAddr;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;

use crate::analyze::analyze;
use crate::challenge;
use crate::responses;
use crate::state::Verdict;
use crate::Shared;

pub fn router(shared: Shared) -> Router {
    Router::new()
        .route("/check", get(check))
        .route("/respond", get(respond))
        .route("/healthz", get(healthz))
        .with_state(shared)
}

async fn healthz() -> &'static str {
    "ok"
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
