//! JSON endpoints for apps: refresh, me, JWKS, health (spec §4.3, §6.1).

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;

use crate::{
    cookies,
    error::ApiError,
    routes::browser::current_session,
    security::{apply_cors, cors_origin, csrf_check, vary_origin, CsrfVerdict},
    state::AppState,
};

fn finish(mut res: Response, origin: Option<&str>) -> Response {
    let h = res.headers_mut();
    if let Some(o) = origin {
        apply_cors(h, o);
    }
    vary_origin(h);
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn unauthorized_clearing(state: &AppState, origin: Option<&str>) -> Response {
    let mut res = ApiError::unauthorized("No valid session").into_response();
    for c in cookies::clear_auth(&state.config) {
        res.headers_mut().append(header::SET_COOKIE, c);
    }
    finish(res, origin)
}

/// `POST /api/session/refresh`: called by apps with `credentials: "include"`.
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let origin = cors_origin(&state, &headers).await;
    // State-changing (sets a cookie), so it gets the same CSRF origin check
    // as every other POST. JSON callers have no form token to fall back on.
    if !matches!(
        csrf_check(&state, &headers, None).await,
        CsrfVerdict::Trusted(_)
    ) {
        return Ok(finish(
            ApiError::forbidden("Origin not allowed").into_response(),
            None,
        ));
    }
    let Some(cur) = current_session(&state, &headers).await? else {
        return Ok(unauthorized_clearing(&state, origin.as_deref()));
    };
    let (jwt, claims) = state.issue_access_token(&cur.user)?;
    let mut res = (StatusCode::OK, Json(claims)).into_response();
    let max_age = (cur.session.expires_at - Utc::now()).num_seconds().max(0);
    res.headers_mut()
        .append(header::SET_COOKIE, cookies::access(&state.config, &jwt));
    res.headers_mut().append(
        header::SET_COOKIE,
        cookies::session(&state.config, &cur.token, max_age),
    );
    tracing::debug!(event = "token_refreshed", user_id = %cur.user.id);
    Ok(finish(res, origin.as_deref()))
}

/// `GET /api/me`: the current user's claims, for SPAs with no backend.
pub async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let origin = cors_origin(&state, &headers).await;
    let Some(cur) = current_session(&state, &headers).await? else {
        return Ok(unauthorized_clearing(&state, origin.as_deref()));
    };
    let claims = state.claims_for(&cur.user, state.config.access_token_ttl);
    Ok(finish(
        (StatusCode::OK, Json(claims)).into_response(),
        origin.as_deref(),
    ))
}

/// CORS preflight for the `/api/*` and `/logout` endpoints. Unregistered
/// origins get a bare 204 with no `Access-Control-Allow-*` headers, which the
/// browser treats as a refusal.
pub async fn preflight(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let mut res = StatusCode::NO_CONTENT.into_response();
    if let Some(origin) = cors_origin(&state, &headers).await {
        let h = res.headers_mut();
        apply_cors(h, &origin);
        h.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        h.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, Accept"),
        );
        h.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("600"),
        );
    }
    vary_origin(res.headers_mut());
    res
}

/// `GET /.well-known/jwks.json`
pub async fn jwks(State(state): State<AppState>) -> Response {
    (
        [
            (header::CACHE_CONTROL, "public, max-age=3600"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        Json(state.keys.jwks()),
    )
        .into_response()
}

/// `GET /health`: checks MongoDB connectivity.
pub async fn health(State(state): State<AppState>) -> Response {
    match state.store.ping().await {
        Ok(()) => (
            [(header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({ "status": "ok" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "health check failed");
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "Database is unreachable",
            )
            .into_response()
        }
    }
}
