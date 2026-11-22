//! `/keys`: self-serve API keys for signed-in users (issue #4).
//!
//! A key belongs to one user and one app and carries a subset of the user's
//! roles there. Scripts and local MCP servers exchange it at `POST /api/token`.

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use chrono::{Duration, Utc};
use clang_auth_core::Error as CoreError;
use serde::Deserialize;

use crate::{
    cookies, html,
    routes::browser::{
        csrf_token, current_session, found, seconds_until, with_cookies, Current, PageResult,
    },
    security::{csrf_check, CsrfVerdict},
    state::AppState,
};

#[derive(Deserialize, Default)]
pub struct KeysQuery {
    pub app: Option<String>,
}

/// CSRF for `/keys` forms. Stricter than the shared check: a registered app
/// origin is *not* enough, only the auth host itself or the double-submit
/// token. No app page should be able to create or revoke a user's keys.
async fn csrf_ok(state: &AppState, headers: &HeaderMap, token: Option<&str>) -> bool {
    match csrf_check(state, headers, token).await {
        CsrfVerdict::Trusted(origin) => origin == state.config.auth_origin,
        CsrfVerdict::TokenOk => true,
        CsrfVerdict::Rejected => false,
    }
}

fn date(t: chrono::DateTime<Utc>) -> String {
    t.format("%Y-%m-%d").to_string()
}

/// Render the page for `cur`. `only_app` limits the create forms to one app.
async fn render(
    state: &AppState,
    headers: &HeaderMap,
    cur: &Current,
    only_app: Option<&str>,
    status: StatusCode,
    new_key: Option<(&str, &str)>,
    error: Option<&str>,
) -> PageResult {
    // Two queries, run together: app names (a handful of apps) and the keys.
    let (apps, keys) = tokio::join!(
        state.store.list_apps(),
        state.store.list_api_keys(Some(cur.user.id), None)
    );
    let names: std::collections::HashMap<String, String> =
        apps?.into_iter().map(|a| (a.slug, a.name)).collect();
    let name_of = |slug: &str| names.get(slug).cloned().unwrap_or_else(|| slug.to_string());

    let rows: Vec<html::KeyRow> = keys?
        .into_iter()
        .map(|k| html::KeyRow {
            id: k.public_id,
            app_name: name_of(&k.app),
            name: k.name,
            roles: k.roles,
            created: date(k.created_at),
            last_used: k.last_used_at.map(date),
            expires: k.expires_at.map(date),
        })
        .collect();
    let only_app = only_app.filter(|a| cur.user.grant(a).is_some());
    let apps: Vec<html::KeyApp> = cur
        .user
        .grants
        .iter()
        .filter(|g| only_app.is_none_or(|a| a == g.app))
        .map(|g| html::KeyApp {
            slug: g.app.clone(),
            name: name_of(&g.app),
            roles: g.roles.clone(),
        })
        .collect();

    let token_url = format!("{}/api/token", state.config.base_url);
    let secs = state.config.access_token_ttl.as_secs();
    let ttl = if secs.is_multiple_of(60) {
        format!("{}-minute", secs / 60)
    } else {
        format!("{secs}-second")
    };
    let new_key = new_key.map(|(raw, app)| html::NewKey {
        raw,
        app_name: names.get(app).map_or(app, String::as_str),
        token_url: &token_url,
        ttl: &ttl,
    });
    let (csrf, fresh) = csrf_token(headers);
    let res = html::keys(status, &cur.user.email, &rows, &apps, new_key, error, &csrf);
    let refresh = cookies::session(
        &state.config,
        &cur.token,
        seconds_until(cur.session.expires_at),
    );
    Ok(with_cookies(
        res,
        std::iter::once(refresh).chain(fresh.then(|| cookies::csrf(&state.config, &csrf))),
    ))
}

fn blocked() -> Response {
    html::message(
        StatusCode::FORBIDDEN,
        "Request blocked",
        "This request did not come from a trusted page. Go back, reload, and try again.",
    )
}

/// `GET /keys[?app=slug]`
pub async fn page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<KeysQuery>,
) -> PageResult {
    let Some(cur) = current_session(&state, &headers).await? else {
        return Ok(found("/login"));
    };
    render(
        &state,
        &headers,
        &cur,
        q.app.as_deref(),
        StatusCode::OK,
        None,
        None,
    )
    .await
}

/// Form fields, parsed by hand because `roles` repeats.
#[derive(Default)]
struct Fields {
    app: String,
    name: String,
    roles: Vec<String>,
    expires: String,
    key_id: String,
    csrf: Option<String>,
}

fn parse(body: &[u8]) -> Fields {
    let mut f = Fields::default();
    for (k, v) in url::form_urlencoded::parse(body) {
        let v = v.into_owned();
        match k.as_ref() {
            "app" => f.app = v,
            "name" => f.name = v,
            "roles" => f.roles.push(v),
            "expires" => f.expires = v,
            "key_id" => f.key_id = v,
            "csrf" => f.csrf = Some(v),
            _ => {}
        }
    }
    f
}

/// `POST /keys`: create a key; the raw key is shown once in the response.
pub async fn create(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> PageResult {
    let f = parse(&body);
    if !csrf_ok(&state, &headers, f.csrf.as_deref()).await {
        tracing::warn!(event = "csrf_rejected", path = "/keys");
        return Ok(blocked());
    }
    let Some(cur) = current_session(&state, &headers).await? else {
        return Ok(found("/login"));
    };
    let days = match f.expires.as_str() {
        "never" => Some(None),
        "30" => Some(Some(30)),
        "90" => Some(Some(90)),
        "365" => Some(Some(365)),
        _ => None,
    };
    let expires_at = match days {
        Some(d) => d.map(|d| Utc::now() + Duration::days(d)),
        None => {
            return render(
                &state,
                &headers,
                &cur,
                None,
                StatusCode::BAD_REQUEST,
                None,
                Some("Choose when the key expires."),
            )
            .await
        }
    };
    match state
        .store
        .create_api_key(cur.user.id, &f.app, &f.name, &f.roles, expires_at)
        .await
    {
        Ok((raw, key)) => {
            tracing::info!(
                event = "api_key_created",
                user_id = %cur.user.id,
                app = %key.app,
                key_id = %key.public_id,
            );
            render(
                &state,
                &headers,
                &cur,
                None,
                StatusCode::OK,
                Some((&raw, &key.app)),
                None,
            )
            .await
        }
        Err(CoreError::Invalid(msg)) => {
            render(
                &state,
                &headers,
                &cur,
                None,
                StatusCode::BAD_REQUEST,
                None,
                Some(&msg),
            )
            .await
        }
        Err(e) => Err(e.into()),
    }
}

/// `POST /keys/revoke`: revoke one of the signed-in user's own keys.
pub async fn revoke(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> PageResult {
    let f = parse(&body);
    if !csrf_ok(&state, &headers, f.csrf.as_deref()).await {
        tracing::warn!(event = "csrf_rejected", path = "/keys/revoke");
        return Ok(blocked());
    }
    let Some(cur) = current_session(&state, &headers).await? else {
        return Ok(found("/login"));
    };
    // Scoped to the session's user, so nobody can revoke someone else's key.
    match state.store.revoke_api_key(cur.user.id, &f.key_id).await {
        Ok(()) => {
            tracing::info!(event = "api_key_revoked", user_id = %cur.user.id, key_id = %f.key_id, by = "user");
            Ok(found("/keys"))
        }
        Err(CoreError::NotFound(_)) => {
            render(
                &state,
                &headers,
                &cur,
                None,
                StatusCode::NOT_FOUND,
                None,
                Some("That key no longer exists."),
            )
            .await
        }
        Err(e) => Err(e.into()),
    }
}
