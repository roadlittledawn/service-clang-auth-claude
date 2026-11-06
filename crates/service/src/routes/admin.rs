//! Admin API (spec §6.2). Every route requires `Authorization: Bearer <key>`.

use std::collections::BTreeMap;

use axum::{
    extract::{Path, Query, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use clang_auth_core::{
    duration,
    model::{App, InvitePurpose, User, UserStatus},
    origin::normalize_origin,
    secret::verify_sha256_hex,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};

use crate::{
    error::{ApiError, JsonBody},
    state::AppState,
};

type ApiResult<T = Response> = Result<T, ApiError>;

/// Middleware: check the bearer key against `ADMIN_API_KEY_HASH` in
/// constant time. Only the hash is held in memory.
pub async fn require_admin(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    match presented {
        Some(key) if verify_sha256_hex(key, &state.config.admin_key_hash) => next.run(req).await,
        _ => {
            tracing::warn!(event = "admin_auth_failed", path = %req.uri().path());
            let mut res =
                ApiError::unauthorized("Missing or invalid admin API key").into_response();
            res.headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
            res
        }
    }
}

// ----------------------------------------------------------------- views

#[derive(Serialize)]
pub struct AppView {
    pub slug: String,
    pub name: String,
    pub origins: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<App> for AppView {
    fn from(a: App) -> Self {
        Self {
            slug: a.slug,
            name: a.name,
            origins: a.origins,
            created_at: a.created_at,
            updated_at: a.updated_at,
        }
    }
}

#[derive(Serialize)]
pub struct GrantView {
    pub app: String,
    pub roles: Vec<String>,
    pub granted_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct UserView {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub status: UserStatus,
    pub has_password: bool,
    pub grants: Vec<GrantView>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_sessions: Option<u64>,
}

impl From<User> for UserView {
    fn from(u: User) -> Self {
        Self {
            id: u.id.to_hex(),
            email: u.email,
            name: u.name,
            status: u.status,
            has_password: u.password_hash.is_some(),
            grants: u
                .grants
                .into_iter()
                .map(|g| GrantView {
                    app: g.app,
                    roles: g.roles,
                    granted_at: g.granted_at,
                })
                .collect(),
            created_at: u.created_at,
            updated_at: u.updated_at,
            active_sessions: None,
        }
    }
}

fn normalize_origins(state: &AppState, origins: &[String]) -> ApiResult<Vec<String>> {
    origins
        .iter()
        .map(|o| normalize_origin(o, state.config.allow_insecure_origins).map_err(ApiError::from))
        .collect()
}

async fn load_user(state: &AppState, user_ref: &str) -> ApiResult<User> {
    state
        .store
        .find_user(user_ref)
        .await?
        .ok_or_else(|| ApiError::not_found("user not found"))
}

fn link(state: &AppState, token: &str) -> String {
    format!("{}/setup?token={token}", state.config.base_url)
}

// ------------------------------------------------------------------ apps

pub async fn list_apps(State(state): State<AppState>) -> ApiResult<Json<Vec<AppView>>> {
    Ok(Json(
        state
            .store
            .list_apps()
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct CreateApp {
    pub slug: String,
    pub name: String,
    pub origins: Vec<String>,
}

pub async fn create_app(
    State(state): State<AppState>,
    JsonBody(body): JsonBody<CreateApp>,
) -> ApiResult {
    let origins = normalize_origins(&state, &body.origins)?;
    let app = state
        .store
        .create_app(&body.slug, &body.name, origins)
        .await?;
    tracing::info!(event = "app_created", app = %app.slug);
    Ok((StatusCode::CREATED, Json(AppView::from(app))).into_response())
}

pub async fn get_app(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> ApiResult<Json<AppView>> {
    let app = state
        .store
        .get_app(&slug)
        .await?
        .ok_or_else(|| ApiError::not_found("app not found"))?;
    Ok(Json(app.into()))
}

#[derive(Deserialize)]
pub struct UpdateApp {
    pub name: Option<String>,
    pub origins: Option<Vec<String>>,
}

pub async fn update_app(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    JsonBody(body): JsonBody<UpdateApp>,
) -> ApiResult<Json<AppView>> {
    let origins = body
        .origins
        .as_deref()
        .map(|o| normalize_origins(&state, o))
        .transpose()?;
    let app = state
        .store
        .update_app(&slug, body.name.as_deref(), origins)
        .await?;
    tracing::info!(event = "app_updated", app = %app.slug);
    Ok(Json(app.into()))
}

pub async fn delete_app(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> ApiResult<Json<Value>> {
    let users = state.store.delete_app(&slug).await?;
    tracing::info!(event = "app_deleted", app = %slug, grants_removed = users);
    Ok(Json(json!({ "deleted": slug, "grants_removed": users })))
}

// ----------------------------------------------------------------- users

#[derive(Deserialize)]
pub struct UserFilter {
    pub app: Option<String>,
}

pub async fn list_users(
    State(state): State<AppState>,
    Query(f): Query<UserFilter>,
) -> ApiResult<Json<Vec<UserView>>> {
    Ok(Json(
        state
            .store
            .list_users(f.app.as_deref())
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub name: Option<String>,
    #[serde(default)]
    pub grants: BTreeMap<String, Vec<String>>,
}

pub async fn create_user(
    State(state): State<AppState>,
    JsonBody(body): JsonBody<CreateUser>,
) -> ApiResult {
    let grants = body.grants.into_iter().collect();
    let user = state
        .store
        .create_user(&body.email, body.name.as_deref(), grants)
        .await?;
    let (token, invite) = state
        .store
        .create_invite(user.id, InvitePurpose::Setup, state.config.invite_ttl)
        .await?;
    tracing::info!(event = "user_created", user_id = %user.id);
    tracing::info!(event = "invite_created", user_id = %user.id, purpose = "setup");
    let body = json!({ "user": UserView::from(user), "setup_link": link(&state, &token), "expires_at": invite.expires_at });
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

pub async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<UserView>> {
    let user = load_user(&state, &id).await?;
    let sessions = state.store.count_active_sessions(user.id).await?;
    let mut view = UserView::from(user);
    view.active_sessions = Some(sessions);
    Ok(Json(view))
}

/// Distinguish "field absent" (`None`) from "field set to null" (`Some(None)`).
fn double_option<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

#[derive(Deserialize)]
pub struct UpdateUser {
    #[serde(default, deserialize_with = "double_option")]
    pub name: Option<Option<String>>,
    pub status: Option<UserStatus>,
}

pub async fn update_user(
    State(state): State<AppState>,
    Path(id): Path<String>,
    JsonBody(body): JsonBody<UpdateUser>,
) -> ApiResult<Json<UserView>> {
    let user = load_user(&state, &id).await?;
    let name = body.name.as_ref().map(|n| n.as_deref());
    let updated = state.store.update_user(user.id, name, body.status).await?;
    tracing::info!(event = "user_updated", user_id = %user.id, status = ?body.status);
    Ok(Json(updated.into()))
}

pub async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let user = load_user(&state, &id).await?;
    state.store.delete_user(user.id).await?;
    tracing::info!(event = "user_deleted", user_id = %user.id);
    Ok(Json(json!({ "deleted": user.id.to_hex() })))
}

pub async fn reset_user(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let user = load_user(&state, &id).await?;
    let (token, invite) = state
        .store
        .create_invite(user.id, InvitePurpose::Reset, state.config.invite_ttl)
        .await?;
    tracing::info!(event = "invite_created", user_id = %user.id, purpose = "reset");
    Ok(Json(
        json!({ "user_id": user.id.to_hex(), "reset_link": link(&state, &token), "expires_at": invite.expires_at }),
    ))
}

#[derive(Deserialize)]
pub struct SetRoles {
    pub roles: Vec<String>,
}

pub async fn set_grant(
    State(state): State<AppState>,
    Path((id, slug)): Path<(String, String)>,
    JsonBody(body): JsonBody<SetRoles>,
) -> ApiResult<Json<UserView>> {
    let user = load_user(&state, &id).await?;
    let updated = state.store.set_grant(user.id, &slug, &body.roles).await?;
    tracing::info!(event = "grant_set", user_id = %user.id, app = %slug, roles = ?body.roles);
    Ok(Json(updated.into()))
}

pub async fn remove_grant(
    State(state): State<AppState>,
    Path((id, slug)): Path<(String, String)>,
) -> ApiResult<Json<UserView>> {
    let user = load_user(&state, &id).await?;
    let updated = state.store.remove_grant(user.id, &slug).await?;
    tracing::info!(event = "grant_removed", user_id = %user.id, app = %slug);
    Ok(Json(updated.into()))
}

pub async fn revoke_sessions(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let user = load_user(&state, &id).await?;
    let n = state.store.revoke_user_sessions(user.id).await?;
    tracing::info!(event = "sessions_revoked", user_id = %user.id, count = n);
    Ok(Json(json!({ "user_id": user.id.to_hex(), "revoked": n })))
}

// ------------------------------------------------------- dev token mint

#[derive(Deserialize)]
#[serde(untagged)]
pub enum Ttl {
    Seconds(u64),
    Text(String),
}

#[derive(Deserialize)]
pub struct MintToken {
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub ttl: Option<Ttl>,
}

/// `POST /admin/tokens`. Only routed when `ALLOW_TOKEN_MINT=true`;
/// otherwise the path falls through to a 404.
pub async fn mint_token(
    State(state): State<AppState>,
    JsonBody(body): JsonBody<MintToken>,
) -> ApiResult<Json<Value>> {
    let user_ref = body
        .user_id
        .or(body.email)
        .ok_or_else(|| ApiError::bad_request("user_id or email is required"))?;
    let user = load_user(&state, &user_ref).await?;
    if !user.is_active() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "user_disabled",
            "user is disabled",
        ));
    }
    let ttl = match body.ttl {
        None => state.config.access_token_ttl,
        Some(Ttl::Seconds(s)) if s > 0 => std::time::Duration::from_secs(s),
        Some(Ttl::Seconds(_)) => return Err(ApiError::bad_request("ttl must be positive")),
        Some(Ttl::Text(t)) => duration::parse(&t).map_err(ApiError::bad_request)?,
    };
    let claims = state.claims_for(&user, ttl);
    let token = state.keys.sign(&claims)?;
    tracing::info!(event = "token_minted", user_id = %user.id, ttl_secs = ttl.as_secs());
    Ok(Json(json!({ "token": token, "claims": claims })))
}
