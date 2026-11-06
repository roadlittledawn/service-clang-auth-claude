//! Browser-facing pages: `/`, `/login`, `/logout`, `/setup` (spec §4).

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Form,
};
use chrono::Utc;
use clang_auth_core::{
    model::{normalize_email, App, InvitePurpose, Session, User},
    origin::parse_redirect,
    password,
    secret::random_token,
};
use serde::Deserialize;

use crate::{
    client::ClientInfo,
    cookies, html,
    security::{apply_cors, cors_origin, csrf_check, vary_origin, CsrfVerdict},
    state::AppState,
};

pub const GENERIC_LOGIN_ERROR: &str = "Invalid email or password";

/// An error while rendering a page: logged, shown as a generic 500 page.
pub struct PageError;

impl<E: std::fmt::Display> From<E> for PageError {
    fn from(e: E) -> Self {
        tracing::error!(error = %e, "request failed");
        PageError
    }
}

impl IntoResponse for PageError {
    fn into_response(self) -> Response {
        html::message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            "Please try again in a moment.",
        )
    }
}

type PageResult = Result<Response, PageError>;

/// A validated redirect target and the app it belongs to.
#[derive(Default)]
pub struct Target {
    pub url: Option<String>,
    pub app: Option<App>,
}

/// Validate `redirect_uri` (spec §4.2): it must be an absolute URL whose
/// origin exactly equals a registered app origin. Anything else falls back
/// to the auth home page.
pub async fn resolve_target(
    state: &AppState,
    raw: Option<&str>,
) -> clang_auth_core::Result<Target> {
    let Some(parsed) = raw.and_then(|r| parse_redirect(r, state.config.allow_insecure_origins))
    else {
        return Ok(Target::default());
    };
    Ok(match state.store.app_for_origin(&parsed.origin).await? {
        Some(app) => Target {
            url: Some(parsed.url),
            app: Some(app),
        },
        None => Target::default(),
    })
}

pub struct Current {
    pub token: String,
    pub session: Session,
    pub user: User,
}

/// Look up and slide the session named by the `ca_session` cookie.
pub async fn current_session(
    state: &AppState,
    headers: &HeaderMap,
) -> clang_auth_core::Result<Option<Current>> {
    let Some(token) = cookies::get(headers, cookies::SESSION) else {
        return Ok(None);
    };
    Ok(state
        .store
        .use_session(&token, state.config.session_ttl)
        .await?
        .map(|(session, user)| Current {
            token,
            session,
            user,
        }))
}

fn seconds_until(t: chrono::DateTime<Utc>) -> i64 {
    (t - Utc::now()).num_seconds().max(0)
}

/// Reuse the visitor's CSRF cookie or mint a new one.
fn csrf_token(headers: &HeaderMap) -> (String, bool) {
    match cookies::get(headers, cookies::CSRF) {
        Some(t) if t.len() >= 32 => (t, false),
        _ => (random_token(32), true),
    }
}

fn with_cookies(mut res: Response, cookies: impl IntoIterator<Item = HeaderValue>) -> Response {
    for c in cookies {
        res.headers_mut().append(header::SET_COOKIE, c);
    }
    res
}

/// A `302 Found` redirect.
pub fn found(location: &str) -> Response {
    let mut res = StatusCode::FOUND.into_response();
    let loc = HeaderValue::from_str(location).unwrap_or_else(|_| HeaderValue::from_static("/"));
    res.headers_mut().insert(header::LOCATION, loc);
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// The response once we know who the user is: set both cookies, then either
/// redirect to the target or show "no access" when the user has no grant.
fn signed_in(
    state: &AppState,
    user: &User,
    session_token: &str,
    session: &Session,
    target: &Target,
    headers: &HeaderMap,
) -> PageResult {
    let (jwt, _) = state.issue_access_token(user)?;
    let set = [
        cookies::session(
            &state.config,
            session_token,
            seconds_until(session.expires_at),
        ),
        cookies::access(&state.config, &jwt),
    ];
    if let Some(app) = &target.app {
        if user.grant(&app.slug).is_none() {
            tracing::info!(event = "access_denied", user_id = %user.id, app = %app.slug);
            let (csrf, new) = csrf_token(headers);
            let res = html::no_access(&app.name, &user.email, user.name.as_deref(), &csrf);
            let extra = new.then(|| cookies::csrf(&state.config, &csrf));
            return Ok(with_cookies(res, set.into_iter().chain(extra)));
        }
    }
    Ok(with_cookies(
        found(target.url.as_deref().unwrap_or("/")),
        set,
    ))
}

fn login_page(
    state: &AppState,
    headers: &HeaderMap,
    status: StatusCode,
    target: &Target,
    email: &str,
    error: Option<&str>,
) -> Response {
    let (csrf, new) = csrf_token(headers);
    let res = html::login(status, target.url.as_deref(), email, error, &csrf);
    with_cookies(res, new.then(|| cookies::csrf(&state.config, &csrf)))
}

// ------------------------------------------------------------------- GET /

pub async fn home(State(state): State<AppState>, headers: HeaderMap) -> PageResult {
    let Some(cur) = current_session(&state, &headers).await? else {
        let res = html::home_signed_out();
        return Ok(if cookies::get(&headers, cookies::SESSION).is_some() {
            with_cookies(res, cookies::clear_auth(&state.config))
        } else {
            res
        });
    };
    let mut apps = Vec::new();
    for g in &cur.user.grants {
        let app = state.store.get_app(&g.app).await?;
        apps.push(match app {
            Some(a) => (a.name.clone(), a.origins.first().cloned()),
            None => (g.app.clone(), None),
        });
    }
    let (csrf, new) = csrf_token(&headers);
    let res = html::home(&cur.user.email, cur.user.name.as_deref(), &apps, &csrf);
    let refresh = cookies::session(
        &state.config,
        &cur.token,
        seconds_until(cur.session.expires_at),
    );
    Ok(with_cookies(
        res,
        std::iter::once(refresh).chain(new.then(|| cookies::csrf(&state.config, &csrf))),
    ))
}

// -------------------------------------------------------------- GET /login

#[derive(Deserialize, Default)]
pub struct RedirectQuery {
    pub redirect_uri: Option<String>,
}

pub async fn login_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RedirectQuery>,
) -> PageResult {
    let target = resolve_target(&state, q.redirect_uri.as_deref()).await?;
    if let Some(cur) = current_session(&state, &headers).await? {
        // Already signed in: skip the form, issue a fresh access token.
        return signed_in(
            &state,
            &cur.user,
            &cur.token,
            &cur.session,
            &target,
            &headers,
        );
    }
    let res = login_page(&state, &headers, StatusCode::OK, &target, "", None);
    Ok(if cookies::get(&headers, cookies::SESSION).is_some() {
        with_cookies(res, cookies::clear_auth(&state.config))
    } else {
        res
    })
}

// ------------------------------------------------------------- POST /login

#[derive(Deserialize)]
pub struct LoginForm {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub password: String,
    pub redirect_uri: Option<String>,
    pub csrf: Option<String>,
}

fn forbidden_csrf() -> Response {
    html::message(
        StatusCode::FORBIDDEN,
        "Request blocked",
        "This request did not come from a trusted page. Go back, reload, and try again.",
    )
}

pub async fn login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    client: ClientInfo,
    Form(form): Form<LoginForm>,
) -> PageResult {
    if csrf_check(&state, &headers, form.csrf.as_deref()).await == CsrfVerdict::Rejected {
        tracing::warn!(event = "csrf_rejected", path = "/login");
        return Ok(forbidden_csrf());
    }
    let target = resolve_target(&state, form.redirect_uri.as_deref()).await?;
    let email = normalize_email(&form.email);
    let cfg = &state.config;
    let fail = |state: &AppState| {
        login_page(
            state,
            &headers,
            StatusCode::UNAUTHORIZED,
            &target,
            &email,
            Some(GENERIC_LOGIN_ERROR),
        )
    };

    // Rate limiting (spec §11): checked before the password, so even the
    // correct password is refused while a key is over its limit.
    let email_key = format!("email:{email}");
    let ip_key = client.ip.as_ref().map(|ip| format!("ip:{ip}"));
    let mut limited = state.store.failure_count(&email_key).await? >= cfg.rate_limit_email;
    if let (false, Some(k)) = (limited, &ip_key) {
        limited = state.store.failure_count(k).await? >= cfg.rate_limit_ip;
    }
    if limited {
        tracing::info!(event = "login_failure", reason = "rate_limited", email = %email);
        return Ok(fail(&state));
    }

    let user = if email.is_empty() {
        None
    } else {
        state.store.find_user_by_email(&email).await?
    };
    let params = cfg.argon2;
    let pw = form.password.clone();
    let (verified, reason) = match &user {
        Some(u) => match (&u.password_hash, u.is_active()) {
            (Some(hash), active) => {
                let hash = hash.clone();
                let ok = tokio::task::spawn_blocking(move || password::verify(&pw, &hash)).await?;
                match (ok, active) {
                    (true, true) => (true, ""),
                    (true, false) => (false, "disabled"),
                    (false, _) => (false, "wrong_credentials"),
                }
            }
            (None, _) => {
                tokio::task::spawn_blocking(move || password::verify_dummy(&pw, params)).await?;
                (false, "setup_incomplete")
            }
        },
        None => {
            tokio::task::spawn_blocking(move || password::verify_dummy(&pw, params)).await?;
            (false, "unknown_email")
        }
    };

    let user = match (verified, user) {
        (true, Some(u)) => u,
        _ => {
            state
                .store
                .record_failure(&email_key, cfg.rate_limit_window)
                .await?;
            if let Some(k) = &ip_key {
                state.store.record_failure(k, cfg.rate_limit_window).await?;
            }
            tracing::info!(event = "login_failure", reason, email = %email);
            return Ok(fail(&state));
        }
    };

    let (token, session) = state
        .store
        .create_session(
            user.id,
            cfg.session_ttl,
            cfg.session_max_ttl,
            client.user_agent,
            client.ip,
        )
        .await?;
    tracing::info!(event = "login_success", user_id = %user.id, app = target.app.as_ref().map(|a| a.slug.as_str()));
    signed_in(&state, &user, &token, &session, &target, &headers)
}

// ------------------------------------------------------------ POST /logout

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RedirectQuery>,
    body: Bytes,
) -> PageResult {
    // Accept an empty body (fetch-style logout) as well as a form post.
    let mut redirect_uri = q.redirect_uri;
    let mut csrf = None;
    for (k, v) in url::form_urlencoded::parse(&body) {
        match k.as_ref() {
            "redirect_uri" => redirect_uri = Some(v.into_owned()),
            "csrf" => csrf = Some(v.into_owned()),
            _ => {}
        }
    }
    if csrf_check(&state, &headers, csrf.as_deref()).await == CsrfVerdict::Rejected {
        tracing::warn!(event = "csrf_rejected", path = "/logout");
        return Ok(forbidden_csrf());
    }
    if let Some(token) = cookies::get(&headers, cookies::SESSION) {
        if let Some((session, _)) = state
            .store
            .use_session(&token, state.config.session_ttl)
            .await?
        {
            tracing::info!(event = "logout", user_id = %session.user_id);
        }
        state.store.delete_session(&token).await?;
    }
    let clear = cookies::clear_auth(&state.config);

    // fetch()/XHR callers ask for JSON and get CORS headers; forms get a redirect.
    let wants_json = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("application/json"));
    if wants_json {
        let mut res = (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "status": "signed_out" })),
        )
            .into_response();
        if let Some(origin) = cors_origin(&state, &headers).await {
            apply_cors(res.headers_mut(), &origin);
        }
        vary_origin(res.headers_mut());
        res.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return Ok(with_cookies(res, clear));
    }
    let target = resolve_target(&state, redirect_uri.as_deref()).await?;
    Ok(with_cookies(
        found(target.url.as_deref().unwrap_or("/")),
        clear,
    ))
}

// -------------------------------------------------------------- /setup

#[derive(Deserialize)]
pub struct SetupQuery {
    #[serde(default)]
    pub token: String,
}

fn invalid_link() -> Response {
    html::message(
        StatusCode::BAD_REQUEST,
        "Link expired or invalid",
        "This link has already been used, has expired, or was replaced by a newer one. Ask the administrator for a new link.",
    )
}

pub async fn setup_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SetupQuery>,
) -> PageResult {
    let Some(invite) = state.store.peek_invite(&q.token).await? else {
        return Ok(invalid_link());
    };
    let Some(user) = state
        .store
        .get_user(invite.user_id)
        .await?
        .filter(User::is_active)
    else {
        return Ok(invalid_link());
    };
    let (csrf, new) = csrf_token(&headers);
    let res = html::setup(
        StatusCode::OK,
        &q.token,
        invite.purpose == InvitePurpose::Reset,
        &user.email,
        None,
        &csrf,
    );
    Ok(with_cookies(
        res,
        new.then(|| cookies::csrf(&state.config, &csrf)),
    ))
}

#[derive(Deserialize)]
pub struct SetupForm {
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub password: String,
    pub password_confirm: Option<String>,
    pub csrf: Option<String>,
}

pub async fn setup_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    client: ClientInfo,
    Form(form): Form<SetupForm>,
) -> PageResult {
    if csrf_check(&state, &headers, form.csrf.as_deref()).await == CsrfVerdict::Rejected {
        tracing::warn!(event = "csrf_rejected", path = "/setup");
        return Ok(forbidden_csrf());
    }
    let Some(invite) = state.store.peek_invite(&form.token).await? else {
        return Ok(invalid_link());
    };
    let Some(user) = state
        .store
        .get_user(invite.user_id)
        .await?
        .filter(User::is_active)
    else {
        return Ok(invalid_link());
    };
    let reset = invite.purpose == InvitePurpose::Reset;
    let problem = match password::check_policy(&form.password) {
        Err(clang_auth_core::Error::Invalid(msg)) => Some(msg),
        Err(e) => return Err(e.into()),
        Ok(())
            if form
                .password_confirm
                .as_deref()
                .is_some_and(|c| c != form.password) =>
        {
            Some("The passwords don't match.".to_string())
        }
        Ok(()) => None,
    };
    if let Some(msg) = problem {
        let (csrf, _) = csrf_token(&headers);
        return Ok(html::setup(
            StatusCode::BAD_REQUEST,
            &form.token,
            reset,
            &user.email,
            Some(&msg),
            &csrf,
        ));
    }

    let params = state.config.argon2;
    let pw = form.password.clone();
    let phc = tokio::task::spawn_blocking(move || password::hash(&pw, params)).await??;
    // Consume atomically *after* the slow hash, so a double submit can only
    // succeed once.
    if state.store.consume_invite(&form.token).await?.is_none() {
        return Ok(invalid_link());
    }
    state.store.set_password_hash(user.id, &phc).await?;
    // A reset must kick out anyone holding an old session (spec §4.5).
    let revoked = state.store.revoke_user_sessions(user.id).await?;
    tracing::info!(event = "invite_used", user_id = %user.id, purpose = if reset { "reset" } else { "setup" }, sessions_revoked = revoked);

    let cfg = &state.config;
    let (token, session) = state
        .store
        .create_session(
            user.id,
            cfg.session_ttl,
            cfg.session_max_ttl,
            client.user_agent,
            client.ip,
        )
        .await?;
    tracing::info!(event = "login_success", user_id = %user.id, via = "setup");
    signed_in(
        &state,
        &user,
        &token,
        &session,
        &Target::default(),
        &headers,
    )
}

// ------------------------------------------------------------ static files

pub async fn stylesheet() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        html::STYLESHEET,
    )
        .into_response()
}
