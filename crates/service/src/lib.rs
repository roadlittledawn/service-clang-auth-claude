//! clang-auth HTTP service.
//!
//! [`router`] builds the axum router that runs both as a local server
//! (`main.rs`, plain tokio) and inside AWS Lambda (via `lambda_http`).

pub mod client;
pub mod config;
pub mod cookies;
pub mod error;
pub mod html;
pub mod logging;
pub mod routes;
pub mod security;
pub mod seed;
pub mod state;

use axum::{
    http::{header, HeaderValue},
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use tower::ServiceBuilder;

use crate::{
    error::ApiError,
    routes::{admin, api, browser},
    state::AppState,
};

pub use config::Config;
pub use state::AppState as State;

/// Build the full application router.
pub fn router(state: AppState) -> Router {
    let mut admin_routes = Router::new()
        .route("/admin/apps", get(admin::list_apps).post(admin::create_app))
        .route(
            "/admin/apps/{slug}",
            get(admin::get_app)
                .patch(admin::update_app)
                .delete(admin::delete_app),
        )
        .route(
            "/admin/users",
            get(admin::list_users).post(admin::create_user),
        )
        .route(
            "/admin/users/{id}",
            get(admin::get_user)
                .patch(admin::update_user)
                .delete(admin::delete_user),
        )
        .route("/admin/users/{id}/reset", post(admin::reset_user))
        .route(
            "/admin/users/{id}/grants/{slug}",
            put(admin::set_grant).delete(admin::remove_grant),
        )
        .route("/admin/users/{id}/sessions", delete(admin::revoke_sessions));
    if state.config.allow_token_mint {
        admin_routes = admin_routes.route("/admin/tokens", post(admin::mint_token));
    }
    // `route_layer` only wraps matched routes, so unknown paths (including
    // /admin/tokens when minting is disabled) are a plain 404.
    let admin_routes = admin_routes.route_layer(middleware::from_fn_with_state(
        state.clone(),
        admin::require_admin,
    ));

    Router::new()
        .route("/", get(browser::home))
        .route(
            "/login",
            get(browser::login_form).post(browser::login_submit),
        )
        .route("/logout", post(browser::logout).options(api::preflight))
        .route(
            "/setup",
            get(browser::setup_form).post(browser::setup_submit),
        )
        .route(
            "/api/session/refresh",
            post(api::refresh).options(api::preflight),
        )
        .route("/api/me", get(api::me).options(api::preflight))
        .route("/.well-known/jwks.json", get(api::jwks))
        .route("/health", get(api::health))
        .route("/static/style.css", get(browser::stylesheet))
        .merge(admin_routes)
        .fallback(|| async { ApiError::not_found("No such route") })
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn(logging::request_logger))
                .layer(axum::middleware::map_response(
                    |mut res: axum::response::Response| async move {
                        res.headers_mut().insert(
                            header::X_CONTENT_TYPE_OPTIONS,
                            HeaderValue::from_static("nosniff"),
                        );
                        res
                    },
                )),
        )
        .with_state(state)
}
