//! CSRF origin checks and CORS (spec §4.3, §6.1).

use axum::http::{header, HeaderMap, HeaderValue};
use clang_auth_core::origin::origin_of;

use crate::{cookies, state::AppState};

/// Where a state-changing request came from, as far as the browser tells us.
fn request_origin(headers: &HeaderMap) -> Option<String> {
    let header_origin = |name| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
    };
    match header_origin(header::ORIGIN) {
        // `Origin: null` is sent for opaque origins (sandboxed iframes, file://)
        // and, importantly, for form posts from pages with
        // `Referrer-Policy: no-referrer` (ours). Treat it as "unknown".
        Some(o) if o != "null" => Some(origin_of(o).unwrap_or_else(|| o.to_string())),
        _ => header_origin(header::REFERER).and_then(origin_of),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CsrfVerdict {
    /// Origin/Referer is the auth host or a registered app.
    Trusted(String),
    /// No usable origin, but the form carried a valid double-submit token.
    TokenOk,
    Rejected,
}

/// CSRF check for state-changing POSTs.
///
/// 1. If the browser reports an origin (via `Origin`, or `Referer` when
///    `Origin` is missing), it must be the auth host or a registered app
///    origin. A foreign origin is always rejected.
/// 2. If the browser reports no origin (`Origin: null`, which our own forms
///    produce because of `Referrer-Policy: no-referrer`), the form must echo
///    the `ca_csrf` cookie in its `csrf` field. That cookie is
///    `SameSite=Strict`, so a cross-site page cannot make the browser send it.
pub async fn csrf_check(
    state: &AppState,
    headers: &HeaderMap,
    form_token: Option<&str>,
) -> CsrfVerdict {
    if let Some(origin) = request_origin(headers) {
        return match state.is_trusted_origin(&origin).await {
            Ok(true) => CsrfVerdict::Trusted(origin),
            _ => CsrfVerdict::Rejected,
        };
    }
    match (cookies::get(headers, cookies::CSRF), form_token) {
        (Some(cookie), Some(field)) if !cookie.is_empty() && constant_eq(&cookie, field) => {
            CsrfVerdict::TokenOk
        }
        _ => CsrfVerdict::Rejected,
    }
}

fn constant_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// If the request's `Origin` is a registered app origin, return it.
/// CORS is only ever granted to registered app origins.
pub async fn cors_origin(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::ORIGIN)?.to_str().ok()?;
    let origin = origin_of(raw)?;
    match state.is_app_origin(&origin).await {
        Ok(true) => Some(origin),
        _ => None,
    }
}

/// Add CORS response headers for an allowed origin.
pub fn apply_cors(headers: &mut HeaderMap, origin: &str) {
    if let Ok(v) = HeaderValue::from_str(origin) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
}

/// Responses vary by `Origin`, so caches must key on it.
pub fn vary_origin(headers: &mut HeaderMap) {
    headers.append(header::VARY, HeaderValue::from_static("Origin"));
}
