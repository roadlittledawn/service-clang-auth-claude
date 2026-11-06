//! Cookie reading and `Set-Cookie` construction (spec §5).
//!
//! Written by hand rather than with a cookie crate so every attribute is
//! visible in one place.

use axum::http::{header, HeaderMap, HeaderValue};

use crate::config::Config;

pub const SESSION: &str = "ca_session";
pub const ACCESS: &str = "ca_access";
/// Double-submit token for forms on the auth host; see `security::csrf`.
pub const CSRF: &str = "ca_csrf";

/// Read a cookie value from the request's `Cookie` header(s).
pub fn get(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
}

pub enum SameSite {
    Lax,
    Strict,
}

struct Spec<'a> {
    name: &'a str,
    value: &'a str,
    domain: Option<&'a str>,
    max_age: i64,
    same_site: SameSite,
}

fn build(cfg: &Config, s: Spec<'_>) -> HeaderValue {
    let mut c = format!(
        "{}={}; Path=/; Max-Age={}; HttpOnly",
        s.name,
        s.value,
        s.max_age.max(0)
    );
    if let Some(d) = s.domain {
        c.push_str("; Domain=");
        c.push_str(d);
    }
    if cfg.cookie_secure {
        c.push_str("; Secure");
    }
    c.push_str(match s.same_site {
        SameSite::Lax => "; SameSite=Lax",
        SameSite::Strict => "; SameSite=Strict",
    });
    HeaderValue::from_str(&c).expect("cookie is valid header")
}

/// Host-only session cookie, readable only by the auth host.
pub fn session(cfg: &Config, token: &str, max_age_secs: i64) -> HeaderValue {
    build(
        cfg,
        Spec {
            name: SESSION,
            value: token,
            domain: None,
            max_age: max_age_secs,
            same_site: SameSite::Lax,
        },
    )
}

/// Access-token cookie, scoped to the parent domain so every app receives it.
pub fn access(cfg: &Config, jwt: &str) -> HeaderValue {
    let max_age = cfg.access_token_ttl.as_secs() as i64;
    build(
        cfg,
        Spec {
            name: ACCESS,
            value: jwt,
            domain: Some(&cfg.cookie_domain),
            max_age,
            same_site: SameSite::Lax,
        },
    )
}

pub fn csrf(cfg: &Config, token: &str) -> HeaderValue {
    build(
        cfg,
        Spec {
            name: CSRF,
            value: token,
            domain: None,
            max_age: 3600 * 12,
            same_site: SameSite::Strict,
        },
    )
}

/// `Set-Cookie` headers that delete both auth cookies. Attributes must match
/// the originals (notably `Domain`) or the browser keeps the old cookie.
pub fn clear_auth(cfg: &Config) -> [HeaderValue; 2] {
    [
        build(
            cfg,
            Spec {
                name: SESSION,
                value: "",
                domain: None,
                max_age: 0,
                same_site: SameSite::Lax,
            },
        ),
        build(
            cfg,
            Spec {
                name: ACCESS,
                value: "",
                domain: Some(&cfg.cookie_domain),
                max_age: 0,
                same_site: SameSite::Lax,
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_cookie() {
        let mut h = HeaderMap::new();
        h.append(header::COOKIE, "a=1; ca_session=abc".parse().unwrap());
        h.append(header::COOKIE, "ca_access=xyz".parse().unwrap());
        assert_eq!(get(&h, "ca_session").as_deref(), Some("abc"));
        assert_eq!(get(&h, "ca_access").as_deref(), Some("xyz"));
        assert_eq!(get(&h, "missing"), None);
    }
}
