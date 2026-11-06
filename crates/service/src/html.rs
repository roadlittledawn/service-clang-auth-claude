//! Server-rendered HTML pages. Deliberately tiny: no JavaScript at all, and
//! one external stylesheet so the CSP can forbid inline code.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

pub const STYLESHEET: &str = include_str!("../static/style.css");

/// `Content-Security-Policy` for every HTML page: nothing may load except
/// our own stylesheet; no scripts at all; no framing.
pub const CSP: &str =
    "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'";

/// Escape text for use in HTML element content and quoted attributes.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Wrap `body` in the page layout and attach the security headers.
pub fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · clang-auth</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<main class="card">
{body}
</main>
</body>
</html>
"#,
        title = esc(title),
    );
    let mut res = (status, html).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn csrf_field(csrf: &str) -> String {
    format!(r#"<input type="hidden" name="csrf" value="{}">"#, esc(csrf))
}

fn error_box(error: Option<&str>) -> String {
    error.map_or_else(String::new, |e| {
        format!(r#"<p class="error" role="alert">{}</p>"#, esc(e))
    })
}

pub fn login(
    status: StatusCode,
    redirect_uri: Option<&str>,
    email: &str,
    error: Option<&str>,
    csrf: &str,
) -> Response {
    let body = format!(
        r#"<h1>Sign in</h1>
{error}
<form method="post" action="/login">
{csrf}
<input type="hidden" name="redirect_uri" value="{redirect}">
<label>Email <input type="email" name="email" value="{email}" autocomplete="username" required autofocus></label>
<label>Password <input type="password" name="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button>
</form>"#,
        error = error_box(error),
        csrf = csrf_field(csrf),
        redirect = esc(redirect_uri.unwrap_or("")),
        email = esc(email),
    );
    page(status, "Sign in", &body)
}

fn logout_form(csrf: &str) -> String {
    format!(
        r#"<form method="post" action="/logout">{}<button type="submit" class="secondary">Sign out</button></form>"#,
        csrf_field(csrf)
    )
}

fn who(email: &str, name: Option<&str>) -> String {
    match name {
        Some(n) => format!("<strong>{}</strong> ({})", esc(n), esc(email)),
        None => format!("<strong>{}</strong>", esc(email)),
    }
}

/// `/` when signed in. `apps` is (name, first origin) for each granted app.
pub fn home(
    email: &str,
    name: Option<&str>,
    apps: &[(String, Option<String>)],
    csrf: &str,
) -> Response {
    let list = if apps.is_empty() {
        "<p>You don't have access to any apps yet.</p>".to_string()
    } else {
        let items: String = apps
            .iter()
            .map(|(n, o)| match o {
                Some(o) => format!(r#"<li><a href="{}">{}</a></li>"#, esc(o), esc(n)),
                None => format!("<li>{}</li>", esc(n)),
            })
            .collect();
        format!("<p>Your apps:</p><ul>{items}</ul>")
    };
    let body = format!(
        "<h1>Signed in</h1><p>Signed in as {}.</p>{list}{}",
        who(email, name),
        logout_form(csrf)
    );
    page(StatusCode::OK, "Signed in", &body)
}

pub fn home_signed_out() -> Response {
    page(
        StatusCode::OK,
        "clang-auth",
        r#"<h1>clang-auth</h1><p>You are not signed in.</p><p><a class="button" href="/login">Sign in</a></p>"#,
    )
}

pub fn no_access(app_name: &str, email: &str, name: Option<&str>, csrf: &str) -> Response {
    let body = format!(
        r#"<h1>No access</h1><p>You don't have access to {app}.</p><p>Signed in as {who}. Ask the administrator to grant you access.</p><p><a href="/">Go to your account</a></p>{logout}"#,
        app = esc(app_name),
        who = who(email, name),
        logout = logout_form(csrf),
    );
    page(StatusCode::FORBIDDEN, "No access", &body)
}

pub fn setup(
    status: StatusCode,
    token: &str,
    reset: bool,
    email: &str,
    error: Option<&str>,
    csrf: &str,
) -> Response {
    let heading = if reset {
        "Reset your password"
    } else {
        "Set your password"
    };
    let body = format!(
        r#"<h1>{heading}</h1>
<p>For {email}. Use at least 12 characters; a passphrase works well.</p>
{error}
<form method="post" action="/setup">
{csrf}
<input type="hidden" name="token" value="{token}">
<input type="text" name="username" value="{email}" autocomplete="username" hidden>
<label>New password <input type="password" name="password" autocomplete="new-password" minlength="12" maxlength="128" required autofocus></label>
<label>Confirm password <input type="password" name="password_confirm" autocomplete="new-password" minlength="12" maxlength="128" required></label>
<button type="submit">Save password</button>
</form>"#,
        email = esc(email),
        error = error_box(error),
        csrf = csrf_field(csrf),
        token = esc(token),
    );
    page(status, heading, &body)
}

pub fn message(status: StatusCode, title: &str, text: &str) -> Response {
    let body = format!(
        r#"<h1>{}</h1><p>{}</p><p><a href="/">Home</a></p>"#,
        esc(title),
        esc(text)
    );
    page(status, title, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes() {
        assert_eq!(
            esc(r#"<a href="x">'&'</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&#x27;&amp;&#x27;&lt;/a&gt;"
        );
    }
}
