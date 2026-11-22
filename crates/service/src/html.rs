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
    page_with_class(status, title, body, "card")
}

/// [`page`] with a different class on the card, e.g. `"card wide"`.
pub fn page_with_class(status: StatusCode, title: &str, body: &str, class: &str) -> Response {
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
<main class="{class}">
{body}
</main>
</body>
</html>
"#,
        title = esc(title),
        class = esc(class),
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
    let keys_link = if apps.is_empty() {
        ""
    } else {
        r#"<p><a href="/keys">API keys</a> <span class="muted">for scripts and local MCP servers</span></p>"#
    };
    let body = format!(
        "<h1>Signed in</h1><p>Signed in as {}.</p>{list}{keys_link}{}",
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

/// One key row on `/keys`.
pub struct KeyRow {
    pub id: String,
    pub app_name: String,
    pub name: String,
    pub roles: Vec<String>,
    pub created: String,
    pub last_used: Option<String>,
    pub expires: Option<String>,
}

/// One "create a key" form on `/keys`: an app the user has a grant for.
pub struct KeyApp {
    pub slug: String,
    pub name: String,
    pub roles: Vec<String>,
}

/// A newly created key, shown exactly once.
pub struct NewKey<'a> {
    pub raw: &'a str,
    pub app_name: &'a str,
    pub token_url: &'a str,
    /// Access-token lifetime, e.g. "15-minute".
    pub ttl: &'a str,
}

fn roles_text(roles: &[String]) -> String {
    if roles.is_empty() {
        "no roles".into()
    } else {
        roles.iter().map(|r| esc(r)).collect::<Vec<_>>().join(", ")
    }
}

/// `/keys`: list the user's API keys and create new ones.
pub fn keys(
    status: StatusCode,
    email: &str,
    keys: &[KeyRow],
    apps: &[KeyApp],
    new_key: Option<NewKey>,
    error: Option<&str>,
    csrf: &str,
) -> Response {
    let created = new_key.map_or_else(String::new, |k| {
        format!(
            r#"<section><h2>New key for {app}</h2>
<p>Copy it now. It won't be shown again.</p>
<code class="secret">{raw}</code>
<p class="muted">Exchange it for a {ttl} access token, then call the app with that token:</p>
<pre>curl -s -X POST {url} \
  -H "Authorization: Bearer $CLANG_AUTH_API_KEY"</pre>
</section>"#,
            app = esc(k.app_name),
            raw = esc(k.raw),
            url = esc(k.token_url),
            ttl = esc(k.ttl),
        )
    });
    let list = if keys.is_empty() {
        "<p>You have no API keys.</p>".to_string()
    } else {
        let items: String = keys
            .iter()
            .map(|k| {
                format!(
                    r#"<li><div><strong>{name}</strong> · {app} · {roles}<br><span class="muted">created {created} · last used {used} · {expires}</span></div>
<form method="post" action="/keys/revoke">{csrf}<input type="hidden" name="key_id" value="{id}"><button type="submit" class="secondary">Revoke</button></form></li>"#,
                    name = esc(&k.name),
                    app = esc(&k.app_name),
                    roles = roles_text(&k.roles),
                    created = esc(&k.created),
                    used = esc(k.last_used.as_deref().unwrap_or("never")),
                    expires = k
                        .expires
                        .as_deref()
                        .map_or("never expires".to_string(), |e| format!("expires {}", esc(e))),
                    csrf = csrf_field(csrf),
                    id = esc(&k.id),
                )
            })
            .collect();
        format!(r#"<ul class="keys">{items}</ul>"#)
    };
    let forms: String = apps
        .iter()
        .map(|a| {
            let roles = if a.roles.is_empty() {
                String::new()
            } else {
                let boxes: String = a
                    .roles
                    .iter()
                    .map(|r| {
                        format!(
                            r#"<label class="check"><input type="checkbox" name="roles" value="{r}"> {r}</label>"#,
                            r = esc(r)
                        )
                    })
                    .collect();
                format!(
                    r#"<fieldset><legend>Roles the key may use (leave unticked for the least access)</legend>{boxes}</fieldset>"#
                )
            };
            format!(
                r#"<section><h2>New key for {name}</h2>
<form method="post" action="/keys">
{csrf}
<input type="hidden" name="app" value="{slug}">
<label>Name <input type="text" name="name" maxlength="64" placeholder="e.g. laptop MCP" required></label>
{roles}
<label>Expires <select name="expires">
<option value="30">in 30 days</option>
<option value="90">in 90 days</option>
<option value="365" selected>in 1 year</option>
<option value="never">never</option>
</select></label>
<button type="submit">Create key</button>
</form></section>"#,
                name = esc(&a.name),
                slug = esc(&a.slug),
                csrf = csrf_field(csrf),
            )
        })
        .collect();
    let body = format!(
        r#"<h1>API keys</h1>
<p>Signed in as {who}. A key lets a script or local MCP server act as you in one app, with only the roles you choose.</p>
{error}
{created}
<section><h2>Your keys</h2>{list}</section>
{forms}
<p><a href="/">Back to your account</a></p>"#,
        who = esc(email),
        error = error_box(error),
    );
    page_with_class(status, "API keys", &body, "card wide")
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
