//! §15 "Auth flow" acceptance items.

mod common;

use axum::http::StatusCode;
use bson::doc;
use chrono::{Duration, Utc};
use clang_auth_core::{model::UserStatus, secret::sha256_hex};
use common::*;

#[tokio::test]
async fn valid_login_redirects_with_both_cookies() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &["admin"])]).await;
    let target = format!("{APP_ORIGIN}/dashboard?x=1");
    let res = app.login("Me@Example.com", PASSWORD, &target).await;

    assert_eq!(res.status, StatusCode::FOUND);
    assert_eq!(res.location(), Some(target.as_str()));

    let s = res.cookie("ca_session").expect("session cookie");
    assert!(s.value.len() >= 43, "32+ random bytes, base64url");
    assert!(s
        .value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    assert_eq!(s.attr("path"), Some("/"));
    assert!(!s.has("domain"), "session cookie must be host-only");
    assert!(s.has("httponly") && s.has("secure"));
    assert_eq!(s.attr("samesite"), Some("Lax"));
    let max_age: i64 = s.attr("max-age").unwrap().parse().unwrap();
    assert!((30 * 86400 - 5..=30 * 86400).contains(&max_age));

    let a = res.cookie("ca_access").expect("access cookie");
    assert_eq!(a.attr("domain"), Some(".localtest.me"));
    assert_eq!(a.attr("path"), Some("/"));
    assert!(a.has("httponly") && a.has("secure"));
    assert_eq!(a.attr("samesite"), Some("Lax"));
    assert_eq!(a.attr("max-age"), Some("900"));
    assert_eq!(a.value.split('.').count(), 3, "JWT");

    // Only the hash of the session token is stored.
    let stored = app
        .store()
        .sessions
        .find_one(doc! { "_id": sha256_hex(&s.value) })
        .await
        .unwrap();
    assert!(stored.is_some());
    assert!(app
        .store()
        .sessions
        .find_one(doc! { "_id": &s.value })
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn cookie_secure_false_omits_secure() {
    let app = TestApp::with(|v| {
        v.insert("COOKIE_SECURE".into(), "false".into());
    })
    .await;
    app.user("me@example.com", &[("demo", &[])]).await;
    let res = app.login("me@example.com", PASSWORD, APP_ORIGIN).await;
    assert!(!res.cookie("ca_session").unwrap().has("secure"));
    assert!(!res.cookie("ca_access").unwrap().has("secure"));
}

#[tokio::test]
async fn bad_credentials_all_look_the_same() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &[])]).await;
    let disabled = app.user("off@example.com", &[("demo", &[])]).await;
    app.store()
        .update_user(disabled.id, None, Some(UserStatus::Disabled))
        .await
        .unwrap();
    // A user who never completed setup has no password.
    app.store()
        .create_user("new@example.com", None, vec![])
        .await
        .unwrap();

    let normalize = |body: &str, email: &str| body.replace(email, "EMAIL");
    let mut bodies = Vec::new();
    for (email, pw) in [
        ("me@example.com", "wrong password!!"),
        ("nobody@example.com", PASSWORD),
        ("off@example.com", PASSWORD),
        ("new@example.com", PASSWORD),
    ] {
        let res = app.login(email, pw, APP_ORIGIN).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{email}");
        assert!(res.body.contains("Invalid email or password"), "{email}");
        assert!(
            res.cookie("ca_session").is_none() && res.cookie("ca_access").is_none(),
            "{email}: no auth cookies"
        );
        // Strip the per-response CSRF token so pages are comparable.
        let body = normalize(&res.body, email);
        let body = regex_lite_strip(&body, "name=\"csrf\" value=\"", "\"");
        bodies.push(body);
    }
    assert!(
        bodies.windows(2).all(|w| w[0] == w[1]),
        "responses must be indistinguishable"
    );
}

/// Replace the text between `start` and the next `end` with `X`.
fn regex_lite_strip(s: &str, start: &str, end: &str) -> String {
    match s.find(start) {
        Some(i) => {
            let rest = &s[i + start.len()..];
            let j = rest.find(end).unwrap();
            format!("{}{start}X{}", &s[..i], &rest[j..])
        }
        None => s.to_string(),
    }
}

#[tokio::test]
async fn bad_redirect_uris_fall_back_to_home() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &[])]).await;
    for bad in [
        "http://evil.localtest.me:3000/",
        "http://demo.localtest.me:3000.evil.com/",
        "http://demo.localtest.me.evil.com:3000/",
        "http://demo.localtest.me:3001/",  // right host, wrong port
        "https://demo.localtest.me:3000/", // right host, wrong scheme
        "//evil.com",
        "//demo.localtest.me:3000/",
        "/relative/path",
        "javascript:alert(document.cookie)",
        "http://demo.localtest.me:3000@evil.com/",
        "",
    ] {
        let res = app.login("me@example.com", PASSWORD, bad).await;
        assert_eq!(res.status, StatusCode::FOUND, "{bad:?}");
        assert_eq!(
            res.location(),
            Some("/"),
            "{bad:?} must not be redirected to"
        );

        // Same rules for the already-signed-in path and for logout.
        let token = res.cookie("ca_session").unwrap().value;
        let q = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("redirect_uri", bad)
            .finish();
        let res = app
            .send(Req::get(&format!("/login?{q}")).session(&token))
            .await;
        assert_eq!(res.location(), Some("/"), "GET /login {bad:?}");
        let res = app
            .send(
                Req::post("/logout")
                    .origin(AUTH)
                    .session(&token)
                    .form(&[("redirect_uri", bad)]),
            )
            .await;
        assert_eq!(res.location(), Some("/"), "logout {bad:?}");
    }
}

#[tokio::test]
async fn http_origin_requires_allow_insecure() {
    let app = TestApp::with(|v| {
        v.insert("ALLOW_INSECURE_ORIGINS".into(), "false".into());
        v.insert("AUTH_BASE_URL".into(), "https://auth.localtest.me".into());
    })
    .await;
    // The harness registered http:// origins directly in the DB; with
    // insecure origins disabled they must not be honoured as redirects.
    app.user("me@example.com", &[("demo", &[])]).await;
    let res = app
        .send(
            Req::post("/login")
                .origin("https://auth.localtest.me")
                .form(&[
                    ("email", "me@example.com"),
                    ("password", PASSWORD),
                    ("redirect_uri", APP_ORIGIN),
                ]),
        )
        .await;
    assert_eq!(res.location(), Some("/"));
    // And the admin API refuses to register them.
    let res = app
        .send(
            Req::post("/admin/apps").admin().json(
                serde_json::json!({"slug":"x1","name":"X","origins":["http://x.localtest.me"]}),
            ),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_with_valid_session_redirects_immediately() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &["member"])]).await;
    let token = app.session_for("me@example.com").await;

    let target = format!("{APP_ORIGIN}/page");
    let q = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("redirect_uri", &target)
        .finish();
    let res = app
        .send(Req::get(&format!("/login?{q}")).session(&token))
        .await;
    assert_eq!(res.status, StatusCode::FOUND);
    assert_eq!(res.location(), Some(target.as_str()));
    assert!(!res.body.contains("<form"), "no form shown");
    let access = res.cookie("ca_access").expect("fresh access token");
    assert!(!access.is_clear());

    // Without a session the form is shown.
    let res = app.send(Req::get(&format!("/login?{q}"))).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res
        .body
        .contains("<form method=\"post\" action=\"/login\">"));
    assert!(res.body.contains(&format!("value=\"{target}\"")));
}

#[tokio::test]
async fn user_without_grant_sees_no_access_page() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("other", &["member"])]).await;
    let res = app
        .login("me@example.com", PASSWORD, &format!("{APP_ORIGIN}/"))
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert!(res.location().is_none(), "no redirect");
    assert!(
        res.body.contains("You don&#x27;t have access to Demo")
            || res.body.contains("You don't have access to Demo")
    );
    // Still logged in.
    let token = res.cookie("ca_session").expect("still logged in").value;
    let res = app.send(Req::get("/").session(&token)).await;
    assert!(res.body.contains("Signed in as"));

    // Same for the already-signed-in path.
    let q = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("redirect_uri", APP_ORIGIN)
        .finish();
    let res = app
        .send(Req::get(&format!("/login?{q}")).session(&token))
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert!(res.location().is_none());
}

#[tokio::test]
async fn refresh_from_registered_origin_sets_cookie_with_cors() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &["admin"])]).await;
    let token = app.session_for("me@example.com").await;

    let res = app
        .send(
            Req::post("/api/session/refresh")
                .origin(APP_ORIGIN)
                .session(&token),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.header("access-control-allow-origin"), Some(APP_ORIGIN));
    assert_eq!(res.header("access-control-allow-credentials"), Some("true"));
    assert!(res.header("vary").unwrap().contains("Origin"));
    assert!(res.cookie("ca_access").is_some_and(|c| !c.is_clear()));
    let claims = res.json();
    assert_eq!(claims["email"], "me@example.com");
    assert_eq!(claims["apps"]["demo"][0], "admin");

    // Preflight.
    let res = app
        .send(
            Req::new(axum::http::Method::OPTIONS, "/api/session/refresh")
                .origin(APP_ORIGIN)
                .header("access-control-request-method", "POST"),
        )
        .await;
    assert_eq!(res.header("access-control-allow-origin"), Some(APP_ORIGIN));
    assert_eq!(res.header("access-control-allow-credentials"), Some("true"));
    assert!(res
        .header("access-control-allow-methods")
        .unwrap()
        .contains("POST"));
}

#[tokio::test]
async fn refresh_from_unregistered_origin_gets_no_cors() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &[])]).await;
    let token = app.session_for("me@example.com").await;
    for evil in [
        "http://evil.localtest.me:3000",
        "http://demo.localtest.me:3000.evil.com",
        "null",
    ] {
        let res = app
            .send(
                Req::post("/api/session/refresh")
                    .origin(evil)
                    .session(&token),
            )
            .await;
        assert_ne!(res.status, StatusCode::OK, "{evil}");
        assert!(
            res.header("access-control-allow-origin").is_none(),
            "{evil}"
        );
        assert!(
            res.header("access-control-allow-credentials").is_none(),
            "{evil}"
        );
        assert!(res.cookie("ca_access").is_none());

        let res = app
            .send(Req::new(axum::http::Method::OPTIONS, "/api/session/refresh").origin(evil))
            .await;
        assert!(
            res.header("access-control-allow-origin").is_none(),
            "preflight {evil}"
        );
        let res = app
            .send(Req::get("/api/me").origin(evil).session(&token))
            .await;
        assert!(
            res.header("access-control-allow-origin").is_none(),
            "/api/me {evil}"
        );
    }
}

#[tokio::test]
async fn refresh_rejects_expired_revoked_or_disabled() {
    let app = TestApp::new().await;
    let user = app.user("me@example.com", &[("demo", &[])]).await;

    let assert_401_clears = |res: Res, why: &str| {
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{why}");
        assert_eq!(res.json()["error"]["code"], "unauthorized");
        assert_eq!(
            res.header("access-control-allow-origin"),
            Some(APP_ORIGIN),
            "{why}: app can read the 401"
        );
        assert!(res.cookie("ca_session").unwrap().is_clear(), "{why}");
        let a = res.cookie("ca_access").unwrap();
        assert!(
            a.is_clear() && a.attr("domain") == Some(".localtest.me"),
            "{why}"
        );
    };
    let refresh = |t: &str| {
        Req::post("/api/session/refresh")
            .origin(APP_ORIGIN)
            .session(t)
    };

    // Expired (sliding expiry passed).
    let t = app.session_for("me@example.com").await;
    let past = bson::DateTime::from_chrono(Utc::now() - Duration::minutes(1));
    app.store()
        .sessions
        .update_one(
            doc! { "_id": sha256_hex(&t) },
            doc! { "$set": { "expires_at": past } },
        )
        .await
        .unwrap();
    assert_401_clears(app.send(refresh(&t)).await, "expired");

    // Absolute lifetime passed even though sliding expiry has not.
    let t = app.session_for("me@example.com").await;
    app.store()
        .sessions
        .update_one(
            doc! { "_id": sha256_hex(&t) },
            doc! { "$set": { "absolute_expires_at": past } },
        )
        .await
        .unwrap();
    assert_401_clears(app.send(refresh(&t)).await, "absolute");

    // Revoked by admin.
    let t = app.session_for("me@example.com").await;
    let res = app
        .send(
            Req::new(
                axum::http::Method::DELETE,
                "/admin/users/me@example.com/sessions",
            )
            .admin(),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_401_clears(app.send(refresh(&t)).await, "revoked");

    // Disabled user (session record left in place to prove the user check).
    let t = app.session_for("me@example.com").await;
    app.store()
        .users
        .update_one(
            doc! { "_id": user.id },
            doc! { "$set": { "status": "disabled" } },
        )
        .await
        .unwrap();
    assert_401_clears(app.send(refresh(&t)).await, "disabled");

    // Garbage token.
    assert_401_clears(app.send(refresh("not-a-real-token")).await, "unknown");
    // /api/me follows the same rules.
    let res = app
        .send(Req::get("/api/me").origin(APP_ORIGIN).session(&t))
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sessions_slide_up_to_the_absolute_cap() {
    let app = TestApp::with(|v| {
        v.insert("SESSION_TTL".into(), "1h".into());
        v.insert("SESSION_MAX_TTL".into(), "2h".into());
    })
    .await;
    app.user("me@example.com", &[("demo", &[])]).await;
    let t = app.session_for("me@example.com").await;
    let id = sha256_hex(&t);
    // Pretend the session was created 90 minutes ago and is about to expire.
    let soon = bson::DateTime::from_chrono(Utc::now() + Duration::minutes(5));
    let cap = bson::DateTime::from_chrono(Utc::now() + Duration::minutes(30));
    app.store()
        .sessions
        .update_one(
            doc! { "_id": &id },
            doc! { "$set": { "expires_at": soon, "absolute_expires_at": cap } },
        )
        .await
        .unwrap();
    let res = app
        .send(
            Req::post("/api/session/refresh")
                .origin(APP_ORIGIN)
                .session(&t),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    let s = app
        .store()
        .sessions
        .find_one(doc! { "_id": &id })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        s.expires_at, s.absolute_expires_at,
        "slid, but only up to the cap"
    );
    let max_age: i64 = res
        .cookie("ca_session")
        .unwrap()
        .attr("max-age")
        .unwrap()
        .parse()
        .unwrap();
    assert!((1700..=1800).contains(&max_age));
}

#[tokio::test]
async fn logout_deletes_the_session() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &[])]).await;
    let t = app.session_for("me@example.com").await;
    let other = app.session_for("me@example.com").await;

    let res = app
        .send(
            Req::post("/logout")
                .origin(APP_ORIGIN)
                .session(&t)
                .form(&[("redirect_uri", &format!("{APP_ORIGIN}/bye"))]),
        )
        .await;
    assert_eq!(res.status, StatusCode::FOUND);
    assert_eq!(res.location(), Some("http://demo.localtest.me:3000/bye"));
    assert!(res.cookie("ca_session").unwrap().is_clear());
    assert!(res.cookie("ca_access").unwrap().is_clear());
    assert!(app
        .store()
        .sessions
        .find_one(doc! { "_id": sha256_hex(&t) })
        .await
        .unwrap()
        .is_none());

    // The old cookie no longer works anywhere.
    let res = app
        .send(
            Req::post("/api/session/refresh")
                .origin(APP_ORIGIN)
                .session(&t),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    let res = app.send(Req::get("/login").session(&t)).await;
    assert!(res.body.contains("<form"));
    // Other sessions are untouched.
    let res = app
        .send(
            Req::post("/api/session/refresh")
                .origin(APP_ORIGIN)
                .session(&other),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);

    // fetch()-style logout gets JSON + CORS.
    let res = app
        .send(
            Req::post("/logout")
                .origin(APP_ORIGIN)
                .header("accept", "application/json")
                .session(&other),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.header("access-control-allow-origin"), Some(APP_ORIGIN));
    assert!(res.cookie("ca_session").unwrap().is_clear());
}

#[tokio::test]
async fn foreign_origin_posts_are_rejected() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &[])]).await;
    let t = app.session_for("me@example.com").await;
    let evil = "https://evil.example.com";

    let res = app
        .send(
            Req::post("/login")
                .origin(evil)
                .form(&[("email", "me@example.com"), ("password", PASSWORD)]),
        )
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert!(res.cookie("ca_session").is_none());

    let res = app
        .send(Req::post("/logout").origin(evil).session(&t))
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert!(
        app.store()
            .sessions
            .find_one(doc! { "_id": sha256_hex(&t) })
            .await
            .unwrap()
            .is_some(),
        "session survives"
    );

    let res = app
        .send(
            Req::post("/setup")
                .origin(evil)
                .form(&[("token", "x"), ("password", "whatever whatever")]),
        )
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);

    let res = app
        .send(Req::post("/api/session/refresh").origin(evil).session(&t))
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);

    // Referer is used when Origin is missing.
    let res = app
        .send(
            Req::post("/login")
                .header("referer", "https://evil.example.com/page")
                .form(&[("email", "me@example.com"), ("password", PASSWORD)]),
        )
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    let res = app
        .send(
            Req::post("/login")
                .header("referer", &format!("{AUTH}/login"))
                .form(&[("email", "me@example.com"), ("password", PASSWORD)]),
        )
        .await;
    assert_eq!(res.status, StatusCode::FOUND);

    // Neither header and no CSRF token: rejected.
    let res = app
        .send(Req::post("/login").form(&[("email", "me@example.com"), ("password", PASSWORD)]))
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn null_origin_form_needs_matching_csrf_token() {
    // Our pages send `Referrer-Policy: no-referrer`, so browsers submit our
    // own forms with `Origin: null`. Those are accepted only with the
    // double-submit token.
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &[])]).await;
    let page = app.send(Req::get("/login")).await;
    let csrf = page.cookie("ca_csrf").expect("csrf cookie");
    assert_eq!(csrf.attr("samesite"), Some("Strict"));
    assert!(page
        .body
        .contains(&format!("name=\"csrf\" value=\"{}\"", csrf.value)));

    let creds = [("email", "me@example.com"), ("password", PASSWORD)];
    let with = |token: &str| {
        let mut f = creds.to_vec();
        f.push(("csrf", token));
        Req::post("/login")
            .origin("null")
            .cookie("ca_csrf", &csrf.value)
            .form(&f)
    };
    assert_eq!(app.send(with(&csrf.value)).await.status, StatusCode::FOUND);
    assert_eq!(
        app.send(with("wrong-token-wrong-token-wrong-token"))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    // Token in the form but no cookie (a cross-site attacker can't send it).
    let mut f = creds.to_vec();
    f.push(("csrf", &csrf.value));
    assert_eq!(
        app.send(Req::post("/login").origin("null").form(&f))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn sixth_failed_login_is_rate_limited_even_with_correct_password() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &[])]).await;
    for i in 0..5 {
        let res = app.login("me@example.com", "wrong password!!", "").await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "attempt {i}");
    }
    let res = app.login("me@example.com", PASSWORD, "").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "6th attempt blocked");
    assert!(res.body.contains("Invalid email or password"));
    assert!(res.cookie("ca_session").is_none());

    // Unknown emails are limited identically (no account enumeration).
    for _ in 0..5 {
        app.login("ghost@example.com", "wrong password!!", "").await;
    }
    let ghost = app.login("ghost@example.com", "wrong password!!", "").await;
    assert_eq!(ghost.status, res.status);

    // When the window expires, the correct password works again.
    let past = bson::DateTime::from_chrono(Utc::now() - Duration::seconds(1));
    app.store()
        .attempts
        .update_many(doc! {}, doc! { "$set": { "expires_at": past } })
        .await
        .unwrap();
    assert_eq!(
        app.login("me@example.com", PASSWORD, "").await.status,
        StatusCode::FOUND
    );
}

#[tokio::test]
async fn successful_logins_are_not_counted() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &[])]).await;
    for _ in 0..8 {
        assert_eq!(
            app.login("me@example.com", PASSWORD, "").await.status,
            StatusCode::FOUND
        );
    }
}

#[tokio::test]
async fn ip_is_limited_after_twenty_failures() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &[])]).await;
    let attempt = |email: String, pw: &'static str, ip: &'static str| {
        Req::post("/login")
            .origin(AUTH)
            .ip(ip)
            .form(&[("email", &email), ("password", pw)])
    };
    for i in 0..20 {
        let res = app
            .send(attempt(
                format!("u{i}@example.com"),
                "wrong password!!",
                "10.9.9.9",
            ))
            .await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    }
    let res = app
        .send(attempt("me@example.com".into(), PASSWORD, "10.9.9.9"))
        .await;
    assert_eq!(
        res.status,
        StatusCode::UNAUTHORIZED,
        "21st from same IP blocked"
    );
    let res = app
        .send(attempt("me@example.com".into(), PASSWORD, "10.1.1.1"))
        .await;
    assert_eq!(res.status, StatusCode::FOUND, "other IPs unaffected");
}

#[tokio::test]
async fn html_pages_have_security_headers() {
    let app = TestApp::new().await;
    for path in ["/", "/login", "/setup?token=nope"] {
        let res = app.send(Req::get(path)).await;
        let csp = res.header("content-security-policy").unwrap_or_default();
        assert!(
            csp.contains("default-src 'none'") && !csp.contains("unsafe-inline"),
            "{path}"
        );
        assert!(
            !csp.contains("script-src"),
            "{path}: scripts fall back to default-src 'none'"
        );
        assert_eq!(res.header("x-frame-options"), Some("DENY"), "{path}");
        assert_eq!(res.header("referrer-policy"), Some("no-referrer"), "{path}");
        assert_eq!(res.header("cache-control"), Some("no-store"), "{path}");
        assert!(!res.body.contains("<script"), "{path}");
    }
}

#[tokio::test]
async fn home_page_shows_status() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &[])]).await;
    let res = app.send(Req::get("/")).await;
    assert!(res.body.contains("not signed in"));
    let t = app.session_for("me@example.com").await;
    let res = app.send(Req::get("/").session(&t)).await;
    assert!(res.body.contains("Signed in as"));
    assert!(res.body.contains("me@example.com"));
    assert!(res.body.contains("action=\"/logout\""));
    assert!(res.body.contains(APP_ORIGIN));
}

#[tokio::test]
async fn health_and_errors() {
    let app = TestApp::new().await;
    let res = app.send(Req::get("/health")).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json(), serde_json::json!({ "status": "ok" }));
    let res = app.send(Req::get("/nope")).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(res.json()["error"]["code"], "not_found");
}
