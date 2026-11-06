//! §15 "Invites": setup links, single use, expiry, supersession, resets.

mod common;

use axum::http::{Method, StatusCode};
use bson::doc;
use chrono::{Duration, Utc};
use clang_auth_core::secret::sha256_hex;
use common::*;
use serde_json::json;

const NEW_PW: &str = "a brand new passphrase";

async fn create_user(app: &TestApp, email: &str) -> (String, String) {
    let res = app
        .send(
            Req::post("/admin/users")
                .admin()
                .json(json!({ "email": email, "name": "New", "grants": { "demo": ["member"] } })),
        )
        .await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.body);
    let body = res.json();
    let link = body["setup_link"].as_str().unwrap().to_string();
    assert!(link.starts_with(&format!("{AUTH}/setup?token=")));
    (body["user"]["id"].as_str().unwrap().to_string(), link)
}

fn setup_post(token: &str, pw: &str) -> Req {
    Req::post("/setup").origin(AUTH).form(&[
        ("token", token),
        ("password", pw),
        ("password_confirm", pw),
    ])
}

#[tokio::test]
async fn setup_link_sets_password_and_logs_in() {
    let app = TestApp::new().await;
    let (id, link) = create_user(&app, "new@example.com").await;
    let token = token_from_link(&link);

    // Stored only as a hash.
    assert!(app
        .store()
        .invites
        .find_one(doc! { "_id": sha256_hex(&token) })
        .await
        .unwrap()
        .is_some());
    assert!(app
        .store()
        .invites
        .find_one(doc! { "_id": &token })
        .await
        .unwrap()
        .is_none());

    // Before setup, the user cannot log in.
    assert_eq!(
        app.login("new@example.com", NEW_PW, "").await.status,
        StatusCode::UNAUTHORIZED
    );

    let form = app.send(Req::get(&format!("/setup?token={token}"))).await;
    assert_eq!(form.status, StatusCode::OK);
    assert!(form.body.contains("Set your password") && form.body.contains("new@example.com"));
    assert_eq!(form.header("referrer-policy"), Some("no-referrer"));

    let res = app.send(setup_post(&token, NEW_PW)).await;
    assert_eq!(res.status, StatusCode::FOUND);
    assert_eq!(res.location(), Some("/"));
    let session = res.cookie("ca_session").expect("logged in").value;
    assert!(res.cookie("ca_access").is_some());
    let home = app.send(Req::get("/").session(&session)).await;
    assert!(home.body.contains("new@example.com"));

    let user = app
        .send(Req::get(&format!("/admin/users/{id}")).admin())
        .await
        .json();
    assert_eq!(user["has_password"], true);
    assert_eq!(
        app.login("new@example.com", NEW_PW, "").await.status,
        StatusCode::FOUND
    );
}

#[tokio::test]
async fn invites_are_single_use() {
    let app = TestApp::new().await;
    let (_, link) = create_user(&app, "new@example.com").await;
    let token = token_from_link(&link);
    assert_eq!(
        app.send(setup_post(&token, NEW_PW)).await.status,
        StatusCode::FOUND
    );
    let again = app
        .send(setup_post(&token, "another passphrase here"))
        .await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert!(again.cookie("ca_session").is_none());
    assert_eq!(
        app.send(Req::get(&format!("/setup?token={token}")))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    // The first password still applies.
    assert_eq!(
        app.login("new@example.com", NEW_PW, "").await.status,
        StatusCode::FOUND
    );
}

#[tokio::test]
async fn invites_expire() {
    let app = TestApp::new().await;
    let (_, link) = create_user(&app, "new@example.com").await;
    let token = token_from_link(&link);
    let past = bson::DateTime::from_chrono(Utc::now() - Duration::seconds(1));
    app.store()
        .invites
        .update_one(
            doc! { "_id": sha256_hex(&token) },
            doc! { "$set": { "expires_at": past } },
        )
        .await
        .unwrap();
    assert_eq!(
        app.send(Req::get(&format!("/setup?token={token}")))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        app.send(setup_post(&token, NEW_PW)).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn invite_ttl_is_configurable() {
    let app = TestApp::with(|v| {
        v.insert("INVITE_TTL".into(), "1h".into());
    })
    .await;
    let res = app
        .send(
            Req::post("/admin/users")
                .admin()
                .json(json!({ "email": "x@example.com" })),
        )
        .await;
    let expires: chrono::DateTime<Utc> =
        res.json()["expires_at"].as_str().unwrap().parse().unwrap();
    let delta = (expires - Utc::now()).num_seconds();
    assert!((3590..=3600).contains(&delta), "{delta}");
}

#[tokio::test]
async fn newer_invite_invalidates_older() {
    let app = TestApp::new().await;
    let (id, link) = create_user(&app, "new@example.com").await;
    let first = token_from_link(&link);
    let res = app
        .send(Req::post(&format!("/admin/users/{id}/reset")).admin())
        .await;
    assert_eq!(res.status, StatusCode::OK);
    let second = token_from_link(res.json()["reset_link"].as_str().unwrap());

    assert_eq!(
        app.send(setup_post(&first, NEW_PW)).await.status,
        StatusCode::BAD_REQUEST,
        "superseded"
    );
    assert_eq!(
        app.send(setup_post(&second, NEW_PW)).await.status,
        StatusCode::FOUND
    );
}

#[tokio::test]
async fn reset_revokes_existing_sessions() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &[])]).await;
    let s1 = app.session_for("me@example.com").await;
    let s2 = app.session_for("me@example.com").await;

    let res = app
        .send(Req::post("/admin/users/me@example.com/reset").admin())
        .await;
    let link = res.json()["reset_link"].as_str().unwrap().to_string();
    let token = token_from_link(&link);
    // Issuing the link alone doesn't log anyone out...
    assert_eq!(
        app.send(
            Req::post("/api/session/refresh")
                .origin(APP_ORIGIN)
                .session(&s1)
        )
        .await
        .status,
        StatusCode::OK
    );

    let form = app.send(Req::get(&format!("/setup?token={token}"))).await;
    assert!(form.body.contains("Reset your password"));
    let res = app.send(setup_post(&token, NEW_PW)).await;
    assert_eq!(res.status, StatusCode::FOUND);
    let fresh = res.cookie("ca_session").unwrap().value;

    // ...completing it does.
    for old in [&s1, &s2] {
        let r = app
            .send(
                Req::post("/api/session/refresh")
                    .origin(APP_ORIGIN)
                    .session(old),
            )
            .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        app.send(
            Req::post("/api/session/refresh")
                .origin(APP_ORIGIN)
                .session(&fresh)
        )
        .await
        .status,
        StatusCode::OK
    );
    assert_eq!(
        app.login("me@example.com", PASSWORD, "").await.status,
        StatusCode::UNAUTHORIZED,
        "old password gone"
    );
    assert_eq!(
        app.login("me@example.com", NEW_PW, "").await.status,
        StatusCode::FOUND
    );
}

#[tokio::test]
async fn password_policy_is_enforced() {
    let app = TestApp::new().await;
    let (_, link) = create_user(&app, "new@example.com").await;
    let token = token_from_link(&link);
    for (pw, msg) in [
        ("short", "at least 12"),
        ("elevenchars", "at least 12"),
        (&"x".repeat(129)[..], "at most 128"),
    ] {
        let res = app.send(setup_post(&token, pw)).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{pw}");
        assert!(res.body.contains(msg), "{pw}");
        assert!(res.cookie("ca_session").is_none());
    }
    let res = app
        .send(Req::post("/setup").origin(AUTH).form(&[
            ("token", &token),
            ("password", NEW_PW),
            ("password_confirm", "different passphrase"),
        ]))
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.body.contains("don&#x27;t match"));
    // Rejections don't burn the invite; exactly 12 characters is fine.
    assert_eq!(
        app.send(setup_post(&token, "twelve chars")).await.status,
        StatusCode::FOUND
    );
}

#[tokio::test]
async fn disabled_or_deleted_users_cannot_use_invites() {
    let app = TestApp::new().await;
    let (id, link) = create_user(&app, "new@example.com").await;
    let token = token_from_link(&link);
    app.send(
        Req::new(Method::PATCH, &format!("/admin/users/{id}"))
            .admin()
            .json(json!({ "status": "disabled" })),
    )
    .await;
    assert_eq!(
        app.send(setup_post(&token, NEW_PW)).await.status,
        StatusCode::BAD_REQUEST
    );

    let (id, link) = create_user(&app, "gone@example.com").await;
    app.send(Req::new(Method::DELETE, &format!("/admin/users/{id}")).admin())
        .await;
    assert_eq!(
        app.send(setup_post(&token_from_link(&link), NEW_PW))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        app.store()
            .invites
            .count_documents(doc! { "user_id": bson::oid::ObjectId::parse_str(&id).unwrap() })
            .await
            .unwrap(),
        0
    );
}
