//! Issue #4: per-user API keys exchanged at `POST /api/token` for access
//! tokens scoped to one app.

mod common;

use std::collections::BTreeMap;

use axum::http::StatusCode;
use bson::doc;
use clang_auth_core::{keys::AccessClaims, model::UserStatus};
use common::*;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};

fn exchange(key: &str) -> Req {
    Req::post("/api/token").header("authorization", &format!("Bearer {key}"))
}

async fn verify(app: &TestApp, token: &str) -> AccessClaims {
    let jwks: JwkSet =
        serde_json::from_str(&app.send(Req::get("/.well-known/jwks.json")).await.body).unwrap();
    let kid = decode_header(token).unwrap().kid.unwrap();
    let key = DecodingKey::from_jwk(jwks.find(&kid).unwrap()).unwrap();
    let mut v = Validation::new(Algorithm::ES256);
    v.set_issuer(&[AUTH]);
    decode::<AccessClaims>(token, &key, &v).unwrap().claims
}

async fn roles_of(app: &TestApp, raw: &str) -> Vec<String> {
    let res = app.send(exchange(raw)).await;
    verify(app, res.json()["token"].as_str().unwrap())
        .await
        .apps["demo"]
        .clone()
}

fn assert_rejected(res: &Res) {
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.body);
    assert_eq!(res.json()["error"]["code"], "invalid_api_key");
    assert_eq!(res.header("www-authenticate"), Some("Bearer"));
    assert!(res.cookies().is_empty());
}

#[tokio::test]
async fn exchange_returns_token_scoped_to_the_keys_app() {
    let app = TestApp::new().await;
    let user = app
        .user(
            "me@example.com",
            &[("demo", &["contributor"]), ("other", &["admin"])],
        )
        .await;
    let (raw, key) = app
        .store()
        .create_api_key(user.id, "demo", "laptop MCP", &["contributor".into()], None)
        .await
        .unwrap();
    assert!(raw.starts_with("ca_key_"));
    assert_ne!(key.id, raw, "only the hash is stored");

    // An Origin header must not earn CORS headers: server-to-server only.
    let res = app.send(exchange(&raw).origin(APP_ORIGIN)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    assert!(res.header("access-control-allow-origin").is_none());
    assert!(res.cookies().is_empty(), "no cookies set");
    let body = res.json();
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 900);

    let claims = verify(&app, body["token"].as_str().unwrap()).await;
    assert_eq!(claims.sub, user.id.to_hex());
    assert_eq!(claims.email, "me@example.com");
    assert_eq!(
        claims.apps,
        BTreeMap::from([("demo".to_string(), vec!["contributor".to_string()])]),
        "only the key's app, not 'other'"
    );
    assert_eq!(claims.amr, Some(vec!["api_key".to_string()]));

    let stored = app
        .store()
        .list_api_keys(Some(user.id), None)
        .await
        .unwrap();
    assert!(stored[0].last_used_at.is_some());
}

#[tokio::test]
async fn key_roles_are_a_subset_of_the_grant_and_never_exceed_it() {
    let app = TestApp::new().await;
    let user = app
        .user("me@example.com", &[("demo", &["admin", "member"])])
        .await;
    let store = app.store();

    // An admin's key created with no roles acts with no roles.
    let (no_roles, _) = store
        .create_api_key(user.id, "demo", "a", &[], None)
        .await
        .unwrap();
    assert_eq!(roles_of(&app, &no_roles).await, Vec::<String>::new());

    let (member, _) = store
        .create_api_key(user.id, "demo", "b", &["member".into()], None)
        .await
        .unwrap();
    assert_eq!(roles_of(&app, &member).await, vec!["member".to_string()]);

    // A role the user doesn't hold can't be put on a key.
    assert!(store
        .create_api_key(user.id, "demo", "c", &["owner".into()], None)
        .await
        .is_err());

    // Demoting the user demotes the key: member is dropped from the grant.
    store
        .set_grant(user.id, "demo", &["admin".into()])
        .await
        .unwrap();
    assert_eq!(roles_of(&app, &member).await, Vec::<String>::new());
    // Promoting the user doesn't promote a key past what it was given.
    store
        .set_grant(
            user.id,
            "demo",
            &["admin".into(), "member".into(), "owner".into()],
        )
        .await
        .unwrap();
    assert_eq!(roles_of(&app, &member).await, vec!["member".to_string()]);
    assert_eq!(roles_of(&app, &no_roles).await, Vec::<String>::new());
}

#[tokio::test]
async fn malformed_and_unknown_keys_are_rejected() {
    let app = TestApp::new().await;
    assert_rejected(&app.send(Req::post("/api/token")).await);
    assert_rejected(&app.send(exchange("ca_key_nope")).await);
    assert_rejected(&app.send(exchange("not-a-key")).await);
    // The admin key is not an API key.
    assert_rejected(&app.send(exchange(ADMIN_KEY)).await);
    assert_rejected(
        &app.send(Req::post("/api/token").header("authorization", "Basic abc"))
            .await,
    );
}

#[tokio::test]
async fn removed_grant_disabled_user_and_revocation_stop_the_key() {
    let app = TestApp::new().await;
    let user = app.user("me@example.com", &[("demo", &["member"])]).await;
    let (raw, key) = app
        .store()
        .create_api_key(user.id, "demo", "k", &[], None)
        .await
        .unwrap();
    assert_eq!(app.send(exchange(&raw)).await.status, StatusCode::OK);

    // Removing the grant stops the key; re-granting brings it back.
    app.store().remove_grant(user.id, "demo").await.unwrap();
    assert_rejected(&app.send(exchange(&raw)).await);
    app.store()
        .set_grant(user.id, "demo", &["member".into()])
        .await
        .unwrap();
    assert_eq!(app.send(exchange(&raw)).await.status, StatusCode::OK);

    // Disabling the user stops it.
    app.store()
        .update_user(user.id, None, Some(UserStatus::Disabled))
        .await
        .unwrap();
    assert_rejected(&app.send(exchange(&raw)).await);
    app.store()
        .update_user(user.id, None, Some(UserStatus::Active))
        .await
        .unwrap();
    assert_eq!(app.send(exchange(&raw)).await.status, StatusCode::OK);

    // Revoking deletes it for good.
    app.store()
        .revoke_api_key(user.id, &key.public_id)
        .await
        .unwrap();
    assert_rejected(&app.send(exchange(&raw)).await);
}

#[tokio::test]
async fn expired_keys_are_rejected_before_the_ttl_monitor_runs() {
    let app = TestApp::new().await;
    let user = app.user("me@example.com", &[("demo", &[])]).await;
    let soon = chrono::Utc::now() + chrono::Duration::days(1);
    let (raw, key) = app
        .store()
        .create_api_key(user.id, "demo", "k", &[], Some(soon))
        .await
        .unwrap();
    assert_eq!(app.send(exchange(&raw)).await.status, StatusCode::OK);
    let past = bson::DateTime::from_chrono(chrono::Utc::now() - chrono::Duration::seconds(5));
    app.store()
        .api_keys
        .update_one(
            doc! { "_id": &key.id },
            doc! { "$set": { "expires_at": past } },
        )
        .await
        .unwrap();
    assert_rejected(&app.send(exchange(&raw)).await);
}

#[tokio::test]
async fn deleting_the_app_or_user_deletes_their_keys() {
    let app = TestApp::new().await;
    let a = app
        .user("a@example.com", &[("demo", &[]), ("other", &[])])
        .await;
    let b = app.user("b@example.com", &[("demo", &[])]).await;
    let store = app.store();
    let (a_demo, _) = store
        .create_api_key(a.id, "demo", "k", &[], None)
        .await
        .unwrap();
    let (a_other, _) = store
        .create_api_key(a.id, "other", "k", &[], None)
        .await
        .unwrap();
    let (b_demo, _) = store
        .create_api_key(b.id, "demo", "k", &[], None)
        .await
        .unwrap();

    store.delete_app("other").await.unwrap();
    assert_rejected(&app.send(exchange(&a_other)).await);
    assert_eq!(
        store
            .list_api_keys(None, Some("other"))
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(app.send(exchange(&a_demo)).await.status, StatusCode::OK);

    store.delete_user(a.id).await.unwrap();
    assert_eq!(
        store.list_api_keys(Some(a.id), None).await.unwrap().len(),
        0
    );
    assert_eq!(app.send(exchange(&b_demo)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn creating_keys_is_validated() {
    let app = TestApp::new().await;
    let user = app.user("me@example.com", &[("demo", &[])]).await;
    let store = app.store();
    assert!(
        store
            .create_api_key(user.id, "other", "k", &[], None)
            .await
            .is_err(),
        "no grant for 'other'"
    );
    assert!(store
        .create_api_key(user.id, "demo", "  ", &[], None)
        .await
        .is_err());
    assert!(store
        .create_api_key(user.id, "demo", &"x".repeat(65), &[], None)
        .await
        .is_err());
    let past = chrono::Utc::now() - chrono::Duration::days(1);
    assert!(store
        .create_api_key(user.id, "demo", "k", &[], Some(past))
        .await
        .is_err());
    for i in 0..10 {
        store
            .create_api_key(user.id, "demo", &format!("k{i}"), &[], None)
            .await
            .unwrap();
    }
    assert!(
        store
            .create_api_key(user.id, "demo", "k11", &[], None)
            .await
            .is_err(),
        "limit of 10 per app"
    );
}

#[tokio::test]
async fn browser_tokens_are_unchanged() {
    // Guard: the browser login token must not grow an `amr` claim or be
    // scoped down. (tokens.rs checks the exact claim set too.)
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &[]), ("other", &[])])
        .await;
    let res = app.login("me@example.com", PASSWORD, APP_ORIGIN).await;
    let claims = verify(&app, &res.cookie("ca_access").unwrap().value).await;
    assert_eq!(claims.amr, None);
    assert_eq!(claims.apps.len(), 2);
}
