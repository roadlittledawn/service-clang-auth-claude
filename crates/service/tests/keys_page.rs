//! Issue #4: the self-serve `/keys` page.

mod common;

use axum::http::StatusCode;
use common::*;

const CSRF: &str = "csrf-token-for-tests-0123456789abcdef";

/// A form post from our own page: `Origin: null` (no-referrer) plus the
/// double-submit CSRF token.
fn own_form(path: &str, session: &str, pairs: &[(&str, &str)]) -> Req {
    let mut all = vec![("csrf", CSRF)];
    all.extend_from_slice(pairs);
    Req::post(path)
        .header("origin", "null")
        .header("cookie", &format!("ca_session={session}; ca_csrf={CSRF}"))
        .form(&all)
}

fn raw_key(body: &str) -> String {
    let i = body.find("ca_key_").expect("raw key shown");
    body[i..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect()
}

#[tokio::test]
async fn signed_out_visitors_are_sent_to_login() {
    let app = TestApp::new().await;
    let res = app.send(Req::get("/keys")).await;
    assert_eq!(res.status, StatusCode::FOUND);
    assert_eq!(res.location(), Some("/login"));
    let res = app
        .send(
            Req::post("/keys")
                .header("origin", "null")
                .cookie("ca_csrf", CSRF)
                .form(&[
                    ("csrf", CSRF),
                    ("app", "demo"),
                    ("name", "k"),
                    ("expires", "never"),
                ]),
        )
        .await;
    assert_eq!(res.status, StatusCode::FOUND);
    assert_eq!(res.location(), Some("/login"));
}

#[tokio::test]
async fn page_shows_a_form_per_granted_app_with_its_roles() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &["admin", "member"])])
        .await;
    let session = app.session_for("me@example.com").await;
    let res = app.send(Req::get("/keys").session(&session)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.header("content-security-policy").is_some());
    assert_eq!(res.header("cache-control"), Some("no-store"));
    assert!(!res.body.contains("<script"));
    assert!(res.body.contains("New key for Demo"));
    assert!(
        !res.body.contains("New key for Other"),
        "no grant for other"
    );
    assert!(res.body.contains(r#"name="roles" value="admin""#));
    assert!(res.body.contains(r#"name="roles" value="member""#));
    assert!(!res.body.contains("checked"), "no role ticked by default");
    assert!(res.body.contains("You have no API keys."));

    // The home page links here.
    let home = app.send(Req::get("/").session(&session)).await;
    assert!(home.body.contains(r#"href="/keys""#));
}

#[tokio::test]
async fn create_shows_the_key_once_and_it_exchanges_with_chosen_roles() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &["admin", "member"])])
        .await;
    let session = app.session_for("me@example.com").await;
    let res = app
        .send(own_form(
            "/keys",
            &session,
            &[
                ("app", "demo"),
                ("name", "laptop MCP"),
                ("roles", "member"),
                ("expires", "90"),
            ],
        ))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(
        res.body.contains("won&#x27;t be shown again") || res.body.contains("won't be shown again")
    );
    assert!(res.body.contains(&format!("{AUTH}/api/token")));
    let raw = raw_key(&res.body);

    let ex = app
        .send(Req::post("/api/token").header("authorization", &format!("Bearer {raw}")))
        .await;
    assert_eq!(ex.status, StatusCode::OK, "{}", ex.body);

    // The listing shows it but never the raw key again.
    let res = app.send(Req::get("/keys").session(&session)).await;
    assert!(res.body.contains("laptop MCP"));
    assert!(res.body.contains("member"));
    assert!(!res.body.contains("ca_key_"));

    let keys = app.store().list_api_keys(None, None).await.unwrap();
    assert_eq!(keys[0].roles, vec!["member".to_string()]);
    let days = (keys[0].expires_at.unwrap() - chrono::Utc::now()).num_days();
    assert!((89..=90).contains(&days), "{days}");
}

#[tokio::test]
async fn create_rejects_bad_input() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &["member"])]).await;
    let session = app.session_for("me@example.com").await;
    for pairs in [
        // Role the user doesn't hold.
        vec![
            ("app", "demo"),
            ("name", "k"),
            ("roles", "admin"),
            ("expires", "never"),
        ],
        // App the user has no grant for.
        vec![("app", "other"), ("name", "k"), ("expires", "never")],
        // Missing name, bad expiry.
        vec![("app", "demo"), ("name", " "), ("expires", "never")],
        vec![("app", "demo"), ("name", "k"), ("expires", "5")],
    ] {
        let res = app.send(own_form("/keys", &session, &pairs)).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{pairs:?}");
        assert!(res.body.contains(r#"class="error""#));
        assert!(!res.body.contains("ca_key_"));
    }
    assert!(app
        .store()
        .list_api_keys(None, None)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn app_origins_and_missing_tokens_cannot_create_or_revoke() {
    let app = TestApp::new().await;
    let user = app.user("me@example.com", &[("demo", &[])]).await;
    let session = app.session_for("me@example.com").await;
    let fields = [("app", "demo"), ("name", "k"), ("expires", "never")];

    // A registered app's page posting cross-origin with the session cookie.
    let res = app
        .send(
            Req::post("/keys")
                .origin(APP_ORIGIN)
                .session(&session)
                .form(&fields),
        )
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    // A foreign origin.
    let res = app
        .send(
            Req::post("/keys")
                .origin("https://evil.example")
                .session(&session)
                .form(&fields),
        )
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    // No origin and no CSRF token.
    let res = app
        .send(
            Req::post("/keys")
                .header("origin", "null")
                .session(&session)
                .form(&fields),
        )
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert!(app
        .store()
        .list_api_keys(None, None)
        .await
        .unwrap()
        .is_empty());

    // The auth host's own origin is fine.
    let res = app
        .send(
            Req::post("/keys")
                .origin(AUTH)
                .session(&session)
                .form(&fields),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);

    // Same rules for revoke.
    let key = &app
        .store()
        .list_api_keys(Some(user.id), None)
        .await
        .unwrap()[0];
    let res = app
        .send(
            Req::post("/keys/revoke")
                .origin(APP_ORIGIN)
                .session(&session)
                .form(&[("key_id", &key.public_id)]),
        )
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(
        app.store().list_api_keys(None, None).await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn users_can_revoke_only_their_own_keys() {
    let app = TestApp::new().await;
    let me = app.user("me@example.com", &[("demo", &[])]).await;
    let them = app.user("them@example.com", &[("demo", &[])]).await;
    let (_, mine) = app
        .store()
        .create_api_key(me.id, "demo", "mine", &[], None)
        .await
        .unwrap();
    let (theirs_raw, theirs) = app
        .store()
        .create_api_key(them.id, "demo", "theirs", &[], None)
        .await
        .unwrap();
    let session = app.session_for("me@example.com").await;

    let res = app
        .send(own_form(
            "/keys/revoke",
            &session,
            &[("key_id", &theirs.public_id)],
        ))
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    let ex = app
        .send(Req::post("/api/token").header("authorization", &format!("Bearer {theirs_raw}")))
        .await;
    assert_eq!(ex.status, StatusCode::OK, "their key still works");

    let res = app
        .send(own_form(
            "/keys/revoke",
            &session,
            &[("key_id", &mine.public_id)],
        ))
        .await;
    assert_eq!(res.status, StatusCode::FOUND);
    assert_eq!(res.location(), Some("/keys"));
    assert_eq!(
        app.store()
            .list_api_keys(Some(me.id), None)
            .await
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn new_key_message_uses_the_configured_token_lifetime() {
    let app = TestApp::with(|v| {
        v.insert("ACCESS_TOKEN_TTL".into(), "5m".into());
    })
    .await;
    app.user("me@example.com", &[("demo", &[])]).await;
    let session = app.session_for("me@example.com").await;
    let res = app
        .send(own_form(
            "/keys",
            &session,
            &[("app", "demo"), ("name", "k"), ("expires", "never")],
        ))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains("a 5-minute access token"));
}
